"""
routers/events.py — REST endpoints for the dashboard's initial data load.

CONCEPT — Why REST AND WebSockets?
────────────────────────────────────
WebSockets (Phase 4) are perfect for *live* data — they push new events as
they arrive.  But when a user first opens the dashboard, the WebSocket
connection hasn't received any history.

These REST endpoints let the dashboard:
  1. Fetch the last N events on page load → populate the initial table.
  2. Fetch aggregate stats → populate the stats cards.

After the initial load, WebSockets take over for real-time updates.  This is
the same hybrid pattern used by Slack, Discord, and most real-time dashboards.

Endpoints:
  GET /api/events          → paginated event history (newest first)
  GET /api/events/stats    → aggregate stats for the dashboard header cards
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.event import HoneypotEvent

router = APIRouter(prefix="/api", tags=["Events"])


# ── GET /api/events ───────────────────────────────────────────────────────────

@router.get("/events", summary="Paginated event history")
async def list_events(
    limit: int = Query(default=1000, ge=1, le=5000, description="Max events to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    threat_level: str | None = Query(default=None, description="Filter by threat level"),
    sort_by: str = Query(default="time_desc", description="Sort by metric: time_desc, time_asc, threat_desc, threat_asc"),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the most recent honeypot events.
    """
    stmt = select(HoneypotEvent)

    if threat_level:
        stmt = stmt.where(HoneypotEvent.threat_level == threat_level.upper())
        
    # Implement sorting
    if sort_by == "time_desc":
        stmt = stmt.order_by(desc(HoneypotEvent.timestamp))
    elif sort_by == "time_asc":
        stmt = stmt.order_by(HoneypotEvent.timestamp)
    elif sort_by == "threat_desc":
        # Hacky but simple sort for text threat levels based on a known order, 
        # but since SQLite doesn't easily do custom order_by arrays, we sort alphabetically?
        # Actually, let's just sort alphabetically for now, or use a CASE statement.
        from sqlalchemy import case
        threat_order = case(
            (HoneypotEvent.threat_level == 'CRITICAL', 1),
            (HoneypotEvent.threat_level == 'HIGH', 2),
            (HoneypotEvent.threat_level == 'MEDIUM', 3),
            (HoneypotEvent.threat_level == 'LOW', 4),
            else_=5
        )
        stmt = stmt.order_by(threat_order, desc(HoneypotEvent.timestamp))
    elif sort_by == "threat_asc":
        from sqlalchemy import case
        threat_order = case(
            (HoneypotEvent.threat_level == 'CRITICAL', 1),
            (HoneypotEvent.threat_level == 'HIGH', 2),
            (HoneypotEvent.threat_level == 'MEDIUM', 3),
            (HoneypotEvent.threat_level == 'LOW', 4),
            else_=5
        )
        stmt = stmt.order_by(desc(threat_order), desc(HoneypotEvent.timestamp))
    else:
        stmt = stmt.order_by(desc(HoneypotEvent.timestamp))

    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    events = result.scalars().all()

    return {
        "total": len(events),
        "offset": offset,
        "limit": limit,
        "events": [e.to_dict() for e in events],
    }


# ── GET /api/events/stats ─────────────────────────────────────────────────────

@router.get("/events/stats", summary="Aggregate dashboard statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """
    Return aggregate statistics for the dashboard header cards.

    Runs multiple COUNT queries in a single round-trip using SQLAlchemy's
    scalar() method, which is optimised for single-value aggregate queries.

    CONCEPT — Why not fetch all rows and count in Python?
    A SQL COUNT(*) executes on the DB engine — it reads only index pages and
    returns a single integer.  Fetching all rows to count them in Python would
    transfer megabytes of data across the DB connection for no reason.
    Always push aggregations to the database.
    """
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_1h  = now - timedelta(hours=1)

    # ── Total events ──────────────────────────────────────────────────────────
    total_result = await db.execute(select(func.count()).select_from(HoneypotEvent))
    total_events = total_result.scalar() or 0

    # ── Events by threat level ─────────────────────────────────────────────────
    level_result = await db.execute(
        select(HoneypotEvent.threat_level, func.count().label("count"))
        .group_by(HoneypotEvent.threat_level)
    )
    by_level = {row.threat_level: row.count for row in level_result}

    # ── Events in last 24 hours ───────────────────────────────────────────────
    recent_24h_result = await db.execute(
        select(func.count())
        .select_from(HoneypotEvent)
        .where(HoneypotEvent.timestamp >= last_24h)
    )
    events_24h = recent_24h_result.scalar() or 0

    # ── Events in last hour ───────────────────────────────────────────────────
    recent_1h_result = await db.execute(
        select(func.count())
        .select_from(HoneypotEvent)
        .where(HoneypotEvent.timestamp >= last_1h)
    )
    events_1h = recent_1h_result.scalar() or 0

    # ── Unique IPs ────────────────────────────────────────────────────────────
    unique_ip_result = await db.execute(
        select(func.count(func.distinct(HoneypotEvent.ip)))
        .select_from(HoneypotEvent)
    )
    unique_ips = unique_ip_result.scalar() or 0

    # ── Top 10 attacking IPs ──────────────────────────────────────────────────
    top_ip_result = await db.execute(
        select(HoneypotEvent.ip, func.count().label("hits"))
        .group_by(HoneypotEvent.ip)
        .order_by(desc("hits"))
        .limit(10)
    )
    top_ips = [{"ip": row.ip, "hits": row.hits} for row in top_ip_result]

    # ── Top 10 targeted paths ─────────────────────────────────────────────────
    top_path_result = await db.execute(
        select(HoneypotEvent.path, func.count().label("hits"))
        .group_by(HoneypotEvent.path)
        .order_by(desc("hits"))
        .limit(10)
    )
    top_paths = [{"path": row.path, "hits": row.hits} for row in top_path_result]

    # ── Top 5 countries ───────────────────────────────────────────────────────
    top_country_result = await db.execute(
        select(HoneypotEvent.country, func.count().label("hits"))
        .group_by(HoneypotEvent.country)
        .order_by(desc("hits"))
        .limit(5)
    )
    top_countries = [{"country": row.country, "hits": row.hits} for row in top_country_result]

    return {
        "total_events": total_events,
        "events_last_24h": events_24h,
        "events_last_1h": events_1h,
        "unique_ips": unique_ips,
        "by_threat_level": {
            "CRITICAL": by_level.get("CRITICAL", 0),
            "HIGH":     by_level.get("HIGH", 0),
            "MEDIUM":   by_level.get("MEDIUM", 0),
            "LOW":      by_level.get("LOW", 0),
        },
        "top_ips": top_ips,
        "top_paths": top_paths,
        "top_countries": top_countries,
    }
