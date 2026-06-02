"""
services/event_store.py — Enrichment pipeline and DB persistence.

CONCEPT — The Enrichment Pipeline
───────────────────────────────────
Every captured ThreatEvent flows through this pipeline:

  ThreatEvent (from middleware)
      │
      ▼
  GeoIP lookup  (async, cached)
      │
      ▼
  Build HoneypotEvent ORM row
      │
      ▼
  Save to SQLite (async)
      │
      ▼
  Broadcast via WebSocket (fan-out to all connected dashboard tabs)
      │
      ▼
  Return HoneypotEvent

CONCEPT — asyncio.create_task vs await
────────────────────────────────────────
The middleware fires this pipeline with asyncio.create_task(handle_event(evt)).
That schedules the coroutine on the event loop WITHOUT blocking the HTTP
response — the client gets their honeypot response immediately, and the GeoIP
lookup + DB write happen concurrently in the background.

This is the same pattern used by analytics libraries (Amplitude, Segment) that
"fire and forget" tracking calls without delaying page loads.

CONCEPT — Handler Registration Pattern
────────────────────────────────────────
The interceptor middleware needs a way to call this service without importing
it at definition time (which would create circular imports).  We solve this with
a simple registration function:

    # In main.py lifespan:
    from app.services.event_store import handle_event
    register_handler(handle_event)

The middleware then iterates over all registered handlers for each event.
This also makes it easy to add more handlers later (e.g. an alert emailer,
a Slack webhook) without touching the middleware code.
"""

from __future__ import annotations

import logging
from typing import Callable, Coroutine, Any

from app.database import AsyncSessionLocal
from app.engine.analyzer import ThreatEvent
from app.models.event import HoneypotEvent
from app.services import geoip
from app.services.connection_manager import manager as ws_manager

logger = logging.getLogger("honeypot.event_store")

# ── Handler registry ──────────────────────────────────────────────────────────
# The interceptor middleware calls every function in this list for each event.
# Functions must be async: async def f(event: ThreatEvent) -> None
_handlers: list[Callable[[ThreatEvent], Coroutine[Any, Any, None]]] = []


def register_handler(fn: Callable[[ThreatEvent], Coroutine[Any, Any, None]]) -> None:
    """Register an async function to be called for each captured event."""
    _handlers.append(fn)


def get_handlers() -> list[Callable[[ThreatEvent], Coroutine[Any, Any, None]]]:
    """Return all registered handlers (read by the middleware)."""
    return _handlers


# ── Core pipeline ─────────────────────────────────────────────────────────────

async def handle_event(event: ThreatEvent) -> HoneypotEvent | None:
    """
    The main event pipeline: enrich with GeoIP then persist to DB.

    Returns the saved ORM object so Phase 4 can broadcast its to_dict().
    Returns None on any error (never raises — broken DB shouldn't kill the app).
    """
    try:
        # ── Step 1: GeoIP enrichment ──────────────────────────────────────────
        geo = await geoip.lookup(event.ip)

        # ── Step 2: Build ORM row ─────────────────────────────────────────────
        db_event = HoneypotEvent(
            ip=event.ip,
            method=event.method,
            path=event.path,
            query_string=event.query_string[:1024],     # Safety cap
            user_agent=event.user_agent[:512],
            body_preview=event.body_preview[:512],
            is_scanner=event.is_scanner,
            hit_count=event.hit_count,
            window_count=event.window_count,
            threat_level=event.threat_level,
            flags=",".join(event.flags),                # ["SQLi","Scanner"] → "SQLi,Scanner"
            country=geo.country,
            city=geo.city,
            isp=geo.isp,
            country_code=geo.country_code,
        )

        # ── Step 3: Persist to SQLite ─────────────────────────────────────────
        # We create a fresh session here (not a shared one from a request)
        # because this runs in a background asyncio.create_task, decoupled
        # from any HTTP request lifecycle.
        async with AsyncSessionLocal() as session:
            session.add(db_event)
            await session.commit()
            await session.refresh(db_event)  # Populate auto-generated id + timestamp

        logger.info(
            "💾 Saved event id=%s | %s %s | %s, %s | level=%s",
            db_event.id,
            db_event.method,
            db_event.path,
            db_event.city,
            db_event.country,
            db_event.threat_level,
        )

        # ── Step 4: WebSocket broadcast ───────────────────────────────────────
        # CONCEPT: We broadcast AFTER commit so the payload contains the real
        # DB-generated `id` and `timestamp`.  The dashboard can use the `id`
        # to de-duplicate events if it receives the same one via REST + WS.
        #
        # ws_manager.broadcast() is a no-op if no clients are connected,
        # so this never raises even when the dashboard isn't open.
        clients_notified = await ws_manager.broadcast(db_event.to_dict())
        if clients_notified:
            logger.debug("📡 Broadcast to %d WebSocket client(s)", clients_notified)

        return db_event

    except Exception as exc:
        logger.error("Failed to persist event for %s: %s", event.ip, exc, exc_info=True)
        return None
