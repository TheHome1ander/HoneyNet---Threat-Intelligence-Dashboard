"""
health.py — Health-check and server-info routes.

These are the only LEGITIMATE routes we expose.  Every other route added in
Phase 2 will be a honeypot — designed to look like real admin endpoints while
secretly logging everything about the attacker.

/health   → lightweight liveness probe (used by load-balancers / uptime monitors)
/status   → slightly richer readiness probe that also checks DB connectivity
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db

router = APIRouter(tags=["Health"])


@router.get("/health", summary="Liveness probe")
async def health():
    """
    Returns HTTP 200 immediately.

    WHY: Load balancers (e.g. AWS ALB) ping this every few seconds to decide
    if the instance is alive.  It must be fast — no DB calls, no heavy logic.
    """
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status", summary="Readiness probe (includes DB check)")
async def status(db: AsyncSession = Depends(get_db)):
    """
    Checks that the app can actually reach the database.

    WHY: 'Liveness' tells the scheduler the process is running.
    'Readiness' tells it the process is ready to serve traffic.
    If the DB is unreachable, we want the load balancer to stop routing here.
    """
    try:
        await db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        db_status = f"error: {exc}"

    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
