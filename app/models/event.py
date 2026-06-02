"""
models/event.py — SQLAlchemy ORM model for a captured honeypot event.

CONCEPT — SQLAlchemy 2.x Declarative Mapping
──────────────────────────────────────────────
SQLAlchemy 2.x introduced a cleaner "mapped_column" syntax with Python type
annotations.  Instead of the old Column(String(…)) style, we use:

    class MyModel(Base):
        __tablename__ = "my_table"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(String(128))

Python type hints (Mapped[int], Mapped[str]) make the ORM understand the types
at runtime AND allow type checkers (mypy/pyright) to validate your queries.

CONCEPT — Schema Design Decisions
───────────────────────────────────
• `flags` is stored as a comma-separated string (e.g. "SQLi,Scanner") rather
  than a JSON array.  SQLite has no native array type, and a simple string is
  easier to query with LIKE for basic filtering.

• `body_preview` is capped at 512 chars before reaching here, preventing the
  DB row from bloating.  We're a honeypot, not a full packet capture system.

• `timestamp` uses server_default=func.now() so the DB itself stamps the time
  even if the application forgets to set it (defense in depth).

• `ip` is String(45) — IPv6 addresses are up to 39 characters; 45 gives us
  comfortable headroom.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class HoneypotEvent(Base):
    """
    One row per request intercepted by the honeypot middleware.

    This model is the single source of truth for the dashboard's history table
    and stats cards.  It merges:
      • Raw request metadata (method, path, IP, user-agent, body preview)
      • Threat engine output (level, flags, is_scanner)
      • GeoIP enrichment (country, city, ISP)
    """

    __tablename__ = "honeypot_events"

    # ── Primary key ───────────────────────────────────────────────────────────
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ── Request metadata ──────────────────────────────────────────────────────
    ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    query_string: Mapped[str] = mapped_column(Text, default="", nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, default="", nullable=False)
    body_preview: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # ── Behavioral analysis ───────────────────────────────────────────────────
    is_scanner: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    window_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # ── Threat verdict ────────────────────────────────────────────────────────
    # threat_level is indexed because the dashboard filters/groups by it often
    threat_level: Mapped[str] = mapped_column(String(10), index=True, nullable=False)

    # Flags stored as comma-separated string: "SQLi,XSS,Scanner"
    flags: Mapped[str] = mapped_column(String(256), default="", nullable=False)

    # ── GeoIP enrichment (populated by Phase 3 service) ──────────────────────
    country: Mapped[str] = mapped_column(String(100), default="Unknown", nullable=False)
    city: Mapped[str] = mapped_column(String(100), default="Unknown", nullable=False)
    isp: Mapped[str] = mapped_column(String(256), default="Unknown", nullable=False)
    country_code: Mapped[str] = mapped_column(String(2), default="XX", nullable=False)

    # ── Timestamp ─────────────────────────────────────────────────────────────
    # server_default uses the DB's NOW() so timestamps are always set,
    # even for direct DB inserts (e.g. test fixtures or manual seeding).
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,   # Dashboard sorts by this frequently
    )

    def to_dict(self) -> dict:
        """Serialise to a JSON-safe dict for REST responses and WS broadcasts."""
        return {
            "id": self.id,
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "user_agent": self.user_agent,
            "body_preview": self.body_preview,
            "is_scanner": self.is_scanner,
            "hit_count": self.hit_count,
            "window_count": self.window_count,
            "threat_level": self.threat_level,
            "flags": self.flags.split(",") if self.flags else [],
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "country_code": self.country_code,
            "timestamp": self.timestamp.replace(tzinfo=timezone.utc).isoformat() if self.timestamp else None,
        }

    def __repr__(self) -> str:
        return (
            f"<HoneypotEvent id={self.id} ip={self.ip!r} "
            f"path={self.path!r} level={self.threat_level!r}>"
        )
