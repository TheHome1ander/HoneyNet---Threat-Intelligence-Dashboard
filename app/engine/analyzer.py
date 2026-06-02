"""
analyzer.py — Combines signature + behavioral engines into a single analysis.

This module is the "brain" that the middleware calls.  It:
  1. Runs the signature scanner across all inspectable text in the request.
  2. Checks the behavioral engine for scanner-rate behaviour.
  3. Computes a composite threat level: LOW / MEDIUM / HIGH / CRITICAL.
  4. Returns a structured ThreatEvent dataclass.

The middleware (interceptor.py) calls analyze() and receives a ThreatEvent.
In Phase 3, that ThreatEvent will be persisted to SQLite.
In Phase 4, it will also be broadcast over WebSockets.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.engine.behavioral import behavioral_engine
from app.engine.signatures import SignatureMatch, scan


# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    """
    A fully-analyzed snapshot of one honeypot hit.

    Everything the dashboard needs is in this single object — no need to
    re-query multiple sources.
    """
    # Request metadata
    ip: str
    method: str
    path: str
    query_string: str
    user_agent: str
    headers: dict[str, str]
    body_preview: str           # First 512 bytes of body as string

    # Behavioral data
    is_scanner: bool
    hit_count: int              # Lifetime hits from this IP
    window_count: int           # Hits in the last 10 seconds

    # Signature matches
    signature_matches: list[SignatureMatch]

    # Composite verdict
    threat_level: str           # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    flags: list[str]            # Human-readable list, e.g. ["SQLi", "Scanner"]

    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # GeoIP fields (populated in Phase 3)
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    
    # ML Anomaly
    ml_anomaly: bool = False    # Scored by Isolation Forest
    ml_reason: str | None = None # Heuristic explanation for the anomaly

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dict for WebSocket broadcast (Phase 4)."""
        return {
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "user_agent": self.user_agent,
            "body_preview": self.body_preview,
            "is_scanner": self.is_scanner,
            "hit_count": self.hit_count,
            "window_count": self.window_count,
            "ml_anomaly": self.ml_anomaly,
            "ml_reason": self.ml_reason,
            "threat_level": self.threat_level,
            "flags": self.flags,
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Threat level matrix ───────────────────────────────────────────────────────
#
# We derive threat level from two dimensions:
#   • attack_signatures: number of distinct attack categories detected
#   • is_scanner: whether the IP exceeded the rate threshold
#
# Matrix:
#   No sigs + no scanner → LOW
#   No sigs + scanner    → MEDIUM   (automated probe, no known payload)
#   1+ sigs + no scanner → HIGH     (targeted attack, manual or slow)
#   1+ sigs + scanner    → CRITICAL (automated attack tool in full flight)

def _compute_threat_level(sig_count: int, is_scanner: bool) -> str:
    if sig_count == 0 and not is_scanner:
        return "LOW"
    if sig_count == 0 and is_scanner:
        return "MEDIUM"
    if sig_count >= 1 and not is_scanner:
        return "HIGH"
    return "CRITICAL"  # sig_count >= 1 and is_scanner


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(
    *,
    ip: str,
    method: str,
    path: str,
    query_string: str,
    user_agent: str,
    headers: dict[str, str],
    raw_body: bytes,
) -> ThreatEvent:
    """
    Analyse one request and return a ThreatEvent.

    CONCEPT — What we scan:
    We concatenate path + query_string + body into a single "inspection string"
    and run all signatures against it.  This is how real WAFs work too —
    attackers often split payloads across multiple request fields, so you must
    check everything at once.

    The body is decoded as UTF-8 with errors='replace' so malformed bytes
    (common in fuzzing tools) don't crash us.  We also URL-decode the string
    once to catch percent-encoded payloads (%27 → ', common SQLi evasion).
    """

    # ── Build inspection string ───────────────────────────────────────────────
    body_str = raw_body[:4096].decode("utf-8", errors="replace")  # 4 KB cap
    body_preview = body_str[:512]

    # Decode URL encoding once (attackers use %27 for ' to evade naive filters)
    decoded_path = urllib.parse.unquote(path)
    decoded_query = urllib.parse.unquote(query_string)
    decoded_body = urllib.parse.unquote(body_str)

    inspection_text = f"{decoded_path} {decoded_query} {decoded_body} {user_agent}"

    # ── Signature scan ────────────────────────────────────────────────────────
    sig_matches = scan(inspection_text)
    attack_flags = [m.category for m in sig_matches]

    # ── Behavioral check ──────────────────────────────────────────────────────
    is_scanner = behavioral_engine.record_and_check(ip)
    hit_count = behavioral_engine.hit_count(ip)
    window_count = behavioral_engine.window_count(ip)

    # ── Assemble flags list ───────────────────────────────────────────────────
    flags = list(attack_flags)
    if is_scanner:
        flags.append("Scanner")

    # ── Compute threat level ──────────────────────────────────────────────────
    threat_level = _compute_threat_level(len(sig_matches), is_scanner)

    return ThreatEvent(
        ip=ip,
        method=method,
        path=path,
        query_string=query_string,
        user_agent=user_agent,
        headers=headers,
        body_preview=body_preview,
        is_scanner=is_scanner,
        hit_count=hit_count,
        window_count=window_count,
        signature_matches=sig_matches,
        threat_level=threat_level,
        flags=flags,
    )
