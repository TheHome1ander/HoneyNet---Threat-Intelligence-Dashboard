"""
behavioral.py — In-memory sliding-window scanner detection.

CONCEPT — Sliding Window Rate Limiting
────────────────────────────────────────
A "sliding window" counter tracks how many events (requests) occurred in the
last N seconds for a given key (IP address).  Unlike a "fixed window" (e.g.
"10 requests per minute, reset every minute"), a sliding window never has
boundary spikes — it always looks at the true last-N-seconds.

Implementation:
  • We keep a dict mapping IP → collections.deque of UTC timestamps.
  • On each request, we:
      1. Append the current timestamp to that IP's deque.
      2. Pop any timestamps older than WINDOW_SECONDS from the left.
      3. If len(deque) > THRESHOLD, the IP is a scanner.

Why a deque?  It supports O(1) append on the right and O(1) pop on the left,
making the cleanup step as cheap as possible.

Thread-safety:
  FastAPI runs in a single asyncio event loop (no true parallelism in one
  process), so a plain dict is safe here.  We don't need asyncio.Lock because
  no await happens between the read and write of the dict.
"""

import time
from collections import deque
from dataclasses import dataclass, field


# ── Tuneable constants ────────────────────────────────────────────────────────
WINDOW_SECONDS: int = 10    # Time window to look back
THRESHOLD: int = 5          # Max requests allowed before flagging


@dataclass
class _IPState:
    """Mutable state bucket for a single IP address."""
    timestamps: deque = field(default_factory=deque)
    total_hits: int = 0  # Lifetime hit counter (survives window cleanup)


class BehavioralEngine:
    """
    Singleton-style engine that tracks per-IP request rates.

    Usage:
        engine = BehavioralEngine()
        is_scanner = engine.record_and_check("203.0.113.42")
        hit_count  = engine.hit_count("203.0.113.42")
    """

    def __init__(self) -> None:
        # IP string → _IPState
        self._state: dict[str, _IPState] = {}

    def record_and_check(self, ip: str) -> bool:
        """
        Record a hit for this IP and return True if it exceeds the threshold.

        This method is intentionally synchronous and fast — it only does dict
        lookups, deque appends, and timestamp comparisons.  No I/O, no await.
        """
        now = time.monotonic()

        if ip not in self._state:
            self._state[ip] = _IPState()

        state = self._state[ip]
        state.total_hits += 1
        state.timestamps.append(now)

        # Evict timestamps outside the sliding window
        cutoff = now - WINDOW_SECONDS
        while state.timestamps and state.timestamps[0] < cutoff:
            state.timestamps.popleft()

        return len(state.timestamps) > THRESHOLD

    def hit_count(self, ip: str) -> int:
        """Return the total (lifetime) number of requests from this IP."""
        return self._state.get(ip, _IPState()).total_hits

    def window_count(self, ip: str) -> int:
        """Return the number of requests from this IP within the current window."""
        state = self._state.get(ip)
        if not state:
            return 0
        now = time.monotonic()
        cutoff = now - WINDOW_SECONDS
        return sum(1 for t in state.timestamps if t >= cutoff)

    def purge_stale(self) -> int:
        """
        Remove IPs that have no activity in the last window.

        This keeps memory bounded.  Call this from a periodic background task
        (e.g. every 60 seconds) rather than on every request.

        Returns the number of entries removed.
        """
        now = time.monotonic()
        cutoff = now - WINDOW_SECONDS
        stale = [
            ip for ip, state in self._state.items()
            if not state.timestamps or state.timestamps[-1] < cutoff
        ]
        for ip in stale:
            del self._state[ip]
        return len(stale)


# ── Module-level singleton ────────────────────────────────────────────────────
# Imported by interceptor.py and the analyzer.  One instance = one shared
# state across all requests in this process.
behavioral_engine = BehavioralEngine()
