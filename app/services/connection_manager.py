"""
services/connection_manager.py — WebSocket connection pool & broadcaster.

CONCEPT — The Fan-Out Broadcast Pattern
─────────────────────────────────────────
When a new honeypot event arrives, we need to push it to ALL currently
connected dashboard tabs simultaneously.  This is called "fan-out":

  New Event
      │
      ├──► WebSocket client 1 (Tab on laptop)
      ├──► WebSocket client 2 (Tab on phone)
      └──► WebSocket client 3 (Another user)

The ConnectionManager maintains a set of active WebSocket connections and
broadcasts to all of them when called.

CONCEPT — Why a Set, Not a List?
──────────────────────────────────
• set.discard(ws) is O(1) vs list.remove(ws) which is O(n).
• Sets prevent duplicate registrations if a client somehow connects twice.
• Python WebSocket objects are hashable (they use the default object identity
  hash), so they can be stored in a set.

CONCEPT — Safe Iteration During Mutation
─────────────────────────────────────────
We iterate over `set(self.active_connections)` (a copy) so we can safely
call `self.active_connections.discard(ws)` inside the loop without raising
"Set changed size during iteration".

CONCEPT — asyncio.gather vs Sequential Sends
──────────────────────────────────────────────
If we have 50 connected clients and send sequentially (await ws.send() in a
loop), client 50 waits for clients 1–49 to complete.  With asyncio.gather,
ALL sends are scheduled concurrently — each one is an I/O coroutine that
yields to the event loop while waiting for the TCP buffer.  This means the
broadcast time is dominated by the SLOWEST client, not the SUM of all clients.

We use return_exceptions=True so a failed send to one client doesn't prevent
the others from receiving the message.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("honeypot.ws")


class ConnectionManager:
    """
    Thread-safe (within a single asyncio event loop) WebSocket connection pool.

    Lifecycle:
        1. Client opens WS connection → connect() adds it to the pool.
        2. Event arrives → broadcast() fans out to all clients in parallel.
        3. Client disconnects → disconnect() removes it from the pool.
        4. Stale clients (sends fail) → auto-removed during broadcast.
    """

    def __init__(self) -> None:
        # Set gives O(1) add/discard and prevents duplicates.
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept the WebSocket handshake and register the client."""
        await websocket.accept()
        self.active_connections.add(websocket)
        count = len(self.active_connections)
        logger.info("🔌 WebSocket connected. Active clients: %d", count)

        # Send a welcome/sync message so the client knows it's live.
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to Honeypot live feed",
            "active_clients": count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove the client from the pool (called after disconnect)."""
        self.active_connections.discard(websocket)
        logger.info(
            "🔌 WebSocket disconnected. Active clients: %d",
            len(self.active_connections),
        )

    async def broadcast(self, data: dict) -> int:
        """
        Push a JSON payload to every connected client concurrently.

        Returns the number of clients that received the message.
        Stale connections (that fail to send) are silently removed.
        """
        if not self.active_connections:
            return 0

        payload = {**data, "type": "event"}

        # Snapshot the set before iteration to allow safe mutation.
        targets = list(self.active_connections)

        async def _send(ws: WebSocket) -> bool:
            try:
                await ws.send_json(payload)
                return True
            except Exception as exc:
                logger.debug("Send failed for client (removing): %s", exc)
                self.active_connections.discard(ws)
                return False

        # Fire all sends concurrently; collect results.
        results = await asyncio.gather(*[_send(ws) for ws in targets], return_exceptions=False)
        success_count = sum(1 for ok in results if ok)

        logger.debug(
            "📡 Broadcast sent to %d/%d clients | path=%s level=%s",
            success_count,
            len(targets),
            data.get("path", "?"),
            data.get("threat_level", "?"),
        )
        return success_count

    async def send_ping(self) -> None:
        """
        Send a keepalive ping to all clients.

        NAT gateways and load balancers silently drop idle TCP connections
        after ~60–90 seconds.  Sending a small ping every 30 seconds keeps
        the connection alive.  The client-side JS simply ignores ping messages.
        """
        if not self.active_connections:
            return

        ping_payload = {
            "type": "ping",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        targets = list(self.active_connections)
        await asyncio.gather(
            *[_safe_send(ws, ping_payload) for ws in targets],
            return_exceptions=True,
        )

    @property
    def client_count(self) -> int:
        return len(self.active_connections)


async def _safe_send(ws: WebSocket, data: dict) -> None:
    """Send JSON to a single WebSocket, silently swallowing errors."""
    try:
        await ws.send_json(data)
    except Exception:
        pass


# ── Module-level singleton ────────────────────────────────────────────────────
# Imported by ws.py (to register clients) and event_store.py (to broadcast).
# One instance = one shared connection pool across the entire server process.
manager = ConnectionManager()
