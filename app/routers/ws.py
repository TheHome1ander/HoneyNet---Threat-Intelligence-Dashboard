"""
routers/ws.py — WebSocket endpoint for the live event feed.

CONCEPT — WebSocket vs HTTP
─────────────────────────────
HTTP is a request/response protocol — the client asks, the server answers,
the connection closes.  To get updates, the client must keep polling.

WebSocket is a full-duplex protocol that upgrades an HTTP connection into a
persistent bidirectional channel.  The server can PUSH data at any time
without the client asking.  This is ideal for a live threat feed.

WebSocket handshake (simplified):
  Client → GET /ws HTTP/1.1
            Upgrade: websocket
            Connection: Upgrade
            Sec-WebSocket-Key: <base64 nonce>

  Server → HTTP/1.1 101 Switching Protocols
            Upgrade: websocket
            Sec-WebSocket-Accept: <HMAC of nonce>
  
  [Connection is now a persistent TCP channel — no more HTTP overhead]

CONCEPT — The Server Loop Pattern
───────────────────────────────────
After accepting a WebSocket, we must keep the server-side handler coroutine
ALIVE for as long as the client is connected.  If the handler returns, FastAPI
closes the connection.

We do this with a loop that:
  1. Awaits data from the client (or a timeout).
  2. Sends a ping every 30 seconds to keep the connection alive.
  3. Catches WebSocketDisconnect to cleanly remove the client.

The client doesn't need to send anything — we only receive to detect
disconnections.  But we allow clients to send a "ping" message and we'll
respond with "pong" (useful for client-side latency measurement).
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.connection_manager import manager

logger = logging.getLogger("honeypot.ws")

router = APIRouter(tags=["WebSocket"])

# How often to send keepalive pings (seconds)
PING_INTERVAL = 30


@router.websocket("/ws")
async def websocket_live_feed(websocket: WebSocket):
    """
    Persistent WebSocket connection for the real-time threat feed.

    The dashboard connects here once on page load.  From that point on,
    every new honeypot event is pushed automatically without any polling.

    Protocol:
      Server → Client messages are JSON objects with a "type" field:
        {"type": "connected",  "message": "...", "active_clients": N}
        {"type": "event",      "ip": "...", "path": "...", ...}
        {"type": "ping",       "timestamp": "..."}

      Client → Server messages (optional):
        {"type": "ping"}   → server replies with {"type": "pong"}
    """
    await manager.connect(websocket)

    try:
        while True:
            # Wait for a client message OR timeout after PING_INTERVAL seconds.
            # asyncio.wait_for raises asyncio.TimeoutError on timeout — that's
            # our cue to send a keepalive ping.
            try:
                raw = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=PING_INTERVAL,
                )
                # Handle client → server messages
                await _handle_client_message(websocket, raw)

            except asyncio.TimeoutError:
                # No client message in PING_INTERVAL seconds → send ping
                await websocket.send_json({
                    "type": "ping",
                    "active_clients": manager.client_count,
                })

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected cleanly.")

    except Exception as exc:
        logger.warning("WebSocket error: %s", exc)
        manager.disconnect(websocket)


async def _handle_client_message(websocket: WebSocket, raw: str) -> None:
    """
    Process an incoming message from a dashboard client.

    Currently only handles "ping" (keepalive echo) — the dashboard doesn't
    need to send anything else.  Future extensions could allow filtering
    (e.g. "only send me CRITICAL events").
    """
    import json
    try:
        msg = json.loads(raw)
        if msg.get("type") == "ping":
            await websocket.send_json({"type": "pong"})
    except (json.JSONDecodeError, Exception):
        pass  # Ignore malformed client messages
