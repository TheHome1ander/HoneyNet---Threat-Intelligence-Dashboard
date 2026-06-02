"""
interceptor.py — Custom async ASGI middleware.

CONCEPT — How ASGI Middleware Works
─────────────────────────────────────
Every HTTP request in an ASGI app flows through a chain of callables:
  
  Client → Uvicorn → [Middleware A] → [Middleware B] → Router → Route Handler
  
Each middleware is a class with __call__(scope, receive, send):
  • scope   — a dict with request metadata (method, path, headers, client IP)
  • receive — an async callable that yields request body chunks
  • send    — an async callable to push response chunks back to the client

CONCEPT — The Body-Caching Problem
────────────────────────────────────
Reading the request body from `receive` is like reading a generator — you can
only do it ONCE.  If our middleware consumes it, the downstream route handler
gets nothing.

Solution: The "replay" pattern.
  1. We drain `receive` to collect all body chunks.
  2. We store them in a bytes buffer.
  3. We replace `receive` with a NEW async callable that replays the buffer.
  4. We pass this fake `receive` to the downstream app — it never knows we
     already read the body.

This is exactly how production middleware (e.g. Sentry's FastAPI integration)
works.

CONCEPT — Non-blocking Design
───────────────────────────────
The analysis (regex + dict lookup) is fast and CPU-bound — no awaits needed.
In Phase 3, the DB write IS async — we'll schedule it with asyncio.create_task()
so it runs concurrently with sending the response back to the client.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from starlette.types import ASGIApp, Receive, Scope, Send

from app.engine.analyzer import ThreatEvent, analyze

logger = logging.getLogger("honeypot.interceptor")

# ── Config ────────────────────────────────────────────────────────────────────
# Paths that are NOT honeypot routes — don't log these to avoid noise
_PASSTHROUGH_PREFIXES = ("/health", "/status", "/docs", "/redoc", "/openapi", "/api/events", "/static")

# Limit how much body we read (prevents memory exhaustion on large uploads)
MAX_BODY_BYTES = 16_384  # 16 KB


class InterceptorMiddleware:
    """
    ASGI middleware that intercepts every HTTP request to honey-routes,
    analyses it, and dispatches it to all registered async handlers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only intercept HTTP requests (not WebSocket handshakes or lifespan events)
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "/")

        # Skip health probes, API docs, static assets, and the main dashboard
        # route — we don't want to log our own legitimate traffic as threats.
        if path == "/" or any(path.startswith(p) for p in _PASSTHROUGH_PREFIXES):
            await self.app(scope, receive, send)
            return

        # ── Step 1: Drain the receive stream (with body cap) ─────────────────
        body = await self._read_body(receive)

        # ── Step 2: Create a "replay" receive callable ────────────────────────
        # This allows the downstream route handler to read the body normally.
        async def cached_receive() -> dict:
            return {"type": "http.request", "body": body, "more_body": False}

        # ── Step 3: Extract request metadata from scope ───────────────────────
        ip = self._extract_ip(scope)
        method = scope.get("method", "GET")
        query_string = scope.get("query_string", b"").decode("utf-8", errors="replace")
        raw_headers = dict(scope.get("headers", []))

        # Headers in ASGI scope are raw bytes — decode them
        headers = {
            k.decode("utf-8", errors="replace"): v.decode("utf-8", errors="replace")
            for k, v in raw_headers.items()
        }
        user_agent = headers.get("user-agent", "unknown")

        # ── Step 4: Run threat analysis (synchronous, fast) ───────────────────
        event = analyze(
            ip=ip,
            method=method,
            path=path,
            query_string=query_string,
            user_agent=user_agent,
            headers=headers,
            raw_body=body,
        )

        # ── Step 4.5: Run ML Inference (Non-blocking) ─────────────────────────
        # Check if the FastAPI app has the model loaded in state
        fastapi_app = scope.get("app")
        ml_model = getattr(fastapi_app.state, "ml_model", None) if fastapi_app and hasattr(fastapi_app, "state") else None
        
        if ml_model:
            try:
                # Extract live features as a 2D array (skipping pandas to save memory)
                # Feature order: ['path_len', 'query_len', 'body_len', 'ua_len', 'velocity']
                features = [[
                    len(path),
                    len(query_string),
                    len(body),
                    len(user_agent),
                    event.window_count * 6  # Approx requests/min (window is 10s)
                ]]
                
                # predict() is synchronous, so we run it in a thread pool
                prediction = await asyncio.to_thread(ml_model.predict, features)
                
                # IsolationForest returns -1 for outliers/anomalies
                if prediction[0] == -1:
                    event.ml_anomaly = True
                    event.flags.append("ML_ANOMALY")
                    
                    # Heuristically determine why it was flagged based on extremes
                    reasons = []
                    if len(path) > 100: reasons.append("Excessive path length")
                    if len(query_string) > 100: reasons.append("Excessive query length")
                    if len(user_agent) > 200 or len(user_agent) < 10: reasons.append("Highly irregular User-Agent size")
                    if len(body) > 512: reasons.append("Unusually large payload")
                    if event.window_count * 6 > 60: reasons.append("Extreme request velocity")
                    
                    event.ml_reason = ", ".join(reasons) if reasons else "Fell outside standard multidimensional cluster"

                    # Elevate threat level if anomalous
                    if event.threat_level in ["LOW", "MEDIUM"]:
                        event.threat_level = "HIGH"
                    elif event.threat_level == "HIGH":
                        event.threat_level = "CRITICAL"
            except Exception as e:
                logger.error(f"ML Inference failed: {e}")

        # ── Step 5: Log to console ────────────────────────────────────────────
        self._log_event(event)

        # ── Step 6: Fire all registered async handlers ────────────────────────
        # Import here (not at module level) to avoid circular imports.
        # event_store registers itself during main.py lifespan startup.
        from app.services.event_store import get_handlers
        for handler in get_handlers():
            # create_task schedules the coroutine concurrently — the HTTP
            # response is sent back WITHOUT waiting for GeoIP + DB write.
            asyncio.create_task(handler(event))

        # ── Step 7: Pass to the actual route handler with the replayed body ───
        await self.app(scope, cached_receive, send)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _read_body(self, receive: Receive) -> bytes:
        """
        Drain the ASGI receive stream into a bytes buffer.

        The receive channel can deliver the body in multiple chunks (chunked
        transfer-encoding).  We loop until more_body is False.  We also cap
        the total bytes read to prevent a DoS via huge payloads.
        """
        chunks: list[bytes] = []
        total = 0

        while True:
            message = await receive()
            chunk = message.get("body", b"")
            total += len(chunk)
            chunks.append(chunk[:max(0, MAX_BODY_BYTES - (total - len(chunk)))])

            if not message.get("more_body", False) or total >= MAX_BODY_BYTES:
                break

        return b"".join(chunks)

    @staticmethod
    def _extract_ip(scope: Scope) -> str:
        """
        Extract the real client IP from the ASGI scope.

        Behind Nginx (Phase 5), the real IP is in the X-Forwarded-For or X-Real-IP header.
        Directly, it's in scope["client"] as a (host, port) tuple.
        """
        headers = scope.get("headers", [])

        # 1. Try X-Forwarded-For (case-insensitive key check)
        for key, value in headers:
            if key.lower() == b"x-forwarded-for":
                try:
                    decoded = value.decode("utf-8", errors="replace").strip()
                    if decoded:
                        # X-Forwarded-For can be a comma-separated list; take the first (client)
                        return decoded.split(",")[0].strip()
                except Exception:
                    pass

        # 2. Try X-Real-IP (case-insensitive key check)
        for key, value in headers:
            if key.lower() == b"x-real-ip":
                try:
                    decoded = value.decode("utf-8", errors="replace").strip()
                    if decoded:
                        return decoded
                except Exception:
                    pass

        # 3. Fallback to direct socket client
        client = scope.get("client")
        return client[0] if client else "unknown"

    @staticmethod
    def _log_event(event: ThreatEvent) -> None:
        """Pretty-print the event to the console in dev mode."""
        flags_str = ", ".join(event.flags) if event.flags else "none"
        logger.warning(
            "🍯 HIT | %-7s | %-15s | %-30s | level=%-8s | flags=[%s]",
            event.method,
            event.ip,
            event.path,
            event.threat_level,
            flags_str,
        )


# ── Module-level singleton ────────────────────────────────────────────────────
# main.py adds this to the app with app.add_middleware().
# Phase 3 will call interceptor.set_event_handler(db_writer) on startup.
interceptor = InterceptorMiddleware
