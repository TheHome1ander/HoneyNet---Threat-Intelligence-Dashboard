"""
main.py — FastAPI application entry point.

CONCEPT — Lifespan (the modern startup/shutdown hook)
───────────────────────────────────────────────────────
Older FastAPI versions used @app.on_event("startup").  That's deprecated.
The modern approach is a single async context manager decorated with
@asynccontextmanager.  Code before `yield` runs at startup; code after runs
at shutdown.

Why does this matter for us?
  • We create all DB tables at startup (so Phase 3 models are auto-provisioned).
  • In Phase 4 we'll also initialise the WebSocket ConnectionManager here.
  • At shutdown we cleanly dispose the engine connection pool — no dangling
    SQLite file locks.
"""

from contextlib import asynccontextmanager

import asyncio
import logging

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import Base, engine
from app.engine.behavioral import behavioral_engine
from app.middleware.interceptor import InterceptorMiddleware
from app.models import event as _event_models  # noqa: F401 — registers HoneypotEvent with Base
from app.routers import health, honeypot, events, ws
from app.services import geoip
from app.services.event_store import handle_event, register_handler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup → yield → shutdown."""

    # ── STARTUP ──────────────────────────────────────────────────────────────
    print("🍯  Honeypot starting up …")

    # Create all tables declared with Base (Phase 3 models will be auto-picked
    # up here once imported above).
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("✅  Database tables ensured.")
    print(f"🌐  Running in [{settings.APP_ENV.upper()}] mode.")

    # ── Register Phase 3 event pipeline ──────────────────────────────────────
    # handle_event: GeoIP lookup → DB write (→ Phase 4: WebSocket broadcast)
    register_handler(handle_event)
    print("✅  Event pipeline registered (GeoIP + DB persistence).")

    # ── Load ML Model ────────────────────────────────────────────────────────
    import os
    model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ml_model.joblib")
    if os.path.exists(model_path):
        try:
            import joblib
            app.state.ml_model = joblib.load(model_path)
            print("🤖  ML Model loaded successfully.")
        except ImportError:
            print("⚠️  joblib/scikit-learn not installed. ML Inference is disabled.")
            app.state.ml_model = None
        except Exception as e:
            print(f"⚠️  Failed to load ML Model: {e}")
            app.state.ml_model = None
    else:
        print("⚠️  No ML Model found. Inference is disabled.")
        app.state.ml_model = None

    # ── Background task: periodically purge stale behavioral engine entries ──
    # CONCEPT: Without cleanup, the in-memory dict grows forever (one entry per
    # unique IP seen since server start).  This task removes IPs that haven't
    # sent a request in the last window, keeping memory bounded.
    async def _purge_loop():
        while True:
            await asyncio.sleep(60)  # Run every 60 seconds
            removed = behavioral_engine.purge_stale()
            if removed:
                print(f"🧹  Purged {removed} stale IP(s) from behavioral engine.")

    purge_task = asyncio.create_task(_purge_loop())

    yield  # ← Server is live and handling requests between here and shutdown

    # ── SHUTDOWN ─────────────────────────────────────────────────────────────
    print("🛑  Honeypot shutting down …")
    purge_task.cancel()
    await geoip.close_http_client()   # Drain the httpx connection pool
    await engine.dispose()            # Cleanly close all DB connections
    print("✅  Database engine disposed.")


# ── Application factory ───────────────────────────────────────────────────────
app = FastAPI(
    title="API Honeypot & Threat Intelligence Dashboard",
    description=(
        "A deceptive API server that logs, enriches, and streams attacker "
        "activity in real time."
    ),
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,   # Hide Swagger in prod
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────────────────────────
# CONCEPT: CORS (Cross-Origin Resource Sharing) headers tell browsers whether
# a page at origin A is allowed to make requests to origin B.
# In development we allow everything so the dashboard can talk to the API.
# In production (Phase 5) we'll lock this to the EC2 domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Middleware ────────────────────────────────────────────────────────────────
# IMPORTANT: Middleware is applied in REVERSE order of registration.
# The last middleware added is the first to process the request.
# We add InterceptorMiddleware AFTER CORSMiddleware so CORS headers are
# already set by the time we log the event.
app.add_middleware(InterceptorMiddleware)

# ── Static files & dashboard ─────────────────────────────────────────────────
# The dashboard HTML/CSS/JS lives in static/.  We mount the whole directory
# under /static so the browser can load assets, then serve index.html at /.
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the threat intelligence dashboard."""
    return FileResponse("static/index.html")


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(honeypot.router)   # Phase 2: deceptive endpoints
app.include_router(events.router)     # Phase 3: history + stats REST API
app.include_router(ws.router)         # Phase 4: WebSocket live feed


# ── Dev runner ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.DEBUG,   # Hot-reload on file changes in dev mode
        log_level="info",
    )
