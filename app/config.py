"""
config.py — Central configuration module.

Reads all settings from environment variables (populated from .env by
python-dotenv).  Every other module imports from here instead of calling
os.getenv() directly, so there is exactly ONE place to change a setting.
"""

import os
from dotenv import load_dotenv

# Load the .env file into os.environ before we read anything.
# This is a no-op in production if you inject env vars via systemd/Docker.
load_dotenv()


class Settings:
    """
    A plain Python class (not Pydantic) to keep Phase 1 dependency-light.
    We'll keep it simple: read once at import time.
    """

    # ── Server ──────────────────────────────────────────────────────────────
    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))

    # ── Debug flag derived from environment ─────────────────────────────────
    # In development, FastAPI will show full tracebacks in error responses.
    DEBUG: bool = APP_ENV == "development"

    # ── Database ─────────────────────────────────────────────────────────────
    # "sqlite+aiosqlite://" tells SQLAlchemy to use the async aiosqlite driver.
    # The path after "///" is relative to the CWD where uvicorn is started.
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite+aiosqlite:///./honeypot.db"
    )

    # ── GeoIP ────────────────────────────────────────────────────────────────
    GEOIP_API_URL: str = os.getenv("GEOIP_API_URL", "http://ip-api.com/json")


# Export a singleton so every import gets the same object.
settings = Settings()
