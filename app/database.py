"""
database.py — Async SQLAlchemy engine + session factory.

CONCEPT — Why async SQLite?
────────────────────────────
FastAPI runs on an async event loop (uvicorn → asyncio). If we used the
standard synchronous SQLAlchemy driver, every DB write would BLOCK the event
loop, making the server unresponsive to new requests during that time.

aiosqlite wraps SQLite's blocking I/O in a thread pool so the event loop stays
free — exactly the same reason we chose FastAPI over Flask.

We don't create tables here.  That happens inside main.py's lifespan so it
runs exactly once when the server starts, after the engine is ready.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# ── Engine ───────────────────────────────────────────────────────────────────
# check_same_thread=False is required for SQLite when used with async because
# SQLAlchemy may hand the connection to a different thread inside aiosqlite.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,          # Logs every SQL statement in dev mode
    connect_args={"check_same_thread": False},
)

# ── Session factory ───────────────────────────────────────────────────────────
# expire_on_commit=False prevents SQLAlchemy from expiring ORM objects after
# commit, which would trigger an extra SELECT when you access attributes later.
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── ORM Base ──────────────────────────────────────────────────────────────────
# All ORM model classes (defined in Phase 3) will inherit from Base.
# DeclarativeBase is the modern SQLAlchemy 2.x style.
class Base(DeclarativeBase):
    pass


# ── Dependency helper ─────────────────────────────────────────────────────────
async def get_db() -> AsyncSession:
    """
    FastAPI dependency that yields a DB session and guarantees it is closed
    even if the request handler raises an exception.

    Usage in a route:
        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        yield session
