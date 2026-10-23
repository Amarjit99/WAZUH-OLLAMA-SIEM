"""Database engine and asynchronous session management.

Configures SQLAlchemy 2.0 async engine, sessionmaker, and connection-level
safety PRAGMAs for SQLite WAL mode.
"""

import logging
import os
import re
from typing import AsyncGenerator, Optional
from urllib.parse import urlparse

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def _ensure_sqlite_directory(database_url: str) -> None:
    """Ensure parent directory exists for file-based SQLite databases."""
    if not database_url.startswith("sqlite"):
        return

    # Extract path portion from sqlite+aiosqlite:///path/to/db.db or sqlite:///...
    clean_url = database_url.split("?")[0]
    match = re.match(r"^sqlite(?:\+[a-z0-9_]+)?:///(.*)$", clean_url)
    if not match:
        return

    db_path = match.group(1)
    if not db_path or db_path == ":memory:":
        return

    # Check for memory in query or URI parameters
    if ":memory:" in database_url:
        return

    abs_dir = os.path.dirname(os.path.abspath(db_path))
    if abs_dir and not os.path.exists(abs_dir):
        os.makedirs(abs_dir, exist_ok=True)
        logger.debug("Created database directory: %s", abs_dir)


def configure_sqlite_pragmas(dbapi_connection, connection_record) -> None:
    """Enforce connection-level SQLite PRAGMAs for foreign keys, WAL, synchronous, and busy timeout."""
    try:
        cursor = dbapi_connection.cursor()
        # 1. Enforce Foreign Key Integrity and Cascades (per connection)
        cursor.execute("PRAGMA foreign_keys = ON;")
        # 2. Enforce Write-Ahead Logging for non-blocking concurrent reads (database scoped)
        cursor.execute("PRAGMA journal_mode = WAL;")
        # 3. Synchronous NORMAL provides safe durability in WAL mode
        cursor.execute("PRAGMA synchronous = NORMAL;")
        # 4. Set busy timeout to 5000ms to allow concurrent write retries
        cursor.execute("PRAGMA busy_timeout = 5000;")
        cursor.close()
    except Exception as e:
        logger.error("Failed to configure SQLite PRAGMAs on connection checkout: %s", e)
        raise


def create_async_db_engine(
    database_url: Optional[str] = None,
    echo: Optional[bool] = None,
) -> AsyncEngine:
    """Create an AsyncEngine configured with safety PRAGMAs for SQLite."""
    settings = get_settings()
    url = database_url or settings.DATABASE_URL
    echo_mode = echo if echo is not None else settings.DATABASE_ECHO

    _ensure_sqlite_directory(url)

    engine = create_async_engine(
        url,
        echo=echo_mode,
        future=True,
    )

    if "sqlite" in url:
        event.listen(engine.sync_engine, "connect", configure_sqlite_pragmas)

    return engine


def get_engine() -> AsyncEngine:
    """Return the application-wide AsyncEngine singleton, initializing if needed."""
    global _engine
    if _engine is None:
        _engine = create_async_db_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the application-wide async sessionmaker singleton."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )
    return _session_factory


async def dispose_engine() -> None:
    """Dispose of the global AsyncEngine and clear session factory."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
    _session_factory = None


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
