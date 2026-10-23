"""Focused tests for database engine, session management, and SQLite safety PRAGMAs.

Covers T-MIG-4 and engine lifecycle requirements from specs/PHASE_7_TEST_PLAN.md.
"""

import os
import tempfile
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import (
    _ensure_sqlite_directory,
    create_async_db_engine,
    dispose_engine,
    get_async_session,
    get_engine,
    get_session_factory,
)


@pytest.mark.asyncio
async def test_sqlite_pragmas_enforced_on_connection():
    """Verify that foreign_keys, journal_mode, synchronous, and busy_timeout PRAGMAs are enforced."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "pragma_test.db")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        engine = create_async_db_engine(database_url=db_url)
        try:
            async with engine.connect() as conn:
                fk_res = await conn.execute(text("PRAGMA foreign_keys;"))
                assert fk_res.scalar() == 1, "Foreign keys must be enabled (PRAGMA foreign_keys = 1)"

                journal_res = await conn.execute(text("PRAGMA journal_mode;"))
                assert journal_res.scalar().lower() == "wal", "Journal mode must be WAL (PRAGMA journal_mode = wal)"

                sync_res = await conn.execute(text("PRAGMA synchronous;"))
                assert sync_res.scalar() == 1, "Synchronous mode must be NORMAL (PRAGMA synchronous = 1)"

                timeout_res = await conn.execute(text("PRAGMA busy_timeout;"))
                assert timeout_res.scalar() == 5000, "Busy timeout must be 5000ms (PRAGMA busy_timeout = 5000)"
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_ensure_sqlite_directory_creates_dir():
    """Verify that parent directories for SQLite databases are safely created."""
    with tempfile.TemporaryDirectory() as tmpdir:
        nested_dir = os.path.join(tmpdir, "nested", "data")
        db_path = os.path.join(nested_dir, "test.db")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        assert not os.path.exists(nested_dir)
        _ensure_sqlite_directory(db_url)
        assert os.path.exists(nested_dir), "Parent directory must be created if missing"


@pytest.mark.asyncio
async def test_session_lifecycle_commit_and_rollback():
    """Verify session creation, transaction execution, and rollback semantics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "session_test.db")
        db_url = f"sqlite+aiosqlite:///{db_path}"

        engine = create_async_db_engine(database_url=db_url)
        try:
            async with engine.begin() as conn:
                await conn.execute(text("CREATE TABLE test_items (id INTEGER PRIMARY KEY, name TEXT);"))

            # Test successful commit
            async with AsyncSession(engine) as session:
                await session.execute(text("INSERT INTO test_items (id, name) VALUES (1, 'item1');"))
                await session.commit()

            # Verify persisted
            async with AsyncSession(engine) as session:
                res = await session.execute(text("SELECT name FROM test_items WHERE id = 1;"))
                assert res.scalar() == "item1"

            # Test rollback
            async with AsyncSession(engine) as session:
                await session.execute(text("INSERT INTO test_items (id, name) VALUES (2, 'item2');"))
                await session.rollback()

            # Verify rollback worked
            async with AsyncSession(engine) as session:
                res = await session.execute(text("SELECT name FROM test_items WHERE id = 2;"))
                assert res.scalar() is None
        finally:
            await engine.dispose()


@pytest.mark.asyncio
async def test_engine_dispose_cleans_up():
    """Verify engine disposal clears global singleton references cleanly."""
    engine = get_engine()
    assert engine is not None

    factory = get_session_factory()
    assert factory is not None

    await dispose_engine()

    from app.db import session as db_session
    assert db_session._engine is None
    assert db_session._session_factory is None
