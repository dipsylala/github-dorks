"""SQLite connection backed by aiosqlite."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Any

import aiosqlite

from pipeline.config import DatabaseConfig

logger = logging.getLogger(__name__)

# aiosqlite returns sqlite3.Row objects; expose the same type for callers.
Row = sqlite3.Row


class DatabasePool:
    """
    Thin async wrapper around an aiosqlite connection.

    aiosqlite does not support a connection pool (SQLite uses a single file),
    so a single persistent connection is reused for the lifetime of the stage.
    WAL mode is enabled on connect so concurrent readers don't block writers.
    """

    def __init__(self, config: DatabaseConfig) -> None:
        self._path = Path(config.path)
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Open the database file, creating it if it does not exist."""
        logger.info("Opening SQLite database: %s", self._path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        # Enable WAL for better concurrent read performance.
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        logger.info("SQLite connection established.")

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            await self._conn.close()
            logger.info("SQLite connection closed.")

    async def execute(self, query: str, *args: Any) -> None:
        """Execute a write statement and commit."""
        assert self._conn is not None, "Not connected — call connect() first"
        await self._conn.execute(query, args)
        await self._conn.commit()

    async def executemany(self, query: str, params: list[Any]) -> None:
        """Execute a write statement for each row in *params* and commit."""
        assert self._conn is not None, "Not connected — call connect() first"
        await self._conn.executemany(query, params)
        await self._conn.commit()

    async def fetch(self, query: str, *args: Any) -> list[sqlite3.Row]:
        """Execute a read query and return all matching rows."""
        assert self._conn is not None, "Not connected — call connect() first"
        async with self._conn.execute(query, args) as cursor:
            return await cursor.fetchall()

    async def fetchrow(self, query: str, *args: Any) -> sqlite3.Row | None:
        """Execute a read query and return at most one row."""
        assert self._conn is not None, "Not connected — call connect() first"
        async with self._conn.execute(query, args) as cursor:
            return await cursor.fetchone()

    async def fetchval(self, query: str, *args: Any) -> Any:
        """Execute a read query and return a single scalar value."""
        row = await self.fetchrow(query, *args)
        return row[0] if row is not None else None

    async def run_script(self, sql: str) -> None:
        """Execute a multi-statement SQL script (e.g. schema bootstrap)."""
        assert self._conn is not None, "Not connected — call connect() first"
        await self._conn.executescript(sql)

    # ------------------------------------------------------------------ #
    # Context manager support
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> "DatabasePool":
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()
