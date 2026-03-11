"""Data-access object for the ``local_repositories`` table."""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime

from pipeline.db.connection import DatabasePool
from pipeline.models.repository import LocalRepository

logger = logging.getLogger(__name__)


def _row_to_local_repository(row: object) -> LocalRepository:
    assert isinstance(row, sqlite3.Row)
    try:
        ts = datetime.fromisoformat(row["clone_timestamp"])
    except ValueError:
        ts = datetime(1970, 1, 1, tzinfo=UTC)
    return LocalRepository(
        repository_id=row["repository_id"],
        local_path=row["local_path"],
        clone_timestamp=ts,
    )


class LocalRepositoryDAO:
    """CRUD operations for :class:`~pipeline.models.repository.LocalRepository`."""

    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def insert(self, local_repo: LocalRepository) -> None:
        """Persist *local_repo*; silently ignores duplicate repository_id."""
        await self._db.execute(
            """
            INSERT INTO local_repositories (repository_id, local_path, clone_timestamp)
            VALUES (?, ?, ?)
            ON CONFLICT(repository_id) DO NOTHING
            """,
            local_repo.repository_id,
            local_repo.local_path,
            local_repo.clone_timestamp.isoformat(),
        )

    async def get(self, repository_id: str) -> LocalRepository | None:
        """Return the local clone record for *repository_id*, or ``None``."""
        row = await self._db.fetchrow(
            "SELECT * FROM local_repositories WHERE repository_id = ?",
            repository_id,
        )
        return _row_to_local_repository(row) if row else None

    async def exists(self, repository_id: str) -> bool:
        """Return ``True`` if a clone record exists for *repository_id*."""
        val = await self._db.fetchval(
            "SELECT 1 FROM local_repositories WHERE repository_id = ? LIMIT 1",
            repository_id,
        )
        return val is not None

    async def list_all(self) -> list[LocalRepository]:
        """Return all local repository records."""
        rows = await self._db.fetch("SELECT * FROM local_repositories")
        return [_row_to_local_repository(r) for r in rows]

    async def delete(self, repository_id: str) -> None:
        """Remove the clone record for *repository_id* (e.g. after disk cleanup)."""
        await self._db.execute(
            "DELETE FROM local_repositories WHERE repository_id = ?",
            repository_id,
        )
