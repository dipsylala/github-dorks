"""Data-access object for the ``repositories`` table."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from pipeline.db.connection import DatabasePool
from pipeline.models.repository import Repository

logger = logging.getLogger(__name__)


def _row_to_repository(row: object) -> Repository:
    import sqlite3
    assert isinstance(row, sqlite3.Row)
    last_push_raw: str = row["last_push"]
    try:
        last_push = datetime.fromisoformat(last_push_raw)
    except ValueError:
        last_push = datetime(1970, 1, 1, tzinfo=UTC)
    return Repository(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        stars=row["stars"],
        language=row["language"],
        last_push=last_push,
        size_mb=row["size_mb"],
        archived=bool(row["archived"]),
        framework=row["framework"],
        score=row["score"],
    )


class RepositoryDAO:
    """CRUD operations for :class:`~pipeline.models.repository.Repository`."""

    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def upsert_many(self, repos: list[Repository]) -> None:
        """Bulk upsert a list of repositories in a single transaction.

        On conflict (same id) only mutable discovery fields are updated.
        ``score``, ``framework``, and ``filtered`` are managed by their own
        stages and must not be reset by re-discovery.
        """
        params = [
            (
                r.id, r.name, r.url, r.stars, r.language,
                r.last_push.isoformat(), r.size_mb, int(r.archived),
            )
            for r in repos
        ]
        await self._db.executemany(
            """
            INSERT INTO repositories
                (id, name, url, stars, language, last_push, size_mb, archived)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name      = excluded.name,
                url       = excluded.url,
                stars     = excluded.stars,
                language  = excluded.language,
                last_push = excluded.last_push,
                size_mb   = excluded.size_mb,
                archived  = excluded.archived
            """,
            params,
        )

    async def get(self, repo_id: str) -> Repository | None:
        """Return the repository with *repo_id*, or ``None`` if not found."""
        row = await self._db.fetchrow(
            "SELECT * FROM repositories WHERE id = ?", repo_id
        )
        return _row_to_repository(row) if row else None

    async def update_framework(self, repo_id: str, framework: str | None) -> None:
        """Set the ``framework`` column for *repo_id* and mark detection complete."""
        await self._db.execute(
            "UPDATE repositories SET framework = ?, framework_detected = 1 WHERE id = ?",
            framework,
            repo_id,
        )

    async def update_score(self, repo_id: str, score: int) -> None:
        """Set the ``score`` column for *repo_id*."""
        await self._db.execute(
            "UPDATE repositories SET score = ? WHERE id = ?",
            score,
            repo_id,
        )

    async def list_unfiltered(self, limit: int = 5000) -> list[Repository]:
        """Return repositories that have not yet passed through the filter stage."""
        rows = await self._db.fetch(
            "SELECT * FROM repositories WHERE filtered = 0 LIMIT ?", limit
        )
        return [_row_to_repository(r) for r in rows]

    async def mark_filtered(self, repo_ids: list[str]) -> None:
        """Mark repositories as having passed the filter stage.

        Chunked in groups of 900 to stay within SQLite's variable limit.
        """
        if not repo_ids:
            return
        for i in range(0, len(repo_ids), 900):
            chunk = repo_ids[i : i + 900]
            placeholders = ",".join("?" * len(chunk))
            await self._db.execute(
                f"UPDATE repositories SET filtered = 1 WHERE id IN ({placeholders})",
                *chunk,
            )

    async def list_unscored(self, limit: int = 5000) -> list[Repository]:
        """Return filtered repositories that have not yet been scored."""
        rows = await self._db.fetch(
            "SELECT * FROM repositories WHERE filtered = 1 AND scored = 0 LIMIT ?", limit
        )
        return [_row_to_repository(r) for r in rows]

    async def list_by_score(self) -> list[Repository]:
        """Return all repositories ordered by score descending."""
        rows = await self._db.fetch(
            "SELECT * FROM repositories ORDER BY score DESC"
        )
        return [_row_to_repository(r) for r in rows]

    async def list_without_framework(self, limit: int = 5000) -> list[Repository]:
        """Return filtered repositories where framework detection has not yet run."""
        rows = await self._db.fetch(
            "SELECT * FROM repositories WHERE filtered = 1 AND framework_detected = 0 LIMIT ?", limit
        )
        return [_row_to_repository(r) for r in rows]

    async def delete_many(self, repo_ids: list[str]) -> None:
        """Delete repositories by id in bulk (cascades to findings / local_repos).

        Chunked in groups of 900 to stay within SQLite's variable limit.
        """
        if not repo_ids:
            return
        for i in range(0, len(repo_ids), 900):
            chunk = repo_ids[i : i + 900]
            placeholders = ",".join("?" * len(chunk))
            await self._db.execute(
                f"DELETE FROM repositories WHERE id IN ({placeholders})",
                *chunk,
            )

    async def update_score_many(self, pairs: list[tuple[int, str]]) -> None:
        """Bulk-update scores and mark repos as scored in a single transaction.

        *pairs* is a list of ``(score, repo_id)`` tuples.
        """
        await self._db.executemany(
            "UPDATE repositories SET score = ?, scored = 1 WHERE id = ?",
            pairs,
        )
