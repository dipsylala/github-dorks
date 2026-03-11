"""Data-access object for the ``findings`` table."""

from __future__ import annotations

import json
import logging
import sqlite3

from pipeline.db.connection import DatabasePool
from pipeline.models.finding import Finding

logger = logging.getLogger(__name__)


def _row_to_finding(row: object) -> Finding:
    assert isinstance(row, sqlite3.Row)
    matched_raw: str = row["matched_pattern_ids"] or "[]"
    try:
        matched: list[str] = json.loads(matched_raw)
    except (json.JSONDecodeError, TypeError):
        matched = []
    return Finding(
        id=row["id"],
        repository_id=row["repository_id"],
        file_path=row["file_path"],
        line_number=row["line_number"],
        pattern_id=row["pattern_id"],
        vulnerability_type=row["vulnerability_type"],
        snippet=row["snippet"],
        matched_pattern_ids=matched,
        score=row["score"],
    )


class FindingDAO:
    """CRUD operations for :class:`~pipeline.models.finding.Finding`.

    Indexes on ``repository_id`` (idx_findings_repository_id) and
    ``score DESC`` (idx_findings_score) are defined in ``schema.sql``.
    """

    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def insert(self, finding: Finding) -> None:
        """Insert *finding*; silently ignores duplicate id."""
        await self._db.execute(
            """
            INSERT INTO findings
                (id, repository_id, file_path, line_number,
                 pattern_id, vulnerability_type, snippet, matched_pattern_ids, score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            finding.id,
            finding.repository_id,
            finding.file_path,
            finding.line_number,
            finding.pattern_id,
            finding.vulnerability_type,
            finding.snippet,
            json.dumps(finding.matched_pattern_ids),
            finding.score,
        )

    async def insert_many(self, findings: list[Finding]) -> None:
        """Bulk-insert a batch of findings in a single transaction."""
        params = [
            (
                f.id, f.repository_id, f.file_path, f.line_number,
                f.pattern_id, f.vulnerability_type, f.snippet,
                json.dumps(f.matched_pattern_ids), f.score,
            )
            for f in findings
        ]
        await self._db.executemany(
            """
            INSERT INTO findings
                (id, repository_id, file_path, line_number,
                 pattern_id, vulnerability_type, snippet, matched_pattern_ids, score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            params,
        )

    async def get(self, finding_id: str) -> Finding | None:
        """Return the finding with *finding_id*, or ``None``."""
        row = await self._db.fetchrow(
            "SELECT * FROM findings WHERE id = ?", finding_id
        )
        return _row_to_finding(row) if row else None

    async def update_snippet(self, finding_id: str, snippet: str) -> None:
        """Update the enriched snippet for *finding_id*."""
        await self._db.execute(
            "UPDATE findings SET snippet = ? WHERE id = ?",
            snippet,
            finding_id,
        )

    async def update_score(self, finding_id: str, score: int) -> None:
        """Update the final score for *finding_id*."""
        await self._db.execute(
            "UPDATE findings SET score = ? WHERE id = ?",
            score,
            finding_id,
        )

    async def update_score_many(self, pairs: list[tuple[int, str]]) -> None:
        """Bulk-update scores in a single transaction.

        *pairs* is a list of ``(score, finding_id)`` tuples, matching the
        ``?`` placeholder order in the UPDATE statement.
        """
        await self._db.executemany(
            "UPDATE findings SET score = ? WHERE id = ?",
            pairs,
        )

    async def list_by_repository(self, repository_id: str) -> list[Finding]:
        """Return all findings for *repository_id*, highest score first."""
        rows = await self._db.fetch(
            """
            SELECT * FROM findings
            WHERE repository_id = ?
            ORDER BY score DESC
            """,
            repository_id,
        )
        return [_row_to_finding(r) for r in rows]

    async def list_unenriched(self, limit: int = 5000) -> list[Finding]:
        """Return findings whose snippet has not been populated yet."""
        rows = await self._db.fetch(
            "SELECT * FROM findings WHERE snippet = '' LIMIT ?", limit
        )
        return [_row_to_finding(r) for r in rows]

    async def list_unscored(self, limit: int = 5000) -> list[Finding]:
        """Return findings whose score has not been calculated yet."""
        rows = await self._db.fetch(
            "SELECT * FROM findings WHERE score = 0 LIMIT ?", limit
        )
        return [_row_to_finding(r) for r in rows]

    async def list_top(self, limit: int = 1000) -> list[Finding]:
        """Return the highest-scored findings via the review_queue view."""
        rows = await self._db.fetch(
            "SELECT * FROM review_queue LIMIT ?", limit
        )
        # review_queue columns are a superset of findings — map only Finding fields.
        results: list[Finding] = []
        for r in rows:
            assert isinstance(r, sqlite3.Row)
            matched_raw: str = r["matched_pattern_ids"] or "[]"
            try:
                matched: list[str] = json.loads(matched_raw)
            except (json.JSONDecodeError, TypeError):
                matched = []
            results.append(
                Finding(
                    id=r["finding_id"],
                    repository_id=r["repository_id"],
                    file_path=r["file_path"],
                    line_number=r["line_number"],
                    pattern_id=r["pattern_id"],
                    vulnerability_type=r["vulnerability_type"],
                    snippet=r["snippet"],
                    matched_pattern_ids=matched,
                    score=r["finding_score"],
                )
            )
        return results

    async def delete_duplicates(self) -> int:
        """
        Remove duplicate findings (same repository_id + file_path + line_number).

        For each group of duplicates, first aggregates all matched pattern IDs
        into the winning row's ``matched_pattern_ids`` field (JSON array), then
        deletes all non-winners.  The winner is the row with the highest score;
        ties are broken deterministically by keeping the lowest ``id``.

        Returns the number of rows deleted.
        """
        before = await self._db.fetchval("SELECT COUNT(*) FROM findings")

        # Step 1 — aggregate all pattern IDs for duplicate locations into the winner.
        # Uses GROUP_CONCAT (available since SQLite 3.0) for broad compatibility.
        rows = await self._db.fetch(
            """
            SELECT
                GROUP_CONCAT(pattern_id, ',') AS all_pattern_ids,
                (
                    SELECT id FROM findings AS f2
                    WHERE f2.repository_id = findings.repository_id
                      AND f2.file_path     = findings.file_path
                      AND f2.line_number   = findings.line_number
                    ORDER BY score DESC, id ASC
                    LIMIT 1
                ) AS winner_id
            FROM findings
            GROUP BY repository_id, file_path, line_number
            HAVING COUNT(*) > 1
            """
        )
        if rows:
            updates: list[tuple[str, str]] = []
            for row in rows:
                assert isinstance(row, sqlite3.Row)
                # Deduplicate pattern IDs preserving order.
                seen: dict[str, None] = {}
                for pid in (row["all_pattern_ids"] or "").split(","):
                    pid = pid.strip()
                    if pid:
                        seen[pid] = None
                updates.append((json.dumps(list(seen)), row["winner_id"]))
            await self._db.executemany(
                "UPDATE findings SET matched_pattern_ids = ? WHERE id = ?",
                updates,
            )

        # Step 2 — delete all non-winners; keep highest score, lowest id on tie.
        await self._db.execute(
            """
            DELETE FROM findings
            WHERE id NOT IN (
                SELECT winner_id FROM (
                    SELECT (
                        SELECT id FROM findings AS f2
                        WHERE f2.repository_id = grp.repository_id
                          AND f2.file_path     = grp.file_path
                          AND f2.line_number   = grp.line_number
                        ORDER BY score DESC, id ASC
                        LIMIT 1
                    ) AS winner_id
                    FROM (
                        SELECT DISTINCT repository_id, file_path, line_number
                        FROM findings
                    ) AS grp
                )
            )
            """
        )
        after = await self._db.fetchval("SELECT COUNT(*) FROM findings")
        deleted: int = (before or 0) - (after or 0)
        logger.info("Deduplication removed %d duplicate findings.", deleted)
        return deleted
