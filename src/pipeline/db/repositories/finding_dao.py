"""Data-access object for the ``findings`` table."""

from __future__ import annotations

import json
import logging
import sqlite3

from pipeline.db.connection import DatabasePool
from pipeline.models.finding import Finding

logger = logging.getLogger(__name__)


def _build_github_url(
    repo_url: str | None,
    file_path: str,
    line_number: int,
    local_path: str | None = None,
) -> str | None:
    """Return a GitHub blob URL for *file_path* at *line_number*, or None.

    Handles both new-style relative POSIX paths (e.g. ``src/app/foo.py``) and
    legacy absolute paths (e.g. ``e:\\temp\\146633589\\src\\app\\foo.py``).
    When *local_path* is supplied (the clone root, e.g. ``e:\\temp\\146633589``)
    it is stripped as a prefix, which is the most reliable approach.
    """
    if not repo_url or not file_path:
        return None
    from pathlib import Path, PurePosixPath

    def _strip_absolute(p: Path) -> str:
        """Convert an absolute path to a relative POSIX string, stripping any drive letter."""
        posix = p.as_posix()
        # Strip Windows drive letter, e.g. "e:/temp/..." → "temp/..."
        if len(posix) >= 2 and posix[1] == ":":
            return posix[2:].lstrip("/")
        return posix.lstrip("/")

    p = Path(file_path)
    if p.is_absolute():
        if local_path:
            try:
                relative = PurePosixPath(p.relative_to(local_path)).as_posix()
            except ValueError:
                relative = _strip_absolute(p)
        else:
            relative = _strip_absolute(p)
    else:
        relative = PurePosixPath(file_path).as_posix().lstrip("/")
    return f"{repo_url}/blob/HEAD/{relative}#L{line_number}"


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
        """Update the enriched snippet for *finding_id* and mark enrichment complete."""
        await self._db.execute(
            "UPDATE findings SET snippet = ?, enriched = 1 WHERE id = ?",
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

    async def list_unenriched(self, limit: int = 5000, language: str | None = None) -> list[Finding]:
        """Return findings that have not yet been through the enricher."""
        if language:
            rows = await self._db.fetch(
                """
                SELECT f.* FROM findings f
                JOIN repositories r ON r.id = f.repository_id
                WHERE f.enriched = 0 AND r.language = ?
                LIMIT ?
                """,
                language, limit,
            )
        else:
            rows = await self._db.fetch(
                "SELECT * FROM findings WHERE enriched = 0 LIMIT ?", limit
            )
        return [_row_to_finding(r) for r in rows]

    async def list_unscored(self, limit: int = 5000, language: str | None = None) -> list[Finding]:
        """Return findings that have not yet been through the result-scorer."""
        if language:
            rows = await self._db.fetch(
                """
                SELECT f.* FROM findings f
                JOIN repositories r ON r.id = f.repository_id
                WHERE f.finding_scored = 0 AND r.language = ?
                LIMIT ?
                """,
                language, limit,
            )
        else:
            rows = await self._db.fetch(
                "SELECT * FROM findings WHERE finding_scored = 0 LIMIT ?", limit
            )
        return [_row_to_finding(r) for r in rows]

    async def count_unscored(self, language: str | None = None) -> int:
        """Return the number of findings not yet through the result-scorer."""
        if language:
            val = await self._db.fetchval(
                """
                SELECT COUNT(*) FROM findings f
                JOIN repositories r ON r.id = f.repository_id
                WHERE f.finding_scored = 0 AND r.language = ?
                """,
                language,
            )
        else:
            val = await self._db.fetchval(
                "SELECT COUNT(*) FROM findings WHERE finding_scored = 0"
            )
        return int(val or 0)

    async def score_all(self, language: str | None = None) -> None:
        """Score all unscored findings in a single SQL UPDATE.

        Replicates the logic in ResultScorer.compute_score() inside the
        database engine, eliminating Python round-trips for each row.
        NOTE: keep this expression in sync with ResultScorer._VULN_BASE_SCORES
        and ResultScorer._PATH_BOOSTS if either changes.
        """
        score_expr = """
            CASE vulnerability_type
                WHEN 'command_injection' THEN 10
                WHEN 'deserialization'   THEN 9
                WHEN 'file_inclusion'    THEN 8
                WHEN 'path_traversal'    THEN 8
                WHEN 'sql_injection'     THEN 7
                WHEN 'ssrf'              THEN 6
                WHEN 'xss'              THEN 3
                ELSE 0
            END
            + CASE WHEN file_path LIKE '%controllers/%' THEN 3 ELSE 0 END
            + CASE WHEN file_path LIKE '%routes/%'      THEN 3 ELSE 0 END
            + COALESCE(
                (SELECT r.score / 10 FROM repositories r WHERE r.id = findings.repository_id),
                0
              )
        """
        if language:
            await self._db.execute(
                f"""
                UPDATE findings
                SET score = ({score_expr}), finding_scored = 1
                WHERE finding_scored = 0
                  AND repository_id IN (SELECT id FROM repositories WHERE language = ?)
                """,
                language,
            )
        else:
            await self._db.execute(
                f"UPDATE findings SET score = ({score_expr}), finding_scored = 1 WHERE finding_scored = 0"
            )

    async def list_top(self, limit: int = 1000, language: str | None = None) -> list[Finding]:
        """Return the highest-scored findings via the review_queue view."""
        if language:
            rows = await self._db.fetch(
                """
                SELECT rq.*, lr.local_path
                FROM review_queue rq
                LEFT JOIN local_repositories lr ON lr.repository_id = rq.repository_id
                WHERE rq.repository_id IN (SELECT id FROM repositories WHERE language = ?)
                LIMIT ?
                """,
                language, limit,
            )
        else:
            rows = await self._db.fetch(
                """
                SELECT rq.*, lr.local_path
                FROM review_queue rq
                LEFT JOIN local_repositories lr ON lr.repository_id = rq.repository_id
                LIMIT ?
                """,
                limit,
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
                    github_url=_build_github_url(
                        r["repository_url"], r["file_path"], r["line_number"],
                        local_path=r["local_path"],
                    ),
                    repository_name=r["repository_name"],
                    repository_url=r["repository_url"],
                    framework=r["framework"],
                )
            )
        return results

    async def delete_duplicates(self, language: str | None = None) -> int:
        """
        Remove duplicate findings (same repository_id + file_path + line_number).

        For each group of duplicates, first aggregates all matched pattern IDs
        into the winning row's ``matched_pattern_ids`` field (JSON array), then
        deletes all non-winners.  The winner is the row with the highest score;
        ties are broken deterministically by keeping the lowest ``id``.
        When *language* is given, only findings from repos of that language
        are processed.

        Returns the number of rows deleted.
        """
        # Build reusable SQL fragments; user value always bound via ? parameter.
        lang_where = (
            "WHERE repository_id IN (SELECT id FROM repositories WHERE language = ?)"
            if language else ""
        )
        lang_and = (
            "AND repository_id IN (SELECT id FROM repositories WHERE language = ?)"
            if language else ""
        )
        lp = (language,) if language else ()  # language param tuple

        before = await self._db.fetchval(
            f"SELECT COUNT(*) FROM findings {lang_where}", *lp
        )

        # Step 1 — aggregate all pattern IDs for duplicate locations into the winner.
        # Uses GROUP_CONCAT (available since SQLite 3.0) for broad compatibility.
        rows = await self._db.fetch(
            f"""
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
            {lang_where}
            GROUP BY repository_id, file_path, line_number
            HAVING COUNT(*) > 1
            """,
            *lp,
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
            f"""
            DELETE FROM findings
            WHERE 1=1
              {lang_and}
              AND id NOT IN (
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
                        {lang_where}
                    ) AS grp
                )
            )
            """,
            *lp, *lp,
        )
        after = await self._db.fetchval(
            f"SELECT COUNT(*) FROM findings {lang_where}", *lp
        )
        deleted: int = (before or 0) - (after or 0)
        logger.info("Deduplication removed %d duplicate findings.", deleted)
        return deleted
