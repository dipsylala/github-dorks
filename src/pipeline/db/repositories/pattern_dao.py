"""Data-access object for the ``patterns`` table."""

from __future__ import annotations

import sqlite3

from pipeline.db.connection import DatabasePool
from pipeline.models.pattern import Pattern


def _row_to_pattern(row: object) -> Pattern:
    assert isinstance(row, sqlite3.Row)
    return Pattern(
        id=row["id"],
        name=row["name"],
        regex=row["regex"],
        vulnerability_type=row["vulnerability_type"],
        severity_score=row["severity_score"],
        language=row["language"],
        cwe=row["cwe"],
        cwe_name=row["cwe_name"],
    )


class PatternDAO:
    """CRUD operations for :class:`~pipeline.models.pattern.Pattern`.

    Patterns are loaded from YAML on startup and upserted into the DB so the
    scanner and enricher stages can look them up by id without touching disk.
    """

    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def upsert(self, pattern: Pattern) -> None:
        """Insert *pattern*, updating all fields on id conflict."""
        await self._db.execute(
            """
            INSERT INTO patterns
                (id, name, regex, vulnerability_type,
                 severity_score, language, cwe, cwe_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name               = excluded.name,
                regex              = excluded.regex,
                vulnerability_type = excluded.vulnerability_type,
                severity_score     = excluded.severity_score,
                language           = excluded.language,
                cwe                = excluded.cwe,
                cwe_name           = excluded.cwe_name
            """,
            pattern.id,
            pattern.name,
            pattern.regex,
            pattern.vulnerability_type,
            pattern.severity_score,
            pattern.language,
            pattern.cwe,
            pattern.cwe_name,
        )

    async def upsert_many(self, patterns: list[Pattern]) -> None:
        """Bulk-upsert a list of patterns in a single transaction."""
        params = [
            (
                p.id, p.name, p.regex, p.vulnerability_type,
                p.severity_score, p.language, p.cwe, p.cwe_name,
            )
            for p in patterns
        ]
        await self._db.executemany(
            """
            INSERT INTO patterns
                (id, name, regex, vulnerability_type,
                 severity_score, language, cwe, cwe_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name               = excluded.name,
                regex              = excluded.regex,
                vulnerability_type = excluded.vulnerability_type,
                severity_score     = excluded.severity_score,
                language           = excluded.language,
                cwe                = excluded.cwe,
                cwe_name           = excluded.cwe_name
            """,
            params,
        )

    async def get(self, pattern_id: str) -> Pattern | None:
        """Return the pattern for *pattern_id*, or ``None``."""
        row = await self._db.fetchrow(
            "SELECT * FROM patterns WHERE id = ?", pattern_id
        )
        return _row_to_pattern(row) if row else None

    async def list_all(self) -> list[Pattern]:
        """Return all patterns ordered by language then severity desc."""
        rows = await self._db.fetch(
            "SELECT * FROM patterns ORDER BY language, severity_score DESC"
        )
        return [_row_to_pattern(r) for r in rows]

    async def list_by_language(self, language: str) -> list[Pattern]:
        """Return patterns for *language*, highest severity first."""
        rows = await self._db.fetch(
            """
            SELECT * FROM patterns
            WHERE language = ?
            ORDER BY severity_score DESC
            """,
            language,
        )
        return [_row_to_pattern(r) for r in rows]

    async def list_by_cwe(self, cwe: str) -> list[Pattern]:
        """Return patterns matching *cwe* (e.g. ``"CWE-78"``)."""
        rows = await self._db.fetch(
            """
            SELECT * FROM patterns
            WHERE cwe = ?
            ORDER BY severity_score DESC
            """,
            cwe,
        )
        return [_row_to_pattern(r) for r in rows]
