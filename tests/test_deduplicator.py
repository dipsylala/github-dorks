"""Tests for FindingDAO.delete_duplicates() — the deduplication logic."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline.config import DatabaseConfig
from pipeline.db.connection import DatabasePool
from pipeline.db.repositories.finding_dao import FindingDAO

_SCHEMA = (
    Path(__file__).parent.parent / "src" / "pipeline" / "db" / "schema.sql"
).read_text()


@pytest.fixture()
async def db(tmp_path):
    """Async in-memory (temp-file) DatabasePool with schema applied."""
    cfg = DatabaseConfig(path=str(tmp_path / "test.db"))
    pool = DatabasePool(cfg)
    await pool.connect()
    await pool.run_script(_SCHEMA)
    yield pool
    await pool.close()


async def _seed_repo(db: DatabasePool, repo_id: str = "repo1") -> None:
    await db.execute(
        """
        INSERT OR IGNORE INTO repositories
            (id, name, url, stars, language, last_push, size_mb)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        repo_id,
        "myapp",
        f"https://github.com/owner/{repo_id}",
        500,
        "java",
        "2024-01-01T00:00:00Z",
        50,
    )


async def _seed_pattern(
    db: DatabasePool, pattern_id: str, score: int = 5
) -> None:
    await db.execute(
        """
        INSERT OR IGNORE INTO patterns
            (id, name, regex, vulnerability_type, severity_score, language)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        pattern_id,
        f"Pattern {pattern_id}",
        r"exec\(",
        "command_injection",
        score,
        "java",
    )


async def _insert_finding(
    db: DatabasePool,
    *,
    finding_id: str,
    repo_id: str = "repo1",
    file_path: str = "src/Foo.java",
    line_number: int = 10,
    pattern_id: str = "pat1",
    score: int = 5,
) -> None:
    await db.execute(
        """
        INSERT INTO findings
            (id, repository_id, file_path, line_number,
             pattern_id, vulnerability_type, snippet, score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        finding_id,
        repo_id,
        file_path,
        line_number,
        pattern_id,
        "command_injection",
        "exec(userInput)",
        score,
    )


class TestDeleteDuplicates:
    async def test_no_duplicates_returns_zero_deleted(self, db):
        await _seed_repo(db)
        await _seed_pattern(db, "pat1")
        await _insert_finding(db, finding_id="f1", pattern_id="pat1", score=5)
        await _insert_finding(db, finding_id="f2", pattern_id="pat1", line_number=20, score=5)

        deleted = await FindingDAO(db).delete_duplicates()

        assert deleted == 0

    async def test_duplicate_lower_score_deleted(self, db):
        await _seed_repo(db)
        await _seed_pattern(db, "pat1", score=8)
        await _seed_pattern(db, "pat2", score=5)
        # Two findings at same (repo, file, line) — f1 has higher score
        await _insert_finding(db, finding_id="f1", pattern_id="pat1", score=8)
        await _insert_finding(db, finding_id="f2", pattern_id="pat2", score=5)

        deleted = await FindingDAO(db).delete_duplicates()

        assert deleted == 1
        remaining = await db.fetch("SELECT id FROM findings")
        assert [r["id"] for r in remaining] == ["f1"]

    async def test_duplicate_pattern_ids_aggregated_on_winner(self, db):
        await _seed_repo(db)
        await _seed_pattern(db, "pat1", score=8)
        await _seed_pattern(db, "pat2", score=5)
        await _insert_finding(db, finding_id="f1", pattern_id="pat1", score=8)
        await _insert_finding(db, finding_id="f2", pattern_id="pat2", score=5)

        await FindingDAO(db).delete_duplicates()

        row = await db.fetchrow("SELECT matched_pattern_ids FROM findings WHERE id = 'f1'")
        assert row is not None
        pids = json.loads(row["matched_pattern_ids"])
        assert set(pids) == {"pat1", "pat2"}

    async def test_tie_broken_by_lowest_id(self, db):
        await _seed_repo(db)
        await _seed_pattern(db, "pat1")
        await _seed_pattern(db, "pat2")
        # Same score — "a-winner" < "z-loser" lexicographically → a-winner kept
        await _insert_finding(db, finding_id="a-winner", pattern_id="pat1", score=5)
        await _insert_finding(db, finding_id="z-loser", pattern_id="pat2", score=5)

        deleted = await FindingDAO(db).delete_duplicates()

        assert deleted == 1
        remaining = await db.fetch("SELECT id FROM findings")
        assert [r["id"] for r in remaining] == ["a-winner"]

    async def test_unique_locations_all_kept(self, db):
        await _seed_repo(db)
        await _seed_pattern(db, "pat1")
        # Three different files — all unique, none should be removed
        for i in range(3):
            await _insert_finding(
                db,
                finding_id=f"f{i}",
                pattern_id="pat1",
                file_path=f"src/File{i}.java",
                score=5,
            )

        deleted = await FindingDAO(db).delete_duplicates()

        assert deleted == 0
        count = await db.fetchval("SELECT COUNT(*) FROM findings")
        assert count == 3

    async def test_language_filter_only_deduplicates_matching_repos(self, db):
        # Two repos with the same (file, line) — only the java repo's duplicate
        # should be affected when language="java".
        await _seed_repo(db, repo_id="java-repo")
        await db.execute(
            """
            INSERT INTO repositories
                (id, name, url, stars, language, last_push, size_mb)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            "python-repo", "other", "https://github.com/owner/other",
            100, "python", "2024-01-01T00:00:00Z", 10,
        )
        await _seed_pattern(db, "pat1")
        await _seed_pattern(db, "pat2")

        # Two duplicate findings in the java repo
        await _insert_finding(db, finding_id="j1", repo_id="java-repo", pattern_id="pat1", score=8)
        await _insert_finding(db, finding_id="j2", repo_id="java-repo", pattern_id="pat2", score=5)
        # One finding in the python repo (no duplicate)
        await db.execute(
            """
            INSERT INTO findings
                (id, repository_id, file_path, line_number,
                 pattern_id, vulnerability_type, snippet, score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            "p1", "python-repo", "src/Foo.java", 10,
            "pat1", "command_injection", "code", 5,
        )

        deleted = await FindingDAO(db).delete_duplicates(language="java")

        assert deleted == 1
        ids = {r["id"] for r in await db.fetch("SELECT id FROM findings")}
        assert "j1" in ids  # winner kept
        assert "j2" not in ids  # duplicate removed
        assert "p1" in ids  # unrelated repo untouched
