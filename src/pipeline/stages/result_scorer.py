"""Stage 9 — Finding result scorer.

Calculates the final integer score for each de-duplicated Finding and
persists the result to the database in batches.

Score formula
-------------
    score  = base_vulnerability_score
           + path_boost              (controllers/ or routes/ → +3 each)
           + repo_score // 10        (normalised repository quality signal)

Base vulnerability scores (from SPEC §8.9)
------------------------------------------
    command_injection   10
    deserialization      9
    file_inclusion       8
    path_traversal       8
    sql_injection        7
    ssrf                 6
    xss                  3

Path boosts (+3 each)
---------------------
    file path contains "controllers/"
    file path contains "routes/"
"""

from __future__ import annotations

import logging

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, FindingDAO, RepositoryDAO
from pipeline.models import Finding

from .base import BaseStage

logger = logging.getLogger(__name__)

_VULN_BASE_SCORES: dict[str, int] = {
    "command_injection": 10,
    "deserialization":    9,
    "file_inclusion":     8,
    "path_traversal":     8,
    "sql_injection":      7,
    "ssrf":               6,
    "xss":                3,
}

_PATH_BOOSTS: dict[str, int] = {
    "controllers/": 3,
    "routes/":      3,
}

# Number of score updates sent to the DB in one executemany call.
_BATCH_SIZE = 500


class ResultScorer(BaseStage):
    """Scores deduplicated findings and persists the result."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)
        self._finding_dao = FindingDAO(db)
        self._repo_dao = RepositoryDAO(db)

    async def run(self, language: str | None = None) -> None:
        # Build a full repo_id → repo_score lookup in one DB round-trip.
        all_repos = await self._repo_dao.list_by_score(limit=100_000)
        repo_scores: dict[str, int] = {r.id: r.score for r in all_repos}

        # Process findings in pages to keep memory bounded.
        page_size = 5_000
        offset = 0
        total_scored = 0
        self._logger.info("score_findings_start")

        while True:
            findings = await self._finding_dao.list_unscored(limit=page_size, language=language)
            if not findings:
                break

            pairs: list[tuple[int, str]] = []
            for finding in findings:
                repo_score = repo_scores.get(finding.repository_id, 0)
                score = self.compute_score(finding, repo_score)
                pairs.append((score, finding.id))

            # Flush in batches so WAL write transactions stay small.
            for i in range(0, len(pairs), _BATCH_SIZE):
                await self._finding_dao.update_score_many(pairs[i : i + _BATCH_SIZE])

            total_scored += len(pairs)
            offset += page_size
            self._logger.info("score_findings_progress scored=%d", total_scored)

            # If fewer findings came back than the page size we're done.
            if len(findings) < page_size:
                break

        self._logger.info("score_findings_complete total=%d", total_scored)

    # ------------------------------------------------------------------ #
    # Public helper — usable in tests without a DB
    # ------------------------------------------------------------------ #

    def compute_score(self, finding: Finding, repo_score: int = 0) -> int:
        """Return the final integer score for *finding*.

        Args:
            finding:    The Finding to score.
            repo_score: The parent repository's pre-computed score.
                        Contributes ``repo_score // 10`` to the final value
                        so high-quality repos provide a small signal boost
                        without dominating the vulnerability base score.
        """
        score = _VULN_BASE_SCORES.get(finding.vulnerability_type, 0)
        for path_fragment, boost in _PATH_BOOSTS.items():
            if path_fragment in finding.file_path:
                score += boost
        score += repo_score // 10
        return score
