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
from pipeline.db import DatabasePool, FindingDAO
from pipeline.models import Finding

from .base import BaseStage

logger = logging.getLogger(__name__)

# NOTE: These dicts also define the scoring logic embedded in FindingDAO.score_all().
# Keep both in sync if either changes.
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


class ResultScorer(BaseStage):
    """Scores deduplicated findings and persists the result."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)
        self._finding_dao = FindingDAO(db)

    async def run(self, language: str | None = None) -> None:
        total = await self._finding_dao.count_unscored(language=language)
        self._logger.info("score_findings_start total=%d", total)

        if total == 0:
            self._logger.info("score_findings_complete total=0")
            return

        # Score all findings in a single SQL UPDATE — the formula is evaluated
        # entirely inside SQLite, avoiding per-row Python round-trips.
        await self._finding_dao.score_all(language=language)

        self._logger.info("score_findings_complete total=%d", total)

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
