"""Stage 4 — Repository scorer.

Assigns an integer priority score to each repository so higher-value
targets are cloned and scanned first.

Scoring rules (additive):
    stars > 500                  +5
    stars > 2000                 +10  (cumulative with above)
    last push < 6 months ago     +4
    framework detected           +8
    controllers/ dir present     +6
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, LocalRepositoryDAO, RepositoryDAO
from pipeline.models import Repository

from .base import BaseStage

logger = logging.getLogger(__name__)

_SIX_MONTHS_SECONDS: float = 60 * 60 * 24 * 30 * 6


class RepoScorer(BaseStage):
    """Scores repositories and writes results back to the database."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)
        self._repo_dao = RepositoryDAO(self._db)

    async def run(self) -> None:
        # Build a local_path map — populated after cloning; empty on first run.
        local_repos = await LocalRepositoryDAO(self._db).list_all()
        local_paths: dict[str, str] = {lr.repository_id: lr.local_path for lr in local_repos}

        batch_size = 5_000
        total = 0

        while True:
            repos = await self._repo_dao.list_unfiltered(limit=batch_size)
            if not repos:
                break

            pairs = [
                (
                    self.compute_score(
                        r,
                        has_controllers_dir=_has_controllers_dir(local_paths.get(r.id)),
                    ),
                    r.id,
                )
                for r in repos
            ]
            await self._repo_dao.update_score_many(pairs)
            total += len(repos)

            if len(repos) < batch_size:
                break

        self._logger.info("score_repos_complete total=%d", total)

    # ------------------------------------------------------------------ #
    # Public helper — usable in tests without a DB
    # ------------------------------------------------------------------ #

    def compute_score(
        self,
        repo: Repository,
        has_controllers_dir: bool = False,
    ) -> int:
        """Compute and return the integer priority score for *repo*."""
        score = 0

        if repo.stars > 500:
            score += 5
        if repo.stars > 2000:
            score += 10

        now = datetime.now(tz=UTC)
        last_push = repo.last_push
        if last_push.tzinfo is None:
            last_push = last_push.replace(tzinfo=UTC)
        age_seconds = (now - last_push).total_seconds()
        if age_seconds < _SIX_MONTHS_SECONDS:
            score += 4

        if repo.framework:   # truthy: real framework name; falsy: None or "" sentinel
            score += 8

        if has_controllers_dir:
            score += 6

        return score


def _has_controllers_dir(local_path: str | None) -> bool:
    """Return True if *local_path* contains a ``controllers`` subdirectory."""
    if not local_path:
        return False
    return Path(local_path, "controllers").is_dir()
