"""Stage 2 — Repository filter.

Removes repositories unlikely to contain useful scan targets before
expensive clone/scan operations are started.

Rejection criteria:
    - stars < min_stars
    - size_mb > max_repo_size_mb
    - archived == true
    - name contains a known noise token (tutorial, demo, example, …)
"""

from __future__ import annotations

import logging

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, RepositoryDAO
from pipeline.models import Repository

from .base import BaseStage

logger = logging.getLogger(__name__)

_REJECTED_NAME_TOKENS: frozenset[str] = frozenset({
    "tutorial",
    "example",
    "demo",
    "practice",
    "cheatsheet",
    "awesome-",
})


class RepoFilter(BaseStage):
    """Filters out repositories that are noise or outside scan scope."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)

    async def run(self, language: str | None = None) -> None:
        repo_dao = RepositoryDAO(self._db)
        batch_size = 5_000
        total_kept = total_deleted = 0

        while True:
            repos = await repo_dao.list_unfiltered(limit=batch_size)
            if not repos:
                break

            rejected_ids = [r.id for r in repos if self.should_reject(r)]
            kept_ids = [r.id for r in repos if r.id not in set(rejected_ids)]

            if rejected_ids:
                await repo_dao.delete_many(rejected_ids)
            if kept_ids:
                await repo_dao.mark_filtered(kept_ids)

            total_deleted += len(rejected_ids)
            total_kept += len(kept_ids)

        self._logger.info(
            "filter_complete kept=%d deleted=%d", total_kept, total_deleted
        )

    # ------------------------------------------------------------------ #
    # Public helper — usable in tests without a DB
    # ------------------------------------------------------------------ #

    def should_reject(self, repo: Repository) -> bool:
        """Return True if *repo* should be excluded from further processing."""
        if repo.archived:
            return True
        if repo.stars < self._config.scanning.min_stars:
            return True
        if repo.size_mb > self._config.scanning.max_repo_size_mb:
            return True
        name_lower = repo.name.lower()
        if any(token in name_lower for token in _REJECTED_NAME_TOKENS):
            return True
        return False
