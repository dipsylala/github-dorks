"""Stage 3 — Framework detector.

Infers the web framework used by a repository from its root-level files
and GitHub topic tags.  Repositories without a detectable framework may be
deprioritised or skipped by the scorer.

Supported frameworks:
    PHP:    laravel, symfony, php (generic via composer.json)
    Node:   express, koa, fastify, nestjs
    Python: django, flask, fastapi
    Java:   spring
    .NET:   aspnetcore
"""

from __future__ import annotations

import asyncio
import logging

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, RepositoryDAO
from pipeline.github import GitHubGraphQLClient
from pipeline.models import Repository

from .base import BaseStage

logger = logging.getLogger(__name__)

# Map framework name → indicator strings to search for in root files / topics.
# More-specific frameworks are listed first so they take precedence over the
# generic "php" fallback.
FRAMEWORK_INDICATORS: dict[str, list[str]] = {
    "laravel":    ["artisan", "laravel"],
    "symfony":    ["symfony"],
    "express":    ["express"],
    "koa":        ["koa"],
    "fastify":    ["fastify"],
    "nestjs":     ["nestjs", "@nestjs"],
    "django":     ["django"],
    "flask":      ["flask"],
    "fastapi":    ["fastapi"],
    "spring":     ["spring-boot", "spring-web"],
    "aspnetcore": ["microsoft.aspnetcore", "startup.cs", "program.cs"],
    # Generic PHP fallback — matches any project with a composer.json.
    # Must come after framework-specific PHP entries (laravel, symfony).
    "php":        ["composer.json"],
}


class FrameworkDetector(BaseStage):
    """Detects web frameworks and updates the repository's ``framework`` field."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)
        # Shared state set before workers start and cleared after.
        self._client: GitHubGraphQLClient | None = None
        self._repo_dao: RepositoryDAO | None = None

    async def run(self, language: str | None = None) -> None:
        repo_dao = RepositoryDAO(self._db)
        repos = await repo_dao.list_without_framework(limit=50_000)
        if not repos:
            self._logger.info("detect_skip no_undetected_repos")
            return

        self._logger.info(
            "detect_start repos=%d workers=%d",
            len(repos),
            self._config.worker_pools.enrichment_workers,
        )

        self._repo_dao = repo_dao
        async with GitHubGraphQLClient(
            token=self._config.github.token,
            per_page=self._config.github.per_page,
            rate_limit_pause_seconds=self._config.github.rate_limit_pause_seconds,
        ) as client:
            self._client = client

            queue: asyncio.Queue[Repository] = asyncio.Queue()
            for repo in repos:
                await queue.put(repo)

            await self._run_workers(
                queue,  # type: ignore[arg-type]
                self._config.worker_pools.enrichment_workers,
            )

        self._client = None
        self._repo_dao = None
        self._logger.info("detect_complete repos=%d", len(repos))

    async def _process(self, item: object) -> None:
        assert isinstance(item, Repository)
        assert self._client is not None
        assert self._repo_dao is not None

        root_files = await self._client.get_root_files(item.url)
        topics = await self._client.get_topics(item.url)
        framework = self.detect_framework(root_files, topics)
        # Store "" as a sentinel meaning "detected — no framework found",
        # so this repo is not re-processed on subsequent runs.
        await self._repo_dao.update_framework(item.id, framework or "")

    # ------------------------------------------------------------------ #
    # Public helper — usable in tests without a DB
    # ------------------------------------------------------------------ #

    def detect_framework(
        self,
        root_files: list[str],
        topics: list[str],
    ) -> str | None:
        """
        Infer the web framework from *root_files* and repository *topics*.

        Returns the framework identifier string or ``None`` if unknown.
        """
        combined = " ".join(root_files + topics).lower()
        for framework, indicators in FRAMEWORK_INDICATORS.items():
            if any(ind.lower() in combined for ind in indicators):
                return framework
        return None
