"""Stage 1 — Repository discovery via the GitHub GraphQL API.

For each (query_template × language) combination, pages through GitHub's
repository search and upserts every result into the ``repositories`` table.

Query templates are configurable in ``config.yaml`` under
``scanning.query_templates``.  Each template may contain these placeholders:

    {language}      — substituted from ``scanning.languages``
    {min_stars}     — substituted from ``scanning.min_stars``
    {pushed_after}  — substituted from ``scanning.pushed_after``

GitHub caps search results at 1 000 items per query.  To sweep larger result
sets, add multiple templates that partition by star range, e.g.:

    - "stars:100..500 fork:false archived:false language:{language}"
    - "stars:501..2000 fork:false archived:false language:{language}"
    - "stars:>2000 fork:false archived:false language:{language}"
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, RepositoryDAO
from pipeline.github import GitHubGraphQLClient
from pipeline.models import Repository

from .base import BaseStage

logger = logging.getLogger(__name__)


def _node_to_repository(node: dict, fallback_language: str) -> Repository:
    """Convert a raw GraphQL repository node to a :class:`Repository`."""
    lang: str = (
        (node.get("primaryLanguage") or {}).get("name") or fallback_language
    )
    pushed_raw: str = node["pushedAt"]  # ISO-8601, e.g. "2024-01-15T10:30:00Z"
    last_push = datetime.fromisoformat(pushed_raw.replace("Z", "+00:00"))
    disk_kb: int = node.get("diskUsage") or 0
    archived: bool = bool(node.get("isArchived", False))
    return Repository(
        id=str(node["databaseId"]),
        name=node["name"],
        url=node["url"],
        stars=node["stargazerCount"],
        language=lang,
        last_push=last_push,
        archived=archived,
        size_mb=max(1, disk_kb // 1024),
    )


class RepoDiscovery(BaseStage):
    """Discovers candidate repositories via the GitHub GraphQL Search API."""

    async def run(self) -> None:
        cfg = self._config
        dao = RepositoryDAO(self._db)

        async with GitHubGraphQLClient(
            token=cfg.github.token,
            per_page=cfg.github.per_page,
            rate_limit_pause_seconds=cfg.github.rate_limit_pause_seconds,
        ) as client:
            for template in cfg.scanning.query_templates:
                for language in cfg.scanning.languages:
                    query = template.format(
                        language=language,
                        min_stars=cfg.scanning.min_stars,
                        pushed_after=cfg.scanning.pushed_after,
                    )
                    self._logger.info("Searching: %s", query)

                    total = 0
                    async for page in client.search_repositories(query):
                        repos = [
                            _node_to_repository(node, language)
                            for node in page
                        ]
                        if repos:
                            await dao.upsert_many(repos)
                            total += len(repos)

                    self._logger.info(
                        "  → %d repositories saved for language '%s'.",
                        total,
                        language,
                    )

        self._logger.info("Repo-discovery stage complete.")
