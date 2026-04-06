"""Stage 1 — Repository discovery via the GitHub GraphQL API.

For each (query_template × language) combination, pages through GitHub's
repository search and upserts every result into the ``repositories`` table.

Query templates are configurable in ``config.yaml`` under
``scanning.query_templates``.  Each template may contain these placeholders:

    {language}      — substituted from ``scanning.languages``
    {min_stars}     — substituted from ``scanning.min_stars``
    {pushed_after}  — substituted from ``scanning.pushed_after``
    {pushed_before} — substituted from ``scanning.pushed_before`` (empty string when unset)
    {pushed}        — computed qualifier: ``pushed:>AFTER`` when only pushed_after is set,
                      or ``pushed:AFTER..BEFORE`` when both are set

GitHub caps search results at 1 000 items per query.  When a sub-range exceeds
this cap the stage automatically bisects the date window in half and retries,
recursing until every leaf query fits within 1 000 results (or the window is
reduced to a single day, at which point the cap is accepted).

To also split by star range, add multiple templates:

    - "stars:100..500 fork:false archived:false {pushed} language:{language}"
    - "stars:>500 fork:false archived:false {pushed} language:{language}"
"""

from __future__ import annotations

import logging
from datetime import date as _date, timedelta
from datetime import datetime

from pipeline.db import RepositoryDAO
from pipeline.github import GitHubGraphQLClient
from pipeline.models import Repository

from .base import BaseStage

logger = logging.getLogger(__name__)


# Map GitHub API primaryLanguage names → config/CLI language keys.
_GITHUB_LANG_TO_CONFIG: dict[str, str] = {
    "c#":         "csharp",
    "javascript": "javascript",
    "typescript": "typescript",
    "php":        "php",
    "python":     "python",
    "java":       "java",
}


def _node_to_repository(node: dict, fallback_language: str) -> Repository:
    """Convert a raw GraphQL repository node to a :class:`Repository`."""
    lang: str = (
        (node.get("primaryLanguage") or {}).get("name") or fallback_language
    )
    lang = _GITHUB_LANG_TO_CONFIG.get(lang.lower(), lang.lower())
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

    async def _discover_language(
        self,
        client: GitHubGraphQLClient,
        dao: RepositoryDAO,
        template: str,
        language: str,
        min_stars: int,
        date_after: _date,
        date_before: _date,
    ) -> int:
        """Fetch all repos matching *template* for the given date window.

        If the result count exceeds GitHub's 1 000-item cap, the date range is
        bisected and each half is queried independently.  Recursion continues
        until every leaf fits within the cap or the window is 1 day wide.
        """
        pushed = f"pushed:{date_after}..{date_before}"
        query = template.format(
            language=language,
            min_stars=min_stars,
            pushed_after=str(date_after),
            pushed_before=str(date_before),
            pushed=pushed,
        )

        count = await client.count_repositories(query)
        if count == 0:
            return 0

        if count <= 1000:
            self._logger.info("Searching: %s", query)
            total = 0
            async for page in client.search_repositories(query):
                repos = [_node_to_repository(node, language) for node in page]
                if repos:
                    await dao.upsert_many(repos)
                    total += len(repos)
            return total

        # Too many results — try to bisect the date range.
        delta_days = (date_before - date_after).days
        if delta_days < 2:
            # Single-day window; can't bisect further — accept the cap.
            self._logger.warning(
                "Query '%s' has %d results and cannot be bisected further "
                "(date window is 1 day). Accepting GitHub's 1 000-result cap.",
                query,
                count,
            )
            total = 0
            async for page in client.search_repositories(query):
                repos = [_node_to_repository(node, language) for node in page]
                if repos:
                    await dao.upsert_many(repos)
                    total += len(repos)
            return total

        mid = date_after + timedelta(days=delta_days // 2)
        self._logger.debug(
            "Bisecting %d results for '%s' (%s..%s) → [%s..%s] + [%s..%s]",
            count,
            query,
            date_after,
            date_before,
            date_after,
            mid - timedelta(days=1),
            mid,
            date_before,
        )
        left = await self._discover_language(
            client, dao, template, language, min_stars,
            date_after, mid - timedelta(days=1),
        )
        right = await self._discover_language(
            client, dao, template, language, min_stars,
            mid, date_before,
        )
        return left + right

    async def run(self, language: str | None = None) -> None:
        cfg = self._config
        dao = RepositoryDAO(self._db)

        date_after = _date.fromisoformat(cfg.scanning.pushed_after)
        date_before = (
            _date.fromisoformat(cfg.scanning.pushed_before)
            if cfg.scanning.pushed_before
            else _date.today()
        )

        async with GitHubGraphQLClient(
            token=cfg.github.token,
            per_page=cfg.github.per_page,
            rate_limit_pause_seconds=cfg.github.rate_limit_pause_seconds,
        ) as client:
            for template in cfg.scanning.query_templates:
                for language in cfg.scanning.languages:
                    total = await self._discover_language(
                        client, dao, template, language,
                        cfg.scanning.min_stars, date_after, date_before,
                    )
                    self._logger.info(
                        "  → %d repositories saved for language '%s'.",
                        total,
                        language,
                    )

        self._logger.info("Repo-discovery stage complete.")
