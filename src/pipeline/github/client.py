"""GitHub GraphQL API client with cursor-based pagination and rate-limit handling."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

_ENDPOINT = "https://api.github.com/graphql"

# Cost: 1 point per page regardless of first= value.
_SEARCH_QUERY = """
query($query: String!, $first: Int!, $cursor: String) {
  search(query: $query, type: REPOSITORY, first: $first, after: $cursor) {
    repositoryCount
    pageInfo {
      endCursor
      hasNextPage
    }
    nodes {
      ... on Repository {
        databaseId
        name
        nameWithOwner
        url
        stargazerCount
        primaryLanguage { name }
        pushedAt
        diskUsage
        isArchived
        repositoryTopics(first: 10) {
          nodes { topic { name } }
        }
      }
    }
  }
  rateLimit {
    limit
    remaining
    resetAt
    cost
  }
}
"""

# If fewer than this many points remain, pause until the window resets.
_DEFAULT_MIN_REMAINING = 50


class GitHubGraphQLClient:
    """Async GitHub GraphQL client that handles pagination and rate limits.

    Usage::

        async with GitHubGraphQLClient(token="ghp_...") as client:
            async for page in client.search_repositories("language:php stars:>100"):
                for node in page:
                    process(node)
    """

    def __init__(
        self,
        token: str,
        per_page: int = 100,
        rate_limit_pause_seconds: int = 60,
        min_remaining: int = _DEFAULT_MIN_REMAINING,
    ) -> None:
        if not token:
            raise ValueError(
                "GitHub token is required. Set the GITHUB_TOKEN environment variable."
            )
        self._token = token
        # GitHub GraphQL search accepts at most 100 items per page.
        self._per_page = min(max(1, per_page), 100)
        self._pause = rate_limit_pause_seconds
        self._min_remaining = min_remaining
        self._session: aiohttp.ClientSession | None = None
        # Shared REST rate-limit state: monotonic timestamp until which we are
        # rate-limited.  Only the first 403 that advances this window logs a
        # warning; all others wait silently.
        self._rest_limited_until: float = 0.0

    # ------------------------------------------------------------------ #
    # Async context manager
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> GitHubGraphQLClient:
        self._session = aiohttp.ClientSession(
            headers={
                "Authorization": f"bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
            }
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def get_topics(self, repo_url: str) -> list[str]:
        """Return the topic names for a repository via the GitHub Topics REST API.

        Parses *repo_url* (``https://github.com/owner/repo``) to build the
        ``/repos/{owner}/{repo}/topics`` request.  Returns an empty list on
        any error.
        """
        assert self._session is not None, (
            "GitHubGraphQLClient must be used as an async context manager."
        )
        parts = repo_url.rstrip("/").split("/")
        if len(parts) < 2:
            return []
        owner, repo = parts[-2], parts[-1]
        api_url = f"https://api.github.com/repos/{owner}/{repo}/topics"

        wait = self._rest_limited_until - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)

        try:
            async with self._session.get(
                api_url,
                headers={"Accept": "application/vnd.github.mercy-preview+json"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    names = data.get("names", [])
                    if isinstance(names, list):
                        return [str(n) for n in names]
                elif resp.status == 403:
                    remaining = resp.headers.get("X-RateLimit-Remaining", "0")
                    await self._handle_rest_rate_limit(resp.headers, repo_url, "rest_rate_limit_topics")
                elif resp.status == 404:
                    pass  # private / deleted repo
        except aiohttp.ClientError as exc:
            logger.debug("topics_error repo=%s error=%s", repo_url, exc)

        return []

    async def get_root_files(self, repo_url: str) -> list[str]:
        """Return filenames in the repository root via the GitHub Contents REST API.

        Parses *repo_url* (``https://github.com/owner/repo``) to build the
        ``/repos/{owner}/{repo}/contents/`` request.  Returns an empty list on
        any error (404, rate limit, network failure, etc.).
        """
        assert self._session is not None, (
            "GitHubGraphQLClient must be used as an async context manager."
        )
        parts = repo_url.rstrip("/").split("/")
        if len(parts) < 2:
            return []
        owner, repo = parts[-2], parts[-1]
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/"

        wait = self._rest_limited_until - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)

        try:
            async with self._session.get(api_url) as resp:
                if resp.status == 200:
                    items = await resp.json()
                    if isinstance(items, list):
                        return [
                            item["name"]
                            for item in items
                            if isinstance(item, dict) and "name" in item
                        ]
                elif resp.status == 403:
                    await self._handle_rest_rate_limit(resp.headers, repo_url, "rest_rate_limit")
                elif resp.status == 404:
                    pass  # private / deleted repo — skip silently
                else:
                    logger.debug(
                        "rest_unexpected_status repo=%s status=%d",
                        repo_url,
                        resp.status,
                    )
        except aiohttp.ClientError as exc:
            logger.warning("rest_error repo=%s error=%s", repo_url, exc)

        return []

    async def search_repositories(
        self, query: str
    ) -> AsyncGenerator[list[dict[str, Any]], None]:
        """Paginate through GitHub repository search results for *query*.

        Yields one page (list of raw GraphQL repository nodes) at a time.

        GitHub caps search results at 1 000 items per query regardless of the
        total ``repositoryCount``. A warning is logged when more results exist
        than can be fetched; callers should narrow the query (e.g. by date
        range) to stay within the cap.
        """
        assert self._session is not None, (
            "GitHubGraphQLClient must be used as an async context manager."
        )

        cursor: str | None = None
        page_num = 0
        total_reported: int | None = None

        while True:
            data = await self._execute(
                _SEARCH_QUERY,
                variables={
                    "query": query,
                    "first": self._per_page,
                    "cursor": cursor,
                },
            )

            search = data["search"]
            rate: dict[str, Any] = data["rateLimit"]
            page_num += 1

            if total_reported is None:
                total_reported = search["repositoryCount"]
                logger.info(
                    "Query '%s' — %d repositories reported.",
                    query,
                    total_reported,
                )
                if total_reported > 1000:
                    logger.warning(
                        "Result set (%d) exceeds GitHub's 1 000-item search cap. "
                        "Consider splitting the query by star range or date range "
                        "to avoid missing results.",
                        total_reported,
                    )

            # Filter out null nodes (union type may include non-Repository hits).
            nodes: list[dict[str, Any]] = [
                n for n in search["nodes"] if n and n.get("databaseId") is not None
            ]

            logger.debug(
                "Page %d: %d nodes fetched. Rate limit: %d/%d remaining (cost %d).",
                page_num,
                len(nodes),
                rate["remaining"],
                rate["limit"],
                rate["cost"],
            )

            if nodes:
                yield nodes

            page_info = search["pageInfo"]
            if not page_info["hasNextPage"]:
                break

            cursor = page_info["endCursor"]

            # Check rate limit budget before fetching the next page.
            await self._maybe_pause(rate)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _execute(
        self,
        query: str,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        """POST a single GraphQL request.

        Retries up to 3 times on HTTP 403/429 rate-limit responses, honouring
        the ``Retry-After`` header when present.  All other non-200 statuses
        raise ``RuntimeError`` immediately.
        """
        assert self._session is not None

        last_exc: Exception | None = None
        for attempt in range(1, 4):
            try:
                async with self._session.post(
                    _ENDPOINT,
                    json={"query": query, "variables": variables},
                ) as resp:
                    if resp.status == 200:
                        payload: dict[str, Any] = await resp.json()
                        if errors := payload.get("errors"):
                            raise RuntimeError(f"GraphQL errors: {errors}")
                        return payload["data"]

                    if resp.status in (403, 429):
                        retry_after = int(
                            resp.headers.get("Retry-After", self._pause)
                        )
                        logger.warning(
                            "Rate limited (HTTP %d). Sleeping %ds (attempt %d/3).",
                            resp.status,
                            retry_after,
                            attempt,
                        )
                        await asyncio.sleep(retry_after)
                        last_exc = RuntimeError(
                            f"HTTP {resp.status} rate limit on attempt {attempt}"
                        )
                        continue

                    body = await resp.text()
                    raise RuntimeError(
                        f"GitHub GraphQL request failed: HTTP {resp.status} — {body[:500]}"
                    )

            except aiohttp.ClientConnectionError as exc:
                logger.warning(
                    "Connection error on attempt %d/3: %s", attempt, exc
                )
                last_exc = exc
                await asyncio.sleep(min(5 * attempt, 30))

        raise RuntimeError(
            "GitHub GraphQL request failed after 3 attempts."
        ) from last_exc

    async def _maybe_pause(self, rate_limit: dict[str, Any]) -> None:
        """Sleep until the rate-limit window resets when points run low."""
        remaining: int = rate_limit["remaining"]
        if remaining > self._min_remaining:
            return

        reset_at = datetime.fromisoformat(
            rate_limit["resetAt"].replace("Z", "+00:00")
        )
        now = datetime.now(tz=UTC)
        sleep_secs = max(0.0, (reset_at - now).total_seconds()) + 5  # +5s buffer

        logger.warning(
            "Rate limit low (%d/%d remaining). Pausing %.0fs until reset at %s.",
            remaining,
            rate_limit["limit"],
            sleep_secs,
            rate_limit["resetAt"],
        )
        await asyncio.sleep(sleep_secs)

    async def _handle_rest_rate_limit(
        self,
        headers: "aiohttp.CIMultiDictProxy[str]",
        repo_url: str,
        log_key: str,
    ) -> None:
        """Handle a 403 REST rate-limit response.

        Calculates the sleep duration from ``X-RateLimit-Reset`` when available,
        otherwise falls back to ``self._pause``.  Logs a WARNING only when this
        call is the one that advances the shared ``_rest_limited_until`` window,
        so concurrent calls that hit the same rate-limit window are silent.
        """
        remaining = headers.get("X-RateLimit-Remaining", "0")
        reset_header = headers.get("X-RateLimit-Reset")
        if reset_header:
            try:
                reset_ts = float(reset_header)
                sleep_secs = max(0.0, reset_ts - time.time()) + 5  # +5s buffer
            except ValueError:
                sleep_secs = float(self._pause)
        else:
            sleep_secs = float(self._pause)

        new_until = time.monotonic() + sleep_secs
        if new_until > self._rest_limited_until:
            self._rest_limited_until = new_until
            logger.warning(
                "%s repo=%s remaining=%s — pausing %.0fs until rate limit resets",
                log_key,
                repo_url,
                remaining,
                sleep_secs,
            )

        wait = self._rest_limited_until - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
