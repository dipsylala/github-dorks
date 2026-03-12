"""Stage 7 — Result enricher.

Adds contextual source-code lines around each raw finding's match line:
    - up to 3 lines before the matched line
    - the matched line itself
    - up to 3 lines after the matched line

The combined snippet replaces Finding.snippet and is persisted to the DB.
Sources are read from the local clone directory; findings for repositories
that have not been cloned yet are silently skipped.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, FindingDAO, LocalRepositoryDAO
from pipeline.models import Finding

from .base import BaseStage

logger = logging.getLogger(__name__)

_CONTEXT_LINES = 3
_PROGRESS_INTERVAL = 500


class ResultEnricher(BaseStage):
    """Enriches raw findings with surrounding source-code context."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)
        self._completed = 0
        self._total = 0

    async def run(self, language: str | None = None) -> None:
        finding_dao = FindingDAO(self._db)
        local_dao = LocalRepositoryDAO(self._db)

        # Build a full repo_id → local_path lookup in one round-trip.
        local_repos = await local_dao.list_all()
        local_paths: dict[str, str] = {
            lr.repository_id: lr.local_path for lr in local_repos
        }

        findings = await finding_dao.list_unenriched(language=language)
        if not findings:
            self._logger.info("enrich_skip no_unenriched_findings")
            return

        self._logger.info("enrich_start findings=%d", len(findings))

        self._total = len(findings)
        self._completed = 0

        queue: asyncio.Queue[tuple[Finding, str]] = asyncio.Queue()
        for finding in findings:
            await queue.put((finding, local_paths.get(finding.repository_id, "")))

        await self._run_workers(queue, self._config.worker_pools.enrichment_workers)
        self._logger.info("enrich_complete findings=%d", len(findings))

    async def _process(self, item: object) -> None:
        """Enrich one ``(Finding, local_repo_path)`` pair."""
        assert isinstance(item, tuple) and len(item) == 2
        finding, local_repo_path = item
        assert isinstance(finding, Finding)
        assert isinstance(local_repo_path, str)

        if not local_repo_path:
            self._logger.debug(
                "enrich_skip_no_clone finding_id=%s repo_id=%s",
                finding.id,
                finding.repository_id,
            )
            return

        full_path = str(Path(local_repo_path) / finding.file_path)
        snippet = self.extract_snippet(full_path, finding.line_number)
        if snippet:
            await FindingDAO(self._db).update_snippet(finding.id, snippet)

        self._completed += 1
        if self._total and (
            self._completed % _PROGRESS_INTERVAL == 0
            or self._completed == self._total
        ):
            self._logger.info(
                "enrich_progress completed=%d/%d (%.0f%%)",
                self._completed,
                self._total,
                self._completed * 100 / self._total,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def extract_snippet(self, file_path: str, line_number: int) -> str:
        """Return a context window of source lines around *line_number*.

        *file_path* must be an absolute (or resolvable) path.
        *line_number* is 1-based.  Lines outside file boundaries are omitted.
        Returns an empty string if the file cannot be read.
        """
        try:
            path = Path(file_path)
            if not path.is_file():
                return ""
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            idx = line_number - 1  # convert to 0-based
            start = max(0, idx - _CONTEXT_LINES)
            end   = min(len(lines), idx + _CONTEXT_LINES + 1)
            return "\n".join(lines[start:end])
        except OSError:
            return ""
