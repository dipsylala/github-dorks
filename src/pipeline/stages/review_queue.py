"""Stage 10 — Review queue.

Produces the final ordered list of findings for manual triage.

Findings are ranked by:
    finding.score + repository.score  (descending)

Results are exported to a structured JSON report file (``config.report_path``)
and can also be queried directly from the ``review_queue`` database view.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, FindingDAO
from pipeline.models import Finding

from .base import BaseStage

logger = logging.getLogger(__name__)


class ReviewQueue(BaseStage):
    """Builds and exports the final prioritised finding queue.

    Reads the ``review_queue`` database view (finding_score + repo_score DESC),
    logs a summary, and writes a JSON report to ``config.report_path``.
    """

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)

    async def run(self, language: str | None = None) -> None:
        self._logger.info("queue_start")
        findings = await self.get_top_findings(language=language)
        self._logger.info("review_queue_ready count=%d", len(findings))
        if findings:
            top = findings[0]
            self._logger.info(
                "top_finding vuln_type=%s file=%s score=%d",
                top.vulnerability_type,
                top.file_path,
                top.score,
            )

        report_path = Path(self._config.report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("w", encoding="utf-8") as fh:
            json.dump([asdict(f) for f in findings], fh, indent=2, default=str)
        self._logger.info("report_written path=%s", report_path)

        # Write repo_report.json alongside findings_report.json.
        # One entry per repository, sorted by highest combined score descending.
        repos: dict[str, dict] = {}
        for f in findings:
            rid = f.repository_id
            if rid not in repos:
                repos[rid] = {
                    "repository_id":   rid,
                    "repository_name": f.repository_name,
                    "repository_url":  f.repository_url,
                    "framework":       f.framework,
                    "top_score":       f.score,
                    "finding_count":   0,
                    "vulnerability_types": [],
                }
            entry = repos[rid]
            entry["finding_count"] += 1
            entry["top_score"] = max(entry["top_score"], f.score)
            if f.vulnerability_type not in entry["vulnerability_types"]:
                entry["vulnerability_types"].append(f.vulnerability_type)

        repo_list = sorted(repos.values(), key=lambda r: r["finding_count"], reverse=True)
        repo_report_path = report_path.with_name("repo_report.json")
        with repo_report_path.open("w", encoding="utf-8") as fh:
            json.dump(repo_list, fh, indent=2, default=str)
        self._logger.info("repo_report_written path=%s repos=%d", repo_report_path, len(repo_list))

    async def get_top_findings(self, limit: int = 1000, language: str | None = None) -> list[Finding]:
        """Return the top *limit* findings ordered by combined score descending.

        Queries the ``review_queue`` view defined in ``schema.sql``.
        """
        return await FindingDAO(self._db).list_top(limit, language=language)
