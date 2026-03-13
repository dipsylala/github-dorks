"""Stage 6 — Regex scanner using ripgrep.

Scans each locally cloned repository against every loaded Pattern using
ripgrep (``rg``).  Raw Finding records are written to the database in
batches.

Directories listed in ``scanning.ignored_paths`` are excluded from every
scan invocation via ripgrep ``--glob !<dir>`` arguments.

Note: this stage treats repositories as **data only** — no repository
code is imported or executed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path, PurePosixPath

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, FindingDAO, LocalRepositoryDAO
from pipeline.models import Finding, LocalRepository, Pattern

from .base import BaseStage

logger = logging.getLogger(__name__)

# ripgrep exit codes:
#   0 — matches found
#   1 — no matches (not an error)
#   2 — real error (e.g. bad regex, missing binary)
_RG_ERROR_CODE = 2

# Flush findings to DB after accumulating this many.
_BATCH_SIZE = 500

# Log a progress line every this many completed (repo, pattern) pairs.
_PROGRESS_INTERVAL = 1000

# Namespace for deterministic finding UUIDs (UUID5).
# Fixed value — do not change, or all existing finding IDs will shift.
_FINDING_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL

# Map pattern language names → ripgrep --type values.
# Only source files for the repo's language are scanned, reducing false
# positives from vendored translations, docs, and unrelated language files.
_LANGUAGE_TO_RG_TYPE: dict[str, str] = {
    "php":        "php",
    "python":     "py",
    "javascript": "js",
    "java":       "java",
    "csharp":     "csharp",
}


class Scanner(BaseStage):
    """Scans local repositories with ripgrep and persists raw findings."""

    def __init__(
        self,
        config: PipelineConfig,
        db: DatabasePool,
        patterns: list[Pattern],
    ) -> None:
        super().__init__(config, db)
        self._patterns = patterns
        self._finding_dao = FindingDAO(db)
        self._local_dao = LocalRepositoryDAO(db)
        # Build the ignore glob args once — they are the same for every invocation.
        self._ignore_args: list[str] = []
        for ignored in config.scanning.ignored_paths:
            self._ignore_args += ["--glob", f"!{ignored}"]
        self._completed = 0
        self._total = 0

    async def run(self, language: str | None = None) -> None:
        if language:
            local_repos = await self._local_dao.list_by_language(language)
            patterns = [p for p in self._patterns if p.language.lower() == language.lower()]
        else:
            local_repos = await self._local_dao.list_all()
            patterns = self._patterns

        if not local_repos:
            self._logger.info("No cloned repositories found — skipping scan.")
            return

        self._logger.info(
            "scan_start repos=%d patterns=%d workers=%d",
            len(local_repos),
            len(patterns),
            self._config.worker_pools.scan_workers,
        )

        self._total = len(local_repos) * len(patterns)
        self._completed = 0

        queue: asyncio.Queue[tuple[LocalRepository, Pattern]] = asyncio.Queue()
        for repo in local_repos:
            for pattern in patterns:
                await queue.put((repo, pattern))

        await self._run_workers(queue, self._config.worker_pools.scan_workers)
        self._logger.info("scan_complete total=%d", self._total)

    async def _process(self, item: object) -> None:
        assert isinstance(item, tuple) and len(item) == 2
        local_repo, pattern = item
        assert isinstance(local_repo, LocalRepository)
        assert isinstance(pattern, Pattern)

        findings = await self._scan_one(local_repo, pattern)
        if findings:
            await self._finding_dao.insert_many(findings)
            self._logger.debug(
                "scan_findings repo_id=%s pattern_id=%s count=%d",
                local_repo.repository_id,
                pattern.id,
                len(findings),
            )

        self._completed += 1
        if self._total and (
            self._completed % _PROGRESS_INTERVAL == 0
            or self._completed == self._total
        ):
            self._logger.info(
                "scan_progress completed=%d/%d (%.0f%%)",
                self._completed,
                self._total,
                self._completed * 100 / self._total,
            )

    # ------------------------------------------------------------------ #
    # Core scan logic
    # ------------------------------------------------------------------ #

    async def _scan_one(
        self,
        local_repo: LocalRepository,
        pattern: Pattern,
    ) -> list[Finding]:
        """Run ripgrep for one (repo, pattern) pair; return Finding objects."""
        repo_path = local_repo.local_path

        # Safety: skip if the directory has been removed since cloning.
        if not Path(repo_path).is_dir():
            self._logger.warning(
                "scan_skip_missing repo_id=%s path=%s",
                local_repo.repository_id,
                repo_path,
            )
            return []

        cmd = [
            "rg",
            "--json",           # structured output — one JSON object per line
            "--line-number",    # include line numbers in match objects
            "--multiline",      # allow patterns to span lines if needed
            "--case-sensitive",
            *self._ignore_args,
        ]

        # Restrict scan to the pattern's source language when available.
        rg_type = _LANGUAGE_TO_RG_TYPE.get(pattern.language.lower()) if pattern.language else None
        if rg_type:
            cmd += ["--type", rg_type]

        cmd += [
            "--",               # end of flags; regex and path follow
            pattern.regex,
            repo_path,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await proc.communicate()
        except OSError as exc:
            self._logger.error(
                "scan_error repo_id=%s pattern_id=%s error=%s",
                local_repo.repository_id,
                pattern.id,
                exc,
            )
            return []

        if proc.returncode == _RG_ERROR_CODE:
            stderr_text = (stderr_bytes or b"").decode(errors="replace").strip()
            self._logger.warning(
                "rg_error repo_id=%s pattern_id=%s stderr=%r",
                local_repo.repository_id,
                pattern.id,
                stderr_text[:400],
            )
            return []

        # returncode 0 → matches, 1 → no matches; both are fine.
        return _parse_rg_output(
            stdout_bytes,
            repository_id=local_repo.repository_id,
            pattern=pattern,
            repo_root=repo_path,
        )


# ------------------------------------------------------------------ #
# ripgrep JSON output parser (module-level — no instance state needed)
# ------------------------------------------------------------------ #

def _parse_rg_output(
    raw: bytes,
    *,
    repository_id: str,
    pattern: Pattern,
    repo_root: str,
) -> list[Finding]:
    """Parse ripgrep ``--json`` output and return :class:`Finding` objects.

    ripgrep emits one JSON object per line.  We only care about lines
    whose ``type`` field is ``"match"``.  Example match object::

        {
          "type": "match",
          "data": {
            "path": {"text": "/tmp/repos/42/src/app.php"},
            "lines": {"text": "exec($_GET['cmd']);\\n"},
            "line_number": 17,
            "absolute_offset": 412,
            "submatches": [...]
          }
        }
    """
    findings: list[Finding] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        if obj.get("type") != "match":
            continue

        data = obj.get("data", {})
        abs_path: str = (data.get("path") or {}).get("text", "")
        line_number: int = data.get("line_number", 0)
        matched_text: str = (data.get("lines") or {}).get("text", "").rstrip("\n")

        # Store as a relative POSIX path so findings are portable across machines
        # and GitHub URLs can be constructed without needing the local clone root.
        try:
            file_path = PurePosixPath(Path(abs_path).relative_to(repo_root)).as_posix()
        except ValueError:
            file_path = abs_path

        # Deterministic ID — same (repo, file, line, pattern) always produces
        # the same UUID, so re-running the scan stage is idempotent.
        finding_key = f"{repository_id}:{file_path}:{line_number}:{pattern.id}"
        finding_id = str(uuid.uuid5(_FINDING_NS, finding_key))

        findings.append(
            Finding(
                id=finding_id,
                repository_id=repository_id,
                file_path=file_path,
                line_number=line_number,
                pattern_id=pattern.id,
                vulnerability_type=pattern.vulnerability_type,
                snippet=matched_text,
                score=0,    # populated by result-scorer stage
            )
        )

    return findings
