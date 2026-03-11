"""Stage 5 — Repository cloner.

Loads scored repositories from the database (highest score first), then
clones each one locally using ``git clone --depth 1`` via a bounded
worker pool.  A :class:`LocalRepository` record is stored for every
successful clone.

Already-cloned repositories are skipped.  Clone failures are logged with
full stderr output and do not stop the pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, LocalRepositoryDAO, RepositoryDAO
from pipeline.models import LocalRepository, Repository

from .base import BaseStage

logger = logging.getLogger(__name__)


class RepoCloner(BaseStage):
    """Clones repositories in parallel using a bounded worker pool."""

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)
        self._clone_dir = Path(config.scanning.clone_dir)
        self._repo_dao = RepositoryDAO(db)
        self._local_dao = LocalRepositoryDAO(db)

    async def run(self) -> None:
        repos = await self._repo_dao.list_by_score()

        queue: asyncio.Queue[Repository] = asyncio.Queue()
        for repo in repos:
            await queue.put(repo)

        concurrency = self._config.worker_pools.clone_workers
        self._logger.info(
            "Cloning %d repositories with %d workers into '%s'.",
            len(repos),
            concurrency,
            self._clone_dir,
        )

        self._clone_dir.mkdir(parents=True, exist_ok=True)
        await self._run_workers(queue, concurrency)
        self._logger.info("Repo-cloner stage complete.")

    async def _process(self, item: object) -> None:
        assert isinstance(item, Repository)
        local = await self._clone_repository(item)
        if local is not None:
            await self._local_dao.insert(local)

    # ------------------------------------------------------------------ #
    # Clone logic
    # ------------------------------------------------------------------ #

    async def _clone_repository(self, repo: Repository) -> LocalRepository | None:
        """
        Shallow-clone *repo* into ``<clone_dir>/<repo.id>/``.

        Skips the clone and returns an existing record if the repository was
        already cloned in a previous run.  Returns ``None`` on any failure.
        """
        # Skip if a DB record already exists for this repo.
        if await self._local_dao.exists(repo.id):
            self._logger.debug(
                "skip already_cloned repo_id=%s name=%s",
                repo.id,
                repo.name,
            )
            return None

        dest = self._clone_dir / repo.id

        # If a leftover directory exists on disk (no DB record), remove it so
        # git does not complain about a non-empty destination.
        if dest.exists():
            self._logger.warning(
                "Removing orphan clone directory prior to re-clone: %s", dest
            )
            shutil.rmtree(dest, ignore_errors=True)

        cmd = [
            "git", "clone",
            "--depth", str(self._config.scanning.clone_depth),
            "--single-branch",   # only fetch the default branch
            "--no-tags",         # skip tag objects — saves bandwidth
            repo.url,
            str(dest),
        ]

        timeout = self._config.scanning.git_clone_timeout_seconds
        self._logger.info(
            "clone_start repo_id=%s name=%s url=%s dest=%s timeout=%ds",
            repo.id,
            repo.name,
            repo.url,
            dest,
            timeout,
        )

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout)
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()  # drain
                self._logger.warning(
                    "clone_timeout repo_id=%s name=%s timeout=%ds",
                    repo.id,
                    repo.name,
                    timeout,
                )
                _cleanup(dest)
                return None

            if proc.returncode != 0:
                stderr_text = (stderr_bytes or b"").decode(errors="replace").strip()
                self._logger.warning(
                    "clone_failed repo_id=%s name=%s returncode=%d stderr=%r",
                    repo.id,
                    repo.name,
                    proc.returncode,
                    stderr_text[:400],
                )
                _cleanup(dest)
                return None

        except OSError as exc:
            self._logger.error(
                "clone_error repo_id=%s name=%s error=%s",
                repo.id,
                repo.name,
                exc,
            )
            _cleanup(dest)
            return None

        self._logger.info(
            "clone_ok repo_id=%s name=%s path=%s",
            repo.id,
            repo.name,
            dest,
        )
        return LocalRepository(
            repository_id=repo.id,
            local_path=str(dest),
            clone_timestamp=datetime.now(tz=timezone.utc),
        )


def _cleanup(path: Path) -> None:
    """Remove a partially-cloned directory, ignoring errors."""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
