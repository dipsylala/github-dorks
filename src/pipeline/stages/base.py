"""Abstract base class shared by every pipeline stage."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool


class BaseStage(ABC):
    """
    Common interface for pipeline stages.

    Each stage receives the global config and a live database pool.
    The ``run()`` coroutine contains the stage's top-level orchestration.
    Individual units of work are processed via ``_process()`` which is called
    by ``_worker()`` coroutines draining an asyncio Queue.
    """

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        self._config = config
        self._db = db
        self._logger = logging.getLogger(
            f"pipeline.stages.{self.__class__.__name__}"
        )

    @abstractmethod
    async def run(self) -> None:
        """Execute the stage's main logic."""
        ...

    async def _run_workers(
        self,
        queue: asyncio.Queue[object],
        concurrency: int,
    ) -> None:
        """Spawn *concurrency* workers that drain *queue*, then wait for completion."""
        workers = [
            asyncio.create_task(self._worker(queue))
            for _ in range(concurrency)
        ]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    async def _worker(self, queue: asyncio.Queue[object]) -> None:
        """Generic worker coroutine — pulls items and delegates to ``_process``."""
        while True:
            item = await queue.get()
            try:
                await self._process(item)
            except Exception:
                self._logger.exception("Worker error processing item: %r", item)
            finally:
                queue.task_done()

    async def _process(self, item: object) -> None:
        """Override in subclasses to handle individual work items."""
        raise NotImplementedError
