"""Stage 8 — Finding deduplicator.

Collapses duplicate findings that share the same
(repository_id, file_path, line_number) key.

When multiple patterns match the same location the record with the
highest severity_score is kept and all matching pattern IDs are
aggregated into a JSON field for reference.
"""

from __future__ import annotations

import logging

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, FindingDAO

from .base import BaseStage

logger = logging.getLogger(__name__)


class Deduplicator(BaseStage):
    """Removes duplicate findings, retaining the highest-scored match.

    Duplicate definition: same (repository_id, file_path, line_number).
    When multiple pattern matches land on the same location, the row with
    the highest score is kept and the rest are deleted.
    """

    def __init__(self, config: PipelineConfig, db: DatabasePool) -> None:
        super().__init__(config, db)

    async def run(self) -> None:
        deleted = await FindingDAO(self._db).delete_duplicates()
        self._logger.info("dedup_complete deleted=%d", deleted)
