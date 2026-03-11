"""Top-level pipeline orchestrator.

Usage::

    from pipeline.config import PipelineConfig
    from pipeline.db import DatabasePool
    from pipeline.pipeline import Pipeline

    config = PipelineConfig.from_yaml("config/config.yaml")

    async with DatabasePool(config.database) as db:
        pipeline = await Pipeline.create(config, db)
        await pipeline.run()          # all stages in order
        await pipeline.run("scan")    # single stage only

Stage names
-----------
discover | filter | detect | score-repos | clone | scan |
enrich   | dedup  | score-findings | queue | all (default)
"""

from __future__ import annotations

import logging
from pathlib import Path

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool, PatternDAO
from pipeline.models import Pattern, load_patterns
from pipeline.stages.deduplicator import Deduplicator
from pipeline.stages.framework_detector import FrameworkDetector
from pipeline.stages.repo_cloner import RepoCloner
from pipeline.stages.repo_discovery import RepoDiscovery
from pipeline.stages.repo_filter import RepoFilter
from pipeline.stages.repo_scorer import RepoScorer
from pipeline.stages.result_enricher import ResultEnricher
from pipeline.stages.result_scorer import ResultScorer
from pipeline.stages.review_queue import ReviewQueue
from pipeline.stages.scanner import Scanner

logger = logging.getLogger(__name__)

# Canonical stage execution order.
STAGE_ORDER: tuple[str, ...] = (
    "discover",
    "filter",
    "detect",
    "score-repos",
    "clone",
    "scan",
    "enrich",
    "score-findings",  # score first so dedup can keep the highest-scored row
    "dedup",
    "queue",
)


class Pipeline:
    """Builds and orchestrates the full vulnerability-hunting pipeline.

    Create via :meth:`Pipeline.create` — the classmethod bootstraps the
    database schema and loads patterns before returning a ready instance.
    """

    def __init__(
        self,
        config: PipelineConfig,
        db: DatabasePool,
        patterns: list[Pattern],
    ) -> None:
        self._config = config
        self._db = db
        self._patterns = patterns
        self._stages = {
            "discover":       RepoDiscovery(config, db),
            "filter":         RepoFilter(config, db),
            "detect":         FrameworkDetector(config, db),
            "score-repos":    RepoScorer(config, db),
            "clone":          RepoCloner(config, db),
            "scan":           Scanner(config, db, patterns),
            "enrich":         ResultEnricher(config, db),
            "dedup":          Deduplicator(config, db),
            "score-findings": ResultScorer(config, db),
            "queue":          ReviewQueue(config, db),
        }

    # ------------------------------------------------------------------ #
    # Factory
    # ------------------------------------------------------------------ #

    @classmethod
    async def create(cls, config: PipelineConfig, db: DatabasePool) -> Pipeline:
        """Bootstrap the schema, load and persist patterns, return a Pipeline.

        This is the preferred way to instantiate the pipeline — calling
        ``Pipeline(...)`` directly skips the setup steps.
        """
        schema_path = Path(__file__).parent / "db" / "schema.sql"
        await db.run_script(schema_path.read_text(encoding="utf-8"))
        logger.info("schema_bootstrap_complete")

        patterns = load_patterns(config.patterns_dir)
        logger.info("patterns_loaded count=%d", len(patterns))

        if patterns:
            await PatternDAO(db).upsert_many(patterns)
            logger.info("patterns_persisted count=%d", len(patterns))

        return cls(config, db, patterns)

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #

    async def run(self, stage: str = "all") -> None:
        """Run *stage* or, when *stage* is ``"all"``, every stage in order.

        Raises :exc:`ValueError` for unknown stage names.
        Re-raises any exception from a stage after logging it.
        """
        if stage == "all":
            for name in STAGE_ORDER:
                await self._run_stage(name)
        else:
            if stage not in self._stages:
                valid = ", ".join(STAGE_ORDER)
                raise ValueError(
                    f"Unknown stage '{stage}'. Valid choices: {valid}, all."
                )
            await self._run_stage(stage)

    async def _run_stage(self, name: str) -> None:
        logger.info("stage_start name=%s", name)
        try:
            await self._stages[name].run()
        except Exception:
            logger.exception("stage_failed name=%s", name)
            raise
        logger.info("stage_complete name=%s", name)
