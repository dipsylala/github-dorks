"""Pipeline entry point.

Usage:
    python -m pipeline [--config PATH] [--log-level LEVEL] [--stage STAGE]

    --config      Path to YAML configuration file (default: config/config.yaml)
    --log-level   One of DEBUG / INFO / WARNING / ERROR   (default: INFO)
    --stage       Run one stage or "all"                  (default: all)
                  Choices: discover | filter | detect | score-repos |
                           clone | scan | enrich | dedup | score-findings |
                           queue | all
    --continue    When combined with --stage, continue running all subsequent
                  stages too
    --force       Reset the stage's processed flag before running, so
                  already-processed rows are re-processed.  Useful after
                  config changes (e.g. updated scoring weights, stricter
                  filter).  Stages with no persistent flag (discover, clone,
                  dedup, queue) ignore this option silently.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from pipeline.config import PipelineConfig
from pipeline.db import DatabasePool
from pipeline.logging_config import configure_logging
from pipeline.pipeline import STAGE_ORDER, Pipeline

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-pipeline",
        description="GitHub Vulnerability Hunting Pipeline",
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML configuration file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--stage",
        default="all",
        choices=[*STAGE_ORDER, "all"],
        help="Run a single stage or the full pipeline (default: all)",
    )
    parser.add_argument(
        "--language",
        default=None,
        choices=["php", "javascript", "python", "java", "csharp"],
        help="Filter by language (default: all languages)",
    )
    parser.add_argument(
        "--continue",
        dest="continue_pipeline",
        action="store_true",
        default=False,
        help="When combined with --stage, continue running all subsequent stages too",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Reset the stage flag(s) before running, so already-processed rows are re-processed",
    )
    return parser


async def _run(
    config: PipelineConfig,
    stage: str,
    language: str | None,
    continue_pipeline: bool,
    force: bool,
) -> None:
    async with DatabasePool(config.database) as db:
        pipeline = await Pipeline.create(config, db)
        if continue_pipeline and stage != "all":
            await pipeline.run_from(stage, language=language, force=force)
        else:
            await pipeline.run(stage, language=language, force=force)


def main() -> None:
    args = _build_parser().parse_args()
    configure_logging(level=args.log_level)

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = PipelineConfig.from_yaml(config_path)
    asyncio.run(_run(config, args.stage, args.language, args.continue_pipeline, args.force))


if __name__ == "__main__":
    main()
