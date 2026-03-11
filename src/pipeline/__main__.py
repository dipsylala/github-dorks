"""Pipeline entry point.

Usage:
    python -m pipeline [--config PATH] [--log-level LEVEL] [--stage STAGE]

    --config      Path to YAML configuration file (default: config/config.yaml)
    --log-level   One of DEBUG / INFO / WARNING / ERROR   (default: INFO)
    --stage       Run one stage or "all"                  (default: all)
                  Choices: discover | filter | detect | score-repos |
                           clone | scan | enrich | dedup | score-findings |
                           queue | all
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
from pipeline.pipeline import Pipeline, STAGE_ORDER

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
    return parser


async def _run(config: PipelineConfig, stage: str) -> None:
    async with DatabasePool(config.database) as db:
        pipeline = await Pipeline.create(config, db)
        await pipeline.run(stage)


def main() -> None:
    args = _build_parser().parse_args()
    configure_logging(level=args.log_level)

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"ERROR: config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    config = PipelineConfig.from_yaml(config_path)
    asyncio.run(_run(config, args.stage))


if __name__ == "__main__":
    main()
