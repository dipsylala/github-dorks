"""Shared pytest fixtures and helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from pipeline.config import PipelineConfig, ScanningConfig
from pipeline.models.repository import Repository


@pytest.fixture()
def default_config() -> PipelineConfig:
    """A minimal PipelineConfig with sensible defaults for unit tests."""
    cfg = PipelineConfig()
    cfg.scanning = ScanningConfig(min_stars=100, max_repo_size_mb=200)
    return cfg


@pytest.fixture()
def make_repo():
    """Factory fixture — returns a callable that builds a Repository."""

    def _make(
        *,
        id: str = "1",
        name: str = "myapp",
        url: str = "https://github.com/owner/myapp",
        stars: int = 500,
        language: str = "python",
        last_push: datetime | None = None,
        size_mb: int = 50,
        archived: bool = False,
        framework: str | None = None,
        score: int = 0,
    ) -> Repository:
        if last_push is None:
            last_push = datetime(2025, 6, 1, tzinfo=timezone.utc)
        return Repository(
            id=id,
            name=name,
            url=url,
            stars=stars,
            language=language,
            last_push=last_push,
            size_mb=size_mb,
            archived=archived,
            framework=framework,
            score=score,
        )

    return _make
