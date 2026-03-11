"""Pipeline configuration loaded from a YAML file.

The GitHub token is never stored in the YAML file;
it is read from the GITHUB_TOKEN environment variable at load time.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

# Load a .env file if present (silently ignored when absent).
load_dotenv(override=False)


@dataclass
class GitHubConfig:
    token: str = ""
    per_page: int = 100
    rate_limit_pause_seconds: int = 60


@dataclass
class DatabaseConfig:
    path: str = "pipeline.db"


@dataclass
class WorkerPoolConfig:
    clone_workers: int = 8
    scan_workers: int = 16
    enrichment_workers: int = 8


@dataclass
class ScanningConfig:
    min_stars: int = 100
    max_repo_size_mb: int = 200
    clone_depth: int = 1
    clone_dir: str = "/tmp/repos"
    pushed_after: str = "2023-01-01"
    git_clone_timeout_seconds: int = 120
    languages: list[str] = field(
        default_factory=lambda: ["php", "javascript", "python", "java", "csharp"]
    )
    ignored_paths: list[str] = field(
        default_factory=lambda: [
            "node_modules", "vendor", "dist", "build", "target", "migrations",
        ]
    )
    # Each template is a GitHub search query string.  Supported placeholders:
    #   {language}     — from scanning.languages
    #   {min_stars}    — from scanning.min_stars
    #   {pushed_after} — from scanning.pushed_after
    # Add multiple templates to sweep different star ranges and avoid the
    # 1 000-result cap imposed by GitHub's search API.
    query_templates: list[str] = field(
        default_factory=lambda: [
            "stars:>{min_stars} fork:false archived:false "
            "pushed:>{pushed_after} language:{language}"
        ]
    )


@dataclass
class PipelineConfig:
    github: GitHubConfig = field(default_factory=GitHubConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    worker_pools: WorkerPoolConfig = field(default_factory=WorkerPoolConfig)
    patterns_dir: str = "config/patterns"
    report_path: str = "findings_report.json"

    @classmethod
    def from_yaml(cls, path: str | Path) -> PipelineConfig:
        with open(path) as fh:
            raw: dict[str, Any] = yaml.safe_load(fh)

        cfg = cls()

        if gh := raw.get("github"):
            cfg.github = GitHubConfig(**gh)
        if db := raw.get("database"):
            cfg.database = DatabaseConfig(**db)
        if sc := raw.get("scanning"):
            cfg.scanning = ScanningConfig(**sc)
        if wp := raw.get("worker_pools"):
            cfg.worker_pools = WorkerPoolConfig(**wp)
        if pd := raw.get("patterns_dir"):
            cfg.patterns_dir = pd
        if rp := raw.get("report_path"):
            cfg.report_path = rp

        # Override token from environment — never commit it to YAML.
        if token := os.getenv("GITHUB_TOKEN"):
            cfg.github.token = token

        return cfg
