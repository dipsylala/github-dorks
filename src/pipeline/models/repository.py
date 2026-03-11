"""Repository and LocalRepository data models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Repository:
    id: str
    name: str
    url: str
    stars: int
    language: str
    last_push: datetime
    size_mb: int
    archived: bool = False
    framework: str | None = None
    score: int = 0


@dataclass
class LocalRepository:
    repository_id: str
    local_path: str
    clone_timestamp: datetime
