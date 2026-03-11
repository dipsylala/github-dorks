"""Finding data model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    repository_id: str
    file_path: str
    line_number: int
    pattern_id: str
    vulnerability_type: str
    snippet: str
    matched_pattern_ids: list[str] = field(default_factory=list)
    score: int = 0
