"""Tests for _node_to_repository() in repo_discovery."""

from __future__ import annotations

from datetime import timezone

import pytest

from pipeline.stages.repo_discovery import _node_to_repository


def _node(**overrides) -> dict:
    base = {
        "databaseId": 12345,
        "name": "myapp",
        "url": "https://github.com/owner/myapp",
        "stargazerCount": 500,
        "primaryLanguage": {"name": "Python"},
        "pushedAt": "2024-06-01T12:00:00Z",
        "diskUsage": 10240,  # 10 MB in KB
        "isArchived": False,
        "repositoryTopics": {"nodes": []},
    }
    base.update(overrides)
    return base


class TestNodeToRepository:
    def test_basic_conversion(self):
        repo = _node_to_repository(_node(), "python")
        assert repo.id == "12345"
        assert repo.name == "myapp"
        assert repo.stars == 500
        assert repo.language == "python"
        assert repo.size_mb == 10

    def test_primary_language_none_uses_fallback(self):
        repo = _node_to_repository(_node(primaryLanguage=None), "php")
        assert repo.language == "php"

    def test_primary_language_missing_name_uses_fallback(self):
        repo = _node_to_repository(_node(primaryLanguage={}), "java")
        assert repo.language == "java"

    def test_disk_usage_zero_gives_size_mb_one(self):
        repo = _node_to_repository(_node(diskUsage=0), "python")
        assert repo.size_mb == 1

    def test_disk_usage_converted_correctly(self):
        repo = _node_to_repository(_node(diskUsage=2048), "python")
        assert repo.size_mb == 2

    def test_is_archived_true(self):
        repo = _node_to_repository(_node(isArchived=True), "python")
        assert repo.archived is True

    def test_is_archived_false(self):
        repo = _node_to_repository(_node(isArchived=False), "python")
        assert repo.archived is False

    def test_is_archived_missing_defaults_false(self):
        node = _node()
        del node["isArchived"]
        repo = _node_to_repository(node, "python")
        assert repo.archived is False

    def test_pushed_at_parsed_as_timezone_aware(self):
        repo = _node_to_repository(_node(pushedAt="2024-01-15T10:30:00Z"), "python")
        assert repo.last_push.tzinfo is not None
        assert repo.last_push.year == 2024
        assert repo.last_push.month == 1

    def test_framework_defaults_none(self):
        repo = _node_to_repository(_node(), "python")
        assert repo.framework is None

    def test_score_defaults_zero(self):
        repo = _node_to_repository(_node(), "python")
        assert repo.score == 0
