"""Tests for finding_dao helpers."""

from __future__ import annotations

import pytest

from pipeline.db.repositories.finding_dao import _build_github_url

REPO_URL = "https://github.com/example/repo"


class TestBuildGithubUrl:
    def test_relative_posix_path(self):
        url = _build_github_url(REPO_URL, "src/app/Foo.java", 42)
        assert url == f"{REPO_URL}/blob/HEAD/src/app/Foo.java#L42"

    def test_absolute_windows_path_with_local_path(self):
        url = _build_github_url(
            REPO_URL,
            r"e:\temp\123456\src\app\Foo.java",
            10,
            local_path=r"e:\temp\123456",
        )
        assert url == f"{REPO_URL}/blob/HEAD/src/app/Foo.java#L10"

    def test_absolute_windows_path_local_path_mismatch_falls_back(self):
        # local_path doesn't match the file prefix → falls back to lstrip("/")
        url = _build_github_url(
            REPO_URL,
            r"e:\temp\123456\src\app\Foo.java",
            5,
            local_path=r"e:\other\path",
        )
        assert url is not None
        assert "e:" not in url  # drive letter stripped
        assert url.endswith("#L5")

    def test_absolute_windows_path_no_local_path(self):
        # No local_path provided — graceful fallback, no drive letter in URL
        url = _build_github_url(
            REPO_URL,
            r"e:\temp\123456\src\app\Foo.java",
            7,
        )
        assert url is not None
        assert "e:" not in url
        assert url.endswith("#L7")

    def test_missing_repo_url_returns_none(self):
        assert _build_github_url(None, "src/Foo.java", 1) is None

    def test_empty_repo_url_returns_none(self):
        assert _build_github_url("", "src/Foo.java", 1) is None

    def test_empty_file_path_returns_none(self):
        assert _build_github_url(REPO_URL, "", 1) is None

    def test_line_number_appended(self):
        url = _build_github_url(REPO_URL, "com/example/Bar.java", 99)
        assert url.endswith("#L99")
