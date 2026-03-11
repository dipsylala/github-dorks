"""Tests for ResultEnricher.extract_snippet()."""

from __future__ import annotations

import pytest

from pipeline.stages.result_enricher import ResultEnricher


@pytest.fixture()
def stage(default_config):
    return ResultEnricher(default_config, db=None)  # type: ignore[arg-type]


@pytest.fixture()
def source_file(tmp_path):
    """Create a 10-line source file in a temp directory."""
    content = "\n".join(f"line {i}" for i in range(1, 11))  # lines 1-10
    f = tmp_path / "app.php"
    f.write_text(content, encoding="utf-8")
    return f


class TestExtractSnippet:
    def test_middle_line_returns_context_window(self, stage, source_file):
        # Line 5 — should get lines 2-8 (±3 context lines)
        snippet = stage.extract_snippet(str(source_file), 5)
        lines = snippet.splitlines()
        assert "line 5" in snippet
        assert len(lines) == 7

    def test_first_line_clips_at_start(self, stage, source_file):
        # Line 1 — can only go back to the beginning of file.
        snippet = stage.extract_snippet(str(source_file), 1)
        assert snippet.startswith("line 1")
        assert "line 4" in snippet

    def test_last_line_clips_at_end(self, stage, source_file):
        # Line 10 — can only go forward to end of file.
        snippet = stage.extract_snippet(str(source_file), 10)
        assert "line 10" in snippet
        assert "line 7" in snippet

    def test_nonexistent_file_returns_empty_string(self, stage, tmp_path):
        result = stage.extract_snippet(str(tmp_path / "missing.php"), 1)
        assert result == ""

    def test_line_number_one_based(self, stage, source_file):
        # Requesting line 1 should return "line 1" as first content line.
        snippet = stage.extract_snippet(str(source_file), 1)
        assert snippet.splitlines()[0] == "line 1"

    def test_returns_string(self, stage, source_file):
        result = stage.extract_snippet(str(source_file), 5)
        assert isinstance(result, str)

    def test_single_line_file(self, stage, tmp_path):
        f = tmp_path / "single.php"
        f.write_text("only line", encoding="utf-8")
        snippet = stage.extract_snippet(str(f), 1)
        assert snippet == "only line"
