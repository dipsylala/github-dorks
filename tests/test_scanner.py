"""Tests for the ripgrep JSON output parser (_parse_rg_output)."""

from __future__ import annotations

import json

import pytest

from pipeline.models.pattern import Pattern
from pipeline.stages.scanner import _parse_rg_output


@pytest.fixture()
def pattern() -> Pattern:
    return Pattern(
        id="php-cmd-exec",
        name="exec with var",
        regex=r"exec\(\$",
        vulnerability_type="command_injection",
        severity_score=10,
        language="php",
    )


def _match_line(abs_path: str, line_number: int, text: str) -> bytes:
    obj = {
        "type": "match",
        "data": {
            "path": {"text": abs_path},
            "lines": {"text": text},
            "line_number": line_number,
            "absolute_offset": 0,
            "submatches": [],
        },
    }
    return json.dumps(obj).encode()


class TestParseRgOutput:
    def test_empty_bytes_returns_empty_list(self, pattern):
        assert _parse_rg_output(b"", repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1") == []

    def test_non_match_types_skipped(self, pattern):
        begin = json.dumps({"type": "begin", "data": {}}).encode()
        summary = json.dumps({"type": "summary", "data": {}}).encode()
        raw = b"\n".join([begin, summary])
        assert _parse_rg_output(raw, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1") == []

    def test_single_match_produces_finding(self, pattern):
        line = _match_line("/tmp/repos/1/src/app.php", 17, "exec($_GET['cmd']);\n")
        findings = _parse_rg_output(line, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert len(findings) == 1
        f = findings[0]
        assert f.repository_id == "r1"
        assert f.line_number == 17
        assert f.vulnerability_type == "command_injection"
        assert f.pattern_id == "php-cmd-exec"

    def test_path_relativized_when_starts_with_root(self, pattern):
        line = _match_line("/tmp/repos/1/src/app.php", 1, "code\n")
        findings = _parse_rg_output(line, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert findings[0].file_path == "src/app.php"

    def test_path_kept_as_is_when_not_under_root(self, pattern):
        line = _match_line("/other/path/file.php", 1, "code\n")
        findings = _parse_rg_output(line, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert findings[0].file_path == "/other/path/file.php"

    def test_repo_root_trailing_slash_normalised(self, pattern):
        # Whether root has trailing slash should not affect relativisation.
        line = _match_line("/tmp/repos/1/src/app.php", 1, "code\n")
        findings = _parse_rg_output(
            line, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1/"
        )
        assert findings[0].file_path == "src/app.php"

    def test_snippet_trailing_newline_stripped(self, pattern):
        line = _match_line("/tmp/repos/1/app.php", 1, "exec($_GET['cmd']);\n")
        findings = _parse_rg_output(line, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert not findings[0].snippet.endswith("\n")

    def test_malformed_json_line_skipped(self, pattern):
        bad = b"not valid json"
        good = _match_line("/tmp/repos/1/app.php", 1, "code\n")
        raw = b"\n".join([bad, good])
        findings = _parse_rg_output(raw, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert len(findings) == 1

    def test_multiple_matches_all_returned(self, pattern):
        lines = b"\n".join(
            _match_line(f"/tmp/repos/1/file{i}.php", i, f"code {i}\n")
            for i in range(5)
        )
        findings = _parse_rg_output(lines, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert len(findings) == 5

    def test_each_finding_has_unique_id(self, pattern):
        lines = b"\n".join(
            _match_line("/tmp/repos/1/app.php", i, f"line {i}\n")
            for i in range(3)
        )
        findings = _parse_rg_output(lines, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        ids = [f.id for f in findings]
        assert len(set(ids)) == 3

    def test_blank_lines_skipped(self, pattern):
        line = _match_line("/tmp/repos/1/app.php", 1, "code\n")
        raw = b"\n\n" + line + b"\n\n"
        findings = _parse_rg_output(raw, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")
        assert len(findings) == 1

    def test_deterministic_id_same_inputs_same_uuid(self, pattern):
        # Calling _parse_rg_output twice with identical input must produce
        # the same finding IDs — the UUID5 must be stable, not random.
        line = _match_line("/tmp/repos/1/src/app.php", 42, "exec(input);\n")
        raw = line
        ids_first  = [f.id for f in _parse_rg_output(raw, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")]
        ids_second = [f.id for f in _parse_rg_output(raw, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")]
        assert ids_first == ids_second

    def test_different_pattern_produces_different_id(self, pattern):
        # Changing only the pattern must produce a different finding ID.
        other = Pattern(
            id="other-pattern",
            name="other",
            regex=r"exec\(",
            vulnerability_type="command_injection",
            severity_score=5,
            language="php",
        )
        line = _match_line("/tmp/repos/1/app.php", 1, "code\n")
        id1 = _parse_rg_output(line, repository_id="r1", pattern=pattern, repo_root="/tmp/repos/1")[0].id
        id2 = _parse_rg_output(line, repository_id="r1", pattern=other, repo_root="/tmp/repos/1")[0].id
        assert id1 != id2
