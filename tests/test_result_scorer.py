"""Tests for ResultScorer.compute_score()."""

from __future__ import annotations

import pytest

from pipeline.models.finding import Finding
from pipeline.stages.result_scorer import ResultScorer


@pytest.fixture()
def stage(default_config):
    return ResultScorer(default_config, db=None)  # type: ignore[arg-type]


def _finding(vulnerability_type: str = "xss", file_path: str = "src/app.php") -> Finding:
    return Finding(
        id="f1",
        repository_id="r1",
        file_path=file_path,
        line_number=10,
        pattern_id="p1",
        vulnerability_type=vulnerability_type,
        snippet="...",
    )


class TestComputeScore:
    # base vulnerability scores --------------------------------------

    @pytest.mark.parametrize("vuln_type,expected_base", [
        ("command_injection", 10),
        ("deserialization",    9),
        ("file_inclusion",     8),
        ("path_traversal",     8),
        ("sql_injection",      7),
        ("ssrf",               6),
        ("xss",                3),
    ])
    def test_base_scores(self, stage, vuln_type, expected_base):
        assert stage.compute_score(_finding(vuln_type)) == expected_base

    def test_unknown_vuln_type_base_zero(self, stage):
        assert stage.compute_score(_finding("novel_vuln")) == 0

    # path boosts ----------------------------------------------------

    def test_controllers_path_boost(self, stage):
        f = _finding(file_path="app/controllers/user.php")
        # xss base (3) + controllers boost (3) = 6
        assert stage.compute_score(f) == 6

    def test_routes_path_boost(self, stage):
        f = _finding(file_path="app/routes/api.py")
        assert stage.compute_score(f) == 6

    def test_both_path_boosts(self, stage):
        f = _finding(file_path="app/controllers/routes/check.php")
        # xss base (3) + controllers (3) + routes (3) = 9
        assert stage.compute_score(f) == 9

    def test_no_path_boost_for_unrelated_path(self, stage):
        f = _finding(file_path="src/models/user.py")
        assert stage.compute_score(f) == 3  # xss base only

    # repo score contribution ----------------------------------------

    def test_repo_score_floor_division(self, stage):
        f = _finding("xss")
        # repo_score=10 → contributes 1; 3 + 1 = 4
        assert stage.compute_score(f, repo_score=10) == 4

    def test_repo_score_below_ten_contributes_zero(self, stage):
        f = _finding("xss")
        assert stage.compute_score(f, repo_score=9) == 3

    def test_repo_score_zero(self, stage):
        assert stage.compute_score(_finding("xss"), repo_score=0) == 3

    def test_repo_score_large(self, stage):
        f = _finding("xss")
        # repo_score=105 → contributes 10; 3 + 10 = 13
        assert stage.compute_score(f, repo_score=105) == 13

    # combined -------------------------------------------------------

    def test_high_severity_with_path_and_repo(self, stage):
        f = _finding("command_injection", file_path="app/controllers/exec.php")
        # base(10) + controllers(3) + repo(33//10=3) = 16
        assert stage.compute_score(f, repo_score=33) == 16
