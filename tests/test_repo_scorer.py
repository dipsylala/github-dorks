"""Tests for RepoScorer.compute_score()."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from pipeline.stages.repo_scorer import RepoScorer

_NOW = datetime.now(tz=timezone.utc)
_RECENT = _NOW - timedelta(days=30)      # 1 month ago — within 6-month window
_OLD = _NOW - timedelta(days=365)        # 1 year ago — outside window
_BOUNDARY = _NOW - timedelta(days=30 * 6)  # exactly at the 6-month edge


@pytest.fixture()
def stage(default_config):
    return RepoScorer(default_config, db=None)  # type: ignore[arg-type]


class TestComputeScore:
    # stars ----------------------------------------------------------

    def test_zero_stars(self, stage, make_repo):
        assert stage.compute_score(make_repo(stars=0, last_push=_OLD)) == 0

    def test_stars_first_tier(self, stage, make_repo):
        # 501 → +5 only
        score = stage.compute_score(make_repo(stars=501, last_push=_OLD))
        assert score == 5

    def test_stars_first_tier_boundary(self, stage, make_repo):
        # Exactly 500 — strict >, so no bonus
        score = stage.compute_score(make_repo(stars=500, last_push=_OLD))
        assert score == 0

    def test_stars_second_tier(self, stage, make_repo):
        # 2001 → +5 +10 = +15
        score = stage.compute_score(make_repo(stars=2001, last_push=_OLD))
        assert score == 15

    def test_stars_second_tier_boundary(self, stage, make_repo):
        # Exactly 2000 — strict >, so only first tier applies
        score = stage.compute_score(make_repo(stars=2000, last_push=_OLD))
        assert score == 5

    # recency --------------------------------------------------------

    def test_recent_push_adds_bonus(self, stage, make_repo):
        score = stage.compute_score(make_repo(stars=0, last_push=_RECENT))
        assert score == 4

    def test_old_push_no_bonus(self, stage, make_repo):
        score = stage.compute_score(make_repo(stars=0, last_push=_OLD))
        assert score == 0

    def test_naive_datetime_handled(self, stage, make_repo):
        # Naive datetimes (no tzinfo) should not raise; use dynamic "recent" date.
        naive = datetime.now().replace(tzinfo=None) - timedelta(days=30)  # 1 month ago, no tz
        score = stage.compute_score(make_repo(stars=0, last_push=naive))
        assert score == 4

    # framework ------------------------------------------------------

    def test_framework_detected_adds_bonus(self, stage, make_repo):
        score = stage.compute_score(make_repo(stars=0, last_push=_OLD, framework="django"))
        assert score == 8

    def test_framework_none_no_bonus(self, stage, make_repo):
        score = stage.compute_score(make_repo(stars=0, last_push=_OLD, framework=None))
        assert score == 0

    def test_framework_empty_string_no_bonus(self, stage, make_repo):
        # "" is the sentinel for "detected but no framework" — should not award +8.
        score = stage.compute_score(make_repo(stars=0, last_push=_OLD, framework=""))
        assert score == 0

    # controllers dir ------------------------------------------------

    def test_controllers_dir_adds_bonus(self, stage, make_repo):
        score = stage.compute_score(
            make_repo(stars=0, last_push=_OLD), has_controllers_dir=True
        )
        assert score == 6

    def test_controllers_dir_false_no_bonus(self, stage, make_repo):
        score = stage.compute_score(
            make_repo(stars=0, last_push=_OLD), has_controllers_dir=False
        )
        assert score == 0

    # cumulative maximum ---------------------------------------------

    def test_all_bonuses_cumulative(self, stage, make_repo):
        # 2001 stars (15) + recent push (4) + framework (8) + controllers (6) = 33
        score = stage.compute_score(
            make_repo(stars=2001, last_push=_RECENT, framework="laravel"),
            has_controllers_dir=True,
        )
        assert score == 33
