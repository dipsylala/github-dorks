"""Tests for RepoFilter.should_reject()."""

from __future__ import annotations

import pytest

from pipeline.stages.repo_filter import RepoFilter


@pytest.fixture()
def stage(default_config):
    return RepoFilter(default_config, db=None)  # type: ignore[arg-type]


class TestShouldReject:
    def test_clean_repo_kept(self, stage, make_repo):
        assert stage.should_reject(make_repo()) is False

    # archived -------------------------------------------------------

    def test_archived_rejected(self, stage, make_repo):
        assert stage.should_reject(make_repo(archived=True)) is True

    def test_archived_overrides_everything(self, stage, make_repo):
        # Even a high-star repo is rejected if archived.
        assert stage.should_reject(make_repo(archived=True, stars=10_000)) is True

    # stars ----------------------------------------------------------

    def test_stars_below_min_rejected(self, stage, make_repo):
        # min_stars=100, so 99 should be rejected.
        assert stage.should_reject(make_repo(stars=99)) is True

    def test_stars_equal_min_kept(self, stage, make_repo):
        # Boundary: strict <, so exactly min_stars is kept.
        assert stage.should_reject(make_repo(stars=100)) is False

    def test_stars_above_min_kept(self, stage, make_repo):
        assert stage.should_reject(make_repo(stars=5000)) is False

    # size -----------------------------------------------------------

    def test_size_above_max_rejected(self, stage, make_repo):
        # max_repo_size_mb=200, so 201 should be rejected.
        assert stage.should_reject(make_repo(size_mb=201)) is True

    def test_size_equal_max_kept(self, stage, make_repo):
        # Boundary: strict >, so exactly max is kept.
        assert stage.should_reject(make_repo(size_mb=200)) is False

    # name tokens ----------------------------------------------------

    @pytest.mark.parametrize("name", [
        "my-tutorial",
        "django-example",
        "spring-demo",
        "practice-project",
        "sql-cheatsheet",
        "awesome-php",
    ])
    def test_noise_name_rejected(self, stage, make_repo, name):
        assert stage.should_reject(make_repo(name=name)) is True

    def test_name_token_case_insensitive(self, stage, make_repo):
        assert stage.should_reject(make_repo(name="My-Tutorial-App")) is True

    def test_clean_name_kept(self, stage, make_repo):
        assert stage.should_reject(make_repo(name="shopify-api")) is False
