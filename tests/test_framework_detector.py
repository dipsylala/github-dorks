"""Tests for FrameworkDetector.detect_framework()."""

from __future__ import annotations

import pytest

from pipeline.stages.framework_detector import FrameworkDetector


@pytest.fixture()
def stage(default_config):
    return FrameworkDetector(default_config, db=None)  # type: ignore[arg-type]


class TestDetectFramework:
    # PHP ------------------------------------------------------------

    def test_artisan_detects_laravel(self, stage):
        assert stage.detect_framework(["artisan", "composer.json"], []) == "laravel"

    def test_laravel_in_filename_detects_laravel(self, stage):
        assert stage.detect_framework(["laravel-app"], []) == "laravel"

    def test_symfony_detected(self, stage):
        assert stage.detect_framework(["symfony.lock", "composer.json"], []) == "symfony"

    def test_composer_json_fallback_to_generic_php(self, stage):
        # No framework-specific indicator, but composer.json present → generic php
        assert stage.detect_framework(["composer.json", "index.php"], []) == "php"

    def test_laravel_takes_precedence_over_generic_php(self, stage):
        # artisan is a Laravel indicator; must match laravel before reaching php fallback.
        result = stage.detect_framework(["composer.json", "artisan"], [])
        assert result == "laravel"

    # Node -----------------------------------------------------------

    def test_express_detected(self, stage):
        assert stage.detect_framework(["express"], []) == "express"

    def test_nestjs_detected_via_at_prefix(self, stage):
        assert stage.detect_framework(["@nestjs"], []) == "nestjs"

    def test_fastify_detected(self, stage):
        assert stage.detect_framework(["fastify"], []) == "fastify"

    # Python ---------------------------------------------------------

    def test_django_detected(self, stage):
        assert stage.detect_framework(["django"], []) == "django"

    def test_flask_detected(self, stage):
        assert stage.detect_framework(["flask"], []) == "flask"

    def test_fastapi_detected(self, stage):
        assert stage.detect_framework(["fastapi"], []) == "fastapi"

    # Java / .NET ----------------------------------------------------

    def test_spring_detected(self, stage):
        assert stage.detect_framework(["spring-boot"], []) == "spring"

    def test_aspnetcore_detected_case_insensitive(self, stage):
        # Startup.cs is mixed-case in real repos.
        assert stage.detect_framework(["Startup.cs"], []) == "aspnetcore"

    def test_program_cs_detected(self, stage):
        assert stage.detect_framework(["Program.cs"], []) == "aspnetcore"

    # Topics ---------------------------------------------------------

    def test_topic_detects_framework(self, stage):
        assert stage.detect_framework([], ["nestjs", "api"]) == "nestjs"

    def test_topic_combined_with_root_files(self, stage):
        result = stage.detect_framework(["composer.json"], ["laravel"])
        assert result == "laravel"

    # No match -------------------------------------------------------

    def test_empty_inputs_returns_none(self, stage):
        assert stage.detect_framework([], []) is None

    def test_unrecognised_files_returns_none(self, stage):
        assert stage.detect_framework(["readme.md", "license"], []) is None
