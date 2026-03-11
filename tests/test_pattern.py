"""Tests for pipeline.models.pattern — Pattern dataclass and _parse_entry()."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pipeline.models.pattern import Pattern, _parse_entry

# A dummy Path used as the source_file argument (only used in log messages).
_SRC = Path("dummy.yaml")


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _valid_entry(**overrides) -> dict:
    """Return a minimal valid raw pattern dict, optionally overriding fields."""
    base = {
        "id": "test-1",
        "name": "Test pattern",
        "regex": r"\beval\s*\(",
        "vulnerability_type": "command_injection",
        "severity_score": 8,
    }
    base.update(overrides)
    return base


def _parse(entry, *, language="php", cwe="CWE-78", cwe_name="OS Command Injection"):
    return _parse_entry(
        entry,
        file_language=language,
        file_cwe=cwe,
        file_cwe_name=cwe_name,
        source_file=_SRC,
    )


# ------------------------------------------------------------------ #
# Pattern.compile() and Pattern.is_valid()
# ------------------------------------------------------------------ #

class TestPatternCompile:
    def test_valid_regex_returns_compiled(self):
        p = Pattern(id="x", name="x", regex=r"\bfoo\b",
                    vulnerability_type="xss", severity_score=3)
        result = p.compile()
        assert isinstance(result, re.Pattern)

    def test_compile_caches_on_second_call(self):
        p = Pattern(id="x", name="x", regex=r"\bfoo\b",
                    vulnerability_type="xss", severity_score=3)
        first = p.compile()
        second = p.compile()
        assert first is second

    def test_invalid_regex_raises(self):
        p = Pattern(id="x", name="x", regex="[",
                    vulnerability_type="xss", severity_score=3)
        with pytest.raises(re.error):
            p.compile()

    def test_is_valid_true_for_valid_regex(self):
        p = Pattern(id="x", name="x", regex=r"\bfoo\b",
                    vulnerability_type="xss", severity_score=3)
        assert p.is_valid() is True

    def test_is_valid_false_for_invalid_regex(self):
        p = Pattern(id="x", name="x", regex="[",
                    vulnerability_type="xss", severity_score=3)
        assert p.is_valid() is False

    def test_empty_regex_compiles(self):
        p = Pattern(id="x", name="x", regex="",
                    vulnerability_type="xss", severity_score=3)
        assert p.is_valid() is True


# ------------------------------------------------------------------ #
# _parse_entry()
# ------------------------------------------------------------------ #

class TestParseEntry:
    def test_valid_entry_returns_pattern(self):
        result = _parse(_valid_entry())
        assert isinstance(result, Pattern)
        assert result.id == "test-1"

    def test_missing_regex_returns_none(self):
        entry = _valid_entry()
        del entry["regex"]
        assert _parse(entry) is None

    def test_missing_severity_score_returns_none(self):
        entry = _valid_entry()
        del entry["severity_score"]
        assert _parse(entry) is None

    def test_missing_id_returns_none(self):
        entry = _valid_entry()
        del entry["id"]
        assert _parse(entry) is None

    def test_severity_score_string_coerced_to_int(self):
        result = _parse(_valid_entry(severity_score="9"))
        assert result is not None
        assert result.severity_score == 9

    def test_severity_score_bad_string_returns_none(self):
        assert _parse(_valid_entry(severity_score="bad")) is None

    def test_severity_score_none_returns_none(self):
        assert _parse(_valid_entry(severity_score=None)) is None

    def test_file_language_injected_when_absent(self):
        result = _parse(_valid_entry(), language="php")
        assert result is not None
        assert result.language == "php"

    def test_entry_language_not_overridden_by_file(self):
        result = _parse(_valid_entry(language="python"), language="php")
        assert result is not None
        assert result.language == "python"

    def test_file_cwe_injected(self):
        result = _parse(_valid_entry(), cwe="CWE-89", cwe_name="SQL Injection")
        assert result is not None
        assert result.cwe == "CWE-89"
        assert result.cwe_name == "SQL Injection"

    def test_unknown_keys_stripped(self):
        entry = _valid_entry(extra_unknown_field="should be removed")
        # Should not raise TypeError from unknown kwarg to Pattern constructor.
        result = _parse(entry)
        assert result is not None

    def test_invalid_regex_returns_none(self):
        assert _parse(_valid_entry(regex="[")) is None

    def test_entry_not_a_dict_returns_none(self):
        assert _parse("not a dict") is None
        assert _parse(42) is None
        assert _parse(None) is None

    def test_returned_pattern_regex_precompiled(self):
        result = _parse(_valid_entry())
        assert result is not None
        # _compiled should be populated by eager compile in _parse_entry.
        assert result._compiled is not None
