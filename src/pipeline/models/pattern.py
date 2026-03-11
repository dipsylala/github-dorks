"""Pattern data model and YAML loader.

Pattern YAML files are organised under ``patterns/<language>/cwe-<id>.yaml``.
Each file carries top-level ``language``, ``cwe_id``, and ``cwe_name`` metadata
that is injected into every Pattern record so callers can filter by language or
CWE without inspecting the file path.

Example file structure::

    language: python
    cwe_id: "CWE-78"
    cwe_name: "OS Command Injection"
    patterns:
      - id: cmd_python_os_system
        name: Python os.system()
        regex: '\\bos\\.system\\s*\\('
        vulnerability_type: command_injection
        severity_score: 9
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Fields every pattern entry must supply.
_REQUIRED_FIELDS = {"id", "name", "regex", "vulnerability_type", "severity_score"}

# Fields injected at the file level; stripped before passing to the dataclass
# constructor so unexpected keyword arguments don't cause a TypeError.
_FILE_LEVEL_FIELDS = {"language", "cwe_id", "cwe_name"}

# All fields accepted by the Pattern dataclass constructor.
_PATTERN_FIELDS = {
    "id", "name", "regex", "vulnerability_type", "severity_score",
    "language", "cwe", "cwe_name",
}


@dataclass
class Pattern:
    id: str
    name: str
    regex: str
    vulnerability_type: str
    severity_score: int
    language: str = ""
    cwe: str = ""       # e.g. "CWE-78"
    cwe_name: str = ""  # e.g. "OS Command Injection"
    _compiled: re.Pattern[str] | None = field(default=None, init=False, repr=False)

    def compile(self) -> re.Pattern[str]:
        """Return the compiled regex for this pattern, caching on first call.

        Raises ``re.error`` if the regex string is invalid.
        """
        if self._compiled is None:
            self._compiled = re.compile(self.regex)
        return self._compiled

    def is_valid(self) -> bool:
        """Return ``True`` if the regex compiles without error."""
        try:
            self.compile()
            return True
        except re.error:
            return False


def load_patterns(patterns_dir: str | Path) -> list[Pattern]:
    """Recursively load all ``*.yaml`` pattern files under *patterns_dir*.

    Each YAML file must have the structure shown in the module docstring.
    Per-file ``language``, ``cwe_id``, and ``cwe_name`` are injected into
    every child pattern entry.

    Invalid patterns (missing required fields, bad regex, wrong types) are
    logged as warnings and skipped rather than raising.  The function always
    returns a list — even an empty one — so the pipeline can continue.

    Raises ``FileNotFoundError`` if *patterns_dir* does not exist.
    """
    directory = Path(patterns_dir)
    if not directory.is_dir():
        raise FileNotFoundError(
            f"Pattern directory not found: {directory.resolve()}"
        )

    patterns: list[Pattern] = []
    files_loaded = 0
    files_skipped = 0

    for yaml_file in sorted(directory.rglob("*.yaml")):
        loaded, skipped = _load_file(yaml_file, patterns)
        files_loaded += 1
        files_skipped += skipped

    logger.info(
        "load_patterns dir=%s files=%d patterns=%d skipped=%d",
        directory,
        files_loaded,
        len(patterns),
        files_skipped,
    )
    return patterns


# ------------------------------------------------------------------ #
# Private helpers
# ------------------------------------------------------------------ #

def _load_file(
    yaml_file: Path,
    out: list[Pattern],
) -> tuple[int, int]:
    """Parse one YAML file and append valid patterns to *out*.

    Returns ``(loaded_count, skipped_count)``.
    """
    try:
        raw: Any = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("pattern_file_error file=%s error=%s", yaml_file, exc)
        return 0, 0

    if not isinstance(raw, dict):
        logger.warning("pattern_file_invalid file=%s reason=not_a_mapping", yaml_file)
        return 0, 0

    file_language: str = str(raw.get("language") or "")
    file_cwe: str = str(raw.get("cwe_id") or "")
    file_cwe_name: str = str(raw.get("cwe_name") or "")

    entries: list[Any] = raw.get("patterns") or []
    if not isinstance(entries, list):
        logger.warning(
            "pattern_file_invalid file=%s reason=patterns_not_a_list", yaml_file
        )
        return 0, 0

    loaded = skipped = 0
    for entry in entries:
        pattern = _parse_entry(
            entry,
            file_language=file_language,
            file_cwe=file_cwe,
            file_cwe_name=file_cwe_name,
            source_file=yaml_file,
        )
        if pattern is None:
            skipped += 1
        else:
            out.append(pattern)
            loaded += 1

    return loaded, skipped


def _parse_entry(
    entry: Any,
    *,
    file_language: str,
    file_cwe: str,
    file_cwe_name: str,
    source_file: Path,
) -> Pattern | None:
    """Validate and construct a single :class:`Pattern` from a raw dict.

    Returns ``None`` and logs a warning on any validation failure.
    """
    if not isinstance(entry, dict):
        logger.warning(
            "pattern_invalid file=%s reason=entry_not_a_mapping entry=%r",
            source_file,
            entry,
        )
        return None

    # Check required fields.
    missing = _REQUIRED_FIELDS - entry.keys()
    if missing:
        logger.warning(
            "pattern_invalid file=%s id=%r reason=missing_fields fields=%s",
            source_file,
            entry.get("id", "<unknown>"),
            sorted(missing),
        )
        return None

    # Inject file-level metadata (do not override if already present per-entry).
    entry.setdefault("language", file_language)
    entry.setdefault("cwe", file_cwe)
    entry.setdefault("cwe_name", file_cwe_name)

    # Strip unknown keys so the dataclass constructor doesn't raise TypeError.
    cleaned = {k: v for k, v in entry.items() if k in _PATTERN_FIELDS}

    # Coerce severity_score to int.
    try:
        cleaned["severity_score"] = int(cleaned["severity_score"])
    except (TypeError, ValueError):
        logger.warning(
            "pattern_invalid file=%s id=%r reason=bad_severity_score value=%r",
            source_file,
            cleaned.get("id"),
            cleaned.get("severity_score"),
        )
        return None

    try:
        pattern = Pattern(**cleaned)
    except TypeError as exc:
        logger.warning(
            "pattern_invalid file=%s id=%r reason=constructor_error error=%s",
            source_file,
            entry.get("id"),
            exc,
        )
        return None

    # Eagerly compile the regex so bad patterns surface at load time.
    try:
        pattern.compile()
    except re.error as exc:
        logger.warning(
            "pattern_invalid file=%s id=%r reason=bad_regex regex=%r error=%s",
            source_file,
            pattern.id,
            pattern.regex,
            exc,
        )
        return None

    return pattern
