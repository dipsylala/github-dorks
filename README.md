# GitHub Vulnerability Hunting Pipeline

An async Python pipeline that discovers, clones, and scans public GitHub repositories for potential vulnerabilities using regex pattern packs, then produces a ranked finding report for manual triage, or pushing into a SAST scanning pipeline.

**Supported languages:** PHP, JavaScript, Python, Java, C#

**Detected vulnerability classes:** Command injection, deserialization, file inclusion / path traversal, SQL injection, SSRF, XSS

Tremendous idea provided by Florian at [https://github.com/dub-flow/github-dorks/](https://github.com/dub-flow/github-dorks/)

---

## How it works

The pipeline runs ten stages in sequence:

```text
repo-discovery    → search GitHub for candidate repos via GraphQL (cursor-paginated)
repo-filter       → drop archived, too-small, or too-large repos
framework-detector → identify web frameworks via root files and repo topics
repo-scorer       → rank repos by stars, freshness, and detected framework
repo-cloner       → git clone --depth 1 into a local directory (120s timeout per repo)
scanner           → run ripgrep against every (repo, pattern) pair; 16 workers by default
result-enricher   → capture ±3 lines of source context around each match
result-scorer     → score each finding (vuln type + path boost + repo score / 10)
deduplicator      → collapse same-location matches; keep highest-scored, aggregate pattern IDs
review-queue      → write findings_report.json ordered by combined score (top 1000 by default)
```

Results are stored in a local SQLite database (`pipeline.db`) and exported to `findings_report.json`.

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- [ripgrep](https://github.com/BurntSushi/ripgrep#installation) (`rg` on PATH)
- git
- A GitHub personal access token with `public_repo` read scope

---

## Setup

```bash
# Clone the repo
git clone https://github.com/dipsylala/github-dorks
cd github-dorks

# Create a virtual environment and install dependencies
uv venv
uv pip install -e .

# Set your GitHub token
export GITHUB_TOKEN=ghp_your_token_here
```

---

## Configuration

Edit `config/config.yaml` to adjust scan targets:

```yaml
scanning:
  min_stars: 100          # ignore repos with fewer stars
  max_repo_size_mb: 200   # skip very large repos
  pushed_after: "2023-01-01"  # only recently active repos
  languages:
    - php
    - javascript
    - python
    - java
    - csharp
  clone_dir: /tmp/repos   # where repos are cloned locally
```

The GitHub token is read from the `GITHUB_TOKEN` environment variable and never stored in the config file.

---

## Running the pipeline

The `vuln-pipeline` command is the entry point defined in `pyproject.toml` and installed by `uv pip install -e .`. You can also run the pipeline directly without installing:

```bash
uv run python -m pipeline
```

**Full pipeline (all stages):**

```bash
uv run vuln-pipeline
# or without installing:
uv run python -m pipeline
```

**Single stage:**

```bash
uv run vuln-pipeline --stage discover
uv run vuln-pipeline --stage scan
uv run vuln-pipeline --stage queue
```

Available stages (in order): `discover`, `filter`, `detect`, `score-repos`, `clone`, `scan`, `enrich`, `score-findings`, `dedup`, `queue`

**Continue from a stage:**

Add `--continue` to run the specified stage and all subsequent ones. Useful for resuming mid-pipeline or for incremental language-by-language runs:

```bash
# Scan C# repos then automatically enrich, score, dedup, and queue
uv run vuln-pipeline --stage scan --language csharp --continue

# Resume from enrichment after a failed run
uv run vuln-pipeline --stage enrich --continue
```

**Filter by language:**

Pass `--language` to restrict any stage (or the full pipeline) to one language.
Valid values: `php`, `javascript`, `python`, `java`, `csharp`

> **Note:** Filtering is based on the repository's primary language as reported by GitHub. A C# repository may still contain JavaScript or Python files, so findings in the output are not guaranteed to be exclusively that language. For precise language filtering on the output, filter by `pattern_id` — all pattern IDs embed the language (e.g., `ssrf_python_*`, `deser_php_*`, `path_java_*`, `sqli_cs_*`).

```bash
# Scan only C# repositories and patterns
uv run vuln-pipeline --stage scan --language csharp

# Run the full pipeline for PHP only
uv run vuln-pipeline --language php

# Export a report limited to Python findings
uv run vuln-pipeline --stage queue --language python
```

**Custom config or verbosity:**

```bash
uv run vuln-pipeline --config path/to/config.yaml --log-level DEBUG
```

---

## Output

After the pipeline completes, `findings_report.json` contains a JSON array of findings ordered by `finding_score + repo_score` descending:

```json
[
  {
    "id": "...",
    "repository_id": "12345678",
    "file_path": "src/controllers/UserController.php",
    "line_number": 42,
    "pattern_id": "php-cmd-exec",
    "vulnerability_type": "command_injection",
    "snippet": "...exec($_GET['cmd'])...",
    "matched_pattern_ids": ["php-cmd-exec"],
    "score": 19
  }
]
```

The raw database (`pipeline.db`) can also be queried directly — the `review_queue` view joins findings with their parent repository scores.

---

## Pattern packs

Patterns live under `config/patterns/<language>/cwe-<id>.yaml`:

```text
config/patterns/php/cwe-78.yaml       OS Command Injection
config/patterns/python/cwe-89.yaml    SQL Injection
config/patterns/javascript/cwe-22.yaml  Path Traversal
...
```

Add new patterns by creating or editing YAML files in that tree. The pipeline loads all patterns at startup via `rglob`.

Example pattern entry:

```yaml
language: php
cwe_id: "CWE-78"
cwe_name: "OS Command Injection"
patterns:
  - id: php-cmd-exec
    name: "exec() with variable"
    regex: "exec\\(\\$"
    vulnerability_type: command_injection
    severity_score: 10
```

---

## Why not just use grep.app?

[grep.app](https://grep.app) is a code search engine that indexes public GitHub repos and supports regex search — essentially ripgrep-over-GitHub without cloning. It has an undocumented JSON API (`https://grep.app/api/search?q=...&regexp=true`) that could theoretically replace both the `discover` and `scan` stages.

In practice, cloning is better for this pipeline:

| Factor | grep.app | Clone + rg |
| --- | --- | --- |
| API stability | Undocumented, unofficial | GitHub API (official) |
| Rate limits | Aggressive | Controlled via token |
| Context window | ~1 line snippet | Full file (±N lines) |
| Multi-pattern | 1 pattern per request | All patterns in one pass |
| Framework detection | Not possible | Full `package.json`, `pom.xml` etc. |
| Result freshness | Cached (days old) | Current HEAD |
| Deduplication | Harder | Owned locally in SQLite |

**Where grep.app could help:** as an alternative `repo_discovery` source. GitHub's built-in code search has poor regex support; grep.app handles it better. As a future TODO, we could query grep.app to find candidate repos containing a pattern and then feed those repo URLs into the existing clone/scan pipeline — getting better discovery without sacrificing any of the downstream analysis.

---

## Development

See [docs/DESIGN.md](docs/DESIGN.md) for architecture details, design decisions, and contribution guidelines.

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Lint
uv run ruff check src/

# Type-check
uv run mypy src/

# Tests
uv run pytest
```
