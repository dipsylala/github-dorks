# SPEC.md - GitHub Vulnerability Hunting Pipeline (LLM-Oriented Specification)

## 1. Overview

This document specifies a system for automatically discovering, cloning, scanning, and prioritizing potential vulnerabilities in public GitHub repositories.

The system is designed to:

* Scan large numbers of repositories efficiently
* Prioritize repositories likely to contain real web applications
* Detect high-impact vulnerability patterns using regex-based scanning
* Produce a ranked list of findings for manual review

This specification is structured to allow **Large Language Models (LLMs)** to generate implementation code reliably.

The system is intended to support scanning **10,000–100,000 repositories**.

---

## 2. System Goals

Primary goals:

1. Discover repositories likely to contain real web applications.
2. Clone repositories locally for fast scanning.
3. Detect potential vulnerabilities using regex pattern packs.
4. Rank findings by likelihood and impact.
5. Store results for manual review.

Target vulnerabilities include:

* Command Injection
* Deserialization vulnerabilities
* File inclusion / path traversal
* SQL injection
* SSRF
* XSS (lower priority)

---

## 3. Non-Goals

The system does **not attempt full static analysis**.

Not supported:

* Full taint tracking
* Multi-file data flow analysis
* Automatic vulnerability verification
* Exploit generation

The pipeline functions as **high-speed triage**, not vulnerability confirmation.

---

## 4. System Architecture

The system consists of the following components:

```text
repo-discovery
repo-filter
framework-detector
repo-scorer
repo-cloner
scanner
result-enricher
deduplicator
result-scorer
review-queue
```

High-level flow:

```text
GitHub API
   ↓
repo-discovery
   ↓
repo-filter
   ↓
framework-detector
   ↓
repo-scorer
   ↓
repo-cloner
   ↓
scanner
   ↓
result-enricher
   ↓
result-scorer   ← scored before dedup so the highest-scored duplicate is kept
   ↓
deduplicator
   ↓
review-queue
```

---

## 5. Execution Model

The pipeline runs as a **worker-based asynchronous system**.

Suggested worker pools:

```text
clone_workers: 8
scan_workers: 16
enrichment_workers: 8
```

Each stage reads from and writes to the database queue.

Stages can run concurrently.

The `framework-detector` stage uses the `enrichment_workers` pool for concurrent API calls.

---

## 6. Configuration

Example configuration file:

```yaml
scanning:
  min_stars: 100
  max_repo_size_mb: 200
  clone_depth: 1
  pushed_after: "2023-01-01"   # lower bound for pushed date
  pushed_before: "2024-01-01" # optional upper bound; omit for open-ended

  languages:
    - php
    - javascript
    - python
    - java
    - csharp

  query_templates:
    - "stars:>{min_stars} fork:false archived:false {pushed} language:{language}"

  ignored_paths:
    - node_modules
    - vendor
    - dist
    - build
    - target
    - migrations

worker_pools:
  clone_workers: 8
  scan_workers: 16
  enrichment_workers: 8
```

The `GITHUB_TOKEN` environment variable is always used for the API token; it is never stored in the config file.

---

## 7. Data Models

### Repository

```json
{
  "id": "string",
  "name": "string",
  "url": "string",
  "stars": "int",
  "language": "string",
  "last_push": "datetime",
  "size_mb": "int",
  "archived": "bool",
  "framework": "string|null",
  "score": "int",
  "filtered": "int",
  "scored": "int",
  "framework_detected": "int"
}
```

`filtered` is `0` until the repo-filter stage processes the repository. Repos that pass are set to `1`; rejected repos are deleted. All stages after `repo-filter` only query rows where `filtered = 1`.

`scored` is `0` until the repo-scorer stage processes the repository. Once scored it is set to `1`, preventing re-scoring on subsequent runs regardless of the computed `score` value.

`framework_detected` is `0` until the framework-detector stage processes the repository. Set to `1` alongside the `framework` write (including when no framework is found — the empty-string sentinel is no longer needed to prevent re-processing).

---

### LocalRepository

```json
{
  "repository_id": "string",
  "local_path": "string",
  "clone_timestamp": "datetime",
  "scanned": "int"
}
```

`scanned` is `0` until the scanner stage processes the repository. Set to `1` after all patterns have been run against it, preventing duplicate findings on subsequent runs.

---

### Finding

```json
{
  "id": "string",
  "repository_id": "string",
  "file_path": "string",
  "line_number": "int",
  "pattern_id": "string",
  "vulnerability_type": "string",
  "snippet": "string",
  "matched_pattern_ids": "list[string]",
  "score": "int",
  "enriched": "int",
  "finding_scored": "int"
}
```

`matched_pattern_ids` is populated by the deduplicator — it aggregates the IDs of every pattern that matched the same `(repository_id, file_path, line_number)` location before duplicates are removed.

`enriched` is `0` until the result-enricher processes the finding. Set to `1` after the snippet write (even when no context lines are available), so findings whose clone has been deleted are not re-queued indefinitely.

`finding_scored` is `0` until the result-scorer processes the finding. Set to `1` alongside the score write.

---

### Pattern

```json
{
  "id": "string",
  "name": "string",
  "regex": "string",
  "vulnerability_type": "string",
  "severity_score": "int",
  "language": "string",
  "cwe": "string",
  "cwe_name": "string"
}
```

---

## 8. Stage Specifications

### 8.1 repo-discovery

Purpose:

Discover candidate repositories using the GitHub API.

Query templates are configurable in `config.yaml` under `scanning.query_templates`. Each template supports these placeholders:

```text
{language}      — substituted from scanning.languages
{min_stars}     — substituted from scanning.min_stars
{pushed_after}  — substituted from scanning.pushed_after
{pushed_before} — substituted from scanning.pushed_before (empty string when unset)
{pushed}        — computed qualifier: pushed:>AFTER when only pushed_after is set,
                  or pushed:AFTER..BEFORE when both are set
```

Default query template:

```text
stars:>{min_stars} fork:false archived:false {pushed} language:{language}
```

Languages targeted:

```text
php
javascript
python
java
csharp
```

GitHub caps search results at **1,000 per query**. The stage automatically bisects the date window in half when a query exceeds 1,000 results, recursing until every leaf fits within the cap or the window is reduced to a single day (at which point the 1,000-result cap is accepted and logged as a warning). The check uses a lightweight `count_repositories` probe (1-node request) before committing to full pagination.

On conflict (same repository id), only mutable discovery fields (`name`, `url`, `stars`, `language`, `last_push`, `size_mb`, `archived`) are updated. `score`, `framework`, and `filtered` are never reset by re-discovery.

Output:

List of `Repository` records stored in the database.

---

### 8.2 repo-filter

Remove repositories that are unlikely to contain useful targets.

Reject if:

```text
stars < min_stars
repo_size > max_repo_size
archived = true
```

Reject repository names containing:

```text
tutorial
example
demo
practice
cheatsheet
awesome-
```

Rejected repositories are deleted (cascading to findings and local_repositories). Kept repositories are marked `filtered = 1` in the database. All subsequent stages only query repositories with `filtered = 1`.

---

### 8.3 framework-detector

Detect web frameworks by scanning repository root files and GitHub topic tags.
Uses a concurrent worker pool (`enrichment_workers`) for API calls.
Both root-file names and topic strings are matched against framework indicators.
Only operates on repositories with `filtered = 1 AND framework_detected = 0`.

Framework indicators:

#### PHP

```text
composer.json
artisan
laravel
symfony
```

#### Node

```text
express
koa
fastify
nestjs
```

#### Python

```text
django
flask
fastapi
```

#### Java

```text
spring-boot
spring-web
```

#### .NET

```text
Microsoft.AspNetCore
Startup.cs
Program.cs
```

Repositories without a framework may be skipped.

---

### 8.4 repo-scorer

Assign repository priority scores. Only operates on repositories with `filtered = 1` and `scored = 0`.

Scoring:

| Condition                     | Score |
| ----------------------------- | ----- |
| stars > 500                   | +5    |
| stars > 2000                  | +10   |
| recent commits (< 6 months)   | +4    |
| framework detected            | +8    |
| controllers directory present | +6    |

After writing the score, `scored` is set to `1`. This prevents re-scoring on subsequent runs regardless of the computed `score` value (a repo that matches none of the bonus conditions scores 0 and stays 0 legitimately).

Higher scores are scanned first.

The `controllers/` directory bonus is evaluated against the locally cloned path. On the initial run (before cloning) it contributes 0; it is applied correctly when the scorer runs after cloning on subsequent runs.

---

### 8.5 repo-cloner

Clone repositories locally.

Command:

```text
git clone --depth 1 <repo_url>
```

Cloning should use a worker pool.

Local repository path stored in `LocalRepository`.

---

### 8.6 scanner

Scan repository files using regex patterns.

Only operates on repositories with `scanned = 0` in `local_repositories`. After all patterns have been run against a repository, it is marked `scanned = 1`. This prevents duplicate findings if the stage is re-run against an existing database.

Recommended tool:

```text
ripgrep
```

Example command:

```text
rg --json --line-number --type <lang> -- "<regex>" <repo_path>
```

Ignore directories:

```text
node_modules
vendor
dist
build
target
```

File-type filtering uses ripgrep's `--type` flag (e.g. `--type php`, `--type py`) derived from the pattern's `language` field, restricting each scan to the relevant source file types and avoiding false positives in vendored or unrelated files.

---

### 8.7 result-enricher

Enhance findings with contextual data.

Only operates on findings with `enriched = 0`. After the snippet is written, `enriched` is set to `1` — even when no context lines are available (e.g. the clone has been deleted). This prevents findings whose clone is missing from being re-queued on every run.

Add:

```text
previous_3_lines
matched_line
next_3_lines
```

Store enriched snippet in `Finding`.

---

### 8.8 deduplicator

Remove duplicate findings.

**Runs after `result-scorer`** so that the winner selection (highest score) is deterministic.

Duplicate definition:

```text
repository_id + file_path + line_number
```

Before deleting duplicates, all matching pattern IDs for each location are aggregated into `Finding.matched_pattern_ids` (a JSON array stored in the winning row). The winner is the row with the highest `score`; ties are broken by keeping the smallest `id`.

---

### 8.9 result-scorer

Calculate final finding score.

Only operates on findings with `finding_scored = 0`. After writing the score, `finding_scored` is set to `1`.

Base vulnerability scores:

| Vulnerability     | Score |
| ----------------- | ----- |
| command injection | 10    |
| deserialization   | 9     |
| file inclusion    | 8     |
| SQL injection     | 7     |
| SSRF              | 6     |
| XSS               | 3     |

Add boosts:

```text
path contains controllers/ +3
path contains routes/ +3
repo score contribution
```

---

### 8.10 review-queue

Findings sorted by:

```text
finding_score + repository_score
```

Highest scores appear first for manual review.

The stage writes a structured JSON report to `config.report_path` (default: `findings_report.json`). The file contains a JSON array of serialised `Finding` objects ordered by combined score descending. Results are also queryable directly via the `review_queue` database view.

A companion file `repo_report.json` is written alongside `findings_report.json`. It contains one entry per repository, sorted by finding count descending, and is the input consumed by `vuln-export`.

---

## 8.11 vuln-export (post-pipeline utility)

A standalone command that copies reviewed repository clones to a staging directory for deeper static analysis or manual review. It is **not** part of the `vuln-pipeline` stage order and must be invoked explicitly by the user.

Input: `repo_report.json` (produced by the review-queue stage).

Output: a destination directory containing a copy of each selected repository clone.

Usage:

```text
vuln-export --dest /path/to/staging
vuln-export --report repo_report.json --dest /path/to/staging --min-score 7
vuln-export --report repo_report.json --dest /path/to/staging --min-findings 10
```

Flags:

```text
--report        Path to repo_report.json (default: repo_report.json)
--dest          Destination directory (required)
--min-score     Only export repos with top_score >= N (default: 0 = all)
--min-findings  Only export repos with finding_count >= N (default: 0 = all)
```

Each repository is copied to `<dest>/<repository_name>`. Name collisions are resolved by appending the repository ID. Repos whose local clone no longer exists on disk are reported and skipped. The tool exits with code 1 only when every entry was skipped.

---

## 8.12 vuln-scan (post-pipeline utility)

A standalone command that packages repository clones with the Veracode CLI and submits them for pipeline static analysis. It is **not** part of the `vuln-pipeline` stage order and must be invoked explicitly by the user.

Input: a staging directory produced by `vuln-export`, containing one subdirectory per repository.

Output: per-project package files and scan result JSON files written inside each project's `.veracode-packaging/` subdirectory, plus a `high_severity_summary.json` in the staging root.

Usage:

```text
vuln-scan --source /path/to/staging
vuln-scan --source /path/to/staging --package-dir .veracode-packaging
vuln-scan --source /path/to/staging --summary-only
```

Flags:

```text
--source        Directory containing the project folders to scan (required)
--package-dir   Subdirectory name (relative to each project) where packages and
                results are written (default: .veracode-packaging)
--summary-only  Skip packaging and scanning; regenerate high_severity_summary.json
                from existing filtered result files
```

For each project directory under `--source`, the tool:

1. Runs `veracode package -s . -a -o <package-dir>` to produce language-appropriate scan archives.
2. Runs `veracode static scan <package> --results-file <stem>.json --filtered-json-output-file filtered_<stem>.json` for every package produced.

Result files are written alongside their package inside `<project>/<package-dir>/`. Existing `.json` files are excluded from the package list to avoid re-scanning previous results.

After all scans complete, the tool globs `*/<package-dir>/filtered_veracode-auto*.json` across the staging directory and writes `high_severity_summary.json` containing all findings with severity 4 (High) or 5 (Very High), keyed by project name. A breakdown is printed to stdout.

The tool exits with code 1 if any individual scan command failed.

Pattern files are stored as YAML and organised by language and CWE:

```text
config/patterns/<language>/cwe-<id>.yaml
```

Example:

```text
config/patterns/php/cwe-78.yaml
config/patterns/python/cwe-89.yaml
config/patterns/javascript/cwe-22.yaml
```

Each YAML file carries top-level metadata injected into every pattern in the file:

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

Each pattern record therefore includes:

```text
id
name
regex
vulnerability_type
severity_score
language
cwe
cwe_name
```

Pattern packs are externally configurable and loaded at startup via `rglob`.

---

## 10. Storage

Database:

```text
SQLite (via aiosqlite)
```

SQLite is used with WAL journal mode and `PRAGMA foreign_keys = ON` enabled at connect time. Timestamps are stored as ISO-8601 `TEXT` strings.

Tables:

```text
repositories       — includes: archived (int, 0/1), filtered (int, 0/1), scored (int, 0/1), framework_detected (int, 0/1)
local_repositories — includes: scanned (int, 0/1)
patterns
findings           — includes: matched_pattern_ids (JSON text array), enriched (int, 0/1), finding_scored (int, 0/1)
```

Indexes:

```text
idx_findings_repository_id
idx_findings_score
idx_findings_pattern_id
idx_findings_unenriched         (partial: enriched = 0)
idx_findings_unscored           (partial: finding_scored = 0)
idx_repositories_score
idx_repositories_language
idx_repositories_unfiltered     (partial: filtered = 0)
idx_repositories_unscored       (partial: filtered = 1 AND scored = 0)
idx_repositories_undetected     (partial: filtered = 1 AND framework_detected = 0)
idx_local_repos_unscanned       (partial: scanned = 0)
```

A `review_queue` view joins `findings` and `repositories`, ordered by `finding_score + repo_score DESC`, for the final review stage. The view exposes `repository_id`, `pattern_id`, and `matched_pattern_ids` alongside the combined score columns.

---

## 11. Performance Expectations

Typical run:

```text
repositories scanned: 10,000
average repo size: 12MB
scan time: 1–2 hours
```

Ripgrep allows scanning hundreds of repositories per minute.

---

## 12. Error Handling

Failures must not stop the pipeline.

Handle:

```text
git clone failures
API rate limits
invalid repositories
regex errors
filesystem errors
```

Log all failures.

---

## 13. Security Considerations

The system scans untrusted repositories.

Precautions:

```text
disable code execution
scan repositories as data only
avoid running repository scripts
sandbox scanning environment
```

---

## 14. Future Enhancements

Possible improvements:

* AST scanning with Semgrep
* heuristic taint tracking
* framework-specific vulnerability packs
* automated PoC generation
* web UI for result browsing

---

## 15. Summary

This specification defines a scalable pipeline capable of scanning tens of thousands of repositories while prioritizing high-value vulnerability signals.

The system uses:

* repository filtering
* framework detection
* local scanning
* vulnerability scoring

to efficiently identify promising targets for manual security review.
