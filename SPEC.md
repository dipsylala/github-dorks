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
min_stars: 100
max_repo_size_mb: 200
clone_depth: 1

languages:
  - php
  - javascript
  - python
  - java
  - csharp

worker_pools:
  clone_workers: 8
  scan_workers: 16

ignored_paths:
  - node_modules
  - vendor
  - dist
  - build
  - target
  - migrations
```

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
  "score": "int"
}
```

---

### LocalRepository

```json
{
  "repository_id": "string",
  "local_path": "string",
  "clone_timestamp": "datetime"
}
```

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
  "score": "int"
}
```

`matched_pattern_ids` is populated by the deduplicator — it aggregates the IDs of every pattern that matched the same `(repository_id, file_path, line_number)` location before duplicates are removed.

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

Query filters:

```text
stars:>100
fork:false
archived:false
pushed:>2023-01-01
```

Languages targeted:

```text
php
javascript
python
java
csharp
```

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

---

### 8.3 framework-detector

Detect web frameworks by scanning repository root files and GitHub topic tags.
Uses a concurrent worker pool (`enrichment_workers`) for API calls.
Both root-file names and topic strings are matched against framework indicators.

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

Assign repository priority scores.

Example scoring:

| Condition                     | Score |
| ----------------------------- | ----- |
| stars > 500                   | +5    |
| stars > 2000                  | +10   |
| recent commits (< 6 months)   | +4    |
| framework detected            | +8    |
| controllers directory present | +6    |

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

---

## 9. Pattern Packs

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
repositories       — includes: archived (int, 0/1)
local_repositories
patterns
findings           — includes: matched_pattern_ids (JSON text array)
```

Indexes:

```text
idx_findings_repository_id
idx_findings_score
idx_findings_pattern_id
idx_repositories_score
idx_repositories_language
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
