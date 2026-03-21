# Design Notes

Architecture and implementation decisions for the GitHub Vulnerability Hunting Pipeline.

---

## Project structure

```text
src/pipeline/
├── __main__.py          # CLI entry point
├── pipeline.py          # Top-level orchestrator (Pipeline class)
├── config.py            # Dataclass config loaded from YAML
├── logging_config.py    # Structured logging setup
├── github/
│   └── client.py        # GitHub GraphQL + REST client
├── models/
│   ├── repository.py
│   ├── finding.py
│   └── pattern.py       # Pattern model + load_patterns()
├── db/
│   ├── connection.py    # DatabasePool (aiosqlite, WAL mode)
│   ├── schema.sql
│   └── repositories/    # DAOs: RepositoryDAO, FindingDAO, PatternDAO, LocalRepositoryDAO
└── stages/
    ├── base.py           # BaseStage + worker pool helpers
    ├── repo_discovery.py
    ├── repo_filter.py
    ├── framework_detector.py
    ├── repo_scorer.py
    ├── repo_cloner.py
    ├── scanner.py
    ├── result_enricher.py
    ├── result_scorer.py
    ├── deduplicator.py
    └── review_queue.py
```

Pattern files: `config/patterns/<language>/cwe-<id>.yaml`

---

## Technology choices

| Concern | Choice | Reason |
| --------- | -------- | -------- |
| Async runtime | `asyncio` | Python stdlib, fits I/O-heavy workload |
| HTTP client | `aiohttp` | Async, supports streaming and persistent sessions |
| Database | SQLite via `aiosqlite` | Zero-server, sufficient for 100k repo runs, portable |
| ORM | None — raw SQL + typed DAOs | Avoids schema migration overhead; SQL is explicit |
| File scanning | ripgrep subprocess | Fastest available regex scanner; `--json` output is stable |
| Config | YAML + dataclasses | Human-editable, no pydantic dependency |

---

## Language handling

Language values are stored in `repositories.language` as lowercase config keys (`php`, `javascript`, `python`, `java`, `csharp`), normalised from the GitHub API's `primaryLanguage.name` at storage time in `_node_to_repository`. GitHub returns mixed-case names like `"C#"` and `"JavaScript"`.

`repositories.language` is a plain `TEXT` column rather than a foreign key to a languages table. With only 5 distinct values across ~4,000 rows, a lookup table would add a join on every query for no practical benefit. Valid values are enforced at the CLI layer via `argparse choices` instead.

---

## Stage design

Every stage extends `BaseStage`, which provides:

- `self._config` — `PipelineConfig`
- `self._db` — `DatabasePool`
- `self._logger` — stage-scoped structlog logger
- `_run_workers(queue, concurrency)` — generic `asyncio.Queue` worker pool

Stages that process items concurrently (cloner, scanner, enricher, framework-detector) push work onto a queue and call `_run_workers()`. Stages that operate on batches from the DB (filter, scorer, deduplicator) loop with `LIST … LIMIT n` queries and process the entire result set sequentially.

`repo-filter` marks kept repositories `filtered = 1` after processing each batch and deletes rejected ones. `repo-scorer` queries only `filtered = 1 AND scored = 0` rows, writes the score, and stamps `scored = 1` atomically — so a repo that computes to score 0 (no bonus conditions met) still exits the queue correctly. `framework-detector` queries only `filtered = 1 AND framework_detected = 0` rows and stamps `framework_detected = 1` alongside the framework write. `scanner` queries `scanned = 0` rows in `local_repositories` and stamps `scanned = 1` after all patterns have been run for a given repo. `result-enricher` queries `enriched = 0` findings and stamps `enriched = 1` after the snippet write. `result-scorer` queries `finding_scored = 0` findings and stamps `finding_scored = 1` alongside the score write.

### Stage execution order

```text
discover → filter → detect → score-repos → clone →
scan → enrich → score-findings → dedup → queue
```

`score-findings` runs **before** `dedup` deliberately — the deduplicator keeps the highest-scored row per `(repository_id, file_path, line_number)` location, so scores must be populated first for that selection to be meaningful.

---

## Database

SQLite is opened in WAL mode with `PRAGMA foreign_keys = ON`. A single persistent connection is held by `DatabasePool` for the lifetime of the pipeline run.

Timestamps are stored as ISO-8601 `TEXT`. All booleans are stored as `INTEGER` (0/1).

### Schema highlights

- `repositories.filtered` — `0` until `repo-filter` processes a row. Repos that pass are set to `1`; rejected repos are deleted. All stages after `repo-filter` only query `filtered = 1` rows. This also prevents `score`, `framework`, and processing flags from being reset if the same repo is re-discovered by the bisecting discovery logic.
- `repositories.scored` — `0` until `repo-scorer` processes a row. Set to `1` alongside the score write. Allows a repo to legitimately hold `score = 0` (no bonus conditions met) without being picked up for re-scoring on subsequent runs.
- `repositories.framework_detected` — `0` until `framework-detector` processes a row. Set to `1` alongside the `framework` write (even when no framework is found), removing the need for the old `framework IS NULL` vs empty-string sentinel distinction.
- `local_repositories.scanned` — `0` until `scanner` finishes all patterns against a repo. Set to `1` atomically at the end of the scan run. Prevents duplicate findings if the stage is re-run on an existing database.
- `findings.enriched` — `0` until `result-enricher` writes the snippet. Set to `1` even when no context lines are available (e.g. clone deleted), so that finding is not re-queued on every subsequent run.
- `findings.finding_scored` — `0` until `result-scorer` writes the score. Set to `1` alongside the score so that `finding_scored = 0` is a reliable queue predicate.
- `findings.matched_pattern_ids` — JSON text array. Populated by the deduplicator before it deletes duplicates; records every pattern that matched the same source location.
- `review_queue` view — joins findings + repositories, exposes `repository_id`, `pattern_id`, `matched_pattern_ids`, and `combined_score`. Used by `FindingDAO.list_top()` and the final report.

---

## GitHub API usage

`GitHubGraphQLClient` handles both:

- **GraphQL search** — cursor-paginated, fetches `isArchived` and `repositoryTopics` in the same query that returns repo metadata.
- **REST Contents API** — `GET /repos/{owner}/{repo}/contents/` for root-file listing (framework detection).
- **REST Topics API** — `GET /repos/{owner}/{repo}/topics` for topic-based framework detection.

Rate-limit handling: pauses until the `resetAt` timestamp when fewer than 50 points remain; retries HTTP 403/429 up to 3× honouring `Retry-After`.

GitHub caps search results at **1,000 per query**. The discovery stage handles this automatically: before paginating, `count_repositories` fires a single cheap probe to read `repositoryCount`. If the count exceeds 1,000, the date window is bisected and each half is queried independently, recursing until every leaf fits within the cap or the window reaches a single day. The `{pushed}` placeholder in query templates resolves to the correct `pushed:AFTER..BEFORE` range for each bisected sub-window.

Query templates support these placeholders:

```text
{language}      — from scanning.languages
{min_stars}     — from scanning.min_stars
{pushed_after}  — from scanning.pushed_after
{pushed_before} — from scanning.pushed_before (empty string when unset)
{pushed}        — computed: pushed:>AFTER or pushed:AFTER..BEFORE
```

---

## Pattern loading

`load_patterns(patterns_dir)` walks `config/patterns/` with `rglob("*.yaml")`. For each file:

1. Top-level `language`, `cwe_id`, `cwe_name` are injected into every pattern entry.
2. Required fields are validated; unknown fields are stripped.
3. The regex is **eagerly compiled** at load time — patterns with invalid regex are skipped and logged, not fatal.

---

## Scoring

### Repository score

| Condition | Points |
| ----------- | -------- |
| stars > 500 | +5 |
| stars > 2000 | +10 (cumulative) |
| last push < 6 months ago | +4 |
| framework detected | +8 |
| `controllers/` directory present (post-clone) | +6 |

The `controllers/` bonus is 0 on the first run (repos not yet cloned). Running `score-repos` again after cloning picks it up.

### Finding score

```text
score = base_vulnerability_score
      + path_boost (controllers/ or routes/ → +3 each)
      + repo_score // 10
```

Base scores: `command_injection=10`, `deserialization=9`, `file_inclusion=8`, `path_traversal=8`, `sql_injection=7`, `ssrf=6`, `xss=3`.

---

## Security considerations

- The `GITHUB_TOKEN` is read exclusively from the environment; it is never written to disk.
- ripgrep treats the repo directory as **data only** — no code from scanned repos is imported or executed.
- The `--` flag in every ripgrep invocation prevents a crafted pattern regex from being interpreted as a CLI flag.
- Cloned repositories should be scanned inside a sandboxed environment (container, VM) in production. The pipeline itself does not enforce this.

---

## Adding a new stage

1. Create `src/pipeline/stages/my_stage.py` extending `BaseStage`.
2. Implement `async def run(self) -> None`.
3. If the stage processes items concurrently, implement `async def _process(self, item)` and call `self._run_workers(queue, concurrency)` from `run()`.
4. Add the stage to `STAGE_ORDER` and `self._stages` in `src/pipeline/pipeline.py`.
5. Update `SPEC.md` §4 and the relevant §8.x section.

---

## Adding new patterns

Create a YAML file under `config/patterns/<language>/cwe-<id>.yaml`:

```yaml
language: python
cwe_id: "CWE-78"
cwe_name: "OS Command Injection"
patterns:
  - id: py-os-system
    name: "os.system() with variable"
    regex: "os\\.system\\(.*\\$"
    vulnerability_type: command_injection
    severity_score: 10
```

No code changes needed — patterns are loaded at startup via `rglob`.

---

## `--force` flag

Each stage has exactly one flag column that acts as its processed queue predicate. This makes `--force` straightforward: reset the flag, then run the stage normally.

`Pipeline._reset_stage()` issues a single `UPDATE` per stage before the stage's `run()` is called:

| Stage | Reset SQL |
| ----- | --------- |
| `filter` | `UPDATE repositories SET filtered = 0` |
| `detect` | `UPDATE repositories SET framework_detected = 0` |
| `score-repos` | `UPDATE repositories SET scored = 0` |
| `scan` | `UPDATE local_repositories SET scanned = 0` |
| `enrich` | `UPDATE findings SET enriched = 0` |
| `score-findings` | `UPDATE findings SET finding_scored = 0` |

Stages with no persistent flag (`discover`, `clone`, `dedup`, `queue`) are silently no-ops.

Usage:

```text
# re-run just the scanner against already-cloned repos
vuln-pipeline --stage scan --force

# re-score findings from scratch
vuln-pipeline --stage score-findings --force

# re-run enrich and everything after it
vuln-pipeline --stage enrich --continue --force

# reset and re-run all stages in order
vuln-pipeline --force
```
