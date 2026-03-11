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

## Stage design

Every stage extends `BaseStage`, which provides:

- `self._config` — `PipelineConfig`
- `self._db` — `DatabasePool`
- `self._logger` — stage-scoped structlog logger
- `_run_workers(queue, concurrency)` — generic `asyncio.Queue` worker pool

Stages that process items concurrently (cloner, scanner, enricher, framework-detector) push work onto a queue and call `_run_workers()`. Stages that operate on batches from the DB (filter, scorer, deduplicator) loop with `LIST … LIMIT n` queries and process the entire result set sequentially.

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

- `repositories.archived` — set from the GraphQL `isArchived` field; archived repos are rejected at the filter stage.
- `findings.matched_pattern_ids` — JSON text array. Populated by the deduplicator before it deletes duplicates; records every pattern that matched the same source location.
- `review_queue` view — joins findings + repositories, exposes `repository_id`, `pattern_id`, `matched_pattern_ids`, and `combined_score`. Used by `FindingDAO.list_top()` and the final report.

---

## GitHub API usage

`GitHubGraphQLClient` handles both:

- **GraphQL search** — cursor-paginated, fetches `isArchived` and `repositoryTopics` in the same query that returns repo metadata.
- **REST Contents API** — `GET /repos/{owner}/{repo}/contents/` for root-file listing (framework detection).
- **REST Topics API** — `GET /repos/{owner}/{repo}/topics` for topic-based framework detection.

Rate-limit handling: pauses until the `resetAt` timestamp when fewer than 50 points remain; retries HTTP 403/429 up to 3× honouring `Retry-After`.

GitHub caps search results at **1 000 per query**. To sweep larger result sets, add multiple `query_templates` in `config.yaml` that partition by star range:

```yaml
query_templates:
  - "stars:100..499 fork:false archived:false pushed:>{pushed_after} language:{language}"
  - "stars:500..2000 fork:false archived:false pushed:>{pushed_after} language:{language}"
  - "stars:>2000 fork:false archived:false pushed:>{pushed_after} language:{language}"
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
