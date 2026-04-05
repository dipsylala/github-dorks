# Veracode Multi-Repo Triage Orchestrator

## Goal

Discover all repositories in the staging directory that contain relevant high-severity Veracode findings, spawn parallel `scan-repo` sub-agents to assess each one, and merge their individual reports into a single `triage_report.json` in the staging root.

---

## Inputs

- **`staging_dir`** — absolute path to the staging root (default: `e:\staging`).
- **`batch_size`** — number of `scan-repo` sub-agents to run in parallel per batch (default: `5`). Tune down if context becomes too large.
- **`high_severity_summary`** — optional path to override the summary file (default: `<staging_dir>\high_severity_summary.json`).

---

## Relevant CWEs

Only assess findings where `cwe_id` is one of: `73`, `78`, `80`, `89`, `327`, `502`, `611`, `918`.

---

## Step 1 — Discover repos

Read `<staging_dir>\high_severity_summary.json`. This file is a JSON object keyed by repo name; each value has a `findings` array.

Build a **target list**: repos where at least one finding has a `cwe_id` that is in the relevant CWE set above.

Print: `Found N repo(s) to assess: <comma-separated list>`.

If the summary file does not exist, fall back to globbing `<staging_dir>/*/.veracode-packaging/filtered_veracode-auto*.json` and use the directory names as the repo list.

---

## Step 2 — Skip already-done repos (resume support)

Before spawning sub-agents, check which repos already have a `<staging_dir>/<repo_name>/triage_report.json`. Skip those and print: `Skipping N already-assessed repo(s)`.

---

## Step 2b — Pre-enrich pending repos

For each repo in the target list that does **not** yet have a `triage_report.json`, the `vuln-scan` pipeline automatically generates `.veracode-packaging/combined_results.json` during scanning. This file contains filtered, sorted, capped, and source-enriched findings and dramatically reduces the number of LLM calls each `scan-repo` sub-agent needs to make.

If a repo's `combined_results.json` is missing (e.g. scans were run without the current pipeline version), sub-agents will fall back to raw JSON reading automatically.

---

## Step 3 — Spawn sub-agents in parallel batches

Split the remaining target repos into batches of `batch_size`. For each batch:

1. Spawn one `scan-repo` sub-agent **per repo in the batch**, all in parallel.
2. Pass each sub-agent a prompt that includes:
   - `repo_name`: the repo folder name.
   - `staging_dir`: the absolute staging path.
3. Wait for all sub-agents in the batch to finish before starting the next batch.
4. After each batch completes, print a progress line: `Batch M/N done — repos: <list>`.

### Sub-agent prompt template

Use this as the prompt for each `scan-repo` invocation:

```
Assess the repository "{{repo_name}}" located at {{staging_dir}}\{{repo_name}}.

staging_dir: {{staging_dir}}
repo_name: {{repo_name}}
```

---

## Step 4 — Merge results

After all batches complete:

1. For each assessed repo, read `<staging_dir>/<repo_name>/triage_report.json`.
2. Concatenate all arrays into one flat list.
3. Sort the merged list by:
   - `severity` descending (5 → 4)
   - then by verdict weight descending: `exploitable` (5) > `likely_exploitable` (4) > `needs_review` (3) > `unlikely_exploitable` (2) > `false_positive` (1)
4. Write the merged list to `<staging_dir>\triage_report.json`.
5. Print a summary:

```
=== Triage complete ===
Repos assessed : N
Total findings : M
  exploitable         : X
  likely_exploitable  : X
  needs_review        : X
  unlikely_exploitable: X
  false_positive      : X
Report written to: <staging_dir>\triage_report.json
```

---

## Error handling

- If a `scan-repo` sub-agent fails or produces malformed JSON, log a warning: `[WARN] <repo_name>: sub-agent failed — skipping` and continue.
- If a per-repo `triage_report.json` exists but is empty array `[]`, still include it in the merge (contributes nothing) and note the repo in the summary as `assessed (0 findings)`.
- Do not abort the entire run because of a single repo failure.
