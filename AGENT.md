# Veracode Findings Exploitability Assessment

## Goal

For every high-severity finding (severity ≥ 4) in a Veracode pipeline-scan staging directory, assess whether the flaw is genuinely exploitable, a theoretical risk requiring unusually difficult conditions, or a false positive. Produce a structured `triage_report.json` in the staging root.

---

## Inputs

- **Staging directory** — passed as the first argument, or `e:\staging` by default.
- **Finding files** — `filtered_veracode-auto*.json` inside each `<repo>/.veracode-packaging/` subdirectory.
- **Source code** — the cloned repo sits at `<staging>/<repo>/`. Use it to read any file referenced in a finding.

---

## Finding schema (relevant fields)

```text
issue_id          — unique ID within this scan
cwe_id            — CWE number (string, e.g. "89")
issue_type        — human-readable flaw category
severity          — 0–5 (4 = High, 5 = Very High)
exploit_level     — Veracode's own exploitability hint ("0"–"5")
display_text      — Veracode's description of the flaw class
files.source_file
  .file           — repo-relative path to the sink
  .line           — line number of the sink
  .function_name  — function containing the sink
stack_dumps.stack_dump[0].Frame[]
  .SourceFile     — file at this step in the data-flow path
  .SourceLine     — line number
  .VarNames       — tainted variable / expression at this step
  .FunctionName   — enclosing function
```

---

## Assessment process

For each finding with severity ≥ 4:

### 1. Read the sink

Read the source file at `<staging>/<repo>/<files.source_file.file>`, focusing on the reported line and ±20 lines of context. Identify:

- What operation is being performed (eval, query, exec, redirect, etc.)
- What variable is tainted at the sink

### 2. Trace the data flow

Walk the `stack_dumps` frames from last to first (source → sink order). For each frame, read the referenced source file and line if the file exists. Answer:

- Where does the tainted value originate? (HTTP input, file, database, config, constant)
- Is it user-controllable from outside the application?
- Does it pass through any sanitization, validation, or allow-listing?

### 3. Assess exploitability

Consider:

- **Reachability** — is this code path reachable in normal execution? Is it dead code, test code, or behind authentication?
- **Input control** — can an unauthenticated or low-privilege attacker supply the tainted value?
- **Sanitization** — is there effective escaping, parameterization, type coercion, or allow-listing that prevents exploitation?
- **Impact** — what is the real-world impact if exploited? (RCE, data exfiltration, privilege escalation, etc.)

### 4. Assign a verdict

| Verdict | Meaning |
| --- | --- |
| `exploitable` | Attacker-controlled input reaches a dangerous sink with no effective sanitization. High confidence. |
| `likely_exploitable` | Path appears reachable and unsanitized but some uncertainty remains (e.g. partial context, indirect input). |
| `needs_review` | Cannot determine exploitability from static context alone (e.g. sanitization happens in an unreadable dependency, or the data flow is opaque). |
| `unlikely_exploitable` | Sanitization or structural constraints make exploitation very difficult but not impossible. |
| `false_positive` | The tainted value is provably not attacker-controlled, or the sink is not actually dangerous in this context. |

---

## Output format

Write `triage_report.json` to the staging root. Structure:

```json
[
  {
    "repo": "FUEL-CMS",
    "issue_id": 1042,
    "cwe_id": "95",
    "issue_type": "Eval Injection",
    "severity": 5,
    "file": "fuel/modules/fuel/core/Loader.php",
    "line": 392,
    "verdict": "likely_exploitable",
    "confidence": "medium",
    "summary": "One-sentence summary of the flaw and taint path.",
    "reasoning": "Detailed explanation: where taint originates, what sanitization (if any) was observed, why the verdict was assigned.",
    "source_excerpt": "The 3–5 most relevant lines of source read during analysis."
  }
]
```

Each **repo subagent** writes its entries to `<staging>/<repo>/.veracode-packaging/triage_partial.json`.  
The **coordinator** merges all partials into `<staging>/triage_report.json`, sorted by severity descending then verdict weight (`exploitable` > `likely_exploitable` > `needs_review` > `unlikely_exploitable` > `false_positive`) descending.

---

## Sequential execution model

Work is split by repository. A **coordinator** discovers all repos that have findings and processes them one at a time using a **repo subagent** per repo. When all subagents finish, the coordinator merges their outputs into a single `triage_report.json`.

> **Note:** Repos are processed sequentially (not concurrently) to avoid resource exhaustion when many repos are present.

---

## Coordinator instructions

1. Glob `<staging>/*/.veracode-packaging/filtered_*.json` to discover the set of repos that have result files.
2. Print a one-line plan: `Found N repo(s) to assess: <list of repo names>`.
3. For each unique repo directory found, spawn a **repo subagent** one at a time (sequentially — finish one before starting the next).  
   Subagents are stateless — they do **not** read this file automatically. The coordinator must build each subagent's prompt by copying the following sections verbatim from this file:
   - **Finding schema**
   - **Assessment process** (all four steps)
   - **Verdict table**
   - **Output format** (the JSON schema)
   - **Repo subagent instructions**  
   Then append the concrete values:
   - `repo_name` — the directory name under staging.
   - `staging_dir` — the absolute path to the staging root.
4. After each subagent completes, print its one-line status before continuing to the next repo.

---

## Repo subagent instructions

Each subagent receives a single `repo_name` and operates independently inside `<staging>/<repo_name>/`.

1. Glob `<staging>/<repo_name>/.veracode-packaging/filtered_*.json` to find all result files for this repo.
2. Load all findings from those files. Skip any with `severity < 4`.
3. Deduplicate: if the same `cwe_id` + `file` + `line` combination appears in more than one result file, assess it once.
4. For each qualifying finding, perform the **Assessment process** above (steps 1–4).
5. If the source file cannot be read (missing, binary, minified), set verdict `needs_review` and note it in `reasoning`.
6. Write the results for this repo as `triage_partial.json` into `<staging>/<repo_name>/.veracode-packaging/`, using the same per-entry schema defined in **Output format** above.
7. Print a one-line status: `[<repo_name>] done — N finding(s) assessed` before finishing.
