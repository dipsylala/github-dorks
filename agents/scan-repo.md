# Veracode Findings Exploitability Assessment — Single Repo

## Goal

For every finding with a relevant CWE ID in **one** cloned repository, assess whether the flaw is genuinely exploitable, a theoretical risk requiring unusually difficult conditions, or a false positive. Write the results to `<staging>/<repo>/triage_report.json`.

---

## FIRST STEP — MANDATORY

**Before doing anything else**, check whether `<staging_dir>/<repo_name>/.veracode-packaging/combined_results.json` exists.

- **If it exists**: Read ONLY that file. Do NOT read any `filtered_veracode-auto*.json` files. Do NOT list the `.veracode-packaging` directory. The pre-enriched file is your complete input — it already contains the filtered, sorted, capped findings with source excerpts attached. Skip directly to the [Assessment process](#assessment-process) section.
- **If it does not exist**: Fall back to the raw loading process described under "Raw loading fallback" in the Assessment process section.

---

## Inputs

- **`repo_name`** — the folder name inside the staging directory (provided in the task context, e.g. `FUEL-CMS`).
- **`staging_dir`** — absolute path to the staging root (default: `e:\staging`, overridable in task context).
- **Pre-enriched input (preferred)** — `<staging_dir>/<repo_name>/.veracode-packaging/combined_results.json` (use this if present — see FIRST STEP above).
- **Finding files (fallback only)** — `filtered_veracode-auto*.json` inside `<staging_dir>/<repo_name>/.veracode-packaging/`.
- **Source code** — the cloned repo lives at `<staging_dir>/<repo_name>/`. Only read source files when the `source_excerpt` in `combined_results.json` is insufficient for a verdict.

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

### Pre-enriched fast path (preferred)

**Step 1: Use `read_file` to load `<staging_dir>/<repo_name>/.veracode-packaging/combined_results.json`.**

Do NOT run any terminal commands to read or parse Veracode JSON files. Do NOT use `Get-Content`, `ConvertFrom-Json`, `grep`, `rg`, or any shell/PowerShell command to inspect `.veracode-packaging/` files. The `combined_results.json` file is the sole input for this step.

The file contains:

- `findings` — the qualifying findings already filtered, sorted by severity desc / CWE asc, and capped at 60.
- `total_qualifying` / `capped` — if `capped` is `true`, include `"NOTE: Capped at 60 of <total_qualifying> total findings due to volume."` in the first entry's `reasoning`.
- Per finding: `issue_id`, `scan_file` (origin file — use to disambiguate duplicate IDs), `cwe_id`, `issue_type`, `severity`, `file`, `line`, `source_excerpt`.
- `source_excerpt` — the sink line marked with `>>>` plus ±8 lines of context. **This is your primary sink read.** Only call `read_file` on the actual source file if you genuinely need broader context beyond what the excerpt provides.

If `combined_results.json` does not exist at that path (e.g. scans were run without the current pipeline version), fall back to the raw process below.

### Raw loading fallback (only when combined_results.json is absent)

Use `read_file` to load each `<staging_dir>/<repo_name>/.veracode-packaging/filtered_veracode-auto*.json` file. Do not use terminal commands for this.

- Only assess findings where `cwe_id` is one of: `22`, `78`, `79`, `80`, `89`, `327`, `502`, `611`, `918`.
- Veracode can assign duplicate `issue_id` values across different scan files — treat findings from different files as distinct. The origin filename is the disambiguator.
- **If more than 60 qualifying findings remain**, assess the first 60 ordered by severity descending then cwe_id ascending, and include a note in the first entry's `reasoning` field: `"NOTE: Capped at 60 of N total findings due to volume."` Do not silently drop findings — always write the cap note.

For each qualifying finding:

### 1. Read the sink

Use the `source_excerpt` from `combined_results.json` as your starting point. Only call `read_file` on the actual source file if you need context beyond the ±8 lines already provided. Do not use terminal commands to read source files.

If using the raw fallback, use `read_file` on `<staging_dir>/<repo_name>/<files.source_file.file>`, focusing on the reported line and ±20 lines of context. Identify:

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

If the source file cannot be read (missing, binary, minified), set verdict `needs_review` and note it in `reasoning`.

---

## Output

Write results to `<staging_dir>/<repo_name>/triage_report.json`. Structure:

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

After writing the file, print a single status line: `[<repo_name>] done — N finding(s) assessed, written to <path>`.
