# Agents

Two agent prompt files for Veracode findings triage:

| File | Purpose |
| --- | --- |
| `scan-repo.md` | Triages findings for a single repository, writes `triage_report.json` |
| `scan-all-repos.md` | Orchestrator — discovers all repos, spawns parallel `scan-repo` sub-agents, merges results |

Start with `scan-all-repos` for a full staging directory, or `scan-repo` for a single repo.

---

## Claude Code

Custom sub-agents live in `.claude/agents/` in your project (or `~/.claude/agents/` for personal use). Each file needs a YAML frontmatter block.

1. Create the directory:

   ```text
   mkdir .claude\agents
   ```

2. Copy the agent files and add frontmatter:

   **.claude/agents/scan-repo.md**

   ```yaml
   ---
   name: scan-repo
   description: Triages Veracode findings for a single repository and writes triage_report.json. Use when given a repo name and staging directory.
   ---

   ```text
   *(paste the rest of `scan-repo.md` content below the frontmatter)*

   **.claude/agents/scan-all-repos.md**

   ```yaml
   ---
   name: scan-all-repos
   description: Discovers all repos in a staging directory with high-severity Veracode findings, spawns parallel scan-repo sub-agents, and merges results into a single triage_report.json.
   ---
   ```

3. Invoke from the CLI:

   ```text
   claude
   > use the scan-all-repos agent on e:\staging
   ```

   Or list available agents with `/agents`.

> **Tip:** Add `isolation: worktree` to the frontmatter to give each sub-agent its own git worktree.

---

## VS Code (GitHub Copilot)

Copilot picks up `AGENTS.md` files placed anywhere in the repository — the nearest one in the directory tree takes precedence.

1. Copy the content of `scan-all-repos.md` (or `scan-repo.md`) into an `AGENTS.md` file at the repo root or in the relevant subdirectory.

2. Alternatively, place them as `.github/instructions/scan-repo.instructions.md` with an `applyTo` frontmatter to scope when they load:

   ```yaml
   ---
   applyTo: "**"
   ---
   ```

3. In VS Code Copilot Chat, the agent instructions are picked up automatically when Copilot is working in that directory context. You can also reference them explicitly by mentioning the task in the chat panel.

> **Note:** VS Code Copilot reads `AGENTS.md`, `CLAUDE.md`, or `GEMINI.md` from the repo root — pick whichever matches your primary tool, or maintain one file and symlink the others.

---

## OpenAI Codex

Codex reads `AGENTS.md` from the repo root and parent directories during a task.

1. Copy the desired agent content into `AGENTS.md` at the repo root:

   ```text
   copy agents\scan-all-repos.md AGENTS.md
   ```

2. Run Codex pointing at your staging directory:

   ```text
   codex "triage all repos in e:\staging"
   ```

For sub-agent orchestration, ensure `scan-repo.md` content is also accessible — either inline in `AGENTS.md` or as a separate file Codex can read via a file reference.

---

## Generic / bring-your-own-agent

The `.md` files are plain prompts with no tool-specific syntax. To use them with any agent framework:

- Pass the file content as the **system prompt** for an orchestrator session.
- For `scan-all-repos`, the agent will spawn child sessions using `scan-repo` — wire those up as sub-agent calls in your framework.
- Required inputs: `staging_dir` (absolute path), optional `batch_size` (default 5) and `repo_name` (for single-repo runs).
