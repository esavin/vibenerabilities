# Guide — porting, performance, troubleshooting

## Requirements
`git`, `jq`, `opencode` on PATH. Optional `timeout` (per-run limits).

## Porting to a new project / language
The pipeline is language-agnostic. Per-project specifics live in two files you edit:
- `agent/project/project-conventions.md` — stack, path prefix, idiomatic dangerous APIs,
  area tags, commit-message style (which phrases signal security fixes).
- `vibenerabilities/config.json` — `source_root`, `source_branch`, …

`bootstrap.sh` auto-detects language/layout and fills these in as a starting point; correct
them if needed. Common `source_root` values:

| Project shape | source_root | path prefix in records |
| --- | --- | --- |
| Project cloned inside workspace | `someproject` (its folder name) | `someproject/...` |
| Single repo (workspace IS the repo) | `.` | `src/...`, `cmd/...` |
| Project outside workspace | absolute path | `<that path>/...` |

**Important:** unlike `vibedocing`, leave `commit_skip_regex` empty. The security pipeline
must inspect every commit. If you do set a regex (e.g. to skip pure `docs:` commits), be
aware you may miss security fixes disguised under those prefixes — verify with `--list`
first.

## The "giant initial commit"
Some projects start with one massive commit. At that commit the agent should:
1. Spot-check the obvious entry points and high-risk modules for clear pre-existing issues
   (hardcoded secrets, missing auth on entrypoints, SQL/HTML/command-injection patterns).
2. Record anything found as `Status: Introduced` (pre-existing in initial commit) or
   `Status: Open` if not yet fixed at HEAD.
3. Let later commits fill in more findings idempotently — re-runs refine, never duplicate.

To chunk a huge first pass, set `scope` in config to a subdirectory and run multiple passes.

## Detecting fixes retroactively (the "lookahead" requirement)
A vulnerability may be missed at the introducing commit but detected later when a fix
lands. This is handled automatically:

- At the fix commit, Pass B (backward analysis) fires.
- The agent uses `git -C <worktree> log -S "<removed-pattern>"`, `git log --diff-filter=A`,
  and `git blame` *at the parent of the fix commit* to locate where the dangerous code
  first appeared.
- It then writes (or updates) the record with both **Introduced in** (found via history)
  and **Fixed in** (this commit) filled.

If the dangerous code is present in the project's initial commit, the agent records it as
`pre-existing` and uses the initial commit as the introduction point.

## Multi-commit fixes
A single issue may be fixed across several commits (e.g. one commit adds the check,
another removes the dangerous API, a third tightens tests). The pipeline records **every**
fixing commit on the **same** record's `## Fixed in` block. Each fixing commit's agent:
1. Reads existing records first.
2. Matches the issue (same file/symbol/class).
3. Appends itself to `## Fixed in` — never creates a duplicate record.

The record's `## Status` stays `Open` until no more danger is present at HEAD; flips to
`Fixed` when the last fix commit lands.

## Performance / cost
- Because **every** commit is analyzed, large repos mean many agent calls. Use `--limit N`
  to bound a run; combine with automatic resume for overnight batches.
- `--dry-run` validates classification cheaply before real writes.
- Start `opencode serve` once and pass `--attach http://localhost:4096` (or `--serve`) to
  avoid per-run cold starts — big speedup on hundreds of commits.
- `run_timeout_seconds` (config) caps each agent call if `timeout` is available.
- `model` (config or `--model`) picks a cheaper/stronger model for the bulk walk. For
  security analysis prefer the strongest model you can afford — false negatives here are
  costly.
- For very large repos, consider scoping a first pass to high-risk directories (auth,
  crypto, input handlers, network) and a second pass to the rest.

## Restart after sync
The committed `agent/project/.vibenerabilities.json` holds the baseline. After `git pull`
in the project, run.sh analyzes only `baseline..HEAD`. `--reset-baseline` restarts from
zero.

## Auto-commit
When `auto_commit` is true (default) and not `--dry-run`/`--no-commit`, each analyzed
project commit with findings produces one workspace commit (`vulns(<project>): <subject>`).
A trailing baseline commit is added if the baseline advanced without a record change. The
workspace git identity defaults to `vibenerabilities <vibenerabilities@local>` (set in
config / by bootstrap).

## Runtime files (gitignored)
- `vibenerabilities/progress.json` — processed[] + counters (fast in-walk resume).
- `vibenerabilities/walk.log`, `vibenerabilities/logs/<sha>.log`,
  `vibenerabilities/verdicts/<sha>.txt`.
- `.vibe-trees/<short>/` — disposable worktrees.

## Troubleshooting
- **worktree add failed** — rerun (worktrees are force-removed first); or
  `git -C <source> worktree prune`.
- **Agent wrote no verdict** → recorded as `failed`; inspect `logs/<sha>.log`. Use
  `--stop-on-fail` to halt on the first one, or `--sha <sha> --dry-run` to test one commit.
- **`source_root … is not a git repository`** — fix `source_root` in `config.json`.
- **Command missing in TUI** — `run.sh --setup` (or just `run.sh`, which auto-installs)
  copies the command + skill into `.opencode/`.
- **Duplicate records** — the agent should match against existing records before creating
  new ones; reinforce the idempotency rules in `opencode/command/vuln-commit.md` and
  `methodology.md` if needed.
- **False negatives on fix commits** — strengthen the "fix" heuristics in
  `project-conventions.md` for this project's commit style; the agent must verify a "fix"
  against the diff, not just the message.
- **Commit fails (no identity)** — `run.sh` sets a local fallback; or set your own:
  `git -C . config user.name/email`.
