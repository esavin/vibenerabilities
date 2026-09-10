# Guide — porting, performance, troubleshooting

## Requirements
`git`, `jq`, `python3` (>=3.8) on PATH — the agent (`vuln_agent/`) is stdlib-only, no pip
packages. Optional `timeout` (per-run limits). Plus any OpenAI-compatible LLM endpoint,
configured in `vibenerabilities/config.json` (`llm` section) or via environment
(`VULN_MODEL`, `VULN_BASE_URL`, `VULN_API_KEY`).

## Porting to a new project / language
The pipeline is language-agnostic. Per-project specifics live in two files you edit:
- `agent/project/project-conventions.md` — stack, idiomatic dangerous APIs (the single
  most useful section), area tags, commit-message style (which phrases signal security
  fixes).
- `vibenerabilities/config.json` — `source_root`, `source_branch`, …

`bootstrap.sh` auto-detects language/layout and fills these in as a starting point;
correct them if needed. Common `source_root` values (records always cite
**repository-root-relative** paths like `src/...`, whatever the clone location):

| Project shape | source_root | path style in records |
| --- | --- | --- |
| Project cloned inside workspace | `someproject` (its folder name) | `src/...` (no clone-folder prefix) |
| Single repo (workspace IS the repo) | `.` | `src/...`, `cmd/...` |
| Project outside workspace | absolute path | `src/...` (no clone-folder prefix) |

The agent's system prompt forbids workspace-folder prefixes and the validator flags them
("stale prefix"). If your `project-conventions.md` was rendered by an older bootstrap and
still asks for a `<clone>/...` path prefix, update that line to repository-root-relative.

**Important:** unlike `vibedocing`, leave `commit_skip_regex` empty. The security pipeline
must inspect every commit. If you do set a regex (e.g. to skip a docs-only subtree), a
matching commit is force-skipped **only when it renames/moves/deletes nothing** — R/D
commits may carry paths that existing records cite (path hygiene). Verify with `--list`
first.

## Model / endpoint configuration
The agent speaks the OpenAI-compatible chat-completions API. Configure in
`vibenerabilities/config.json` (`llm` section) or via environment:

| Setting | config.json | env override | default |
| --- | --- | --- | --- |
| model | `llm.model` | `VULN_MODEL` (or `--model`) | — (required) |
| endpoint | `llm.base_url` | `VULN_BASE_URL` | `https://api.openai.com/v1` |
| API key | `llm.api_key_env` names the env var | `VULN_API_KEY` (fallback `OPENAI_API_KEY`) | — |

Known `base_url` values that work: OpenAI (default), OpenRouter
`https://openrouter.ai/api/v1`, DeepSeek `https://api.deepseek.com/v1`, Groq
`https://api.groq.com/openai/v1`, vLLM/llama.cpp `http://host:8000/v1`, Ollama
`http://localhost:11434/v1` (no key needed), LiteLLM proxy. Local gateways need no key.

Other `llm` knobs: `max_steps` (tool-call rounds per commit, default 24),
`max_steps_initial` (step budget for the root/initial-snapshot commit; 48 is set by
bootstrap's template and is a good value for projects born as one giant commit),
`max_steps_cap` (default 48), `request_timeout_seconds` (per HTTP request, default 180),
`retries` (default 5), `temperature` and `max_tokens` (omitted when null/0 — some strict
gateways reject explicit values), `heartbeat_seconds` (default 60 — one
`[llm] waiting for <model>: Ns` line per interval while a single request is in flight;
reasoning models regularly take minutes per round-trip, and without it the pipeline
looks hung; 0 silences), `extra_body` (keys merged into the request payload — e.g.
backend-specific thinking toggles; keep `{}` on strict gateways that reject unknown
fields), `log_transcript` (default true — per-commit transcript JSONL, see
Troubleshooting).

Built-in loop guardrails (the agent loop compensates for the most common weak-model
traits, observed on real runs): exact duplicate tool calls are refused instead of
executed; the last 5 steps of the budget carry deadline pressure and a hard "call finish
NOW" message; a budget that runs out with records already written gets a finish-only
grace round — and if even that passes without a finish call, the verdict is synthesized
from the records actually written (still validated). Text-only replies (narration, or
tool calls the gateway left as plain text in `content` — DeepSeek's DSML syntax is
auto-lifted into the tool-call channel) are nudged back to tools but never forever: 5
text-only or 3 empty replies in a row abort with an ERROR. `write_record` supports
`{"append": true}` for records too long for one call, and a tool call whose JSON was cut
off by the gateway's output token limit gets a split-and-append hint instead of a bare
parse error.

## The "giant initial commit" (initial-snapshot mode)
Some projects start with one massive commit containing the whole codebase. The pipeline
detects root commits (no parent) automatically: the agent gets a **tree digest** (real
directories + file counts) instead of the diffstat and a bigger step budget
(`llm.max_steps_initial`). At that commit the agent should:
1. Spot-check the obvious entry points and high-risk modules for clear pre-existing
   issues (hardcoded secrets, missing auth on entrypoints, SQL/HTML/command-injection
   patterns).
2. Record anything found as `Status: Introduced` (pre-existing in initial commit) or
   `Status: Open` if not yet fixed at HEAD.
3. Let later commits fill in more findings idempotently — re-runs refine, never
   duplicate.

Coverage may be partial; later commits refine the map. To chunk a huge first pass
further, set `scope` in config to a subdirectory (pathspec filter on which commits are
processed) and run multiple passes.

## Snapshot deep-scan instead of full replay (--snapshot)
Replaying thousands+ commits costs days-to-weeks of agent time. `run.sh --snapshot [REF]`
inverts the process — deep-scan the **current tree** at REF (default HEAD) for
pre-existing vulnerabilities:

1. The tree at REF is checked out into a worktree; a **planner** request (one cheap LLM
   call, no tools; `snapshot.planner_model`, defaults to `llm.model`) partitions the tree
   into modules; a mechanical top-level-directory partition is the fallback.
2. One full agent session **per module** scans it with the regular guarded toolset,
   validation and repair rounds. Per-module context stays small at any repository size —
   the snapshot cannot blow the window.
3. `run.sh` sets the committed baseline to REF (`.vibenerabilities.json` gains a
   `"snapshot"` marker) and commits the map. Later regular runs analyze only commits
   newer than the snapshot.

Interrupted snapshots **resume**: finished modules are skipped on a re-run. Progress
streams live to the terminal and is kept in `logs/snapshot-<short>.log`; the aggregate
verdict lands in `verdicts/<sha>~snapshot.txt`. Typical cost: (modules + 1) agent
sessions instead of tens of thousands — a 30k-commit repository maps in hours, not
weeks (`bootstrap.sh` suggests `--snapshot` automatically at 2000+ commits).

Trade-off: a snapshot records pre-existing vulnerabilities in the current tree but does
not recover history-only signals (exact introducing commits, fix chronology before REF).
Incremental runs pick up new introductions and fixes from REF onward. `--snapshot`
cannot be combined with `--list`/`--dry-run`/`--validate`/`--reset-baseline`/`--sha`/
`--range`/`--limit`/`--reuse-verdicts`/`--skip-list`/`--record-hints`.

## Detecting fixes retroactively (the "lookahead" requirement)
A vulnerability may be missed at the introducing commit but detected later when a fix
lands. This is handled automatically:

- At the fix commit, Pass B (backward analysis) fires.
- The agent uses read-only git history queries at the parent of the fix commit — e.g.
  `git log -S "<removed-pattern>"` and `git log --diff-filter=A -- <file>` — to locate
  where the dangerous code first appeared.
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

## Deterministic self-healing (not LLM-trusted)
State the LLM cannot be trusted to maintain is maintained mechanically, in code:

### Hub maintenance (vuln_agent/hub.py)
After every processed commit the pipeline rewrites `INDEX.md`'s **Sync Status** (baseline
commit / last synced) — an external audit once found "(none)/(never)" in a fully analyzed
project because the sync fields were left to the LLM. It also reconciles the **Findings
table**: a row is re-added for every record the table no longer lists, rows whose record
file vanished are dropped, and cells of surviving rows are never touched (the agent owns
status flips, refined titles). Row **order** is pipeline-owned: after every processed
commit the data rows are permuted into ascending VULN-ID order (stable) and duplicate
rows for the same record are dropped — the first occurrence wins, so the agent-maintained
row survives. VULN rows stranded outside the `## Findings` section (e.g. appended after
Sync Status) are removed as drift. A dropped section heading (`## Summary`
/ `## Findings`) is re-created from the canonical template. The Summary counts are
deliberately NOT recomputed here — the validator reports drift and the agent repairs it
(a silent recompute would mask an agent that stopped maintaining them).

### Path hygiene (vuln_agent/hygiene.py)
A rename pre-pass runs BEFORE the agent session: citations of source paths git detected
as renamed are rewritten to the new location in place — a pure text substitution, applied
only when the new path EXISTS in the commit worktree, so the pre-pass can never
introduce a dead path. Whatever it cannot fix (deletions, ambiguous moves) becomes a
stale-references worklist for the agent, and oversized repair workloads are split into
small batched sessions with a scoped validator — so a mass-rename commit never blows the
context window with combined `write_record` payloads.

## Validation (the quality gate)
After every record-writing session the records map is validated mechanically (config
`validation`) — the same external audit found broken links, duplicate VULN numbering,
clone-folder path prefixes, references to files renamed/deleted later, and records that
silently lost their INDEX.md row; all of it is mechanically checkable:

- checks: fixed layout (only `INDEX.md`, `methodology.md`, `project-conventions.md`,
  `vulnerabilities/`, `design/` at the top level); `VULN-NNN-<slug>.md` naming with
  unique three-digit numbers (design notes: two-digit `NN-<slug>.md`); all relative
  markdown links resolve; repository-path-like references resolve in the worktree; no
  record still cites a path renamed/deleted by this commit; the hub keeps both fixed
  sections; Summary-count drift (warnings); orphaned records (warnings — hub.py re-adds
  them itself);
- problems go back to the agent for up to `validation.rounds` (default 2) repair rounds;
- `mode: "strict"` (default) flips the verdict to ERROR if deterministic errors remain →
  the commit is requeued and retried, broken records are not published; `"warn"` only
  records the report (`verdicts/<sha>.validation.md`); `"off"` disables;
- `path_check` (`error`|`warn`|`off`) controls the cited-path-exists check. It ships as
  `"warn"` because vulnerability records legitimately cite HISTORICAL paths — the
  vulnerable file may no longer exist at later commits;
- audit an existing records map any time, no agent involved:
  `./vibenerabilities/run.sh --validate [sha]` (report lands in
  `verdicts/validate-<short>.md`).

## Performance / cost
- Because **every** commit is analyzed, large repos mean many agent calls. `--limit N`
  bounds a run; combine with automatic resume for overnight batches.
- **Triage cascade for long walks** (`"triage": {"enabled": true}`): each commit first
  gets ONE cheap no-tools request (subject + message + name-status + the complete diff
  when it fits `triage.diff_chars`); only a confident `CLEARLY_IRRELEVANT` answer marks
  the commit NO_VULN without a full session. Recall guardrails: fix/security-keyword
  messages, renames/deletes, root commits, oversized diffs, prior-run hints, doubt and
  failed/unparsable replies all fall through to the FULL session. `triage.model` can
  point at a cheaper/faster model; `triage.irrelevant_globs` (e.g.
  `["docs/**", "**/*_test.go", "*.md", "assets/**"]`) skips matching commits with no
  LLM call at all. Measured on a 634-commit walk with a wandering model: multi-step
  NO_VULN sessions were ~57% of total wall time (~9h of 15.4h) at ~111s mean per
  commit — the cascade replaces most of those with one ~700-token request.
  `triage.diff_chars: 0` (default) is AUTO: the cap is derived from the provider window
  the pipeline discovered (`verdicts/provider-limit.json`, ~3 chars per input token
  minus a reserve; a conservative 16k fallback applies until a window is learned —
  e.g. a 46k-token window auto-caps at ~132k chars). An explicit value always wins,
  and a triage request that still overflows learns the real limit and falls back to
  the full session, so a wrong cap can never break a commit.
- **Triage prefetch** (`triage.prefetch_ahead: 3`): run.sh then starts a background
  worker (`vuln_agent.prefetch`, log in `logs/prefetch.log`) that keeps triage
  decisions cached this many commits ahead of the walk (`verdicts/triage/<sha>.json`),
  so the cascade decision costs the main invocation zero LLM round-trips and its
  latency hides behind the running full session. Safe because the decision is a pure
  function of the commit (diff + message + model) — it never depends on the records
  map or earlier outcomes. Delete `verdicts/triage/` to reset the cache (also after
  changing `triage.diff_chars` or the model).
- **Parallel classify-ahead** (`--parallel [K]`, worktree mode only): a `NO_VULN`
  verdict is a pure function of the commit (the `--reuse-verdicts` contract), so it
  can be computed *ahead* of the ordered records tape. K workers (default 4, or
  config `parallel.workers`) each run classify-only sessions over a window of
  `parallel.window` commits (default 32; `--parallel-window W` overrides) against a
  per-window **snapshot** of the records map; the main process — the only writer —
  then replays the window in history order: classified NO_VULN commits are finalized
  with no second session, everything else gets a full record session against the live
  records map. The next window's classification overlaps the current window's replay
  (K classify workers + 1 record session in flight at most).
  Safety: the records snapshot is stale by up to the window, which is fine because
  fix detection (Pass B) reads the *diff*, not the records — staleness can only cost
  a duplicate record later (collapsed by the record phase's read-before-write
  matcher), never a false NO_VULN. Rename/delete commits, prior-run hint commits
  (`--record-hints`), preseeded/regex skips and root commits skip classification
  entirely and go straight to the record phase. A classify ERROR or crash falls back
  to a record session, so a worker failure never loses a commit.
  Semantics of the other flags are unchanged: `--limit` bounds replayed commits,
  `--stop-on-fail` halts on a record-session failure, `--dry-run` classifies with no
  side effects at all. Interrupt-safe: killed workers' worktrees are swept on exit,
  the baseline only ever advances in the replay, and un-replayed classification is
  simply redone next run. Watch live classification with `tail -f walk.log`
  (`CLASSIFY` lines). Expected speedup at 12–15% VULN commits with K=6–8: ~3–4x —
  the ceiling is the serialized VULN tape (0.15 × N × ~250s), so raise K only while
  classify lines still dominate `walk.log`.
- **Range-squash for guard-forced noise** (`--squash`, or config `squash.enabled`;
  sequential walk only): a NO_VULN on a "probably irrelevant" commit is the common
  outcome of a full multi-step session the triage cascade could not skip — the classic
  is a docs/tests-only commit whose *message* contains a fix/security keyword (the
  keyword guard refuses any cheap path). Runs of `squash.min_series` (default 3) or
  more such commits are glued into ONE classify-only session over the **cumulative**
  diff `first^..tip`: the agent sees the cumulative name-status/diff plus every
  member's short-sha+subject, may drill into single commits with `git show -M`, and
  finishes `NO_VULN` only when the WHOLE range is clearly irrelevant. Any other
  answer (vuln candidate, doubt, ERROR) **splits** the range back into per-commit
  full record sessions, so recall is never traded for speed. The planner
  (`vuln_agent/squash.py`) is pure git plumbing: a commit may join a range only when
  it is not a root/merge commit, renames/deletes nothing, its individual diff fits
  `squash.member_diff_chars` (0 = `limits.diff_chars`), and it belongs to a
  configured class — `keyword` (message matches the same Pass-B keyword list the
  triage cascade uses) and/or `globs` (every changed file matches
  `triage.irrelevant_globs`); preseeded (`--reuse-verdicts`/`--skip-list`),
  prior-run-hint and regex-skip commits never join. Ranges are capped at
  `squash.max_commits` members (default 12) and a cumulative diff of
  `squash.diff_chars` (0 = AUTO: 2 × `limits.diff_chars`). Member verdicts carry a
  `NO_VULN(squash <a>..<b>)` marker that `--reuse-verdicts` replays like any other
  NO_VULN; transcripts/verdict JSONs note the `squash_range`. Preview the plan with
  `run.sh --list --squash` (SQUASH decisions, no agent calls); watch `SQUASH n
  commits` / `CLEAN (squashed a..b)` / `-> split (...)` lines in `walk.log`. With
  `--parallel` the flag is ignored with a warning — classify-ahead already cheapens
  guard-forced commits.
- **Provider context-limit persistence** (automatic): the first session that hits a
  context-overflow HTTP 400 persists the provider-reported window to
  `verdicts/provider-limit.json`; every later session seeds its compaction threshold
  from it (0.82 × window) and arms the pre-flight overflow guard with the window
  itself, instead of paying its own overflow round-trip first. The
  stored window is ignored once `llm.model`/`llm.base_url` change; an explicit
  `limits.compact_threshold_tokens` still decides when history compaction triggers
  (lowered to 0.82 × window if set above it), but never disables the guard.
  Delete the file to re-learn.
- **Completion tokens are wall-clock time**: on reasoning models most latency is token
  generation, so the system prompt pins a response-economy contract (no narration
  between tool calls, terse `finish` reasons). If your endpoint accepts
  `extra_body` (e.g. vLLM's `chat_template_kwargs: {"enable_thinking": false}` on
  Qwen-style models), disabling visible/hidden thinking where quality allows is the
  single biggest latency lever — on the measured walk ~37% of generated tokens never
  surfaced as content or tool arguments.
- **Snapshot first for big histories**: `--snapshot` scans the current tree in
  (modules + 1) sessions; replay is then only ever needed for NEW commits. See
  "Snapshot deep-scan instead of full replay".
- The first user message includes the **FULL DIFF** (`limits.diff_chars`, default 16k
  chars) whenever the complete change fits the cap — injected whole or not at all. Most
  `NO_VULN` verdicts then classify in a single round-trip with no `git show` call. Raise
  the cap on large-context models.
- Re-running a project from scratch? `--reuse-verdicts` replays previous `NO_VULN`
  verdicts for free (see "Re-running from scratch").
- `--dry-run` validates classification cheaply before real writes — truly non-mutating:
  no record writes, no baseline advance, no progress marks, no commits.
- For security analysis prefer the **strongest model you can afford** — false negatives
  here are costly. `llm.model` (config), `VULN_MODEL` (env) or `--model` picks it.
- For very large repos, consider scoping a first pass to high-risk directories (auth,
  crypto, input handlers, network) via `scope`, and a second pass to the rest.
- Small-context (~32k) models: set `"limits": {"profile": "small"}` in config.json. The
  profile bundles tighter caps on every injected blob (diff, diffstat, name-status,
  conventions, per-tool-result) **and enables history compaction**: normally the whole
  message history is re-sent on every tool round-trip, which overflows a 32k window
  mid-session (HTTP 400/context-length → ERROR → requeue). With compaction on, once a
  request reports `prompt_tokens` >= `compact_threshold_tokens` (20k in the profile),
  older tool results are shrunk in place to `compact_result_chars`; the last
  `compact_keep_groups` assistant+tool rounds stay verbatim. Set
  `compact_threshold_tokens` to roughly window minus max reply size (e.g. 24k on a 32k
  model with 8k output). On prefix-cached endpoints (OpenAI, vLLM) leave compaction off
  unless the window demands it — rewriting old messages misses the cache.
- **Overflow auto-recovery**: when the endpoint still rejects a request as too big
  (context-limit HTTP 400), the agent runs escalating emergency compaction passes,
  truncates oversized injected messages, retries the request in place, and adapts its
  compaction threshold to the provider-reported window for the rest of the session. No
  restart, no requeue: the commit finishes with a slightly degraded context instead of
  ERRORing out.
- Every cap is individually configurable under `limits` (see `templates/config.json`);
  explicit keys override the profile.
- `run_timeout_seconds` (config) caps each agent call if `timeout` is available.
- The run summary prints **token accounting** (prompt/completion/total across all agent
  verdicts) so you can price a walk afterwards.

## Restart after sync
The committed `agent/project/.vibenerabilities.json` holds the baseline. After `git pull`
in the project, run.sh analyzes only `baseline..HEAD`. `--reset-baseline` restarts from
zero.

Every processed commit is prefixed with a progress counter — `[9/832] [ab12cd3] ANALYZE …`
— where `9` is the commit's absolute position in the project history (oldest = 1) and
`832` the total commit count with the current walk filters (`skip_merges`, `scope`). The
numbering is **stable across interruptions**: a run restarted after 8 of 832 commits
continues at `[9/832]`, and after syncing new upstream commits it continues past the old
denominator (`[833/840]`). The run header shows `todo=N total=M` for the same reason.

## Re-running from scratch (verdict reuse)
A `NO_VULN` verdict is a pure function of the commit (diff + tree), so it can be replayed
across runs. Save the old run's `vibenerabilities/verdicts/` folder and pass it to the
fresh run — those commits are marked clean with **zero agent calls**, and their
`<sha>.txt`/`<sha>.json` artifacts are copied into the new run's verdicts dir for
traceability:

```bash
cp -r mywork/vibenerabilities/verdicts ~/verdicts-someproject-run1   # keep the old verdicts
# ... new workspace, bootstrap ...
./vibenerabilities/run.sh --reuse-verdicts ~/verdicts-someproject-run1
```

What is and is NOT reusable, and why:
- **`NO_VULN` — reusable.** It depends only on the commit's diff and tree, not on the
  records map.
- **`VULN_UPDATED` — NOT reusable.** The verdict names record files; the fresh workspace
  rebuilds the records map from scratch (different numbering, different prior state), so
  those commits are re-analyzed fully.
- Commits that don't exist in the source repo are ignored, so the same verdicts folder
  can be shared across projects safely.
- Caveat: verdicts also depend on `project-conventions.md` and the model — don't reuse
  them after editing conventions and expect identical coverage. Preview with `--list`
  (preseeded commits appear as `SKIP*`).

`--skip-list FILE` takes a plain list of hashes (one per line, `#` comments, short or
full SHAs) and force-treats them as `NO_VULN` without agent calls — handy to override
commits a previous run flagged.

### --record-hints (reconsideration round)
Borderline findings legitimately flip between runs (LLM sampling noise + a different
records-map state), and a missed vulnerability is much costlier than a missed clean.
With `--reuse-verdicts DIR --record-hints`, commits the prior run flagged
(`VULN_UPDATED`) get a second chance: if the current agent finishes `NO_VULN`, the loop
does NOT accept it yet — it feeds the prior run's actual record **content** back into
the same session and asks for one reconsideration round before the verdict stands. This
helps borderline findings converge across reruns instead of flip-flopping. The prior
records are located automatically at `<verdicts-dir>/../..` + the `records_root` from
the prior workspace's config — keep the prior workspace intact. In `--dry-run` mode the
reconsideration round asks for the verdict only (writes stay disabled).

## Auto-commit
When `auto_commit` is true (default) and not `--dry-run`/`--no-commit`, each analyzed
project commit with findings produces one workspace commit (`vulns(<project>): <subject>`).
A trailing baseline commit is added if the baseline advanced without a record change. The
workspace git identity defaults to `vibenerabilities <vibenerabilities@local>` (set in
config / by bootstrap).

## Runtime files (gitignored)
- `vibenerabilities/progress.json` — processed[] + failures[] + counters (fast in-walk
  resume; failed commits are requeued from here).
- `vibenerabilities/walk.log`, `vibenerabilities/logs/<sha>.log`,
  `vibenerabilities/verdicts/<sha>.{txt,json}`.
- `vibenerabilities/logs/snapshot-<short>.log`,
  `vibenerabilities/verdicts/<sha>~snapshot.txt` — snapshot deep-scan log and aggregate
  verdict; `verdicts/validate-<short>.md` — standalone validation reports.
- `vibenerabilities/verdicts/<sha>.transcript.jsonl` — full LLM interaction log for that
  commit: every model response (content, tool calls, `finish_reason`, per-step token
  usage) and every tool result exactly as it was fed back. Disable with
  `llm.log_transcript: false`.
- `.vibe-trees/<short>/` — disposable worktrees.

## The agent (vuln_agent/)
`vibenerabilities/vuln_agent/` — Python package, stdlib-only (`http.client` for HTTP, keep-alive):
- `cli.py` — argument parsing, verdict artifacts (written atomically), validation wiring.
- `llm.py` — OpenAI-compatible HTTP client with retries, heartbeat and a persistent (keep-alive) connection.
- `tools.py` — the seven tools with **code-level guards**: git restricted to
  `show|log|diff|ls-tree|grep` (scrubbed `GIT_*` env, no pager, forbidden flags like
  `-c`/`--output`/`--git-dir` rejected), reads confined to the worktree and records
  root, writes confined to `.md` under the records root with the fixed layout and
  three-digit `VULN-NNN` numbering enforced at write time.
- `prompt.py` — compact system prompt + grounded first message (commit meta,
  rename-aware name-status, full diff when it fits, tree digest for root commits,
  conventions, records overview).
- `agent.py` — the loop; ends only via the `finish` tool; compaction, overflow recovery,
  duplicate guard, bounded nudges, deadline pressure, finish grace + verdict synthesis.
- `hygiene.py` — deterministic rename pre-pass + batched stale-path repair.
- `snapshot.py` — the snapshot deep-scan CLI (`run.sh --snapshot`): planner request,
  mechanical fallback partition, one module session each, resume markers.
- `validate.py` — the mechanical records validator (also a standalone CLI).
- `hub.py` — deterministic INDEX.md maintenance (Sync Status, Findings reconciliation).
- `transcript.py` — transcript analyzer CLI (see Troubleshooting).

You can run one commit standalone (as `run.sh` does):
```bash
PYTHONPATH=vibenerabilities python3 -m vuln_agent --config vibenerabilities/config.json \
  --sha <sha> --worktree <worktree-path> --records-root agent/project \
  --records-root-rel agent/project --verdicts-dir vibenerabilities/verdicts \
  [--classify-only] [--model M]
```

## Config reference
Important keys from `templates/config.json` (all optional unless marked; `$comment`
fields in the template explain each):

| key | meaning | default |
| --- | --- | --- |
| `source_root` / `source_branch` | which repo/branch to analyze | set by bootstrap |
| `records_root` | where the map lives | `agent/project` |
| `use_worktree` | disposable worktree vs `--in-place` checkout | `true` |
| `skip_merges` | skip merge commits in the walk | `true` |
| `commit_skip_regex` | subject regex force-skip — keep **empty** for security analysis | `""` |
| `scope` | pathspec: analyze only commits touching this subdirectory | `""` |
| `run_timeout_seconds` | per-agent-call cap (needs `timeout`; 0 = off) | `0` |
| `auto_commit` | commit record changes to the workspace repo | `true` |
| `llm.model` | any model behind an OpenAI-compatible API | — (required) |
| `llm.base_url` | endpoint URL | `https://api.openai.com/v1` |
| `llm.api_key_env` | env var holding the API key | `VULN_API_KEY` |
| `llm.max_steps` / `max_steps_initial` / `max_steps_cap` | step budgets (per commit / root commit / cap) | 24 / 48 / 48 |
| `llm.request_timeout_seconds` | per HTTP request | `180` |
| `llm.retries` | HTTP retries (1→16 min backoff, `Retry-After` honored) | `5` |
| `llm.heartbeat_seconds` | `[… waiting]` line interval; 0 = silent | `60` |
| `llm.temperature` / `max_tokens` | omitted when null/0 | `null` / `0` |
| `llm.extra_body` | extra request payload keys (backend switches) | `{}` |
| `llm.log_transcript` | write `verdicts/<sha>.transcript.jsonl` | `true` |
| `limits.profile` | `default` (historical caps, compaction off) or `small` (~32k models) | `default` |
| `limits.diff_chars` | full-diff injection cap (whole or not at all; 0 disables) | `16000` |
| `limits.compact_threshold_tokens` | history-compaction trigger (0 = off) | `0` |
| `limits.compact_keep_groups` / `compact_result_chars` | compaction: rounds kept verbatim / shrunk size | `4` / `2000` |
| other `limits.*` caps | per-blob caps: `diffstat_chars`, `name_status_chars`, `tree_digest_chars`, `conventions_chars`, `records_overview_chars`, `tool_result_chars`, `git_output_chars`, `read_file_chars`, `list_dir_chars` | see template |
| `snapshot.planner_model` | model for the one planner request (`""` = `llm.model`) | `""` |
| `snapshot.max_modules` | cap on the module partition (excess merges into "misc") | `40` |
| `snapshot.max_steps` | per-module step budget (0 = `llm.max_steps_initial`) | `0` |
| `validation.mode` | `strict` (errors → ERROR verdict, commit requeued) / `warn` / `off` | `strict` |
| `validation.rounds` | agent repair rounds before the final verdict | `2` |
| `validation.path_check` | severity of the cited-path-exists check | `warn` |
| `squash.enabled` | range-squash of guard-forced probably-irrelevant runs (also `--squash`) | `false` |
| `squash.classes` | candidate classes: `keyword` (Pass-B keyword message) and/or `globs` (all files under `triage.irrelevant_globs`) | `["keyword","globs"]` |
| `squash.min_series` / `max_commits` | range size bounds (shorter runs stay per-commit / hard member cap) | `3` / `12` |
| `squash.member_diff_chars` / `diff_chars` | per-commit candidacy cap / cumulative range diff cap (0 = AUTO: `limits.diff_chars` / 2 × `limits.diff_chars`) | `0` / `0` |

## Troubleshooting
- **A commit FAILED — what happens** — verdict files for the SHA are cleared before
  every attempt (a crashed agent never inherits a stale verdict), the baseline rolls
  back to the commit's PARENT, and the SHA is recorded in `progress.json` `failures[]`;
  the next run requeues it automatically. Inspect `logs/<sha>.log` and
  `verdicts/<sha>.transcript.jsonl`. Use `--stop-on-fail` to halt on the first one, or
  `--sha <sha> --dry-run` to test a single commit.
- **`ERROR max_steps (N) reached without finish`** — the model never called the
  `finish` tool within its step budget. Diagnose from the recorded transcript:
  ```bash
  python3 -m vuln_agent.transcript vibenerabilities/verdicts/<sha>.transcript.jsonl
  ```
  The summary prints the context-growth curve (per-step `prompt_tokens`), a tool
  histogram with refused calls, identical repeated calls, and anomalies. Read it as:
  - `finish_reason=length` on some responses → `llm.max_tokens` is too small: the
    tool-call JSON is truncated mid-way, the call is refused as invalid JSON, and the
    loop burns all steps. Raise `llm.max_tokens` (or remove the cap).
  - `prompt_tokens` climbing steeply toward the model's context window → context
    pressure, not model quality: large tool results (`git show` on a big commit,
    `read_file` on huge files) crowd out the instructions. Mitigate by splitting the
    work (`scope`), lowering `max_steps`, using a model with a larger window, or — on a
    small-window model — `"limits": {"profile": "small"}` (tighter caps + history
    compaction).
  - identical tool calls repeated, plain-text answers that never call `finish`, or
    garbage tool arguments at a small token count → the model itself is too weak for
    tool loops; switch model. The pipeline already compensates for the most common
    weak-model traits (duplicate-call guard, bounded nudges, deadline pressure, finish
    grace + verdict synthesis — see "Model / endpoint configuration").
  Note: a genuinely *exceeded* context window surfaces differently — as a context-limit
  HTTP 400 (auto-recovered, see next item), not as max_steps.
- **Context-limit HTTP 400 in logs** — expected on small windows and handled in place:
  the agent runs escalating emergency compaction, truncates oversized injected
  messages, retries, and adapts its compaction threshold to the provider-reported
  window for the rest of the session. The commit finishes with a slightly degraded
  context. If it happens often, set `"limits": {"profile": "small"}` or a lower
  `compact_threshold_tokens`.
- **`ERROR llm: …` verdict** — the endpoint failed after retries (rate limit, outage,
  e.g. HTTP 503 on busy gateways). HTTP-level retries are patient by design: they wait
  **1, 2, 4, 8, 16 minutes** between attempts (`retries` defaults to 5 — up to ~31 min
  total), riding out provider outages in place; an explicit `Retry-After` header wins,
  capped at 16 min. Connection errors keep a fast exponential curve. Note
  `run_timeout_seconds`, if set, caps the whole agent call and can cut the retry waits
  short — keep it `0` for unattended runs, and raise `llm.retries` for longer outages.
  The commit is requeued automatically on the next run.
- **`ERROR validation failed …` verdict** — the records still had mechanical errors
  after `validation.rounds` repair rounds (see `verdicts/<sha>.validation.md`). The
  commit is requeued automatically; the next attempt starts from the partially-fixed
  records. Either re-run, fix the records by hand, or — for legitimately unresolvable
  historical path references — set `validation.path_check: "off"` or
  `validation.mode: "warn"` in config.
- **worktree add failed** — stale worktree registrations are pruned automatically
  before every add, and the error message includes git's stderr; if it still happens,
  run `git -C <source> worktree prune` by hand.
- **In-place mode refuses to start** — `--in-place` checks out each commit in the
  source clone itself and needs it **clean**: commit or stash first (worktree mode, the
  default, has no such requirement).
- **`no model configured`** — set `llm.model` in `config.json`, or
  `export VULN_MODEL=…`, or pass `--model`.
- **HTTP 401/403 in logs** — export the API key named by `llm.api_key_env`
  (`VULN_API_KEY` by default; `OPENAI_API_KEY` is a fallback).
- **HTTP 404 / "model not found"** — wrong `llm.model` or `llm.base_url` for that
  gateway.
- **HTTP 400 mentioning tools/function-calling** — that model or gateway does not
  support tool calls; pick another model.
- **macOS notes** — `timeout` is not in the base OS: `run_timeout_seconds` is silently
  skipped unless a `timeout` binary is on PATH (e.g. coreutils). `bootstrap.sh` avoids
  GNU-only `realpath --relative-to`, so it works on BSD/macOS as is.
- **`source_root … is not a git repository`** — fix `source_root` in `config.json`.
- **Duplicate records** — the agent should match against existing records before
  creating new ones; reinforce the idempotency wording in
  `agent/project/methodology.md` and `project-conventions.md` if needed.
- **False negatives on fix commits** — strengthen the "fix" heuristics in
  `project-conventions.md` for this project's commit style; the agent must verify a
  "fix" against the diff, not just the message.
- **Commit fails (no identity)** — `run.sh` sets a local fallback; or set your own:
  `git -C . config user.name/email`.
