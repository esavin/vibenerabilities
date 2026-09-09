# vibenerabilities — incremental security-analysis pipeline (portable kit)

Generate a **map of security vulnerabilities and security issues** for any git project, in
any language, by replaying its history commit-by-commit. For each commit, a purpose-built
agent — **vuln_agent**, a stdlib-only Python package speaking any OpenAI-compatible API —
in a fresh, small context decides whether it **introduces** a vulnerability, **fixes**
one, or **reveals a previously-missed** pre-existing issue, and updates the records under
`agent/project/vulnerabilities/` accordingly.

**Unlike `vibedocing`, every commit is analyzed.** There is no skip filter: `fix:`,
`chore:`, `refactor:` and similar commits may be the *only* signal of a security fix and
must be inspected against the actual diff.

Each record captures the full **lifecycle** of an issue: the commit that introduced it
(found via `git log -S` / `git log --diff-filter=A` when the fix is detected
retroactively) and every commit that fixed it (a single issue may be fixed across
multiple commits — they are all appended to the same record).

The outer loop is a bash script (**outside** every agent call), so no single agent ever
holds the whole codebase in context. The agent itself is a minimal single-purpose loop
with seven hard-guarded tools (read-only git, read/list, search-records,
write/edit-record, finish) — no shell, no general-purpose system prompt — so nearly the
whole context window is spent on the actual commit.

## Quick start

```bash
# 1. make a working folder and clone this tooling into it
mkdir mywork && cd mywork
git clone https://github.com/esavin/vibenerabilities.git ./vibenerabilities   # -> ./vibenerabilities/

# 2. clone the project you want to analyze, into the same folder
git clone <project-url> ./someproject

# 3. bootstrap (creates .gitignore, agent/project/, git repo, config)
./vibenerabilities/bootstrap.sh ./someproject

# 4. point the agent at your model (any OpenAI-compatible endpoint)
$EDITOR vibenerabilities/config.json       # llm.model, llm.base_url
                                            # ~32k-context model? set limits.profile = "small"
export VULN_API_KEY=...                    # or whatever llm.api_key_env names

# 5a. BIG HISTORY (thousands+ commits)? deep-scan the current tree instead:
./vibenerabilities/run.sh --snapshot        # module-by-module scan of HEAD; later
                                             # runs analyze only NEW commits

# 5b. or replay the full history commit-by-commit:
./vibenerabilities/run.sh --list | tail -1     # how many commits to process
./vibenerabilities/run.sh --limit 20           # analyze first 20 commits (auto-committed)
./vibenerabilities/run.sh                      # continue from baseline to HEAD
```

## What you get

```
mywork/                                <- workspace (its own git repo)
  .gitignore                           project folder + tooling are gitignored
  someproject/                         (gitignored) the project under analysis
  vibenerabilities/                    (gitignored) THIS solution (run.sh, bootstrap.sh, vuln_agent/, templates…)
  agent/project/                       COMMITTED — the vulnerability map
    INDEX.md                           navigation hub + counts + Sync Status
    methodology.md                     generic methodology
    project-conventions.md             per-project specifics (you edit this)
    .vibenerabilities.json             last-processed commit (for restart-after-sync)
    vulnerabilities/
      VULN-001-<slug>.md               one record per issue (3-digit numbering, enforced at write time)
      VULN-002-<slug>.md
      …
    design/                            (optional) cross-cutting theme notes
```

Each `VULN-NNN-*.md` record contains:

- **Summary**, **Classification** (CWE, severity), **Status** (`Introduced`/`Open`/`Fixed`).
- **Affected Code** — repository-root-relative file paths and symbols.
- **Evidence** — the vulnerable lines quoted from the source at the introducing commit.
- **Introduced in** — commit SHA, date, subject (located via `git log -S` /
  `git log --diff-filter=A` when the fix is detected retroactively).
- **Fixed in** — one or more commits (multi-commit fixes are appended here, never split).
- **Detection** — forward-analysis / retroactive-from-fix / late-discovery, plus confidence.

## How it works (per commit)

1. `run.sh` checks the commit out into a disposable git worktree (stateful replay).
2. A deterministic rename pre-pass (`vuln_agent/hygiene.py`) rewrites citations of source
   paths the commit renamed — worktree-verified text substitutions, no agent call.
3. `python3 -m vuln_agent --config … --sha <sha> --worktree <path> --records-root …
   --records-root-rel … --verdicts-dir …` — fresh session — injects the commit metadata,
   a rename-aware name-status, the full diff whenever it fits a size cap
   (`limits.diff_chars`), and project conventions, then runs three detection passes
   (introduced / fixed / late-discovered) through the guarded tools, using read-only git
   history commands at the parent to locate origins when a fix is detected.
4. If findings: the agent creates/updates `agent/project/vulnerabilities/VULN-NNN-<slug>.md`
   idempotently and refreshes `INDEX.md`. Multi-commit fixes **append** to the existing
   record — the agent reads existing records first and never duplicates.
5. The records map is then **validated mechanically** (numbering, links, layout, source
   paths, hub sections, summary drift); problems go back to the agent for repair rounds,
   and in strict mode remaining errors flip the verdict to `ERROR` so broken records are
   never published.
6. `run.sh` reads the first line of `verdicts/<sha>.txt` (`VERDICT: VULN_UPDATED <files>`
   / `VERDICT: NO_VULN` / `VERDICT: ERROR <reason>`), advances the committed baseline
   (`agent/project/.vibenerabilities.json`), rewrites `INDEX.md`'s Sync Status and
   reconciles the Findings table deterministically (`vuln_agent/hub.py`) —
   coverage repair plus a stable sort of the data rows by VULN ID, with
   duplicate rows for the same record dropped — and
   **git-commits** the record changes (`vulns(<project>): <subject>`).

**Optional triage cascade** (`triage.*` in config, off by default): each commit
first gets ONE cheap no-tools request — subject, full message, name-status and
the COMPLETE diff whenever it fits `triage.diff_chars` (0 = auto-sized from the
provider window the pipeline discovered) — and only a confident
`CLEARLY_IRRELEVANT` answer marks the commit NO_VULN without a full session.
Everything else falls through to the full three-pass session: fix/security
keywords in the message, any rename/deletion, root commits, oversized diffs,
prior-run hints, doubt, or an unparsable/failed reply. With
`triage.irrelevant_globs`, commits whose every changed file matches
(docs/tests/assets style globs) skip with no LLM call at all. With
`triage.prefetch_ahead: 3`, run.sh keeps a background worker caching triage
decisions a few commits ahead of the walk (`verdicts/triage/`), so the
cascade costs the main invocation zero LLM round-trips — safe because the
decision is a pure function of the commit. On a measured
634-commit walk, multi-step NO_VULN sessions dominated ~57% of wall time — the
cascade turns those into one small request while preserving recall guardrails.
The agent also persists a provider-reported context window
(`verdicts/provider-limit.json`) after the first context-overflow HTTP 400, so
later sessions seed their compaction threshold instead of re-discovering the
limit the hard way.

A failed commit (LLM outage, timeout, validation error) rolls the baseline back to its
parent and is requeued automatically on the next run — nothing is ever silently skipped.

Each processed commit is prefixed with an interruption-stable progress counter
(`[9/832] [ab12cd3] ANALYZE …`): `9` is the commit's absolute position in the project
history, `832` the total with the current walk filters — so after any interruption and
restart the numbering continues where it stopped, and you always see how much is done
and how much remains.

When a step creates a *new* record, an extra line flags it — `new record
VULN-NNN-<slug>.md (introduced …)` — and says `found retroactively at this commit`
when the record was recovered from a fix while its `Introduced in` cites earlier
commits (Detection: retroactive-from-fix). A vulnerability the forward pass missed
is therefore visible in the walk log at the commit where the pipeline learned of
it, together with its real introduction point — not only inside the record file.

## Restart after upstream changes

The last fully-processed commit is stored (committed) in
`agent/project/.vibenerabilities.json`. When the project gets new commits:

```bash
git -C someproject pull        # sync new changes
./vibenerabilities/run.sh      # analyzes only baseline..HEAD (the new commits)
```

`--reset-baseline` starts over from the project's first commit.

## Fresh-workspace reruns

A `NO_VULN` verdict is a pure function of the commit (diff + tree), so verdicts from a
previous run of the same project replay for free: `run.sh --reuse-verdicts <old
verdicts dir>` marks those commits clean with zero agent calls (`--skip-list FILE` lists
SHAs by hand). `VULN_UPDATED` verdicts are never reused — the records map is rebuilt from
scratch. With `--record-hints`, commits the prior run flagged get a reconsideration
round: the prior run's actual record content is fed back before a `NO_VULN` flip is
accepted. See `GUIDE.md` for the full semantics.

## Common options

```
--list               show ANALYZE/SKIP/DONE decisions, no agent calls
--snapshot [REF]     deep-scan the CURRENT tree at REF (default HEAD): a planner
                     request partitions the tree into modules, one agent session
                     per module scans it; baseline jumps to REF. Resumes after
                     interruption. Config snapshot.*
--dry-run            classify only (no record writes, no baseline advance, no commits)
--validate [S]       audit existing records against the tree at S (default HEAD):
                     links, numbering, layout, source paths, stale references —
                     no agent calls
--reset-baseline     reset the committed baseline to the project's first commit
--limit N            process at most N commits
--range A..B         process a specific range
--sha S              process a single commit
--reuse-verdicts DIR replay NO_VULN verdicts from a previous run's verdicts dir
--skip-list FILE     treat the commits listed in FILE as NO_VULN (one hash per line)
--record-hints       with --reuse-verdicts: reconsideration round feeding the prior
                     run's record content back on a NO_VULN flip
--in-place           checkout in the source clone instead of a worktree
--no-commit          don't git-commit this run
--stop-on-fail       halt on the first failed commit (default: roll the baseline
                     back to the parent, requeue next run, continue)
--model M            override the model (or export VULN_MODEL)
```

See `GUIDE.md` for porting to a new project/language, performance tips, reruns, and
troubleshooting.
See `SECURITY.md` for the **important** trust model — the agent reads untrusted code.
Requires: `git`, `jq`, `python3` (>=3.8, stdlib only — no pip packages), and any
OpenAI-compatible LLM endpoint.
