# vibenerabilities — incremental security-analysis pipeline (portable kit)

Generate a **map of security vulnerabilities and security issues** for any git project, in
any language, by replaying its history commit-by-commit. For each commit, an opencode agent
— in a fresh, small context — decides whether it **introduces** a vulnerability, **fixes**
one, or **reveals a previously-missed** pre-existing issue, and updates the records under
`agent/project/vulnerabilities/` accordingly.

**Unlike `vibedocing`, every commit is analyzed.** There is no skip filter: `fix:`,
`chore:`, `refactor:` and similar commits may be the *only* signal of a security fix and
must be inspected against the actual diff.

Each record captures the full **lifecycle** of an issue: the commit that introduced it
(found via `git log`/`git blame` when the fix is detected retroactively) and every commit
that fixed it (a single issue may be fixed across multiple commits — they are all appended
to the same record).

The outer loop is a bash script (**outside** every agent call), so no single agent ever
holds the whole codebase in context.

## Quick start

```bash
# 1. make a working folder and clone this tooling into it
mkdir mywork && cd mywork
git clone https://github.com/esavin/vibenerabilities.git ./vibenerabilities   # -> ./vibenerabilities/

# 2. clone the project you want to analyze, into the same folder
git clone <project-url> ./someproject

# 3. bootstrap (creates .gitignore, agent/project/, git repo, config)
./vibenerabilities/bootstrap.sh ./someproject

# 4. preview, then run
./vibenerabilities/run.sh --list | tail -1     # how many commits to process
./vibenerabilities/run.sh --limit 20           # analyze first 20 commits (auto-committed)
./vibenerabilities/run.sh                      # continue from baseline to HEAD
```

## What you get

```
mywork/                                <- workspace (its own git repo)
  .gitignore                           project folder + tooling are gitignored
  someproject/                         (gitignored) the project under analysis
  vibenerabilities/                    (gitignored) THIS solution (run.sh, bootstrap.sh, templates…)
  .opencode/                           (gitignored) installed command + skill
  agent/project/                       COMMITTED — the vulnerability map
    INDEX.md                           navigation hub + counts + Sync Status
    methodology.md                     generic methodology
    project-conventions.md             per-project specifics (you edit this)
    .vibenerabilities.json             last-processed commit (for restart-after-sync)
    vulnerabilities/
      VULN-001-<slug>.md               one record per issue
      VULN-002-<slug>.md
      …
    design/                            (optional) cross-cutting theme notes
```

Each `VULN-NNN-*.md` record contains:

- **Summary**, **Classification** (CWE, severity), **Status** (`Introduced`/`Open`/`Fixed`).
- **Affected Code** — concrete file paths and symbols.
- **Evidence** — the vulnerable lines quoted from the source at the introducing commit.
- **Introduced in** — commit SHA, date, subject (located via `git log -S`/`blame` when the
  fix is detected retroactively).
- **Fixed in** — one or more commits (multi-commit fixes are appended here, never split).
- **Detection** — forward-analysis / retroactive-from-fix / late-discovery, plus confidence.

## How it works (per commit)

1. `run.sh` checks the commit out into a disposable git worktree (stateful replay).
2. `opencode run --command vuln-commit "<sha> <worktree>" --auto` — fresh session — runs
   three detection passes (introduced / fixed / late-discovered), using `git -C <worktree>
   log`/`blame` to locate origins when a fix is detected.
3. If findings: the agent creates/updates `agent/project/vulnerabilities/VULN-*.md`
   idempotently and refreshes `INDEX.md`. Multi-commit fixes **append** to the existing
   record — the agent reads existing records first and never duplicates.
4. `run.sh` reads the agent's verdict, advances the committed baseline
   (`agent/project/.vibenerabilities.json`), and **git-commits** the record changes
   (`vulns(<project>): <subject>`).

## Restart after upstream changes

The last fully-processed commit is stored (committed) in
`agent/project/.vibenerabilities.json`. When the project gets new commits:

```bash
git -C someproject pull        # sync new changes
./vibenerabilities/run.sh      # analyzes only baseline..HEAD (the new commits)
```

`--reset-baseline` starts over from the project's first commit.

## Common options

```
--list               show PROCESS/DONE decisions, no agent calls
--dry-run            classify only (no record writes, no commits)
--limit N            process at most N commits
--range A..B         process a specific range
--sha S              process a single commit
--in-place           checkout in the source clone instead of a worktree
--no-commit          don't git-commit this run
--stop-on-fail       halt on the first failed commit
--attach URL         attach to a running 'opencode serve' (faster for big batches)
--serve              manage an 'opencode serve' for the run
--model M            override the model
```

See `GUIDE.md` for porting to a new project/language, performance tips, and troubleshooting.
See `SECURITY.md` for the **important** trust model — the agent reads untrusted code.
Requires: `git`, `jq`, `opencode`.
