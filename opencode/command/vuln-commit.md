---
description: One step of the incremental security-analysis pipeline. Inspects a single commit (stateful replay) for security vulnerabilities and issues, both introduced and fixed, and updates per-vulnerability .md records under agent/project/vulnerabilities/. Invoked headlessly by vibenerabilities/run.sh.
---

# Analyze one commit for security issues

You are one step of an automated, commit-by-commit security-analysis pipeline. You receive
exactly one commit, checked out in a disposable git worktree, and you must decide whether
it **introduces** new security issues, **fixes** previously-known ones, or **reveals**
previously-missed pre-existing ones — then update the vulnerability records accordingly.

**This pipeline analyzes EVERY commit.** Do not skip a commit because its message looks
like a chore, a refactor, or a bug fix — `fix:`/`chore:`/`refactor:` commits are often the
*only* signal of a security fix.

## Inputs
- `$1` — the commit SHA under review.
- `$2` — absolute path to a git worktree that has **this commit checked out** (the source
  tree exactly as it was at this commit). Read source files and run `git` history commands
  here.
- `$3` — absolute path of the verdict file you must write your single-line verdict to
  (see "Emit the verdict" below). Create the file and its parent directory if they do not
  exist.
- `$4` — optional mode token. If it equals `classify-only`, decide and emit the verdict
  **without writing any records**.

The records you may edit live under `agent/project/` in the **project root** (your current
working directory), NOT in the worktree. The worktree is read-only context.

## Methodology (binding)
Follow these two files exactly:
- @agent/project/methodology.md — the generic methodology (what counts as a vulnerability,
  classification, severity rubric, lifecycle, file format, idempotency).
- @agent/project/project-conventions.md — this project's specifics (language, framework,
  path prefix, idiomatic dangerous APIs, commit-message style). If it is missing, infer
  conservatively.

## What to do

### 1. Inspect the commit
Run, in the worktree (`$2`):
- `git -C "$2" show --stat "$1"` — file-level summary.
- `git -C "$2" log -1 --format='%H%n%an%n%ad%n%s%n%n%b' "$1"` — the full commit message.
- `git -C "$2" show "$1" -- <path>` — the actual diff for any path that looks
  security-relevant.

Read affected source files **as they exist at this commit** from the worktree. Never read
source from anywhere except `$2` — other copies are at a different point in history.

### 2. Three detection passes

Run **all three** passes per commit. They are not exclusive — a single commit can both
introduce and fix different issues.

#### Pass A — Introduced in this commit (forward analysis)
Examine every hunk of the diff (`git -C "$2" show "$1"`). Flag the commit as INTRODUCING a
vulnerability when the **added/modified** lines exhibit any of the dangerous patterns from
`methodology.md → What counts as a vulnerability` (SQL string concat, command exec with
user input, raw HTML output, path traversal, unsafe deserialization, weak crypto, hardcoded
secrets, missing auth, XXE, SSRF, race conditions, info disclosure, …) or any pattern from
`project-conventions.md → Project-specific dangerous APIs`.

When in doubt for Pass A, **prefer recording** the issue with severity `Low`/`Info` rather
than skipping. False positives can be corrected by a later note, but missed vulnerabilities
are lost. The pipeline tracks fixes, so a soft call now is recoverable; a silent miss is
not.

#### Pass B — Fixed in this commit (backward analysis)
Flag the commit as FIXING a vulnerability when **either**:

- The commit message contains (case-insensitive) any of: `fix`, `security`,
  `vulnerability`, `vuln`, `CVE-`, `CWE-`, `XSS`, `CSRF`, `SSRF`, `injection`,
  `traversal`, `escape`, `sanitize`, `sanitise`, `patch`, `hotfix`, `hardening`, `auth`,
  `privilege`, `disclosure`, `leak`, `RCE`, `DoS`, `bypass`, `overflow`, `forgery`,
  `hijack`, `disclose` — **and** the diff actually removes/replaces a dangerous pattern
  (message alone is **never** sufficient); **or**
- The diff alone removes a dangerous pattern from Pass A's list and adds a safer
  alternative (string-concat SQL → parameterized; raw output → escaped; hardcoded secret →
  env-var lookup; `yaml.load` → `yaml.safe_load`; `md5` → bcrypt; `verify=False` →
  `verify=True`; missing auth check → check added; etc.).

When Pass B fires:

1. **Identify the specific issue** being fixed: vulnerability class (CWE), affected file(s),
   symbol(s), and what made the old code dangerous.
2. **Find the origin** using the worktree's git history:
   - `git -C "$2" log --diff-filter=A --format='%H %ad %s' --date=short -- <file>` — when
     the affected file was first added.
   - `git -C "$2" log -S "<removed-dangerous-fragment>" --reverse --format='%H %ad %s'
     --date=short -- <file>` — when the dangerous construct first appeared (the earliest
     commit in the `-S` pickaxe output).
    - `git -C "$2" log --all -L <start>,<end>:<file>` (if a line range is known) or
     `git -C "$2" blame -t "$1^" -- <file>` to attribute surviving dangerous lines to
     their introducing commits.
   - If the dangerous code is present in the project's **initial commit** (verify with
     `git -C "$2" log --max-parents=0 --format='%H %s'`), record it as `pre-existing` and
     use the initial commit as the introduction point.
3. **Match against existing records** — read `agent/project/INDEX.md` and every
   `agent/project/vulnerabilities/*.md`. If a record already describes **this exact issue**
   (same file/symbol/class), **update it**: append this commit to its `## Fixed in` block
   (multi-commit fixes append, never overwrite). Do NOT create a duplicate.
4. **If no existing record matches**, create a new one (per Step 3 below) with **both**
   `## Introduced in` (found via Step 2.2 above) and `## Fixed in` (this commit) filled.

#### Pass C — Late-discovered pre-existing issues (origin/back-dating)
While looking at the diff and its surrounding code, you may recognize a clear pre-existing
issue that:
- is present at this commit,
- is **not** introduced by this commit's diff, and
- has **not yet been recorded** under `agent/project/vulnerabilities/`.

Record it as a **separate** finding with `## Introduced in` set to "earlier — exact commit
not identified from this pass; present at `$1`" and severity `Info`/`Low`. This catches
silent pre-existing issues and is required by the pipeline's "lookahead" semantics. Do this
**sparingly** — only for clear, high-confidence findings — to avoid noise.

> **Pass A and Pass B can both fire on the same commit.** Record both findings. (A commit
> that fixes one vuln and introduces another is normal.)

### 3. Update records (if not classify-only)

Apply the methodology in `methodology.md`:

1. **Read existing records first.** Read `agent/project/INDEX.md` and every
   `agent/project/vulnerabilities/*.md`. Decide **NEW vs UPDATE** per finding. Never
   duplicate. Matching key: (file, symbol/range, vulnerability class) — be tolerant of
   cosmetic edits in the file between commits.
2. For each finding of this commit:
   - **NEW** — create `vulnerabilities/VULN-<NNN>-<slug>.md` (lowest free `<NNN>`,
     zero-padded, `<slug>` = short kebab-case). Fill the template fully — Summary,
     Classification, Affected Code, Evidence, **Introduced in**, **Fixed in** (if known),
     Detection, Remediation Notes.
   - **UPDATE** — open the matching record; **append** this commit to `## Introduced in`
     (rare — only if original introduction turned out to span multiple commits) or
     `## Fixed in` (typical for fix commits — append, never overwrite); refresh `## Status`
     (`Open` → `Fixed` only when no more danger is present at HEAD; otherwise leave
     `Open` and note partial fix), `## Severity`, `## Evidence`, and `## Remediation
     Notes`.
3. **Update `INDEX.md`** — add new rows for new records; flip Status column (Open → Fixed)
   when a record's status changes; refresh the Summary counts (total / open / fixed, by
   severity) in the header block.
4. **Bump `*Last updated: YYYY-MM-DD*`** (today) in every file you actually modify.
5. **Tag `*Areas: ..., security*`** per the conventions file.
6. Be **surgical and idempotent** — touch only records that correspond to real findings in
   THIS commit. Do not rewrite untouched records. Do not fabricate.

### 4. Emit the verdict (always, last)
Write exactly one line to the verdict file whose absolute path is `$3` (create the file and
its parent directory if needed):
- If you created or modified records:
  `VERDICT: VULN_UPDATED <comma-separated relative doc paths>` (list only the record files
  under `agent/project/` that you created/modified — typically `agent/project/INDEX.md`
  plus the per-vuln `.md` files).
- If you skipped (no findings): `VERDICT: NO_VULN`
- In `classify-only` mode: emit the verdict you WOULD have produced, but make no edits.

Then print the same single line as your final message. Do not print anything else of
substance — the runner parses this line.

## Hard rules
- Only edit files under `agent/project/`. Never touch the worktree or any source code.
- Only read source / run git history commands in the worktree (`$2`). The repo-root source
  (if any) is at HEAD and will mislead you about this historical commit.
- Never `git add`, `git commit`, or `git push` anything.
- Never run the pipeline script yourself; you are a single step, not the loop.
- If `$2` is missing or `git -C "$2" show "$1"` fails, write
  `VERDICT: ERROR cannot-inspect-commit` to the file at `$3` and stop.
- **Do not invent vulnerabilities.** Every record must trace to concrete lines in concrete
  files at concrete commits. If you cannot point to evidence (file path + line + SHA), do
  not record.
- **Never fabricate commit SHAs** for `Introduced in` / `Fixed in`. Use the SHAs you read
  from `git log` / `git blame` output verbatim. If you cannot determine an introduction
  point, say so explicitly in the record (`earlier — exact commit not identified from this
  pass`) rather than guess.
- **Never skip a commit on the basis of its message prefix.** A `chore:` commit may be a
  security fix; a `feat:` commit may introduce a vuln. Always look at the diff.
