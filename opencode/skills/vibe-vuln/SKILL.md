---
name: vibe-vuln
description: Use when creating or updating the project's security-vulnerability records under agent/project/ (INDEX.md navigation hub, vulnerabilities/VULN-NNN-*.md per-issue records, optional design/*.md cross-cutting notes). Covers both incremental per-commit analysis driven by agent/vibenerabilities/run.sh and ad-hoc/manual analysis requests. Loads the generic methodology and per-project conventions.
---

# Skill: Record security vulnerabilities

You maintain the project's **security-vulnerability map** under `agent/project/`.

## Binding references (read these first)
- Methodology (generic, portable): `agent/project/methodology.md`
- This project's specifics: `agent/project/project-conventions.md`
- Navigation hub you keep in sync: `agent/project/INDEX.md`

## What "the map" is
A 2-level hierarchy (plus an optional 3rd):
1. `INDEX.md` — overview + summary counts + a table of all findings.
2. `vulnerabilities/VULN-<NNN>-<slug>.md` — one record per issue, end-to-end:
   *what* is wrong, *where* in code, *when* introduced, *when* fixed (one or more commits),
   *how* detected, *how severe*.
3. (optional) `design/*.md` — cross-cutting themes (auth model, crypto audit,
   input-validation strategy, dependency CVEs) when many findings share a root cause.

The goal: a reader finds, by ID or by description, the full lifecycle of any security
issue — introduced-when, fixed-when, evidence, severity. **High signal, full
traceability.**

## Decision rule: record vs skip
Record when a commit **introduces** a security issue, **fixes** one (verified against the
diff — message alone is insufficient), or **reveals** a previously-missed pre-existing
issue. Skip only when nothing security-relevant changed. Unlike the documentation
pipeline, **`fix:` and `chore:` commits are NOT skipped** — they may be the only signal of
a security fix.

## When invoked incrementally (per-commit)
You are one step of `vibenerabilities/run.sh`. A commit is checked out in a worktree. Run
all three detection passes per `methodology.md`:

1. **Pass A — Introduced** (forward analysis of the diff for new dangerous patterns).
2. **Pass B — Fixed** (backward analysis: when the message or the diff indicates a fix,
   trace the origin via `git -C <worktree> log -S`/`log --diff-filter=A`/`blame <sha>^`,
   then either update the matching existing record or create one with both Introduced-in
   and Fixed-in filled).
3. **Pass C — Late discovery** (a high-confidence pre-existing issue not yet tracked).

Then update records idempotently (read existing records first, never duplicate, **append**
multi-commit fixes to the same record's `## Fixed in`), refresh `INDEX.md`, and emit the
verdict line to the verdict file whose path was passed to the command as `$3`, exactly as
the `vuln-commit` command specifies.

## Always
- Cite full source-root-relative paths (prefix per `project-conventions.md`).
- Cite **concrete commit SHAs** for Introduced-in and Fixed-in — read them from
  `git log`/`git blame` output verbatim. Never fabricate SHAs.
- Bump `*Last updated: YYYY-MM-DD*` and tag `*Areas: ..., security*` in every file you
  touch.
- Keep `INDEX.md` table and Summary counts in sync when records change.
- For multi-commit fixes: append every fixing commit to the **same** record. Never split
  one issue into multiple records.
- Be surgical and idempotent.
- If you cannot point to evidence (file + line + SHA), do not record.

## Never
- Do not invent vulnerabilities or fabricate SHAs.
- Do not skip a commit on its message prefix alone — always look at the diff.
- Do not rely on commit messages alone for "fix" — verify against the diff.
- Do not duplicate records. Read existing ones first.
