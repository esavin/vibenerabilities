"""System prompt (compact digest of the security methodology) + first-user-message builder.

The first user message is grounded in *mechanically derived* facts about the
commit: subject/message/diffstat, rename-aware name-status (R/D entries
highlighted), a precomputed list of records that still cite paths
renamed/deleted by this commit, and - for the root (initial snapshot)
commit - a directory digest of the real tree, so the agent never has to
invent scope from prior knowledge of the project.
"""

import json
import os
import re
import subprocess

SYSTEM_PROMPT = """You are one step of an automated, commit-by-commit security-analysis \
pipeline. For each project commit a fresh agent instance (you) decides whether \
that commit INTRODUCES a security vulnerability, FIXES a previously recorded \
one, or REVEALS a previously missed pre-existing one, and updates the \
vulnerability records map only when warranted. You see exactly one commit. \
This pipeline analyzes EVERY commit - NEVER skip analysis because of the \
commit message prefix: a fix:/chore:/refactor: commit may be the only signal \
of a security fix.

# Inputs (first user message)
- COMMIT metadata: sha, subject, full message, diffstat.
- NAME STATUS: per-file change list (A/M/D/R) against the parent commit. Renames (R) \
show old -> new paths; deletions (D) show the removed path.
- FULL DIFF (when present): the complete rename-aware diff of this commit. When \
present, the whole change is already in front of you - do NOT re-fetch it with \
`git show`; read worktree files only when you need surrounding context.
- STALE RECORD REFERENCES (when present): records that cite paths renamed/deleted \
by THIS commit. This is your mandatory repair worklist.
- INITIAL SNAPSHOT MODE (root commits only): replaces the diff with a TREE DIGEST \
of the real directory/file layout at this commit.
- WORKTREE: absolute path of a git worktree with THIS commit checked out. Read \
source files and run git history commands ONLY here - other copies of the repo \
are at a different point in history. The worktree is READ-ONLY context.
- RECORDS ROOT: absolute path of the vulnerability records map you may write to \
(INDEX.md, vulnerabilities/VULN-NNN-<slug>.md, design/NN-<topic>.md, \
project-conventions.md).
- MODE: "record" or "classify-only".
- The full generic methodology is at <RECORDS ROOT>/methodology.md - read it only \
if the digest below is not enough.

# Ground truth rules (hard)
- The ONLY source of truth is the repository content in the WORKTREE at this \
commit. Prior knowledge about this project - other releases, older versions, \
forks, upstream articles, public advisories - is NOT a source. Package names, \
class/method/field names, file paths and the code itself must all be read from \
the worktree before you write them.
- NEVER invent vulnerabilities. Every finding must trace to concrete evidence: \
file path + line + commit SHA. If you cannot point to evidence, do not record.
- NEVER fabricate commit SHAs. Use SHAs you read from git log / git show / git \
blame output verbatim. If you cannot determine an introduction point, write \
"earlier - exact commit not identified" rather than guess.
- Cite source files as paths relative to the REPOSITORY ROOT (the worktree \
root), exactly as they exist at this commit (verify with list_dir/read_file/ \
git ls-tree). Never prefix paths with a workspace folder name, and never cite \
a path you have not seen in the worktree.

# Workflow
1. If FULL DIFF is present in the first user message, analyze directly from it - \
do not call git show for the commit (read worktree files only when you need \
surrounding context). Otherwise inspect the commit with the git tool: \
`git show --stat <sha>`, then `git show -M <sha> -- <path>` for security-\
relevant paths (use -M so renames are followed). Read affected source files \
from the WORKTREE as they exist at this commit.
2. Run ALL THREE detection passes (below). They are not exclusive - a single \
commit can both introduce and fix different issues. Commit messages are \
unreliable - judge from the actual diff and NAME STATUS.
3. If any pass produced findings and MODE is "record": update the records map \
idempotently (rules below). If MODE is "classify-only": do the same analysis, \
write nothing, and report the verdict you WOULD have produced.
4. Always end by calling the finish tool exactly once. Verdict "VULN_UPDATED" \
when any record was created/updated or INDEX.md was refreshed; "NO_VULN" only \
when nothing changed; "ERROR" when the commit could not be inspected. After \
you finish, an automated validator checks what you wrote (record-internal \
links, unique VULN numbering, fixed records layout, that cited repo paths \
exist in the worktree, that no record still cites a path renamed/deleted by \
this commit, and that INDEX.md counts match the records). If it reports \
problems you will get one repair round: fix ONLY the listed problems with \
edit_record (targeted replacements - never rewrite whole records for a path \
fix), then IMMEDIATELY call finish again - do not re-read files, re-verify, \
or explore anything else first. Also: read_file/list_dir paths are absolute \
or relative to the WORKTREE or RECORDS ROOT themselves - never prefix them \
with a workspace folder like agent/project/. Repeated exploration near the \
step limit is cut off: watch the step counter in tool results and call \
finish in time.

# Response economy (latency-critical)
- Between tool calls, reply with the tool calls ONLY: no narration, no \
markdown analysis in message content - the pipeline consumes tool calls and \
the final finish, nothing else, and every generated token is wall-clock time.
- finish(reason) is at most 3 sentences.
- When the FULL DIFF is present and shows no security-relevant change \
(documentation, comments, tests, formatting, assets, pure UI cosmetics), call \
finish (NO_VULN) IMMEDIATELY - do not read worktree files to double-confirm \
irrelevance.

# Pass A - Introduced in this commit (forward analysis)
Examine every hunk of the diff. Flag INTRODUCTION when the added/modified \
lines exhibit any baseline dangerous pattern:
- Injection: SQL built by string concatenation with user input (CWE-89); \
command exec with concatenated/user-controlled arguments (CWE-78); \
eval/dynamic require/import/Function() on user data (CWE-94); SSTI; \
LDAP/XPath/NoSQL/header/log injection.
- XSS: user-controlled data output into HTML/JS without escaping - innerHTML, \
dangerouslySetInnerHTML, v-html, raw HTML sinks, unescaped template output \
(CWE-79).
- Path traversal: file operations on user-controlled paths without \
normalization/allow-listing, ../ not blocked, ZIP-slip, symlink following \
(CWE-22).
- Authn/authz: missing authorization on NEW endpoints, role bypass, IDOR, \
predictable tokens, session fixation, default credentials, JWT with alg:none \
or unverified signature (CWE-287, CWE-862, CWE-306, CWE-639).
- Crypto: weak/broken hashes for security (MD5, SHA1), weak ciphers/modes \
(DES, RC4, ECB), hardcoded keys/seeds, static IVs, predictable RNG for \
tokens/IDs, unsalted or fast password hashing (CWE-327, CWE-329, CWE-330).
- Secrets: hardcoded API keys, tokens, passwords, private keys, connection \
strings committed to source (CWE-798).
- Unsafe deserialization: pickle.loads, Marshal.load, \
ObjectInputStream.readObject, yaml.load without SafeLoader, PHP unserialize, \
.NET BinaryFormatter (CWE-502).
- SSRF / XXE / open redirect / CSRF: server fetch of a user-supplied URL \
without an allow-list (CWE-918); XML external entities enabled (CWE-611); \
unvalidated redirect (CWE-601); state-changing POST without anti-CSRF token \
(CWE-352).
- Insecure defaults: verbose errors leaking stack traces, debug mode on by \
default, CORS * with credentials, TLS verification disabled (verify=False, \
rejectUnauthorized: false, InsecureSkipVerify).
- Info disclosure: secrets/PII written to logs, detailed errors returned to \
clients, tokens in URLs/query strings (CWE-200, CWE-532).
- Race conditions / TOCTOU: security check then use without atomicity, \
check-then-act on shared state without synchronization (CWE-362, CWE-367).
- Dangerous dependencies: reachable imports of packages with known critical \
CVEs - only when exploitation is plausible, not every outdated dependency.
- Project-specific dangerous APIs from project-conventions.md.
When in doubt, PREFER RECORDING at severity Low/Info over skipping: a soft \
call now is recoverable (the pipeline tracks later fixes and refines \
records), a silent miss is not.

# Pass B - Fixed in this commit (backward analysis)
Fires when EITHER:
- the commit message contains (case-insensitive) any of: fix, security, \
vuln, CVE-, CWE-, XSS, CSRF, SSRF, injection, traversal, sanitize, patch, \
hotfix, hardening, auth, privilege, disclosure, leak, RCE, DoS, bypass, \
overflow, forgery, hijack - AND the diff actually removes or replaces a \
dangerous pattern (the message alone is NEVER sufficient); OR
- the diff alone swaps a dangerous pattern for a safer one: string-concat \
SQL -> parameterized; yaml.load -> yaml.safe_load; md5 -> bcrypt; \
verify=False -> verify=True; hardcoded secret -> env-var lookup; raw \
output -> escaped; missing auth check -> check added.
When Pass B fires:
1. Identify the specific issue being fixed: vulnerability class (CWE), \
affected file(s), symbol(s), and what made the old code dangerous.
2. Trace the introducing commit with the worktree's git history: \
`git log --diff-filter=A --format='%H %ad %s' --date=short -- <file>` (when \
the affected file was first added); `git log -S "<removed-dangerous-\
fragment>" --reverse --format='%H %ad %s' --date=short -- <file>` (the \
earliest hit is the introduction); `git log -L <start>,<end>:<file>`; \
`git blame <sha>^ -- <file>` (attribute surviving dangerous lines to their \
introducing commits). If the dangerous code is present in the project's \
initial commit (verify with `git log --max-parents=0`), record it as \
"pre-existing" and use the initial commit as the introduction point.
3. Match against existing records: read INDEX.md and find records describing \
THIS exact issue with search_records/read_file (matching key: file, symbol/\
range, vulnerability class - be tolerant of cosmetic edits between commits). \
If a record already describes it, APPEND this commit under its \
"### Fixed in" block - never create a duplicate.
4. If no existing record matches, create a new record with BOTH \
"### Introduced in" (from step 2) and "### Fixed in" (this commit) filled.

# Pass C - Late-discovered pre-existing issues
While reading the diff and its surrounding code you may recognize a CLEAR \
pre-existing issue that: is present at this commit, is NOT touched by this \
diff, and is NOT yet recorded under vulnerabilities/. Record it as a NEW \
record with "### Introduced in": "earlier - exact commit not identified \
from this pass; present at <sha>" and severity Info/Low. Use this pass \
SPARINGLY - only for clear, high-confidence findings - to avoid noise.

# Initial snapshot (root commit) mode
A root commit contains the whole codebase at once; there is no parent and no \
diff. This is a deep Pass C scan of the initial tree:
- Keep the pass SPARING: a handful of the clearest, highest-confidence \
findings; partial coverage is fine. Budget your steps - call finish well \
before the step limit; never let the limit cut you off.
- Work from the TREE DIGEST and from `git ls-tree` / list_dir of the \
worktree - real directories and files only, never package names or APIs \
from memory.
- Focus on DANGEROUS APIs: scan the initial tree for the baseline patterns \
above (and project-conventions dangerous APIs); record only what you can \
VERIFY in this session with file path + line + the root SHA. For these \
records set "### Introduced in" to "pre-existing in the initial commit" \
(with the root sha) and Detection how-found late-discovery.
- Do not attempt to enumerate every file; prioritize entry points, input \
handling and dangerous sinks. Later commits refine the map (idempotency), \
so partial coverage now is fine - invented coverage is not.

# Rename / move / delete handling (path hygiene)
When NAME STATUS shows renames or deletions of files that records cite (in \
Affected Code, Evidence or Remediation Notes):
1. Use the search_records tool to find EVERY record mentioning the old path \
(the precomputed STALE RECORD REFERENCES list is a starting point, not a \
guarantee of completeness).
2. Replace old paths with the new ones (for R) with edit_record - find the \
old path text, replace with the new path - keeping the rest of each record \
intact. A whole-record rewrite (write_record) for a path change is WRONG: \
it risks losing lifecycle content and is refused by the shrink guard when \
it drops half the record.
3. For deletions (D): remove or rewrite the reference - never leave a \
citation of a file that no longer exists at this commit.
4. Also fix any OTHER broken links or stale paths you notice in the records \
you touch. Path-only repairs count as VULN_UPDATED.

# Record update rules (idempotent, surgical)
1. Read INDEX.md and the relevant vulnerabilities/*.md records FIRST; decide \
NEW vs UPDATE per finding. Never duplicate a record; matching key: (file, \
symbol/range, vulnerability class). For a new record reuse the lowest free \
VULN-NNN from the RECORDS NUMBERING section (<NNN> = three digits: VULN-001, \
VULN-002, ...); <slug> is a short kebab-case description of the issue. Never \
create a second record for an ISSUE that already has one (update the \
existing file instead).
2. Create/update records using the template below. Cite source files as \
repository-root-relative paths, exactly as they exist in the worktree at the \
relevant commit. Quote Evidence lines VERBATIM from the source at the \
introducing commit.
 3. After ANY record change, refresh INDEX.md: append rows for NEW records \
at the END of the "## Findings" table (| ID | Title | Severity | Status | \
Introduced | Fixed | Record |; Record cell = the bare records-root-relative \
path of the file, e.g. vulnerabilities/VULN-NNN-<slug>.md - NOT a markdown \
link) - row order is maintained by the pipeline, \
and never add a second row for an ID the table already lists (edit that \
row instead) - flip Status (Open -> Fixed) when a record's status changes, \
refresh the "## Summary" counts (Total/Open/Fixed and per-severity \
open/total), and bump "*Last updated:*". NEVER edit the "## Sync Status" \
block at the bottom of INDEX.md - the pipeline maintains it \
deterministically.
4. In every file you modify: set *Last updated: <TODAY>* and *Areas: \
<project>, <subsystem>, security* per the conventions file (always include \
security).
5. Touch only records that correspond to real findings in THIS commit (plus \
stale-path repairs). Never fabricate.
6. write_record paths are RECORDS-ROOT-relative and the layout is FIXED: \
write only vulnerabilities/VULN-NNN-<slug>.md, design/NN-<topic>.md, \
INDEX.md, project-conventions.md, or methodology.md (<NN> = two digits: 01, \
02, ...). Do NOT prefix paths with agent/ or agent/project/ (the tool \
resolves paths against RECORDS ROOT itself) and do NOT mirror source-tree \
folders inside the records root. Keep each write_record SHORT (~150 lines \
max): if a call is ever refused with "arguments JSON is incomplete", your \
output was cut by the token limit - write the first half, then continue the \
SAME file with write_record {"path": ..., "append": true, "content": ...} \
parts.

## Vulnerability record template (vulnerabilities/VULN-NNN-<slug>.md)
# VULN-NNN: <Title>
## Summary
<one paragraph: what is wrong, impact, who could exploit it, under what trust boundary>
## Classification
- **Type:** <e.g. SQL Injection (CWE-89) / Stored XSS (CWE-79) / Hardcoded Credentials (CWE-798)>
- **Severity:** <Critical | High | Medium | Low | Info>
- **CWE:** <CWE-XXX> (<name>)
- **Status:** <Introduced | Open | Fixed>
## Affected Code
- `<repository-root-relative>/path/to/file.ext` - <function/symbol/range> - <what is vulnerable>
## Evidence
```<lang>
// the concrete vulnerable lines, quoted verbatim from the source at the introducing commit
```
## Lifecycle
### Introduced in
- commit `<short>` (`<full-sha>`, `<ISO date>`) - `<commit subject>`
  - _(pre-existing in initial commit / introduced by this commit / found via git log -S)_
### Fixed in
- _(not yet fixed - open at HEAD)_      <- if unfixed
- commit `<short>` (`<full-sha>`, `<ISO date>`) - `<commit subject>`   <- repeatable; multi-commit fixes APPEND
## Detection
- **How found:** <forward-analysis | retroactive-from-fix | late-discovery>
- **Confidence:** <high | medium | low>
- **Notes:** <caveats - assumed trust boundary, uncertain introduction point, etc.>
## Remediation Notes
<what the fix did, residual risk or follow-up; for multi-commit fixes summarise each commit's contribution>

---
*Last updated: YYYY-MM-DD*
*Areas: <project>, <subsystem>, security*

## Severity rubric
- Critical - RCE, auth bypass, full DB compromise, secrets in source reachable \
by an attacker, cryptanalytic break of a core primitive, full account takeover.
- High - SQL injection on a privileged path, stored XSS on a multi-user app, \
privilege escalation, IDOR on sensitive resources, broken access control on \
admin surfaces.
- Medium - reflected XSS, missing CSRF on a non-critical state change, weak \
password hashing, predictable tokens, verbose error leakage with exploitable \
info, SSRF to internal network.
- Low - missing security headers, insecure cookie flags on a low-impact \
session, debug logging of non-critical data, open redirect with no clear \
phishing path.
- Info - code smell with potential security implication; depends on context; \
tracked for completeness.
When in doubt between two levels, choose the HIGHER of the two and note the \
uncertainty in Detection -> Notes.

# Hard rules
- Write ONLY .md files under RECORDS ROOT; never modify the worktree or any \
other file. Read source and run git history commands ONLY in the worktree.
- The git tool is read-only (log/show/diff/blame/ls-tree/grep). Never commit, \
push, or change config. You are one step of the loop, not the loop.
- If you cannot inspect the commit (worktree missing, git fails), call finish \
with verdict "ERROR" and a reason.
- NEVER skip analysis based on the commit message prefix; a fix:/chore:/\
refactor: commit may be the only signal of a security fix.
- finish(verdict, files, reason) is the ONLY way to end. verdict: \
"VULN_UPDATED", "NO_VULN", or "ERROR"; files = records-root-relative paths \
you created/modified."""


def system_prompt():
    """The per-commit security-analysis system prompt (flat records map)."""
    return SYSTEM_PROMPT


class InspectError(Exception):
    """The commit could not be inspected in the worktree."""


def _git(worktree, argv):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        proc = subprocess.run(["git", "--no-pager", "-C", worktree] + argv,
                              capture_output=True, text=True, errors="replace",
                              timeout=60, env=env)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise InspectError(str(exc))
    if proc.returncode != 0:
        raise InspectError((proc.stderr or "unknown git error").strip()[:300])
    return proc.stdout


def _git_ok(worktree, argv):
    """Like _git but returns "" instead of raising on a non-zero exit."""
    try:
        return _git(worktree, argv)
    except InspectError:
        return ""


def _cap(text, limit):
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated, %d more chars]" % (len(text) - limit)


def is_root_commit(worktree, sha):
    """True when <sha> has no parent (the repository's initial snapshot)."""
    try:
        _git(worktree, ["rev-parse", "--verify", "--quiet", sha + "^"])
    except InspectError:
        return True
    return False


def parent_sha(worktree, sha):
    return _git_ok(worktree, ["rev-parse", "--verify", "--quiet", sha + "^"]).strip()


def _grouped_pairs(entries, max_groups=60):
    """[(old_dir, new_dir), ...] -> [((old_dir, new_dir), count), ...] sorted
    by count desc, capped."""
    groups = {}
    for key in entries:
        groups[key] = groups.get(key, 0) + 1
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))
    return ordered[:max_groups], max(0, len(ordered) - max_groups)


def name_status(worktree, parent, sha, max_am=150, max_rd=500, group_after=100):
    """Rename-aware `git diff --name-status -M parent sha`, R/D entries first.

    Returns (text, old_paths, changed) where old_paths are the pre-rename /
    deleted paths (what existing records may still cite) and changed is the
    total number of touched files (the caller sizes the agent step budget
    from it).

    Giant moves (whole-subtree renames of hundreds of files) are GROUPED by
    directory pair: a 900-line flat list is noise the model skips, while
    "test/x/ (112 files) -> testData/roundTrip/x/" is a pattern it can apply
    to every citation.
    """
    raw = _git(worktree, ["diff", "--name-status", "-M", parent, sha])
    renames, deletes, others = [], [], []
    old_paths = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        if status.startswith("R") and len(parts) >= 3:
            old, new = parts[1], parts[2]
            renames.append((old, new))
            old_paths.append(old)
        elif status.startswith("D"):
            deletes.append(parts[1])
            old_paths.append(parts[1])
        else:
            others.append((status, parts[-1]))
    changed = len(renames) + len(deletes) + len(others)
    if changed == 0:
        return "", old_paths, 0
    lines = []
    grouped = len(renames) + len(deletes) > group_after
    if renames:
        if grouped:
            lines.append("renames (old directory -> new directory, GROUPED - "
                         "%d renamed files total):" % len(renames))
            entries = [(os.path.dirname(o) or ".", os.path.dirname(n) or ".")
                       for o, n in renames]
            pairs, extra = _grouped_pairs(entries)
            lines.extend("  R  %s/*  ->  %s/*  (%d files)" % (od, nd, count)
                         for (od, nd), count in pairs)
            if extra:
                lines.append("  ... [+%d more directory groups - enumerate "
                             "with `git diff --name-status -M %s`]"
                             % (extra, sha[:10]))
        else:
            lines.append("renames (old -> new):")
            lines.extend("  R  %s  ->  %s" % (o, n) for o, n in renames[:max_rd])
    if deletes:
        if grouped:
            lines.append("deletions (GROUPED - %d deleted files total):"
                         % len(deletes))
            entries = [(os.path.dirname(d) or ".", ".") for d in deletes]
            pairs, extra = _grouped_pairs(entries)
            lines.extend("  D  %s/*  (%d files)" % (od, count)
                         for (od, _), count in pairs)
            if extra:
                lines.append("  ... [+%d more directory groups]"
                             % extra)
        else:
            lines.append("deletions:")
            lines.extend("  D  %s" % d for d in deletes[:max_rd])
    if others:
        lines.append("added/modified:")
        shown = others[:max_am]
        lines.extend("  %s  %s" % (s, p) for s, p in shown)
        if len(others) > max_am:
            lines.append("  ... [+%d more A/M entries — use `git show --stat %s`]"
                         % (len(others) - max_am, sha[:10]))
    return "\n".join(lines), old_paths, changed


def _tree_digest(worktree, sha, max_dirs=30, max_files=20000):
    """Directory digest of the tree at <sha>: real dirs + file counts."""
    raw = _git(worktree, ["ls-tree", "-r", "--name-only", sha])
    names = raw.splitlines()[:max_files]
    total = max(len(raw.splitlines()), len(names))
    per_dir = {}
    top = {}
    for name in names:
        dirn = os.path.dirname(name)
        if dirn:
            per_dir[dirn] = per_dir.get(dirn, 0) + 1
            top[dirn.split("/")[0]] = top.get(dirn.split("/")[0], 0) + 1
    lines = ["total files: %d%s" % (total,
             "  (digest capped at %d)" % max_files if total >= max_files else "")]
    lines.append("top-level entries (files inside):")
    for name, count in sorted(top.items(), key=lambda kv: (-kv[1], kv[0]))[:max_dirs]:
        lines.append("  %s  (%d files)" % (name, count))
    lines.append("largest directories (real layout — prioritize the dangerous-"
                 "API scan from THIS):")
    for name, count in sorted(per_dir.items(), key=lambda kv: (-kv[1], kv[0]))[:max_dirs]:
        lines.append("  %s  (%d files)" % (name, count))
    return "\n".join(lines)


def stale_record_references(records_root, old_paths, max_report=30, max_records=8):
    """Records that still cite paths renamed/deleted by this commit (precomputed).

    Scans ALL old paths (cited hits can sit deep in a big move commit) but
    reports at most max_report cited paths.
    """
    if not old_paths or not os.path.isdir(records_root):
        return ""
    records = []
    for dirpath, dirnames, filenames in os.walk(records_root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            if fn.lower().endswith(".md"):
                records.append(os.path.join(dirpath, fn))
    texts = {}
    for path in records:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                texts[path] = fh.read()
        except OSError:
            texts[path] = ""
    entries = []
    for old in old_paths:
        citing = []
        for path in records:
            if old in texts[path]:
                citing.append(os.path.relpath(path, records_root).replace(os.sep, "/"))
                if len(citing) >= max_records:
                    break
        if citing:
            entries.append("- %s  cited in: %s" % (old, ", ".join(citing)))
    if not entries:
        return ""
    more = ""
    if len(entries) > max_report:
        more = ("\n(+%d more cited paths — use search_records to enumerate them all)"
                % (len(entries) - max_report))
        entries = entries[:max_report]
    return "\n".join(entries) + more


# Numbering regexes for the two records-map contexts, kept in sync with the
# shapes in tools.py: vulnerabilities/ records share ONE VULN-NNN counter;
# design/ notes carry their own two-digit counter. Defined locally because
# the records map is flat (no module subdirectories to walk).
_VULN_NUMBER_RE = re.compile(r"^VULN-(\d{1,4})[-_]", re.IGNORECASE)
_NUMBER_RE = re.compile(r"^(\d{1,3})[-_]")


def _compact_ranges(numbers, width=2):
    """[1, 2, 3, 7, 9, 10] -> '01-03, 07, 09-10' (zero-padded to 2 digits;
    width=3 for VULN-NNN numbers)."""
    ranges = []
    start = prev = numbers[0]
    for n in numbers[1:]:
        if n == prev + 1:
            prev = n
            continue
        ranges.append((start, prev))
        start = prev = n
    ranges.append((start, prev))
    out = []
    fmt = "%%0%dd" % width
    for a, b in ranges:
        if a == b:
            out.append(fmt % a)
        else:
            out.append((fmt + "-" + fmt) % (a, b))
    return ", ".join(out)


def records_numbering(records_root):
    """Per-context numbering state with the exact next free number, so the
    model never guesses (a continued design/ counter must never leak into
    vulnerabilities/ - the two contexts are independent). Two contexts:
    vulnerabilities/ (VULN-NNN, three digits) and design/ (NN, two digits);
    the records map is otherwise flat."""
    lines = []

    vdir = os.path.join(records_root, "vulnerabilities")
    if os.path.isdir(vdir):
        used = []
        for name in sorted(os.listdir(vdir)):
            if name.startswith(".") or not name.lower().endswith(".md"):
                continue
            match = _VULN_NUMBER_RE.match(name)
            if match:
                used.append(int(match.group(1)))
        if used:
            used = sorted(set(used))
            lowest = 1
            while lowest in used:
                lowest += 1
            lines.append(
                "- VULN NUMBERING (vulnerabilities/): VULN numbers in use "
                "VULN-%s - the LOWEST FREE number for a NEW record here is "
                "VULN-%03d. NEVER reuse a number already in use and NEVER "
                "renumber existing records." % (_compact_ranges(used, 3), lowest))
        else:
            lines.append(
                "- VULN NUMBERING (vulnerabilities/): no records yet - the "
                "first record is VULN-001.")

    ddir = os.path.join(records_root, "design")
    if os.path.isdir(ddir):
        used = []
        for name in sorted(os.listdir(ddir)):
            if name.startswith(".") or not name.lower().endswith(".md"):
                continue
            match = _NUMBER_RE.match(name)
            if match:
                used.append(int(match.group(1)))
        if used:
            used = sorted(set(used))
            lowest = 1
            while lowest in used:
                lowest += 1
            lines.append(
                "- DESIGN NUMBERING (design/): numbers in use %s - the LOWEST "
                "FREE number for a NEW design note here is %02d. Number notes "
                "per-directory: NEVER continue another directory's numbering."
                % (_compact_ranges(used), lowest))
    return "\n".join(lines)


def records_overview(records_root, max_chars=6000, max_entries=80):
    """One line per records-map entry (id + first '# ' title), plus a visible
    "(no records yet)" marker for an EMPTY vulnerabilities/ directory.

    Mechanically rebuilt from disk for every commit - like
    records_numbering - so it can never go stale. Injecting it into the
    first user message lets the agent decide NEW vs UPDATE (never duplicate
    a finding) without spending read_file steps re-discovering the map.
    """
    def first_title(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh.read(4000).splitlines():
                    if line.startswith("# "):
                        return line[2:].strip()
        except OSError:
            pass
        return ""

    rows = []
    hub = os.path.join(records_root, "INDEX.md")
    if os.path.isfile(hub):
        rows.append("- INDEX.md - %s" % (first_title(hub) or "(untitled)"))
    vdir = os.path.join(records_root, "vulnerabilities")
    vnames = []
    if os.path.isdir(vdir):
        for name in sorted(os.listdir(vdir)):
            if name.startswith(".") or not name.lower().endswith(".md"):
                continue
            vnames.append(name)
    if vnames:
        for name in vnames:
            rows.append("- vulnerabilities/%s - %s"
                        % (name, first_title(os.path.join(vdir, name))
                           or "(untitled)"))
    elif os.path.isdir(vdir):
        rows.append("- vulnerabilities/ - (no records yet - new "
                    "VULN-NNN-<slug>.md records belong here)")
    ddir = os.path.join(records_root, "design")
    dnames = []
    if os.path.isdir(ddir):
        for name in sorted(os.listdir(ddir)):
            if name.startswith(".") or not name.lower().endswith(".md"):
                continue
            dnames.append(name)
    if dnames:
        for name in dnames:
            rows.append("- design/%s - %s"
                        % (name, first_title(os.path.join(ddir, name))
                           or "(untitled)"))
    elif os.path.isdir(ddir):
        rows.append("- design/ - (no design notes yet)")
    if not rows:
        return ""
    more = ""
    if len(rows) > max_entries:
        more = ("\n(+%d more - enumerate with list_dir vulnerabilities/ design/)"
                % (len(rows) - max_entries))
        rows = rows[:max_entries]
    text = "\n".join(rows) + more
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... [truncated]"
    return text


def focus_section(focus):
    """The scoped worklist of a path-hygiene batch session (cli splits a
    giant repair worklist into several fresh sessions; this section replaces
    the generic stale-records section and pins the session to its batch)."""
    lines = [
        "SESSION SCOPE - PATH HYGIENE (batch %d of %d; sibling sessions repair "
        "the other affected records - do NOT read or write any record outside "
        "this list, do not touch INDEX.md, do not create or renumber records):"
        % (focus.get("batch", 1), focus.get("batches", 1)),
    ]
    for record, olds in sorted(focus.get("stale", {}).items()):
        lines.append("- %s cites old paths (renamed/deleted by THIS commit):"
                     % record)
        lines.extend("    %s" % old for old in olds)
    lines.append(
        "For every cited old path: NAME STATUS above shows where this commit "
        "moved it (R entries / grouped directory moves). With edit_record "
        "replace each cited old path with its new path when it exists in the "
        "worktree (verify with list_dir/read_file), else remove or rephrase "
        "the reference - the old path no longer exists at this commit. Never "
        "rewrite a whole record for a path fix. Then call finish with verdict "
        "VULN_UPDATED listing exactly the records you modified (or NO_VULN "
        "if a listed record needed no change after all)."
    )
    return "\n".join(lines)


def build_first_user(sha, worktree, records_root, mode, today, conventions,
                     limits=None, focus=None):
    """Build the first user message. Returns (text, info) where info carries
    {"is_root": bool, "old_paths": [...], "changed": int} for the caller
    (validation old-paths and adaptive step budgeting).

    `focus` (path-hygiene batch mode): {"batch": k, "batches": n, "stale":
    {record: [old paths]}} - the session is pinned to repairing exactly these
    records; the diff injection, records numbering and the records-map
    overview are skipped (not needed for repair), keeping the session context
    minimal."""
    lim = limits if isinstance(limits, dict) else {}
    subject = _git(worktree, ["log", "-1", "--format=%s", sha]).strip()
    message = _git(worktree, ["log", "-1", "--format=%B", sha]).strip()

    root = is_root_commit(worktree, sha)
    old_paths = []
    changed = 0
    sections = []

    if root:
        sections.append(
            "INITIAL SNAPSHOT MODE: this is the ROOT commit (no parent) - the whole "
            "codebase appears at once. There is no diff; this is a deep Pass C scan "
            "of the initial tree (use it SPARINGLY - only clear, high-confidence "
            "findings): hunt dangerous APIs (the baseline patterns and any "
            "project-conventions dangerous APIs) across the TREE DIGEST below and "
            "the worktree itself; verify every path/symbol in the worktree before "
            "writing it; record with \"### Introduced in\": \"pre-existing in the "
            "initial commit (<root sha>)\". Do NOT use prior knowledge of this "
            "project (older versions, forks, upstream advisories) - the worktree "
            "at this commit is the only source."
        )
        sections.append("TREE DIGEST (git ls-tree at this commit):\n%s"
                        % _cap(_tree_digest(worktree, sha),
                               int(lim.get("tree_digest_chars") or 8000)))
    else:
        parent = parent_sha(worktree, sha)
        if parent:
            status_text, old_paths, changed = name_status(worktree, parent, sha)
            if status_text:
                sections.append("NAME STATUS (git diff --name-status -M, "
                                "renames/deletions first):\n%s"
                                % _cap(status_text,
                                       int(lim.get("name_status_chars") or 20000)))
        stat = _git(worktree, ["show", "--stat", "--format=", sha]).strip("\n")
        sections.append("DIFFSTAT (git show --stat):\n%s"
                        % _cap("\n".join(stat.splitlines()[:300]),
                               int(lim.get("diffstat_chars") or 30000)) or "(empty)")

        # FULL DIFF: when the complete change fits the cap, inject it so the
        # agent can run its three passes without a git-show round-trip (most
        # NO_VULN verdicts become a single request). Injected only whole - a
        # truncated diff would look complete but is not. 0 disables. Skipped
        # in focus mode (path-hygiene repair needs the moves, not the diff).
        diff_cap = int(lim.get("diff_chars") or 0)
        if diff_cap > 0 and parent and focus is None:
            diff = _git_ok(worktree, ["diff", "-M", parent, sha]).strip("\n")
            if diff and len(diff) <= diff_cap:
                sections.append(
                    "FULL DIFF (git diff -M parent..commit - the COMPLETE change, "
                    "nothing truncated; run your three detection passes on it "
                    "directly, no need to re-fetch with git show):\n%s" % diff
                )

    if focus is not None:
        sections.append(focus_section(focus))
    elif old_paths:
        stale = stale_record_references(records_root, old_paths)
        if stale:
            sections.append(
                "STALE RECORD REFERENCES (existing records citing paths renamed/"
                "deleted by THIS commit — your mandatory repair worklist; also run "
                "search_records for each old path):\n%s" % stale
            )

    if focus is None:
        numbering = records_numbering(records_root)
        if numbering:
            sections.append(
                "RECORDS NUMBERING (exact current state - use these numbers, do "
                "not compute your own):\n%s" % numbering
            )

        overview = records_overview(records_root,
                                    int(lim.get("records_overview_chars") or 6000))
        if overview:
            sections.append(
                "RECORDS MAP OVERVIEW (records with their titles - "
                "vulnerabilities/ records document one vulnerability each, "
                "design/ notes cross-cutting themes; decide NEW vs UPDATE from "
                "this list and never create a second record for an issue "
                "already covered; read a specific record ONLY if you will edit "
                "it):\n%s"
                % overview
            )

    if not conventions:
        conventions = ("(missing - infer conservatively from the source tree and flag "
                       "uncertainties in the record footer)")
    parts = [
        "COMMIT: %s" % sha,
        "SUBJECT: %s" % (subject or "(none)"),
        "",
        "FULL COMMIT MESSAGE:",
        message or "(none)",
        "",
    ]
    parts.extend(section + "\n" for section in sections)
    parts.extend([
        "WORKTREE: %s" % worktree,
        "RECORDS ROOT: %s" % records_root,
        "MODE: %s" % mode,
        "TODAY: %s" % today,
        "",
        "PROJECT CONVENTIONS (from project-conventions.md):",
        _cap(conventions.strip(), int(lim.get("conventions_chars") or 12000)),
        "",
        "Begin: inspect the commit, run the three detection passes, update the "
        "records map if warranted, then call finish.",
    ])
    return "\n".join(parts), {"is_root": root, "old_paths": old_paths,
                              "changed": changed}


_SHA_RE = re.compile(r"^[0-9a-fA-F]{4,40}$")


def sha_looks_valid(sha):
    return bool(sha) and bool(_SHA_RE.match(sha))


# ---- prior-run record hints (--record-hints reconsideration round) ----
# Caps keep the injected prior records comparable to the commit context
# itself: big enough to judge substance, small enough not to crowd out the
# diff.
HINT_MAX_FILES = 6
HINT_MAX_FILE_CHARS = 16_000
HINT_MAX_TOTAL_CHARS = 48_000


def load_prior_hint(prior_verdict_path, prior_records_root, records_root_rel):
    """Load a previous run's VULN_UPDATED verdict plus the records it produced.

    Returns {"files": [...], "reason": str, "docs": [(rel, content-or-None)]}
    or None when the hint is unusable (missing/unreadable verdict, verdict is
    not VULN_UPDATED, or no files listed). Each file is read from the PRIOR
    run's records root, tolerating both workspace-relative ("agent/project/
    vulnerabilities/x.md") and records-root-relative ("vulnerabilities/x.md")
    spellings; unreadable files are kept as (rel, None) so the message can
    say so.
    """
    try:
        with open(prior_verdict_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("verdict") != "VULN_UPDATED":
        return None
    files = []
    for item in data.get("files") or []:
        text = str(item).strip().replace("\\", "/")
        if text and text not in files:
            files.append(text)
    if not files:
        return None
    prefix = (records_root_rel or "").strip("/")
    docs = []
    for rel in files[:HINT_MAX_FILES]:
        candidates = [rel]
        if prefix:
            if rel.startswith(prefix + "/"):
                candidates.append(rel[len(prefix) + 1:])
            else:
                candidates.append(prefix + "/" + rel)
        content = None
        for cand in candidates:
            path = os.path.normpath(os.path.join(prior_records_root, cand))
            if os.path.isfile(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read(HINT_MAX_FILE_CHARS)
                except OSError:
                    content = None
                break
        docs.append((rel, content))
    return {"files": files, "reason": str(data.get("reason") or ""),
            "docs": docs}


def build_reconsider_message(hint, classify_only=False):
    """The one-shot reconsideration user message fed back after a NO_VULN
    finish when a previous run recorded findings for the same commit (a
    fresh rerun whose records map was reset --record-hints style)."""
    parts = []
    total = 0
    for rel, content in hint["docs"]:
        if content is None:
            parts.append("=== %s ===\n(file not found in the prior run's records "
                         "map - judge from the diff alone)" % rel)
            continue
        if total >= HINT_MAX_TOTAL_CHARS:
            parts.append("=== %s ===\n(skipped: hint size cap reached)" % rel)
            continue
        if len(content) > HINT_MAX_FILE_CHARS:
            content = content[:HINT_MAX_FILE_CHARS] + "\n... [truncated]"
        if total + len(content) > HINT_MAX_TOTAL_CHARS:
            content = (content[:HINT_MAX_TOTAL_CHARS - total]
                       + "\n... [truncated]")
        total += len(content)
        parts.append("=== %s ===\n%s" % (rel, content))
    extra = ""
    if len(hint["files"]) > HINT_MAX_FILES:
        extra = "\n(+%d more file(s) from the prior verdict not shown)\n" \
                % (len(hint["files"]) - HINT_MAX_FILES)
    action = ("report VULN_UPDATED with the files you would have written"
              if classify_only else
              "write the corresponding records now (write_record), ADAPTED to "
              "the current records map state (numbering, INDEX.md rows, cited "
              "paths), then finish with VULN_UPDATED")
    reason = ("Prior run's finish reason: %s\n" % hint["reason"]
              if hint["reason"] else "")
    return (
        "RECONSIDER - prior-run record hint for THIS commit.\n"
        "\n"
        "An earlier run of this pipeline classified this commit as "
        "VULN_UPDATED and produced the records attached below. You have just "
        "finished with NO_VULN. The records map was reset before this rerun, "
        "so the prior records no longer exist - re-derive the same findings "
        "from THIS commit's diff and the worktree instead of trusting the "
        "attachments blindly:\n"
        "- if the vulnerability (or fix) described below is real for THIS "
        "commit's diff and is NOT already covered by the current records "
        "map, %s;\n"
        "- if the current map already covers it adequately, or the prior "
        "record is stale or wrong for this diff, keep NO_VULN and justify "
        "briefly in the finish reason.\n"
        "\n"
        "The prior records are reference material - do NOT copy them "
        "blindly; re-check numbering, INDEX.md rows, cited paths and the "
        "evidence against the CURRENT map and worktree.\n"
        "%s%s\n"
        "This reconsideration is offered exactly once: call finish now with "
        "your FINAL verdict." % (action, reason, extra)
    ) + "\n" + "\n\n".join(parts)


# ---- snapshot bootstrap (run.sh --snapshot; vuln_agent/snapshot.py) ----
# One planner request partitions the tree into security-review modules;
# then ONE agent session per module deep-scans that module's share of the
# CURRENT tree for pre-existing vulnerabilities. The baseline then jumps
# to the snapshot commit and only NEW commits are replayed - the only sane
# cost curve for histories of tens of thousands of commits.

SNAPSHOT_SYSTEM_PROMPT = """You are one session of an automated security-analysis \
pipeline that bootstraps a vulnerability records map from the CURRENT tree \
of a project (a "snapshot" - no commit history is replayed; every file in \
the worktree is at the snapshot REF state). Your session owns exactly ONE \
module. You deep-scan that module's code for PRE-EXISTING vulnerabilities \
(late-discovery semantics at scale) and write one record per clear finding.

# Ground truth rules (hard)
- The ONLY source of truth is the repository content in the WORKTREE at the \
REF. Prior knowledge about this project - other releases, older versions, \
forks, upstream articles, public advisories - is NOT a source. Package \
names, class/method/field names, file paths and the code itself must all be \
read from the worktree before you write them.
- NEVER invent vulnerabilities. Every finding must trace to concrete \
evidence: file path + line + the REF worktree. If you cannot point to \
evidence, do not record.
- NEVER fabricate commit SHAs. In snapshot mode the introducing commit is \
NOT traced - write the fixed wording below instead of guessing an origin.
- Cite source files as paths relative to the REPOSITORY ROOT (the worktree \
root), exactly as they exist at the REF (verify with list_dir/read_file/ \
git ls-tree).

# How to scan (in this order)
1. Read the module's key files from the TREE DIGEST and the module source \
roots - entry points first, then input handling, then the dangerous sinks.
2. Flag any baseline dangerous pattern on lines PRESENT at the REF: \
injection (SQL string concat, command exec with user input, eval/dynamic \
import, SSTI, LDAP/XPath/NoSQL/header/log injection); XSS (raw HTML \
sinks - innerHTML, dangerouslySetInnerHTML, v-html, unescaped template \
output); path traversal (user-controlled paths without normalization/\
allow-listing, ../, ZIP-slip, symlinks); authn/authz gaps (missing auth on \
sensitive endpoints, role bypass, IDOR, predictable tokens, session \
fixation, default credentials, JWT alg:none/unverified); weak crypto (MD5/\
SHA1 for security, DES/RC4/ECB, hardcoded keys/seeds, static IVs, \
predictable RNG, unsalted/fast password hashing); hardcoded secrets (keys, \
tokens, passwords, private keys, connection strings); unsafe \
deserialization (pickle.loads, Marshal.load, ObjectInputStream.readObject, \
yaml.load without SafeLoader, PHP unserialize, .NET BinaryFormatter); SSRF, \
XXE, open redirect, CSRF; insecure defaults (verbose errors, debug mode on, \
CORS * with credentials, TLS verification disabled - verify=False, \
InsecureSkipVerify); info disclosure (secrets/PII in logs, detailed errors \
to clients, tokens in URLs); race conditions/TOCTOU; reachable imports of \
packages with known critical CVEs. Add any project-specific dangerous API \
from project-conventions.md.
3. Calibrate severity to the rubric below; when in doubt between two \
levels choose the HIGHER and note the uncertainty in Detection -> Notes.
4. COMPLETENESS BIAS: a snapshot session that records nothing plausible \
for a large module is suspicious - but the evidence rule stands: NEVER \
record a finding you cannot back with file path + line from the worktree.
Budget your steps: verify by reading the module's key files, write the \
records, call finish before the step limit. Partial coverage is fine - \
invented coverage is not.

# Record update rules
1. Records you create follow the template below. Take the number from the \
RECORDS NUMBERING section (lowest free VULN-NNN - use it, do not compute \
your own); <slug> is a short kebab-case description of the issue.
2. Every record from this scan gets Detection "How found:" late-discovery \
(snapshot scan) and "### Introduced in": "earlier - pre-existing at <ref> \
(snapshot)". NEVER fabricate an introducing SHA - the exact origin is not \
traced in snapshot mode.
3. Refresh INDEX.md after each record: append its row at the END of the \
"## Findings" table (| ID | Title | Severity | Status | Introduced | Fixed \
| Record |; Record cell = the bare records-root-relative path of the file, \
e.g. vulnerabilities/VULN-NNN-<slug>.md - NOT a markdown link) - \
row order is maintained by the pipeline, and never add a \
second row for an ID the table already lists (edit that row instead) - \
refresh the "## Summary" counts (Total/Open/Fixed and per-severity \
open/total), bump "*Last updated:*". NEVER edit the "## Sync Status" block \
at the bottom of INDEX.md - the pipeline maintains it deterministically.
4. In every file you write: set *Last updated: <TODAY>* and *Areas: \
<project>, <subsystem>, security* per the conventions file (always include \
security).
5. Touch only findings from YOUR module's source roots; other modules \
belong to sibling sessions running against the same tree.
6. write_record paths are RECORDS-ROOT-relative; keep each call SHORT \
(~150 lines max) and split longer records with {"append": true} parts.
7. Always end by calling the finish tool exactly once with verdict \
"VULN_UPDATED" and files = the records-root-relative paths you created/\
modified (or "NO_VULN" when the module genuinely has no recordable \
findings; "ERROR" when the worktree is unusable).

## Vulnerability record template (vulnerabilities/VULN-NNN-<slug>.md)
# VULN-NNN: <Title>
## Summary
<one paragraph: what is wrong, impact, who could exploit it, under what trust boundary>
## Classification
- **Type:** <e.g. SQL Injection (CWE-89) / Stored XSS (CWE-79) / Hardcoded Credentials (CWE-798)>
- **Severity:** <Critical | High | Medium | Low | Info>
- **CWE:** <CWE-XXX> (<name>)
- **Status:** <Introduced | Open | Fixed>
## Affected Code
- `<repository-root-relative>/path/to/file.ext` - <function/symbol/range> - <what is vulnerable>
## Evidence
```<lang>
// the concrete vulnerable lines, quoted verbatim from the source at the snapshot ref
```
## Lifecycle
### Introduced in
- earlier - pre-existing at <ref> (snapshot)
### Fixed in
- _(not yet fixed - open at the analyzed HEAD)_
## Detection
- **How found:** late-discovery (snapshot scan)
- **Confidence:** <high | medium | low>
- **Notes:** <caveats - assumed trust boundary, etc.>
## Remediation Notes
<what would fix it, and any residual risk or follow-up>

---
*Last updated: YYYY-MM-DD*
*Areas: <project>, <subsystem>, security*

## Severity rubric
- Critical - RCE, auth bypass, full DB compromise, secrets in source reachable \
by an attacker, cryptanalytic break of a core primitive, full account takeover.
- High - SQL injection on a privileged path, stored XSS on a multi-user app, \
privilege escalation, IDOR on sensitive resources, broken access control on \
admin surfaces.
- Medium - reflected XSS, missing CSRF on a non-critical state change, weak \
password hashing, predictable tokens, verbose error leakage with exploitable \
info, SSRF to internal network.
- Low - missing security headers, insecure cookie flags on a low-impact \
session, debug logging of non-critical data, open redirect with no clear \
phishing path.
- Info - code smell with potential security implication; depends on context; \
tracked for completeness.
When in doubt between two levels, choose the HIGHER of the two and note the \
uncertainty in Detection -> Notes.

# Hard rules
- Write ONLY .md files under RECORDS ROOT, and only findings from YOUR \
module's source roots; never modify the worktree or any other file.
- The git tool is read-only (log/show/diff/blame/ls-tree/grep).
- finish(verdict, files, reason) is the ONLY way to end. verdict: \
"VULN_UPDATED", "NO_VULN", or "ERROR"; files = records-root-relative paths \
you created/modified."""


def tree_digest_paths(worktree, ref, paths, max_dirs=30, max_files=20000):
    """Directory digest of the tree at <ref> restricted to <paths> (a module's
    source roots). Same shape as _tree_digest so both read naturally."""
    argv = ["ls-tree", "-r", "--name-only", ref, "--"] + list(paths)
    raw = _git(worktree, argv)
    names = raw.splitlines()[:max_files]
    total = max(len(raw.splitlines()), len(names))
    per_dir = {}
    for name in names:
        dirn = os.path.dirname(name)
        if dirn:
            per_dir[dirn] = per_dir.get(dirn, 0) + 1
    lines = ["total files under this module's roots: %d%s"
             % (total, "  (digest capped at %d)" % max_files
                if total >= max_files else "")]
    lines.append("directories (real layout - read the key files from THIS):")
    for name, count in sorted(per_dir.items(), key=lambda kv: (-kv[1], kv[0]))[:max_dirs]:
        lines.append("  %s  (%d files)" % (name, count))
    if not names:
        lines.append("  (no files found under the module roots - check with "
                     "git ls-tree)")
    return "\n".join(lines)


def build_snapshot_user(module, ref, worktree, records_root, today, conventions,
                        limits=None):
    """First user message of one per-module snapshot session.

    `module` = {"module": slug, "title": str, "paths": [...], "summary": str}
    from the planner (or the mechanical fallback partition)."""
    lim = limits if isinstance(limits, dict) else {}
    sections = []
    slug = module["module"]
    sections.append(
        "MODULE: %s - %s\n%s" % (slug, module.get("title") or slug,
                                 module.get("summary") or ""))
    sections.append("MODULE SOURCE ROOTS (the files below these roots are "
                    "yours; other modules belong to sibling sessions):\n%s"
                    % "\n".join("- %s" % p for p in module.get("paths") or []))
    sections.append("TREE DIGEST at the snapshot ref, restricted to your "
                    "module's roots:\n%s"
                    % _cap(tree_digest_paths(worktree, ref,
                                             module.get("paths") or []),
                           int(lim.get("tree_digest_chars") or 8000)))
    sections.append(
        "YOUR FILES: records vulnerabilities/VULN-NNN-<slug>.md plus the "
        "INDEX.md rows for them (design/NN-<topic>.md notes only when a "
        "cross-cutting theme genuinely needs one).")
    numbering = records_numbering(records_root)
    if numbering:
        sections.append("RECORDS NUMBERING (exact current state - use these "
                        "numbers, do not compute your own):\n%s" % numbering)
    overview = records_overview(records_root,
                                int(lim.get("records_overview_chars") or 6000))
    if overview:
        sections.append(
            "RECORDS MAP OVERVIEW (records with their titles; to see another "
            "module's findings read INDEX.md - do NOT re-list it):\n%s" % overview)
    if not conventions:
        conventions = ("(missing - infer conservatively from the source tree and flag "
                       "uncertainties in the record footer)")
    parts = [
        "SNAPSHOT BOOTSTRAP: security-scan the CURRENT TREE of module \"%s\"." % slug,
        "",
        "This is not a commit review: every file in the worktree is at the "
        "snapshot ref. Deep-scan this module for pre-existing vulnerabilities "
        "and write the records now.",
        "",
    ]
    parts.extend(section + "\n" for section in sections)
    parts.extend([
        "WORKTREE: %s" % worktree,
        "RECORDS ROOT: %s" % records_root,
        "MODE: record",
        "TODAY: %s" % today,
        "REF: %s" % ref,
        "",
        "PROJECT CONVENTIONS (from project-conventions.md):",
        _cap(conventions.strip(), int(lim.get("conventions_chars") or 12000)),
        "",
        "Begin: scan your module's key files for dangerous patterns, write "
        "the records and refresh INDEX.md, then call finish.",
    ])
    return "\n".join(parts)


PLANNER_SYSTEM = """You are the module planner of an automated security-analysis \
pipeline. Given a digest of a repository tree, partition the source tree \
into SECURITY-REVIEW MODULES: coherent code areas a security reviewer would \
sweep as one unit. Reply with ONLY a JSON array (no markdown fences, no \
prose), each element:
{"module": "<lowercase-slug>", "title": "<Short Title>", "paths": ["<repo path prefix>", ...], "summary": "<one sentence>"}
Rules:
- 3 to 25 modules; each module's paths are repository-root-relative directory \
prefixes that exist in the digest.
- Cover the SOURCE code; you may skip obvious non-reviewable trees (build \
scripts, vendored dependencies, test fixtures, generated code) by simply not \
listing them.
- Slugs: lowercase ASCII letters, digits and dashes only.
- Prefer grouping a large uniform tree (e.g. many sibling subsystem \
directories) into a few modules over one module per leaf directory."""


def build_planner_user(tree_digest_text, conventions):
    return (
        "Partition this repository into security-review modules.\n\n"
        "TREE DIGEST:\n%s\n\n"
        "PROJECT CONVENTIONS:\n%s\n\n"
        "Reply with ONLY the JSON array."
        % (tree_digest_text, (conventions or "(none)")[:4000])
    )
