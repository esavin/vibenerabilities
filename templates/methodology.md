# How to Record Security Vulnerabilities

## Purpose

This document is the **generic, language-agnostic methodology** for finding and recording
security vulnerabilities and security issues in the analyzed project. It is the same in
every project you apply the pipeline to.

Project-specific information (language, framework, dangerous APIs, idiomatic risks,
commit-message style) lives in:

→ [`./project-conventions.md`](./project-conventions.md)

The records live in `agent/project/` and capture **the security lifecycle** of every issue
discovered: when it was introduced, when (and how) it was fixed, and whether it is still
open at the analyzed HEAD.

> Two modes of operation:
> - **Incremental (per-commit)** — driven by `vibenerabilities/run.sh`, which replays the
>   project commit-by-commit (stateful replay) and invokes the `vuln-commit` command for
>   each. See *Incremental mode* below.
> - **Manual** — a human or agent edits records directly following the same rules.

## Core Goal

Produce a **navigable map of security issues**: for each issue, a reader can find the code
that was vulnerable, the commit that introduced the problem, and the commit(s) that fixed
it. The map supports triage, audit, and learning.

This means:
- **Analyze every commit** — no skip filter. A `fix:` commit may be a security fix; a
  `feat:` commit may introduce a vulnerability. Skip nothing on the basis of message prefix
  alone.
- Every record **traces to source files** and **specific commits** with concrete paths and
  SHAs.
- The map is **built up incrementally** as the analysis walks the project's history.

---

## Documentation Structure

### Level 1 — `INDEX.md`
**Location:** `agent/project/INDEX.md`
**Purpose:** High-level overview and navigation table.
**Contents:** project description; summary counts (total / open / fixed by severity); a
table of all findings (ID, title, severity, status, introduced-at, fixed-at, link to
record); links to aggregated design notes if any.
**Update when:** a record is created, status changes (Open → Fixed), severity changes, or
counts shift.

### Level 2 — Vulnerability Records
**Location:** `agent/project/vulnerabilities/*.md`
**Naming:** `VULN-<NNN>-<slug>.md` (e.g. `VULN-001-sql-injection-in-login.md`). `<NNN>` is
a zero-padded sequential ID, stable for the lifetime of the record; reuse the lowest free
number for new records. `<slug>` is a short kebab-case description of the issue.
**Purpose:** Document one security issue end-to-end.
**Template:**
````markdown
# <VULN-NNN>: <Title>

## Summary
<one-paragraph description: what is wrong, what is the impact, who could exploit it, under
what trust boundary>

## Classification
- **Type:** <e.g. SQL Injection (CWE-89) / Stored XSS (CWE-79) / Hardcoded Credentials (CWE-798)>
- **Severity:** <Critical | High | Medium | Low | Info>
- **CWE:** <CWE-XXX> (<name>)
- **Status:** <Introduced | Open | Fixed>

## Affected Code
- `<source-root-relative>/path/to/file.ext` — <function/symbol/range> — <what is vulnerable>
- (additional files / cross-references as needed)

## Evidence
```<lang>
// the concrete vulnerable lines, quoted from the source at the introducing commit
```

## Lifecycle
### Introduced in
- commit `<short>` (`<full-sha>`, `<ISO date>`) — `<commit subject>`
  - _(pre-existing in initial commit / introduced by this commit / found via git log -S)_

### Fixed in
- _(not yet fixed — open at HEAD)_      ← if unfixed
- commit `<short>` (`<full-sha>`, `<ISO date>`) — `<commit subject>`   ← repeatable for multi-commit fixes

## Detection
- **How found:** <forward-analysis-of-introducing-commit | retroactive-from-fix-commit | late-discovery-at-<sha>>
- **Confidence:** <high | medium | low>
- **Notes:** <any caveats — assumed trust boundary, dependency on missing input validation
  upstream, uncertain introduction point, etc.>

## Remediation Notes
<what the fix did, and any residual risk or follow-up. For multi-commit fixes, summarise
each commit's contribution.>

---
*Last updated: YYYY-MM-DD*
*Areas: <area>, security*
````
**Update when:** new finding; status change; a new fix commit lands on an existing issue;
refinement of evidence or classification.

### Level 3 — (Optional) Aggregated Design Notes
**Location:** `agent/project/design/*.md`
**Naming:** `<NN>-<topic>.md` (e.g. `01-auth-model.md`, `02-crypto-audit.md`).
**Purpose:** Cross-cutting themes — e.g. "auth model and known gaps", "crypto usage
audit", "input-validation strategy", "dependency CVEs". Useful when many individual
findings share a root cause. Created on demand only — not required.

---

## Incremental Mode (per-commit, stateful replay)

The pipeline checks out each commit into a disposable git worktree and asks the agent:
*"does this commit introduce a security issue, fix one, or expose a previously-missed one?
If yes, update the records; if no, do nothing."* The whole point is a **fresh, small
context per commit**, so nothing gets missed and the agent never has to swallow the entire
codebase at once.

### Step 1 — Three detection passes

Run **all three** passes on every commit. They are not exclusive — a single commit can both
introduce and fix different issues.

**Pass A — Introduced in this commit (forward analysis).** Examine every diff hunk. Flag
introduction when newly added/modified lines exhibit a known dangerous pattern from the
list below (SQL string concat, command exec with user input, raw HTML output, path
traversal, unsafe deserialization, weak crypto, hardcoded secrets, missing auth, XXE,
SSRF, etc.). Use `project-conventions.md → Project-specific dangerous APIs` as additional
hints.

**Pass B — Fixed in this commit (backward analysis).** Flag a fix when **either**:
- the commit message indicates a security fix (`fix`, `security`, `vulnerability`,
  `CVE-`, `CWE-`, `XSS`, `CSRF`, `SSRF`, `injection`, `traversal`, `escape`, `sanitize`,
  `patch`, `hotfix`, `hardening`, `auth`, `privilege`, `disclosure`, `leak`, `RCE`, `DoS`,
  `bypass`, `overflow`, …) **and** the diff actually removes/replaces a dangerous pattern; **or**
- the diff alone removes a dangerous pattern and adds a safer alternative (string-concat
  SQL → parameterized; raw output → escaped; hardcoded secret → env-var lookup;
  `yaml.load` → `yaml.safe_load`; etc.).

Then **trace the origin** via the worktree's git history:
- `git -C <worktree> log --diff-filter=A --format='%H %ad %s' -- <file>` — when the
  affected file was first added.
- `git -C <worktree> log -S "<removed-dangerous-fragment>" --reverse --format='%H %ad %s' -- <file>`
  — when the dangerous construct first appeared (`-S` picks up the add; reverse puts the
  earliest first).
- `git -C <worktree> blame -t <sha>^ -- <file>` (or `blame` at `$1^`) — to attribute the
  surviving dangerous lines to their introducing commits.
- If the dangerous code is present in the project's initial commit, record it as
  `pre-existing` and use the initial commit as the introduction point.

**Pass C — Late-discovered pre-existing issues.** While reading the surrounding code at
this commit, you may recognize a clear pre-existing issue that:
- is present at this commit,
- is **not** in this commit's diff (i.e. not introduced here), and
- has **not yet been recorded** under `agent/project/vulnerabilities/`.

Record it as a new finding with `## Introduced in` set to "earlier — exact commit not
identified from this pass; present at `$1`" and severity `Info`/`Low`. Use this pass
sparingly (only for clear, high-confidence findings) to avoid noise.

**When Pass A and Pass B disagree** (e.g. a commit fixes one issue and introduces another),
record **both** findings.

### Step 2 — If any finding: update idempotently
1. **Read existing records first.** Read `INDEX.md` and every `vulnerabilities/*.md`.
   Decide whether each finding is NEW or UPDATE. Never duplicate.
2. **NEW** → create `vulnerabilities/VULN-<NNN>-<slug>.md` from the template. Pick the
   lowest free number.
3. **UPDATE** → open the matching record; add this commit to `## Introduced in` (rare —
   only if the original introduction turned out to span multiple commits) or `## Fixed in`
   (typical for fix commits — append, never overwrite). Refresh `## Status`, `## Severity`,
   `## Evidence`, and `## Remediation Notes`.
4. **Update `INDEX.md`** — add a row for a new record; flip status (Open → Fixed) when a
   record's status changes; refresh the severity counts in the Summary block.
5. **Bump timestamps** (`*Last updated: YYYY-MM-DD*`) in every file you modify.
6. **Tag areas** (`*Areas: ...*`) per the conventions file — always include `security`.
7. Be **surgical**: touch only records that correspond to real findings in THIS commit. Do
   not rewrite untouched records. Do not fabricate SHAs or line numbers.

### Step 3 — Emit a verdict
After deciding, write exactly one line to the verdict file whose path was passed to the
command as `$3`:
- `VERDICT: NO_VULN` — no findings; nothing written.
- `VERDICT: VULN_UPDATED <comma-separated relative doc paths>` — records were created or
  changed (list only files under `agent/project/`).
In `classify-only` (dry-run) mode, decide and emit the verdict **without writing any
records**.

---

## What counts as a vulnerability (language-agnostic heuristics)

Use these categories as the baseline. The conventions file may add project-specific ones.

### Injection
- **SQL injection (CWE-89)** — SQL built by concatenating/gluing strings with
  user-controlled input instead of parameterized queries or an ORM.
- **Command injection (CWE-78)** — `exec`/`system`/`Runtime.exec`/`child_process`/
  `subprocess`/`os/exec`/backticks with concatenated or user-controlled arguments.
- **Code injection (CWE-94)** — `eval`, `Function(...)`, `vm.runInNewContext`, dynamic
  `require`/`import` on user data.
- **LDAP / XPath / NoSQL / header injection / log injection** — analogously.
- **Expression-language / SSTI** — user input fed into a template engine (`Jinja2` from a
  string, `Mustache` render of unescaped input, `eval`-style template engines).

### Cross-Site Scripting (XSS, CWE-79)
Reflected, stored, or DOM-based. Output of user-controlled data into HTML/JS without
escaping; `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, unescaped template output,
triple-brace `{{{ }}}`.

### Path Traversal (CWE-22)
File operations (`open`, `readFile`, `File`, `Path.GetFullPath`, `ioutil.ReadFile`,
`os.Open`) on user-controlled paths without normalization/allow-listing; `../` not blocked;
ZIP-slip; symlink-following on user-supplied paths.

### Authentication & Authorization (CWE-287, CWE-862, CWE-306, CWE-639)
Missing auth checks on sensitive endpoints; role bypass; **IDOR** (insecure direct object
reference); predictable tokens; session fixation; default credentials; JWT with `alg:
none`, weak secret, or unverified signature; password reset tokens with weak expiry /
binding.

### Cryptography (CWE-327, CWE-326, CWE-329, CWE-330)
- Weak/broken hashes for security (MD5, SHA1, NTLM).
- Weak/broken ciphers/modes (DES, 3DES, RC4, ECB, AES-CBC without MAC / padding oracle).
- Hardcoded keys/seeds; static or non-random IVs; predictable RNG (`Math.random`,
  `random.random`, `rand`) used for tokens, IDs, nonces, or keys.
- Passwords hashed without a salt, or with a fast hash (no bcrypt/scrypt/argon2/PBKDF2 with
  sufficient rounds).

### Secrets (CWE-798)
Hardcoded API keys, tokens, passwords, private keys, connection strings; default passwords
shipped in code or config; secrets committed to source.

### Deserialization (CWE-502)
`pickle.loads`, `Marshal.load`, `ObjectInputStream.readObject`, `yaml.load` without
`SafeLoader`, PHP `unserialize`, .NET `BinaryFormatter`, Java XMl binding on untrusted
data.

### SSRF (CWE-918), XXE (CWE-611), Open Redirect (CWE-601), CSRF (CWE-352)
Server fetches a user-supplied URL without an allow-list; XML parser with external
entities enabled; redirect to a user-supplied URL without validation; state-changing POST
without anti-CSRF token or same-origin check.

### Insecure Defaults & Misconfiguration
Verbose error pages leaking stack traces; debug mode on by default; CORS `*` with
credentials; missing security headers; insecure cookie flags (`HttpOnly`, `Secure`,
`SameSite`); TLS verification disabled (`verify=False`, `rejectUnauthorized: false`,
`InsecureSkipVerify: true`, `CURLOPT_SSL_VERIFYPEER: false`).

### Information Disclosure (CWE-200, CWE-532)
Secrets/PII written to logs; detailed errors returned to clients; directory listing
enabled; sensitive data in URLs (tokens in query strings); stack traces / SQL errors to
clients.

### Race Conditions / TOCTOU (CWE-362, CWE-367)
Security check then use without atomicity; file-based locks; check-then-act on shared
state without synchronization.

### Dangerous Dependencies
Imports of packages with publicly known critical CVEs **that are actually reachable** from
the analyzed code path. Do not flag every outdated dependency — only when exploitation is
plausible given how the code uses the package.

### Project-specific
Anything listed in `project-conventions.md → Project-specific dangerous APIs`.

---

## Severity Rubric

- **Critical** — Remote code execution, auth bypass, full DB compromise, secrets in source
  reachable by an attacker, cryptanalytic break of a core primitive, full account takeover.
- **High** — SQL injection on a privileged path, stored XSS on a multi-user app, privilege
  escalation, IDOR on sensitive resources, broken access control on admin surfaces.
- **Medium** — Reflected XSS, missing CSRF on a non-critical state change, weak password
  hashing, predictable tokens, verbose error leakage with exploitable info, SSRF to
  internal network.
- **Low** — Missing security headers, insecure cookie flags on a low-impact session, debug
  logging of non-critical data, open redirect with no clear phishing path.
- **Info** — Code smell with potential security implication; depends on context; tracked
  for completeness.

When in doubt between two levels, choose the higher of the two and note the uncertainty in
`Detection → Notes`.

---

## Documentation Principles

1. **Traceability** — every record cites specific file paths, specific lines, specific
   commit SHAs. If you cannot point to evidence, do not record.
2. **Lifecycle-first** — `## Introduced in` and `## Fixed in` are the heart of each
   record. Every record has at least one of the two filled; if neither is known, it is not
   a recordable finding yet.
3. **Idempotency** — re-running over the same commits must refine records, never duplicate
   them. Always check existing records before creating new ones.
4. **Honesty** — record `Confidence: low` rather than inflate; mark `Detection:
   late-discovery` rather than pretend a forward analysis caught it; never fabricate SHAs.
5. **Completeness over noise** — prefer recording with `Low`/`Info` severity over silent
   omission; but never invent issues. False negatives are worse than low-severity noise.
6. **Multi-commit fixes** — append every fixing commit to `## Fixed in` on the **same**
   record. Do not split one issue into multiple records just because the fix landed in
   several commits.
7. **Surgical edits** — touch only records corresponding to real findings in THIS commit.

## File Organization
```
agent/project/
├── methodology.md             # this generic methodology
├── project-conventions.md     # per-project specifics (language, framework, dangerous APIs)
├── INDEX.md                   # navigation hub + counts + table + Sync Status
├── vulnerabilities/
│   ├── VULN-001-<slug>.md     # one record per issue
│   └── …
└── design/                    # optional: cross-cutting theme notes
```

## DO / DON'T
**DO:** cite concrete paths/lines/SHAs; mark status accurately; bump timestamps; tag areas
with `security`; check existing records before creating new ones; append every fix commit
for multi-commit fixes; record `Confidence` and `How found` honestly.
**DON'T:** invent vulnerabilities or fabricate SHAs; duplicate records; omit both
`## Introduced in` and `## Fixed in`; classify without consulting the diff; rely on commit
messages alone for "fix"; leave broken links or stale counts in `INDEX.md`; skip a commit
because its message looks innocuous.

---
*Last updated: 2026-07-17*
*Document: methodology.md (generic, portable)*
