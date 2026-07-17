# Project Conventions — @@PROJECT_NAME@@

> Per-project specifics for the security-analysis pipeline. The generic methodology lives
> in [`./methodology.md`](./methodology.md). **Edit this file** to match your project's
> stack — it is the main thing you customize per project. The `vuln-commit` agent reads
> both files on every run.

## Identity
- **Project name:** @@PROJECT_NAME@@
- **Source root** (matches `vibenerabilities/config.json` → `source_root`): `@@SOURCE_ROOT@@`
  (a folder containing the project's git repository, gitignored by the analysis workspace).
- **Default branch:** @@BRANCH@@
- **Detected language:** @@LANGUAGE@@
- **Layout:** @@LAYOUT@@

## Stack / language conventions
<!-- Fill these in. Examples below; replace with what's true for YOUR project. -->
- **Language:** @@LANGUAGE@@. Reference the appropriate source file extensions.
- **Runtime / framework:** (e.g. Node+Express, Django, Spring Boot, Rails, Go stdlib …)
- **Path prefix** to use in record source references: `@@SOURCE_ROOT@@/...`
- **Module / package shape:** (e.g. monorepo packages, single `src/`, Go modules …)
- **Authoritative references:** link to the project's own SECURITY.md / contributing /
  architecture docs if they exist.

## Project-specific dangerous APIs
<!-- List idiomatic dangerous APIs/patterns for this stack. The agent uses these as hints,
     in addition to the generic categories in methodology.md. This is the single most
     useful section to fill in — it tells the agent exactly what to look for. -->
- _(examples — replace with what's true for your project)_
- _SQL: `db.query("... " + userInput)` is a SQLi; safe is `db.query(sql, [params])` or an ORM._
- _HTML: `{{{ value }}}` (triple-brace, unescaped) / `v-html` / `dangerouslySetInnerHTML` /
  `innerHTML =` is XSS-prone; the framework's default `{{ value }}` is escaped._
- _FS: `fs.readFile(req.query.path)` / `new File(req.query.name)` is path-traversal-prone._
- _Shell: `child_process.exec("cmd " + arg)` / `Runtime.exec` / `os/exec.Command` with
  shell-form strings and concatenated input is command-injection-prone; safe is the array
  form without a shell._
- _Crypto: `md5` / `sha1` for passwords; `Math.random` / `random.random` for tokens; ECB
  mode; hardcoded keys/IVs._
- _Deserialization: `pickle.loads`, `Marshal.load`, `ObjectInputStream.readObject`,
  `yaml.load` (use `yaml.safe_load`), PHP `unserialize`, .NET `BinaryFormatter`._

## Area tags
Records are tagged `*Areas: ...*` by **package / subsystem**. Always include `security`:
`*Areas: @@PROJECT_NAME@@, <subsystem>, security*`.

## Commit-message conventions
<!-- Unlike the documentation pipeline, the security pipeline does NOT skip any commits.
     This section is just a hint to the agent about how this project phrases security
     fixes, so it can spot fix commits more reliably. -->
- This project uses Conventional Commits — security fixes usually appear under `fix:`.
- Watch also for: `security`, `CVE-`, `CWE-`, `vulnerability`, `XSS`, `CSRF`, `SSRF`,
  `injection`, `traversal`, `escape`, `sanitize`, `auth`, `privilege`, `disclosure`,
  `RCE`, `DoS`, `bypass`, `overflow` in any commit subject or body.
- The agent must still verify a "fix" against the actual diff — message alone is **not**
  sufficient.

## Notes for the analyzing agent
- Cite source paths exactly as they appear at the commit being reviewed, prefixed with
  `@@SOURCE_ROOT@@/`.
- Use `git -C <worktree>` (not `git` alone) so history commands run against the worktree.
- For multi-commit fixes, every fixing commit's agent will append to the same record's
  `## Fixed in` block — read existing records first to avoid duplicates.
- If a vulnerability is present in the initial commit, record it as `pre-existing` and use
  the initial commit as the introduction point.
- Multi-commit fixes: append every fixing commit to the same record's `## Fixed in`; never
  split one issue into multiple records.
- Late discovery is allowed but must be high-confidence — record `Detection:
  late-discovery` and severity `Low`/`Info`, do not fabricate SHAs.

---
*Last updated: @@DATE@@*
