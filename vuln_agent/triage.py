"""Triage fast-path: one cheap, no-tools request in front of the full session.

Measured on real walks, the dominant cost of a commit-by-commit replay is NOT
the commits that find vulnerabilities - it is the ~60-70% of sessions that
wander through read_file/git calls for several minutes only to conclude
NO_VULN. This module is an opt-in two-stage cascade (config ``triage.enabled``):

  stage 1 (here): subject + full message + name-status + the COMPLETE diff
     (when it fits ``triage.diff_chars``) -> one no-tools request that must
     answer CLEARLY_IRRELEVANT before the commit is marked NO_VULN without a
     full session;
  stage 2: everything else - the ordinary full agent session.

Recall guardrails (any of these falls through to the FULL session, no triage
request at all):

- the commit is a root commit (initial-snapshot deep scan);
- anything was renamed or deleted (path hygiene + fix-removal analysis);
- the commit message matches the Pass B trigger keywords (fix/harden/CVE/...)
  - the same list the system prompt uses for fix detection;
- the diff exceeds ``triage.diff_chars`` (a truncated diff could hide the one
  dangerous hunk, so no judgment is attempted);
- the triage reply is unparsable, ambiguous, or the request itself fails -
  the error is swallowed and the full session runs;
- a prior-run hint (--record-hints) or a hygiene worklist exists (checked by
  the caller).

``triage.irrelevant_globs`` is an even cheaper local fast path: when EVERY
changed file matches (docs/tests/assets style globs), the commit is marked
NO_VULN with no LLM call at all. Off by default (empty list).
"""

import fnmatch
import os
import re
import subprocess

TRIAGE_SYSTEM = """You are a fast pre-filter of a commit-by-commit security-analysis \
pipeline. For each commit you decide whether a full analysis session (an agent \
that reads the worktree and updates vulnerability records) must examine it, or \
whether the commit is CLEARLY irrelevant to security.

Reply with EXACTLY one line, one of:
SECURITY_RELEVANT   - the commit might introduce, fix, or reveal a security \
vulnerability, touches anything security-adjacent (auth, crypto, input \
handling, network, process spawning, config, permissions, dependencies), \
or you are simply not sure
CLEARLY_IRRELEVANT  - purely documentation, comments, tests, formatting, \
build metadata, or binary/UI assets with no conceivable security impact

Rules:
- Judge by the ACTUAL DIFF, never by the commit message prefix alone.
- When in doubt, ALWAYS answer SECURITY_RELEVANT - a false CLEARLY_IRRELEVANT \
hides a real vulnerability, a false SECURITY_RELEVANT only costs one session.
- Answer with the single word line only; no explanation."""

# Keep in sync with the Pass B trigger list in prompt.SYSTEM_PROMPT.
_PASS_B_KEYWORDS = re.compile(
    r"fix|security|vuln|cve-|cwe-|xss|csrf|ssrf|injection|traversal|sanitize"
    r"|patch|hotfix|hardening|auth|privilege|disclosure|leak|rce|dos|bypass"
    r"|overflow|forgery|hijack",
    re.IGNORECASE,
)

_DECISION_RE = re.compile(
    r"\b(SECURITY_RELEVANT|CLEARLY_IRRELEVANT)\b")


def _git(worktree, argv):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        proc = subprocess.run(["git", "--no-pager", "-C", worktree] + argv,
                              capture_output=True, text=True, errors="replace",
                              timeout=60, env=env)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _cap(text, limit):
    text = text or ""
    if limit <= 0 or len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated, %d more chars]" % (len(text) - limit)


def parse_decision(text):
    """LLM reply -> 'analyze' | 'skip'. Anything ambiguous is 'analyze'."""
    decisions = _DECISION_RE.findall(text or "")
    if len(decisions) == 1 and decisions[0] == "CLEARLY_IRRELEVANT":
        return "skip"
    return "analyze"


def _file_matches(path, pattern):
    pattern = pattern.strip().strip("/")
    if not pattern:
        return False
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-2] + "/") or path == pattern[:-3]
    if "/" in pattern:
        return fnmatch.fnmatch(path, pattern)
    return fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern)


def all_files_irrelevant(files, globs):
    """True when every changed path matches at least one glob."""
    globs = [g for g in (globs or []) if str(g).strip()]
    if not globs or not files:
        return False
    return all(any(_file_matches(f, str(g)) for g in globs) for f in files)


def build_triage_user(subject, message, name_status, diff):
    parts = [
        "SUBJECT: %s" % (subject or "(none)"),
        "",
        "FULL COMMIT MESSAGE:",
        message or "(none)",
        "",
        "NAME STATUS (files changed by this commit):",
        name_status or "(none)",
    ]
    if diff:
        parts.extend(["",
                      "FULL DIFF (the COMPLETE change - judge by this):",
                      diff])
    else:
        parts.extend(["",
                      "(diff too large to inline - answer SECURITY_RELEVANT "
                      "unless the name-status alone is unambiguous)"])
    parts.extend(["",
                  "One line: SECURITY_RELEVANT or CLEARLY_IRRELEVANT."])
    return "\n".join(parts)


def run_triage(client, worktree, sha, cfg, log,
               root_commit=False, old_paths=None, changed=0,
               limits=None, transcript=None, model="", base_url=""):
    """Decide skip-vs-analyze for one commit.

    Returns a NO_VULN verdict dict when the commit may skip the full session,
    or None when the full session must run. Never raises: any failure falls
    back to the full session (the caller's retry/requeue semantics then apply
    there, exactly as before triage existed).
    """
    lim = limits if isinstance(limits, dict) else {}
    diff_cap = int(cfg.get("diff_chars") or 0)
    message_cap = int(cfg.get("message_chars") or 2000)
    ns_cap = int(cfg.get("name_status_chars") or 6000)
    globs = cfg.get("irrelevant_globs") or []

    def refuse(reason):
        log("triage: full session (%s)" % reason)
        return None

    if root_commit:
        return refuse("root commit - initial snapshot scan")
    if changed <= 0:
        return refuse("empty name-status")
    if old_paths:
        return refuse("renames/deletes present (path hygiene / fix removal)")

    subject = _git(worktree, ["log", "-1", "--format=%s", sha]).strip()
    message = _git(worktree, ["log", "-1", "--format=%B", sha]).strip()

    if _PASS_B_KEYWORDS.search(message or ""):
        return refuse("commit message matches fix/security keywords")

    parent = _git(worktree, ["rev-parse", "--verify", "--quiet",
                             sha + "^"]).strip()
    if not parent:
        return refuse("no parent found")
    ns_raw = _git(worktree, ["diff", "--name-status", "-M", parent, sha])
    files = []
    for line in ns_raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            files.append(parts[-1])

    if all_files_irrelevant(files, globs):
        reason = ("local fast path: all %d changed file(s) match "
                  "triage.irrelevant_globs" % len(files))
        log("triage: skip without LLM call (%s)" % reason)
        if transcript is not None:
            transcript.record({"type": "triage", "decision": "skip",
                               "via": "globs", "reason": reason,
                               "model": model, "sha": sha})
            transcript.record({"type": "end", "verdict": "NO_VULN",
                               "reason": "triage: %s" % reason})
        return {"verdict": "NO_VULN", "files": [],
                "reason": "triage: %s" % reason, "steps": 0,
                "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                          "total_tokens": 0},
                "sessions": 1}

    diff = _git(worktree, ["diff", "-M", parent, sha]).strip("\n")
    if diff_cap <= 0 or len(diff) > diff_cap:
        return refuse("diff (%d chars) over triage cap (%d)"
                      % (len(diff), diff_cap))

    user = build_triage_user(subject, _cap(message, message_cap),
                             _cap(ns_raw, ns_cap), diff)
    try:
        response = client.chat(
            [{"role": "system", "content": TRIAGE_SYSTEM},
             {"role": "user", "content": user}], [])
    except Exception as exc:  # FatalLLMError et al - never block the commit
        return refuse("triage request failed (%s)" % exc)

    reply = str((response.get("message") or {}).get("content") or "")
    usage = response.get("usage") or {}
    decision = parse_decision(reply)
    if decision != "skip":
        return refuse("model answered SECURITY_RELEVANT/doubted")

    reason = "cascade pre-filter: CLEARLY_IRRELEVANT (diff seen in full)"
    log("triage: skip (%s)" % reason)
    if transcript is not None:
        transcript.record({
            "type": "session", "sha": sha, "model": model,
            "base_url": base_url, "mode": "triage", "root_commit": False,
            "max_steps": 1, "repair_rounds": 0,
            "limits_profile": lim.get("profile"),
            "compact_threshold_tokens": 0,
            "system_prompt_chars": len(TRIAGE_SYSTEM),
            "first_user_chars": len(user),
        })
        transcript.record({"type": "assistant", "step": 1, "content": reply,
                           "tool_calls": [],
                           "finish_reason": response.get("finish_reason"),
                           "usage": usage})
        transcript.record({"type": "triage", "decision": "skip", "via": "llm",
                           "reason": reason, "model": model, "sha": sha})
        transcript.record({"type": "end", "verdict": "NO_VULN",
                           "reason": "triage: %s" % reason})
    return {"verdict": "NO_VULN", "files": [],
            "reason": "triage: %s" % reason, "steps": 1,
            "usage": {"prompt_tokens": int(usage.get("prompt_tokens") or 0),
                      "completion_tokens": int(usage.get("completion_tokens")
                                               or 0),
                      "total_tokens": int(usage.get("total_tokens") or 0)},
            "sessions": 1}
