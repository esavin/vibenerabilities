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
import json
import os
import re
import subprocess
import time

from .agent import load_provider_limit, save_provider_limit
from .llm import ContextOverflowError

# triage.diff_chars == 0 (or absent): auto-size the cap from the persisted
# provider window (verdicts/provider-limit.json) - ~3.5 chars per input token
# leaves room for the triage overhead (~2.5k tokens) and the one-line reply.
# No window discovered yet (fresh workspace, no overflow ever seen): fall back
# to the conservative historical default until one is learned.
AUTO_DIFF_CHARS_FALLBACK = 16_000
AUTO_CHARS_PER_TOKEN = 3
AUTO_WINDOW_RESERVE_TOKENS = 2_000

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

# Keep in sync with the Pass B trigger list in prompt.SYSTEM_PROMPT, but
# WORD-BOUNDARY anchored: the Pass B text match runs inside a full session
# where a substring hit merely opens an extra detection pass, while here it
# outright blocks the cheap path - "fix" inside "prefix"/"fixtures" must not
# force a full session on a docs-only commit (measured: 14 of 36 guarded
# commits on one stretch were substring-only false positives).
_PASS_B_KEYWORDS = re.compile(
    r"\b(fix(es|ed|ing)?|secur(e|ity)|vuln(erabilit(y|ies))?|cve-\d+"
    r"|cwe-\d+|xss|csrf|ssrf|injection|traversal|sanitiz(e|es|ed|ation)"
    r"|patch(es|ed)?|hotfix(es)?|hardening|auth(orize|orized|orizes"
    r"|orization|enticate|enticated|enticates|entication)?"
    r"|privileges?|disclosure|leaks?(ed|age)?|rce|dos|bypass(es|ed)?"
    r"|overflows?(ed)?|forgery|hijack(ing|ed)?)\b",
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


def triage_cache_path(cache_dir, sha):
    return os.path.join(cache_dir, sha + ".json") if cache_dir else ""


def load_triage_cache(cache_dir, sha, model=""):
    """Cached LLM triage decision for a commit, or None.

    The decision is a pure function of (commit, model, diff cap), so it can be
    computed AHEAD of the walk by a prefetch worker (vuln_agent.prefetch) and
    replayed here with zero LLM calls. Guards (root/renames/keywords/...) are
    NOT cached - they are local and re-derived every time.
    """
    path = triage_cache_path(cache_dir, sha)
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if state.get("sha") != sha or state.get("decision") not in ("skip",
                                                                   "analyze"):
            return None
        if model and state.get("model") and state.get("model") != model:
            return None
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return state


def save_triage_cache(cache_dir, sha, model, decision, reason, usage):
    if not cache_dir:
        return
    state = {"sha": sha, "model": model, "decision": decision,
             "via": "llm", "reason": reason,
             "usage": {"prompt_tokens": int((usage or {}).get("prompt_tokens")
                                            or 0),
                       "completion_tokens": int((usage or {})
                                                .get("completion_tokens")
                                                or 0),
                       "total_tokens": int((usage or {}).get("total_tokens")
                                           or 0)},
             "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
    try:
        os.makedirs(cache_dir, exist_ok=True)
        tmp = triage_cache_path(cache_dir, sha) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(state, ensure_ascii=False) + "\n")
        os.replace(tmp, triage_cache_path(cache_dir, sha))
    except (OSError, ValueError):
        pass


def auto_diff_chars(limit_state_path=None, base_url=""):
    """Auto cap for triage.diff_chars == 0: derived from the persisted
    provider window; the conservative fallback when none is known yet."""
    known = load_provider_limit(limit_state_path, model="", base_url=base_url)
    if not known:
        return AUTO_DIFF_CHARS_FALLBACK, None
    chars = max(4_000, AUTO_CHARS_PER_TOKEN * max(0, known
                                                  - AUTO_WINDOW_RESERVE_TOKENS))
    return chars, known


def run_triage(client, worktree, sha, cfg, log,
               root_commit=False, old_paths=None, changed=0,
               limits=None, transcript=None, model="", base_url="",
               cache_dir=None, limit_state_path=None):
    """Decide skip-vs-analyze for one commit.

    Returns a NO_VULN verdict dict when the commit may skip the full session,
    or None when the full session must run. Never raises: any failure falls
    back to the full session (the caller's retry/requeue semantics then apply
    there, exactly as before triage existed).

    `worktree` may be the WORKTREE at this commit (main invocation) or simply
    the source repository - every git call here is object-database plumbing
    (log/rev-parse/diff against explicit shas), so no checkout is needed.
    That is what lets a prefetch worker triage FUTURE commits directly
    against the clone while the walk is still elsewhere.

    `cache_dir` (optional): verdicts/triage - LLM decisions are cached per
    sha and reused across invocations (pure function of commit + model).
    """
    lim = limits if isinstance(limits, dict) else {}
    diff_cap = int(cfg.get("diff_chars") or 0)
    if diff_cap <= 0:
        # auto: size from the provider's discovered window (3 chars per
        # token minus reserve); conservative fallback until one is learned
        diff_cap, known = auto_diff_chars(limit_state_path, base_url)
        log("triage: diff_chars auto = %d%s"
            % (diff_cap, " (provider window %d tokens)" % known
               if known else " (no provider window learned yet - fallback)"))
    message_cap = int(cfg.get("message_chars") or 2000)
    ns_cap = int(cfg.get("name_status_chars") or 6000)
    globs = cfg.get("irrelevant_globs") or []

    def refuse(reason):
        log("triage: full session (%s)" % reason)
        return None

    parent = _git(worktree, ["rev-parse", "--verify", "--quiet",
                             sha + "^"]).strip()
    if root_commit or (root_commit is None and not parent):
        return refuse("root commit - initial snapshot scan")
    if not parent:
        return refuse("no parent found")
    ns_raw = _git(worktree, ["diff", "--name-status", "-M", parent, sha])
    files = []
    ns_old_paths = []
    for line in ns_raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            files.append(parts[-1])
            if parts[0].startswith("R") and len(parts) >= 3:
                ns_old_paths.append(parts[1])
            elif parts[0].startswith("D"):
                ns_old_paths.append(parts[1])
    if old_paths is None:
        old_paths = ns_old_paths
    if not changed:
        changed = len(files)
    if changed <= 0:
        return refuse("empty name-status")
    if old_paths:
        return refuse("renames/deletes present (path hygiene / fix removal)")

    # local glob fast path BEFORE the keyword guard: an explicitly configured
    # irrelevant_globs match is a deliberate opt-in for docs/tests/assets-only
    # diffs, and must not be vetoed by a stray "fix" substring in the message
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

    subject = _git(worktree, ["log", "-1", "--format=%s", sha]).strip()
    message = _git(worktree, ["log", "-1", "--format=%B", sha]).strip()

    if _PASS_B_KEYWORDS.search(message or ""):
        return refuse("commit message matches fix/security keywords")

    diff = _git(worktree, ["diff", "-M", parent, sha]).strip("\n")
    if diff_cap <= 0 or len(diff) > diff_cap:
        return refuse("diff (%d chars) over triage cap (%d)"
                      % (len(diff), diff_cap))

    # cached decision (usually written ahead by the prefetch worker while the
    # walk was still on an earlier commit): replay with zero LLM calls
    cached = load_triage_cache(cache_dir, sha, model=model)
    if cached is not None:
        usage = cached.get("usage") or {}
        if cached["decision"] != "skip":
            if transcript is not None:
                transcript.record({"type": "triage", "decision": "analyze",
                                   "via": "cache",
                                   "reason": cached.get("reason"),
                                   "model": model, "sha": sha})
            return refuse("cached decision: SECURITY_RELEVANT")
        reason = cached.get("reason") or \
            "cascade pre-filter: CLEARLY_IRRELEVANT (diff seen in full)"
        log("triage: skip (cached: %s)" % reason)
        if transcript is not None:
            transcript.record({"type": "triage", "decision": "skip",
                               "via": "cache", "reason": reason,
                               "model": model, "sha": sha,
                               "usage": usage})
            transcript.record({"type": "end", "verdict": "NO_VULN",
                               "reason": "triage: %s (cached)" % reason})
        return {"verdict": "NO_VULN", "files": [],
                "reason": "triage: %s (cached)" % reason, "steps": 1,
                "usage": {"prompt_tokens": int(usage.get("prompt_tokens")
                                               or 0),
                          "completion_tokens": int(usage.get(
                              "completion_tokens") or 0),
                          "total_tokens": int(usage.get("total_tokens") or 0)},
                "sessions": 1}

    user = build_triage_user(subject, _cap(message, message_cap),
                             _cap(ns_raw, ns_cap), diff)
    try:
        response = client.chat(
            [{"role": "system", "content": TRIAGE_SYSTEM},
             {"role": "user", "content": user}], [])
    except ContextOverflowError as exc:
        # the auto cap (or a manual one) overshot the window: learn the real
        # limit for future auto-sizing and let the full session handle it
        url = base_url or ""
        save_provider_limit(limit_state_path, exc.limit or 0,
                            model=model, base_url=url)
        return refuse("triage request over the provider window "
                      "(diff %d chars, limit %s)" % (len(diff), exc.limit))
    except Exception as exc:  # FatalLLMError et al - never block the commit
        return refuse("triage request failed (%s)" % exc)

    reply = str((response.get("message") or {}).get("content") or "")
    usage = response.get("usage") or {}
    decision = parse_decision(reply)
    reason = "cascade pre-filter: CLEARLY_IRRELEVANT (diff seen in full)"
    save_triage_cache(cache_dir, sha, model, decision, reason, usage)
    if decision != "skip":
        return refuse("model answered SECURITY_RELEVANT/doubted")

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
