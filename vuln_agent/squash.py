"""R2 range-squash planner: partition a walk's todo list into squash ranges.

Measured on real walks, a large share of FULL sessions is spent on commits
that are almost certainly irrelevant but were forced past the triage cascade
by a recall guard - the classic example is a docs/tests-only commit whose
message contains a Pass B keyword ("fix", "security", ...): the keyword guard
skips triage entirely and the commit gets a full multi-step session that
almost always concludes NO_VULN.

This module (run with ``--squash``, or config ``squash.enabled: true``)
partitions run.sh's ordered todo list into:

  RANGE <n> <sha1> <sha2> ... <shaN>   - one squashed classification session
                                         covers these n consecutive commits
  SINGLE <sha>                          - per-commit processing as before

A commit may join a range only when it is structurally squashable AND
belongs to a configured guard-forced class:

  - not a root commit, not a merge, no renames/deletes (those owe the record
    phase deterministic path hygiene);
  - its INDIVIDUAL diff fits ``squash.member_diff_chars`` (0 = limits.
    diff_chars) - oversized diffs keep their own session;
  - class "keyword": the full message matches the Pass B fix/security
    keyword list (the exact regex the triage cascade uses - imported from
    vuln_agent.triage so the two can never drift apart);
  - class "globs": every changed file matches triage.irrelevant_globs;
  - never a preseeded (--reuse-verdicts/--skip-list), prior-run-hint or
    regex-skip commit - run.sh passes those via --exclude.

Grouping: a consecutive run of candidates is greedily extended while the
CUMULATIVE diff ``git diff -M first^ next`` fits ``squash.diff_chars`` (0 =
auto: 2 x limits.diff_chars) and the member count stays under
``squash.max_commits``; runs shorter than ``squash.min_series`` stay
per-commit (a range must pay for itself). The planner also verifies that the
first member is an ancestor of the last (retried commits appended out of
history order must not be glued into a range).

The plan is a pure function of (repo, todo order, config) - no LLM calls,
pure git plumbing against the source clone, like vuln_agent.prefetch.

The RANGE session itself runs in vuln_agent's classify-only mode over the
cumulative diff (see cli.py --squash-range): NO_VULN finalizes every member,
anything else (VULN candidate, ERROR) splits the range back into per-commit
full sessions - recall before speed.
"""

import argparse
import os
import subprocess
import sys

from .config import (ConfigError, load_config, resolve_limits,
                     resolve_squash, resolve_triage)
from .triage import all_files_irrelevant, message_guarded


def log(message):
    print("[squash] %s" % message, file=sys.stderr, flush=True)


def git(source, argv):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        proc = subprocess.run(["git", "--no-pager", "-C", source] + argv,
                              capture_output=True, text=True, errors="replace",
                              timeout=60, env=env)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _parents(source, sha):
    out = git(source, ["rev-list", "--parents", "-n", "1", sha]).split()
    return out[1:] if out else []


def _name_status(source, parent, sha):
    """(files, has_rd) of `git diff --name-status -M parent sha`."""
    files = []
    has_rd = False
    for line in git(source, ["diff", "--name-status", "-M", parent,
                             sha]).splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        files.append(parts[-1])
        if parts[0][:1] in ("R", "D"):
            has_rd = True
    return files, has_rd


def is_candidate(source, sha, cfg, globs):
    """(candidate?, reason) - structural + class check for one commit."""
    parents = _parents(source, sha)
    if not parents:
        return False, "root commit"
    if len(parents) > 1:
        return False, "merge commit"
    parent = parents[0]
    files, has_rd = _name_status(source, parent, sha)
    if not files:
        return False, "empty name-status"
    if has_rd:
        return False, "renames/deletes (record-phase hygiene)"
    if cfg["member_diff_chars"] > 0:
        diff = git(source, ["diff", "-M", parent, sha])
        if len(diff) > cfg["member_diff_chars"]:
            return False, "individual diff over member cap"
    if "keyword" in cfg["classes"]:
        message = git(source, ["log", "-1", "--format=%B", sha])
        if message_guarded(message):
            return True, "keyword-guarded"
    if "globs" in cfg["classes"] and globs \
            and all_files_irrelevant(files, globs):
        return True, "all files match irrelevant_globs"
    return False, "no guard-forced class"


def cumulative_diff_chars(source, first_parent, sha):
    return len(git(source, ["diff", "-M", first_parent, sha]))


def plan(source, shas, excluded, cfg, globs):
    """Ordered todo shas -> [(kind, [shas])] with kind in ("range","single")."""
    states = []
    reasons = {"keyword-guarded": 0, "all files match irrelevant_globs": 0}
    for sha in shas:
        if sha in excluded:
            states.append((sha, False, "excluded by run.sh"))
            continue
        ok, reason = is_candidate(source, sha, cfg, globs)
        states.append((sha, ok, reason))
        if ok:
            reasons[reason] = reasons.get(reason, 0) + 1

    groups = []
    run = []

    def close_run():
        """Try to emit the pending candidate run as one or more RANGEs."""
        i = 0
        while i < len(run):
            series = [run[i]]
            first_parent = _parents(source, series[0])[0]
            j = i + 1
            while j < len(run) and len(series) < cfg["max_commits"]:
                nxt = run[j]
                if cumulative_diff_chars(source, first_parent, nxt) \
                        > cfg["diff_chars_total"]:
                    break
                series.append(nxt)
                j += 1
            if len(series) >= cfg["min_series"] \
                    and _is_ancestor(source, series[0], series[-1]):
                groups.append(("range", series))
            else:
                groups.extend(("single", [sha]) for sha in series)
            i = j

    for sha, ok, _reason in states:
        if ok:
            run.append(sha)
            continue
        close_run()
        run = []
        groups.append(("single", [sha]))
    close_run()

    n_ranges = sum(1 for kind, _ in groups if kind == "range")
    n_squashed = sum(len(g) for kind, g in groups if kind == "range")
    log("plan: %d/%d commit(s) squashable (%s); %d range(s) covering %d "
        "commit(s), %d single"
        % (sum(1 for _, ok, _ in states if ok), len(shas),
           ", ".join("%s=%d" % kv for kv in sorted(reasons.items())),
           n_ranges, n_squashed, len(groups) - n_ranges))
    return groups


def _is_ancestor(source, first, last):
    """True when `first` is an ancestor of `last` (history-ordered range)."""
    proc = subprocess.run(
        ["git", "-C", source, "merge-base", "--is-ancestor", first, last],
        capture_output=True)
    return proc.returncode == 0


def read_excluded(path):
    if not path:
        return set()
    out = set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.add(line)
    except OSError as exc:
        print("squash: cannot read --exclude file: %s" % exc, file=sys.stderr)
    return out


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="vuln-agent-squash",
        description="Partition the walk's todo commits into squash ranges "
                    "(R2 range-squash planner; pure git plumbing, no LLM).")
    parser.add_argument("--config", default="", help="pipeline config.json")
    parser.add_argument("--source", required=True,
                        help="project source clone (git)")
    parser.add_argument("--exclude", default="",
                        help="file with SHAs run.sh handles without a full "
                             "session (preseeded/hints/regex) - they break "
                             "ranges and stay SINGLE")
    parser.add_argument("--enabled", action="store_true",
                        help="force-enable even when config squash.enabled "
                             "is false (run.sh passes this for its --squash "
                             "flag)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        config = load_config(args.config)
        limits = resolve_limits(config)
        cfg = resolve_squash(config, limits)
        triage = resolve_triage(config, {"model": ""})
    except ConfigError as exc:
        print("squash: %s" % exc, file=sys.stderr)
        return 2
    if not (cfg["enabled"] or args.enabled):
        log("squash disabled (config squash.enabled is false and no "
            "--enabled flag) - nothing to plan")
        return 0

    shas = [line.strip() for line in sys.stdin if line.strip()]
    excluded = read_excluded(args.exclude)
    groups = plan(args.source, shas, excluded, cfg,
                  triage["irrelevant_globs"])
    for kind, members in groups:
        if kind == "range":
            print("RANGE %d %s" % (len(members), " ".join(members)))
        else:
            print("SINGLE %s" % members[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
