"""Triage prefetch worker: keep a rolling window of AHEAD triage decisions.

`triage.enabled` makes the cascade decision inside every agent invocation;
when it fires, its one LLM round-trip (5-30s on a slow model) is paid
SERIALLY, right before the full session. This worker hides that latency: it
runs in the background next to run.sh's main loop and, while the walker is
still on commit N, triages commits N+1..N+ahead ahead of time against the
source clone (no worktrees needed - triage is pure git plumbing), caching the
decisions under verdicts/triage/<sha>.json. The main invocation then replays
the cached decision with zero LLM calls (see triage.run_triage).

Correctness: the triage decision is a pure function of (commit, model,
diff cap) - it does NOT depend on the records map, the baseline, or any
earlier commit's outcome - so precomputing it for future commits cannot
change the walk's semantics. The main invocation re-derives every local
guard (root/renames/keywords/globs/diff cap) itself and consults the cache
only where it would otherwise have made the LLM call itself.

run.sh starts/kills this worker automatically when
`triage.prefetch_ahead` > 0; manual use:

    python3 -m vuln_agent.prefetch --config vibenerabilities/config.json \
        --source someproject --verdicts-dir vibenerabilities/verdicts \
        --records-root agent/project --ahead 3
"""

import argparse
import json
import os
import subprocess
import sys
import time

from .config import (ConfigError, load_config, resolve_llm, resolve_limits,
                     resolve_triage)
from .llm import ChatClient
from .triage import load_triage_cache, run_triage, triage_cache_path


def log(message):
    print("[prefetch] %s" % message, flush=True)


def git(source, argv):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        proc = subprocess.run(["git", "--no-pager", "-C", source] + argv,
                              capture_output=True, text=True, errors="replace",
                              timeout=60, env=env)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def read_baseline(records_root):
    """The walk's last fully-processed commit (agent/project/.vibenerabilities.json)."""
    path = os.path.join(records_root, ".vibenerabilities.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return str(json.load(fh).get("baseline") or "")
    except (OSError, ValueError, json.JSONDecodeError):
        return ""


def upcoming(source, baseline, skip_merges, scope):
    """Commits the walk will process next, oldest first (same filters)."""
    argv = ["rev-list", "--reverse"]
    if skip_merges:
        argv.append("--no-merges")
    rng = ("%s..HEAD" % baseline) if baseline else "HEAD"
    argv.append(rng)
    if scope:
        argv.extend(["--", scope])
    out = git(source, argv)
    return [line for line in out.split() if line]


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        config = load_config(args.config)
        llm = resolve_llm(config)
        triage = resolve_triage(config, llm)
        limits = resolve_limits(config)
    except ConfigError as exc:
        print("prefetch: %s" % exc, file=sys.stderr)
        return 2
    if not triage["enabled"]:
        log("triage disabled - nothing to prefetch")
        return 0

    client = ChatClient(
        base_url=llm["base_url"], api_key=llm["api_key"],
        model=llm["model"], timeout=llm["timeout"], retries=llm["retries"],
        temperature=llm["temperature"], max_tokens=llm["max_tokens"],
        extra_body=llm["extra_body"],
        heartbeat_seconds=llm["heartbeat_seconds"])
    cache_dir = os.path.join(args.verdicts_dir, "triage")

    skip_merges = config.get("skip_merges") is True
    scope = str(config.get("scope") or "").strip()

    log("start: source=%s ahead=%d interval=%ds cache=%s"
        % (args.source, args.ahead, args.interval, cache_dir))
    idle = 0
    handled = set()  # shas triaged/refused THIS process (refuses never change:
    #              # the decision is a pure function of the commit)
    while True:
        baseline = read_baseline(args.records_root)
        plan = upcoming(args.source, baseline, skip_merges, scope)
        if not plan:
            log("plan exhausted (baseline at HEAD) - exiting")
            return 0
        for sha in plan[:args.ahead * 3]:
            if load_triage_cache(cache_dir, sha, model=llm["model"]) is not None:
                handled.add(sha)  # cached by an earlier poll/process
        window = [sha for sha in plan if sha not in handled][:args.ahead]
        if not window:
            idle += args.interval
            if idle >= args.max_idle:
                log("no work for %ds (baseline stuck at %s?) - exiting"
                    % (idle, baseline[:10] or "none"))
                return 0
            time.sleep(args.interval)
            continue
        idle = 0
        for sha in window:
            run_triage(client, args.source, sha, triage, log,
                       root_commit=None, old_paths=None, changed=0,
                       limits=limits, transcript=None,
                       model=llm["model"], base_url=llm["base_url"],
                       cache_dir=cache_dir)
            handled.add(sha)
        # the walk advances meanwhile: re-derive the window promptly
        time.sleep(min(args.interval, 2))


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="vuln-agent-prefetch",
        description="Precompute triage decisions AHEAD of the walk "
                    "(background worker for run.sh).")
    parser.add_argument("--config", default="", help="pipeline config.json")
    parser.add_argument("--source", required=True,
                        help="project source clone (git) - no worktree needed")
    parser.add_argument("--verdicts-dir", required=True,
                        help="verdicts dir; cache lands in verdicts/triage/")
    parser.add_argument("--records-root", required=True,
                        help="records root, to read the current baseline")
    parser.add_argument("--ahead", type=int, default=3,
                        help="how many commits ahead to keep triaged")
    parser.add_argument("--interval", type=int, default=5,
                        help="seconds between baseline polls")
    parser.add_argument("--max-idle", dest="max_idle", type=int, default=900,
                        help="exit after this many idle seconds")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
