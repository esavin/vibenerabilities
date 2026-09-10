"""CLI entry point: one agent invocation = one commit.

Writes two verdict artifacts for the outer bash loop:
  verdicts/<sha>.json - full verdict (verdict, files, reason, steps, usage,
                        sessions, validation)
  verdicts/<sha>.txt  - one line, backward-compatible with run.sh parsing:
                        VERDICT: VULN_UPDATED <files...> | NO_VULN | ERROR <reason>
plus, whenever records were written:
  verdicts/<sha>.validation.md - the records validation report (last state)

Pipeline per commit: deterministic path hygiene pre-pass first (citations of
renamed paths rewritten in place; the remaining repair worklist split into
per-batch sessions), then a grounded first message (commit meta, rename-aware
name-status, stale-record worklist, tree digest for the root commit), the
agent loop, then validation of the records and - if problems remain - repair
rounds feeding them back for up to `validation.rounds` rounds. In strict mode
(default) remaining errors flip the verdict to ERROR, so the commit is
requeued and retried instead of publishing broken security records.
"""

import argparse
import datetime
import json
import os
import sys

from .agent import (PROVIDER_LIMIT_FILE, load_provider_limit, run_agent)
from .config import (ConfigError, load_config, resolve_llm, resolve_limits,
                     resolve_squash, resolve_triage)
from .hygiene import hygiene_plan
from .llm import ChatClient, FatalLLMError
from .prompt import (InspectError, build_first_user, build_reconsider_message,
                     load_prior_hint, sha_looks_valid, system_prompt)
from .tools import ToolSet
from .transcript import Transcript
from .triage import run_triage
from .validate import format_report, repair_message, validate_records


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="vuln-agent",
        description="Classify one project commit and update the vulnerability "
                    "records map (single step of the vibenerabilities pipeline).",
    )
    parser.add_argument("--config", default="", help="pipeline config.json path")
    parser.add_argument("--sha", required=True, help="commit under review")
    parser.add_argument("--worktree", required=True,
                        help="worktree with the commit checked out")
    parser.add_argument("--records-root", required=True,
                        help="vulnerability records root (writable)")
    parser.add_argument("--records-root-rel", default="agent/project",
                        help="records root relative to the workspace, for "
                             "verdict paths")
    parser.add_argument("--verdicts-dir", required=True,
                        help="directory for verdict files")
    parser.add_argument("--classify-only", action="store_true",
                        help="decide and report without writing records")
    parser.add_argument("--squash-range", default="",
                        help="comma-separated SHAs of a squashed range "
                             "(oldest first; the LAST must equal --sha, the "
                             "range tip). Runs ONE range classification "
                             "session over the cumulative diff first^..tip: "
                             "NO_VULN finalizes the whole range, anything "
                             "else makes run.sh replay it commit-by-commit")
    parser.add_argument("--prior-verdict", default="",
                        help="verdict JSON from a previous run (VULN_UPDATED "
                             "hint; enables the reconsideration round)")
    parser.add_argument("--prior-records", default="",
                        help="records root of the previous run, to read the "
                             "hint records from")
    parser.add_argument("--model", default="", help="override the configured model")
    parser.add_argument("--max-steps", type=int, default=0,
                        help="override the max agent steps")
    return parser.parse_args(argv)


def log(message):
    print("[vuln-agent] %s" % message, flush=True)


def read_conventions(records_root, limits):
    path = os.path.join(records_root, "project-conventions.md")
    cap = int((limits or {}).get("conventions_chars") or 12000)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(cap)
    except OSError:
        return ""


def validation_settings(config, classify_only):
    section = config.get("validation")
    if not isinstance(section, dict):
        section = {}
    mode = str(section.get("mode") or "strict").lower()
    if mode not in ("strict", "warn", "off"):
        mode = "strict"
    try:
        rounds = max(0, int(section.get("rounds", 2)))
    except (TypeError, ValueError):
        rounds = 2
    # DEVIATION from the docs pipeline: default "warn", not "error" -
    # vulnerability records legitimately cite historical file paths that may
    # no longer exist at the commit under review, so a hard path error would
    # poison otherwise-good records; still configurable via config
    # validation.path_check.
    path_check = str(section.get("path_check") or "warn").lower()
    if path_check not in ("error", "warn", "off"):
        path_check = "warn"
    if classify_only or mode == "off":
        rounds = 0
    return mode, rounds, path_check


def repo_relative(path, records_root, records_root_rel):
    """Normalize a record path reported by the model to workspace-relative."""
    text = str(path).strip().replace("\\", "/")
    records_abs = os.path.realpath(records_root).replace(os.sep, "/").rstrip("/")
    if text.startswith(records_abs + "/"):
        text = text[len(records_abs) + 1:]
    text = text.lstrip("./")
    prefix = records_root_rel.strip("/")
    if prefix and text.startswith(prefix + "/"):
        return text
    return (prefix + "/" + text) if prefix else text


def verdict_line(verdict, records_root, records_root_rel):
    if verdict["verdict"] == "VULN_UPDATED":
        files = ",".join(repo_relative(f, records_root, records_root_rel)
                         for f in verdict.get("files") or [])
        return ("VERDICT: VULN_UPDATED " + files).rstrip()
    if verdict["verdict"] == "NO_VULN":
        return "VERDICT: NO_VULN"
    reason = " ".join(str(verdict.get("reason") or "unspecified").split())[:200]
    return "VERDICT: ERROR %s" % reason


def write_atomic(path, text):
    # pid-suffixed tmp so concurrent processes never clobber each other's
    # in-flight temp file before the atomic replace
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if not sha_looks_valid(args.sha):
        print("vuln-agent: --sha does not look like a commit hash", file=sys.stderr)
        return 2

    squash_range = [s.strip() for s in (args.squash_range or "").split(",")
                    if s.strip()]
    if squash_range:
        if len(squash_range) < 2 \
                or any(not sha_looks_valid(s) for s in squash_range):
            print("vuln-agent: --squash-range needs >= 2 valid comma-separated "
                  "SHAs", file=sys.stderr)
            return 2
        if squash_range[-1] != args.sha:
            print("vuln-agent: --squash-range must end with the --sha (tip) "
                  "commit %s" % args.sha, file=sys.stderr)
            return 2

    try:
        config = load_config(args.config)
        llm = resolve_llm(config, cli_model=args.model or None,
                          cli_max_steps=args.max_steps or None)
        limits = resolve_limits(config)
        squash_cfg = resolve_squash(config, limits)
        triage = resolve_triage(config, llm)
    except ConfigError as exc:
        print("vuln-agent: %s" % exc, file=sys.stderr)
        return 2

    # arm the pre-flight overflow guard from a provider limit discovered by
    # an EARLIER session (verdicts/provider-limit.json): each session
    # otherwise re-pays one context-overflow HTTP 400 before adapting. The
    # window itself seeds the guard REGARDLESS of compaction settings - an
    # explicit limits.compact_threshold_tokens only overrides WHEN history
    # compaction triggers, never WHETHER over-size requests are shrunk
    # before being sent (a threshold above 82% of the window would fire
    # too late, so it is lowered to that ceiling). The stored window is
    # ignored once model/endpoint change.
    limit_state_path = os.path.join(args.verdicts_dir, PROVIDER_LIMIT_FILE)
    known = load_provider_limit(limit_state_path, model=llm["model"],
                                base_url=llm["base_url"])
    if known:
        limits["provider_input_limit"] = known
        safe = max(1000, int(known * 0.82))
        if not limits.get("compact_threshold_tokens"):
            limits["compact_threshold_tokens"] = safe
            log("compaction threshold seeded to %d tokens from persisted "
                "provider limit %d (%s)"
                % (safe, known, PROVIDER_LIMIT_FILE))
        elif limits["compact_threshold_tokens"] > safe:
            log("compaction threshold %d lowered to %d tokens from persisted "
                "provider limit %d (%s)"
                % (limits["compact_threshold_tokens"], safe, known,
                   PROVIDER_LIMIT_FILE))
            limits["compact_threshold_tokens"] = safe
        else:
            log("pre-flight overflow guard armed from persisted provider "
                "limit %d (%s)" % (known, PROVIDER_LIMIT_FILE))

    records_root = os.path.realpath(args.records_root)
    worktree = os.path.realpath(args.worktree)
    # a squashed-range session never writes records: it decides clean-vs-split
    # (run.sh replays the range per-commit on anything but NO_VULN), so it is
    # a classify-only session even without the explicit flag
    classify_only = args.classify_only or bool(squash_range)
    mode = "squash-range" if squash_range else (
        "classify-only" if args.classify_only else "record")
    if squash_range:
        # the range diff injection cap (planner admitted the range under it)
        limits["squash_diff_chars"] = squash_cfg["diff_chars_total"]
    today = datetime.date.today().isoformat()
    val_mode, val_rounds, path_check = validation_settings(config,
                                                           classify_only)
    sys_prompt = system_prompt()

    tools = ToolSet(worktree, records_root, classify_only=classify_only,
                    limits=limits)
    client = ChatClient(
        base_url=llm["base_url"],
        api_key=llm["api_key"],
        model=llm["model"],
        timeout=llm["timeout"],
        retries=llm["retries"],
        temperature=llm["temperature"],
        max_tokens=llm["max_tokens"],
        extra_body=llm["extra_body"],
        heartbeat_seconds=llm["heartbeat_seconds"],
    )

    transcript = None
    if llm["log_transcript"]:
        try:
            os.makedirs(args.verdicts_dir, exist_ok=True)
            transcript = Transcript(os.path.join(
                args.verdicts_dir, args.sha + ".transcript.jsonl"))
        except OSError:
            transcript = None

    verdict = None
    old_paths = []
    root_commit = False
    changed = 0
    plan = None
    try:
        # deterministic path hygiene FIRST (mode=record only): citations of
        # RENAMED paths are rewritten in place before any LLM call, and a
        # remaining repair worklist bigger than hygiene_batch_records
        # records is split into per-batch sessions (hygiene.py)
        if not classify_only:
            plan = hygiene_plan(worktree, args.sha, records_root,
                                batch_records=int(
                                    limits.get("hygiene_batch_records") or 5))
            if plan["prepass_edited"]:
                log("rename pre-pass: %d citation(s) rewritten across %d "
                    "record(s) (deterministic, no LLM)"
                    % (sum(plan["prepass_edited"].values()),
                       len(plan["prepass_edited"])))
        first_user, info = build_first_user(args.sha, worktree, records_root,
                                            mode, today,
                                            read_conventions(records_root,
                                                             limits),
                                            limits=limits,
                                            squash_range=squash_range or None)
        old_paths = info["old_paths"]
        root_commit = info["is_root"]
        changed = info.get("changed", 0)
    except InspectError as exc:
        verdict = {"verdict": "ERROR", "files": [], "reason":
                   "cannot-inspect-commit: %s" % exc, "steps": 0,
                   "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                             "total_tokens": 0},
                   "sessions": 0}
        if transcript is not None:
            transcript.record({"type": "end", "verdict": "ERROR",
                               "reason": verdict["reason"]})

    last_validation = None

    # --prior-verdict/--prior-records: prior run recorded this commit; if the
    # agent finishes NO_VULN, feed the prior run's actual records back for
    # one reconsideration round (see agent.run_agent).
    reconsider = None
    reconsider_state = {"fired": False}
    if args.prior_verdict and args.prior_records:
        prior_hint = load_prior_hint(args.prior_verdict, args.prior_records,
                                     args.records_root_rel)
        if prior_hint is not None:
            def reconsider(hint=prior_hint):
                message = build_reconsider_message(hint,
                                                   classify_only)
                reconsider_state["fired"] = bool(message)
                return message
            log("prior-run hint loaded: %d record(s) eligible for "
                "reconsideration" % len(prior_hint["docs"]))

    def validator(scope_records=None):
        """Called by the agent loop after a VULN_UPDATED finish (repair
        rounds).

        With scope_records (a path-hygiene batch session) only that batch's
        records are checked and fed back: other batches' stale paths belong
        to their own sessions and would be pure repair noise here."""
        problems = validate_records(records_root, worktree, old_paths,
                                    path_check)
        if scope_records is not None:
            scope = set(scope_records)
            problems = {
                "errors": [e for e in problems["errors"]
                           if e.split(":", 1)[0].strip() in scope],
                "warnings": [w for w in problems["warnings"]
                             if w.split(":", 1)[0].strip() in scope],
            }
        report_path = os.path.join(args.verdicts_dir,
                                   args.sha + ".validation.md")
        try:
            os.makedirs(args.verdicts_dir, exist_ok=True)
            write_atomic(report_path, format_report(problems, args.sha))
        except OSError:
            pass
        if problems["errors"] or problems["warnings"]:
            log("validation: %d error(s), %d warning(s)"
                % (len(problems["errors"]), len(problems["warnings"])))
        if problems["errors"]:
            return repair_message(problems, val_rounds)
        return None

    if verdict is None:
        max_steps = llm["max_steps"]
        boost = 0
        batches = (plan or {}).get("batches") or []
        stale_by_record = (plan or {}).get("stale_by_record") or {}
        if root_commit and llm["max_steps_initial"] > 0:
            max_steps = llm["max_steps_initial"]
        elif changed and not batches and not (
                plan and (plan["prepass_edited"] or plan["stale_by_record"])):
            # record-heavy commits (big moves touching many cited records)
            # need more tool rounds: +1 step per 8 changed files, capped at
            # max_steps_cap. NOT applied when path hygiene ran (pre-pass or
            # a batched worklist): the repair workload is handled by its own
            # mechanical pass / batch sessions, and a giant changed-file
            # count then only buys the classification session room to
            # wander.
            boost = min(max(0, llm["max_steps_cap"] - max_steps), changed // 8)
            max_steps += boost
        limits_label = limits["profile"]
        if limits["compact_threshold_tokens"]:
            limits_label += " (compact >= %d tokens)" % limits["compact_threshold_tokens"]
        if batches:
            limits_label += (" hygiene=%d record(s) in %d batch(es)"
                             % (len(stale_by_record), len(batches)))
        log("model=%s endpoint=%s mode=%s root_commit=%s steps<=%d%s validation=%s/%d limits=%s"
            % (llm["model"], llm["base_url"], mode, root_commit, max_steps,
               (" (+%d for %d changed files)" % (boost, changed)) if boost else "",
               val_mode, val_rounds, limits_label))

        def record_session(extra=None):
            if transcript is None:
                return
            record = {
                "type": "session",
                "sha": args.sha,
                "model": llm["model"],
                "base_url": llm["base_url"],
                "mode": mode,
                "root_commit": root_commit,
                "max_steps": max_steps,
                "repair_rounds": val_rounds,
                "limits_profile": limits["profile"],
                "compact_threshold_tokens": limits["compact_threshold_tokens"],
                "system_prompt_chars": len(sys_prompt),
                "first_user_chars": len(first_user),
            }
            if extra:
                record.update(extra)
            transcript.record(record)

        # triage fast-path (config triage.enabled): ONE cheap no-tools
        # request (or a pure local glob match) may mark the commit NO_VULN
        # without the full session. Every guard - root commit, renames/
        # deletes, hygiene worklist, prior-run hint, fix/security keywords,
        # oversized diff, unparsable reply - falls through to the FULL
        # session below, so recall is preserved. Skipped for squashed-range
        # sessions: the range session IS the triage (with tools).
        triage_skip = None
        if (triage["enabled"] and reconsider is None
                and not squash_range
                and not batches
                and not (plan and (plan["prepass_edited"]
                                   or plan["stale_by_record"]))):
            triage_client = client
            if triage["model"] != llm["model"]:
                triage_client = ChatClient(
                    base_url=llm["base_url"], api_key=llm["api_key"],
                    model=triage["model"], timeout=llm["timeout"],
                    retries=llm["retries"], temperature=llm["temperature"],
                    max_tokens=llm["max_tokens"],
                    extra_body=llm["extra_body"],
                    heartbeat_seconds=llm["heartbeat_seconds"])
            triage_skip = run_triage(
                triage_client, worktree, args.sha, triage, log,
                root_commit=root_commit, old_paths=old_paths,
                changed=changed, limits=limits, transcript=transcript,
                model=triage["model"], base_url=llm["base_url"],
                cache_dir=os.path.join(args.verdicts_dir, "triage"),
                limit_state_path=limit_state_path)

        if triage_skip is not None:
            session_verdicts = [triage_skip]
            wrote_records = False
            verdict = triage_skip
            if transcript is not None:
                transcript.close()
        else:
            record_session({"squash_range": squash_range}
                           if squash_range else None)
            session_verdicts = []
            wrote_records = False
            try:
                # path-hygiene batches: one fresh, small session per batch of
                # the repair worklist (giant single sessions blow the context
                # window)
                for index, batch in enumerate(batches):
                    batch_records = tuple(sorted(batch))
                    focus_user, _info = build_first_user(
                        args.sha, worktree, records_root, mode, today,
                        read_conventions(records_root, limits), limits=limits,
                        focus={"batch": index + 1, "batches": len(batches),
                               "stale": batch})
                    batch_tools = ToolSet(worktree, records_root,
                                          classify_only=classify_only,
                                          limits=limits)
                    record_session({"batch": "%d/%d" % (index + 1, len(batches)),
                                    "focus_records": list(batch_records),
                                    "first_user_chars": len(focus_user),
                                    "max_steps": llm["max_steps"]})
                    log("hygiene batch %d/%d: %s" % (index + 1, len(batches),
                                                     ", ".join(batch_records)))
                    session_verdicts.append(run_agent(
                        client, batch_tools, sys_prompt, focus_user,
                        llm["max_steps"], log,
                        validator=lambda records=batch_records: validator(records),
                        repair_rounds=val_rounds, transcript=transcript,
                        limits=limits, limit_state_path=limit_state_path))
                    wrote_records = wrote_records or batch_tools.wrote_records

                # main session: classification as usual. After batches the
                # records changed, so the first message is rebuilt (its
                # stale-records worklist must reflect the post-repair state,
                # not the old one).
                if batches:
                    first_user, _info = build_first_user(
                        args.sha, worktree, records_root, mode, today,
                        read_conventions(records_root, limits), limits=limits)
                verdict = run_agent(client, tools, sys_prompt, first_user,
                                    max_steps, log,
                                    validator=validator, repair_rounds=val_rounds,
                                    transcript=transcript, reconsider=reconsider,
                                    limits=limits,
                                    limit_state_path=limit_state_path)
                session_verdicts.append(verdict)
                wrote_records = wrote_records or tools.wrote_records
            except FatalLLMError as exc:
                verdict = {"verdict": "ERROR", "files": [], "reason":
                           "llm: %s" % exc, "steps": 0,
                           "usage": {"prompt_tokens": 0, "completion_tokens": 0,
                                     "total_tokens": 0}}
                session_verdicts.append(verdict)
                if transcript is not None:
                    transcript.record({"type": "end", "verdict": "ERROR",
                                       "reason": verdict["reason"]})
            finally:
                if transcript is not None:
                    transcript.close()

        # aggregate the pre-pass + every session into ONE commit verdict
        prepass_edited = (plan or {}).get("prepass_edited") or {}
        files = list(prepass_edited)
        for session in session_verdicts:
            for item in session.get("files") or []:
                if item and item not in files:
                    files.append(item)
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        steps = 0
        for session in session_verdicts:
            for key in usage:
                usage[key] += int((session.get("usage") or {}).get(key) or 0)
            steps += int(session.get("steps") or 0)
        failed = [s for s in session_verdicts if s["verdict"] == "ERROR"]
        verdict = {
            "verdict": session_verdicts[-1]["verdict"] if session_verdicts
                       else "ERROR",
            "files": files,
            "reason": (session_verdicts[-1].get("reason") or "")
                      if session_verdicts else "no session ran",
            "steps": steps,
            "usage": usage,
            "sessions": len(session_verdicts),
        }
        if failed:
            verdict["verdict"] = "ERROR"
            verdict["files"] = []
            verdict["reason"] = failed[0].get("reason") or "session failed"
        elif files and verdict["verdict"] == "NO_VULN":
            # records changed this invocation (pre-pass / batches) - never
            # report NO_VULN with dirty records on disk
            verdict["verdict"] = "VULN_UPDATED"
        if len(session_verdicts) > 1 or prepass_edited:
            note = ("path hygiene: %d deterministic rewrite(s) in %d record(s), "
                    "%d agent session(s)"
                    % (sum(prepass_edited.values()), len(prepass_edited),
                       len(session_verdicts)))
            if verdict["reason"]:
                verdict["reason"] = note + "; " + verdict["reason"]
            else:
                verdict["reason"] = note

        # final validation state (the validator callback tracks the last
        # run); gated on ANY records change this invocation - agent
        # sessions, the deterministic rename pre-pass, or both
        if (val_mode != "off" and not classify_only
                and (wrote_records or prepass_edited)):
            problems = validate_records(records_root, worktree, old_paths,
                                        path_check)
            last_validation = {"errors": len(problems["errors"]),
                               "warnings": len(problems["warnings"]),
                               "report": args.sha + ".validation.md"}
            try:
                os.makedirs(args.verdicts_dir, exist_ok=True)
                write_atomic(os.path.join(args.verdicts_dir,
                                          args.sha + ".validation.md"),
                             format_report(problems, args.sha))
            except OSError:
                pass
            if (val_mode == "strict" and problems["errors"]
                    and verdict["verdict"] == "VULN_UPDATED"):
                verdict["verdict"] = "ERROR"
                verdict["reason"] = ("validation failed with %d error(s) - "
                                     "records NOT published; see "
                                     "verdicts/%s.validation.md"
                                     % (len(problems["errors"]), args.sha))

    verdict["model"] = llm["model"]
    verdict["mode"] = mode
    verdict["sha"] = args.sha
    verdict["root_commit"] = root_commit
    if squash_range:
        verdict["squash_range"] = {"first": squash_range[0],
                                   "tip": squash_range[-1],
                                   "commits": len(squash_range)}
    if reconsider_state["fired"]:
        verdict["reconsidered"] = True
    if transcript is not None:
        verdict["transcript"] = os.path.basename(transcript.path)
    if last_validation is not None:
        verdict["validation"] = last_validation
    verdict["timestamp"] = datetime.datetime.now().isoformat(timespec="seconds")

    line = verdict_line(verdict, records_root, args.records_root_rel)
    try:
        os.makedirs(args.verdicts_dir, exist_ok=True)
        write_atomic(os.path.join(args.verdicts_dir, args.sha + ".json"),
                     json.dumps(verdict, ensure_ascii=False, indent=2) + "\n")
        write_atomic(os.path.join(args.verdicts_dir, args.sha + ".txt"),
                     line + "\n")
    except OSError as exc:
        print("vuln-agent: cannot write verdict: %s" % exc, file=sys.stderr)
        return 2

    usage = verdict.get("usage", {}).get("total_tokens", 0)
    log("done in %s steps, %s tokens: %s" % (verdict.get("steps", 0), usage, line))
    if verdict["verdict"] == "ERROR":
        if transcript is not None:
            log("to analyze: python3 -m vuln_agent.transcript %s" % transcript.path)
        elif not llm["log_transcript"]:
            log("(transcript disabled - set llm.log_transcript: true in config)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
