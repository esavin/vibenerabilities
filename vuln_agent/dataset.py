"""Export session transcripts into a supervised fine-tuning dataset (JSONL).

Reads the per-commit ``<sha>.transcript.jsonl`` files written by the agent
(see ``transcript.py``) and emits one JSON line per model round-trip - a
*sample* the student model can be trained on:

    {"meta":   {"file", "sha", "model", "mode", "verdict", "step", ...},
     "messages": [ ...exactly what the teacher saw at that step... ],
     "target":  {"role": "assistant", "content": ..., "tool_calls": [...]},
     "reasoning": "<the teacher's chain of thought, captured before cleanup>"}

``messages`` replays the conversation the TEACHER model saw: system prompt,
first user message, then assistant (API form - content + nested tool_calls,
WITHOUT reasoning) and tool results in order. ``target`` is the teacher's
actual next move; ``reasoning`` (null when the backend reported none) is the
pre-cleanup chain of thought kept only for distillation - never re-entering
the request history.

Caveat: history compaction / overflow shrinks shrink tool results in place,
and the transcript does not record the shrunk texts, so a prefix that
crossed a compact/overflow event is rebuilt UNCOMPACTED. Such samples are
flagged ``"diverged": true`` (the model actually saw less than the replay
shows); ``--stop-at-compaction`` drops them instead.

Usage:

    python3 -m vuln_agent.dataset -o train.jsonl verdicts/
    python3 -m vuln_agent.dataset --verdict NO_VULN --mode record \
        verdicts/*.transcript.jsonl > train.jsonl

Samples from sessions that ended ERROR are skipped unless
``--include-errors``; triage one-shots (mode "triage") are included when
their session event carries the full prompt texts.
"""

import argparse
import copy
import glob
import json
import os
import sys

from . import transcript as transcript_mod

# injected user-message sources that are pipeline machinery, not analysis
# input; a sample whose prefix ENDS with one of these teaches recovery from
# pipeline pressure - tag it so the consumer can filter
SYNTHETIC_SOURCES = ("nudge:", "deadline", "grace", "extension")

DIVERGE_EVENTS = ("compact", "overflow", "preflight_overflow")


def _api_tool_calls(flat_calls):
    """Flat transcript form -> OpenAI request form (nested under function)."""
    out = []
    for call in flat_calls or []:
        out.append({
            "id": call.get("id") or "call_0",
            "type": "function",
            "function": {
                "name": call.get("name") or "",
                "arguments": call.get("arguments") or "{}",
            },
        })
    return out


def _collect(paths):
    files = []
    for pattern in paths:
        if os.path.isdir(pattern):
            files.extend(sorted(glob.glob(os.path.join(pattern,
                                                        "*.transcript.jsonl"))))
        else:
            files.extend(sorted(glob.glob(pattern)))
    seen = set()
    unique = []
    for path in files:
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            unique.append(path)
    return unique


class _Session(object):
    """Replay state for one agent session (one transcript may hold several:
    triage + full session, or multiple hygiene batches)."""

    stop_at_compaction = False   # per-export flag (set from export_file)

    def on_diverge(self, event):
        """Compaction/overflow shrank the live history.

        Transcripts from agents that snapshot the post-shrink history
        (``messages_after``) replay byte-exact: swap the prefix for the
        snapshot. Older transcripts only recorded the shrink fact - the
        rebuilt prefix is then UNCOMPACTED and such samples are flagged
        ``diverged`` (or dropped with --stop-at-compaction)."""
        if self.stop_at_compaction:
            self.replayable = False
            return
        if event.get("messages_after"):
            self.prefix = copy.deepcopy(event["messages_after"])
        else:
            self.diverged = True

    def __init__(self, header):
        self.header = header
        self.prefix = []
        self.samples = []
        self.diverged = False
        self.step = 0
        self.sources = []
        self.pending_calls = []   # tool_call ids of the last assistant step
        self.finished_batch = False
        self.verdict = None
        if header.get("system_prompt") and header.get("first_user"):
            self.prefix.append({"role": "system",
                                "content": header["system_prompt"]})
            self.prefix.append({"role": "user",
                                "content": header["first_user"]})
        elif header.get("mode") != "triage":
            # old transcripts recorded only char counts - input not
            # reconstructible; emit nothing for this session
            self.replayable = False
            return
        self.replayable = True

    def on_assistant(self, event, path):
        self.step = event.get("step") or (self.step + 1)
        if self.replayable and not self.finished_batch:
            self.samples.append({
                "meta": {
                    "file": os.path.basename(path),
                    "sha": self.header.get("sha"),
                    "model": self.header.get("model"),
                    "mode": self.header.get("mode"),
                    "verdict": None,   # filled at the session end event
                    "step": self.step,
                    "diverged": self.diverged,
                    "synthetic_tail": (self.sources[-1].startswith(
                        SYNTHETIC_SOURCES) if self.sources else False),
                },
                "messages": [dict(m) for m in self.prefix],
                "target": {
                    "role": "assistant",
                    "content": event.get("content") or "",
                    **({"tool_calls": _api_tool_calls(
                        event.get("tool_calls"))}
                       if event.get("tool_calls") else {}),
                },
                "reasoning": event.get("reasoning"),
            })
        # extend the prefix with what went back to the API: content (the
        # hypothesis narration) + nested tool_calls, NEVER the reasoning
        message = {"role": "assistant",
                   "content": event.get("content") or ""}
        calls = event.get("tool_calls") or []
        if calls:
            message["tool_calls"] = _api_tool_calls(calls)
        self.prefix.append(message)
        self.pending_calls = [c.get("id") for c in calls]
        self.finished_batch = False

    def on_tool(self, event):
        if not self.pending_calls:
            return
        call_id = self.pending_calls.pop(0)
        self.prefix.append({"role": "tool", "tool_call_id": call_id,
                            "content": event.get("result") or ""})
        if event.get("name") == "finish" and event.get("ok"):
            self.finished_batch = True   # later calls in the batch were dropped

    def on_user(self, event):
        self.prefix.append({"role": "user",
                            "content": event.get("content") or ""})
        self.sources.append(str(event.get("source") or "pipeline"))
        self.finished_batch = False

    def on_end(self, event):
        self.verdict = event.get("verdict")
        for sample in self.samples:
            sample["meta"]["verdict"] = self.verdict


def export_file(path, args):
    """One transcript file -> list of samples (session-filtered)."""
    _Session.stop_at_compaction = bool(args.stop_at_compaction)
    sessions = []
    current = None
    for event in transcript_mod.load(path):
        kind = event.get("type")
        if kind == "session":
            current = _Session(event)
            sessions.append(current)
        elif kind == "assistant" and current is not None:
            current.on_assistant(event, path)
        elif kind == "tool" and current is not None:
            current.on_tool(event)
        elif kind == "user" and current is not None:
            current.on_user(event)
        elif kind in DIVERGE_EVENTS and current is not None:
            current.on_diverge(event)
        elif kind == "end" and current is not None:
            current.on_end(event)
    samples = []
    for session in sessions:
        if not session.replayable:
            continue
        verdict = session.verdict
        if verdict == "ERROR" and not args.include_errors:
            continue
        if args.verdict and verdict not in args.verdict:
            continue
        if args.mode and session.header.get("mode") not in args.mode:
            continue
        for sample in session.samples:
            if args.drop_synthetic and sample["meta"]["synthetic_tail"]:
                continue
            if args.stop_at_compaction and sample["meta"]["diverged"]:
                continue
            if not args.reasoning:
                sample.pop("reasoning", None)
            samples.append(sample)
    return samples


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python3 -m vuln_agent.dataset",
        description="Export agent transcripts to a JSONL fine-tuning dataset "
                    "(one sample per model round-trip).")
    parser.add_argument("paths", nargs="+", metavar="TRANSCRIPT|DIR",
                        help="*.transcript.jsonl files or directories")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="output JSONL (default: stdout)")
    parser.add_argument("--verdict", metavar="LIST",
                        help="comma-separated verdicts to keep "
                             "(NO_VULN,VULN_UPDATED,ERROR); default: all "
                             "but ERROR")
    parser.add_argument("--mode", metavar="LIST",
                        help="comma-separated session modes to keep "
                             "(record,classify-only,squash-range,triage); "
                             "default: all")
    parser.add_argument("--include-errors", action="store_true",
                        help="keep samples from sessions that ended ERROR")
    parser.add_argument("--drop-synthetic", action="store_true",
                        help="drop samples whose prefix ends with a pipeline "
                             "nudge/deadline/grace message")
    parser.add_argument("--stop-at-compaction", action="store_true",
                        help="drop samples after the point where history "
                             "compaction/overflow shrank the live context "
                             "(otherwise they are kept but flagged "
                             "diverged=true)")
    parser.add_argument("--reasoning", action="store_true",
                        help="keep the teacher's pre-cleanup reasoning in "
                             "each sample (default: drop)")
    args = parser.parse_args(argv)

    args.verdict = ([v.strip().upper() for v in args.verdict.split(",")]
                    if args.verdict else [])
    args.mode = [m.strip() for m in args.mode.split(",")] if args.mode else []

    files = _collect(args.paths)
    if not files:
        print("dataset: no transcript files matched", file=sys.stderr)
        return 1

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    total = 0
    with_reasoning = 0
    diverged = 0
    try:
        for path in files:
            for sample in export_file(path, args):
                out.write(json.dumps(sample, ensure_ascii=False) + "\n")
                total += 1
                if sample.get("reasoning"):
                    with_reasoning += 1
                if sample.get("meta", {}).get("diverged"):
                    diverged += 1
    finally:
        if args.output:
            out.close()
    print("dataset: %d sample(s) from %d transcript(s); %d with reasoning, "
          "%d diverged (compacted replay)" % (total, len(files),
                                              with_reasoning, diverged),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
