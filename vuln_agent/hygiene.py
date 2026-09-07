"""Deterministic path hygiene for rename/delete commits.

A commit that renames/moves/deletes files must update every record citation
of the old paths. Two mechanical accelerators keep that workload small enough
for the model context:

  1. rename pre-pass: citations of a path git detected as RENAMED are
     rewritten to the new location in place - a pure text substitution, no
     agent call at all. A rewrite is applied only when the new path EXISTS in
     the commit worktree, so the pre-pass can never introduce a dead path.
  2. stale worklist batching: whatever the pre-pass could not fix (deletions,
     ambiguous moves) is handed to the agent in small per-batch sessions with
     a scoped repair validator, instead of one giant session whose combined
     write_record payloads cannot fit the context window (fernflower
     842af198: 17 records in one session - 2.7M prompt tokens, 18
     context-limit HTTP 400s, ERROR after 67 steps). config
     limits.hygiene_batch_records (default 5) sets the batch size; 0 disables
     batching.
"""

import os
import re

from .prompt import _git_ok, parent_sha


def rename_pairs(worktree, parent, sha):
    """[(old, new)] for every rename git detected (any similarity score)."""
    raw = _git_ok(worktree, ["diff", "--name-status", "-M", parent, sha])
    pairs = []
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].startswith("R"):
            pairs.append((parts[1], parts[2]))
    return pairs


# read-only kit files ship with the map and are never rewritten by the
# pre-pass (same set the validator's path check exempts)
_FIXED_FILES_L = frozenset(("methodology.md", "project-conventions.md"))


def _iter_md_files(records_root):
    if not os.path.isdir(records_root):
        return
    for dirpath, dirnames, filenames in os.walk(records_root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            if not name.lower().endswith(".md"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name),
                                  records_root).replace(os.sep, "/")
            if rel.lower() in _FIXED_FILES_L:
                continue
            yield os.path.join(dirpath, name)


def _rel(path, records_root):
    return os.path.relpath(path, records_root).replace(os.sep, "/")


def _citation_re(path):
    """Match `path` as a whole token: not inside a longer path/identifier
    (same boundary rules the validator's stale check uses, plus a lookbehind
    so a rewrite can never splice a prefix)."""
    return re.compile(r"(?<![A-Za-z0-9_.@/\-])" + re.escape(path)
                      + r"(?![\w.\-/])")


def _dir_pattern(old_dir):
    """Match `old_dir/<path continuation>` as one whole path token."""
    return re.compile(r"(?<![A-Za-z0-9_.@/\-])" + re.escape(old_dir)
                      + r"/([A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*)")


def apply_renames(records_root, worktree, pairs):
    """Rewrite citations of renamed paths to their new locations, in place.

    Exact file pairs first; citations of files that were not themselves
    renamed but live under a renamed directory are fixed by the directory-
    pair fallback (a moved subtree often carries untracked/generated
    siblings the records also cite). Every candidate rewrite is verified
    against the worktree before it is applied.

    Returns {record_rel: replacement_count} for the records actually changed.
    """
    if not pairs or not os.path.isdir(records_root) or not os.path.isdir(worktree):
        return {}
    exact = dict(pairs)
    dir_counts = {}
    for old, new in pairs:
        od, nd = os.path.dirname(old), os.path.dirname(new)
        if od != nd:
            dir_counts[(od, nd)] = dir_counts.get((od, nd), 0) + 1
    dir_pairs = [pair for pair, _ in sorted(dir_counts.items(),
                                            key=lambda kv: (-kv[1], kv[0]))]
    edited = {}
    for path in _iter_md_files(records_root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if not text:
            continue
        original = text
        count = 0
        # pass 1: exact file-level old -> new
        for old, new in exact.items():
            if old not in text:
                continue
            if os.path.exists(os.path.join(worktree, new)):
                text, n = _citation_re(old).subn(lambda m, new=new: new, text)
                count += n
        # pass 2: directory-level fallback for what is still under a moved
        # directory (paths that were not tracked individually)
        for od, nd in dir_pairs:
            if od + "/" not in text:
                continue
            text, n = _dir_pattern(od).subn(
                lambda m, od=od, nd=nd: _dir_rewrite(m, nd, worktree), text)
            count += n
        if count and text != original:
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                edited[_rel(path, records_root)] = count
            except OSError:
                pass
    return edited


def _dir_rewrite(match, new_dir, worktree):
    """Rewrite `old_dir/rest...` -> `new_dir/rest...` when the target exists."""
    candidate = new_dir + "/" + match.group(1)
    if os.path.exists(os.path.join(worktree, candidate)):
        return candidate
    return match.group(0)


def stale_refs_by_record(records_root, old_paths):
    """{record_rel: [old paths still cited]} - the agent's repair worklist.

    Ordered by record path; runs on the CURRENT records state, so anything
    the rename pre-pass already fixed disappears from the worklist.
    """
    by_record = {}
    if not old_paths or not os.path.isdir(records_root):
        return by_record
    for path in _iter_md_files(records_root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        cited = []
        for old in old_paths:
            if old in text and _citation_re(old).search(text):
                cited.append(old)
        if cited:
            by_record[_rel(path, records_root)] = cited
    return by_record


def split_worklist(by_record, batch_records):
    """Split the worklist into batches of at most batch_records records."""
    items = list(by_record.items())
    return [dict(items[i:i + batch_records])
            for i in range(0, len(items), batch_records)]


def hygiene_plan(worktree, sha, records_root, batch_records=5):
    """Pre-pass + batch plan for one commit. Returns a dict:

      {"parent": str, "renames": [(old,new)], "prepass_edited": {record: n},
       "stale_by_record": {record: [old paths]}, "batches": [{record: [olds]}]}

    `batches` is non-empty only when more than batch_records records still
    cite old paths after the pre-pass (smaller worklists stay in the single
    classification session, as before).
    """
    parent = parent_sha(worktree, sha)
    plan = {"parent": parent, "renames": [], "prepass_edited": {},
            "stale_by_record": {}, "batches": []}
    if not parent:
        return plan
    from .prompt import name_status
    _text, old_paths, _changed = name_status(worktree, parent, sha)
    if not old_paths:
        return plan
    pairs = rename_pairs(worktree, parent, sha)
    plan["renames"] = pairs
    if pairs:
        plan["prepass_edited"] = apply_renames(records_root, worktree, pairs)
    # the worklist is computed on the POST-pre-pass records state
    by_record = stale_refs_by_record(records_root, old_paths)
    plan["stale_by_record"] = by_record
    if batch_records > 0 and len(by_record) > batch_records:
        plan["batches"] = split_worklist(by_record, batch_records)
    return plan
