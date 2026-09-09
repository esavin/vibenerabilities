"""Deterministic maintenance of INDEX.md (Sync Status, navigation coverage).

Records layout (flat - no module tiers):

  vulnerabilities/VULN-NNN-<slug>.md   one row in the INDEX.md Findings table
  design/NN-<slug>.md                  one bullet in the Aggregated Design Notes

LLM-drift failure modes maintained by the pipeline, not by the model:

- the external audit found "Baseline commit: (none), Last synced: (never)" in
  a fully analyzed project: the sync fields were left to the LLM, which never
  filled them. The pipeline (run.sh) now rewrites the marker bullets itself
  after every processed commit.
- findings-table drift: the agent rewrites the hub per commit from a small
  per-commit context and rows fall out - records exist on disk but are no
  longer reachable from the Findings table, or the table lists records that
  no longer exist (the docs-project incident behind this heal: 45 of 197
  docs linked). After every processed commit the pipeline now re-adds a row
  for every record the table no longer lists and drops rows whose record
  file vanished. Cells of SURVIVING rows are never touched: the agent
  maintains them (status flips, refined titles) and the mechanical pass
  must not overwrite that work.
- findings-row order: the agent inserts rows wherever it is working in the
  table (a real run had VULN-015 between VULN-004 and VULN-005, plus
  duplicate rows for the same record - a second full-SHA row appended
  instead of editing the existing one). Row ORDER is pipeline-owned state,
  like Sync Status: after every processed commit the data rows are
  permuted into ascending VULN-number order (stable; a row's cell content
  is still the agent's), duplicate rows for the same number are dropped
  (first occurrence wins - it is the older, agent-maintained row), and
  VULN data rows stranded OUTSIDE the Findings section (a real run left
  two after the Sync Status block) are removed as drift.
- dropped navigation sections: an agent rewrite of the hub can delete a
  whole section heading (a real run lost "## Function Documentation" in the
  root commit and every later capability doc then landed in design/). The
  reconciliation now re-creates a missing section from the canonical
  template (## Summary / ## Findings / ## Aggregated Design Notes),
  anchored above the Aggregated Design Notes / Sync Status section, with
  either the records' rows and links or the template "_(none yet)_"
  placeholder. The Summary COUNTS are deliberately never recomputed here:
  the validator reports drift and the agent repairs (a silent recompute
  would mask an agent that stopped maintaining them).

    python3 -m vuln_agent.hub --records-root agent/project --baseline <sha> \
        --label "<short sha> (<subject>)" --date YYYY-MM-DD

Idempotent: rewrites the marker bullets in place; the navigation pass is a
no-op when the hub already covers every record and keeps both sections.
Section headings are located by the "findings" / "summary" / "design"
substrings (## Findings, ## Summary, ## Aggregated Design Notes).
"""

import argparse
import os
import re
import sys

from .validate import (HUB, _HEADING_RE, _LINK_RE, _NUMBER_RE, _SKIP_PREFIXES,
                       _VULN_NUMBER_RE, _read, _section_span,
                       parse_record_fields)

_BASELINE_RE = re.compile(r"^(\s*-\s*\*\*[Bb]aseline commit:\*\*.*)$")
_SYNCED_RE = re.compile(r"^(\s*-\s*\*\*[Ll]ast synced:\*\*.*)$")
_SYNC_HEADING_RE = re.compile(r"^#{1,6}\s+sync\s+status\s*$", re.IGNORECASE)
_DESIGN_HEADING_RE = re.compile(r"^#{1,6}\s+aggregated\s+design\s+notes\s*$",
                                re.IGNORECASE)

# canonical section blocks, kept in sync with templates/INDEX.md; used to
# re-create a navigation section the agent dropped from the hub entirely.
# The Summary counts stay at the template placeholders ON PURPOSE - see the
# module docstring for why hub.py never recomputes them.
_SUMMARY_BLOCK = [
    "## Summary",
    "",
    "<!-- The pipeline fills these counts in as records are created/updated. Refresh the whole",
    "     block whenever you add or change a record, so the numbers stay accurate. -->",
    "",
    "- **Total findings:** 0",
    "- **Open at HEAD:** 0",
    "- **Fixed:** 0",
    "",
    "By severity (open / total):",
    "- Critical: 0 / 0",
    "- High: 0 / 0",
    "- Medium: 0 / 0",
    "- Low: 0 / 0",
    "- Info: 0 / 0",
]
_FINDINGS_COMMENT = [
    "<!-- One row per VULN-NNN. Update Status when a fix commit is recorded.",
    "     Rows are kept sorted by VULN ID by the pipeline - append new rows at",
    "     the end of the table; EDIT an existing row instead of adding a",
    "     second one for the same ID. -->",
]
_TABLE_HEADER = [
    "| ID | Title | Severity | Status | Introduced | Fixed | Record |",
    "| --- | --- | --- | --- | --- | --- | --- |",
]
_PLACEHOLDER_ROW = "| _(none yet)_ | | | | | | |"
_DESIGN_COMMENT = [
    "<!-- Cross-cutting themes (auth model and known gaps, crypto audit, input-validation",
    "     strategy, dependency CVEs, …). Optional; created on demand under design/. -->",
]
_HR_RE = re.compile(r"^-{3,}\s*$")
_PLACEHOLDER_RE = re.compile(r"^_\(.*\)_$|^_To be populated\._$")
_VULN_ID_RE = re.compile(r"^VULN-(\d+)$", re.IGNORECASE)


def update_sync_status(records_root, baseline, label="", today=""):
    path = os.path.join(records_root, HUB)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return False
    changed = False
    if baseline:
        text = "`%s`%s" % (baseline[:12], (" — %s" % label) if label else "")
        synced = "%s%s" % (today or "n/a",
                           (" (through `%s`)" % baseline[:12]))
    else:
        text = "_(none yet — first run analyzes from the beginning)_"
        synced = "_(never)_"
    found = set()
    for index, line in enumerate(lines):
        if _BASELINE_RE.match(line):
            new = "- **Baseline commit:** %s" % text
            found.add("baseline")
            if lines[index] != new:
                lines[index] = new
                changed = True
        elif _SYNCED_RE.match(line):
            new = "- **Last synced:** %s" % synced
            found.add("synced")
            if lines[index] != new:
                lines[index] = new
                changed = True
    # a hub missing the Sync Status section (or a marker bullet) gets the
    # canonical block created - the sync fields are never left to the LLM
    # (the audit finding in the module docstring)
    missing_bullets = []
    if "baseline" not in found:
        missing_bullets.append("- **Baseline commit:** %s" % text)
    if "synced" not in found:
        missing_bullets.append("- **Last synced:** %s" % synced)
    if missing_bullets:
        sync_at = None
        for index, line in enumerate(lines):
            if _SYNC_HEADING_RE.match(line):
                sync_at = index
                break
        if sync_at is None:
            # create the section at the end of the hub, template shape
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend(["---", "", "## Sync Status", ""])
            lines.extend(missing_bullets)
        else:
            # the section exists but a marker bullet is missing: insert it
            # after the section's last content line (before the next heading)
            insert_at = sync_at + 1
            for index in range(sync_at + 1, len(lines)):
                if _HEADING_RE.match(lines[index]):
                    break
                if lines[index].strip():
                    insert_at = index + 1
            lines[insert_at:insert_at] = missing_bullets
        changed = True
    if changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return changed


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


def _write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _link_targets(line, base):
    """Base-relative paths of every markdown link target on this line.

    `base` is the absolute directory the containing file lives in (the
    records root for INDEX.md), so relative links resolve the way markdown
    renders them."""
    targets = []
    for match in _LINK_RE.finditer(line):
        target = match.group(2).strip()
        if not target or target.startswith(_SKIP_PREFIXES):
            continue
        target = target.split("#", 1)[0].split()[0]
        if not target:
            continue
        rel = os.path.relpath(os.path.normpath(os.path.join(base, target)),
                              base)
        targets.append(rel.replace(os.sep, "/"))
    return targets


def _vuln_records(records_root):
    """Every vulnerabilities/VULN-*.md with its mechanically parsed row
    fields (id, title, severity, status, introduced/fixed short SHAs),
    sorted by number. Parse failures degrade to the placeholders the table
    shows - never to an error."""
    records = []
    vdir = os.path.join(records_root, "vulnerabilities")
    if os.path.isdir(vdir):
        for name in sorted(os.listdir(vdir)):
            if name.startswith(".") or not name.lower().endswith(".md"):
                continue
            match = _VULN_NUMBER_RE.match(name)
            if not match:
                continue  # check_naming reports it
            number = int(match.group(1))
            fields = parse_record_fields(_read(os.path.join(vdir, name)))
            records.append({
                "number": number,
                "id": "VULN-%03d" % number,
                "file": name,
                "title": fields["title"],
                "severity": fields["severity"],
                "status": fields["status"],
                "introduced": fields["introduced"],
                "fixed": fields["fixed"],
            })
    records.sort(key=lambda record: record["number"])
    return records


def _design_docs(records_root):
    """Sorted design/ note filenames (NN-<slug>.md only)."""
    names = []
    ddir = os.path.join(records_root, "design")
    if os.path.isdir(ddir):
        for name in sorted(os.listdir(ddir)):
            if name.startswith(".") or not name.lower().endswith(".md"):
                continue
            if _NUMBER_RE.match(name):
                names.append(name)
    return names


def _findings_row(record):
    """Canonical table row for one record: id, title, severity, status,
    Introduced/Fixed short SHAs ('-' when the record has none), Record cell
    linking the file. Parse failures already degraded to 'Unknown'."""
    cells = [record["id"], record["title"] or "Unknown",
             record["severity"] or "Unknown", record["status"] or "Unknown",
             record["introduced"] or "-", record["fixed"] or "-",
             "[%s](vulnerabilities/%s)" % (record["id"], record["file"])]
    return "| " + " | ".join(cell.replace("|", "/") for cell in cells) + " |"


def _summary_block():
    return list(_SUMMARY_BLOCK) + [""]


def _findings_block(records):
    """Canonical '## Findings' block with one row per record (placeholder row
    when the map has no records yet)."""
    block = ["## Findings", ""] + _FINDINGS_COMMENT + [""] + list(_TABLE_HEADER)
    if records:
        block.extend(_findings_row(record) for record in records)
    else:
        block.append(_PLACEHOLDER_ROW)
    block.append("")
    return block


def _design_block(designs):
    block = ["## Aggregated Design Notes", ""] + _DESIGN_COMMENT + [""]
    block.extend("- [%s](design/%s)" % (name[:-3], name) for name in designs)
    block.append("")
    return block


def _skeleton_lines(records):
    """Minimal INDEX.md for a records root whose hub is missing entirely
    (run.sh usually creates it from templates/INDEX.md; this is the safety
    net). The Sync Status markers are filled by update_sync_status."""
    return (["# Security Analysis", "",
             "> Blurb placeholder - describe the analyzed project and its "
             "trust boundaries here.",
             ""] + _summary_block() + _findings_block(records)
            + ["---", "", "## Sync Status", ""])


def _pop_section_tail(out):
    """Strip the blank lines and the --- separator at the end of a section
    slice (they separate it from the NEXT section, they are not content);
    returns the stripped tail so callers can re-attach it after appending."""
    while out and not out[-1].strip():
        out.pop()
    tail = []
    if out and _HR_RE.match(out[-1]):
        tail.append(out.pop())
        while out and not out[-1].strip():
            out.pop()
        tail.insert(0, "")
    return tail


def _sort_findings_rows(rows):
    """Deterministic order for the Findings table's data rows: permute them
    (among their own slots) into ascending VULN-number order - stable, so
    rows for the same number keep their relative order - and drop duplicate
    rows for a number already listed (first occurrence wins: it is the
    older, agent-maintained row). Header/placeholder/non-table lines keep
    their positions untouched. Returns (duplicates_dropped, rows_moved)."""
    slots = []   # index of every VULN data row, first-occurrence only
    dupes_at = []  # indices of duplicate rows (same number seen before)
    kept = []    # (number, line) for those first occurrences
    seen = set()
    for index, line in enumerate(rows):
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        match = _VULN_ID_RE.match(cells[0]) if cells else None
        if not match:
            continue
        number = int(match.group(1))
        if number in seen:
            dupes_at.append(index)
            continue
        seen.add(number)
        slots.append(index)
        kept.append((number, line))
    if not slots:
        return 0, 0
    moved = 0
    for slot, (_number, line) in zip(slots, sorted(kept,
                                                   key=lambda pair: pair[0])):
        if rows[slot] != line:
            rows[slot] = line
            moved += 1
    for index in reversed(dupes_at):
        del rows[index]
    return len(dupes_at), moved


def _reconcile_findings_table(lines, span, records):
    """Tier 1 of the heal: the '## Findings' table covers every record file.
    Rows whose VULN id has no record file are dropped, a canonical row is
    appended for every record the table does not list yet, rows of
    SURVIVING records are never touched - the agent maintains their cells -
    and the data rows are permuted into ascending VULN-number order
    (duplicate rows for the same number are dropped; see
    _sort_findings_rows). Returns (rows_added, rows_dropped, rows_duped,
    rows_moved)."""
    start, end = span
    by_number = {record["number"]: record for record in records}
    seen = set()
    for index in range(start, end):
        line = lines[index]
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        match = _VULN_ID_RE.match(cells[0]) if cells else None
        if match:
            seen.add(int(match.group(1)))
    missing = [record for record in records if record["number"] not in seen]
    out = []
    dropped = 0
    for index in range(start, end):
        line = lines[index]
        if not line.lstrip().startswith("|"):
            out.append(line)
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        match = _VULN_ID_RE.match(cells[0]) if cells else None
        if match and int(match.group(1)) not in by_number:
            dropped += 1
            continue  # the record file is gone - the row is dead
        if not match and missing and _PLACEHOLDER_RE.match(cells[0]):
            continue  # first real rows replace the template placeholder
        out.append(line)
    if missing:
        rows = [_findings_row(record) for record in missing]
        insert_at = None
        for offset, line in enumerate(out):
            if line.lstrip().startswith("|"):
                insert_at = offset + 1
        if insert_at is None:
            # the section survived without its table - restore the header too
            tail = _pop_section_tail(out)
            if out and out[-1].strip():
                out.append("")
            out.extend(_TABLE_HEADER)
            out.extend(rows)
            out.extend(tail)
        else:
            out[insert_at:insert_at] = rows
    else:
        # a table left without a single data row gets its placeholder back
        alive = placeholder = False
        insert_at = None
        for offset, line in enumerate(out):
            if not line.lstrip().startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            first = cells[0] if cells else ""
            if _VULN_ID_RE.match(first):
                alive = True
            elif _PLACEHOLDER_RE.match(first):
                placeholder = True
            insert_at = offset + 1
        if not alive and not placeholder and insert_at is not None:
            out.insert(insert_at, _PLACEHOLDER_ROW)
    dupes, moved = _sort_findings_rows(out)
    lines[start:end] = out
    return len(missing), dropped, dupes, moved


def _reconcile_design_notes(lines, span, designs, records_root):
    """Design-notes section heal: drop bullets whose target doc no longer
    exists, add a bullet for every design/ doc the section no longer lists.
    Returns (links_added, links_dropped)."""
    start, end = span
    linked = set()
    for index in range(start, end):
        for target in _link_targets(lines[index], records_root):
            if target.startswith("design/"):
                linked.add(target)
    missing = ["design/%s" % name for name in designs
               if "design/%s" % name not in linked]
    out = []
    dropped = 0
    for index in range(start, end):
        line = lines[index]
        if missing and _PLACEHOLDER_RE.match(line):
            continue  # first real entries replace the template placeholder
        own = [t for t in _link_targets(line, records_root)
               if t.startswith("design/")]
        if own and all(not os.path.isfile(os.path.join(records_root, t))
                       for t in own):
            dropped += 1
            continue
        out.append(line)
    if missing:
        tail = _pop_section_tail(out)
        for target in missing:
            stem = target.split("/", 1)[1][:-3]
            out.append("- [%s](%s)" % (stem, target))
        out.extend(tail)
    lines[start:end] = out
    return len(missing), dropped


def _anchor_for(lines, keys):
    """Insertion index for a re-created section: immediately above the first
    heading matching one of `keys` ('finding' by substring, 'design'/'sync'
    by their canonical headings), above the --- rule when one separates it;
    None when no anchor heading exists (the block is appended at the end)."""
    for index, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if not match:
            continue
        text = match.group(1).lower()
        if (("finding" in text and "finding" in keys)
                or (_DESIGN_HEADING_RE.match(line) and "design" in keys)
                or (_SYNC_HEADING_RE.match(line) and "sync" in keys)):
            back = index
            while back > 0 and not lines[back - 1].strip():
                back -= 1
            if back > 0 and _HR_RE.match(lines[back - 1]):
                return back - 1  # keep a new section above the --- rule
            return index
    return None


def reconcile_navigation(records_root):
    """Guarantee navigation coverage: the '## Findings' table covers every
    vulnerabilities/ record (rows added/dropped mechanically, surviving
    rows' cells never touched - but the data rows are kept sorted by VULN
    number, duplicates dropped), the Aggregated Design Notes section covers
    every design/ note, and a navigation section whose heading the agent
    dropped entirely is re-created from the canonical template (anchored
    above the Aggregated Design Notes / Sync Status sections). Returns a
    one-line change summary, '' when everything is already complete."""
    hub_path = os.path.join(records_root, HUB)
    lines = _read_lines(hub_path)
    skeleton = lines is None
    if skeleton:
        lines = _skeleton_lines(_vuln_records(records_root))
    original = list(lines)

    records = _vuln_records(records_root)
    designs = _design_docs(records_root)

    rows_added = rows_dropped = rows_duped = rows_moved = 0
    links_added = links_dropped = 0
    created = []

    # Tier 1 - heal the existing sections row by row
    span = _section_span(lines, "finding")
    if span is not None:
        rows_added, rows_dropped, rows_duped, rows_moved = \
            _reconcile_findings_table(lines, span, records)
    span = _section_span(lines, "design")
    if span is not None:
        links_added, links_dropped = _reconcile_design_notes(
            lines, span, designs, records_root)

    # Tier 2 - re-create a section whose heading is missing entirely, in
    # template order (Summary, Findings, Aggregated Design Notes), anchored
    # above the first heading each section precedes in the canonical layout
    blocks = []
    if _section_span(lines, "summary") is None:
        blocks.append(("summary", _summary_block()))
        created.append("Summary")
    if _section_span(lines, "finding") is None:
        blocks.append(("findings", _findings_block(records)))
        created.append("Findings")
        rows_added += len(records)
    if _section_span(lines, "design") is None and designs:
        blocks.append(("design", _design_block(designs)))
        created.append("Aggregated Design Notes")
        links_added += len(designs)
    if blocks:
        # canonical anchor precedence per section: Summary sits above the
        # Findings section, Findings above the design notes, design notes
        # above Sync Status (whichever of those headings exists first)
        anchor_keys = {
            "summary": ("finding", "design", "sync"),
            "findings": ("design", "sync"),
            "design": ("sync",),
        }
        anchors = [_anchor_for(lines, anchor_keys[key]) for key, _b in blocks]
        if lines and lines[-1].strip() and any(a is None for a in anchors):
            lines.append("")  # separate appended sections from the last line
        resolved = [len(lines) if a is None else a for a in anchors]
        # insert highest anchor first; blocks sharing an anchor insert in
        # reverse template order so they still land in template order
        order = sorted(range(len(blocks)), key=lambda i: (resolved[i], i),
                       reverse=True)
        for i in order:
            lines[resolved[i]:resolved[i]] = blocks[i][1]

    # Tier 3 - a VULN data row outside the Findings section is agent drift
    # (a real run left two rows appended after the Sync Status block): the
    # section's own table is the single source of truth, so such orphans
    # are dropped wherever they landed
    in_findings = False
    protected = set()
    for index, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if match:
            in_findings = "finding" in match.group(1).lower()
            continue
        if in_findings:
            protected.add(index)
    orphans = 0
    if len(protected) < len(lines):
        kept_lines = []
        for index, line in enumerate(lines):
            if index not in protected and line.lstrip().startswith("|"):
                cells = [cell.strip()
                         for cell in line.strip().strip("|").split("|")]
                if cells and _VULN_ID_RE.match(cells[0]):
                    orphans += 1
                    continue
            kept_lines.append(line)
        lines[:] = kept_lines

    summary_parts = []
    if skeleton:
        summary_parts.append("created missing INDEX.md (skeleton)")
    if rows_added or rows_dropped:
        summary_parts.append("findings rows: %+d, -%d dead"
                             % (rows_added, rows_dropped))
    if rows_duped:
        summary_parts.append("-%d duplicate row(s)" % rows_duped)
    if rows_moved:
        summary_parts.append("rows sorted by ID (%d moved)" % rows_moved)
    if orphans:
        summary_parts.append("-%d orphaned row(s) outside ## Findings"
                             % orphans)
    if links_added or links_dropped:
        summary_parts.append("design links: %+d, -%d dead"
                             % (links_added, links_dropped))
    if created:
        summary_parts.append("created section(s): %s" % ", ".join(created))
    if lines != original or skeleton:
        _write_lines(hub_path, lines)
    if not summary_parts:
        return ""
    return "navigation: " + "; ".join(summary_parts)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vuln-agent-hub",
        description="Maintain INDEX.md: Sync Status (baseline / last synced) "
                    "and full Findings / design-notes coverage.")
    parser.add_argument("--records-root", required=True)
    parser.add_argument("--baseline", default="", help="last analyzed commit sha")
    parser.add_argument("--label", default="", help="short sha + commit subject")
    parser.add_argument("--date", default="", help="YYYY-MM-DD")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    records_root = os.path.realpath(args.records_root)
    nav = reconcile_navigation(records_root)
    sync = "sync: no flags given - markers left untouched"
    if args.baseline or args.label or args.date:
        changed = update_sync_status(records_root, args.baseline, args.label,
                                     args.date)
        sync = ("sync: updated" if changed
                else "sync: no change (markers not found)")
    print("hub: %s, %s" % (sync, nav or "navigation: complete"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
