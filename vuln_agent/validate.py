"""Post-write records validation (all checks are mechanical and language-agnostic).

Rationale: an external audit of generated records found broken internal links,
duplicate VULN numbering, paths prefixed with a workspace folder that is not part
of the repository, references to files renamed/deleted later, identifiers written
from memory, and records that silently lost their INDEX.md navigation row. All of
these are mechanically checkable, so the pipeline now validates after every
record-writing commit and feeds the problems back to the agent for repair.

Records layout (flat - no module tiers):
  INDEX.md                            the hub (Findings table, Summary counts)
  methodology.md                      fixed read-only kit files
  project-conventions.md
  vulnerabilities/VULN-NNN-<slug>.md  one record per issue (THREE-digit numbers)
  design/NN-<slug>.md                 cross-cutting notes (TWO-digit numbers)
The two directories number independently: vulnerabilities/ counts in VULN-NNN,
design/ in NN.

Checks:
  1. layout - the records root contains only the fixed top-level entries
               (INDEX.md, methodology.md, project-conventions.md,
                vulnerabilities/, design/, dotfiles like .vibenerabilities.json).
               Strays and missing fixed kit files are warnings: they are drift
               signals, the map itself still works.
  2. naming - files in vulnerabilities/ match VULN-NNN-<slug>.md, files in
               design/ match NN-<slug>.md; numbers are unique per directory
               (duplicates are errors; numbering gaps are warnings).
  3. links  - every relative markdown link resolves to an existing file under the
               records root (http(s)/mailto/anchor targets are skipped).
  4. paths  - repository-path-like references (contain "/" and a file extension, no
               placeholder markers) resolve inside the worktree = the repository at
               the commit being analyzed. Catches stale prefixes such as
               "<clone>/src/..." and citations of files that no longer exist.
  5. stale  - no record still cites a path renamed/deleted by the commit under review
               (old paths come from the rename-aware name-status of this commit).
  6. orphans - every vulnerabilities/ and design/ record is reachable from
               INDEX.md. Warnings only: the pipeline's hub reconciliation
               (vuln_agent/hub.py) re-adds missing rows itself after each
               processed commit, so this is a drift signal, not a repair task
               for the agent.
  7. hub sections - INDEX.md keeps BOTH fixed sections (## Findings, ## Summary).
               A dropped section heading leaves every later record without an
               anchor. Errors: the heading is trivial to restore in a repair
               round, and hub.py re-creates a missing section deterministically
               as a safety net. The Summary COUNTS are checked separately
               (check_summary_drift) as warnings: the agent owns the counts and
               repairs the drift - hub.py deliberately never recomputes them.

Severities: errors are deterministic and block publication in strict mode; warnings
are heuristics recorded in the report. Usable standalone:

    python3 -m vuln_agent.validate --records-root agent/project [--worktree <tree>]
            [--old-path p ...] [--path-check error|warn|off] [--report FILE]
"""

import argparse
import os
import re
import sys

RECORDS_TOP_FILES = {"INDEX.md", "methodology.md", "project-conventions.md"}
RECORDS_FIXED_FILES = {"methodology.md", "project-conventions.md"}
RECORDS_TOP_DIRS = {"vulnerabilities", "design"}
HUB = "INDEX.md"

# numbering regexes for the two record directories, kept in sync with the
# shapes in tools.py: vulnerabilities/ records share ONE VULN-NNN counter;
# design/ notes carry their own two-digit counter.
_VULN_NUMBER_RE = re.compile(r"^VULN-(\d{1,4})[-_]", re.IGNORECASE)
_NUMBER_RE = re.compile(r"^(\d{1,3})[-_]")

_HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")
# fixed sections of INDEX.md are located by a substring of their heading
# text - tolerates reasonable renames an agent might produce ("## Findings
# Table" still anchors the findings section)
HUB_SECTION_KEYS = (("finding", "findings"), ("summary", "summary"))

# at least one "/" and plain filename characters only
_PATH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_.@/\-])[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+")
_FILE_EXT_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,4}$")
_LINK_RE = re.compile(r"!?\[([^\]]*)\]\(\s*<?([^)>]+?)>?\s*\)")
_FENCE_RE = re.compile(r"^(`{3,}|~{3,})")
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
_SKIP_PREFIXES = ("http://", "https://", "mailto:", "ftp://", "#", "data:", "//")
_SKIP_TOKEN_CONTAINS = ("<", ">", "@@", "...", "*", "://")
_PLACEHOLDER_FIRST = {
    "path", "paths", "file", "files", "foo", "bar", "baz", "qux", "your", "some",
    "example", "examples", "name", "names", "placeholder", "of", "to",
}


def _number_match(top, name):
    """Numbering regex for one records directory (vulnerabilities/ counts in
    VULN-NNN, design/ in NN - the two counters are independent)."""
    return (_VULN_NUMBER_RE if top == "vulnerabilities" else _NUMBER_RE).match(name)


def _number_width(top):
    return 3 if top == "vulnerabilities" else 2


def _format_number(top, number):
    """Canonical spelling of a record number: 'VULN-001' / '01'."""
    if top == "vulnerabilities":
        return "VULN-%03d" % number
    return "%02d" % number


_RECORDS_TOP_FILES_L = frozenset(name.lower() for name in RECORDS_TOP_FILES)


def parse_record_path(rel):
    """Parse a records-root-relative path of the fixed layout.

    Returns None for anything else, else a dict:
      INDEX.md                      -> {"top": None, "file": "INDEX.md",
                                        "number": None}   (the hub)
      methodology.md                -> {"top": None, ...}  (read-only kit file)
      vulnerabilities/VULN-001-x.md -> {"top": "vulnerabilities",
                                        "file": "VULN-001-x.md", "number": 1}
      design/01-x.md                -> {"top": "design", "file": "01-x.md",
                                        "number": 1}
    """
    parts = [p for p in str(rel).replace("\\", "/").split("/")
             if p not in ("", ".")]
    if len(parts) == 1:
        name = parts[0]
        if name.lower() in _RECORDS_TOP_FILES_L:
            return {"top": None, "file": name, "number": None}
        return None
    if len(parts) == 2:
        top, name = parts[0].lower(), parts[1]
        if top not in RECORDS_TOP_DIRS or not name.lower().endswith(".md"):
            return None
        match = (_VULN_NUMBER_RE if top == "vulnerabilities"
                 else _NUMBER_RE).match(name)
        if not match:
            return None
        return {"top": top, "file": name, "number": int(match.group(1))}
    return None


def records_inventory(records_root):
    """Structural inventory of the records map.

    Returns {top: [record file names]} for both records directories. Anything
    that does not parse (weird names, stray files) is simply absent here -
    check_naming reports it.
    """
    inv = {}
    for top in sorted(RECORDS_TOP_DIRS):
        base = os.path.join(records_root, top)
        names = []
        if os.path.isdir(base):
            for name in sorted(os.listdir(base)):
                if name.startswith("."):
                    continue
                if name.lower().endswith(".md") and _number_match(top, name):
                    names.append(name)
        inv[top] = names
    return inv


_RECORD_TITLE_RE = re.compile(r"^#\s+VULN-\d+\s*:\s*(.*)$", re.IGNORECASE)
_FIELD_LINE_RES = {
    "severity": re.compile(r"^-\s*\*\*[Ss]everity:\*\*\s*(\S.*?)\s*$"),
    "status": re.compile(r"^-\s*\*\*[Ss]tatus:\*\*\s*(\S.*?)\s*$"),
}
_SHA_TOKEN_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
_LIFECYCLE_KEYS = (("introduced", "introduced in"), ("fixed", "fixed in"))


def parse_record_fields(text):
    """Mechanical field extraction from one vulnerability record: the
    '# VULN-NNN: <Title>' heading, the Severity/Status bullets of
    '## Classification', and the first commit SHA appearing under
    '### Introduced in' / '### Fixed in'. Returns {"title", "severity",
    "status", "introduced", "fixed"} - None wherever the shape is not
    recognized (tolerant regexes; callers fall back to placeholders)."""
    fields = {"title": None, "severity": None, "status": None,
              "introduced": None, "fixed": None}
    section = ""
    for line in text.splitlines():
        if fields["title"] is None:
            match = _RECORD_TITLE_RE.match(line)
            if match:
                fields["title"] = match.group(1).strip() or None
        heading = _HEADING_RE.match(line)
        if heading:
            section = heading.group(1).strip().lower()
            continue
        if "classification" in section:
            for key, regex in _FIELD_LINE_RES.items():
                match = regex.match(line)
                if match and fields[key] is None:
                    fields[key] = match.group(1).strip()
        for key, marker in _LIFECYCLE_KEYS:
            if marker in section and fields[key] is None:
                match = _SHA_TOKEN_RE.search(line)
                if match:
                    fields[key] = match.group(0)
    return fields


def _section_span(lines, key):
    """(start, end) of the first hub section whose heading text contains
    `key` (lowercased substring - tolerates reasonable agent renames); end is
    exclusive at the next heading of any level. None when absent."""
    start = None
    for index, line in enumerate(lines):
        match = _HEADING_RE.match(line)
        if not match:
            continue
        if start is not None:
            return (start, index)
        if key in match.group(1).lower():
            start = index
    return (start, len(lines)) if start is not None else None


def _iter_md_files(records_root):
    if not os.path.isdir(records_root):
        return
    for dirpath, dirnames, filenames in os.walk(records_root):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            if name.lower().endswith(".md"):
                yield os.path.join(dirpath, name)


def _rel(path, records_root):
    return os.path.relpath(path, records_root).replace(os.sep, "/")


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _strip_code(text):
    """Blank out fenced code blocks and inline code spans before markup
    checks: markdown inside code is literal text, not markup. Without this,
    a quoted Go generics call ('parseArgs[runCommandArgs](jsonArgs)') matches
    _LINK_RE as a fake '[runCommandArgs](jsonArgs)' link and fails link
    validation with a bogus 'broken link' error."""
    out = []
    fence = None  # fence character while inside a block, else None
    for line in text.split("\n"):
        stripped = line.lstrip()
        if fence is None:
            opener = _FENCE_RE.match(stripped)
            if opener:
                fence = opener.group(1)[0]
                out.append("")
                continue
            out.append(line)
        else:
            if stripped.startswith(fence * 3):
                fence = None
            out.append("")
    return _INLINE_CODE_RE.sub(" ", "\n".join(out))


def check_layout(records_root, warnings):
    allowed = RECORDS_TOP_FILES | RECORDS_TOP_DIRS
    allowed_l = {name.lower() for name in allowed}
    present = set()
    for name in sorted(os.listdir(records_root)):
        if name.startswith("."):
            continue  # .vibenerabilities.json and friends
        present.add(name.lower())
        if name.lower() not in allowed_l:
            warnings.append("layout: unexpected top-level entry '%s' (allowed: %s)"
                            % (name, ", ".join(sorted(allowed))))
    for fixed in sorted(RECORDS_FIXED_FILES):
        if fixed not in present:
            warnings.append(
                "layout: fixed kit file '%s' is missing from the records root "
                "- restore it from the vibenerabilities templates" % fixed)


def _check_numbered_set(directory, names, errors, warnings):
    """Uniqueness/gap checks for one directory's numbered records."""
    numbers = {}
    for name in names:
        match = _number_match(directory, name)
        if not match:
            continue
        number = match.group(1)
        if len(number) < _number_width(directory):
            errors.append(
                "naming: %s/%s uses an unpadded number - the fixed layout "
                "numbers %s records with %s digits. write_record retargets "
                "the padded spelling automatically ('%s/%s-%s')"
                % (directory, name, directory,
                   "THREE" if directory == "vulnerabilities" else "TWO",
                   directory, _format_number(directory, int(number)),
                   name[match.end():]))
        numbers.setdefault(int(number), []).append(name)
    for number, dupes in sorted(numbers.items()):
        if len(dupes) > 1:
            errors.append(
                "naming: duplicate number %s in %s/: %s. Keep ONE of these "
                "records (merge the content if both have value, or renumber "
                "the survivor via write_record to the lowest free number) "
                "and DELETE the others with write_record({\"path\": "
                "\"%s/<file>\", \"delete\": true}). Do NOT create yet another "
                "numbered record for this issue."
                % (_format_number(directory, number), directory,
                   ", ".join(dupes), directory))
    if numbers:
        highest = max(numbers)
        if highest > len(numbers):
            warnings.append(
                "naming: numbering gap in %s/ - highest number %s but only %d "
                "numbered records; reuse the lowest free number for new records"
                % (directory, _format_number(directory, highest), len(numbers)))


def check_naming(records_root, errors, warnings):
    for directory in sorted(RECORDS_TOP_DIRS):
        path = os.path.join(records_root, directory)
        if not os.path.isdir(path):
            continue
        names = []
        for name in sorted(os.listdir(path)):
            if name.startswith("."):
                continue
            if not name.lower().endswith(".md"):
                errors.append("naming: %s/%s is not a .md file" % (directory, name))
                continue
            if _number_match(directory, name):
                names.append(name)
            else:
                errors.append(
                    "naming: %s/%s must follow the %s pattern"
                    % (directory, name,
                       "VULN-NNN-<slug>.md (VULN- prefix, THREE-digit number)"
                       if directory == "vulnerabilities"
                       else "NN-<slug>.md (TWO-digit number)"))
        _check_numbered_set(directory, names, errors, warnings)


def check_links(records_root, errors):
    for path in _iter_md_files(records_root):
        rel = _rel(path, records_root)
        base = os.path.dirname(path)
        for match in _LINK_RE.finditer(_strip_code(_read(path))):
            target = match.group(2).strip()
            if not target or target.startswith(_SKIP_PREFIXES):
                continue
            target = target.split("#", 1)[0].strip()
            if not target or target.startswith(_SKIP_PREFIXES):
                continue
            resolved = os.path.normpath(os.path.join(base, target))
            if not os.path.exists(resolved):
                errors.append("%s: broken link '(%s)'" % (rel, target))


def _path_candidates(line):
    for match in _PATH_TOKEN_RE.finditer(line):
        token = match.group(0)
        if any(marker in token for marker in _SKIP_TOKEN_CONTAINS):
            continue
        if token.startswith("www.") or token.endswith(".md"):
            continue
        if not _FILE_EXT_RE.search(token):
            continue
        if token.split("/", 1)[0].lower() in _PLACEHOLDER_FIRST:
            continue
        yield token


_SHA_LIKE_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def _cited_path_ok(records_root, worktree, token):
    """Exemptions + existence for one cited path token (same rules as the
    write-time lint in tools.py): SHAs, the records state file, and paths
    inside the records root itself never count as dead repository paths."""
    if token.split("/")[-1].lower() == ".vibenerabilities.json":
        return True  # the records state file, never part of the worktree
    if any(_SHA_LIKE_RE.match(part) for part in token.split("/")):
        return True  # pasted git output such as '<sha>/src/foo.c'
    if os.path.exists(os.path.join(worktree, token)):
        return True
    if os.path.exists(os.path.join(records_root, token)):
        return True  # records legitimately cite the map, not the repo
    return False


# fixed kit files use example paths ("e.g. src/path/to/file.ext") by
# design - the source-path check targets agent-written records
PATH_CHECK_EXEMPT = {"methodology.md", "project-conventions.md"}


def check_paths(records_root, worktree, problems, severity):
    if not worktree or not os.path.isdir(worktree) or severity == "off":
        return
    for path in _iter_md_files(records_root):
        rel = _rel(path, records_root)
        if rel in PATH_CHECK_EXEMPT:
            continue
        seen = set()
        for line in _read(path).splitlines():
            for token in _path_candidates(line):
                if token in seen:
                    continue
                seen.add(token)
                if _cited_path_ok(records_root, worktree, token):
                    continue
                problems.append(
                    "%s: path '%s' does not exist in the repository at this commit "
                    "(fix the prefix, update to the current path, or remove the "
                    "reference)" % (rel, token))


def check_stale(records_root, old_paths, errors):
    if not old_paths:
        return
    for path in _iter_md_files(records_root):
        rel = _rel(path, records_root)
        text = _read(path)
        if not text:
            continue
        for old in old_paths:
            # boundary check: an old path EXTENDED with more filename
            # characters is a different, valid path - 'build.gradle' inside
            # 'build.gradle.kts' must NOT count as a stale citation
            if re.search(re.escape(old) + r"(?![\w.\-/])", text):
                errors.append("%s: still cites '%s' (renamed/deleted by this commit)"
                              % (rel, old))


def check_orphans(records_root, warnings):
    """Reverse direction of check_links: navigation coverage. Every
    vulnerabilities/ and design/ record must be reachable from INDEX.md -
    via a markdown link OR a bare records-root-relative path mention (the
    Findings Record column carries the plain path, no link markup). The
    agent rewrites the hub per commit in a small context and old rows fall
    out (orphan drift); this reports the drift. Warnings only -
    vuln_agent/hub.py heals them."""
    hub = os.path.join(records_root, HUB)
    if not os.path.isfile(hub):
        return
    text = _strip_code(_read(hub))
    linked = set()
    for match in _LINK_RE.finditer(text):
        target = match.group(2).strip()
        if not target or target.startswith(_SKIP_PREFIXES):
            continue
        target = target.split("#", 1)[0].split()[0]
        if not target:
            continue
        rel = os.path.relpath(os.path.normpath(os.path.join(records_root, target)),
                              records_root)
        linked.add(rel.replace(os.sep, "/"))
    for directory, names in records_inventory(records_root).items():
        for name in names:
            rel = "%s/%s" % (directory, name)
            if rel in linked or rel in text:
                continue
            warnings.append(
                "%s: not linked from INDEX.md (navigation coverage; "
                "the pipeline re-adds missing rows itself after this "
                "commit)" % rel)


def check_hub_sections(records_root, errors):
    """INDEX.md must keep BOTH fixed sections (Findings + Summary). When the
    agent drops a section heading, every later record loses its anchor and
    the map silently stops being navigable, so this is an error, not a
    warning."""
    hub = os.path.join(records_root, HUB)
    if not os.path.isfile(hub):
        return
    present = set()
    for line in _read(hub).splitlines():
        match = _HEADING_RE.match(line)
        if not match:
            continue
        text = match.group(1).lower()
        for key, section in HUB_SECTION_KEYS:
            if key in text:
                present.add(section)
    for _key, section in HUB_SECTION_KEYS:
        if section not in present:
            errors.append(
                "INDEX.md: missing %s section - restore its heading "
                "('## Findings' / '## Summary'); the findings table / summary "
                "counts live there" % section)


_SUMMARY_TOTAL_RE = re.compile(r"^-\s*\*\*[Tt]otal findings:\*\*\s*(\d+)\s*$")
_SUMMARY_SEVERITY_RE = re.compile(
    r"^-\s*(Critical|High|Medium|Low|Info)\s*:\s*(\d+)\s*/\s*(\d+)\s*$",
    re.IGNORECASE)
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def check_summary_drift(records_root, warnings):
    """'## Summary' counts vs the records actually on disk (parsed
    Severity/Status). The agent owns the counts (it refreshes them per record
    change; hub.py deliberately never recomputes them), so drift is a repair
    signal for the agent, not something this check fixes."""
    hub = os.path.join(records_root, HUB)
    if not os.path.isfile(hub):
        return
    lines = _read(hub).splitlines()
    span = _section_span(lines, "summary")
    if span is None:
        return  # a missing section is check_hub_sections' error
    records = []
    vdir = os.path.join(records_root, "vulnerabilities")
    if os.path.isdir(vdir):
        for name in sorted(os.listdir(vdir)):
            if (not name.startswith(".") and name.lower().endswith(".md")
                    and _number_match("vulnerabilities", name)):
                records.append(parse_record_fields(_read(os.path.join(vdir, name))))
    said_total = None
    said_severity = {}
    for line in lines[span[0]:span[1]]:
        match = _SUMMARY_TOTAL_RE.match(line.strip())
        if match:
            said_total = int(match.group(1))
            continue
        match = _SUMMARY_SEVERITY_RE.match(line.strip())
        if match:
            said_severity[match.group(1).capitalize()] = (
                int(match.group(2)), int(match.group(3)))
    drift = []
    if said_total is not None and said_total != len(records):
        drift.append("'Total findings' says %d, records present %d"
                     % (said_total, len(records)))
    for severity in _SEVERITIES:
        said = said_severity.get(severity)
        if said is None:
            continue
        matching = [rec for rec in records
                    if (rec["severity"] or "").strip().lower() == severity.lower()]
        have_open = sum(1 for rec in matching
                        if (rec["status"] or "").strip().lower() != "fixed")
        if said != (have_open, len(matching)):
            drift.append("%s says %d/%d, records %d/%d"
                         % (severity, said[0], said[1], have_open, len(matching)))
    if drift:
        warnings.append(
            "INDEX.md: Summary counts drifted from the records (%s) - "
            "refresh the whole Summary block" % "; ".join(drift))


def validate_records(records_root, worktree=None, old_paths=(), path_check="error"):
    """Run all checks. Returns {"errors": [...], "warnings": [...]}."""
    errors, warnings = [], []
    check_layout(records_root, warnings)
    check_naming(records_root, errors, warnings)
    check_links(records_root, errors)
    path_problems = []
    check_paths(records_root, worktree, path_problems, path_check)
    if path_check == "error":
        errors.extend(path_problems)
    elif path_check == "warn":
        warnings.extend(path_problems)
    check_stale(records_root, old_paths, errors)
    check_orphans(records_root, warnings)
    check_hub_sections(records_root, errors)
    check_summary_drift(records_root, warnings)
    return {"errors": errors, "warnings": warnings}


def format_report(problems, sha=""):
    lines = ["# Validation report%s" % ((" for %s" % sha) if sha else ""), ""]
    lines.append("- errors: %d" % len(problems["errors"]))
    lines.append("- warnings: %d" % len(problems["warnings"]))
    lines.append("")
    if problems["errors"]:
        lines.append("## Errors (block publication in strict mode)")
        lines.extend("- %s" % item for item in problems["errors"])
        lines.append("")
    if problems["warnings"]:
        lines.append("## Warnings")
        lines.extend("- %s" % item for item in problems["warnings"])
        lines.append("")
    return "\n".join(lines)


def repair_message(problems, rounds_left):
    parts = [
        "VALIDATION FAILED - your records have mechanical problems. Fix ALL of them "
        "now with edit_record (targeted text replacements) or write_record (new "
        "records only), and search_records to locate every occurrence, then call "
        "finish again with verdict VULN_UPDATED listing every file you modified "
        "(across all rounds). Never rewrite a whole existing record to fix a path - "
        "edit_record is the right tool and a lossy rewrite is refused.",
    ]
    if any("duplicate number" in item for item in problems["errors"]):
        parts.append(
            "DUPLICATE NUMBERING: two or more records share a number. Merge their "
            "content into the single best file (or renumber the survivor to the "
            "lowest free number via write_record), then DELETE every redundant "
            "file with write_record({\"path\": ..., \"delete\": true}). Creating "
            "yet another NEW numbered record for the issue is WRONG - it adds "
            "another duplicate.")
    if any("does not exist in the repository" in item for item in problems["errors"]):
        parts.append(
            "DEAD PATHS: a file was renamed or moved by this commit (see the "
            "grouped renames in NAME STATUS). With edit_record, replace each cited "
            "old path with its NEW location in the worktree (find=old path, "
            "replace=new path), or remove the citation if the file is gone - "
            "never keep a path that does not exist at this commit.")
    if any("still cites" in item for item in problems["errors"]):
        parts.append(
            "STALE RENAME REFERENCES: a record still cites a path renamed or "
            "deleted by this commit. Update every citation to the new path (NAME "
            "STATUS shows where the file moved) with edit_record, or remove the "
            "reference when the file is gone for good.")
    if problems["errors"]:
        parts.append("Errors (must fix):")
        parts.extend("- %s" % item for item in problems["errors"])
    if problems["warnings"]:
        parts.append("Warnings (verify and fix if genuine):")
        parts.extend("- %s" % item for item in problems["warnings"])
    parts.append("Repair rounds remaining after this one: %d. If a reported path is "
                 "intentionally not part of the repository, remove or rephrase the "
                 "reference instead of leaving it." % max(0, rounds_left - 1))
    return "\n".join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="vuln-agent-validate",
        description="Validate the records map (links, numbering, layout, "
                    "source paths, stale references, hub coverage).")
    parser.add_argument("--records-root", required=True)
    parser.add_argument("--worktree", default="",
                        help="worktree with the project at the commit being analyzed "
                             "(enables the source-path checks)")
    parser.add_argument("--old-path", action="append", default=[],
                        help="path renamed/deleted by the commit; records citing it fail")
    parser.add_argument("--path-check", choices=["error", "warn", "off"],
                        default="error")
    parser.add_argument("--report", default="", help="also write the report to FILE")
    parser.add_argument("--sha", default="", help="commit for the report header")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    records_root = os.path.realpath(args.records_root)
    worktree = os.path.realpath(args.worktree) if args.worktree else None
    problems = validate_records(records_root, worktree, args.old_path, args.path_check)
    report = format_report(problems, args.sha)
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report)
    print(report)
    return 1 if problems["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
