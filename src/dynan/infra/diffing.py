"""Diff generation, parsing and function attribution.

dynAn computes the diff itself rather than asking the user for one. File-level
metadata (added / removed / renamed, binary-ness, similarity) comes from
``git diff --raw``, which is machine-readable and authoritative; the unified
body is parsed separately for hunks and line numbers. Cross-checking the two
avoids leaning on pattern matching alone for structural facts.

Function attribution maps changed line numbers onto enclosing C/C++ function
spans. It is a deliberate heuristic - a brace-matching scanner over
comment-and-string-stripped source - and the correlation engine treats its
output as *supporting evidence*, never as proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..domain.models import DiffHunk, DiffLine, FileDiff, StructuredDiff
from . import git

_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<heading>.*)$"
)
_DIFF_HEADER_RE = re.compile(r"^diff --git (?P<a>.+?) (?P<b>.+)$")
_RAW_RE = re.compile(
    r"^:(?P<old_mode>\d+) (?P<new_mode>\d+) (?P<old_sha>[0-9a-f]+) "
    r"(?P<new_sha>[0-9a-f]+) (?P<status>[A-Z])(?P<score>\d*)\t(?P<paths>.*)$"
)

#: Source extensions we attempt function attribution for.
_C_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inl"}

#: Keywords that look like a call but introduce a block, not a function.
_NOT_FUNCTIONS = {
    "if", "for", "while", "switch", "catch", "return", "sizeof", "do",
    "else", "struct", "union", "enum", "class", "namespace", "typedef",
    "static_assert", "decltype", "noexcept", "alignas", "__attribute__",
}

_IDENT_RE = re.compile(r"(~?[A-Za-z_][A-Za-z0-9_]*)\s*$")


# --------------------------------------------------------------------------
# Function span scanning
# --------------------------------------------------------------------------


@dataclass(slots=True)
class FunctionSpan:
    name: str
    start_line: int
    end_line: int

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


def _blank_out(text: str) -> str:
    """Replace comment and string contents with spaces, preserving offsets.

    Keeping byte offsets and newlines identical means line numbers computed on
    the blanked text apply directly to the original source.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
        elif ch in "\"'":
            quote = ch
            out[i] = " "
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    if text[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def _extract_function_name(signature: str) -> tuple[str, int] | None:
    """Pull the function name out of the text preceding an opening brace.

    Returns the name together with its offset *within ``signature``*. The
    offset matters: a declaration's segment starts after the previous
    statement, so it can include unrelated leading text (a ``#include`` line,
    say), and anchoring the reported line to the identifier is what keeps the
    attribution pointing at the function rather than at the top of the file.
    """
    sig = signature
    if not sig.strip() or sig.rstrip().endswith(("=", ",")):
        return None
    # Ignore initialiser lists and control structures.
    close = sig.rfind(")")
    if close == -1:
        return None

    depth = 0
    open_paren = -1
    for idx in range(close, -1, -1):
        if sig[idx] == ")":
            depth += 1
        elif sig[idx] == "(":
            depth -= 1
            if depth == 0:
                open_paren = idx
                break
    if open_paren <= 0:
        return None

    match = _IDENT_RE.search(sig[:open_paren])
    if not match:
        return None
    name = match.group(1)
    if name in _NOT_FUNCTIONS:
        return None
    offset = match.start(1)
    # A C++ qualified name keeps its class prefix for readability.
    prefix = sig[:open_paren][:offset].rstrip()
    if prefix.endswith("::"):
        qual = re.search(r"([A-Za-z_][A-Za-z0-9_]*)::\s*$", prefix)
        if qual:
            return f"{qual.group(1)}::{name}", qual.start(1)
    return name, offset


def find_functions(text: str) -> list[FunctionSpan]:
    """Locate top-level function definitions and their line ranges."""
    clean = _blank_out(text)
    # Precompute line numbers for offsets.
    line_starts = [0]
    for idx, ch in enumerate(clean):
        if ch == "\n":
            line_starts.append(idx + 1)

    def line_of(offset: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    spans: list[FunctionSpan] = []
    depth = 0
    segment_start = 0
    pending: tuple[str, int] | None = None

    for idx, ch in enumerate(clean):
        if ch == "{":
            if depth == 0:
                extracted = _extract_function_name(clean[segment_start:idx])
                if extracted is not None:
                    name, name_offset = extracted
                    pending = (name, line_of(segment_start + name_offset))
                else:
                    pending = None
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth <= 0:
                depth = max(depth, 0)
                if pending is not None:
                    spans.append(FunctionSpan(pending[0], pending[1], line_of(idx)))
                    pending = None
                segment_start = idx + 1
        elif ch == ";" and depth == 0:
            segment_start = idx + 1
            pending = None

    return spans


def functions_for_lines(source: Path, lines: set[int]) -> list[str]:
    """Names of functions whose body overlaps any of ``lines``."""
    if not lines or source.suffix.lower() not in _C_EXTENSIONS:
        return []
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    spans = find_functions(text)
    names: list[str] = []
    for span in spans:
        if any(span.contains(line) for line in lines) and span.name not in names:
            names.append(span.name)
    return names


def function_at_line(source: Path, line: int) -> str | None:
    """Name of the function containing ``line``, if it can be determined."""
    if source.suffix.lower() not in _C_EXTENSIONS:
        return None
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for span in find_functions(text):
        if span.contains(line):
            return span.name
    return None


# --------------------------------------------------------------------------
# Diff parsing
# --------------------------------------------------------------------------


def _strip_prefix(path: str, roots: list[Path]) -> str:
    """Normalise a diff path to a tree-relative form."""
    if path in ("/dev/null", ""):
        return ""
    cleaned = path
    for marker in ("a/", "b/"):
        if cleaned.startswith(marker):
            cleaned = cleaned[len(marker) :]
            break
    candidate = Path("/" + cleaned if not cleaned.startswith("/") else cleaned)
    for root in roots:
        try:
            return str(candidate.relative_to(root))
        except ValueError:
            continue
    return cleaned.lstrip("/")


def _parse_raw_status(raw: str, roots: list[Path]) -> dict[str, tuple[str, int | None]]:
    """Map path -> (status letter, similarity) from ``git diff --raw``."""
    statuses: dict[str, tuple[str, int | None]] = {}
    for line in raw.splitlines():
        match = _RAW_RE.match(line)
        if not match:
            continue
        status = match.group("status")
        score = match.group("score")
        similarity = int(score) if score else None
        paths = match.group("paths").split("\t")
        key = _strip_prefix(paths[-1], roots)
        statuses[key] = (status, similarity)
    return statuses


def parse_unified_diff(text: str, *, roots: list[Path] | None = None) -> list[FileDiff]:
    """Parse a unified diff into structured per-file entries."""
    roots = roots or []
    files: list[FileDiff] = []

    current: dict | None = None
    hunk: DiffHunk | None = None
    old_lineno = new_lineno = 0

    def flush() -> None:
        nonlocal current, hunk
        if current is None:
            return
        if hunk is not None:
            current["hunks"].append(hunk)
            hunk = None
        old_path = current["old_path"] or None
        new_path = current["new_path"] or None
        if current["is_new"]:
            kind = "added"
        elif current["is_deleted"]:
            kind = "removed"
        elif current["is_rename"]:
            kind = "renamed"
        else:
            kind = "modified"
        files.append(
            FileDiff(
                old_path=old_path,
                new_path=new_path,
                change_kind=kind,
                is_binary=current["is_binary"],
                similarity=current["similarity"],
                hunks=current["hunks"],
            )
        )
        current = None

    for line in text.splitlines():
        header = _DIFF_HEADER_RE.match(line)
        if header:
            flush()
            current = {
                "old_path": _strip_prefix(header.group("a"), roots),
                "new_path": _strip_prefix(header.group("b"), roots),
                "hunks": [],
                "is_binary": False,
                "is_new": False,
                "is_deleted": False,
                "is_rename": False,
                "similarity": None,
            }
            continue

        if current is None:
            continue

        if line.startswith("new file mode"):
            current["is_new"] = True
        elif line.startswith("deleted file mode"):
            current["is_deleted"] = True
        elif line.startswith("similarity index"):
            value = line.rsplit(" ", 1)[-1].rstrip("%")
            current["similarity"] = int(value) if value.isdigit() else None
        elif line.startswith(("rename from", "rename to")):
            current["is_rename"] = True
        elif line.startswith("Binary files") or line.startswith("GIT binary patch"):
            current["is_binary"] = True
        elif line.startswith("--- "):
            path = line[4:].strip()
            if path == "/dev/null":
                current["is_new"] = True
            else:
                current["old_path"] = _strip_prefix(path, roots)
        elif line.startswith("+++ "):
            path = line[4:].strip()
            if path == "/dev/null":
                current["is_deleted"] = True
            else:
                current["new_path"] = _strip_prefix(path, roots)
        else:
            match = _HUNK_RE.match(line)
            if match:
                if hunk is not None:
                    current["hunks"].append(hunk)
                old_lineno = int(match.group("old_start"))
                new_lineno = int(match.group("new_start"))
                hunk = DiffHunk(
                    old_start=old_lineno,
                    old_count=int(match.group("old_count") or 1),
                    new_start=new_lineno,
                    new_count=int(match.group("new_count") or 1),
                    section_heading=(match.group("heading") or "").strip() or None,
                )
                continue
            if hunk is None:
                continue
            if line.startswith("+"):
                hunk.lines.append(
                    DiffLine(kind="added", new_lineno=new_lineno, text=line[1:])
                )
                new_lineno += 1
            elif line.startswith("-"):
                hunk.lines.append(
                    DiffLine(kind="removed", old_lineno=old_lineno, text=line[1:])
                )
                old_lineno += 1
            elif line.startswith(" "):
                hunk.lines.append(
                    DiffLine(
                        kind="context",
                        old_lineno=old_lineno,
                        new_lineno=new_lineno,
                        text=line[1:],
                    )
                )
                old_lineno += 1
                new_lineno += 1
            elif line.startswith("\\"):
                continue  # "\ No newline at end of file"

    flush()
    return files


def _apply_raw_metadata(
    files: list[FileDiff], statuses: dict[str, tuple[str, int | None]]
) -> None:
    """Reconcile parsed entries with git's authoritative status letters."""
    mapping = {"A": "added", "D": "removed", "R": "renamed", "M": "modified", "C": "renamed"}
    for fd in files:
        key = fd.new_path or fd.old_path or ""
        entry = statuses.get(key)
        if entry is None:
            continue
        status, similarity = entry
        kind = mapping.get(status)
        if kind:
            fd.change_kind = kind  # type: ignore[assignment]
        if similarity is not None:
            fd.similarity = similarity


def _attribute_functions(files: list[FileDiff], base_dir: Path, patched_dir: Path) -> None:
    for fd in files:
        names: list[str] = []
        if fd.new_path:
            names += functions_for_lines(patched_dir / fd.new_path, fd.changed_new_linenos())
        if fd.old_path:
            for name in functions_for_lines(base_dir / fd.old_path, fd.changed_old_linenos()):
                if name not in names:
                    names.append(name)
        fd.changed_functions = names


def compute_diff(
    *,
    base_dir: Path,
    patched_dir: Path,
    repo: Path | None = None,
    base_commit: str | None = None,
    patched_commit: str | None = None,
) -> tuple[StructuredDiff, str]:
    """Produce the structured diff and the raw unified text.

    When both revisions come from one repository we diff the commits, which
    gives git full rename detection across the whole tree. Otherwise we fall
    back to a directory comparison.
    """
    roots = [base_dir.resolve(), patched_dir.resolve()]

    if repo and base_commit and patched_commit:
        raw_text = git.diff_commits(repo, base_commit, patched_commit)
        raw_status = git.run_git(
            ["diff", "--raw", "--find-renames", base_commit, patched_commit],
            cwd=repo,
            check=False,
        ).stdout_text
    else:
        raw_text = git.diff_trees(base_dir, patched_dir)
        raw_status = git.run_git(
            [
                "diff", "--no-index", "--raw", "--find-renames",
                str(base_dir), str(patched_dir),
            ],
            check=False,
        ).stdout_text

    files = parse_unified_diff(raw_text, roots=roots)
    _apply_raw_metadata(files, _parse_raw_status(raw_status, roots))
    _attribute_functions(files, base_dir, patched_dir)

    return StructuredDiff(files=files), raw_text


def check_external_patch(computed: str, supplied_path: Path) -> str | None:
    """Compare a user-supplied patch with the computed diff.

    Returns a warning string when they disagree. We never substitute the
    supplied patch for our own: the computed diff is what the two trees
    actually differ by, and that is what the correlation stage must reason
    about.
    """
    try:
        supplied = supplied_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"could not read supplied patch {supplied_path}: {exc}"

    def changed_lines(text: str) -> set[str]:
        return {
            line.rstrip()
            for line in text.splitlines()
            if (line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
        }

    supplied_changes = changed_lines(supplied)
    computed_changes = changed_lines(computed)
    if not supplied_changes:
        return f"supplied patch {supplied_path.name} contains no changed lines"
    missing = supplied_changes - computed_changes
    extra = computed_changes - supplied_changes
    if missing or extra:
        return (
            f"supplied patch {supplied_path.name} does not match the computed diff "
            f"({len(missing)} supplied line(s) absent, {len(extra)} computed line(s) "
            "not in the patch); the computed diff was used"
        )
    return None
