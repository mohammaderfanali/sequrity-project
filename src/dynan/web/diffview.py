"""Turning a structured diff into side-by-side rows for display.

Pure presentation, computed on the server from the canonical
:class:`~dynan.domain.models.StructuredDiff` so the browser receives rows
rather than reimplementing diff alignment in JavaScript.

Alignment rule: consecutive removed and added lines inside a hunk are paired
positionally, which is what makes a modified line read as one row with the old
text on the left and the new text on the right. Unequal runs are padded.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.models import DiffHunk, FileDiff


@dataclass(slots=True)
class SideBySideRow:
    left_lineno: int | None
    left_text: str | None
    right_lineno: int | None
    right_text: str | None
    #: "context", "change", "add" or "del" - drives row styling.
    kind: str

    @property
    def left_class(self) -> str:
        if self.left_text is None:
            return "empty"
        return "del" if self.kind in ("change", "del") else "ctx"

    @property
    def right_class(self) -> str:
        if self.right_text is None:
            return "empty"
        return "add" if self.kind in ("change", "add") else "ctx"


@dataclass(slots=True)
class SideBySideHunk:
    header: str
    section: str | None
    rows: list[SideBySideRow]


def _flush(removed: list, added: list, rows: list[SideBySideRow]) -> None:
    """Pair a run of removed lines with a run of added lines."""
    for index in range(max(len(removed), len(added))):
        left = removed[index] if index < len(removed) else None
        right = added[index] if index < len(added) else None
        if left is not None and right is not None:
            kind = "change"
        elif left is not None:
            kind = "del"
        else:
            kind = "add"
        rows.append(
            SideBySideRow(
                left_lineno=left.old_lineno if left else None,
                left_text=left.text if left else None,
                right_lineno=right.new_lineno if right else None,
                right_text=right.text if right else None,
                kind=kind,
            )
        )
    removed.clear()
    added.clear()


def hunk_to_rows(hunk: DiffHunk) -> SideBySideHunk:
    rows: list[SideBySideRow] = []
    removed: list = []
    added: list = []

    for line in hunk.lines:
        if line.kind == "removed":
            removed.append(line)
        elif line.kind == "added":
            added.append(line)
        else:
            _flush(removed, added, rows)
            rows.append(
                SideBySideRow(
                    left_lineno=line.old_lineno,
                    left_text=line.text,
                    right_lineno=line.new_lineno,
                    right_text=line.text,
                    kind="context",
                )
            )
    _flush(removed, added, rows)

    header = (
        f"@@ -{hunk.old_start},{hunk.old_count} "
        f"+{hunk.new_start},{hunk.new_count} @@"
    )
    return SideBySideHunk(header=header, section=hunk.section_heading, rows=rows)


def file_to_hunks(file_diff: FileDiff) -> list[SideBySideHunk]:
    return [hunk_to_rows(hunk) for hunk in file_diff.hunks]
