"""Patch-to-finding correlation.

This is the core requirement of the project (PDF section 3.1), and the
specification constrains it tightly:

* The failure location need **not** be on a changed line. A changed
  length-check in a caller can cause a failure in a callee, so caller frames
  are examined, not just the innermost one.
* Superficial adjacency is **not** proof. A frame merely sitting in a file the
  patch touched is weak evidence and never reaches a confident verdict alone.
* When the evidence is insufficient the relationship must be reported as
  **unknown**, not guessed.

So correlation is built from named, individually inspectable signals, each
carrying the file/line/function it came from. The verdict is a function of
those signals, and the rationale states which ones drove it. A reviewer can
disagree with the conclusion while still seeing exactly what it rested on.

Correlation expresses a *relationship to the patch*, not a proven root cause;
nothing in this module claims causation.
"""

from __future__ import annotations

from pathlib import Path

from ..domain.enums import (
    Confidence,
    CorrelationEvidenceKind,
    CorrelationVerdict,
    FindingStatus,
    Version,
)
from ..domain.models import (
    CorrelationEvidence,
    Finding,
    FindingComparison,
    FindingCorrelation,
    StackFrame,
    StructuredDiff,
)

# Signal weights. Tuned so that no single weak signal can reach the
# "conclusive" threshold on its own, which is what keeps adjacency from
# masquerading as proof.
_W_CHANGED_LINE = 3.0
_W_CHANGED_FUNCTION = 2.5
_W_CALLER_CHANGED = 2.0
_W_CHANGED_FILE = 0.75
_W_DIFFERENTIAL = 1.5
_W_PERSISTED = 0.5
_W_NO_OVERLAP = -2.5

#: Score at or above which a direct-location verdict is reported as confirmed.
_CONCLUSIVE_SCORE = 4.0
#: Score needed for an indirect (caller-mediated) relationship.
_INDIRECT_SCORE = 2.0


def _relative_path(file: str, roots: list[Path]) -> str | None:
    """Map a frame's file onto a tree-relative path.

    A relative frame path is already tree-relative - it just has to be
    confirmed against one of the prepared trees before we trust it, so that a
    coincidental name from outside the project is not matched to the diff.
    """
    if not file:
        return None
    candidate = Path(file)

    if not candidate.is_absolute():
        if candidate.parts and candidate.parts[0] == "..":
            return None
        return str(candidate) if any((r / candidate).exists() for r in roots) else None

    for root in roots:
        try:
            return str(candidate.resolve().relative_to(root.resolve()))
        except (ValueError, OSError):
            continue
    return None


def _project_frames(
    frames: list[StackFrame], roots: list[Path]
) -> list[tuple[StackFrame, str]]:
    """Frames that resolve into the project tree, innermost first."""
    resolved: list[tuple[StackFrame, str]] = []
    for frame in frames:
        if not frame.file or frame.line is None:
            continue
        rel = _relative_path(frame.file, roots)
        if rel:
            resolved.append((frame, rel))
    return resolved


def correlate_finding(
    finding: Finding,
    diff: StructuredDiff,
    *,
    source_roots: list[Path],
    status: FindingStatus | None = None,
) -> FindingCorrelation:
    """Relate one finding to the patch, with explicit evidence."""
    evidence: list[CorrelationEvidence] = []
    diff_locations: list[str] = []

    frames = _project_frames(finding.frames, source_roots)
    changed_lines_attr = (
        "changed_old_linenos" if finding.version == Version.BASE else "changed_new_linenos"
    )

    has_direct_location = False
    has_caller_signal = False
    touched_changed_file = False

    for position, (frame, rel_path) in enumerate(frames):
        file_diff = diff.find_file(rel_path)
        if file_diff is None:
            continue

        touched_changed_file = True
        innermost = position == 0
        changed_lines: set[int] = getattr(file_diff, changed_lines_attr)()
        line = frame.line or -1

        if line in changed_lines:
            evidence.append(
                CorrelationEvidence(
                    kind=CorrelationEvidenceKind.FRAME_ON_CHANGED_LINE,
                    description=(
                        f"stack frame #{frame.index} executes {rel_path}:{line}, "
                        "a line the patch changed"
                    ),
                    file=rel_path,
                    line=line,
                    function=frame.function,
                    weight=_W_CHANGED_LINE if innermost else _W_CALLER_CHANGED,
                )
            )
            diff_locations.append(f"{rel_path}:{line}")
            if innermost:
                has_direct_location = True
            else:
                has_caller_signal = True

        elif frame.function and frame.function in file_diff.changed_functions:
            evidence.append(
                CorrelationEvidence(
                    kind=(
                        CorrelationEvidenceKind.FRAME_IN_CHANGED_FUNCTION
                        if innermost
                        else CorrelationEvidenceKind.CALLER_CHANGED
                    ),
                    description=(
                        f"stack frame #{frame.index} is inside {frame.function}() in "
                        f"{rel_path}, whose body the patch modified"
                        + ("" if innermost else "; it calls toward the failing frame")
                    ),
                    file=rel_path,
                    line=line if line > 0 else None,
                    function=frame.function,
                    weight=_W_CHANGED_FUNCTION if innermost else _W_CALLER_CHANGED,
                )
            )
            diff_locations.append(f"{rel_path}:{line}" if line > 0 else rel_path)
            if innermost:
                has_direct_location = True
            else:
                has_caller_signal = True

        else:
            evidence.append(
                CorrelationEvidence(
                    kind=CorrelationEvidenceKind.FRAME_IN_CHANGED_FILE,
                    description=(
                        f"stack frame #{frame.index} is in {rel_path}, a file the patch "
                        "touched, but not in a changed function or line"
                    ),
                    file=rel_path,
                    line=line if line > 0 else None,
                    function=frame.function,
                    weight=_W_CHANGED_FILE,
                )
            )

    # -- differential evidence ------------------------------------------
    if status == FindingStatus.NEW_ISSUE:
        evidence.append(
            CorrelationEvidence(
                kind=CorrelationEvidenceKind.SIGNATURE_APPEARED,
                description=(
                    "this signature was not observed on the base version under the "
                    "same tests and build profile, and appears after the patch"
                ),
                weight=_W_DIFFERENTIAL,
            )
        )
    elif status == FindingStatus.FIXED:
        evidence.append(
            CorrelationEvidence(
                kind=CorrelationEvidenceKind.SIGNATURE_DISAPPEARED,
                description=(
                    "this signature was observed on the base version and is no longer "
                    "observable after the patch under the same tests"
                ),
                weight=_W_DIFFERENTIAL,
            )
        )
    elif status == FindingStatus.INCOMPLETE_FIX:
        evidence.append(
            CorrelationEvidence(
                kind=CorrelationEvidenceKind.DIFFERENTIAL_BEHAVIOUR,
                description=(
                    "the signature is present both before and after the patch, so the "
                    "patch did not remove this failure path"
                ),
                weight=_W_PERSISTED,
            )
        )

    # -- negative evidence ----------------------------------------------
    if not frames:
        evidence.append(
            CorrelationEvidence(
                kind=CorrelationEvidenceKind.NO_STACK_TRACE,
                description=(
                    "no stack frame resolved to project source, so the failure cannot "
                    "be located relative to the patch"
                ),
                weight=0.0,
            )
        )
    elif not touched_changed_file:
        evidence.append(
            CorrelationEvidence(
                kind=CorrelationEvidenceKind.NO_OVERLAP,
                description=(
                    "every resolved frame lies in a file the patch did not touch "
                    f"({', '.join(sorted({rel for _f, rel in frames}))})"
                ),
                weight=_W_NO_OVERLAP,
            )
        )

    score = sum(item.weight for item in evidence)
    verdict, confidence, rationale = _decide(
        score=score,
        has_frames=bool(frames),
        has_direct_location=has_direct_location,
        has_caller_signal=has_caller_signal,
        touched_changed_file=touched_changed_file,
        status=status,
    )

    return FindingCorrelation(
        finding_id=finding.finding_id,
        verdict=verdict,
        confidence=confidence,
        evidence=evidence,
        rationale=rationale,
        related_diff_locations=sorted(set(diff_locations)),
    )


def _decide(
    *,
    score: float,
    has_frames: bool,
    has_direct_location: bool,
    has_caller_signal: bool,
    touched_changed_file: bool,
    status: FindingStatus | None,
) -> tuple[CorrelationVerdict, Confidence, str]:
    """Map accumulated evidence onto a verdict.

    Ordered from strongest to weakest claim. Anything that does not clear a
    threshold falls through to UNKNOWN, which is the specification's required
    behaviour for insufficient evidence.
    """
    if not has_frames:
        if status in (FindingStatus.NEW_ISSUE, FindingStatus.FIXED):
            return (
                CorrelationVerdict.UNKNOWN,
                Confidence.UNCONFIRMED,
                "The failure's differential behaviour changed with the patch, but no "
                "stack frame resolved to project source, so no location-based link "
                "to the diff can be established.",
            )
        return (
            CorrelationVerdict.UNKNOWN,
            Confidence.UNCONFIRMED,
            "No stack frame resolved to project source; the relationship to the "
            "patch cannot be determined.",
        )

    if has_direct_location and score >= _CONCLUSIVE_SCORE:
        return (
            CorrelationVerdict.DIRECT,
            Confidence.CONFIRMED,
            "The failing frame itself is inside code the patch changed, and the "
            "differential behaviour between the two versions agrees with that.",
        )

    if has_direct_location:
        return (
            CorrelationVerdict.DIRECT,
            Confidence.PROBABLE,
            "The failing frame is inside code the patch changed, but the supporting "
            "differential evidence is limited.",
        )

    if has_caller_signal and score >= _INDIRECT_SCORE:
        return (
            CorrelationVerdict.INDIRECT,
            Confidence.PROBABLE,
            "The failure is not located in changed code, but a caller on the same "
            "stack was modified, so the patch plausibly influences the path that "
            "reaches it. This is a relationship, not a demonstrated root cause.",
        )

    if not touched_changed_file and score <= 0:
        return (
            CorrelationVerdict.UNRELATED,
            Confidence.PROBABLE,
            "Every resolved frame lies outside the files the patch touched, and no "
            "differential evidence connects the failure to the change.",
        )

    return (
        CorrelationVerdict.UNKNOWN,
        Confidence.UNCONFIRMED,
        "The available signals are too weak to assert or exclude a relationship: "
        "frames overlap the patch only at file granularity, which the specification "
        "treats as insufficient evidence.",
    )


def correlate_all(
    findings: list[Finding],
    comparisons: list[FindingComparison],
    diff: StructuredDiff,
    *,
    source_roots: list[Path],
) -> list[FindingCorrelation]:
    """Correlate every finding, using its differential status as extra evidence."""
    status_by_finding: dict[str, FindingStatus] = {}
    for comparison in comparisons:
        for finding_id in comparison.base_finding_ids + comparison.patched_finding_ids:
            status_by_finding[finding_id] = comparison.status

    return [
        correlate_finding(
            finding,
            diff,
            source_roots=source_roots,
            status=status_by_finding.get(finding.finding_id),
        )
        for finding in findings
    ]


def attach_correlations(
    comparisons: list[FindingComparison], correlations: list[FindingCorrelation]
) -> None:
    """Give each comparison the correlation of its most relevant finding.

    The patched side is preferred: when judging whether a patch introduced or
    failed to fix something, the post-patch evidence is what matters.
    """
    by_id = {c.finding_id: c for c in correlations}
    for comparison in comparisons:
        for finding_id in comparison.patched_finding_ids + comparison.base_finding_ids:
            correlation = by_id.get(finding_id)
            if correlation is not None:
                comparison.correlation = correlation
                break
