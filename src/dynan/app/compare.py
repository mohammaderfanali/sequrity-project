"""Differential security comparison between the base and patched versions.

Findings are grouped by signature *within a build profile*. Comparing a
release base against a sanitized patched build would be comparing two
different programs, which the PDF forbids, so the profile is part of the
grouping key.

The four classes the specification names map onto presence in the two
versions:

====================  ========================================
base / patched        status
====================  ========================================
present / absent      FIXED
present / present     INCOMPLETE_FIX  (the error remains)
absent  / present     NEW_ISSUE
====================  ========================================

Signature equality deliberately ignores line numbers: a patch shifts lines, and
requiring exact line equality would report every surviving defect as brand new.
"""

from __future__ import annotations

from collections import defaultdict

from ..domain.enums import (
    BuildProfile,
    Confidence,
    FindingStatus,
    Severity,
    Version,
)
from ..domain.models import Finding, FindingComparison, FindingSignature

#: Severities that make a differential claim about security at all. Resource
#: outcomes (timeouts) and benign exits are tracked but never classified as a
#: fix or a regression.
_SECURITY_SEVERITIES = (Severity.MEMORY_SAFETY, Severity.UNDEFINED_BEHAVIOR)

_CONFIDENCE_RANK = {
    Confidence.CONFIRMED: 3,
    Confidence.PROBABLE: 2,
    Confidence.UNCONFIRMED: 1,
}


def _strongest(findings: list[Finding]) -> Confidence:
    if not findings:
        return Confidence.UNCONFIRMED
    return max((f.confidence for f in findings), key=lambda c: _CONFIDENCE_RANK[c])


def _dominant_severity(findings: list[Finding]) -> Severity:
    for severity in (
        Severity.MEMORY_SAFETY,
        Severity.UNDEFINED_BEHAVIOR,
        Severity.CRASH,
        Severity.RESOURCE,
        Severity.BENIGN,
    ):
        if any(f.severity == severity for f in findings):
            return severity
    return Severity.BENIGN


def _status_for(
    base: list[Finding], patched: list[Finding], severity: Severity
) -> tuple[FindingStatus, str]:
    """Pick the differential class and explain it."""
    if severity not in _SECURITY_SEVERITIES:
        # Unclassified crashes cannot support a fix/remain claim either way;
        # the PDF routes them to the inconclusive bucket explicitly.
        if severity == Severity.CRASH:
            if patched:
                return (
                    FindingStatus.INCONCLUSIVE,
                    "abnormal termination without a classifying diagnostic; "
                    "insufficient evidence to confirm or exclude a vulnerability",
                )
            return (
                FindingStatus.INCONCLUSIVE,
                "unclassified termination observed on the base version only",
            )
        return (
            FindingStatus.UNCHANGED,
            "resource or benign outcome; not a security classification",
        )

    if base and not patched:
        return (
            FindingStatus.FIXED,
            "observed on the base version and no longer observable on the patched "
            "version within this test scope",
        )
    if base and patched:
        return (
            FindingStatus.INCOMPLETE_FIX,
            "the same error signature is still reachable after the patch",
        )
    return (
        FindingStatus.NEW_ISSUE,
        "not observed on the base version but present after the patch",
    )


def compare_findings(findings: list[Finding]) -> list[FindingComparison]:
    """Build the differential view over every observed signature."""
    grouped: dict[tuple[tuple[str, ...], BuildProfile], list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.signature.key(), finding.profile)].append(finding)

    comparisons: list[FindingComparison] = []
    for (_key, profile), group in grouped.items():
        base = [f for f in group if f.version == Version.BASE]
        patched = [f for f in group if f.version == Version.PATCHED]
        severity = _dominant_severity(group)
        status, rationale = _status_for(base, patched, severity)

        # Confidence follows whichever side the claim rests on: a remaining or
        # new issue is only as strong as the evidence from the patched run.
        relevant = patched if status != FindingStatus.FIXED else base
        confidence = _strongest(relevant or group)

        signature: FindingSignature = (relevant or group)[0].signature
        test_ids: list[str] = []
        for finding in group:
            if finding.test_id not in test_ids:
                test_ids.append(finding.test_id)

        comparisons.append(
            FindingComparison(
                signature=signature,
                status=status,
                base_finding_ids=[f.finding_id for f in base],
                patched_finding_ids=[f.finding_id for f in patched],
                test_ids=test_ids,
                profile=profile,
                confidence=confidence,
                rationale=rationale,
            )
        )

    order = {
        FindingStatus.INCOMPLETE_FIX: 0,
        FindingStatus.NEW_ISSUE: 1,
        FindingStatus.INCONCLUSIVE: 2,
        FindingStatus.FIXED: 3,
        FindingStatus.UNCHANGED: 4,
        FindingStatus.FUNCTIONAL_REGRESSION: 5,
    }
    comparisons.sort(
        key=lambda c: (order.get(c.status, 9), c.profile.value, c.signature.digest)
    )
    return comparisons


def baseline_signatures(comparisons: list[FindingComparison]) -> list[FindingComparison]:
    """Comparisons whose signature was actually reproduced on the base version.

    These are the ones the patch is being judged against. Without at least one,
    the run cannot show the patch fixed anything.
    """
    return [c for c in comparisons if c.is_targeted_baseline]
