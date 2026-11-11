"""The failure-preservation predicate.

Minimisation and replay both need one shared answer to "is this still the same
failure?". The PDF states the criterion explicitly: a non-zero exit code is
**not** sufficient; the minimised input must still produce the same error type
at the related location.

Keeping that decision in one place means the reproducer and the minimiser
cannot drift apart - a minimised input that the minimiser accepted will always
be one the reproducer also recognises.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..domain.models import ExecutionResult, FindingSignature, TestCaseSpec
from . import classify


@dataclass(slots=True)
class SignatureObservation:
    """What an execution produced, reduced to a comparable signature."""

    signature: FindingSignature | None
    matched: bool
    detail: str


def observe(
    execution: ExecutionResult,
    test: TestCaseSpec,
    target: FindingSignature,
    *,
    source_roots: list[Path],
) -> SignatureObservation:
    """Classify an execution and compare it against the target signature."""
    finding, _report = classify.classify_execution(
        execution, test, source_roots=source_roots
    )
    if finding is None:
        return SignatureObservation(
            signature=None,
            matched=False,
            detail=(
                f"no failure observed (exit={execution.exit_code}, "
                f"signal={execution.signal_name})"
            ),
        )

    observed = finding.signature
    if observed.matches(target):
        return SignatureObservation(
            signature=observed, matched=True, detail=observed.describe()
        )

    return SignatureObservation(
        signature=observed,
        matched=False,
        detail=(
            f"different failure: observed {observed.describe()}, "
            f"expected {target.describe()}"
        ),
    )


def preserves_signature(
    execution: ExecutionResult,
    test: TestCaseSpec,
    target: FindingSignature,
    *,
    source_roots: list[Path],
) -> bool:
    """Whether an execution still exhibits the target failure."""
    return observe(execution, test, target, source_roots=source_roots).matched
