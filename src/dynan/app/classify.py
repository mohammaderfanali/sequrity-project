"""Turning raw execution observations into normalised findings.

The rules here encode two prohibitions the specification states explicitly:

* A non-zero exit code is **not** a vulnerability. A program that rejects bad
  input and exits 1 is working correctly, so no finding is produced.
* A SIGSEGV is **not** automatically a buffer overflow. Without a sanitizer
  report or another concrete signal, a crash is recorded as
  ``UNCLASSIFIED_CRASH`` with ``UNCONFIRMED`` confidence - enough to make the
  run inconclusive, never enough on its own to confirm exit code 10.

Source locations are only ever copied from real symbolised frames. When no
frame resolves into the project's tree, the finding carries no location.
"""

from __future__ import annotations

import signal as signal_module
from pathlib import Path

from ..domain.enums import (
    MEMORY_SAFETY_ERRORS,
    UNDEFINED_BEHAVIOR_ERRORS,
    Confidence,
    DetectionMechanism,
    ErrorType,
    ExecutionOutcome,
    Severity,
)
from ..domain.models import (
    ExecutionResult,
    Finding,
    FindingSignature,
    StackFrame,
    TestCaseSpec,
)
from ..infra import sanitizer

#: Signals that carry a specific, defensible meaning on their own.
_SIGNAL_CLASSIFICATION: dict[int, tuple[ErrorType, Confidence]] = {
    signal_module.SIGFPE: (ErrorType.DIVISION_BY_ZERO, Confidence.CONFIRMED),
    signal_module.SIGSEGV: (ErrorType.UNCLASSIFIED_CRASH, Confidence.UNCONFIRMED),
    signal_module.SIGBUS: (ErrorType.UNCLASSIFIED_CRASH, Confidence.UNCONFIRMED),
    signal_module.SIGILL: (ErrorType.UNCLASSIFIED_CRASH, Confidence.UNCONFIRMED),
    signal_module.SIGABRT: (ErrorType.ABORT, Confidence.PROBABLE),
    signal_module.SIGSYS: (ErrorType.UNCLASSIFIED_CRASH, Confidence.UNCONFIRMED),
}


def severity_for(error_type: ErrorType) -> Severity:
    if error_type in MEMORY_SAFETY_ERRORS:
        return Severity.MEMORY_SAFETY
    if error_type in UNDEFINED_BEHAVIOR_ERRORS:
        return Severity.UNDEFINED_BEHAVIOR
    if error_type in (ErrorType.TIMEOUT, ErrorType.RESOURCE_EXHAUSTION, ErrorType.MEMORY_LEAK):
        return Severity.RESOURCE
    if error_type in (
        ErrorType.UNCLASSIFIED_CRASH,
        ErrorType.ABORT,
        ErrorType.ASSERTION_FAILURE,
        ErrorType.STACK_OVERFLOW,
    ):
        return Severity.CRASH
    return Severity.BENIGN


def _confidence_for_report(report: sanitizer.SanitizerReport) -> Confidence:
    """How strongly a parsed report supports a claim.

    Sanitizer and binary-guard diagnostics name the defect precisely, so they
    are confirmed. An unclassified crash reported *through* a sanitizer is
    still unclassified.
    """
    if report.error_type == ErrorType.UNCLASSIFIED_CRASH:
        return Confidence.UNCONFIRMED
    if report.detection in (
        DetectionMechanism.ASAN,
        DetectionMechanism.UBSAN,
        DetectionMechanism.LSAN,
        DetectionMechanism.STACK_PROTECTOR,
        DetectionMechanism.GLIBC_HARDENING,
    ):
        return Confidence.CONFIRMED
    return Confidence.PROBABLE


def _signature(
    error_type: ErrorType,
    detection: DetectionMechanism,
    frame: StackFrame | None,
) -> FindingSignature:
    return FindingSignature(
        error_type=error_type,
        detection=detection,
        function=frame.function if frame else None,
        file=frame.file if frame else None,
        line=frame.line if frame else None,
    )


def make_finding_id(execution_id: str, digest: str) -> str:
    return f"{execution_id}#{digest}"


def classify_execution(
    execution: ExecutionResult,
    test: TestCaseSpec,
    *,
    source_roots: list[Path] | None = None,
) -> tuple[Finding | None, sanitizer.SanitizerReport | None]:
    """Decide whether an execution represents a failure worth recording.

    Returns the finding (or ``None`` when the execution was a normal, even if
    unsuccessful, program run) together with the parsed report so the caller
    can persist the raw evidence.
    """
    roots = source_roots or []
    combined_output = execution.stderr + ("\n" + execution.stdout if execution.stdout else "")
    report = sanitizer.parse_output(combined_output)

    # -- 1. A parsed diagnostic is the strongest evidence available ------
    if report is not None:
        frame = sanitizer.select_project_frame(report.frames, roots)
        sig = _signature(report.error_type, report.detection, frame)
        return (
            Finding(
                finding_id=make_finding_id(execution.execution_id, sig.digest),
                signature=sig,
                severity=severity_for(report.error_type),
                confidence=_confidence_for_report(report),
                version=execution.version,
                profile=execution.profile,
                test_id=test.test_id,
                execution_id=execution.execution_id,
                message=report.message,
                frames=report.frames,
                exit_code=execution.exit_code,
                signal=execution.signal,
                signal_name=execution.signal_name,
                details=dict(report.details),
            ),
            report,
        )

    # -- 2. Resource outcomes -------------------------------------------
    # The PDF is explicit that exceeding a time or resource limit must be
    # reported, and equally explicit that it is not automatically a
    # vulnerability. Both halves are honoured: we record it, with RESOURCE
    # severity that the decision engine never promotes to exit code 10.
    if execution.outcome == ExecutionOutcome.TIMEOUT:
        sig = _signature(ErrorType.TIMEOUT, DetectionMechanism.TIMEOUT, None)
        return (
            Finding(
                finding_id=make_finding_id(execution.execution_id, sig.digest),
                signature=sig,
                severity=Severity.RESOURCE,
                confidence=Confidence.CONFIRMED,
                version=execution.version,
                profile=execution.profile,
                test_id=test.test_id,
                execution_id=execution.execution_id,
                message=f"execution exceeded its {execution.timeout_s}s timeout",
                exit_code=execution.exit_code,
                signal=execution.signal,
                signal_name=execution.signal_name,
                details={"timeout_s": execution.timeout_s},
            ),
            None,
        )

    if execution.outcome == ExecutionOutcome.RESOURCE_LIMIT:
        sig = _signature(
            ErrorType.RESOURCE_EXHAUSTION, DetectionMechanism.RESOURCE_LIMIT, None
        )
        return (
            Finding(
                finding_id=make_finding_id(execution.execution_id, sig.digest),
                signature=sig,
                severity=Severity.RESOURCE,
                confidence=Confidence.CONFIRMED,
                version=execution.version,
                profile=execution.profile,
                test_id=test.test_id,
                execution_id=execution.execution_id,
                message=(
                    f"execution hit a resource limit "
                    f"(signal {execution.signal_name})"
                ),
                exit_code=execution.exit_code,
                signal=execution.signal,
                signal_name=execution.signal_name,
            ),
            None,
        )

    # -- 3. A signal with no diagnostic text ----------------------------
    if execution.signal is not None:
        error_type, confidence = _SIGNAL_CLASSIFICATION.get(
            execution.signal, (ErrorType.UNCLASSIFIED_CRASH, Confidence.UNCONFIRMED)
        )
        sig = _signature(error_type, DetectionMechanism.OS_SIGNAL, None)
        return (
            Finding(
                finding_id=make_finding_id(execution.execution_id, sig.digest),
                signature=sig,
                severity=severity_for(error_type),
                confidence=confidence,
                version=execution.version,
                profile=execution.profile,
                test_id=test.test_id,
                execution_id=execution.execution_id,
                message=(
                    f"terminated by {execution.signal_name} with no sanitizer or "
                    "runtime diagnostic; the symptom alone does not identify the defect"
                ),
                exit_code=execution.exit_code,
                signal=execution.signal,
                signal_name=execution.signal_name,
                details={"signal": execution.signal},
            ),
            None,
        )

    # -- 4. Failure to even start is an infrastructure problem ----------
    if execution.outcome == ExecutionOutcome.SPAWN_ERROR:
        sig = _signature(
            ErrorType.UNCLASSIFIED_CRASH, DetectionMechanism.EXIT_STATUS, None
        )
        return (
            Finding(
                finding_id=make_finding_id(execution.execution_id, sig.digest),
                signature=sig,
                severity=Severity.CRASH,
                confidence=Confidence.UNCONFIRMED,
                version=execution.version,
                profile=execution.profile,
                test_id=test.test_id,
                execution_id=execution.execution_id,
                message=f"could not start the target: {execution.spawn_error}",
                exit_code=None,
            ),
            None,
        )

    # -- 5. Clean termination, whatever the exit code -------------------
    # Deliberately no finding. Rejecting malformed input with a non-zero exit
    # status is correct behaviour, and treating it as a security event is the
    # classic false positive the PDF warns against.
    return None, None
