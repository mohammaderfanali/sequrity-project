"""Classification, sanitizer parsing, comparison, correlation and the oracle."""

from __future__ import annotations

from pathlib import Path

import pytest

from dynan.app import classify, compare, correlate, oracle
from dynan.config.testsuite import has_independent_oracle
from dynan.domain.enums import (
    BuildProfile,
    Confidence,
    CorrelationVerdict,
    DetectionMechanism,
    ErrorType,
    ExecutionOutcome,
    FindingStatus,
    InputDelivery,
    Severity,
    TestCategory,
    TestOutcome,
    Version,
)
from dynan.domain.models import (
    DiffHunk,
    DiffLine,
    ExecutionResult,
    FileDiff,
    Finding,
    FindingSignature,
    OracleCheck,
    OracleExpectation,
    StackFrame,
    StructuredDiff,
    TestCaseSpec,
)
from dynan.infra import sanitizer

# Captured verbatim from GCC 13 libasan / libubsan.
ASAN_STACK_OVERFLOW = """\
=================================================================
==14103==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7bde at pc 0x7bde
WRITE of size 25 at 0x7bdee7b00028 thread T0
    #0 0x7bdeeaca7922 in strcpy ../../../../src/libsanitizer/asan/asan_interceptors.cpp:563
    #1 0x58804740e27f in strcpy /usr/include/x86_64-linux-gnu/bits/string_fortified.h:79
    #2 0x58804740e27f in copy_in /src/sb.c:3
    #3 0x58804740e328 in main /src/sb.c:4
    #4 0x7bdeea02a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58

SUMMARY: AddressSanitizer: stack-buffer-overflow ../../../../src/libsanitizer/asan/asan_interceptors.cpp:563 in strcpy
"""

UBSAN_OVERFLOW = """\
ub.c:2:31: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x5a5e0b7962fc in add /src/ub.c:2
    #1 0x5a5e0b7962fc in main /src/ub.c:3
"""

GLIBC_CANARY = "*** stack smashing detected ***: terminated\n"


# ------------------------------------------------------------ parsing


def test_asan_report_is_parsed():
    report = sanitizer.parse_output(ASAN_STACK_OVERFLOW)
    assert report is not None
    assert report.error_type is ErrorType.STACK_BUFFER_OVERFLOW
    assert report.detection is DetectionMechanism.ASAN
    assert report.details["access_operation"] == "WRITE"
    assert report.details["access_size"] == 25


def test_project_frame_skips_sanitizer_and_libc_internals(tmp_path: Path):
    """The innermost frame is libsanitizer's interceptor, not the defect site."""
    root = tmp_path
    (root / "src").mkdir()
    (root / "src" / "sb.c").write_text("x")

    report = sanitizer.parse_output(ASAN_STACK_OVERFLOW.replace("/src/", f"{root}/src/"))
    frame = sanitizer.select_project_frame(report.frames, [root])
    assert frame is not None
    assert frame.function == "copy_in"
    assert frame.line == 3


def test_relative_frame_paths_resolve_against_the_prepared_tree(tmp_path: Path):
    """A Makefile compiling 'src/x.c' yields relative paths in debug info."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "confparse.c").write_text("x")

    frames = [StackFrame(index=0, function="store_value", file="src/confparse.c", line=70)]
    assert sanitizer.select_project_frame(frames, [tmp_path]) is frames[0]
    # A file that is not in the tree must not be claimed as project source.
    other = [StackFrame(index=0, function="f", file="src/elsewhere.c", line=1)]
    assert sanitizer.select_project_frame(other, [tmp_path]) is None


def test_ubsan_and_glibc_reports_are_parsed():
    ub = sanitizer.parse_output(UBSAN_OVERFLOW)
    assert ub.error_type is ErrorType.SIGNED_INTEGER_OVERFLOW
    assert ub.detection is DetectionMechanism.UBSAN

    canary = sanitizer.parse_output(GLIBC_CANARY)
    assert canary.error_type is ErrorType.STACK_SMASHING_DETECTED
    assert canary.detection is DetectionMechanism.STACK_PROTECTOR


def test_ubsan_object_size_is_a_buffer_overflow_not_generic_ub():
    text = (
        "src/confparse.c:67:16: runtime error: store to address 0x70 with "
        "insufficient space for an object of type 'char'\n"
    )
    report = sanitizer.parse_output(text)
    assert report.error_type is ErrorType.BUFFER_OVERFLOW
    assert classify.severity_for(report.error_type) is Severity.MEMORY_SAFETY


# ----------------------------------------------------- classification


def _execution(**kwargs) -> ExecutionResult:
    defaults = dict(
        execution_id="e", test_id="t", version=Version.PATCHED,
        profile=BuildProfile.RELEASE, argv=["/bin/x"], cwd="/tmp",
        delivery=InputDelivery.STDIN,
    )
    defaults.update(kwargs)
    return ExecutionResult(**defaults)


def _spec(**kwargs) -> TestCaseSpec:
    defaults = dict(test_id="t", category=TestCategory.VALID)
    defaults.update(kwargs)
    return TestCaseSpec(**defaults)


def test_nonzero_exit_is_not_a_finding():
    """Rejecting bad input with a non-zero status is correct behaviour."""
    finding, _ = classify.classify_execution(_execution(exit_code=2), _spec())
    assert finding is None


def test_segv_is_unclassified_not_a_buffer_overflow():
    """The PDF forbids reading a buffer overflow out of a bare SIGSEGV."""
    finding, _ = classify.classify_execution(
        _execution(exit_code=None, signal=11, signal_name="SIGSEGV",
                   outcome=ExecutionOutcome.SIGNALED),
        _spec(),
    )
    assert finding is not None
    assert finding.signature.error_type is ErrorType.UNCLASSIFIED_CRASH
    assert finding.confidence is Confidence.UNCONFIRMED
    assert finding.severity is Severity.CRASH
    # No location may be invented when nothing resolved.
    assert finding.signature.function is None


def test_timeout_is_recorded_but_is_resource_severity():
    finding, _ = classify.classify_execution(
        _execution(outcome=ExecutionOutcome.TIMEOUT, timeout_s=5.0), _spec()
    )
    assert finding.signature.error_type is ErrorType.TIMEOUT
    assert finding.severity is Severity.RESOURCE


def test_sanitizer_output_yields_a_confirmed_memory_finding(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sb.c").write_text("x")
    execution = _execution(
        exit_code=1, stderr=ASAN_STACK_OVERFLOW.replace("/src/", f"{tmp_path}/src/")
    )
    finding, report = classify.classify_execution(
        execution, _spec(), source_roots=[tmp_path]
    )
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.severity is Severity.MEMORY_SAFETY
    assert finding.signature.function == "copy_in"
    assert report is not None


# -------------------------------------------------------- comparison


def _finding(version: Version, function: str = "store_value", **kwargs) -> Finding:
    sig = FindingSignature(
        error_type=ErrorType.STACK_BUFFER_OVERFLOW,
        detection=DetectionMechanism.ASAN,
        function=function, file="src/confparse.c", line=kwargs.pop("line", 70),
    )
    return Finding(
        finding_id=f"{version.value}.{function}.{sig.digest}", signature=sig,
        severity=Severity.MEMORY_SAFETY, confidence=Confidence.CONFIRMED,
        version=version, profile=BuildProfile.SANITIZED,
        test_id=kwargs.pop("test_id", "t1"), execution_id="e", **kwargs,
    )


def test_comparison_classifies_fixed_remaining_and_new():
    fixed = compare.compare_findings([_finding(Version.BASE)])
    assert fixed[0].status is FindingStatus.FIXED

    both = compare.compare_findings([_finding(Version.BASE), _finding(Version.PATCHED)])
    assert both[0].status is FindingStatus.INCOMPLETE_FIX

    new = compare.compare_findings([_finding(Version.PATCHED)])
    assert new[0].status is FindingStatus.NEW_ISSUE


def test_signature_ignores_line_shifts_but_not_function():
    """A patch moves lines; that must not make a surviving defect look new."""
    base = _finding(Version.BASE, line=70)
    patched = _finding(Version.PATCHED, line=84)
    assert compare.compare_findings([base, patched])[0].status is FindingStatus.INCOMPLETE_FIX

    elsewhere = _finding(Version.PATCHED, function="other_sink")
    statuses = {c.status for c in compare.compare_findings([base, elsewhere])}
    assert statuses == {FindingStatus.FIXED, FindingStatus.NEW_ISSUE}


def test_profiles_are_compared_separately():
    """Release and sanitized observations must never be mixed."""
    base = _finding(Version.BASE)
    patched = _finding(Version.PATCHED)
    patched.profile = BuildProfile.RELEASE
    statuses = {c.status for c in compare.compare_findings([base, patched])}
    assert statuses == {FindingStatus.FIXED, FindingStatus.NEW_ISSUE}


# -------------------------------------------------------- correlation


def _diff_with_changed_function(function: str, line: int) -> StructuredDiff:
    hunk = DiffHunk(
        old_start=line, old_count=1, new_start=line, new_count=1,
        lines=[DiffLine(kind="added", new_lineno=line, text="  guard();")],
    )
    return StructuredDiff(
        files=[
            FileDiff(
                old_path="src/confparse.c", new_path="src/confparse.c",
                change_kind="modified", hunks=[hunk], changed_functions=[function],
            )
        ]
    )


def test_failure_inside_changed_code_is_a_direct_relationship(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "confparse.c").write_text("x")

    finding = _finding(Version.PATCHED)
    finding.frames = [
        StackFrame(index=0, function="store_value", file="src/confparse.c", line=70)
    ]
    result = correlate.correlate_finding(
        finding, _diff_with_changed_function("store_value", 70),
        source_roots=[tmp_path], status=FindingStatus.NEW_ISSUE,
    )
    assert result.verdict is CorrelationVerdict.DIRECT
    assert result.confidence is Confidence.CONFIRMED
    assert result.related_diff_locations == ["src/confparse.c:70"]


def test_changed_caller_gives_an_indirect_relationship(tmp_path: Path):
    """PDF 3.1: a changed length check in a caller can cause a callee failure."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "confparse.c").write_text("x")

    finding = _finding(Version.PATCHED)
    finding.frames = [
        StackFrame(index=0, function="store_value", file="src/confparse.c", line=70),
        StackFrame(index=1, function="parse_equals", file="src/confparse.c", line=102),
    ]
    result = correlate.correlate_finding(
        finding, _diff_with_changed_function("parse_equals", 102),
        source_roots=[tmp_path], status=FindingStatus.NEW_ISSUE,
    )
    assert result.verdict is CorrelationVerdict.INDIRECT


def test_file_level_overlap_alone_is_not_sufficient_evidence(tmp_path: Path):
    """Adjacency is explicitly not proof; the verdict must be unknown."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "confparse.c").write_text("x")

    finding = _finding(Version.PATCHED)
    finding.frames = [
        StackFrame(index=0, function="store_value", file="src/confparse.c", line=70)
    ]
    result = correlate.correlate_finding(
        finding, _diff_with_changed_function("unrelated_helper", 300),
        source_roots=[tmp_path], status=FindingStatus.INCOMPLETE_FIX,
    )
    assert result.verdict is CorrelationVerdict.UNKNOWN


def test_without_frames_the_relationship_is_unknown():
    finding = _finding(Version.PATCHED)
    finding.frames = []
    result = correlate.correlate_finding(
        finding, _diff_with_changed_function("store_value", 70),
        source_roots=[Path("/nonexistent")], status=FindingStatus.NEW_ISSUE,
    )
    assert result.verdict is CorrelationVerdict.UNKNOWN
    assert result.confidence is Confidence.UNCONFIRMED


def test_frames_entirely_outside_the_patch_are_unrelated(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "other.c").write_text("x")

    finding = _finding(Version.PATCHED, function="elsewhere")
    finding.frames = [
        StackFrame(index=0, function="elsewhere", file="src/other.c", line=5)
    ]
    result = correlate.correlate_finding(
        finding, _diff_with_changed_function("store_value", 70),
        source_roots=[tmp_path], status=None,
    )
    assert result.verdict is CorrelationVerdict.UNRELATED


# -------------------------------------------------------------- oracle


def _check(version: Version, outcome: TestOutcome, test_id="valid") -> OracleCheck:
    return OracleCheck(
        test_id=test_id, version=version, profile=BuildProfile.RELEASE,
        execution_id=f"{version.value}.{test_id}", outcome=outcome,
        violations=["expected exit code 0, got 2"] if outcome is TestOutcome.FAIL else [],
    )


def test_regression_requires_base_pass_and_patched_fail():
    spec = _spec(test_id="valid", expectation=OracleExpectation(exit_code=0, provenance="SPEC.md 4"))
    checks = [_check(Version.BASE, TestOutcome.PASS), _check(Version.PATCHED, TestOutcome.FAIL)]
    assert len(oracle.detect_regressions(checks, [spec])) == 1

    # Base already failing is not a regression.
    checks = [_check(Version.BASE, TestOutcome.FAIL), _check(Version.PATCHED, TestOutcome.FAIL)]
    assert oracle.detect_regressions(checks, [spec]) == []


def test_regression_needs_an_independent_oracle():
    """Without provenance plus a real assertion there is nothing to regress against."""
    weak = _spec(test_id="valid", expectation=OracleExpectation(must_not_crash=True))
    assert not has_independent_oracle(weak)

    checks = [_check(Version.BASE, TestOutcome.PASS), _check(Version.PATCHED, TestOutcome.FAIL)]
    assert oracle.detect_regressions(checks, [weak]) == []


def test_oracle_check_reports_each_violated_field():
    spec = _spec(
        expectation=OracleExpectation(
            exit_code=0, stdout_exact="ok 1\n", provenance="SPEC.md"
        )
    )
    result = oracle.check_execution(
        _execution(exit_code=2, stdout="", version=Version.PATCHED), spec
    )
    assert result.outcome is TestOutcome.FAIL
    assert len(result.violations) == 2
