"""The decision engine - the single authority for a verdict.

These tests encode the specification's rules directly, so a change in
behaviour here is a change in what dynAn claims about a patch.
"""

from __future__ import annotations

import pytest

from dynan import RESULT_SCHEMA_VERSION
from dynan.domain.decision import evaluate, resolve_exit_code
from dynan.domain.enums import (
    EXIT_CODE_PRECEDENCE,
    AnalysisCompleteness,
    BuildProfile,
    Confidence,
    DetectionMechanism,
    ErrorType,
    ExitCode,
    FindingStatus,
    FunctionalStatus,
    SecurityStatus,
    Severity,
    TestOutcome,
    Version,
)
from dynan.domain.models import (
    BinaryHardening,
    BuildResult,
    ExecutionResult,
    Finding,
    FindingComparison,
    FindingSignature,
    FunctionalRegression,
    HardeningComparison,
    HardeningProperty,
    OracleCheck,
    ReplayAttempt,
    ReproductionResult,
    SourcePair,
    SourceRevision,
    StructuredDiff,
    ValidationRun,
)
from dynan.domain.enums import HardeningState, InputDelivery


# ---------------------------------------------------------------- helpers


def _signature(
    error_type: ErrorType = ErrorType.STACK_BUFFER_OVERFLOW,
    function: str = "store_value",
) -> FindingSignature:
    return FindingSignature(
        error_type=error_type,
        detection=DetectionMechanism.ASAN,
        function=function,
        file="src/confparse.c",
        line=70,
    )


def _finding(
    version: Version,
    *,
    signature: FindingSignature | None = None,
    severity: Severity = Severity.MEMORY_SAFETY,
    confidence: Confidence = Confidence.CONFIRMED,
    test_id: str = "t1",
) -> Finding:
    sig = signature or _signature()
    return Finding(
        finding_id=f"{version.value}.{test_id}.{sig.digest}",
        signature=sig,
        severity=severity,
        confidence=confidence,
        version=version,
        profile=BuildProfile.SANITIZED,
        test_id=test_id,
        execution_id=f"{version.value}.sanitized.{test_id}",
    )


def _hardening(version: Version) -> BinaryHardening:
    prop = HardeningProperty(name="NX", state=HardeningState.ENABLED)
    return BinaryHardening(
        version=version,
        profile=BuildProfile.RELEASE,
        binary_path="/tmp/bin",
        nx=prop,
        pie=HardeningProperty(name="PIE", state=HardeningState.ENABLED),
        relro=HardeningProperty(name="RELRO", state=HardeningState.ENABLED),
        canary=HardeningProperty(name="Stack Canary", state=HardeningState.ENABLED),
    )


def make_run(**overrides) -> ValidationRun:
    """A run that would otherwise PASS, so each test changes exactly one thing."""
    revision = SourceRevision(
        version=Version.BASE, kind="git", path="/tmp/base", commit="a" * 40,
        short_commit="aaaaaaa", content_hash="h",
    )
    patched = revision.model_copy(update={"version": Version.PATCHED, "commit": "b" * 40})

    run = ValidationRun(
        schema_version=RESULT_SCHEMA_VERSION,
        run_id="20260101T000000Z-deadbeef",
        dynan_version="test",
        target_name="fixture",
        sources=SourcePair(base=revision, patched=patched),
        diff=StructuredDiff(),
        builds=[
            BuildResult(version=v, profile=p, success=True, binary_path="/tmp/b",
                        binary_sha256="0" * 64)
            for v in (Version.BASE, Version.PATCHED)
            for p in (BuildProfile.RELEASE, BuildProfile.SANITIZED)
        ],
        executions=[
            ExecutionResult(
                execution_id="base.sanitized.t1", test_id="t1", version=Version.BASE,
                profile=BuildProfile.SANITIZED, argv=["/tmp/b"], cwd="/tmp",
                delivery=InputDelivery.STDIN, exit_code=1,
            )
        ],
        hardening=HardeningComparison(
            base=_hardening(Version.BASE), patched=_hardening(Version.PATCHED)
        ),
    )

    # A reproduced-and-fixed baseline vulnerability: the PASS precondition.
    base_finding = _finding(Version.BASE)
    run.findings = [base_finding]
    run.comparisons = [
        FindingComparison(
            signature=base_finding.signature,
            status=FindingStatus.FIXED,
            base_finding_ids=[base_finding.finding_id],
            profile=BuildProfile.SANITIZED,
            confidence=Confidence.CONFIRMED,
        )
    ]
    run.reproductions = [
        ReproductionResult(
            finding_id=base_finding.finding_id,
            bundle_path="reproducers/x",
            attempts=[
                ReplayAttempt(attempt=i, execution_id=f"r{i}", reproduced=True)
                for i in (1, 2, 3)
            ],
            reproduced_count=3,
            total_attempts=3,
            stable=True,
        )
    ]
    run.oracle_checks = [
        OracleCheck(
            test_id="t1", version=Version.BASE, profile=BuildProfile.RELEASE,
            execution_id="e1", outcome=TestOutcome.PASS,
        )
    ]

    for key, value in overrides.items():
        setattr(run, key, value)
    return run


# ------------------------------------------------------------- precedence


def test_precedence_follows_the_specification_order():
    """PDF 3.5: "the exit-code priority is, in order, 30, 10, 20, 40 and 0"."""
    assert EXIT_CODE_PRECEDENCE == (
        ExitCode.BUILD_OR_CONFIG_ERROR,
        ExitCode.VULN_REMAINS,
        ExitCode.FUNC_REGRESSION,
        ExitCode.INCONCLUSIVE,
        ExitCode.PASS,
    )


@pytest.mark.parametrize(
    "codes,expected",
    [
        ({ExitCode.PASS}, ExitCode.PASS),
        ({ExitCode.INCONCLUSIVE, ExitCode.PASS}, ExitCode.INCONCLUSIVE),
        ({ExitCode.FUNC_REGRESSION, ExitCode.INCONCLUSIVE}, ExitCode.FUNC_REGRESSION),
        ({ExitCode.VULN_REMAINS, ExitCode.FUNC_REGRESSION}, ExitCode.VULN_REMAINS),
        ({ExitCode.BUILD_OR_CONFIG_ERROR, ExitCode.VULN_REMAINS}, ExitCode.BUILD_OR_CONFIG_ERROR),
        (set(), ExitCode.PASS),
    ],
)
def test_resolve_exit_code(codes, expected):
    assert resolve_exit_code(codes) is expected


# ------------------------------------------------------------------ rules


def test_clean_run_passes():
    decision = evaluate(make_run())
    assert decision.exit_code is ExitCode.PASS
    assert decision.security_status is SecurityStatus.PASS
    assert decision.functional_status is FunctionalStatus.PASS
    assert decision.analysis_completeness is AnalysisCompleteness.COMPLETE


def test_failed_build_is_thirty_and_never_a_security_claim():
    run = make_run()
    run.builds[0].success = False
    run.builds[0].error = "compilation failed"

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.BUILD_OR_CONFIG_ERROR
    # Explicitly must not be reported as a confirmed patch or a finding.
    assert decision.security_status is SecurityStatus.NOT_ASSESSED
    assert decision.functional_status is not FunctionalStatus.PASS


def test_surviving_vulnerability_is_ten():
    run = make_run()
    patched = _finding(Version.PATCHED)
    run.findings.append(patched)
    run.comparisons[0].status = FindingStatus.INCOMPLETE_FIX
    run.comparisons[0].patched_finding_ids = [patched.finding_id]
    run.reproductions.append(
        ReproductionResult(
            finding_id=patched.finding_id, bundle_path="reproducers/y",
            reproduced_count=3, total_attempts=3, stable=True,
        )
    )

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.VULN_REMAINS
    assert decision.security_status is SecurityStatus.VULN_REMAINS


def test_functional_regression_is_twenty_and_independent_of_security():
    run = make_run()
    check_base = OracleCheck(
        test_id="valid", version=Version.BASE, profile=BuildProfile.RELEASE,
        execution_id="b", outcome=TestOutcome.PASS,
    )
    check_patched = OracleCheck(
        test_id="valid", version=Version.PATCHED, profile=BuildProfile.RELEASE,
        execution_id="p", outcome=TestOutcome.FAIL, violations=["expected exit 0, got 2"],
    )
    run.regressions = [
        FunctionalRegression(
            test_id="valid", profile=BuildProfile.RELEASE,
            base_check=check_base, patched_check=check_patched,
            violations=["expected exit 0, got 2"],
            base_execution_id="b", patched_execution_id="p",
        )
    ]

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.FUNC_REGRESSION
    assert decision.functional_status is FunctionalStatus.REGRESSION
    # The security side stays its own verdict, as the PDF requires.
    assert decision.security_status is SecurityStatus.PASS


def test_unreproduced_baseline_is_inconclusive_not_pass():
    """PDF 3.5 names "base error not reproduced" as an example of code 40."""
    run = make_run()
    run.findings = []
    run.comparisons = []
    run.reproductions = []

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.INCONCLUSIVE
    assert decision.security_status is SecurityStatus.INCONCLUSIVE


def test_unstable_finding_blocks_pass():
    run = make_run()
    run.reproductions[0].stable = False
    run.reproductions[0].reproduced_count = 1

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.INCONCLUSIVE
    assert decision.analysis_completeness is AnalysisCompleteness.INCOMPLETE


def test_unclassified_crash_alone_does_not_confirm_a_vulnerability():
    """A stop with no classifying evidence is inconclusive, never code 10."""
    run = make_run()
    crash_sig = _signature(ErrorType.UNCLASSIFIED_CRASH, function=None)
    crash = _finding(
        Version.PATCHED, signature=crash_sig, severity=Severity.CRASH,
        confidence=Confidence.UNCONFIRMED, test_id="t2",
    )
    run.findings.append(crash)
    run.comparisons.append(
        FindingComparison(
            signature=crash_sig, status=FindingStatus.NEW_ISSUE,
            patched_finding_ids=[crash.finding_id],
            profile=BuildProfile.SANITIZED, confidence=Confidence.UNCONFIRMED,
        )
    )

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.INCONCLUSIVE
    assert ExitCode.VULN_REMAINS not in decision.candidate_codes


def test_new_undefined_behaviour_is_not_promoted_to_code_ten():
    """Code 10's second clause is restricted to a confirmed *memory* error."""
    run = make_run()
    ub_sig = _signature(ErrorType.SIGNED_INTEGER_OVERFLOW, function="add")
    ub = _finding(
        Version.PATCHED, signature=ub_sig, severity=Severity.UNDEFINED_BEHAVIOR,
        test_id="t3",
    )
    run.findings.append(ub)
    run.comparisons.append(
        FindingComparison(
            signature=ub_sig, status=FindingStatus.NEW_ISSUE,
            patched_finding_ids=[ub.finding_id],
            profile=BuildProfile.SANITIZED, confidence=Confidence.CONFIRMED,
        )
    )
    run.reproductions.append(
        ReproductionResult(
            finding_id=ub.finding_id, bundle_path="r/z",
            reproduced_count=3, total_attempts=3, stable=True,
        )
    )

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.INCONCLUSIVE


def test_surviving_undefined_behaviour_does_reach_code_ten():
    """Code 10's first clause covers "the previous error still occurs"."""
    run = make_run()
    ub_sig = _signature(ErrorType.SIGNED_INTEGER_OVERFLOW, function="add")
    base = _finding(Version.BASE, signature=ub_sig,
                    severity=Severity.UNDEFINED_BEHAVIOR, test_id="t3")
    patched = _finding(Version.PATCHED, signature=ub_sig,
                       severity=Severity.UNDEFINED_BEHAVIOR, test_id="t3")
    run.findings = [base, patched]
    run.comparisons = [
        FindingComparison(
            signature=ub_sig, status=FindingStatus.INCOMPLETE_FIX,
            base_finding_ids=[base.finding_id],
            patched_finding_ids=[patched.finding_id],
            profile=BuildProfile.SANITIZED, confidence=Confidence.CONFIRMED,
        )
    ]
    run.reproductions = [
        ReproductionResult(finding_id=f.finding_id, bundle_path="r",
                           reproduced_count=3, total_attempts=3, stable=True)
        for f in (base, patched)
    ]

    assert evaluate(run).exit_code is ExitCode.VULN_REMAINS


def test_build_error_outranks_a_confirmed_vulnerability():
    run = make_run()
    run.builds[2].success = False
    run.builds[2].error = "link failed"
    patched = _finding(Version.PATCHED)
    run.findings.append(patched)
    run.comparisons[0].status = FindingStatus.INCOMPLETE_FIX
    run.comparisons[0].patched_finding_ids = [patched.finding_id]

    decision = evaluate(run)
    assert decision.exit_code is ExitCode.BUILD_OR_CONFIG_ERROR
    assert ExitCode.VULN_REMAINS in decision.candidate_codes


def test_incomplete_hardening_inspection_blocks_pass():
    run = make_run()
    run.hardening = HardeningComparison(base=None, patched=None)
    assert evaluate(run).exit_code is ExitCode.INCONCLUSIVE


def test_every_decision_carries_a_reason():
    for run in (make_run(), make_run(errors=["boom"])):
        decision = evaluate(run)
        assert decision.reasons, "a verdict must always be explainable"
        assert decision.summary
