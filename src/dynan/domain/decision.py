"""The deterministic decision engine.

This module is the *only* place in dynAn where a verdict is produced. The CLI,
the JSON report and the web UI all read the :class:`Decision` it returns; none
of them re-derives status from findings. Optional LLM extensions can annotate a
run but can never reach this code path.

Rules implemented here come from PDF section 3.5. Each branch below cites the
clause it encodes so the mapping stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import (
    EXIT_CODE_PRECEDENCE,
    AnalysisCompleteness,
    BuildProfile,
    Confidence,
    ErrorType,
    ExitCode,
    FindingStatus,
    FunctionalStatus,
    SecurityStatus,
    Severity,
    Stage,
    StageState,
    Version,
)
from .models import Decision, DecisionReason, ValidationRun

#: Builds that must succeed before any comparison is meaningful. The PDF
#: requires release and instrumented observations to be reported separately and
#: compared against matching builds, so all four are mandatory.
REQUIRED_BUILDS: tuple[tuple[Version, BuildProfile], ...] = (
    (Version.BASE, BuildProfile.RELEASE),
    (Version.BASE, BuildProfile.SANITIZED),
    (Version.PATCHED, BuildProfile.RELEASE),
    (Version.PATCHED, BuildProfile.SANITIZED),
)


@dataclass
class _Verdict:
    """Accumulator used while walking the rules."""

    codes: set[ExitCode] = field(default_factory=set)
    reasons: list[DecisionReason] = field(default_factory=list)

    def add(
        self,
        code: ExitCode,
        rule: str,
        message: str,
        references: list[str] | None = None,
    ) -> None:
        self.codes.add(code)
        self.reasons.append(
            DecisionReason(code=rule, message=message, references=references or [])
        )


def resolve_exit_code(codes: set[ExitCode]) -> ExitCode:
    """Apply the official precedence to a set of simultaneously valid statuses.

    Order is ``30 > 10 > 20 > 40 > 0`` - see
    :data:`dynan.domain.enums.EXIT_CODE_PRECEDENCE` for the specification
    quote this encodes.
    """
    for code in EXIT_CODE_PRECEDENCE:
        if code in codes:
            return code
    return ExitCode.PASS


def _confirmed_remaining(confidence: Confidence, severity: Severity) -> bool:
    """Whether a *surviving baseline* finding justifies exit code 10.

    PDF 3.5 code 10 reads: «خطای قبلی همچنان رخ می‌دهد (VULN_REMAINS) یا یک
    خطای حافظه‌ای دیگر با شواهد معتبر تأیید شده است (NEW_ISSUE)» - "the
    previous error still occurs, or another memory error is confirmed with
    valid evidence".

    The first clause is about *the* reproduced baseline error, whatever its
    kind, so a confirmed undefined-behaviour defect that survives the patch
    counts here. The second clause is narrower - see
    :func:`_confirmed_new_issue`.
    """
    return confidence == Confidence.CONFIRMED and severity in (
        Severity.MEMORY_SAFETY,
        Severity.UNDEFINED_BEHAVIOR,
    )


def _confirmed_new_issue(confidence: Confidence, severity: Severity) -> bool:
    """Whether a newly appeared finding justifies exit code 10.

    The specification restricts this clause to a confirmed *memory* error, so
    a newly observed UB finding or an unclassified stop is reported but routed
    to INCONCLUSIVE rather than silently promoted to a failure verdict.
    """
    return confidence == Confidence.CONFIRMED and severity == Severity.MEMORY_SAFETY


def assess_completeness(run: ValidationRun) -> tuple[AnalysisCompleteness, list[str]]:
    """Check the mandatory analysis steps actually ran.

    Returns the completeness status plus human-readable gaps. A gap means we
    must not emit PASS, because PDF 3.5 code 0 requires every mandatory check
    to be "successful and complete".
    """
    gaps: list[str] = []

    if run.sources is None:
        gaps.append("source resolution did not complete")
    if run.diff is None:
        gaps.append("diff was not computed")

    for version, profile in REQUIRED_BUILDS:
        build = run.build(version, profile)
        if build is None:
            gaps.append(f"build missing: {version.value}/{profile.value}")
        elif not build.success:
            gaps.append(f"build failed: {version.value}/{profile.value}")

    if not run.executions:
        gaps.append("no target executions were recorded")

    if run.hardening is None or run.hardening.base is None or run.hardening.patched is None:
        gaps.append("binary hardening inspection incomplete")

    # Every confirmed failure must carry a reproducer bundle whose replays were
    # stable - PDF 3.3 requires >= 3 replays and explicit identification of
    # unstable cases.
    #
    # Coverage is assessed per *signature* within a version and profile, not
    # per finding: when several inputs reach the same defect, one reproducer
    # establishes it. Demanding a bundle per input would mark a complete
    # analysis as incomplete purely because the defect is reachable twice.
    groups: dict[tuple, list] = {}
    for finding in run.findings:
        if finding.confidence != Confidence.CONFIRMED:
            continue
        if finding.severity not in (Severity.MEMORY_SAFETY, Severity.UNDEFINED_BEHAVIOR):
            continue
        key = (finding.signature.key(), finding.version, finding.profile)
        groups.setdefault(key, []).append(finding)

    for key, members in groups.items():
        reproductions = [
            repro
            for member in members
            if (repro := run.reproduction_for(member.finding_id)) is not None
        ]
        describe = f"{members[0].signature.describe()} ({key[1].value}/{key[2].value})"
        if not reproductions:
            gaps.append(f"no reproducer bundle for {describe}")
        elif not any(r.stable for r in reproductions):
            worst = reproductions[0]
            gaps.append(
                f"{describe} reproduced "
                f"{worst.reproduced_count}/{worst.total_attempts} times (unstable)"
            )

    for stage_status in run.stages:
        if stage_status.state == StageState.FAILED:
            gaps.append(f"stage failed: {stage_status.stage.value}")

    if gaps:
        failed_infra = any(
            s.state == StageState.FAILED
            and s.stage in (Stage.SOURCE, Stage.BUILD, Stage.PREFLIGHT)
            for s in run.stages
        )
        return (
            AnalysisCompleteness.FAILED if failed_infra else AnalysisCompleteness.INCOMPLETE,
            gaps,
        )
    return AnalysisCompleteness.COMPLETE, []


def evaluate(run: ValidationRun) -> Decision:
    """Produce the authoritative verdict for a completed pipeline run."""
    verdict = _Verdict()

    # -- Rule 30: build / configuration / environment failures ------------
    # PDF 3.5: "target does not compile, the configuration file is incomplete,
    # or the execution environment and the tool itself have an error. These
    # cases must not be counted as finding a security error or as confirming
    # the patch." So we record it and deliberately do not let any security
    # conclusion derived from a broken run stand in for a real verdict.
    build_broken = False
    for version, profile in REQUIRED_BUILDS:
        build = run.build(version, profile)
        if build is None:
            build_broken = True
            verdict.add(
                ExitCode.BUILD_OR_CONFIG_ERROR,
                "build.missing",
                f"Required build {version.value}/{profile.value} was never produced.",
            )
        elif not build.success:
            build_broken = True
            verdict.add(
                ExitCode.BUILD_OR_CONFIG_ERROR,
                "build.failed",
                f"Build {version.value}/{profile.value} failed: "
                f"{build.error or 'see build logs'}",
                [build.key],
            )

    if run.errors:
        build_broken = True
        for err in run.errors:
            verdict.add(
                ExitCode.BUILD_OR_CONFIG_ERROR,
                "infrastructure.error",
                err,
            )

    # -- Security assessment ----------------------------------------------
    security_status = SecurityStatus.NOT_ASSESSED
    remaining: list[str] = []
    new_issues: list[str] = []
    inconclusive_security: list[str] = []

    baseline_reproduced = any(c.is_targeted_baseline for c in run.comparisons)

    for comparison in run.comparisons:
        severity = Severity.MEMORY_SAFETY
        # Severity is carried by the underlying findings; take the strongest.
        related_ids = comparison.patched_finding_ids or comparison.base_finding_ids
        severities = [
            f.severity for fid in related_ids if (f := run.finding(fid)) is not None
        ]
        if severities:
            severity = (
                Severity.MEMORY_SAFETY
                if Severity.MEMORY_SAFETY in severities
                else severities[0]
            )

        if comparison.status == FindingStatus.INCOMPLETE_FIX:
            if _confirmed_remaining(comparison.confidence, severity):
                remaining.append(comparison.signature.digest)
                verdict.add(
                    ExitCode.VULN_REMAINS,
                    "security.incomplete_fix",
                    f"Baseline vulnerability still reachable in the patched version: "
                    f"{comparison.signature.describe()}",
                    comparison.patched_finding_ids,
                )
            else:
                inconclusive_security.append(comparison.signature.digest)
                verdict.add(
                    ExitCode.INCONCLUSIVE,
                    "security.incomplete_fix.weak_evidence",
                    f"Possible remaining vulnerability with insufficient evidence: "
                    f"{comparison.signature.describe()}",
                    comparison.patched_finding_ids,
                )

        elif comparison.status == FindingStatus.NEW_ISSUE:
            if _confirmed_new_issue(comparison.confidence, severity):
                new_issues.append(comparison.signature.digest)
                verdict.add(
                    ExitCode.VULN_REMAINS,
                    "security.new_issue",
                    f"New confirmed memory error introduced by the patched version: "
                    f"{comparison.signature.describe()}",
                    comparison.patched_finding_ids,
                )
            else:
                inconclusive_security.append(comparison.signature.digest)
                verdict.add(
                    ExitCode.INCONCLUSIVE,
                    "security.new_issue.weak_evidence",
                    f"New observation without sufficient evidence to confirm a "
                    f"vulnerability: {comparison.signature.describe()}",
                    comparison.patched_finding_ids,
                )

        elif comparison.status == FindingStatus.INCONCLUSIVE:
            inconclusive_security.append(comparison.signature.digest)
            verdict.add(
                ExitCode.INCONCLUSIVE,
                "security.inconclusive",
                f"Inconclusive security observation: {comparison.signature.describe()}"
                + (f" - {comparison.rationale}" if comparison.rationale else ""),
                comparison.patched_finding_ids or comparison.base_finding_ids,
            )

    # PDF 3.5 code 40 names "base error not reproduced" as an explicit example
    # of an inconclusive run: without a reproduced baseline we cannot claim the
    # patch fixed anything.
    if not baseline_reproduced and not build_broken:
        verdict.add(
            ExitCode.INCONCLUSIVE,
            "security.baseline_not_reproduced",
            "No security finding was reproduced on the vulnerable base version, "
            "so the patch cannot be shown to fix anything within the test scope.",
        )

    # Unclassified crashes on the patched version: real, reported, but
    # explicitly insufficient to confirm a vulnerability on their own.
    for finding in run.findings:
        if (
            finding.version == Version.PATCHED
            and finding.signature.error_type == ErrorType.UNCLASSIFIED_CRASH
        ):
            verdict.add(
                ExitCode.INCONCLUSIVE,
                "security.unclassified_stop",
                f"Unclassified abnormal termination in the patched version "
                f"(test {finding.test_id}); not sufficient to confirm a vulnerability.",
                [finding.finding_id],
            )
            inconclusive_security.append(finding.finding_id)

    if build_broken:
        # Security cannot be meaningfully assessed from a broken build.
        security_status = SecurityStatus.NOT_ASSESSED
    elif remaining:
        security_status = SecurityStatus.VULN_REMAINS
    elif new_issues:
        security_status = SecurityStatus.NEW_ISSUE
    elif inconclusive_security or not baseline_reproduced:
        security_status = SecurityStatus.INCONCLUSIVE
    elif run.comparisons:
        security_status = SecurityStatus.PASS
    else:
        security_status = SecurityStatus.NOT_ASSESSED

    # -- Rule 20: functional regression -----------------------------------
    # PDF 3.5: "at least one of the valid functional tests passed on the base
    # version and failed on the patched version. This status is recorded
    # independently of the security status."
    functional_status = FunctionalStatus.NOT_ASSESSED
    if run.regressions:
        functional_status = FunctionalStatus.REGRESSION
        for reg in run.regressions:
            verdict.add(
                ExitCode.FUNC_REGRESSION,
                "functional.regression",
                f"Test {reg.test_id} ({reg.profile.value}) satisfied the independent "
                f"oracle on base but violated it after the patch: "
                + "; ".join(reg.violations),
                [reg.test_id],
            )
    elif run.oracle_checks:
        functional_status = (
            FunctionalStatus.NOT_ASSESSED if build_broken else FunctionalStatus.PASS
        )

    # -- Rule 40: analysis completeness -----------------------------------
    completeness, gaps = assess_completeness(run)
    if completeness != AnalysisCompleteness.COMPLETE and not build_broken:
        for gap in gaps:
            verdict.add(ExitCode.INCONCLUSIVE, "analysis.incomplete", gap)

    # -- Rule 0: PASS ------------------------------------------------------
    if not verdict.codes:
        verdict.add(
            ExitCode.PASS,
            "pass",
            "The reproduced baseline vulnerability is no longer observable in the "
            "patched version, no other confirmed security finding was recorded, "
            "all functional tests satisfied the independent oracle, and every "
            "mandatory check completed.",
        )

    exit_code = resolve_exit_code(verdict.codes)

    if exit_code == ExitCode.PASS:
        security_status = SecurityStatus.PASS
        functional_status = FunctionalStatus.PASS

    return Decision(
        exit_code=exit_code,
        security_status=security_status,
        functional_status=functional_status,
        analysis_completeness=completeness,
        candidate_codes=sorted(verdict.codes, key=lambda c: EXIT_CODE_PRECEDENCE.index(c)),
        reasons=verdict.reasons,
        summary=_summarise(exit_code, security_status, functional_status, completeness),
    )


def _summarise(
    exit_code: ExitCode,
    security: SecurityStatus,
    functional: FunctionalStatus,
    completeness: AnalysisCompleteness,
) -> str:
    headline = {
        ExitCode.PASS: "Patch validated",
        ExitCode.VULN_REMAINS: "Security issue confirmed in the patched version",
        ExitCode.FUNC_REGRESSION: "Functional regression confirmed",
        ExitCode.BUILD_OR_CONFIG_ERROR: "Build or configuration error",
        ExitCode.INCONCLUSIVE: "Validation inconclusive",
    }[exit_code]
    return (
        f"{headline} (exit {exit_code.value}). "
        f"security={security.value}, functional={functional.value}, "
        f"analysis={completeness.value}"
    )
