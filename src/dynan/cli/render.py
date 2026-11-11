"""Terminal rendering.

Presentation only. Nothing here recomputes a status: every verdict, severity
and correlation shown is read from the canonical models the pipeline produced,
which is what keeps the CLI, the JSON report and the web UI in agreement.

The readable summary this module prints is the PDF's "human-readable developer
report", and it is available in CLI-only operation with no web server running.
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..domain.enums import (
    AnalysisCompleteness,
    Confidence,
    CorrelationVerdict,
    DependencyStatus,
    ExitCode,
    FindingStatus,
    FunctionalStatus,
    HardeningDelta,
    SecurityStatus,
    Severity,
    StageState,
    TestOutcome,
)
from ..domain.models import DoctorReport, RunSummary, ValidationRun

#: One colour vocabulary, used by every table below.
_STATUS_STYLE: dict[str, str] = {
    # exit codes
    ExitCode.PASS.name: "bold green",
    ExitCode.VULN_REMAINS.name: "bold red",
    ExitCode.FUNC_REGRESSION.name: "bold yellow",
    ExitCode.BUILD_OR_CONFIG_ERROR.name: "bold magenta",
    ExitCode.INCONCLUSIVE.name: "bold cyan",
    # finding status
    FindingStatus.FIXED.value: "green",
    FindingStatus.INCOMPLETE_FIX.value: "red",
    FindingStatus.NEW_ISSUE.value: "red",
    FindingStatus.INCONCLUSIVE.value: "cyan",
    FindingStatus.UNCHANGED.value: "dim",
    # severity
    Severity.MEMORY_SAFETY.value: "red",
    Severity.UNDEFINED_BEHAVIOR.value: "yellow",
    Severity.CRASH.value: "magenta",
    Severity.RESOURCE.value: "cyan",
    Severity.BENIGN.value: "dim",
    # correlation
    CorrelationVerdict.DIRECT.value: "green",
    CorrelationVerdict.INDIRECT.value: "yellow",
    CorrelationVerdict.UNRELATED.value: "dim",
    CorrelationVerdict.UNKNOWN.value: "cyan",
    # confidence
    Confidence.CONFIRMED.value: "green",
    Confidence.PROBABLE.value: "yellow",
    Confidence.UNCONFIRMED.value: "cyan",
    # stages
    StageState.COMPLETED.value: "green",
    StageState.FAILED.value: "red",
    StageState.RUNNING.value: "yellow",
    StageState.SKIPPED.value: "dim",
    StageState.BLOCKED.value: "magenta",
    StageState.PENDING.value: "dim",
    # aggregate statuses
    SecurityStatus.PASS.value: "green",
    SecurityStatus.VULN_REMAINS.value: "red",
    SecurityStatus.NEW_ISSUE.value: "red",
    SecurityStatus.INCONCLUSIVE.value: "cyan",
    SecurityStatus.NOT_ASSESSED.value: "dim",
    FunctionalStatus.REGRESSION.value: "yellow",
    AnalysisCompleteness.COMPLETE.value: "green",
    AnalysisCompleteness.INCOMPLETE.value: "cyan",
    AnalysisCompleteness.FAILED.value: "red",
    # doctor
    DependencyStatus.READY.value: "green",
    DependencyStatus.MISSING.value: "red",
    DependencyStatus.MISCONFIGURED.value: "yellow",
    DependencyStatus.UNSUPPORTED.value: "red",
    DependencyStatus.NOT_REQUIRED.value: "dim",
    # test outcomes
    TestOutcome.PASS.value: "green",
    TestOutcome.FAIL.value: "red",
    TestOutcome.ERROR.value: "magenta",
    TestOutcome.SKIPPED.value: "dim",
}


def styled(value: str) -> Text:
    return Text(value, style=_STATUS_STYLE.get(value, ""))


def _table(*columns: str, title: str | None = None) -> Table:
    table = Table(
        title=title,
        title_justify="left",
        title_style="bold",
        header_style="bold dim",
        box=None,
        pad_edge=False,
        show_edge=False,
    )
    for column in columns:
        table.add_column(column, overflow="fold")
    return table


# --------------------------------------------------------------------------
# Doctor
# --------------------------------------------------------------------------


def render_doctor(console: Console, report: DoctorReport) -> None:
    by_category: dict[str, list] = {}
    for diagnostic in report.diagnostics:
        by_category.setdefault(diagnostic.category, []).append(diagnostic)

    for category in sorted(by_category):
        table = _table("", "Component", "Detail", title=category)
        for diagnostic in by_category[category]:
            marker = {
                DependencyStatus.READY: Text("ok", style="green"),
                DependencyStatus.MISSING: Text("MISSING", style="red"),
                DependencyStatus.MISCONFIGURED: Text("CHECK", style="yellow"),
                DependencyStatus.UNSUPPORTED: Text("UNSUPPORTED", style="red"),
                DependencyStatus.NOT_REQUIRED: Text("n/a", style="dim"),
            }[diagnostic.status]

            detail = diagnostic.detail
            if diagnostic.version:
                detail = f"{detail}  [{diagnostic.version}]"
            if diagnostic.remediation and diagnostic.status != DependencyStatus.READY:
                detail += f"\n  -> {diagnostic.remediation}"

            name = diagnostic.name + ("" if diagnostic.required else "  (optional)")
            table.add_row(marker, name, detail)
        console.print(table)
        console.print()

    if report.blocking:
        console.print(
            Panel(
                "\n".join(f"- {d.name}: {d.detail}" for d in report.blocking),
                title="Blocking problems",
                border_style="red",
            )
        )
    else:
        console.print(Text("Environment is ready.", style="bold green"))


# --------------------------------------------------------------------------
# Run summary
# --------------------------------------------------------------------------


def render_verdict(console: Console, run: ValidationRun) -> None:
    decision = run.decision
    if decision is None:
        console.print(Text("No decision was produced.", style="bold red"))
        return

    style = _STATUS_STYLE.get(decision.exit_code.name, "bold")
    header = Text()
    header.append(decision.exit_code.name, style=style)
    header.append(f"  (exit {decision.exit_code.value})", style="dim")

    body = _table("", "")
    body.add_row("Security", styled(decision.security_status.value))
    body.add_row("Functionality", styled(decision.functional_status.value))
    body.add_row("Analysis", styled(decision.analysis_completeness.value))
    if len(decision.candidate_codes) > 1:
        codes = ", ".join(
            f"{c.name}({c.value})" for c in decision.candidate_codes
        )
        body.add_row("Applied precedence", Text(codes, style="dim"))

    console.print(Panel(Group(header, "", body), title="Verdict", border_style=style))


def render_reasons(console: Console, run: ValidationRun) -> None:
    decision = run.decision
    if decision is None or not decision.reasons:
        return
    table = _table("Rule", "Explanation", title="Why")
    for reason in decision.reasons:
        table.add_row(Text(reason.code, style="dim"), reason.message)
    console.print(table)
    console.print()


def render_sources(console: Console, run: ValidationRun) -> None:
    if run.sources is None:
        return
    table = _table("Version", "Revision", "Origin", title="Sources")
    for revision in (run.sources.base, run.sources.patched):
        label = Text(revision.display_revision)
        if not revision.is_exact_vcs_revision:
            label.append("  (content hash, not a VCS revision)", style="yellow")
        table.add_row(revision.version.value, label, revision.origin or "")
    console.print(table)
    console.print()


def render_builds(console: Console, run: ValidationRun) -> None:
    if not run.builds:
        return
    table = _table("Build", "Status", "Binary sha256", "Toolchain", title="Builds")
    for build in run.builds:
        status = (
            Text("ok", style="green") if build.success else Text("FAILED", style="red")
        )
        detail = (build.binary_sha256 or "")[:16] or (build.error or "")
        table.add_row(build.key, status, detail, build.toolchain or "")
    console.print(table)
    console.print()


def render_tests(console: Console, run: ValidationRun) -> None:
    if not run.oracle_checks:
        return
    failures = [c for c in run.oracle_checks if c.outcome != TestOutcome.PASS]
    passes = len(run.oracle_checks) - len(failures)

    table = _table(
        "Test", "Version", "Profile", "Outcome", "Detail", title="Oracle checks"
    )
    for check in run.oracle_checks:
        if check.outcome == TestOutcome.PASS:
            continue
        table.add_row(
            check.test_id,
            check.version.value,
            check.profile.value,
            styled(check.outcome.value),
            "; ".join(check.violations[:2]),
        )

    if failures:
        console.print(table)
    console.print(
        Text(
            f"{passes}/{len(run.oracle_checks)} oracle checks passed.",
            style="green" if not failures else "yellow",
        )
    )
    console.print()


def render_findings(console: Console, run: ValidationRun) -> None:
    if not run.comparisons:
        console.print(Text("No findings were recorded.", style="dim"))
        console.print()
        return

    table = _table(
        "Status", "Error", "Location", "Profile", "Correlation", "Tests",
        title="Findings (differential)",
    )
    for comparison in run.comparisons:
        signature = comparison.signature
        location = signature.function or "-"
        if signature.file:
            location = f"{signature.function or '?'} @ {signature.file.rsplit('/', 1)[-1]}"
            if signature.line:
                location += f":{signature.line}"

        correlation = Text("-", style="dim")
        if comparison.correlation is not None:
            correlation = styled(comparison.correlation.verdict.value)
            correlation.append(
                f" ({comparison.correlation.confidence.value})", style="dim"
            )

        table.add_row(
            styled(comparison.status.value),
            signature.error_type.value,
            location,
            comparison.profile.value,
            correlation,
            ", ".join(comparison.test_ids[:3]),
        )
    console.print(table)
    console.print()


def render_correlation_detail(console: Console, run: ValidationRun) -> None:
    """Show the evidence behind each conclusive correlation."""
    interesting = [
        c
        for c in run.correlations
        if c.verdict in (CorrelationVerdict.DIRECT, CorrelationVerdict.INDIRECT)
    ]
    if not interesting:
        return

    for correlation in interesting[:5]:
        finding = run.finding(correlation.finding_id)
        title = finding.signature.describe() if finding else correlation.finding_id
        lines = [Text(correlation.rationale, style="italic")]
        for item in correlation.evidence:
            location = ""
            if item.file:
                location = f" [{item.file}" + (f":{item.line}" if item.line else "") + "]"
            lines.append(Text(f"  - {item.description}{location}", style="dim"))
        console.print(
            Panel(
                Group(*lines),
                title=f"{styled(correlation.verdict.value).plain}: {title}",
                border_style=_STATUS_STYLE.get(correlation.verdict.value, "dim"),
            )
        )
    console.print()


def render_regressions(console: Console, run: ValidationRun) -> None:
    if not run.regressions:
        return
    table = _table("Test", "Profile", "Violation", title="Functional regressions")
    for regression in run.regressions:
        table.add_row(
            regression.test_id,
            regression.profile.value,
            "; ".join(regression.violations[:2]),
        )
    console.print(table)
    console.print()


def render_reproduction(console: Console, run: ValidationRun) -> None:
    if not run.reproductions and not run.minimizations:
        return

    table = _table(
        "Finding", "Replays", "Stable", "Minimised", "Bundle",
        title="Reproduction and minimisation",
    )
    for repro in run.reproductions:
        finding = run.finding(repro.finding_id)
        label = finding.signature.error_type.value if finding else repro.finding_id
        minimization = run.minimization_for(repro.finding_id)
        if minimization:
            reduction = (
                f"{minimization.original_size} -> {minimization.minimized_size} B "
                f"({minimization.reduction_ratio:.0%})"
            )
            if not minimization.verified:
                reduction += " (unverified)"
        else:
            reduction = "-"

        table.add_row(
            label,
            f"{repro.reproduced_count}/{repro.total_attempts}",
            Text("yes", style="green") if repro.stable else Text("NO", style="red"),
            reduction,
            repro.bundle_path,
        )
    console.print(table)
    console.print()


def render_generated_tests(console: Console, run: ValidationRun) -> None:
    if not run.generated_tests:
        return
    table = _table(
        "Test id", "Fails on base", "Passes on patched", "Notes",
        title="Generated regression tests",
    )
    for generated in run.generated_tests:
        def mark(value: bool | None) -> Text:
            if value is None:
                return Text("not verified", style="dim")
            return Text("yes", style="green") if value else Text("no", style="red")

        table.add_row(
            generated.test_id,
            mark(generated.verified_fails_on_base),
            mark(generated.verified_passes_on_patched),
            generated.notes,
        )
    console.print(table)
    console.print()


def render_hardening(console: Console, run: ValidationRun) -> None:
    hardening = run.hardening
    if hardening is None or hardening.base is None or hardening.patched is None:
        return

    table = _table("Protection", "Base", "Patched", "Change", title="Binary hardening")
    for change in hardening.changes:
        delta_style = {
            HardeningDelta.WEAKENED: "red",
            HardeningDelta.STRENGTHENED: "green",
            HardeningDelta.UNCHANGED: "dim",
            HardeningDelta.UNKNOWN: "yellow",
        }[change.delta]
        table.add_row(
            change.property_name,
            change.base_state.value,
            change.patched_state.value,
            Text(change.delta.value, style=delta_style),
        )
    table.add_row(
        "RELRO level",
        hardening.base.relro_level.value,
        hardening.patched.relro_level.value,
        Text("", style="dim"),
    )
    console.print(table)
    for caveat in hardening.base.caveats:
        console.print(Text(f"  note: {caveat}", style="dim"))
    console.print()


def render_messages(console: Console, run: ValidationRun) -> None:
    if run.errors:
        console.print(
            Panel(
                "\n".join(f"- {e}" for e in run.errors),
                title="Errors",
                border_style="red",
            )
        )
    if run.warnings:
        console.print(
            Panel(
                "\n".join(f"- {w}" for w in run.warnings),
                title="Warnings",
                border_style="yellow",
            )
        )
    if run.errors or run.warnings:
        console.print()


def render_stages(console: Console, run: ValidationRun) -> None:
    if not run.stages:
        return
    table = _table("Stage", "State", "Duration", "Detail", title="Stages")
    for status in run.stages:
        duration = f"{status.duration_s:.2f}s" if status.duration_s is not None else "-"
        table.add_row(
            status.stage.value, styled(status.state.value), duration, status.message
        )
    console.print(table)
    console.print()


def render_run(console: Console, run: ValidationRun, *, verbose: bool = False) -> None:
    """The full readable report for one run."""
    console.print()
    console.print(
        Text(f"dynAn  {run.target_name}", style="bold")
        + Text(f"   run {run.run_id}", style="dim")
    )
    if run.duration_s is not None:
        console.print(Text(f"completed in {run.duration_s:.1f}s", style="dim"))
    console.print()

    render_verdict(console, run)
    console.print()
    render_messages(console, run)
    render_sources(console, run)
    render_builds(console, run)

    if run.diff is not None:
        console.print(
            Text(
                f"Diff: {run.diff.files_changed} file(s), "
                f"+{run.diff.total_added}/-{run.diff.total_removed}; "
                f"changed functions: "
                f"{', '.join(sorted(run.diff.all_changed_functions())) or 'none detected'}"
            )
        )
        console.print()

    render_tests(console, run)
    render_findings(console, run)
    render_correlation_detail(console, run)
    render_regressions(console, run)
    render_reproduction(console, run)
    render_generated_tests(console, run)
    render_hardening(console, run)
    render_reasons(console, run)

    if verbose:
        render_stages(console, run)


def render_run_list(console: Console, summaries: list[RunSummary]) -> None:
    if not summaries:
        console.print(
            Text("No runs recorded yet. Start one with 'dynan validate'.", style="dim")
        )
        return

    table = _table(
        "Run id", "Target", "Started", "Duration", "Verdict", "Security", "Functional",
    )
    for summary in summaries:
        # PASS is exit code 0, which is falsy - test for None explicitly or
        # every successful run renders as having no verdict.
        if summary.exit_code is not None:
            verdict = styled(summary.exit_code.name)
            verdict.append(f" ({summary.exit_code.value})", style="dim")
        else:
            verdict = Text("-", style="dim")

        duration = f"{summary.duration_s:.1f}s" if summary.duration_s else "-"
        table.add_row(
            Text(summary.run_id, style="bold"),
            summary.target_name,
            summary.created_at.strftime("%m-%d %H:%M"),
            duration,
            verdict,
            styled(summary.security_status.value) if summary.security_status else Text("-"),
            styled(summary.functional_status.value)
            if summary.functional_status
            else Text("-"),
        )
    console.print(table)
    console.print()
    console.print(
        Text("Inspect one with: dynan runs show <run-id>", style="dim")
    )
