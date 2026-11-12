"""The independent correctness oracle and functional regression detection.

The PDF is unambiguous that the patched program's own output may not serve as
the correctness criterion. So dynAn only treats an expectation as a
correctness oracle when the manifest recorded where it came from (program
documentation or an independent reference test) *and* it asserts something
concrete. An expectation that merely says "must not crash" is a safety check,
not a functional criterion, and cannot by itself establish a regression.

A regression requires both halves of the evidence the PDF demands: the base
version satisfied the independent expectation, and the patched version
violated it, for the same input under the same build profile.
"""

from __future__ import annotations

import re

from ..config.testsuite import has_independent_oracle
from ..domain.enums import BuildProfile, ExecutionOutcome, TestOutcome, Version
from ..domain.models import (
    ExecutionResult,
    FunctionalRegression,
    OracleCheck,
    OracleExpectation,
    OutputFileExpectation,
    TestCaseSpec,
)


def _summarise_expectation(expectation: OracleExpectation) -> str:
    parts: list[str] = []
    if expectation.exit_code is not None:
        parts.append(f"exit={expectation.exit_code}")
    if expectation.stdout_exact is not None:
        parts.append(f"stdout=={expectation.stdout_exact!r}")
    for needle in expectation.stdout_contains:
        parts.append(f"stdout contains {needle!r}")
    if expectation.stdout_regex:
        parts.append(f"stdout matches /{expectation.stdout_regex}/")
    for needle in expectation.stderr_contains:
        parts.append(f"stderr contains {needle!r}")
    for output in expectation.output_files:
        if not output.exists:
            parts.append(f"no file {output.path!r}")
        elif output.exact is not None:
            parts.append(f"file {output.path!r} == {output.exact!r}")
        elif output.has_content_assertion:
            parts.append(f"file {output.path!r} matches")
        else:
            parts.append(f"file {output.path!r} exists")
    if expectation.must_not_crash:
        parts.append("no abnormal termination")
    if expectation.max_duration_s is not None:
        parts.append(f"duration<={expectation.max_duration_s}s")
    return "; ".join(parts) or "no assertions"


def _summarise_actual(execution: ExecutionResult) -> str:
    if execution.signal is not None:
        status = f"signal={execution.signal_name}"
    else:
        status = f"exit={execution.exit_code}"
    extra = ""
    if execution.outcome == ExecutionOutcome.TIMEOUT:
        extra = ", timed out"
    stdout = execution.stdout.strip()
    preview = stdout if len(stdout) <= 60 else stdout[:57] + "..."
    summary = f"{status}{extra}, stdout={preview!r}"
    for captured in execution.output_files:
        state = f"{captured.size}B" if captured.exists else "absent"
        summary += f", file {captured.path!r}={state}"
    return summary


def _check_output_files(
    execution: ExecutionResult, expectation: OracleExpectation
) -> list[str]:
    """Compare declared output files against what the execution produced."""
    violations: list[str] = []
    captured = {item.path: item for item in execution.output_files}

    for expected in expectation.output_files:
        actual = captured.get(expected.path)

        if actual is None:
            # The runner captures exactly what the expectation declares, so a
            # gap here is a dynAn bug rather than a target failure. Report it
            # as such instead of blaming the program under test.
            violations.append(
                f"output file {expected.path!r} was declared but never captured"
            )
            continue

        if actual.error:
            violations.append(
                f"output file {expected.path!r} could not be read: {actual.error}"
            )
            continue

        if not expected.exists:
            if actual.exists:
                violations.append(
                    f"output file {expected.path!r} exists but was expected not to"
                )
            continue

        if not actual.exists:
            violations.append(f"output file {expected.path!r} was not created")
            continue

        if actual.truncated and expected.exact is not None:
            violations.append(
                f"output file {expected.path!r} is too large to compare exactly "
                f"({actual.size} bytes)"
            )
            continue

        if expected.exact is not None and actual.text != expected.exact:
            violations.append(
                f"output file {expected.path!r} did not match exactly "
                f"(expected {expected.exact!r}, got {actual.text!r})"
            )

        for needle in expected.contains:
            if needle not in actual.text:
                violations.append(
                    f"output file {expected.path!r} did not contain {needle!r}"
                )

        if expected.regex and not re.search(expected.regex, actual.text, re.MULTILINE):
            violations.append(
                f"output file {expected.path!r} did not match /{expected.regex}/"
            )

    return violations


def check_execution(execution: ExecutionResult, test: TestCaseSpec) -> OracleCheck:
    """Evaluate one execution against its test's expectation."""
    expectation = test.expectation
    violations: list[str] = []

    if execution.outcome == ExecutionOutcome.SPAWN_ERROR:
        return OracleCheck(
            test_id=test.test_id,
            version=execution.version,
            profile=execution.profile,
            execution_id=execution.execution_id,
            outcome=TestOutcome.ERROR,
            violations=[f"target could not be started: {execution.spawn_error}"],
            expected_summary=_summarise_expectation(expectation),
            actual_summary=_summarise_actual(execution),
        )

    if expectation.must_not_crash and execution.signal is not None:
        violations.append(
            f"process terminated by {execution.signal_name}, expected normal termination"
        )

    if execution.outcome == ExecutionOutcome.TIMEOUT:
        violations.append(f"execution exceeded its {execution.timeout_s}s timeout")

    if expectation.exit_code is not None:
        if execution.signal is not None:
            violations.append(
                f"expected exit code {expectation.exit_code} but the process was "
                f"killed by {execution.signal_name}"
            )
        elif execution.exit_code != expectation.exit_code:
            violations.append(
                f"expected exit code {expectation.exit_code}, got {execution.exit_code}"
            )

    if expectation.stdout_exact is not None:
        if execution.stdout != expectation.stdout_exact:
            violations.append(
                f"stdout did not match exactly "
                f"(expected {expectation.stdout_exact!r}, got {execution.stdout!r})"
            )

    for needle in expectation.stdout_contains:
        if needle not in execution.stdout:
            violations.append(f"stdout did not contain {needle!r}")

    if expectation.stdout_regex:
        if not re.search(expectation.stdout_regex, execution.stdout, re.MULTILINE):
            violations.append(f"stdout did not match /{expectation.stdout_regex}/")

    for needle in expectation.stderr_contains:
        if needle not in execution.stderr:
            violations.append(f"stderr did not contain {needle!r}")

    if expectation.max_duration_s is not None and execution.duration_s > expectation.max_duration_s:
        violations.append(
            f"took {execution.duration_s:.2f}s, expected at most "
            f"{expectation.max_duration_s}s"
        )

    violations.extend(_check_output_files(execution, expectation))

    return OracleCheck(
        test_id=test.test_id,
        version=execution.version,
        profile=execution.profile,
        execution_id=execution.execution_id,
        outcome=TestOutcome.FAIL if violations else TestOutcome.PASS,
        violations=violations,
        expected_summary=_summarise_expectation(expectation),
        actual_summary=_summarise_actual(execution),
    )


def detect_regressions(
    checks: list[OracleCheck], tests: list[TestCaseSpec]
) -> list[FunctionalRegression]:
    """Find tests that the base version satisfied and the patched version broke.

    Comparison is strictly within one build profile: mixing a release base
    against a sanitized patched build would compare different programs.
    """
    by_test = {test.test_id: test for test in tests}
    index: dict[tuple[str, BuildProfile, Version], OracleCheck] = {
        (check.test_id, check.profile, check.version): check for check in checks
    }

    regressions: list[FunctionalRegression] = []
    for (test_id, profile, version), check in index.items():
        if version != Version.BASE or check.outcome != TestOutcome.PASS:
            continue

        test = by_test.get(test_id)
        if test is None:
            continue

        # Without a recorded, independent criterion we have nothing to call a
        # regression *against*, so the pair is skipped rather than guessed at.
        if not has_independent_oracle(test):
            continue

        patched = index.get((test_id, profile, Version.PATCHED))
        if patched is None or patched.outcome != TestOutcome.FAIL:
            continue

        regressions.append(
            FunctionalRegression(
                test_id=test_id,
                profile=profile,
                base_check=check,
                patched_check=patched,
                violations=list(patched.violations),
                base_execution_id=check.execution_id,
                patched_execution_id=patched.execution_id,
            )
        )

    regressions.sort(key=lambda r: (r.test_id, r.profile.value))
    return regressions


def oracle_coverage(tests: list[TestCaseSpec]) -> tuple[int, int]:
    """How many tests carry a usable independent oracle, out of the total.

    Surfaced in the report so a reviewer can see how much of the suite can
    actually support a regression claim.
    """
    usable = sum(1 for test in tests if has_independent_oracle(test))
    return usable, len(tests)
