"""Input delivery and output-file checking.

A validator that can only feed stdin and only read stdout cannot express the
correctness criterion of a program that takes a filename and writes a report.
These tests cover the three delivery mechanisms and the output-file oracle,
including the ways each can be misconfigured.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dynan.config.loader import ConfigError
from dynan.config.testsuite import load_manifest, validate_delivery
from dynan.domain.enums import (
    BuildProfile,
    InputDelivery,
    TestCategory,
    TestOutcome,
    Version,
)
from dynan.domain.models import (
    CapturedFile,
    ExecutionResult,
    OracleExpectation,
    OutputFileExpectation,
    TestCaseSpec,
)
from dynan.app.oracle import check_execution


def write_manifest(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "m.yaml"
    path.write_text("version: 1\ntests:\n" + body)
    return path


# --------------------------------------------------------------------------
# Manifest parsing
# --------------------------------------------------------------------------


def test_output_file_singular_and_plural_forms(tmp_path):
    manifest = write_manifest(
        tmp_path,
        """
  - id: t1
    input: 'x'
    expect:
      output_file:
        path: a.txt
        exact: "hello"
  - id: t2
    input: 'x'
    expect:
      output_files:
        - path: b.txt
          contains: ["one", "two"]
        - c.txt
""",
    )
    t1, t2 = load_manifest(manifest)
    assert t1.expectation.output_files[0].exact == "hello"
    assert t2.expectation.output_files[0].contains == ["one", "two"]
    # A bare string means "this file must exist".
    assert t2.expectation.output_files[1].path == "c.txt"
    assert t2.expectation.output_files[1].exists is True


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("/etc/passwd", "must be relative"),
        ("../escape.txt", "must be relative"),
        ("sub/../../out.txt", "must be relative"),
    ],
)
def test_output_path_cannot_escape_the_working_directory(tmp_path, path, message):
    manifest = write_manifest(
        tmp_path, f"\n  - id: t\n    input: 'x'\n    expect:\n      output_file: {path}\n"
    )
    with pytest.raises(ConfigError, match=message):
        load_manifest(manifest)


def test_absent_file_cannot_also_assert_content(tmp_path):
    manifest = write_manifest(
        tmp_path,
        """
  - id: t
    input: 'x'
    expect:
      output_file:
        path: a.txt
        exists: false
        exact: "something"
""",
    )
    with pytest.raises(ConfigError, match="cannot be both absent and matching"):
        load_manifest(manifest)


def test_duplicate_output_path_is_rejected(tmp_path):
    manifest = write_manifest(
        tmp_path,
        """
  - id: t
    input: 'x'
    expect:
      output_files:
        - path: a.txt
        - path: a.txt
""",
    )
    with pytest.raises(ConfigError, match="duplicate output file path"):
        load_manifest(manifest)


def test_invalid_output_regex_is_rejected(tmp_path):
    manifest = write_manifest(
        tmp_path,
        "\n  - id: t\n    input: 'x'\n    expect:\n"
        "      output_file:\n        path: a.txt\n        regex: '([unclosed'\n",
    )
    with pytest.raises(ConfigError, match="regex is invalid"):
        load_manifest(manifest)


# --------------------------------------------------------------------------
# Delivery validation
# --------------------------------------------------------------------------


def spec(delivery: InputDelivery, argv: list[str] | None = None) -> TestCaseSpec:
    return TestCaseSpec(
        test_id="t",
        category=TestCategory.VALID,
        delivery=delivery,
        argv=argv or [],
        input_bytes=b"x",
    )


def test_file_delivery_without_input_placeholder_is_rejected():
    """Otherwise the input silently never reaches the program, and the test
    'fails' for a reason unrelated to the patch."""
    with pytest.raises(ConfigError, match=r"contains \{input\}"):
        validate_delivery([spec(InputDelivery.FILE)], ["{binary}"])


def test_argv_delivery_without_input_placeholder_is_rejected():
    with pytest.raises(ConfigError, match=r"contains \{input\}"):
        validate_delivery([spec(InputDelivery.ARGV)], ["{binary}"])


def test_placeholder_may_come_from_the_test_itself():
    """A stdin-by-default suite may still hold one file-delivery test."""
    validate_delivery([spec(InputDelivery.FILE, ["{input}"])], ["{binary}"])


def test_placeholder_may_come_from_execution_argv():
    validate_delivery([spec(InputDelivery.FILE)], ["{binary}", "{input}"])


def test_stdin_delivery_needs_no_placeholder():
    validate_delivery([spec(InputDelivery.STDIN)], ["{binary}"])


def test_fuzz_file_delivery_without_placeholder_is_rejected(config_factory):
    with pytest.raises(Exception, match=r"contains \{input\}"):
        config_factory(
            "correct",
            extra=(
                "extensions:\n"
                "  enabled: [fuzz]\n"
                "  fuzz:\n"
                "    enabled: true\n"
                "    strategy: mutation\n"
                "    delivery: file\n"
            ),
        )


def test_fuzz_file_delivery_with_its_own_argv_is_accepted(config_factory):
    config = config_factory(
        "correct",
        extra=(
            "extensions:\n"
            "  enabled: [fuzz]\n"
            "  fuzz:\n"
            "    enabled: true\n"
            "    strategy: mutation\n"
            "    delivery: file\n"
            "    argv: ['{input}']\n"
        ),
    )
    assert config.fuzz_delivery() is InputDelivery.FILE


def test_fuzz_delivery_defaults_to_the_suite_mechanism(config_factory):
    config = config_factory("correct")
    assert config.fuzz_delivery() is config.execution.delivery


# --------------------------------------------------------------------------
# Output-file oracle
# --------------------------------------------------------------------------


def execution(captured: list[CapturedFile], exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(
        execution_id="e",
        test_id="t",
        version=Version.PATCHED,
        profile=BuildProfile.RELEASE,
        argv=["/bin/true"],
        cwd="/tmp",
        delivery=InputDelivery.STDIN,
        exit_code=exit_code,
        output_files=captured,
    )


def case(*expectations: OutputFileExpectation) -> TestCaseSpec:
    """A test case asserting only on output files."""
    return TestCaseSpec(
        test_id="t",
        category=TestCategory.VALID,
        input_bytes=b"x",
        expectation=OracleExpectation(
            output_files=list(expectations), provenance="SPEC"
        ),
    )


def test_matching_output_file_passes():
    check = check_execution(
        execution([CapturedFile(path="a.txt", exists=True, size=2, text="ok")]),
        case(OutputFileExpectation(path="a.txt", exact="ok")),
    )
    assert check.outcome is TestOutcome.PASS


def test_missing_output_file_fails():
    check = check_execution(
        execution([CapturedFile(path="a.txt", exists=False)]),
        case(OutputFileExpectation(path="a.txt", exact="ok")),
    )
    assert check.outcome is TestOutcome.FAIL
    assert "was not created" in check.violations[0]


def test_wrong_output_content_fails():
    check = check_execution(
        execution([CapturedFile(path="a.txt", exists=True, text="nope")]),
        case(OutputFileExpectation(path="a.txt", exact="ok")),
    )
    assert check.outcome is TestOutcome.FAIL
    assert "did not match exactly" in check.violations[0]


def test_empty_output_file_is_distinguishable_from_a_missing_one():
    """`exact: ""` must mean "exists and is empty", not "absent"."""
    present = check_execution(
        execution([CapturedFile(path="a.txt", exists=True, size=0, text="")]),
        case(OutputFileExpectation(path="a.txt", exact="")),
    )
    absent = check_execution(
        execution([CapturedFile(path="a.txt", exists=False)]),
        case(OutputFileExpectation(path="a.txt", exact="")),
    )
    assert present.outcome is TestOutcome.PASS
    assert absent.outcome is TestOutcome.FAIL


def test_exists_false_is_violated_by_a_present_file():
    check = check_execution(
        execution([CapturedFile(path="a.txt", exists=True, text="leftover")]),
        case(OutputFileExpectation(path="a.txt", exists=False)),
    )
    assert check.outcome is TestOutcome.FAIL
    assert "expected not to" in check.violations[0]


def test_contains_and_regex_on_output_file():
    captured = [CapturedFile(path="a.txt", exists=True, text="alpha\nbeta\n")]
    passing = check_execution(
        execution(captured),
        case(
            OutputFileExpectation(path="a.txt", contains=["alpha"], regex=r"^beta$")
        ),
    )
    failing = check_execution(
        execution(captured),
        case(OutputFileExpectation(path="a.txt", contains=["gamma"])),
    )
    assert passing.outcome is TestOutcome.PASS
    assert failing.outcome is TestOutcome.FAIL


def test_unreadable_output_file_is_reported_as_such():
    check = check_execution(
        execution([CapturedFile(path="a.txt", exists=True, error="permission denied")]),
        case(OutputFileExpectation(path="a.txt", exact="ok")),
    )
    assert check.outcome is TestOutcome.FAIL
    assert "could not be read" in check.violations[0]


def test_truncated_file_cannot_be_compared_exactly():
    """Comparing a truncated capture against `exact` would be a false pass."""
    check = check_execution(
        execution(
            [CapturedFile(path="a.txt", exists=True, size=10**7, text="ab", truncated=True)]
        ),
        case(OutputFileExpectation(path="a.txt", exact="ab")),
    )
    assert check.outcome is TestOutcome.FAIL
    assert "too large to compare" in check.violations[0]


def test_output_file_assertion_makes_a_test_an_independent_oracle():
    """A file-output program's correctness criterion must count as an oracle,
    otherwise its regressions could never be detected."""
    from dynan.config.testsuite import has_independent_oracle

    assert has_independent_oracle(
        case(OutputFileExpectation(path="a.txt", exact="ok"))
    )


def test_bare_existence_is_not_an_independent_oracle():
    """"The file was created" is a safety check, not a statement about what
    the program computed - so it must not license a regression claim."""
    from dynan.config.testsuite import has_independent_oracle

    assert not has_independent_oracle(case(OutputFileExpectation(path="a.txt")))


def test_asserted_absence_is_an_independent_oracle():
    from dynan.config.testsuite import has_independent_oracle

    assert has_independent_oracle(
        case(OutputFileExpectation(path="a.txt", exists=False))
    )
