"""End-to-end validation against real compiled C fixtures.

These tests compile and execute genuine vulnerable and patched programs. No
finding here is mocked: a mocked finding would prove nothing about a tool
whose whole purpose is dynamic analysis, and the specification is explicit
that claims must rest on real execution.

Each of the four official scenarios is asserted on its required exit code.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import requires_sanitizers, requires_toolchain
from dynan.app.service import ValidationService
from dynan.domain.enums import (
    BuildProfile,
    Confidence,
    CorrelationVerdict,
    ExitCode,
    FindingStatus,
    RunState,
    Severity,
    Version,
)

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def _run(config_factory, variant: str, **kwargs):
    config = config_factory(variant, **kwargs)
    service = ValidationService.for_config(config)
    return service, service.validate(config)


@pytest.fixture(scope="module")
def sandbox_backend() -> str:
    """Prefer real isolation; fall back only if namespaces are unavailable here."""
    from dynan.infra.sandbox import BwrapSandbox

    return "bwrap" if BwrapSandbox().selftest().ok else "none"


# ------------------------------------------------- the four scenarios


@requires_toolchain
@requires_sanitizers
def test_correct_patch_passes(config_factory, sandbox_backend):
    """Scenario 2: the vulnerability is gone and functional tests still pass."""
    _service, run = _run(config_factory, "correct", sandbox=sandbox_backend)

    assert run.decision.exit_code is ExitCode.PASS
    assert run.state is RunState.COMPLETED
    assert run.decision.security_status.value == "pass"
    assert run.decision.functional_status.value == "pass"
    assert run.decision.analysis_completeness.value == "complete"

    # A PASS is only meaningful if the baseline was actually reproduced.
    assert any(c.is_targeted_baseline for c in run.comparisons)
    assert all(
        c.status in (FindingStatus.FIXED, FindingStatus.UNCHANGED)
        for c in run.comparisons
    )


@requires_toolchain
@requires_sanitizers
def test_incomplete_patch_reports_vuln_remains(config_factory, sandbox_backend):
    """Scenario 3: only the '=' path is guarded, so ':' still reaches the sink."""
    _service, run = _run(config_factory, "incomplete", sandbox=sandbox_backend)

    assert run.decision.exit_code is ExitCode.VULN_REMAINS
    assert run.decision.security_status.value == "vuln_remains"

    remaining = [c for c in run.comparisons if c.status is FindingStatus.INCOMPLETE_FIX]
    assert remaining, "the surviving vulnerability must be classified"
    assert remaining[0].confidence is Confidence.CONFIRMED

    # It must be reachable through the colon path specifically.
    surviving_tests = {t for c in remaining for t in c.test_ids}
    assert "security_oversized_value_colon" in surviving_tests


@requires_toolchain
@requires_sanitizers
def test_regression_patch_reports_functional_regression(config_factory, sandbox_backend):
    """Scenario 4: memory-safe, but it breaks input the specification allows."""
    _service, run = _run(config_factory, "regression", sandbox=sandbox_backend)

    assert run.decision.exit_code is ExitCode.FUNC_REGRESSION
    assert run.decision.functional_status.value == "regression"
    # Security and functionality are tracked independently.
    assert run.decision.security_status.value == "pass"

    broken = {r.test_id for r in run.regressions}
    assert "valid_twelve_char_value" in broken

    for regression in run.regressions:
        # Both halves of the evidence the PDF demands must be present.
        assert regression.base_check.outcome.value == "pass"
        assert regression.patched_check.outcome.value == "fail"
        assert regression.violations


@requires_toolchain
def test_broken_build_is_a_configuration_error(config_factory, tmp_path, sandbox_backend):
    """Scenario: the target does not compile. Must be 30, never a security code."""
    config = config_factory("correct", sandbox=sandbox_backend)
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "src").mkdir()
    (broken / "src" / "confparse.c").write_text("this is not valid C;\n")
    (broken / "Makefile").write_text(
        "CC ?= cc\nCFLAGS ?= -O2\nall:\n\tmkdir -p build\n"
        "\t$(CC) $(CFLAGS) -o build/confparse src/confparse.c\nclean:\n\trm -rf build\n"
    )
    config = config.model_copy(
        update={"source": config.source.model_copy(update={"patched_path": str(broken)})}
    )

    service = ValidationService.for_config(config)
    run = service.validate(config)

    assert run.decision.exit_code is ExitCode.BUILD_OR_CONFIG_ERROR
    assert run.decision.security_status.value == "not_assessed"
    # A failed validation still preserves whatever report was obtainable.
    assert service.store.paths(run.run_id).results.is_file()
    assert run.diff is not None


# ------------------------------------------------- mandatory capabilities


@requires_toolchain
@requires_sanitizers
def test_profiles_are_observed_and_reported_separately(config_factory, sandbox_backend):
    """PDF 3.2: release and instrumented results must not be mixed."""
    _service, run = _run(config_factory, "correct", sandbox=sandbox_backend)

    profiles = {b.profile for b in run.builds if b.success}
    assert profiles == {BuildProfile.RELEASE, BuildProfile.SANITIZED}

    # The two profiles must be distinct binaries, not one overwriting the other.
    hashes = {b.key: b.binary_sha256 for b in run.builds}
    assert hashes["base/release"] != hashes["base/sanitized"]
    assert len({h for h in hashes.values() if h}) == 4

    # Each comparison belongs to exactly one profile.
    assert all(c.profile in profiles for c in run.comparisons)

    # The uninstrumented binary detects the overflow through its own guard,
    # which is a different mechanism from the sanitizer's.
    mechanisms = {
        (f.profile, f.signature.detection.value)
        for f in run.findings
        if f.version is Version.BASE
    }
    release = {m for p, m in mechanisms if p is BuildProfile.RELEASE}
    sanitized = {m for p, m in mechanisms if p is BuildProfile.SANITIZED}
    assert release and sanitized and release != sanitized


@requires_toolchain
@requires_sanitizers
def test_reproduction_minimisation_and_regression_generation(
    config_factory, sandbox_backend, tmp_path
):
    """PDF 3.3: >= 3 replays, signature-preserving minimisation, promoted tests."""
    service, run = _run(config_factory, "correct", sandbox=sandbox_backend)

    assert run.reproductions
    for repro in run.reproductions:
        assert repro.total_attempts >= 3
        assert repro.stable
        # The bundle must contain everything needed to re-run by hand.
        for name in ("input.bin", "metadata.json", "reproduce.sh"):
            assert service.store.resolve_artifact(
                run.run_id, f"{repro.bundle_path}/{name}"
            ).is_file()

        metadata = json.loads(
            service.read_artifact(run.run_id, f"{repro.bundle_path}/metadata.json")
        )
        assert metadata["binary"]["sha256"]
        assert metadata["execution"]["argv"]
        assert metadata["revision"]

    assert run.minimizations
    for minimization in run.minimizations:
        assert minimization.minimized_size <= minimization.original_size
        assert minimization.verified, "the stored minimised input must still fail"
        assert minimization.preserved_signature

    assert run.generated_tests
    for generated in run.generated_tests:
        assert generated.verified_fails_on_base is True
        assert generated.verified_passes_on_patched is True
        assert Path(generated.manifest_path).is_file()


@requires_toolchain
@requires_sanitizers
def test_generated_suite_feeds_the_next_run(config_factory, sandbox_backend):
    """A promoted regression test must actually participate in later runs."""
    config = config_factory("correct", sandbox=sandbox_backend)
    service = ValidationService.for_config(config)

    first = service.validate(config)
    assert first.generated_tests
    promoted = {g.test_id for g in first.generated_tests}

    second = service.validate(config)
    assert promoted <= {t.test_id for t in second.tests}
    assert second.decision.exit_code is ExitCode.PASS


@requires_toolchain
@requires_sanitizers
def test_correlation_links_the_fix_to_the_changed_function(
    config_factory, sandbox_backend
):
    """PDF 3.1: findings must be tied to the diff with real evidence."""
    _service, run = _run(config_factory, "correct", sandbox=sandbox_backend)

    assert run.diff is not None
    assert "store_value" in run.diff.all_changed_functions()

    located = [
        c for c in run.correlations
        if c.verdict in (CorrelationVerdict.DIRECT, CorrelationVerdict.INDIRECT)
    ]
    assert located, "the fixed defect sits in changed code and must be linked"

    for correlation in located:
        assert correlation.evidence
        assert correlation.rationale
        # Every signal names where it came from or what it observed.
        assert all(e.description for e in correlation.evidence)


@requires_toolchain
@requires_sanitizers
def test_hardening_is_compared_between_versions(config_factory, sandbox_backend):
    _service, run = _run(config_factory, "correct", sandbox=sandbox_backend)

    assert run.hardening and run.hardening.base and run.hardening.patched
    names = {c.property_name for c in run.hardening.changes}
    assert {"NX", "PIE", "RELRO", "Stack Canary"} <= names
    assert run.hardening.base.relro_level.value in ("none", "partial", "full")
    # The caveats the specification insists on must be stated.
    assert any("ASLR" in c for c in run.hardening.base.caveats)
    assert any("canary" in c.lower() for c in run.hardening.base.caveats)


@requires_toolchain
@requires_sanitizers
def test_every_finding_references_real_evidence(config_factory, sandbox_backend):
    service, run = _run(config_factory, "incomplete", sandbox=sandbox_backend)

    for finding in run.findings:
        execution = run.execution(finding.execution_id)
        assert execution is not None, "a finding must point at a real execution"
        assert execution.stderr_artifact
        assert service.store.resolve_artifact(
            run.run_id, execution.stderr_artifact
        ).is_file()
        if finding.severity is Severity.MEMORY_SAFETY:
            assert finding.raw_report_artifact


# ------------------------------------------------------ CLI and the UI


@requires_toolchain
@requires_sanitizers
def test_cli_exit_code_matches_the_decision(config_factory, sandbox_backend):
    """The CLI must work standalone, with no web server involved."""
    config = config_factory("incomplete", sandbox=sandbox_backend)
    result = subprocess.run(
        [sys.executable, "-m", "dynan.cli.main", "validate",
         "--config", config.config_path, "--quiet"],
        capture_output=True, text=True, timeout=900,
    )
    assert result.returncode == ExitCode.VULN_REMAINS.value, result.stderr[-2000:]


@requires_toolchain
@requires_sanitizers
def test_cli_run_is_visible_in_the_web_ui_without_re_execution(
    config_factory, sandbox_backend
):
    """A run created by the CLI must open in the GUI, with identical data."""
    from fastapi.testclient import TestClient

    from dynan.web.app import create_app

    config = config_factory("correct", sandbox=sandbox_backend)
    service = ValidationService.for_config(config)
    run = service.validate(config)

    client = TestClient(create_app(artifacts_root=config.artifacts.root))

    listing = client.get("/api/v1/runs").json()
    assert run.run_id in {r["run_id"] for r in listing["runs"]}

    api = client.get(f"/api/v1/runs/{run.run_id}").json()
    assert api["decision"]["exit_code"] == run.decision.exit_code.value
    assert api["decision"]["security_status"] == run.decision.security_status.value
    assert len(api["findings"]) == len(run.findings)

    page = client.get(f"/runs/{run.run_id}")
    assert page.status_code == 200
    assert run.decision.exit_code.name in page.text


@requires_toolchain
@requires_sanitizers
def test_cli_json_output_matches_the_stored_run(config_factory, tmp_path, sandbox_backend):
    config = config_factory("correct", sandbox=sandbox_backend)
    out = tmp_path / "result.json"

    subprocess.run(
        [sys.executable, "-m", "dynan.cli.main", "validate",
         "--config", config.config_path, "--quiet", "--json-out", str(out)],
        capture_output=True, text=True, timeout=900,
    )

    emitted = json.loads(out.read_text())
    service = ValidationService.for_config(config)
    stored = service.get_run(emitted["run_id"])

    assert emitted["decision"]["exit_code"] == stored.decision.exit_code.value
    assert emitted["schema_version"] == stored.schema_version
    assert emitted["dynan_version"] == stored.dynan_version


def test_disabled_llm_extension_makes_no_requests(config_factory, monkeypatch):
    """An optional feature that is off must not reach the network at all."""
    import dynan.ext.llm.provider as provider_module

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the disabled LLM extension attempted a request")

    monkeypatch.setattr(provider_module.LlmProvider, "complete", explode)

    config = config_factory("correct")
    assert config.extensions.llm.enabled is False
    assert config.extensions.enabled == []

    from dynan.ext.registry import load_enabled

    assert load_enabled(config) == []
