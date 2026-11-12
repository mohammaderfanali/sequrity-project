"""The validation pipeline.

This is the one authoritative implementation of the workflow. The CLI and the
web UI both reach it through :mod:`dynan.app.service`; neither contains
validation logic of its own.

Design notes:

* **Stages are explicit.** Progress reported to either front end comes from
  real stage transitions and real completed-unit counts.
* **Failure is a result, not an exception.** A target that will not build, a
  missing sandbox or an unreadable test input all end in a persisted run with
  a verdict - PDF section 3.5 requires exactly that, and a failed validation
  must still preserve whatever report was obtainable.
* **Nothing is skipped silently.** When a stage cannot run it is recorded as
  failed or blocked, which the decision engine then treats as incomplete
  analysis rather than success.
"""

from __future__ import annotations

import shutil
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .. import RESULT_SCHEMA_VERSION, __version__
from ..config.loader import ConfigError
from ..config.schema import DynanConfig
from ..config.testsuite import load_manifests, read_test_input, validate_delivery
from ..domain import decision as decision_engine
from ..domain.enums import (
    AnalysisCompleteness,
    BuildProfile,
    Confidence,
    ExitCode,
    FunctionalStatus,
    HardeningDelta,
    HardeningState,
    RunState,
    SecurityStatus,
    Severity,
    Stage,
    StageState,
    Version,
)
from ..domain.models import (
    BinaryHardening,
    BuildResult,
    Decision,
    DecisionReason,
    Finding,
    HardeningChange,
    HardeningComparison,
    MinimizationResult,
    StructuredDiff,
    TestCaseSpec,
    ValidationRun,
)
from ..infra import diffing, elf
from ..infra.build import BuildExecutor
from ..infra.runner import ExecutionRequest, TargetRunner, make_execution_id
from ..infra.sandbox import Sandbox, SandboxUnavailable, build_sandbox
from ..infra.source import PreparedSources, SourceError, resolve_sources
from ..infra.store import RunStore
from . import classify, compare, correlate, doctor, minimize, oracle, regression
from . import signature as signature_mod
from .events import EventEmitter
from .reproduce import ReproductionService


class PipelineAbort(RuntimeError):
    """A stage failed in a way that makes continuing pointless."""


@dataclass
class _State:
    """Mutable working state threaded through the stages."""

    sources: PreparedSources | None = None
    diff: StructuredDiff | None = None
    raw_diff: str = ""
    builds: dict[tuple[Version, BuildProfile], BuildResult] = field(default_factory=dict)
    tests: list[TestCaseSpec] = field(default_factory=list)
    inputs: dict[str, bytes] = field(default_factory=dict)
    source_roots: list[Path] = field(default_factory=list)


class ValidationPipeline:
    """Executes one validation from source acquisition to verdict."""

    def __init__(
        self,
        config: DynanConfig,
        *,
        store: RunStore,
        emitter: EventEmitter,
        run_id: str,
    ) -> None:
        self.config = config
        self.store = store
        self.emitter = emitter
        self.run_id = run_id
        self.run = ValidationRun(
            schema_version=RESULT_SCHEMA_VERSION,
            run_id=run_id,
            dynan_version=__version__,
            target_name=config.target.name,
            config_snapshot=config.model_dump(mode="json"),
            config_path=config.config_path or None,
            state=RunState.RUNNING,
        )
        self.state = _State()
        self.sandbox: Sandbox | None = None

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def execute(self) -> ValidationRun:
        """Run every stage, always producing a persisted, decided run."""
        try:
            self._stage_preflight()
            self._stage_source()
            self._stage_diff()
            self._stage_build()
            self._stage_execute()
            self._stage_analyze()
            self._stage_correlate()
            self._stage_reproduce()
            self._stage_minimize()
            self._stage_regression()
            self._stage_hardening()
            self._stage_extensions()
        except PipelineAbort as exc:
            self.run.errors.append(str(exc))
            self.emitter.emit(str(exc), level="error")
        except Exception as exc:  # unexpected - still produce a report
            detail = f"internal error: {exc}"
            self.run.errors.append(detail)
            self.emitter.emit(detail, level="error", traceback=traceback.format_exc())
        finally:
            self._stage_decide()
            self._finalise()

        return self.run

    # ------------------------------------------------------------------
    # Stages
    # ------------------------------------------------------------------

    def _stage_preflight(self) -> None:
        self.emitter.start_stage(Stage.PREFLIGHT, "checking the environment")

        report = doctor.run_doctor(self.config)
        self.run.doctor = report

        for diagnostic in report.blocking:
            self.emitter.emit(
                f"{diagnostic.name}: {diagnostic.detail}",
                stage=Stage.PREFLIGHT,
                level="error",
            )

        if report.blocking:
            names = ", ".join(d.name for d in report.blocking)
            self.emitter.finish_stage(
                Stage.PREFLIGHT,
                StageState.FAILED,
                f"blocking environment problems: {names}",
            )
            # A missing mandatory dependency is a configuration/environment
            # error, never a security conclusion.
            raise PipelineAbort(
                f"environment is not ready: {names}. Run 'dynan doctor' for details."
            )

        try:
            self.sandbox = build_sandbox(self.config.sandbox)
        except SandboxUnavailable as exc:
            self.emitter.finish_stage(Stage.PREFLIGHT, StageState.FAILED, str(exc))
            raise PipelineAbort(str(exc)) from exc

        self._load_tests()

        self.emitter.finish_stage(
            Stage.PREFLIGHT,
            StageState.COMPLETED,
            f"environment ready; sandbox={self.sandbox.describe()}; "
            f"{len(self.state.tests)} test(s) loaded",
        )

    def _load_tests(self) -> None:
        manifests = list(self.config.tests.manifests)

        # The generated regression suite is just another manifest, so promoted
        # tests participate exactly like hand-written ones.
        if self.config.tests.include_generated:
            generated = Path(self.config.tests.regression_suite) / regression.MANIFEST_NAME
            if generated.is_file() and str(generated) not in manifests:
                manifests.append(str(generated))
                self.emitter.emit(
                    f"including generated regression suite: {generated}",
                    stage=Stage.PREFLIGHT,
                )

        try:
            tests = load_manifests(manifests)
        except ConfigError as exc:
            raise PipelineAbort(f"test suite could not be loaded: {exc}") from exc

        if not tests:
            raise PipelineAbort("the configured test manifests define no tests")

        try:
            validate_delivery(tests, self.config.execution.argv)
        except ConfigError as exc:
            raise PipelineAbort(str(exc)) from exc

        for spec in tests:
            try:
                self.state.inputs[spec.test_id] = read_test_input(spec)
            except ConfigError as exc:
                raise PipelineAbort(str(exc)) from exc

        self.state.tests = tests
        self.run.tests = tests

        usable, _total = oracle.oracle_coverage(tests)
        if usable == 0:
            self.run.warnings.append(
                "No test defines an independent oracle (provenance plus a concrete "
                "assertion), so no functional regression can be established."
            )

    # -- source ---------------------------------------------------------

    def _stage_source(self) -> None:
        self.emitter.start_stage(Stage.SOURCE, "resolving source versions")
        workspace = self.store.paths(self.run_id).sources

        try:
            prepared = resolve_sources(
                self.config, workspace=workspace, cache_dir=self.store.cache_dir
            )
        except SourceError as exc:
            self.emitter.finish_stage(Stage.SOURCE, StageState.FAILED, str(exc))
            raise PipelineAbort(f"source resolution failed: {exc}") from exc

        self.state.sources = prepared
        self.state.source_roots = [prepared.base_dir, prepared.patched_dir]
        self.run.sources = prepared.pair

        for revision in (prepared.pair.base, prepared.pair.patched):
            if not revision.is_exact_vcs_revision:
                self.run.warnings.append(
                    f"{revision.version.value} source is identified by content hash "
                    f"{revision.content_hash[:12]}, not an exact VCS revision"
                )

        self.emitter.finish_stage(
            Stage.SOURCE,
            StageState.COMPLETED,
            f"base={prepared.pair.base.display_revision} "
            f"patched={prepared.pair.patched.display_revision}",
        )

    # -- diff -----------------------------------------------------------

    def _stage_diff(self) -> None:
        self.emitter.start_stage(Stage.DIFF, "computing the patch diff")
        prepared = self.state.sources
        assert prepared is not None

        try:
            structured, raw = diffing.compute_diff(
                base_dir=prepared.base_dir,
                patched_dir=prepared.patched_dir,
                repo=prepared.repo,
                base_commit=prepared.base_commit,
                patched_commit=prepared.patched_commit,
            )
        except Exception as exc:
            self.emitter.finish_stage(Stage.DIFF, StageState.FAILED, str(exc))
            raise PipelineAbort(f"diff generation failed: {exc}") from exc

        structured.raw_diff_artifact = self.store.write_artifact(
            self.run_id, "diff.patch", raw
        )

        if self.config.source.patch_file:
            structured.externally_supplied = True
            warning = diffing.check_external_patch(
                raw, Path(self.config.source.patch_file)
            )
            if warning:
                structured.consistency_warning = warning
                self.run.warnings.append(warning)

        self.state.diff = structured
        self.state.raw_diff = raw
        self.run.diff = structured

        if structured.is_empty:
            self.run.warnings.append(
                "The two source versions are identical; there is no patch to validate."
            )

        self.emitter.finish_stage(
            Stage.DIFF,
            StageState.COMPLETED,
            f"{structured.files_changed} file(s) changed, "
            f"+{structured.total_added}/-{structured.total_removed}",
            files=structured.files_changed,
        )

    # -- build ----------------------------------------------------------

    def _stage_build(self) -> None:
        self.emitter.start_stage(Stage.BUILD, "building all four profiles")
        prepared = self.state.sources
        assert prepared is not None and self.sandbox is not None

        executor = BuildExecutor(
            self.config, sandbox=self.sandbox, store=self.store, run_id=self.run_id
        )

        # Each profile gets its own copy of the tree. Targets normally build
        # to a fixed output path, so building both profiles in one tree would
        # leave the second binary overwriting the first - and every "release"
        # observation would silently come from the instrumented binary. The
        # specification requires these two to stay separate, so the isolation
        # is structural rather than a convention the target has to honour.
        build_root = self.store.paths(self.run_id).sources / "build"
        targets: list[tuple[Version, BuildProfile, Path]] = []
        for version, canonical in (
            (Version.BASE, prepared.base_dir),
            (Version.PATCHED, prepared.patched_dir),
        ):
            for profile in (BuildProfile.RELEASE, BuildProfile.SANITIZED):
                tree = build_root / f"{version.value}-{profile.value}"
                if tree.exists():
                    shutil.rmtree(tree)
                tree.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(canonical, tree, symlinks=True)
                targets.append((version, profile, tree))
                self.state.source_roots.append(tree)

        failures: list[str] = []
        for index, (version, profile, source_dir) in enumerate(targets, start=1):
            self.emitter.progress(
                Stage.BUILD,
                index - 1,
                len(targets),
                f"building {version.value}/{profile.value}",
            )
            result = executor.build(version, profile, source_dir)
            self.state.builds[(version, profile)] = result
            self.run.builds.append(result)

            if result.success:
                digest = (result.binary_sha256 or "")[:12] or "n/a"
                self.emitter.emit(f"built {result.key} ({digest})", stage=Stage.BUILD)
            else:
                failures.append(f"{result.key}: {result.error}")
                self.emitter.emit(
                    f"build failed for {result.key}: {result.error}",
                    stage=Stage.BUILD,
                    level="error",
                )

        self.emitter.progress(Stage.BUILD, len(targets), len(targets), "builds finished")

        if failures:
            self.emitter.finish_stage(Stage.BUILD, StageState.FAILED, "; ".join(failures))
            raise PipelineAbort("required builds failed: " + "; ".join(failures))

        self.emitter.finish_stage(
            Stage.BUILD, StageState.COMPLETED, "all four builds succeeded"
        )

    # -- execute --------------------------------------------------------

    def _runner(self) -> TargetRunner:
        assert self.sandbox is not None
        return TargetRunner(
            self.config, sandbox=self.sandbox, store=self.store, run_id=self.run_id
        )

    def _stage_execute(self) -> None:
        self.emitter.start_stage(Stage.EXECUTE, "running the test suite")

        runner = self._runner()
        profiles = list(self.config.analysis.profiles)
        total = len(self.state.tests) * len(profiles) * 2
        done = 0

        for profile in profiles:
            for version in (Version.BASE, Version.PATCHED):
                build = self.state.builds.get((version, profile))
                if build is None or not build.success:
                    continue
                for spec in self.state.tests:
                    execution = runner.execute(
                        ExecutionRequest(
                            test=spec,
                            build=build,
                            input_bytes=self.state.inputs[spec.test_id],
                            execution_id=make_execution_id(spec.test_id, version, profile),
                        )
                    )
                    self.run.executions.append(execution)
                    done += 1
                    self.emitter.progress(
                        Stage.EXECUTE,
                        done,
                        total,
                        f"{version.value}/{profile.value} {spec.test_id}",
                    )

        self.emitter.finish_stage(
            Stage.EXECUTE,
            StageState.COMPLETED,
            f"{len(self.run.executions)} execution(s) recorded",
        )

    # -- analyze --------------------------------------------------------

    def _stage_analyze(self) -> None:
        self.emitter.start_stage(Stage.ANALYZE, "classifying results")
        by_id = {t.test_id: t for t in self.state.tests}

        for execution in self.run.executions:
            spec = by_id.get(execution.test_id)
            if spec is None:
                continue

            finding, report = classify.classify_execution(
                execution, spec, source_roots=self.state.source_roots
            )
            if finding is not None:
                if report is not None and report.raw:
                    finding.raw_report_artifact = self.store.write_artifact(
                        self.run_id,
                        f"evidence/findings/{_safe(finding.finding_id)}.report.txt",
                        report.raw,
                    )
                self.run.findings.append(finding)
                self.emitter.emit(
                    f"{execution.version.value}/{execution.profile.value} "
                    f"{execution.test_id}: {finding.signature.describe()}",
                    stage=Stage.ANALYZE,
                    level="warning",
                )

            self.run.oracle_checks.append(oracle.check_execution(execution, spec))

        self.run.comparisons = compare.compare_findings(self.run.findings)
        self.run.regressions = oracle.detect_regressions(
            self.run.oracle_checks, self.state.tests
        )

        self.emitter.finish_stage(
            Stage.ANALYZE,
            StageState.COMPLETED,
            f"{len(self.run.findings)} finding(s), "
            f"{len(self.run.comparisons)} signature comparison(s), "
            f"{len(self.run.regressions)} functional regression(s)",
        )

    # -- correlate ------------------------------------------------------

    def _stage_correlate(self) -> None:
        if not self.config.analysis.correlate:
            self.emitter.finish_stage(
                Stage.CORRELATE, StageState.SKIPPED, "disabled in configuration"
            )
            return

        self.emitter.start_stage(Stage.CORRELATE, "correlating findings with the diff")
        diff = self.state.diff
        if diff is None:
            self.emitter.finish_stage(
                Stage.CORRELATE, StageState.BLOCKED, "no diff available"
            )
            return

        self.run.correlations = correlate.correlate_all(
            self.run.findings,
            self.run.comparisons,
            diff,
            source_roots=self.state.source_roots,
        )
        correlate.attach_correlations(self.run.comparisons, self.run.correlations)

        conclusive = sum(1 for c in self.run.correlations if c.is_conclusive)
        self.emitter.finish_stage(
            Stage.CORRELATE,
            StageState.COMPLETED,
            f"{conclusive}/{len(self.run.correlations)} finding(s) linked to the patch",
        )

    # -- reproduce ------------------------------------------------------

    def _reproducible_findings(self) -> list[Finding]:
        """One representative finding per signature, version and profile.

        Reproducing the same signature ten times because ten inputs reached it
        would cost minutes without adding evidence.
        """
        seen: set[tuple] = set()
        selected: list[Finding] = []
        for finding in self.run.findings:
            if finding.confidence != Confidence.CONFIRMED:
                continue
            if finding.severity not in (Severity.MEMORY_SAFETY, Severity.UNDEFINED_BEHAVIOR):
                continue
            key = (finding.signature.key(), finding.version, finding.profile)
            if key in seen:
                continue
            seen.add(key)
            selected.append(finding)
        return selected

    def _stage_reproduce(self) -> None:
        candidates = self._reproducible_findings()
        self.emitter.start_stage(
            Stage.REPRODUCE, f"replaying {len(candidates)} confirmed finding(s)"
        )

        if not candidates:
            self.emitter.finish_stage(
                Stage.REPRODUCE,
                StageState.COMPLETED,
                "no confirmed security findings to reproduce",
            )
            return

        service = ReproductionService(
            runner=self._runner(),
            store=self.store,
            run_id=self.run_id,
            analysis=self.config.analysis,
            source_roots=self.state.source_roots,
        )
        by_id = {t.test_id: t for t in self.state.tests}
        prepared = self.state.sources
        assert prepared is not None

        for index, finding in enumerate(candidates, start=1):
            spec = by_id.get(finding.test_id)
            build = self.state.builds.get((finding.version, finding.profile))
            if spec is None or build is None:
                continue

            revision = (
                prepared.pair.base
                if finding.version == Version.BASE
                else prepared.pair.patched
            )
            result = service.reproduce(
                finding, spec, build, self.state.inputs[spec.test_id], revision
            )
            self.run.reproductions.append(result)

            self.emitter.progress(
                Stage.REPRODUCE,
                index,
                len(candidates),
                f"{finding.signature.describe()}: "
                f"{result.reproduced_count}/{result.total_attempts} replays",
            )
            if not result.stable:
                self.run.warnings.append(
                    f"Finding {finding.finding_id} is unstable "
                    f"({result.reproduced_count}/{result.total_attempts} replays)."
                )

        stable = sum(1 for r in self.run.reproductions if r.stable)
        self.emitter.finish_stage(
            Stage.REPRODUCE,
            StageState.COMPLETED,
            f"{stable}/{len(self.run.reproductions)} finding(s) reproduced stably",
        )

    # -- minimize -------------------------------------------------------

    def _stage_minimize(self) -> None:
        if not self.config.analysis.minimize:
            self.emitter.finish_stage(
                Stage.MINIMIZE, StageState.SKIPPED, "disabled in configuration"
            )
            return

        candidates = [
            f
            for f in self._reproducible_findings()
            if (repro := self.run.reproduction_for(f.finding_id)) and repro.stable
        ]
        self.emitter.start_stage(Stage.MINIMIZE, f"minimising {len(candidates)} input(s)")

        if not candidates:
            self.emitter.finish_stage(
                Stage.MINIMIZE,
                StageState.COMPLETED,
                "no stable findings available to minimise",
            )
            return

        runner = self._runner()
        by_id = {t.test_id: t for t in self.state.tests}

        for index, finding in enumerate(candidates, start=1):
            spec = by_id.get(finding.test_id)
            build = self.state.builds.get((finding.version, finding.profile))
            if spec is None or build is None:
                continue

            original = self.state.inputs[spec.test_id]
            if not original:
                continue

            counter = {"n": 0}

            def predicate(candidate: bytes, _spec=spec, _build=build, _f=finding) -> bool:
                counter["n"] += 1
                execution = runner.execute(
                    ExecutionRequest(
                        test=_spec,
                        build=_build,
                        input_bytes=candidate,
                        execution_id=f"minimize.{_f.finding_id}.{counter['n']}",
                        persist=False,
                    )
                )
                # Strictly the same signature at the same location - a non-zero
                # exit code is explicitly not a sufficient criterion.
                return signature_mod.preserves_signature(
                    execution, _spec, _f.signature, source_roots=self.state.source_roots
                )

            outcome = minimize.ddmin(
                original,
                predicate,
                max_iterations=self.config.analysis.minimization_max_iterations,
                timeout_s=self.config.analysis.minimization_timeout_s,
            )

            original_art = self.store.write_artifact(
                self.run_id,
                f"evidence/minimized/{_safe(finding.finding_id)}/original.bin",
                original,
            )
            minimized_art = self.store.write_artifact(
                self.run_id,
                f"evidence/minimized/{_safe(finding.finding_id)}/minimized.bin",
                outcome.data,
            )

            # Confirm the final candidate once more, persisted this time, so
            # the stored minimised input is backed by a real execution.
            verify_exec = runner.execute(
                ExecutionRequest(
                    test=spec,
                    build=build,
                    input_bytes=outcome.data,
                    execution_id=f"minimized.{finding.finding_id}",
                )
            )
            verified = signature_mod.preserves_signature(
                verify_exec, spec, finding.signature, source_roots=self.state.source_roots
            )

            result = MinimizationResult(
                finding_id=finding.finding_id,
                original_size=len(original),
                minimized_size=len(outcome.data),
                original_artifact=original_art,
                minimized_artifact=minimized_art,
                iterations=outcome.iterations,
                preserved_signature=finding.signature.describe(),
                verified=verified,
                duration_s=outcome.duration_s,
                notes="; ".join(outcome.notes),
            )
            self.run.minimizations.append(result)
            self.run.executions.append(verify_exec)

            self.emitter.progress(
                Stage.MINIMIZE,
                index,
                len(candidates),
                f"{finding.signature.error_type.value}: "
                f"{len(original)} -> {len(outcome.data)} bytes "
                f"({result.reduction_ratio:.0%} smaller)",
            )

        self.emitter.finish_stage(
            Stage.MINIMIZE,
            StageState.COMPLETED,
            f"{len(self.run.minimizations)} input(s) minimised",
        )

    # -- regression suite -----------------------------------------------

    def _stage_regression(self) -> None:
        if not self.config.analysis.generate_regression_tests:
            self.emitter.finish_stage(
                Stage.REGRESSION, StageState.SKIPPED, "disabled in configuration"
            )
            return

        self.emitter.start_stage(Stage.REGRESSION, "generating regression tests")

        # The generated test must reveal the error on the base version, so it
        # is built from confirmed findings observed on the base.
        candidates = [
            f
            for f in self._reproducible_findings()
            if f.version == Version.BASE
            and (repro := self.run.reproduction_for(f.finding_id))
            and repro.stable
        ]

        if not candidates:
            self.emitter.finish_stage(
                Stage.REGRESSION,
                StageState.COMPLETED,
                "no stable base-version findings to promote",
            )
            return

        writer = regression.RegressionSuiteWriter(
            Path(self.config.tests.regression_suite), run_id=self.run_id
        )
        writer.load_existing()

        by_id = {t.test_id: t for t in self.state.tests}
        runner = self._runner()

        for finding in candidates:
            spec = by_id.get(finding.test_id)
            if spec is None:
                continue

            minimization = self.run.minimization_for(finding.finding_id)
            if minimization and minimization.verified and minimization.minimized_artifact:
                payload = self.store.read_artifact(
                    self.run_id, minimization.minimized_artifact
                )
                minimized = True
            else:
                payload = self.state.inputs[spec.test_id]
                minimized = False

            generated = writer.emit(finding, spec, payload, minimized=minimized)

            if self.config.analysis.verify_generated_tests:
                base_build = self.state.builds.get((Version.BASE, finding.profile))
                patched_build = self.state.builds.get((Version.PATCHED, finding.profile))
                if base_build and patched_build:
                    regression.verify_generated_test(
                        generated,
                        finding,
                        spec,
                        payload,
                        runner=runner,
                        base_build=base_build,
                        patched_build=patched_build,
                        source_roots=self.state.source_roots,
                    )

        self.run.generated_tests = writer.flush()
        self.emitter.finish_stage(
            Stage.REGRESSION,
            StageState.COMPLETED,
            regression.suite_summary(self.run.generated_tests)
            + f"; suite at {writer.manifest_path}",
        )

    # -- hardening ------------------------------------------------------

    def _stage_hardening(self) -> None:
        if not self.config.analysis.hardening:
            self.emitter.finish_stage(
                Stage.HARDENING, StageState.SKIPPED, "disabled in configuration"
            )
            return

        self.emitter.start_stage(Stage.HARDENING, "inspecting ELF protections")

        # Release binaries only: the PDF asks about the protections of the
        # normally shipped artifact, and sanitizer instrumentation changes
        # several of them.
        comparison = HardeningComparison()
        for version, slot in ((Version.BASE, "base"), (Version.PATCHED, "patched")):
            build = self.state.builds.get((version, BuildProfile.RELEASE))
            if build is None or not build.success or not build.binary_path:
                continue
            try:
                report = elf.inspect_binary(
                    Path(build.binary_path),
                    version=version,
                    profile=BuildProfile.RELEASE,
                    sha256=build.binary_sha256,
                )
                setattr(comparison, slot, report)
            except (elf.ElfError, OSError) as exc:
                self.run.warnings.append(
                    f"could not inspect {version.value} binary: {exc}"
                )

        if comparison.base and comparison.patched:
            comparison.changes = compare_hardening(comparison.base, comparison.patched)

        self.run.hardening = comparison

        weakened = comparison.weakened
        if weakened:
            names = ", ".join(c.property_name for c in weakened)
            self.run.warnings.append(f"binary protections weakened by the patch: {names}")
            self.emitter.finish_stage(
                Stage.HARDENING,
                StageState.COMPLETED,
                f"protections weakened: {names}",
                level="warning",
            )
        else:
            self.emitter.finish_stage(
                Stage.HARDENING, StageState.COMPLETED, "no protections weakened"
            )

    # -- extensions -----------------------------------------------------

    def _stage_extensions(self) -> None:
        from ..ext.registry import ExtensionContext, load_enabled

        extensions = load_enabled(self.config)
        if not extensions:
            self.emitter.finish_stage(
                Stage.EXTENSIONS, StageState.SKIPPED, "no optional extensions enabled"
            )
            return

        self.emitter.start_stage(Stage.EXTENSIONS, f"running {len(extensions)} extension(s)")

        # An extension that executes the target reuses the pipeline's own
        # runner, so generated inputs go through the same sandbox, the same
        # limits and the same classifier as the core test suite.
        runnable = all(build.success for build in self.state.builds.values())
        context = ExtensionContext(
            config=self.config,
            run=self.run,
            source_roots=[str(p) for p in self.state.source_roots],
            raw_diff=self.state.raw_diff,
            runner=self._runner() if runnable else None,
            builds={
                build.key: build
                for build in self.state.builds.values()
                if build.success
            },
            tests=list(self.state.tests),
            inputs=dict(self.state.inputs),
            store=self.store,
            run_id=self.run_id,
        )

        for extension in extensions:
            try:
                result = extension.run(context)
            except Exception as exc:
                # An advisory feature must never break a validation.
                result = {"status": "failed", "error": str(exc)}
                self.run.warnings.append(f"extension '{extension.name}' failed: {exc}")
            self.run.extension_results[extension.name] = result
            self.emitter.emit(
                f"extension '{extension.name}': {_describe_extension(result)}",
                stage=Stage.EXTENSIONS,
                level="warning" if result.get("status") == "failed" else "info",
            )

        self.emitter.finish_stage(
            Stage.EXTENSIONS,
            StageState.COMPLETED,
            f"{len(extensions)} extension(s) completed",
        )

    # -- decide ---------------------------------------------------------

    def _stage_decide(self) -> None:
        self.emitter.start_stage(Stage.DECIDE, "applying the decision rules")
        self.run.stages = self.emitter.stage_status()

        try:
            self.run.decision = decision_engine.evaluate(self.run)
        except Exception as exc:  # pragma: no cover - defensive
            self.run.decision = Decision(
                exit_code=ExitCode.BUILD_OR_CONFIG_ERROR,
                security_status=SecurityStatus.NOT_ASSESSED,
                functional_status=FunctionalStatus.NOT_ASSESSED,
                analysis_completeness=AnalysisCompleteness.FAILED,
                reasons=[
                    DecisionReason(
                        code="decision.error",
                        message=f"the decision engine failed: {exc}",
                    )
                ],
                summary="Decision engine failure",
            )

        self.emitter.finish_stage(
            Stage.DECIDE,
            StageState.COMPLETED,
            self.run.decision.summary,
            exit_code=self.run.decision.exit_code.value,
        )

    # -- finalise -------------------------------------------------------

    def _finalise(self) -> None:
        self.run.stages = self.emitter.stage_status()
        self.run.finished_at = datetime.now(timezone.utc)
        self.run.state = (
            RunState.FAILED
            if self.run.errors and self.run.decision is None
            else RunState.COMPLETED
        )

        try:
            self.store.save(self.run)
        except Exception as exc:  # pragma: no cover - last resort
            self.emitter.emit(f"could not persist run: {exc}", level="error")

        if self.state.sources is not None and not self.config.artifacts.keep_worktrees:
            # Worktree registrations are removed; the materialised trees stay
            # so the paths recorded in findings still resolve afterwards.
            self.state.sources.cleanup()


def compare_hardening(
    base: BinaryHardening, patched: BinaryHardening
) -> list[HardeningChange]:
    """Detect protections the patch strengthened or weakened."""
    rank = {
        HardeningState.DISABLED: 0,
        HardeningState.UNKNOWN: 1,
        HardeningState.PARTIAL: 2,
        HardeningState.ENABLED: 3,
    }
    changes: list[HardeningChange] = []
    patched_by_name = {p.name: p for p in patched.properties()}

    for prop in base.properties():
        other = patched_by_name.get(prop.name)
        if other is None:
            continue
        if prop.state == other.state:
            delta = HardeningDelta.UNCHANGED
        elif HardeningState.UNKNOWN in (prop.state, other.state):
            delta = HardeningDelta.UNKNOWN
        elif rank[other.state] < rank[prop.state]:
            delta = HardeningDelta.WEAKENED
        else:
            delta = HardeningDelta.STRENGTHENED

        changes.append(
            HardeningChange(
                property_name=prop.name,
                base_state=prop.state,
                patched_state=other.state,
                delta=delta,
                detail=f"{prop.detail} -> {other.detail}",
            )
        )

    # RELRO level is reported separately because "enabled" hides the
    # partial/full distinction the specification asks for explicitly.
    if base.relro_level != patched.relro_level:
        order = {"none": 0, "unknown": 1, "partial": 2, "full": 3}
        weakened = order.get(patched.relro_level.value, 1) < order.get(
            base.relro_level.value, 1
        )
        changes.append(
            HardeningChange(
                property_name="RELRO level",
                base_state=HardeningState.PARTIAL,
                patched_state=HardeningState.PARTIAL,
                delta=HardeningDelta.WEAKENED if weakened else HardeningDelta.STRENGTHENED,
                detail=f"{base.relro_level.value} -> {patched.relro_level.value}",
            )
        )

    return changes


def _describe_extension(result: dict) -> str:
    """One-line summary of an extension's output for the progress log."""
    status = result.get("status", "ok")
    if status != "ok":
        return f"{status}" + (f" ({result['error']})" if result.get("error") else "")

    parts: list[str] = []
    findings = result.get("findings")
    if isinstance(findings, list):
        confirmed = sum(1 for f in findings if isinstance(f, dict) and f.get("confirmed"))
        parts.append(f"{len(findings)} finding(s), {confirmed} confirmed")
    promoted = result.get("promoted_tests")
    if isinstance(promoted, list) and promoted:
        parts.append(f"{len(promoted)} promoted to the regression suite")
    executed = sum(
        c.get("executed", 0)
        for c in result.get("campaigns", [])
        if isinstance(c, dict)
    )
    if executed:
        parts.insert(0, f"{executed} input(s) executed")
    return "; ".join(parts) or status


def _safe(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)
