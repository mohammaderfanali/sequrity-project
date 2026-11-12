"""Canonical data structures shared by every layer of dynAn.

These models are the single representation used by the pipeline, the JSON
report, the CLI renderer and the web UI. Pydantic gives us validation plus a
deterministic JSON encoding for free, so there is exactly one serialisation
path for run data.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .enums import (
    AnalysisCompleteness,
    BuildProfile,
    Confidence,
    CorrelationEvidenceKind,
    CorrelationVerdict,
    DependencyStatus,
    DetectionMechanism,
    ErrorType,
    ExecutionOutcome,
    ExitCode,
    FindingStatus,
    FunctionalStatus,
    HardeningDelta,
    HardeningState,
    InputDelivery,
    RelroLevel,
    RunState,
    SecurityStatus,
    Severity,
    Stage,
    StageState,
    TestCategory,
    TestOutcome,
    Version,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Model(BaseModel):
    """Base model: immutable-ish, enum values serialised as plain strings."""

    model_config = ConfigDict(use_enum_values=False, extra="forbid")


# --------------------------------------------------------------------------
# Source
# --------------------------------------------------------------------------


class SourceRevision(Model):
    """Identity of one source tree.

    ``commit`` is only populated for genuinely Git-backed sources. For plain
    directories we record ``content_hash`` instead and never pretend it is a
    commit identifier - the PDF requires exact version identification, so the
    distinction has to stay visible.
    """

    version: Version
    #: "git" or "directory".
    kind: Literal["git", "directory"]
    #: Where the prepared tree lives during the run.
    path: str
    #: Full 40-char SHA when kind == "git".
    commit: str | None = None
    short_commit: str | None = None
    #: Deterministic hash over tracked source content. Always populated.
    content_hash: str = ""
    #: Origin URL or original local path, for provenance.
    origin: str | None = None
    #: True when a Git working tree had uncommitted modifications.
    dirty: bool = False
    subject: str | None = None

    @property
    def display_revision(self) -> str:
        """Short label identifying this version.

        Only an exact, clean VCS revision is shown as a commit. A directory
        that merely happens to live inside a repository is identified by its
        content hash instead - otherwise two different directories in the same
        checkout would display the same identifier.
        """
        if self.is_exact_vcs_revision:
            return self.short_commit or (self.commit or "")[:12]
        return f"content:{self.content_hash[:12]}"

    @property
    def is_exact_vcs_revision(self) -> bool:
        return self.kind == "git" and bool(self.commit) and not self.dirty


class SourcePair(Model):
    base: SourceRevision
    patched: SourceRevision


# --------------------------------------------------------------------------
# Diff
# --------------------------------------------------------------------------


class DiffLine(Model):
    kind: Literal["context", "added", "removed"]
    #: Line number in the base file (None for added lines).
    old_lineno: int | None = None
    #: Line number in the patched file (None for removed lines).
    new_lineno: int | None = None
    text: str


class DiffHunk(Model):
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    #: Function context git puts after the @@ marker, when available.
    section_heading: str | None = None
    lines: list[DiffLine] = Field(default_factory=list)

    @property
    def old_end(self) -> int:
        return self.old_start + max(self.old_count, 1) - 1

    @property
    def new_end(self) -> int:
        return self.new_start + max(self.new_count, 1) - 1


class FileDiff(Model):
    old_path: str | None
    new_path: str | None
    change_kind: Literal["added", "removed", "modified", "renamed"]
    is_binary: bool = False
    similarity: int | None = None
    hunks: list[DiffHunk] = Field(default_factory=list)
    #: Functions whose body overlaps a changed line, resolved from the source
    #: tree rather than guessed from the hunk header alone.
    changed_functions: list[str] = Field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or "<unknown>"

    @property
    def added_lines(self) -> int:
        return sum(1 for h in self.hunks for ln in h.lines if ln.kind == "added")

    @property
    def removed_lines(self) -> int:
        return sum(1 for h in self.hunks for ln in h.lines if ln.kind == "removed")

    def changed_new_linenos(self) -> set[int]:
        return {
            ln.new_lineno
            for h in self.hunks
            for ln in h.lines
            if ln.kind == "added" and ln.new_lineno is not None
        }

    def changed_old_linenos(self) -> set[int]:
        return {
            ln.old_lineno
            for h in self.hunks
            for ln in h.lines
            if ln.kind == "removed" and ln.old_lineno is not None
        }


class StructuredDiff(Model):
    files: list[FileDiff] = Field(default_factory=list)
    #: Relative path of the stored raw unified diff artifact.
    raw_diff_artifact: str | None = None
    #: True when the diff was supplied externally rather than computed.
    externally_supplied: bool = False
    #: Set when an externally supplied patch disagreed with the computed diff.
    consistency_warning: str | None = None

    @property
    def is_empty(self) -> bool:
        return not self.files

    @property
    def files_changed(self) -> int:
        return len(self.files)

    @property
    def total_added(self) -> int:
        return sum(f.added_lines for f in self.files)

    @property
    def total_removed(self) -> int:
        return sum(f.removed_lines for f in self.files)

    def all_changed_functions(self) -> set[str]:
        return {fn for f in self.files for fn in f.changed_functions}

    def find_file(self, path: str) -> FileDiff | None:
        """Match a diff entry by path, tolerating absolute/partial paths."""
        norm = path.replace("\\", "/").lstrip("./")
        for fd in self.files:
            for cand in (fd.new_path, fd.old_path):
                if not cand:
                    continue
                c = cand.replace("\\", "/")
                if c == norm or norm.endswith("/" + c) or c.endswith("/" + norm):
                    return fd
        return None


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


class CommandRecord(Model):
    """One executed command with its captured output references."""

    argv: list[str]
    cwd: str
    exit_code: int | None = None
    duration_s: float = 0.0
    stdout_artifact: str | None = None
    stderr_artifact: str | None = None
    #: Inline tail kept for quick display without opening the artifact.
    stderr_tail: str = ""
    timed_out: bool = False


class BuildResult(Model):
    version: Version
    profile: BuildProfile
    success: bool
    commands: list[CommandRecord] = Field(default_factory=list)
    binary_path: str | None = None
    binary_sha256: str | None = None
    #: Compiler identification string, captured from the real toolchain.
    toolchain: str | None = None
    compiler_flags: list[str] = Field(default_factory=list)
    env_overrides: dict[str, str] = Field(default_factory=dict)
    duration_s: float = 0.0
    error: str | None = None

    @property
    def key(self) -> str:
        return f"{self.version.value}/{self.profile.value}"


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


class ResourceUsage(Model):
    max_rss_kb: int | None = None
    user_time_s: float | None = None
    system_time_s: float | None = None


class ExecutionResult(Model):
    """A single observation of the target running. Purely descriptive.

    The execution engine never decides whether something is a vulnerability;
    it only records what happened.
    """

    execution_id: str
    test_id: str
    version: Version
    profile: BuildProfile
    argv: list[str]
    cwd: str
    delivery: InputDelivery
    #: Size of the input actually delivered, in bytes.
    input_size: int = 0
    input_artifact: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    exit_code: int | None = None
    signal: int | None = None
    signal_name: str | None = None
    outcome: ExecutionOutcome = ExecutionOutcome.COMPLETED
    stdout: str = ""
    stderr: str = ""
    stdout_artifact: str | None = None
    stderr_artifact: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    #: Files the test declared as outputs, captured after the run.
    output_files: list[CapturedFile] = Field(default_factory=list)
    duration_s: float = 0.0
    timeout_s: float | None = None
    usage: ResourceUsage = Field(default_factory=ResourceUsage)
    sandbox: str = "none"
    spawn_error: str | None = None

    @property
    def crashed(self) -> bool:
        return self.signal is not None or self.outcome == ExecutionOutcome.SIGNALED


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


class StackFrame(Model):
    index: int
    function: str | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    module: str | None = None
    address: str | None = None

    @property
    def is_source_resolved(self) -> bool:
        return bool(self.file and self.line)


class FindingSignature(Model):
    """Stable identity of a failure.

    Used for three things that must agree: matching a base failure against a
    patched failure, deciding whether minimisation preserved "the same" error,
    and de-duplicating findings. Deliberately excludes addresses, PIDs and
    timings, which vary between runs.
    """

    error_type: ErrorType
    detection: DetectionMechanism
    #: Innermost frame that resolved to project source, if any.
    function: str | None = None
    file: str | None = None
    #: Line is recorded but excluded from equality: a patch legitimately shifts
    #: line numbers, and requiring equality would make every finding "new".
    line: int | None = None

    def key(self) -> tuple[str, str, str, str]:
        return (
            self.error_type.value,
            self.detection.value,
            self.function or "",
            (self.file or "").rsplit("/", 1)[-1],
        )

    def matches(self, other: FindingSignature) -> bool:
        return self.key() == other.key()

    @property
    def digest(self) -> str:
        return hashlib.sha256("|".join(self.key()).encode()).hexdigest()[:16]

    def describe(self) -> str:
        loc = self.function or (self.file or "unknown location")
        return f"{self.error_type.value} at {loc} via {self.detection.value}"


class Finding(Model):
    """A normalised failure observation tied to real evidence."""

    finding_id: str
    signature: FindingSignature
    severity: Severity
    confidence: Confidence
    version: Version
    profile: BuildProfile
    test_id: str
    execution_id: str
    message: str = ""
    frames: list[StackFrame] = Field(default_factory=list)
    #: Raw sanitizer/crash text, stored as an artifact for traceability.
    raw_report_artifact: str | None = None
    exit_code: int | None = None
    signal: int | None = None
    signal_name: str | None = None
    #: Extra sanitizer detail (access size, operation, allocation site...).
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def error_type(self) -> ErrorType:
        return self.signature.error_type

    @property
    def detection(self) -> DetectionMechanism:
        return self.signature.detection

    @property
    def primary_frame(self) -> StackFrame | None:
        for f in self.frames:
            if f.is_source_resolved:
                return f
        return self.frames[0] if self.frames else None


# --------------------------------------------------------------------------
# Correlation (PDF section 3.1 - highest weighted requirement)
# --------------------------------------------------------------------------


class CorrelationEvidence(Model):
    kind: CorrelationEvidenceKind
    description: str
    #: Where this signal came from, so a reviewer can re-check it.
    file: str | None = None
    line: int | None = None
    function: str | None = None
    #: Positive values support a relationship, negative values argue against.
    weight: float = 0.0


class FindingCorrelation(Model):
    finding_id: str
    verdict: CorrelationVerdict
    confidence: Confidence
    evidence: list[CorrelationEvidence] = Field(default_factory=list)
    rationale: str = ""
    #: Diff regions a reviewer should look at, as "path:line" references.
    related_diff_locations: list[str] = Field(default_factory=list)

    @property
    def is_conclusive(self) -> bool:
        return self.verdict in (CorrelationVerdict.DIRECT, CorrelationVerdict.INDIRECT)


# --------------------------------------------------------------------------
# Tests and the functional oracle
# --------------------------------------------------------------------------


class OutputFileExpectation(Model):
    """Assertion about a file the target is expected to write.

    Many real programs report their result through an output file rather than
    stdout, so a validator that can only read stdout cannot express their
    correctness criterion at all.

    ``path`` is relative to the execution's working directory, which is the
    per-execution scratch directory unless ``execution.working_dir`` says
    otherwise.
    """

    path: str
    #: False asserts the file must *not* exist - useful for checking that a
    #: rejected input produced no partial output.
    exists: bool = True
    exact: str | None = None
    contains: list[str] = Field(default_factory=list)
    regex: str | None = None

    @property
    def has_content_assertion(self) -> bool:
        return self.exact is not None or bool(self.contains) or self.regex is not None


class CapturedFile(Model):
    """A declared output file as it was found after an execution."""

    path: str
    exists: bool
    size: int = 0
    #: Run-relative artifact holding the bytes, so the evidence survives.
    artifact: str | None = None
    #: Decoded content, bounded for display and matching.
    text: str = ""
    truncated: bool = False
    #: Populated when the file could not be read at all.
    error: str | None = None


class OracleExpectation(Model):
    """What the independent oracle says *should* happen.

    Provenance is mandatory: the PDF requires the correctness criterion to be
    defined independently of the patched program.
    """

    exit_code: int | None = None
    stdout_exact: str | None = None
    stdout_contains: list[str] = Field(default_factory=list)
    stdout_regex: str | None = None
    stderr_contains: list[str] = Field(default_factory=list)
    #: Assertions about files the target writes.
    output_files: list[OutputFileExpectation] = Field(default_factory=list)
    must_not_crash: bool = True
    max_duration_s: float | None = None
    provenance: str = "unspecified"


class TestCaseSpec(Model):
    test_id: str
    category: TestCategory
    description: str = ""
    delivery: InputDelivery = InputDelivery.STDIN
    #: Resolved absolute path of the input file, when delivery is FILE/STDIN.
    input_path: str | None = None
    #: Literal input, used when the manifest inlines data instead of a file.
    #: Excluded from JSON: the bytes actually delivered are persisted as an
    #: execution artifact, which is the traceable copy.
    input_bytes: bytes | None = Field(default=None, exclude=True, repr=False)
    argv: list[str] = Field(default_factory=list)
    timeout_s: float | None = None
    expectation: OracleExpectation = Field(default_factory=OracleExpectation)
    #: Signature the base version is expected to exhibit, for security tests.
    expected_baseline_signature: str | None = None
    #: True when this test came from dynAn's generated regression suite.
    generated: bool = False
    source_manifest: str | None = None

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)


class OracleCheck(Model):
    """Outcome of evaluating one execution against the oracle."""

    test_id: str
    version: Version
    profile: BuildProfile
    execution_id: str
    outcome: TestOutcome
    #: Human-readable reasons the check failed, each tied to a concrete field.
    violations: list[str] = Field(default_factory=list)
    expected_summary: str = ""
    actual_summary: str = ""


class FunctionalRegression(Model):
    """Evidence-backed functional regression.

    Only constructed when the base execution satisfied the independent oracle
    and the patched execution violated it.
    """

    test_id: str
    profile: BuildProfile
    base_check: OracleCheck
    patched_check: OracleCheck
    violations: list[str] = Field(default_factory=list)
    base_execution_id: str
    patched_execution_id: str


# --------------------------------------------------------------------------
# Reproduction, minimisation, regression generation (PDF section 3.3)
# --------------------------------------------------------------------------


class ReplayAttempt(Model):
    attempt: int
    execution_id: str
    reproduced: bool
    observed_signature: str | None = None


class ReproductionResult(Model):
    """Reproducer bundle metadata. The PDF requires >= 3 replays."""

    finding_id: str
    #: Directory, relative to the run root, holding input + metadata + runner.
    bundle_path: str
    attempts: list[ReplayAttempt] = Field(default_factory=list)
    reproduced_count: int = 0
    total_attempts: int = 0
    stable: bool = False
    #: Everything needed to re-run the failure by hand.
    revision: str = ""
    binary_sha256: str | None = None
    argv: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    delivery: InputDelivery = InputDelivery.STDIN
    build_profile: BuildProfile = BuildProfile.SANITIZED

    @property
    def reproduction_rate(self) -> float:
        return self.reproduced_count / self.total_attempts if self.total_attempts else 0.0


class MinimizationResult(Model):
    finding_id: str
    original_size: int
    minimized_size: int
    original_artifact: str
    minimized_artifact: str | None = None
    #: Number of candidate inputs executed during the search.
    iterations: int = 0
    #: The signature the predicate required to be preserved. An arbitrary
    #: non-zero exit code is explicitly not sufficient (PDF 3.3).
    preserved_signature: str = ""
    verified: bool = False
    technique: str = "ddmin"
    duration_s: float = 0.0
    notes: str = ""

    @property
    def reduction_ratio(self) -> float:
        if not self.original_size:
            return 0.0
        return 1.0 - (self.minimized_size / self.original_size)


class GeneratedRegressionTest(Model):
    test_id: str
    finding_id: str
    #: Path of the emitted input, relative to the regression suite root.
    input_artifact: str
    manifest_path: str
    delivery: InputDelivery
    argv: list[str] = Field(default_factory=list)
    expected_base_signature: str = ""
    #: Verified by actually running it, not assumed.
    verified_fails_on_base: bool | None = None
    verified_passes_on_patched: bool | None = None
    notes: str = ""


# --------------------------------------------------------------------------
# Binary hardening (PDF section 3.4)
# --------------------------------------------------------------------------


class HardeningProperty(Model):
    name: str
    state: HardeningState
    detail: str = ""
    #: Concrete observation that justifies the state, e.g. the ELF header bit
    #: or dynamic-section entry we read.
    evidence: str = ""


class BinaryHardening(Model):
    version: Version
    profile: BuildProfile
    binary_path: str
    binary_sha256: str | None = None
    nx: HardeningProperty
    pie: HardeningProperty
    relro: HardeningProperty
    relro_level: RelroLevel = RelroLevel.UNKNOWN
    canary: HardeningProperty
    fortify: HardeningProperty | None = None
    #: Caveats the PDF explicitly demands we state.
    caveats: list[str] = Field(default_factory=list)

    def properties(self) -> list[HardeningProperty]:
        props = [self.nx, self.pie, self.relro, self.canary]
        if self.fortify:
            props.append(self.fortify)
        return props


class HardeningChange(Model):
    property_name: str
    base_state: HardeningState
    patched_state: HardeningState
    delta: HardeningDelta
    detail: str = ""


class HardeningComparison(Model):
    base: BinaryHardening | None = None
    patched: BinaryHardening | None = None
    changes: list[HardeningChange] = Field(default_factory=list)

    @property
    def weakened(self) -> list[HardeningChange]:
        return [c for c in self.changes if c.delta == HardeningDelta.WEAKENED]


# --------------------------------------------------------------------------
# Differential security comparison
# --------------------------------------------------------------------------


class FindingComparison(Model):
    """One differential conclusion about a signature across both versions."""

    signature: FindingSignature
    status: FindingStatus
    base_finding_ids: list[str] = Field(default_factory=list)
    patched_finding_ids: list[str] = Field(default_factory=list)
    test_ids: list[str] = Field(default_factory=list)
    profile: BuildProfile = BuildProfile.SANITIZED
    confidence: Confidence = Confidence.CONFIRMED
    rationale: str = ""
    correlation: FindingCorrelation | None = None

    @property
    def is_targeted_baseline(self) -> bool:
        """True when this signature was observed on the base version."""
        return bool(self.base_finding_ids)


# --------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------


class DecisionReason(Model):
    code: str
    message: str
    #: IDs of findings / tests / stages that justify this reason.
    references: list[str] = Field(default_factory=list)


class Decision(Model):
    exit_code: ExitCode
    security_status: SecurityStatus
    functional_status: FunctionalStatus
    analysis_completeness: AnalysisCompleteness
    #: Every status that applied, before precedence was used to pick one code.
    candidate_codes: list[ExitCode] = Field(default_factory=list)
    reasons: list[DecisionReason] = Field(default_factory=list)
    summary: str = ""

    @property
    def verdict_label(self) -> str:
        return self.exit_code.name


# --------------------------------------------------------------------------
# Progress and stages
# --------------------------------------------------------------------------


class StageStatus(Model):
    stage: Stage
    state: StageState = StageState.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    message: str = ""
    #: Completed units of work, when the stage knows its own size.
    progress_current: int | None = None
    progress_total: int | None = None

    @property
    def duration_s(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


class ProgressEvent(Model):
    """Structured pipeline event. Streamed to the UI, appended to events.jsonl.

    Events describe things that actually happened; there are no synthetic
    percentages anywhere in the product.
    """

    sequence: int
    timestamp: datetime = Field(default_factory=utc_now)
    stage: Stage | None = None
    state: StageState | None = None
    level: Literal["debug", "info", "warning", "error"] = "info"
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------
# Environment doctor
# --------------------------------------------------------------------------


class Diagnostic(Model):
    name: str
    status: DependencyStatus
    required: bool
    detail: str = ""
    version: str | None = None
    remediation: str | None = None
    category: str = "general"

    @property
    def blocking(self) -> bool:
        return self.required and self.status in (
            DependencyStatus.MISSING,
            DependencyStatus.MISCONFIGURED,
            DependencyStatus.UNSUPPORTED,
        )


class DoctorReport(Model):
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    config_path: str | None = None

    @property
    def blocking(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.blocking]

    @property
    def ok(self) -> bool:
        return not self.blocking


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


class RunSummary(Model):
    """Lightweight projection used by run listings in CLI and UI."""

    run_id: str
    target_name: str
    state: RunState
    created_at: datetime
    finished_at: datetime | None = None
    duration_s: float | None = None
    exit_code: ExitCode | None = None
    security_status: SecurityStatus | None = None
    functional_status: FunctionalStatus | None = None
    analysis_completeness: AnalysisCompleteness | None = None
    base_revision: str = ""
    patched_revision: str = ""
    findings_count: int = 0


class ValidationRun(Model):
    """The central product object: one complete validation execution."""

    schema_version: str
    run_id: str
    dynan_version: str
    target_name: str
    created_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    state: RunState = RunState.PENDING

    #: Snapshot of the effective configuration, after defaults and overrides.
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    config_path: str | None = None

    sources: SourcePair | None = None
    diff: StructuredDiff | None = None
    builds: list[BuildResult] = Field(default_factory=list)
    tests: list[TestCaseSpec] = Field(default_factory=list)
    executions: list[ExecutionResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    oracle_checks: list[OracleCheck] = Field(default_factory=list)
    comparisons: list[FindingComparison] = Field(default_factory=list)
    regressions: list[FunctionalRegression] = Field(default_factory=list)
    correlations: list[FindingCorrelation] = Field(default_factory=list)
    reproductions: list[ReproductionResult] = Field(default_factory=list)
    minimizations: list[MinimizationResult] = Field(default_factory=list)
    generated_tests: list[GeneratedRegressionTest] = Field(default_factory=list)
    hardening: HardeningComparison | None = None
    doctor: DoctorReport | None = None
    stages: list[StageStatus] = Field(default_factory=list)
    decision: Decision | None = None
    #: Non-fatal problems worth surfacing, e.g. a skipped optional extension.
    warnings: list[str] = Field(default_factory=list)
    #: Fatal errors that stopped the pipeline.
    errors: list[str] = Field(default_factory=list)
    extension_results: dict[str, Any] = Field(default_factory=dict)

    # -- convenience lookups used by renderers -----------------------------

    @property
    def duration_s(self) -> float | None:
        if self.finished_at:
            return (self.finished_at - self.created_at).total_seconds()
        return None

    def build(self, version: Version, profile: BuildProfile) -> BuildResult | None:
        for b in self.builds:
            if b.version == version and b.profile == profile:
                return b
        return None

    def execution(self, execution_id: str) -> ExecutionResult | None:
        return next((e for e in self.executions if e.execution_id == execution_id), None)

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.finding_id == finding_id), None)

    def test(self, test_id: str) -> TestCaseSpec | None:
        return next((t for t in self.tests if t.test_id == test_id), None)

    def correlation_for(self, finding_id: str) -> FindingCorrelation | None:
        return next((c for c in self.correlations if c.finding_id == finding_id), None)

    def reproduction_for(self, finding_id: str) -> ReproductionResult | None:
        return next((r for r in self.reproductions if r.finding_id == finding_id), None)

    def minimization_for(self, finding_id: str) -> MinimizationResult | None:
        return next((m for m in self.minimizations if m.finding_id == finding_id), None)

    def stage(self, stage: Stage) -> StageStatus | None:
        return next((s for s in self.stages if s.stage == stage), None)

    def to_summary(self) -> RunSummary:
        return RunSummary(
            run_id=self.run_id,
            target_name=self.target_name,
            state=self.state,
            created_at=self.created_at,
            finished_at=self.finished_at,
            duration_s=self.duration_s,
            exit_code=self.decision.exit_code if self.decision else None,
            security_status=self.decision.security_status if self.decision else None,
            functional_status=self.decision.functional_status if self.decision else None,
            analysis_completeness=(
                self.decision.analysis_completeness if self.decision else None
            ),
            base_revision=(
                self.sources.base.display_revision if self.sources else ""
            ),
            patched_revision=(
                self.sources.patched.display_revision if self.sources else ""
            ),
            findings_count=len(self.findings),
        )
