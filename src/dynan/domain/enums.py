"""Canonical vocabulary for dynAn.

Every status word the product displays - in the CLI, the JSON report and the
web UI - originates here. Presentation layers map these values to labels and
colours but never invent new ones.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """``str``-backed enum so values serialise directly to JSON."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


# --------------------------------------------------------------------------
# Exit codes (PDF section 3.5)
# --------------------------------------------------------------------------


class ExitCode(int, Enum):
    """Process exit codes mandated by the project specification."""

    PASS = 0
    VULN_REMAINS = 10
    FUNC_REGRESSION = 20
    BUILD_OR_CONFIG_ERROR = 30
    INCONCLUSIVE = 40


#: Precedence used when several statuses hold at once.
#:
#: The specification PDF (section 3.5, final paragraph) states:
#:
#:     «در صورت همزمانی چند وضعیت، اولویت کد خروج به ترتیب 30، 10، 20، 40 و 0 است.»
#:     "When several statuses coincide, the exit-code priority is, in order,
#:      30, 10, 20, 40 and 0."
#:
#: So a build/configuration error outranks everything: if we could not build or
#: configure the target, no security or functional claim derived from that run
#: is trustworthy. INCONCLUSIVE sits below the two confirmed verdicts because a
#: confirmed finding is more decisive than missing evidence, but above PASS
#: because incomplete analysis must never be reported as success.
#:
#: This tuple is the single authoritative definition; the decision engine, the
#: CLI and the web UI all read it rather than hard-coding an order.
EXIT_CODE_PRECEDENCE: tuple[ExitCode, ...] = (
    ExitCode.BUILD_OR_CONFIG_ERROR,  # 30
    ExitCode.VULN_REMAINS,           # 10
    ExitCode.FUNC_REGRESSION,        # 20
    ExitCode.INCONCLUSIVE,           # 40
    ExitCode.PASS,                   # 0
)


# --------------------------------------------------------------------------
# Build and execution
# --------------------------------------------------------------------------


class Version(StrEnum):
    """Which side of the patch a given artifact belongs to."""

    BASE = "base"
    PATCHED = "patched"


class BuildProfile(StrEnum):
    """Build flavour.

    The PDF requires that release and instrumented observations are never
    mixed, and that base/patched comparisons happen between matching profiles.
    """

    RELEASE = "release"
    SANITIZED = "sanitized"


class InputDelivery(StrEnum):
    """How a test case hands its input to the target process."""

    STDIN = "stdin"
    FILE = "file"
    ARGV = "argv"
    NONE = "none"


class TestCategory(StrEnum):
    """Test taxonomy required by PDF section 3.2."""

    VALID = "valid"
    BOUNDARY = "boundary"
    INVALID = "invalid"
    SECURITY = "security"


class ExecutionOutcome(StrEnum):
    """What the process runner observed, before any security interpretation."""

    COMPLETED = "completed"
    TIMEOUT = "timeout"
    SIGNALED = "signaled"
    RESOURCE_LIMIT = "resource_limit"
    SPAWN_ERROR = "spawn_error"


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


class ErrorType(StrEnum):
    """Error taxonomy (PDF section 3.2, "Error Type").

    This is a classification of the *observed symptom*, explicitly not a
    root-cause analysis.
    """

    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
    GLOBAL_BUFFER_OVERFLOW = "global_buffer_overflow"
    #: An out-of-bounds access whose storage region is not identified. UBSan's
    #: object-size check reports this: it proves the access is out of bounds
    #: but, unlike ASan, does not say whether the object was on the stack, the
    #: heap or in static storage.
    BUFFER_OVERFLOW = "buffer_overflow"
    STACK_OVERFLOW = "stack_overflow"
    USE_AFTER_FREE = "use_after_free"
    USE_AFTER_RETURN = "use_after_return"
    USE_AFTER_SCOPE = "use_after_scope"
    DOUBLE_FREE = "double_free"
    INVALID_FREE = "invalid_free"
    MEMORY_LEAK = "memory_leak"
    NULL_DEREFERENCE = "null_dereference"
    INTEGER_OVERFLOW = "integer_overflow"
    SIGNED_INTEGER_OVERFLOW = "signed_integer_overflow"
    SHIFT_OUT_OF_BOUNDS = "shift_out_of_bounds"
    DIVISION_BY_ZERO = "division_by_zero"
    ARRAY_INDEX_OUT_OF_BOUNDS = "array_index_out_of_bounds"
    MISALIGNED_POINTER = "misaligned_pointer"
    UNDEFINED_BEHAVIOR = "undefined_behavior"
    STACK_SMASHING_DETECTED = "stack_smashing_detected"
    ASSERTION_FAILURE = "assertion_failure"
    ABORT = "abort"
    #: A crash we genuinely could not classify. The PDF is explicit that an
    #: unclassified stop is *not* sufficient to confirm a vulnerability.
    UNCLASSIFIED_CRASH = "unclassified_crash"
    TIMEOUT = "timeout"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


#: Error types that denote a genuine memory-safety violation. Only these can
#: justify exit code 10 on their own.
MEMORY_SAFETY_ERRORS: frozenset[ErrorType] = frozenset(
    {
        ErrorType.STACK_BUFFER_OVERFLOW,
        ErrorType.HEAP_BUFFER_OVERFLOW,
        ErrorType.GLOBAL_BUFFER_OVERFLOW,
        ErrorType.BUFFER_OVERFLOW,
        ErrorType.USE_AFTER_FREE,
        ErrorType.USE_AFTER_RETURN,
        ErrorType.USE_AFTER_SCOPE,
        ErrorType.DOUBLE_FREE,
        ErrorType.INVALID_FREE,
        ErrorType.STACK_SMASHING_DETECTED,
    }
)

#: Undefined-behaviour findings. Real, reportable, but weaker evidence than a
#: memory-safety violation.
UNDEFINED_BEHAVIOR_ERRORS: frozenset[ErrorType] = frozenset(
    {
        ErrorType.SIGNED_INTEGER_OVERFLOW,
        ErrorType.INTEGER_OVERFLOW,
        ErrorType.SHIFT_OUT_OF_BOUNDS,
        ErrorType.DIVISION_BY_ZERO,
        ErrorType.ARRAY_INDEX_OUT_OF_BOUNDS,
        ErrorType.MISALIGNED_POINTER,
        ErrorType.NULL_DEREFERENCE,
        ErrorType.UNDEFINED_BEHAVIOR,
    }
)


class DetectionMechanism(StrEnum):
    """How the failure became visible (PDF section 3.2, "Detection Mechanism")."""

    ASAN = "asan"
    UBSAN = "ubsan"
    LSAN = "lsan"
    OS_SIGNAL = "os_signal"
    #: Binary guard: ``__stack_chk_fail`` / "stack smashing detected".
    STACK_PROTECTOR = "stack_protector"
    GLIBC_HARDENING = "glibc_hardening"
    ASSERTION = "assertion"
    EXIT_STATUS = "exit_status"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"


class Severity(StrEnum):
    MEMORY_SAFETY = "memory_safety"
    UNDEFINED_BEHAVIOR = "undefined_behavior"
    CRASH = "crash"
    RESOURCE = "resource"
    #: A clean, intentional error path (e.g. "invalid input" + exit 1).
    BENIGN = "benign"


class Confidence(StrEnum):
    """How much the evidence supports the claim."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    UNCONFIRMED = "unconfirmed"


class FindingStatus(StrEnum):
    """Differential status of a finding (PDF section 3.1, "status classification").

    The PDF names exactly four classes plus an explicit inconclusive state.
    """

    FIXED = "fixed"
    INCOMPLETE_FIX = "incomplete_fix"
    NEW_ISSUE = "new_issue"
    FUNCTIONAL_REGRESSION = "functional_regression"
    INCONCLUSIVE = "inconclusive"
    #: Present identically in both versions and not the targeted vulnerability -
    #: tracked so it is visible, but it is not a patch-introduced problem.
    UNCHANGED = "unchanged"


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------


class CorrelationVerdict(StrEnum):
    """Relationship between a finding and the patch diff.

    The PDF insists that mere textual adjacency is not proof, and that
    insufficient evidence must be reported as unknown.
    """

    DIRECT = "direct"
    INDIRECT = "indirect"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class CorrelationEvidenceKind(StrEnum):
    """Individual signals feeding a correlation verdict."""

    FRAME_IN_CHANGED_FUNCTION = "frame_in_changed_function"
    FRAME_IN_CHANGED_FILE = "frame_in_changed_file"
    FRAME_ON_CHANGED_LINE = "frame_on_changed_line"
    CALLER_CHANGED = "caller_changed"
    DIFFERENTIAL_BEHAVIOUR = "differential_behaviour"
    SIGNATURE_DISAPPEARED = "signature_disappeared"
    SIGNATURE_APPEARED = "signature_appeared"
    NO_OVERLAP = "no_overlap"
    NO_STACK_TRACE = "no_stack_trace"


# --------------------------------------------------------------------------
# Aggregate statuses (kept independent, per PDF section 3.5)
# --------------------------------------------------------------------------


class SecurityStatus(StrEnum):
    PASS = "pass"
    VULN_REMAINS = "vuln_remains"
    NEW_ISSUE = "new_issue"
    INCONCLUSIVE = "inconclusive"
    NOT_ASSESSED = "not_assessed"


class FunctionalStatus(StrEnum):
    PASS = "pass"
    REGRESSION = "regression"
    INCONCLUSIVE = "inconclusive"
    NOT_ASSESSED = "not_assessed"


class AnalysisCompleteness(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class TestOutcome(StrEnum):
    """Result of checking one execution against the independent oracle."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    #: Oracle intentionally does not constrain this execution (e.g. a security
    #: test whose only job is to trigger a crash).
    NOT_APPLICABLE = "not_applicable"


# --------------------------------------------------------------------------
# Binary hardening (PDF section 3.4)
# --------------------------------------------------------------------------


class RelroLevel(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"
    UNKNOWN = "unknown"


class HardeningState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class HardeningDelta(StrEnum):
    UNCHANGED = "unchanged"
    WEAKENED = "weakened"
    STRENGTHENED = "strengthened"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Environment doctor
# --------------------------------------------------------------------------


class DependencyStatus(StrEnum):
    READY = "ready"
    MISSING = "missing"
    MISCONFIGURED = "misconfigured"
    UNSUPPORTED = "unsupported"
    NOT_REQUIRED = "not_required"


# --------------------------------------------------------------------------
# Run lifecycle
# --------------------------------------------------------------------------


class RunState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StageState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class Stage(StrEnum):
    """Pipeline stages. Progress reporting is driven by these, never simulated."""

    PREFLIGHT = "preflight"
    SOURCE = "source"
    DIFF = "diff"
    BUILD = "build"
    EXECUTE = "execute"
    ANALYZE = "analyze"
    CORRELATE = "correlate"
    REPRODUCE = "reproduce"
    MINIMIZE = "minimize"
    REGRESSION = "regression"
    HARDENING = "hardening"
    DECIDE = "decide"
    EXTENSIONS = "extensions"


#: Canonical stage order used by the pipeline and rendered by both front ends.
STAGE_ORDER: tuple[Stage, ...] = (
    Stage.PREFLIGHT,
    Stage.SOURCE,
    Stage.DIFF,
    Stage.BUILD,
    Stage.EXECUTE,
    Stage.ANALYZE,
    Stage.CORRELATE,
    Stage.REPRODUCE,
    Stage.MINIMIZE,
    Stage.REGRESSION,
    Stage.HARDENING,
    Stage.EXTENSIONS,
    Stage.DECIDE,
)
