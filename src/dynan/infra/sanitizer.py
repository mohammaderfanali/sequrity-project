"""Parsing of sanitizer and runtime-error output.

Written against real GCC 13 libasan/libubsan output rather than from memory.
Two details from that output shape the design:

* Stack traces interleave project frames with libsanitizer internals
  (``../../../../src/libsanitizer/...``), glibc startup (``../csu/...``) and
  fortified-header inlines (``/usr/include/.../string_fortified.h``). Picking
  the innermost frame blindly would attribute every ``strcpy`` overflow to
  libsanitizer, so frames are classified against the project's source roots.
* ASan prints both an ``ERROR:`` header and a ``SUMMARY:`` line; the latter is
  the more stable place to read the error kind from.

Nothing here invents a location. If no frame resolves to project source, the
finding simply carries no source attribution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..domain.enums import DetectionMechanism, ErrorType
from ..domain.models import StackFrame

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

_ASAN_ERROR_RE = re.compile(
    r"ERROR:\s+(?P<tool>AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer):\s+"
    r"(?P<kind>[A-Za-z0-9_\-]+)(?P<rest>[^\n]*)"
)
_ASAN_SUMMARY_RE = re.compile(
    r"SUMMARY:\s+(?P<tool>AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer):\s+"
    r"(?P<kind>[A-Za-z0-9_\-]+)(?P<rest>[^\n]*)"
)
_UBSAN_RE = re.compile(
    r"^(?P<file>[^\s:]+):(?P<line>\d+):(?P<col>\d+):\s+runtime error:\s+(?P<msg>.+)$",
    re.MULTILINE,
)
_FRAME_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+0x(?P<address>[0-9a-fA-F]+)\s+in\s+(?P<rest>.+?)\s*$",
    re.MULTILINE,
)
_ACCESS_RE = re.compile(
    r"^(?P<op>READ|WRITE)\s+of\s+size\s+(?P<size>\d+)\s+at\s+0x(?P<addr>[0-9a-fA-F]+)",
    re.MULTILINE,
)
_BUILDID_RE = re.compile(r"\s*\(BuildId:\s*[0-9a-fA-F]+\)\s*$")
_MODULE_RE = re.compile(r"^(?P<func>.*?)\s+\((?P<module>[^()]+)\+0x(?P<offset>[0-9a-fA-F]+)\)$")
_FILELINE_RE = re.compile(r"^(?P<func>.*?)\s+(?P<file>[^\s]+):(?P<line>\d+)(?::(?P<col>\d+))?$")

#: Path fragments that mean "not the project's own code".
_FOREIGN_PATH_MARKERS = (
    "/src/libsanitizer/",
    "/sysdeps/",
    "/csu/",
    "/libc-start",
    "/usr/include/",
    "/usr/lib/",
    "<null>",
)

#: Glibc hardening messages (not sanitizer output).
_GLIBC_PATTERNS: tuple[tuple[str, ErrorType], ...] = (
    ("stack smashing detected", ErrorType.STACK_SMASHING_DETECTED),
    ("double free or corruption", ErrorType.DOUBLE_FREE),
    ("free(): invalid pointer", ErrorType.INVALID_FREE),
    ("free(): invalid next size", ErrorType.INVALID_FREE),
    ("free(): double free detected", ErrorType.DOUBLE_FREE),
    ("munmap_chunk(): invalid pointer", ErrorType.INVALID_FREE),
    ("malloc(): corrupted top size", ErrorType.HEAP_BUFFER_OVERFLOW),
    ("malloc(): invalid size", ErrorType.HEAP_BUFFER_OVERFLOW),
    ("corrupted size vs. prev_size", ErrorType.HEAP_BUFFER_OVERFLOW),
    ("buffer overflow detected", ErrorType.HEAP_BUFFER_OVERFLOW),
)

_ASSERT_RE = re.compile(
    r"(?P<file>[^\s:]+):(?P<line>\d+):\s*(?P<func>[^:]*):\s*Assertion\s+`(?P<expr>.*)'\s+failed",
)

#: ASan error-kind token -> canonical error type.
_ASAN_KIND_MAP: dict[str, ErrorType] = {
    "stack-buffer-overflow": ErrorType.STACK_BUFFER_OVERFLOW,
    "stack-buffer-underflow": ErrorType.STACK_BUFFER_OVERFLOW,
    "dynamic-stack-buffer-overflow": ErrorType.STACK_BUFFER_OVERFLOW,
    "heap-buffer-overflow": ErrorType.HEAP_BUFFER_OVERFLOW,
    "heap-buffer-underflow": ErrorType.HEAP_BUFFER_OVERFLOW,
    "global-buffer-overflow": ErrorType.GLOBAL_BUFFER_OVERFLOW,
    "heap-use-after-free": ErrorType.USE_AFTER_FREE,
    "stack-use-after-return": ErrorType.USE_AFTER_RETURN,
    "stack-use-after-scope": ErrorType.USE_AFTER_SCOPE,
    "double-free": ErrorType.DOUBLE_FREE,
    "bad-free": ErrorType.INVALID_FREE,
    "alloc-dealloc-mismatch": ErrorType.INVALID_FREE,
    "attempting-free-on-address-which-was-not-malloc": ErrorType.INVALID_FREE,
    "stack-overflow": ErrorType.STACK_OVERFLOW,
    "negative-size-param": ErrorType.HEAP_BUFFER_OVERFLOW,
    "memcpy-param-overlap": ErrorType.UNDEFINED_BEHAVIOR,
}

#: UBSan message fragment -> canonical error type. Order matters: the first
#: fragment found in the message wins, so more specific entries come first.
_UBSAN_MESSAGE_MAP: tuple[tuple[str, ErrorType], ...] = (
    ("signed integer overflow", ErrorType.SIGNED_INTEGER_OVERFLOW),
    ("unsigned integer overflow", ErrorType.INTEGER_OVERFLOW),
    ("integer overflow", ErrorType.INTEGER_OVERFLOW),
    ("division by zero", ErrorType.DIVISION_BY_ZERO),
    ("divide by zero", ErrorType.DIVISION_BY_ZERO),
    ("shift exponent", ErrorType.SHIFT_OUT_OF_BOUNDS),
    ("left shift of negative value", ErrorType.SHIFT_OUT_OF_BOUNDS),
    ("out of bounds for type", ErrorType.ARRAY_INDEX_OUT_OF_BOUNDS),
    # UBSan's object-size check. It proves the access is out of bounds but,
    # unlike ASan, does not identify the storage region - so it maps to the
    # region-agnostic overflow type rather than being downgraded to generic
    # undefined behaviour.
    ("insufficient space for an object", ErrorType.BUFFER_OVERFLOW),
    ("null pointer", ErrorType.NULL_DEREFERENCE),
    ("misaligned address", ErrorType.MISALIGNED_POINTER),
    ("not a valid value for type", ErrorType.UNDEFINED_BEHAVIOR),
    ("variable length array bound", ErrorType.UNDEFINED_BEHAVIOR),
    ("pointer overflow", ErrorType.UNDEFINED_BEHAVIOR),
)


@dataclass(slots=True)
class SanitizerReport:
    """One parsed runtime failure report."""

    error_type: ErrorType
    detection: DetectionMechanism
    message: str
    frames: list[StackFrame] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    @property
    def primary_frame(self) -> StackFrame | None:
        for frame in self.frames:
            if frame.is_source_resolved:
                return frame
        return self.frames[0] if self.frames else None


# --------------------------------------------------------------------------
# Frame parsing
# --------------------------------------------------------------------------


def is_project_path(path: str, roots: list[Path]) -> bool:
    """Whether a frame's file belongs to the code under test.

    Handles both forms compilers emit. When the build passes an absolute
    source path, debug info carries an absolute path and we test containment.
    When the build passes a relative path - ``cc ... src/confparse.c``, which
    is what a typical Makefile does - the frame says ``src/confparse.c``, and
    the only way to tell whether that belongs to the project is to look for it
    under each prepared tree.
    """
    if not path:
        return False
    if any(marker in path for marker in _FOREIGN_PATH_MARKERS):
        return False
    if not roots:
        # Without roots we fall back to "not obviously foreign", which keeps
        # the parser usable in unit tests over captured output.
        return not path.startswith("..")

    candidate = Path(path)
    if candidate.is_absolute():
        for root in roots:
            try:
                candidate.resolve().relative_to(root.resolve())
                return True
            except (ValueError, OSError):
                continue
        return False

    if candidate.parts and candidate.parts[0] == "..":
        return False
    return any((root / candidate).exists() for root in roots)


def parse_frames(text: str) -> list[StackFrame]:
    """Parse ``#N 0xADDR in ...`` lines into structured frames.

    ASan prints several traces in one report (the failing access, then the
    free site, then the allocation site). Only the first is the failure's own
    stack, so parsing stops when the frame counter restarts at ``#0``.
    """
    frames: list[StackFrame] = []

    for match in _FRAME_RE.finditer(text):
        index = int(match.group("index"))
        if index == 0 and frames:
            break

        rest = _BUILDID_RE.sub("", match.group("rest")).strip()
        function: str | None = None
        file: str | None = None
        line: int | None = None
        column: int | None = None
        module: str | None = None

        mod = _MODULE_RE.match(rest)
        if mod:
            function = mod.group("func").strip() or None
            module = mod.group("module")
        else:
            fl = _FILELINE_RE.match(rest)
            if fl:
                function = fl.group("func").strip() or None
                file = fl.group("file")
                line = int(fl.group("line"))
                column = int(fl.group("col")) if fl.group("col") else None
            else:
                function = rest or None

        frames.append(
            StackFrame(
                index=index,
                function=function,
                file=file,
                line=line,
                column=column,
                module=module,
                address="0x" + match.group("address"),
            )
        )

    return frames


def select_project_frame(
    frames: list[StackFrame], source_roots: list[Path] | None = None
) -> StackFrame | None:
    """Innermost frame that belongs to the project's own source.

    This is what gives a finding its ``file``/``function`` attribution. When
    nothing matches we return ``None`` rather than guessing - a fabricated
    location would poison the correlation stage.
    """
    roots = source_roots or []
    for frame in frames:
        if frame.file and frame.line and is_project_path(frame.file, roots):
            return frame
    return None


# --------------------------------------------------------------------------
# Report parsing
# --------------------------------------------------------------------------


def _classify_asan_kind(kind: str, rest: str, raw: str) -> ErrorType:
    normalised = kind.strip().lower()
    if normalised in _ASAN_KIND_MAP:
        return _ASAN_KIND_MAP[normalised]
    if normalised == "segv":
        if "zero page" in raw or re.search(r"unknown address 0x0+\b", raw):
            return ErrorType.NULL_DEREFERENCE
        return ErrorType.UNCLASSIFIED_CRASH
    if "leak" in normalised or "leak" in rest.lower():
        return ErrorType.MEMORY_LEAK
    return ErrorType.UNCLASSIFIED_CRASH


def _classify_ubsan_message(message: str) -> ErrorType:
    lowered = message.lower()
    for fragment, error_type in _UBSAN_MESSAGE_MAP:
        if fragment in lowered:
            return error_type
    return ErrorType.UNDEFINED_BEHAVIOR


def parse_asan(text: str) -> SanitizerReport | None:
    match = _ASAN_ERROR_RE.search(text) or _ASAN_SUMMARY_RE.search(text)
    if not match:
        return None

    tool = match.group("tool")
    kind = match.group("kind")
    rest = match.group("rest") or ""

    if tool == "LeakSanitizer":
        error_type = ErrorType.MEMORY_LEAK
        detection = DetectionMechanism.LSAN
    elif tool == "UndefinedBehaviorSanitizer":
        error_type = _classify_ubsan_message(kind + " " + rest)
        detection = DetectionMechanism.UBSAN
    else:
        error_type = _classify_asan_kind(kind, rest, text)
        detection = DetectionMechanism.ASAN

    details: dict[str, Any] = {"sanitizer_kind": kind}
    access = _ACCESS_RE.search(text)
    if access:
        details["access_operation"] = access.group("op")
        details["access_size"] = int(access.group("size"))

    summary = _ASAN_SUMMARY_RE.search(text)
    if summary:
        details["summary"] = summary.group(0).strip()

    newline = text.find("\n", match.start())
    header_line = text[match.start() : newline if newline != -1 else len(text)].strip()

    return SanitizerReport(
        error_type=error_type,
        detection=detection,
        message=header_line or f"{tool}: {kind}",
        frames=parse_frames(text),
        details=details,
        raw=text,
    )


def parse_ubsan(text: str) -> SanitizerReport | None:
    match = _UBSAN_RE.search(text)
    if not match:
        return None

    message = match.group("msg").strip()
    error_type = _classify_ubsan_message(message)

    frames = parse_frames(text[match.end() :])
    # UBSan always names the offending location in its header. Keep it as the
    # outermost frame so the finding has a location even when the stack trace
    # is unavailable.
    header_frame = StackFrame(
        index=0,
        function=None,
        file=match.group("file"),
        line=int(match.group("line")),
        column=int(match.group("col")),
    )
    if not frames:
        frames = [header_frame]

    return SanitizerReport(
        error_type=error_type,
        detection=DetectionMechanism.UBSAN,
        message=f"runtime error: {message}",
        frames=frames,
        details={"ubsan_message": message, "header_location": header_frame.model_dump()},
        raw=text,
    )


def parse_glibc_hardening(text: str) -> SanitizerReport | None:
    """Detect glibc / stack-protector diagnostics in the absence of sanitizers.

    This is what makes the *release* build useful: an uninstrumented binary
    still reports canary violations and heap corruption, and the PDF asks
    specifically for the detection mechanism to be recorded separately.
    """
    for pattern, error_type in _GLIBC_PATTERNS:
        if pattern in text:
            detection = (
                DetectionMechanism.STACK_PROTECTOR
                if error_type == ErrorType.STACK_SMASHING_DETECTED
                else DetectionMechanism.GLIBC_HARDENING
            )
            line = next(
                (ln.strip() for ln in text.splitlines() if pattern in ln), pattern
            )
            return SanitizerReport(
                error_type=error_type,
                detection=detection,
                message=line,
                details={"glibc_pattern": pattern},
                raw=text,
            )
    return None


def parse_assertion(text: str) -> SanitizerReport | None:
    match = _ASSERT_RE.search(text)
    if not match:
        return None
    return SanitizerReport(
        error_type=ErrorType.ASSERTION_FAILURE,
        detection=DetectionMechanism.ASSERTION,
        message=match.group(0).strip(),
        frames=[
            StackFrame(
                index=0,
                function=(match.group("func") or "").strip() or None,
                file=match.group("file"),
                line=int(match.group("line")),
            )
        ],
        details={"assertion": match.group("expr")},
        raw=text,
    )


def parse_output(text: str) -> SanitizerReport | None:
    """Best available interpretation of a process's error output.

    Order reflects evidence strength: a sanitizer report is more precise than
    a glibc message, which is more precise than a bare assertion.
    """
    if not text:
        return None
    for parser in (parse_asan, parse_ubsan, parse_glibc_hardening, parse_assertion):
        report = parser(text)
        if report is not None:
            return report
    return None
