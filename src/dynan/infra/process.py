"""Low-level process execution with timeouts, resource limits and capture.

This is the only place in dynAn that spawns a process. Everything else -
builds, target executions, replays, minimisation candidates, doctor probes -
goes through :func:`run_process`, so limits and isolation cannot be bypassed
by accident.
"""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config.schema import ResourceLimits
from ..domain.enums import ExecutionOutcome

#: Grace period between SIGKILL of the group and giving up on reaping.
_REAP_TIMEOUT_S = 5.0


@dataclass(slots=True)
class ExecSpec:
    """Everything needed to run one command."""

    argv: list[str]
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    stdin_data: bytes | None = None
    timeout_s: float = 30.0
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    max_output_bytes: int = 1_000_000
    #: Host paths the command must be able to write to (sandbox binds).
    writable_paths: list[Path] = field(default_factory=list)
    #: Extra host paths the command must be able to read.
    readable_paths: list[Path] = field(default_factory=list)
    network: bool = False
    #: Disabled for sanitized builds - see :func:`_build_preexec`.
    address_space_limit: bool = True
    #: Replace the inherited environment entirely instead of extending it.
    clear_env: bool = False


@dataclass(slots=True)
class RawResult:
    """Raw observation. Carries no security interpretation whatsoever."""

    argv: list[str]
    exit_code: int | None
    signal: int | None
    stdout: bytes
    stderr: bytes
    duration_s: float
    outcome: ExecutionOutcome
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    max_rss_kb: int | None = None
    user_time_s: float | None = None
    system_time_s: float | None = None
    spawn_error: str | None = None

    @property
    def signal_name(self) -> str | None:
        if self.signal is None:
            return None
        try:
            return signal.Signals(self.signal).name
        except ValueError:
            return f"SIG{self.signal}"

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.signal is None


def _build_preexec(spec: ExecSpec):
    """Return a ``preexec_fn`` applying rlimits in the child.

    ``RLIMIT_AS`` is deliberately conditional. AddressSanitizer reserves a
    very large virtual address range for its shadow memory (tens of
    terabytes); capping the address space makes every sanitized binary die at
    startup with a confusing allocator error. For sanitized builds we leave
    the address space alone and bound memory through ASan's own
    ``hard_rss_limit_mb`` instead - see :func:`sanitizer_env`.
    """
    limits = spec.limits
    use_as = spec.address_space_limit

    def preexec() -> None:  # pragma: no cover - runs in the forked child
        os.setsid()
        if limits.cpu_s:
            # Hard limit one second above soft, so SIGXCPU can be observed
            # before SIGKILL lands.
            resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_s, limits.cpu_s + 1))
        if limits.memory_mb and use_as:
            nbytes = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
        if limits.file_size_mb:
            nbytes = limits.file_size_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (nbytes, nbytes))
        if limits.processes:
            # Opt-in only: this is a per-UID limit, so setting it too low
            # breaks unrelated processes' forks, including the sandbox's.
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (limits.processes, limits.processes))
            except (ValueError, OSError):
                pass
        if not limits.core_dump:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return preexec


def _truncate(data: bytes, limit: int) -> tuple[bytes, bool]:
    if len(data) <= limit:
        return data, False
    half = limit // 2
    marker = b"\n...[dynAn: output truncated]...\n"
    return data[:half] + marker + data[-half:], True


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill the whole process group so forked children cannot outlive us."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def build_env(spec: ExecSpec) -> dict[str, str]:
    base: dict[str, str] = {} if spec.clear_env else dict(os.environ)
    if spec.clear_env:
        # Keep the few variables a toolchain genuinely needs.
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TERM"):
            if key in os.environ:
                base[key] = os.environ[key]
        base.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    base.update(spec.env)
    return base


def sanitizer_env(limits: ResourceLimits, *, detect_leaks: bool = False) -> dict[str, str]:
    """Environment making sanitizer output parseable and bounded.

    ``halt_on_error`` / ``abort_on_error`` are chosen so a sanitized run stops
    at the *first* error with a non-zero status, which is what makes the
    failure observable to a dynamic tool.
    """
    asan_opts = [
        "detect_leaks=" + ("1" if detect_leaks else "0"),
        "abort_on_error=0",
        "exitcode=1",
        "print_stacktrace=1",
        "symbolize=1",
        "handle_segv=1",
        "handle_abort=1",
        "allocator_may_return_null=1",
        # Interleaved output from several processes is unparseable.
        "log_exe_name=0",
    ]
    if limits.memory_mb:
        asan_opts.append(f"hard_rss_limit_mb={limits.memory_mb}")

    ubsan_opts = [
        "print_stacktrace=1",
        "halt_on_error=1",
        "symbolize=1",
    ]
    return {
        "ASAN_OPTIONS": ":".join(asan_opts),
        "UBSAN_OPTIONS": ":".join(ubsan_opts),
        "LSAN_OPTIONS": "report_objects=1",
    }


def run_process(spec: ExecSpec) -> RawResult:
    """Execute ``spec`` and return what was observed.

    Never raises for target misbehaviour: a crash, a timeout or a failure to
    spawn all come back as a :class:`RawResult` with the corresponding
    outcome, because all of those are data the pipeline needs to analyse.
    """
    env = build_env(spec)
    started = time.monotonic()

    try:
        proc = subprocess.Popen(
            spec.argv,
            cwd=str(spec.cwd),
            env=env,
            stdin=subprocess.PIPE if spec.stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_build_preexec(spec),
            close_fds=True,
        )
    except (OSError, ValueError) as exc:
        return RawResult(
            argv=list(spec.argv),
            exit_code=None,
            signal=None,
            stdout=b"",
            stderr=str(exc).encode(),
            duration_s=time.monotonic() - started,
            outcome=ExecutionOutcome.SPAWN_ERROR,
            spawn_error=str(exc),
        )

    timed_out = False
    try:
        stdout, stderr = proc.communicate(
            input=spec.stdin_data, timeout=spec.timeout_s
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        try:
            stdout, stderr = proc.communicate(timeout=_REAP_TIMEOUT_S)
        except subprocess.TimeoutExpired:  # pragma: no cover - pathological
            stdout, stderr = b"", b""
    except BrokenPipeError:
        # Target exited before consuming stdin; still a valid observation.
        stdout, stderr = b"", b""
        proc.wait(timeout=_REAP_TIMEOUT_S)

    duration = time.monotonic() - started
    returncode = proc.returncode

    sig: int | None = None
    exit_code: int | None = returncode
    if returncode is not None and returncode < 0:
        sig = -returncode
        exit_code = None

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)

    if timed_out:
        outcome = ExecutionOutcome.TIMEOUT
    elif sig is not None:
        outcome = (
            ExecutionOutcome.RESOURCE_LIMIT
            if sig in (signal.SIGXCPU, signal.SIGXFSZ)
            else ExecutionOutcome.SIGNALED
        )
    else:
        outcome = ExecutionOutcome.COMPLETED

    out, out_trunc = _truncate(stdout or b"", spec.max_output_bytes)
    err, err_trunc = _truncate(stderr or b"", spec.max_output_bytes)

    return RawResult(
        argv=list(spec.argv),
        exit_code=exit_code,
        signal=sig,
        stdout=out,
        stderr=err,
        duration_s=duration,
        outcome=outcome,
        stdout_truncated=out_trunc,
        stderr_truncated=err_trunc,
        max_rss_kb=usage.ru_maxrss or None,
        user_time_s=usage.ru_utime or None,
        system_time_s=usage.ru_stime or None,
    )


def which(name: str) -> str | None:
    """Locate an executable without importing shutil at call sites."""
    from shutil import which as _which

    return _which(name)


def probe_version(argv: list[str], *, timeout_s: float = 10.0) -> str | None:
    """Run a ``--version``-style command and return its first output line."""
    result = run_process(
        ExecSpec(
            argv=argv,
            cwd=Path.cwd(),
            timeout_s=timeout_s,
            limits=ResourceLimits(memory_mb=None, cpu_s=10),
        )
    )
    if result.outcome == ExecutionOutcome.SPAWN_ERROR:
        return None
    text = (result.stdout_text or result.stderr_text).strip()
    return text.splitlines()[0].strip() if text else None
