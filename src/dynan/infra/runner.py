"""Target execution.

One generic execution path serves every input-delivery mechanism the PDF
requires (stdin, file, argv) for both text and binary payloads. The runner
reports observations only - exit status, signal, output, timing - and never
decides whether something constitutes a vulnerability. That separation is what
keeps classification testable against recorded evidence.

Each execution gets a fresh scratch directory, so a target that writes files
cannot leak state into the next test and skew a differential comparison.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..config.schema import DynanConfig
from ..domain.enums import (
    BuildProfile,
    ExecutionOutcome,
    InputDelivery,
    Version,
)
from ..domain.models import (
    BuildResult,
    CapturedFile,
    ExecutionResult,
    ResourceUsage,
    TestCaseSpec,
)
from .process import ExecSpec, run_process, sanitizer_env
from .sandbox import Sandbox
from .store import RunStore

#: Placeholders usable in ``execution.argv``.
_BINARY_TOKEN = "{binary}"
_INPUT_TOKEN = "{input}"
_WORKDIR_TOKEN = "{workdir}"


@dataclass(slots=True)
class ExecutionRequest:
    """One thing to run. Decouples the runner from where the input came from."""

    test: TestCaseSpec
    build: BuildResult
    input_bytes: bytes
    execution_id: str
    #: Overrides the test's own argv when replaying a minimised candidate.
    argv_override: list[str] | None = None
    #: Skip artifact persistence for throwaway minimisation candidates.
    persist: bool = True


def make_execution_id(test_id: str, version: Version, profile: BuildProfile, suffix: str = "") -> str:
    base = f"{version.value}.{profile.value}.{test_id}"
    return f"{base}.{suffix}" if suffix else base


class TargetRunner:
    """Executes built targets against test inputs inside the sandbox."""

    def __init__(
        self,
        config: DynanConfig,
        *,
        sandbox: Sandbox,
        store: RunStore,
        run_id: str,
    ) -> None:
        self.config = config
        self.sandbox = sandbox
        self.store = store
        self.run_id = run_id

    # -- command construction -------------------------------------------

    def _scratch_dir(self, execution_id: str) -> Path:
        safe = execution_id.replace("/", "_")
        path = self.store.paths(self.run_id).evidence / "exec" / safe / "cwd"
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _resolve_cwd(self, build: BuildResult, scratch: Path) -> Path:
        """Where the target runs.

        Default is the per-execution scratch directory, which gives maximum
        isolation. A target that needs to run next to its build outputs sets
        ``execution.working_dir`` and gets that directory instead.
        """
        configured = self.config.execution.working_dir
        if configured in (".", "", None):
            return scratch
        binary = Path(build.binary_path or "")
        base = binary.parent if binary else scratch
        candidate = (base / configured).resolve()
        return candidate if candidate.is_dir() else scratch

    def _build_argv(
        self,
        request: ExecutionRequest,
        build: BuildResult,
        input_path: Path | None,
        scratch: Path,
    ) -> list[str]:
        template = list(
            request.argv_override
            if request.argv_override is not None
            else self.config.execution.argv
        )
        template += list(request.test.argv)

        text_input = ""
        if request.test.delivery == InputDelivery.ARGV:
            text_input = request.input_bytes.decode("utf-8", errors="replace")

        argv: list[str] = []
        for token in template:
            value = token.replace(_BINARY_TOKEN, build.binary_path or "")
            value = value.replace(_WORKDIR_TOKEN, str(scratch))
            if _INPUT_TOKEN in value:
                replacement = (
                    str(input_path)
                    if request.test.delivery == InputDelivery.FILE and input_path
                    else text_input
                )
                value = value.replace(_INPUT_TOKEN, replacement)
            argv.append(value)
        return argv

    def _environment(self, profile: BuildProfile) -> dict[str, str]:
        env = dict(self.config.execution.env)
        if profile == BuildProfile.SANITIZED:
            # Sanitizer behaviour must be deterministic and parseable; see
            # process.sanitizer_env for why each option is set.
            env.update(sanitizer_env(self.config.execution.limits))
        return env

    # -- execution ------------------------------------------------------

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """Run one test case against one build."""
        test = request.test
        build = request.build
        exec_cfg = self.config.execution
        profile = build.profile

        scratch = self._scratch_dir(request.execution_id)
        cwd = self._resolve_cwd(build, scratch)

        input_path: Path | None = None
        stdin_data: bytes | None = None

        if test.delivery == InputDelivery.FILE:
            input_path = scratch / "input.bin"
            input_path.write_bytes(request.input_bytes)
        elif test.delivery == InputDelivery.STDIN:
            stdin_data = request.input_bytes

        argv = self._build_argv(request, build, input_path, scratch)
        env = self._environment(profile)
        timeout = test.timeout_s or exec_cfg.timeout_s

        writable = [scratch]
        if cwd != scratch:
            writable.append(cwd)

        spec = ExecSpec(
            argv=argv,
            cwd=cwd,
            env=env,
            stdin_data=stdin_data,
            timeout_s=timeout,
            limits=exec_cfg.limits,
            max_output_bytes=exec_cfg.max_output_bytes,
            writable_paths=writable,
            readable_paths=[Path(build.binary_path).parent] if build.binary_path else [],
            network=False,
            # ASan reserves a huge shadow mapping; RLIMIT_AS would kill it at
            # startup, so sanitized runs are bounded by hard_rss_limit_mb.
            address_space_limit=profile != BuildProfile.SANITIZED,
        )

        raw = run_process(self.sandbox.wrap(spec))
        captured = self._capture_outputs(test, cwd)

        result = ExecutionResult(
            execution_id=request.execution_id,
            test_id=test.test_id,
            version=build.version,
            profile=profile,
            argv=argv,
            cwd=str(cwd),
            delivery=test.delivery,
            input_size=len(request.input_bytes),
            env=env,
            exit_code=raw.exit_code,
            signal=raw.signal,
            signal_name=raw.signal_name,
            outcome=raw.outcome,
            stdout=raw.stdout_text,
            stderr=raw.stderr_text,
            stdout_truncated=raw.stdout_truncated,
            stderr_truncated=raw.stderr_truncated,
            duration_s=raw.duration_s,
            timeout_s=timeout,
            usage=ResourceUsage(
                max_rss_kb=raw.max_rss_kb,
                user_time_s=raw.user_time_s,
                system_time_s=raw.system_time_s,
            ),
            sandbox=self.sandbox.name,
            spawn_error=raw.spawn_error,
            output_files=captured,
        )

        if request.persist:
            self._persist(result, request.input_bytes, raw.stdout, raw.stderr)

        # The scratch tree is only kept when it holds something a reviewer
        # might need; empty directories per execution would just be noise.
        if not any(scratch.iterdir()):
            shutil.rmtree(scratch, ignore_errors=True)

        return result

    def _capture_outputs(
        self, test: TestCaseSpec, cwd: Path
    ) -> list[CapturedFile]:
        """Read back the files a test declared as outputs.

        Done immediately after the process exits and before the scratch
        directory can be reused, so the bytes checked by the oracle are the
        bytes that execution actually produced.
        """
        captured: list[CapturedFile] = []
        limit = self.config.execution.max_output_bytes

        for expectation in test.expectation.output_files:
            declared = expectation.path
            resolved = (cwd / declared).resolve()

            # A manifest is user input; an output path must not escape the
            # working directory into the rest of the filesystem.
            try:
                resolved.relative_to(cwd.resolve())
            except ValueError:
                captured.append(
                    CapturedFile(
                        path=declared,
                        exists=False,
                        error=(
                            f"output path {declared!r} escapes the execution "
                            "working directory and was not read"
                        ),
                    )
                )
                continue

            if not resolved.exists():
                captured.append(CapturedFile(path=declared, exists=False))
                continue
            if not resolved.is_file():
                captured.append(
                    CapturedFile(
                        path=declared, exists=False, error="path is not a regular file"
                    )
                )
                continue

            try:
                data = resolved.read_bytes()
            except OSError as exc:
                captured.append(
                    CapturedFile(path=declared, exists=True, error=str(exc))
                )
                continue

            truncated = len(data) > limit
            captured.append(
                CapturedFile(
                    path=declared,
                    exists=True,
                    size=len(data),
                    text=data[:limit].decode("utf-8", errors="replace"),
                    truncated=truncated,
                )
            )

        return captured

    def _persist(
        self, result: ExecutionResult, input_bytes: bytes, stdout: bytes, stderr: bytes
    ) -> None:
        safe = result.execution_id.replace("/", "_")
        prefix = f"evidence/exec/{safe}"
        result.input_artifact = self.store.write_artifact(
            self.run_id, f"{prefix}/input.bin", input_bytes
        )
        result.stdout_artifact = self.store.write_artifact(
            self.run_id, f"{prefix}/stdout.log", stdout
        )
        result.stderr_artifact = self.store.write_artifact(
            self.run_id, f"{prefix}/stderr.log", stderr
        )
        for index, captured in enumerate(result.output_files):
            if not captured.exists:
                continue
            safe_name = captured.path.replace("/", "_") or f"output{index}"
            captured.artifact = self.store.write_artifact(
                self.run_id,
                f"{prefix}/outputs/{safe_name}",
                captured.text.encode("utf-8", errors="replace"),
            )


def describe_command(result: ExecutionResult) -> str:
    """Shell-ish rendering of an execution, for reproducer bundles and the UI."""
    import shlex

    rendered = " ".join(shlex.quote(part) for part in result.argv)
    if result.delivery == InputDelivery.STDIN:
        rendered += " < input.bin"
    return rendered


def env_exports(result: ExecutionResult) -> str:
    import shlex

    return "\n".join(
        f"export {key}={shlex.quote(value)}" for key, value in sorted(result.env.items())
    )
