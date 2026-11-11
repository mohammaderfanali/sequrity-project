"""Build execution.

Four builds are produced for every validation: base and patched, each in a
release and an instrumented profile. The PDF requires that release and
sanitized observations stay separate and that comparisons happen between
matching profiles, so the profile is part of a build's identity everywhere.

Profiles parameterise the build through ``CFLAGS``/``CXXFLAGS``/``LDFLAGS``
and ``DYNAN_PROFILE`` environment variables rather than by rewriting the
target's build files. That is the idiom make- and cmake-based C projects
already follow, and it is what lets a new target be onboarded with
configuration alone.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from ..config.schema import DynanConfig, ResourceLimits
from ..domain.enums import BuildProfile, ExecutionOutcome, Version
from ..domain.models import BuildResult, CommandRecord
from .process import ExecSpec, run_process
from .sandbox import Sandbox
from .store import RunStore


class BuildError(RuntimeError):
    """Raised only for dynAn-side problems, never for a failing target build.

    A target that does not compile is a *result* (exit code 30), so it comes
    back as ``BuildResult(success=False)`` rather than an exception.
    """


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class BuildExecutor:
    """Runs a target's configured build commands inside the sandbox."""

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

    # -- environment ----------------------------------------------------

    def _profile_env(self, profile: BuildProfile) -> dict[str, str]:
        build = self.config.build
        pcfg = build.profile(profile)

        env: dict[str, str] = dict(build.env)
        env.update(pcfg.env)
        env["DYNAN_PROFILE"] = profile.value

        cflags = " ".join(pcfg.cflags)
        cxxflags = " ".join(pcfg.effective_cxxflags())
        ldflags = " ".join(pcfg.ldflags)
        if cflags:
            env["CFLAGS"] = (env.get("CFLAGS", "") + " " + cflags).strip()
        if cxxflags:
            env["CXXFLAGS"] = (env.get("CXXFLAGS", "") + " " + cxxflags).strip()
        if ldflags:
            env["LDFLAGS"] = (env.get("LDFLAGS", "") + " " + ldflags).strip()

        # Reproducible-ish builds: stop the compiler embedding the build path
        # where it is avoidable, so two builds of the same source hash alike.
        env.setdefault("LC_ALL", "C")
        return env

    # -- toolchain ------------------------------------------------------

    def _detect_toolchain(self, workdir: Path, env: dict[str, str]) -> str | None:
        """Ask the actual compiler that will be used to identify itself."""
        compiler = env.get("CC") or self.config.build.env.get("CC") or "cc"
        spec = ExecSpec(
            argv=[compiler, "--version"],
            cwd=workdir,
            env=env,
            timeout_s=30.0,
            readable_paths=[workdir],
        )
        result = run_process(self.sandbox.wrap(spec))
        if result.outcome == ExecutionOutcome.SPAWN_ERROR or not result.ok:
            return None
        first = (result.stdout_text or result.stderr_text).strip().splitlines()
        return first[0].strip() if first else None

    # -- building -------------------------------------------------------

    def build(
        self, version: Version, profile: BuildProfile, source_dir: Path
    ) -> BuildResult:
        """Build one (version, profile) pair and record everything about it."""
        build_cfg = self.config.build
        pcfg = build_cfg.profile(profile)
        workdir = (source_dir / build_cfg.working_dir).resolve()

        env = self._profile_env(profile)
        commands = pcfg.commands if pcfg.commands is not None else build_cfg.commands
        binary_rel = pcfg.binary or build_cfg.binary

        result = BuildResult(
            version=version,
            profile=profile,
            success=False,
            compiler_flags=list(pcfg.cflags),
            env_overrides=env,
        )

        if not workdir.is_dir():
            result.error = (
                f"build.working_dir '{build_cfg.working_dir}' does not exist in the "
                f"{version.value} source tree"
            )
            return result

        started = time.monotonic()
        log_prefix = f"logs/build/{version.value}-{profile.value}"

        for index, argv in enumerate(commands):
            spec = ExecSpec(
                argv=list(argv),
                cwd=workdir,
                env=env,
                timeout_s=build_cfg.timeout_s,
                writable_paths=[source_dir],
                readable_paths=[source_dir],
                network=build_cfg.network,
                max_output_bytes=4_000_000,
                # A compiler legitimately needs lots of memory and CPU, and a
                # sanitized link step maps the ASan shadow, so the address
                # space stays unbounded here. The wall-clock timeout is what
                # actually bounds a runaway build.
                limits=ResourceLimits(
                    memory_mb=None,
                    cpu_s=int(build_cfg.timeout_s) + 60,
                    file_size_mb=None,
                    processes=None,
                ),
                address_space_limit=False,
            )
            raw = run_process(self.sandbox.wrap(spec))

            stdout_art = self.store.write_artifact(
                self.run_id, f"{log_prefix}-{index}.stdout.log", raw.stdout
            )
            stderr_art = self.store.write_artifact(
                self.run_id, f"{log_prefix}-{index}.stderr.log", raw.stderr
            )

            record = CommandRecord(
                argv=list(argv),
                cwd=str(workdir),
                exit_code=raw.exit_code,
                duration_s=raw.duration_s,
                stdout_artifact=stdout_art,
                stderr_artifact=stderr_art,
                stderr_tail="\n".join(raw.stderr_text.strip().splitlines()[-20:]),
                timed_out=raw.outcome == ExecutionOutcome.TIMEOUT,
            )
            result.commands.append(record)

            if raw.outcome == ExecutionOutcome.SPAWN_ERROR:
                result.error = f"could not start build command {argv}: {raw.spawn_error}"
                result.duration_s = time.monotonic() - started
                return result
            if raw.outcome == ExecutionOutcome.TIMEOUT:
                result.error = (
                    f"build command {argv} exceeded build.timeout_s "
                    f"({build_cfg.timeout_s}s)"
                )
                result.duration_s = time.monotonic() - started
                return result
            if not raw.ok:
                tail = record.stderr_tail or raw.stdout_text.strip()[-500:]
                result.error = (
                    f"build command {' '.join(argv)} failed with exit "
                    f"{raw.exit_code}{f' (signal {raw.signal_name})' if raw.signal else ''}"
                    + (f": {tail.splitlines()[-1]}" if tail.strip() else "")
                )
                result.duration_s = time.monotonic() - started
                return result

        binary_path = (workdir / binary_rel).resolve()
        if not binary_path.is_file():
            result.error = (
                f"build reported success but the expected binary '{binary_rel}' "
                f"was not found at {binary_path}"
            )
            result.duration_s = time.monotonic() - started
            return result
        if not binary_path.stat().st_mode & 0o111:
            result.error = f"built artifact {binary_path} is not executable"
            result.duration_s = time.monotonic() - started
            return result

        result.binary_path = str(binary_path)
        result.binary_sha256 = sha256_file(binary_path)
        result.toolchain = self._detect_toolchain(workdir, env)
        result.success = True
        result.duration_s = time.monotonic() - started
        return result
