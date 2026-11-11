"""Container backend (Podman or Docker).

Podman is preferred when present because it runs rootless by default; the CLI
surface we use is identical, so one implementation serves both.

Host paths are mounted at the same absolute paths inside the container, which
keeps every command line recorded in evidence directly reusable.

Note on memory limits: the container memory cgroup bounds *resident* memory,
so unlike ``RLIMIT_AS`` it coexists fine with AddressSanitizer's large shadow
reservation.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from ...config.schema import ResourceLimits
from ...infra.process import ExecSpec, probe_version, run_process, which
from .base import PassthroughMixin, Sandbox, SandboxProbe


class ContainerSandbox(Sandbox, PassthroughMixin):
    name = "container"

    def __init__(
        self,
        *,
        image: str,
        runtime: str | None = None,
        ro_binds: list[str] | None = None,
    ) -> None:
        self.image = image
        self._extra_ro = ro_binds or []
        self._runtime_path, self._runtime_name = self._discover(runtime)
        self.name = self._runtime_name or "container"

    @staticmethod
    def _discover(preferred: str | None) -> tuple[str | None, str | None]:
        candidates = [preferred] if preferred else ["podman", "docker"]
        for cand in candidates:
            if not cand:
                continue
            path = which(cand)
            if path:
                return path, cand
        return None, preferred

    # -- availability ---------------------------------------------------

    def probe(self) -> SandboxProbe:
        if not self._runtime_path:
            return SandboxProbe(
                ok=False, detail="neither podman nor docker was found on PATH"
            )
        version = probe_version([self._runtime_path, "--version"])
        return SandboxProbe(
            ok=True, detail=f"{self._runtime_name} at {self._runtime_path}", version=version
        )

    def selftest(self) -> SandboxProbe:
        """Run a trivial command in the configured image.

        This also verifies the daemon/service is reachable and the image is
        either present or pullable - both common failure points that would
        otherwise surface only during the first build.
        """
        probed = self.probe()
        if not probed.ok:
            return probed

        assert self._runtime_path is not None
        result = run_process(
            ExecSpec(
                argv=[
                    self._runtime_path,
                    "run",
                    "--rm",
                    "--network=none",
                    self.image,
                    "/bin/true",
                ],
                cwd=Path.cwd(),
                timeout_s=180.0,
                limits=ResourceLimits(memory_mb=None, cpu_s=180, processes=None),
            )
        )
        if result.ok:
            return SandboxProbe(
                ok=True,
                detail=f"{self._runtime_name} ran image {self.image}",
                version=probed.version,
            )
        tail = result.stderr_text.strip().splitlines()
        reason = tail[-1] if tail else f"exit={result.exit_code}"
        return SandboxProbe(
            ok=False,
            detail=f"{self._runtime_name} could not run image {self.image}: {reason}",
            version=probed.version,
        )

    # -- wrapping -------------------------------------------------------

    def wrap(self, spec: ExecSpec) -> ExecSpec:
        runtime = self._runtime_path or "docker"

        argv: list[str] = [
            runtime,
            "run",
            "--rm",
            "--init",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
        ]
        if spec.stdin_data is not None:
            argv.append("-i")
        argv.append("--network=" + ("bridge" if spec.network else "none"))

        limits = spec.limits
        if limits.memory_mb:
            argv += ["--memory", f"{limits.memory_mb}m"]
        if limits.processes:
            argv += ["--pids-limit", str(limits.processes)]

        # Run as the invoking user so build outputs are not root-owned.
        if hasattr(os, "getuid"):
            argv += ["--user", f"{os.getuid()}:{os.getgid()}"]

        for path in self.normalise([Path(p) for p in self._extra_ro] + spec.readable_paths):
            if os.path.exists(path):
                argv += ["-v", f"{path}:{path}:ro"]
        for path in self.normalise(spec.writable_paths):
            if os.path.exists(path):
                argv += ["-v", f"{path}:{path}"]

        # Containers do not inherit our environment, so it has to be explicit.
        for key, value in spec.env.items():
            argv += ["-e", f"{key}={value}"]

        argv += ["-w", str(Path(spec.cwd).resolve())]
        argv.append(self.image)
        argv += list(spec.argv)

        return replace(spec, argv=argv, cwd=Path.cwd())

    def describe(self) -> str:
        return f"{self._runtime_name or 'container'} ({self.image})"
