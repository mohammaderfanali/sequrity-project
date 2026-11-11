"""Bubblewrap backend.

Rootless, daemon-less and available on any modern Linux with user namespaces,
which makes it a good default for an academic environment where installing a
container runtime may not be possible.

Isolation applied: fresh user/IPC/PID/UTS/cgroup namespaces, no network by
default, a read-only view of the filesystem with an explicit writable
allow-list, a private ``/tmp`` and a private ``/proc``.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from ...config.schema import ResourceLimits
from ...infra.process import ExecSpec, run_process, which
from .base import PassthroughMixin, Sandbox, SandboxProbe


class BwrapSandbox(Sandbox, PassthroughMixin):
    name = "bwrap"

    def __init__(self, *, ro_binds: list[str] | None = None) -> None:
        self._extra_ro = ro_binds or []
        self._path = which("bwrap")

    # -- availability ---------------------------------------------------

    def probe(self) -> SandboxProbe:
        if not self._path:
            return SandboxProbe(
                ok=False,
                detail="bwrap executable not found on PATH",
            )
        from ...infra.process import probe_version

        version = probe_version([self._path, "--version"])
        return SandboxProbe(ok=True, detail=f"found at {self._path}", version=version)

    def selftest(self) -> SandboxProbe:
        """Create a real namespace and run ``/bin/true`` inside it.

        Catches the common failure where bwrap is installed but unprivileged
        user namespaces are restricted by sysctl or AppArmor.
        """
        probed = self.probe()
        if not probed.ok:
            return probed

        spec = ExecSpec(
            argv=["/bin/true"],
            cwd=Path("/"),
            timeout_s=20.0,
            limits=ResourceLimits(memory_mb=None, cpu_s=10, processes=None),
        )
        result = run_process(self.wrap(spec))
        if result.ok:
            return SandboxProbe(ok=True, detail="namespace creation succeeded", version=probed.version)

        hint = result.stderr_text.strip().splitlines()
        reason = hint[-1] if hint else f"exit={result.exit_code} signal={result.signal}"
        return SandboxProbe(
            ok=False,
            detail=f"bwrap present but unusable: {reason}",
            version=probed.version,
        )

    # -- wrapping -------------------------------------------------------

    def wrap(self, spec: ExecSpec) -> ExecSpec:
        bwrap = self._path or "bwrap"

        argv: list[str] = [
            bwrap,
            "--die-with-parent",
            "--unshare-all",
        ]
        if spec.network:
            argv.append("--share-net")

        # Read-only root, then carve out the pieces that must be special.
        argv += [
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--tmpfs", "/run",
        ]

        for path in self.normalise([Path(p) for p in self._extra_ro] + spec.readable_paths):
            if os.path.exists(path):
                argv += ["--ro-bind", path, path]

        # Writable allow-list last so it overrides the read-only root.
        for path in self.normalise(spec.writable_paths):
            if os.path.exists(path):
                argv += ["--bind", path, path]

        cwd = str(Path(spec.cwd).resolve())
        argv += ["--chdir", cwd, "--"]
        argv += list(spec.argv)

        # The sandboxed process inherits our environment, so the spec's env is
        # still applied by the process runner. cwd is handled by --chdir;
        # bwrap itself starts from a directory that definitely exists.
        return replace(spec, argv=argv, cwd=Path("/"))

    def describe(self) -> str:
        return "bwrap (rootless user namespace)"
