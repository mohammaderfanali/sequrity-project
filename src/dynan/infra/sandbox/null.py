"""Unsandboxed backend.

Only selectable when the configuration sets both ``backend: none`` and
``allow_unsandboxed: true``. It exists for debugging trusted fixtures and for
environments where no namespace support is available at all; the schema makes
choosing it a deliberate, visible act.

Resource limits still apply - those come from the process runner, not the
sandbox.
"""

from __future__ import annotations

from ...infra.process import ExecSpec
from .base import Sandbox, SandboxProbe


class NullSandbox(Sandbox):
    name = "none"

    def probe(self) -> SandboxProbe:
        return SandboxProbe(
            ok=True,
            detail=(
                "No isolation. Target builds and binaries run directly on the host "
                "with resource limits only."
            ),
        )

    def selftest(self) -> SandboxProbe:
        return self.probe()

    def wrap(self, spec: ExecSpec) -> ExecSpec:
        return spec

    def describe(self) -> str:
        return "none (explicitly allowed)"
