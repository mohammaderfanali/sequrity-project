"""Sandbox backend selection."""

from __future__ import annotations

from ...config.schema import SandboxConfig
from .base import Sandbox, SandboxProbe, SandboxUnavailable
from .bwrap import BwrapSandbox
from .container import ContainerSandbox
from .null import NullSandbox

__all__ = [
    "BwrapSandbox",
    "ContainerSandbox",
    "NullSandbox",
    "Sandbox",
    "SandboxProbe",
    "SandboxUnavailable",
    "build_sandbox",
]


def build_sandbox(config: SandboxConfig) -> Sandbox:
    """Instantiate the configured backend.

    Construction never falls back to a weaker backend. If the configured one
    turns out to be unusable, the caller gets a :class:`SandboxUnavailable`
    and the run ends as a build/configuration error - a visible failure rather
    than a silent loss of isolation.
    """
    if config.backend == "bwrap":
        return BwrapSandbox(ro_binds=config.ro_binds)
    if config.backend in ("container", "podman", "docker"):
        runtime = None if config.backend == "container" else config.backend
        return ContainerSandbox(
            image=config.image, runtime=runtime, ro_binds=config.ro_binds
        )
    if config.backend == "none":
        if not config.allow_unsandboxed:
            raise SandboxUnavailable(
                "sandbox.backend='none' requires sandbox.allow_unsandboxed: true"
            )
        return NullSandbox()
    raise SandboxUnavailable(f"unknown sandbox backend: {config.backend}")


def ensure_usable(sandbox: Sandbox) -> SandboxProbe:
    """Run the backend's self-test, raising if it cannot be used."""
    probe = sandbox.selftest()
    if not probe.ok:
        raise SandboxUnavailable(
            f"sandbox backend '{sandbox.name}' is not usable: {probe.detail}"
        )
    return probe
