"""Sandbox abstraction.

A sandbox wraps an :class:`~dynan.infra.process.ExecSpec` so the command runs
isolated from the host. The pipeline is written against this interface only,
which is what allows the backend to change without touching validation logic.

Both builds and target executions go through a sandbox: build scripts from an
untrusted repository are no safer than the binaries they produce.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from pathlib import Path

from ...infra.process import ExecSpec


class SandboxUnavailable(RuntimeError):
    """Raised when the configured backend cannot be used.

    Deliberately fatal: dynAn never degrades to unrestricted host execution
    because the requested isolation is missing. That would silently void the
    isolation requirement while still reporting a confident verdict.
    """


@dataclass(slots=True)
class SandboxProbe:
    ok: bool
    detail: str
    version: str | None = None


class Sandbox(ABC):
    """Wraps commands for isolated execution."""

    #: Stable identifier recorded on every execution result.
    name: str = "base"

    @abstractmethod
    def probe(self) -> SandboxProbe:
        """Check the backend is installed and usable, without running a payload."""

    @abstractmethod
    def selftest(self) -> SandboxProbe:
        """Actually execute a trivial command through the backend.

        The environment doctor calls this rather than trusting a ``which``
        lookup, because an installed binary that cannot create namespaces is
        worse than an absent one: it fails deep inside the first real build.
        """

    @abstractmethod
    def wrap(self, spec: ExecSpec) -> ExecSpec:
        """Return a new spec whose argv runs ``spec`` inside the sandbox."""

    def describe(self) -> str:
        return self.name


class PassthroughMixin:
    """Helper for backends that keep host paths identical inside the sandbox.

    Keeping the mapping identity-shaped means binary paths, working
    directories and input file paths recorded in evidence are the same strings
    a human would use to reproduce the failure by hand.
    """

    @staticmethod
    def normalise(paths: list[Path]) -> list[str]:
        seen: list[str] = []
        for p in paths:
            resolved = str(Path(p).resolve())
            if resolved not in seen:
                seen.append(resolved)
        return seen

    @staticmethod
    def with_argv(spec: ExecSpec, argv: list[str]) -> ExecSpec:
        return replace(spec, argv=argv)
