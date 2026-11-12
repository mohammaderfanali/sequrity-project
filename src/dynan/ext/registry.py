"""Extension registry.

Intentionally small: a name-to-factory table plus a narrow protocol. A plugin
framework would be more machinery than the problem needs, and the PDF's
mandatory capabilities are part of the core pipeline rather than extensions.

Heavy dependencies are imported inside the factory, so merely listing the
available extensions never pulls in an optional package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, runtime_checkable

from ..config.schema import DynanConfig
from ..domain.models import Diagnostic, ValidationRun


@dataclass(slots=True)
class ExtensionContext:
    """What an extension is allowed to see.

    Analysis-only extensions need just the run and the diff. An extension that
    must *execute* the target - the fuzzer - additionally receives the
    pipeline's own runner and builds, so it drives the same sandboxed
    execution path as the core and cannot invent a second one.
    """

    config: DynanConfig
    run: ValidationRun
    #: Absolute paths of the prepared source trees.
    source_roots: list[str]
    #: Raw unified diff, so an extension need not re-read the repository.
    raw_diff: str = ""

    #: Configured :class:`~dynan.infra.runner.TargetRunner`, when builds
    #: succeeded. ``None`` means no extension may execute anything.
    runner: Any = None
    #: Successful builds keyed by ``"<version>/<profile>"``.
    builds: dict[str, Any] = field(default_factory=dict)
    #: The loaded test suite and the bytes each test delivers, usable as a
    #: seed corpus.
    tests: list[Any] = field(default_factory=list)
    inputs: dict[str, bytes] = field(default_factory=dict)
    #: Run store and id, for persisting extension artifacts.
    store: Any = None
    run_id: str = ""


@runtime_checkable
class Extension(Protocol):
    """Narrow interface every optional capability implements."""

    name: str
    description: str

    def diagnose(self, config: DynanConfig) -> list[Diagnostic]:
        """Report readiness. Called by the environment doctor."""
        ...

    def run(self, context: ExtensionContext) -> dict[str, Any]:
        """Produce advisory output, stored under ``run.extension_results``."""
        ...


def _load_llm() -> Extension:
    from .llm.extension import LlmExtension

    return LlmExtension()


def _load_fuzz() -> Extension:
    from .fuzz.extension import FuzzExtension

    return FuzzExtension()


#: name -> factory. Factories defer imports so disabled extensions stay inert.
_FACTORIES: dict[str, Callable[[], Extension]] = {
    "llm": _load_llm,
    "fuzz": _load_fuzz,
}


def extension_names() -> list[str]:
    return sorted(_FACTORIES)


def available_extensions() -> dict[str, Extension]:
    """Instantiate every known extension.

    Used by the doctor to validate ``extensions.enabled``. An extension whose
    optional dependency is absent still constructs - it reports the problem
    through :meth:`Extension.diagnose` rather than exploding on import.
    """
    loaded: dict[str, Extension] = {}
    for name, factory in _FACTORIES.items():
        try:
            loaded[name] = factory()
        except Exception as exc:  # pragma: no cover - defensive
            loaded[name] = _BrokenExtension(name, str(exc))
    return loaded


def load_enabled(config: DynanConfig) -> list[Extension]:
    """Instantiate only the extensions the configuration switched on."""
    extensions: list[Extension] = []
    for name in config.extensions.enabled:
        factory = _FACTORIES.get(name)
        if factory is None:
            continue
        try:
            extensions.append(factory())
        except Exception as exc:  # pragma: no cover - defensive
            extensions.append(_BrokenExtension(name, str(exc)))
    return extensions


@dataclass
class _BrokenExtension:
    """Stand-in for an extension that failed to load.

    Keeps a broken optional feature from taking down the core workflow; the
    problem surfaces as a diagnostic instead.
    """

    name: str
    error: str
    description: str = "extension failed to load"

    def diagnose(self, config: DynanConfig) -> list[Diagnostic]:
        from ..domain.enums import DependencyStatus

        return [
            Diagnostic(
                name=f"extension: {self.name}",
                status=DependencyStatus.MISCONFIGURED,
                required=False,
                detail=f"could not be loaded: {self.error}",
                remediation="install the extension's optional dependencies, or disable it",
                category="extensions",
            )
        ]

    def run(self, context: ExtensionContext) -> dict[str, Any]:
        return {"error": self.error, "status": "not_loaded"}
