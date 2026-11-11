"""Configuration schema and loading.

One schema serves the CLI, the web UI and CI. Path resolution semantics are
defined once in :mod:`dynan.config.loader` and documented in
``docs/configuration.md``.
"""

from .loader import ConfigError, load_config, load_config_text, resolve_paths
from .schema import (
    AnalysisConfig,
    ArtifactsConfig,
    BuildConfig,
    BuildProfileConfig,
    DynanConfig,
    ExecutionConfig,
    ExtensionsConfig,
    LlmConfig,
    ResourceLimits,
    SandboxConfig,
    SourceConfig,
    TargetConfig,
    TestsConfig,
)

__all__ = [
    "AnalysisConfig",
    "ArtifactsConfig",
    "BuildConfig",
    "BuildProfileConfig",
    "ConfigError",
    "DynanConfig",
    "ExecutionConfig",
    "ExtensionsConfig",
    "LlmConfig",
    "ResourceLimits",
    "SandboxConfig",
    "SourceConfig",
    "TargetConfig",
    "TestsConfig",
    "load_config",
    "load_config_text",
    "resolve_paths",
]
