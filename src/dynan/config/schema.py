"""Versioned configuration schema.

Design goals, in order:

* A new target must be addable by editing configuration only - no code change.
  This is an explicit PDF requirement (section 2, "generalisability").
* Common cases stay short. Defaults cover a typical ``make``-based C project.
* No default silently weakens security validation: sanitizers stay on, the
  sandbox stays on, and network access during build/test stays off.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..domain.enums import BuildProfile, InputDelivery

#: Current configuration format version. Bump when a breaking change lands.
CONFIG_VERSION = 1


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------
# Target and source
# --------------------------------------------------------------------------


class TargetConfig(Base):
    name: str = Field(..., min_length=1, description="Short identifier for the target.")
    description: str = ""
    language: Literal["c", "cpp"] = "c"


class SourceConfig(Base):
    """Source acquisition. Exactly one mode's fields are required."""

    mode: Literal["directories", "local_git", "remote_git"]

    # mode == "directories"
    base_path: str | None = None
    patched_path: str | None = None

    # mode == "local_git"
    repo_path: str | None = None

    # mode == "remote_git"
    repo_url: str | None = None
    #: Optional second origin, when base and patched live in different repos.
    patched_repo_url: str | None = None

    # git modes
    base_commit: str | None = None
    patched_commit: str | None = None
    #: Shallow-ish fetch depth when cloning. None clones fully.
    fetch_depth: int | None = None

    #: Optional externally supplied unified diff. When present dynAn still
    #: computes its own diff and reports any disagreement rather than trusting
    #: the supplied file blindly.
    patch_file: str | None = None

    @model_validator(mode="after")
    def _check_mode_fields(self) -> SourceConfig:
        missing: list[str] = []
        if self.mode == "directories":
            if not self.base_path:
                missing.append("source.base_path")
            if not self.patched_path:
                missing.append("source.patched_path")
        elif self.mode == "local_git":
            if not self.repo_path:
                missing.append("source.repo_path")
            if not self.base_commit:
                missing.append("source.base_commit")
            if not self.patched_commit:
                missing.append("source.patched_commit")
        elif self.mode == "remote_git":
            if not self.repo_url:
                missing.append("source.repo_url")
            if not self.base_commit:
                missing.append("source.base_commit")
            if not self.patched_commit:
                missing.append("source.patched_commit")
        if missing:
            raise ValueError(
                f"source.mode='{self.mode}' requires: {', '.join(missing)}"
            )
        return self


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

#: Sanitizer flags used by the default instrumented profile.
#:
#: ``-fno-sanitize-recover=all`` matters: without it UBSan merely prints a
#: warning and the process exits 0, which would make undefined behaviour
#: invisible to a dynamic tool.
DEFAULT_SANITIZER_CFLAGS: list[str] = [
    "-O1",
    "-g",
    "-fno-omit-frame-pointer",
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
]

DEFAULT_RELEASE_CFLAGS: list[str] = ["-O2", "-g"]


class BuildProfileConfig(Base):
    """Per-profile build settings.

    Flags are exported to the build as ``CFLAGS``/``CXXFLAGS``/``LDFLAGS``
    environment variables plus ``DYNAN_PROFILE``, which is the idiomatic way to
    parameterise make/cmake projects without rewriting their build files.
    """

    cflags: list[str] = Field(default_factory=list)
    cxxflags: list[str] | None = None
    ldflags: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    #: Overrides ``build.commands`` entirely for this profile, when needed.
    commands: list[list[str]] | None = None
    #: Overrides ``build.binary`` for this profile.
    binary: str | None = None

    def effective_cxxflags(self) -> list[str]:
        return self.cxxflags if self.cxxflags is not None else list(self.cflags)


def _default_profiles() -> dict[str, BuildProfileConfig]:
    return {
        BuildProfile.RELEASE.value: BuildProfileConfig(
            cflags=list(DEFAULT_RELEASE_CFLAGS)
        ),
        BuildProfile.SANITIZED.value: BuildProfileConfig(
            cflags=list(DEFAULT_SANITIZER_CFLAGS),
            ldflags=["-fsanitize=address,undefined"],
        ),
    }


class BuildConfig(Base):
    #: Directory inside the prepared source tree where commands run.
    working_dir: str = "."
    #: Ordered argv arrays. Arrays rather than shell strings, so there is no
    #: implicit shell parsing and no quoting ambiguity.
    commands: list[list[str]] = Field(
        default_factory=lambda: [["make", "clean"], ["make"]]
    )
    #: Path of the produced executable, relative to ``working_dir``.
    binary: str
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: float = 600.0
    profiles: dict[str, BuildProfileConfig] = Field(default_factory=_default_profiles)
    #: Build commands never need the network; keeping it off by default stops a
    #: malicious build script from exfiltrating anything.
    network: bool = False

    @model_validator(mode="after")
    def _check_profiles(self) -> BuildConfig:
        required = {BuildProfile.RELEASE.value, BuildProfile.SANITIZED.value}
        missing = required - set(self.profiles)
        if missing:
            raise ValueError(
                "build.profiles must define both 'release' and 'sanitized'; "
                f"missing: {', '.join(sorted(missing))}"
            )
        for cmd in self.commands:
            if not cmd:
                raise ValueError("build.commands contains an empty command")
        return self

    def profile(self, profile: BuildProfile) -> BuildProfileConfig:
        return self.profiles[profile.value]


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


class ResourceLimits(Base):
    """Per-execution limits, applied via ``setrlimit`` and/or the sandbox."""

    memory_mb: int | None = 2048
    cpu_s: int | None = 30
    file_size_mb: int | None = 256
    #: Process-count cap. Off by default on purpose: ``RLIMIT_NPROC`` counts
    #: every process owned by the *user*, not just this execution's children,
    #: so on a normal desktop session any value below the user's existing
    #: process count makes the very first fork fail with EAGAIN - including
    #: the sandbox's own namespace setup. Use the container backend's
    #: ``--pids-limit``, which is per-container, when you need this bound.
    processes: int | None = None
    core_dump: bool = False


class ExecutionConfig(Base):
    """How the target is invoked.

    ``argv`` is a template. ``{binary}`` expands to the built executable and
    ``{input}`` to the input file path when delivery is ``file``. Keeping this
    in configuration is what makes dynAn target-agnostic.
    """

    argv: list[str] = Field(default_factory=lambda: ["{binary}"])
    delivery: InputDelivery = InputDelivery.STDIN
    timeout_s: float = 10.0
    env: dict[str, str] = Field(default_factory=dict)
    #: Working directory for the target, relative to the build working dir.
    working_dir: str = "."
    limits: ResourceLimits = Field(default_factory=ResourceLimits)
    #: Maximum captured stdout/stderr per execution, in bytes.
    max_output_bytes: int = 1_000_000

    @model_validator(mode="after")
    def _check_argv(self) -> ExecutionConfig:
        if not self.argv:
            raise ValueError("execution.argv must not be empty")
        if "{binary}" not in " ".join(self.argv):
            raise ValueError("execution.argv must reference {binary}")
        if self.delivery == InputDelivery.FILE and "{input}" not in " ".join(self.argv):
            raise ValueError(
                "execution.delivery='file' requires {input} in execution.argv"
            )
        return self


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


class TestsConfig(Base):
    #: Test manifests, resolved relative to the config file.
    manifests: list[str] = Field(default_factory=list)
    #: Directory holding dynAn's generated regression suite. Kept inside the
    #: project rather than the target repo, so validation never mutates the
    #: user's sources.
    regression_suite: str = "regression"
    #: Whether previously generated regression tests participate in this run.
    include_generated: bool = True

    @model_validator(mode="after")
    def _check(self) -> TestsConfig:
        if not self.manifests:
            raise ValueError("tests.manifests must list at least one manifest")
        return self


# --------------------------------------------------------------------------
# Sandbox
# --------------------------------------------------------------------------


class SandboxConfig(Base):
    """Isolation backend.

    PDF section 5 requires all tests to run in an isolated environment with
    resource limits. ``none`` exists for debugging on a trusted fixture and is
    never selected automatically: if a configured backend is unavailable the
    run fails with a build/config error rather than silently falling back to
    unrestricted host execution.
    """

    #: ``container`` picks podman when available and falls back to docker;
    #: naming a specific runtime forces it.
    backend: Literal["bwrap", "container", "podman", "docker", "none"] = "bwrap"
    #: Container image, used by the container backends only.
    image: str = "docker.io/library/gcc:13"
    #: Network inside the sandbox. Off by default for build and test.
    network: bool = False
    #: Extra read-only host paths the target may see.
    ro_binds: list[str] = Field(default_factory=list)
    #: Explicitly allow running without isolation. Must be set *and* backend
    #: must be "none"; a missing backend never degrades to this automatically.
    allow_unsandboxed: bool = False

    @model_validator(mode="after")
    def _check(self) -> SandboxConfig:
        if self.backend == "none" and not self.allow_unsandboxed:
            raise ValueError(
                "sandbox.backend='none' also requires sandbox.allow_unsandboxed: true. "
                "Running untrusted build scripts and targets on the host is unsafe and "
                "violates the isolation requirement."
            )
        return self


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


class AnalysisConfig(Base):
    #: PDF 3.3 mandates at least three replays per confirmed finding.
    replay_count: Annotated[int, Field(ge=3)] = 3
    minimize: bool = True
    minimization_max_iterations: Annotated[int, Field(ge=1)] = 400
    minimization_timeout_s: float = 120.0
    generate_regression_tests: bool = True
    #: Verify generated regression tests by executing them on both versions.
    verify_generated_tests: bool = True
    correlate: bool = True
    hardening: bool = True
    #: Profiles the test suite runs on. Both are required by PDF 3.2, which
    #: demands release and instrumented results be reported separately.
    profiles: list[BuildProfile] = Field(
        default_factory=lambda: [BuildProfile.RELEASE, BuildProfile.SANITIZED]
    )

    @model_validator(mode="after")
    def _check(self) -> AnalysisConfig:
        if not self.profiles:
            raise ValueError("analysis.profiles must not be empty")
        return self


class ArtifactsConfig(Base):
    #: Root for run storage, resolved relative to the config file.
    root: str = ".dynan"
    #: Keep prepared source worktrees after the run (useful for debugging).
    keep_worktrees: bool = False


# --------------------------------------------------------------------------
# Optional extensions
# --------------------------------------------------------------------------


class LlmConfig(Base):
    """Optional LLM advisor. Disabled by default and never load-bearing."""

    enabled: bool = False
    provider: Literal["openai", "openai_compatible", "local"] = "openai"
    base_url: str | None = None
    model: str = "gpt-4o-mini"
    #: Name of the environment variable holding the key. The key itself is
    #: never stored in configuration.
    api_key_env: str = "OPENAI_API_KEY"
    timeout_s: float = 60.0
    max_retries: int = 2
    #: Source code leaves the machine only with explicit opt-in.
    allow_source_upload: bool = False
    max_prompt_chars: int = 24_000


class ExtensionsConfig(Base):
    #: Names of optional extensions to activate. Unknown names are reported as
    #: configuration errors rather than ignored.
    enabled: list[str] = Field(default_factory=list)
    llm: LlmConfig = Field(default_factory=LlmConfig)

    @model_validator(mode="after")
    def _check(self) -> ExtensionsConfig:
        if self.llm.enabled and "llm" not in self.enabled:
            raise ValueError(
                "extensions.llm.enabled is true but 'llm' is not in extensions.enabled"
            )
        return self


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------


class DynanConfig(Base):
    version: int = CONFIG_VERSION
    target: TargetConfig
    source: SourceConfig
    build: BuildConfig
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    tests: TestsConfig
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    artifacts: ArtifactsConfig = Field(default_factory=ArtifactsConfig)
    extensions: ExtensionsConfig = Field(default_factory=ExtensionsConfig)

    #: Absolute path of the directory the config was loaded from. Populated by
    #: the loader; all relative paths in the file resolve against it.
    config_dir: str = ""
    config_path: str = ""

    @model_validator(mode="after")
    def _check_version(self) -> DynanConfig:
        if self.version != CONFIG_VERSION:
            raise ValueError(
                f"unsupported config version {self.version}; "
                f"this build of dynAn understands version {CONFIG_VERSION}"
            )
        return self
