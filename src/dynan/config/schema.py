"""Versioned configuration schema.

Design goals, in order:

* A new target must be addable by editing configuration only - no code change.
  This is an explicit PDF requirement (section 2, "generalisability").
* Common cases stay short. Defaults cover a typical ``make``-based C project.
* No default silently weakens security validation: sanitizers stay on, the
  sandbox stays on, and network access during build/test stays off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..domain.enums import BuildProfile, InputDelivery, Version

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


_GRAMMAR_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True, slots=True)
class GrammarToken:
    """One piece of a grammar alternative: literal text or a reference."""

    is_reference: bool
    value: str


def tokenize_grammar_alternative(
    text: str, *, where: str = "grammar alternative"
) -> tuple[GrammarToken, ...]:
    """Split an alternative into literals and references.

    A single left-to-right scan rather than a regular expression. The regex
    approach that this replaced used a negative lookbehind to skip ``{{``, and
    it got ``{{{b}}}`` wrong - the inner reference went unexpanded - because a
    lookbehind cannot tell an escaped brace from the start of a reference once
    they are adjacent.

    Malformed references are **errors**, not literal text. Silently treating
    ``{ value }`` or ``{valu`` as literal means a typo in a grammar produces a
    fuzzer that quietly explores nothing, with no diagnostic anywhere.

    Grammar:

    * ``{{`` -> literal ``{``
    * ``}}`` -> literal ``}``
    * ``{name}`` -> reference to rule ``name``
    * any other ``{`` or ``}`` -> error
    """
    tokens: list[GrammarToken] = []
    literal: list[str] = []
    index = 0
    length = len(text)

    def flush() -> None:
        if literal:
            tokens.append(GrammarToken(False, "".join(literal)))
            literal.clear()

    while index < length:
        char = text[index]

        if char == "{":
            if index + 1 < length and text[index + 1] == "{":
                literal.append("{")
                index += 2
                continue
            close = text.find("}", index + 1)
            if close == -1:
                raise ValueError(
                    f"{where}: unterminated '{{' in {text!r}. "
                    "Write '{{' for a literal opening brace."
                )
            name = text[index + 1 : close]
            if not _GRAMMAR_IDENT.fullmatch(name):
                raise ValueError(
                    f"{where}: {'{' + name + '}'!r} in {text!r} is not a valid "
                    "reference. A reference is '{name}' with no spaces, where "
                    "name matches [A-Za-z_][A-Za-z0-9_]*. Write '{{' and '}}' "
                    "for literal braces."
                )
            flush()
            tokens.append(GrammarToken(True, name))
            index = close + 1
            continue

        if char == "}":
            if index + 1 < length and text[index + 1] == "}":
                literal.append("}")
                index += 2
                continue
            raise ValueError(
                f"{where}: stray '}}' in {text!r}. "
                "Write '}}' for a literal closing brace."
            )

        literal.append(char)
        index += 1

    flush()
    return tuple(tokens)


def grammar_references(text: str, *, where: str = "grammar alternative") -> list[str]:
    """Rule names referenced by one alternative."""
    return [t.value for t in tokenize_grammar_alternative(text, where=where) if t.is_reference]


def grammar_expansion_costs(rules: dict[str, list[str]]) -> dict[str, int]:
    """Cheapest number of expansion steps each rule needs to terminate.

    A rule is *productive* when at least one of its alternatives can be fully
    expanded into literal text in finitely many steps. Requiring every rule to
    have a reference-free alternative would be too strict - ``document:
    ["{line}"]`` terminates perfectly well when ``line`` does - so this
    computes the real property by fixpoint instead.

    The costs are also what makes generation terminate deterministically: past
    the depth budget the generator picks a cheapest alternative, which always
    closes the branch.

    Raises ``ValueError`` naming the rules that can never terminate.
    """
    costs: dict[str, int] = {}

    changed = True
    while changed:
        changed = False
        for name, alternatives in rules.items():
            best: int | None = None
            for alternative in alternatives:
                references = grammar_references(
                    alternative, where=f"grammar rule '{name}'"
                )
                if not references:
                    candidate = 0
                elif all(ref in costs for ref in references):
                    candidate = 1 + max(costs[ref] for ref in references)
                else:
                    continue
                if best is None or candidate < best:
                    best = candidate
            if best is not None and (name not in costs or best < costs[name]):
                costs[name] = best
                changed = True

    unproductive = sorted(set(rules) - set(costs))
    if unproductive:
        raise ValueError(
            "grammar rule(s) "
            + ", ".join(f"'{name}'" for name in unproductive)
            + " can never terminate: every alternative leads back into an "
            "endlessly recursive rule. Give at least one of them an "
            "alternative that reaches literal text."
        )
    return costs


class GrammarConfig(Base):
    """A context-free grammar used to generate structurally valid inputs.

    Purely random bytes almost never get past a parser's first validity check,
    so they only ever exercise the rejection path. A grammar lets the fuzzer
    produce inputs that reach the deeper code the patch actually touches.

    Format: ``rules`` maps a non-terminal to its alternatives. Inside an
    alternative, ``{name}`` expands the non-terminal ``name``; everything else
    is a literal. Use ``{{`` and ``}}`` for literal braces.

    Termination is guaranteed by ``max_depth``: past that depth the generator
    only picks alternatives that contain no references, so a left-recursive
    rule like ``value: ["x", "{value}{value}"]`` is safe.
    """

    #: Non-terminal the generator starts from.
    start: str = Field(..., min_length=1)
    rules: dict[str, list[str]] = Field(..., min_length=1)
    #: Expansion depth after which only terminal alternatives are chosen.
    max_depth: Annotated[int, Field(ge=1, le=64)] = 12

    @model_validator(mode="after")
    def _check(self) -> GrammarConfig:
        if self.start not in self.rules:
            raise ValueError(
                f"grammar.start '{self.start}' has no rule; "
                f"defined rules: {', '.join(sorted(self.rules))}"
            )

        for name, alternatives in self.rules.items():
            if not alternatives:
                raise ValueError(f"grammar rule '{name}' has no alternatives")
            for alternative in alternatives:
                # Tokenising here is what turns a malformed reference into a
                # configuration error instead of silent literal text.
                for referenced in grammar_references(
                    alternative, where=f"grammar rule '{name}'"
                ):
                    if referenced not in self.rules:
                        raise ValueError(
                            f"grammar rule '{name}' references undefined "
                            f"non-terminal '{referenced}'"
                        )

        # Proves the grammar terminates before a run ever expands it.
        grammar_expansion_costs(self.rules)
        return self


class FuzzConfig(Base):
    """Optional grammar- and mutation-based fuzzing.

    Findings from fuzzing are reported separately and never alter the official
    exit code: the specification judges a patch within the agreed test scope,
    and a fuzzer by definition invents inputs outside it. The honest path from
    a fuzz crash to the verdict is ``promote_to_regression`` - the input
    becomes a regression test, so the *next* run has it legitimately in scope.
    """

    enabled: bool = False
    #: Number of generated inputs to execute. The budget that matters most.
    iterations: Annotated[int, Field(ge=1, le=1_000_000)] = 300
    #: Wall-clock ceiling for the whole campaign.
    time_budget_s: float = 120.0
    #: Seed for the PRNG. Fixed by default so campaigns are reproducible;
    #: set to null for a different corpus on every run.
    seed: int | None = 1337
    max_input_bytes: Annotated[int, Field(ge=1)] = 8192
    #: "grammar" needs `grammar`; "mutation" mutates the existing test inputs;
    #: "both" alternates between them.
    strategy: Literal["grammar", "mutation", "both"] = "both"
    #: How generated inputs reach the target. Defaults to the suite's own
    #: ``execution.delivery``; set it to fuzz a different mechanism - a target
    #: that reads both stdin and a named file has two attack surfaces, and
    #: fuzzing only one of them tests only half the program.
    delivery: InputDelivery | None = None
    #: Extra arguments appended to ``execution.argv`` for generated inputs,
    #: exactly like a test case's own ``argv``. Needed when ``delivery`` is
    #: ``file`` or ``argv``, to place the ``{input}`` placeholder.
    argv: list[str] = Field(default_factory=list)
    grammar: GrammarConfig | None = None
    #: Which versions to fuzz. Fuzzing the patched build looks for defects the
    #: patch introduced or left behind; including the base lets dynAn tell the
    #: two apart instead of reporting a pre-existing bug as new.
    versions: list[Version] = Field(
        default_factory=lambda: [Version.BASE, Version.PATCHED]
    )
    #: Instrumented build by default - an uninstrumented binary silently
    #: tolerates most of what a fuzzer finds.
    profile: BuildProfile = BuildProfile.SANITIZED
    #: Re-run each candidate crash to separate real defects from flakes.
    confirm_replays: Annotated[int, Field(ge=1)] = 3
    minimize: bool = True
    minimization_max_iterations: Annotated[int, Field(ge=1)] = 150
    #: Emit confirmed, patched-version-only crashes into the regression suite.
    promote_to_regression: bool = True
    #: Stop after this many distinct signatures, so one noisy defect cannot
    #: consume the whole budget.
    max_findings: Annotated[int, Field(ge=1)] = 10

    @model_validator(mode="after")
    def _check(self) -> FuzzConfig:
        # Requirements are only enforced when the extension is switched on.
        # These defaults sit in every configuration, so validating them
        # unconditionally would make a grammar mandatory for users who never
        # asked for fuzzing at all.
        if not self.enabled:
            return self
        if self.strategy == "grammar" and self.grammar is None:
            raise ValueError(
                "extensions.fuzz.strategy='grammar' requires extensions.fuzz.grammar"
            )
        if not self.versions:
            raise ValueError("extensions.fuzz.versions must not be empty")
        return self


class ExtensionsConfig(Base):
    #: Names of optional extensions to activate. Unknown names are reported as
    #: configuration errors rather than ignored.
    enabled: list[str] = Field(default_factory=list)
    llm: LlmConfig = Field(default_factory=LlmConfig)
    fuzz: FuzzConfig = Field(default_factory=FuzzConfig)

    @model_validator(mode="after")
    def _check(self) -> ExtensionsConfig:
        for name in ("llm", "fuzz"):
            section = getattr(self, name)
            if section.enabled and name not in self.enabled:
                raise ValueError(
                    f"extensions.{name}.enabled is true but '{name}' is not in "
                    "extensions.enabled"
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

    @model_validator(mode="after")
    def _check_fuzz_delivery(self) -> DynanConfig:
        """A fuzz campaign must be able to deliver its generated input.

        Checked here rather than inside ``FuzzConfig`` because it depends on
        ``execution.argv``, which lives in a sibling section.
        """
        fuzz = self.extensions.fuzz
        if not fuzz.enabled:
            return self

        delivery = fuzz.delivery or self.execution.delivery
        if delivery in (InputDelivery.FILE, InputDelivery.ARGV):
            combined = " ".join([*self.execution.argv, *fuzz.argv])
            if "{input}" not in combined:
                raise ValueError(
                    f"extensions.fuzz delivery is '{delivery.value}' but neither "
                    "execution.argv nor extensions.fuzz.argv contains {input}, "
                    "so generated inputs would never reach the target"
                )
        return self

    def fuzz_delivery(self) -> InputDelivery:
        """Effective delivery mechanism for generated fuzz inputs."""
        return self.extensions.fuzz.delivery or self.execution.delivery
