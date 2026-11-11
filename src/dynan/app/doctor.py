"""Environment Doctor.

Checks that the environment can actually satisfy the workflow *before* a
validation starts, so a missing tool surfaces as a clear diagnostic instead of
a confusing failure deep inside a build.

The checks go beyond ``which``. A compiler on PATH that cannot link
AddressSanitizer, or a ``bwrap`` binary that cannot create a user namespace,
both pass a path lookup and then fail at the worst possible moment - so the
doctor compiles and runs a real instrumented program, and really creates a
sandbox.

Diagnostics are a shared structured model; the CLI and the web UI render the
same objects. Nothing here installs anything: remediation is advice, never an
action, and dynAn never invokes a privileged package manager.
"""

from __future__ import annotations

import platform
import shutil
import sys
import tempfile
from importlib import metadata
from pathlib import Path

from ..config.loader import ConfigError
from ..config.schema import DynanConfig, ResourceLimits
from ..config.testsuite import load_manifests, read_test_input
from ..domain.enums import BuildProfile, DependencyStatus
from ..domain.models import Diagnostic, DoctorReport
from ..infra import git
from ..infra.process import ExecSpec, probe_version, run_process, sanitizer_env
from ..infra.sandbox import Sandbox, SandboxUnavailable, build_sandbox

MIN_PYTHON = (3, 11)

#: Program used to prove the sanitizer toolchain genuinely works.
_ASAN_PROBE = """\
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(4);
    memset(buf, 'A', 8);   /* deliberate 4-byte heap overflow */
    int rc = buf[0];
    free(buf);
    return rc;
}
"""


def _distro_id() -> str:
    try:
        for line in Path("/etc/os-release").read_text("utf-8").splitlines():
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        pass
    return ""


def _install_hint(packages: dict[str, str]) -> str:
    """Build a distro-appropriate installation hint.

    ``packages`` maps a package-manager family to the package name.
    """
    distro = _distro_id()
    if distro in ("arch", "manjaro", "endeavouros") and "pacman" in packages:
        return f"sudo pacman -S {packages['pacman']}"
    if distro in ("fedora", "rhel", "centos") and "dnf" in packages:
        return f"sudo dnf install {packages['dnf']}"
    if distro in ("debian", "ubuntu", "linuxmint", "pop") and "apt" in packages:
        return f"sudo apt install {packages['apt']}"
    parts = [f"{mgr}: {pkg}" for mgr, pkg in packages.items()]
    return "install one of - " + "; ".join(parts)


def _ok(name: str, detail: str, *, version: str | None = None, category: str = "general",
        required: bool = True) -> Diagnostic:
    return Diagnostic(
        name=name,
        status=DependencyStatus.READY,
        required=required,
        detail=detail,
        version=version,
        category=category,
    )


def _missing(name: str, detail: str, remediation: str, *, required: bool = True,
             category: str = "general") -> Diagnostic:
    return Diagnostic(
        name=name,
        status=DependencyStatus.MISSING,
        required=required,
        detail=detail,
        remediation=remediation,
        category=category,
    )


def _broken(name: str, detail: str, remediation: str | None = None, *,
            required: bool = True, category: str = "general") -> Diagnostic:
    return Diagnostic(
        name=name,
        status=DependencyStatus.MISCONFIGURED,
        required=required,
        detail=detail,
        remediation=remediation,
        category=category,
    )


# --------------------------------------------------------------------------
# General checks
# --------------------------------------------------------------------------


def check_python() -> Diagnostic:
    current = sys.version_info[:3]
    text = ".".join(str(p) for p in current)
    if current[:2] < MIN_PYTHON:
        return Diagnostic(
            name="Python",
            status=DependencyStatus.UNSUPPORTED,
            required=True,
            detail=f"Python {text} is older than the required {MIN_PYTHON[0]}.{MIN_PYTHON[1]}",
            version=text,
            remediation="install a newer Python and recreate the virtual environment",
        )
    return _ok("Python", f"Python {text}", version=text)


def check_platform() -> Diagnostic:
    system = platform.system()
    machine = platform.machine()
    detail = f"{system} {platform.release()} on {machine}"
    if system != "Linux":
        return Diagnostic(
            name="Operating system",
            status=DependencyStatus.UNSUPPORTED,
            required=True,
            detail=f"{detail}; dynAn targets Linux ELF binaries",
            remediation="run dynAn on Linux x86_64, or inside a Linux container",
        )
    if machine not in ("x86_64", "amd64"):
        return Diagnostic(
            name="Operating system",
            status=DependencyStatus.UNSUPPORTED,
            required=True,
            detail=f"{detail}; the project scope is Linux x86_64",
            remediation="use an x86_64 host or an emulated x86_64 container",
        )
    return _ok("Operating system", detail)


def check_git() -> Diagnostic:
    if shutil.which("git") is None:
        return _missing(
            "git",
            "git is required for source resolution and diff generation",
            _install_hint({"pacman": "git", "apt": "git", "dnf": "git"}),
        )
    return _ok("git", "available", version=probe_version(["git", "--version"]))


def check_compiler(config: DynanConfig | None) -> Diagnostic:
    compiler = (config.build.env.get("CC") if config else None) or "cc"
    path = shutil.which(compiler)
    if path is None:
        return _missing(
            f"C compiler ({compiler})",
            f"'{compiler}' was not found on PATH",
            _install_hint({"pacman": "gcc", "apt": "build-essential", "dnf": "gcc"}),
            category="toolchain",
        )
    return _ok(
        f"C compiler ({compiler})",
        f"found at {path}",
        version=probe_version([compiler, "--version"]),
        category="toolchain",
    )


def check_build_tools(config: DynanConfig | None) -> list[Diagnostic]:
    """Verify the executables the configured build commands actually invoke."""
    if config is None:
        return []
    wanted: list[str] = []
    for profile in config.build.profiles.values():
        commands = profile.commands if profile.commands is not None else config.build.commands
        for argv in commands:
            if argv and argv[0] not in wanted:
                wanted.append(argv[0])

    diagnostics: list[Diagnostic] = []
    for tool in wanted:
        if Path(tool).is_absolute():
            exists = Path(tool).is_file()
            diagnostics.append(
                _ok(f"build tool ({tool})", "present", category="toolchain")
                if exists
                else _missing(
                    f"build tool ({tool})",
                    f"{tool} does not exist",
                    "correct the path in build.commands",
                    category="toolchain",
                )
            )
            continue
        path = shutil.which(tool)
        if path is None:
            diagnostics.append(
                _missing(
                    f"build tool ({tool})",
                    f"'{tool}' is referenced by build.commands but not found on PATH",
                    _install_hint({"pacman": tool, "apt": tool, "dnf": tool}),
                    category="toolchain",
                )
            )
        else:
            diagnostics.append(
                _ok(
                    f"build tool ({tool})",
                    f"found at {path}",
                    version=probe_version([tool, "--version"]),
                    category="toolchain",
                )
            )
    return diagnostics


def check_sanitizers(config: DynanConfig | None) -> Diagnostic:
    """Compile and run an instrumented program that must trigger ASan.

    A path lookup cannot tell us whether ``libasan`` is installed or whether
    the sanitizer runtime can map its shadow memory here, so we prove it.
    """
    compiler = (config.build.env.get("CC") if config else None) or "cc"
    if shutil.which(compiler) is None:
        return _missing(
            "AddressSanitizer / UndefinedBehaviorSanitizer",
            f"cannot test sanitizers because '{compiler}' is unavailable",
            _install_hint({"pacman": "gcc", "apt": "build-essential", "dnf": "gcc"}),
            category="toolchain",
        )

    flags = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-g", "-O1"]
    if config is not None:
        profile = config.build.profiles.get(BuildProfile.SANITIZED.value)
        if profile and profile.cflags:
            flags = list(profile.cflags)

    with tempfile.TemporaryDirectory(prefix="dynan-doctor-") as tmp:
        tmpdir = Path(tmp)
        source = tmpdir / "probe.c"
        binary = tmpdir / "probe"
        source.write_text(_ASAN_PROBE, encoding="utf-8")

        compile_result = run_process(
            ExecSpec(
                argv=[compiler, *flags, "-o", str(binary), str(source)],
                cwd=tmpdir,
                timeout_s=120.0,
                limits=ResourceLimits(memory_mb=None, cpu_s=120, processes=None),
                address_space_limit=False,
            )
        )
        if not compile_result.ok:
            tail = compile_result.stderr_text.strip().splitlines()[-3:]
            return _broken(
                "AddressSanitizer / UndefinedBehaviorSanitizer",
                "the sanitized profile does not compile: " + " / ".join(tail),
                _install_hint(
                    {"pacman": "gcc", "apt": "libasan8 libubsan1", "dnf": "libasan libubsan"}
                ),
                category="toolchain",
            )

        run_result = run_process(
            ExecSpec(
                argv=[str(binary)],
                cwd=tmpdir,
                env=sanitizer_env(ResourceLimits(memory_mb=None)),
                timeout_s=60.0,
                limits=ResourceLimits(memory_mb=None, cpu_s=60, processes=None),
                address_space_limit=False,
            )
        )
        if "AddressSanitizer" not in run_result.stderr_text:
            return _broken(
                "AddressSanitizer / UndefinedBehaviorSanitizer",
                "an instrumented program with a deliberate heap overflow produced no "
                "AddressSanitizer report; dynamic detection would silently miss defects",
                "check that the sanitizer runtime libraries are installed and that "
                "ASAN_OPTIONS is not overridden in your environment",
                category="toolchain",
            )

    return _ok(
        "AddressSanitizer / UndefinedBehaviorSanitizer",
        "instrumented build compiled and reported a deliberate overflow",
        category="toolchain",
    )


def check_sandbox(config: DynanConfig | None) -> Diagnostic:
    if config is None:
        return Diagnostic(
            name="Sandbox",
            status=DependencyStatus.NOT_REQUIRED,
            required=False,
            detail="no configuration supplied; the sandbox backend is configuration-driven",
            category="isolation",
        )

    backend = config.sandbox.backend
    try:
        sandbox: Sandbox = build_sandbox(config.sandbox)
    except SandboxUnavailable as exc:
        return _broken(
            f"Sandbox ({backend})", str(exc), "review the sandbox section of your config",
            category="isolation",
        )

    if backend == "none":
        return Diagnostic(
            name="Sandbox (none)",
            status=DependencyStatus.MISCONFIGURED,
            required=False,
            detail=(
                "isolation is disabled; target builds and binaries run directly on "
                "the host. The project specification requires an isolated environment"
            ),
            remediation="set sandbox.backend to 'bwrap' or 'container'",
            category="isolation",
        )

    probe = sandbox.selftest()
    if not probe.ok:
        hint = (
            _install_hint({"pacman": "bubblewrap", "apt": "bubblewrap", "dnf": "bubblewrap"})
            if backend == "bwrap"
            else _install_hint({"pacman": "podman", "apt": "podman", "dnf": "podman"})
        )
        return _broken(
            f"Sandbox ({sandbox.describe()})", probe.detail, hint, category="isolation"
        )
    return _ok(
        f"Sandbox ({sandbox.describe()})",
        probe.detail,
        version=probe.version,
        category="isolation",
    )


def check_python_packages(config: DynanConfig | None) -> list[Diagnostic]:
    """Core dependencies are required; optional extras only when enabled."""
    diagnostics: list[Diagnostic] = []

    for package in ("pydantic", "PyYAML", "rich", "typer"):
        try:
            version = metadata.version(package)
            diagnostics.append(
                _ok(f"python: {package}", "installed", version=version, category="packages")
            )
        except metadata.PackageNotFoundError:
            diagnostics.append(
                _missing(
                    f"python: {package}",
                    f"{package} is required by dynAn",
                    "pip install -e '.[web]'",
                    category="packages",
                )
            )

    llm_enabled = bool(config and config.extensions.llm.enabled)
    for package in ("fastapi", "uvicorn", "jinja2"):
        try:
            version = metadata.version(package)
            diagnostics.append(
                Diagnostic(
                    name=f"python: {package}",
                    status=DependencyStatus.READY,
                    required=False,
                    detail="installed (needed for the web UI)",
                    version=version,
                    category="packages",
                )
            )
        except metadata.PackageNotFoundError:
            diagnostics.append(
                Diagnostic(
                    name=f"python: {package}",
                    status=DependencyStatus.MISSING,
                    required=False,
                    detail="not installed; the CLI works without it, 'dynan ui' does not",
                    remediation="pip install -e '.[web]'",
                    category="packages",
                )
            )

    # An optional dependency is only a problem when its feature is switched on.
    try:
        version = metadata.version("httpx")
        diagnostics.append(
            Diagnostic(
                name="python: httpx",
                status=DependencyStatus.READY,
                required=llm_enabled,
                detail="installed (needed only by the optional LLM extension)",
                version=version,
                category="packages",
            )
        )
    except metadata.PackageNotFoundError:
        diagnostics.append(
            Diagnostic(
                name="python: httpx",
                status=(
                    DependencyStatus.MISSING if llm_enabled else DependencyStatus.NOT_REQUIRED
                ),
                required=llm_enabled,
                detail=(
                    "the LLM extension is enabled but httpx is not installed"
                    if llm_enabled
                    else "not installed; not needed because the LLM extension is disabled"
                ),
                remediation="pip install -e '.[llm]'" if llm_enabled else None,
                category="packages",
            )
        )

    return diagnostics


# --------------------------------------------------------------------------
# Configuration-specific checks
# --------------------------------------------------------------------------


def check_sources(config: DynanConfig) -> list[Diagnostic]:
    src = config.source
    diagnostics: list[Diagnostic] = []

    if src.mode == "directories":
        for label, raw in (("base", src.base_path), ("patched", src.patched_path)):
            path = Path(raw or "")
            if path.is_dir():
                diagnostics.append(
                    _ok(f"source: {label} directory", str(path), category="source")
                )
            else:
                diagnostics.append(
                    _missing(
                        f"source: {label} directory",
                        f"{path} does not exist or is not a directory",
                        f"correct source.{label}_path",
                        category="source",
                    )
                )

    elif src.mode == "local_git":
        repo = Path(src.repo_path or "")
        if not git.is_git_repo(repo):
            diagnostics.append(
                _missing(
                    "source: repository",
                    f"{repo} is not a git repository",
                    "correct source.repo_path",
                    category="source",
                )
            )
        else:
            diagnostics.append(_ok("source: repository", str(repo), category="source"))
            for label, rev in (("base", src.base_commit), ("patched", src.patched_commit)):
                try:
                    sha = git.resolve_commit(repo, rev or "")
                    diagnostics.append(
                        _ok(f"source: {label} commit", f"{rev} -> {sha[:12]}", category="source")
                    )
                except git.GitError as exc:
                    diagnostics.append(
                        _broken(
                            f"source: {label} commit",
                            str(exc),
                            f"check source.{label}_commit, or fetch the missing objects",
                            category="source",
                        )
                    )

    else:  # remote_git
        diagnostics.append(
            Diagnostic(
                name="source: remote repository",
                status=DependencyStatus.READY,
                required=True,
                detail=(
                    f"{src.repo_url} will be cloned or refreshed at run time; "
                    "network access is needed for the first run only"
                ),
                category="source",
            )
        )

    if src.patch_file:
        path = Path(src.patch_file)
        diagnostics.append(
            _ok("source: supplied patch", str(path), category="source")
            if path.is_file()
            else _missing(
                "source: supplied patch",
                f"{path} does not exist",
                "correct source.patch_file or remove it",
                category="source",
            )
        )

    return diagnostics


def check_tests(config: DynanConfig) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    existing = [m for m in config.tests.manifests if Path(m).is_file()]

    for manifest in config.tests.manifests:
        if Path(manifest).is_file():
            diagnostics.append(_ok("tests: manifest", manifest, category="tests"))
        else:
            diagnostics.append(
                _missing(
                    "tests: manifest",
                    f"{manifest} does not exist",
                    "correct tests.manifests",
                    category="tests",
                )
            )

    if not existing:
        return diagnostics

    try:
        specs = load_manifests(existing)
    except ConfigError as exc:
        diagnostics.append(
            _broken("tests: definitions", str(exc), "fix the manifest", category="tests")
        )
        return diagnostics

    missing_inputs = []
    for spec in specs:
        try:
            read_test_input(spec)
        except ConfigError as exc:
            missing_inputs.append(f"{spec.test_id}: {exc}")

    if missing_inputs:
        diagnostics.append(
            _broken(
                "tests: input files",
                "; ".join(missing_inputs[:5]),
                "check input_file paths in the manifest",
                category="tests",
            )
        )
        return diagnostics

    from ..config.testsuite import has_independent_oracle

    with_oracle = sum(1 for s in specs if has_independent_oracle(s))
    categories = sorted({s.category.value for s in specs})
    diagnostics.append(
        _ok(
            "tests: definitions",
            f"{len(specs)} test(s) across {', '.join(categories)}; "
            f"{with_oracle} carry an independent oracle",
            category="tests",
        )
    )
    if with_oracle == 0:
        diagnostics.append(
            Diagnostic(
                name="tests: independent oracle",
                status=DependencyStatus.MISCONFIGURED,
                required=False,
                detail=(
                    "no test defines both a provenance and a concrete assertion, so "
                    "no functional regression can be established"
                ),
                remediation=(
                    "add expect.provenance plus an assertion (exit_code, "
                    "stdout_exact, stdout_contains...) to your functional tests"
                ),
                category="tests",
            )
        )

    return diagnostics


def check_artifacts(config: DynanConfig) -> Diagnostic:
    root = Path(config.artifacts.root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".dynan-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return _broken(
            "artifacts directory",
            f"{root} is not writable: {exc}",
            "choose a writable artifacts.root",
            category="storage",
        )
    return _ok("artifacts directory", str(root), category="storage")


def check_extensions(config: DynanConfig) -> list[Diagnostic]:
    """Only enabled extensions are checked; disabled ones never block."""
    from ..ext.registry import available_extensions

    diagnostics: list[Diagnostic] = []
    known = available_extensions()

    for name in config.extensions.enabled:
        if name not in known:
            diagnostics.append(
                _broken(
                    f"extension: {name}",
                    f"unknown extension '{name}'; known: {', '.join(sorted(known)) or 'none'}",
                    "remove it from extensions.enabled",
                    category="extensions",
                )
            )
            continue
        diagnostics.extend(known[name].diagnose(config))

    if not config.extensions.enabled:
        diagnostics.append(
            Diagnostic(
                name="extensions",
                status=DependencyStatus.NOT_REQUIRED,
                required=False,
                detail="no optional extensions enabled",
                category="extensions",
            )
        )
    return diagnostics


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def run_doctor(config: DynanConfig | None = None) -> DoctorReport:
    """Produce the full diagnostic report, with or without a configuration."""
    diagnostics: list[Diagnostic] = [
        check_python(),
        check_platform(),
        check_git(),
        check_compiler(config),
    ]
    diagnostics.extend(check_build_tools(config))
    diagnostics.append(check_sanitizers(config))
    diagnostics.append(
        _ok(
            "ELF inspection",
            "built in; dynAn parses ELF headers directly and needs no external tool",
            category="toolchain",
        )
    )
    diagnostics.append(check_sandbox(config))
    diagnostics.extend(check_python_packages(config))

    if config is not None:
        diagnostics.extend(check_sources(config))
        diagnostics.extend(check_tests(config))
        diagnostics.append(check_artifacts(config))
        diagnostics.extend(check_extensions(config))

    return DoctorReport(
        diagnostics=diagnostics,
        config_path=config.config_path if config else None,
    )
