"""Shared fixtures.

Integration tests compile and execute real C programs - mocked findings would
prove nothing about a tool whose entire job is dynamic analysis.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGETS = REPO_ROOT / "targets" / "confparse"
CONFIGS = REPO_ROOT / "configs"


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


requires_toolchain = pytest.mark.skipif(
    not (_have("gcc") or _have("cc")) or not _have("make"),
    reason="a C toolchain and make are required",
)

requires_git = pytest.mark.skipif(not _have("git"), reason="git is required")


def _sanitizers_work() -> bool:
    """Prove the sanitizer toolchain is usable.

    Delegates to dynAn's own Environment Doctor check rather than
    reimplementing it: the doctor compiles and runs an instrumented program
    with the project's real sanitized flags, so this skip condition matches
    exactly what a user would be told by ``dynan doctor``.
    """
    from dynan.app.doctor import check_sanitizers
    from dynan.domain.enums import DependencyStatus

    return check_sanitizers(None).status is DependencyStatus.READY


requires_sanitizers = pytest.mark.skipif(
    not _sanitizers_work(), reason="a working AddressSanitizer toolchain is required"
)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def targets_dir() -> Path:
    if not TARGETS.is_dir():
        pytest.skip("confparse fixture is not present")
    return TARGETS


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    path = tmp_path / "work"
    path.mkdir()
    return path


@pytest.fixture
def config_factory(tmp_path: Path, targets_dir: Path):
    """Build a working configuration pointing at a chosen patch variant.

    Artifacts land in the test's own tmp_path, so tests never touch the
    repository's ``.dynan`` directory or each other's runs.
    """
    import textwrap

    from dynan.config.loader import load_config

    def make(variant: str = "correct", *, extra: str = "", sandbox: str = "bwrap"):
        artifacts = tmp_path / "artifacts"
        suite = tmp_path / "regression"
        config_path = tmp_path / f"{variant}.yaml"
        sandbox_block = (
            "sandbox:\n  backend: none\n  allow_unsandboxed: true\n"
            if sandbox == "none"
            else f"sandbox:\n  backend: {sandbox}\n"
        )
        config_path.write_text(
            textwrap.dedent(f"""\
                version: 1
                target:
                  name: confparse-{variant}
                  language: c
                source:
                  mode: directories
                  base_path: {targets_dir / 'base'}
                  patched_path: {targets_dir / variant}
                build:
                  working_dir: "."
                  binary: build/confparse
                  commands:
                    - ["make", "clean"]
                    - ["make"]
                  env:
                    CC: gcc
                execution:
                  argv: ["{{binary}}"]
                  delivery: stdin
                  timeout_s: 10
                tests:
                  manifests:
                    - {targets_dir / 'tests' / 'manifest.yaml'}
                  regression_suite: {suite}
                artifacts:
                  root: {artifacts}
                """)
            + sandbox_block
            + extra
        )
        return load_config(config_path)

    return make
