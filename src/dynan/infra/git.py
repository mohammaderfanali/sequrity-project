"""Git operations.

Git runs on the host rather than inside the sandbox: cloning needs network
access, which the build/execution sandbox deliberately denies. The separation
is intentional - network-based *acquisition* happens first, then everything
derived from untrusted repository content runs isolated.

dynAn never mutates a user's working tree. Checkouts are always produced as
separate worktrees or copies.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..config.schema import ResourceLimits
from .process import ExecSpec, RawResult, run_process, which

_SHA_RE = re.compile(r"^[0-9a-f]{4,40}$")

#: Git invocations are given generous time but still bounded.
_GIT_TIMEOUT_S = 600.0


class GitError(RuntimeError):
    """A git command failed. Message carries git's own stderr."""


@dataclass(slots=True)
class CommitInfo:
    sha: str
    short: str
    subject: str
    author: str
    committed_at: str


def git_available() -> bool:
    return which("git") is not None


def run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout_s: float = _GIT_TIMEOUT_S,
    network: bool = False,
    check: bool = True,
) -> RawResult:
    """Run a git command and optionally raise on failure."""
    env = {
        # Keep git non-interactive: a credential prompt would hang CI forever.
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GCM_INTERACTIVE": "never",
    }
    if not network:
        env["GIT_ALLOW_PROTOCOL"] = "file"

    result = run_process(
        ExecSpec(
            argv=["git", *args],
            cwd=cwd or Path.cwd(),
            env=env,
            timeout_s=timeout_s,
            limits=ResourceLimits(memory_mb=None, cpu_s=None, processes=None),
            max_output_bytes=40_000_000,
        )
    )
    if check and not result.ok:
        raise GitError(
            f"git {' '.join(args)} failed "
            f"(exit={result.exit_code}, signal={result.signal_name}): "
            f"{result.stderr_text.strip() or result.stdout_text.strip()}"
        )
    return result


def is_git_repo(path: Path) -> bool:
    if not path.exists():
        return False
    result = run_git(["rev-parse", "--is-inside-work-tree"], cwd=path, check=False)
    return result.ok and result.stdout_text.strip() == "true"


def repo_root(path: Path) -> Path | None:
    result = run_git(["rev-parse", "--show-toplevel"], cwd=path, check=False)
    if not result.ok:
        return None
    return Path(result.stdout_text.strip())


def looks_like_sha(rev: str) -> bool:
    return bool(_SHA_RE.match(rev.strip()))


def resolve_commit(repo: Path, rev: str) -> str:
    """Resolve any revision expression to a full 40-char SHA."""
    result = run_git(["rev-parse", "--verify", f"{rev}^{{commit}}"], cwd=repo, check=False)
    if not result.ok:
        raise GitError(
            f"revision '{rev}' does not exist in {repo}: "
            f"{result.stderr_text.strip()}"
        )
    return result.stdout_text.strip()


def commit_info(repo: Path, sha: str) -> CommitInfo:
    fmt = "%H%x00%h%x00%s%x00%an%x00%cI"
    result = run_git(["show", "-s", f"--format={fmt}", sha], cwd=repo)
    parts = result.stdout_text.strip().split("\0")
    while len(parts) < 5:
        parts.append("")
    return CommitInfo(
        sha=parts[0], short=parts[1], subject=parts[2], author=parts[3], committed_at=parts[4]
    )


def is_dirty(repo: Path) -> bool:
    """True when the working tree has staged or unstaged modifications."""
    result = run_git(["status", "--porcelain", "--untracked-files=no"], cwd=repo, check=False)
    return bool(result.ok and result.stdout_text.strip())


def clone(url: str, dest: Path, *, depth: int | None = None) -> None:
    """Clone ``url`` into ``dest``.

    Uses ``--no-checkout``: we only need the object database, since each
    version is materialised as its own worktree afterwards.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--no-checkout"]
    if depth:
        args += ["--depth", str(depth)]
    args += [url, str(dest)]
    run_git(args, timeout_s=_GIT_TIMEOUT_S, network=True)


def fetch(repo: Path, url: str | None = None, ref: str | None = None) -> None:
    args = ["fetch", "--tags", "--force"]
    if url:
        args.append(url)
        if ref:
            args.append(ref)
    run_git(args, cwd=repo, network=True)


def has_commit(repo: Path, sha: str) -> bool:
    result = run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo, check=False)
    return result.ok


def add_worktree(repo: Path, sha: str, dest: Path) -> None:
    """Materialise ``sha`` as a detached worktree at ``dest``.

    Worktrees are how dynAn keeps the user's checkout untouched while still
    getting a real, buildable tree per version.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    run_git(
        ["worktree", "add", "--detach", "--force", str(dest), sha],
        cwd=repo,
    )


def remove_worktree(repo: Path, dest: Path) -> None:
    run_git(["worktree", "remove", "--force", str(dest)], cwd=repo, check=False)


def diff_commits(repo: Path, base: str, patched: str) -> str:
    """Unified diff between two commits, with rename detection."""
    result = run_git(
        [
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--find-renames",
            "--unified=3",
            base,
            patched,
        ],
        cwd=repo,
    )
    return result.stdout_text


def diff_trees(base_dir: Path, patched_dir: Path) -> str:
    """Unified diff between two directories that share no history.

    ``git diff --no-index`` exits 1 when differences exist, which is success
    for our purposes, so the exit status is interpreted rather than checked.
    """
    result = run_git(
        [
            "-c", "core.quotePath=false",
            "diff",
            "--no-index",
            "--no-color",
            "--no-ext-diff",
            "--find-renames",
            "--unified=3",
            str(base_dir),
            str(patched_dir),
        ],
        check=False,
    )
    if result.exit_code not in (0, 1):
        raise GitError(
            f"git diff --no-index failed (exit={result.exit_code}): "
            f"{result.stderr_text.strip()}"
        )
    return result.stdout_text


def list_tracked_files(repo: Path, sha: str) -> list[str]:
    result = run_git(["ls-tree", "-r", "--name-only", sha], cwd=repo)
    return [line for line in result.stdout_text.splitlines() if line]


def content_hash(root: Path, *, ignore: set[str] | None = None) -> str:
    """Deterministic hash over a directory's file contents.

    Used for non-Git sources. It is explicitly *not* presented as a commit
    identifier anywhere in the product: the PDF requires exact version
    identification, so conflating the two would be dishonest.
    """
    ignore = ignore or {".git", ".dynan", "__pycache__", ".cache"}
    digest = hashlib.sha256()
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        # Match against the path *relative to the tree*. Checking the absolute
        # path would ignore every file whenever the tree itself happens to sit
        # under a directory named like one of the ignore entries - which is
        # exactly what happens for prepared sources under `.dynan/`.
        if any(part in ignore for part in path.relative_to(root).parts):
            continue
        if path.is_file() and not path.is_symlink():
            files.append(path)
    for path in sorted(files, key=lambda p: str(p.relative_to(root))):
        rel = str(path.relative_to(root)).encode()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        try:
            data = path.read_bytes()
        except OSError:
            data = b"<unreadable>"
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()
