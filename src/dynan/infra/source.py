"""Source acquisition.

Three acquisition modes converge on one representation. Downstream stages -
diff, build, execution, correlation - never learn where the code came from.

Two invariants hold in every mode:

* The user's own directories and working trees are never modified. Local
  directories are copied; Git revisions are materialised as detached
  worktrees.
* Version identity is recorded honestly. A Git-backed source gets a commit
  SHA; a plain directory gets a content hash that is clearly labelled as such.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..config.schema import DynanConfig, SourceConfig
from ..domain.enums import Version
from ..domain.models import SourcePair, SourceRevision
from . import git

#: Directories never copied into a prepared tree.
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".dynan", "__pycache__", "*.pyc", ".mypy_cache", ".pytest_cache"
)


class SourceError(RuntimeError):
    """Source could not be acquired or identified."""


@dataclass(slots=True)
class PreparedSources:
    """Materialised trees plus the context the diff stage needs."""

    pair: SourcePair
    base_dir: Path
    patched_dir: Path
    #: Repository both revisions came from, when there is exactly one.
    repo: Path | None = None
    base_commit: str | None = None
    patched_commit: str | None = None
    #: Worktrees to remove during cleanup, as (repo, path) pairs.
    _worktrees: list[tuple[Path, Path]] = field(default_factory=list)

    @property
    def same_repository(self) -> bool:
        return self.repo is not None and bool(self.base_commit and self.patched_commit)

    def cleanup(self) -> None:
        for repo, path in self._worktrees:
            git.remove_worktree(repo, path)


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _describe_directory_revision(
    version: Version, source_dir: Path, prepared: Path
) -> SourceRevision:
    """Record identity for a plain directory, including Git info when present.

    If the directory happens to live inside a repository we capture the commit
    too, but we keep ``kind="directory"`` and flag ``dirty`` honestly, so a
    reader can tell whether the revision is exact.
    """
    commit: str | None = None
    short: str | None = None
    subject: str | None = None
    dirty = False

    if git.git_available() and git.is_git_repo(source_dir):
        root = git.repo_root(source_dir)
        if root is not None:
            try:
                commit = git.resolve_commit(root, "HEAD")
                info = git.commit_info(root, commit)
                short, subject = info.short, info.subject
                dirty = git.is_dirty(root)
            except git.GitError:
                commit = None

    return SourceRevision(
        version=version,
        kind="directory",
        path=str(prepared),
        commit=commit,
        short_commit=short,
        content_hash=git.content_hash(prepared),
        origin=str(source_dir),
        dirty=dirty or commit is None,
        subject=subject,
    )


def _copy_tree(src: Path, dest: Path) -> None:
    if not src.exists():
        raise SourceError(f"source directory does not exist: {src}")
    if not src.is_dir():
        raise SourceError(f"source path is not a directory: {src}")
    if dest.exists():
        shutil.rmtree(dest)
    try:
        shutil.copytree(src, dest, ignore=_COPY_IGNORE, symlinks=True)
    except OSError as exc:
        raise SourceError(f"could not copy {src} to {dest}: {exc}") from exc


def _prepare_worktree(
    repo: Path, rev: str, dest: Path, version: Version, origin: str
) -> tuple[SourceRevision, tuple[Path, Path]]:
    try:
        sha = git.resolve_commit(repo, rev)
    except git.GitError as exc:
        raise SourceError(str(exc)) from exc

    if dest.exists():
        shutil.rmtree(dest)
    try:
        git.add_worktree(repo, sha, dest)
    except git.GitError as exc:
        raise SourceError(f"could not create worktree for {rev}: {exc}") from exc

    info = git.commit_info(repo, sha)
    revision = SourceRevision(
        version=version,
        kind="git",
        path=str(dest),
        commit=sha,
        short_commit=info.short,
        content_hash=git.content_hash(dest),
        origin=origin,
        dirty=False,
        subject=info.subject,
    )
    return revision, (repo, dest)


def _ensure_remote_repo(cfg: SourceConfig, cache_dir: Path, url: str) -> Path:
    """Clone or refresh a remote repository in the shared cache."""
    repo = cache_dir / _cache_key(url)
    if repo.exists():
        # Only fetch when a required commit is genuinely missing, so repeated
        # runs do not hit the network for nothing.
        needed = [c for c in (cfg.base_commit, cfg.patched_commit) if c]
        if all(git.has_commit(repo, c) for c in needed):
            return repo
        try:
            git.fetch(repo, url)
        except git.GitError as exc:
            raise SourceError(f"could not fetch {url}: {exc}") from exc
        return repo

    try:
        git.clone(url, repo, depth=cfg.fetch_depth)
    except git.GitError as exc:
        raise SourceError(f"could not clone {url}: {exc}") from exc
    return repo


def resolve_sources(
    config: DynanConfig, *, workspace: Path, cache_dir: Path
) -> PreparedSources:
    """Materialise both versions into ``workspace`` and identify them."""
    if not git.git_available():
        raise SourceError("git is required for source resolution but was not found")

    src = config.source
    base_dir = workspace / "base"
    patched_dir = workspace / "patched"
    workspace.mkdir(parents=True, exist_ok=True)

    if src.mode == "directories":
        base_src = Path(src.base_path or "")
        patched_src = Path(src.patched_path or "")
        _copy_tree(base_src, base_dir)
        _copy_tree(patched_src, patched_dir)
        pair = SourcePair(
            base=_describe_directory_revision(Version.BASE, base_src, base_dir),
            patched=_describe_directory_revision(
                Version.PATCHED, patched_src, patched_dir
            ),
        )
        return PreparedSources(
            pair=pair, base_dir=base_dir, patched_dir=patched_dir
        )

    if src.mode == "local_git":
        repo = Path(src.repo_path or "")
        if not git.is_git_repo(repo):
            raise SourceError(f"not a git repository: {repo}")
        root = git.repo_root(repo) or repo
        base_rev, base_wt = _prepare_worktree(
            root, src.base_commit or "", base_dir, Version.BASE, str(root)
        )
        patched_rev, patched_wt = _prepare_worktree(
            root, src.patched_commit or "", patched_dir, Version.PATCHED, str(root)
        )
        return PreparedSources(
            pair=SourcePair(base=base_rev, patched=patched_rev),
            base_dir=base_dir,
            patched_dir=patched_dir,
            repo=root,
            base_commit=base_rev.commit,
            patched_commit=patched_rev.commit,
            _worktrees=[base_wt, patched_wt],
        )

    # mode == "remote_git"
    cache_dir.mkdir(parents=True, exist_ok=True)
    base_url = src.repo_url or ""
    patched_url = src.patched_repo_url or base_url

    base_repo = _ensure_remote_repo(src, cache_dir, base_url)
    patched_repo = (
        base_repo
        if patched_url == base_url
        else _ensure_remote_repo(src, cache_dir, patched_url)
    )

    base_rev, base_wt = _prepare_worktree(
        base_repo, src.base_commit or "", base_dir, Version.BASE, base_url
    )
    patched_rev, patched_wt = _prepare_worktree(
        patched_repo, src.patched_commit or "", patched_dir, Version.PATCHED, patched_url
    )

    single_repo = base_repo if base_repo == patched_repo else None
    return PreparedSources(
        pair=SourcePair(base=base_rev, patched=patched_rev),
        base_dir=base_dir,
        patched_dir=patched_dir,
        repo=single_repo,
        base_commit=base_rev.commit if single_repo else None,
        patched_commit=patched_rev.commit if single_repo else None,
        _worktrees=[base_wt, patched_wt],
    )
