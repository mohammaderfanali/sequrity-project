"""Application services.

The public surface of dynAn's core. The CLI calls these functions directly and
the web API's route handlers call the same ones - no validation logic lives in
either front end, and the CLI never issues HTTP requests to the local server.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..config.schema import DynanConfig
from ..domain.models import (
    DoctorReport,
    ProgressEvent,
    RunSummary,
    StructuredDiff,
    ValidationRun,
)
from ..infra import diffing
from ..infra.source import SourceError, resolve_sources
from ..infra.store import RunStore, StoreError, generate_run_id
from . import doctor as doctor_module
from .events import EventEmitter, EventListener
from .pipeline import ValidationPipeline


@dataclass(slots=True)
class DiffPreview:
    """Result of computing a diff without running a full validation."""

    diff: StructuredDiff
    raw: str
    base_revision: str
    patched_revision: str


class ValidationService:
    """Entry point for everything a front end can ask dynAn to do."""

    def __init__(self, store: RunStore) -> None:
        self.store = store

    # -- construction ---------------------------------------------------

    @classmethod
    def for_config(cls, config: DynanConfig) -> ValidationService:
        store = RunStore(config.artifacts.root)
        store.ensure()
        return cls(store)

    @classmethod
    def for_root(cls, artifacts_root: str | Path) -> ValidationService:
        store = RunStore(artifacts_root)
        store.ensure()
        return cls(store)

    # -- validation -----------------------------------------------------

    def create_run_id(self) -> str:
        return generate_run_id()

    def validate(
        self,
        config: DynanConfig,
        *,
        run_id: str | None = None,
        listener: EventListener | None = None,
        emitter: EventEmitter | None = None,
    ) -> ValidationRun:
        """Execute a full validation and return the persisted run.

        Always returns a run with a decision attached - including when the
        environment, the build or the configuration was at fault. The caller
        reads ``run.decision.exit_code`` for the process exit status.
        """
        identifier = run_id or self.create_run_id()
        self.store.ensure()
        self.store.create(identifier)

        active = emitter or EventEmitter(self.store, identifier)
        if listener is not None:
            active.subscribe(listener)

        pipeline = ValidationPipeline(
            config, store=self.store, emitter=active, run_id=identifier
        )
        return pipeline.execute()

    # -- doctor ---------------------------------------------------------

    def doctor(self, config: DynanConfig | None = None) -> DoctorReport:
        return doctor_module.run_doctor(config)

    # -- diff preview ---------------------------------------------------

    def preview_diff(self, config: DynanConfig) -> DiffPreview:
        """Resolve both versions and diff them without building anything.

        Backs ``dynan show-diff`` and the UI's diff preview. Uses a temporary
        workspace so it never creates a run directory for a read-only action.
        """
        workspace = Path(tempfile.mkdtemp(prefix="dynan-diff-"))
        prepared = None
        try:
            prepared = resolve_sources(
                config, workspace=workspace, cache_dir=self.store.cache_dir
            )
            structured, raw = diffing.compute_diff(
                base_dir=prepared.base_dir,
                patched_dir=prepared.patched_dir,
                repo=prepared.repo,
                base_commit=prepared.base_commit,
                patched_commit=prepared.patched_commit,
            )
            return DiffPreview(
                diff=structured,
                raw=raw,
                base_revision=prepared.pair.base.display_revision,
                patched_revision=prepared.pair.patched.display_revision,
            )
        except SourceError as exc:
            raise ServiceError(str(exc)) from exc
        finally:
            if prepared is not None:
                prepared.cleanup()
            shutil.rmtree(workspace, ignore_errors=True)

    # -- run access -----------------------------------------------------

    def list_runs(self, *, limit: int | None = 50) -> list[RunSummary]:
        return self.store.list_summaries(limit=limit)

    def get_run(self, run_id: str) -> ValidationRun:
        try:
            return self.store.load(run_id)
        except StoreError as exc:
            raise ServiceError(str(exc)) from exc

    def latest_run(self) -> ValidationRun | None:
        run_id = self.store.latest_run_id()
        return self.get_run(run_id) if run_id else None

    def get_events(self, run_id: str, *, after: int = -1) -> list[ProgressEvent]:
        return self.store.read_events(run_id, after=after)

    def read_artifact(self, run_id: str, relative: str) -> bytes:
        try:
            return self.store.read_artifact(run_id, relative)
        except StoreError as exc:
            raise ServiceError(str(exc)) from exc

    def resolve_artifact_path(self, run_id: str, relative: str) -> Path:
        try:
            return self.store.resolve_artifact(run_id, relative)
        except StoreError as exc:
            raise ServiceError(str(exc)) from exc


class ServiceError(RuntimeError):
    """A service call failed in a way the caller should report, not crash on."""
