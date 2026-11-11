"""Background execution of validations started from the web UI.

A validation takes minutes, so an HTTP request cannot wait for it. Runs
execute on a worker thread while the request returns a run id immediately;
progress reaches the browser through the same event stream the CLI prints.

The run itself goes through :class:`~dynan.app.service.ValidationService` -
identical code path, identical persistence - so a run started here is
indistinguishable from one started by the CLI, and vice versa.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

from ..app.events import EventEmitter
from ..app.service import ValidationService
from ..config.schema import DynanConfig
from ..domain.models import ValidationRun


@dataclass
class ActiveRun:
    """A run currently executing, with its live event emitter."""

    run_id: str
    config_path: str | None
    target_name: str
    emitter: EventEmitter
    future: Future[ValidationRun] | None = field(default=None, repr=False)

    @property
    def finished(self) -> bool:
        return self.future is not None and self.future.done()


class RunManager:
    """Tracks in-flight validations started from the UI."""

    def __init__(self, service: ValidationService, *, max_concurrent: int = 1) -> None:
        self.service = service
        # One at a time by default: concurrent validations would compete for
        # CPU and make timing-sensitive observations - timeouts, replay
        # stability - unreliable.
        self._pool = ThreadPoolExecutor(
            max_workers=max_concurrent, thread_name_prefix="dynan-run"
        )
        self._lock = threading.Lock()
        self._active: dict[str, ActiveRun] = {}

    def start(self, config: DynanConfig) -> ActiveRun:
        run_id = self.service.create_run_id()
        emitter = EventEmitter(self.service.store, run_id)
        active = ActiveRun(
            run_id=run_id,
            config_path=config.config_path or None,
            target_name=config.target.name,
            emitter=emitter,
        )

        with self._lock:
            self._active[run_id] = active

        active.future = self._pool.submit(self._execute, config, active)
        return active

    def _execute(self, config: DynanConfig, active: ActiveRun) -> ValidationRun:
        try:
            return self.service.validate(
                config, run_id=active.run_id, emitter=active.emitter
            )
        finally:
            # Keep the entry briefly so a client polling right after
            # completion still finds the emitter; it is pruned on next sweep.
            self._prune()

    def _prune(self) -> None:
        with self._lock:
            done = [
                run_id
                for run_id, run in self._active.items()
                if run.finished and run_id != getattr(self, "_keep", None)
            ]
            # Retain the most recent finished run so late SSE subscribers can
            # still attach and immediately read the terminal events.
            for run_id in done[:-1]:
                self._active.pop(run_id, None)

    def get(self, run_id: str) -> ActiveRun | None:
        with self._lock:
            return self._active.get(run_id)

    def is_running(self, run_id: str) -> bool:
        active = self.get(run_id)
        return active is not None and not active.finished

    def active_runs(self) -> list[ActiveRun]:
        with self._lock:
            return [run for run in self._active.values() if not run.finished]

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
