"""Progress events.

Every event corresponds to something that actually happened in the pipeline.
There are no synthetic percentages: when the UI shows a stage as running, a
stage is running, and when it shows 7/12 tests executed, seven have finished.

Events are persisted to ``events.jsonl`` *and* fanned out to live subscribers,
so the web UI can follow a run in flight and still replay it afterwards from
the same data.
"""

from __future__ import annotations

import queue
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Protocol

from ..domain.enums import Stage, StageState
from ..domain.models import ProgressEvent, StageStatus
from ..infra.store import RunStore


class EventListener(Protocol):
    def __call__(self, event: ProgressEvent) -> None: ...


class EventEmitter:
    """Creates, persists and broadcasts progress events.

    Safe to use from a worker thread while HTTP handlers subscribe from
    another, which is how the web UI streams a run it just started.
    """

    def __init__(self, store: RunStore | None, run_id: str) -> None:
        self._store = store
        self._run_id = run_id
        self._lock = threading.Lock()
        self._sequence = 0
        self._listeners: list[EventListener] = []
        self._stages: dict[Stage, StageStatus] = {}

    # -- subscription ---------------------------------------------------

    def subscribe(self, listener: EventListener) -> None:
        with self._lock:
            self._listeners.append(listener)

    def unsubscribe(self, listener: EventListener) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    @contextmanager
    def stream(self, *, maxsize: int = 1000) -> Iterator[queue.Queue[ProgressEvent]]:
        """Context manager yielding a queue fed with live events."""
        channel: queue.Queue[ProgressEvent] = queue.Queue(maxsize=maxsize)

        def listener(event: ProgressEvent) -> None:
            try:
                channel.put_nowait(event)
            except queue.Full:
                # A slow consumer must never stall the pipeline.
                pass

        self.subscribe(listener)
        try:
            yield channel
        finally:
            self.unsubscribe(listener)

    # -- emitting -------------------------------------------------------

    def emit(
        self,
        message: str,
        *,
        stage: Stage | None = None,
        state: StageState | None = None,
        level: str = "info",
        **data: Any,
    ) -> ProgressEvent:
        with self._lock:
            self._sequence += 1
            event = ProgressEvent(
                sequence=self._sequence,
                stage=stage,
                state=state,
                level=level,  # type: ignore[arg-type]
                message=message,
                data=data,
            )
            listeners = list(self._listeners)

        if self._store is not None:
            try:
                self._store.append_event(self._run_id, event)
            except Exception:  # pragma: no cover - persistence must not abort a run
                pass

        for listener in listeners:
            try:
                listener(event)
            except Exception:  # pragma: no cover - a bad subscriber is not fatal
                pass

        return event

    # -- stage lifecycle ------------------------------------------------

    def stage_status(self) -> list[StageStatus]:
        from ..domain.enums import STAGE_ORDER

        with self._lock:
            known = dict(self._stages)
        return [known[s] for s in STAGE_ORDER if s in known]

    def start_stage(self, stage: Stage, message: str = "", **data: Any) -> None:
        with self._lock:
            self._stages[stage] = StageStatus(
                stage=stage,
                state=StageState.RUNNING,
                started_at=datetime.now(timezone.utc),
                message=message,
            )
        self.emit(
            message or f"{stage.value} started",
            stage=stage,
            state=StageState.RUNNING,
            **data,
        )

    def finish_stage(
        self,
        stage: Stage,
        state: StageState = StageState.COMPLETED,
        message: str = "",
        level: str | None = None,
        **data: Any,
    ) -> None:
        with self._lock:
            status = self._stages.get(stage) or StageStatus(stage=stage)
            status.state = state
            status.finished_at = datetime.now(timezone.utc)
            if message:
                status.message = message
            self._stages[stage] = status

        resolved_level = level or (
            "error" if state == StageState.FAILED else "info"
        )
        self.emit(
            message or f"{stage.value} {state.value}",
            stage=stage,
            state=state,
            level=resolved_level,
            **data,
        )

    def progress(
        self, stage: Stage, current: int, total: int, message: str, **data: Any
    ) -> None:
        """Report real completed-unit counts for a stage."""
        with self._lock:
            status = self._stages.get(stage)
            if status is not None:
                status.progress_current = current
                status.progress_total = total
        self.emit(
            message,
            stage=stage,
            state=StageState.RUNNING,
            current=current,
            total=total,
            **data,
        )

    @contextmanager
    def stage(self, stage: Stage, message: str = "") -> Iterator[None]:
        """Run a block as a stage, marking it failed if it raises."""
        self.start_stage(stage, message)
        try:
            yield
        except Exception as exc:
            self.finish_stage(stage, StageState.FAILED, f"{stage.value} failed: {exc}")
            raise
        else:
            status = next((s for s in self.stage_status() if s.stage == stage), None)
            if status is not None and status.state == StageState.RUNNING:
                self.finish_stage(stage, StageState.COMPLETED)
