"""Versioned internal API.

Route handlers do no validation work. They load a configuration, call an
application service and serialise the canonical models - the same objects the
CLI renders - so the two front ends cannot disagree about a run.

Security posture, for an interface that binds to localhost and has no login:

* Path parameters are validated before they reach the filesystem; artifact
  downloads resolve inside the run directory or fail.
* State-changing routes require a same-origin request, which stops a page in
  another tab from driving the local server.
* Configuration is loaded from paths the user supplies, so the API refuses to
  read anything that is not a readable dynAn configuration file.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from ..app.service import ServiceError, ValidationService
from ..config.loader import ConfigError, load_config
from ..domain.models import ProgressEvent
from ..infra.store import is_valid_run_id
from .runner import RunManager


def _require_same_origin(request: Request) -> None:
    """Reject cross-origin state-changing requests.

    The UI is local-only and unauthenticated, so without this a malicious page
    could POST to 127.0.0.1 and start runs. Requests with no Origin header
    (curl, the test client) are allowed; browsers always send one on
    cross-origin requests.
    """
    origin = request.headers.get("origin")
    if origin is None:
        return
    host = request.headers.get("host", "")
    if origin.split("://", 1)[-1] != host:
        raise HTTPException(
            status_code=403, detail="cross-origin requests are not accepted"
        )


def _valid_run(run_id: str) -> str:
    if not is_valid_run_id(run_id):
        raise HTTPException(status_code=400, detail="malformed run id")
    return run_id


def _load(path_text: str):
    path = Path(path_text).expanduser()
    if not path.is_file():
        raise HTTPException(status_code=400, detail=f"no such configuration: {path}")
    try:
        return load_config(path)
    except ConfigError as exc:
        raise HTTPException(
            status_code=422,
            detail={"message": exc.message, "problems": exc.problems},
        ) from exc


def build_router(service: ValidationService, manager: RunManager) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    # -- runs -----------------------------------------------------------

    @router.get("/runs")
    def list_runs(limit: int = Query(50, ge=1, le=500)) -> JSONResponse:
        summaries = service.list_runs(limit=limit)
        return JSONResponse(
            {
                "runs": [json.loads(s.model_dump_json()) for s in summaries],
                "active": [r.run_id for r in manager.active_runs()],
            }
        )

    @router.post("/runs", status_code=202)
    def start_run(
        request: Request, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        _require_same_origin(request)
        config_path = payload.get("config_path")
        if not config_path:
            raise HTTPException(status_code=400, detail="config_path is required")

        config = _load(str(config_path))
        active = manager.start(config)
        return JSONResponse(
            {"run_id": active.run_id, "target": active.target_name},
            status_code=202,
        )

    @router.get("/runs/{run_id}")
    def get_run(run_id: str) -> JSONResponse:
        _valid_run(run_id)
        try:
            run = service.get_run(run_id)
        except ServiceError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return JSONResponse(json.loads(run.model_dump_json()))

    @router.get("/runs/{run_id}/findings")
    def get_findings(run_id: str) -> JSONResponse:
        _valid_run(run_id)
        try:
            run = service.get_run(run_id)
        except ServiceError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return JSONResponse(
            {
                "findings": [json.loads(f.model_dump_json()) for f in run.findings],
                "comparisons": [
                    json.loads(c.model_dump_json()) for c in run.comparisons
                ],
                "correlations": [
                    json.loads(c.model_dump_json()) for c in run.correlations
                ],
            }
        )

    @router.get("/runs/{run_id}/diff")
    def get_diff(run_id: str) -> JSONResponse:
        _valid_run(run_id)
        try:
            run = service.get_run(run_id)
        except ServiceError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if run.diff is None:
            raise HTTPException(status_code=404, detail="this run has no diff")
        return JSONResponse(json.loads(run.diff.model_dump_json()))

    @router.get("/runs/{run_id}/artifacts")
    def get_artifact(run_id: str, path: str = Query(..., min_length=1)) -> FileResponse:
        _valid_run(run_id)
        try:
            resolved = service.resolve_artifact_path(run_id, path)
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not resolved.is_file():
            raise HTTPException(status_code=404, detail="artifact not found")
        return FileResponse(
            resolved,
            media_type="text/plain" if resolved.suffix in (".log", ".txt", ".patch") else None,
            filename=resolved.name,
        )

    # -- events ---------------------------------------------------------

    @router.get("/runs/{run_id}/events")
    async def stream_events(run_id: str, after: int = Query(-1)) -> StreamingResponse:
        """Server-Sent Events carrying real pipeline progress.

        Replays everything already persisted, then follows the live emitter
        when the run is still going. A finished run therefore streams its full
        history and closes, which is what lets the UI render past runs with
        the same component it uses for live ones.
        """
        _valid_run(run_id)

        active = manager.get(run_id)

        async def generate():
            sent = after
            for event in service.get_events(run_id, after=after):
                sent = max(sent, event.sequence)
                yield _sse(event)

            if active is None or active.finished:
                yield "event: end\ndata: {}\n\n"
                return

            loop = asyncio.get_running_loop()
            queue: asyncio.Queue[ProgressEvent] = asyncio.Queue(maxsize=500)

            def listener(event: ProgressEvent) -> None:
                loop.call_soon_threadsafe(_offer, queue, event)

            active.emitter.subscribe(listener)
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    except asyncio.TimeoutError:
                        # Keep proxies and the browser from closing an idle
                        # stream during a long build.
                        yield ": keep-alive\n\n"
                        if active.finished:
                            break
                        continue
                    if event.sequence <= sent:
                        continue
                    sent = event.sequence
                    yield _sse(event)
            finally:
                active.emitter.unsubscribe(listener)

            yield "event: end\ndata: {}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # -- environment ----------------------------------------------------

    @router.get("/doctor")
    def doctor(config_path: str | None = Query(None)) -> JSONResponse:
        config = _load(config_path) if config_path else None
        report = service.doctor(config)
        return JSONResponse(json.loads(report.model_dump_json()))

    @router.post("/config/validate")
    def validate_config(
        request: Request, payload: dict[str, Any] = Body(...)
    ) -> JSONResponse:
        """Check a configuration without running anything."""
        _require_same_origin(request)
        config = _load(str(payload.get("config_path", "")))
        return JSONResponse(
            {
                "ok": True,
                "target": config.target.name,
                "source_mode": config.source.mode,
                "sandbox": config.sandbox.backend,
                "manifests": config.tests.manifests,
            }
        )

    @router.post("/llm/test")
    def test_llm(request: Request, payload: dict[str, Any] = Body(...)) -> JSONResponse:
        """Test an LLM provider with a real request.

        Reports success only when a supported API call actually succeeds -
        reachability alone is never shown as a working connection.
        """
        _require_same_origin(request)
        config = _load(str(payload.get("config_path", "")))
        if not config.extensions.llm.enabled:
            return JSONResponse(
                {"ok": False, "detail": "the LLM extension is disabled in this configuration"}
            )
        from ..ext.llm.provider import LlmProvider

        ok, detail = LlmProvider(config.extensions.llm).test_connection()
        return JSONResponse({"ok": ok, "detail": detail})

    return router


def _offer(queue: asyncio.Queue, event: ProgressEvent) -> None:
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:  # pragma: no cover - slow client
        pass


def _sse(event: ProgressEvent) -> str:
    return f"id: {event.sequence}\nevent: progress\ndata: {event.model_dump_json()}\n\n"
