"""Local web application.

Pages are server-rendered from the same canonical models the CLI prints. The
browser-side JavaScript only streams progress and switches tabs; it never
decides a status, a severity or a verdict.

There is deliberately no separate HTML report generator: this interface *is*
the report viewer, for live and historical runs alike.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import PRODUCT_NAME, __version__
from ..app.service import ServiceError, ValidationService
from ..config.schema import DynanConfig
from ..domain.enums import CorrelationVerdict, Severity, TestOutcome
from ..infra.store import is_valid_run_id
from .api import build_router
from .diffview import file_to_hunks
from .runner import RunManager

_HERE = Path(__file__).parent
_TEMPLATES = _HERE / "templates"
_STATIC = _HERE / "static"


def _discover_configs(default: DynanConfig | None) -> list[str]:
    """Offer nearby configuration files in the new-validation form."""
    candidates: list[Path] = []
    roots = [Path.cwd(), Path.cwd() / "configs"]
    if default and default.config_path:
        roots.append(Path(default.config_path).parent)
    for root in roots:
        if root.is_dir():
            candidates.extend(sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml")))

    seen: list[str] = []
    for path in candidates:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.append(resolved)
    return seen


def create_app(
    *, artifacts_root: str | Path, default_config: DynanConfig | None = None
) -> FastAPI:
    service = ValidationService.for_root(artifacts_root)
    manager = RunManager(service)

    app = FastAPI(
        title=f"{PRODUCT_NAME} local UI",
        version=__version__,
        docs_url=None,
        redoc_url=None,
    )
    app.include_router(build_router(service, manager))
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    templates = Jinja2Templates(directory=str(_TEMPLATES))
    templates.env.globals.update(
        product=PRODUCT_NAME,
        version=__version__,
        artifacts_root=str(service.store.root),
        # Diff alignment is computed on the server from the canonical model,
        # so the browser never reimplements it.
        side_by_side=file_to_hunks,
    )
    templates.env.filters["severity_class"] = _severity_class
    templates.env.filters["outcome_class"] = _outcome_class
    templates.env.filters["verdict_class"] = _verdict_class
    templates.env.filters["duration"] = _duration

    @app.on_event("shutdown")
    def _shutdown() -> None:  # pragma: no cover - lifecycle hook
        manager.shutdown()

    # -- pages ----------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(
            request,
            "runs.html",
            {
                "nav": "runs",
                "runs": service.list_runs(limit=100),
                "active": {r.run_id for r in manager.active_runs()},
            },
        )

    @app.get("/new", response_class=HTMLResponse)
    def new_validation(request: Request):
        return templates.TemplateResponse(
            request,
            "new.html",
            {
                "nav": "new",
                "configs": _discover_configs(default_config),
                "default_config": default_config.config_path if default_config else "",
            },
        )

    @app.get("/doctor", response_class=HTMLResponse)
    def doctor_page(request: Request, config_path: str | None = None):
        config = None
        error = None
        if config_path:
            from ..config.loader import ConfigError, load_config

            try:
                config = load_config(config_path)
            except ConfigError as exc:
                error = str(exc)

        report = service.doctor(config) if error is None else None
        return templates.TemplateResponse(
            request,
            "doctor.html",
            {
                "nav": "doctor",
                "report": report,
                "error": error,
                "config_path": config_path or "",
                "configs": _discover_configs(default_config),
            },
        )

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: str):
        if not is_valid_run_id(run_id):
            raise HTTPException(status_code=400, detail="malformed run id")
        try:
            run = service.get_run(run_id)
        except ServiceError:
            # A run that exists but has not been persisted yet is still live;
            # show the progress view rather than a 404.
            if manager.is_running(run_id):
                return templates.TemplateResponse(
                    request,
                    "running.html",
                    {"nav": "runs", "run_id": run_id},
                )
            raise HTTPException(status_code=404, detail="no such run") from None

        return templates.TemplateResponse(
            request,
            "run.html",
            {
                "nav": "runs",
                "run": run,
                "live": manager.is_running(run_id),
                "failures": [
                    c for c in run.oracle_checks if c.outcome != TestOutcome.PASS
                ],
                "passed": sum(
                    1 for c in run.oracle_checks if c.outcome == TestOutcome.PASS
                ),
            },
        )

    @app.get("/runs/latest")
    def latest(request: Request):
        run_id = service.store.latest_run_id()
        if run_id is None:
            return RedirectResponse("/")
        return RedirectResponse(f"/runs/{run_id}")

    return app


# -- template filters ---------------------------------------------------


def _severity_class(value) -> str:
    return {
        Severity.MEMORY_SAFETY: "sev-high",
        Severity.UNDEFINED_BEHAVIOR: "sev-medium",
        Severity.CRASH: "sev-medium",
        Severity.RESOURCE: "sev-low",
        Severity.BENIGN: "sev-none",
    }.get(value, "sev-none")


def _outcome_class(value) -> str:
    return {
        TestOutcome.PASS: "ok",
        TestOutcome.FAIL: "bad",
        TestOutcome.ERROR: "warn",
        TestOutcome.SKIPPED: "muted",
        TestOutcome.NOT_APPLICABLE: "muted",
    }.get(value, "muted")


def _verdict_class(value) -> str:
    """Map an exit code name or correlation verdict to a style token."""
    name = getattr(value, "name", None) or getattr(value, "value", str(value))
    return {
        "PASS": "ok",
        "VULN_REMAINS": "bad",
        "FUNC_REGRESSION": "warn",
        "BUILD_OR_CONFIG_ERROR": "info",
        "INCONCLUSIVE": "muted",
        CorrelationVerdict.DIRECT.value: "ok",
        CorrelationVerdict.INDIRECT.value: "warn",
        CorrelationVerdict.UNRELATED.value: "muted",
        CorrelationVerdict.UNKNOWN.value: "info",
    }.get(name, "muted")


def _duration(value) -> str:
    if value is None:
        return "-"
    if value < 60:
        return f"{value:.1f}s"
    minutes, seconds = divmod(int(value), 60)
    return f"{minutes}m {seconds:02d}s"
