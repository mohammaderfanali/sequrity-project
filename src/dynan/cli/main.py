"""``dynan`` command-line entry point.

Exit codes follow the project specification exactly and come straight from the
decision engine, so a CI pipeline can branch on them:

====  ==========================================================
  0   PASS
 10   VULN_REMAINS / NEW_ISSUE
 20   FUNC_REGRESSION
 30   BUILD_OR_CONFIG_ERROR
 40   INCONCLUSIVE
====  ==========================================================

Anything the CLI itself fails at - an unreadable configuration, a bad
argument - is a configuration error and exits 30, never 0 and never a
security code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.text import Text

from .. import PRODUCT_NAME, __version__
from ..config.loader import ConfigError, load_config
from ..domain.enums import ExitCode, StageState
from ..domain.models import ProgressEvent
from ..app.service import ServiceError, ValidationService
from . import render

app = typer.Typer(
    name="dynan",
    help=f"{PRODUCT_NAME} - dynamic security patch validation for C/C++ ELF targets.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
runs_app = typer.Typer(help="Inspect previously recorded validation runs.", no_args_is_help=True)
app.add_typer(runs_app, name="runs")

console = Console()
err_console = Console(stderr=True)

ConfigOption = Annotated[
    Path,
    typer.Option(
        "--config",
        "-c",
        help="Path to the dynAn configuration file.",
        exists=False,
        dir_okay=False,
    ),
]


def _fail(message: str, *, code: ExitCode = ExitCode.BUILD_OR_CONFIG_ERROR) -> None:
    """Report a tool-side failure and exit with the configuration-error code."""
    err_console.print(Text(f"error: {message}", style="bold red"))
    raise typer.Exit(code.value)


def _load(path: Path, overrides: dict | None = None):
    try:
        return load_config(path, overrides=overrides)
    except ConfigError as exc:
        _fail(str(exc))


# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the dynAn version."""
    console.print(f"{PRODUCT_NAME} {__version__}")


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


@app.command()
def doctor(
    config: Annotated[
        Optional[Path],
        typer.Option("--config", "-c", help="Also run configuration-specific checks."),
    ] = None,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the diagnostics as JSON.")
    ] = False,
) -> None:
    """Check that this environment can run a validation.

    Verifies the toolchain by compiling and running an instrumented probe and
    by really creating a sandbox - not just by looking for executables.
    """
    loaded = _load(config) if config else None
    service = (
        ValidationService.for_config(loaded)
        if loaded
        else ValidationService.for_root(Path.cwd() / ".dynan")
    )
    report = service.doctor(loaded)

    if as_json:
        console.print_json(report.model_dump_json(indent=2))
    else:
        console.print()
        render.render_doctor(console, report)

    raise typer.Exit(0 if report.ok else ExitCode.BUILD_OR_CONFIG_ERROR.value)


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


@app.command()
def validate(
    config: ConfigOption,
    json_out: Annotated[
        Optional[Path],
        typer.Option("--json-out", help="Write the full structured result to this path."),
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress progress output (for CI).")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Also print the stage timeline.")
    ] = False,
    no_minimize: Annotated[
        bool, typer.Option("--no-minimize", help="Skip input minimisation.")
    ] = False,
    no_regression: Annotated[
        bool,
        typer.Option("--no-regression", help="Do not generate regression tests."),
    ] = False,
    sandbox: Annotated[
        Optional[str],
        typer.Option("--sandbox", help="Override sandbox.backend for this run."),
    ] = None,
    artifacts: Annotated[
        Optional[Path],
        typer.Option("--artifacts", help="Override artifacts.root for this run."),
    ] = None,
) -> None:
    """Validate a security patch and exit with the specification's status code."""
    overrides: dict = {}
    if no_minimize:
        overrides["analysis.minimize"] = False
    if no_regression:
        overrides["analysis.generate_regression_tests"] = False
    if sandbox:
        overrides["sandbox.backend"] = sandbox
        if sandbox == "none":
            overrides["sandbox.allow_unsandboxed"] = True
    if artifacts:
        overrides["artifacts.root"] = str(artifacts)

    loaded = _load(config, overrides)
    service = ValidationService.for_config(loaded)

    listener = None
    if not quiet:
        listener = _progress_listener()
        console.print(
            Text(f"{PRODUCT_NAME} validating ", style="bold")
            + Text(loaded.target.name, style="bold cyan")
        )
        console.print()

    try:
        run = service.validate(loaded, listener=listener)
    except ServiceError as exc:
        _fail(str(exc))
    except KeyboardInterrupt:
        err_console.print(Text("\ninterrupted by user", style="yellow"))
        raise typer.Exit(ExitCode.INCONCLUSIVE.value)

    if json_out:
        try:
            json_out.parent.mkdir(parents=True, exist_ok=True)
            json_out.write_text(run.model_dump_json(indent=2), encoding="utf-8")
        except OSError as exc:
            err_console.print(Text(f"warning: could not write {json_out}: {exc}", style="yellow"))

    render.render_run(console, run, verbose=verbose)
    console.print(
        Text(
            f"Full result: {service.store.paths(run.run_id).results}",
            style="dim",
        )
    )

    code = run.decision.exit_code.value if run.decision else ExitCode.INCONCLUSIVE.value
    raise typer.Exit(code)


def _progress_listener():
    """Print real pipeline events as they happen."""

    def listener(event: ProgressEvent) -> None:
        if event.level == "debug":
            return
        stage = event.stage.value if event.stage else ""
        style = {"error": "red", "warning": "yellow"}.get(event.level, "")

        marker = "  "
        if event.state == StageState.RUNNING and not event.data.get("current"):
            marker = "> "
        elif event.state == StageState.COMPLETED:
            marker = "+ "
        elif event.state in (StageState.FAILED, StageState.BLOCKED):
            marker = "! "
        elif event.state == StageState.SKIPPED:
            marker = "- "

        prefix = Text(f"{marker}{stage:<11}", style="dim")
        console.print(prefix + Text(event.message, style=style))

    return listener


# --------------------------------------------------------------------------
# show-diff
# --------------------------------------------------------------------------


@app.command("show-diff")
def show_diff(
    config: ConfigOption,
    raw: Annotated[
        bool, typer.Option("--raw", help="Print the unified diff instead of a summary.")
    ] = False,
) -> None:
    """Resolve both versions and show the computed patch, without building."""
    loaded = _load(config)
    service = ValidationService.for_config(loaded)

    try:
        preview = service.preview_diff(loaded)
    except ServiceError as exc:
        _fail(str(exc))

    if raw:
        console.print(preview.raw or "(no differences)")
        raise typer.Exit(0)

    console.print()
    console.print(
        Text(f"{preview.base_revision}", style="cyan")
        + Text("  ->  ", style="dim")
        + Text(f"{preview.patched_revision}", style="cyan")
    )
    console.print()

    diff = preview.diff
    if diff.is_empty:
        console.print(Text("The two versions are identical.", style="yellow"))
        raise typer.Exit(0)

    from rich.table import Table

    table = Table(box=None, header_style="bold dim", pad_edge=False, show_edge=False)
    for column in ("File", "Change", "+", "-", "Changed functions"):
        table.add_column(column, overflow="fold")
    for file_diff in diff.files:
        table.add_row(
            file_diff.path,
            file_diff.change_kind,
            Text(f"+{file_diff.added_lines}", style="green"),
            Text(f"-{file_diff.removed_lines}", style="red"),
            ", ".join(file_diff.changed_functions) or "-",
        )
    console.print(table)
    console.print()
    console.print(
        Text(
            f"{diff.files_changed} file(s), +{diff.total_added}/-{diff.total_removed}",
            style="dim",
        )
    )


# --------------------------------------------------------------------------
# runs
# --------------------------------------------------------------------------


def _service_for(config: Optional[Path], artifacts: Optional[Path]) -> ValidationService:
    if artifacts:
        return ValidationService.for_root(artifacts)
    if config:
        return ValidationService.for_config(_load(config))
    default = Path.cwd() / ".dynan"
    if not default.exists():
        _fail(
            "no artifacts directory found. Pass --artifacts or --config so dynAn "
            "knows where runs are stored."
        )
    return ValidationService.for_root(default)


@runs_app.command("list")
def runs_list(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    artifacts: Annotated[Optional[Path], typer.Option("--artifacts")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Maximum rows.")] = 20,
) -> None:
    """List recorded validation runs, newest first."""
    service = _service_for(config, artifacts)
    console.print()
    render.render_run_list(console, service.list_runs(limit=limit))


@runs_app.command("show")
def runs_show(
    run_id: Annotated[str, typer.Argument(help="Run id, or 'latest'.")],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    artifacts: Annotated[Optional[Path], typer.Option("--artifacts")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the full run as JSON.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Show a stored run, including runs created by the web UI."""
    service = _service_for(config, artifacts)

    try:
        run = service.latest_run() if run_id == "latest" else service.get_run(run_id)
    except ServiceError as exc:
        _fail(str(exc))

    if run is None:
        _fail("no runs recorded yet")

    if as_json:
        sys.stdout.write(run.model_dump_json(indent=2) + "\n")
    else:
        render.render_run(console, run, verbose=verbose)

    # Re-exposing the verdict as an exit code makes 'runs show' usable in CI.
    raise typer.Exit(run.decision.exit_code.value if run.decision else ExitCode.INCONCLUSIVE.value)


@runs_app.command("events")
def runs_events(
    run_id: Annotated[str, typer.Argument(help="Run id, or 'latest'.")],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    artifacts: Annotated[Optional[Path], typer.Option("--artifacts")] = None,
) -> None:
    """Print the recorded progress events of a run."""
    service = _service_for(config, artifacts)
    identifier = run_id
    if run_id == "latest":
        latest = service.store.latest_run_id()
        if latest is None:
            _fail("no runs recorded yet")
        identifier = latest

    for event in service.get_events(identifier):
        stamp = event.timestamp.strftime("%H:%M:%S")
        stage = event.stage.value if event.stage else "-"
        console.print(
            Text(f"{stamp} {stage:<11} ", style="dim")
            + Text(event.message, style="red" if event.level == "error" else "")
        )


# --------------------------------------------------------------------------
# ui
# --------------------------------------------------------------------------


@app.command()
def ui(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    artifacts: Annotated[Optional[Path], typer.Option("--artifacts")] = None,
    host: Annotated[str, typer.Option("--host", help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8723,
    reload: Annotated[bool, typer.Option("--reload", hidden=True)] = False,
) -> None:
    """Start the local web UI.

    Binds to 127.0.0.1 by default; the interface is local-only and has no
    authentication, so exposing it on a public address is not recommended.
    """
    try:
        import uvicorn
    except ImportError:
        _fail(
            "the web UI needs the optional web dependencies. "
            "Install them with: pip install -e '.[web]'"
        )

    from ..web.app import create_app

    loaded = _load(config) if config else None
    root = (
        Path(artifacts)
        if artifacts
        else (Path(loaded.artifacts.root) if loaded else Path.cwd() / ".dynan")
    )

    application = create_app(artifacts_root=root, default_config=loaded)

    if host not in ("127.0.0.1", "localhost", "::1"):
        err_console.print(
            Text(
                f"warning: binding to {host} exposes dynAn beyond this machine; "
                "it has no authentication.",
                style="yellow",
            )
        )

    console.print(
        Text(f"{PRODUCT_NAME} UI", style="bold")
        + Text(f"  http://{host}:{port}", style="cyan")
    )
    console.print(Text(f"artifacts: {root}", style="dim"))
    uvicorn.run(application, host=host, port=port, log_level="warning", reload=reload)


def main() -> None:
    """Console-script entry point."""
    try:
        app()
    except ConfigError as exc:  # pragma: no cover - defensive
        err_console.print(Text(f"error: {exc}", style="bold red"))
        sys.exit(ExitCode.BUILD_OR_CONFIG_ERROR.value)


if __name__ == "__main__":  # pragma: no cover
    main()
