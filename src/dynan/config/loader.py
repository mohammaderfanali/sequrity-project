"""Loading, validating and path-resolving dynAn configuration.

Path resolution rule, applied uniformly and documented in the configuration
reference: **every path in a configuration file is resolved relative to the
directory containing that file**, unless it is already absolute. Paths that
describe locations *inside the target source tree* (``build.working_dir``,
``build.binary``, ``execution.working_dir``) are deliberately left alone,
because the tree does not exist yet at load time.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .schema import DynanConfig


class ConfigError(Exception):
    """Raised for unreadable, malformed or semantically invalid configuration.

    Carries a list of human-readable problems so the CLI and the web UI can
    present the same diagnostics.
    """

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.problems = problems or []

    def __str__(self) -> str:
        if not self.problems:
            return self.message
        bullets = "\n".join(f"  - {p}" for p in self.problems)
        return f"{self.message}\n{bullets}"


#: Config fields holding filesystem paths that resolve against the config dir.
_PATH_FIELDS: tuple[tuple[str, str], ...] = (
    ("source", "base_path"),
    ("source", "patched_path"),
    ("source", "repo_path"),
    ("source", "patch_file"),
    ("tests", "regression_suite"),
    ("artifacts", "root"),
)


def _format_validation_error(exc: ValidationError) -> list[str]:
    problems: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        problems.append(f"{loc}: {err['msg']}")
    return problems


def load_config_text(
    text: str,
    *,
    config_dir: Path,
    config_path: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> DynanConfig:
    """Parse and validate configuration from a YAML string.

    Separated from :func:`load_config` so the web UI can validate an uploaded
    configuration without writing it to disk first.
    """
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError("Configuration is not valid YAML.", [str(exc)]) from exc

    if raw is None:
        raise ConfigError("Configuration file is empty.")
    if not isinstance(raw, dict):
        raise ConfigError(
            "Configuration root must be a mapping.",
            [f"found {type(raw).__name__}"],
        )

    if overrides:
        raw = apply_overrides(raw, overrides)

    raw["config_dir"] = str(config_dir.resolve())
    raw["config_path"] = str(config_path.resolve()) if config_path else ""

    try:
        config = DynanConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(
            "Configuration is invalid.", _format_validation_error(exc)
        ) from exc

    return resolve_paths(config)


def load_config(
    path: str | os.PathLike[str],
    *,
    overrides: dict[str, Any] | None = None,
) -> DynanConfig:
    """Load configuration from ``path``."""
    cfg_path = Path(path).expanduser()
    if not cfg_path.exists():
        raise ConfigError(f"Configuration file not found: {cfg_path}")
    if not cfg_path.is_file():
        raise ConfigError(f"Configuration path is not a file: {cfg_path}")

    try:
        text = cfg_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration file: {cfg_path}", [str(exc)]) from exc

    return load_config_text(
        text,
        config_dir=cfg_path.parent,
        config_path=cfg_path,
        overrides=overrides,
    )


def resolve_paths(config: DynanConfig) -> DynanConfig:
    """Return a copy of ``config`` with config-relative paths made absolute."""
    base = Path(config.config_dir or ".").resolve()

    def absolutise(value: str) -> str:
        p = Path(value).expanduser()
        return str(p if p.is_absolute() else (base / p).resolve())

    data = config.model_dump()

    for section, field in _PATH_FIELDS:
        value = data.get(section, {}).get(field)
        if isinstance(value, str) and value:
            data[section][field] = absolutise(value)

    data["tests"]["manifests"] = [
        absolutise(m) for m in data["tests"]["manifests"]
    ]
    data["sandbox"]["ro_binds"] = [
        absolutise(b) for b in data["sandbox"]["ro_binds"]
    ]

    return DynanConfig.model_validate(data)


def apply_overrides(raw: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Apply dotted-key overrides, e.g. ``{"analysis.minimize": False}``.

    Used for CLI flags such as ``--no-minimize`` so that frequently changed
    values do not require editing the file. Only existing sections may be
    targeted; a typo raises rather than silently creating a dead key.
    """
    result = dict(raw)
    for dotted, value in overrides.items():
        if value is None:
            continue
        parts = dotted.split(".")
        cursor: dict[str, Any] = result
        for part in parts[:-1]:
            nxt = cursor.get(part)
            if nxt is None:
                nxt = {}
                cursor[part] = nxt
            elif not isinstance(nxt, dict):
                raise ConfigError(
                    f"Cannot apply override '{dotted}': "
                    f"'{part}' is not a configuration section."
                )
            cursor = nxt
        cursor[parts[-1]] = value
    return result
