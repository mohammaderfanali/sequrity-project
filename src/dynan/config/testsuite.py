"""Test manifest loading.

Test definitions live outside the main configuration file so a target's suite
can grow without touching tool settings, and so dynAn's generated regression
suite can be just another manifest.

The oracle described by a manifest must be independent of the patched program
(PDF section 2): every expectation carries a ``provenance`` string naming the
documentation or reference test it came from. dynAn refuses to treat an
expectation with no provenance as a correctness criterion for regression
detection.
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from ..domain.enums import InputDelivery, TestCategory
from ..domain.models import OracleExpectation, OutputFileExpectation, TestCaseSpec
from .loader import ConfigError, safe_load_strict

MANIFEST_VERSION = 1

#: Value meaning "nobody recorded where this expectation came from".
UNSPECIFIED_PROVENANCE = "unspecified"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _require_mapping(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{what} must be a mapping, found {type(value).__name__}")
    return value


def _parse_expectation(
    raw: dict[str, Any] | None,
    *,
    default_provenance: str,
    where: str,
) -> OracleExpectation:
    raw = dict(raw or {})
    unknown = set(raw) - {
        "exit_code",
        "stdout_exact",
        "stdout_contains",
        "stdout_regex",
        "stderr_contains",
        "output_file",
        "output_files",
        "must_not_crash",
        "max_duration_s",
        "provenance",
    }
    if unknown:
        raise ConfigError(f"{where}: unknown expectation keys: {', '.join(sorted(unknown))}")

    regex = raw.get("stdout_regex")
    if regex is not None:
        try:
            re.compile(regex)
        except re.error as exc:
            raise ConfigError(f"{where}: stdout_regex is not a valid regex: {exc}") from exc

    contains = raw.get("stdout_contains") or []
    if isinstance(contains, str):
        contains = [contains]
    stderr_contains = raw.get("stderr_contains") or []
    if isinstance(stderr_contains, str):
        stderr_contains = [stderr_contains]

    return OracleExpectation(
        exit_code=raw.get("exit_code"),
        stdout_exact=raw.get("stdout_exact"),
        stdout_contains=list(contains),
        stdout_regex=regex,
        stderr_contains=list(stderr_contains),
        output_files=_parse_output_files(raw, where),
        must_not_crash=bool(raw.get("must_not_crash", True)),
        max_duration_s=raw.get("max_duration_s"),
        provenance=raw.get("provenance") or default_provenance,
    )


def _parse_output_files(
    raw: dict[str, Any], where: str
) -> list[OutputFileExpectation]:
    """Parse ``output_file`` (one mapping) or ``output_files`` (a list)."""
    entries: list[Any] = []
    if "output_file" in raw:
        entries.append(raw["output_file"])
    if "output_files" in raw:
        listed = raw["output_files"]
        if not isinstance(listed, list):
            raise ConfigError(f"{where}: 'output_files' must be a list")
        entries.extend(listed)

    parsed: list[OutputFileExpectation] = []
    seen: set[str] = set()

    for entry in entries:
        # A bare string means "this file must exist".
        if isinstance(entry, str):
            entry = {"path": entry}
        item = _require_mapping(entry, f"{where}: output file")

        unknown = set(item) - {"path", "exists", "exact", "contains", "regex"}
        if unknown:
            raise ConfigError(
                f"{where}: unknown output file keys: {', '.join(sorted(unknown))}"
            )

        path = str(item.get("path") or "").strip()
        if not path:
            raise ConfigError(f"{where}: output file entry needs a 'path'")
        if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ConfigError(
                f"{where}: output file path {path!r} must be relative to the "
                "execution working directory and must not contain '..'"
            )
        if path in seen:
            raise ConfigError(f"{where}: duplicate output file path {path!r}")
        seen.add(path)

        regex = item.get("regex")
        if regex is not None:
            try:
                re.compile(regex)
            except re.error as exc:
                raise ConfigError(
                    f"{where}: output file {path!r} regex is invalid: {exc}"
                ) from exc

        contains = item.get("contains") or []
        if isinstance(contains, str):
            contains = [contains]

        exists = bool(item.get("exists", True))
        expectation = OutputFileExpectation(
            path=path,
            exists=exists,
            exact=item.get("exact"),
            contains=list(contains),
            regex=regex,
        )
        if not exists and expectation.has_content_assertion:
            raise ConfigError(
                f"{where}: output file {path!r} sets exists: false but also "
                "asserts content; a file cannot be both absent and matching"
            )
        parsed.append(expectation)

    return parsed


def _resolve_input(
    entry: dict[str, Any], manifest_dir: Path, where: str
) -> tuple[str | None, bytes | None]:
    """Return ``(input_path, inline_bytes)`` for one test entry."""
    given = [k for k in ("input_file", "input", "input_hex", "input_base64") if k in entry]
    if len(given) > 1:
        raise ConfigError(f"{where}: specify only one of {', '.join(given)}")
    if not given:
        return None, None

    key = given[0]
    if key == "input_file":
        raw_path = Path(str(entry["input_file"])).expanduser()
        path = raw_path if raw_path.is_absolute() else (manifest_dir / raw_path)
        if not path.is_file():
            raise ConfigError(f"{where}: input_file not found: {path}")
        return str(path.resolve()), None

    if key == "input":
        value = entry["input"]
        if not isinstance(value, str):
            raise ConfigError(f"{where}: 'input' must be a string")
        return None, value.encode("utf-8")

    if key == "input_hex":
        try:
            return None, bytes.fromhex(re.sub(r"\s+", "", str(entry["input_hex"])))
        except ValueError as exc:
            raise ConfigError(f"{where}: input_hex is not valid hex: {exc}") from exc

    try:
        return None, base64.b64decode(str(entry["input_base64"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(f"{where}: input_base64 is not valid base64: {exc}") from exc


def load_manifest(path: str | Path) -> list[TestCaseSpec]:
    """Load one manifest file into canonical test specs."""
    manifest_path = Path(path).expanduser().resolve()
    if not manifest_path.is_file():
        raise ConfigError(f"Test manifest not found: {manifest_path}")

    try:
        # Strict parsing: a duplicated key in a manifest would silently drop
        # a test definition, which is exactly the kind of quiet coverage loss
        # a validation tool must not have.
        raw = safe_load_strict(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Test manifest is not valid YAML: {manifest_path}", [str(exc)]) from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read test manifest: {manifest_path}", [str(exc)]) from exc

    if raw is None:
        raise ConfigError(f"Test manifest is empty: {manifest_path}")
    doc = _require_mapping(raw, f"{manifest_path}")

    version = doc.get("version", MANIFEST_VERSION)
    if version != MANIFEST_VERSION:
        raise ConfigError(
            f"{manifest_path}: unsupported manifest version {version} "
            f"(expected {MANIFEST_VERSION})"
        )

    manifest_dir = manifest_path.parent
    defaults = _require_mapping(doc.get("defaults") or {}, f"{manifest_path}: defaults")
    oracle_meta = _require_mapping(doc.get("oracle") or {}, f"{manifest_path}: oracle")
    default_provenance = str(oracle_meta.get("provenance") or UNSPECIFIED_PROVENANCE)

    entries = doc.get("tests")
    if not isinstance(entries, list) or not entries:
        raise ConfigError(f"{manifest_path}: 'tests' must be a non-empty list")

    default_delivery = InputDelivery(str(defaults.get("delivery", InputDelivery.STDIN.value)))
    default_timeout = defaults.get("timeout_s")
    default_argv = list(defaults.get("argv") or [])

    specs: list[TestCaseSpec] = []
    seen: set[str] = set()

    for index, item in enumerate(entries):
        where = f"{manifest_path.name}[{index}]"
        entry = _require_mapping(item, where)

        test_id = str(entry.get("id") or "").strip()
        if not test_id:
            raise ConfigError(f"{where}: missing 'id'")
        if not _ID_RE.match(test_id):
            raise ConfigError(
                f"{where}: id '{test_id}' must match {_ID_RE.pattern} "
                "(it is used in file names and URLs)"
            )
        if test_id in seen:
            raise ConfigError(f"{manifest_path}: duplicate test id '{test_id}'")
        seen.add(test_id)

        try:
            category = TestCategory(str(entry.get("category", TestCategory.VALID.value)))
        except ValueError as exc:
            raise ConfigError(
                f"{where}: unknown category '{entry.get('category')}'; expected one of "
                + ", ".join(c.value for c in TestCategory)
            ) from exc

        try:
            delivery = (
                InputDelivery(str(entry["delivery"]))
                if "delivery" in entry
                else default_delivery
            )
        except ValueError as exc:
            raise ConfigError(f"{where}: unknown delivery '{entry.get('delivery')}'") from exc

        input_path, inline = _resolve_input(entry, manifest_dir, where)
        if delivery in (InputDelivery.STDIN, InputDelivery.FILE) and input_path is None and inline is None:
            raise ConfigError(
                f"{where}: delivery='{delivery.value}' requires one of "
                "input_file / input / input_hex / input_base64"
            )

        expectation = _parse_expectation(
            entry.get("expect"),
            default_provenance=default_provenance,
            where=where,
        )

        specs.append(
            TestCaseSpec(
                test_id=test_id,
                category=category,
                description=str(entry.get("description") or ""),
                delivery=delivery,
                input_path=input_path,
                input_bytes=inline,
                argv=[str(a) for a in (entry.get("argv") or default_argv)],
                timeout_s=entry.get("timeout_s", default_timeout),
                expectation=expectation,
                expected_baseline_signature=entry.get("expect_baseline_signature"),
                generated=bool(entry.get("generated", False)),
                source_manifest=str(manifest_path),
            )
        )

    return specs


def load_manifests(paths: list[str]) -> list[TestCaseSpec]:
    """Load several manifests, rejecting test-id collisions across files."""
    specs: list[TestCaseSpec] = []
    origin: dict[str, str] = {}
    for p in paths:
        for spec in load_manifest(p):
            if spec.test_id in origin:
                raise ConfigError(
                    f"Duplicate test id '{spec.test_id}' in {spec.source_manifest} "
                    f"(already defined in {origin[spec.test_id]})"
                )
            origin[spec.test_id] = spec.source_manifest or p
            specs.append(spec)
    return specs


def validate_delivery(specs: list[TestCaseSpec], execution_argv: list[str]) -> None:
    """Check every test can actually receive its input.

    ``file`` and ``argv`` delivery work by substituting ``{input}`` into the
    command line. The global ``execution.argv`` is validated by the schema,
    but a *per-test* delivery override can differ from the global default - a
    suite whose global delivery is stdin may still contain one file-delivery
    test. Without this check that test would run with the input silently
    never reaching the program, and then "fail" for a reason that has nothing
    to do with the patch.
    """
    problems: list[str] = []
    global_argv = " ".join(execution_argv)

    for spec in specs:
        if spec.delivery not in (InputDelivery.FILE, InputDelivery.ARGV):
            continue
        combined = global_argv + " " + " ".join(spec.argv)
        if "{input}" not in combined:
            problems.append(
                f"test '{spec.test_id}' uses delivery='{spec.delivery.value}' but "
                "neither execution.argv nor the test's own argv contains {input}, "
                "so the input would never reach the target"
            )

    if problems:
        raise ConfigError("Test input delivery is misconfigured.", problems)


def read_test_input(spec: TestCaseSpec) -> bytes:
    """Return the bytes a test delivers, from file or inline definition."""
    if spec.input_bytes is not None:
        return spec.input_bytes
    if spec.input_path:
        try:
            return Path(spec.input_path).read_bytes()
        except OSError as exc:
            raise ConfigError(
                f"Cannot read input for test '{spec.test_id}': {spec.input_path}", [str(exc)]
            ) from exc
    return b""


def has_independent_oracle(spec: TestCaseSpec) -> bool:
    """Whether this test's expectation may be used as a correctness criterion.

    Requires both a recorded provenance and at least one concrete assertion.
    An expectation that only says "must not crash" is a safety check, not a
    functional-correctness oracle, so it cannot by itself prove a regression.
    """
    exp = spec.expectation
    if exp.provenance == UNSPECIFIED_PROVENANCE or not exp.provenance.strip():
        return False
    return any(
        (
            exp.exit_code is not None,
            exp.stdout_exact is not None,
            bool(exp.stdout_contains),
            exp.stdout_regex is not None,
            bool(exp.stderr_contains),
            # An assertion about a file the program writes is as concrete and
            # falsifiable as one about stdout; without this, a program whose
            # real output is a file could never support a regression claim.
            #
            # Bare existence does not count, though: "the file was created"
            # is closer to must_not_crash than to a statement about what the
            # program computed. Only asserted content - or an asserted
            # absence - is a correctness criterion.
            any(
                output.has_content_assertion or not output.exists
                for output in exp.output_files
            ),
        )
    )
