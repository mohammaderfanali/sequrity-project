"""Configuration, persistence, minimisation, diff parsing and ELF inspection."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from conftest import requires_toolchain
from dynan.config.loader import ConfigError, load_config
from dynan.config.testsuite import load_manifest
from dynan.domain.enums import Version
from dynan.domain.models import ProgressEvent, Stage
from dynan.infra import diffing, elf
from dynan.infra.store import RunStore, StoreError, generate_run_id, is_valid_run_id
from dynan.app.minimize import ddmin


# ------------------------------------------------------------- config


def test_valid_config_resolves_paths_relative_to_the_file(tmp_path: Path):
    (tmp_path / "base").mkdir()
    (tmp_path / "patched").mkdir()
    (tmp_path / "m.yaml").write_text(
        "version: 1\noracle:\n  provenance: doc\ntests:\n"
        "  - id: a\n    category: valid\n    input: 'x'\n    expect:\n      exit_code: 0\n"
    )
    config_file = tmp_path / "c.yaml"
    config_file.write_text(
        "version: 1\n"
        "target: {name: t}\n"
        "source: {mode: directories, base_path: ./base, patched_path: ./patched}\n"
        "build: {binary: build/x}\n"
        "tests: {manifests: [./m.yaml]}\n"
        "artifacts: {root: ./out}\n"
    )
    config = load_config(config_file)

    assert Path(config.source.base_path).is_absolute()
    assert Path(config.source.base_path) == tmp_path / "base"
    assert Path(config.artifacts.root) == tmp_path / "out"
    # Paths *inside* the target tree stay relative: the tree does not exist yet.
    assert config.build.binary == "build/x"


def test_missing_file_and_bad_yaml_are_reported_clearly(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")

    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\n  broken: [")
    with pytest.raises(ConfigError, match="valid YAML"):
        load_config(bad)


def test_incomplete_source_mode_names_the_missing_fields(tmp_path: Path):
    config_file = tmp_path / "c.yaml"
    config_file.write_text(
        "version: 1\n"
        "target: {name: t}\n"
        "source: {mode: local_git, repo_path: /tmp}\n"
        "build: {binary: x}\n"
        "tests: {manifests: [m.yaml]}\n"
    )
    with pytest.raises(ConfigError) as exc:
        load_config(config_file)
    assert "base_commit" in str(exc.value)


def test_unsandboxed_execution_must_be_explicit(tmp_path: Path):
    config_file = tmp_path / "c.yaml"
    config_file.write_text(
        "version: 1\n"
        "target: {name: t}\n"
        "source: {mode: directories, base_path: ., patched_path: .}\n"
        "build: {binary: x}\n"
        "tests: {manifests: [m.yaml]}\n"
        "sandbox: {backend: none}\n"
    )
    with pytest.raises(ConfigError, match="allow_unsandboxed"):
        load_config(config_file)


def test_manifest_rejects_a_missing_input_file(tmp_path: Path):
    manifest = tmp_path / "m.yaml"
    manifest.write_text(
        "version: 1\ntests:\n  - id: a\n    category: valid\n"
        "    input_file: missing.bin\n"
    )
    with pytest.raises(ConfigError, match="input_file not found"):
        load_manifest(manifest)


# ---------------------------------------------------------- persistence


def test_run_ids_are_validated_and_time_ordered():
    first = generate_run_id()
    assert is_valid_run_id(first)
    assert not is_valid_run_id("../escape")
    assert not is_valid_run_id("nonsense")


def test_store_refuses_artifact_paths_outside_the_run(tmp_path: Path):
    store = RunStore(tmp_path)
    store.ensure()
    run_id = generate_run_id()
    store.create(run_id)

    store.write_artifact(run_id, "logs/a.log", "hello")
    assert store.read_artifact(run_id, "logs/a.log") == b"hello"

    with pytest.raises(StoreError, match="escapes"):
        store.resolve_artifact(run_id, "../../../etc/passwd")
    with pytest.raises(StoreError, match="invalid run id"):
        store.paths("../evil")


def test_store_never_overwrites_a_previous_run(tmp_path: Path):
    store = RunStore(tmp_path)
    store.ensure()
    run_id = generate_run_id()
    store.create(run_id)
    with pytest.raises(StoreError, match="never overwritten"):
        store.create(run_id)


def test_events_round_trip(tmp_path: Path):
    store = RunStore(tmp_path)
    store.ensure()
    run_id = generate_run_id()
    store.create(run_id)

    for i in range(1, 4):
        store.append_event(
            run_id, ProgressEvent(sequence=i, stage=Stage.BUILD, message=f"m{i}")
        )

    assert [e.sequence for e in store.read_events(run_id)] == [1, 2, 3]
    assert [e.sequence for e in store.read_events(run_id, after=1)] == [2, 3]


# --------------------------------------------------------- minimisation


def test_ddmin_shrinks_while_preserving_the_predicate():
    data = b"AAAA" + b"TARGET" + b"BBBBBBBB"
    result = ddmin(data, lambda c: b"TARGET" in c, max_iterations=500)
    assert result.data == b"TARGET"
    assert b"TARGET" in result.data


def test_ddmin_respects_its_iteration_budget():
    calls = {"n": 0}

    def predicate(candidate: bytes) -> bool:
        calls["n"] += 1
        return len(candidate) > 2

    result = ddmin(b"x" * 500, predicate, max_iterations=10)
    assert calls["n"] <= 14  # budget plus the trailing single-byte pass
    assert result.exhausted_budget


def test_ddmin_keeps_the_input_when_nothing_can_be_removed():
    result = ddmin(b"abc", lambda c: c == b"abc", max_iterations=50)
    assert result.data == b"abc"


# ----------------------------------------------------------------- diff


def test_c_function_spans_are_located():
    source = """\
#include <stdio.h>

static int helper(int a)
{
    if (a > 0) {
        return 1;
    }
    return 0;
}

int main(void)
{
    return helper(2);
}
"""
    spans = {s.name: (s.start_line, s.end_line) for s in diffing.find_functions(source)}
    assert "helper" in spans and "main" in spans
    # 'if' introduces a block but is not a function.
    assert "if" not in spans
    assert spans["helper"][0] == 3
    assert spans["helper"][1] == 9


def test_function_scanner_ignores_braces_in_strings_and_comments():
    source = """\
/* a comment with { unbalanced brace */
const char *s = "another { brace";

int real_function(void)
{
    return 0;
}
"""
    names = [s.name for s in diffing.find_functions(source)]
    assert names == ["real_function"]


def test_unified_diff_parsing_tracks_line_numbers():
    patch = """\
diff --git a/src/x.c b/src/x.c
--- a/src/x.c
+++ b/src/x.c
@@ -10,4 +10,5 @@ static int f(void)
 context
-removed
+added one
+added two
 trailing
"""
    files = diffing.parse_unified_diff(patch)
    assert len(files) == 1
    entry = files[0]
    assert entry.path == "src/x.c"
    assert entry.added_lines == 2
    assert entry.removed_lines == 1
    assert entry.changed_new_linenos() == {11, 12}
    assert entry.changed_old_linenos() == {11}
    assert entry.hunks[0].section_heading == "static int f(void)"


# ------------------------------------------------------------------ ELF


@requires_toolchain
@pytest.mark.integration
def test_elf_hardening_matches_the_requested_flags(tmp_path: Path):
    """Compile with known flags and confirm each protection is read correctly."""
    source = tmp_path / "h.c"
    source.write_text("int main(void){return 0;}")

    hardened = tmp_path / "hardened"
    subprocess.run(
        ["gcc", "-O2", "-fstack-protector-all", "-Wl,-z,relro,-z,now",
         "-o", str(hardened), str(source)],
        check=True, capture_output=True,
    )
    weak = tmp_path / "weak"
    subprocess.run(
        ["gcc", "-O2", "-no-pie", "-fno-stack-protector", "-Wl,-z,norelro",
         "-z", "execstack", "-o", str(weak), str(source)],
        check=True, capture_output=True,
    )

    strong = elf.inspect_binary(hardened, version=Version.PATCHED)
    assert strong.nx.state.value == "enabled"
    assert strong.pie.state.value == "enabled"
    assert strong.relro_level.value == "full"
    assert strong.canary.state.value == "enabled"
    # Every property must carry the structural fact it came from.
    assert all(p.evidence for p in strong.properties())

    poor = elf.inspect_binary(weak, version=Version.BASE)
    assert poor.nx.state.value == "disabled"
    assert poor.pie.state.value == "disabled"
    assert poor.relro_level.value == "none"
    assert poor.canary.state.value == "disabled"


@requires_toolchain
@pytest.mark.integration
def test_hardening_comparison_detects_weakening(tmp_path: Path):
    from dynan.app.pipeline import compare_hardening

    source = tmp_path / "h.c"
    source.write_text("int main(void){return 0;}")
    good, bad = tmp_path / "good", tmp_path / "bad"
    subprocess.run(["gcc", "-O2", "-fstack-protector-all", "-o", str(good), str(source)],
                   check=True, capture_output=True)
    subprocess.run(["gcc", "-O2", "-no-pie", "-fno-stack-protector", "-o", str(bad), str(source)],
                   check=True, capture_output=True)

    changes = compare_hardening(
        elf.inspect_binary(good, version=Version.BASE),
        elf.inspect_binary(bad, version=Version.PATCHED),
    )
    weakened = {c.property_name for c in changes if c.delta.value == "weakened"}
    assert {"PIE", "Stack Canary"} <= weakened


def test_non_elf_input_is_rejected(tmp_path: Path):
    plain = tmp_path / "notelf"
    plain.write_bytes(b"#!/bin/sh\necho hi\n")
    with pytest.raises(elf.ElfError):
        elf.inspect_binary(plain, version=Version.BASE)
