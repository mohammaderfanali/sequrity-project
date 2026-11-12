"""Tests for the optional fuzzing extension.

Two properties matter most and are asserted directly:

* A fuzz finding must **never** change the authoritative verdict.
* A crash that already exists on the base version must **never** be reported
  as something the patch introduced.
"""

from __future__ import annotations

import random

import pytest
from pydantic import ValidationError

from dynan.config.schema import (
    FuzzConfig,
    GrammarConfig,
    grammar_expansion_costs,
)
from dynan.domain.enums import (
    BuildProfile,
    Confidence,
    DetectionMechanism,
    ErrorType,
    ExitCode,
    InputDelivery,
    Severity,
    Version,
)
from dynan.domain.models import Finding, FindingSignature, StackFrame
from dynan.ext.fuzz import corpus as corpus_mod
from dynan.ext.fuzz.extension import FuzzExtension
from dynan.ext.fuzz.grammar import Grammar
from dynan.ext.fuzz.mutator import mutate, splice
from dynan.ext.fuzz.triage import BASE_VERSION, PATCHED_ONLY, PRE_EXISTING, TriagedCrash
from dynan.ext.registry import ExtensionContext, extension_names

# --------------------------------------------------------------------------
# Grammar
# --------------------------------------------------------------------------

SIMPLE_RULES = {
    "doc": ["{line}", "{line}\n{doc}"],
    "line": ["k={value}", "k:{value}", "#c", ""],
    "value": ["a", "{value}{value}"],
}


def make_grammar(**overrides) -> Grammar:
    config = GrammarConfig(
        start=overrides.pop("start", "doc"),
        rules=overrides.pop("rules", SIMPLE_RULES),
        max_depth=overrides.pop("max_depth", 6),
    )
    return Grammar.from_config(config)


def test_expansion_costs_accept_indirectly_terminating_rules():
    """`doc -> {line}` terminates because `line` does; it needs no literal
    alternative of its own."""
    costs = grammar_expansion_costs(SIMPLE_RULES)
    assert costs["line"] == 0
    assert costs["doc"] == 1
    assert costs["value"] == 0


def test_expansion_costs_reject_non_terminating_grammar():
    with pytest.raises(ValueError, match="can never terminate"):
        grammar_expansion_costs({"a": ["{b}"], "b": ["{a}"]})


def test_grammar_rejects_undefined_reference():
    with pytest.raises(ValidationError, match="undefined"):
        GrammarConfig(start="a", rules={"a": ["{missing}"]})


def test_grammar_rejects_unknown_start():
    with pytest.raises(ValidationError, match="has no rule"):
        GrammarConfig(start="nope", rules={"a": ["x"]})


def test_generation_always_terminates_and_respects_size():
    """Deeply recursive rules must not hang or exceed the byte budget."""
    grammar = make_grammar(max_depth=3)
    rng = random.Random(7)
    for _ in range(2000):
        out = grammar.generate(rng, max_bytes=64)
        assert isinstance(out, bytes)
        assert len(out) <= 64


def test_generation_is_reproducible_for_a_fixed_seed():
    grammar = make_grammar()
    first = [grammar.generate(random.Random(99), max_bytes=256) for _ in range(3)]
    second = [grammar.generate(random.Random(99), max_bytes=256) for _ in range(3)]
    assert first == second


def test_generation_varies_within_one_sequence():
    grammar = make_grammar()
    rng = random.Random(5)
    samples = {grammar.generate(rng, max_bytes=256) for _ in range(40)}
    assert len(samples) > 1


def test_escaped_braces_are_literal():
    grammar = make_grammar(start="a", rules={"a": ["{{literal}}"]})
    assert grammar.generate(random.Random(1), max_bytes=64) == b"{literal}"


# --------------------------------------------------------------------------
# Mutation
# --------------------------------------------------------------------------


def test_mutation_stays_within_budget_and_is_never_empty():
    rng = random.Random(3)
    seed = b"host=localhost\nport=8080\n"
    for _ in range(500):
        out = mutate(seed, rng, max_bytes=128)
        assert 0 < len(out) <= 128


def test_mutation_handles_empty_seed():
    assert mutate(b"", random.Random(1), max_bytes=32)


def test_splice_respects_budget():
    rng = random.Random(2)
    out = splice(b"A" * 100, b"B" * 100, rng, max_bytes=50)
    assert len(out) <= 50


def test_seed_corpus_deduplicates_and_drops_empty():
    corpus = corpus_mod.seed_corpus({"a": b"x", "b": b"x", "c": b"", "d": b"y"})
    assert sorted(corpus) == [b"x", b"y"]


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_grammar_strategy_requires_a_grammar():
    with pytest.raises(ValidationError, match="requires"):
        FuzzConfig(enabled=True, strategy="grammar", grammar=None)


def test_mutation_strategy_needs_no_grammar():
    assert FuzzConfig(enabled=True, strategy="mutation").grammar is None


def test_fuzz_defaults_to_disabled():
    """An optional capability must cost nothing when it is not asked for.

    The defaults must also be *constructible*: ``FuzzConfig`` sits in every
    configuration, so a requirement enforced on a disabled extension would
    make an unrelated configuration fail to load.
    """
    config = FuzzConfig()
    assert config.enabled is False
    assert config.grammar is None


def test_every_shipped_config_still_loads(repo_root):
    """Regression guard for the above: adding fuzz options must not break
    configurations that never mention fuzzing."""
    from dynan.config.loader import load_config

    for path in sorted((repo_root / "configs").glob("*.yaml")):
        load_config(path)


def test_enabling_fuzz_without_listing_it_is_rejected(config_factory):
    with pytest.raises(Exception, match="extensions.enabled"):
        config_factory(
            "correct",
            extra="extensions:\n  fuzz:\n    enabled: true\n",
        )


# --------------------------------------------------------------------------
# Triage and attribution
# --------------------------------------------------------------------------


def make_finding(version: Version, function: str = "store_value") -> Finding:
    signature = FindingSignature(
        error_type=ErrorType.BUFFER_OVERFLOW,
        detection=DetectionMechanism.UBSAN,
        function=function,
        file="src/confparse.c",
        line=67,
    )
    return Finding(
        finding_id=f"{version.value}.fuzz",
        signature=signature,
        severity=Severity.MEMORY_SAFETY,
        confidence=Confidence.CONFIRMED,
        version=version,
        profile=BuildProfile.SANITIZED,
        test_id="fuzz_probe",
        execution_id="exec",
        frames=[
            StackFrame(index=0, function=function, file="src/confparse.c", line=67)
        ],
    )


def make_crash(version: Version, *, reproduced: int = 3, attribution: str = PATCHED_ONLY):
    return TriagedCrash(
        finding=make_finding(version),
        probe=corpus_mod.build_probe(version, InputDelivery.STDIN),
        payload=b"k=AAAAAAAAAAAAAAAA",
        original_size=64,
        replays_reproduced=reproduced,
        replays_total=3,
        minimized=True,
        attribution=attribution,
    )


def test_unstable_crash_is_not_confirmed():
    assert make_crash(Version.PATCHED, reproduced=2).confirmed is False


def test_only_confirmed_patched_only_crashes_are_promotable():
    assert make_crash(Version.PATCHED, attribution=PATCHED_ONLY).promotable is True
    # A crash the base version also exhibits predates the patch.
    assert make_crash(Version.PATCHED, attribution=PRE_EXISTING).promotable is False
    # A base-version crash says nothing about the patch.
    assert make_crash(Version.BASE, attribution=BASE_VERSION).promotable is False
    # An intermittent crash is not evidence.
    assert make_crash(Version.PATCHED, reproduced=1).promotable is False


def test_report_exposes_location_and_attribution():
    report = make_crash(Version.PATCHED).to_report()
    assert report["attribution"] == PATCHED_ONLY
    assert report["location"]["function"] == "store_value"
    assert report["location"]["line"] == 67
    assert report["replays"] == "3/3"


def test_fuzz_probe_is_not_an_independent_oracle():
    """A fuzzer has no notion of correct output, so its probe must never be
    usable as the criterion for a functional regression."""
    from dynan.config.testsuite import has_independent_oracle

    probe = corpus_mod.build_probe(Version.PATCHED, InputDelivery.STDIN)
    assert has_independent_oracle(probe) is False


# --------------------------------------------------------------------------
# Registry and isolation
# --------------------------------------------------------------------------


def test_fuzz_is_registered():
    assert "fuzz" in extension_names()


def test_disabled_fuzz_executes_nothing(config_factory):
    """A disabled extension must not run, even if something calls it."""
    config = config_factory("correct")

    class Exploding:  # pragma: no cover - must never be reached
        def execute(self, *_args, **_kwargs):
            raise AssertionError("a disabled extension executed the target")

    context = ExtensionContext(
        config=config, run=None, source_roots=[], runner=Exploding()
    )
    assert FuzzExtension().run(context) == {"status": "disabled"}


def test_fuzz_skips_cleanly_without_a_runner(config_factory):
    """No builds means nothing to fuzz - report it, do not crash."""
    config = config_factory(
        "correct",
        extra=(
            "extensions:\n"
            "  enabled: [fuzz]\n"
            "  fuzz:\n"
            "    enabled: true\n"
            "    strategy: mutation\n"
        ),
    )
    result = FuzzExtension().run(
        ExtensionContext(config=config, run=None, source_roots=[], runner=None)
    )
    assert result["status"] == "skipped"


def test_disabled_fuzz_reports_as_not_required(config_factory):
    config = config_factory("correct")
    statuses = {d.status.value for d in FuzzExtension().diagnose(config)}
    assert statuses == {"not_required"}


# --------------------------------------------------------------------------
# Non-authoritativeness
# --------------------------------------------------------------------------


def test_extension_results_cannot_change_the_verdict():
    """The decision engine reads findings and comparisons - never extension
    output. Injecting alarming fuzz results must leave the verdict untouched."""
    from dynan.domain.decision import evaluate

    from test_decision import make_run

    run = make_run()
    before = evaluate(run)
    assert before.exit_code is ExitCode.PASS

    run.extension_results["fuzz"] = {
        "status": "ok",
        "findings": [
            {
                "version": "patched",
                "error_type": "heap_buffer_overflow",
                "severity": "memory_safety",
                "confirmed": True,
                "attribution": "patched_only",
            }
        ],
    }
    after = evaluate(run)
    assert after.exit_code is ExitCode.PASS
    assert after.security_status == before.security_status
