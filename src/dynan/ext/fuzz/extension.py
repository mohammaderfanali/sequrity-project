"""Fuzzing extension: readiness checks, campaign orchestration, promotion.

Relationship to the verdict
---------------------------
Fuzz findings never change the official exit code. The specification judges a
patch "within the specified test scope", and a fuzzer invents inputs outside
that scope by construction - letting it move the verdict would mean the same
patch passes or fails depending on a random seed.

The honest path from a fuzz crash to the verdict is explicit instead: a crash
that is confirmed by repeated replay, minimised, and absent on the base
version is written into the regression suite. The next run then evaluates it
in scope, where it does affect the verdict - and by then it is a named,
reviewable test rather than a lucky draw.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from ...app import regression as regression_mod
from ...config.schema import DynanConfig
from ...domain.enums import BuildProfile, DependencyStatus, Version
from ...domain.models import Diagnostic
from ..registry import ExtensionContext
from . import corpus as corpus_mod
from .campaign import run_campaign
from .grammar import Grammar, GrammarError

#: How many samples the doctor generates to prove a grammar works.
_PROBE_SAMPLES = 5


class FuzzExtension:
    name = "fuzz"
    description = (
        "Grammar- and mutation-based fuzzing of the built targets, reported "
        "separately from the authoritative verdict."
    )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def diagnose(self, config: DynanConfig) -> list[Diagnostic]:
        fuzz = config.extensions.fuzz
        if not fuzz.enabled:
            return [
                Diagnostic(
                    name="extension: fuzz",
                    status=DependencyStatus.NOT_REQUIRED,
                    required=False,
                    detail="listed but disabled; no fuzzing will run",
                    category="extensions",
                )
            ]

        diagnostics: list[Diagnostic] = []

        if fuzz.strategy in ("grammar", "both"):
            if fuzz.grammar is not None:
                diagnostics.append(self._check_grammar(fuzz))
            else:
                # Allowed, but the user should know what they are actually
                # getting rather than assuming the grammar half is running.
                diagnostics.append(
                    Diagnostic(
                        name="extension: fuzz (grammar)",
                        status=DependencyStatus.MISCONFIGURED,
                        required=False,
                        detail=(
                            f"strategy is '{fuzz.strategy}' but no grammar is "
                            "configured, so only mutation of the existing test "
                            "corpus will run"
                        ),
                        remediation=(
                            "add extensions.fuzz.grammar, or set strategy: mutation "
                            "to make the intent explicit"
                        ),
                        category="extensions",
                    )
                )

        if fuzz.profile == BuildProfile.RELEASE:
            diagnostics.append(
                Diagnostic(
                    name="extension: fuzz (profile)",
                    status=DependencyStatus.MISCONFIGURED,
                    required=False,
                    detail=(
                        "fuzzing the release build will miss most memory errors, "
                        "because an uninstrumented binary tolerates them silently"
                    ),
                    remediation="set extensions.fuzz.profile: sanitized",
                    category="extensions",
                )
            )

        if Version.BASE not in fuzz.versions:
            diagnostics.append(
                Diagnostic(
                    name="extension: fuzz (attribution)",
                    status=DependencyStatus.MISCONFIGURED,
                    required=False,
                    detail=(
                        "only the patched version will be fuzzed, so a crash that "
                        "already existed before the patch cannot be distinguished "
                        "from one the patch introduced"
                    ),
                    remediation="add 'base' to extensions.fuzz.versions",
                    category="extensions",
                )
            )

        seed_note = (
            f"fixed seed {fuzz.seed}" if fuzz.seed is not None else "random seed"
        )
        diagnostics.append(
            Diagnostic(
                name="extension: fuzz",
                status=DependencyStatus.READY,
                required=False,
                detail=(
                    f"strategy={fuzz.strategy}, {fuzz.iterations} iteration(s), "
                    f"budget {fuzz.time_budget_s}s, {seed_note}; findings are "
                    "reported separately and never change the exit code"
                ),
                category="extensions",
            )
        )
        return diagnostics

    @staticmethod
    def _check_grammar(fuzz) -> Diagnostic:
        """Prove the grammar generates input before a run spends its budget."""
        try:
            grammar = Grammar.from_config(fuzz.grammar)
            rng = random.Random(fuzz.seed if fuzz.seed is not None else 0)
            samples = [
                grammar.generate(rng, max_bytes=fuzz.max_input_bytes)
                for _ in range(_PROBE_SAMPLES)
            ]
        except GrammarError as exc:
            return Diagnostic(
                name="extension: fuzz (grammar)",
                status=DependencyStatus.MISCONFIGURED,
                required=True,
                detail=f"grammar cannot generate input: {exc}",
                remediation="check the rules for unbounded recursion",
                category="extensions",
            )

        distinct = len({bytes(s) for s in samples})
        if distinct == 1:
            return Diagnostic(
                name="extension: fuzz (grammar)",
                status=DependencyStatus.MISCONFIGURED,
                required=False,
                detail=(
                    f"the grammar produced the same input {_PROBE_SAMPLES} times; "
                    "it has no variation to explore"
                ),
                remediation="add alternatives to the rules",
                category="extensions",
            )

        return Diagnostic(
            name="extension: fuzz (grammar)",
            status=DependencyStatus.READY,
            required=False,
            detail=(
                f"start='{fuzz.grammar.start}', {len(fuzz.grammar.rules)} rule(s), "
                f"max_depth={fuzz.grammar.max_depth}; "
                f"{distinct}/{_PROBE_SAMPLES} distinct samples generated"
            ),
            category="extensions",
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, context: ExtensionContext) -> dict[str, Any]:
        fuzz = context.config.extensions.fuzz
        if not fuzz.enabled:
            return {"status": "disabled"}
        if context.runner is None:
            return {
                "status": "skipped",
                "detail": "no target runner available; builds did not complete",
            }

        rng = random.Random(fuzz.seed)
        grammar = Grammar.from_config(fuzz.grammar) if fuzz.grammar else None
        corpus = corpus_mod.seed_corpus(context.inputs)
        source_roots = [Path(p) for p in context.source_roots]

        results: dict[str, Any] = {
            "status": "ok",
            "authoritative": False,
            "disclaimer": (
                "Fuzzing explores inputs outside the agreed test scope, so these "
                "findings are reported separately and do not affect the exit "
                "code. Confirmed, patched-only crashes are promoted into the "
                "regression suite, where the next run evaluates them in scope."
            ),
            "strategy": fuzz.strategy,
            "seed": fuzz.seed,
            "profile": fuzz.profile.value,
            "seed_corpus_size": len(corpus),
            "campaigns": [],
            "findings": [],
            "promoted_tests": [],
            "errors": [],
        }

        base_build = context.builds.get(f"{Version.BASE.value}/{fuzz.profile.value}")
        all_crashes = []

        for version in fuzz.versions:
            build = context.builds.get(f"{version.value}/{fuzz.profile.value}")
            if build is None or not getattr(build, "success", False):
                results["errors"].append(
                    f"no successful {version.value}/{fuzz.profile.value} build to fuzz"
                )
                continue

            campaign = run_campaign(
                context.config,
                version=version,
                build=build,
                # Attribution only applies to patched-version crashes.
                base_build=base_build if version == Version.PATCHED else None,
                grammar=grammar,
                corpus=corpus,
                rng=rng,
                runner=context.runner,
                source_roots=source_roots,
                store=context.store,
                run_id=context.run_id,
            )
            results["campaigns"].append(campaign.summary(fuzz.profile.value))
            if campaign.error:
                results["errors"].append(campaign.error)
            all_crashes.extend(campaign.crashes)

        results["findings"] = [crash.to_report() for crash in all_crashes]

        if fuzz.promote_to_regression:
            results["promoted_tests"] = self._promote(context, all_crashes)

        if results["errors"] and not results["findings"]:
            results["status"] = "failed" if not results["campaigns"] else "ok"

        return results

    # ------------------------------------------------------------------
    # Promotion
    # ------------------------------------------------------------------

    @staticmethod
    def _promote(context: ExtensionContext, crashes: list) -> list[dict[str, Any]]:
        """Write confirmed, patched-only crashes into the regression suite."""
        selected = [crash for crash in crashes if crash.promotable]
        if not selected:
            return []

        writer = regression_mod.RegressionSuiteWriter(
            Path(context.config.tests.regression_suite), run_id=context.run_id
        )
        writer.load_existing()

        promoted: list[dict[str, Any]] = []
        for crash in selected:
            generated = writer.emit(
                crash.finding, crash.probe, crash.payload, minimized=crash.minimized
            )
            generated.notes = (
                "discovered by the fuzzing extension; promoted so a later run "
                "evaluates it inside the agreed test scope"
            )
            promoted.append(
                {
                    "test_id": generated.test_id,
                    "signature": crash.finding.signature.describe(),
                    "input_artifact": generated.input_artifact,
                    "size_bytes": len(crash.payload),
                }
            )

        writer.flush()
        return promoted
