"""The fuzzing loop.

Generates inputs, runs them through the pipeline's sandboxed runner, and hands
anything interesting to the triager. Stops on whichever budget runs out first:
iterations, wall clock, or distinct findings.

Deliberately *not* here: any notion of what counts as a crash. That decision
belongs to :mod:`dynan.app.classify`, which is the same code the core pipeline
uses, so the fuzzer cannot drift into a second definition of a finding.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...app import classify as classify_mod
from ...config.schema import DynanConfig
from ...domain.enums import Confidence, Severity, Version
from ...domain.models import BuildResult
from ...infra.runner import ExecutionRequest
from . import corpus as corpus_mod
from .grammar import Grammar, GrammarError
from .triage import TriagedCrash, Triager

#: Severities worth reporting. A clean rejection of malformed input is the
#: program working correctly, not a finding.
_REPORTABLE = (Severity.MEMORY_SAFETY, Severity.UNDEFINED_BEHAVIOR)


@dataclass(slots=True)
class CampaignResult:
    version: Version
    executed: int = 0
    duration_s: float = 0.0
    crashes: list[TriagedCrash] = field(default_factory=list)
    stop_reason: str = "iterations exhausted"
    error: str | None = None

    def summary(self, profile: str) -> dict[str, Any]:
        return {
            "version": self.version.value,
            "profile": profile,
            "executed": self.executed,
            "duration_s": round(self.duration_s, 2),
            "distinct_findings": len(self.crashes),
            "confirmed_findings": sum(1 for c in self.crashes if c.confirmed),
            "stop_reason": self.stop_reason,
            **({"error": self.error} if self.error else {}),
        }


def run_campaign(
    config: DynanConfig,
    *,
    version: Version,
    build: BuildResult,
    base_build: BuildResult | None,
    grammar: Grammar | None,
    corpus: list[bytes],
    rng: random.Random,
    runner: Any,
    source_roots: list[Path],
    store: Any = None,
    run_id: str = "",
    on_progress=None,
) -> CampaignResult:
    """Fuzz one build until a budget is exhausted."""
    fuzz = config.extensions.fuzz
    probe = corpus_mod.build_probe(version, config.fuzz_delivery(), fuzz.argv)
    triager = Triager(
        config=fuzz,
        runner=runner,
        source_roots=source_roots,
        store=store,
        run_id=run_id,
    )

    result = CampaignResult(version=version)
    seen: set[tuple] = set()
    started = time.monotonic()

    for iteration in range(fuzz.iterations):
        if time.monotonic() - started >= fuzz.time_budget_s:
            result.stop_reason = "time budget exhausted"
            break
        if len(seen) >= fuzz.max_findings:
            result.stop_reason = "max_findings reached"
            break

        try:
            payload = corpus_mod.generate(fuzz, grammar, corpus, rng)
        except GrammarError as exc:
            result.error = str(exc)
            result.stop_reason = "grammar error"
            break

        execution = runner.execute(
            ExecutionRequest(
                test=probe,
                build=build,
                input_bytes=payload,
                execution_id=f"fuzz.{version.value}.{iteration}",
                persist=False,
            )
        )
        result.executed += 1

        finding, _report = classify_mod.classify_execution(
            execution, probe, source_roots=source_roots
        )
        if finding is None or finding.severity not in _REPORTABLE:
            continue
        if finding.confidence != Confidence.CONFIRMED:
            continue

        key = finding.signature.key()
        if key in seen:
            continue
        seen.add(key)

        crash = triager.triage(finding, probe, build, payload, iteration=iteration)
        triager.attribute(crash, base_build)
        result.crashes.append(crash)

        if on_progress is not None:
            on_progress(crash)

    result.duration_s = time.monotonic() - started
    return result
