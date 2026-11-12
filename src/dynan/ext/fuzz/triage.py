"""Triage of candidate crashes.

A raw fuzz crash is weak evidence. Before it is reported - and long before it
is allowed anywhere near a later verdict - it goes through the same scrutiny
the core pipeline applies to its own findings:

1. **Confirm** by replaying the exact input several times. An intermittent
   crash is recorded as unconfirmed, never promoted.
2. **Minimise** with the shared ddmin implementation, under the shared
   signature-preserving predicate. A non-zero exit code is not sufficient.
3. **Attribute** by checking whether the base version crashes the same way. A
   crash that pre-dates the patch is reported as pre-existing, because calling
   it patch-introduced would be exactly the false attribution the
   specification warns against.

Only a confirmed, patched-only crash becomes a promotion candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...app import minimize as minimize_mod
from ...app import signature as signature_mod
from ...config.schema import FuzzConfig
from ...domain.enums import Version
from ...domain.models import BuildResult, Finding, TestCaseSpec
from ...infra.runner import ExecutionRequest

#: Attribution labels used in the report.
PATCHED_ONLY = "patched_only"
PRE_EXISTING = "pre_existing"
BASE_VERSION = "base_version"


@dataclass(slots=True)
class TriagedCrash:
    """One candidate crash after confirmation and minimisation."""

    finding: Finding
    probe: TestCaseSpec
    payload: bytes
    original_size: int
    replays_reproduced: int
    replays_total: int
    minimized: bool
    attribution: str = PATCHED_ONLY
    input_artifact: str | None = None
    iteration: int = 0

    @property
    def confirmed(self) -> bool:
        return self.replays_reproduced == self.replays_total and self.replays_total > 0

    @property
    def promotable(self) -> bool:
        return (
            self.confirmed
            and self.finding.version == Version.PATCHED
            and self.attribution == PATCHED_ONLY
        )

    def to_report(self) -> dict[str, Any]:
        frame = self.finding.primary_frame
        return {
            "version": self.finding.version.value,
            "signature": self.finding.signature.describe(),
            "signature_digest": self.finding.signature.digest,
            "error_type": self.finding.signature.error_type.value,
            "detection": self.finding.signature.detection.value,
            "severity": self.finding.severity.value,
            "location": (
                {"file": frame.file, "line": frame.line, "function": frame.function}
                if frame
                else None
            ),
            "confirmed": self.confirmed,
            "replays": f"{self.replays_reproduced}/{self.replays_total}",
            "attribution": self.attribution,
            "original_size": self.original_size,
            "minimized_size": len(self.payload),
            "minimized": self.minimized,
            "input_artifact": self.input_artifact,
            "iteration": self.iteration,
        }


@dataclass(slots=True)
class Triager:
    """Confirms, minimises and attributes candidate crashes."""

    config: FuzzConfig
    runner: Any
    source_roots: list[Path]
    store: Any = None
    run_id: str = ""
    _counter: int = field(default=0, init=False)

    # -- execution helper ----------------------------------------------

    def _reproduces(
        self,
        finding: Finding,
        probe: TestCaseSpec,
        build: BuildResult,
        payload: bytes,
        tag: str,
    ) -> bool:
        self._counter += 1
        execution = self.runner.execute(
            ExecutionRequest(
                test=probe,
                build=build,
                input_bytes=payload,
                execution_id=f"fuzz.{tag}.{self._counter}",
                persist=False,
            )
        )
        return signature_mod.preserves_signature(
            execution, probe, finding.signature, source_roots=self.source_roots
        )

    # -- stages ---------------------------------------------------------

    def triage(
        self,
        finding: Finding,
        probe: TestCaseSpec,
        build: BuildResult,
        payload: bytes,
        *,
        iteration: int,
    ) -> TriagedCrash:
        reproduced = sum(
            1
            for _ in range(self.config.confirm_replays)
            if self._reproduces(finding, probe, build, payload, "confirm")
        )

        crash = TriagedCrash(
            finding=finding,
            probe=probe,
            payload=payload,
            original_size=len(payload),
            replays_reproduced=reproduced,
            replays_total=self.config.confirm_replays,
            minimized=False,
            iteration=iteration,
        )

        if crash.confirmed and self.config.minimize and payload:
            outcome = minimize_mod.ddmin(
                payload,
                lambda candidate: self._reproduces(
                    finding, probe, build, candidate, "min"
                ),
                max_iterations=self.config.minimization_max_iterations,
                # A quarter of the campaign budget: minimisation must not eat
                # the time that finding more defects would use better.
                timeout_s=max(self.config.time_budget_s / 4, 10.0),
            )
            crash.payload = outcome.data
            crash.minimized = True

        crash.input_artifact = self._persist(crash)
        return crash

    def attribute(
        self,
        crash: TriagedCrash,
        base_build: BuildResult | None,
    ) -> None:
        """Decide whether the patched-version crash pre-dates the patch."""
        if crash.finding.version == Version.BASE:
            crash.attribution = BASE_VERSION
            return
        if base_build is None or not base_build.success:
            # Without a base build we cannot tell, so we do not claim to.
            crash.attribution = "unknown"
            return

        crash.attribution = (
            PRE_EXISTING
            if self._reproduces(
                crash.finding, crash.probe, base_build, crash.payload, "attribute"
            )
            else PATCHED_ONLY
        )

    def _persist(self, crash: TriagedCrash) -> str | None:
        if self.store is None or not self.run_id:
            return None
        return self.store.write_artifact(
            self.run_id,
            f"evidence/fuzz/{crash.finding.version.value}/"
            f"{crash.finding.signature.digest}.bin",
            crash.payload,
        )
