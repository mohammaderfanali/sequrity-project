"""Failure-preserving input minimisation.

Implements ddmin (Zeller & Hildebrandt's delta debugging) over raw bytes, so
binary inputs reduce as well as text. The algorithm removes increasingly fine
slices of the input and keeps any reduction the predicate still accepts.

The predicate is deliberately strict: it is satisfied only when the candidate
reproduces the *same error signature at the same location*, not merely when
the process exits non-zero. The PDF calls this out specifically, and a loose
predicate is the classic way minimisation silently turns one bug into another.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

#: Predicate: does this candidate still reproduce the target failure?
Predicate = Callable[[bytes], bool]


@dataclass(slots=True)
class MinimizationOutcome:
    data: bytes
    iterations: int
    duration_s: float
    exhausted_budget: bool = False
    notes: list[str] = field(default_factory=list)


def _without(data: bytes, start: int, end: int) -> bytes:
    return data[:start] + data[end:]


def ddmin(
    data: bytes,
    predicate: Predicate,
    *,
    max_iterations: int = 400,
    timeout_s: float = 120.0,
) -> MinimizationOutcome:
    """Reduce ``data`` while ``predicate`` keeps holding.

    Bounded twice over - by iteration count and wall clock - because the
    predicate executes the target, and an unbounded search would dominate the
    runtime of a validation.
    """
    started = time.monotonic()
    iterations = 0
    notes: list[str] = []
    current = data

    if not current:
        return MinimizationOutcome(data=current, iterations=0, duration_s=0.0)

    def budget_exhausted() -> bool:
        return (
            iterations >= max_iterations
            or (time.monotonic() - started) >= timeout_s
        )

    granularity = 2
    while len(current) >= 2:
        if budget_exhausted():
            notes.append("stopped early: iteration or time budget exhausted")
            return MinimizationOutcome(
                data=current,
                iterations=iterations,
                duration_s=time.monotonic() - started,
                exhausted_budget=True,
                notes=notes,
            )

        chunk_size = max(len(current) // granularity, 1)
        reduced = False

        # Try removing each complement, largest removals first.
        for index in range(granularity):
            start = index * chunk_size
            end = len(current) if index == granularity - 1 else start + chunk_size
            if start >= len(current):
                break

            candidate = _without(current, start, end)
            if not candidate:
                continue

            iterations += 1
            if budget_exhausted():
                break
            if predicate(candidate):
                current = candidate
                granularity = max(granularity - 1, 2)
                reduced = True
                break

        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(granularity * 2, len(current))

    # Final pass: try shaving single bytes from both ends, which ddmin's
    # block structure can leave behind.
    for _ in range(2):
        changed = True
        while changed and len(current) > 1 and not budget_exhausted():
            changed = False
            for candidate in (current[1:], current[:-1]):
                if not candidate:
                    continue
                iterations += 1
                if predicate(candidate):
                    current = candidate
                    changed = True
                    break

    return MinimizationOutcome(
        data=current,
        iterations=iterations,
        duration_s=time.monotonic() - started,
        exhausted_budget=budget_exhausted(),
        notes=notes,
    )
