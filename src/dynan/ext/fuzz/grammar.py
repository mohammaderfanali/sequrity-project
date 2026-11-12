"""Grammar-based input generation.

A parser rejects random bytes on its first validity check, so unstructured
fuzzing of a text format mostly exercises the error path. Generating from a
grammar produces inputs that are structurally plausible and therefore reach
the deeper code a security patch usually touches.

The generator is a straightforward recursive expander over the configured
rules. The only subtlety is termination: a useful grammar is recursive
(``value: ["x", "{value}{value}"]``), so beyond ``max_depth`` the expander
restricts itself to alternatives that contain no references. The schema
validates that every rule has at least one such alternative, which makes that
fallback always available.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ...config.schema import (
    GRAMMAR_REFERENCE as _REFERENCE,
    GrammarConfig,
    grammar_expansion_costs,
)

#: Guards against a pathological grammar producing an enormous string before
#: the size check in the caller ever runs.
_HARD_EXPANSION_LIMIT = 1_000_000


class GrammarError(RuntimeError):
    """The grammar could not produce an input."""


@dataclass(slots=True)
class Grammar:
    """A validated, ready-to-expand grammar."""

    start: str
    rules: dict[str, list[str]]
    max_depth: int
    #: Cheapest expansion cost per rule, from the productivity analysis.
    costs: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config: GrammarConfig) -> Grammar:
        rules = {name: list(alts) for name, alts in config.rules.items()}
        return cls(
            start=config.start,
            rules=rules,
            max_depth=config.max_depth,
            costs=grammar_expansion_costs(rules),
        )

    def _alternative_cost(self, alternative: str) -> int:
        references = _REFERENCE.findall(alternative)
        if not references:
            return 0
        return 1 + max(self.costs.get(ref, 0) for ref in references)

    def closing_alternatives(self, name: str) -> list[str]:
        """Cheapest-to-terminate alternatives of ``name``.

        Used once the depth budget is spent. Choosing a minimum-cost
        alternative guarantees the branch closes, which is what makes
        termination deterministic rather than a matter of luck.
        """
        alternatives = self.rules[name]
        costs = [self._alternative_cost(alt) for alt in alternatives]
        cheapest = min(costs)
        return [alt for alt, cost in zip(alternatives, costs) if cost == cheapest]

    def generate(self, rng: random.Random, *, max_bytes: int) -> bytes:
        """Expand the start symbol into one concrete input."""
        text = self._expand(self.start, rng, depth=0)
        encoded = text.encode("utf-8", errors="surrogateescape")
        return encoded[:max_bytes]

    def _expand(self, name: str, rng: random.Random, *, depth: int) -> str:
        alternatives = self.rules.get(name)
        if not alternatives:
            raise GrammarError(f"no rule for non-terminal '{name}'")

        if depth >= self.max_depth:
            # Past the depth budget, restrict the choice to alternatives that
            # terminate fastest, so every open branch is forced to close.
            alternatives = self.closing_alternatives(name)

        chosen = rng.choice(alternatives)
        out: list[str] = []
        cursor = 0
        length = 0

        for match in _REFERENCE.finditer(chosen):
            literal = chosen[cursor : match.start()]
            out.append(literal)
            length += len(literal)
            expanded = self._expand(match.group(1), rng, depth=depth + 1)
            out.append(expanded)
            length += len(expanded)
            if length > _HARD_EXPANSION_LIMIT:
                raise GrammarError(
                    f"grammar expansion exceeded {_HARD_EXPANSION_LIMIT} characters; "
                    "check for an unbounded recursive rule"
                )
            cursor = match.end()

        out.append(chosen[cursor:])
        return _unescape_braces("".join(out))


def _unescape_braces(text: str) -> str:
    return text.replace("{{", "{").replace("}}", "}")
