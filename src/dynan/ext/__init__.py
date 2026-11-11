"""Optional extensions.

Extensions are advisory. They may annotate a run, never decide it: the
deterministic engine in :mod:`dynan.domain.decision` owns the verdict.

A disabled extension must cost nothing - no import of its dependencies, no
network traffic, no diagnostics that block an unrelated run. The registry
enforces that by importing an extension's implementation only when it is
actually enabled.
"""
