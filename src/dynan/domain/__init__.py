"""Domain layer: canonical data structures and deterministic decision rules.

This package is deliberately free of I/O. Nothing here reads files, spawns
processes or talks to the network, which keeps the validation semantics
testable in isolation and guarantees exactly one authoritative definition of
every rule the product relies on.
"""
