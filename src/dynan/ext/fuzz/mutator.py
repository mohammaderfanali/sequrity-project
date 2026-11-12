"""Byte-level mutation of a seed corpus.

Complements grammar generation. The grammar explores shapes the author
anticipated; mutation explores what happens just outside them - a field grown
past its limit, a separator deleted, a boundary value spliced in. Together
they cover more than either does alone.

Operators are deliberately simple and byte-oriented so binary inputs mutate
as readily as text.
"""

from __future__ import annotations

import random

#: Values that disproportionately often sit on a boundary condition.
_INTERESTING_BYTES = bytes([0x00, 0x01, 0x07, 0x0A, 0x0D, 0x20, 0x2C, 0x3A, 0x3D,
                            0x5C, 0x7F, 0x80, 0xFE, 0xFF])

#: Token-ish fragments worth splicing into structured text input.
_INTERESTING_CHUNKS = (
    b"=", b":", b"#", b"\n", b"\x00", b" ",
    b"A" * 16, b"A" * 64, b"A" * 256,
    b"-1", b"0", b"2147483647", b"4294967295",
)


def mutate(data: bytes, rng: random.Random, *, max_bytes: int) -> bytes:
    """Apply one or a few random mutations to ``data``."""
    if not data:
        data = b"a"

    out = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        out = _apply_one(out, rng, max_bytes)
        if not out:
            out = bytearray(b"a")
    return bytes(out[:max_bytes])


def _apply_one(data: bytearray, rng: random.Random, max_bytes: int) -> bytearray:
    operator = rng.randrange(8)
    size = len(data)

    if operator == 0:  # flip a bit
        index = rng.randrange(size)
        data[index] ^= 1 << rng.randrange(8)

    elif operator == 1:  # overwrite with an interesting byte
        index = rng.randrange(size)
        data[index] = rng.choice(_INTERESTING_BYTES)

    elif operator == 2:  # delete a span
        if size > 1:
            start = rng.randrange(size)
            end = min(size, start + rng.randint(1, max(1, size // 4)))
            del data[start:end]

    elif operator == 3:  # insert an interesting chunk
        chunk = rng.choice(_INTERESTING_CHUNKS)
        index = rng.randrange(size + 1)
        data = bytearray(data[:index] + chunk + data[index:])

    elif operator == 4:  # duplicate a span, growing a field past its limit
        start = rng.randrange(size)
        end = min(size, start + rng.randint(1, max(1, size // 2)))
        span = bytes(data[start:end])
        if len(data) + len(span) <= max_bytes:
            data = bytearray(data[:end] + span + data[end:])

    elif operator == 5:  # repeat one byte into a long run
        index = rng.randrange(size)
        count = rng.choice((8, 16, 32, 64, 128, 512))
        if size + count <= max_bytes:
            data = bytearray(data[:index] + bytes([data[index]]) * count + data[index:])

    elif operator == 6:  # truncate
        if size > 1:
            data = bytearray(data[: rng.randrange(1, size)])

    else:  # swap two spans
        if size > 3:
            cut = rng.randrange(1, size)
            data = bytearray(data[cut:] + data[:cut])

    return data


def splice(left: bytes, right: bytes, rng: random.Random, *, max_bytes: int) -> bytes:
    """Join the head of one input to the tail of another."""
    if not left or not right:
        return (left or right)[:max_bytes]
    cut_left = rng.randrange(1, len(left) + 1)
    cut_right = rng.randrange(0, len(right))
    return (left[:cut_left] + right[cut_right:])[:max_bytes]
