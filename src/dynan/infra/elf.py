"""ELF binary hardening inspection (PDF section 3.4).

Implemented by reading the ELF structures directly rather than shelling out to
``checksec``: it removes an external dependency, works identically everywhere,
and - more importantly - lets every reported property carry the specific
structural fact it was derived from, which the PDF requires as evidence.

Two caveats the specification explicitly calls out are encoded as data on the
report rather than left to the reader:

* PIE in the binary does **not** prove ASLR is active in the environment.
* The presence of a stack canary symbol does **not** mean every function is
  protected; GCC instruments selectively.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from ..domain.enums import HardeningState, RelroLevel, Version
from ..domain.enums import BuildProfile
from ..domain.models import BinaryHardening, HardeningProperty

# ELF constants we need.
_ET_EXEC = 2
_ET_DYN = 3
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_BIND_NOW = 0x8
_DF_1_NOW = 0x1
_SHT_DYNSYM = 11
_SHT_SYMTAB = 2

#: Symbols that indicate stack-protector instrumentation.
_CANARY_SYMBOLS = {"__stack_chk_fail", "__stack_chk_fail_local", "__stack_chk_guard"}

#: Symbol prefix emitted by _FORTIFY_SOURCE.
_FORTIFY_SUFFIX = "_chk"


class ElfError(RuntimeError):
    """The file is not a usable 64-bit little-endian ELF."""


@dataclass(slots=True)
class _Section:
    name: str
    sh_type: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass(slots=True)
class ElfInfo:
    e_type: int
    segments: list[tuple[int, int]]  # (p_type, p_flags)
    dynamic: dict[int, list[int]]
    symbols: set[str]
    sections: set[str]
    has_dynamic_segment: bool


def _read_elf(path: Path) -> ElfInfo:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError(f"{path} is not an ELF file")
    if data[4] != 2:
        raise ElfError(f"{path} is not 64-bit ELF (dynAn targets x86_64)")
    if data[5] != 1:
        raise ElfError(f"{path} is not little-endian ELF")

    (e_type,) = struct.unpack_from("<H", data, 16)
    e_phoff, e_shoff = struct.unpack_from("<QQ", data, 32)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
        "<HHHHH", data, 54
    )

    # Program headers -> segment flags (NX, RELRO, PIE evidence).
    segments: list[tuple[int, int]] = []
    dynamic_off = dynamic_size = 0
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        if base + 56 > len(data):
            break
        p_type, p_flags = struct.unpack_from("<II", data, base)
        p_offset, _p_vaddr, _p_paddr, p_filesz = struct.unpack_from("<QQQQ", data, base + 8)
        segments.append((p_type, p_flags))
        if p_type == _PT_DYNAMIC:
            dynamic_off, dynamic_size = p_offset, p_filesz

    # Section headers -> symbol tables and section names.
    sections: list[_Section] = []
    section_names: set[str] = set()
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        strtab_base = e_shoff + e_shstrndx * e_shentsize
        str_off, str_size = struct.unpack_from("<QQ", data, strtab_base + 24)
        shstr = data[str_off : str_off + str_size]

        def sh_name(idx: int) -> str:
            end = shstr.find(b"\0", idx)
            return shstr[idx:end].decode("utf-8", "replace") if end >= 0 else ""

        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            if base + 64 > len(data):
                break
            name_idx, sh_type = struct.unpack_from("<II", data, base)
            sh_offset, sh_size = struct.unpack_from("<QQ", data, base + 24)
            sh_link = struct.unpack_from("<I", data, base + 40)[0]
            sh_entsize = struct.unpack_from("<Q", data, base + 56)[0]
            name = sh_name(name_idx)
            section_names.add(name)
            sections.append(
                _Section(name, sh_type, sh_offset, sh_size, sh_link, sh_entsize)
            )

    # Dynamic table.
    dynamic: dict[int, list[int]] = {}
    if dynamic_off and dynamic_size:
        for off in range(dynamic_off, min(dynamic_off + dynamic_size, len(data)) - 15, 16):
            d_tag, d_val = struct.unpack_from("<qQ", data, off)
            dynamic.setdefault(d_tag, []).append(d_val)
            if d_tag == _DT_NULL:
                break

    # Symbol names from .symtab and .dynsym.
    symbols: set[str] = set()
    for sec in sections:
        if sec.sh_type not in (_SHT_SYMTAB, _SHT_DYNSYM) or not sec.entsize:
            continue
        if sec.link >= len(sections):
            continue
        strsec = sections[sec.link]
        strdata = data[strsec.offset : strsec.offset + strsec.size]
        count = sec.size // sec.entsize
        for i in range(count):
            off = sec.offset + i * sec.entsize
            if off + 24 > len(data):
                break
            (name_idx,) = struct.unpack_from("<I", data, off)
            if not name_idx or name_idx >= len(strdata):
                continue
            end = strdata.find(b"\0", name_idx)
            if end < 0:
                continue
            symbols.add(strdata[name_idx:end].decode("utf-8", "replace"))

    return ElfInfo(
        e_type=e_type,
        segments=segments,
        dynamic=dynamic,
        symbols=symbols,
        sections=section_names,
        has_dynamic_segment=bool(dynamic_off),
    )


def _check_nx(info: ElfInfo) -> HardeningProperty:
    """NX is on when PT_GNU_STACK exists and is not executable."""
    for p_type, p_flags in info.segments:
        if p_type == _PT_GNU_STACK:
            executable = bool(p_flags & _PF_X)
            return HardeningProperty(
                name="NX",
                state=HardeningState.DISABLED if executable else HardeningState.ENABLED,
                detail=(
                    "stack segment is executable"
                    if executable
                    else "stack segment is non-executable"
                ),
                evidence=f"PT_GNU_STACK p_flags=0x{p_flags:x}",
            )
    # Absent PT_GNU_STACK means the kernel applies its default, which on
    # modern Linux is an executable stack for ELF without the marker.
    return HardeningProperty(
        name="NX",
        state=HardeningState.UNKNOWN,
        detail="no PT_GNU_STACK segment; the kernel default applies",
        evidence="PT_GNU_STACK absent",
    )


def _check_pie(info: ElfInfo) -> HardeningProperty:
    """PIE requires ET_DYN *and* a dynamic segment (a shared object is ET_DYN too)."""
    if info.e_type == _ET_DYN and info.has_dynamic_segment:
        return HardeningProperty(
            name="PIE",
            state=HardeningState.ENABLED,
            detail="position-independent executable",
            evidence="e_type=ET_DYN with PT_DYNAMIC",
        )
    if info.e_type == _ET_EXEC:
        return HardeningProperty(
            name="PIE",
            state=HardeningState.DISABLED,
            detail="fixed load address",
            evidence="e_type=ET_EXEC",
        )
    return HardeningProperty(
        name="PIE",
        state=HardeningState.UNKNOWN,
        detail=f"unexpected ELF type {info.e_type}",
        evidence=f"e_type={info.e_type}",
    )


def _check_relro(info: ElfInfo) -> tuple[HardeningProperty, RelroLevel]:
    """RELRO level from PT_GNU_RELRO plus BIND_NOW flags."""
    has_relro = any(p_type == _PT_GNU_RELRO for p_type, _ in info.segments)
    if not has_relro:
        return (
            HardeningProperty(
                name="RELRO",
                state=HardeningState.DISABLED,
                detail="no RELRO",
                evidence="PT_GNU_RELRO absent",
            ),
            RelroLevel.NONE,
        )

    flags = info.dynamic.get(_DT_FLAGS, [0])
    flags1 = info.dynamic.get(_DT_FLAGS_1, [0])
    bind_now = (
        any(f & _DF_BIND_NOW for f in flags)
        or any(f & _DF_1_NOW for f in flags1)
        or 24 in info.dynamic  # DT_BIND_NOW
    )
    if bind_now:
        return (
            HardeningProperty(
                name="RELRO",
                state=HardeningState.ENABLED,
                detail="full RELRO (GOT mapped read-only after relocation)",
                evidence="PT_GNU_RELRO present with BIND_NOW",
            ),
            RelroLevel.FULL,
        )
    return (
        HardeningProperty(
            name="RELRO",
            state=HardeningState.PARTIAL,
            detail="partial RELRO (GOT still writable; lazy binding in use)",
            evidence="PT_GNU_RELRO present without BIND_NOW",
        ),
        RelroLevel.PARTIAL,
    )


def _check_canary(info: ElfInfo) -> HardeningProperty:
    found = sorted(_CANARY_SYMBOLS & info.symbols)
    if found:
        return HardeningProperty(
            name="Stack Canary",
            state=HardeningState.ENABLED,
            detail=(
                "stack-protector instrumentation present; note that GCC protects "
                "selected functions only, so this is not whole-program coverage"
            ),
            evidence=f"symbols: {', '.join(found)}",
        )
    return HardeningProperty(
        name="Stack Canary",
        state=HardeningState.DISABLED,
        detail="no stack-protector symbols found",
        evidence=f"none of {', '.join(sorted(_CANARY_SYMBOLS))} present",
    )


def _check_fortify(info: ElfInfo) -> HardeningProperty:
    fortified = sorted(
        s for s in info.symbols if s.startswith("__") and s.endswith(_FORTIFY_SUFFIX)
    )
    if fortified:
        sample = ", ".join(fortified[:4])
        return HardeningProperty(
            name="FORTIFY_SOURCE",
            state=HardeningState.ENABLED,
            detail=f"{len(fortified)} fortified libc wrapper(s) referenced",
            evidence=f"symbols: {sample}" + (" ..." if len(fortified) > 4 else ""),
        )
    return HardeningProperty(
        name="FORTIFY_SOURCE",
        state=HardeningState.UNKNOWN,
        detail=(
            "no fortified wrappers referenced; this can mean fortification is off "
            "or that no fortifiable call sites exist"
        ),
        evidence="no __*_chk symbols",
    )


def inspect_binary(
    path: Path,
    *,
    version: Version,
    profile: BuildProfile = BuildProfile.RELEASE,
    sha256: str | None = None,
) -> BinaryHardening:
    """Inspect one ELF binary and report its protections with evidence."""
    info = _read_elf(path)
    relro_prop, relro_level = _check_relro(info)
    pie = _check_pie(info)

    caveats = [
        "PIE only enables ASLR; it does not prove ASLR is active in the "
        "execution environment (see /proc/sys/kernel/randomize_va_space).",
        "Stack-canary symbols show the protector is linked in, not that every "
        "function is instrumented.",
    ]

    return BinaryHardening(
        version=version,
        profile=profile,
        binary_path=str(path),
        binary_sha256=sha256,
        nx=_check_nx(info),
        pie=pie,
        relro=relro_prop,
        relro_level=relro_level,
        canary=_check_canary(info),
        fortify=_check_fortify(info),
        caveats=caveats,
    )
