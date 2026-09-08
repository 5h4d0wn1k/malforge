"""Static binary parsers: ELF, PE, Mach-O and raw byte utilities.

All parsers are hand-written against the file formats and depend only on the
Python standard library. Optional LIEF/capstone acceleration is not required.
"""
from __future__ import annotations

from . import rawbytes
from .elf import ELFFile, ELFError, parse as parse_elf
from .macho import MachOFile, MachOError, parse as parse_macho
from .pe import PEFile, PEError, parse as parse_pe

__all__ = [
    "rawbytes",
    "parse_elf",
    "parse_pe",
    "parse_macho",
    "ELFFile",
    "PEFile",
    "MachOFile",
    "ELFError",
    "PEError",
    "MachOError",
]


def identify(data: bytes) -> str:
    """Return 'elf', 'pe', 'macho', 'raw' based on magic bytes."""
    if data[:4] == b"\x7fELF":
        return "elf"
    if len(data) >= 2 and data[0] == 0x4D and data[1] == 0x5A:
        return "pe"
    if len(data) >= 4:
        m = data[:4]
        if m in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                 b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
            return "macho"
    return "raw"
