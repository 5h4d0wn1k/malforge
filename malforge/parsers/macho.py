"""Mach-O static parser (hand-written, stdlib only).

Parses Mach-O magic, load commands, LC_DYLD_INFO (bind/export offsets) and
symbols. Focus is byte-level accuracy on crafted fixtures.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import rawbytes as raw

MH_MAGIC = 0xFEEDFACE      # 32-bit LE
MH_CIGAM = 0xCEFAEDFE      # 32-bit BE
MH_MAGIC_64 = 0xFEEDFACF   # 64-bit LE
MH_CIGAM_64 = 0xCFFAEDFE   # 64-bit BE

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022

MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_DYLIB = 0x6


class MachOError(Exception):
    pass


MACHO_TYPES = {
    MH_OBJECT: "MH_OBJECT",
    MH_EXECUTE: "MH_EXECUTE",
    MH_DYLIB: "MH_DYLIB",
}


@dataclass
class MachOFile:
    path: str = ""
    magic: int = 0
    is_64bit: bool = False
    is_big_endian: bool = False
    cputype: int = 0
    filetype: int = 0
    ncmds: int = 0
    load_commands: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    dynamic_info: dict = field(default_factory=dict)
    strings: list = field(default_factory=list)
    raw: bytes = b""

    @property
    def filetype_name(self):
        return MACHO_TYPES.get(self.filetype, str(self.filetype))


def parse(data: bytes, path: str = "") -> MachOFile:
    if len(data) < 4:
        raise MachOError("truncated file")
    m4 = data[:4]
    if m4 == b"\xfe\xed\xfa\xce":
        f = MachOFile(path=path, magic=MH_MAGIC, raw=data)
        le, be, is64 = True, False, False
    elif m4 == b"\xce\xfa\xed\xfe":
        f = MachOFile(path=path, magic=MH_CIGAM, raw=data)
        le, be, is64 = False, True, False
    elif m4 == b"\xcf\xfa\xed\xfe":
        f = MachOFile(path=path, magic=MH_MAGIC_64, raw=data)
        le, be, is64 = True, False, True
    elif m4 == b"\xfe\xed\xfa\xcf":
        f = MachOFile(path=path, magic=MH_CIGAM_64, raw=data)
        le, be, is64 = False, True, True
    else:
        raise MachOError("not a Mach-O (bad magic)")
    f.is_big_endian = be
    f.is_64bit = is64
    endian = "<" if le else ">"

    (f.cputype, f.filetype, f.ncmds) = struct.unpack_from(endian + "iii", data, 4)
    _sizecmds, _flags = struct.unpack_from(endian + "ii", data, 16)

    off = 32 if f.is_64bit else 28
    for _ in range(f.ncmds):
        if off + 8 > len(data):
            break
        (cmd, cmdsize) = struct.unpack_from(endian + "II", data, off)
        block = data[off:off + cmdsize]
        lc = {"cmd": cmd, "cmdsize": cmdsize, "offset": off}
        if cmd == LC_SYMTAB:
            lc["nsyms"] = struct.unpack_from(endian + "II", block, 24)[0]
            lc["symoff"] = struct.unpack_from(endian + "I", block, 16)[0]
            lc["stroff"] = struct.unpack_from(endian + "I", block, 20)[0]
            f.symbols = _parse_symtab(data, lc, endian, f.is_64bit)
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            f.dynamic_info = {
                "export_off": struct.unpack_from(endian + "I", block, 8)[0],
                "export_size": struct.unpack_from(endian + "I", block, 12)[0],
                "bind_off": struct.unpack_from(endian + "I", block, 16)[0],
                "bind_size": struct.unpack_from(endian + "I", block, 20)[0],
                "weak_bind_off": struct.unpack_from(endian + "I", block, 24)[0],
                "lazy_bind_off": struct.unpack_from(endian + "I", block, 28)[0],
            }
        f.load_commands.append(lc)
        off += cmdsize

    f.strings = raw.extract_strings(data, min_len=5)
    return f


def _parse_symtab(data: bytes, lc: dict, endian: str, is_64bit: bool) -> list:
    syms = []
    entsize = 16 if is_64bit else 12
    base = lc.get("symoff", 0)
    stroff = lc.get("stroff", 0)
    count = lc.get("nsyms", 0)
    for i in range(count):
        off = base + i * entsize
        if off + entsize > len(data):
            break
        if is_64bit:
            (n_strx, n_type, n_sect, n_desc, n_value) = \
                struct.unpack_from(endian + "IBBHQ", data, off)
        else:
            (n_strx, n_type, n_sect, n_desc, n_value) = \
                struct.unpack_from(endian + "IBBHI", data, off)
        name = raw.cstr(data, stroff + n_strx) if n_strx else ""
        syms.append({
            "name": name,
            "type": n_type,
            "section": n_sect,
            "value": n_value,
        })
    return syms
