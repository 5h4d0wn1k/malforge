"""PE (Portable Executable) static parser (hand-written, stdlib only).

Parses DOS/NT headers, section table, imports/exports, resources, entry point
and checks ASLR/DEP (NX) mitigation flags.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import rawbytes as raw


class PEError(Exception):
    pass


IMAGE_DOS_MAGIC = 0x5A4D  # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"

IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040  # ASLR
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100  # DEP / NX

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_READ = 0x40000000


@dataclass
class PEFile:
    path: str = ""
    is_pe: bool = False
    is_32bit: bool = False
    e_lfanew: int = 0
    machine: int = 0
    number_of_sections: int = 0
    entry_point: int = 0
    image_base: int = 0
    size_of_image: int = 0
    dll_characteristics: int = 0
    sections: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    raw: bytes = b""
    aslr: bool = False
    dep: bool = False
    errors: list = field(default_factory=list)


def _read_cstr(buf: bytes, off: int, max_len: int = 1024) -> str:
    if off is None or off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off, off + max_len)
    if end == -1:
        end = min(off + max_len, len(buf))
    return buf[off:end].decode("ascii", errors="replace")


def parse(data: bytes, path: str = "") -> PEFile:
    f = PEFile(path=path, raw=data)
    if len(data) < 64:
        raise PEError("truncated file")
    dos_magic = struct.unpack_from("<H", data, 0)[0]
    if dos_magic != IMAGE_DOS_MAGIC:
        raise PEError("not a PE (bad DOS magic)")
    f.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if f.e_lfanew + 4 > len(data):
        raise PEError("invalid e_lfanew")
    nt = struct.unpack_from("<I", data, f.e_lfanew)[0]
    if nt != IMAGE_NT_SIGNATURE:
        raise PEError("not a PE (missing NT signature)")
    f.is_pe = True
    fcoff = f.e_lfanew + 4

    f.machine = struct.unpack_from("<H", data, fcoff)[0]
    f.number_of_sections = struct.unpack_from("<H", data, fcoff + 2)[0]
    opt_off = fcoff + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    f.is_32bit = (magic == 0x10B)
    is_64bit = (magic == 0x20B)
    if not (f.is_32bit or is_64bit):
        raise PEError("bad optional header magic")

    f.entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]
    f.image_base = struct.unpack_from("<Q" if is_64bit else "<I", data, opt_off + 24)[0]
    f.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
    f.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]

    if is_64bit:
        num_rva_sizes = struct.unpack_from("<I", data, opt_off + 108)[0]
        dd_base = opt_off + 112
        size_opt = 240
    else:
        num_rva_sizes = struct.unpack_from("<I", data, opt_off + 92)[0]
        dd_base = opt_off + 96
        size_opt = 224

    f.aslr = bool(f.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    f.dep = bool(f.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    dd = {}
    for i in range(min(num_rva_sizes, 16)):
        rva, sz = struct.unpack_from("<II", data, dd_base + i * 8)
        dd[i] = (rva, sz)

    # ---- sections ----
    sec_off = fcoff + 20 + size_opt
    for i in range(f.number_of_sections):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].decode("ascii", errors="replace").rstrip("\x00")
        sec = {
            "index": i,
            "name": name,
            "virtual_size": struct.unpack_from("<I", data, off + 8)[0],
            "virtual_address": struct.unpack_from("<I", data, off + 12)[0],
            "raw_size": struct.unpack_from("<I", data, off + 16)[0],
            "raw_offset": struct.unpack_from("<I", data, off + 20)[0],
            "characteristics": struct.unpack_from("<I", data, off + 36)[0],
            "entropy": 0.0,
            "rwx": False,
            "raw_bytes": b"",
        }
        rs = sec["raw_offset"]
        rsz = sec["raw_size"]
        if rs < len(data) and rsz:
            sec["raw_bytes"] = data[rs:rs + rsz]
        sec["entropy"] = round(raw.entropy(sec["raw_bytes"]), 3)
        c = sec["characteristics"]
        sec["rwx"] = bool(c & IMAGE_SCN_MEM_EXECUTE and c & IMAGE_SCN_MEM_WRITE)
        f.sections.append(sec)

    f.imports = _parse_imports(data, dd, f.sections, is_64bit)
    f.exports = _parse_exports(data, dd, f.sections, is_64bit)
    f.resources = _parse_resources(data, dd, f.sections)

    f.strings = raw.extract_strings(data, min_len=5)
    return f


def _rva_to_offset(rva: int, sections: list) -> int | None:
    for s in sections:
        va = s["virtual_address"]
        vs = max(s["virtual_size"], s["raw_size"])
        if va <= rva < va + vs:
            return s["raw_offset"] + (rva - va)
    return None


def _parse_imports(data: bytes, dd: dict, sections: list, is_64bit: bool) -> list:
    rva, size = dd.get(1, (0, 0))
    if not rva:
        return []
    off = _rva_to_offset(rva, sections)
    if off is None:
        return []
    imports = []
    cur = off
    while cur + 20 <= len(data):
        entry = data[cur:cur + 20]
        if is_64bit:
            (orig_first_thunk, _td, _fc, name_rva, first_thunk) = \
                struct.unpack_from("<QQQII", entry, 0)
            tsz = 8
        else:
            (orig_first_thunk, _td, _fc, name_rva, first_thunk) = \
                struct.unpack_from("<IIIII", entry, 0)
            tsz = 4
        if orig_first_thunk == 0 and first_thunk == 0 and name_rva == 0:
            break
        name_off = _rva_to_offset(name_rva, sections)
        dll_name = _read_cstr(data, name_off) if name_off else ""
        thunk_rva = orig_first_thunk or first_thunk
        thunk_off = _rva_to_offset(thunk_rva, sections)
        funcs = []
        if thunk_off is not None:
            j = 0
            while thunk_off + j + tsz <= len(data):
                rawval = data[thunk_off + j:thunk_off + j + tsz]
                val = struct.unpack_from("<Q" if tsz == 8 else "<I", rawval, 0)[0]
                if val == 0:
                    break
                if val >> (63 if tsz == 8 else 31):
                    funcs.append({"ordinal": val & 0xFFFF})
                else:
                    hint_rva = val & 0x7FFFFFFF
                    hint_off = _rva_to_offset(hint_rva, sections)
                    name = _read_cstr(data, hint_off + 2) if hint_off else ""
                    funcs.append({"hint_ordinal": val & 0xFFFF, "name": name})
                j += tsz
        imports.append({"dll": dll_name, "functions": funcs})
        cur += 20
    return imports


def _parse_exports(data: bytes, dd: dict, sections: list, is_64bit: bool) -> list:
    rva, size = dd.get(0, (0, 0))
    if not rva:
        return []
    off = _rva_to_offset(rva, sections)
    if off is None or off + 40 > len(data):
        return []
    num_names = struct.unpack_from("<I", data, off + 24)[0]
    addr_names = struct.unpack_from("<I", data, off + 32)[0]
    names_off = _rva_to_offset(addr_names, sections)
    exports = []
    if names_off is None:
        return exports
    for i in range(num_names):
        if names_off + i * 4 + 4 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
        n_off = _rva_to_offset(name_rva, sections)
        exports.append(_read_cstr(data, n_off) if n_off else "")
    return exports


def _parse_resources(data: bytes, dd: dict, sections: list) -> list:
    rva, size = dd.get(2, (0, 0))
    if not rva:
        return []
    off = _rva_to_offset(rva, sections)
    if off is None:
        return []
    return [{"directory_rva": rva, "size": size}]
