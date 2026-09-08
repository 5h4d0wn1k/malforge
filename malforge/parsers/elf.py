"""ELF32/64 static parser (hand-written, stdlib only).

Parses ELF headers, program/section headers, symbols, relocations, dynamic
imports (GOT/PLT mapping), section strings and per-section entropy.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from . import rawbytes as raw

ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
ET_EXEC = 2
ET_DYN = 3

SHN_UNDEF = 0

SHT_RELA = 4
SHT_REL = 9
SHT_DYNSYM = 11
SHT_STRTAB = 3
SHT_SYMTAB = 2


class ELFError(Exception):
    pass


@dataclass
class ELFFile:
    path: str = ""
    elf_class: int = 0
    data_encoding: int = 0
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0
    ident: bytes = b""
    sections: list = field(default_factory=list)
    segments: list = field(default_factory=list)
    symbols: list = field(default_factory=list)
    dynamic_symbols: list = field(default_factory=list)
    relocations: list = field(default_factory=list)
    dynamic_imports: list = field(default_factory=list)
    got_plt: list = field(default_factory=list)
    plt_entries: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    is_pie: bool = False
    is_dynamic: bool = False
    raw: bytes = b""
    errors: list = field(default_factory=list)


def _parse_ident(buf: bytes) -> tuple[int, int]:
    if len(buf) < 16 or buf[:4] != b"\x7fELF":
        raise ELFError("not an ELF (bad magic)")
    elf_class = buf[4]
    data_encoding = buf[5]
    if elf_class not in (ELFCLASS32, ELFCLASS64):
        raise ELFError(f"unsupported ELF class {elf_class}")
    if data_encoding not in (ELFDATA2LSB, ELFDATA2MSB):
        raise ELFError("unsupported ELF data encoding")
    return elf_class, data_encoding


def _words(elf_class: int):
    if elf_class == ELFCLASS64:
        return 8, "Q"
    return 4, "I"


def parse(data: bytes, path: str = "") -> ELFFile:
    if len(data) < 64:
        raise ELFError("truncated ELF header")
    f = ELFFile(path=path, raw=data)
    f.ident = data[:16]
    f.elf_class, f.data_encoding = _parse_ident(data)
    if f.data_encoding == ELFDATA2LSB:
        endian = "<"
    else:
        endian = ">"

    if f.elf_class == ELFCLASS64:
        fmt = "16sHHIQQQIHHHHHH"
        sz = 64
    else:
        fmt = "16sHHIIIIIHHHHHH"
        sz = 52
    if len(data) < sz:
        raise ELFError("truncated ELF header")
    (_, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, f.e_phnum, e_shentsize,
     f.e_shnum, f.e_shstrndx) = struct.unpack_from(endian + fmt, data, 0)
    f.e_type = e_type
    f.e_machine = e_machine
    f.e_version = e_version
    f.e_entry = e_entry
    f.e_phoff = e_phoff
    f.e_shoff = e_shoff
    f.e_shentsize = e_shentsize
    f.is_pie = e_type == ET_DYN

    _bits, addr_fmt = _words(f.elf_class)

    # ---- sections ----
    shdr_fmt_64 = "IIQQQQIIQQ"
    shdr_fmt_32 = "IIIIIIIIII"
    shdr_fmt = shdr_fmt_64 if f.elf_class == ELFCLASS64 else shdr_fmt_32
    shdr_sz = 64 if f.elf_class == ELFCLASS64 else 40
    strtab = b""
    strtab_off = 0
    if f.e_shoff and f.e_shnum:
        for i in range(f.e_shnum):
            off = f.e_shoff + i * shdr_sz
            if off + shdr_sz > len(data):
                break
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info, sh_addralign, sh_entsize) = \
                struct.unpack_from(endian + shdr_fmt, data, off)
            sec = {
                "index": i,
                "name_off": sh_name,
                "name": "",
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "info": sh_info,
                "entsize": sh_entsize,
                "raw_bytes": b"",
                "entropy": 0.0,
            }
            if sh_offset < len(data) and sh_size:
                sec["raw_bytes"] = data[sh_offset:sh_offset + sh_size]
            sec["entropy"] = round(raw.entropy(sec["raw_bytes"]), 3)
            f.sections.append(sec)
            if i == f.e_shstrndx:
                strtab = sec["raw_bytes"]
                strtab_off = sec["offset"]
        # name each section
        for sec in f.sections:
            sec["name"] = _read_strtab(strtab, sec["name_off"])

    # ---- segment (program) headers ----
    phdr_fmt_64 = "IIQQQQQQ"
    phdr_fmt_32 = "IIIIIIII"
    phdr_fmt = phdr_fmt_64 if f.elf_class == ELFCLASS64 else phdr_fmt_32
    phdr_sz = 56 if f.elf_class == ELFCLASS64 else 32
    if f.e_phoff and f.e_phnum:
        for i in range(f.e_phnum):
            off = f.e_phoff + i * phdr_sz
            if off + phdr_sz > len(data):
                break
            vals = struct.unpack_from(endian + phdr_fmt, data, off)
            seg = {
                "index": i,
                "type": vals[0],
                "flags": vals[1],
                "offset": vals[2],
                "vaddr": vals[3],
                "paddr": vals[4],
                "filesz": vals[5],
                "memsz": vals[6],
                "align": vals[7],
            }
            f.segments.append(seg)

    # ---- strings (section .rodata/.data/.dynstr etc.) ----
    f.strings = raw.extract_strings(data, min_len=5)

    # ---- dynamic imports + symbols ----
    _parse_symbols_and_dynamic(f, endian)
    _parse_relocations(f, endian)

    f.is_dynamic = any(s["name"] in (".dynamic", ".dynsym", ".rela.plt")
                       for s in f.sections)
    return f


def _read_strtab(strtab: bytes, off: int) -> str:
    if not strtab or off >= len(strtab):
        return ""
    end = strtab.find(b"\x00", off)
    if end == -1:
        end = len(strtab)
    return strtab[off:end].decode("ascii", errors="replace")


def _symbols_from_section(f: ELFFile, sec, endian: str) -> list:
    if f.elf_class == ELFCLASS64:
        fmt = "IBBHQQ"
        sz = 24
        addr_fmt = "Q"
    else:
        fmt = "IIIBBH"
        sz = 16
        addr_fmt = "I"
    raw_bytes = sec["raw_bytes"]
    # link -> index of associated string table
    strtab_sec = None
    if sec["link"] < len(f.sections):
        strtab_sec = f.sections[sec["link"]]
    strtab = strtab_sec["raw_bytes"] if strtab_sec else b""
    syms = []
    entsize = sec["entsize"] or sz
    for i in range(0, len(raw_bytes) - sz + 1, entsize):
        (st_name, st_value, st_size, st_info, st_other, st_shndx) = \
            struct.unpack_from(endian + fmt, raw_bytes, i)
        name = _read_strtab(strtab, st_name)
        if not name and st_name != 0:
            continue
        syms.append({
            "index": i // entsize,
            "name": name,
            "value": st_value,
            "size": st_size,
            "info": st_info,
            "bind": st_info >> 4,
            "type": st_info & 0xF,
            "shndx": st_shndx,
        })
    return syms


def _parse_symbols_and_dynamic(f: ELFFile, endian: str):
    dynstr = b""
    dynstr_sec = None
    for s in f.sections:
        if s["name"] == ".dynstr":
            dynstr = s["raw_bytes"]
            dynstr_sec = s
            break
    for s in f.sections:
        if s["type"] == SHT_SYMTAB and s["name"] == ".symtab":
            f.symbols = _symbols_from_section(f, s, endian)
        elif s["type"] == SHT_DYNSYM and s["name"] == ".dynsym":
            f.dynamic_symbols = _symbols_from_section(f, s, endian)

    # Relocations that define GOT.plt / imports (x86-64 for typical fixtures).
    reloc_names = {}
    for s in f.sections:
        if s["type"] in (SHT_RELA, SHT_REL):
            sec_syms = None
            for ss in f.sections:
                if ss["index"] == s["link"]:
                    sec_syms = ss
            st = sec_syms["raw_bytes"] if sec_syms else b""
            rel_fmt = "QQq" if f.elf_class == ELFCLASS64 else "IIi"
            rel_sz = 24 if f.elf_class == ELFCLASS64 else 12
            raw_bytes = s["raw_bytes"]
            for i in range(0, len(raw_bytes) - rel_sz + 1, rel_sz):
                (r_off, r_info, r_addend) = \
                    struct.unpack_from(endian + rel_fmt, raw_bytes, i)
                symidx = r_info >> 32 if f.elf_class == ELFCLASS64 else r_info >> 8
                rtype = r_info & 0xFFFFFFFF if f.elf_class == ELFCLASS64 else r_info & 0xFF
                name = _lookup_sym_name(f.dynamic_symbols, symidx, dynstr)
                reloc_names[r_off] = {"name": name, "type": rtype, "offset": r_off}
                f.relocations.append({
                    "section": s["name"],
                    "offset": r_off,
                    "type": rtype,
                    "symbol": name,
                    "sym_index": symidx,
                    "addend": r_addend,
                })

    # Build dynamic import list from dynsym whose st_shndx == SHN_UNDEF (undefined =
    # imported) and bind==GLOBAL.
    for sym in f.dynamic_symbols:
        if sym["shndx"] == SHN_UNDEF and sym["bind"] == 1 and sym["name"]:
            if sym["name"] not in [x["name"] for x in f.dynamic_imports]:
                f.dynamic_imports.append({"name": sym["name"], "type": sym["type"]})

    # GOT/PLT reconstruction (x86-64 typical PLT layout).
    for r in f.relocations:
        if r["type"] == 7 or r["type"] == 6:  # R_X86_64_JUMP_SLOT / GLOB_DAT
            f.got_plt.append({"offset": r["offset"], "symbol": r["symbol"]})


def _lookup_sym_name(dynsyms: list, idx: int, dynstr: bytes) -> str:
    if idx < len(dynsyms):
        return dynsyms[idx]["name"]
    return ""


def _parse_relocations(f: ELFFile, endian: str):
    # relocations already accumulated in _parse_symbols_and_dynamic
    return
