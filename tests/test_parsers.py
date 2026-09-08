"""Tests for static parsers: ELF, PE, Mach-O, raw bytes."""
from __future__ import annotations

import os
import struct
import unittest

from malforge.parsers import elf as elfmod
from malforge.parsers import pe as pemod
from malforge.parsers import macho as machomod
from malforge.parsers import rawbytes as raw
from malforge.parsers import identify

from .fixtures import make_fixtures, make_elf_fixtures, make_pe_fixture


class TestRawBytes(unittest.TestCase):
    def test_entropy_zero_constant(self):
        self.assertEqual(raw.entropy(b"\x00" * 256), 0.0)

    def test_entropy_maximum(self):
        # all 256 distinct bytes -> 8.0 bits/byte
        e = raw.entropy(bytes(range(256)))
        self.assertAlmostEqual(e, 8.0, places=4)

    def test_entropy_known_string(self):
        e = raw.entropy(b"hello world")
        self.assertGreater(e, 2.5)
        self.assertLess(e, 5.0)

    def test_block_entropies_count(self):
        data = bytes(range(256)) * 4 + b"abc"
        bl = raw.block_entropies(data, 256)
        self.assertEqual(len(bl), 5)

    def test_crc32_known(self):
        self.assertEqual(raw.crc32(b"123456789"), 0xCBF43926)

    def test_ngrams(self):
        g = raw.ngrams(b"abcdef", 3)
        self.assertEqual(g, [b"abc", b"bcd", b"cde", b"def"])

    def test_le_helpers(self):
        buf = b"\x01\x02\x03\x04"
        self.assertEqual(raw.u16le(buf, 0), 0x0201)
        self.assertEqual(raw.u32le(buf, 0), 0x04030201)
        self.assertEqual(raw.u16be(buf, 0), 0x0102)
        self.assertEqual(raw.u32be(buf, 0), 0x01020304)

    def test_cstr(self):
        buf = b"abc\x00def\x00"
        self.assertEqual(raw.cstr(buf, 0), "abc")
        self.assertEqual(raw.cstr(buf, 4), "def")

    def test_extract_strings(self):
        buf = b"xxhello_worldzz\x00paddingmorehere"
        res = raw.extract_strings(buf, min_len=5)
        vals = [s for _, s in res]
        self.assertIn("xxhello_worldzz", vals)
        self.assertIn("paddingmorehere", vals)


class TestELF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = make_elf_fixtures()
        cls.hello = elfmod.parse(cls.fx["hello"])

    def test_ident_magic(self):
        self.assertEqual(self.hello.ident[:4], b"\x7fELF")

    def test_class_64(self):
        self.assertEqual(self.hello.elf_class, elfmod.ELFCLASS64)

    def test_data_encoding(self):
        self.assertEqual(self.hello.data_encoding, elfmod.ELFDATA2LSB)

    def test_machine(self):
        self.assertIn(self.hello.e_machine, (62, 3))  # x86-64 or i386

    def test_entry_point_nonzero(self):
        self.assertGreater(self.hello.e_entry, 0)

    def test_sections_present(self):
        self.assertGreater(len(self.hello.sections), 5)
        names = [s["name"] for s in self.hello.sections]
        self.assertIn(".text", names)
        self.assertIn(".symtab", names)  # debug build keeps symtab

    def test_symbols_present(self):
        self.assertGreater(len(self.hello.symbols), 0)
        names = [s["name"] for s in self.hello.symbols]
        self.assertIn("main", names)

    def test_strings_present(self):
        vals = [s for _, s in self.hello.strings]
        self.assertTrue(any("hello_malforge_fixture" in v for v in vals))

    def test_dynamic_imports_on_hello(self):
        # hello is compiled -no-pie static? we used -fno-PIE, so dynamic imports
        # may not be present. Just assert no crash.
        self.assertIsInstance(self.hello.dynamic_imports, list)

    def test_section_entropy_plausible(self):
        for s in self.hello.sections:
            self.assertGreaterEqual(s["entropy"], 0.0)
            self.assertLessEqual(s["entropy"], 8.0)

    def test_parse_failure(self):
        with self.assertRaises(elfmod.ELFError):
            elfmod.parse(b"not an elf file at all")


class TestPE(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe_bytes = make_pe_fixture()
        cls.pe = pemod.parse(cls.pe_bytes)

    def test_is_pe(self):
        self.assertTrue(self.pe.is_pe)

    def test_32bit(self):
        self.assertTrue(self.pe.is_32bit)

    def test_machine_i386(self):
        self.assertEqual(self.pe.machine, 0x14C)

    def test_entry_point(self):
        self.assertEqual(self.pe.entry_point, 0x1000)

    def test_sections_count(self):
        self.assertEqual(self.pe.number_of_sections, 1)
        self.assertEqual(len(self.pe.sections), 1)

    def test_section_name(self):
        self.assertEqual(self.pe.sections[0]["name"], ".text")

    def test_section_rwx_flag(self):
        # characteristics: execute|read, not write -> rwx False
        self.assertFalse(self.pe.sections[0]["rwx"])

    def test_imports_12(self):
        self.assertEqual(len(self.pe.imports), 1)
        dll = self.pe.imports[0]
        self.assertEqual(dll["dll"], "KERNEL32.dll")
        self.assertEqual(len(dll["functions"]), 12)

    def test_import_names(self):
        names = [f["name"] for f in self.pe.imports[0]["functions"]]
        self.assertIn("CreateFileA", names)
        self.assertIn("Sleep", names)
        self.assertIn("ExitProcess", names)

    def test_exports(self):
        self.assertEqual(self.pe.exports, ["FakeExport"])

    def test_aslr_dep(self):
        # default characteristics 0 -> no flags
        self.assertFalse(self.pe.aslr)
        self.assertFalse(self.pe.dep)

    def test_parse_failure(self):
        with self.assertRaises(pemod.PEError):
            pemod.parse(b"just some junk bytes")


class TestMachO(unittest.TestCase):
    def test_parse_64bit_le(self):
        # craft a minimal 64-bit little-endian Mach-O
        mh = bytearray(64)
        struct.pack_into("<I", mh, 0, machomod.MH_MAGIC_64)
        struct.pack_into("<i", mh, 4, 0x01000007)  # x86_64 cputype
        struct.pack_into("<i", mh, 8, machomod.MH_EXECUTE)
        struct.pack_into("<I", mh, 12, 0)  # ncmds
        m = machomod.parse(bytes(mh))
        self.assertTrue(m.is_64bit)
        self.assertFalse(m.is_big_endian)
        self.assertEqual(m.filetype_name, "MH_EXECUTE")

    def test_parse_32bit_be(self):
        mh = bytearray(64)
        struct.pack_into(">I", mh, 0, machomod.MH_CIGAM)
        struct.pack_into(">i", mh, 4, 7)
        struct.pack_into(">i", mh, 8, machomod.MH_OBJECT)
        struct.pack_into(">I", mh, 12, 0)
        m = machomod.parse(bytes(mh))
        self.assertFalse(m.is_64bit)
        self.assertTrue(m.is_big_endian)
        self.assertEqual(m.filetype_name, "MH_OBJECT")

    def test_parse_failure(self):
        with self.assertRaises(machomod.MachOError):
            machomod.parse(b"\x00\x01\x02\x03")


class TestIdentify(unittest.TestCase):
    def test_elf(self):
        self.assertEqual(identify(b"\x7fELFxxxx"), "elf")

    def test_pe(self):
        self.assertEqual(identify(b"MZ\x90\x00"), "pe")

    def test_macho(self):
        self.assertEqual(identify(b"\xce\xfa\xed\xfe"), "macho")

    def test_raw(self):
        self.assertEqual(identify(b"hello world raw"), "raw")


if __name__ == "__main__":
    unittest.main()
