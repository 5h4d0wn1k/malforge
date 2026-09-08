"""Tests for packer detector."""
from __future__ import annotations

import unittest
import os
import struct

from malforge import packer
from malforge.parsers import rawbytes as raw


class TestPackerDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.fixtures import make_pe_fixture
        cls.pe_data = make_pe_fixture()

    def test_pe_format(self):
        r = packer.build_report(self.pe_data)
        self.assertEqual(r["format"], "pe")

    def test_entropy_range(self):
        r = packer.build_report(self.pe_data)
        self.assertGreaterEqual(r["overall_entropy"], 0.0)
        self.assertLessEqual(r["overall_entropy"], 8.0)

    def test_rwx_detection(self):
        rwx_pe = bytearray(self.pe_data)
        # Set .text section characteristics to RWX: WRITE|EXEC|READ
        e_lfanew = struct.unpack_from("<I", rwx_pe, 0x3C)[0]
        opt = e_lfanew + 4 + 20
        size_opt = 224
        sec_off = e_lfanew + 4 + 20 + size_opt
        chars = struct.unpack_from("<I", rwx_pe, sec_off + 36)[0]
        chars |= 0x80000000 | 0x20000000  # WRITE | EXECUTE
        struct.pack_into("<I", rwx_pe, sec_off + 36, chars)
        r = packer.build_report(bytes(rwx_pe))
        rwx_flags = [f for f in r["flags"] if f["flag"] == "RWX_SECTION"]
        self.assertGreater(len(rwx_flags), 0)

    def test_high_entropy_random(self):
        r = packer.build_report(os.urandom(16384))
        self.assertGreater(r["overall_entropy"], 7.0)

    def test_signature_detection(self):
        # Inject UPX signature
        data = bytearray(self.pe_data)
        data[0x210:0x214] = b"UPX!"
        r = packer.build_report(bytes(data))
        sig_flags = [f for f in r["flags"] if f["flag"] == "PACKER_SIGNATURE"]
        self.assertGreater(len(sig_flags), 0)

    def test_report_structure(self):
        r = packer.build_report(self.pe_data)
        self.assertIn("format", r)
        self.assertIn("overall_entropy", r)
        self.assertIn("suspected_packed", r)
        self.assertIn("flags", r)
        self.assertIn("sections", r)
        self.assertIn("summary", r)
        self.assertIsInstance(r["flags"], list)
        self.assertIsInstance(r["sections"], list)


class TestPackerEvidence(unittest.TestCase):
    def test_add_flag(self):
        e = packer.PackerEvidence()
        e.add_flag("TEST", "test detail", 2)
        self.assertEqual(len(e.flags), 1)
        self.assertEqual(e.flags[0]["flag"], "TEST")

    def test_summary(self):
        e = packer.PackerEvidence()
        self.assertEqual(e.summary(), "no packer evidence")
        e.add_flag("X", "detail1", 1)
        self.assertIn("detail1", e.summary())


if __name__ == "__main__":
    unittest.main()
