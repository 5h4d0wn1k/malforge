"""Tests for shellcode encoder/decoder."""
from __future__ import annotations

import unittest

from malforge.shellcode import ShellcodeCodec
from malforge.shellcode.codec import EncodeResult


class TestShellcodeCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = ShellcodeCodec()
        cls.fixtures = [
            b"\x90\x90\xcc\x90\xcc\x90\xcc",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x31\xc0\x40\x48\x83\xc0\x01",
            b"\xeb\xfe",  # infinite loop (just data, not executed)
        ]

    def test_xor_roundtrip(self):
        for data in self.fixtures:
            enc = self.codec.encode_xor(data)
            dec = self.codec.decode_xor(enc.encoded, enc.key)
            self.assertEqual(dec, data)

    def test_rot_roundtrip(self):
        for data in self.fixtures:
            enc = self.codec.encode_rot(data)
            dec = self.codec.decode_rot(enc.encoded, enc.key)
            self.assertEqual(dec, data)

    def test_multibyte_xor_roundtrip(self):
        for data in self.fixtures:
            enc = self.codec.encode_multibyte_xor(data)
            key = bytes.fromhex(enc.details.split("=")[1])
            dec = self.codec.decode_multibyte_xor(enc.encoded, key)
            self.assertEqual(dec, data)

    def test_hex_literal_roundtrip(self):
        data = b"\x90\xcc\x90\xcc"
        lit = self.codec.to_hex_literal(data)
        roundtrip = self.codec.from_hex_literal(lit)
        self.assertEqual(roundtrip, data)

    def test_to_hex_literal_format(self):
        lit = self.codec.to_hex_literal(b"\x90\xcc")
        self.assertIn("0x90", lit)
        self.assertIn("0xcc", lit)

    def test_encode_result(self):
        enc = self.codec.encode_xor(b"\x90\x90")
        self.assertIsInstance(enc, EncodeResult)
        self.assertTrue(enc.roundtrip_ok)

    def test_key_nonzero(self):
        enc = self.codec.encode_xor(b"\x90\x90", key=0x42)
        self.assertEqual(enc.key, 0x42)

    def test_roundtrip_all(self):
        for data in self.fixtures:
            results = self.codec.roundtrip_test(data)
            self.assertTrue(all(results.values()), f"roundtrip failed: {results}")


if __name__ == "__main__":
    unittest.main()
