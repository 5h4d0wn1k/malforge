"""Tests for deobfuscation engine."""
from __future__ import annotations

import base64
import unittest

from malforge.deobfuscator import Deobfuscator
from malforge.deobfuscator.engine import (
    xor_single_byte, xor_multi_byte, brute_xor_single,
    try_base64_decode, decode_hex_escapes,
    unescape_string_stacking, safe_ast_fold,
)


class TestXOR(unittest.TestCase):
    def test_roundtrip_single(self):
        data = b"hello malforge test"
        key = 0x42
        enc = xor_single_byte(data, key)
        dec = xor_single_byte(enc, key)
        self.assertEqual(dec, data)

    def test_roundtrip_multi(self):
        data = b"malforge multibyte test payload"
        key = b"\x01\x02\x03"
        enc = xor_multi_byte(data, key)
        dec = xor_multi_byte(enc, key)
        self.assertEqual(dec, data)

    def test_brute_xor_finds_payload(self):
        original = "malforge_deobfuscation_test_payload_42"
        key = 0x1B
        obfuscated = bytes(b ^ key for b in original.encode())
        candidates = brute_xor_single(obfuscated)
        decoded_strings = [d.decode() for _, d in candidates]
        self.assertIn(original, decoded_strings)

    def test_brute_xor_all_zero(self):
        candidates = brute_xor_single(b"\x00" * 10)
        printable = [c for c in candidates
                     if all(0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
                            for b in c[1])]
        self.assertEqual(len(printable), len(candidates))

    def test_brute_xor_finds_key_zero(self):
        # identity: key 0 must decode 0x00 -> 0x00
        candidates = brute_xor_single(b"\x41\x42\x43")
        decoded = {k: d for k, d in candidates}
        self.assertEqual(decoded.get(0), b"ABC")


class TestBase64(unittest.TestCase):
    def test_standard_b64(self):
        payload = "hello_malforge_b64"
        encoded = base64.b64encode(payload.encode()).decode()
        results = try_base64_decode(encoded)
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0][1], payload)

    def test_invalid_b64(self):
        results = try_base64_decode("not_base64!!!")
        self.assertEqual(len(results), 0)


class TestHexEscapes(unittest.TestCase):
    def test_decode(self):
        result = decode_hex_escapes(r"\x48\x65\x6c\x6c\x6f")
        self.assertEqual(result, "Hello")

    def test_no_escapes(self):
        result = decode_hex_escapes("no escapes here")
        self.assertIsNone(result)


class TestStringStacking(unittest.TestCase):
    def test_concat(self):
        result = unescape_string_stacking('"hello" " " "world"')
        self.assertEqual(result, "hello world")

    def test_single(self):
        result = unescape_string_stacking('"alone"')
        self.assertEqual(result, "alone")


class TestASTFold(unittest.TestCase):
    def test_string_concat(self):
        result = safe_ast_fold('"a" + "b"')
        self.assertEqual(result, "ab")

    def test_int_add(self):
        result = safe_ast_fold("1 + 2")
        self.assertEqual(result, "3")

    def test_string_repeat(self):
        result = safe_ast_fold('"x" * 3')
        self.assertEqual(result, "xxx")

    def test_invalid(self):
        result = safe_ast_fold("import os")
        self.assertIsNone(result)


class TestDeobfuscator(unittest.TestCase):
    def test_xor_recovery(self):
        original = "malforge_planted_payload_success"
        key = 0x1B
        obfuscated = bytes(b ^ key for b in original.encode())
        deob = Deobfuscator(obfuscated)
        results = deob.auto_deobfuscate()
        recovered = [r for r in results if original in r.recovered]
        self.assertGreater(len(recovered), 0)

    def test_b64_recovery(self):
        payload = "test_base64_recovery_123"
        encoded = base64.b64encode(payload.encode()).decode()
        deob = Deobfuscator(encoded)
        results = deob.auto_deobfuscate()
        self.assertTrue(any(payload in r.recovered for r in results))

    def test_hex_escape_recovery(self):
        payload = r"\x48\x65\x6c\x6c\x6f"
        deob = Deobfuscator(payload)
        results = deob.auto_deobfuscate()
        self.assertTrue(any("Hello" in r.recovered for r in results))

    def test_string_stacking(self):
        deob = Deobfuscator('"mal" "forge"')
        results = deob.auto_deobfuscate()
        self.assertTrue(any("malforge" in r.recovered for r in results))

    def test_auto_deob_multiple(self):
        original = "multi_strategy_test"
        key = 0x42
        obf = bytes(b ^ key for b in original.encode())
        deob = Deobfuscator(obf)
        results = deob.auto_deobfuscate()
        self.assertGreater(len(results), 0)


if __name__ == "__main__":
    unittest.main()
