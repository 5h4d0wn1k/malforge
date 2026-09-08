"""Tests for Frida generator."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from malforge.frida_gen import FridaGenerator, HookConfig
from malforge.frida_gen.generator import _validate_js_syntax


class TestFridaGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = FridaGenerator()

    def test_log_hook(self):
        c = HookConfig(module="libc.so.6", function="open")
        s = self.gen.generate(c)
        self.assertTrue(s.syntax_valid, f"errors: {s.errors}")
        self.assertIn("Interceptor.attach", s.js_code)
        self.assertIn('Module.findExportByName("libc.so.6", "open")', s.js_code)
        self.assertIn("onEnter", s.js_code)
        self.assertIn("onLeave", s.js_code)

    def test_replace_hook(self):
        c = HookConfig(module="libc.so.6", function="open",
                       action="replace", replacement_value="-1")
        s = self.gen.generate(c)
        self.assertTrue(s.syntax_valid)
        self.assertIn("retval.replace(-1)", s.js_code)

    def test_block_hook(self):
        c = HookConfig(module="libc.so.6", function="open", action="block")
        s = self.gen.generate(c)
        self.assertTrue(s.syntax_valid)
        self.assertIn("BLOCKED", s.js_code)

    def test_syntax_validator(self):
        self.assertEqual(_validate_js_syntax("function(){}"), [])
        self.assertGreater(len(_validate_js_syntax("function(){")), 0)

    def test_syntax_validator_parens(self):
        self.assertEqual(_validate_js_syntax("foo(bar);"), [])
        self.assertGreater(len(_validate_js_syntax("foo(bar();")), 0)

    def test_batch_generate(self):
        configs = [
            HookConfig(module="m1", function="f1"),
            HookConfig(module="m2", function="f2", action="block"),
        ]
        snippets = self.gen.generate_batch(configs)
        self.assertEqual(len(snippets), 2)
        for s in snippets:
            self.assertTrue(s.syntax_valid)

    def test_save_snippet(self):
        c = HookConfig(module="libc.so.6", function="read")
        s = self.gen.generate(c)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "hook.js"
            self.gen.save_snippet(s, str(out))
            self.assertTrue(out.exists())
            self.assertIn("Interceptor", out.read_text())


if __name__ == "__main__":
    unittest.main()
