"""Tests for YARA rule generation."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from malforge.yara_gen import YaraGenerator, YaraRuleSet, YaraRule


class TestYaraRule(unittest.TestCase):
    def test_rule_render(self):
        rule = YaraRule(
            name="test_rule",
            meta={"author": "malforge", "description": "test"},
            strings=[("s0", "str", "hello"), ("h0", "hex", "90 90")],
            condition="s0",
        )
        text = rule.to_yar()
        self.assertIn("rule test_rule {", text)
        self.assertIn('author = "malforge"', text)
        self.assertIn('$s0 = "hello"', text)
        self.assertIn('$h0 = { 90 90 }', text)
        self.assertIn("condition:", text)

    def test_rule_meta_types(self):
        rule = YaraRule(name="r", meta={"n": 5}, strings=[], condition="false")
        text = rule.to_yar()
        self.assertIn("n = 5", text)


class TestYaraRuleSet(unittest.TestCase):
    def test_to_yar(self):
        r1 = YaraRule(name="a", strings=[("s0", "str", "x")], condition="s0")
        r2 = YaraRule(name="b", strings=[("s0", "str", "y")], condition="s0")
        rs = YaraRuleSet(rules=[r1, r2])
        text = rs.to_yar()
        self.assertIn("rule a {", text)
        self.assertIn("rule b {", text)


class TestYaraGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.fixtures import make_elf_fixtures, make_clean_samples_for_yara
        fx = make_elf_fixtures()
        cls.samples = {
            "hello": fx["hello"],
            "packed": fx["packed"],
            "clean": fx["clean"],
        }
        cls.clean = make_clean_samples_for_yara()

    def test_generate_three_rules(self):
        gen = YaraGenerator(self.samples)
        ruleset = gen.generate(negatives=self.clean)
        self.assertEqual(len(ruleset.rules), 3)

    def test_rules_markup(self):
        gen = YaraGenerator(self.samples)
        ruleset = gen.generate(negatives=self.clean)
        old_rule_names = [r.name for r in ruleset.rules]
        new_names = set()
        for r in ruleset.rules:
            self.assertTrue(r.name.startswith("malforge_"))
            self.assertNotIn(r.name, new_names)
            new_names.add(r.name)

    def test_validate_positive_hits(self):
        gen = YaraGenerator(self.samples)
        ruleset = gen.generate(negatives=self.clean)
        valid = gen.validate(ruleset, self.samples, self.clean)
        self.assertGreaterEqual(valid["true_positives"], 2,
                                f"only {valid['true_positives']} TP")
        self.assertEqual(valid["false_positives"], 0,
                         f"{valid['false_positives']} FP")

    def test_save_rules(self):
        gen = YaraGenerator(self.samples)
        ruleset = gen.generate(negatives=self.clean)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "rules.yar"
            gen.save_rules(ruleset, out)
            self.assertTrue(out.exists())
            text = out.read_text()
            self.assertIn("rule ", text)

    def test_ngram_extract(self):
        from malforge.yara_gen.generator import _extract_ngrams
        data = b"\x01\x02\x03\x04\x05\x01\x02\x03\xff\x00\x11\x22"
        grams = _extract_ngrams(data, n=4)
        self.assertGreater(len(grams), 0)
        for g in grams:
            self.assertEqual(len(g), 4)


if __name__ == "__main__":
    unittest.main()
