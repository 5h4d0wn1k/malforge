"""Tests for binary diff."""
from __future__ import annotations

import unittest

from malforge.diff import BinaryDiffer, DiffReport
from malforge.diff.differ import diff_files, _ngram_similarity


class TestBinaryDiffer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.fixtures import make_elf_fixtures
        fx = make_elf_fixtures()
        cls.va = fx["variant_a"]
        cls.vb = fx["variant_b"]
        cls.hello = fx["hello"]

    def test_identical(self):
        d = BinaryDiffer(self.va, self.va, "a", "a")
        r = d.diff()
        self.assertTrue(r.identical)
        self.assertEqual(r.similarity, 1.0)

    def test_different(self):
        d = BinaryDiffer(self.va, self.vb, "va", "vb")
        r = d.diff()
        self.assertLess(r.similarity, 1.0)
        self.assertGreater(r.similarity, 0.0)
        self.assertFalse(r.identical)

    def test_completely_different(self):
        a = b"\x00" * 1024
        b = b"\xff" * 1024
        d = BinaryDiffer(a, b, "a", "b")
        r = d.diff()
        self.assertLess(r.similarity, 0.5)

    def test_similar_but_not_identical(self):
        a = b"hello world this is a test payload"
        b = b"hello world this is a test payloaX"
        d = BinaryDiffer(a, b, "a", "b")
        r = d.diff()
        self.assertLessEqual(r.similarity, 1.0)

    def test_report_structure(self):
        d = BinaryDiffer(self.va, self.vb, "va", "vb")
        r = d.diff()
        dct = r.to_dict()
        self.assertIn("similarity", dct)
        self.assertIn("identical", dct)
        self.assertIn("section_diff", dct)
        self.assertIn("import_diff", dct)
        self.assertIn("ngram_similarity", dct)


class TestNgramSimilarity(unittest.TestCase):
    def test_same(self):
        data = b"abcdefghijklmnop"
        self.assertEqual(_ngram_similarity(data, data), 1.0)

    def test_different(self):
        a = b"aaaaaaaaaaaaaaaa"
        b = b"bbbbbbbbbbbbbbbb"
        self.assertLess(_ngram_similarity(a, b), 1.0)


class TestDiffFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.fixtures import (FIXTURES)
        cls.va = FIXTURES / "variant_a"
        cls.vb = FIXTURES / "variant_b"

    def test_files(self):
        if not self.va.exists():
            self.skipTest("no fixtures")
        report = diff_files(self.va, self.vb)
        self.assertIsInstance(report, DiffReport)
        self.assertGreater(report.similarity, 0.0)


if __name__ == "__main__":
    unittest.main()
