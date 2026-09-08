"""Tests for dynamic sandbox."""
from __future__ import annotations

import os
import tempfile
import unittest

from malforge.sandbox import run_sandbox, BehaviorReport, SandboxRunner


class TestSandboxRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.fixtures import make_elf_fixtures
        fx = make_elf_fixtures()
        cls.benign = fx.get("benign")
        cls.hello = fx.get("hello")

    def test_benign_produces_report(self):
        if not self.benign:
            self.skipTest("no benign fixture")
        with tempfile.NamedTemporaryFile(suffix="_ben", delete=False,
                                         dir="/tmp") as tf:
            tf.write(self.benign)
            tf.flush()
            os.chmod(tf.name, 0o755)
            path = tf.name
        try:
            report = run_sandbox(path, timeout=3)
            self.assertIsInstance(report, BehaviorReport)
            self.assertGreater(report.pid, 0)
            self.assertGreater(report.duration_ms, 0)
        finally:
            os.unlink(path)

    def test_watermark(self):
        r = BehaviorReport()
        self.assertEqual(r.watermark, "SAMPLE:benign-lab")

    def test_to_json(self):
        r = BehaviorReport(binary="test")
        j = r.to_json()
        self.assertIn("SAMPLE:benign-lab", j)
        self.assertIn("test", j)

    def test_to_dict(self):
        r = BehaviorReport(binary="test.bin")
        d = r.to_dict()
        self.assertEqual(d["binary"], "test.bin")
        self.assertIn("watermark", d)

    def test_nonexistent_binary(self):
        with self.assertRaises(FileNotFoundError):
            SandboxRunner("/nonexistent_binary_xyz")

    def test_hello_produces_output(self):
        if not self.hello:
            self.skipTest("no hello fixture")
        with tempfile.NamedTemporaryFile(suffix="_hl", delete=False,
                                         dir="/tmp") as tf:
            tf.write(self.hello)
            tf.flush()
            os.chmod(tf.name, 0o755)
            path = tf.name
        try:
            report = run_sandbox(path, timeout=3)
            self.assertGreater(report.duration_ms, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
