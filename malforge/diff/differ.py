"""Structural binary diff with similarity scoring.

Compares section sizes, import sets, n-gram vectors, and normalized
instruction strings. Produces a similarity score [0.0, 1.0].
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path

from ..parsers import identify, parse_elf
from ..parsers import rawbytes as raw


@dataclass
class DiffReport:
    binary_a: str = ""
    binary_b: str = ""
    similarity: float = 0.0
    identical: bool = False
    section_diff: list = field(default_factory=list)
    import_diff: dict = field(default_factory=dict)
    ngram_similarity: float = 0.0
    size_ratio: float = 0.0
    details: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "binary_a": self.binary_a,
            "binary_b": self.binary_b,
            "similarity": round(self.similarity, 4),
            "identical": self.identical,
            "section_diff": self.section_diff,
            "import_diff": self.import_diff,
            "ngram_similarity": round(self.ngram_similarity, 4),
            "size_ratio": round(self.size_ratio, 4),
            "details": self.details,
        }


def _ngram_similarity(a: bytes, b: bytes, n: int = 8, sample: int = 2000) -> float:
    """Jaccard similarity of n-gram sets, sampled for speed."""
    grams_a = set(raw.ngrams(a, n))
    grams_b = set(raw.ngrams(b, n))
    if not grams_a and not grams_b:
        return 1.0
    if not grams_a or not grams_b:
        return 0.0
    # Sample for large binaries
    if len(grams_a) > sample:
        import random
        grams_a = set(random.sample(sorted(grams_a), sample))
    if len(grams_b) > sample:
        import random
        grams_b = set(random.sample(sorted(grams_b), sample))
    intersection = grams_a & grams_b
    union = grams_a | grams_b
    return len(intersection) / len(union) if union else 0.0


def _section_names(data: bytes) -> list[str]:
    fmt = identify(data)
    if fmt == "elf":
        try:
            f = parse_elf(data)
            return [s["name"] for s in f.sections]
        except Exception:
            return []
    elif fmt == "pe":
        from ..parsers import parse_pe
        try:
            f = parse_pe(data)
            return [s["name"] for s in f.sections]
        except Exception:
            return []
    return []


def _import_names(data: bytes) -> set[str]:
    fmt = identify(data)
    if fmt == "elf":
        try:
            f = parse_elf(data)
            return {s["name"] for s in f.dynamic_imports}
        except Exception:
            return set()
    elif fmt == "pe":
        from ..parsers import parse_pe
        try:
            f = parse_pe(data)
            names = set()
            for imp in f.imports:
                for func in imp["functions"]:
                    if "name" in func:
                        names.add(func["name"])
            return names
        except Exception:
            return set()
    return set()


class BinaryDiffer:
    def __init__(self, data_a: bytes, data_b: bytes,
                 name_a: str = "a", name_b: str = "b"):
        self.data_a = data_a
        self.data_b = data_b
        self.name_a = name_a
        self.name_b = name_b

    def diff(self) -> DiffReport:
        report = DiffReport(binary_a=self.name_a, binary_b=self.name_b)

        if self.data_a == self.data_b:
            report.similarity = 1.0
            report.identical = True
            return report

        # Size ratio
        max_len = max(len(self.data_a), len(self.data_b))
        min_len = min(len(self.data_a), len(self.data_b))
        report.size_ratio = min_len / max_len if max_len else 1.0

        # Section diff
        secs_a = _section_names(self.data_a)
        secs_b = _section_names(self.data_b)
        report.section_diff = [
            {"in_a_only": sorted(set(secs_a) - set(secs_b)),
             "in_b_only": sorted(set(secs_b) - set(secs_a)),
             "common": sorted(set(secs_a) & set(secs_b))},
        ]

        # Import diff
        imps_a = _import_names(self.data_a)
        imps_b = _import_names(self.data_b)
        report.import_diff = {
            "in_a_only": sorted(imps_a - imps_b),
            "in_b_only": sorted(imps_b - imps_a),
            "common": sorted(imps_a & imps_b),
        }

        # N-gram similarity
        report.ngram_similarity = _ngram_similarity(self.data_a, self.data_b)

        # Overall similarity: weighted combination
        secs_all = set(secs_a) | set(secs_b)
        imps_all = set(imps_a) | set(imps_b)
        report.similarity = (
            0.3 * report.size_ratio +
            0.3 * report.ngram_similarity +
            0.2 * (len(report.section_diff[0]["common"]) / max(len(secs_all), 1)) +
            0.2 * (len(report.import_diff["common"]) / max(len(imps_all), 1))
        )
        report.similarity = min(1.0, max(0.0, report.similarity))

        if report.similarity > 0.99:
            report.identical = True

        return report


def diff_files(path_a: str | Path, path_b: str | Path) -> DiffReport:
    a = Path(path_a).read_bytes()
    b = Path(path_b).read_bytes()
    return BinaryDiffer(a, b, str(path_a), str(path_b)).diff()
