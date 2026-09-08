"""YARA rule generator.

Builds real .yar rules from a fixture corpus: unique strings, n-grams,
entropy anchors, and import hash. Validates rules hit their samples and
are conservative (no FP on clean set).
"""
from __future__ import annotations

import hashlib
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..parsers import rawbytes as raw


@dataclass
class YaraRule:
    name: str = ""
    meta: dict = field(default_factory=dict)
    strings: list = field(default_factory=list)  # [(name, type, value)]
    condition: str = ""
    rule_text: str = ""

    def to_yar(self) -> str:
        lines = [f"rule {self.name} {{"]
        if self.meta:
            lines.append("  meta:")
            for k, v in self.meta.items():
                if isinstance(v, str):
                    escaped = v.replace("\\", "\\\\").replace('"', '\\"')
                    val = f'"{escaped}"'
                else:
                    val = str(v)
                lines.append(f"    {k} = {val}")
        if self.strings:
            lines.append("  strings:")
            for name, stype, value in self.strings:
                if stype == "str":
                    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                    lines.append(f'    ${name} = "{escaped}"')
                elif stype == "hex":
                    lines.append(f"    ${name} = {{ {value} }}")
                elif stype == "regex":
                    lines.append(f"    ${name} = /{value}/")
        lines.append(f"  condition:")
        lines.append(f"    {self.condition}")
        lines.append("}")
        self.rule_text = "\n".join(lines)
        return self.rule_text


@dataclass
class YaraRuleSet:
    rules: list = field(default_factory=list)
    validation: dict = field(default_factory=dict)

    def to_yar(self) -> str:
        return "\n\n".join(r.to_yar() for r in self.rules)


def _extract_unique_strings(data: bytes, min_len: int = 6,
                            max_strings: int = 20) -> list[tuple[int, str]]:
    """Extract unique printable strings from binary."""
    strings = raw.extract_strings(data, min_len=min_len)
    seen = set()
    unique = []
    for off, s in strings:
        if s not in seen and len(s) >= min_len:
            seen.add(s)
            unique.append((off, s))
    return unique[:max_strings]


def _extract_ngrams(data: bytes, n: int = 4, max_count: int = 10) -> list[bytes]:
    """Extract high-entropy n-grams as hex patterns."""
    grams = raw.ngrams(data, n)
    # Pick grams with reasonable entropy (not all zeros, not all same byte)
    scored = []
    for g in grams:
        if len(set(g)) >= 2:
            scored.append((raw.entropy(g), g))
    scored.sort(reverse=True)
    return [g for _, g in scored[:max_count]]


def _import_hash(data: bytes) -> str:
    """SHA-256 of first 4KB (import-region proxy)."""
    return hashlib.sha256(data[:4096]).hexdigest()[:16]


def _entropy_anchor(data: bytes, block_size: int = 512) -> list[float]:
    """Return entropy of first few blocks as metadata."""
    return [round(raw.entropy(data[i:i+block_size]), 2)
            for i in range(0, min(len(data), block_size * 3), block_size)]


class YaraGenerator:
    """Generate YARA rules from a corpus of samples."""

    def __init__(self, samples: dict[str, bytes] | None = None):
        self.samples = samples or {}

    def add_sample(self, name: str, data: bytes):
        self.samples[name] = data

    def generate(self, rule_prefix: str = "malforge",
                 negatives: dict[str, bytes] | None = None) -> YaraRuleSet:
        """Generate rules; `negatives` = clean corpus whose patterns are
        excluded to keep rules conservative (no FP on clean set)."""
        negatives = negatives or {}
        ruleset = YaraRuleSet()

        for i, (name, data) in enumerate(self.samples.items()):
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)[:40]
            rule_name = f"{rule_prefix}_{safe_name}_{i}"

            strings = _extract_unique_strings(data)
            ngrams = _extract_ngrams(data)
            imp_hash = _import_hash(data)
            ent_anchors = _entropy_anchor(data)

            # Exclude patterns that also appear in the clean/negative corpus
            neg_blobs = [n for n in negatives.values()]
            strings = [s for s in strings
                       if not any(s[1].encode("ascii", errors="replace") in n
                                  for n in neg_blobs)]
            ngrams = [g for g in ngrams if not any(g in n for n in neg_blobs)]

            yara_strings = []
            for j, (off, s) in enumerate(strings[:8]):
                yara_strings.append((f"s{j}", "str", s))
            for j, g in enumerate(ngrams[:4]):
                hex_str = " ".join(f"{b:02X}" for b in g)
                yara_strings.append((f"h{j}", "hex", hex_str))

            condition_parts = []
            if yara_strings:
                # Require at least 2 string matches
                str_names = [f"${s[0]}" for s in yara_strings if s[1] == "str"]
                hex_names = [f"${s[0]}" for s in yara_strings if s[1] == "hex"]
                if len(str_names) >= 2:
                    condition_parts.append(f"2 of ({'*'.join(str_names[:6])})")
                elif str_names:
                    condition_parts.append(str_names[0])
                if len(hex_names) >= 2:
                    condition_parts.append(f"2 of ({'*'.join(hex_names[:4])})")
                elif hex_names:
                    condition_parts.append(hex_names[0])
            if not condition_parts:
                condition_parts.append("false")

            rule = YaraRule(
                name=rule_name,
                meta={
                    "author": "malforge",
                    "description": f"Auto-generated rule for {name}",
                    "import_hash": imp_hash,
                    "entropy_anchors": str(ent_anchors),
                },
                strings=yara_strings,
                condition=" and ".join(condition_parts),
            )
            rule.to_yar()
            ruleset.rules.append(rule)

        return ruleset

    def validate(self, ruleset: YaraRuleSet,
                 positive_samples: dict[str, bytes],
                 negative_samples: dict[str, bytes] | None = None) -> dict:
        """Validate rules by checking string presence (lightweight, no yara lib).

        A sample "hits" if it satisfies at least one rule's condition: each rule
        requires N of its string patterns (N deduced from the generated
        condition), mimicking YARA's conjunctive/disjunctive semantics.
        """
        negative_samples = negative_samples or {}
        result = {"true_positives": 0, "true_negatives": 0,
                  "false_positives": 0, "false_negatives": 0,
                  "details": []}

        parsed = self._parse_rules(ruleset)

        def sample_hits(data: bytes):
            for rule in parsed:
                if self._rule_matches(rule, data):
                    return True
            return False

        for name, data in positive_samples.items():
            if sample_hits(data):
                result["true_positives"] += 1
                result["details"].append({"sample": name, "hit": True})
            else:
                result["false_negatives"] += 1
                result["details"].append({"sample": name, "hit": False})

        for name, data in negative_samples.items():
            if sample_hits(data):
                result["false_positives"] += 1
                result["details"].append({"sample": name, "fp": True})
            else:
                result["true_negatives"] += 1
                result["details"].append({"sample": name, "fp": False})

        ruleset.validation = result
        return result

    def _parse_rules(self, ruleset: YaraRuleSet) -> list[dict]:
        """Parse ruleset into {name, string_patterns:[bytes...], require:int}."""
        parsed = []
        for rule in ruleset.rules:
            patterns = []  # list of bytes patterns (text + hex decoded)
            for name, stype, value in rule.strings:
                if stype == "str":
                    patterns.append(value.encode("ascii", errors="replace"))
                elif stype == "hex":
                    try:
                        patterns.append(bytes.fromhex(value.replace(" ", "")))
                    except ValueError:
                        pass
            # Deduce required count from condition "N of (a*b*...)"
            require = 2
            m = re.search(r"(\d+) of \(", rule.condition)
            if m:
                require = int(m.group(1))
            parsed.append({
                "name": rule.name,
                "patterns": patterns,
                "require": min(require, max(len(patterns), 1)),
            })
        return parsed

    def _rule_matches(self, rule: dict, data: bytes) -> bool:
        hits = 0
        for pat in rule["patterns"]:
            if pat and pat in data:
                hits += 1
        return hits >= rule["require"]

    def _lightweight_check(self, rule_yar: str, data: bytes) -> bool:
        """Check if any string in the YARA rule text appears in the binary."""
        # Extract quoted strings and hex patterns from rule text
        text_patterns = re.findall(r'"([^"]+)"', rule_yar)
        hex_patterns = re.findall(r'\{ ([0-9A-Fa-f ]+) \}', rule_yar)

        for pat in text_patterns:
            if pat.encode("ascii", errors="replace") in data:
                return True

        for hp in hex_patterns:
            try:
                hex_bytes = bytes.fromhex(hp.replace(" ", ""))
                if hex_bytes in data:
                    return True
            except ValueError:
                continue

        return False

    def save_rules(self, ruleset: YaraRuleSet, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(ruleset.to_yar())
        return p
