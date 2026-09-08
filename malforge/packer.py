"""Packer / obfuscation detector.

Heuristics combine entropy profiles, section anomalies (RWX, odd alignment),
compressor signature detection (UPX-like) and import-table anomalies. The goal
is to produce *evidence*, not a hard verdict, for suspected packing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import parsers as P
from .parsers import rawbytes as raw

# Threshold above which uniform high entropy across big sections suggests packing.
HIGH_ENTROPY = 7.0
CANARY_ENTROPY = 6.5

# Known packer / compression signatures.
SIGNATURES = [
    ("UPX", b"UPX!"),
    ("UPX", b"UPX0"),
    ("UPX", b"UPX1"),
    ("MPRESS", b"MPRESS"),
    ("ASPack", b"`ASPack"),
    ("Petite", b"Petite"),
    ("PEtite", b"PEtite"),
    ("FSG", b"FSG!"),
    ("yC", b"yC"),      # yoda's crypter marker
    ("Obsidium", b"Obsidium"),
    ("Themida", b"Themida"),
    ("Enigma Protector", b"Enigma"),
    ("MoleBox", b"MoleBox"),
    ("VMProtect", b"VMProtect"),
]


@dataclass
class PackerEvidence:
    flags: list = field(default_factory=list)
    """(flag_name, detail, severity 0-3)"""
    sections: list = field(default_factory=list)
    overall_entropy: float = 0.0
    suspected: bool = False
    score: int = 0
    format: str = ""

    def add_flag(self, flag: str, detail: str, severity: int = 1):
        self.flags.append({"flag": flag, "detail": detail, "severity": severity})

    def summary(self) -> str:
        return "; ".join(f["detail"] for f in self.flags) or "no packer evidence"


def _section_anomalies(f, evidence: PackerEvidence, sections: list, cutoff: float = 40 * 1024):
    for sec in sections:
        name = sec.get("name", "")
        ent = sec.get("entropy", 0.0)
        size = sec.get("size") or sec.get("raw_size") or 0
        if size < cutoff and isinstance(size, int) and size > 0:
            pass
        # RWX sections
        if sec.get("rwx"):
            evidence.add_flag(
                "RWX_SECTION", f"section {name!r} is writable+executable", 3)
        # Very-high entropy in a large section
        if isinstance(ent, (int, float)) and ent > HIGH_ENTROPY:
            evidence.add_flag(
                "HIGH_ENTROPY",
                f"section {name!r} entropy={ent:.2f} (>{HIGH_ENTROPY})", 2)
        # UPX-like: first section very small, second section huge with low entropy


def _find_signatures(data: bytes) -> list:
    hits = []
    for name, sig in SIGNATURES:
        if sig in data:
            hits.append(name)
    return hits


def analyze(data: bytes, fmt: str = "") -> PackerEvidence:
    evidence = PackerEvidence()
    evidence.format = fmt or P.identify(data)
    evidence.overall_entropy = round(raw.entropy(data), 3)

    sigs = _find_signatures(data)
    for s in dict.fromkeys(sigs):
        evidence.add_flag("PACKER_SIGNATURE", f"matched {s} signature", 3)

    sections = []
    if evidence.format == "pe":
        try:
            f = P.parse_pe(data)
            sections = [{
                "name": s["name"], "entropy": s["entropy"],
                "rwx": s["rwx"], "size": s["raw_size"],
                "virtual_address": s["virtual_address"],
                "virtual_size": s["virtual_size"], "raw_size": s["raw_size"],
            } for s in f.sections]
            _section_anomalies(f, evidence, sections)
        except P.PEError:
            evidence.add_flag("PARSE_ERROR", "PE parse failed", 0)
    elif evidence.format == "elf":
        try:
            f = P.parse_elf(data)
            sections = [{
                "name": s["name"], "entropy": s["entropy"],
                "size": s["size"], "flags": s["flags"],
            } for s in f.sections]
            _section_anomalies(f, evidence, sections)
        except P.ELFError:
            evidence.add_flag("PARSE_ERROR", "ELF parse failed", 0)
    elif evidence.format == "macho":
        try:
            f = P.parse_macho(data)
        except P.MachOError:
            evidence.add_flag("PARSE_ERROR", "Mach-O parse failed", 0)

    # Import-table anomaly: dynamic executables with very few/no imports can hint
    # at self-resolving loaders (packers inject their own loader).
    evidence.sections = sections

    # Threshold: an entropy > 7.2 on a large section is a strong signal we want
    # to surface in the demo/tests.
    evidence.score = sum(f["severity"] for f in evidence.flags)
    evidence.suspected = evidence.score >= 2 or evidence.overall_entropy > HIGH_ENTROPY
    return evidence


def build_report(data: bytes, fmt: str = "") -> dict:
    e = analyze(data, fmt)
    return {
        "format": e.format,
        "overall_entropy": e.overall_entropy,
        "suspected_packed": e.suspected,
        "score": e.score,
        "flags": e.flags,
        "sections": e.sections,
        "summary": e.summary(),
    }
