"""Raw binary analysis utilities.

Hand-written, dependency-free byte parsing helpers shared across parsers.
"""
from __future__ import annotations

import math
import zlib
from dataclasses import dataclass, field


def entropy(data: bytes) -> float:
    """Shannon entropy (bits per byte) of a byte string. Empty -> 0.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = float(len(data))
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def block_entropies(data: bytes, block_size: int = 256) -> list[float]:
    """Entropy of each fixed-size block."""
    out = []
    for i in range(0, len(data), block_size):
        out.append(entropy(data[i:i + block_size]))
    return out


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def ngrams(data: bytes, n: int = 8) -> list[bytes]:
    """Extract overlapping n-grams from data."""
    if n <= 0:
        return []
    grams: list[bytes] = []
    for i in range(0, len(data) - n + 1):
        grams.append(data[i:i + n])
    return grams


def u8(buf: bytes, off: int) -> int:
    return buf[off]


def u16le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 2], "little")


def u32le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 4], "little")


def u64le(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 8], "little")


def u16be(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 2], "big")


def u32be(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 4], "big")


def u64be(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 8], "big")


def cstr(buf: bytes, off: int, max_len: int = 1024) -> str:
    """Read a null-terminated ASCII string starting at off."""
    end = buf.find(b"\x00", off, off + max_len)
    if end == -1:
        end = min(off + max_len, len(buf))
    return buf[off:end].decode("ascii", errors="replace")


@dataclass
class StringsResult:
    """Result of a strings extraction pass."""
    strings: list = field(default_factory=list)
    """Each entry: (offset, ascii_str, flags)"""


DEFAULT_STRINGS_MIN = 4


def extract_strings(data: bytes, min_len: int = DEFAULT_STRINGS_MIN,
                    ascii_only: bool = True) -> list[tuple[int, str]]:
    """Extract printable ASCII strings (offset, value)."""
    out: list[tuple[int, str]] = []
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E or b == 0x09:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append((start, cur.decode("ascii")))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append((start, cur.decode("ascii")))
    return out


def section_entropy_report(sections: list[dict]) -> list[dict]:
    """Attach per-section entropy metadata if raw bytes available."""
    for s in sections:
        raw = s.get("raw_bytes") or b""
        s["entropy"] = round(entropy(raw), 3)
        s["size"] = len(raw)
    return sections
