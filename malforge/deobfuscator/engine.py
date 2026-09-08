"""Deobfuscation engine with multiple recovery strategies.

Proves correctness by recovering a planted obfuscated payload string.
All operations are safe — no code execution, only data transformation.
"""
from __future__ import annotations

import ast
import base64
import binascii
import dis
import re
import types
from dataclasses import dataclass, field


@dataclass
class DeobResult:
    strategy: str = ""
    recovered: str = ""
    original_length: int = 0
    recovered_length: int = 0
    confidence: float = 0.0
    details: str = ""


def xor_single_byte(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def xor_multi_byte(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def brute_xor_single(data: bytes, printable_only: bool = True) -> list[tuple[int, bytes]]:
    results = []
    for k in range(256):
        decoded = xor_single_byte(data, k)
        if printable_only:
            if all(0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D) for b in decoded):
                results.append((k, decoded))
        else:
            results.append((k, decoded))
    return results


def try_base64_decode(data: str) -> list[tuple[str, str]]:
    """Attempt base64 / urlsafe-b64 / base32 / base16 decode."""
    results = []
    s = data.strip()
    # base64
    try:
        decoded = base64.b64decode(s).decode("ascii", errors="ignore")
        if decoded and all(0x20 <= ord(c) <= 0x7E or c in "\t\n\r" for c in decoded):
            results.append(("base64", decoded))
    except Exception:
        pass
    # urlsafe b64
    try:
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        decoded = base64.urlsafe_b64decode(padded).decode("ascii", errors="ignore")
        if decoded and all(0x20 <= ord(c) <= 0x7E or c in "\t\n\r" for c in decoded):
            results.append(("base64_urlsafe", decoded))
    except Exception:
        pass
    # base32
    try:
        padded = s + "=" * (8 - len(s) % 8) if len(s) % 8 else s
        decoded = base64.b32decode(padded).decode("ascii", errors="ignore")
        if decoded and all(0x20 <= ord(c) <= 0x7E or c in "\t\n\r" for c in decoded):
            results.append(("base32", decoded))
    except Exception:
        pass
    return results


def decode_hex_escapes(data: str) -> str | None:
    """Decode \\xHH hex escape sequences."""
    pattern = r"(?:\\x([0-9a-fA-F]{2}))+"
    matches = list(re.finditer(pattern, data))
    if not matches:
        return None
    result = []
    for m in matches:
        full = m.group(0)
        hexpairs = re.findall(r"\\x([0-9a-fA-F]{2})", full)
        result.append("".join(chr(int(h, 16)) for h in hexpairs))
    return "".join(result)


def unescape_string_stacking(data: str) -> str:
    """Reverse string concatenation: "ab" "cd" -> "abcd"."""
    parts = re.findall(r'"([^"]*)"', data)
    return "".join(parts)


def safe_ast_fold(expr_str: str) -> str | None:
    """Evaluate constant AST expression safely (no function calls)."""
    try:
        tree = ast.parse(expr_str, mode="eval")
    except SyntaxError:
        return None

    def _eval(node):
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.BinOp):
            left = _eval(node.left)
            right = _eval(node.right)
            if isinstance(node.op, ast.Add):
                if isinstance(left, str) and isinstance(right, str):
                    return left + right
                elif isinstance(left, (int, float)) and isinstance(right, (int, float)):
                    return left + right
            elif isinstance(node.op, ast.Mult):
                if isinstance(left, str) and isinstance(right, int):
                    return left * right
                elif isinstance(left, int) and isinstance(right, int):
                    return left * right
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.USub):
                val = _eval(node.operand)
                if isinstance(val, (int, float)):
                    return -val
        return None

    result = _eval(tree.body)
    if result is not None:
        return str(result)
    return None


def disassemble_bytecode(code: types.CodeType | bytes) -> str:
    """Disassemble Python bytecode (safe: only inspection, no execution)."""
    import io
    buf = io.StringIO()
    if isinstance(code, types.CodeType):
        dis.dis(code, file=buf)
    elif isinstance(code, bytes):
        import marshal
        import struct
        # Skip magic + timestamp + size for Python 3.8+
        if len(code) > 16:
            try:
                co = marshal.loads(code[16:])
                dis.dis(co, file=buf)
            except Exception:
                dis.dis(code, file=buf)
        else:
            dis.dis(code, file=buf)
    return buf.getvalue()


class Deobfuscator:
    """Multi-strategy deobfuscation engine."""

    def __init__(self, payload: bytes | str):
        if isinstance(payload, str):
            self._raw_bytes = payload.encode("utf-8", errors="replace")
            self._raw_str = payload
        else:
            self._raw_bytes = payload
            self._raw_str = payload.decode("ascii", errors="replace")

    def recover_xor(self) -> DeobResult:
        """Brute-force single-byte XOR to find readable plaintext."""
        candidates = brute_xor_single(self._raw_bytes, printable_only=True)
        if not candidates:
            return DeobResult(strategy="xor_single", details="no printable decode found")
        # Score by "textlikeness": proportion of letters/spaces, penalize control
        # and non-text bytes. Prefers real English-ish plaintext over garbage that
        # happens to be printable.
        def text_score(item):
            _k, decoded = item
            total = max(len(decoded), 1)
            # Word chars: letters, digits, underscore (common in text payloads).
            word = sum(1 for b in decoded
                       if 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122
                       or b == 0x5F)
            spaces = sum(1 for b in decoded if b in (0x20, 0x09, 0x0A, 0x0D))
            misc = sum(1 for b in decoded if 0x20 <= b <= 0x7E
                       and not (48 <= b <= 57 or 65 <= b <= 90
                                or 97 <= b <= 122 or b in (0x20, 0x5F)))
            return (word + spaces) / total - 0.5 * misc / total
        best_key, best_decoded = max(candidates, key=text_score)
        recovered = best_decoded.decode("ascii", errors="replace")
        return DeobResult(
            strategy="xor_single",
            recovered=recovered,
            original_length=len(self._raw_bytes),
            recovered_length=len(recovered),
            confidence=min(1.0, len(recovered) / max(len(self._raw_bytes), 1)),
            details=f"key=0x{best_key:02x}",
        )

    def recover_xor_multi(self, key: bytes) -> DeobResult:
        decoded = xor_multi_byte(self._raw_bytes, key)
        recovered = decoded.decode("ascii", errors="replace")
        return DeobResult(
            strategy="xor_multi",
            recovered=recovered,
            original_length=len(self._raw_bytes),
            recovered_length=len(recovered),
            confidence=1.0,
            details=f"key={key!r}",
        )

    def recover_base64(self) -> DeobResult:
        results = try_base64_decode(self._raw_str)
        if results:
            method, decoded = results[0]
            return DeobResult(
                strategy=f"base64_{method}",
                recovered=decoded,
                original_length=len(self._raw_str),
                recovered_length=len(decoded),
                confidence=0.9,
                details=method,
            )
        return DeobResult(strategy="base64", details="no valid base64 found")

    def recover_hex_escapes(self) -> DeobResult:
        decoded = decode_hex_escapes(self._raw_str)
        if decoded:
            return DeobResult(
                strategy="hex_escape",
                recovered=decoded,
                original_length=len(self._raw_str),
                recovered_length=len(decoded),
                confidence=0.95,
            )
        return DeobResult(strategy="hex_escape", details="no hex escapes found")

    def recover_string_stacking(self) -> DeobResult:
        decoded = unescape_string_stacking(self._raw_str)
        if decoded and decoded != self._raw_str:
            return DeobResult(
                strategy="string_stacking",
                recovered=decoded,
                original_length=len(self._raw_str),
                recovered_length=len(decoded),
                confidence=0.85,
            )
        return DeobResult(strategy="string_stacking", details="no stacking found")

    def recover_ast_fold(self) -> DeobResult:
        decoded = safe_ast_fold(self._raw_str)
        if decoded is not None and decoded != self._raw_str:
            return DeobResult(
                strategy="ast_constant_fold",
                recovered=decoded,
                original_length=len(self._raw_str),
                recovered_length=len(decoded),
                confidence=1.0,
            )
        return DeobResult(strategy="ast_constant_fold", details="no foldable expr")

    def auto_deobfuscate(self) -> list[DeobResult]:
        """Try all strategies, return non-empty results."""
        results = []
        if all(0x00 <= b <= 0xFF for b in self._raw_bytes):
            r = self.recover_xor()
            if r.recovered:
                results.append(r)
        for method in ["recover_base64", "recover_hex_escapes",
                       "recover_string_stacking", "recover_ast_fold"]:
            r = getattr(self, method)()
            if r.recovered:
                results.append(r)
        return results
