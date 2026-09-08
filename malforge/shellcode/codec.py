"""Shellcode encoder/decoder.

Alphanumeric-ish XOR and ROT encoders with round-trip decode on fixture
arrays. No injection, no execution — purely data transformation.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field


@dataclass
class EncodeResult:
    encoder: str = ""
    encoded: bytes = b""
    key: int = 0
    roundtrip_ok: bool = False
    details: str = ""


class ShellcodeCodec:
    """Encode/decode shellcode byte arrays (no execution)."""

    def encode_xor(self, data: bytes, key: int | None = None) -> EncodeResult:
        """Single-byte XOR encode with random or specified key."""
        if key is None:
            key = secrets.randbelow(254) + 1  # avoid 0
        encoded = bytes(b ^ key for b in data)
        return EncodeResult(
            encoder="xor",
            encoded=encoded,
            key=key,
            roundtrip_ok=(self.decode_xor(encoded, key) == data),
            details=f"key=0x{key:02x}",
        )

    def decode_xor(self, data: bytes, key: int) -> bytes:
        return bytes(b ^ key for b in data)

    def encode_rot(self, data: bytes, rotation: int = 13) -> EncodeResult:
        """ROT-N encode (caesar cipher for bytes, mod 256)."""
        encoded = bytes((b + rotation) & 0xFF for b in data)
        return EncodeResult(
            encoder="rot",
            encoded=encoded,
            key=rotation,
            roundtrip_ok=(self.decode_rot(encoded, rotation) == data),
            details=f"rotation={rotation}",
        )

    def decode_rot(self, data: bytes, rotation: int = 13) -> bytes:
        return bytes((b - rotation) & 0xFF for b in data)

    def encode_multibyte_xor(self, data: bytes, key: bytes | None = None) -> EncodeResult:
        """Multi-byte XOR encode."""
        if key is None:
            key = secrets.token_bytes(4)
        encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return EncodeResult(
            encoder="multibyte_xor",
            encoded=encoded,
            roundtrip_ok=(self.decode_multibyte_xor(encoded, key) == data),
            details=f"key={key.hex()}",
        )

    def decode_multibyte_xor(self, data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def to_hex_literal(self, data: bytes) -> str:
        """Format bytes as C hex literal array."""
        parts = [f"0x{b:02x}" for b in data]
        lines = []
        for i in range(0, len(parts), 8):
            lines.append(",".join(parts[i:i+8]))
        return "{\n" + ",\n".join(lines) + "\n}"

    def from_hex_literal(self, text: str) -> bytes:
        """Parse C hex literal array back to bytes."""
        import re
        hexvals = re.findall(r"0x([0-9a-fA-F]{2})", text)
        return bytes(int(h, 16) for h in hexvals)

    def roundtrip_test(self, data: bytes) -> dict:
        """Test all encoders for round-trip correctness."""
        results = {}
        # XOR
        enc = self.encode_xor(data)
        dec = self.decode_xor(enc.encoded, enc.key)
        results["xor"] = dec == data
        # ROT
        enc = self.encode_rot(data)
        dec = self.decode_rot(enc.encoded, enc.key)
        results["rot"] = dec == data
        # Multi-byte XOR
        enc = self.encode_multibyte_xor(data)
        dec = self.decode_multibyte_xor(enc.encoded, bytes.fromhex(enc.details.split("=")[1]))
        results["multibyte_xor"] = dec == data
        return results
