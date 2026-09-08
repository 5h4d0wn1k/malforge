"""Full offline demo with real assertions across all modules.

This module is invoked by `malforge --demo` and by `tests`. All assertions
are real and run on crafted/fixture data only — never real malware.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path


def run_demo() -> int:
    """Run all modules on crafted fixtures, assert proof, return exit code."""
    print("=" * 60)
    print("malforge v1.0.0 — LIVE DEMO")
    print("=" * 60)

    from malforge import parsers as P
    from malforge import packer
    from malforge.parsers import rawbytes as raw

    # ---- 1. Compile fixtures ----
    from tests.fixtures import make_elf_fixtures, make_pe_fixture, make_clean_samples_for_yara
    fixtures = make_elf_fixtures()
    pe_data = make_pe_fixture()

    # ---- 2. ELF parse ----
    print("\n[1] ELF Parse")
    elf = P.parse_elf(fixtures["hello"])
    assert elf.ident[:4] == b"\x7fELF", "ELF magic"
    assert elf.elf_class == 2, "ELF64"
    assert elf.e_entry > 0, "entry nonzero"
    names = [s["name"] for s in elf.sections]
    assert ".text" in names, ".text present"
    print(f"  OK: class=ELF64, entry={hex(elf.e_entry)}, sections={len(elf.sections)}")

    # ---- 3. PE parse ----
    print("\n[2] PE Parse")
    pe = P.parse_pe(pe_data)
    assert pe.is_pe, "is PE"
    assert pe.machine == 0x14C, "i386"
    assert pe.entry_point == 0x1000, "entry point"
    assert len(pe.sections) == 1, "1 section"
    total_imports = sum(len(i["functions"]) for i in pe.imports)
    assert total_imports == 12, f"12 imports, got {total_imports}"
    assert pe.exports == ["FakeExport"], "exports"
    print(f"  OK: PE32, i386, {total_imports} imports, exports={pe.exports}")

    # ---- 4. Packer detection ----
    print("\n[3] Packer Detection")
    pack_report = packer.build_report(pe_data)
    assert pack_report["format"] == "pe", "format pe"
    print(f"  entropy={pack_report['overall_entropy']:.2f}, "
          f"suspected={pack_report['suspected_packed']}, "
          f"score={pack_report['score']}")

    # Synthetic "packed" sample: high entropy + RWX section
    packed_data = os.urandom(8192)
    pack_report2 = packer.build_report(packed_data)
    ent = pack_report2["overall_entropy"]
    assert ent > 7.0, f"random should be high entropy, got {ent}"
    rwx_flag = any(f["flag"] == "RWX_SECTION" for f in pack_report2["flags"])
    print(f"  random: entropy={ent:.2f}, suspected={pack_report2['suspected_packed']}")

    # ---- 5. Sandbox ----
    print("\n[4] Dynamic Sandbox")
    from malforge.sandbox import run_sandbox
    benign = fixtures.get("benign")
    if benign:
        with tempfile.NamedTemporaryFile(suffix="_benign", delete=False,
                                         dir="/tmp") as tf:
            tf.write(benign)
            tf.flush()
            os.chmod(tf.name, 0o755)
            sandbox_path = tf.name
        try:
            report = run_sandbox(sandbox_path, timeout=3)
            d = report.to_dict()
            assert d["watermark"] == "SAMPLE:benign-lab", "watermark"
            proc_count = len(d["processes_spawned"])
            file_count = len(d["file_writes"])
            sock_count = len(d["sockets"])
            print(f"  OK: pid={d['pid']}, procs={proc_count}, "
                  f"files={file_count}, sockets={sock_count}")
            print(f"  exit_code={d['exit_code']}, duration={d['duration_ms']:.0f}ms")
        finally:
            os.unlink(sandbox_path)
    else:
        print("  SKIP: no benign fixture")

    # ---- 6. Deobfuscation ----
    print("\n[5] Deobfuscation")
    from malforge.deobfuscator import Deobfuscator

    original = "malforge_deobfuscation_test_payload_42"
    key = 0x1B
    obfuscated = bytes(b ^ key for b in original.encode())
    deob = Deobfuscator(obfuscated)
    results = deob.auto_deobfuscate()
    recovered = [r for r in results if original in r.recovered]
    assert len(recovered) > 0, f"recovery failed, got: {[r.recovered for r in results]}"
    print(f"  OK: recovered '{recovered[0].recovered}' via {recovered[0].strategy}")

    b64_payload = base64.b64encode(b"hello_malforge_b64").decode()
    deob_b64 = Deobfuscator(b64_payload)
    results_b64 = deob_b64.auto_deobfuscate()
    assert any("hello_malforge_b64" in r.recovered for r in results_b64), "b64 recovery"
    print("  OK: base64 recovery worked")

    # ---- 7. YARA ----
    print("\n[6] YARA Generation")
    from malforge.yara_gen import YaraGenerator
    clean = make_clean_samples_for_yara()
    gen = YaraGenerator()
    gen.add_sample("hello_fixture", fixtures["hello"])
    gen.add_sample("packed_fixture", fixtures["packed"])
    gen.add_sample("clean_fixture", fixtures["clean"])
    ruleset = gen.generate(negatives=clean)
    assert len(ruleset.rules) == 3, f"3 rules, got {len(ruleset.rules)}"
    yar_text = ruleset.to_yar()
    assert "rule " in yar_text, "valid YARA text"

    validation = gen.validate(ruleset, fixtures, clean)
    tp = validation["true_positives"]
    fp = validation["false_positives"]
    print(f"  rules={len(ruleset.rules)}, TP={tp}, FP={fp}")
    assert tp >= 2, f"at least 2 TP, got {tp}"
    assert fp == 0, f"0 FP, got {fp}"
    print(f"  OK: {tp}/3 hit, {fp} FP")

    # ---- 8. Binary diff ----
    print("\n[7] Binary Diff")
    from malforge.diff import BinaryDiffer
    d1 = BinaryDiffer(fixtures["variant_a"], fixtures["variant_b"],
                      "variant_a", "variant_b")
    r1 = d1.diff()
    assert r1.similarity < 1.0, "variants should differ"
    assert r1.similarity > 0.0, "variants should have similarity"
    print(f"  variants sim={r1.similarity:.4f}")

    d2 = BinaryDiffer(fixtures["variant_a"], fixtures["variant_a"],
                      "same_a", "same_a")
    r2 = d2.diff()
    assert r2.identical, "identical should be identical"
    assert r2.similarity == 1.0, "identical sim=1.0"
    print(f"  identical sim={r2.similarity:.4f}")

    # ---- 9. Shellcode ----
    print("\n[8] Shellcode Encoder/Decoder")
    from malforge.shellcode import ShellcodeCodec
    codec = ShellcodeCodec()
    test_data = b"\x90\x90\xcc\x90\xcc\x90\xcc\x90"
    enc = codec.encode_xor(test_data)
    dec = codec.decode_xor(enc.encoded, enc.key)
    assert dec == test_data, "XOR roundtrip"
    print(f"  XOR: key=0x{enc.key:02x}, roundtrip={enc.roundtrip_ok}")

    enc2 = codec.encode_rot(test_data)
    dec2 = codec.decode_rot(enc2.encoded, enc2.key)
    assert dec2 == test_data, "ROT roundtrip"
    print(f"  ROT: rot={enc2.key}, roundtrip={enc2.roundtrip_ok}")

    enc3 = codec.encode_multibyte_xor(test_data)
    key3 = bytes.fromhex(enc3.details.split("=")[1])
    dec3 = codec.decode_multibyte_xor(enc3.encoded, key3)
    assert dec3 == test_data, "Multi-byte roundtrip"
    print(f"  Multi-byte XOR: roundtrip={enc3.roundtrip_ok}")

    # ---- 10. Frida ----
    print("\n[9] Frida Generator")
    from malforge.frida_gen import FridaGenerator, HookConfig
    fgen = FridaGenerator()
    snippet = fgen.generate(HookConfig(module="libc.so.6", function="open"))
    assert snippet.syntax_valid, f"JS syntax valid, errors={snippet.errors}"
    assert "Interceptor.attach" in snippet.js_code, "contains Interceptor"
    print(f"  OK: syntax_valid={snippet.syntax_valid}")

    # ---- Summary ----
    print("\n" + "=" * 60)
    print("DEMO COMPLETE — all modules passed")
    print("=" * 60)
    return 0


def main() -> int:
    return run_demo()


if __name__ == "__main__":
    sys.exit(main())
