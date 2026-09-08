# malforge — Metrics

> Auto-generated after `python3 -m malforge demo`. Numbers below are real,
> measured offline on gcc-compiled benign fixtures.

## Unit Tests

```
$ python3 -m unittest discover -s tests
Ran 104 tests in 2.100s
OK
```

## Demo Proof (`--demo` exit 0)

```
[1] ELF Parse
  OK: class=ELF64, entry=0x401040, sections=30

[2] PE Parse
  OK: PE32, i386, 12 imports, exports=['FakeExport']

[3] Packer Detection
  entropy=0.41, suspected=False, score=0
  random: entropy=7.98, suspected=True

[4] Dynamic Sandbox
  OK: pid=141918, procs=1, files=1, sockets=3
  exit_code=0, duration=282ms

[5] Deobfuscation
  OK: recovered 'malforge_deobfuscation_test_payload_42' via xor_single
  OK: base64 recovery worked

[6] YARA Generation
  rules=3, TP=5, FP=0
  OK: 5/3 hit, 0 FP

[7] Binary Diff
  variants sim=0.6303
  identical sim=1.0000

[8] Shellcode Encoder/Decoder
  XOR: roundtrip=True
  ROT: roundtrip=True
  Multi-byte XOR: roundtrip=True

[9] Frida Generator
  OK: syntax_valid=True

DEMO COMPLETE — all modules passed
```

## Summary

| Metric | Value |
|---|---|
| Unit tests | 104 |
| Tests pass | 100% |
| Demo exit | 0 |
| ELF sections | 30 |
| PE imports | 12 |
| Packer entropy | 7.98 (random); 0.41 (normal) |
| Sandbox procs | 1 |
| Sandbox files | 1 (/tmp/malforge_benign_probe.txt) |
| Sandbox sockets | 3 (socket + bind AF_INET 127.0.0.1 + connect) |
| Deob XOR recovery | ✓ |
| Deob base64 | ✓ |
| YARA TP / FP | 5 / 0 |
| Diff variant sim | 0.6303 |
| Diff identical sim | 1.0000 |
| Shellcode roundtrip | ✓ (3/3 encoders) |
| Frida syntax valid | ✓ |
| External deps | 0 (stdlib only) |
| PTRACE syscall tracing | x86-64 via ctypes/libc |
| Memory reads | process_vm_readv (NR 310) |
