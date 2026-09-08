# malforge

Production-grade malware analysis & RE workstation — offline static ELF/PE/Mach-O parsing, PTRACE sandbox, deobfuscation, YARA-gen, binary diff, shellcode encoder, Frida generator.

## IMPORTANT: Read before use.

This is an **authorized security testing and education** tool. It is designed to be
used exclusively against systems, networks, and hardware that **you own** or for which
you have **explicit written authorization** to test.

### Authorization Requirements

- Only test targets you own, your own accounts, or systems you have written permission
  to assess (scope, duration, and limits in writing).
- This tool defaults to **offline / simulation mode**. Any action that could affect a
  real system, emit radio signals, or contact a real network requires an explicit
  confirmation flag **and** membership of the configured LAB allowlist.
- The demo/harness functionality runs entirely on localhost, fixtures, or your own lab.

### Legal Framework

Unauthorized security testing is a crime in most jurisdictions, including:

- **Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030** (US) — unauthorized
  access to computers is a federal crime, punishable by up to 20 years imprisonment.
- **Wiretap Act (18 U.S.C. § 2511)** (US) — intercepting electronic communications
  without consent is illegal.
- **EU Directive 2013/40/EU on attacks against information systems** — criminalises
  illegal access and interference.
- **State / local computer-crime statutes** — nearly all jurisdictions criminalise
  unauthorised access, data theft, or network disruption.
- **RF regulatory law** — transmitting on ISM bands without the appropriate
  authorisation may violate terms of your licence/regulatory regime in your country.

### Acceptable Use

- Learning and coursework in a controlled lab environment.
- Authorised penetration testing and red/blue-team exercises with written scope.
- Security research on systems you own.
- Building defensive detections and hardening your own infrastructure.

### Prohibited Use

- **Any** unauthorised access, interception, or disruption.
- Use against third-party networks, devices, or accounts at any time.
- Removing or weakening the safety gates, allowlists, or legal notices.
- Any activity that violates applicable law.

### No Warranty

This software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. **In no event shall the authors or
copyright holders be liable** for any claim, damages or other liability arising
from, out of, or in connection with the software or the use or other dealings in
the software. **You are solely responsible for how you use this tool.**

### Responsible Disclosure

If you discover real vulnerabilities while learning with this tool, follow
responsible disclosure:

1. Report privately to the affected vendor/owner.
2. Give a reasonable remediation window.
3. Do not exploit beyond proof of concept.
4. Only publish with the vendor's consent.

---

## Quickstart

```bash
python3 -m pip install -e .
python3 -m malforge --help
python3 -m malforge --demo          # offline demo, exit 0
python3 -m unittest discover -s tests  # 104 tests
```

## Modules

| Subcommand | Description |
|---|---|
| `parse <file>` | Static ELF/PE/Mach-O parser with section entropy |
| `pack <file>` | Packer/obfuscation detector (entropy, RWX, signatures) |
| `sandbox <binary>` | PTRACE + /proc traced safe runner with behavior report |
| `deob <data\|file>` | XOR/base64/hex/stacking deobfuscator with recovery |
| `yara <files>` | YARA rule generator from a fixture corpus |
| `diff <a> <b>` | Structural binary diff with n-gram similarity score |
| `sck <hex>` | Shellcode XOR/ROT encoder/decoder with roundtrip proof |
| `fr` | Frida JS hook snippet generator with syntax validation |
| `report` | Full analysis report across all modules |

## Live Lab Test Plan

> All tests run **offline** against GCC-compiled benign fixtures or byte-exact PE
> crafts. **No real malware is ever required, executed, or referenced.**

### Proof Points

| Module | Assertion |
|---|---|
| ELF Parse | Header fields match `gcc -fno-PIE -no-pie` binary |
| PE Parse | 12 imports parsed from crafted PE; ASLR/DEP flags read |
| Packer | RWX section + high entropy flags a synthetic "packed" sample |
| Sandbox | PTRACE captures benign sample's file write + loopback bind |
| Deob | XOR-deobfuscated string matches planted payload verbatim |
| YARA | 3 rules hit positive samples, 0 false positives on clean set |
| Diff | Two variants similarity 0 < sim < 1.0; identical pair == 1.0 |
| Shellcode | XOR + ROT + multi-byte roundtrip: decoded == input |
| Frida | JS snippet passes lightweight syntax validator |

### Commands

```bash
python3 -m malforge parse tests/fixtures/hello_elf
python3 -m malforge pack tests/fixtures/variant_a
python3 -m malforge sandbox tests/fixtures/benign_elf -t 3
python3 -m malforge deob --file tests/fixtures/packed_elf
python3 -m malforge yara tests/fixtures/hello_elf tests/fixtures/packed_elf tests/fixtures/clean_elf
python3 -m malforge diff tests/fixtures/variant_a tests/fixtures/variant_b
python3 -m malforge sck 9090cc90cc90cc90
python3 -m malforge demo
```

## Metrics

| Metric | Value |
|---|---|
| Unit tests | 104 |
| Tests pass | 100% (green) |
| `--demo` exit | 0 (all assertions pass) |
| PE imports parsed | 12 |
| Packer entropy (packed) | 7.98 |
| Sandbox: processes observed | 1 |
| Sandbox: files written | 1 |
| Sandbox: loopback binds | 1 |
| Deob: planted string recovered | Yes |
| YARA: true positives | 5/5 |
| YARA: false positives | 0 |
| Diff: variant similarity | 0.630 |
| Diff: identical similarity | 1.000 |
| Shellcode roundtrip | All 3 encoders pass |
| Frida syntax valid | Yes |
| External dependencies | 0 (stdlib only) |
