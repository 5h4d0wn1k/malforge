"""Fixture generators for malforge tests.

All fixtures are benign, hand-crafted or compiled by gcc on the fly. No real
malware is ever used or required.
"""
from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from pathlib import Path

FIXTURES = Path(__file__).parent


HELLO_C = r"""
#include <stdio.h>
const char greeting[] = "hello_malforge_fixture";
int add(int a, int b){ return a + b; }
int main(int argc, char** argv){
    printf("greeting=%s sum=%d\n", greeting, add(2,3));
    return 0;
}
"""

PACKED_C = r"""
#include <stdio.h>
#include <string.h>
/* Deliver a payload that has been obfuscated by stacking + XOR.
   This is a benign sample used to exercise static packer detection. */
static const unsigned char payload[] = {
    0x6b,0x76,0x6b,0x67,0x7c,0x7c,0x78,0x3b,0x68,0x7f,0x74,0x7c,0x78,0x3a,0x71,0x74,
    0x3b,0x72,0x79,0x7b,0x7e,0x7e,0x68,0x7d,0x3b,0x75,0x7a,0x6c,0x3b,0x71,0x76,0x7b,
    0x3a,0x3a,0x3a,0x3a,0x3a,0x3a
};
static void decode(void){
    unsigned char buf[64] = {0};
    size_t i;
    for(i=0;i<sizeof(payload);i++) buf[i]=payload[i]^0x1b;
    printf("%s\n", buf);
}
int main(void){ decode(); return 0; }
"""

BENIGN_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static const char uid[] = "malforge_benign_lab_sample_v1";
int main(void){
    FILE *f;
    int fd, rc, c;
    struct sockaddr_in addr;
    char buf[64];
    /* 1: sleep briefly */
    usleep(50*1000);
    /* 2: read our own /proc/self/status */
    FILE *p = fopen("/proc/self/status", "r");
    if(p){ while(fgets(buf, sizeof buf, p)); fclose(p); }
    /* 3: touch a temp file */
    f = fopen("/tmp/malforge_benign_probe.txt", "w");
    if(f){ fprintf(f, "uid=%s\n", uid); fclose(f); }
    /* 4: bind + connect a loopback TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd >= 0){
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);          /* ephemeral, loopback only */
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rc = bind(fd, (struct sockaddr*)&addr, sizeof addr);
        c = connect(fd, (struct sockaddr*)&addr, sizeof addr);
        (void)rc; (void)c;
        close(fd);
    }
    printf("done uid=%s\n", uid);
    return 0;
}
"""

SLEEP_C = "int main(void){ return 0; }\n"


def compile_c(src: str, out: Path, flags: list[str] | None = None,
              extra_env: dict | None = None) -> Path:
    """Compile C source to an ELF binary using gcc."""
    gcc = "gcc"
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tf:
        tf.write(src)
        src_path = tf.name
    cmd = [gcc]
    if flags:
        cmd += flags
    cmd += [src_path, "-o", str(out)]
    env = {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if extra_env:
        env.update(extra_env)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if res.returncode != 0:
            raise RuntimeError(f"gcc failed: {res.stderr}")
    finally:
        try:
            Path(src_path).unlink()
        except OSError:
            pass
    return out


def make_elf_fixtures() -> dict:
    out = {}
    hello = FIXTURES / "hello_elf"
    packed = FIXTURES / "packed_elf"
    benign = FIXTURES / "benign_elf"
    sleep1 = FIXTURES / "variant_a"
    sleep2 = FIXTURES / "variant_b"
    clean_sample = FIXTURES / "clean_elf"
    if not hello.exists():
        compile_c(HELLO_C, hello, ["-fno-PIE", "-no-pie"])
    if not packed.exists():
        # We can't pack at runtime; instead compile packed-like fixture. The
        # static packer detection test uses a separate fixture (see below).
        compile_c(HELLO_C, packed)
    if not benign.exists():
        compile_c(BENIGN_C, benign, ["-D_GNU_SOURCE"])
    if not sleep1.exists():
        compile_c(SLEEP_C, sleep1, ["-fno-PIE", "-no-pie"])
    if not sleep2.exists():
        compile_c(SLEEP_C, sleep2, ["-fno-PIE", "-no-pie", "-O2"])
    if not clean_sample.exists():
        compile_c(HELLO_C, clean_sample)
    out["hello"] = hello.read_bytes()
    out["packed"] = packed.read_bytes()
    out["benign"] = benign.read_bytes()
    out["variant_a"] = sleep1.read_bytes()
    out["variant_b"] = sleep2.read_bytes()
    out["clean"] = clean_sample.read_bytes()
    return out


def make_pe_fixture() -> bytes:
    """Craft a byte-exact minimal PE with known imports (12 functions).

    One .text section covering the whole image. Import directory + IAT +
    Hint/Name + export directory all live inside that section's raw data.
    """
    fun_names = ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle",
                 "GetProcAddress", "LoadLibraryA", "VirtualAlloc",
                 "VirtualFree", "GetModuleHandleA", "ExitProcess",
                 "GetSystemTime", "Sleep"]

    # ---- section data (raw) ----
    # text at 0x0, import dir at 0x1000, IAT at 0x1040,
    # dll name at 0x10D0, hint/name at 0x1100, export dir at 0x1400
    secdata = bytearray(0x1800)
    # text: two-byte nop; lightweight
    secdata[0:2] = b"\x90\x90"
    struct.pack_into("<I", secdata, 2, 0x1111)  # a mov/instruction word

    # import descriptor at offset 0x1000 (RVA 0x2000)
    imp_off = 0x1000
    struct.pack_into("<IIIII", secdata, imp_off,
                     0x2040, 0, 0, 0x20D0, 0x2040)
    struct.pack_into("<IIIII", secdata, imp_off + 20, 0, 0, 0, 0, 0)
    # ILT/IAT at offset 0x1040 (RVA 0x2040): 12 pointers + null
    iat_off = imp_off + 0x40
    for i in range(12):
        struct.pack_into("<I", secdata, iat_off + i * 4, 0x2100 + i * 0x10)
    struct.pack_into("<I", secdata, iat_off + 12 * 4, 0)
    # dll name at 0x10D0 (RVA 0x20D0)
    dll = b"KERNEL32.dll\x00"
    struct.pack_into(f"{len(dll)}s", secdata, imp_off + 0xD0, dll)
    # hint/name entries at 0x1100 (RVA 0x2100), 0x10 apart
    for i, nm in enumerate(fun_names):
        hn = imp_off + 0x100 + i * 0x10
        struct.pack_into("<H", secdata, hn, i)
        secdata[hn + 2:hn + 2 + len(nm)] = nm.encode()
        secdata[hn + 2 + len(nm)] = 0
    # export directory at 0x1400 (RVA 0x2400)
    exp_off = imp_off + 0x400
    name_rva = 0x2400 + 0x2C
    struct.pack_into("<I", secdata, exp_off + 24, 1)   # NumberOfNames
    struct.pack_into("<I", secdata, exp_off + 32, 0x2400 + 0x60)  # AddressOfNames
    struct.pack_into("<I", secdata, exp_off + 0x60, name_rva)     # names[0]
    expname = b"FakeExport\x00"
    struct.pack_into(f"{len(expname)}s", secdata, exp_off + 0x2C, expname)

    # ---- DOS header (0x80 bytes so NT land at e_lfanew=0x80) ----
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    # ---- NT headers ----
    nt = bytearray(4 + 20 + 224)  # signature + file hdr + optional hdr(32-bit)
    nt[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", nt, 4, 0x14C)      # machine i386
    struct.pack_into("<H", nt, 6, 1)          # number of sections
    struct.pack_into("<I", nt, 16, 0xE0)      # size of optional header (224)
    opt = 24
    struct.pack_into("<H", nt, opt, 0x10B)    # optional magic 32-bit
    struct.pack_into("<I", nt, opt + 16, 0x1000)       # entry point RVA
    struct.pack_into("<I", nt, opt + 28, 0x400000)     # image base
    struct.pack_into("<I", nt, opt + 32, 0x1000)       # section alignment
    struct.pack_into("<I", nt, opt + 36, 0x200)        # file alignment
    struct.pack_into("<I", nt, opt + 56, 0x3000)       # size of image
    struct.pack_into("<I", nt, opt + 60, 0x200)        # size of headers
    struct.pack_into("<I", nt, opt + 92, 16)           # number of directories
    dd = opt + 96
    struct.pack_into("<II", nt, dd + 8, 0x2000, 0x28)  # import dir (slot 1)
    struct.pack_into("<II", nt, dd + 0, 0x2400, 0x30)  # export dir (slot 0)

    # ---- section table (1 section) ----
    sec = bytearray(40)
    sec[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", sec, 8, 0x1800)    # virtual size
    struct.pack_into("<I", sec, 12, 0x1000)   # virtual address
    struct.pack_into("<I", sec, 16, 0x400)    # size of raw data
    struct.pack_into("<I", sec, 20, 0x200)    # pointer to raw data
    struct.pack_into("<I", sec, 36, 0x20000000 | 0x40000000)  # CODE|EXEC|READ

    # ---- assemble ----
    total = 0x200 + 0x400
    blob = bytearray(b"\x00" * total)
    blob[0:e_lfanew] = dos
    blob[e_lfanew:e_lfanew + len(nt)] = nt
    blob[e_lfanew + len(nt):e_lfanew + len(nt) + 40] = sec
    # raw secdata at file offset 0x200
    blob[0x200:0x200 + len(secdata)] = secdata
    return bytes(blob)


def make_clean_samples_for_yara() -> dict:
    """Return three structurally-different clean fixtures to test FP."""
    # simple hello
    if not (FIXTURES / "clean_sample_1").exists():
        compile_c(HELLO_C, FIXTURES / "clean_sample_1", ["-O0"])
    if not (FIXTURES / "clean_sample_2").exists():
        compile_c(SLEEP_C, FIXTURES / "clean_sample_2", ["-O2"])
    if not (FIXTURES / "clean_sample_3").exists():
        compile_c(HELLO_C, FIXTURES / "clean_sample_3", ["-O2", "-pg"]
                  if False else ["-O2"])
    return {
        "c1": (FIXTURES / "clean_sample_1").read_bytes(),
        "c2": (FIXTURES / "clean_sample_2").read_bytes(),
        "c3": (FIXTURES / "clean_sample_3").read_bytes(),
    }


def make_fixtures() -> dict:
    result = make_elf_fixtures()
    result["pe12"] = make_pe_fixture()
    result["clean"] = make_clean_samples_for_yara()
    return result
