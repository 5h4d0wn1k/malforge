"""malforge CLI — unified entry point for all analysis modules."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__


def cmd_parse(args):
    from . import parsers as P
    from .parsers import rawbytes as raw

    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    data = path.read_bytes()
    fmt = args.format or P.identify(data)

    if fmt == "elf":
        f = P.parse_elf(data)
        result = {
            "format": "elf",
            "class": "ELF64" if f.elf_class == 2 else "ELF32",
            "endian": "little" if f.data_encoding == 1 else "big",
            "machine": f.e_machine,
            "entry": hex(f.e_entry),
            "sections": [{"name": s["name"], "size": s["size"],
                          "entropy": s["entropy"]} for s in f.sections],
            "symbols": [s["name"] for s in f.symbols[:20]],
            "dynamic_imports": [s["name"] for s in f.dynamic_imports],
            "strings_count": len(f.strings),
            "is_pie": f.is_pie,
        }
    elif fmt == "pe":
        f = P.parse_pe(data)
        result = {
            "format": "pe",
            "is_32bit": f.is_32bit,
            "machine": hex(f.machine),
            "entry_point": hex(f.entry_point),
            "image_base": hex(f.image_base),
            "sections": [{"name": s["name"], "raw_size": s["raw_size"],
                          "entropy": s["entropy"], "rwx": s["rwx"]}
                         for s in f.sections],
            "imports": [{"dll": i["dll"], "count": len(i["functions"])}
                        for i in f.imports],
            "exports": f.exports,
            "aslr": f.aslr,
            "dep": f.dep,
        }
    elif fmt == "macho":
        f = P.parse_macho(data)
        result = {
            "format": "macho",
            "is_64bit": f.is_64bit,
            "is_big_endian": f.is_big_endian,
            "filetype": f.filetype_name,
            "load_commands": len(f.load_commands),
            "symbols": [s["name"] for s in f.symbols[:20]],
            "dynamic_info": f.dynamic_info,
        }
    else:
        ent = raw.entropy(data)
        result = {
            "format": "raw",
            "size": len(data),
            "entropy": round(ent, 3),
            "strings": [(o, s) for o, s in raw.extract_strings(data, min_len=5)[:20]],
        }

    print(json.dumps(result, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))
    return 0


def cmd_pack(args):
    from . import packer
    data = Path(args.file).read_bytes()
    report = packer.build_report(data)
    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    return 0


def cmd_sandbox(args):
    from .sandbox import run_sandbox, save_report
    report = run_sandbox(args.binary, timeout=args.timeout)
    print(report.to_json())
    if args.output:
        save_report(report, args.output)
    return 0


def cmd_deob(args):
    from .deobfuscator import Deobfuscator
    data = args.payload
    if args.file:
        data = Path(args.file).read_bytes()
    elif data.startswith("\\x") or all(c in "0123456789abcdefABCDEFx\\," for c in data):
        import re
        hexvals = re.findall(r"[0-9a-fA-F]{2}", data.replace("\\x", ""))
        if hexvals:
            data = bytes(int(h, 16) for h in hexvals)

    if isinstance(data, str):
        deob = Deobfuscator(data)
    else:
        deob = Deobfuscator(data)

    results = deob.auto_deobfuscate()
    output = [r.__dict__ for r in results]
    print(json.dumps(output, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2))
    return 0


def cmd_yara(args):
    from .yara_gen import YaraGenerator
    gen = YaraGenerator()
    for f in args.samples:
        gen.add_sample(Path(f).name, Path(f).read_bytes())
    ruleset = gen.generate()
    print(ruleset.to_yar())
    if args.output:
        gen.save_rules(ruleset, args.output)
    return 0


def cmd_diff(args):
    from .diff import diff_files
    report = diff_files(args.file_a, args.file_b)
    print(json.dumps(report.to_dict(), indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2))
    return 0


def cmd_sck(args):
    from .shellcode import ShellcodeCodec
    codec = ShellcodeCodec()
    if args.decode:
        data = bytes.fromhex(args.data)
        result = codec.decode_xor(data, args.key)
        print(result.hex())
    else:
        data = bytes.fromhex(args.data)
        enc = codec.encode_xor(data, key=args.key if args.key else None)
        print(json.dumps({
            "encoder": enc.encoder,
            "encoded_hex": enc.encoded.hex(),
            "key": enc.key,
            "roundtrip_ok": enc.roundtrip_ok,
        }, indent=2))
    return 0


def cmd_fr(args):
    from .frida_gen import FridaGenerator, HookConfig
    gen = FridaGenerator()
    configs = []
    if args.config:
        cfgs = json.loads(Path(args.config).read_text())
        for c in cfgs:
            configs.append(HookConfig(**c))
    else:
        configs.append(HookConfig(
            module=args.module or "libc.so.6",
            function=args.function or "open",
            action=args.action or "log",
        ))
    snippets = gen.generate_batch(configs)
    for s in snippets:
        print(s.js_code)
        print()
    return 0


def cmd_report(args):
    from . import parsers as P
    from . import packer
    from .deobfuscator import Deobfuscator
    from .diff import diff_files

    report = {"version": __version__, "modules": {}}

    if args.file:
        data = Path(args.file).read_bytes()
        fmt = P.identify(data)
        report["modules"]["parse"] = {"format": fmt}
        report["modules"]["packer"] = packer.build_report(data)

    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2))
    return 0


def cmd_demo(_args):
    """Run the full demo: all modules with real assertions."""
    import tests.test_all as demo
    return demo.run_demo()


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="malforge",
        description="Malware analysis & RE workstation v" + __version__,
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # parse
    p = sub.add_parser("parse", help="Static parse ELF/PE/Mach-O/raw")
    p.add_argument("file")
    p.add_argument("-f", "--format", choices=["elf", "pe", "macho", "raw"])
    p.add_argument("-o", "--output")

    # pack
    p = sub.add_parser("pack", help="Packer detection")
    p.add_argument("file")
    p.add_argument("-o", "--output")

    # sandbox
    p = sub.add_parser("sandbox", help="Dynamic sandbox")
    p.add_argument("binary")
    p.add_argument("-t", "--timeout", type=int, default=5)
    p.add_argument("-o", "--output")

    # deob
    p = sub.add_parser("deob", help="Deobfuscation")
    p.add_argument("payload", nargs="?", default="")
    p.add_argument("--file")
    p.add_argument("-o", "--output")

    # yara
    p = sub.add_parser("yara", help="YARA rule generation")
    p.add_argument("samples", nargs="+")
    p.add_argument("-o", "--output")

    # diff
    p = sub.add_parser("diff", help="Binary diff")
    p.add_argument("file_a")
    p.add_argument("file_b")
    p.add_argument("-o", "--output")

    # sck
    p = sub.add_parser("sck", help="Shellcode encode/decode")
    p.add_argument("data")
    p.add_argument("-k", "--key", type=int)
    p.add_argument("-d", "--decode", action="store_true")

    # fr
    p = sub.add_parser("fr", help="Frida snippet generation")
    p.add_argument("--config")
    p.add_argument("--module")
    p.add_argument("--function")
    p.add_argument("--action", default="log")

    # report
    p = sub.add_parser("report", help="Full analysis report")
    p.add_argument("--file")
    p.add_argument("-o", "--output")

    # demo
    sub.add_parser("demo", help="Run offline demo with assertions")

    args = parser.parse_args(argv)
    cmd_map = {
        "parse": cmd_parse, "pack": cmd_pack, "sandbox": cmd_sandbox,
        "deob": cmd_deob, "yara": cmd_yara, "diff": cmd_diff,
        "sck": cmd_sck, "fr": cmd_fr, "report": cmd_report,
        "demo": cmd_demo,
    }
    return cmd_map[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
