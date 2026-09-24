#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael Loomis
# kiteshear_unpack.py
#
# Standalone Kiteshield unpacker. Produces an original, loadable ELF plus a
# forensic key/metadata log, an IOC bundle, and a YARA rule -- no Ghidra needed.
# This is the "skip Ghidra and produce the original ELF" path.
#
# Usage:
#   python3 kiteshear_unpack.py packed.ks
#   python3 kiteshear_unpack.py packed.ks -o out.elf --json keys.json --ioc iocs.txt
#   python3 kiteshear_unpack.py packed.ks --layer1-only     # stop after outer layer
#
# The unpacked ELF is byte-for-byte loadable in Ghidra / IDA / objdump / gdb and
# retains the original section headers, so every recovered function is analyzable
# whether or not it ever executes.

import argparse
import json
import os
import sys

import kiteshear_core as ks


def build_iocs(log):
    lines = []
    lines.append("# Kiteshear unpack IOCs")
    lines.append("packed_sha256=%s" % log.get("packed_sha256"))
    lines.append("unpacked_sha256=%s" % log.get("unpacked_sha256"))
    # The outer effective RC4 key is unique per sample and survives across the
    # packed/unpacked pair -> a strong hunting pivot.
    lines.append("outer_rc4_key_effective=%s" % log.get("layer1_key_effective"))
    lines.append("outer_rc4_key_raw=%s" % log.get("layer1_key_raw"))
    if log.get("layer2_applied"):
        lines.append("encrypted_function_count=%d" % log.get("nfuncs", 0))
        for f in log.get("functions", []):
            lines.append("func_key id=%d vaddr=%s len=%d key=%s"
                         % (f["id"], f["vaddr"], f["len"], f["key"]))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Static unpacker for Kiteshield-packed ELF binaries")
    ap.add_argument("packed")
    ap.add_argument("-o", "--out", help="unpacked ELF output (default: <packed>.unpacked.elf)")
    ap.add_argument("--json", help="write full key/metadata log as JSON")
    ap.add_argument("--ioc", help="write IOC bundle")
    ap.add_argument("--yara", help="write YARA detection rule")
    ap.add_argument("--layer1-only", action="store_true", help="stop after outer RC4 layer")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    data = open(args.packed, "rb").read()
    try:
        out, log = ks.unpack(data, want_layer2=not args.layer1_only)
    except Exception as e:
        print("[!] unpack failed: %s" % e, file=sys.stderr)
        print("[*] Try the dynamic path (kiteshear_frida.js) for hardened variants.",
              file=sys.stderr)
        sys.exit(2)

    out_path = args.out or (args.packed + ".unpacked.elf")
    open(out_path, "wb").write(out)

    json_path = args.json or (args.packed + ".keys.json")
    open(json_path, "w").write(json.dumps(log, indent=2))

    ioc_path = args.ioc or (args.packed + ".iocs.txt")
    open(ioc_path, "w").write(build_iocs(log))

    if args.yara:
        open(args.yara, "w").write(ks.YARA_RULE)

    if not args.quiet:
        print("[+] class           : %s / %s" % (log.get("ei_class"), log.get("e_type")))
        print("[+] outer key (raw) : %s" % log.get("layer1_key_raw"))
        print("[+] outer key (eff) : %s" % log.get("layer1_key_effective"))
        if log.get("layer2_applied"):
            print("[+] layer 2         : %d funcs decrypted, %d trap bytes restored"
                  % (log.get("nfuncs", 0), log.get("traps_restored", 0)))
        else:
            print("[+] layer 2         : not present (layer-1-only / -n) or dynamic needed")
        ad = log.get("antidebug_strings", {})
        if ad:
            print("[+] anti-debug      : " + ", ".join(sorted(ad.keys())))
        print("[+] unpacked ELF    : %s (%d bytes, sha256 %s)"
              % (out_path, log.get("unpacked_size"), log.get("unpacked_sha256")))
        print("[+] keys/metadata   : %s" % json_path)
        print("[+] IOCs            : %s" % ioc_path)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
