#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael Loomis
# run_frida_dump.py
#
# Takes the layer-1 image dumped by kiteshear_frida.js (/tmp/ks_layer1.bin) and
# finishes the job: it locates the ELF inside the raw memory dump, then applies
# layer-2 decryption using runtime_info parsed from the ORIGINAL packed loader
# (still the most reliable source of per-function keys) -- giving full function
# coverage even for samples where the static outer layer defeated us.
#
# Usage:
#   python3 run_frida_dump.py --packed packed.ks --dump /tmp/ks_layer1.bin -o out.elf
#
# If the packed loader's runtime_info is also unreadable, you still get the
# layer-1 ELF (all non-encrypted code + data), which is usually enough to
# triage, hash, and generate IOCs.

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kiteshear_core as ks


def carve_elf(dump):
    """The layer-1 image is mapped page-aligned at the base; the ELF header sits
    at the start of the first LOAD. Find the ELF magic and validate phdrs."""
    i = dump.find(b"\x7fELF")
    while i != -1:
        try:
            elf = ks.Elf(dump[i:])
            if elf.e_phnum and elf.loads():
                return dump[i:], i
        except Exception:
            pass
        i = dump.find(b"\x7fELF", i + 4)
    raise ValueError("no ELF found in dump")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packed", required=True, help="original packed file (for runtime_info)")
    ap.add_argument("--dump", required=True, help="layer-1 memory dump from Frida/Qiling")
    ap.add_argument("-o", "--out")
    ap.add_argument("--json")
    args = ap.parse_args()

    dump = open(args.dump, "rb").read()
    layer1, off = carve_elf(dump)
    log = dict(source="dynamic-dump", dump_elf_offset=hex(off),
               layer1_sha256=ks.sha256(layer1))

    result = layer1
    # Recover per-function keys from the packed loader and finish layer 2.
    try:
        packed = open(args.packed, "rb").read()
        _, l1log = ks.unpack(packed)          # gives us loader bytes indirectly
        # Re-extract loader for rt_info (strip_layer1 returns clear + loader).
        clear, loader_bytes = ks.strip_layer1(packed, {})
        traps, funcs, rt_off = ks.find_rt_info(loader_bytes, ks.Elf(layer1))
        if funcs:
            result = ks.strip_layer2(layer1, traps, funcs, log)
            log["layer2_applied"] = True
            log["rt_info_offset"] = hex(rt_off)
        else:
            log["layer2_applied"] = False
            log["note"] = "runtime_info not recoverable; layer-1 ELF returned"
    except Exception as e:
        log["layer2_applied"] = False
        log["note"] = "layer-2 skipped: %s" % e

    out_path = args.out or (args.packed + ".dynamic.elf")
    open(out_path, "wb").write(result)
    log["unpacked_sha256"] = ks.sha256(result)
    json.dump(log, open(args.json or (out_path + ".json"), "w"), indent=2)
    print("[+] wrote %s (layer2=%s)" % (out_path, log.get("layer2_applied")))
    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
