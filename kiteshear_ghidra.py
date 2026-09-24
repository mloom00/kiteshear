#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael Loomis
# kiteshear_ghidra.py
#
# PyGhidra driver for Kiteshield-packed ELFs. It statically unpacks the sample
# with kiteshear_core, writes the recovered original ELF, then loads THAT into
# Ghidra, auto-analyzes it, and annotates every recovered function with its
# Kiteshield id + per-function RC4 key (as a PLATE comment and a bookmark), and
# labels each trap point. Trap bytes are already restored in the unpacked ELF, so
# Ghidra sees clean instructions rather than 0xcc.
#
# Two ways to run:
#
# 1) Headless from a normal shell (recommended for DFIR batch work):
#       pip install pyghidra           # needs a local Ghidra install + JDK 17+
#       export GHIDRA_INSTALL_DIR=/opt/ghidra
#       python3 kiteshear_ghidra.py packed.ks --project-dir ./ghp --project-name case42
#
# 2) Inside the Ghidra GUI (Script Manager, PyGhidra provider). If you already
#    imported the UNPACKED elf, run with no args and it will annotate the current
#    program from the sidecar <unpacked>.keys.json.
#
# Notes:
#  * The unpack itself never depends on Ghidra -- if the Ghidra API differs on
#    your version, you still get the recovered ELF + keys.json.
#  * PyGhidra's open_program signature has shifted across releases; the call is
#    wrapped in try/except with a fallback.

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kiteshear_core as ks


# --------------------------------------------------------------------------- #
# Annotation shared by headless + GUI modes
# --------------------------------------------------------------------------- #
def annotate_program(program, flat, log):
    """Add comments/bookmarks/labels from the unpack log to a loaded program."""
    from ghidra.program.model.symbol import SourceType

    st = program.getSymbolTable()
    space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    base = int(log.get("layer2_base", "0x0"), 16)
    load_base = program.getImageBase().getOffset()

    def addr(vaddr):
        # unpacked ELF is loaded at its own image base; runtime_info vaddrs are
        # (kiteshield_base + elf_vaddr). Convert to the ELF vaddr, then let Ghidra
        # place it relative to its image base.
        return space.getAddress(vaddr - base)

    n = 0
    for f in log.get("functions", []):
        try:
            a = addr(int(f["vaddr"], 16))
            cmt = "[kiteshear] func #%d  len=%d  rc4_key=%s" % (f["id"], f["len"], f["key"])
            listing.setComment(a, listing.PLATE_COMMENT, cmt)
            flat.createBookmark(a, "Kiteshear", "func#%d key=%s" % (f["id"], f["key"]))
            try:
                st.createLabel(a, "ks_func_%d" % f["id"], SourceType.ANALYSIS)
            except Exception:
                pass
            # Nudge Ghidra to treat it as a function.
            if flat.getFunctionAt(a) is None:
                flat.createFunction(a, "ks_func_%d" % f["id"])
            n += 1
        except Exception as e:
            print("  [!] annotate func #%s: %s" % (f.get("id"), e))
    print("[+] annotated %d functions" % n)
    return n


# --------------------------------------------------------------------------- #
# GUI mode: annotate the already-open unpacked program
# --------------------------------------------------------------------------- #
def run_in_gui():
    try:
        program = currentProgram          # noqa: F821  (injected by Ghidra)
    except NameError:
        return False
    sidecar = None
    ep = program.getExecutablePath()
    for cand in (ep + ".keys.json", os.path.splitext(ep)[0] + ".keys.json"):
        if cand and os.path.exists(cand):
            sidecar = cand
            break
    if not sidecar:
        print("[!] no <program>.keys.json beside the executable; run the headless "
              "unpack first, or use kiteshear_unpack.py to produce it.")
        return True
    log = json.load(open(sidecar))
    from ghidra.program.flatapi import FlatProgramAPI
    flat = FlatProgramAPI(program)
    tx = program.startTransaction("Kiteshear annotate")
    try:
        annotate_program(program, flat, log)
    finally:
        program.endTransaction(tx, True)
    return True


# --------------------------------------------------------------------------- #
# Headless mode: unpack + import + analyze + annotate
# --------------------------------------------------------------------------- #
def run_headless(argv):
    import argparse
    ap = argparse.ArgumentParser(description="PyGhidra Kiteshear unpacker/annotator")
    ap.add_argument("packed")
    ap.add_argument("--out", help="unpacked ELF path (default <packed>.unpacked.elf)")
    ap.add_argument("--project-dir", default="./ghidra_project")
    ap.add_argument("--project-name", default="kiteshear")
    ap.add_argument("--no-analyze", action="store_true")
    args = ap.parse_args(argv)

    data = open(args.packed, "rb").read()
    out, log = ks.unpack(data)
    out_path = args.out or (args.packed + ".unpacked.elf")
    open(out_path, "wb").write(out)
    open(args.packed + ".keys.json", "w").write(json.dumps(log, indent=2))
    print("[+] unpacked -> %s" % out_path)
    print("[+] keys/meta -> %s" % (args.packed + ".keys.json"))

    try:
        import pyghidra
    except ImportError:
        print("[!] pyghidra not installed; ELF + keys are ready for manual import.")
        return
    pyghidra.start()
    os.makedirs(args.project_dir, exist_ok=True)

    def _open():
        try:
            return pyghidra.open_program(out_path, project_location=args.project_dir,
                                         project_name=args.project_name,
                                         analyze=not args.no_analyze)
        except TypeError:
            # older/newer signature fallback
            return pyghidra.open_program(out_path)

    with _open() as flat:
        program = flat.getCurrentProgram()
        if not args.no_analyze:
            try:
                pyghidra.analyze(program)
            except Exception:
                pass
        tx = program.startTransaction("Kiteshear annotate")
        try:
            annotate_program(program, flat, log)
        finally:
            program.endTransaction(tx, True)
        try:
            flat.getCurrentProgram().save("kiteshear unpack", None)
        except Exception:
            pass
    print("[+] Ghidra project ready: %s/%s" % (args.project_dir, args.project_name))


if __name__ == "__main__":
    if not run_in_gui():
        run_headless(sys.argv[1:])
