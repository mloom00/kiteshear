#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael Loomis
# kiteshear_qiling.py
#
# Qiling emulation harness for HARDENED Kiteshield variants -- the cases where
# the static path (kiteshear_unpack.py) can't recover the outer key and the
# Frida path is blocked by anti-debug.
#
# Why Qiling: the emulator owns every syscall, so all of Kiteshield's evasion is
# inert -- the /proc/self/status TracerPid read, prctl(PR_SET_DUMPABLE,0), the
# LD_* clearing and setrlimit(RLIMIT_CORE,0) all run against a controlled kernel.
# No ptrace conflict, no injection, deterministic.
#
# Approach:
#   1. Emulate ONLY the loader, until it maps the layer-1-decrypted payload and
#      transfers control to it (entry.S tail `pop rbx ; jmp rbx` == 5B FF E3,
#      or the fork/clone that spawns the traced child -- whichever comes first).
#   2. Snapshot emulated memory at the Kiteshield base (payload fully decrypted).
#   3. Reassemble a loadable ELF from the snapshot (file-carve if the loader
#      mapped the payload blob contiguously, else rebuild a process-image ELF),
#      then apply layer-2 statically from runtime_info in the (plaintext) loader
#      -> FULL function coverage, not just executed code.
#   4. Log the sample's evasion syscalls for the report.
#
# We deliberately do NOT run the payload: at runtime Kiteshield keeps only the
# live function decrypted and re-encrypts on exit, so a running snapshot is worse
# than static layer-2. Layer 1 from emulation + layer 2 from runtime_info wins.
#
# Install:
#   pip install qiling
#   # rootfs (glibc etc.): git clone https://github.com/qilingframework/rootfs
#   #   or use qiling's examples/rootfs/x8664_linux
#
# Run:
#   python3 kiteshear_qiling.py packed.ks --rootfs ./rootfs/x8664_linux
#   python3 kiteshear_qiling.py packed.ks --rootfs ./rootfs/x8664_linux \
#           --stop-at 0x<addr>  --dump-len 0x600000  --timeout 120
#
# ADAPT markers flag variant-dependent knobs (base, signature, dump length).

import argparse
import json
import os
import signal
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kiteshear_core as ks

TRANSFER_SIG = b"\x5b\xff\xe3"          # pop rbx ; jmp rbx   (entry.S tail)  ADAPT
DEFAULT_DUMP_LEN = 0x600000             # bytes to snapshot from base         ADAPT
INTERESTING_SYSCALLS = ["ptrace", "prctl", "clone", "fork", "vfork", "openat",
                        "open", "read", "mmap", "mmap2", "mprotect", "execve",
                        "socket", "connect", "getpid", "kill", "arch_prctl"]


# --------------------------------------------------------------------------- #
# Snapshot -> ELF reconstruction (pure; testable without Qiling)
# --------------------------------------------------------------------------- #
def carve_file_elf(dump):
    """
    If the loader mapped the decrypted payload BLOB contiguously at base, the
    snapshot begins with a normal ELF *file*. Find it, validate that its LOAD
    segments fit inside the dump, and return a trimmed clean file. Returns
    (elf_bytes, "file") or None.
    """
    i = dump.find(b"\x7fELF")
    while i != -1:
        try:
            elf = ks.Elf(dump[i:])
            loads = elf.loads()
            if loads and all(p["offset"] + p["filesz"] <= len(dump) - i for p in loads):
                end = max(p["offset"] + p["filesz"] for p in loads)
                if elf.e_shoff:
                    end = max(end, elf.e_shoff + elf.e_shnum * elf.e_shentsize)
                end = min(end, len(dump) - i)
                return dump[i:i + end], "file"
        except Exception:
            pass
        i = dump.find(b"\x7fELF", i + 4)
    return None


def rebuild_image_elf(dump, base):
    """
    Fallback: the loader mapped each PT_LOAD at its vaddr (a process image, not a
    file). Rebuild a loadable ELF whose file offsets equal virtual addresses
    (identity), copying each segment's bytes out of the snapshot. Ghidra/IDA load
    it with correct addresses. Returns (elf_bytes, "image") or None. ELF64 only.
    """
    hdr_off = dump.find(b"\x7fELF")              # image origin within the snapshot
    if hdr_off < 0:
        return None
    try:
        src = ks.Elf(dump[hdr_off:])
    except Exception:
        return None
    if not src.is64:
        return None
    loads = src.loads()
    if not loads:
        return None
    origin = min(p["vaddr"] for p in loads)      # virtual addr the header maps to
    file_end = max(p["vaddr"] + p["memsz"] for p in loads) - origin
    if file_end <= 0 or file_end > 0x10000000:   # 256 MiB sanity cap
        return None

    def mem_index(vaddr):                         # snapshot index for a virtual addr
        return hdr_off + (vaddr - origin)

    out = bytearray(file_end)
    for p in loads:
        seg = dump[mem_index(p["vaddr"]):mem_index(p["vaddr"]) + p["filesz"]]
        foff = p["vaddr"] - origin                # identity: file offset == vaddr-origin
        out[foff:foff + len(seg)] = seg
    # rewrite each PT_LOAD p_offset to its identity offset; keep p_vaddr intact
    for idx, p in enumerate(src.phdrs):
        if p["type"] != ks.PT_LOAD:
            continue
        ph_off = src.e_phoff + idx * src.e_phentsize
        if ph_off + 16 <= len(out):
            struct.pack_into("<Q", out, ph_off + 8, p["vaddr"] - origin)
    # stale section-header table: neutralize so parsers don't chase bad offsets
    if len(out) >= 0x40:
        struct.pack_into("<Q", out, 0x28, 0)      # e_shoff
        struct.pack_into("<H", out, 0x3c, 0)      # e_shnum
    return bytes(out), "image"


def loader_segment_bytes(packed):
    """Plaintext loader bytes (first LOAD segment) -- holds runtime_info even when
    the outer key scheme is modified. Superset scan is fine (rt_info XOR is
    position-internal)."""
    elf = ks.Elf(packed)
    seg = elf.loads()[0]
    return packed[seg["offset"]:seg["offset"] + seg["filesz"]]


def reassemble(packed, dump, base, log):
    """snapshot -> loadable, layer-2-decrypted ELF."""
    carved = carve_file_elf(dump)
    if carved is None:
        carved = rebuild_image_elf(dump, base)
    if carved is None:
        raise ValueError("could not reconstruct an ELF from the snapshot")
    layer1, method = carved
    log["reconstruction"] = method
    log["layer1_sha256"] = ks.sha256(layer1)

    result = layer1
    try:
        loader_bytes = loader_segment_bytes(packed)
        traps, funcs, rt_off = ks.find_rt_info(loader_bytes, ks.Elf(layer1))
        if funcs:
            log["rt_info_offset"] = hex(rt_off)
            result = ks.strip_layer2(layer1, traps, funcs, log)
            log["layer2_applied"] = True
        else:
            log["layer2_applied"] = False
            log["note"] = "runtime_info not found; layer-1 image returned (-n or hardened table)"
    except Exception as e:
        log["layer2_applied"] = False
        log["layer2_error"] = str(e)
    return result


# --------------------------------------------------------------------------- #
# Qiling driver
# --------------------------------------------------------------------------- #
def safe_dump(ql, base, length):
    """Read what's mapped in [base, base+length); zero-fill gaps up to last page."""
    PAGE = 0x1000
    out = bytearray()
    last_ok = 0
    for off in range(0, length, PAGE):
        try:
            out += bytes(ql.mem.read(base + off, PAGE))
            last_ok = len(out)
        except Exception:
            out += b"\x00" * PAGE
    return bytes(out[:last_ok]) if last_ok else b""


def run(args):
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except ImportError:
        print("[!] Qiling not installed. `pip install qiling` and fetch a rootfs.",
              file=sys.stderr)
        sys.exit(3)
    try:
        from qiling.const import QL_INTERCEPT
        HAVE_INTERCEPT = True
    except Exception:
        HAVE_INTERCEPT = False

    packed = open(args.packed, "rb").read()
    pelf = ks.Elf(packed)
    if args.base is not None:
        base = args.base
    else:
        base = ks.DEFAULT_DYN_BASE if pelf.e_type == ks.ET_DYN else 0
    log = dict(packed_sha256=ks.sha256(packed), base=hex(base),
               e_type=("ET_DYN" if pelf.e_type == ks.ET_DYN else "ET_EXEC"),
               syscalls=[])

    verbose = {"off": QL_VERBOSE.OFF, "default": QL_VERBOSE.DEFAULT,
               "debug": QL_VERBOSE.DEBUG, "disasm": QL_VERBOSE.DISASM}.get(
                   args.verbose, QL_VERBOSE.OFF)
    ql = Qiling([args.packed], args.rootfs, verbose=verbose)

    state = dict(dumped=False, dump=b"")

    def do_dump(ql, why):
        if state["dumped"]:
            return
        # only trip when the payload really is mapped & decrypted
        try:
            head = bytes(ql.mem.read(base, 4))
        except Exception:
            head = b""
        if head[:4] != b"\x7fELF" and why == "transfer":
            return                                   # false-positive signature site
        state["dump"] = safe_dump(ql, base, args.dump_len)
        state["dumped"] = True
        log["dump_trigger"] = why
        log["dump_size"] = len(state["dump"])
        print("[+] snapshot at base %#x via %s (%d bytes)" % (base, why, len(state["dump"])))
        ql.emu_stop()

    # syscall logging (best-effort across Qiling versions)
    def mk_log(name):
        def _h(ql, *a, **k):
            try:
                ql.log  # noqa
            except Exception:
                pass
            entry = dict(sc=name, args=[hex(x) if isinstance(x, int) else str(x) for x in a[:4]])
            log["syscalls"].append(entry)
            if name in ("fork", "vfork", "clone"):
                do_dump(ql, "fork")                  # payload decrypted by fork time
        return _h

    for name in INTERESTING_SYSCALLS:
        try:
            if HAVE_INTERCEPT:
                ql.os.set_syscall(name, mk_log(name), QL_INTERCEPT.ENTER)
            else:
                ql.os.set_syscall(name, mk_log(name))
        except Exception:
            pass

    # address hooks on the transfer signature (auto) or user --stop-at
    hooked = 0
    if args.stop_at is not None:
        ql.hook_address(lambda ql: do_dump(ql, "stop-at"), args.stop_at)
        hooked += 1
    else:
        try:
            for a in ql.mem.search(TRANSFER_SIG):
                ql.hook_address(lambda ql, why="transfer": do_dump(ql, why), a)
                hooked += 1
        except Exception:
            pass
    log["transfer_hooks"] = hooked
    if hooked == 0:
        print("[!] no transfer hook set; relying on fork trigger / timeout")

    # wall-clock timeout -> stop and dump whatever exists
    def on_alarm(signum, frame):
        print("[!] timeout; dumping current memory")
        do_dump(ql, "timeout")
        try:
            ql.emu_stop()
        except Exception:
            pass
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(args.timeout)

    try:
        ql.run()
    except Exception as e:
        log["emu_stop_reason"] = "exception: %s" % e
        print("[!] emulation ended: %s" % e)
        do_dump(ql, "emu-exception")
    finally:
        signal.alarm(0)

    if not state["dump"]:
        print("[!] no snapshot captured. Try --stop-at, larger --timeout, or "
              "--verbose debug to find where emulation diverged.", file=sys.stderr)
        json.dump(log, open(args.packed + ".qiling.json", "w"), indent=2)
        sys.exit(4)

    # persist raw snapshot + reconstruct
    dump_path = args.dump or (args.packed + ".layer1.bin")
    open(dump_path, "wb").write(state["dump"])
    result = reassemble(packed, state["dump"], base, log)
    out_path = args.out or (args.packed + ".unpacked.elf")
    open(out_path, "wb").write(result)
    log["unpacked_sha256"] = ks.sha256(result)
    json.dump(log, open(args.packed + ".qiling.json", "w"), indent=2)

    print("[+] reconstruction : %s" % log.get("reconstruction"))
    print("[+] layer 2        : %s (%s funcs)" %
          (log.get("layer2_applied"), log.get("nfuncs", "?")))
    print("[+] evasion syscalls seen: %s" %
          ", ".join(sorted({s["sc"] for s in log["syscalls"]
                            if s["sc"] in ("ptrace", "prctl", "clone", "fork", "vfork")})) or "none")
    print("[+] snapshot       : %s" % dump_path)
    print("[+] unpacked ELF   : %s" % out_path)
    print("[+] log            : %s" % (args.packed + ".qiling.json"))


def main():
    ap = argparse.ArgumentParser(description="Qiling harness for hardened Kiteshield variants")
    ap.add_argument("packed")
    ap.add_argument("--rootfs", default=os.environ.get("QILING_ROOTFS", "./rootfs/x8664_linux"),
                    help="Qiling rootfs dir (default $QILING_ROOTFS or ./rootfs/x8664_linux)")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=None,
                    help="payload base (default 0x800000000 for PIE, 0 for ET_EXEC)")
    ap.add_argument("--stop-at", type=lambda x: int(x, 0), default=None,
                    help="explicit address to snapshot at (overrides signature scan)")
    ap.add_argument("--dump-len", dest="dump_len", type=lambda x: int(x, 0),
                    default=DEFAULT_DUMP_LEN)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out")
    ap.add_argument("--dump", help="raw snapshot output path")
    ap.add_argument("--verbose", choices=["off", "default", "debug", "disasm"], default="off")
    args = ap.parse_args()
    if not os.path.isdir(args.rootfs):
        print("[!] rootfs '%s' not found. Fetch qilingframework/rootfs." % args.rootfs,
              file=sys.stderr)
        sys.exit(2)
    run(args)


if __name__ == "__main__":
    main()
