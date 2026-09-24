#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Michael Loomis
# kiteshear_core.py
#
# Static unpacking engine for GunshipPenguin/kiteshield-packed ELF binaries
# and known in-the-wild variants (Winnti / amdc6766 / Gafgyt samples etc.).
#
# Pure standard-library Python 3 (no lief / no pycryptodome required) so it runs
# unchanged inside a PyGhidra (CPython) interpreter and in a bare DFIR VM.
#
# WHAT THIS RECOVERS
# ------------------
#   Layer 1 ("outer"): a single RC4 pass over the whole original ELF. The 16-byte
#     RC4 key is stored between the program-header table and the entry point, and
#     is XOR-folded with every byte of the loader before use (this both hides the
#     key and checksums the loader). We reproduce that exactly.
#   Layer 2 ("inner"): per-function RC4 encryption + int3 traps on each function
#     entry and every ret. The runtime_info table (function list w/ per-function
#     keys, and trap list w/ original overwritten bytes) is embedded in the
#     loader, XOR-obfuscated with a running byte index. We deobfuscate it, RC4-
#     decrypt each function in place, then restore every trapped byte.
#
# Because the whole function table + keys live in the file, every encrypted
# function is recovered whether or not it is ever called -> full code coverage.
#
# Reference for the on-disk format / obfuscation scheme:
#   XLab (QiAnXin) "Kiteshield Packer is being abused by cybercriminals", 2024.
#   Upstream: github.com/GunshipPenguin/kiteshield  (common/include/defs.h,
#   loader/entry.S, loader/obfuscated_strings.h).
#
# Anything marked "# ADAPT:" is where a hardened variant may need tuning.

import hashlib
import json
import re
import struct

KEY_SIZE = 16                      # RC4 key length used by Kiteshield
TRAP_SIZE = 17                     # sizeof(struct trap_point):  <QIBI>
FUNC_SIZE = 32                     # sizeof(struct function):    <IQI16s>
DEFAULT_DYN_BASE = 0x800000000     # loader maps PIE payloads here (KITESHIELD base)

# struct runtime_info starts with two uint32 (small counts) then the trap array
# then the function array.  Same signature used by the XLab unpacker.
RT_INFO_RE = re.compile(rb".\x00\x00\x00.\x00\x00\x00.{8}[\x08-\x0a]\x09\x0a\x0b", re.DOTALL)

# Anti-debug strings the loader carries, single-byte XOR with (0x83 + i) % 256.
DEOBF_STR_KEY = 0x83               # loader/include/obfuscation.h DEOBF_STR macro
OBFUSCATED_STRINGS = {
    "PROC_STATUS_FMT":     bytes.fromhex("acf4f7e9e4a7acee a4fff9effbe5e2".replace(" ", "")),
    "TRACERPID_FIELD":     bytes.fromhex("d7f6e4e5e2fad9e3efb6"),
    "PROC_STAT_FMT":       bytes.fromhex("acf4f7e9e4a7acee a4fff9effb".replace(" ", "")),
    "LD_PRELOAD":          bytes.fromhex("cfc0dad6d5cdc5c5cac8"),
    "LD_AUDIT":            bytes.fromhex("cfc0dac7d2ccc0de"),
    "LD_DEBUG":            bytes.fromhex("cfc0dac2c2cadccd"),
    "HEX_DIGITS":          bytes.fromhex("b3b5b7b5b3bdbfbdb3b5ececec f4f4f4".replace(" ", "")),
}


# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #
def rc4(key, data):
    """RC4 (identical for encrypt/decrypt). key/data: bytes-like -> bytes."""
    key = bytes(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[n] = data[n] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def deobf_str(buf):
    """Undo the loader's DEOBF_STR single-byte position XOR."""
    return bytes((b ^ ((DEOBF_STR_KEY + i) & 0xFF)) & 0xFF for i, b in enumerate(buf))


def sha256(data):
    return hashlib.sha256(bytes(data)).hexdigest()


# --------------------------------------------------------------------------- #
# Minimal ELF reader (header + program headers; enough for unpacking)
# --------------------------------------------------------------------------- #
ET_EXEC, ET_DYN = 2, 3
PT_LOAD = 1


class Elf:
    def __init__(self, data):
        data = bytes(data)
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF (bad magic)")
        self.data = data
        self.ei_class = data[4]                 # 1 = ELF32, 2 = ELF64
        self.ei_data = data[5]                  # 1 = little endian
        self.is64 = self.ei_class == 2
        self.en = "<" if self.ei_data == 1 else ">"
        if self.is64:
            fmt = self.en + "HHIQQQIHHHHHH"
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from(fmt, data, 16)
        else:
            fmt = self.en + "HHIIIIIHHHHHH"
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from(fmt, data, 16)
        self.phdrs = self._parse_phdrs()

    def _parse_phdrs(self):
        phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                    struct.unpack_from(self.en + "IIQQQQQQ", self.data, off)
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                    struct.unpack_from(self.en + "IIIIIIII", self.data, off)
            phdrs.append(dict(type=p_type, flags=p_flags, offset=p_offset,
                              vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz))
        return phdrs

    def loads(self):
        return [p for p in self.phdrs if p["type"] == PT_LOAD]

    def vaddr_to_off(self, vaddr):
        """Translate a virtual address to a file offset via LOAD segments."""
        for p in self.loads():
            if p["vaddr"] <= vaddr < p["vaddr"] + p["filesz"]:
                return p["offset"] + (vaddr - p["vaddr"])
        return None


# --------------------------------------------------------------------------- #
# Layer 1  (outer RC4)
# --------------------------------------------------------------------------- #
def _fold_key_with_loader(key16, loader_bytes):
    key = bytearray(key16)
    for i, c in enumerate(loader_bytes):
        key[i % KEY_SIZE] ^= c
    return bytes(key)


def strip_layer1(data, log):
    """
    Locate the outer RC4 key, XOR-fold it with the loader, RC4-decrypt the payload
    and return (original_elf_bytes, meta_dict). Validated by ELF magic so it is
    robust to phdr-count / layout variation in modified samples.
    """
    packed = Elf(data)
    loads = packed.loads()
    if len(packed.phdrs) < 2 or len(loads) < 2:
        raise ValueError("expected >=2 PT_LOAD segments (loader + payload); "
                         "got %d LOADs / %d phdrs" % (len(loads), len(packed.phdrs)))

    loader_seg, payload_seg = loads[0], loads[-1]
    payload = data[payload_seg["offset"]:payload_seg["offset"] + payload_seg["filesz"]]

    # Primary key position: immediately after the program-header table.
    primary = packed.e_phoff + packed.e_phentsize * packed.e_phnum

    # Candidate key offsets (primary first, then a small brute window for variants).
    candidates = [primary]
    win_start = packed.e_phoff + packed.e_phentsize * 2
    for off in range(win_start, min(len(data) - KEY_SIZE, primary + 256)):
        if off not in candidates:
            candidates.append(off)

    for key_off in candidates:
        raw_key = bytearray(data[key_off:key_off + KEY_SIZE])
        if len(raw_key) != KEY_SIZE:
            continue
        loader_off = key_off + KEY_SIZE
        loader_size = (loader_seg["offset"] + loader_seg["filesz"]) - loader_off
        if loader_size <= 0:
            continue
        loader_bytes = data[loader_off:loader_off + loader_size]
        eff_key = _fold_key_with_loader(raw_key, loader_bytes)
        clear = rc4(eff_key, payload)
        if clear[:4] == b"\x7fELF":
            log.update(dict(
                layer1_key_offset=key_off,
                layer1_key_raw=bytes(raw_key).hex(),
                layer1_key_effective=eff_key.hex(),
                loader_offset=loader_off,
                loader_size=loader_size,
                payload_offset=payload_seg["offset"],
                payload_size=payload_seg["filesz"],
            ))
            return clear, loader_bytes
    raise ValueError("layer-1 decryption failed: no key candidate produced an ELF. "
                     "Sample may use a modified outer scheme - use the dynamic path.")


# --------------------------------------------------------------------------- #
# Layer 2  (runtime_info + per-function RC4)
# --------------------------------------------------------------------------- #
def _parse_rt_info(blob):
    """blob starts at the two count uint32s. Returns (traps, funcs) or None."""
    if len(blob) < 8:
        return None
    nfuncs, ntraps = struct.unpack_from("<II", blob, 0)
    if not (0 < ntraps < 200000 and 0 <= nfuncs < 200000):
        return None
    size = TRAP_SIZE * ntraps + FUNC_SIZE * nfuncs
    body = blob[8:8 + size]
    if len(body) < size:
        return None
    res = bytes((c ^ i) & 0xFF for i, c in enumerate(body))   # index XOR deobfuscation

    traps = []
    for i in range(ntraps):
        addr, ttype, value, fcn_i = struct.unpack_from("<QIBI", res, i * TRAP_SIZE)
        traps.append(dict(addr=addr, type=ttype, value=value, fcn_i=fcn_i))
    foff = TRAP_SIZE * ntraps
    funcs = []
    for i in range(nfuncs):
        fid, start, length, key = struct.unpack_from("<IQI16s", res, foff + i * FUNC_SIZE)
        funcs.append(dict(id=fid, start_addr=start, len=length, key=key))
    return traps, funcs


def find_rt_info(loader_bytes, unpacked_elf):
    """
    Find runtime_info inside the loader. Primary = XLab regex; fallback = sliding
    scan validated against the unpacked ELF (function starts must resolve to a
    LOAD segment). Returns (traps, funcs, offset) or (None, None, None).
    """
    def validate(parsed):
        if not parsed:
            return False
        _, funcs = parsed
        if not funcs:
            return False
        ok = 0
        for f in funcs:
            for base in (0, DEFAULT_DYN_BASE):
                if unpacked_elf.vaddr_to_off(f["start_addr"] - base) is not None:
                    ok += 1
                    break
        return ok >= max(1, len(funcs) // 2)

    for m in RT_INFO_RE.finditer(loader_bytes):
        parsed = _parse_rt_info(loader_bytes[m.start():])
        if validate(parsed):
            return parsed[0], parsed[1], m.start()

    # Fallback: brute scan on 4-byte alignment. Slow but only runs if regex misses.
    for off in range(0, len(loader_bytes) - 8, 4):
        if loader_bytes[off + 1:off + 4] != b"\x00\x00\x00":
            continue
        if loader_bytes[off + 5:off + 8] != b"\x00\x00\x00":
            continue
        parsed = _parse_rt_info(loader_bytes[off:])
        if validate(parsed):
            return parsed[0], parsed[1], off
    return None, None, None


def _pick_base(unpacked_elf, funcs):
    if unpacked_elf.e_type == ET_DYN:
        order = [DEFAULT_DYN_BASE, 0]
    else:
        order = [0, DEFAULT_DYN_BASE]
    best, best_hits = order[0], -1
    for base in order:
        hits = sum(1 for f in funcs
                   if unpacked_elf.vaddr_to_off(f["start_addr"] - base) is not None)
        if hits > best_hits:
            best, best_hits = base, hits
    return best


def strip_layer2(unpacked, traps, funcs, log):
    """Decrypt each function in the layer-1 output and restore trapped bytes."""
    elf = Elf(unpacked)
    out = bytearray(unpacked)
    base = _pick_base(elf, funcs)
    log["layer2_base"] = hex(base)

    dec_funcs = []
    for f in funcs:
        off = elf.vaddr_to_off(f["start_addr"] - base)
        entry = dict(id=f["id"], vaddr=hex(f["start_addr"]),
                     file_off=(hex(off) if off is not None else None),
                     len=f["len"], key=f["key"].hex())
        dec_funcs.append(entry)
        if off is None or f["len"] <= 0 or off + f["len"] > len(out):
            entry["decrypted"] = False
            continue
        out[off:off + f["len"]] = rc4(f["key"], bytes(out[off:off + f["len"]]))
        entry["decrypted"] = True

    restored = 0
    for t in traps:
        off = elf.vaddr_to_off(t["addr"] - base)
        if off is not None and 0 <= off < len(out):
            out[off] = t["value"] & 0xFF          # replace 0xcc with original byte
            restored += 1

    log["functions"] = dec_funcs
    log["traps_restored"] = restored
    log["nfuncs"] = len(funcs)
    log["ntraps"] = len(traps)
    return bytes(out)


# --------------------------------------------------------------------------- #
# Forensic extras
# --------------------------------------------------------------------------- #
def extract_antidebug_strings(loader_bytes):
    """Locate the loader's XOR-obfuscated anti-debug strings; return what's found."""
    found = {}
    for name, needle in OBFUSCATED_STRINGS.items():
        idx = loader_bytes.find(needle)
        if idx != -1:
            found[name] = dict(offset=hex(idx), value=deobf_str(needle).rstrip(b"\x00").decode("latin1"))
    return found


YARA_RULE = r'''rule kiteshield_packed
{
    meta:
        description = "GunshipPenguin Kiteshield packer (entry stub + obfuscated anti-debug strings)"
        reference   = "github.com/GunshipPenguin/kiteshield ; XLab 2024"
    strings:
        // entry.S register-clear + jmp *%rbx tail (fixed loader signature)
        $jmp = {31 D2 31 C0 31 C9 31 F6 31 FF 31 ED 45 31 C0 45 31 C9 45 31 D2 45 31 DB 45 31 E4 45 31 ED 45 31 F6 45 31 FF 5B FF E3}
        $s1 = {ac f4 f7 e9 e4 a7 ac ee a4 ff f9 ef fb e5 e2}   // /proc/%d/status
        $s2 = {d7 f6 e4 e5 e2 fa d9 e3 ef b6}                  // TracerPid:
        $s3 = {ac f4 f7 e9 e4 a7 ac ee a4 ff f9 ef fb}         // /proc/%d/stat
        $s4 = {cf c0 da d6 d5 cd c5 c5 ca c8}                  // LD_PRELOAD
        $s5 = {cf c0 da c7 d2 cc c0 de}                        // LD_AUDIT
        $s6 = {cf c0 da c2 c2 ca dc cd}                        // LD_DEBUG
    condition:
        $jmp and 4 of ($s*) and uint32(0) == 0x464c457f
}
'''


# --------------------------------------------------------------------------- #
# Top-level driver
# --------------------------------------------------------------------------- #
def unpack(data, want_layer2=True):
    """
    Full static unpack. Returns (unpacked_bytes, log_dict).
    Works for -n (layer-1-only) samples too: if no runtime_info is present the
    layer-1 output is already the complete original ELF.
    """
    data = bytes(data)
    log = dict(packed_sha256=sha256(data), packed_size=len(data))
    packed = Elf(data)
    log.update(e_type={ET_EXEC: "ET_EXEC", ET_DYN: "ET_DYN"}.get(packed.e_type, packed.e_type),
               e_machine=packed.e_machine, ei_class=("ELF64" if packed.is64 else "ELF32"))

    layer1, loader_bytes = strip_layer1(data, log)
    log["antidebug_strings"] = extract_antidebug_strings(loader_bytes)

    result = layer1
    log["layer2_applied"] = False
    if want_layer2:
        traps, funcs, rt_off = find_rt_info(loader_bytes, Elf(layer1))
        if funcs:
            log["rt_info_offset"] = hex(rt_off)
            result = strip_layer2(layer1, traps, funcs, log)
            log["layer2_applied"] = True
        else:
            log["note"] = ("no runtime_info found - sample is layer-1-only (-n) or "
                           "the table is obfuscated beyond the static parser; "
                           "layer-1 ELF returned. Use the dynamic path for layer 2.")

    log["unpacked_sha256"] = sha256(result)
    log["unpacked_size"] = len(result)
    return result, log


if __name__ == "__main__":
    import sys
    blob = open(sys.argv[1], "rb").read()
    out, log = unpack(blob)
    open(sys.argv[2], "wb").write(out)
    print(json.dumps(log, indent=2))
