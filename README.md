# Kiteshear - A Kiteshield unpacking toolkit

Recovers the original ELF from binaries packed with **GunshipPenguin/kiteshield**
and known in-the-wild variants (samples attributed to Winnti, amdc6766/DarkMozzie,
Gafgyt). Built for forensics: full function coverage, key/metadata logging, and
IOC + YARA output.

## Why static works (and recovers *everything*)
Kiteshear stores everything needed to reverse both layers **inside the file**:

* **Layer 1 (outer)** — one RC4 pass over the whole original ELF. The 16-byte key
  sits between the program-header table and the entry point. Before use it is
  XOR-folded byte-by-byte with the entire loader (this hides the key *and*
  checksums the loader). `strip_layer1()` reproduces this and validates by ELF
  magic, so it tolerates layout changes in modified samples.
* **Layer 2 (inner)** — per-function RC4 + an `int3` on every function entry and
  `ret`. The `runtime_info` table (function list with **per-function keys**, trap
  list with the **original overwritten bytes**) is embedded in the loader,
  obfuscated only by a running-index XOR. `strip_layer2()` deobfuscates it,
  RC4-decrypts each function, and restores the trapped bytes.

Because the whole function table lives in the file, **every encrypted function is
recovered whether or not it ever runs** — no execution, no call-stack limitation.
Samples packed with `-n` have only layer 1; the outer decrypt already yields the
complete original.

### On-disk structures (x86-64)
```
key            : 16 bytes at  e_phoff + e_phentsize * 2   (after the 2 phdrs)
loader region  : key_off+16 .. end(LOAD[0])   (folds into the key; holds runtime_info)
payload        : LOAD[last]                    (RC4(effective_key) of the original ELF)

struct trap_point { u64 addr; u32 type; u8 value; u32 fcn_i; }   // 17 bytes  <QIBI>
struct function   { u32 id; u64 start_addr; u32 len; u8 key[16]; } // 32 bytes <IQI16s>
runtime_info      : u32 nfuncs; u32 ntraps; trap_point[]; function[]  (body index-XOR'd)
PIE payload base  : 0x800000000  (ET_EXEC uses 0)
```

## Tools

| File | Role |
|------|------|
| `kiteshear_core.py` | Engine: RC4, ELF parse, key extraction, runtime_info parse, layer1/2, ELF rebuild, YARA. Pure stdlib. |
| `kiteshear_unpack.py` | **Skip-Ghidra path.** Produces original ELF + `keys.json` + `iocs.txt` + YARA. |
| `kiteshear_ghidra.py` | PyGhidra: unpack → import → analyze → annotate each function with its RC4 key; label traps. |
| `kiteshear_frida.js` + `run_frida_dump.py` | **Dynamic fallback** for hardened variants: anti-debug neutralization, layer-1 memory dump, reassembly. |

## Workflow

```bash
# 1) Static unpack (does 95% of cases, full coverage)
python3 kiteshear_unpack.py packed.ks
#   -> packed.ks.unpacked.elf   (load in Ghidra/IDA/objdump/gdb)
#      packed.ks.keys.json      (outer + per-function keys, offsets, base, traps)
#      packed.ks.iocs.txt       (hashes + keys for hunting)

# 2) Straight into Ghidra with annotations
export GHIDRA_INSTALL_DIR=/opt/ghidra          # pip install pyghidra ; JDK 17+
python3 kiteshear_ghidra.py packed.ks --project-dir ./ghp --project-name case42

# 3) Only if static fails (custom outer scheme / mangled runtime_info) — in a VM:
frida -f ./packed.ks -l kiteshear_frida.js --runtime=v8 -o frida.log
python3 run_frida_dump.py --packed packed.ks --dump /tmp/ks_layer1.bin -o out.elf
```

## DFIR / remediation notes
* **Triage pivot:** the outer *effective* RC4 key is random per sample but stable
  across the packed/unpacked pair — a strong hunting term. Per-function keys and
  the `runtime_info` layout are also loggable IOCs.
* **Detection:** ship `--yara` (matches the fixed `entry.S` register-clear +
  `jmp *%rbx` tail and the XOR-obfuscated anti-debug strings). This flags the
  *packer*, not the payload.
* **Real IOCs come from the unpacked payload**, not the wrapper — hash it, extract
  C2/strings/config from it, and build detections on that.
* **Anti-debug the sample used** (all inert once unpacked, but note for the
  report): `/proc/<pid>/status` TracerPid check; `prctl(PR_SET_DUMPABLE,0)`;
  clearing `LD_PRELOAD`/`LD_AUDIT`/`LD_DEBUG`; `setrlimit(RLIMIT_CORE,0)`.
  `keys.json.antidebug_strings` reports which were present.

## Scope / caveats
* Upstream Kiteshield is **x86-64 only**. The engine parses ELF32 too and
  `struct`/base handling is parameterized, but a real 32-bit *variant* would be a
  custom fork — re-derive struct sizes/base from its loader before trusting output.
* `# ADAPT:` markers flag the spots a hardened variant may move (key offset,
  runtime_info signature, base, anti-debug sites, RC4 routine address).
* Crypto/format logic is validated by an end-to-end round-trip against the
  documented format; always confirm against a known sample in your environment.
* Run unknown samples only in an isolated analysis VM.

## Format Reference
* XLab/QiAnXin, "Kiteshield Packer is being abused by
cybercriminals" (2024)
* Kiteshield Project, `github.com/GunshipPenguin/kiteshield`

## License

MIT © 2026 Michael Loomis. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for
format/reference attributions (Kiteshield, XLab/QiAnXin).
