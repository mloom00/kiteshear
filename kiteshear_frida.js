// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Michael Loomis
// kiteshear_frida.js
//
// DYNAMIC FALLBACK for Kiteshield samples where the static path fails (custom
// outer key scheme, mangled/absent runtime_info, or extra layers). Use ONLY in
// an isolated analysis VM/sandbox -- it executes the malware.
//
// Strategy (spawn mode, so hooks land before the loader's anti-debug runs):
//   1. Neutralize the loader's anti-debug so an external tracer/instrumenter can
//      coexist with its own child-ptrace.
//   2. Wait until layer-1 mapping is done and control is about to jump to the
//      payload (the fixed entry.S tail `pop rbx ; jmp rbx` == 5B FF E3), then
//      dump the fully layer-1-decrypted image mapped at the Kiteshield base.
//   3. Optionally hook the loader's RC4 to log the outer key and every
//      per-function key live as functions decrypt.
//
// The layer-1 dump is written to disk; feed it back to run_frida_dump.py, which
// hands it (plus any statically-parsed runtime_info) to kiteshear_core to finish
// layer 2 for FULL function coverage.
//
// Run:
//   frida -f ./packed.ks -l kiteshear_frida.js --runtime=v8 -o frida.log
//
// Everything marked ADAPT is variant-dependent -- verify against your sample.

'use strict';

const KS_BASE = ptr('0x800000000');     // ADAPT: PIE payload base; 0 for ET_EXEC
const DUMP_LEN = 0x400000;              // ADAPT: bytes to dump from base (cover all LOADs)
const DUMP_PATH = '/tmp/ks_layer1.bin';

// ---- syscall numbers (x86-64) ----
const SYS_prctl = 157, SYS_openat = 257, SYS_read = 0, SYS_setrlimit = 160, SYS_ptrace = 101;
const PR_SET_DUMPABLE = 4;

function loaderModule() {
    // The loader is the main executable image.
    return Process.enumerateModules()[0];
}

// ---------------------------------------------------------------------------
// 1) Anti-debug neutralization.
//    The loader issues raw syscalls (no libc). We scan its executable ranges for
//    `syscall` (0F 05) sites and vet rax at call time, faking the results of the
//    four documented checks: TracerPid read, PR_SET_DUMPABLE=0, LD_* clearing,
//    RLIMIT_CORE=0. This lets Frida stay attached without tripping detection.
// ---------------------------------------------------------------------------
function neutralizeAntiDebug() {
    const mod = loaderModule();
    const pattern = '0F 05';                 // syscall
    Memory.scanSync(mod.base, mod.size, pattern).forEach(function (m) {
        try {
            Interceptor.attach(m.address, {
                onEnter(args) {
                    this.nr = this.context.rax.toInt32();
                    this.a0 = this.context.rdi;
                    this.a1 = this.context.rsi;
                },
                onLeave(retval) {
                    // prctl(PR_SET_DUMPABLE, 0) -> pretend success but stays dumpable
                    if (this.nr === SYS_prctl && this.a0.toInt32() === PR_SET_DUMPABLE) {
                        retval.replace(ptr(0));
                    }
                    // ptrace(PTRACE_TRACEME/...) self checks -> success
                    if (this.nr === SYS_ptrace) {
                        retval.replace(ptr(0));
                    }
                    // setrlimit(RLIMIT_CORE,0) -> success, harmless
                    if (this.nr === SYS_setrlimit) {
                        retval.replace(ptr(0));
                    }
                    // read() of /proc/self/status: blank out any "TracerPid:\tN"
                    if (this.nr === SYS_read && !this.a1.isNull()) {
                        try {
                            const n = retval.toInt32();
                            if (n > 0) {
                                let s = this.a1.readUtf8String(n);
                                if (s && s.indexOf('TracerPid') !== -1) {
                                    s = s.replace(/TracerPid:\s*\d+/g, 'TracerPid:\t0');
                                    this.a1.writeUtf8String(s);
                                }
                            }
                        } catch (e) {}
                    }
                }
            });
        } catch (e) {}
    });
    console.log('[ks] anti-debug syscall hooks installed');
}

// ---------------------------------------------------------------------------
// 2) Dump the layer-1 image at the transfer to the payload.
//    entry.S clears all GPRs then `pop rbx ; jmp rbx`. That 3-byte tail is a
//    stable signature; when it executes, the decrypted payload is fully mapped.
// ---------------------------------------------------------------------------
function hookPayloadTransfer() {
    const mod = loaderModule();
    const hits = Memory.scanSync(mod.base, mod.size, '5B FF E3');   // pop rbx ; jmp rbx
    if (hits.length === 0) {
        console.log('[ks] entry tail not found; ADAPT the signature');
        return;
    }
    hits.forEach(function (h) {
        Interceptor.attach(h.address, {
            onEnter() {
                try {
                    const buf = KS_BASE.readByteArray(DUMP_LEN);
                    const f = new File(DUMP_PATH, 'wb');
                    f.write(buf);
                    f.close();
                    console.log('[ks] dumped layer-1 image (' + DUMP_LEN + ' bytes) -> ' + DUMP_PATH);
                    console.log('[ks] target=' + KS_BASE + '  jmp_target(rbx)=' + this.context.rbx);
                } catch (e) {
                    console.log('[ks] dump failed at ' + h.address + ': ' + e);
                }
            }
        });
    });
    console.log('[ks] payload-transfer dump hook armed (' + hits.length + ' site/s)');
}

// ---------------------------------------------------------------------------
// 3) OPTIONAL: hook the loader RC4 to log the outer key + per-function keys.
//    Kiteshield's rc4 KSA is a 256-iteration key-schedule. Locate it by
//    signature in YOUR sample, set RC4_KSA below, and this logs (key,len) for
//    every RC4 use -- the outer pass and each function decrypt at runtime.
// ---------------------------------------------------------------------------
const RC4_KSA = null;   // ADAPT: ptr to rc4 key-schedule fn, e.g. mod.base.add(0xXXXX)
function hookRc4() {
    if (!RC4_KSA) { console.log('[ks] RC4_KSA unset; skipping key logger'); return; }
    Interceptor.attach(RC4_KSA, {
        onEnter(args) {
            // ADAPT calling convention: assume (ctx=rdi, key=rsi, keylen=rdx).
            try {
                const key = args[1].readByteArray(16);
                console.log('[ks] RC4 key: ' + hexdump(key, { length: 16, header: false, ansi: false }).trim());
            } catch (e) {}
        }
    });
    console.log('[ks] RC4 key logger installed');
}

// ---------------------------------------------------------------------------
neutralizeAntiDebug();
hookPayloadTransfer();
hookRc4();
console.log('[ks] instrumentation ready; resuming target');

// ============================================================================
// ALTERNATIVE (more robust vs anti-debug): emulate with Qiling instead of Frida.
//   from qiling import Qiling
//   ql = Qiling(['./packed.ks'], '/', console=False)
//   # Qiling owns every syscall, so anti-debug is inert. Hook address of the
//   # `pop rbx ; jmp rbx` tail, then ql.mem.read(0x800000000, DUMP_LEN) and save.
//   ql.hook_address(dump_cb, transfer_addr); ql.run()
// This avoids the Frida/self-ptrace conflict entirely and is the recommended
// path for heavily-hardened samples.
// ============================================================================
