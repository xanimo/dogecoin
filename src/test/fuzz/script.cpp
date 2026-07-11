// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// libFuzzer harness: attacker bytes -> VerifyScript(scriptSig, scriptPubKey).
//
// Drives the script interpreter (EvalScript's opcode/stack/CScriptNum logic,
// P2SH recursion, CLEANSTACK/SIGPUSHONLY, the encoding checks) with fuzzer-
// controlled verification flags and two attacker-controlled scripts. A base
// (no-op) signature checker is used, so OP_CHECKSIG/OP_CHECKLOCKTIMEVERIFY etc.
// exercise the ENCODING/validation paths without needing real crypto or a tx.
//
// scope: the secp256k1-backed CPubKey::Verify/CheckLowS are stubbed (well-fuzzed
// upstream; the un-reviewed delta is the opcode interpreter, which runs in full).
//
// Build: see src/test/fuzz/build-script-fuzz.sh.

#include "script/interpreter.h"
#include "script/script.h"

#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3)
        return 0;

    // 2 bytes -> verification flags (covers all defined SCRIPT_VERIFY_* bits);
    // 1 byte -> split point between scriptSig and scriptPubKey.
    unsigned int flags = (unsigned int)data[0] | ((unsigned int)data[1] << 8);

    // VerifyScript documents (and asserts) flag-dependency invariants that every
    // real caller satisfies: WITNESS implies P2SH, and CLEANSTACK implies both.
    // Normalise arbitrary fuzzer flags to a valid combination so we exercise the
    // interpreter, not the intentional API-contract assertions.
    if (flags & SCRIPT_VERIFY_WITNESS)
        flags |= SCRIPT_VERIFY_P2SH;
    if (flags & SCRIPT_VERIFY_CLEANSTACK)
        flags |= (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
    const size_t body = size - 3;
    const size_t split = body ? ((size_t)data[2] * body / 256) : 0;

    const CScript scriptSig(data + 3, data + 3 + split);
    const CScript scriptPubKey(data + 3 + split, data + size);

    BaseSignatureChecker checker;
    ScriptError err;
    (void)VerifyScript(scriptSig, scriptPubKey, NULL, flags, checker, &err);

    return 0;
}
