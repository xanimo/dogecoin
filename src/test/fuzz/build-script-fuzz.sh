#!/usr/bin/env bash
# Build the script-interpreter (VerifyScript) libFuzzer target under ASan+UBSan.
# CPubKey::Verify/CheckLowS (secp256k1) are stubbed (script_shims.cpp) so no
# secp/ECC linkage is needed. Requires a configured tree (src/config/bitcoin-config.h).
set -euo pipefail
cd "$(dirname "$0")/../../.."
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/script_fuzz}"
SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"
clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/script.cpp" \
    "$SRC/test/fuzz/script_shims.cpp" \
    "$SRC/script/interpreter.cpp" \
    "$SRC/script/script.cpp" \
    "$SRC/script/script_error.cpp" \
    "$SRC/support/cleanse.cpp" \
    "$SRC/hash.cpp" \
    "$SRC/uint256.cpp" \
    "$SRC/utilstrencodings.cpp" \
    "$SRC/crypto/sha256.cpp" "$SRC/crypto/sha512.cpp" "$SRC/crypto/ripemd160.cpp" \
    "$SRC/crypto/sha1.cpp" "$SRC/crypto/hmac_sha512.cpp" \
    -lpthread -lcrypto \
    -o "$OUT"
echo "built: $OUT"
