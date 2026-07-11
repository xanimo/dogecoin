#!/usr/bin/env bash
# Build the "headers" (vector<CBlockHeader>) libFuzzer target under ASan+UBSan.
# Reuses the auxpow closure (each header carries an optional auxpow); fuzz_shims
# supplies LogPrintStr + scrypt/CMerkleTx daemon stubs.
# Requires a configured tree (src/config/bitcoin-config.h).
set -euo pipefail
cd "$(dirname "$0")/../../.."
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/headers_fuzz}"
SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"
clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/headers.cpp" \
    "$SRC/test/fuzz/fuzz_shims.cpp" \
    "$SRC/auxpow.cpp" \
    "$SRC/support/cleanse.cpp" \
    "$SRC/primitives/transaction.cpp" \
    "$SRC/primitives/pureheader.cpp" \
    "$SRC/consensus/merkle.cpp" \
    "$SRC/script/script.cpp" \
    "$SRC/hash.cpp" \
    "$SRC/arith_uint256.cpp" \
    "$SRC/uint256.cpp" \
    "$SRC/utilstrencodings.cpp" \
    "$SRC/crypto/sha256.cpp" "$SRC/crypto/sha512.cpp" "$SRC/crypto/ripemd160.cpp" \
    "$SRC/crypto/sha1.cpp" "$SRC/crypto/hmac_sha512.cpp" \
    -lpthread -lcrypto \
    -o "$OUT"
echo "built: $OUT"
