#!/usr/bin/env bash
# Build the focused CAuxPow libFuzzer target under ASan+UBSan.
#
# A curated source closure (not the whole tree) is compiled with clang so the
# deserialize + check() code is fully sanitizer-instrumented; --gc-sections drops
# the unused CMerkleTx daemon-global baggage so no validation/net/util linkage is
# needed (LogPrintStr is shimmed in fuzz_shims.cpp).
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root (…/dogecoin-psbt)
SRC=src
OUT="${1:-/tmp/claude-1000/-home-bluezr-source-repos-dogecoin-psbt/4944105a-e188-4cc9-83c0-4618f4cddbdd/scratchpad/auxpow_fuzz}"

SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"

clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/auxpow.cpp" \
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
    "$SRC/crypto/sha256.cpp" \
    "$SRC/crypto/sha512.cpp" \
    "$SRC/crypto/ripemd160.cpp" \
    "$SRC/crypto/sha1.cpp" \
    "$SRC/crypto/hmac_sha512.cpp" \
    -lpthread -lcrypto \
    -o "$OUT"

echo "built: $OUT"
