#!/usr/bin/env bash
# Build the "addr" (vector<CAddress>) libFuzzer target under ASan+UBSan.
# Requires a configured tree (src/config/bitcoin-config.h).
set -euo pipefail
cd "$(dirname "$0")/../../.."
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/addr_fuzz}"
SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"
clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/addr.cpp" \
    "$SRC/test/fuzz/addr_shims.cpp" \
    "$SRC/protocol.cpp" \
    "$SRC/netaddress.cpp" \
    "$SRC/support/cleanse.cpp" \
    "$SRC/hash.cpp" \
    "$SRC/uint256.cpp" \
    "$SRC/utilstrencodings.cpp" \
    "$SRC/crypto/sha256.cpp" "$SRC/crypto/sha512.cpp" "$SRC/crypto/ripemd160.cpp" \
    "$SRC/crypto/sha1.cpp" "$SRC/crypto/hmac_sha512.cpp" \
    -lpthread -lcrypto \
    -o "$OUT"
echo "built: $OUT"
