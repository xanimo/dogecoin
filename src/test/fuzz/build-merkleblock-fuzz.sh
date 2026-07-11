#!/usr/bin/env bash
# Build the CPartialMerkleTree (BIP37 merkleblock) libFuzzer target under ASan+UBSan.
#
# A small curated closure — CPartialMerkleTree has light dependencies (hash +
# uint256 + utilstrencodings only; no transaction/mempool/net linkage), so no
# daemon stubs are needed. merkleblock.cpp has no logging/error() references.
#
# Requires a configured tree (src/config/bitcoin-config.h must exist — run
# ./configure once first).
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/merkleblock_fuzz}"

SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"

clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/merkleblock.cpp" \
    "$SRC/test/fuzz/merkleblock_shims.cpp" \
    "$SRC/merkleblock.cpp" \
    "$SRC/support/cleanse.cpp" \
    "$SRC/hash.cpp" \
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
