#!/usr/bin/env bash
# Build the CBloomFilter (BIP37 filterload) libFuzzer target under ASan+UBSan.
#
# Light closure: bloom.cpp + transaction/script (IsRelevantAndUpdate + the
# COutPoint/uint256 insert/contains overloads) + hash (MurmurHash3). GetRand and
# LogPrintStr are stubbed (bloom_shims.cpp) so no random/util linkage is needed.
#
# Requires a configured tree (src/config/bitcoin-config.h — run ./configure once).
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/bloom_fuzz}"

SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"

clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/bloom.cpp" \
    "$SRC/test/fuzz/bloom_shims.cpp" \
    "$SRC/bloom.cpp" \
    "$SRC/support/cleanse.cpp" \
    "$SRC/primitives/transaction.cpp" \
    "$SRC/script/script.cpp" \
    "$SRC/script/standard.cpp" \
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
