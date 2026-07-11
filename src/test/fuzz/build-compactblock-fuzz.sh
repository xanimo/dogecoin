#!/usr/bin/env bash
# Build the BIP152 compact-block (CBlockHeaderAndShortTxIDs) libFuzzer target
# under ASan+UBSan.
#
# The deserializer is header-inline (blockencodings.h), so blockencodings.cpp is
# NOT compiled (it would drag txmempool/validation via InitData/FillBlock);
# FillShortTxIDSelector/GetShortID are provided by compactblock_shims.cpp. The
# header carries an optional auxpow, so the auxpow closure is linked;
# fuzz_shims.cpp supplies LogPrintStr + the scrypt/CMerkleTx daemon stubs.
#
# Requires a configured tree (src/config/bitcoin-config.h — run ./configure once).
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/compactblock_fuzz}"

SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"

clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" \
    "$SRC/test/fuzz/compactblock.cpp" \
    "$SRC/test/fuzz/compactblock_shims.cpp" \
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
