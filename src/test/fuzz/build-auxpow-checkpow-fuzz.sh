#!/usr/bin/env bash
# Build the full-entry-point CheckAuxPowProofOfWork libFuzzer target under ASan+UBSan.
#
# Extends the check()-only target's curated closure with dogecoin.cpp
# (CheckAuxPowProofOfWork) and pow.cpp (CheckProofOfWork). -ffunction-sections +
# --gc-sections drops the unreferenced retarget/subsidy/GetNextWorkRequired code so
# no validation/net/mempool linkage is needed (daemon globals shimmed in
# fuzz_shims.cpp; scrypt stubbed there too). dogecoin.cpp needs boost/random headers.
#
# Requires a configured tree (src/config/bitcoin-config.h must exist — run
# ./configure once first), same as build-auxpow-fuzz.sh.
set -euo pipefail

cd "$(dirname "$0")/../../.."   # repo root
SRC=src
OUT="${1:-${TMPDIR:-/tmp}/auxpow_checkpow_fuzz}"

# boost/random headers (dogecoin.cpp needs them) + boost_system lib from the
# configured depends tree. Override DEPENDS for your host, e.g.
#   DEPENDS=/path/to/depends/<host-triplet> ./build-auxpow-checkpow-fuzz.sh
DEPENDS="${DEPENDS:-/home/bluezr/source/repos/dogecoin/depends/x86_64-pc-linux-gnu}"
BOOST_INC="-I$DEPENDS/include"

SANFLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=address,undefined"

clang++ -std=c++11 -gdwarf-4 -O1 $SANFLAGS \
    -fvisibility=hidden -fvisibility-inlines-hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--no-export-dynamic \
    -DHAVE_CONFIG_H -I "$SRC" -I "$SRC/config" $BOOST_INC \
    "$SRC/test/fuzz/auxpow_checkpow.cpp" \
    "$SRC/test/fuzz/fuzz_shims.cpp" \
    "$SRC/test/fuzz/checkpow_shims.cpp" \
    "$SRC/dogecoin.cpp" \
    "$SRC/pow.cpp" \
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
    -L"$DEPENDS/lib" -lboost_system-mt \
    -lpthread -lcrypto \
    -o "$OUT"

echo "built: $OUT"
