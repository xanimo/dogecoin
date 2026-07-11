// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The interpreter references two secp256k1-backed CPubKey methods
// (Verify via TransactionSignatureChecker::VerifySignature, and CheckLowS via
// CheckSignatureEncoding). Neither is the un-reviewed script delta and both wrap
// well-fuzzed libsecp256k1; stub them so the harness needs no secp/ECC context.
// The interpreter's own DER/encoding checks (IsValidSignatureEncoding etc.) still
// run on attacker bytes.

#include "pubkey.h"

bool CPubKey::Verify(const uint256& /*hash*/, const std::vector<unsigned char>& /*vchSig*/) const { return false; }
bool CPubKey::CheckLowS(const std::vector<unsigned char>& /*vchSig*/) { return true; }
