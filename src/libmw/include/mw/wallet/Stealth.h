// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_WALLET_STEALTH_H
#define MW_WALLET_STEALTH_H

#include <mw/common/Macros.h>
#include <mw/models/tx/Output.h>
#include <mw/crypto/Keys.h>
#include <mw/crypto/Pedersen.h>
#include <mw/crypto/Bulletproof.h>

#include <hash.h>
#include <uint256.h>

#include <memory>
#include <vector>

MW_NAMESPACE
namespace wallet {

// A recipient's stealth address: a scan key (used to detect incoming outputs)
// and a spend key (used to authorize spending them). Published once; every
// payment to it is unlinkable.
struct StealthAddress {
    PublicKey scan;  // A = a*G
    PublicKey spend; // B = b*G
};

// Result of building a stealth output: the output plus the blind, which the
// recipient can independently recover from the shared secret.
struct StealthResult {
    Output output;
    BlindingFactor blind;
};

// One-sided (stealth) payments. The sender derives an ECDH shared secret with
// the recipient's scan key and from it a per-output blind and a one-time spend
// key B + tweak*G; the recipient recovers both via the symmetric ECDH, so no
// interaction is needed and outputs are unlinkable.
class Stealth {
public:
    // Sender: pay `value` to `address`, using ephemeral secret `ephemeralKey`.
    static StealthResult Send(const StealthAddress& address, uint64_t value, const SecretKey& ephemeralKey)
    {
        const SecretKey shared = Keys::ECDH(ephemeralKey, address.scan); // e*A
        const BlindingFactor blind = ToBlind(shared);
        const SecretKey tweak = Tweak(shared);

        // Ephemeral pubkey R = e*G goes in the output so the recipient can
        // recompute the shared secret; the one-time key is B + tweak*G.
        const PublicKey R = Keys::PublicKeyFrom(ephemeralKey);
        const PublicKey oneTimeKey = Keys::AddPublicKeys(address.spend, Keys::PublicKeyFrom(tweak));

        const Commitment commit = Pedersen::Commit(value, blind);
        auto proof = std::make_shared<RangeProof>(Bulletproof::Prove(value, blind));

        Output output(commit, R, oneTimeKey, OutputMessage(), proof, Signature());
        return StealthResult{ output, blind };
    }

    // Recipient: is this output addressed to (scanKey, spendPubKey)?
    static bool IsMine(const Output& output, const SecretKey& scanKey, const PublicKey& spendPubKey)
    {
        const SecretKey shared = Keys::ECDH(scanKey, output.GetSenderPubKey()); // a*R = e*A
        const PublicKey expected = Keys::AddPublicKeys(spendPubKey, Keys::PublicKeyFrom(Tweak(shared)));
        return expected == output.GetReceiverPubKey();
    }

    // Recipient: recover the blinding factor (needed to spend / reconstruct).
    static BlindingFactor RecoverBlind(const Output& output, const SecretKey& scanKey)
    {
        return ToBlind(Keys::ECDH(scanKey, output.GetSenderPubKey()));
    }

    // Recipient: the private key that authorizes spending this output
    // (spendKey + tweak), whose public key is the output's one-time key.
    static SecretKey RecoverSpendKey(const Output& output, const SecretKey& scanKey, const SecretKey& spendKey)
    {
        const SecretKey shared = Keys::ECDH(scanKey, output.GetSenderPubKey());
        return Keys::AddSecretKeys(spendKey, Tweak(shared));
    }

private:
    static BlindingFactor ToBlind(const SecretKey& s)
    {
        return BlindingFactor(std::vector<uint8_t>(s.data(), s.data() + SecretKey::SIZE));
    }

    // Domain-separated scalar derived from the shared secret, used to offset the
    // recipient's spend key into a fresh one-time key per output.
    static SecretKey Tweak(const SecretKey& shared)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss.write(reinterpret_cast<const char*>(shared.data()), SecretKey::SIZE);
        ss << static_cast<uint8_t>('T');
        const uint256 h = ss.GetHash();
        return SecretKey(std::vector<uint8_t>(h.begin(), h.end()));
    }
};

}
END_NAMESPACE

#endif // MW_WALLET_STEALTH_H
