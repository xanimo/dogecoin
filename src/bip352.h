// Copyright (c) 2023-2026 The Bitcoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * BIP352 silent payments, adapted to P2PKH outputs.
 *
 * A receiver publishes one static address. Each payment to it lands on a fresh output that
 * cannot be linked to the address or to other payments. The sender derives the output from an
 * ECDH secret built from the public keys its own inputs reveal and the receiver's scan key; the
 * receiver recovers the same secret from those revealed input public keys.
 *
 * BIP352 pays to taproot, using x-only output keys. Dogecoin has no taproot, so outputs here are
 * ordinary P2PKH. The derivation is otherwise BIP352 unchanged, including the BIP0352 hash tags,
 * so the input_hash, shared secret and output tweak values match the BIP's own test vectors; only
 * the final output encoding differs. Two consequences of paying to a hash rather than a key:
 *
 *   - The output public key is committed in full (compressed, 33 bytes) rather than x-only, so
 *     there is no y-parity negation step on either side.
 *   - A receiver cannot recover a label by subtracting the unlabeled output from the output key,
 *     the way BIP352 does, because the transaction only reveals hash160 of the output key. Labels
 *     must be walked forward instead, one hash160 per label per k. Scanning cost is therefore
 *     linear in the number of labels in use, and a receiver should hold only the change label.
 *
 * Nothing here is consensus code. A mismatch between a sender's and a receiver's reading of these
 * rules does not fork the chain, it loses the payment.
 */

#ifndef BITCOIN_BIP352_H
#define BITCOIN_BIP352_H

#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/script.h"
#include "uint256.h"

#include <map>
#include <string>
#include <vector>

class CChainParams;

namespace bip352 {

/** Payload version of the only address format defined here. */
static const uint8_t ADDRESS_VERSION = 0;

/** Label reserved for the receiver's own change outputs. */
static const uint32_t CHANGE_LABEL_M = 0;

/**
 * Maximum number of outputs one sender may create for a single scan public key in one
 * transaction, and correspondingly the largest k a receiver will try. BIP352 fixes this at 2323
 * to bound scanning cost.
 */
static const uint32_t RECIPIENT_GROUP_LIMIT = 2323;

/** BIP0352 tagged hash. SHA256(SHA256(tag) || SHA256(tag) || data), as in BIP340. */
uint256 TaggedHash(const std::string& tag, const std::vector<unsigned char>& data);

/**
 * A silent payments address: a scan public key and a spend public key, where the spend key may
 * already carry a label tweak. Both keys are always compressed.
 */
class CSilentPaymentsAddress
{
public:
    CSilentPaymentsAddress() : m_version(ADDRESS_VERSION) {}

    /** Build an address. Returns false unless both keys are valid and compressed. */
    static bool Create(CSilentPaymentsAddress& out, const CPubKey& scan_pubkey, const CPubKey& spend_pubkey, uint8_t version = ADDRESS_VERSION);

    uint8_t GetVersion() const { return m_version; }
    const CPubKey& GetScanPubKey() const { return m_scan_pubkey; }
    const CPubKey& GetSpendPubKey() const { return m_spend_pubkey; }

    bool IsValid() const { return m_scan_pubkey.IsValid() && m_spend_pubkey.IsValid(); }

    friend bool operator==(const CSilentPaymentsAddress& a, const CSilentPaymentsAddress& b)
    {
        return a.m_version == b.m_version && a.m_scan_pubkey == b.m_scan_pubkey && a.m_spend_pubkey == b.m_spend_pubkey;
    }

private:
    uint8_t m_version;
    CPubKey m_scan_pubkey;
    CPubKey m_spend_pubkey;
};

/** Encode an address as bech32m under the chain's silent payments HRP. */
std::string EncodeSilentPaymentsAddress(const CSilentPaymentsAddress& address, const CChainParams& params);

/**
 * Decode a bech32m silent payments address. On failure returns false and sets error to a reason
 * fit to show a user.
 */
bool DecodeSilentPaymentsAddress(CSilentPaymentsAddress& out, const std::string& str, const CChainParams& params, std::string& error);

/**
 * Extract the public key an input reveals, for inputs eligible to derive a shared secret.
 *
 * Only P2PKH inputs are eligible. Dogecoin has no segwit, so every other script type either
 * reveals no single public key (bare multisig, P2SH) or reveals it only inside a redeem script
 * whose shape a sender cannot commit to. BIP352 excludes inputs with conditional branches or
 * several public keys for the same reason: a malicious participant in a collaborative
 * transaction could otherwise re-sign with a different key set after the outputs were derived.
 *
 * The public key is found by walking every data push in scriptSig and matching hash160 of each
 * candidate against the pubkey hash in the prevout script, as BIP352 requires. The last push is
 * not sufficient: P2PKH scriptSigs are third-party malleable, so `<dummy> OP_DROP <sig> <key>`
 * and similar remain valid, and a rule that only accepts the canonical two-push shape would make
 * a malleated payment invisible to its receiver. Evaluating the scriptSig is not safe either,
 * since a malleated one can leave a different key on the stack than validation would.
 *
 * Unlike BIP352, uncompressed (65-byte) keys are accepted. Plenty of Dogecoin P2PKH coin sits
 * behind them, and the scalar and the curve point are the same either way; A is always summed and
 * serialized compressed, so accepting them changes only which inputs are eligible. Measured at
 * 16.4% of eligible inputs in 2014 and under 2% since, so the tail is small but real and those
 * holders could not pay at all without sweeping first.
 *
 * Accepted prefixes are exactly 0x02, 0x03 and 0x04. The hybrid encodings 0x06 and 0x07 are
 * refused even though libsecp256k1 parses them, so that a reader which checks the prefix and one
 * which only calls the parser agree on the same A.
 *
 * @param[out] out        The revealed public key.
 * @param[in]  scriptSig  The input's scriptSig.
 * @param[in]  prevout_spk The scriptPubKey of the output being spent.
 * @return false if this input is not eligible.
 */
bool GetPubKeyFromInput(CPubKey& out, const CScript& scriptSig, const CScript& prevout_spk);

/**
 * The per-transaction values a receiver needs in order to scan it, derived from its inputs.
 *
 * `pubkey_sum` is A, the sum of every eligible input public key. `input_hash` is
 * hash_BIP0352/Inputs(outpoint_L || ser_p(A)), which binds the secret to this transaction's
 * inputs so that reusing the same input keys cannot produce the same output twice. The two are
 * kept apart rather than combined so a scanner can fold input_hash into its scan key and save a
 * curve multiplication per transaction.
 */
struct CPrevoutsSummary
{
    CPubKey pubkey_sum;
    uint256 input_hash;

    bool IsNull() const { return !pubkey_sum.IsValid(); }
};

enum PrevoutsSummaryError {
    PREVOUTS_OK,
    //! An input's prevout script was not supplied.
    PREVOUTS_MISSING_COIN,
    //! No input revealed an eligible public key, or the eligible keys summed to infinity, so this
    //! transaction cannot carry a silent payment.
    PREVOUTS_NOT_ELIGIBLE,
    //! A P2PKH input whose scriptSig yielded no push matching the prevout's pubkey hash.
    //!
    //! Never seen on mainnet: the whole chain to 6381544 has zero. It is an error rather than a
    //! skipped input because skipping is only safe while every implementation skips identically,
    //! and a looser reader that did recover a key would compute a different A and disagree about
    //! where the payment went. Failing is how that disagreement surfaces instead of losing coins.
    PREVOUTS_UNREADABLE_INPUT,
};

/**
 * Compute the prevouts summary for a transaction.
 *
 * `prevout_spks` must hold the scriptPubKey of every outpoint in vin; a missing entry is an error
 * rather than a skipped input, since silently skipping one would change A and lose the payment.
 * The smallest outpoint is taken over all inputs, eligible or not.
 */
PrevoutsSummaryError GetPrevoutsSummary(CPrevoutsSummary& out, const std::vector<CTxIn>& vin, const std::map<COutPoint, CScript>& prevout_spks);

/**
 * The 33-byte value a scanner needs per transaction: input_hash * A, compressed.
 *
 * Folding the two halves of the summary together here costs the indexer one curve multiplication
 * per transaction and saves the scanner nothing, since it multiplies by its scan key either way.
 * It is done because this value is what goes over the wire to a light client, where 33 bytes
 * against 65 is the difference that decides whether scanning on a phone is affordable.
 */
bool ComputeScanTweak(CPubKey& out, const CPrevoutsSummary& summary);

/** The smallest outpoint of a transaction's inputs, by BIP352's 36-byte lexicographic order. */
bool GetSmallestOutpoint(COutPoint& out, const std::vector<CTxIn>& vin);

/** Serialize an outpoint the way input_hash commits to it: txid little-endian, then vout little-endian. */
std::vector<unsigned char> SerializeOutpoint(const COutPoint& outpoint);

/** One output a sender was asked to create. */
struct CRecipient
{
    CSilentPaymentsAddress address;
    //! Position this output must take in the final vout array.
    size_t index;

    CRecipient() : index(0) {}
    CRecipient(const CSilentPaymentsAddress& a, size_t i) : address(a), index(i) {}
};

/**
 * Derive the P2PKH output scripts for a set of recipients.
 *
 * Recipients are grouped by scan public key and k runs from 0 within each group, so repeating an
 * address requests another output for the same receiver. Every returned output must appear in the
 * final transaction: dropping one shifts the k values the receiver walks and can hide the rest.
 *
 * `input_keys` must be the private keys of every eligible input, and the caller must own all of
 * them. A sender that cannot produce the key for an eligible input must not use this input set,
 * because the receiver will sum that input's public key regardless.
 *
 * @param[out] outputs           Output script per recipient, keyed by the recipient's index.
 * @param[in]  recipients        Recipients, whose index fields must cover 0..n-1 exactly once.
 * @param[in]  input_keys        Private keys of the eligible inputs.
 * @param[in]  smallest_outpoint The smallest outpoint over all inputs.
 * @return false if a group exceeds RECIPIENT_GROUP_LIMIT, the input keys sum to zero, or a key is
 *         invalid.
 */
bool CreateOutputs(std::map<size_t, CScript>& outputs, const std::vector<CRecipient>& recipients, const std::vector<CKey>& input_keys, const COutPoint& smallest_outpoint);

/** An output found while scanning, with what is needed to spend it. */
struct CFoundOutput
{
    //! Index in the transaction's vout.
    size_t vout;
    //! The output's full public key, as committed by hash160 in the script.
    CPubKey output_pubkey;
    //! Added to the spend private key to get this output's private key. Includes the label tweak
    //! when the output was found through a label.
    uint256 tweak;
    //! Whether the output was found through a label, and which one.
    bool found_with_label;
    uint32_t label_m;

    CFoundOutput() : vout(0), found_with_label(false), label_m(0) {}
};

/**
 * A receiver's scanning identity: its scan private key, its unlabeled spend public key, and the
 * labels it knows. The change label (m = 0) is always present.
 */
class CSilentPaymentsReceiver
{
public:
    /** Constructs invalid, so a receiver can be declared and built later. IsValid() says so. */
    CSilentPaymentsReceiver() : m_valid(false) {}

    CSilentPaymentsReceiver(const CKey& scan_key, const CPubKey& spend_pubkey);

    bool IsValid() const { return m_valid; }

    /** The address to publish. */
    bool GetAddress(CSilentPaymentsAddress& out) const;

    /**
     * Register label m and return the resulting address.
     *
     * Each registered label costs one more hash160 per k on every transaction scanned, since a
     * P2PKH output cannot be reduced to its key. Hand out labeled addresses sparingly.
     */
    bool GenerateLabeledAddress(CSilentPaymentsAddress& out, uint32_t m);

    /** The address this receiver's own change goes to, which is label m = 0. */
    bool GetChangeAddress(CSilentPaymentsAddress& out) const;

    /** label_tweak = hash_BIP0352/Label(scan_key || ser32(m)) */
    bool CreateLabelTweak(uint256& out, uint32_t m) const;

    /**
     * Scan a transaction's outputs for payments to this receiver.
     *
     * @param[out] found   Outputs found, in increasing k.
     * @param[in]  summary The transaction's prevouts summary.
     * @param[in]  vout    The transaction's outputs, in vout order.
     * @return false if scanning could not be performed; an empty `found` means no payment.
     */
    bool Scan(std::vector<CFoundOutput>& found, const CPrevoutsSummary& summary, const std::vector<CTxOut>& vout) const;

    /**
     * Scan against a precomputed tweak, input_hash * A, as a tweak index or a light client server
     * supplies it. Equivalent to Scan, for a caller that never sees the prevouts.
     */
    bool ScanWithTweak(std::vector<CFoundOutput>& found, const CPubKey& tweak_point, const std::vector<CTxOut>& vout) const;

    /**
     * Build the output scripts this receiver would own in a transaction with this tweak, for
     * every k below k_max and every label held.
     *
     * This is the one thing Scan cannot do for a light client: it needs the scripts before it
     * has the outputs, so it can ask a BIP158 filter whether the block is worth downloading at
     * all. k_max = 1 is enough to answer that, because a sender that created output k also
     * created every smaller one, so a transaction paying this receiver always has a k = 0
     * output. Scanning the block it fetches still walks k properly.
     */
    bool GetCandidateScripts(std::vector<CScript>& scripts, const CPubKey& tweak_point,
                             uint32_t k_max = 1) const;

    /**
     * The private key for a found output: d = b_spend + tweak (mod n). The caller supplies the
     * spend private key, which a scan-only receiver does not hold.
     */
    static bool DeriveSpendingKey(CKey& out, const CKey& spend_key, const uint256& tweak);

private:
    /** The half of scanning that both entry points share, once the shared secret is in hand. */
    bool ScanWithSecret(std::vector<CFoundOutput>& found, const CPubKey& shared_secret, const std::vector<CTxOut>& vout) const;

    CKey m_scan_key;
    CPubKey m_spend_pubkey;
    //! m -> label tweak, always containing m = 0.
    std::map<uint32_t, uint256> m_labels;
    bool m_valid;
};

} // namespace bip352

#endif // BITCOIN_BIP352_H
