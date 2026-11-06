// Copyright (c) 2023-2026 The Bitcoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bip352.h"

#include "bech32.h"
#include "chainparams.h"
#include "hash.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <algorithm>
#include <assert.h>
#include <string.h>

namespace bip352 {

namespace {

/** The context ECCVerifyHandle owns. Every caller in this file must hold a handle. */
const secp256k1_context* Ctx()
{
    const secp256k1_context* ctx = ECCVerifyContext();
    assert(ctx != NULL);
    return ctx;
}

const char* TAG_INPUTS = "BIP0352/Inputs";
const char* TAG_SHARED_SECRET = "BIP0352/SharedSecret";
const char* TAG_LABEL = "BIP0352/Label";

/** Serialized address payload: version || ser_p(B_scan) || ser_p(B_spend). */
const size_t ADDRESS_PAYLOAD_SIZE = 1 + 2 * CPubKey::COMPRESSED_SIZE;

void WriteBE32(std::vector<unsigned char>& out, uint32_t x)
{
    out.push_back((unsigned char)(x >> 24));
    out.push_back((unsigned char)(x >> 16));
    out.push_back((unsigned char)(x >> 8));
    out.push_back((unsigned char)x);
}

/** Parse a CPubKey into a secp256k1 point. Accepts compressed and uncompressed. */
bool LoadPubKey(secp256k1_pubkey& out, const CPubKey& key)
{
    return key.size() > 0 && secp256k1_ec_pubkey_parse(Ctx(), &out, key.begin(), key.size()) == 1;
}

/** Serialize a secp256k1 point as a 33-byte compressed CPubKey. */
CPubKey SavePubKeyCompressed(const secp256k1_pubkey& point)
{
    unsigned char buf[CPubKey::COMPRESSED_SIZE];
    size_t len = sizeof(buf);
    const int ret = secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &point, SECP256K1_EC_COMPRESSED);
    assert(ret == 1 && len == sizeof(buf));
    CPubKey key;
    key.Set(buf, buf + len);
    return key;
}

/* ECDH hash callback emitting ser_p(point): BIP352 consumes the compressed point, not a hash. */
int EcdhSerializeCompressed(unsigned char* output, const unsigned char* x32, const unsigned char* y32, void* data)
{
    (void)data;
    output[0] = (y32[31] & 0x01) | 0x02;
    memcpy(output + 1, x32, 32);
    return 1;
}

/**
 * shared_secret = scalar * point, serialized compressed.
 *
 * Both sides call this: the sender with (input_hash * a) and B_scan, the receiver with
 * (input_hash * b_scan) and A. Multiplying the scalars before the point saves one curve
 * multiplication over doing it the other way round.
 *
 * secp256k1_ecdh rather than ec_pubkey_tweak_mul: the latter reaches secp256k1_ecmult, which is
 * variable time in the scalar, and this scalar is secret. Both reject a zero or overflowing one.
 */
bool CreateSharedSecret(CPubKey& out, const CPubKey& point, const unsigned char* scalar32)
{
    secp256k1_pubkey p;
    if (!LoadPubKey(p, point)) return false;

    unsigned char buf[CPubKey::COMPRESSED_SIZE];
    if (!secp256k1_ecdh(Ctx(), buf, &p, scalar32, EcdhSerializeCompressed, NULL)) return false;
    out.Set(buf, buf + sizeof(buf));
    memory_cleanse(buf, sizeof(buf));
    return true;
}

/** t_k = hash_BIP0352/SharedSecret(ser_p(ecdh) || ser32(k)), rejected if not a valid scalar. */
bool CreateOutputTweak(uint256& out, const CPubKey& shared_secret, uint32_t k)
{
    std::vector<unsigned char> buf(shared_secret.begin(), shared_secret.begin() + shared_secret.size());
    WriteBE32(buf, k);
    out = TaggedHash(TAG_SHARED_SECRET, buf);
    // A hash landing on zero or past the curve order is negligibly unlikely, but BIP352 specifies
    // failing rather than clamping, and a sender and receiver must agree on which it is.
    return secp256k1_ec_seckey_verify(Ctx(), out.begin()) == 1;
}

/** P = base + tweak*G */
bool TweakPubKeyAdd(CPubKey& out, const CPubKey& base, const uint256& tweak)
{
    secp256k1_pubkey p;
    if (!LoadPubKey(p, base)) return false;
    if (!secp256k1_ec_pubkey_tweak_add(Ctx(), &p, tweak.begin())) return false;
    out = SavePubKeyCompressed(p);
    return true;
}

/** The P2PKH script committing to a public key. */
CScript ScriptForPubKey(const CPubKey& key)
{
    return GetScriptForDestination(CTxDestination(key.GetID()));
}

/** Order recipients by scan public key, then by original index to break ties deterministically. */
struct RecipientSort {
    bool operator()(const CRecipient& a, const CRecipient& b) const
    {
        const CPubKey& ka = a.address.GetScanPubKey();
        const CPubKey& kb = b.address.GetScanPubKey();
        const int cmp = memcmp(ka.begin(), kb.begin(), CPubKey::COMPRESSED_SIZE);
        if (cmp != 0) return cmp < 0;
        return a.index < b.index;
    }
};

} // namespace

uint256 TaggedHash(const std::string& tag, const std::vector<unsigned char>& data)
{
    unsigned char tag_hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write((const unsigned char*)tag.data(), tag.size()).Finalize(tag_hash);

    uint256 result;
    CSHA256()
        .Write(tag_hash, sizeof(tag_hash))
        .Write(tag_hash, sizeof(tag_hash))
        .Write(data.empty() ? NULL : &data[0], data.size())
        .Finalize(result.begin());
    return result;
}

std::vector<unsigned char> SerializeOutpoint(const COutPoint& outpoint)
{
    std::vector<unsigned char> ret;
    ret.reserve(36);
    ret.insert(ret.end(), outpoint.hash.begin(), outpoint.hash.end());
    const uint32_t n = outpoint.n;
    ret.push_back((unsigned char)n);
    ret.push_back((unsigned char)(n >> 8));
    ret.push_back((unsigned char)(n >> 16));
    ret.push_back((unsigned char)(n >> 24));
    return ret;
}

bool ComputeScanTweak(CPubKey& out, const CPrevoutsSummary& summary)
{
    if (summary.IsNull()) return false;
    return CreateSharedSecret(out, summary.pubkey_sum, summary.input_hash.begin());
}

bool GetSmallestOutpoint(COutPoint& out, const std::vector<CTxIn>& vin)
{
    if (vin.empty()) return false;
    // Compare the 36-byte serializations directly. uint256's own ordering happens to be a memcmp
    // here, but relying on that would couple this to a detail of uint256 rather than to BIP352.
    std::vector<unsigned char> best = SerializeOutpoint(vin[0].prevout);
    out = vin[0].prevout;
    for (size_t i = 1; i < vin.size(); ++i) {
        const std::vector<unsigned char> cur = SerializeOutpoint(vin[i].prevout);
        if (cur < best) {
            best = cur;
            out = vin[i].prevout;
        }
    }
    return true;
}

bool CSilentPaymentsAddress::Create(CSilentPaymentsAddress& out, const CPubKey& scan_pubkey, const CPubKey& spend_pubkey, uint8_t version)
{
    if (!scan_pubkey.IsFullyValid() || !scan_pubkey.IsCompressed()) return false;
    if (!spend_pubkey.IsFullyValid() || !spend_pubkey.IsCompressed()) return false;
    out.m_version = version;
    out.m_scan_pubkey = scan_pubkey;
    out.m_spend_pubkey = spend_pubkey;
    return true;
}

std::string EncodeSilentPaymentsAddress(const CSilentPaymentsAddress& address, const CChainParams& params)
{
    assert(address.IsValid());
    std::vector<unsigned char> payload;
    payload.reserve(ADDRESS_PAYLOAD_SIZE);
    payload.push_back(address.GetVersion());
    payload.insert(payload.end(), address.GetScanPubKey().begin(), address.GetScanPubKey().begin() + CPubKey::COMPRESSED_SIZE);
    payload.insert(payload.end(), address.GetSpendPubKey().begin(), address.GetSpendPubKey().begin() + CPubKey::COMPRESSED_SIZE);

    std::vector<unsigned char> values;
    values.reserve((ADDRESS_PAYLOAD_SIZE * 8 + 4) / 5);
    const bool ok = ConvertBits<8, 5, true>(values, payload.begin(), payload.end());
    assert(ok);
    return bech32::Encode(bech32::Encoding::BECH32M, params.SilentPaymentsHRP(), values);
}

bool DecodeSilentPaymentsAddress(CSilentPaymentsAddress& out, const std::string& str, const CChainParams& params, std::string& error)
{
    const bech32::DecodeResult dec = bech32::Decode(str, bech32::CharLimit::SILENT_PAYMENTS);
    if (dec.encoding == bech32::Encoding::INVALID) {
        error = "not a valid bech32m string";
        return false;
    }
    if (dec.encoding != bech32::Encoding::BECH32M) {
        error = "silent payments addresses are bech32m, not bech32";
        return false;
    }
    if (dec.hrp != params.SilentPaymentsHRP()) {
        error = strprintf("address is for a different network (expected prefix %s, got %s)", params.SilentPaymentsHRP(), dec.hrp);
        return false;
    }
    std::vector<unsigned char> payload;
    payload.reserve(ADDRESS_PAYLOAD_SIZE);
    if (!ConvertBits<5, 8, false>(payload, dec.data.begin(), dec.data.end())) {
        error = "address payload is not a whole number of bytes";
        return false;
    }
    if (payload.empty()) {
        error = "address payload is empty";
        return false;
    }
    // Unknown versions are rejected rather than ignored. A future version may change what the
    // payload means, and paying it under v0 rules would send coin somewhere unspendable.
    if (payload[0] != ADDRESS_VERSION) {
        error = strprintf("unknown address version %u", (unsigned)payload[0]);
        return false;
    }
    if (payload.size() != ADDRESS_PAYLOAD_SIZE) {
        error = strprintf("address payload is %u bytes, expected %u", (unsigned)payload.size(), (unsigned)ADDRESS_PAYLOAD_SIZE);
        return false;
    }
    CPubKey scan_pubkey, spend_pubkey;
    scan_pubkey.Set(payload.begin() + 1, payload.begin() + 1 + CPubKey::COMPRESSED_SIZE);
    spend_pubkey.Set(payload.begin() + 1 + CPubKey::COMPRESSED_SIZE, payload.end());
    if (!CSilentPaymentsAddress::Create(out, scan_pubkey, spend_pubkey, payload[0])) {
        error = "address contains an invalid public key";
        return false;
    }
    return true;
}

bool GetPubKeyFromInput(CPubKey& out, const CScript& scriptSig, const CScript& prevout_spk)
{
    txnouttype type;
    std::vector<std::vector<unsigned char> > solutions;
    if (!Solver(prevout_spk, type, solutions) || type != TX_PUBKEYHASH) return false;
    assert(solutions.size() == 1 && solutions[0].size() == 20);
    const uint160 pubkey_hash(solutions[0]);

    CScript::const_iterator pc = scriptSig.begin();
    while (pc < scriptSig.end()) {
        opcodetype opcode;
        std::vector<unsigned char> candidate;
        if (!scriptSig.GetOp(pc, opcode, candidate)) return false;
        if (candidate.size() != CPubKey::COMPRESSED_SIZE && candidate.size() != CPubKey::SIZE) continue;
        // 0x02/0x03 compressed or 0x04 uncompressed only. libsecp256k1 also parses the hybrid
        // encodings 0x06/0x07, so without this an implementation built on it would accept a key
        // that one checking the prefix rejects, and the two would compute different A. The chain
        // has none: zero across 1.68M eligible inputs sampled from 2014 to 2026. Excluding them
        // costs nothing real and removes a way for two readers to disagree.
        if (candidate[0] != 0x02 && candidate[0] != 0x03 && candidate[0] != 0x04) continue;
        if (Hash160(candidate) != pubkey_hash) continue;
        const CPubKey key(candidate.begin(), candidate.end());
        if (key.IsFullyValid()) {
            out = key;
            return true;
        }
    }
    return false;
}

PrevoutsSummaryError GetPrevoutsSummary(CPrevoutsSummary& out, const std::vector<CTxIn>& vin, const std::map<COutPoint, CScript>& prevout_spks)
{
    COutPoint smallest;
    if (!GetSmallestOutpoint(smallest, vin)) return PREVOUTS_NOT_ELIGIBLE;

    std::vector<secp256k1_pubkey> points;
    points.reserve(vin.size());
    for (size_t i = 0; i < vin.size(); ++i) {
        const std::map<COutPoint, CScript>::const_iterator it = prevout_spks.find(vin[i].prevout);
        if (it == prevout_spks.end()) return PREVOUTS_MISSING_COIN;
        CPubKey key;
        if (!GetPubKeyFromInput(key, vin[i].scriptSig, it->second)) {
            // Distinguish "this script type is out of scope" from "this one should have worked".
            txnouttype type;
            std::vector<std::vector<unsigned char> > solutions;
            if (Solver(it->second, type, solutions) && type == TX_PUBKEYHASH) {
                return PREVOUTS_UNREADABLE_INPUT;
            }
            continue;
        }
        secp256k1_pubkey point;
        if (!LoadPubKey(point, key)) continue;
        points.push_back(point);
    }
    if (points.empty()) return PREVOUTS_NOT_ELIGIBLE;

    std::vector<const secp256k1_pubkey*> ptrs(points.size());
    for (size_t i = 0; i < points.size(); ++i) ptrs[i] = &points[i];
    secp256k1_pubkey sum;
    // Fails when the eligible keys sum to the point at infinity, which a hostile sender can
    // arrange. Bail here so a scanner or index builder never does the rest of the work.
    if (!secp256k1_ec_pubkey_combine(Ctx(), &sum, &ptrs[0], ptrs.size())) {
        return PREVOUTS_NOT_ELIGIBLE;
    }
    out.pubkey_sum = SavePubKeyCompressed(sum);

    std::vector<unsigned char> buf = SerializeOutpoint(smallest);
    buf.insert(buf.end(), out.pubkey_sum.begin(), out.pubkey_sum.begin() + CPubKey::COMPRESSED_SIZE);
    out.input_hash = TaggedHash(TAG_INPUTS, buf);
    if (!secp256k1_ec_seckey_verify(Ctx(), out.input_hash.begin())) {
        return PREVOUTS_NOT_ELIGIBLE;
    }
    return PREVOUTS_OK;
}

bool CreateOutputs(std::map<size_t, CScript>& outputs, const std::vector<CRecipient>& recipients, const std::vector<CKey>& input_keys, const COutPoint& smallest_outpoint)
{
    outputs.clear();
    if (recipients.empty() || input_keys.empty()) return false;

    // a = sum of the eligible input private keys. Uncompressed inputs contribute the same scalar
    // as compressed ones, so nothing here depends on the encoding they were revealed in.
    unsigned char seckey_sum[32];
    memcpy(seckey_sum, input_keys[0].begin(), 32);
    if (!secp256k1_ec_seckey_verify(Ctx(), seckey_sum)) return false;
    for (size_t i = 1; i < input_keys.size(); ++i) {
        if (!input_keys[i].IsValid()) return false;
        if (!secp256k1_ec_seckey_tweak_add(Ctx(), seckey_sum, input_keys[i].begin())) {
            // The sum hit zero, so this input set cannot carry a silent payment at all.
            memory_cleanse(seckey_sum, sizeof(seckey_sum));
            return false;
        }
    }

    // A = a*G, always serialized compressed inside input_hash.
    CKey sum_key;
    sum_key.Set(seckey_sum, seckey_sum + 32, true);
    if (!sum_key.IsValid()) {
        memory_cleanse(seckey_sum, sizeof(seckey_sum));
        return false;
    }
    const CPubKey pubkey_sum = sum_key.GetPubKey();

    std::vector<unsigned char> buf = SerializeOutpoint(smallest_outpoint);
    buf.insert(buf.end(), pubkey_sum.begin(), pubkey_sum.begin() + CPubKey::COMPRESSED_SIZE);
    const uint256 input_hash = TaggedHash(TAG_INPUTS, buf);
    if (!secp256k1_ec_seckey_verify(Ctx(), input_hash.begin())) {
        memory_cleanse(seckey_sum, sizeof(seckey_sum));
        return false;
    }
    // Fold input_hash into the scalar, so the per-recipient work is one curve multiplication.
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), seckey_sum, input_hash.begin())) {
        memory_cleanse(seckey_sum, sizeof(seckey_sum));
        return false;
    }

    // Group by scan public key so k runs from 0 within each group, as BIP352 requires.
    std::vector<CRecipient> sorted(recipients);
    std::sort(sorted.begin(), sorted.end(), RecipientSort());

    bool ok = true;
    CPubKey shared_secret;
    uint32_t k = 0;
    for (size_t i = 0; i < sorted.size() && ok; ++i) {
        if (i == 0 || sorted[i].address.GetScanPubKey() != sorted[i - 1].address.GetScanPubKey()) {
            if (!CreateSharedSecret(shared_secret, sorted[i].address.GetScanPubKey(), seckey_sum)) {
                ok = false;
                break;
            }
            k = 0;
        }
        if (k >= RECIPIENT_GROUP_LIMIT) {
            // Past this a receiver would stop looking, so the output would be unfindable.
            ok = false;
            break;
        }
        uint256 t_k;
        CPubKey output_pubkey;
        if (!CreateOutputTweak(t_k, shared_secret, k) ||
            !TweakPubKeyAdd(output_pubkey, sorted[i].address.GetSpendPubKey(), t_k)) {
            ok = false;
            break;
        }
        outputs[sorted[i].index] = ScriptForPubKey(output_pubkey);
        ++k;
    }

    memory_cleanse(seckey_sum, sizeof(seckey_sum));
    if (!ok || outputs.size() != recipients.size()) {
        // A duplicated or out-of-range index would silently drop an output, so treat a short map
        // as a caller error rather than returning a partial set.
        outputs.clear();
        return false;
    }
    return true;
}

CSilentPaymentsReceiver::CSilentPaymentsReceiver(const CKey& scan_key, const CPubKey& spend_pubkey)
    : m_scan_key(scan_key), m_spend_pubkey(spend_pubkey), m_valid(false)
{
    if (!m_scan_key.IsValid()) return;
    if (!m_spend_pubkey.IsFullyValid() || !m_spend_pubkey.IsCompressed()) return;
    uint256 change_tweak;
    if (!CreateLabelTweak(change_tweak, CHANGE_LABEL_M)) return;
    m_labels[CHANGE_LABEL_M] = change_tweak;
    m_valid = true;
}

bool CSilentPaymentsReceiver::CreateLabelTweak(uint256& out, uint32_t m) const
{
    if (!m_scan_key.IsValid()) return false;
    std::vector<unsigned char> buf(m_scan_key.begin(), m_scan_key.begin() + 32);
    WriteBE32(buf, m);
    out = TaggedHash(TAG_LABEL, buf);
    return secp256k1_ec_seckey_verify(Ctx(), out.begin()) == 1;
}

bool CSilentPaymentsReceiver::GetAddress(CSilentPaymentsAddress& out) const
{
    if (!m_valid) return false;
    return CSilentPaymentsAddress::Create(out, m_scan_key.GetPubKey(), m_spend_pubkey);
}

bool CSilentPaymentsReceiver::GenerateLabeledAddress(CSilentPaymentsAddress& out, uint32_t m)
{
    if (!m_valid || m == CHANGE_LABEL_M) return false;
    uint256 tweak;
    if (!CreateLabelTweak(tweak, m)) return false;
    CPubKey labeled_spend;
    if (!TweakPubKeyAdd(labeled_spend, m_spend_pubkey, tweak)) return false;
    if (!CSilentPaymentsAddress::Create(out, m_scan_key.GetPubKey(), labeled_spend)) return false;
    m_labels[m] = tweak;
    return true;
}

bool CSilentPaymentsReceiver::GetChangeAddress(CSilentPaymentsAddress& out) const
{
    if (!m_valid) return false;
    const std::map<uint32_t, uint256>::const_iterator it = m_labels.find(CHANGE_LABEL_M);
    assert(it != m_labels.end());
    CPubKey labeled_spend;
    if (!TweakPubKeyAdd(labeled_spend, m_spend_pubkey, it->second)) return false;
    return CSilentPaymentsAddress::Create(out, m_scan_key.GetPubKey(), labeled_spend);
}

bool CSilentPaymentsReceiver::Scan(std::vector<CFoundOutput>& found, const CPrevoutsSummary& summary, const std::vector<CTxOut>& vout) const
{
    found.clear();
    if (!m_valid || summary.IsNull() || vout.empty()) return false;

    // ecdh = (b_scan * input_hash) * A. Folding input_hash into the scan key first keeps this to
    // one curve multiplication.
    unsigned char scan_scalar[32];
    memcpy(scan_scalar, m_scan_key.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), scan_scalar, summary.input_hash.begin())) {
        memory_cleanse(scan_scalar, sizeof(scan_scalar));
        return false;
    }
    CPubKey shared_secret;
    const bool got_secret = CreateSharedSecret(shared_secret, summary.pubkey_sum, scan_scalar);
    memory_cleanse(scan_scalar, sizeof(scan_scalar));
    if (!got_secret) return false;

    return ScanWithSecret(found, shared_secret, vout);
}

bool CSilentPaymentsReceiver::ScanWithTweak(std::vector<CFoundOutput>& found, const CPubKey& tweak_point, const std::vector<CTxOut>& vout) const
{
    found.clear();
    if (!m_valid || !tweak_point.IsValid() || vout.empty()) return false;

    // A tweak index has already folded input_hash into A, so the scan key applies directly.
    CPubKey shared_secret;
    if (!CreateSharedSecret(shared_secret, tweak_point, m_scan_key.begin())) return false;

    return ScanWithSecret(found, shared_secret, vout);
}

bool CSilentPaymentsReceiver::ScanWithSecret(std::vector<CFoundOutput>& found, const CPubKey& shared_secret, const std::vector<CTxOut>& vout) const
{
    found.clear();

    // Collect the pubkey hash of every P2PKH output. Everything else in the transaction cannot
    // be a silent payment under this scheme, so it never needs to be looked at again.
    std::vector<std::pair<uint160, size_t> > p2pkh;
    p2pkh.reserve(vout.size());
    for (size_t i = 0; i < vout.size(); ++i) {
        txnouttype type;
        std::vector<std::vector<unsigned char> > solutions;
        if (!Solver(vout[i].scriptPubKey, type, solutions) || type != TX_PUBKEYHASH) continue;
        p2pkh.push_back(std::make_pair(uint160(solutions[0]), i));
    }
    if (p2pkh.empty()) return true;

    // Flatten the labels once, so the per-k walk below is a plain indexed loop.
    std::vector<std::pair<uint32_t, uint256> > labels(m_labels.begin(), m_labels.end());

    const uint32_t k_max = std::min((uint32_t)p2pkh.size(), RECIPIENT_GROUP_LIMIT);
    std::vector<bool> consumed(p2pkh.size(), false);
    for (uint32_t k = 0; k < k_max; ++k) {
        uint256 t_k;
        CPubKey unlabeled;
        if (!CreateOutputTweak(t_k, shared_secret, k)) return false;
        if (!TweakPubKeyAdd(unlabeled, m_spend_pubkey, t_k)) return false;

        // A P2PKH output commits to hash160 of the key, not the key, so a label cannot be
        // recovered by subtracting the unlabeled output from it the way BIP352 does. Every known
        // label has to be tried forward instead, which is why holding many is expensive.
        bool matched = false;
        for (size_t attempt = 0; attempt <= labels.size() && !matched; ++attempt) {
            CPubKey candidate;
            uint256 tweak = t_k;
            bool with_label = false;
            uint32_t label_m = 0;
            if (attempt == 0) {
                candidate = unlabeled;
            } else {
                const std::pair<uint32_t, uint256>& label = labels[attempt - 1];
                if (!TweakPubKeyAdd(candidate, unlabeled, label.second)) continue;
                if (!secp256k1_ec_seckey_tweak_add(Ctx(), tweak.begin(), label.second.begin())) continue;
                with_label = true;
                label_m = label.first;
            }
            const CKeyID candidate_id = candidate.GetID();
            for (size_t j = 0; j < p2pkh.size(); ++j) {
                if (consumed[j] || p2pkh[j].first != candidate_id) continue;
                CFoundOutput out;
                out.vout = p2pkh[j].second;
                out.output_pubkey = candidate;
                out.tweak = tweak;
                out.found_with_label = with_label;
                out.label_m = label_m;
                found.push_back(out);
                consumed[j] = true;
                matched = true;
                break;
            }
        }
        // BIP352 stops at the first k with no output, since a sender that created k also created
        // every smaller k.
        if (!matched) break;
    }
    return true;
}

bool CSilentPaymentsReceiver::DeriveSpendingKey(CKey& out, const CKey& spend_key, const uint256& tweak)
{
    if (!spend_key.IsValid()) return false;
    unsigned char d[32];
    memcpy(d, spend_key.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_add(Ctx(), d, tweak.begin())) {
        memory_cleanse(d, sizeof(d));
        return false;
    }
    out.Set(d, d + 32, true);
    memory_cleanse(d, sizeof(d));
    return out.IsValid();
}

} // namespace bip352
