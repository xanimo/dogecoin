// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_TX_KERNEL_H
#define MW_MODELS_TX_KERNEL_H

#include <mw/common/Traits.h>
#include <mw/models/crypto/Commitment.h>
#include <mw/models/crypto/Signature.h>
#include <mw/models/tx/PegInCoin.h>
#include <mw/models/tx/PegOutCoin.h>
#include <amount.h>
#include <serialize.h>
#include <vector>
#include <memory>

MW_NAMESPACE

/// A MimbleWimble transaction kernel.
/// Kernels contain the excess value (commitment to zero) and the signature
/// proving the excess is valid. They also carry optional features like
/// fee, peg-in, peg-out, height lock, stealth excess, and extra data.
class Kernel : public Traits::IHashable {
public:
    enum FeatureBit : uint8_t {
        FEE_FEATURE_BIT             = 0x01,
        PEGIN_FEATURE_BIT           = 0x02,
        PEGOUT_FEATURE_BIT          = 0x04,
        HEIGHT_LOCK_FEATURE_BIT     = 0x08,
        STEALTH_EXCESS_FEATURE_BIT  = 0x10,
        EXTRA_DATA_FEATURE_BIT      = 0x20,
        ALL_FEATURE_BITS            = 0x3F
    };

    using CPtr = std::shared_ptr<const Kernel>;
    using Ptr = std::shared_ptr<Kernel>;

    Kernel() : m_features(0), m_fee(0), m_pegin(0), m_lockHeight(0) {}

    // Getters
    uint8_t GetFeatures() const { return m_features; }
    CAmount GetFee() const { return m_fee; }
    CAmount GetPegIn() const { return m_pegin; }
    const std::vector<PegOutCoin>& GetPegOuts() const { return m_pegouts; }
    int32_t GetLockHeight() const { return m_lockHeight; }
    const Commitment& GetExcess() const { return m_excess; }
    const Signature& GetSignature() const { return m_signature; }
    const mw::Hash& GetKernelID() const { return GetHash(); }

    bool HasFee() const { return m_features & FEE_FEATURE_BIT; }
    bool HasPegIn() const { return m_features & PEGIN_FEATURE_BIT; }
    bool HasPegOut() const { return m_features & PEGOUT_FEATURE_BIT; }
    bool HasHeightLock() const { return m_features & HEIGHT_LOCK_FEATURE_BIT; }
    bool HasStealthExcess() const { return m_features & STEALTH_EXCESS_FEATURE_BIT; }
    bool HasExtraData() const { return m_features & EXTRA_DATA_FEATURE_BIT; }
    bool IsStandard() const { return m_features < EXTRA_DATA_FEATURE_BIT; }
    const std::vector<uint8_t>& GetExtraData() const { return m_extraData; }

    /// The supply change introduced by this kernel (pegin - pegout amounts)
    CAmount GetSupplyChange() const {
        CAmount pegout_total = 0;
        for (const auto& pegout : m_pegouts) {
            pegout_total += pegout.GetAmount();
        }
        return m_pegin - pegout_total;
    }

    const mw::Hash& GetHash() const override {
        if (m_hash.IsNull()) {
            m_hash = Hashed(*this);
        }
        return m_hash;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s << m_features;
        if (m_features & FEE_FEATURE_BIT) ser_writedata64(s, m_fee);
        if (m_features & PEGIN_FEATURE_BIT) ser_writedata64(s, m_pegin);
        if (m_features & PEGOUT_FEATURE_BIT) {
            WriteCompactSize(s, m_pegouts.size());
            for (const auto& pegout : m_pegouts) {
                s << pegout;
            }
        }
        if (m_features & HEIGHT_LOCK_FEATURE_BIT) ser_writedata32(s, m_lockHeight);
        if (m_features & STEALTH_EXCESS_FEATURE_BIT) s << m_stealthExcess;
        if (m_features & EXTRA_DATA_FEATURE_BIT) {
            WriteCompactSize(s, m_extraData.size());
            s.write((const char*)m_extraData.data(), m_extraData.size());
        }
        s << m_excess;
        s << m_signature;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> m_features;
        if (m_features & FEE_FEATURE_BIT) m_fee = ser_readdata64(s);
        else m_fee = 0;
        if (m_features & PEGIN_FEATURE_BIT) m_pegin = ser_readdata64(s);
        else m_pegin = 0;
        if (m_features & PEGOUT_FEATURE_BIT) {
            size_t count = ReadCompactSize(s);
            m_pegouts.resize(count);
            for (auto& pegout : m_pegouts) {
                s >> pegout;
            }
        } else {
            m_pegouts.clear();
        }
        if (m_features & HEIGHT_LOCK_FEATURE_BIT) m_lockHeight = ser_readdata32(s);
        else m_lockHeight = 0;
        if (m_features & STEALTH_EXCESS_FEATURE_BIT) s >> m_stealthExcess;
        else m_stealthExcess = PublicKey();
        if (m_features & EXTRA_DATA_FEATURE_BIT) {
            size_t len = ReadCompactSize(s);
            m_extraData.resize(len);
            s.read((char*)m_extraData.data(), len);
        } else {
            m_extraData.clear();
        }
        s >> m_excess;
        s >> m_signature;
        m_hash = mw::Hash(); // reset cached hash
    }

private:
    uint8_t m_features;
    CAmount m_fee;
    CAmount m_pegin;
    std::vector<PegOutCoin> m_pegouts;
    int32_t m_lockHeight;
    PublicKey m_stealthExcess;
    std::vector<uint8_t> m_extraData;
    Commitment m_excess;
    Signature m_signature;
    mutable mw::Hash m_hash;
};

END_NAMESPACE

#endif // MW_MODELS_TX_KERNEL_H
