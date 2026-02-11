// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_CRYPTO_RANGEPROOF_H
#define MW_MODELS_CRYPTO_RANGEPROOF_H

#include <mw/common/Traits.h>
#include <serialize.h>
#include <vector>
#include <memory>

MW_NAMESPACE

/// Variable-length Bulletproof range proof
class RangeProof : public Traits::IHashable {
public:
    using CPtr = std::shared_ptr<const RangeProof>;
    using Ptr = std::shared_ptr<RangeProof>;

    RangeProof() = default;
    explicit RangeProof(const std::vector<uint8_t>& data) : m_data(data) {}
    explicit RangeProof(std::vector<uint8_t>&& data) : m_data(std::move(data)) {}

    const mw::Hash& GetHash() const override {
        if (m_hash.IsNull() && !m_data.empty()) {
            m_hash = Hashed(*this);
        }
        return m_hash;
    }

    const std::vector<uint8_t>& GetProofData() const { return m_data; }
    size_t size() const { return m_data.size(); }
    bool empty() const { return m_data.empty(); }

    template<typename Stream>
    void Serialize(Stream& s) const {
        WriteCompactSize(s, m_data.size());
        s.write((const char*)m_data.data(), m_data.size());
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        size_t len = ReadCompactSize(s);
        m_data.resize(len);
        s.read((char*)m_data.data(), len);
        m_hash = mw::Hash(); // reset cached hash
    }

private:
    std::vector<uint8_t> m_data;
    mutable mw::Hash m_hash;
};

END_NAMESPACE

#endif // MW_MODELS_CRYPTO_RANGEPROOF_H
