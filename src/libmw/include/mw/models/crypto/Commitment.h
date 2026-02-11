// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_CRYPTO_COMMITMENT_H
#define MW_MODELS_CRYPTO_COMMITMENT_H

#include <mw/common/Traits.h>
#include <serialize.h>
#include <vector>
#include <cstring>
#include <string>
#include <memory>

MW_NAMESPACE

/// 33-byte Pedersen commitment (compressed point on the curve)
class Commitment {
public:
    static constexpr size_t SIZE = 33;
    using CPtr = std::shared_ptr<const Commitment>;

    Commitment() { memset(m_data, 0, SIZE); }
    explicit Commitment(const std::vector<uint8_t>& data) {
        assert(data.size() == SIZE);
        memcpy(m_data, data.data(), SIZE);
    }
    explicit Commitment(const uint8_t* data) {
        memcpy(m_data, data, SIZE);
    }

    bool operator==(const Commitment& rhs) const { return memcmp(m_data, rhs.m_data, SIZE) == 0; }
    bool operator!=(const Commitment& rhs) const { return !(*this == rhs); }
    bool operator<(const Commitment& rhs) const { return memcmp(m_data, rhs.m_data, SIZE) < 0; }

    const uint8_t* data() const { return m_data; }
    std::vector<uint8_t> vec() const { return std::vector<uint8_t>(m_data, m_data + SIZE); }

    bool IsNull() const {
        for (size_t i = 0; i < SIZE; i++) {
            if (m_data[i] != 0) return false;
        }
        return true;
    }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s.write((const char*)m_data, SIZE);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s.read((char*)m_data, SIZE);
    }

private:
    uint8_t m_data[SIZE];
};

END_NAMESPACE

#endif // MW_MODELS_CRYPTO_COMMITMENT_H
