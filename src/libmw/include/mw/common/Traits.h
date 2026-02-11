// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_COMMON_TRAITS_H
#define MW_COMMON_TRAITS_H

#include <mw/common/Macros.h>
#include <serialize.h>
#include <uint256.h>
#include <hash.h>
#include <streams.h>

#include <memory>
#include <vector>
#include <string>
#include <cstdint>

MW_NAMESPACE

/// Hash type used throughout the MW library (32-byte hash)
class Hash {
public:
    static constexpr size_t size() { return 32; }

    Hash() { memset(m_data, 0, 32); }
    Hash(const uint256& hash) { memcpy(m_data, hash.begin(), 32); }
    explicit Hash(const std::vector<uint8_t>& data) {
        assert(data.size() == 32);
        memcpy(m_data, data.data(), 32);
    }
    explicit Hash(std::vector<uint8_t>&& data) {
        assert(data.size() == 32);
        memcpy(m_data, data.data(), 32);
    }

    const uint8_t* data() const { return m_data; }
    uint8_t* data() { return m_data; }
    const uint8_t* begin() const { return m_data; }
    const uint8_t* end() const { return m_data + 32; }

    std::vector<uint8_t> vec() const { return std::vector<uint8_t>(m_data, m_data + 32); }
    uint256 ToUInt256() const {
        uint256 result;
        memcpy(result.begin(), m_data, 32);
        return result;
    }

    bool IsNull() const {
        for (int i = 0; i < 32; i++) {
            if (m_data[i] != 0) return false;
        }
        return true;
    }

    bool operator==(const Hash& rhs) const { return memcmp(m_data, rhs.m_data, 32) == 0; }
    bool operator!=(const Hash& rhs) const { return !(*this == rhs); }
    bool operator<(const Hash& rhs) const { return memcmp(m_data, rhs.m_data, 32) < 0; }

    std::string GetHex() const { return ToUInt256().GetHex(); }

    template<typename Stream>
    void Serialize(Stream& s) const {
        s.write((const char*)m_data, 32);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s.read((char*)m_data, 32);
    }

private:
    uint8_t m_data[32];
};

/// Compute a hash from serializable data
template<typename T>
Hash Hashed(const T& obj) {
    CHashWriter ss(SER_GETHASH, 0);
    ss << obj;
    return Hash(ss.GetHash());
}

namespace Traits {

/// Interface for objects that can be serialized to bytes
class ISerializable {
public:
    virtual ~ISerializable() = default;
    virtual std::vector<uint8_t> Serialized() const = 0;
};

/// Interface for objects that have a string representation
class IPrintable {
public:
    virtual ~IPrintable() = default;
    virtual std::string Format() const = 0;
};

/// Interface for objects that have a Pedersen commitment
class ICommitted {
public:
    virtual ~ICommitted() = default;
};

/// Interface for objects that have a hash identifier
class IHashable {
public:
    virtual ~IHashable() = default;
    virtual const mw::Hash& GetHash() const = 0;
};

} // namespace Traits

END_NAMESPACE

/// Macro to implement Serialized() and static Deserialize() from SERIALIZE_METHODS
#define IMPL_SERIALIZED(T) \
    std::vector<uint8_t> Serialized() const { \
        CDataStream ss(SER_DISK, PROTOCOL_VERSION); \
        ss << *this; \
        return std::vector<uint8_t>(ss.begin(), ss.end()); \
    } \
    static T Deserialize(const std::vector<uint8_t>& bytes) { \
        CDataStream ss(bytes, SER_DISK, PROTOCOL_VERSION); \
        T obj; \
        ss >> obj; \
        return obj; \
    }

#define IMPL_SERIALIZABLE(T, obj) \
    IMPL_SERIALIZED(T)

#endif // MW_COMMON_TRAITS_H
