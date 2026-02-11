// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_MODELS_BLOCK_HEADER_H
#define MW_MODELS_BLOCK_HEADER_H

#include <mw/common/Macros.h>
#include <mw/common/Traits.h>
#include <mw/models/crypto/BlindingFactor.h>
#include <serialize.h>
#include <memory>
#include <cstdint>

MW_NAMESPACE

/// MWEB block header containing the Merkle roots and aggregate offsets
/// that summarize the state of the extension block.
///
/// Fields:
///   height        - block height
///   output_root   - root of the output PMMR (Prunable Merkle Mountain Range)
///   kernel_root   - root of the kernel MMR
///   leafset_root  - root hash of the leafset bitmap
///   kernel_offset - aggregate kernel offset for all kernels
///   stealth_offset- aggregate stealth offset for all outputs
///   num_txos      - total number of transaction outputs in the PMMR
///   num_kernels   - total number of kernels in the kernel MMR
class Header : public Traits::IHashable
{
public:
    using CPtr = std::shared_ptr<const Header>;
    using Ptr = std::shared_ptr<Header>;

    Header()
        : m_height(0), m_numTXOs(0), m_numKernels(0) {}

    template<typename Stream>
    Header(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    Header(
        int32_t height,
        mw::Hash outputRoot,
        mw::Hash kernelRoot,
        mw::Hash leafsetRoot,
        BlindingFactor kernelOffset,
        BlindingFactor stealthOffset,
        uint64_t numTXOs,
        uint64_t numKernels)
        : m_height(height),
          m_outputRoot(std::move(outputRoot)),
          m_kernelRoot(std::move(kernelRoot)),
          m_leafsetRoot(std::move(leafsetRoot)),
          m_kernelOffset(std::move(kernelOffset)),
          m_stealthOffset(std::move(stealthOffset)),
          m_numTXOs(numTXOs),
          m_numKernels(numKernels)
    {
        m_hash = Hashed(*this);
    }

    //
    // Getters
    //
    int32_t GetHeight() const noexcept { return m_height; }
    const mw::Hash& GetOutputRoot() const noexcept { return m_outputRoot; }
    const mw::Hash& GetKernelRoot() const noexcept { return m_kernelRoot; }
    const mw::Hash& GetLeafsetRoot() const noexcept { return m_leafsetRoot; }
    const BlindingFactor& GetKernelOffset() const noexcept { return m_kernelOffset; }
    const BlindingFactor& GetStealthOffset() const noexcept { return m_stealthOffset; }
    uint64_t GetNumTXOs() const noexcept { return m_numTXOs; }
    uint64_t GetNumKernels() const noexcept { return m_numKernels; }

    //
    // IHashable
    //
    const mw::Hash& GetHash() const noexcept override {
        if (m_hash.IsNull()) {
            m_hash = Hashed(*this);
        }
        return m_hash;
    }

    //
    // Serialization
    //
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata32(s, m_height);
        s << m_outputRoot;
        s << m_kernelRoot;
        s << m_leafsetRoot;
        s << m_kernelOffset;
        s << m_stealthOffset;
        ser_writedata64(s, m_numTXOs);
        ser_writedata64(s, m_numKernels);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        m_height = ser_readdata32(s);
        s >> m_outputRoot;
        s >> m_kernelRoot;
        s >> m_leafsetRoot;
        s >> m_kernelOffset;
        s >> m_stealthOffset;
        m_numTXOs = ser_readdata64(s);
        m_numKernels = ser_readdata64(s);
        m_hash = mw::Hash(); // reset cached hash
    }

private:
    int32_t m_height;
    mw::Hash m_outputRoot;
    mw::Hash m_kernelRoot;
    mw::Hash m_leafsetRoot;
    BlindingFactor m_kernelOffset;
    BlindingFactor m_stealthOffset;
    uint64_t m_numTXOs;
    uint64_t m_numKernels;
    mutable mw::Hash m_hash;
};

END_NAMESPACE

#endif // MW_MODELS_BLOCK_HEADER_H
