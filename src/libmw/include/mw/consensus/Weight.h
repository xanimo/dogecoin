// Copyright (c) 2021 The Litecoin Core developers
// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MW_CONSENSUS_WEIGHT_H
#define MW_CONSENSUS_WEIGHT_H

#include <mw/consensus/Params.h>
#include <mw/models/tx/TxBody.h>
#include <mw/models/tx/PegOutCoin.h>
#include <script/script.h>
#include <numeric>
#include <utility>

/// Calculates the weight of MWEB transaction bodies and components.
/// Weight is a measure of the cost of including components in a block.
/// Inputs have zero base weight but extra_data contributes.
/// Kernels have a base weight of 2 (3 with stealth excess).
/// Outputs have a base weight of 17 (18 for standard outputs).
class Weight
{
public:
    /// Calculate total weight of a TxBody (inputs + kernels + outputs)
    static size_t Calculate(const mw::TxBody& tx_body)
    {
        size_t input_weight = std::accumulate(
            tx_body.GetInputs().begin(), tx_body.GetInputs().end(), (size_t)0,
            [](size_t sum, const mw::Input& input) {
                // Inputs themselves have 0 base weight; only extra data costs weight
                return sum + CalcInputWeight(input.GetExtraData());
            }
        );

        size_t kernel_weight = std::accumulate(
            tx_body.GetKernels().begin(), tx_body.GetKernels().end(), (size_t)0,
            [](size_t sum, const mw::Kernel& kernel) {
                size_t kern_weight = CalcKernelWeight(
                    kernel.HasStealthExcess(),
                    kernel.GetPegOuts(),
                    kernel.GetExtraData()
                );
                return sum + kern_weight;
            }
        );

        size_t output_weight = std::accumulate(
            tx_body.GetOutputs().begin(), tx_body.GetOutputs().end(), (size_t)0,
            [](size_t sum, const mw::Output& output) {
                return sum + CalcOutputWeight(output.HasStandardFields(), output.GetExtraData());
            }
        );

        return input_weight + kernel_weight + output_weight;
    }

    /// Check if a TxBody exceeds the maximum allowed block weight
    static bool ExceedsMaximum(const mw::TxBody& tx_body)
    {
        return tx_body.GetInputs().size() > mw::MAX_NUM_INPUTS || Calculate(tx_body) > mw::MAX_BLOCK_WEIGHT;
    }

    /// Weight contribution of an input's extra data
    static size_t CalcInputWeight(const std::vector<uint8_t>& extra_data = {})
    {
        return ExtraBytesToWeight(extra_data.size());
    }

    /// Weight of a kernel with a script-based pegout
    static size_t CalcKernelWeight(
        const bool has_stealth_excess,
        const CScript& pegout_script = CScript{},
        const std::vector<uint8_t>& extra_data = {})
    {
        size_t base_weight = has_stealth_excess ? mw::KERNEL_WITH_STEALTH_WEIGHT : mw::BASE_KERNEL_WEIGHT;
        return base_weight + ExtraBytesToWeight(pegout_script.size()) + ExtraBytesToWeight(extra_data.size());
    }

    /// Weight of a kernel given a vector of pegout coins
    static size_t CalcKernelWeight(
        const bool has_stealth_excess,
        const std::vector<mw::PegOutCoin>& pegouts = {},
        const std::vector<uint8_t>& extra_data = {})
    {
        size_t base_weight = has_stealth_excess ? mw::KERNEL_WITH_STEALTH_WEIGHT : mw::BASE_KERNEL_WEIGHT;

        size_t pegout_weight = std::accumulate(
            pegouts.begin(), pegouts.end(), (size_t)0,
            [](size_t sum, const mw::PegOutCoin& pegout) {
                return sum + ExtraBytesToWeight(pegout.GetScriptPubKey().size());
            }
        );

        return base_weight + pegout_weight + ExtraBytesToWeight(extra_data.size());
    }

    /// Weight of an output, with optional standard fields and extra data
    static size_t CalcOutputWeight(const bool standard_fields, const std::vector<uint8_t>& extra_data = {})
    {
        size_t base_weight = standard_fields ? mw::STANDARD_OUTPUT_WEIGHT : mw::BASE_OUTPUT_WEIGHT;
        return base_weight + ExtraBytesToWeight(extra_data.size());
    }

private:
    /// Convert extra data byte count to weight units
    static size_t ExtraBytesToWeight(const size_t extra_bytes)
    {
        return (extra_bytes + (mw::BYTES_PER_WEIGHT - 1)) / mw::BYTES_PER_WEIGHT;
    }
};

#endif // MW_CONSENSUS_WEIGHT_H
