// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /**
     * SegWit (BIP141/143/147) activation via AuxPoW-safe version-5 supermajority.
     * Phase 0 activation substrate (DIP dip-xanimo-auxpow-versionbits): SegWit
     * activates when nSegwitEnforceVersion (>=5) base-version blocks reach a
     * supermajority within nMajorityWindow, at or after nSegwitStartHeight.
     * Uses IsSuperMajority (BIP34/65 mechanism), which reads GetBaseVersion()
     * (nVersion % VERSION_AUXPOW) and therefore never touches the AuxPoW chain
     * ID in nVersion bits 16-31 -- no versionbits, no nVersion collision.
     */
    int nSegwitStartHeight;
    int nSegwitEnforceVersion;
    /**
     * Whether SegWit is scheduled on this chain at all, i.e. whether the
     * version-5 gate can ever activate. Sites that need "is segwit part of
     * this chain's rules" (witness commitment generation, NODE_WITNESS
     * advertisement) must use this rather than the BIP9 DEPLOYMENT_SEGWIT
     * timeout, which is 0 (disabled) on mainnet and testnet and says nothing
     * about the version-5 gate. Distinct from IsWitnessEnabled(), which
     * answers whether segwit has already activated at a given block.
     */
    bool IsSegwitConfigured() const { return nSegwitEnforceVersion > 0; }
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    uint32_t nCoinbaseMaturity;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }

    /** Dogecoin-specific parameters */
    bool fDigishieldDifficultyCalculation;
    bool fPowAllowDigishieldMinDifficultyBlocks; // Allow minimum difficulty blocks where a retarget would normally occur
    bool fSimplifiedRewards; // Use block height derived rewards rather than previous block hash derived

    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;

    /** Auxpow parameters */
    int32_t nAuxpowChainId;
    bool fStrictChainId;
    bool fAllowLegacyBlocks;

    /** Height-aware consensus parameters */
    uint32_t nHeightEffective; // When these parameters come into use
    struct Params *pLeft = nullptr;      // Left hand branch
    struct Params *pRight = nullptr;     // Right hand branch
    const Consensus::Params *GetConsensus(uint32_t nTargetHeight) const;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
