#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Phase 0: SegWit activation via AuxPoW-safe version-5 supermajority.
#
# Dogecoin cannot use BIP9 versionbits for activation: the AuxPoW chain ID
# occupies nVersion bits 16-31, and freeing it for versionbits requires an
# out-of-band chain-ID relocation hard fork (proven in auxpow-versionbits.py).
# This test exercises the alternative Phase 0 substrate: the BIP34/65
# IsSuperMajority mechanism, which reads GetBaseVersion() = nVersion %
# VERSION_AUXPOW and therefore never touches the AuxPoW chain ID. No
# versionbits, no collision, no hard fork.
#
# SCOPE OF THIS TEST (what is proven here):
#   * IsWitnessEnabled is rewired to a version-5 supermajority gate
#     (nSegwitStartHeight=100, nSegwitEnforceVersion=5, threshold/window
#     reuse nMajorityEnforceBlockUpgrade/nMajorityWindow = 750/1000 regtest).
#   * Below the start height, SegWit is NOT active.
#   * Past the start height but below the supermajority threshold, SegWit is
#     STILL not active -- the threshold gates activation, not just the height.
#   * Once the threshold is met, SegWit IS active.
#   * Activation is LATCHED: it survives signalling falling back below the
#     threshold. IsSuperMajority() is a rolling-window predicate, so a gate
#     that re-derives it per block would silently deactivate SegWit; the
#     latch in IsWitnessEnabled() is what makes activation monotonic.
#   * base-version-5 blocks mine and validate as AuxPoW-legal: the chain ID
#     in nVersion bits 16-31 (0x0062 on regtest) is intact and untouched,
#     and v5 blocks are accepted and synced between peers.
#
# HOW ACTIVATION IS PROBED:
#   Via getblocktemplate's sizelimit/weightlimit/sigoplimit, which flow from
#   fPreSegWit = !IsWitnessEnabled() in rpc/mining.cpp and therefore track the
#   version-5 gate directly. The template's 'rules' array is deliberately NOT
#   used: it is still built from VersionBitsState(DEPLOYMENT_SEGWIT), so
#   'segwit' can never appear there under version-5 activation, and asserting
#   on it would pass whether or not the gate works.
#
# REMAINING WORK (deliberately NOT asserted here; see DIP
# dip-xanimo-auxpow-versionbits):
#   getblocktemplate 'rules'/'vbavailable' and getblockchaininfo's
#   bip9_softforks entry still report segwit from versionbits state, so
#   activation-reporting to miners and RPC clients does not yet track the
#   version-5 gate. The consensus enforcement path, the witness commitment
#   emission (GenerateCoinbaseCommitment) and NODE_WITNESS advertisement do.
#   Structural lesson from the auxpow-versionbits boundary: an activation
#   substrate must be consulted consistently at EVERY site that independently
#   queries activation, and those sites outnumber the enforcement grep.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

SEGWIT_START_HEIGHT = 100
ENFORCE_VERSION     = 5
MAJORITY_ENFORCE    = 750   # nMajorityEnforceBlockUpgrade (regtest)
MAJORITY_WINDOW     = 1000  # nMajorityWindow (regtest)
REGTEST_CHAIN_ID    = 0x0062

# consensus.h / primitives/transaction.h
MAX_BLOCK_BASE_SIZE       = 1000000
MAX_BLOCK_SERIALIZED_SIZE = 4000000
MAX_BLOCK_WEIGHT          = 4000000
MAX_BLOCK_SIGOPS_COST     = 80000
WITNESS_SCALE_FACTOR      = 4

class Version5SegwitActivationTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self, split=False):
        # -blockversion=5 makes node0 mine base-version-5 blocks (the signal).
        # Two nodes so getblocktemplate has a peer (mining.cpp GetNodeCount>0).
        self.nodes = start_nodes(2, self.options.tmpdir,
                                 [["-blockversion=5"], []])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def get_template(self):
        try:
            return self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        except JSONRPCException:
            return self.nodes[0].getblocktemplate()

    def assert_segwit_inactive(self, where):
        # fPreSegWit = !IsWitnessEnabled(): pre-activation the template is
        # advertised with pre-segwit block limits and no weight limit at all.
        tmpl = self.get_template()
        assert "weightlimit" not in tmpl, \
            "%s: weightlimit present, SegWit active too early" % where
        assert_equal(tmpl["sizelimit"], MAX_BLOCK_BASE_SIZE)
        assert_equal(tmpl["sigoplimit"], MAX_BLOCK_SIGOPS_COST // WITNESS_SCALE_FACTOR)

    def assert_segwit_active(self, where):
        tmpl = self.get_template()
        assert "weightlimit" in tmpl, \
            "%s: no weightlimit, SegWit did not activate" % where
        assert_equal(tmpl["weightlimit"], MAX_BLOCK_WEIGHT)
        assert_equal(tmpl["sizelimit"], MAX_BLOCK_SERIALIZED_SIZE)
        assert_equal(tmpl["sigoplimit"], MAX_BLOCK_SIGOPS_COST)

    def run_test(self):
        node = self.nodes[0]

        # 1. Below the start height: SegWit is not active.
        node.generate(50)
        self.sync_all()
        assert_equal(node.getblockcount(), 50)
        self.assert_segwit_inactive("height 50")
        print("height 50 (< start %d): SegWit not active OK" % SEGWIT_START_HEIGHT)

        # 2. Past the start height, below the supermajority threshold: still
        #    not active. Every block so far is base-version 5 (-blockversion=5),
        #    so nFound == height; at 700 that is short of the 750 required.
        node.generate(650)
        self.sync_all()
        assert_equal(node.getblockcount(), 700)
        assert 700 > SEGWIT_START_HEIGHT and 700 < MAJORITY_ENFORCE
        self.assert_segwit_inactive("height 700")
        print("height 700 (>= start, %d v5 blocks < %d threshold): SegWit not active OK"
              % (700, MAJORITY_ENFORCE))

        # 3. Cross the supermajority threshold: SegWit activates.
        node.generate(100)
        self.sync_all()
        height = node.getblockcount()
        assert_equal(height, 800)
        assert height >= MAJORITY_ENFORCE
        self.assert_segwit_active("height %d" % height)
        print("height %d (%d v5 blocks >= %d threshold): SegWit ACTIVE OK"
              % (height, height, MAJORITY_ENFORCE))

        # 4. The signal is base-version 5 and AuxPoW-legal.
        tip = node.getbestblockhash()
        tip_ver = node.getblock(tip)["version"]
        assert_equal(tip_ver % 256, ENFORCE_VERSION)   # GetBaseVersion() == 5
        print("height %d: base-version-5 blocks mining (nVersion=0x%08x, base=%d) OK"
              % (height, tip_ver & 0xffffffff, tip_ver % 256))

        # 5. AuxPoW safety: chain ID in nVersion bits 16-31 untouched;
        #    v5 blocks accepted and synced to the peer.
        chain_id = (tip_ver >> 16) & 0xffff
        assert_equal(chain_id, REGTEST_CHAIN_ID)
        assert_equal(self.nodes[1].getblockcount(), height)
        print("AuxPoW untouched: nVersion bits 16-31 = 0x%04x (chain ID intact); "
              "v5 blocks accepted and synced to peer OK" % chain_id)

        # 6. Activation is LATCHED: it must not revert when signalling stops.
        #    IsSuperMajority() is a rolling-window predicate, so re-deriving it
        #    per block would deactivate SegWit here. Restart the miner on
        #    base-version 4 and bury the window: 300 v4 blocks leaves 700 v5 in
        #    the last 1000, below the 750 threshold. SegWit must stay active.
        assert MAJORITY_WINDOW - 300 < MAJORITY_ENFORCE, "window no longer falls below threshold"
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, ["-blockversion=4"])
        connect_nodes_bi(self.nodes, 0, 1)
        node = self.nodes[0]
        node.generate(300)
        self.sync_all()
        assert_equal(node.getblockcount(), 1100)
        assert_equal(node.getblock(node.getbestblockhash())["version"] % 256, 4)
        self.assert_segwit_active("height 1100 after 300 non-signalling blocks")
        print("height 1100 (last 1000 blocks: 700 v5 < %d threshold): SegWit STILL "
              "active, activation is latched OK" % MAJORITY_ENFORCE)

        print("")
        print("PASS: version-5 supermajority is an AuxPoW-safe SegWit enforcement gate.")
        print("  - not active below the start height")
        print("  - not active above the start height until the supermajority")
        print("    threshold is met")
        print("  - active once the threshold is met")
        print("  - stays active when signalling later drops below the")
        print("    threshold (activation is latched, not rolling)")
        print("  - base-version-5 blocks mine and validate")
        print("  - chain ID (nVersion 16-31) untouched: no versionbits, no")
        print("    nVersion collision, no hard fork")
        print("  - remaining work: reroute getblocktemplate 'rules'/'vbavailable'")
        print("    and getblockchaininfo reporting off versionbits (see DIP)")

if __name__ == '__main__':
    Version5SegwitActivationTest().main()
