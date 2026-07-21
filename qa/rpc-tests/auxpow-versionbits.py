#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test the AuxPoW v1 -> v2 versionbits transition BOUNDARY (Test B).
#
# nAuxPowVersion epochs on regtest:
#   height 10-19 : digishield   nAuxPowVersion 0 (legacy PoW)
#   height 20-29 : auxpow       nAuxPowVersion 1 (chain ID in nVersion)
#   height 30+   : versionbits  nAuxPowVersion 2 (nVersion freed for BIP9)
#
# This test proves the MECHANISM and its BOUNDARY, not the hard fork:
#
#   1. v1 epoch: the chain ID occupies nVersion bits 16-31, so the BIP9
#      versionbits top-3-bit selector is never 0x20000000 -- versionbits
#      signalling is structurally impossible. (the collision, on-chain)
#
#   2. v2 epoch, MINER side: with nAuxPowVersion=2 the miner takes the
#      ComputeBlockVersion() path and the block template carries a full
#      versionbits nVersion (top bits 0x20000000, segwit bit set). The
#      nVersion has been freed. (the lever works)
#
#   3. v2 epoch, VALIDATION side: such a block is correctly REJECTED by
#      CheckAuxPowProofOfWork, because freeing nVersion removed the chain-ID
#      commitment and NOTHING has replaced it -- the "validated out-of-band"
#      part of nAuxPowVersion==2 is NOT implemented. This is deliberate:
#      the chain-ID relocation is a hard fork requiring DIP acceptance and
#      merge-mining coordination (see DIP dip-xanimo-auxpow-versionbits).
#
# So the test asserts: the lever frees nVersion (mining), AND validation
# refuses v2 blocks until the out-of-band chain-ID commitment exists. It
# will start accepting v2 blocks -- and this assertion will need updating --
# only once that commitment is designed and implemented. That is the point
# at which this stops being regtest groundwork and becomes a consensus
# change requiring coordination.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# from src/versionbits.h
VERSIONBITS_TOP_BITS = 0x20000000
VERSIONBITS_TOP_MASK = 0xE0000000
SEGWIT_BIT = 1  # regtest DEPLOYMENT_SEGWIT.bit

# epoch boundaries from CRegTestParams
DIGISHIELD_START = 10
AUXPOW_START     = 20
VERSIONBITS_START = 30

class AuxpowVersionbitsTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self, split=False):
        # getblocktemplate refuses to build a template when the node has zero
        # peers (mining.cpp: GetNodeCount == 0 -> "not connected"), so run two
        # nodes and connect them. All mining/inspection happens on nodes[0].
        self.nodes = start_nodes(2, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def block_version_at_tip(self):
        h = self.nodes[0].getbestblockhash()
        return self.nodes[0].getblock(h)["version"]

    def template_version(self):
        # getblocktemplate builds the next block's template (taking the
        # miner's version path for the current epoch) WITHOUT submitting it,
        # so it does not hit ProcessNewBlock / CheckAuxPowProofOfWork.
        try:
            tmpl = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        except JSONRPCException:
            # older GBT may not accept the rules arg; the epoch params still
            # drive ComputeBlockVersion regardless.
            tmpl = self.nodes[0].getblocktemplate()
        return tmpl["version"]

    def run_test(self):
        node = self.nodes[0]

        # ---------------------------------------------------------------
        # 1. v1 epoch: chain ID in nVersion, versionbits impossible
        # ---------------------------------------------------------------
        node.generate(AUXPOW_START + 5)  # tip at height 25, inside v1
        height = node.getblockcount()
        assert AUXPOW_START <= height < VERSIONBITS_START, \
            "expected v1 (auxpow) epoch, height=%d" % height

        v1_version = self.block_version_at_tip()
        assert_equal(v1_version & VERSIONBITS_TOP_MASK != VERSIONBITS_TOP_BITS, True)
        print("v1 epoch (height %d): nVersion=0x%08x, top=0x%08x "
              "(chain ID in version, versionbits impossible) OK"
              % (height, v1_version & 0xffffffff, v1_version & VERSIONBITS_TOP_MASK))

        # ---------------------------------------------------------------
        # 2. v2 epoch, MINER side: nVersion freed for versionbits
        #    Mine up to height 29 (still v1), then inspect the template for
        #    block 30, which is built under the v2 epoch params.
        # ---------------------------------------------------------------
        to_29 = 29 - node.getblockcount()
        if to_29 > 0:
            node.generate(to_29)
        assert_equal(node.getblockcount(), 29)

        # the template for the NEXT block (height 30) is built under v2
        v2_tmpl_version = self.template_version()
        assert_equal(v2_tmpl_version & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS)
        print("v2 epoch (template for height 30): version=0x%08x, top=0x%08x, "
              "nVersion freed for versionbits) OK"
              % (v2_tmpl_version & 0xffffffff, v2_tmpl_version & VERSIONBITS_TOP_MASK))

        # ---------------------------------------------------------------
        # 3. v2 epoch, VALIDATION side: the block is correctly REJECTED
        #    because the chain-ID commitment was removed from nVersion and
        #    the out-of-band replacement is not implemented (hard fork).
        #    generate() submits via ProcessNewBlock -> CheckAuxPowProofOfWork,
        #    which fails "block does not have our chain ID".
        # ---------------------------------------------------------------
        assert_raises_message(
            JSONRPCException,
            "not accepted",
            node.generate, 1)
        # tip must NOT have advanced past 29
        assert_equal(node.getblockcount(), 29)
        print("v2 epoch (height 30): block REJECTED by CheckAuxPowProofOfWork "
              "(chain-ID commitment removed from nVersion, out-of-band "
              "replacement not implemented) OK")

        print("")
        print("PASS: v1->v2 versionbits transition boundary proven.")
        print("  - v1: chain ID in nVersion, versionbits impossible")
        print("  - v2 mining: nVersion freed (versionbits present)")
        print("  - v2 validation: correctly refuses until out-of-band chain-ID")
        print("    commitment is designed (hard fork; see DIP).")

if __name__ == '__main__':
    AuxpowVersionbitsTest().main()
