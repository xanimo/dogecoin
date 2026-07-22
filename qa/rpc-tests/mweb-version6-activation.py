#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Phase 0: MWEB activation via the AuxPoW-safe version-6 supermajority latch,
# and a peg-in end to end.
#
# MWEB reuses the same activation substrate as SegWit (see
# segwit-version5-activation.py), one rung up the ladder at base version 6.
# Because IsSuperMajority() compares GetBaseVersion() >= minVersion, a v6 block
# also signals SegWit v5, so MWEB cannot activate before or without SegWit.
# Activation is latched on CBlockIndex so it can never revert once reached --
# non-negotiable for MWEB, whose extension blocks hold funds.
#
# Activation is probed behaviourally rather than through getblocktemplate
# (whose 'rules' reporting still reads versionbits and does not track the
# version-6 gate): once MWEB is active every block -- even an empty one -- must
# carry a HogEx integrating transaction, so an empty block's transaction count
# goes from 1 (coinbase only) to 2 (coinbase + HogEx).
#
# Four activation points, then the peg-in:
#   1. below the start height            -> inactive
#   2. past the start, below threshold   -> still inactive (threshold gates)
#   3. threshold met                     -> active
#   4. signalling stops (v4 blocks)      -> still active (the latch)
#   5. peg-in -> mine -> confirmed in a [coinbase, peg-in, HogEx] block
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from decimal import Decimal

MWEB_START_HEIGHT = 100
ENFORCE_VERSION   = 6
MAJORITY_ENFORCE  = 750   # nMajorityEnforceBlockUpgrade (regtest)
MAJORITY_WINDOW   = 1000  # nMajorityWindow (regtest)
REGTEST_CHAIN_ID  = 0x0062


class MwebVersion6ActivationTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self, split=False):
        # Single node: this test exercises the consensus activation gate and the
        # wallet/miner peg-in path. Multi-node relay of MWEB blocks needs the
        # BIP152 version-3 compact-block encoding to carry the extension block,
        # which is not yet implemented (CBlockHeaderAndShortTxIDs has no
        # mweb_block), so relayed post-activation blocks reconstruct without the
        # extension and are rejected as mweb-missing. That is a separate P2P item.
        #
        # -blockversion=6 makes the node mine base-version-6 blocks, which signal
        # both SegWit (v5) and MWEB (v6). -fallbackfee lets the wallet fund the
        # peg-in without fee estimation data on a fresh regtest chain.
        self.nodes = start_nodes(1, self.options.tmpdir,
                                 [["-blockversion=6", "-fallbackfee=0.001"]])
        self.is_network_split = False

    def mweb_active(self, node):
        # An empty block carries a HogEx (2 txs) only once MWEB is active.
        tip = node.getbestblockhash()
        return len(node.getblock(tip)["tx"]) >= 2

    def assert_mweb_inactive(self, node, where):
        assert not self.mweb_active(node), \
            "%s: extension block present, MWEB active too early" % where

    def assert_mweb_active(self, node, where):
        assert self.mweb_active(node), \
            "%s: no extension block, MWEB did not activate" % where

    def run_test(self):
        node = self.nodes[0]

        # 1. Below the start height: MWEB is not active.
        node.generate(50)
        assert_equal(node.getblockcount(), 50)
        self.assert_mweb_inactive(node, "height 50")
        print("height 50 (< start %d): MWEB not active OK" % MWEB_START_HEIGHT)

        # 2. Past the start height, below the supermajority threshold: still not
        #    active. Every block so far is base-version 6, so the v6 count equals
        #    the height; at 700 that is short of the 750 required.
        node.generate(650)
        assert_equal(node.getblockcount(), 700)
        assert 700 > MWEB_START_HEIGHT and 700 < MAJORITY_ENFORCE
        self.assert_mweb_inactive(node, "height 700")
        print("height 700 (>= start, %d v6 blocks < %d threshold): MWEB not active OK"
              % (700, MAJORITY_ENFORCE))

        # 3. Cross the supermajority threshold: MWEB activates.
        node.generate(100)
        height = node.getblockcount()
        assert_equal(height, 800)
        assert height >= MAJORITY_ENFORCE
        self.assert_mweb_active(node, "height %d" % height)
        print("height %d (%d v6 blocks >= %d threshold): MWEB ACTIVE OK"
              % (height, height, MAJORITY_ENFORCE))

        # 4. The signal is base-version 6 and AuxPoW-legal: the chain ID in
        #    nVersion bits 16-31 is untouched (no versionbits collision).
        tip_ver = node.getblock(node.getbestblockhash())["version"]
        assert_equal(tip_ver % 256, ENFORCE_VERSION)          # GetBaseVersion() == 6
        assert_equal((tip_ver >> 16) & 0xffff, REGTEST_CHAIN_ID)
        print("base-version-6 blocks mine (nVersion=0x%08x, base=%d), chain ID 0x%04x intact OK"
              % (tip_ver & 0xffffffff, tip_ver % 256, (tip_ver >> 16) & 0xffff))

        # 5. Peg-in end to end: the wallet builds/funds/signs a peg-in, it is
        #    accepted to the mempool (only possible with MWEB active), and it
        #    confirms in a block of [coinbase, peg-in, HogEx].
        res = node.pegin(10.0)
        txid = res["txid"]
        assert txid in node.getrawmempool(), "peg-in not accepted to mempool"
        assert_equal(res["mweb_output_value"], Decimal("9.99900000"))
        node.generate(1)
        assert_equal(node.gettransaction(txid)["confirmations"], 1)
        blocktxs = node.getblock(node.getbestblockhash())["tx"]
        assert_equal(len(blocktxs), 3)          # coinbase + peg-in + HogEx
        assert txid in blocktxs
        print("peg-in %s confirmed in a [coinbase, peg-in, HogEx] block OK" % txid)

        # 6. Activation is LATCHED: it must not revert when signalling stops.
        #    IsSuperMajority() is a rolling-window predicate, so re-deriving it
        #    per block would deactivate MWEB here. Restart the miner on
        #    base-version 4 and bury the window: 300 v4 blocks leaves fewer than
        #    750 v6 blocks in the last 1000. MWEB must stay active -- an empty
        #    v4 block must still carry a HogEx.
        assert MAJORITY_WINDOW - 300 < MAJORITY_ENFORCE, "window no longer falls below threshold"
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, ["-blockversion=4"])
        node = self.nodes[0]
        node.generate(300)
        assert_equal(node.getblock(node.getbestblockhash())["version"] % 256, 4)
        self.assert_mweb_active(node, "after 300 non-signalling v4 blocks")
        print("v4 blocks past activation: MWEB STILL active, activation is latched OK")

        print("")
        print("PASS: MWEB activates on the AuxPoW-safe version-6 supermajority gate.")
        print("  - not active below the start height")
        print("  - not active above the start height until the threshold is met")
        print("  - active once the threshold is met")
        print("  - stays active when signalling later drops (activation is latched)")
        print("  - a wallet peg-in confirms in a valid MWEB block once active")


if __name__ == '__main__':
    MwebVersion6ActivationTest().main()
