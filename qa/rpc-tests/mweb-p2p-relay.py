#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Multi-node MWEB relay: two peers relay MWEB blocks (which carry an extension
# block) and MWEB transactions to each other.
#
# MWEB blocks cannot be represented by the BIP152 compact-block encoding
# (CBlockHeaderAndShortTxIDs has no extension block), so they are relayed as full
# blocks; the compact-block high-bandwidth path is skipped for them. Nodes
# advertise NODE_MWEB so peers request MWEB blocks/txs (which carry the
# extension) rather than mweb-stripped bodies. Ordinary transaction relay must
# keep working once MWEB is active: MWEB-tagged fetches are gated on activation
# and resolved by AlreadyHave.
#
# What this checks:
#   1. Post-activation blocks (each carrying a HogEx + extension block) relay
#      from the miner to the peer and validate there -- the peer reaches the same
#      height and tip.
#   2. A peg-in transaction relays to the peer's mempool.
#   3. The peg-in confirms and the block (coinbase + peg-in + HogEx) relays; both
#      nodes agree on the tip.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

MWEB_START_HEIGHT = 100
MAJORITY_ENFORCE  = 750


class MwebP2PRelayTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self, split=False):
        # Two MWEB-capable nodes mining base-version-6 blocks (which signal both
        # SegWit and MWEB), connected to each other.
        self.nodes = start_nodes(2, self.options.tmpdir,
                                 [["-blockversion=6", "-fallbackfee=0.001"]] * 2)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mweb_active(self, node):
        # An empty block carries a HogEx (2 txs) only once MWEB is active.
        return len(node.getblock(node.getbestblockhash())["tx"]) >= 2

    def run_test(self):
        node0, node1 = self.nodes

        # 1. Mine past the supermajority threshold on node0 to activate MWEB, and
        #    let the blocks relay to node1. Every post-activation block carries a
        #    HogEx and an extension block, so this exercises full-block MWEB relay
        #    and validation on the receiving node.
        node0.generate(MAJORITY_ENFORCE + 60)   # 810 -> comfortably past threshold
        sync_blocks(self.nodes)
        assert_equal(node0.getblockcount(), node1.getblockcount())
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        assert self.mweb_active(node0), "MWEB did not activate on the miner"
        assert self.mweb_active(node1), "MWEB extension block did not relay to the peer"
        print("post-activation MWEB blocks relayed to peer: both at height %d OK"
              % node1.getblockcount())

        # 2. Ordinary MWEB transaction relay: a peg-in built on node0 reaches
        #    node1's mempool. (If MWEB-tagged fetches were mis-handled, this would
        #    hang -- the failure mode that made advertising NODE_MWEB unsafe.)
        res = node0.pegin(10.0)
        txid = res["txid"]
        assert txid in node0.getrawmempool(), "peg-in not accepted to node0 mempool"
        sync_mempools(self.nodes)
        assert txid in node1.getrawmempool(), "peg-in did not relay to node1 mempool"
        print("peg-in %s relayed to peer mempool OK" % txid)

        # 3. Mine the peg-in on node0 and relay the block to node1. The block is
        #    [coinbase, peg-in, HogEx]; node1 must accept it and match the tip.
        node0.generate(1)
        sync_blocks(self.nodes)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        blocktxs = node1.getblock(node1.getbestblockhash())["tx"]
        assert_equal(len(blocktxs), 3)       # coinbase + peg-in + HogEx
        assert txid in blocktxs, "peg-in not in the relayed block on node1"
        print("peg-in block relayed and accepted by peer (both tips match) OK")

        print("")
        print("PASS: MWEB blocks and transactions relay between nodes.")
        print("  - post-activation extension blocks relay as full blocks and validate")
        print("  - MWEB transactions relay to peers' mempools (tx relay stays healthy)")
        print("  - a peg-in block confirms on both nodes")


if __name__ == '__main__':
    MwebP2PRelayTest().main()
