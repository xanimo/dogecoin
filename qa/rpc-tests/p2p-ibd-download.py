#!/usr/bin/env python3
# Copyright (c) 2024 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import logging

'''
Test IBD-adaptive parallel block download limits.

During IBD, per-peer in-flight blocks should be allowed up to
MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD (128), versus the normal limit of
MAX_BLOCKS_IN_TRANSIT_PER_PEER (16).

Setup: Two nodes, node0 and node1. Node1 pre-mines a chain of 250 blocks.
Node0 starts with a clean chain (in IBD). We connect them and verify
node0 requests more than 16 blocks in-flight from node1 during the sync.

After node0 finishes syncing (leaves IBD), we verify the normal limit
of at most 16 is restored by disconnecting, mining more blocks on node1,
and reconnecting.
'''

# IBD per-peer limit
MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD = 128
# Normal per-peer limit
MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16

class IBDParallelDownloadTest(BitcoinTestFramework):
    def add_options(self, parser):
        parser.add_option("--testbinary", dest="testbinary",
                          default=os.getenv("DOGECOIND", "dogecoind"),
                          help="Binary to test IBD parallel download behavior")

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = []
        # Node0: clean chain, will be in IBD
        self.nodes.append(start_node(0, self.options.tmpdir,
                          ["-debug"],
                          binary=self.options.testbinary))
        # Node1: will pre-mine blocks to serve to node0
        self.nodes.append(start_node(1, self.options.tmpdir,
                          ["-debug"],
                          binary=self.options.testbinary))

    def get_max_inflight_from_peer(self, node_idx):
        """Sample getpeerinfo multiple times and return the maximum inflight count seen."""
        max_inflight = 0
        for _ in range(40):
            peers = self.nodes[node_idx].getpeerinfo()
            for p in peers:
                inflight = len(p.get("inflight", []))
                if inflight > max_inflight:
                    max_inflight = inflight
            time.sleep(0.25)
        return max_inflight

    def run_test(self):
        # Pre-mine 250 blocks on node1 so it has a chain to serve.
        print("Generating 250 blocks on node1...")
        self.nodes[1].generate(250)

        # Verify node0 is in IBD (clean chain, 0 blocks)
        assert_equal(self.nodes[0].getblockcount(), 0)

        # --- Test 1: During IBD, node0 should request more than 16 blocks in-flight ---
        print("Test 1: Connecting node0 (IBD) to node1 and checking in-flight blocks...")
        connect_nodes(self.nodes[0], 1)

        # Sample the in-flight block count while syncing
        max_inflight = self.get_max_inflight_from_peer(0)

        # Wait for sync to complete
        sync_blocks(self.nodes)
        assert_equal(self.nodes[0].getblockcount(), 250)

        print("  Max blocks in-flight from single peer during IBD: %d" % max_inflight)

        # During IBD, should have had more than 16 blocks in-flight
        # (the old non-IBD limit) proving the elevated IBD limit is active
        assert max_inflight > MAX_BLOCKS_IN_TRANSIT_PER_PEER, \
            "Expected more than %d in-flight during IBD, saw max %d" % (
                MAX_BLOCKS_IN_TRANSIT_PER_PEER, max_inflight)
        assert max_inflight <= MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD, \
            "Expected at most %d in-flight during IBD, saw max %d" % (
                MAX_BLOCKS_IN_TRANSIT_PER_PEER_IBD, max_inflight)

        print("  PASSED: IBD elevated limit confirmed (%d > %d)" % (
            max_inflight, MAX_BLOCKS_IN_TRANSIT_PER_PEER))

        # --- Test 2: After leaving IBD, verify normal limit applies ---
        print("Test 2: Post-IBD block request limit should revert to normal...")

        # Disconnect the nodes
        url = "127.0.0.1:" + str(p2p_port(1))
        self.nodes[0].disconnectnode(url)
        time.sleep(2)

        # Mine more blocks on node1 while disconnected
        self.nodes[1].generate(50)
        time.sleep(1)

        # Reconnect — node0 is no longer in IBD
        connect_nodes(self.nodes[0], 1)

        max_inflight_post = self.get_max_inflight_from_peer(0)

        sync_blocks(self.nodes)
        assert_equal(self.nodes[0].getblockcount(), 300)

        print("  Max blocks in-flight from single peer post-IBD: %d" % max_inflight_post)

        assert max_inflight_post <= MAX_BLOCKS_IN_TRANSIT_PER_PEER, \
            "Expected at most %d in-flight post-IBD, saw max %d" % (
                MAX_BLOCKS_IN_TRANSIT_PER_PEER, max_inflight_post)

        print("  PASSED: Normal limit confirmed (<= %d)" % MAX_BLOCKS_IN_TRANSIT_PER_PEER)
        print("All tests passed!")


if __name__ == '__main__':
    IBDParallelDownloadTest().main()
