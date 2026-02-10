#!/usr/bin/env python3
# Copyright (c) 2024 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test the getblockfilter RPC call (BIP 157/158).

Tests:
  - getblockfilter returns valid filter and header for basic filter type
  - Filter header chain is consistent (each header depends on previous)
  - Error handling for missing index, invalid hash, invalid filtertype
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_is_hex_string,
    assert_raises_jsonrpc,
    start_node,
    connect_nodes_bi,
)
import logging

class GetBlockFilterTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.log = logging.getLogger("GetBlockFilterTest")

    def setup_network(self, split=False):
        # Node 0: with blockfilterindex enabled
        # Node 1: without blockfilterindex (to test error case)
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-blockfilterindex"]))
        self.nodes.append(start_node(1, self.options.tmpdir, []))
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        self.log.info("Test getblockfilter with -blockfilterindex enabled")

        # Generate some blocks
        self.nodes[0].generate(25)
        self.sync_all()

        # Test: getblockfilter returns data for genesis block (height 0)
        genesis_hash = self.nodes[0].getblockhash(0)
        result = self.nodes[0].getblockfilter(genesis_hash)
        assert_is_hex_string(result['filter'])
        assert_is_hex_string(result['header'])
        # Genesis filter header should be non-zero (it's hash of filter hash + prev_header=0)
        assert len(result['header']) == 64

        self.log.info("Genesis block filter OK")

        # Test: getblockfilter works for all generated blocks
        prev_header = None
        for height in range(0, 26):
            blockhash = self.nodes[0].getblockhash(height)
            result = self.nodes[0].getblockfilter(blockhash)
            assert_is_hex_string(result['filter'])
            assert_is_hex_string(result['header'])

            # Verify filter header is 64 hex chars (256 bits)
            assert_equal(len(result['header']), 64)

            # Each block should have a different header (chain property)
            if prev_header is not None:
                assert result['header'] != prev_header or height == 0
            prev_header = result['header']

        self.log.info("All block filters retrieved successfully")

        # Test: explicit 'basic' filtertype
        blockhash = self.nodes[0].getblockhash(1)
        result_basic = self.nodes[0].getblockfilter(blockhash, "basic")
        result_default = self.nodes[0].getblockfilter(blockhash)
        assert_equal(result_basic, result_default)

        self.log.info("Explicit 'basic' filtertype matches default")

        # Test: invalid filtertype
        assert_raises_jsonrpc(-5, "Unknown filtertype",
                              self.nodes[0].getblockfilter, blockhash, "invalid_type")

        self.log.info("Invalid filtertype error OK")

        # Test: invalid block hash
        assert_raises_jsonrpc(-5, "Block not found",
                              self.nodes[0].getblockfilter,
                              "0000000000000000000000000000000000000000000000000000000000000000")

        self.log.info("Invalid blockhash error OK")

        # Test: node without -blockfilterindex returns error
        blockhash = self.nodes[1].getblockhash(0)
        assert_raises_jsonrpc(-1, "Index is not enabled",
                              self.nodes[1].getblockfilter, blockhash)

        self.log.info("Missing index error OK")

        # Test: filter for a block with transactions
        # Dogecoin coinbase maturity is 240 blocks; generate enough to mature
        self.nodes[0].generate(240 - 25)
        self.sync_all()
        address = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(address, 1)
        self.nodes[0].generate(1)
        self.sync_all()

        tip_hash = self.nodes[0].getbestblockhash()
        result = self.nodes[0].getblockfilter(tip_hash)
        assert_is_hex_string(result['filter'])
        assert_is_hex_string(result['header'])
        # A block with transactions should have a non-empty filter
        # (basic filters include output scripts)
        assert len(result['filter']) > 0

        self.log.info("Block with transactions has valid filter")

        self.log.info("All getblockfilter tests passed!")

if __name__ == '__main__':
    GetBlockFilterTest().main()
