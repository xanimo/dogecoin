#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test AssumeUTXO interaction with prune mode.

Verifies that a node started with -prune can successfully activate a UTXO
snapshot via loadtxoutset.  Mirrors the structure of feature_assumeutxo.py
but starts the snapshot node with -prune=550 so that the prune codepath in
ChainstateManager::GetPruneRange runs against a multi-chainstate setup.
"""

import os
import time
from io import BytesIO

from test_framework.mininode import (
    CBlockHeader,
    NetworkThread,
    NodeConn,
    SingleNodeConnCB,
    msg_headers,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes_bi,
    hex_str_to_bytes,
    p2p_port,
    start_nodes,
    sync_blocks,
)

# Matches the m_assumeutxo_data regtest entry in chainparams.cpp.
SNAPSHOT_HEIGHT = 110

REGTEST_MINING_WIF  = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
REGTEST_MINING_ADDR = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"

EXPECTED_MUHASH = (
    "36bb190106d9f55432f4012c7f781d17b77cf6621f3f35ef9454290eac9407aa"
)


class HeadersOnlyPeer(SingleNodeConnCB):
    """Mininode peer that delivers headers and ignores all data requests."""

    def on_getdata(self, conn, message):
        pass

    def send_block_headers(self, headers):
        msg = msg_headers()
        msg.headers = headers
        self.send_message(msg)


class AssumeutxoPruneTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        # node0: full node (source).  node1: pruned node that will load the
        # snapshot.  Dogecoin's minimum prune target is 2200 MiB.
        self.nodes = start_nodes(
            self.num_nodes,
            self.options.tmpdir,
            [[], ["-prune=2200"]],
        )
        self.is_network_split = True

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Mine deterministic chain on node0 and dump the snapshot.
        node0.importprivkey(REGTEST_MINING_WIF, "assumeutxo_prune", True)
        node0.generatetoaddress(SNAPSHOT_HEIGHT, REGTEST_MINING_ADDR)
        info = node0.gettxoutsetinfo('muhash')
        assert_equal(info['height'], SNAPSHOT_HEIGHT)
        assert_equal(info['muhash'], EXPECTED_MUHASH)

        snapshot_path = os.path.join(self.options.tmpdir, 'utxo_prune_110.dat')
        result = node0.dumptxoutset(snapshot_path)
        assert_equal(result['coins_written'], SNAPSHOT_HEIGHT)
        snapshot_tip_hash = result['base_hash']

        # Confirm node1 was actually started in prune mode.
        ci = node1.getblockchaininfo()
        assert_equal(ci.get('pruned', False), True)

        # Push headers (1..SNAPSHOT_HEIGHT) to the pruned node so that
        # mapBlockIndex contains the snapshot base block.
        headers = []
        for height in range(1, SNAPSHOT_HEIGHT + 1):
            bh = node0.getblockhash(height)
            raw_hex = node0.getblockheader(bh, False)
            hdr = CBlockHeader()
            hdr.deserialize(BytesIO(hex_str_to_bytes(raw_hex)))
            headers.append(hdr)

        peer = HeadersOnlyPeer()
        conn = NodeConn('127.0.0.1', p2p_port(1), node1, peer)
        peer.add_connection(conn)
        NetworkThread().start()
        peer.wait_for_verack()
        peer.send_block_headers(headers)
        peer.sync_with_ping()

        ci = node1.getblockchaininfo()
        assert_equal(ci['headers'], SNAPSHOT_HEIGHT)
        assert_equal(ci['blocks'], 0)
        assert_equal(ci.get('pruned'), True)

        # Activate the snapshot on the pruned node.  This exercises the
        # multi-chainstate path in GetPruneRange / FlushStateToDisk.
        result = node1.loadtxoutset(snapshot_path)
        assert_equal(result['coins_loaded'], SNAPSHOT_HEIGHT)
        assert_equal(result['base_height'], SNAPSHOT_HEIGHT)
        assert_equal(result['tip_hash'], snapshot_tip_hash)
        assert_equal(node1.getblockcount(), SNAPSHOT_HEIGHT)

        # Disconnect mininode peer before connecting to node0.
        conn.disconnect_node()
        time.sleep(0.3)

        # Mine extra blocks on node0 and sync node1 to the new tip.
        # Pruning should not affect this short post-snapshot extension.
        extra = 10
        node0.generatetoaddress(extra, REGTEST_MINING_ADDR)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes, timeout=60)
        assert_equal(node1.getblockcount(), SNAPSHOT_HEIGHT + extra)

        # Pruned node should still report pruned=True after snapshot+sync.
        ci = node1.getblockchaininfo()
        assert_equal(ci.get('pruned'), True)


if __name__ == '__main__':
    AssumeutxoPruneTest().main()
