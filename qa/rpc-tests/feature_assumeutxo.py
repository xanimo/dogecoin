#!/usr/bin/env python3
# Copyright (c) 2024 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test AssumeUTXO: dumptxoutset and loadtxoutset.

Two nodes:
  - node0 (SOURCE): mines SNAPSHOT_HEIGHT blocks, creates a UTXO snapshot,
    then mines extra blocks so node1 has somewhere to sync to.
  - node1 (SNAPSHOT): receives only block headers from a mininode peer (no
    block data), activates the snapshot via loadtxoutset, then syncs the
    remaining blocks from node0.

Using a header-only mininode peer for node1 ensures it has the necessary
entry in mapBlockIndex (required by loadtxoutset) while keeping its active
chainstate at height 0.  This guarantees the snapshot chainstate has strictly
more work than the active tip, satisfying ActivateSnapshot()'s work check.
"""

import os
import time
from io import BytesIO

from test_framework.mininode import (
    CBlockHeader,
    NetworkThread,
    NodeConn,
    NodeConnCB,
    SingleNodeConnCB,
    mininode_lock,
    msg_headers,
    msg_ping,
    msg_pong,
    wait_until,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises,
    connect_nodes_bi,
    hex_str_to_bytes,
    p2p_port,
    start_nodes,
    sync_blocks,
)

# Matches the m_assumeutxo_data regtest entry in chainparams.cpp.
SNAPSHOT_HEIGHT = 110

# All blocks in this test are mined to a single deterministic P2PKH address
# derived from privkey=1 (secp256k1 generator point G) so that the UTXO
# set hash is stable across runs.  The WIF is imported to node0's wallet.
REGTEST_MINING_WIF  = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"
REGTEST_MINING_ADDR = "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"

# MuHash of the UTXO set at regtest height 110 when all coinbase outputs go
# to REGTEST_MINING_ADDR.  MuHash is a pure function of UTXO contents (unlike
# hash_serialized_2 which also commits to the tip block hash) so it is
# deterministic across different mining runs.  Must match
# AssumeutxoData::hash_serialized in chainparams.cpp.
EXPECTED_MUHASH = (
    "36bb190106d9f55432f4012c7f781d17b77cf6621f3f35ef9454290eac9407aa"
)


class HeadersOnlyPeer(SingleNodeConnCB):
    """A mininode peer that delivers block headers but silently ignores all
    block/tx data requests.

    Sending only headers populates the remote node's mapBlockIndex so that
    loadtxoutset can find the snapshot base block, while keeping the node's
    validated chain (blocks) at height 0.
    """

    def on_getdata(self, conn, message):
        # Ignore all GETDATA requests (blocks, txs, …).  The remote node will
        # never receive the block data it requested, so its chain stays at
        # height 0.
        pass

    def send_block_headers(self, headers):
        msg = msg_headers()
        msg.headers = headers
        self.send_message(msg)


class AssumeutxoTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        # Start both nodes completely isolated from each other so we control
        # exactly when and how they exchange data.
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [[], []])
        self.is_network_split = True

    def run_test(self):
        self._test_dumptxoutset()
        self._test_loadtxoutset()

    # ------------------------------------------------------------------
    # dumptxoutset
    # ------------------------------------------------------------------

    def _test_dumptxoutset(self):
        node0 = self.nodes[0]

        # Import the deterministic private key so all coinbase outputs go to
        # a fixed address, making the UTXO set hash stable across runs.
        node0.importprivkey(REGTEST_MINING_WIF, "assumeutxo_test", True)

        # Mine SNAPSHOT_HEIGHT blocks so node0 has a stable UTXO set.
        node0.generatetoaddress(SNAPSHOT_HEIGHT, REGTEST_MINING_ADDR)
        assert_equal(node0.getblockcount(), SNAPSHOT_HEIGHT)

        # The UTXO set MuHash must match the value recorded in chainparams so
        # that loadtxoutset's verification step will pass.
        info = node0.gettxoutsetinfo('muhash')
        assert_equal(info['height'], SNAPSHOT_HEIGHT)
        assert_equal(info['txouts'], SNAPSHOT_HEIGHT)  # one coinbase per block
        assert_equal(info['muhash'], EXPECTED_MUHASH)

        # Create the snapshot file.
        snapshot_path = os.path.join(self.options.tmpdir, 'utxo_110.dat')
        result = node0.dumptxoutset(snapshot_path)
        assert_equal(result['coins_written'], SNAPSHOT_HEIGHT)
        assert_equal(result['base_height'], SNAPSHOT_HEIGHT)
        assert_equal(result['base_hash'], node0.getblockhash(SNAPSHOT_HEIGHT))
        assert_equal(result['path'], snapshot_path)
        assert os.path.exists(snapshot_path)

        # A second dump to the same path must be rejected.
        try:
            node0.dumptxoutset(snapshot_path)
            raise AssertionError('Expected dumptxoutset to fail on existing file')
        except Exception as e:
            assert 'already exists' in str(e), "Unexpected error: %s" % e

        # Persist across test phases.
        self.snapshot_path = snapshot_path
        self.snapshot_tip_hash = result['base_hash']

    # ------------------------------------------------------------------
    # loadtxoutset
    # ------------------------------------------------------------------

    def _test_loadtxoutset(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        # Collect the serialised 80-byte block headers for heights 1..110
        # from node0.  getblockheader(<hash>, False) returns hex.
        headers = []
        for height in range(1, SNAPSHOT_HEIGHT + 1):
            bh = node0.getblockhash(height)
            raw_hex = node0.getblockheader(bh, False)
            hdr = CBlockHeader()
            hdr.deserialize(BytesIO(hex_str_to_bytes(raw_hex)))
            headers.append(hdr)

        # Open a header-only P2P connection to node1 and push the headers.
        # The peer silently ignores any GETDATA requests for blocks, so node1
        # accumulates header data in mapBlockIndex but downloads no blocks.
        peer = HeadersOnlyPeer()
        conn = NodeConn('127.0.0.1', p2p_port(1), node1, peer)
        peer.add_connection(conn)
        NetworkThread().start()
        peer.wait_for_verack()

        peer.send_block_headers(headers)
        # sync_with_ping ensures node1 has processed the headers message
        # before we interrogate its state via RPC.
        peer.sync_with_ping()

        # node1 must have all headers but no validated blocks.
        ci = node1.getblockchaininfo()
        assert_equal(ci['headers'], SNAPSHOT_HEIGHT)
        assert_equal(ci['blocks'], 0)

        # loadtxoutset: the base block header is already in mapBlockIndex so
        # the call returns without waiting.  ActivateSnapshot succeeds because
        # snapshot work (height 110) > active tip work (height 0).
        result = node1.loadtxoutset(self.snapshot_path)
        assert_equal(result['coins_loaded'], SNAPSHOT_HEIGHT)
        assert_equal(result['base_height'], SNAPSHOT_HEIGHT)
        assert_equal(result['tip_hash'], self.snapshot_tip_hash)

        # The snapshot chainstate is now node1's active chain.
        assert_equal(node1.getblockcount(), SNAPSHOT_HEIGHT)

        # Clean up the mininode connection.
        conn.disconnect_node()
        time.sleep(0.3)  # Allow disconnect to propagate before connecting peers.

        # Mine extra blocks on node0 so node1 has somewhere to extend to,
        # then connect the two nodes and verify node1 syncs to the tip.
        extra = 10
        node0.generatetoaddress(extra, REGTEST_MINING_ADDR)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes, timeout=60)
        assert_equal(node1.getblockcount(), SNAPSHOT_HEIGHT + extra)


if __name__ == '__main__':
    AssumeutxoTest().main()
