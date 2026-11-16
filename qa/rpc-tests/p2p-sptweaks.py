#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test BIP352 scanning tweak P2P message handling.

The tweak index is the server half of a light client: a client that cannot derive tweaks itself,
because deriving them needs the block, asks a serving peer for them and then tests the candidate
scripts it builds against a BIP158 filter. This covers the serving side, which is the half that
has to exist before any client can be written.
"""

import struct
import time

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (assert_equal, connect_nodes_bi, p2p_port, start_node,
                                 sync_blocks)


NODE_SP_TWEAKS = 1 << 25
MAX_GETSPTWEAKS_SIZE = 1000


class msg_getsptweaks(object):
    command = b"getsptweaks"

    def __init__(self, start_height=0, stop_hash=0):
        self.start_height = start_height
        self.stop_hash = stop_hash

    def serialize(self):
        return struct.pack("<I", self.start_height) + ser_uint256(self.stop_hash)


class msg_sptweaks(object):
    command = b"sptweaks"

    def deserialize(self, f):
        self.height = struct.unpack("<I", f.read(4))[0]
        self.block_hash = deser_uint256(f)
        count = deser_compact_size(f)
        self.entries = []
        for _ in range(count):
            tx_index = struct.unpack("<I", f.read(4))[0]
            self.entries.append((tx_index, deser_string(f)))


NodeConn.messagemap[b"sptweaks"] = msg_sptweaks


class SPTweakP2PNode(SingleNodeConnCB):
    def __init__(self):
        super().__init__()
        self.version_services = 0
        self.sptweaks = []

    def on_version(self, conn, message):
        self.version_services = message.nServices
        super().on_version(conn, message)

    def on_sptweaks(self, conn, message):
        self.sptweaks.append(message)

    def wait_for_disconnect(self, timeout=60):
        if self.connection is None:
            return True
        sleep_time = 0.05
        is_closed = self.connection.state == "closed"
        while not is_closed and timeout > 0:
            time.sleep(sleep_time)
            timeout -= sleep_time
            is_closed = self.connection.state == "closed"
        return is_closed


class SPTweaksTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        # Two nodes so the client has somewhere other than the serving node to get headers
        # from. Checking an answer's block hash against the node that sent it only establishes
        # that the node agrees with itself.
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = [start_node(0, self.options.tmpdir,
                                 ['-tweakindex', '-peersptweaks', '-usehd=1']),
                      start_node(1, self.options.tmpdir, ['-usehd=1'])]
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def wait_for_index(self, height, timeout=60):
        """Wait until the tweak index has actually reached a height.

        getindexinfo reports synced once the first sync is over, after which the index follows
        the chain from a queue, so synced does not mean this height is in it.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            info = self.nodes[0].getindexinfo('tweakindex').get('tweakindex', {})
            if info.get('synced') and info.get('best_block_height', -1) >= height:
                return
            time.sleep(0.5)
        raise AssertionError('tweakindex did not reach height %d' % height)

    def check_answer(self, peer, start, stop):
        """Every message names a block this client can find in headers from the other node."""
        assert_equal(len(peer.sptweaks), stop - start + 1)
        assert_equal([m.height for m in peer.sptweaks], list(range(start, stop + 1)))
        for m in peer.sptweaks:
            named = "%064x" % m.block_hash
            assert_equal(named, self.nodes[1].getblockhash(m.height))
            # The entries have to belong to the block the message names, not merely be
            # well-formed. An index that answered with a block since reorged away would still
            # name the right hash, so index into the named block and require every entry to
            # land on a transaction it actually has.
            ntx = len(self.nodes[1].getblock(named)['tx'])
            for tx_index, tweak in m.entries:
                assert tx_index > 0, 'coinbase cannot be scannable'
                assert tx_index < ntx, \
                    'entry names tx %d of block %d, which has %d' % (tx_index, m.height, ntx)
                assert_equal(len(tweak), 33)
                assert tweak[0] in (2, 3), 'tweak is not a compressed point: %d' % tweak[0]

    def connect(self, start_thread=False):
        """Attach a peer. Exactly one NetworkThread may run: it drives the shared asyncore map
        for every connection, and starting a second races it and corrupts reads."""
        node = SPTweakP2PNode()
        conn = NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], node)
        node.add_connection(conn)
        if start_thread:
            NetworkThread().start()
        node.wait_for_verack()
        return node

    def run_test(self):
        node0 = self.nodes[0]
        peer = self.connect(start_thread=True)

        # The service has to be advertised, otherwise a client has no way to tell a serving peer
        # from one that will disconnect it for asking.
        assert peer.version_services & NODE_SP_TWEAKS, \
            'NODE_SP_TWEAKS not advertised: %x' % peer.version_services

        # Build a chain with something to find. Coinbases are P2PK and ineligible, so the
        # eligible transactions come from spending them onward to P2PKH.
        node0.generate(200)
        for _ in range(3):
            node0.sendtoaddress(node0.getnewaddress(), 100)
            node0.generate(1)
        tip_height = node0.getblockcount()
        sync_blocks(self.nodes)
        self.wait_for_index(tip_height)

        # A range is answered with one message per block, oldest first, each carrying its height
        # so a client never has to infer position from arrival order.
        start = tip_height - 4
        peer.sptweaks = []
        peer.send_message(msg_getsptweaks(start_height=start,
                                          stop_hash=int(node0.getblockhash(tip_height), 16)))
        peer.sync_with_ping()
        self.check_answer(peer, start, tip_height)

        # The blocks that spent a P2PKH output must carry a tweak. An empty answer everywhere
        # would pass a weaker assertion.
        assert any(len(m.entries) > 0 for m in peer.sptweaks), \
            'no block in the range carried a tweak'

        # Across a reorg the answer must describe the chain the client holds, not the one the
        # index happened to be built on. The index follows the chain from a queue, so there is
        # a window after a reorg where the entry left at a height was computed from the block
        # that used to be there; serving it would name the new block's hash beside the old
        # block's entries, which is what an earlier revision of this code did.
        reorg_from = tip_height - 1
        old_hashes = [node0.getblockhash(h) for h in range(reorg_from, tip_height + 1)]
        for node in self.nodes:
            node.invalidateblock(old_hashes[0])
        assert_equal(node0.getblockcount(), reorg_from - 1)

        # Rebuild longer, so the replacement blocks hold different transactions at the same
        # heights: the spends that were in the old blocks are back in the mempool and land
        # wherever this run puts them.
        node0.sendtoaddress(node0.getnewaddress(), 50)
        node0.generate(3)
        sync_blocks(self.nodes)
        new_tip = node0.getblockcount()
        assert new_tip > tip_height, 'the replacement chain has to win'
        assert node0.getblockhash(reorg_from) != old_hashes[0], 'no reorg happened'
        self.wait_for_index(new_tip)

        peer.sptweaks = []
        peer.send_message(msg_getsptweaks(start_height=reorg_from,
                                          stop_hash=int(node0.getblockhash(new_tip), 16)))
        peer.sync_with_ping()
        self.check_answer(peer, reorg_from, new_tip)

        # Nothing in the answer may name a block the reorg discarded.
        served = set("%064x" % m.block_hash for m in peer.sptweaks)
        assert not served & set(old_hashes), \
            'answer names a block that was reorged away: %s' % (served & set(old_hashes))

        # A stop hash that is not on the active chain is refused rather than answered from a
        # stale branch, because a range has to describe one chain.
        peer = self.connect()
        peer.send_message(msg_getsptweaks(start_height=0, stop_hash=0xdeadbeef))
        assert peer.wait_for_disconnect()

        # And a range wider than the cap is refused rather than served in full.
        peer = self.connect()
        peer.send_message(msg_getsptweaks(start_height=0,
                                          stop_hash=int(node0.getblockhash(tip_height), 16)))
        if tip_height >= MAX_GETSPTWEAKS_SIZE:
            assert peer.wait_for_disconnect()


if __name__ == '__main__':
    SPTweaksTest().main()
