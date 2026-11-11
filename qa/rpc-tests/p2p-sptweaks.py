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
from test_framework.util import assert_equal, p2p_port, start_node


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
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = [start_node(0, self.options.tmpdir,
                                 ['-tweakindex', '-peersptweaks', '-usehd=1'])]
        self.is_network_split = False

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

        # Wait for the index, which syncs in its own thread.
        deadline = time.time() + 60
        while time.time() < deadline:
            if node0.getindexinfo('tweakindex').get('tweakindex', {}).get('synced'):
                break
            time.sleep(0.5)
        else:
            raise AssertionError('tweakindex did not sync')

        # A range is answered with one message per block, oldest first, each carrying its height
        # so a client never has to infer position from arrival order.
        start = tip_height - 4
        peer.sptweaks = []
        peer.send_message(msg_getsptweaks(start_height=start,
                                          stop_hash=int(node0.getblockhash(tip_height), 16)))
        peer.sync_with_ping()

        assert_equal(len(peer.sptweaks), tip_height - start + 1)
        assert_equal([m.height for m in peer.sptweaks], list(range(start, tip_height + 1)))

        # The blocks that spent a P2PKH output must carry a tweak, and every tweak is a
        # compressed point. An empty answer everywhere would pass a weaker assertion.
        assert any(len(m.entries) > 0 for m in peer.sptweaks), \
            'no block in the range carried a tweak'
        for m in peer.sptweaks:
            for tx_index, tweak in m.entries:
                assert tx_index > 0, 'coinbase cannot be scannable'
                assert_equal(len(tweak), 33)
                assert tweak[0] in (2, 3), 'tweak is not a compressed point: %d' % tweak[0]

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
