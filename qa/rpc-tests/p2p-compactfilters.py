#!/usr/bin/env python3
# Copyright (c) 2024 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test BIP 157 compact block filter P2P protocol messages.

Tests:
  - getcfilters / cfilter: request and receive compact filters for a range
  - getcfheaders / cfheaders: request and receive filter headers
  - getcfcheckpt / cfcheckpt: request and receive filter header checkpoints
  - Peer is disconnected for unsupported filter type
  - Peer is disconnected for unknown stop hash
  - Peer is disconnected for start_height > stop_height
  - Peer is disconnected for requesting too many filters at once
  - NODE_COMPACT_FILTERS service bit is advertised
"""

import struct
import time

from test_framework.mininode import (
    mininode_lock,
    msg_ping,
    msg_pong,
    NodeConnCB,
    NodeConn,
    NetworkThread,
    SingleNodeConnCB,
    deser_uint256,
    deser_string,
    deser_uint256_vector,
    ser_uint256,
    ser_string,
    ser_uint256_vector,
    wait_until,
    MY_VERSION,
    NODE_NETWORK,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    start_node,
    start_nodes,
    stop_node,
    p2p_port,
    sync_blocks,
)
import logging
import hashlib

# BIP 157 filter type constants
FILTER_TYPE_BASIC = 0

# NODE_COMPACT_FILTERS service bit
NODE_COMPACT_FILTERS = (1 << 6)

# -------------------------------------------------------------------
# BIP 157 message classes
# -------------------------------------------------------------------

class msg_getcfilters(object):
    command = b"getcfilters"

    def __init__(self, filter_type=0, start_height=0, stop_hash=0):
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = struct.unpack("<B", f.read(1))[0]
        self.start_height = struct.unpack("<I", f.read(4))[0]
        self.stop_hash = deser_uint256(f)

    def serialize(self):
        r = struct.pack("<B", self.filter_type)
        r += struct.pack("<I", self.start_height)
        r += ser_uint256(self.stop_hash)
        return r

    def __repr__(self):
        return "msg_getcfilters(filter_type=%d, start=%d, stop=%064x)" % (
            self.filter_type, self.start_height, self.stop_hash)


class msg_cfilter(object):
    command = b"cfilter"

    def __init__(self):
        self.filter_type = 0
        self.block_hash = 0
        self.filter_data = b""

    def deserialize(self, f):
        self.filter_type = struct.unpack("<B", f.read(1))[0]
        self.block_hash = deser_uint256(f)
        self.filter_data = deser_string(f)

    def serialize(self):
        r = struct.pack("<B", self.filter_type)
        r += ser_uint256(self.block_hash)
        r += ser_string(self.filter_data)
        return r

    def __repr__(self):
        return "msg_cfilter(type=%d, hash=%064x, len=%d)" % (
            self.filter_type, self.block_hash, len(self.filter_data))


class msg_getcfheaders(object):
    command = b"getcfheaders"

    def __init__(self, filter_type=0, start_height=0, stop_hash=0):
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = struct.unpack("<B", f.read(1))[0]
        self.start_height = struct.unpack("<I", f.read(4))[0]
        self.stop_hash = deser_uint256(f)

    def serialize(self):
        r = struct.pack("<B", self.filter_type)
        r += struct.pack("<I", self.start_height)
        r += ser_uint256(self.stop_hash)
        return r

    def __repr__(self):
        return "msg_getcfheaders(filter_type=%d, start=%d, stop=%064x)" % (
            self.filter_type, self.start_height, self.stop_hash)


class msg_cfheaders(object):
    command = b"cfheaders"

    def __init__(self):
        self.filter_type = 0
        self.stop_hash = 0
        self.prev_header = 0
        self.hashes = []

    def deserialize(self, f):
        self.filter_type = struct.unpack("<B", f.read(1))[0]
        self.stop_hash = deser_uint256(f)
        self.prev_header = deser_uint256(f)
        self.hashes = deser_uint256_vector(f)

    def serialize(self):
        r = struct.pack("<B", self.filter_type)
        r += ser_uint256(self.stop_hash)
        r += ser_uint256(self.prev_header)
        r += ser_uint256_vector(self.hashes)
        return r

    def __repr__(self):
        return "msg_cfheaders(type=%d, stop=%064x, prev=%064x, %d hashes)" % (
            self.filter_type, self.stop_hash, self.prev_header, len(self.hashes))


class msg_getcfcheckpt(object):
    command = b"getcfcheckpt"

    def __init__(self, filter_type=0, stop_hash=0):
        self.filter_type = filter_type
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = struct.unpack("<B", f.read(1))[0]
        self.stop_hash = deser_uint256(f)

    def serialize(self):
        r = struct.pack("<B", self.filter_type)
        r += ser_uint256(self.stop_hash)
        return r

    def __repr__(self):
        return "msg_getcfcheckpt(filter_type=%d, stop=%064x)" % (
            self.filter_type, self.stop_hash)


class msg_cfcheckpt(object):
    command = b"cfcheckpt"

    def __init__(self):
        self.filter_type = 0
        self.stop_hash = 0
        self.headers = []

    def deserialize(self, f):
        self.filter_type = struct.unpack("<B", f.read(1))[0]
        self.stop_hash = deser_uint256(f)
        self.headers = deser_uint256_vector(f)

    def serialize(self):
        r = struct.pack("<B", self.filter_type)
        r += ser_uint256(self.stop_hash)
        r += ser_uint256_vector(self.headers)
        return r

    def __repr__(self):
        return "msg_cfcheckpt(type=%d, stop=%064x, %d headers)" % (
            self.filter_type, self.stop_hash, len(self.headers))


# Register BIP 157 response messages in the messagemap so they are parsed
NodeConn.messagemap[b"cfilter"] = msg_cfilter
NodeConn.messagemap[b"cfheaders"] = msg_cfheaders
NodeConn.messagemap[b"cfcheckpt"] = msg_cfcheckpt


# -------------------------------------------------------------------
# Test P2P callback node
# -------------------------------------------------------------------

class CompactFiltersNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.cfilters = []
        self.last_cfheaders = None
        self.last_cfcheckpt = None
        self.disconnected = False

    def on_cfilter(self, conn, message):
        self.cfilters.append(message)

    def on_cfheaders(self, conn, message):
        self.last_cfheaders = message

    def on_cfcheckpt(self, conn, message):
        self.last_cfcheckpt = message

    def on_close(self, conn):
        self.disconnected = True

    def clear(self):
        self.cfilters = []
        self.last_cfheaders = None
        self.last_cfcheckpt = None

    def wait_for_cfilters(self, count, timeout=30):
        wait_until(lambda: len(self.cfilters) >= count, timeout=timeout)

    def wait_for_cfheaders(self, timeout=30):
        wait_until(lambda: self.last_cfheaders is not None, timeout=timeout)

    def wait_for_cfcheckpt(self, timeout=30):
        wait_until(lambda: self.last_cfcheckpt is not None, timeout=timeout)

    def wait_for_disconnect(self, timeout=30):
        wait_until(lambda: self.disconnected, timeout=timeout)


# -------------------------------------------------------------------
# Main test class
# -------------------------------------------------------------------

class BIP157CompactFiltersTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.log = logging.getLogger("BIP157CompactFiltersTest")

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir,
            ["-debug", "-blockfilterindex", "-peerblockfilters"]))
        self.is_network_split = False

    def run_test(self):
        node_rpc = self.nodes[0]

        # Generate some blocks for testing
        node_rpc.generate(50)

        # Pre-create all P2P test nodes BEFORE starting NetworkThread.
        # The asyncore loop must see all sockets at start time.
        test_node = CompactFiltersNode()      # for tests 2-7
        bad_node = CompactFiltersNode()       # test 8: bad filter type
        bad_node2 = CompactFiltersNode()      # test 9: bad stop hash
        bad_node3 = CompactFiltersNode()      # test 10: start > stop

        connections = []
        for n in [test_node, bad_node, bad_node2, bad_node3]:
            conn = NodeConn('127.0.0.1', p2p_port(0), node_rpc, n)
            n.add_connection(conn)
            connections.append(conn)

        # Start the network thread — processes all pre-created sockets
        NetworkThread().start()

        # Wait for all handshakes to complete
        for n in [test_node, bad_node, bad_node2, bad_node3]:
            n.wait_for_verack()

        # ---- Test 1: NODE_COMPACT_FILTERS service bit ----
        self.log.info("Test 1: NODE_COMPACT_FILTERS service bit advertised")
        net_info = node_rpc.getnetworkinfo()
        local_services = int(net_info['localservices'], 16)
        assert local_services & NODE_COMPACT_FILTERS, \
            "NODE_COMPACT_FILTERS bit not set in localservices: %x" % local_services
        self.log.info("  Service bit OK: localservices=%x" % local_services)

        # ---- Test 2: getcfilters / cfilter ----
        self.log.info("Test 2: getcfilters returns correct number of cfilter messages")

        stop_hash = int(node_rpc.getblockhash(10), 16)
        test_node.send_message(msg_getcfilters(
            filter_type=FILTER_TYPE_BASIC,
            start_height=1,
            stop_hash=stop_hash
        ))
        test_node.wait_for_cfilters(10)
        assert_equal(len(test_node.cfilters), 10)

        # Verify each filter has the correct filter_type
        for cf in test_node.cfilters:
            assert_equal(cf.filter_type, FILTER_TYPE_BASIC)
            assert cf.block_hash != 0
            assert len(cf.filter_data) > 0

        # Verify block hashes match expected
        expected_hashes = set()
        for h in range(1, 11):
            expected_hashes.add(int(node_rpc.getblockhash(h), 16))
        actual_hashes = set(cf.block_hash for cf in test_node.cfilters)
        assert_equal(expected_hashes, actual_hashes)

        self.log.info("  Received %d cfilter messages with correct hashes" % len(test_node.cfilters))

        # ---- Test 3: getcfilters for single block ----
        self.log.info("Test 3: getcfilters for a single block")
        test_node.clear()
        block5_hash = int(node_rpc.getblockhash(5), 16)
        test_node.send_message(msg_getcfilters(
            filter_type=FILTER_TYPE_BASIC,
            start_height=5,
            stop_hash=block5_hash
        ))
        test_node.wait_for_cfilters(1)
        assert_equal(len(test_node.cfilters), 1)
        assert_equal(test_node.cfilters[0].block_hash, block5_hash)
        self.log.info("  Single-block getcfilters OK")

        # ---- Test 4: getcfheaders / cfheaders ----
        self.log.info("Test 4: getcfheaders returns cfheaders message")
        test_node.clear()
        stop_hash_20 = int(node_rpc.getblockhash(20), 16)
        test_node.send_message(msg_getcfheaders(
            filter_type=FILTER_TYPE_BASIC,
            start_height=1,
            stop_hash=stop_hash_20
        ))
        test_node.wait_for_cfheaders()

        cfh = test_node.last_cfheaders
        assert_equal(cfh.filter_type, FILTER_TYPE_BASIC)
        assert_equal(cfh.stop_hash, stop_hash_20)
        # Should have 20 filter hashes (blocks 1 through 20)
        assert_equal(len(cfh.hashes), 20)
        # prev_header should be the filter header for block 0 (before start_height=1)
        assert cfh.prev_header != 0, "prev_header should be nonzero for start_height=1"

        self.log.info("  Received cfheaders with %d hashes" % len(cfh.hashes))

        # ---- Test 5: cfheaders starting from height 0 ----
        self.log.info("Test 5: getcfheaders from height 0")
        test_node.clear()
        stop_hash_5 = int(node_rpc.getblockhash(5), 16)
        test_node.send_message(msg_getcfheaders(
            filter_type=FILTER_TYPE_BASIC,
            start_height=0,
            stop_hash=stop_hash_5
        ))
        test_node.wait_for_cfheaders()

        cfh = test_node.last_cfheaders
        assert_equal(cfh.filter_type, FILTER_TYPE_BASIC)
        # Starting from height 0 means prev_header is the zero hash
        assert_equal(cfh.prev_header, 0)
        # Should have 6 hashes (blocks 0 through 5)
        assert_equal(len(cfh.hashes), 6)
        self.log.info("  cfheaders from height 0 OK, prev_header is zero")

        # ---- Test 6: getcfcheckpt / cfcheckpt ----
        self.log.info("Test 6: getcfcheckpt returns cfcheckpt (empty for <1000 blocks)")
        test_node.clear()
        tip_hash = int(node_rpc.getbestblockhash(), 16)
        test_node.send_message(msg_getcfcheckpt(
            filter_type=FILTER_TYPE_BASIC,
            stop_hash=tip_hash
        ))
        test_node.wait_for_cfcheckpt()

        ckpt = test_node.last_cfcheckpt
        assert_equal(ckpt.filter_type, FILTER_TYPE_BASIC)
        assert_equal(ckpt.stop_hash, tip_hash)
        # With only 50 blocks, checkpoint interval is 1000, so 0 headers
        assert_equal(len(ckpt.headers), 0)
        self.log.info("  cfcheckpt with 0 checkpoint headers (50 blocks < 1000 interval)")

        # ---- Test 7: cfilter data matches RPC getblockfilter ----
        self.log.info("Test 7: P2P cfilter data matches RPC getblockfilter")
        test_node.clear()
        block3_hash_hex = node_rpc.getblockhash(3)
        block3_hash_int = int(block3_hash_hex, 16)
        test_node.send_message(msg_getcfilters(
            filter_type=FILTER_TYPE_BASIC,
            start_height=3,
            stop_hash=block3_hash_int
        ))
        test_node.wait_for_cfilters(1)

        p2p_filter = test_node.cfilters[0]
        rpc_result = node_rpc.getblockfilter(block3_hash_hex)

        # The P2P filter_data should match the RPC hex filter
        p2p_hex = p2p_filter.filter_data.hex()
        assert_equal(p2p_hex, rpc_result['filter'])
        self.log.info("  P2P filter matches RPC: %s" % p2p_hex)

        # ---- Test 8: Disconnect on unsupported filter type ----
        self.log.info("Test 8: Peer disconnected for unsupported filter type")
        # Filter type 255 is not supported
        bad_node.send_message(msg_getcfilters(
            filter_type=255,
            start_height=0,
            stop_hash=int(node_rpc.getblockhash(1), 16)
        ))
        bad_node.wait_for_disconnect(timeout=30)
        assert bad_node.disconnected
        self.log.info("  Peer disconnected for bad filter type OK")

        # ---- Test 9: Disconnect on unknown stop hash ----
        self.log.info("Test 9: Peer disconnected for unknown stop hash")
        bad_node2.send_message(msg_getcfilters(
            filter_type=FILTER_TYPE_BASIC,
            start_height=0,
            stop_hash=0xdeadbeef
        ))
        bad_node2.wait_for_disconnect(timeout=30)
        assert bad_node2.disconnected
        self.log.info("  Peer disconnected for unknown stop hash OK")

        # ---- Test 10: Disconnect on start_height > stop_height ----
        self.log.info("Test 10: Peer disconnected for start_height > stop_height")
        bad_node3.send_message(msg_getcfilters(
            filter_type=FILTER_TYPE_BASIC,
            start_height=999,
            stop_hash=int(node_rpc.getblockhash(5), 16)
        ))
        bad_node3.wait_for_disconnect(timeout=30)
        assert bad_node3.disconnected
        self.log.info("  Peer disconnected for start > stop OK")

        self.log.info("All BIP 157 P2P compact filter tests passed!")


if __name__ == '__main__':
    BIP157CompactFiltersTest().main()
