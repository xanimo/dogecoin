#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Scan for silent payments the way a light client would.

A client cannot derive scanning tweaks itself, so it asks a serving peer for them, builds the
scripts it would own from each tweak, and asks that block's BIP158 filter whether any appear.
It reads only the blocks that match.

Two things have to hold for that to be worth doing. It must find exactly what a full scan finds,
otherwise it is a faster way to miss payments. And it must read far fewer blocks than it walks,
otherwise it is a full scan with extra steps.
"""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    start_node,
    start_nodes,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
    assert_equal,
    assert_raises_jsonrpc,
)


def wait_for_indexes(node, names, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = node.getindexinfo()
        if all(info.get(n, {}).get('synced') for n in names):
            return
        time.sleep(0.5)
    raise AssertionError('indexes did not sync: %s' % node.getindexinfo())


class SilentPaymentsFilteredTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        args = [['-tweakindex', '-blockfilterindex=basic', '-usehd=1'],
                ['-tweakindex', '-blockfilterindex=basic', '-usehd=1']]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, args)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        sender, receiver = self.nodes[0], self.nodes[1]
        sp_address = receiver.getsilentpaymentaddress()

        sender.generate(200)
        self.sync_all()
        sender.sendtoaddress(sender.getnewaddress(), 1000)
        sender.generate(1)
        self.sync_all()

        # Noise: blocks that carry eligible transactions paying somebody else entirely. These
        # are what the filter has to let the client skip, and without them the test would
        # prove nothing about skipping.
        for _ in range(12):
            sender.sendtoaddress(sender.getnewaddress(), 5)
            sender.generate(1)
        self.sync_all()

        # Two real payments, separated by more noise.
        paid = []
        for amount in (40, 25):
            txid = sender.sendtosilentpaymentaddress(sp_address, amount)
            sync_mempools(self.nodes)
            sender.generate(1)
            paid.append(txid)
            for _ in range(6):
                sender.sendtoaddress(sender.getnewaddress(), 5)
                sender.generate(1)
        sync_blocks(self.nodes)
        tip = sender.getblockcount()

        wait_for_indexes(receiver, ['tweakindex', 'basic block filter index'])

        full = receiver.scansilentpayments(0, tip)['found']
        light = receiver.scansilentpaymentsfiltered(0, tip)

        # Same answer, or the filter path is a faster way to miss money.
        assert_equal(sorted(f['txid'] for f in light['found']),
                     sorted(f['txid'] for f in full))
        assert_equal(sorted(paid), sorted(set(f['txid'] for f in light['found'])))
        assert_equal(sorted(f['amount'] for f in light['found']), [25, 40])

        # And it has to actually skip. Every block after the first spend carries a tweak, so
        # blocks_with_tweaks is the work a client without filters would do, and blocks_read is
        # what it does with them.
        assert light['blocks_with_tweaks'] > light['blocks_read'], \
            'the filter skipped nothing: %s' % light
        assert light['blocks_read'] >= 2, \
            'the two blocks holding payments must be read: %s' % light
        assert light['candidates_queried'] > 0

        print('light client over %d blocks: %d carried tweaks, %d read, %d candidates queried, '
              '%d false positives' % (light['blocks_in_range'], light['blocks_with_tweaks'],
                                      light['blocks_read'], light['candidates_queried'],
                                      light['false_positives']))

        # The derived key still has to spend, same as the full path.
        hit = light['found'][0]
        unspent = [u for u in receiver.listunspent(0, 9999999, [hit['address']])
                   if u['txid'] == hit['txid']]
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]['spendable'], True)

        # Without the filter index there is nothing to query, and saying so beats quietly
        # falling back to reading every block.
        self.stop_node(1)
        self.nodes[1] = start_node(1, self.options.tmpdir, ['-tweakindex', '-usehd=1'])
        assert_raises_jsonrpc(-1, "needs -blockfilterindex=basic",
                              self.nodes[1].scansilentpaymentsfiltered, 0, 1)
        connect_nodes_bi(self.nodes, 0, 1)


if __name__ == '__main__':
    SilentPaymentsFilteredTest().main()
