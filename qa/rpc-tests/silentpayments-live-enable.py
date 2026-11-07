#!/usr/bin/env python3
"""Independent regression: first payment after enabling live scanning.

Run against unmodified binaries. Exit 1 demonstrates the missed payment;
the explicit scan is a control proving the payment is valid and recoverable.
"""
import json
from pathlib import Path
import sys

# Invoke from the checkout root; --srcdir can select the built binaries.
sys.path.insert(0, str(Path.cwd() / 'qa/rpc-tests'))
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (start_nodes, start_node, connect_nodes_bi,
                                 sync_blocks, sync_mempools, assert_equal)
from silentpayments import wait_for_port_free, wait_for_index_sync
from test_framework.util import rpc_port


class LiveEnableRegression(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = start_nodes(2, self.options.tmpdir,
                                 [['-tweakindex', '-usehd=1'], ['-usehd=1']])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        sender, receiver = self.nodes
        sender.generate(200)
        self.sync_all()
        sender.sendtoaddress(sender.getnewaddress(), 1000)
        sender.generate(1)
        self.sync_all()
        address = receiver.getsilentpaymentaddress()
        historical_txid = sender.sendtosilentpaymentaddress(address, 30)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        historical_height = receiver.getblockcount()

        # Turn live scanning on for the first time on an already synced node.
        self.stop_node(1)
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = start_node(1, self.options.tmpdir,
                                  ['-tweakindex', '-usehd=1', '-silentpaymentscan'])
        receiver = self.nodes[1]
        connect_nodes_bi(self.nodes, 0, 1)
        self.sync_all()
        wait_for_index_sync(receiver, 'tweakindex')
        start_height = receiver.getblockcount()
        historical = [f for f in receiver.scansilentpayments(0, historical_height)['found']
                      if f['txid'] == historical_txid and f['amount'] == 30]
        assert_equal(len(historical), 1)
        print('Fresh index built from genesis; explicit scan recovered the historical payment', flush=True)

        txid = sender.sendtosilentpaymentaddress(address, 100)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        # Record first-block discovery, then check again after another tip notification.
        live_first = [u for u in receiver.listunspent(0, 9999999)
                      if u['txid'] == txid and u['amount'] == 100]

        # Confirm another tip notification does not repair the skipped height.
        sender.generate(1)
        sync_blocks(self.nodes)
        live_next = [u for u in receiver.listunspent(0, 9999999)
                     if u['txid'] == txid and u['amount'] == 100]
        manual = [f for f in receiver.scansilentpayments(start_height + 1, start_height + 1)['found']
                  if f['txid'] == txid and f['amount'] == 100]
        recovered = [u for u in receiver.listunspent(0, 9999999)
                     if u['txid'] == txid and u['amount'] == 100 and u['spendable']]
        print(json.dumps({'enabled_at_height': start_height, 'historical_payment_found': len(historical),
                          'payment_txid': txid,
                          'live_first_block': len(live_first), 'live_next_block': len(live_next),
                          'manual_scan': len(manual), 'spendable_after_manual_scan': len(recovered)},
                         indent=2), flush=True)
        assert_equal(len(manual), 1)
        assert_equal(len(recovered), 1)
        assert_equal(len(live_first), 1)


if __name__ == '__main__':
    LiveEnableRegression().main()
