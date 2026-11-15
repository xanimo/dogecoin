#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A scan over history must not credit an output that was spent since.

The case is a restore. A wallet is backed up, paid at its silent payment address, and sweeps
the payment out again with no change. The backup is then put back: it holds the seed and
neither transaction. A scan from the seed finds the payment and imports its key, and the
wallet is handed that one transaction. The sweep was passed over while the key was unknown,
it pays nothing back to the wallet, and nothing looks for it again, so the wallet used to
show the payment as its balance and select it, and a send built on it never left the node.

Run twice: once with no block filter index, where every block from the payment on is read,
and once through scansilentpaymentsfiltered, where the filters say which blocks to read.
"""

import os
import shutil
import socket
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    rpc_port,
    start_node,
    start_nodes,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
    assert_equal,
    assert_raises_jsonrpc,
)


def wait_for_port_free(port, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(('127.0.0.1', port))
        except (ConnectionRefusedError, socket.timeout):
            return
        finally:
            s.close()
        time.sleep(0.25)
    raise AssertionError('port %d still in use' % port)


def wait_for_indexes(node, names, timeout=60):
    """Until every named index has written the node's tip. An index reports itself synced once
    its first sync is over and follows the chain from a queue after that, so synced alone does
    not say the newest block is in it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = node.getindexinfo()
        tip = node.getblockcount()
        if all(info.get(n, {}).get('synced') and info[n]['best_block_height'] == tip for n in names):
            return
        time.sleep(0.25)
    raise AssertionError('indexes did not reach the tip: %s' % node.getindexinfo())


class SilentPaymentsRestoreTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir,
                                 [['-usehd=1'], ['-tweakindex', '-usehd=1']])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def restore(self, extra_args):
        self.stop_node(1)
        wait_for_port_free(rpc_port(1))
        shutil.copyfile(self.backup, os.path.join(self.options.tmpdir, 'node1', 'regtest', 'wallet.dat'))
        self.nodes[1] = start_node(1, self.options.tmpdir, ['-tweakindex', '-usehd=1', '-rescan'] + extra_args)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        return self.nodes[1]

    def check_knows_the_spend(self, receiver):
        assert_equal(receiver.getbalance(), 0)
        assert (self.txid, self.vout) not in [(u['txid'], u['vout']) for u in receiver.listunspent(0)]
        assert receiver.gettransaction(self.sweep)['confirmations'] >= 1
        # and so it does not build a transaction on a coin that is gone
        assert_raises_jsonrpc(-6, "Insufficient funds", receiver.sendtoaddress,
                              self.nodes[0].getnewaddress(), 300)

    def run_test(self):
        sender, receiver = self.nodes[0], self.nodes[1]
        sender.generate(200)
        self.sync_all()
        # Coinbases are P2PK, which the rule does not count, so give the sender a P2PKH coin.
        sender.sendtoaddress(sender.getnewaddress(), 1000)
        sender.generate(1)
        self.sync_all()

        # The backup lands in the node's backup directory. It holds the seed and no payment.
        receiver.backupwallet('before-payment.dat')
        self.backup = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'backups', 'before-payment.dat')
        assert os.path.exists(self.backup)
        address = receiver.getsilentpaymentaddress()

        self.txid = sender.sendtosilentpaymentaddress(address, 600)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        wait_for_indexes(receiver, ['tweakindex'])
        found = receiver.scansilentpayments(0, receiver.getblockcount())['found']
        assert_equal(len(found), 1)
        self.vout = found[0]['vout']
        assert_equal(receiver.getbalance(), 600)

        # Swept with the fee taken from the amount, so nothing comes back to the wallet.
        self.sweep = receiver.sendtoaddress(sender.getnewaddress(), 600, "", "", True)
        sync_mempools(self.nodes)
        sender.generate(3)
        sync_blocks(self.nodes)
        assert_equal(receiver.getbalance(), 0)
        assert receiver.gettxout(self.txid, self.vout) is None

        # Restored with no block filter index: the scan reads every block from the payment on.
        receiver = self.restore([])
        wait_for_indexes(receiver, ['tweakindex'])
        assert_equal(receiver.getsilentpaymentaddress(), address)
        assert_equal(receiver.getbalance(), 0)          # -rescan alone finds nothing: no key yet
        found = receiver.scansilentpayments(0, receiver.getblockcount())['found']
        assert_equal([(f['txid'], f['vout']) for f in found], [(self.txid, self.vout)])
        self.check_knows_the_spend(receiver)

        # Restored again, with the filters, through the scan a light client would run.
        receiver = self.restore(['-blockfilterindex=basic'])
        wait_for_indexes(receiver, ['tweakindex', 'basic block filter index'])
        assert_equal(receiver.getbalance(), 0)
        found = receiver.scansilentpaymentsfiltered(0, receiver.getblockcount())['found']
        assert_equal([(f['txid'], f['vout']) for f in found], [(self.txid, self.vout)])
        self.check_knows_the_spend(receiver)

        # And the plain scan with the filters at hand, which takes the same shortcut.
        receiver = self.restore(['-blockfilterindex=basic'])
        wait_for_indexes(receiver, ['tweakindex', 'basic block filter index'])
        found = receiver.scansilentpayments(0, receiver.getblockcount())['found']
        assert_equal(len(found), 1)
        self.check_knows_the_spend(receiver)

        # -salvagewallet rewrites the wallet file from the records it recognises, which used to
        # be the keys and the hd chain. A label is a record of its own, and one that is dropped
        # is one the next scan does not look for.
        labelled = receiver.getsilentpaymentaddress(9)
        self.stop_node(1)
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = receiver = start_node(1, self.options.tmpdir, ['-tweakindex', '-usehd=1', '-salvagewallet'])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        paid = sender.sendtosilentpaymentaddress(labelled, 40)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        wait_for_indexes(receiver, ['tweakindex'])
        found = [f['txid'] for f in receiver.scansilentpayments(0, receiver.getblockcount())['found']]
        assert paid in found, 'a payment to a label handed out before -salvagewallet was not found'


if __name__ == '__main__':
    SilentPaymentsRestoreTest().main()
