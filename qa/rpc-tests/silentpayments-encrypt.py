#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""An address given out before encryptwallet goes on being paid to, and found.

encryptwallet replaces the HD seed with a new one, because the old one has been on disk in the
clear. The silent payment keys are derived from the seed in use, so the address the wallet
returns changes with it. That alone is what the wallet does for every other address. What it
must not do is stop looking for payments to the address it already gave out, since a silent
payment address is one string published once: the scan used to cover the seed in use and no
other, and a payment to the earlier address was derived, confirmed and never seen.
"""

import socket
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    dogecoind_processes,
    rpc_port,
    start_node,
    start_nodes,
    connect_nodes_bi,
    sync_blocks,
    sync_mempools,
    assert_equal,
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
    """Until every named index has written the node's tip, which is later than synced."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = node.getindexinfo()
        tip = node.getblockcount()
        if all(info.get(n, {}).get('synced') and info[n]['best_block_height'] == tip for n in names):
            return
        time.sleep(0.25)
    raise AssertionError('indexes did not reach the tip: %s' % node.getindexinfo())


class SilentPaymentsEncryptTest(BitcoinTestFramework):

    RECEIVER_ARGS = ['-tweakindex', '-blockfilterindex=basic', '-usehd=1', '-silentpaymentscan']
    INDEXES = ['tweakindex', 'basic block filter index']

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [['-usehd=1'], self.RECEIVER_ARGS])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def pay(self, address, amount):
        txid = self.nodes[0].sendtosilentpaymentaddress(address, amount)
        sync_mempools(self.nodes)
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)
        wait_for_indexes(self.nodes[1], self.INDEXES)
        return txid

    def wait_for_balance(self, amount, timeout=30):
        # The live scanner runs behind the tip notification, on its own thread.
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.nodes[1].getbalance() == amount:
                return
            time.sleep(0.25)
        assert_equal(self.nodes[1].getbalance(), amount)

    def run_test(self):
        sender, receiver = self.nodes[0], self.nodes[1]
        sender.generate(200)
        self.sync_all()
        # Coinbases are P2PK, which the rule does not count, so give the sender a P2PKH coin.
        sender.sendtoaddress(sender.getnewaddress(), 1000)
        sender.generate(1)
        self.sync_all()

        before = receiver.getsilentpaymentaddress()
        labelled_before = receiver.getsilentpaymentaddress(5)
        paid = [self.pay(before, 100)]
        self.wait_for_balance(100)

        # encryptwallet stops the node once it has rewritten the wallet.
        receiver.encryptwallet('a passphrase')
        dogecoind_processes[1].wait()
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = receiver = start_node(1, self.options.tmpdir, self.RECEIVER_ARGS)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        receiver.walletpassphrase('a passphrase', 3600)

        # A new seed, so a new address, as for every other key the wallet hands out from here.
        after = receiver.getsilentpaymentaddress()
        assert after != before

        # The address already given out is still paid to and still found, live and unlocked.
        paid.append(self.pay(before, 250))
        self.wait_for_balance(350)
        # So is a labelled address under the earlier seed: a label is recorded by number alone.
        paid.append(self.pay(labelled_before, 30))
        self.wait_for_balance(380)
        # And the new address.
        paid.append(self.pay(after, 70))
        self.wait_for_balance(450)

        # A scan from the keys alone covers both seeds, by either route.
        tip = receiver.getblockcount()
        plain = set(f['txid'] for f in receiver.scansilentpayments(0, tip)['found'])
        assert set(paid) <= plain, (paid, plain)
        filtered = set(f['txid'] for f in receiver.scansilentpaymentsfiltered(0, tip)['found'])
        assert set(paid) <= filtered, (paid, filtered)

        # What was received under the earlier seed can be spent.
        receiver.sendtoaddress(sender.getnewaddress(), 440)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        assert receiver.getbalance() < 10


if __name__ == '__main__':
    SilentPaymentsEncryptTest().main()
