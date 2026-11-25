#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A reorganisation the live scan does not see.

The live scan keeps a mark of how far it has scanned and catches up from it. The handler that
moves the mark returns early while the wallet is locked and does not run at all while the
option is off, and a reorganisation that goes by then is in no later notification. If the
mark were a height alone, the block that replaced the one at the mark would never be scanned,
and a payment in it would be credited only by an explicit scan.

Twice over, once with the option off across the reorganisation and once with the wallet
locked: a payment is found live, which puts the mark on its block; that block is replaced
by one carrying a second payment while the handler is not looking; and once it is looking
again the second payment has to be credited with nobody asking for a scan.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (start_node, start_nodes, stop_node, connect_nodes_bi, sync_blocks,
                                 sync_mempools, rpc_port, dogecoind_processes, assert_equal)
from silentpayments import wait_for_index_sync, wait_for_port_free, wait_for_credit

LIVE = ['-tweakindex', '-usehd=1', '-silentpaymentscan']
QUIET = ['-tweakindex', '-usehd=1']
PASSPHRASE = 'a passphrase'


class ReorgMark(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = start_nodes(2, self.options.tmpdir, [['-usehd=1'], LIVE])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def start_receiver(self, args):
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = start_node(1, self.options.tmpdir, args)
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        wait_for_index_sync(self.nodes[1], 'tweakindex')

    def replaced_at_the_mark(self, amount, hide, show):
        """Pay, let the live scan find it, then replace that block while hide() is in force."""
        sender = self.nodes[0]
        address = self.nodes[1].getsilentpaymentaddress()
        first = sender.sendtosilentpaymentaddress(address, amount)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        assert_equal(len(wait_for_credit(self.nodes[1], first, amount)), 1)
        height = self.nodes[1].getblockcount()
        replaced = self.nodes[1].getblockhash(height)

        hide()
        for node in self.nodes:
            node.invalidateblock(replaced)
        second = sender.sendtosilentpaymentaddress(address, amount + 1)
        sync_mempools(self.nodes)
        sender.generate(2)
        sync_blocks(self.nodes)
        assert self.nodes[1].getblockhash(height) != replaced
        assert second in self.nodes[1].getblock(self.nodes[1].getblockhash(height))['tx']
        show()

        # The handler runs again on the next tip, and the mark is two blocks behind it.
        sender.generate(1)
        sync_blocks(self.nodes)
        wait_for_index_sync(self.nodes[1], 'tweakindex')
        credited = wait_for_credit(self.nodes[1], second, amount + 1)
        assert_equal(len(credited), 1)
        assert_equal(credited[0]['spendable'], True)

    def run_test(self):
        sender = self.nodes[0]
        sender.generate(200)
        self.sync_all()
        # Coinbases are P2PK, which the rule does not count, so give the sender P2PKH coins.
        sender.sendmany('', dict((sender.getnewaddress(), 100) for _ in range(10)))
        sender.generate(1)
        self.sync_all()
        wait_for_index_sync(self.nodes[1], 'tweakindex')

        def option_off():
            stop_node(self.nodes[1], 1)
            self.start_receiver(QUIET)

        def option_on():
            stop_node(self.nodes[1], 1)
            self.start_receiver(LIVE)

        self.replaced_at_the_mark(10, option_off, option_on)

        # encryptwallet stops the node once it has rewritten the wallet.
        self.nodes[1].encryptwallet(PASSPHRASE)
        dogecoind_processes[1].wait()
        self.start_receiver(LIVE)
        self.nodes[1].walletpassphrase(PASSPHRASE, 3600)

        self.replaced_at_the_mark(20, lambda: self.nodes[1].walletlock(),
                                  lambda: self.nodes[1].walletpassphrase(PASSPHRASE, 3600))


if __name__ == '__main__':
    ReorgMark().main()
