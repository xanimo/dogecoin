#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""BIP352 silent payments end to end: publish an address, pay it, scan it, spend it.

Two nodes so the payment crosses a real wallet boundary rather than a wallet paying itself: node
0 is the sender and node 1 the receiver, and node 1 never learns anything but the address string.

Also covers the way this scheme loses money. Sender and receiver recover the eligible input set
from different material, the sender from the coins it owns and the receiver from the scriptSigs,
so if the two disagree the output commits to a key neither holds. Regtest reaches that case for
free because its coinbases are P2PK, which the receiver's P2PKH-only rule ignores.
"""

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
    """Wait until nothing is listening on `port`.

    A node that fails during startup has already bound its rpc port, and the next node can race
    it: "Binding RPC on address ::1 port N failed" is a flake, not a result, and it only showed
    up on the slower debug build.

    Probes by connecting rather than binding. Binding to test would leave this process's own
    sockets in TIME_WAIT and poison the port for the next poll.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        listening = False
        for family, addr in ((socket.AF_INET6, '::1'), (socket.AF_INET, '127.0.0.1')):
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
            except OSError:
                continue
            sock.settimeout(1)
            try:
                sock.connect((addr, port))
                listening = True
            except OSError:
                pass
            finally:
                sock.close()
            if listening:
                break
        if not listening:
            return
        time.sleep(0.5)
    raise AssertionError('something is still listening on rpc port %d' % port)


def wait_for_index_sync(node, name, timeout=60):
    """Wait until the named index reports itself synced.

    The index catches up in its own thread, so there is a window after startup where a scan would
    read a height it has not written yet.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = node.getindexinfo(name)
        if info.get(name, {}).get('synced'):
            return
        time.sleep(0.5)
    raise AssertionError('%s did not finish syncing: %s' % (name, node.getindexinfo(name)))


class SilentPaymentsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        args = [['-tweakindex', '-usehd=1'],
                ['-tweakindex', '-usehd=1', '-silentpaymentscan']]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, args)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        sender, receiver = self.nodes[0], self.nodes[1]

        sp_address = receiver.getsilentpaymentaddress()
        assert sp_address.startswith('dsprt1'), sp_address
        # Stable across calls: it is derived from the seed, not handed out from a pool.
        assert_equal(sp_address, receiver.getsilentpaymentaddress())

        sender.generate(200)
        self.sync_all()

        # Coinbases are P2PK, which the receiver's rule does not count. A sender that offered
        # them anyway would compute a different A and burn the coins, so it must refuse.
        assert_raises_jsonrpc(-4, "every selected coin must be P2PKH",
                              sender.sendtosilentpaymentaddress, sp_address, 100)

        # Give the sender P2PKH coins to spend.
        sender.sendtoaddress(sender.getnewaddress(), 1000)
        sender.generate(1)
        self.sync_all()

        txid = sender.sendtosilentpaymentaddress(sp_address, 100)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        height = sender.getblockcount()

        # The receiver runs -silentpaymentscan, so the payment should already be spendable
        # without anyone calling the rpc. This is the whole point of live scanning: a wallet
        # notices it was paid when the block arrives, not when its owner thinks to ask.
        live = [u for u in receiver.listunspent(0, 9999999)
                if u['txid'] == txid and u['amount'] == 100]
        assert_equal(len(live), 1)
        assert_equal(live[0]['spendable'], True)

        # The receiver was told nothing but the address, so it has to find this itself.
        scan = receiver.scansilentpayments(0, height)
        assert_equal(len(scan['found']), 1)
        found = scan['found'][0]
        assert_equal(found['txid'], txid)
        assert_equal(found['amount'], 100)
        assert_equal(found['height'], height)

        # The sender's own scan finds exactly one thing, its change, because change goes to the
        # sender's silent payment change address, BIP352's label 0. That is what makes change
        # recoverable by scanning from the seed rather than from the keypool; it is not a
        # privacy gain over a fresh keypool address.
        sender_scan = sender.scansilentpayments(0, height)['found']
        assert_equal(len(sender_scan), 1)
        assert_equal(sender_scan[0]['txid'], txid)
        assert sender_scan[0]['vout'] != found['vout'], 'change collided with the payment'

        # And the sender can spend that change without waiting for a scan, since the send
        # imported the key at the time it built the transaction.
        change_utxo = [u for u in sender.listunspent(0, 9999999, [sender_scan[0]['address']])
                       if u['txid'] == txid]
        assert_equal(len(change_utxo), 1)
        assert_equal(change_utxo[0]['spendable'], True)

        # The derived key has to actually spend, which is the only proof that matters.
        unspent = [u for u in receiver.listunspent(0, 9999999, [found['address']])
                   if u['txid'] == txid and u['vout'] == found['vout']]
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]['spendable'], True)

        raw = receiver.createrawtransaction(
            [{'txid': txid, 'vout': found['vout']}], {sender.getnewaddress(): 99})
        signed = receiver.signrawtransaction(raw)
        assert_equal(signed['complete'], True)
        spend_txid = receiver.sendrawtransaction(signed['hex'])
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        assert_equal(sender.getrawtransaction(spend_txid, 1)['confirmations'], 1)

        # Rescanning is idempotent: the same payment, not a second one.
        rescan = receiver.scansilentpayments(0, sender.getblockcount())
        assert_equal(len(rescan['found']), 1)

        # Two payments in one block where the second spends the first's change. The tweak is
        # derived from the coins a transaction spends, and for the second of these one of those
        # coins is an output of the first, which does not exist in the view until UpdateCoins has
        # run for it. Computing a block's tweaks up front rather than per transaction aborted the
        # node on mainnet at height 1181 for exactly this. Regtest only reaches it deliberately,
        # because every other block here holds a single transaction.
        before = sender.getblockcount()
        first = sender.sendtosilentpaymentaddress(sp_address, 50)
        # Lock every other coin so the second send has nothing to spend but the first's change.
        # Without this, coin selection picks an unrelated utxo and no chain forms.
        others = [{'txid': u['txid'], 'vout': u['vout']}
                  for u in sender.listunspent(0) if u['txid'] != first]
        if others:
            sender.lockunspent(False, others)
        second = sender.sendtosilentpaymentaddress(sp_address, 25)
        sender.lockunspent(True, others) if others else None
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        chained_height = sender.getblockcount()
        assert_equal(chained_height, before + 1)

        block = sender.getblock(sender.getblockhash(chained_height))
        assert first in block['tx'] and second in block['tx'], 'expected both in one block'
        # The second must actually spend the first, otherwise this proves nothing.
        spends = [vin['txid'] for vin in sender.getrawtransaction(second, 1)['vin']]
        assert first in spends, 'second transaction did not spend the first'

        chained = receiver.scansilentpayments(chained_height, chained_height)['found']
        assert_equal(sorted(f['amount'] for f in chained), [25, 50])

        # Labels. A labelled address is a different string paying the same wallet, and the label
        # must outlive the process: hand one out, restart, and a payment to it still has to be
        # found. A label the scanner has forgotten is a payment nobody sees.
        labelled = receiver.getsilentpaymentaddress(7)
        assert labelled != sp_address, 'labelled address should differ from the plain one'
        assert labelled.startswith('dsprt1'), labelled
        assert_equal(labelled, receiver.getsilentpaymentaddress(7))
        assert_raises_jsonrpc(-8, "reserved for change", receiver.getsilentpaymentaddress, 0)

        self.stop_node(1)
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = start_node(1, self.options.tmpdir,
                                   ['-usehd=1', '-tweakindex', '-silentpaymentscan'])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        receiver = self.nodes[1]
        assert_equal(receiver.getsilentpaymentaddress(7), labelled)

        label_txid = sender.sendtosilentpaymentaddress(labelled, 40)
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        label_height = sender.getblockcount()

        hit = [f for f in receiver.scansilentpayments(label_height, label_height)['found']
               if f['txid'] == label_txid and f['amount'] == 40]
        assert_equal(len(hit), 1)
        spendable = [u for u in receiver.listunspent(0, 9999999, [hit[0]['address']])
                     if u['txid'] == label_txid]
        assert_equal(len(spendable), 1)
        assert_equal(spendable[0]['spendable'], True)

        # Without the index there is nothing to scan, and saying so beats returning an empty set.
        self.stop_node(1)
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = start_node(1, self.options.tmpdir, ['-usehd=1'])
        assert_raises_jsonrpc(-1, "needs -tweakindex",
                              self.nodes[1].scansilentpayments, 0, 1)
        connect_nodes_bi(self.nodes, 0, 1)   # start_node drops the peer connection

        # Enabling the index on a node that is already synced must not need a reindex. The index
        # syncs the blocks it missed in its own thread, so a payment made while it was switched
        # off is still found afterwards. Pay while node 1 has no index at all, which is the state
        # a node is in the first time someone sets -tweakindex.
        offline_txid = sender.sendtosilentpaymentaddress(sp_address, 30)
        sync_mempools(self.nodes)
        sender.generate(5)
        sync_blocks(self.nodes)
        offline_height = sender.getblockcount()

        self.stop_node(1)
        wait_for_port_free(rpc_port(1))
        self.nodes[1] = start_node(1, self.options.tmpdir, ['-usehd=1', '-tweakindex'])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks(self.nodes)
        receiver = self.nodes[1]

        # No -reindex and no -reindex-chainstate anywhere in that restart.
        wait_for_index_sync(receiver, 'tweakindex')
        assert_equal(receiver.getindexinfo('tweakindex')['tweakindex']['best_block_height'],
                     receiver.getblockcount())

        caught_up = [f for f in receiver.scansilentpayments(0, offline_height)['found']
                     if f['txid'] == offline_txid and f['amount'] == 30]
        assert_equal(len(caught_up), 1)
        spendable = [u for u in receiver.listunspent(0, 9999999, [caught_up[0]['address']])
                     if u['txid'] == offline_txid]
        assert_equal(len(spendable), 1)
        assert_equal(spendable[0]['spendable'], True)


if __name__ == '__main__':
    SilentPaymentsTest().main()
