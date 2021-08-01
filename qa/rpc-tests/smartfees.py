#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test fee estimation code
#

from collections import OrderedDict
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Construct 2 trivial P2SH's and the ScriptSigs that spend them
# So we can create many many transactions without needing to spend
# time signing.
P2SH_1 = "2MySexEGVzZpRgNQ1JdjdP5bRETznm3roQ2" # P2SH of "OP_1 OP_DROP"
P2SH_2 = "2NBdpwq8Aoo1EEKEXPNrKvr5xQr3M9UfcZA" # P2SH of "OP_2 OP_DROP"
# Associated ScriptSig's to spend satisfy P2SH_1 and P2SH_2
# 4 bytes of OP_TRUE and push 2-byte redeem script of "OP_1 OP_DROP" or "OP_2 OP_DROP"
SCRIPT_SIG = ["0451025175", "0451025275"]

def small_txpuzzle_randfee(from_node, conflist, unconflist, amount, min_fee, fee_increment):
    '''
    Create and send a transaction with a random fee.
    The transaction pays to a trivial P2SH script, and assumes that its inputs
    are of the same form.
    The function takes a list of confirmed outputs and unconfirmed outputs
    and attempts to use the confirmed list first for its inputs.
    It adds the newly created outputs to the unconfirmed list.
    Returns (raw transaction, fee)
    '''
    # It's best to exponentially distribute our random fees
    # because the buckets are exponentially spaced.
    # Exponentially distributed from 1-128 * fee_increment
    rand_fee = float(fee_increment)*(1.1892**random.randint(0,28))
    # Total fee ranges from min_fee to min_fee + 127*fee_increment
    fee = min_fee - fee_increment + satoshi_round(rand_fee)
    inputs = []
    total_in = Decimal("0.00000000")
    while total_in <= (amount + fee) and len(conflist) > 0:
        t = conflist.pop(0)
        total_in += t["amount"]
        inputs.append({ "txid" : t["txid"], "vout" : t["vout"]} )
    if total_in <= amount + fee:
        while total_in <= (amount + fee) and len(unconflist) > 0:
            t = unconflist.pop(0)
            total_in += t["amount"]
            inputs.append({ "txid" : t["txid"], "vout" : t["vout"]} )
        if total_in <= amount + fee:
            raise RuntimeError("Insufficient funds: need %d, have %d"%(amount+fee, total_in))
    outputs = {}
    outputs = OrderedDict([(P2SH_1, total_in - amount - fee),
                           (P2SH_2, amount)])
    rawtx = from_node.createrawtransaction(inputs, outputs)
    # createrawtransaction constructs a transaction that is ready to be signed.
    # These transactions don't need to be signed, but we still have to insert the ScriptSig
    # that will satisfy the ScriptPubKey.
    completetx = rawtx[0:10]
    inputnum = 0
    for inp in inputs:
        completetx += rawtx[10+82*inputnum:82+82*inputnum]
        completetx += SCRIPT_SIG[inp["vout"]]
        completetx += rawtx[84+82*inputnum:92+82*inputnum]
        inputnum += 1
    completetx += rawtx[10+82*inputnum:]
    txid = from_node.sendrawtransaction(completetx, True)
    unconflist.append({ "txid" : txid, "vout" : 0 , "amount" : total_in - amount - fee})
    unconflist.append({ "txid" : txid, "vout" : 1 , "amount" : amount})

    return (completetx, fee)

def split_inputs(from_node, txins, txouts, initial_split = False):
    '''
    We need to generate a lot of very small inputs so we can generate a ton of transactions
    and they will have low priority.
    This function takes an input from txins, and creates and sends a transaction
    which splits the value into 2 outputs which are appended to txouts.
    '''
    prevtxout = txins.pop()
    inputs = []
    inputs.append({ "txid" : prevtxout["txid"], "vout" : prevtxout["vout"] })
    half_change = satoshi_round(prevtxout["amount"]/2)
    rem_change = prevtxout["amount"] - half_change  - Decimal("0.00001000")
    outputs = OrderedDict([(P2SH_1, half_change), (P2SH_2, rem_change)])
    rawtx = from_node.createrawtransaction(inputs, outputs)
    # If this is the initial split we actually need to sign the transaction
    # Otherwise we just need to insert the property ScriptSig
    if (initial_split) :
        completetx = from_node.signrawtransaction(rawtx)["hex"]
    else :
        completetx = rawtx[0:82] + SCRIPT_SIG[prevtxout["vout"]] + rawtx[84:]
    txid = from_node.sendrawtransaction(completetx, True)
    txouts.append({ "txid" : txid, "vout" : 0 , "amount" : half_change})
    txouts.append({ "txid" : txid, "vout" : 1 , "amount" : rem_change})


class EstimateFeeTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = False

    def setup_network(self):
        '''
        We'll setup the network to have 3 nodes that all mine with different parameters.
        But first we need to use one node to create a lot of small low priority outputs
        which we will use to generate our transactions.
        '''
        self.nodes = []
        # Use node0 to mine blocks for input splitting
        self.nodes.append(start_node(0, self.options.tmpdir, ["-maxorphantx=1000",
                                                              "-whitelist=127.0.0.1"]))

        print("This test is time consuming, please be patient")
        print("Splitting inputs to small size so we can generate low priority tx's")
        self.txouts = []
        self.txouts2 = []
        # Split a coinbase into two transaction puzzle outputs
        split_inputs(self.nodes[0], self.nodes[0].listunspent(0), self.txouts, True)

        # Mine
        while (len(self.nodes[0].getrawmempool()) > 0):
            self.nodes[0].generate(1)

        # Repeatedly split those 2 outputs, doubling twice for each rep
        # Use txouts to monitor the available utxo, since these won't be tracked in wallet
        reps = 0
        while (reps < 5):
            #Double txouts to txouts2
            while (len(self.txouts)>0):
                split_inputs(self.nodes[0], self.txouts, self.txouts2)
            while (len(self.nodes[0].getrawmempool()) > 0):
                self.nodes[0].generate(1)
            #Double txouts2 to txouts
            while (len(self.txouts2)>0):
                split_inputs(self.nodes[0], self.txouts2, self.txouts)
            while (len(self.nodes[0].getrawmempool()) > 0):
                self.nodes[0].generate(1)
            reps += 1
        print("Finished splitting")

        # Now we can connect the other nodes, didn't want to connect them earlier
        # so the estimates would not be affected by the splitting transactions
        # Node1 mines small blocks but that are bigger than the expected transaction rate,
        # and allows free transactions.
        # NOTE: the CreateNewBlock code starts counting block size at 1,000 bytes,
        # (17k is room enough for 110 or so transactions)
        self.nodes.append(start_node(1, self.options.tmpdir,
                                     ["-blockprioritysize=1500", "-blockmaxsize=17000",
                                      "-maxorphantx=1000", "-debug=estimatefee"]))
        connect_nodes(self.nodes[1], 0)

        # Node2 is a stingy miner, that
        # produces too small blocks (room for only 55 or so transactions)
        node2args = ["-blockprioritysize=0", "-blockmaxsize=8000", "-maxorphantx=1000"]

        self.nodes.append(start_node(2, self.options.tmpdir, node2args))
        connect_nodes(self.nodes[0], 2)
        connect_nodes(self.nodes[2], 1)

        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        # Prime the memory pool with pairs of transactions
        # (high-priority, random fee and zero-priority, random fee)
        min_fee = Decimal("1.0000")
        fees_per_kb = [];
        for i in range(12):
            (txid, txhex, fee) = random_zeropri_transaction(self.nodes, Decimal("1.1"),
                                                            min_fee, min_fee, 20)
            tx_kbytes = (len(txhex)/2)/5
            fees_per_kb.append(float(fee)/tx_kbytes)

        # Mine blocks with node2 until the memory pool clears:
        count_start = self.nodes[2].getblockcount()
        while len(self.nodes[2].getrawmempool()) > 0:
            self.nodes[2].generate(1)
            self.sync_all()

        all_estimates = [ self.nodes[0].estimatefee(i) for i in range(1,20) ]
        print("Fee estimates, super-stingy miner: "+str([str(e) for e in all_estimates]))

        # Estimates should be within the bounds of what transactions fees actually were:
        delta = 1.0e-6 # account for rounding error
        for e in filter(lambda x: x >= 0, all_estimates):
            if float(e)+delta < min(fees_per_kb) or float(e)-delta > max(fees_per_kb):
                raise AssertionError("Estimated fee (%f) out of range (%f,%f)"%(float(e), min(fees_per_kb), max(fees_per_kb)))

        # Generate transactions while mining 30 more blocks, this time with node1:
        for i in range(30):
            for j in range(random.randrange(6-4,6+4)):
                (txid, txhex, fee) = random_transaction(self.nodes, Decimal("1.1"),
                                                        Decimal("1"), min_fee, 20)
                tx_kbytes = (len(txhex)/2)/200
                fees_per_kb.append(float(fee)/tx_kbytes)
            self.nodes[1].generate(1)
            self.sync_all()

        all_estimates = [ self.nodes[0].estimatefee(i) for i in range(1,20) ]
        print("Fee estimates, more generous miner: "+str([ str(e) for e in all_estimates]))
        for e in filter(lambda x: x >= 0, all_estimates):
            if float(e)+delta < min(fees_per_kb) or float(e)-delta > max(fees_per_kb):
                raise AssertionError("Estimated fee (%f) out of range (%f,%f)"%(float(e), min(fees_per_kb), max(fees_per_kb)))

        # Finish by mining a normal-sized block:
        while len(self.nodes[0].getrawmempool()) > 0:
            self.nodes[0].generate(1)
            self.sync_all()

        final_estimates = [ self.nodes[0].estimatefee(i) for i in range(1,20) ]
        print("Final fee estimates: "+str([ str(e) for e in final_estimates]))

if __name__ == '__main__':
    EstimateFeeTest().main()
