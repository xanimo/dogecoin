#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Three rules of the specification, from its text and against a node.

The derivation paths, the sighash flag and the reading of an address are fixed in code that
no vector reaches: the vectors start from keys, the wallet starts from a seed, and a unit
case decodes an address without anything being paid to it. A second wallet has only the text
for these, so this does what the text says with code of its own and compares.

The scan and spend keys are derived from the wallet's dumped master key at m/352'/3'/0'/0'
and m/352'/3'/0'/1' and have to be the two keys in the address the wallet gives out. An
address is re-encoded at versions 1 and 30 with bytes added after the 66, and at the 1023
character limit, and each has to be payable and the payment found by the same receiver;
version 0 with a byte added, version 31 and a string past the limit have to be refused.
Every signature in every payment made has to end in SIGHASH_ALL.
"""
import hashlib
import hmac
import os
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (start_nodes, connect_nodes_bi, sync_blocks, sync_mempools,
                                 assert_equal, JSONRPCException)
from silentpayments import wait_for_index_sync

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def padd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P)) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)

def pmul(pt, k):
    r = None
    while k:
        if k & 1:
            r = padd(r, pt)
        pt = padd(pt, pt)
        k >>= 1
    return r

def ser(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


def b58decode_check(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(82, 'big')
    assert hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]
    return raw[:-4]

def ckd_hardened(key, chain, i):
    I = hmac.new(chain, b'\x00' + key.to_bytes(32, 'big') + (i | 0x80000000).to_bytes(4, 'big'), hashlib.sha512).digest()
    return (int.from_bytes(I[:32], 'big') + key) % N, I[32:]

def polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i, g in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            chk ^= g if (top >> i) & 1 else 0
    return chk

def hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def to5(data):
    acc, bits, out = 0, 0, []
    for b in data:
        acc, bits = (acc << 8) | b, bits + 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out

def encode(hrp, version, payload):
    data = [version] + to5(payload)
    pm = polymod(hrp_expand(hrp) + data + [0] * 6) ^ 0x2bc830a3
    return hrp + '1' + ''.join(CHARSET[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])

def decode(address):
    hrp, data = address.rsplit('1', 1)
    values = [CHARSET.index(c) for c in data]
    assert polymod(hrp_expand(hrp) + values) == 0x2bc830a3
    acc, bits, payload = 0, 0, bytearray()
    for v in values[1:-6]:
        acc, bits = (acc << 5) | v, bits + 5
        if bits >= 8:
            bits -= 8
            payload.append((acc >> bits) & 0xff)
    return hrp, values[0], bytes(payload)

class SpecFromTheText(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = start_nodes(2, self.options.tmpdir, [['-usehd=1'], ['-tweakindex', '-usehd=1']])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        sender, receiver = self.nodes
        sender.generate(200)
        self.sync_all()
        # Coinbases are P2PK, which the rule does not count, so give the sender P2PKH coins.
        sender.sendmany('', dict((sender.getnewaddress(), 50) for _ in range(20)))
        sender.generate(1)
        self.sync_all()
        address = receiver.getsilentpaymentaddress()
        hrp, version, payload = decode(address)
        assert_equal((hrp, version, len(payload)), ('dsprt', 0, 66))
        assert_equal(encode(hrp, version, payload), address)

        # The paths, from the master key the wallet dumps.
        dump = os.path.join(self.options.tmpdir, 'dump.txt')
        receiver.dumpwallet(dump)
        if not os.path.exists(dump):
            dump = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'backups', 'dump.txt')
        xprv = [l.split(': ')[1].strip() for l in open(dump) if 'extended private masterkey' in l][0]
        raw = b58decode_check(xprv)
        chain, key = raw[13:45], int.from_bytes(raw[46:78], 'big')
        for i in (352, 3, 0):
            key, chain = ckd_hardened(key, chain, i)
        assert_equal(ser(pmul(G, ckd_hardened(key, chain, 0)[0])), payload[:33])     # scan
        assert_equal(ser(pmul(G, ckd_hardened(key, chain, 1)[0])), payload[33:66])   # spend

        # The address: what is payable and what is refused.
        extra = bytes([1, 2, 3, 4, 5])
        payable = [address,
                   encode(hrp, 1, payload),
                   encode(hrp, 1, payload + extra),
                   encode(hrp, 30, payload + extra),
                   encode(hrp, 1, payload + bytes(565))]
        refused = [encode(hrp, 0, payload + bytes(1)),
                   encode(hrp, 31, payload),
                   encode(hrp, 1, payload + bytes(566))]
        assert_equal((len(payable[-1]), len(refused[-1])), (1023, 1025))
        paid = [sender.sendtosilentpaymentaddress(a, 1) for a in payable]
        for a in refused:
            try:
                sender.sendtosilentpaymentaddress(a, 1)
            except JSONRPCException as e:
                assert 'Invalid silent payment address' in e.error['message'], e.error['message']
            else:
                raise AssertionError('paid an address the text refuses: %s...' % a[:24])
        sync_mempools(self.nodes)
        sender.generate(1)
        sync_blocks(self.nodes)
        wait_for_index_sync(receiver, 'tweakindex')
        height = receiver.getblockcount()
        found = set(f['txid'] for f in receiver.scansilentpayments(height, height)['found'])
        assert_equal(found, set(paid))

        # The sighash flag of every signature in those payments.
        for txid in paid:
            for vin in sender.getrawtransaction(txid, 1)['vin']:
                script = bytes.fromhex(vin['scriptSig']['hex'])
                assert_equal(script[script[0]], 1)      # the last byte of the first push


if __name__ == '__main__':
    SpecFromTheText().main()
