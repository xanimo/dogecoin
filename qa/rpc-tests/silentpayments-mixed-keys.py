#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A payment from one compressed and one uncompressed coin, built outside the wallet.

BIP352 leaves an input that reveals an uncompressed key out of the sum and keeps the
transaction. The wallet never builds such a payment, because it pays a silent payment address
only from coins that all count, so the receiving side of that rule has only ever been run
against vectors. This builds one against a node: two keys held here, one compressed and one
not, a transaction spending a coin of each, and an output derived to the BIP's rule from the
compressed key alone, with the smallest outpoint taken over both inputs.

The receiver is told nothing but its own address. Its index has to serve a tweak for the
transaction and its scan has to find the output, which then has to spend. Two outputs a
receiver with a different rule would look for are derived as well, and are not what was paid.

The arithmetic is written out here rather than taken from the node or from contrib/bip352, so
that agreement is between two derivations.
"""
import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (start_nodes, connect_nodes_bi, sync_blocks, sync_mempools,
                                 assert_equal)
from test_framework.address import byte_to_base58
from test_framework.ripemd160 import ripemd160
from silentpayments import wait_for_index_sync

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

REGTEST_PUBKEY_ADDRESS = 111
REGTEST_SECRET_KEY = 239


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(point, k):
    r = None
    while k:
        if k & 1:
            r = point_add(r, point)
        point = point_add(point, point)
        k >>= 1
    return r


def compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def uncompressed(point):
    return b'\x04' + point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big')


def lift(data):
    """The point a 33-byte compressed key stands for."""
    x = int.from_bytes(data[1:], 'big')
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    assert (y * y - pow(x, 3, P) - 7) % P == 0
    return (x, y if (y & 1) == (data[0] & 1) else P - y)


def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


def tagged_hash(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def bech32m_keys(address):
    """The version and the scan and spend keys of a silent payment address."""
    hrp, data = address.rsplit('1', 1)
    values = [CHARSET.index(c) for c in data]
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i, g in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            chk ^= g if (top >> i) & 1 else 0
    assert chk == 0x2bc830a3, 'not bech32m'
    acc, bits, payload = 0, 0, bytearray()
    for v in values[1:-6]:
        acc, bits = (acc << 5) | v, bits + 5
        if bits >= 8:
            bits -= 8
            payload.append((acc >> bits) & 0xff)
    return values[0], bytes(payload[:33]), bytes(payload[33:66])


def wif(secret, is_compressed):
    return byte_to_base58(secret.to_bytes(32, 'big') + (b'\x01' if is_compressed else b''), REGTEST_SECRET_KEY)


def p2pkh_address(pubkey):
    return byte_to_base58(hash160(pubkey), REGTEST_PUBKEY_ADDRESS)


def outpoint(txid, vout):
    return bytes.fromhex(txid)[::-1] + vout.to_bytes(4, 'little')


def output_key(scan, spend, secret_sum, pubkey_sum, smallest, k=0):
    """BIP352's P_k for a sender whose eligible keys sum to secret_sum."""
    input_hash = int.from_bytes(tagged_hash('BIP0352/Inputs', smallest + compressed(pubkey_sum)), 'big')
    shared = point_mul(lift(scan), input_hash * secret_sum % N)
    t_k = int.from_bytes(tagged_hash('BIP0352/SharedSecret', compressed(shared) + k.to_bytes(4, 'big')), 'big')
    return point_add(lift(spend), point_mul(G, t_k))


class MixedKeys(BitcoinTestFramework):
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
        funder, receiver = self.nodes
        funder.generate(200)
        self.sync_all()

        a1 = int.from_bytes(hashlib.sha256(b'a compressed key').digest(), 'big') % N
        a2 = int.from_bytes(hashlib.sha256(b'an uncompressed key').digest(), 'big') % N
        A1, A2 = point_mul(G, a1), point_mul(G, a2)
        addr1, addr2 = p2pkh_address(compressed(A1)), p2pkh_address(uncompressed(A2))

        def fund(addr):
            txid = funder.sendtoaddress(addr, 60)
            vout = [o['n'] for o in funder.getrawtransaction(txid, 1)['vout']
                    if o['scriptPubKey'].get('addresses') == [addr]]
            assert_equal(len(vout), 1)
            return {'txid': txid, 'vout': vout[0]}

        # the uncompressed coin is given the smaller outpoint, so that a receiver taking the
        # smallest outpoint over the inputs that count would derive something else
        coins = [fund(addr1)]
        while len(coins) == 1:
            coin = fund(addr2)
            if outpoint(coin['txid'], coin['vout']) < outpoint(coins[0]['txid'], coins[0]['vout']):
                coins.append(coin)
        funder.generate(1)
        self.sync_all()

        address = receiver.getsilentpaymentaddress()
        version, scan, spend = bech32m_keys(address)
        assert_equal(version, 0)

        # the BIP's rule: the compressed key alone, the smallest outpoint over every input
        smallest = min(outpoint(c['txid'], c['vout']) for c in coins)
        paid = output_key(scan, spend, a1, A1, smallest)
        # a receiver that counted the uncompressed key too
        both = output_key(scan, spend, (a1 + a2) % N, point_add(A1, A2), smallest)
        # a receiver that took the smallest outpoint over the inputs that count
        own = output_key(scan, spend, a1, A1, outpoint(coins[0]['txid'], coins[0]['vout']))

        raw = funder.createrawtransaction(coins, {p2pkh_address(compressed(paid)): 100,
                                                  funder.getnewaddress(): 19})
        signed = funder.signrawtransaction(raw, [], [wif(a1, True), wif(a2, False)])
        assert_equal(signed['complete'], True)
        decoded = funder.decoderawtransaction(signed['hex'])
        sigs = [vin['scriptSig']['hex'] for vin in decoded['vin']]
        assert sigs[0].endswith(compressed(A1).hex()) and sigs[1].endswith(uncompressed(A2).hex())
        txid = funder.sendrawtransaction(signed['hex'])
        sync_mempools(self.nodes)
        funder.generate(1)
        sync_blocks(self.nodes)
        height = receiver.getblockcount()
        wait_for_index_sync(receiver, 'tweakindex')

        found = [f for f in receiver.scansilentpayments(height, height)['found'] if f['txid'] == txid]
        print('paid to %s; the scan of block %d found %d output(s) of %s'
              % (p2pkh_address(compressed(paid)), height, len(found), txid), flush=True)
        assert_equal(len(found), 1)
        assert_equal(found[0]['amount'], 100)
        assert_equal(found[0]['address'], p2pkh_address(compressed(paid)))
        # and neither of the other two readings is the output that was paid
        assert smallest == outpoint(coins[1]['txid'], coins[1]['vout'])
        assert found[0]['address'] != p2pkh_address(compressed(both))
        assert found[0]['address'] != p2pkh_address(compressed(own))

        spendable = [u for u in receiver.listunspent(0, 9999999, [found[0]['address']]) if u['txid'] == txid]
        assert_equal(len(spendable), 1)
        assert_equal(spendable[0]['spendable'], True)
        spent = receiver.sendtoaddress(funder.getnewaddress(), 99)
        assert txid in [vin['txid'] for vin in receiver.getrawtransaction(spent, 1)['vin']]
        sync_mempools(self.nodes)
        funder.generate(1)
        sync_blocks(self.nodes)
        assert_equal(receiver.gettransaction(spent)['confirmations'], 1)
        print('the output spent in %s, confirmed' % spent, flush=True)


if __name__ == '__main__':
    MixedKeys().main()
