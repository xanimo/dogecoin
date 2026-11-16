#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Measure what a BIP158 filter costs a silent payments scanner, against real filters.

A scanner derives one candidate output script per transaction with an eligible input and asks the
block's filter whether any of them is present. A match it did not expect costs one block
download. That rate is the thing deciding whether the filter-first path is worth having, and it
is a property of the filter parameters rather than of how a candidate was derived, so random
P2PKH scripts measure it directly and far more cheaply than deriving real candidates would.

The control is that every non-OP_RETURN output script in a block must be found in that block's
own filter. Without it a rate of zero is indistinguishable from a decoder that matches nothing,
which is the failure this measurement is most likely to make and least likely to notice.

  ./filter_probe.py --datadir /mnt/bigdata/dogecoin --blocks 400 --probes 500000

Needs a node with -blockfilterindex synced over the range being probed.
"""

import argparse
import json
import random
import subprocess
import sys

import numpy as np

P = 19
M = 784931                                  # BIP158's false positive parameter
MASK = np.uint64(0xFFFFFFFFFFFFFFFF)
MASK64 = (1 << 64) - 1
TWO64 = 1 << 64


def rotl64(n, b):
    return ((n << b) | (n >> (64 - b))) & MASK64


def siphash24(k0, k1, data):
    """SipHash-2-4 over arbitrary bytes. The reference the vectorised path is checked against."""
    v0 = 0x736f6d6570736575 ^ k0
    v1 = 0x646f72616e646f6d ^ k1
    v2 = 0x6c7967656e657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    def rounds(n):
        nonlocal v0, v1, v2, v3
        for _ in range(n):
            v0 = (v0 + v1) & MASK64; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32)
            v2 = (v2 + v3) & MASK64; v3 = rotl64(v3, 16); v3 ^= v2
            v0 = (v0 + v3) & MASK64; v3 = rotl64(v3, 21); v3 ^= v0
            v2 = (v2 + v1) & MASK64; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32)

    n = len(data)
    for i in range(0, n - (n % 8), 8):
        word = int.from_bytes(data[i:i + 8], 'little')
        v3 ^= word
        rounds(2)
        v0 ^= word

    last = (n & 0xff) << 56
    for i, b in enumerate(data[n - (n % 8):]):
        last |= b << (8 * i)
    v3 ^= last
    rounds(2)
    v0 ^= last

    v2 ^= 0xff
    rounds(4)
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64


def _rotl(x, b):
    b = np.uint64(b)
    return (x << b) | (x >> np.uint64(64 - b))


def siphash24_batch(k0, k1, scripts):
    """SipHash-2-4 over an (n, 25) array of P2PKH scripts.

    Every operation SipHash uses is add, xor and rotate on uint64, which numpy does elementwise,
    so a whole batch costs about what one scalar hash costs in interpreted Python. A 25-byte
    script is three full words and a one-byte tail, so the schedule is fixed.
    """
    assert scripts.shape[1] == 25
    k0 = np.uint64(k0); k1 = np.uint64(k1)
    n = scripts.shape[0]

    words = np.zeros((n, 4), dtype=np.uint64)
    for w in range(3):
        for byte in range(8):
            words[:, w] |= scripts[:, w * 8 + byte].astype(np.uint64) << np.uint64(8 * byte)
    words[:, 3] = scripts[:, 24].astype(np.uint64) | (np.uint64(25) << np.uint64(56))

    v = [np.full(n, np.uint64(0x736f6d6570736575) ^ k0, dtype=np.uint64),
         np.full(n, np.uint64(0x646f72616e646f6d) ^ k1, dtype=np.uint64),
         np.full(n, np.uint64(0x6c7967656e657261) ^ k0, dtype=np.uint64),
         np.full(n, np.uint64(0x7465646279746573) ^ k1, dtype=np.uint64)]

    def rounds(n_rounds):
        v0, v1, v2, v3 = v
        for _ in range(n_rounds):
            v0 = v0 + v1; v1 = _rotl(v1, 13); v1 ^= v0; v0 = _rotl(v0, 32)
            v2 = v2 + v3; v3 = _rotl(v3, 16); v3 ^= v2
            v0 = v0 + v3; v3 = _rotl(v3, 21); v3 ^= v0
            v2 = v2 + v1; v1 = _rotl(v1, 17); v1 ^= v2; v2 = _rotl(v2, 32)
        v[:] = [v0, v1, v2, v3]

    for w in range(4):
        v[3] ^= words[:, w]
        rounds(2)
        v[0] ^= words[:, w]

    v[2] ^= np.uint64(0xff)
    rounds(4)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def membership_bounds(values, f):
    """Turn filter values into the digest intervals that map onto them.

    BIP158 maps a digest d to (d * f) >> 64, so d lands on value v exactly when
    ceil(v * 2^64 / f) <= d < ceil((v + 1) * 2^64 / f). Comparing against those bounds avoids a
    128-bit multiply per query, which numpy has no native width for and which splitting into
    32-bit halves gets wrong on the carry. The intervals are disjoint and ascending, so a digest
    is a member exactly when searchsorted puts it at an odd index.
    """
    bounds = []
    for v in sorted(values):
        bounds.append(-(-v * TWO64 // f))                    # ceil, in integer arithmetic
        bounds.append(min(-(-(v + 1) * TWO64 // f), TWO64 - 1))
    return np.array(bounds, dtype=np.uint64)


def count_members(k0, k1, scripts, bounds):
    digests = siphash24_batch(k0, k1, scripts)
    return int((np.searchsorted(bounds, digests, side='right') & 1).sum())


class BitReader(object):
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def bit(self):
        b = (self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return b

    def bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self.bit()
        return v


def read_compact_size(data, pos):
    n = data[pos]
    if n < 253:
        return n, pos + 1
    if n == 253:
        return int.from_bytes(data[pos + 1:pos + 3], 'little'), pos + 3
    if n == 254:
        return int.from_bytes(data[pos + 1:pos + 5], 'little'), pos + 5
    return int.from_bytes(data[pos + 1:pos + 9], 'little'), pos + 9


def decode_filter(filter_hex):
    """The set of values a filter encodes, as Golomb-Rice coded ascending differences."""
    data = bytes.fromhex(filter_hex)
    count, pos = read_compact_size(data, 0)
    reader = BitReader(data[pos:])
    values = set()
    acc = 0
    for _ in range(count):
        quotient = 0
        while reader.bit():
            quotient += 1
        acc += (quotient << P) | reader.bits(P)
        values.add(acc)
    return values, count


def filter_key(block_hash_hex):
    """The siphash key is the first 16 bytes of the block hash in internal byte order."""
    h = bytes.fromhex(block_hash_hex)[::-1]
    return int.from_bytes(h[0:8], 'little'), int.from_bytes(h[8:16], 'little')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--datadir', required=True)
    ap.add_argument('--cli', default='./src/dogecoin-cli')
    ap.add_argument('--blocks', type=int, default=400)
    ap.add_argument('--probes', type=int, default=500000, help='queries per block')
    ap.add_argument('--controls', type=int, default=5, help='blocks to check own scripts against')
    ap.add_argument('--seed', type=int, default=20261116)
    args = ap.parse_args()

    def cli(*cmd):
        out = subprocess.run([args.cli, '-datadir=' + args.datadir] + list(cmd),
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError('%s: %s' % (cmd, out.stderr.strip()))
        return out.stdout.strip()

    # Cross-check the vectorised hash against the scalar one before trusting 10^8 of its answers.
    rng = random.Random(args.seed)
    sample = [b'\x76\xa9\x14' + bytes(rng.randrange(256) for _ in range(20)) + b'\x88\xac'
              for _ in range(64)]
    arr = np.frombuffer(b''.join(sample), dtype=np.uint8).reshape(len(sample), 25)
    batch = siphash24_batch(0x0123456789abcdef, 0xfedcba9876543210, arr)
    for got, want in zip(batch, (siphash24(0x0123456789abcdef, 0xfedcba9876543210, s)
                                 for s in sample)):
        assert int(got) == want, 'vectorised siphash disagrees with the scalar one'

    stop = int(cli('getblockcount'))
    start = stop - args.blocks + 1
    controls = queries = false_positives = elements = done = 0

    for height in range(start, stop + 1):
        bh = cli('getblockhash', str(height))
        values, count = decode_filter(json.loads(cli('getblockfilter', bh))['filter'])
        k0, k1 = filter_key(bh)
        f = count * M
        elements += count

        if done < args.controls:
            for tx in json.loads(cli('getblock', bh, '2'))['tx']:
                for vout in tx['vout']:
                    spk = bytes.fromhex(vout['scriptPubKey']['hex'])
                    if not spk or spk[0] == 0x6a:          # BIP158 excludes OP_RETURN
                        continue
                    digest = siphash24(k0, k1, spk)
                    assert (digest * f) >> 64 in values, \
                        'height %d: an output script is missing from its own filter' % height
                    controls += 1

        batch = np.frombuffer(
            b''.join(b'\x76\xa9\x14' + rng.randbytes(20) + b'\x88\xac'
                     for _ in range(args.probes)), dtype=np.uint8).reshape(args.probes, 25)
        queries += args.probes
        false_positives += count_members(k0, k1, batch, membership_bounds(values, f))

        done += 1
        if done % 50 == 0:
            print('[%d/%d] queries=%d fp=%d controls=%d' %
                  (done, args.blocks, queries, false_positives, controls), file=sys.stderr)

    rate = false_positives / queries if queries else 0
    print(json.dumps({
        'height_range': [start, stop],
        'blocks': done,
        'filter_elements_mean': round(elements / done, 1) if done else 0,
        'control_scripts_matched': controls,
        'queries': queries,
        'false_positives': false_positives,
        'measured_one_in': round(1 / rate) if rate else None,
        'specified_one_in': M,
    }, indent=2))


if __name__ == '__main__':
    main()
