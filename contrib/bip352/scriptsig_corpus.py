#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the BIP352 input eligibility rule over real mainnet inputs and report what it finds.

The rule in src/bip352.cpp walks every data push in a P2PKH scriptSig and takes the push whose
hash160 matches the prevout's pubkey hash. That is a claim about real-world scriptSig encodings,
and a scriptSig a receiver reads differently from the sender silently loses the payment. This
measures the claim rather than asserting it.

Per input it reports one of:

  eligible    a push matched the prevout's pubkey hash
  no_match    a P2PKH prevout whose scriptSig has no push matching the hash, so no sender and no
              receiver can derive from it. Expected to be zero; a non-zero count is a finding.
  ambiguous   more than one distinct push matched the hash. Impossible short of a hash160
              collision, so also a finding, and reported separately so it can never hide inside
              the eligible count.
  not_p2pkh   the prevout is some other script type, which the scheme ignores by design

and breaks the eligible ones down by key type and by scriptSig shape, where "canonical" means
exactly two pushes with the key last. Anything else is a malleated or unusual encoding that the
canonical-shape rule would have missed.

It also counts transactions with at least one eligible input, which is what sizes the tweak
index at 33 bytes per such transaction.

Reads blocks over RPC:

  ./scriptsig_corpus.py --rpcuser u --rpcpassword p --start 5000000 --count 1000

The rule needs the prevout script of every input, and Dogecoin Core has no RPC that serves those
per block: getblock verbosity 2 returns getrawtransaction-shaped objects with no prevout field,
and getblockstats reads the undo data without exposing it. So prevouts are resolved with
getrawtransaction, one call per distinct prevout txid, cached. That requires a node running
-txindex. Outputs of blocks already walked are cached too, so a contiguous range resolves its
own internal spends for free. An input whose prevout cannot be resolved is counted as unresolved
and left out of the verdicts rather than guessed at.
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from collections import Counter

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'qa', 'rpc-tests'))
from test_framework.ripemd160 import ripemd160  # noqa: E402

P = 2**256 - 2**32 - 977


def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


def is_p2pkh(spk):
    return len(spk) == 25 and spk[0:3] == b'\x76\xa9\x14' and spk[23:25] == b'\x88\xac'


def script_pushes(script):
    """Yield (data, is_push) for every opcode, stopping on a malformed script.

    A truncated push is not an error to report: such a scriptSig cannot have been accepted by
    consensus in a confirmed block, so reaching one means the input was decoded wrong.
    """
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0 or op > 78:
            yield None, False
            continue
        if op < 76:
            n = op
        elif op == 76:
            if i + 1 > len(script):
                return
            n, i = script[i], i + 1
        elif op == 77:
            if i + 2 > len(script):
                return
            n, i = int.from_bytes(script[i:i + 2], 'little'), i + 2
        else:
            if i + 4 > len(script):
                return
            n, i = int.from_bytes(script[i:i + 4], 'little'), i + 4
        if i + n > len(script):
            return
        yield script[i:i + n], True
        i += n


def on_curve(data):
    """Whether a push is a point on secp256k1, not merely the right length."""
    if len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], 'big')
        if x >= P:
            return False
        return pow(x * x * x + 7, (P - 1) // 2, P) in (0, 1)
    if len(data) == 65 and data[0] == 4:
        x = int.from_bytes(data[1:33], 'big')
        y = int.from_bytes(data[33:], 'big')
        return x < P and y < P and (y * y - x * x * x - 7) % P == 0
    return False


def classify(script_sig, spk):
    """Return (verdict, key_type, shape) for one input."""
    if not is_p2pkh(spk):
        return 'not_p2pkh', None, None

    pubkey_hash = spk[3:23]
    pushes = list(script_pushes(script_sig))
    matches = set()
    for data, is_push in pushes:
        if not is_push or len(data) not in (33, 65):
            continue
        if hash160(data) == pubkey_hash:
            matches.add(data)

    if not matches:
        return 'no_match', None, None
    if len(matches) > 1:
        return 'ambiguous', None, None

    key = matches.pop()
    if len(key) == 33:
        key_type = 'compressed' if on_curve(key) else 'compressed_off_curve'
    else:
        key_type = 'uncompressed' if on_curve(key) else 'uncompressed_off_curve'

    # Canonical is exactly <sig> <key>; anything else the two-push rule would have missed.
    data_pushes = [d for d, p in pushes if p]
    if len(pushes) == 2 and len(data_pushes) == 2 and data_pushes[-1] == key:
        shape = 'canonical'
    elif data_pushes and data_pushes[-1] == key:
        shape = 'key_last_extra_ops(%d)' % len(pushes)
    else:
        shape = 'key_not_last(%d)' % len(pushes)
    return 'eligible', key_type, shape


class Stats(object):
    def __init__(self):
        self.verdicts = Counter()
        self.key_types = Counter()
        self.shapes = Counter()
        self.prevout_types = Counter()
        self.findings = []
        self.txs = 0
        self.txs_eligible = 0
        self.blocks = 0
        self.unresolved = 0
        self.prevout_lookups = 0

    def add_tx(self, txid, vin):
        """vin is a list of (script_sig, prevout_spk_or_None)."""
        self.txs += 1
        any_eligible = False
        for n, (script_sig, spk) in enumerate(vin):
            if spk is None:
                self.unresolved += 1
                continue
            verdict, key_type, shape = classify(script_sig, spk)
            self.verdicts[verdict] += 1
            if verdict == 'eligible':
                any_eligible = True
                self.key_types[key_type] += 1
                self.shapes[shape] += 1
            elif verdict == 'not_p2pkh':
                self.prevout_types[spk_kind(spk)] += 1
            else:
                if len(self.findings) < 50:
                    self.findings.append({
                        'verdict': verdict,
                        'txid': txid,
                        'vin': n,
                        'script_sig': script_sig.hex(),
                        'prevout_script': spk.hex(),
                    })
        if any_eligible:
            self.txs_eligible += 1

    def report(self):
        total = sum(self.verdicts.values())
        out = {
            'blocks': self.blocks,
            'transactions': self.txs,
            'transactions_with_eligible_input': self.txs_eligible,
            'inputs_classified': total,
            'inputs_unresolved': self.unresolved,
            'prevout_rpc_lookups': self.prevout_lookups,
            'verdicts': dict(self.verdicts),
            'eligible_by_key_type': dict(self.key_types),
            'eligible_by_scriptsig_shape': dict(self.shapes),
            'ineligible_prevout_types': dict(self.prevout_types),
            'findings': self.findings,
        }
        # 33 bytes of tweak per transaction with an eligible input is the index cost.
        out['tweak_index_bytes'] = self.txs_eligible * 33
        if self.blocks:
            out['tweak_index_bytes_per_block_mean'] = round(out['tweak_index_bytes'] / self.blocks, 1)
        return out


def spk_kind(spk):
    if len(spk) == 23 and spk[0:2] == b'\xa9\x14' and spk[22] == 0x87:
        return 'p2sh'
    if len(spk) in (35, 67) and spk[-1] == 0xac:
        return 'p2pk'
    if spk and spk[0] == 0x6a:
        return 'nulldata'
    if spk and spk[-1] == 0xae:
        return 'multisig'
    if not spk:
        return 'empty'
    return 'other'


def selftest():
    """Classify the BIP352 vector inputs, so the classifier is checked without needing a node.

    The vectors carry a malleated P2PKH scriptSig and a pair of uncompressed-key inputs, which
    are exactly the two shapes this harness exists to count.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..',
                        'src', 'test', 'data', 'bip352_p2pkh_vectors.json')
    cases = json.load(open(path))
    seen = Counter()
    failures = 0
    for case in cases:
        for v in case['given']['vin']:
            verdict, key_type, shape = classify(bytes.fromhex(v['script_sig']),
                                                bytes.fromhex(v['prevout_script']))
            seen[verdict] += 1
            if verdict == 'eligible':
                seen['key:' + key_type] += 1
                seen['shape:' + shape.split('(')[0]] += 1
            else:
                failures += 1
                print('unexpected %s in %r vin' % (verdict, case['comment']), file=sys.stderr)

    print(json.dumps(dict(seen), indent=2))
    # Every vector input is a P2PKH spend whose key the generator found, so nothing may fall out.
    expect = [
        ('no_match', 0),
        ('ambiguous', 0),
        ('not_p2pkh', 0),
        ('key:compressed_off_curve', 0),
        ('key:uncompressed_off_curve', 0),
    ]
    for name, want in expect:
        if seen[name] != want:
            failures += 1
            print('expected %s == %d, got %d' % (name, want, seen[name]), file=sys.stderr)
    # The shapes the canonical two-push rule would have missed must actually be detected.
    for name in ('shape:canonical', 'shape:key_last_extra_ops', 'key:compressed', 'key:uncompressed'):
        if not seen[name]:
            failures += 1
            print('expected at least one %s in the vectors, got none' % name, file=sys.stderr)
    print('selftest: %d inputs, %d failures' % (seen['eligible'], failures), file=sys.stderr)
    return 1 if failures else 0


class RPC(object):
    def __init__(self, url, user, password):
        self.url = url
        import base64
        self.auth = base64.b64encode(('%s:%s' % (user, password)).encode()).decode()
        self.id = 0

    def call(self, method, *params):
        self.id += 1
        body = json.dumps({'jsonrpc': '1.0', 'id': self.id, 'method': method, 'params': list(params)})
        req = urllib.request.Request(self.url, data=body.encode(),
                                     headers={'Authorization': 'Basic ' + self.auth,
                                              'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as r:
            payload = json.load(r)
        if payload.get('error'):
            raise RuntimeError('%s: %s' % (method, payload['error']))
        return payload['result']


class PrevoutResolver(object):
    """Prevout scripts by (txid, vout), from blocks already walked or from getrawtransaction."""

    def __init__(self, rpc, cache_limit=2000000):
        self.rpc = rpc
        self.scripts = {}
        self.cache_limit = cache_limit
        self.rpc_calls = 0
        self.txindex_missing = False

    def remember_block(self, block):
        for tx in block['tx']:
            txid = tx.get('txid', '')
            for n, out in enumerate(tx.get('vout', [])):
                h = out.get('scriptPubKey', {}).get('hex')
                if h:
                    self.scripts[(txid, n)] = bytes.fromhex(h)
        # Bound memory on long runs; a dropped entry just costs one getrawtransaction later.
        if len(self.scripts) > self.cache_limit:
            self.scripts.clear()

    def get(self, txid, vout):
        key = (txid, vout)
        if key in self.scripts:
            return self.scripts[key]
        if self.txindex_missing:
            return None
        try:
            tx = self.rpc.call('getrawtransaction', txid, 1)
            self.rpc_calls += 1
        except RuntimeError:
            # No txindex, so historical prevouts cannot be fetched at all. Say so once.
            self.txindex_missing = True
            print('getrawtransaction failed; the node needs -txindex to resolve prevouts',
                  file=sys.stderr)
            return None
        for n, out in enumerate(tx.get('vout', [])):
            h = out.get('scriptPubKey', {}).get('hex')
            if h:
                self.scripts[(txid, n)] = bytes.fromhex(h)
        return self.scripts.get(key)


def walk_rpc(rpc, start, count, stats, verbose):
    """Classify `count` blocks from height `start`."""
    resolver = PrevoutResolver(rpc)
    for height in range(start, start + count):
        block_hash = rpc.call('getblockhash', height)
        block = rpc.call('getblock', block_hash, 2)
        stats.blocks += 1
        resolver.remember_block(block)
        for tx in block['tx']:
            vin = []
            for v in tx.get('vin', []):
                if 'coinbase' in v:
                    continue
                script_sig = bytes.fromhex(v.get('scriptSig', {}).get('hex', ''))
                vin.append((script_sig, resolver.get(v['txid'], v['vout'])))
            if vin:
                stats.add_tx(tx.get('txid', ''), vin)
        if verbose and stats.blocks % 100 == 0:
            print('%d blocks, %d inputs, %d prevout lookups' %
                  (stats.blocks, sum(stats.verdicts.values()), resolver.rpc_calls), file=sys.stderr)
    stats.prevout_lookups = resolver.rpc_calls


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--rpcurl', default='http://127.0.0.1:22555')
    ap.add_argument('--rpcuser')
    ap.add_argument('--rpcpassword')
    ap.add_argument('--start', type=int, help='first block height')
    ap.add_argument('--count', type=int, default=1000, help='blocks to walk')
    ap.add_argument('--out', help='write the report here instead of stdout')
    ap.add_argument('--selftest', action='store_true',
                    help='classify the BIP352 vector inputs and check the verdicts')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    stats = Stats()
    if args.start is None or not args.rpcuser:
        ap.error('need --start and --rpcuser/--rpcpassword')

    rpc = RPC(args.rpcurl, args.rpcuser, args.rpcpassword)
    walk_rpc(rpc, args.start, args.count, stats, args.verbose)

    report = json.dumps(stats.report(), indent=2)
    if args.out:
        with open(args.out, 'w') as f:
            f.write(report + '\n')
    else:
        print(report)

    # A no_match or ambiguous input means the rule in bip352.cpp does not hold on real data.
    if stats.verdicts['no_match'] or stats.verdicts['ambiguous']:
        print('FINDING: %d no_match, %d ambiguous' % (stats.verdicts['no_match'], stats.verdicts['ambiguous']),
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
