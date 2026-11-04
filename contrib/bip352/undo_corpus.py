#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the BIP352 input eligibility rule over the whole chain, reading blk/rev files directly.

scriptsig_corpus.py asks the node for prevout scripts over RPC, which costs a getrawtransaction
per distinct prevout and makes a full-chain pass take days. The same data is already on disk:
rev*.dat holds, for every block, the CTxOut of every input that block spent. That is exactly
the prevout script the rule needs, so a full pass becomes sequential local I/O and no RPC.

Verdicts and their meaning are identical to scriptsig_corpus.py, whose classify() this imports
rather than reimplements, so the two cannot drift apart.

Pairing a block to its undo record is self-verifying. UndoWriteToDisk checksums the record as
SHA256d(hashPrevBlock || undo_bytes), and hashPrevBlock is in the block header, so a candidate
pairing can be confirmed outright instead of trusted. Records whose pairing cannot be confirmed
are counted and skipped, never guessed at.

  ./undo_corpus.py --datadir /mnt/bigdata/dogecoin
  ./undo_corpus.py --datadir /mnt/bigdata/dogecoin --max-files 3   # smoke test

A block whose undo record is absent (genesis, or an unconnected block sitting in a blk file) is
skipped and counted as no_undo. The parent chain of an AuxPoW block is parsed only far enough to
skip it; its transactions are not part of the Dogecoin block and are not classified.
"""

import argparse
import hashlib
import json
import multiprocessing
import os
import sys
from collections import Counter

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scriptsig_corpus import P, Stats, classify  # noqa: E402

VERSION_AUXPOW = 1 << 8


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Reader(object):
    """Cursor over a bytes buffer, in the serialization formats Core writes."""

    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos

    def take(self, n):
        if self.pos + n > len(self.buf):
            raise EOFError('short read')
        b = self.buf[self.pos:self.pos + n]
        self.pos += n
        return b

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), 'little')

    def u32(self):
        return int.from_bytes(self.take(4), 'little')

    def i32(self):
        return int.from_bytes(self.take(4), 'little', signed=True)

    def u64(self):
        return int.from_bytes(self.take(8), 'little')

    def compact_size(self):
        n = self.u8()
        if n < 253:
            return n
        if n == 253:
            return self.u16()
        if n == 254:
            return self.u32()
        return self.u64()

    def var_int(self):
        """Core's VARINT, which is not CompactSize: base-128, MSB first, minus-one adjusted."""
        n = 0
        while True:
            ch = self.u8()
            n = (n << 7) | (ch & 0x7F)
            if ch & 0x80:
                n += 1
            else:
                return n

    def var_bytes(self):
        return self.take(self.compact_size())


def decompress_amount(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    return n * (10 ** e)


def decompress_script(r):
    """CScriptCompressor: sizes 0..5 are special forms, anything else is size-6 raw bytes."""
    n = r.var_int()
    if n == 0:
        return b'\x76\xa9\x14' + r.take(20) + b'\x88\xac'          # P2PKH
    if n == 1:
        return b'\xa9\x14' + r.take(20) + b'\x87'                   # P2SH
    if n in (2, 3):
        return b'\x21' + bytes([n]) + r.take(32) + b'\xac'          # P2PK, compressed
    if n in (4, 5):
        # P2PK uncompressed: only x is stored, y is recovered and its parity comes from n.
        x = int.from_bytes(r.take(32), 'big')
        y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
        if (y & 1) != (n & 1):
            y = P - y
        return (b'\x41\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big') + b'\xac')
    return r.take(n - 6)


def parse_tx(r):
    """Returns (vin, vout_count), vin being the scriptSigs.

    Dogecoin transactions are never witness-serialized, but an AuxPoW block embeds its parent
    chain's coinbase, and that chain does have segwit. Miss the marker and the whole block
    derails, so the marker/flag form is handled here even though no Dogecoin tx uses it.
    """
    r.i32()                                   # version
    witness = False
    if r.buf[r.pos:r.pos + 2] == b'\x00\x01':
        r.take(2)                             # segwit marker and flag
        witness = True
    vin = []
    for _ in range(r.compact_size()):
        r.take(36)                            # prevout
        vin.append(r.var_bytes())             # scriptSig
        r.u32()                               # sequence
    nout = r.compact_size()
    for _ in range(nout):
        r.u64()                               # value
        r.var_bytes()                         # scriptPubKey
    if witness:
        for _ in range(len(vin)):
            for _ in range(r.compact_size()):
                r.var_bytes()                 # witness stack item
    r.u32()                                   # locktime
    return vin, nout


def skip_auxpow(r):
    """Parent coinbase, its merkle branch, the chain branch, and the parent header."""
    parse_tx(r)                               # CMerkleTx: the parent coinbase
    r.take(32)                                # hashBlock
    r.take(32 * r.compact_size())             # vMerkleBranch
    r.i32()                                   # nIndex
    r.take(32 * r.compact_size())             # vChainMerkleBranch
    r.i32()                                   # nChainIndex
    r.take(80)                                # parentBlock header


def parse_block(buf):
    """Returns (hash_prev, [vin per tx]) with the coinbase's vin included at index 0."""
    r = Reader(buf)
    version = r.i32()
    hash_prev = r.take(32)
    r.take(32 + 4 + 4 + 4)                    # merkle root, time, bits, nonce
    if version & VERSION_AUXPOW:
        skip_auxpow(r)
    txs = []
    for _ in range(r.compact_size()):
        vin, _ = parse_tx(r)
        txs.append(vin)
    return hash_prev, txs


def parse_undo(buf):
    """Returns [[prevout_spk per input] per non-coinbase tx]."""
    r = Reader(buf)
    out = []
    for _ in range(r.compact_size()):
        ins = []
        for _ in range(r.compact_size()):
            code = r.var_int()
            if code // 2 > 0:
                r.var_int()                   # nVersion, present only when nHeight > 0
            decompress_amount(r.var_int())    # nValue
            ins.append(decompress_script(r))
        out.append(ins)
    return out


def records(path, magic, trailer=0):
    """Yield (payload, trailing_bytes) for each magic-framed record in a blk or rev file."""
    with open(path, 'rb') as f:
        data = f.read()
    pos = 0
    n = len(data)
    while pos + 8 <= n:
        if data[pos:pos + 4] != magic:
            pos += 1                          # zero padding between records, resync
            continue
        size = int.from_bytes(data[pos + 4:pos + 8], 'little')
        pos += 8
        if size == 0 or pos + size + trailer > n:
            break
        yield data[pos:pos + size], data[pos + size:pos + size + trailer]
        pos += size + trailer


def process_file(task):
    """One blk/rev pair, in its own process. CPU bound on hash160, so it scales with cores.

    Results are checkpointed per file: a whole-chain pass runs for hours and will sometimes be
    interrupted, and recomputing finished files on every restart is pure waste.
    """
    blocks_dir, name, magic, cache_dir = task

    cached = os.path.join(cache_dir, name + '.json') if cache_dir else None
    if cached and os.path.exists(cached):
        try:
            with open(cached) as f:
                res = json.load(f)
            for k in ('verdicts', 'key_types', 'shapes', 'prevout_types', 'pairing'):
                res[k] = Counter(res[k])
            res['cached'] = True
            return res
        except (ValueError, KeyError):
            pass                        # unreadable checkpoint, just redo the file

    stats = Stats()
    pairing = Counter()
    _run_file(blocks_dir, name, magic, stats, pairing)
    res = {
        'name': name,
        'blocks': stats.blocks,
        'txs': stats.txs,
        'txs_eligible': stats.txs_eligible,
        'unresolved': stats.unresolved,
        'verdicts': stats.verdicts,
        'key_types': stats.key_types,
        'shapes': stats.shapes,
        'prevout_types': stats.prevout_types,
        'findings': stats.findings,
        'pairing': pairing,
    }
    if cached:
        tmp = cached + '.tmp%d' % os.getpid()
        with open(tmp, 'w') as f:
            json.dump({k: (dict(v) if isinstance(v, Counter) else v) for k, v in res.items()}, f)
        os.replace(tmp, cached)         # atomic, so a kill cannot leave a half-written checkpoint
    res['cached'] = False
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--datadir', required=True, help='node datadir holding blocks/')
    ap.add_argument('--max-files', type=int, help='stop after this many blk files')
    ap.add_argument('--jobs', type=int, default=max(1, (os.cpu_count() or 2) - 1),
                    help='worker processes (default: cores - 1)')
    ap.add_argument('--cache-dir', help='checkpoint per-file results here and resume from them')
    ap.add_argument('--out', help='write the report here instead of stdout')
    args = ap.parse_args()
    if args.cache_dir:
        os.makedirs(args.cache_dir, exist_ok=True)

    blocks_dir = os.path.join(args.datadir, 'blocks')
    blk_files = sorted(f for f in os.listdir(blocks_dir)
                       if f.startswith('blk') and f.endswith('.dat'))
    if args.max_files:
        blk_files = blk_files[:args.max_files]
    if not blk_files:
        sys.exit('no blk*.dat under %s' % blocks_dir)

    with open(os.path.join(blocks_dir, blk_files[0]), 'rb') as f:
        magic = f.read(4)

    stats = Stats()
    pairing = Counter()
    tasks = [(blocks_dir, n, magic, args.cache_dir) for n in blk_files]
    done = 0

    with multiprocessing.Pool(args.jobs) as pool:
        for res in pool.imap_unordered(process_file, tasks):
            stats.blocks += res['blocks']
            stats.txs += res['txs']
            stats.txs_eligible += res['txs_eligible']
            stats.unresolved += res['unresolved']
            stats.verdicts.update(res['verdicts'])
            stats.key_types.update(res['key_types'])
            stats.shapes.update(res['shapes'])
            stats.prevout_types.update(res['prevout_types'])
            stats.findings.extend(res['findings'][:max(0, 50 - len(stats.findings))])
            pairing.update(res['pairing'])
            done += 1
            print('[%d/%d] %s%s  eligible=%d no_match=%d ambiguous=%d' %
                  (done, len(tasks), res['name'], ' (cached)' if res.get('cached') else '',
                   stats.verdicts['eligible'], stats.verdicts['no_match'],
                   stats.verdicts['ambiguous']), file=sys.stderr)

    report = stats.report()
    report['pairing'] = dict(pairing)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, 'w') as f:
            f.write(text + '\n')
    else:
        print(text)


def _run_file(blocks_dir, name, magic, stats, pairing):
    rev = os.path.join(blocks_dir, 'rev' + name[3:])
    if not os.path.exists(rev):
        pairing['missing_rev_file'] += 1
        return

    parsed = []
    for payload, _ in records(os.path.join(blocks_dir, name), magic):
        try:
            parsed.append(parse_block(payload) + (sha256d(payload[:80]),))
        except (EOFError, IndexError, ValueError):
            pairing['block_parse_error'] += 1

    # A blk file holds blocks in arrival order and may contain several disjoint chain
    # segments, so neither file order nor a chain relink pairs them reliably. Index blocks by
    # a shape fingerprint instead: an undo record has one entry per non-coinbase transaction
    # and one prevout per input, so the tuple of input counts identifies its block almost
    # uniquely. The checksum then confirms the candidate, so a collision cannot slip through.
    by_shape = {}
    for i, (_, txs, _) in enumerate(parsed):
        sig = (len(txs) - 1, tuple(len(v) for v in txs[1:]))
        by_shape.setdefault(sig, []).append(i)

    used = set()
    for payload, checksum in records(rev, magic, trailer=32):
        try:
            undo = parse_undo(payload)
        except (EOFError, IndexError, ValueError):
            pairing['undo_parse_error'] += 1
            continue

        sig = (len(undo), tuple(len(ins) for ins in undo))
        hit = None
        for cand in by_shape.get(sig, ()):
            if cand not in used and sha256d(parsed[cand][0] + payload) == checksum:
                hit = cand
                break
        if hit is None:
            pairing['unmatched_undo'] += 1
            continue
        pairing['matched'] += 1
        used.add(hit)

        # The shape fingerprint already guarantees the counts line up, so no recheck here.
        txs = parsed[hit][1]
        stats.blocks += 1
        for tx_i, ins in enumerate(undo):
            stats.add_tx('', list(zip(txs[tx_i + 1], ins)))

    pairing['blocks_without_undo'] += len(parsed) - len(used)


if __name__ == '__main__':
    main()
