#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Port BIP352's send/receive test vectors to P2PKH outputs.

Reads bitcoin/bitcoin's src/test/data/bip352_send_and_receive_vectors.json and writes the
Dogecoin equivalent. The hash tags are unchanged, so input_hash, the shared secret and the output
tweak carry over verbatim; what changes is that an output is hash160 of the compressed output key
rather than its x-only serialization.

The curve arithmetic here is deliberately a plain independent implementation rather than a binding
to libsecp256k1, so that agreement between this file and src/bip352.cpp means two implementations
agree rather than one agreeing with itself.

  ./generate_test_vectors.py upstream.json ../../src/test/data/bip352_p2pkh_vectors.json
"""

import hashlib
import json
import os
import sys

# OpenSSL 3 drops ripemd160 from the default provider, so use the test framework's own.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'qa', 'rpc-tests'))
from test_framework.ripemd160 import ripemd160  # noqa: E402

# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


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
    for i in range(k.bit_length()):
        if (k >> i) & 1:
            r = point_add(r, point)
        point = point_add(point, point)
    return r


def ser_compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def parse_point(data):
    """Parse a 33-byte compressed or 65-byte uncompressed point."""
    if len(data) == 65 and data[0] == 4:
        return (int.from_bytes(data[1:33], 'big'), int.from_bytes(data[33:65], 'big'))
    assert len(data) == 33 and data[0] in (2, 3), data.hex()
    x = int.from_bytes(data[1:], 'big')
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y % 2 != data[0] - 2:
        y = P - y
    return (x, y)


def tagged_hash(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


# bech32m, per BIP350.
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def bech32m_encode(hrp, data):
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    values = expanded + data
    polymod = bech32_polymod(values + [0] * 6) ^ 0x2bc830a3
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(CHARSET[d] for d in data + checksum)


def convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def encode_address(hrp, scan_pubkey, spend_pubkey, version=0):
    payload = bytes([version]) + scan_pubkey + spend_pubkey
    return bech32m_encode(hrp, convertbits(payload, 8, 5))


def is_p2pkh(spk_hex):
    return len(spk_hex) == 50 and spk_hex.startswith('76a914') and spk_hex.endswith('88ac')


def p2pkh_script(pubkey):
    return '76a914' + hash160(pubkey).hex() + '88ac'


def script_pushes(script):
    """Yield every data push in a script, ignoring non-push opcodes."""
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0 or op > 78:
            continue
        if op < 76:
            n = op
        elif op == 76:
            n, i = script[i], i + 1
        elif op == 77:
            n, i = int.from_bytes(script[i:i + 2], 'little'), i + 2
        else:
            n, i = int.from_bytes(script[i:i + 4], 'little'), i + 4
        yield script[i:i + n]
        i += n


def input_pubkey(script_sig, spk):
    """The public key a P2PKH input reveals, matched against the prevout's pubkey hash.

    Walks every push rather than taking the last one, because P2PKH scriptSigs are third-party
    malleable. Unlike BIP352, 65-byte uncompressed keys are accepted.
    """
    if not is_p2pkh(spk.hex()):
        return None
    pubkey_hash = spk[3:23]
    for push in script_pushes(script_sig):
        if len(push) in (33, 65) and hash160(push) == pubkey_hash:
            return push
    return None


def ser_outpoint(txid_hex, vout):
    return bytes.fromhex(txid_hex)[::-1] + vout.to_bytes(4, 'little')


def smallest_outpoint(vin):
    return min(ser_outpoint(v['txid'], v['vout']) for v in vin)


def eligible_pubkeys(vin):
    """The hex public keys the inputs reveal, in vin order."""
    keys = []
    for v in vin:
        spk = bytes.fromhex(v['prevout']['scriptPubKey']['hex'])
        key = input_pubkey(bytes.fromhex(v['scriptSig']), spk)
        if key is not None:
            keys.append(key.hex())
    return keys


def derive(vin, keyed):
    """Return (pubkey_sum, input_hash) for a transaction's inputs, or (None, None)."""
    points = []
    for v in vin:
        spk = bytes.fromhex(v['prevout']['scriptPubKey']['hex'])
        key = input_pubkey(bytes.fromhex(v['scriptSig']), spk)
        if key is not None:
            points.append(parse_point(key))
    if not points:
        return None, None
    total = None
    for pt in points:
        total = point_add(total, pt)
    if total is None:
        return None, None
    ser = ser_compressed(total)
    return ser, tagged_hash('BIP0352/Inputs', smallest_outpoint(vin) + ser)


def seckey_sum(vin):
    """Sum the private keys of the eligible inputs, as the sender does."""
    total = 0
    for v in vin:
        spk = bytes.fromhex(v['prevout']['scriptPubKey']['hex'])
        if input_pubkey(bytes.fromhex(v['scriptSig']), spk) is None:
            continue
        total = (total + int(v['private_key'], 16)) % N
    return total


def label_tweak(scan_key, m):
    return tagged_hash('BIP0352/Label', bytes.fromhex(scan_key) + m.to_bytes(4, 'big'))


def port_case(case, hrp):
    send = case['sending'][0]['given']
    vin = send['vin']
    if not all(is_p2pkh(v['prevout']['scriptPubKey']['hex']) for v in vin):
        return None

    recv = case['receiving'][0]
    scan_key = recv['given']['key_material']['scan_priv_key']
    spend_key = recv['given']['key_material']['spend_priv_key']
    scan_pubkey = ser_compressed(point_mul(G, int(scan_key, 16)))
    spend_pubkey = ser_compressed(point_mul(G, int(spend_key, 16)))

    pubkey_sum, input_hash = derive(vin, True)

    # Where our eligibility rule differs from BIP352's, say so in the vector rather than letting
    # it read as a mismatch. The only intended difference is that we accept uncompressed keys.
    ours_eligible = sorted(eligible_pubkeys(vin))
    theirs_eligible = sorted(case['sending'][0]['expected']['input_pub_keys'])
    diverges = None
    if ours_eligible != theirs_eligible:
        extra = [k for k in ours_eligible if k not in theirs_eligible]
        assert all(len(k) == 130 for k in extra), extra
        diverges = 'accepts %d uncompressed input key(s) that BIP352 skips' % len(extra)

    out = {
        'comment': case['comment'],
        'diverges_from_bip352': diverges,
        'given': {
            'vin': [{
                'txid': v['txid'],
                'vout': v['vout'],
                'script_sig': v['scriptSig'],
                'prevout_script': v['prevout']['scriptPubKey']['hex'],
                'private_key': v['private_key'],
            } for v in vin],
            'scan_priv_key': scan_key,
            'spend_priv_key': spend_key,
            'labels': recv['given']['labels'],
        },
        'expected': {},
    }

    if pubkey_sum is None:
        # No eligible input, so the transaction cannot carry a payment in either direction.
        out['expected']['eligible'] = False
        out['expected']['addresses'] = []
        out['expected']['outputs'] = []
        return out

    out['expected']['eligible'] = True
    out['expected']['input_pubkey_sum'] = pubkey_sum.hex()
    out['expected']['input_hash'] = input_hash.hex()
    out['expected']['input_privkey_sum'] = '%064x' % seckey_sum(vin)

    # The address the receiver publishes, plus one per label in use.
    addresses = [encode_address(hrp, scan_pubkey, spend_pubkey)]
    for m in recv['given']['labels']:
        labeled = point_add(parse_point(spend_pubkey), point_mul(G, int.from_bytes(label_tweak(scan_key, m), 'big')))
        addresses.append(encode_address(hrp, scan_pubkey, ser_compressed(labeled)))
    out['expected']['addresses'] = addresses

    # Walk k the way a receiver does, against the recipient set the sender was given.
    shared_secret = ser_compressed(point_mul(parse_point(pubkey_sum),
                                             int.from_bytes(input_hash, 'big') * int(scan_key, 16) % N))
    out['expected']['shared_secret'] = shared_secret.hex()

    # Which (address, k) pairs the sender was asked for, grouped by scan key as BIP352 requires.
    wanted = []
    for i, r in enumerate(send['recipients']):
        wanted.append((r['scan_pub_key'], r['spend_pub_key'], i))
    wanted.sort(key=lambda t: (t[0], t[2]))

    outputs = []
    k_by_group = {}
    for scan_hex, spend_hex, index in wanted:
        if scan_hex != scan_pubkey.hex():
            continue  # paid to somebody else
        k = k_by_group.get(scan_hex, 0)
        k_by_group[scan_hex] = k + 1
        t_k = tagged_hash('BIP0352/SharedSecret', shared_secret + k.to_bytes(4, 'big'))
        output_point = point_add(parse_point(bytes.fromhex(spend_hex)), point_mul(G, int.from_bytes(t_k, 'big')))
        output_pubkey = ser_compressed(output_point)

        # Which label, if any, this spend key carries. The receiver learns this by trying each
        # label forward; here we know the answer and record it.
        label_m = None
        tweak = int.from_bytes(t_k, 'big')
        if spend_hex != spend_pubkey.hex():
            for m in recv['given']['labels']:
                lt = label_tweak(scan_key, m)
                if ser_compressed(point_add(parse_point(spend_pubkey), point_mul(G, int.from_bytes(lt, 'big')))).hex() == spend_hex:
                    label_m = m
                    tweak = (tweak + int.from_bytes(lt, 'big')) % N
                    break
            else:
                continue  # a labeled address this receiver does not hold
        outputs.append({
            'index': index,
            # The address the sender was asked to pay, so a test can drive both halves.
            'address': encode_address(hrp, scan_pubkey, bytes.fromhex(spend_hex)),
            'script': p2pkh_script(output_pubkey),
            'output_pubkey': output_pubkey.hex(),
            'priv_key_tweak': '%064x' % tweak,
            'label': label_m,
        })

    outputs.sort(key=lambda o: o['index'])
    out['expected']['outputs'] = outputs
    return out


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    upstream = json.load(open(sys.argv[1]))
    hrp = 'dsp'
    ported = [c for c in (port_case(case, hrp) for case in upstream) if c is not None]
    with open(sys.argv[2], 'w') as f:
        json.dump(ported, f, indent=2)
        f.write('\n')
    print('%d of %d upstream cases have all-P2PKH inputs' % (len(ported), len(upstream)), file=sys.stderr)


if __name__ == '__main__':
    main()
