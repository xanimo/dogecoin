#!/usr/bin/env python3
# Copyright (c) 2026 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the address_type argument to getnewaddress.

Covers the three accepted types, the rejection of anything else, and that funds
sent to each type are credited. SegWit is not active on regtest here, so the
witness outputs are anyone-can-spend to old nodes; what is checked is that the
wallet encodes each type correctly, recognises it as its own, and sees the
payment.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    start_nodes,
    assert_equal,
    assert_raises_jsonrpc,
)


class WalletAddressTypesTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [[]])
        self.is_network_split = False

    def run_test(self):
        node = self.nodes[0]
        node.generate(101)

        # The default is unchanged: no second argument means legacy, and asking
        # for legacy explicitly gives the same encoding.
        default_addr = node.getnewaddress()
        legacy_addr = node.getnewaddress("", "legacy")
        for addr in (default_addr, legacy_addr):
            info = node.validateaddress(addr)
            assert_equal(info["isvalid"], True)
            assert_equal(info["ismine"], True)
            assert_equal(info["isscript"], False)
            assert not addr.startswith("dcrt1"), "legacy address is bech32-encoded"

        # p2sh-segwit wraps the witness program in a P2SH, so the wallet sees a
        # script rather than a key.
        p2sh_addr = node.getnewaddress("", "p2sh-segwit")
        info = node.validateaddress(p2sh_addr)
        assert_equal(info["isvalid"], True)
        assert_equal(info["ismine"], True)
        assert_equal(info["isscript"], True)

        # bech32 is the native witness program, under the regtest HRP.
        bech32_addr = node.getnewaddress("", "bech32")
        assert bech32_addr.startswith("dcrt1"), \
            "bech32 address %s does not carry the regtest HRP" % bech32_addr
        assert_equal(node.validateaddress(bech32_addr)["isvalid"], True)

        # The three types must not collide.
        assert len({legacy_addr, p2sh_addr, bech32_addr}) == 3

        # Anything else is refused rather than silently treated as legacy.
        for bad in ["p2sh", "segwit", "bech32m", "LEGACY", ""]:
            assert_raises_jsonrpc(-8, "Unknown address type",
                                  node.getnewaddress, "", bad)

        # Funds sent to each type are credited to that address.
        txids = {}
        for addr in (legacy_addr, p2sh_addr, bech32_addr):
            txids[addr] = node.sendtoaddress(addr, 10)
        node.generate(1)
        for addr in (legacy_addr, p2sh_addr, bech32_addr):
            assert_equal(node.getreceivedbyaddress(addr), 10)

        def find_vout(txid, addr):
            for v in node.getrawtransaction(txid, 1)["vout"]:
                if addr in (v["scriptPubKey"].get("addresses") or []):
                    return v["n"]
            raise AssertionError("no output paying %s" % addr)

        # The witness outputs are receivable but not yet spendable: SegWit is
        # inactive, so the wallet signs them and the node refuses to relay.
        # This is the soft-fork property that makes the address layer safe to
        # ship ahead of activation, so it is pinned rather than assumed.
        for addr in (p2sh_addr, bech32_addr):
            rawtx = node.createrawtransaction(
                [{"txid": txids[addr], "vout": find_vout(txids[addr], addr)}],
                {node.getnewaddress(): 9})
            signed = node.signrawtransaction(rawtx)
            assert_equal(signed["complete"], True)
            assert_raises_jsonrpc(-26, "no-witness-yet",
                                  node.sendrawtransaction, signed["hex"])

        # A legacy output from the same batch still spends, so the rejection
        # above is about the witness program and not about the test setup.
        rawtx = node.createrawtransaction(
            [{"txid": txids[legacy_addr],
              "vout": find_vout(txids[legacy_addr], legacy_addr)}],
            {node.getnewaddress(): 9})
        signed = node.signrawtransaction(rawtx)
        assert_equal(signed["complete"], True)
        node.sendrawtransaction(signed["hex"])


if __name__ == '__main__':
    WalletAddressTypesTest().main()
