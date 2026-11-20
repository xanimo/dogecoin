// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "consensus/merkle.h"
#include "primitives/block.h"
#include "script/script.h"
#include "addrman.h"
#include "chain.h"
#include "coins.h"
#include "compressor.h"
#include "net.h"
#include "protocol.h"
#include "streams.h"
#include "undo.h"
#include "version.h"
#include "pubkey.h"
#include "bip352.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "key.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

enum TEST_ID {
    CBLOCK_DESERIALIZE=0,
    CTRANSACTION_DESERIALIZE,
    CBLOCKLOCATOR_DESERIALIZE,
    CBLOCKMERKLEROOT,
    CADDRMAN_DESERIALIZE,
    CBLOCKHEADER_DESERIALIZE,
    CBANENTRY_DESERIALIZE,
    CTXUNDO_DESERIALIZE,
    CBLOCKUNDO_DESERIALIZE,
    CCOINS_DESERIALIZE,
    CNETADDR_DESERIALIZE,
    CSERVICE_DESERIALIZE,
    CMESSAGEHEADER_DESERIALIZE,
    CADDRESS_DESERIALIZE,
    CINV_DESERIALIZE,
    CBLOOMFILTER_DESERIALIZE,
    CDISKBLOCKINDEX_DESERIALIZE,
    CTXOUTCOMPRESSOR_DESERIALIZE,
    BIP352_ADDRESS_DECODE,
    BIP352_INPUT_PUBKEY,
    TEST_ID_END
};

bool read_stdin(std::vector<char> &data) {
    char buffer[1024];
    ssize_t length=0;
    while((length = read(STDIN_FILENO, buffer, 1024)) > 0) {
        data.insert(data.end(), buffer, buffer+length);

        if (data.size() > (1<<20)) return false;
    }
    return length==0;
}

int main(int argc, char **argv)
{
    ECCVerifyHandle globalVerifyHandle;
    std::vector<char> buffer;
    if (!read_stdin(buffer)) return 0;

    if (buffer.size() < sizeof(uint32_t)) return 0;

    uint32_t test_id = 0xffffffff;
    memcpy(&test_id, &buffer[0], sizeof(uint32_t));
    buffer.erase(buffer.begin(), buffer.begin() + sizeof(uint32_t));

    if (test_id >= TEST_ID_END) return 0;

    CDataStream ds(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try {
        int nVersion;
        ds >> nVersion;
        ds.SetVersion(nVersion);
    } catch (const std::ios_base::failure& e) {
        return 0;
    }

    switch(test_id) {
        case CBLOCK_DESERIALIZE:
        {
            try
            {
                CBlock block;
                ds >> block;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CTRANSACTION_DESERIALIZE:
        {
            try
            {
                CTransaction tx(deserialize, ds);
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKLOCATOR_DESERIALIZE:
        {
            try
            {
                CBlockLocator bl;
                ds >> bl;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKMERKLEROOT:
        {
            try
            {
                CBlock block;
                ds >> block;
                bool mutated;
                BlockMerkleRoot(block, &mutated);
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CADDRMAN_DESERIALIZE:
        {
            try
            {
                CAddrMan am;
                ds >> am;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKHEADER_DESERIALIZE:
        {
            try
            {
                CBlockHeader bh;
                ds >> bh;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBANENTRY_DESERIALIZE:
        {
            try
            {
                CBanEntry be;
                ds >> be;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CTXUNDO_DESERIALIZE:
        {
            try
            {
                CTxUndo tu;
                ds >> tu;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKUNDO_DESERIALIZE:
        {
            try
            {
                CBlockUndo bu;
                ds >> bu;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CCOINS_DESERIALIZE:
        {
            try
            {
                CCoins block;
                ds >> block;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CNETADDR_DESERIALIZE:
        {
            try
            {
                CNetAddr na;
                ds >> na;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CSERVICE_DESERIALIZE:
        {
            try
            {
                CService s;
                ds >> s;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CMESSAGEHEADER_DESERIALIZE:
        {
            CMessageHeader::MessageStartChars pchMessageStart = {0x00, 0x00, 0x00, 0x00};
            try
            {
                CMessageHeader mh(pchMessageStart);
                ds >> mh;
                if (!mh.IsValid(pchMessageStart)) {return 0;}
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CADDRESS_DESERIALIZE:
        {
            try
            {
                CAddress a;
                ds >> a;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CINV_DESERIALIZE:
        {
            try
            {
                CInv i;
                ds >> i;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOOMFILTER_DESERIALIZE:
        {
            try
            {
                CBloomFilter bf;
                ds >> bf;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CDISKBLOCKINDEX_DESERIALIZE:
        {
            try
            {
                CDiskBlockIndex dbi;
                ds >> dbi;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CTXOUTCOMPRESSOR_DESERIALIZE:
        {
            CTxOut to;
            CTxOutCompressor toc(to);
            try
            {
                ds >> toc;
            } catch (const std::ios_base::failure& e) {return 0;}

            break;
        }
        case BIP352_ADDRESS_DECODE:
        {
            // The remaining bytes are the address string. Checking only that the decoder does
            // not crash would miss the failure that matters, which is accepting something and
            // handing back a key nobody holds, so this asserts what a caller is entitled to
            // assume: a decoded address carries two valid compressed keys, and re-encoding it
            // yields a string that decodes to the same address. An encoder and a decoder that
            // share a mistake round-trip perfectly, so the keys are checked directly too.
            const std::vector<unsigned char> raw(ds.begin(), ds.end());
            const std::string str(raw.begin(), raw.end());

            const std::string nets[] = {CBaseChainParams::MAIN, CBaseChainParams::TESTNET,
                                        CBaseChainParams::REGTEST};
            for (size_t i = 0; i < sizeof(nets) / sizeof(nets[0]); ++i) {
                SelectParams(nets[i]);
                bip352::CSilentPaymentsAddress addr;
                std::string error;
                if (!bip352::DecodeSilentPaymentsAddress(addr, str, Params(), error)) {
                    assert(!error.empty());         // a refusal has to say why
                    continue;
                }
                assert(addr.IsValid());
                assert(addr.GetScanPubKey().IsFullyValid() && addr.GetScanPubKey().IsCompressed());
                assert(addr.GetSpendPubKey().IsFullyValid() && addr.GetSpendPubKey().IsCompressed());
                assert(addr.GetVersion() <= 30);    // 31 is reserved and must never decode

                const std::string again = bip352::EncodeSilentPaymentsAddress(addr, Params());
                bip352::CSilentPaymentsAddress rt;
                assert(bip352::DecodeSilentPaymentsAddress(rt, again, Params(), error));
                assert(rt == addr);
            }
            break;
        }
        case BIP352_INPUT_PUBKEY:
        {
            // Two scripts off the stream: the scriptSig and the prevout it spends. The rule is
            // what both sides of a payment depend on agreeing about, so the postcondition is
            // the whole point: a key it returns must be compressed, valid, and hash to the
            // pubkey hash in that prevout. Anything else is an output neither party can spend.
            std::vector<unsigned char> sig_bytes, spk_bytes;
            try {
                ds >> sig_bytes;
                ds >> spk_bytes;
            } catch (const std::ios_base::failure& e) {return 0;}
            const CScript script_sig(sig_bytes.begin(), sig_bytes.end());
            const CScript prevout_spk(spk_bytes.begin(), spk_bytes.end());

            CPubKey key;
            if (!bip352::GetPubKeyFromInput(key, script_sig, prevout_spk)) break;

            assert(key.IsFullyValid());
            assert(key.IsCompressed());
            assert(prevout_spk.size() == 25);       // only the canonical P2PKH script is eligible
            const CKeyID id = key.GetID();
            assert(memcmp(&prevout_spk[3], id.begin(), 20) == 0);
            break;
        }
        default:
            return 0;
    }
    return 0;
}

