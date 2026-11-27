// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "consensus/merkle.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "addrman.h"
#include "arith_uint256.h"
#include "chain.h"
#include "coins.h"
#include "compressor.h"
#include "net.h"
#include "net_processing.h"
#include "protocol.h"
#include "streams.h"
#include "undo.h"
#include "validation.h"
#include "version.h"
#include "pubkey.h"
#include "bip352.h"
#include "hash.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "key.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
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
    BIP352_GETSPTWEAKS,
    TEST_ID_END
};

/** Blocks on the active chain the getsptweaks target builds, enough to reach both sides of the
 *  thousand-block request limit. One more index sits past them, off the chain. */
static const size_t FUZZ_CHAIN_LEN = 1200;

/**
 * A chain a request can name, reachable by hash: heights 0 to FUZZ_CHAIN_LEN-1 are the active
 * chain, and the index after them is a stale tip, in mapBlockIndex and not on the chain, so the
 * rule that a stop hash has to name an active block has something to refuse that is not simply
 * unknown. The hash of entry i is i+1, so a request names a block by number.
 */
static void BuildFuzzChain()
{
    LOCK(cs_main);
    std::vector<CBlockIndex*> chain;
    for (size_t i = 0; i <= FUZZ_CHAIN_LEN; i++) {
        // On the heap because mapBlockIndex owns what it holds: the cleanup that runs at exit
        // deletes every index in it.
        CBlockIndex* index = new CBlockIndex();
        const bool stale = i == FUZZ_CHAIN_LEN;
        index->nHeight = stale ? (int)FUZZ_CHAIN_LEN - 1 : (int)i;
        index->pprev = i == 0 ? NULL : chain[stale ? FUZZ_CHAIN_LEN - 2 : i - 1];
        const uint256 hash = ArithToUint256(arith_uint256(i + 1));
        BlockMap::iterator it = mapBlockIndex.insert(std::make_pair(hash, index)).first;
        index->phashBlock = &it->first;
        index->BuildSkip();
        chain.push_back(index);
    }
    chainActive.SetTip(chain[FUZZ_CHAIN_LEN - 1]);
}

/**
 * Takes every signature. A scriptSig that verifies against its prevout under this checker and
 * no flags is one consensus would accept if its signature were good, so the set is a superset
 * of the spends that can be on the chain, and nothing has to be signed to get into it.
 */
class AnySignatureChecker : public BaseSignatureChecker
{
public:
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return true;
    }
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
                Coin coin;
                ds >> coin;
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
            std::string lower(str);
            for (size_t c = 0; c < lower.size(); ++c) lower[c] = ToLower((unsigned char)lower[c]);

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

                // Decoding the re-encoding only shows the decoder agrees with itself. One that
                // stopped checking the prefix, took bech32 for bech32m, or kept reading past
                // the keys of a version 0 address still hands back two good keys and still
                // round-trips, so the string is compared as well. Version 0 is the two keys
                // and nothing else and has one spelling, so encoding what was decoded gives the
                // whole string back, in lower case. A later version may carry more than this
                // build keeps, so there it is the prefix, the separator and the version.
                const size_t same = addr.GetVersion() == 0 ? std::string::npos
                                                           : Params().SilentPaymentsHRP().size() + 2;
                assert(again.compare(0, same, lower, 0, same) == 0);
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
            const bool got = bip352::GetPubKeyFromInput(key, script_sig, prevout_spk);

            // BIP352's reference code does not parse the scriptSig. It slides a 33-byte window
            // back from the end and takes the first that hashes to the prevout's pubkey hash and
            // is a compressed key. The rule here walks the pushes instead. Another wallet may
            // do either, and a key one side finds and the other does not is a payment sent to
            // an output the receiver never derives, so the two are compared.
            CPubKey ref;
            bool ref_got = false;
            if (prevout_spk.size() == 25 && prevout_spk[0] == OP_DUP && prevout_spk[1] == OP_HASH160 &&
                prevout_spk[2] == 20 && prevout_spk[23] == OP_EQUALVERIFY && prevout_spk[24] == OP_CHECKSIG) {
                const uint160 want(std::vector<unsigned char>(prevout_spk.begin() + 3, prevout_spk.begin() + 23));
                for (size_t end = sig_bytes.size(); end >= 33 && !ref_got; --end) {
                    const std::vector<unsigned char> window(sig_bytes.begin() + (end - 33), sig_bytes.begin() + end);
                    if (Hash160(window) != want) continue;
                    const CPubKey candidate(window);
                    if (!candidate.IsCompressed() || !candidate.IsFullyValid()) continue;
                    ref = candidate;
                    ref_got = true;
                }
            }
            // A push is 33 bytes in a row, so whatever the walk finds the window finds too.
            if (got) assert(ref_got && ref == key);
            // The other way round holds only for a spend that verifies. The window also
            // matches a key buried in a longer push, or one behind bytes that do not parse,
            // and neither can be what a valid spend leaves on the stack: with the splice
            // opcodes disabled, 33 bytes get there by being pushed whole.
            if (VerifyScript(script_sig, prevout_spk, NULL, SCRIPT_VERIFY_NONE, AnySignatureChecker())) {
                assert(got == ref_got);
            }
            if (!got) break;

            assert(key.IsFullyValid());
            assert(key.IsCompressed());
            // Only the canonical P2PKH script is eligible, and that is one script per key, so
            // the whole prevout is compared. Its length and the twenty bytes in the middle
            // leave the five opcode bytes to an implementation that stopped looking at them.
            assert(prevout_spk == GetScriptForDestination(CTxDestination(key.GetID())));
            break;
        }
        case BIP352_GETSPTWEAKS:
        {
            // The request handler, reached the way a peer reaches it: a framed getsptweaks goes
            // into the node's queue and ProcessMessages dispatches it. The payload is two
            // fixed-size fields, so surviving the bytes is not the interesting property. What a
            // peer is charged for them is: a request outside the protocol costs the connection,
            // and one inside it never does. A node that disconnects on a request it should have
            // served is a light client that cannot sync, and one that serves a request it should
            // have refused answers unbounded work, so both directions are asserted.
            //
            // A flags byte, then the stop block, then the start height:
            //   bit 0  the node offers NODE_SP_TWEAKS
            //   bit 1  the stop hash names a block from the chain above, by a uint16 index;
            //          without it the hash comes off the stream and is almost never known
            //   bit 2  the start height is a uint16 below the stop height rather than a uint32,
            //          which puts the thousand-block limit in reach without coverage feedback
            uint8_t flags;
            uint256 stop_hash;
            try {
                ds >> flags;
                if (flags & 2) {
                    uint16_t which;
                    ds >> which;
                    stop_hash = ArithToUint256(arith_uint256(which % (FUZZ_CHAIN_LEN + 1) + 1));
                } else {
                    ds >> stop_hash;
                }
            } catch (const std::ios_base::failure& e) {return 0;}

            SelectParams(CBaseChainParams::REGTEST);
            BuildFuzzChain();

            const CBlockIndex* stop_index;
            {
                LOCK(cs_main);
                stop_index = LookupBlockIndex(stop_hash);
                if (stop_index != NULL && !chainActive.Contains(stop_index)) stop_index = NULL;
            }

            uint32_t start_height;
            try {
                if (flags & 4) {
                    uint16_t back;
                    ds >> back;
                    // The tip's height when the stop hash named nothing on the chain, so a
                    // request for a block this build refuses still carries a start the chain
                    // holds. Anchoring it one higher put every such request above the tip,
                    // where the start-above-stop rule answers first and hides the rest.
                    const int64_t from = stop_index != NULL ? stop_index->nHeight
                                                            : (int64_t)FUZZ_CHAIN_LEN - 1;
                    start_height = (uint32_t)(from - (int64_t)back);
                } else {
                    ds >> start_height;
                }
            } catch (const std::ios_base::failure& e) {return 0;}

            CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
            payload << start_height << stop_hash;

            CConnman connman(0x1337, 0x1337);
            const ServiceFlags services = (flags & 1) ? (ServiceFlags)(NODE_NETWORK | NODE_SP_TWEAKS)
                                                      : NODE_NETWORK;
            CNode node(0, services, 0, INVALID_SOCKET, CAddress(), 0, 0, CAddress(), "", true);
            node.SetSendVersion(PROTOCOL_VERSION);
            // Registered first, or the signal has no slot, InitializeNode does nothing and the
            // per-peer state the dispatcher dereferences on its way out is never created.
            RegisterNodeSignals(GetNodeSignals());
            GetNodeSignals().InitializeNode(&node, connman);
            node.nVersion = PROTOCOL_VERSION;
            node.fSuccessfullyConnected = true;

            // Framed with its own header, so the bytes above are spent on the payload instead of
            // on a checksum no fuzzer guesses.
            CMessageHeader hdr(Params().MessageStart(), NetMsgType::GETSPTWEAKS, payload.size());
            const uint256 checksum = Hash(payload.begin(), payload.end());
            memcpy(hdr.pchChecksum, checksum.begin(), CMessageHeader::CHECKSUM_SIZE);
            CDataStream framed(SER_NETWORK, PROTOCOL_VERSION);
            framed << hdr;
            assert(framed.size() == CMessageHeader::HEADER_SIZE);

            CNetMessage msg(Params().MessageStart(), SER_NETWORK, PROTOCOL_VERSION);
            assert(msg.readHeader(&framed[0], framed.size()) > 0);
            assert(msg.readData(&payload[0], payload.size()) > 0);
            assert(msg.complete());
            node.nProcessQueueSize = payload.size() + CMessageHeader::HEADER_SIZE;
            node.vProcessMsg.push_back(msg);

            std::atomic<bool> interrupt(false);
            ProcessMessages(&node, connman, interrupt);

            // Derived from the chain this built, on signed values, so a limit the handler keeps
            // by wrapping a subtraction does not hold here as well.
            bool in_spec = (flags & 1) != 0 && stop_index != NULL;
            if (in_spec) {
                const int64_t blocks = (int64_t)stop_index->nHeight - (int64_t)start_height + 1;
                in_spec = blocks >= 1 && blocks <= 1000;   // MAX_GETSPTWEAKS_SIZE, the limit the DIP states
            }
            assert(node.fDisconnect == !in_spec);

            // There is no tweak index here, so the handler stops before it reads one and the
            // serving loop, the walk to each ancestor and the stop on a full send buffer are not
            // covered. This target is about what the peer's own two fields are allowed to ask for.
            break;
        }
        default:
            return 0;
    }
    return 0;
}

