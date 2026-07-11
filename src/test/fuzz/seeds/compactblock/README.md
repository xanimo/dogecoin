# Seed corpus — BIP152 compact-block fuzz target (compactblock.cpp)

Size-diverse seeds distilled via `-merge` from a ~0.83M-exec ASan+UBSan campaign
over CBlockHeaderAndShortTxIDs deserialize. Each input is a serialized cmpctblock:
a CBlockHeader (optional auxpow), an 8-byte nonce, a COMPACTSIZE count + packed
6-byte short txids, and a vector of differential-index-encoded prefilled
transactions (each a full CTransaction) — all attacker-controlled on the wire.
