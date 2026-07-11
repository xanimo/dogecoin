# Seed corpus — CPartialMerkleTree (BIP37 merkleblock) fuzz target (merkleblock.cpp)

Size-diverse seeds distilled via `-merge` from a ~3M-exec ASan+UBSan campaign over
CPartialMerkleTree deserialize + ExtractMatches (recursive TraverseAndExtract).
Each input is a serialized CPartialMerkleTree: uint32 nTransactions, a vector of
32-byte hashes, and a bit-vector (as bytes) — all attacker-controlled as they
arrive in a P2P "merkleblock" message.
