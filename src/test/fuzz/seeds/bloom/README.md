# Seed corpus — CBloomFilter (BIP37 filterload) fuzz target (bloom.cpp)

Size-diverse seeds distilled via `-merge` from a ~0.84M-exec ASan+UBSan campaign.
Each input is a serialized CBloomFilter (vData, nHashFuncs, nTweak, nFlags — all
attacker-supplied), optionally followed by a serialized CTransaction. The harness
mirrors the net_processing FILTERLOAD handler (deserialize -> IsWithinSizeConstraints
-> UpdateEmptyFull) then exercises insert/contains (Hash = MurmurHash3 %
(vData.size()*8), vData bit indexing) and IsRelevantAndUpdate (tx matching).
