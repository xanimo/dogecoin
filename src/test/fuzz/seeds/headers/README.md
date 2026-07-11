# Seed corpus - headers (vector<CBlockHeader>) fuzz target

Distilled from a ~135k-exec ASan+UBSan campaign over the "headers" P2P message
deserialize (COMPACTSIZE count + auxpow-bearing block headers).
