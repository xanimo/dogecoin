# Seed corpus - addr (vector<CAddress>) fuzz target

Distilled from a ~277k-exec ASan+UBSan campaign over the "addr" P2P message
deserialize (COMPACTSIZE count + CAddress entries = nServices/nTime/CService).
