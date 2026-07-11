# Seed corpus — CheckAuxPowProofOfWork fuzz target (auxpow_checkpow.cpp)

10 size-diverse seeds (5 B – ~2.5 KB) distilled via `-merge` from a 548k-exec
ASan+UBSan campaign over `CheckAuxPowProofOfWork` (the full merge-mining network
entry point: version-gated CBlockHeader deserialize -> chain-ID/legacy gate ->
CheckProofOfWork(SetCompact) -> CAuxPow::check). The majority set the
VERSION_AUXPOW (0x100) version bit so the auxpow-present branch is exercised.

Layout: byte 0 is the harness control byte (toggles fStrictChainId); bytes 1..
are a serialized CBlockHeader. scrypt is stubbed in the harness, so PoW-hash
gating is neutralised and execution reaches the auxpow verification logic.
