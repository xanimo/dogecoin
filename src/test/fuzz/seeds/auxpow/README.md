# auxpow fuzz seed corpus

Seed inputs for the CAuxPow deserialize+check() libFuzzer target (../auxpow.cpp).
Input format: 1 control byte (bit0 = fStrictChainId, perturbs aux hash) followed by a
serialized CAuxPow. These seeds are a size-diverse subset distilled (libFuzzer -merge)
from a 1.42M-exec ASan+UBSan campaign; they exercise full deserialization and the
merkle-linkage checks. Run: build-auxpow-fuzz.sh then ./auxpow_fuzz seeds/auxpow
