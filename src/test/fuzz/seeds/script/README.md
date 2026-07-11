# Seed corpus - script interpreter fuzz target (script.cpp)

Distilled via -merge from a ~3.9M-exec ASan+UBSan campaign over VerifyScript.
Layout: 2 bytes flags (SCRIPT_VERIFY_* bits, normalised to valid combos) + 1 byte
split + scriptSig bytes + scriptPubKey bytes.

NOTE: on a pristine tree this target trips UBSan in the crypto Write() functions
(nullptr+offset on empty-input hashing, finding F-02) via hash opcodes on an empty
stack element; guard crypto Write() with `if (len==0) return *this;` (or add a
UBSan suppression) for a clean run.
