provenance of this vendored tree
================================

upstream is mimblewimble/secp256k1-zkp. the vendored base is

    b247e1ec8ed62b9abf123dc83189d253e17d488d
    "Merge pull request #67 from yeastplume/sig_neg"

every other file in this directory is that commit verbatim, including the
upstream README.md above. `include/` is byte-identical to the base.

local changes
-------------

one source change, in `src/secp256k1.c`: a single added

    #include "../prefix.h"

prefix.h renames every `secp256k1_` identifier to `mw_secp256k1_`, so this
library and the consensus `src/secp256k1` link into one binary without
colliding. the include is in the source rather than only a build flag so the
rename applies in every build environment; prefix.h is include-guarded, so a
duplicate `-include` is harmless. the built archive exports 87 `mw_secp256k1_*`
symbols and no unprefixed ones, which is what makes the isolation real rather
than assumed.

`src/java` (the JNI bindings) is dropped. the generated build files present here
and absent upstream (`libsecp256k1-config.h`, `ecmult_static_context.h`,
`stamp-h1`) are build artefacts, not source edits.

why a second secp256k1
----------------------

mweb needs pedersen commitments, bulletproof rangeproofs, aggsig kernel
signatures, the alternate H generator and ecdh. the consensus secp has none of
those modules. porting them onto the modern baseline crosses the ecmult_context
refactor, so the fork is vendored whole instead and kept away from consensus
code by the symbol prefix.

one consequence worth knowing: this fork predates the upstream `privkey` to
`seckey` rename, so it exports `secp256k1_ec_privkey_tweak_add` and a 4-argument
ecdh where the consensus copy has `secp256k1_ec_seckey_tweak_add` and a
6-argument ecdh. `Makefile.am` puts `secp256k1/include` on the include path
before `secp256k1-zkp/include`, so `#include <secp256k1.h>` inside libmw
resolves to the *consensus* header. `libmw/keys.cpp` forward-declares the two
signatures that actually differ rather than pull in the wrong header, and that
is why the build prints deprecation warnings naming `mw_secp256k1_*` symbols:
the attribute comes from the consensus header, macro-renamed, for a symbol that
at link time comes from this library, which deprecates nothing.

distance from upstream
----------------------

one commit behind upstream master as of 2026-11-02: `0eefced "fix scratch
leak"`, merged as `4b185b1`. it adds a missing
`secp256k1_scratch_deallocate_frame` on the two malformed-point paths in
`secp256k1_bulletproof_rangeproof_verify_impl`.

not reachable through libmw as written. the single-proof wrapper
`secp256k1_bulletproof_rangeproof_verify`, which is the only entry point
`libmw/bulletproof.cpp` calls, allocates its own frame and deallocates it
unconditionally after the impl returns; frames are a LIFO stack, so that rewinds
anything the impl leaked above it. this matters because libmw's scratch space is
a process-wide static that is never destroyed, so a leak that did accumulate
would be permanent. feeding 4000 malformed rangeproofs through
`Bulletproof::Verify` and re-verifying a valid proof after each one showed no
degradation.

take the fix on the next sync anyway; the reasoning above is about one call
path, and `..._verify_multi` was not examined.
