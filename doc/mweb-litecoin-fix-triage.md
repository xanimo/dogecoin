# litecoin mweb fix triage

triages every litecoin commit touching `src/libmw` or `src/mweb` after
v0.21.5.6 (2026-07-29), the version the divergence writeup pins, against this
port. sorted by the buckets that writeup argues for: applicable, applicable with
a different shape, and not-applicable-for-absence, which is a different claim
than behavioural equivalence and is recorded as such.

five commits. one is not applicable, four are applicable and unported.

## a399fc4ca73d  validate: reject empty MWEB kernel extradata  (2026-08-07)

applicable, unported.

adds `Kernel::HasCanonicalExtraDataFeature()` and rejects a block whose kernels
set the extra-data feature bit without carrying extra data, gated on a new
`mweb_extradata_feature_activation_height`. mirrors the pegout rule already
upstream.

the port has the feature bit and `HasExtraData()`
(`include/mw/models/tx/Kernel.h:33,67`) and neither canonical-feature rule:
no extra-data check and no pegout equivalent, and `consensus/params.h` has
neither activation height. so the port is missing both halves of a pair, of
which this is the newer.

partially mitigated by policy rather than consensus: `Kernel::IsStandard()` is
`m_features < EXTRA_DATA_FEATURE_BIT` (`Kernel.h:68`), so an extra-data kernel
is non-standard and `MWEB::Policy::IsStandardTx` will not relay it. a miner can
still put one in a block, which is what the consensus rule is for.

## f6afd2682620  mweb: validate staged block aggregates incrementally  (2026-09-05)

applicable, unported, different shape.

validates kernel and stealth aggregates as transactions are staged into a block
rather than only when the block is built, so a staged set that cannot balance is
rejected at the point it stops balancing.

upstream carries this in `KernelSumValidator.h` and `StealthSumValidator.h`. the
port has no such files: both sums are inline in `ValidateBodyCrypto`
(`libmw.cpp`), which the divergence writeup records. the fix therefore applies to
the port's `BlockBuilder` but cannot be taken as a diff.

## 70ea696f361c  mweb: harden same-hash block mutation handling  (2026-09-05)

applicable, unported, and the port has the exact pre-fix shape.

upstream moved the HogEx marker check ahead of the loop that rejects peg-in
outputs in the coinbase or HogEx, because the marker is not committed by the
canonical merkle root: a mutated block carrying the same hash would otherwise be
rejected as consensus-invalid rather than mutated, which poisons the hash as
permanently failed. it also factors out `Block::HasValidKernelMMR`.

the port runs the two in the pre-fix order: the peg-in loop at
`src/mweb/mweb_node.cpp:55`, the marker check at `:66`.

## b4313c34d27b  mweb: prevent disk-reparse validation bypass  (2026-09-05)

applicable, unported.

calls `ContextualCheckBlock` at the top of `Node::ConnectBlock` so the body
actually being applied is revalidated, including after a reload from disk.

the port's `MWEB::Node::ContextualCheckBlock` is reached only from the generic
`ContextualCheckBlock` (`validation.cpp:3449`), which runs on first receipt.
`validation.cpp:1865` says outright that ConnectBlock does not re-invoke it. a
block that reaches connect from disk rather than from the network is therefore
not re-checked against the MWEB rules.

## b8ccaf3552a9  libmw: close POSIX copy file descriptors  (2026-09-08)

not applicable, for absence.

a two-line fix in the vendored `ghc::filesystem` header
(`src/libmw/deps/ghc/include/ghc/filesystem.hpp`). the port vendors no
dependencies under `src/libmw`: there is no `deps` directory, and filesystem
access goes through the tree's own `fs`. nothing to port rather than already
equivalent.

## order

b4313c34d27b and 70ea696f361c first: both are small, both are reachable by a
peer, and neither needs a design decision. a399fc4ca73d next, together with the
pegout rule it mirrors, since adding one canonical-feature check without the
other leaves the pair half-done. f6afd2682620 last, as it needs the port's
inline sums restructured before the fix has anywhere to go.

## not verified here

each classification is from reading the upstream diff and the port's
corresponding path. none of the four applicable fixes has been ported, so none
has been tested here. the commit list is everything touching those two
directories after the pinned tag; fixes landing elsewhere in litecoin that
affect mweb indirectly are not covered.
