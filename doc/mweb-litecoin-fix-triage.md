# litecoin mweb fix triage

triages every litecoin commit touching `src/libmw` or `src/mweb` after
v0.21.5.6 (2026-07-29), the version the divergence writeup pins, against this
port. sorted by the buckets that writeup argues for: applicable, applicable with
a different shape, and not-applicable-for-absence, which is a different claim
than behavioural equivalence and is recorded as such.

five commits. one is not applicable, four are ported, none remain.

ported since this was written: a399fc4ca73d, 70ea696f361c, b4313c34d27b (with
the hogex accounting move ahead of it), f6afd2682620. each section below records
what actually landed, which in two cases is not the shape the upstream diff has.
ported work is named by what the commit does rather than by hash, since the
branch rebases and hashes do not survive it.

## a399fc4ca73d  validate: reject empty MWEB kernel extradata  (2026-08-07)

PORTED, with both halves of the pair rather than one: the commit adding
`HasCanonicalPegOutFeature` and `HasCanonicalExtraDataFeature`.

adds `Kernel::HasCanonicalExtraDataFeature()` and rejects a block whose kernels
set the extra-data feature bit without carrying extra data, gated on a new
`mweb_extradata_feature_activation_height`. mirrors the pegout rule already
upstream.

the port was missing both halves of that pair, so both landed together:
`HasCanonicalPegOutFeature` and `HasCanonicalExtraDataFeature` on `Kernel`, both
enforced in `ContextualCheckBlock`.

two deliberate divergences. no activation height, because mweb has never
activated here and there are no kernels predating the rule to grandfather, so
`consensus/params.h` gains neither of upstream's two params. and the rejection
is classified as mutation rather than consensus, though not for upstream's
stated reason: `ReadCompactSize` rejects non-canonical encodings and the
features byte differs, so such a kernel does not reserialize to the same mmr
leaf. it must still not be a consensus verdict because nothing has
authenticated the body against the hogex-committed header at that point, so a
body swapped in under an honest header carries the honest block's hash.

policy already kept these off the relay path (`Kernel::IsStandard()` is
`m_features < EXTRA_DATA_FEATURE_BIT`), but a miner could put one in a block,
which is what the consensus rule is for.

## f6afd2682620  mweb: validate staged block aggregates incrementally  (2026-09-05)

PORTED in two commits: the one extracting the sum validators, and the one
validating the staged set in `BlockBuilder::AddTransaction`.

validates kernel and stealth aggregates as transactions are staged into a block
rather than only when the block is built, so a staged set that cannot balance is
rejected at the point it stops balancing.

upstream carries this in `KernelSumValidator.h` and `StealthSumValidator.h`. the
port had no such files: both sums were inline in `ValidateBodyCrypto`
(`libmw.cpp`), which the divergence writeup records, so the fix could not be
taken as a diff. the first extracts the two sums into headers of those names
under `mw/consensus` with no behaviour change, and the second has
`BlockBuilder::AddTransaction` merge into a running body, run both rules over
it, and roll the merge back on failure. `Build()` consumes that body rather than
re-merging, so there is one accumulation.

the port checks the whole staged set where upstream carries running sum state.
the two agree on what they reject: balanced transactions sum to a balanced set
whenever the block offset is the scalar sum of theirs. checking the set does not
assume `CombineOffsets` produces that sum, which is the bug the XOR aggregation
had. the cost is a sum over the staged set per addition, paid by the builder.

## 70ea696f361c  mweb: harden same-hash block mutation handling  (2026-09-05)

PORTED, in the commit classifying mutated blocks as mutation rather than
consensus failure.

upstream moved the HogEx marker check ahead of the loop that rejects peg-in
outputs in the coinbase or HogEx, because the marker is not committed by the
canonical merkle root: a mutated block carrying the same hash would otherwise be
rejected as consensus-invalid rather than mutated, which poisons the hash as
permanently failed. it also factors out `Block::HasValidKernelMMR`.

the port ran them in the pre-fix order and landed the reorder, plus the check
that only the last transaction carries the marker, which the port never had.
the five rejections reachable by mutating the marker or the extension block now
set `corruptionPossible`, which is 1.14's equivalent of `BLOCK_MUTATED`:
`AcceptBlock` (`validation.cpp:3581`) sets `BLOCK_FAILED_VALID` only when it is
clear.

the `HasValidKernelMMR` factoring is NOT ported. upstream uses it to
authenticate the body before making feature-bit decisions permanent; here those
decisions are classified as mutation instead, which is safe but coarser. worth
revisiting if the feature rules ever need a consensus verdict.

## b4313c34d27b  mweb: prevent disk-reparse validation bypass  (2026-09-05)

PORTED, in the commit revalidating the body `ConnectBlock` applies, after the
commit moving the hogex accounting to connect made it possible.

calls `ContextualCheckBlock` at the top of `Node::ConnectBlock` so the body
actually being applied is revalidated, including after a reload from disk.

the port has no `MWEB::Node::ConnectBlock` to patch, so the call went where the
accumulator is actually mutated, in `ConnectBlock` (`validation.cpp`), ahead of
the `fJustCheck` return so a mining template is checked too.

porting it first required moving the hogex accounting. it reads the previous
block's `hogex_hash` and `mweb_amount`, which only `ConnectBlock` populates, and
it was running from `AcceptBlock`. `LoadExternalBlockFile` accepts every block in
a file before activating anything, so a reindex of a chain with mweb active died
at the second mweb block with `bad-hogex-prevout`. measured: 751 of 800 blocks
before, 800 of 800 after.

## b8ccaf3552a9  libmw: close POSIX copy file descriptors  (2026-09-08)

not applicable, for absence.

a two-line fix in the vendored `ghc::filesystem` header
(`src/libmw/deps/ghc/include/ghc/filesystem.hpp`). the port vendors no
dependencies under `src/libmw`: there is no `deps` directory, and filesystem
access goes through the tree's own `fs`. nothing to port rather than already
equivalent.

## order

that order was followed, with one correction found on the way: b4313c34d27b
could not land as written until the hogex accounting moved, so that went ahead
of it. a399fc4ca73d followed with both halves of its pair.

f6afd2682620 went last, since it needed the port's inline sums restructured
before the fix had anywhere to go. nothing in the list remains.

## not verified here

every ported fix carries unit tests and, for the reindex half, a functional one.

the mweb functional tests could not run in the sanitiser tree at all, which is
configured `--disable-wallet`, so `mweb-version6-activation.py` and
`mweb-p2p-relay.py` had never executed locally before this round. a
wallet-enabled build is needed for them, and running them is what surfaced the
stealth-offset bug fixed by building the stealth output's coin with the key it
will carry.

they have now run against the branch tip in a wallet-enabled tree:
`mweb-version6-activation.py` and `mweb-p2p-relay.py` both pass. that covers
the miner path the staging change touches, which the `--disable-wallet` tree
cannot reach. unit counts are not quoted here because they move with the branch; the commit
messages carry them. the wallet tree is built `--disable-tests` and has no test
binary, so its functional runs are the only evidence it produces.

the upstream corpus carries no ci signal. litecoin has `.cirrus.yml` and a
`ci/` directory inherited from bitcoin core but no github actions, and a merge
commit there reports zero check runs with a combined status of pending and no
statuses. the fixes triaged above therefore landed on review alone, and the
port's own tests are the only automated evidence for the ported versions.

the commit list is everything touching those two directories after the pinned
tag; fixes landing elsewhere in litecoin that affect mweb indirectly are not
covered.
