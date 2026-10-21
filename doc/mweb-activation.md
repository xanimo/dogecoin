# mweb activation on an auxpow chain

records how this port activates segwit and mweb, why it cannot use bip9, and what
the chain's block versions actually look like today. the mechanism is in
`src/validation.cpp` (`IsWitnessEnabled`, `IsMWEBEnabled`, `IsSegwitLatched`,
`IsMWEBLatched`); the census below is measured, the conclusions drawn from it are
not predictions about what pools will do.

## why not bip9

bip9 signals in the high bits of `nVersion`, which on dogecoin hold the auxpow
chain id: `SetBaseVersion` packs it at `VERSION_CHAIN_START = 1 << 16`
(`primitives/pureheader.h:23,26`). signalling there either collides with the
chain id or requires relocating it, which is a hard fork. the miner does not
signal in any case: `ComputeBlockVersion` is commented out and the template
always carries `VERSIONBITS_LAST_OLD_BLOCK_VERSION` (`miner.cpp:156`). a bip9
deployment on this chain therefore cannot lock in, on mainnet or regtest.

## what the port uses instead

the pre-bip9 `IsSuperMajority` mechanism, which compares `GetBaseVersion() =
nVersion % 256` and so never reads the chain id. segwit activates when
`nSegwitEnforceVersion` base-version blocks reach the supermajority at or after
`nSegwitStartHeight`; mweb sits one rung up at `nMwebEnforceVersion >=
nSegwitEnforceVersion`, so mweb cannot activate before or without segwit. both
answers are latched, since extension blocks hold funds and a mid-flight
deactivation would strand them.

mainnet thresholds are `nMajorityEnforceBlockUpgrade = 1500` of
`nMajorityWindow = 2000`, so 75% of a rolling 2000-block window, about a day and
a half at target spacing. mainnet currently configures neither deployment
(`nSegwitEnforceVersion = 0`, `nMwebEnforceVersion = 0`), so nothing activates
until versions and heights are set.

## census

504,631 blocks from the local block files, september 2025 through september 2026:

    base   auxpow  chain      count    share
    4      1       98        504435   99.96%
    4      0       98           193    0.04%

every block is base version 4. the 193 without the auxpow bit are natively
mined, also version 4. chain id 98 throughout. month by month across those
thirteen months there is no variance at all: v4 is 100.0% of every month.

the only precedent for moving the base version is v3 to v4:

    2019-02   v4 first appears,  1.89%
    2019-09   v4 19.25%
    2020-03   v4 crosses half,  51.81%
    2020-07   v4 70.01%
    2020-11   v4 100%

about twenty-one months from first appearance to universal, thirteen to half.
the chain has been uniformly v4 since.

## what this means for the ladder

75% of 2000 blocks is a day and a half of chain once the hashrate is emitting
the new version, so the window is not the constraint. shipping is. the ladder
requires merge-mining pools to deliberately bump the base version in their own
software, there is no latent signalling to ride on, and the one time this chain
did it the first fifth of hashrate took seven months and half took thirteen.

that is a coordination problem, not a protocol one, and it should be treated as
the long pole in any mweb schedule rather than as a deployment detail.

## not measured here

no pool attribution: the coinbase tags that would say which operators produce
the 99.96% were not parsed, so there is no list of who would have to ship. the
census is local block files up to 2026-09 and does not include the two weeks
before this was written. nothing here measures whether pools would agree to bump,
only that none has since 2020.
