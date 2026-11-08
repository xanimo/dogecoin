bip352 silent payments over p2pkh, dogecoin core 1.14 line
==========================================================

this is a snapshot of the feature/bip352-silent-payments branch,
branched off b7cb494581 (merge of #4085 on master). the head it was cut
at is in the archive filename. the source tree here is the branch at
that head; bip352-patches/ holds the commits on top of the base as a
git format-patch series, applicable with `git am`.

status: staging only, not proposed for mainnet. there is a dip draft
but it is unfiled, so the wire and address formats are not ratified.

what it adds
------------

src/bech32.{h,cpp}        bech32 and bech32m codec (new, no segwit dependency)
src/bip352.{h,cpp}        address derivation, ecdh shared secret, output scan
src/tweakindex.{h,cpp}    per-block index of scanning tweaks
src/wallet/               silent payment keys derived from the hd seed
src/wallet/rpcwallet.cpp  getsilentpaymentaddress, sendtosilentpaymentaddress,
                          scansilentpayments
qa/rpc-tests/silentpayments.py
                          end to end functional test
contrib/bip352/           corpus harnesses: scriptsig eligibility over rpc,
                          undo-file scan, test vector generation

the scheme is bip352 restricted to p2pkh inputs, since dogecoin has no
segwit and therefore no taproot. input public keys are recovered from
the scriptSig. the tweak index lets a scanner work from a compact
per-transaction value rather than re-deriving from every input.

what has been measured
----------------------

the eligibility rule has been run over the whole chain, not a sample.
contrib/bip352/undo_corpus.py reads the blk and rev files directly
rather than going through rpc, which is what makes a full pass take
hours instead of days. every block to height 6381544:

    inputs classified   768800287
    eligible            551429032   all canonical
    no_match                    0
    ambiguous                   0

coverage is complete rather than sampled: 412261244 classified
transactions plus 6381545 coinbases, which undo data omits by
construction, is 418642789, the chain total to the transaction.

the tweak index has been built over mainnet: 10.3gb on disk for
278571058 entries, complete to 6381544, and the node restarts clean
against it.

key encodings, sampled across five eras, 1.68m eligible inputs:
uncompressed is 16.4% in 2014 and under 2% since. hybrid (0x06/0x07)
is zero everywhere, and is refused by the rule for that reason.

p2sh is out of scope and stays that way. 60.7% of p2sh inputs do
reveal one compressed key, but 97% of those are
`<key> OP_CHECKSIGVERIFY` followed by a run of OP_DROPs, which is the
reveal side of a data carrier rather than a wallet anyone would pay.

reproducing the measurements
----------------------------

whole-chain corpus. run at contrib/bip352/undo_corpus.py as of cc00b0ac87, against a node
synced to height 6381544, block hash
4c38566f20178bad6ec3e5835b22dfa26ad12d02dc4da7077f92a5391b1cd6dc:

    ./contrib/bip352/undo_corpus.py --datadir /mnt/bigdata/dogecoin \
        --jobs 7 --cache-dir /path/to/ckpt --out corpus_fullchain.json

--cache-dir checkpoints each blk file as it finishes, so an interrupted run resumes instead of
starting over; the pass takes hours. the full json report this produced is in
bip352-reports/corpus_fullchain.json here, and the 1357 per-file checkpoints it was summed from
are in bip352-reports/per-file/. those let a single blk file be checked without re-running the
chain, and they add up to the aggregate.

the classifier was tightened afterwards, in e2daafd05d, to refuse hybrid pubkey prefixes. that
does not change the result and the report was not regenerated: a hybrid key would have been
counted eligible under an off_curve key type, and the report has no off_curve bucket at all, its
526056252 compressed plus 25372780 uncompressed summing to the whole 551429032 eligible.

key encodings by era, and the p2sh breakdown, are samples rather than whole-chain. the era
sample reads blk00100, blk00400, blk00900, blk01200 and blk01356; the p2sh sample reads
blk00700, blk01000, blk01200 and blk01356. both drive _run_file from undo_corpus.py directly
rather than through the cli, so reproducing them means a short script, not a flag.

index size. measured with the node stopped, so nothing is mid-compaction:

    du -sb /mnt/bigdata/dogecoin/indexes/tweakindex
    10771497975

which is 10283 MiB, over 278571058 entries, so 38.7 bytes each against 33 bytes of payload.
entries are batched per block rather than per transaction, which is why the overhead is small.

building and testing
--------------------

    ./autogen.sh
    ./configure --without-gui --disable-bench --disable-zmq --with-incompatible-bdb
    make
    src/test/test_dogecoin --run_test=bip352_tests
    src/test/test_dogecoin --run_test=bech32_tests
    qa/pull-tester/rpc-tests.py silentpayments

the wallet is required, so --disable-wallet will not build the rpcs or
the functional test. bdb 5.3 needs --with-incompatible-bdb.

known gaps
----------

no dip filed, so nothing here is ratified.

no light client. the tweak index is the server half of one; the client
half needs bip158 filters to test candidate outputs against a block
without downloading it, and those live on another branch.

the index is built from ConnectBlock and so needs a reindex to populate
over blocks already on disk. the newer index framework on the bip157
branch syncs in the background instead, which would remove that cost,
and is the shape this should take once those filters land.

review status: one external review has been through the eligibility
rule, the index, the connectblock hooks and the harnesses. it found the
index completeness bug and the hybrid key divergence, both fixed here.
