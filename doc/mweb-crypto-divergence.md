# mweb crypto divergence from litecoin

documents where this port's ownership cryptography diverges from litecoin's mweb, what each signature commits to, the two balance equations, and which litecoin protections the port replaces, drops, or has not yet ported. it argues that the divergences are justified and shows how litecoin's fixes re-sort against this model; it does not establish that the scheme is sound, which is a different claim and needs review by someone other than its author. dogecoin references are to branch `mweb` at 394d8b6434, litecoin references to `litecoin-project/litecoin` at 992c5272e157 (v0.21.5.6), paths under `src/libmw` unless noted.

## kernel signatures

the kernel signs the hash of its feature byte and every present optional field: fee, peg-in amount, peg-outs, lock height, stealth excess, extra data (`include/mw/models/tx/Kernel.h` `SerializeSigMessage`). the verification key is the excess itself reinterpreted as a public key (`libmw.cpp:56`). the excess is not part of the message; litecoin hashes it in (`src/models/tx/Kernel.cpp:98`). binding through the key gives the same effect, since re-attributing the message to a different excess requires a fresh signature under that excess, which requires its discrete log.

litecoin additionally weights the verification key when a stealth excess is present: the key becomes `X*H(X||X_s) + X_s` where `X` is the excess and `X_s` the stealth excess (`Kernel.cpp:60-72`), and the stealth excesses enter the stealth balance. the port has neither. a kernel carrying the stealth excess feature bit parses and the field is committed by the kernel signature, but its key signs nothing and enters no balance, so the field is wire-compatible and cryptographically inert. the wallet never sets it (`include/mw/wallet/TxBuilder.h:117-119` builds kernels with fee, peg-in and peg-out features only).

## input signatures

the input signs the hash of the entire input minus the signature: features, spent output id, commitment, input pubkey if present, output pubkey, extra data (`include/mw/models/tx/Input.h:71-81`). the verification key is the output pubkey alone (`libmw.cpp:48`). the stateful connect path then requires the claimed commitment and output pubkey to equal the spent output's commitment and one-time receiver key (`src/mweb/mweb_db.cpp:112-121`), so a valid spend proves control of the specific output referenced.

litecoin signs only features and output id and pushes the binding into the key instead: the verification key is the aggregate `K_agg = K_i + H(K_i||K_o)*K_o` of a fresh per-spend input key and the output's one-time key (`src/models/tx/Input.cpp:39-64`). the hash coefficient exists because `K_i` is attacker-chosen relative to `K_o`; without it, `K_i = K - K_o` lets a signer who knows only `k` satisfy the aggregate. the port's verification equation contains no attacker-chosen key, the single key being pinned to the spent output by consensus state, so there is nothing for a coefficient to defend and the aggregation is not needed.

what is dropped with it: litecoin's `K_i` is fresh randomness the spender feeds into the stealth balance. the port carries the field (stealth key feature bit) and commits it under the input signature, but nothing verifies against it and the wallet never sets it (`TxBuilder.h:95,97` pass a null `PublicKey`).

## output signatures

litecoin outputs carry a signature by the sender's ephemeral key over the commitment, sender pubkey, receiver pubkey, output message hash and rangeproof hash (`src/models/tx/Output.cpp:91-101`), batch-verified in consensus (`src/models/tx/TxBody.cpp:149-155`), and the rangeproof commits to the serialized output message as extra data (`Output.cpp:103-106`). the port serializes an output signature but never creates one (`include/mw/wallet/Stealth.h:66`, `TxBuilder.h:107-108` pass empty signatures) and never verifies one, and `Bulletproof::Verify` takes only the proof and commitment (`bulletproof.cpp:76-91`). nothing in port consensus binds the receiver one-time key, key-exchange pubkey, view tag or masked value to the output. consequences below.

## balance equations

value: `sum(outputs) + (fees + pegouts)*H == sum(inputs) + sum(excesses) + pegins*H + kernel_offset*G`, checked as sum-to-zero with `secp256k1_pedersen_verify_tally` (`libmw.cpp:63-99`). this is litecoin's `KernelSumValidator` identity with the supply change folded into the `H` terms rather than a signed transparent commitment. a block validates the merged body against a single offset which is the scalar sum of its transactions' offsets (`libmw.cpp:302-322`), matching litecoin's header offset.

stealth: `sum(output sender keys) - sum(input owner keys) == stealth_offset*G` (`libmw.cpp:101-127`), where each input's owner key is the receiver one-time key of the output it spends. litecoin's equation is `sum(K_s) + sum(K_i) == sum(E') + x'*G + sum(K_o)` (`include/mw/consensus/StealthSumValidator.h:14`). remove the input stealth keys `K_i` and kernel stealth excesses `E'`, the two key classes the port does not use, and litecoin's equation reduces to the port's, so the port's stealth balance is the litecoin balance restricted to the keys that exist here. sender keys remain non-malleable under it: substituting a sender key or the offset requires the original sender's secret to compute the compensating delta.

## what this leaves open

output binding is the hole. with no verified output signature and no extra commit data in the rangeproof, a relaying peer can rewrite an output's receiver key, key-exchange pubkey, view tag or masked value in flight and the transaction still passes every consensus check: the commitment is untouched so the value balance and rangeproof hold, the sender key is untouched so the stealth balance holds, and no signature covers the rewritten fields. the rewrite cannot steal, since spending needs the blind, an ecdh secret between keys the relay holds neither of, and it cannot substitute the sender key, which the stealth balance protects. it destroys or hides the payment: the recipient's scan no longer matches, no one can spend the coin, and the kernel id, which is the transaction's identity, is unchanged, so the sender sees the payment confirm. the fix is litecoin's mechanism: create and verify the output signature and commit the output message in the rangeproof.

the value-balance-only carve-outs are consensus, not test scaffolding. validation skips the owner signature for an input whose output pubkey is null (`libmw.cpp:44`) and skips the stealth balance entirely when no stealth key is present in the body (`libmw.cpp:123`), and connect accepts a null claimed key against an output created without a receiver key. an output with a null receiver key is therefore spendable by anyone who knows its blind, with no signature at all. the wallet never creates such outputs, but the network accepts them; both carve-outs need closing before this is proposed.

the litecoin fix audit re-triages against this model. fixes touching input key aggregation or stealth-excess weighting have no port counterpart, which is a different not-applicable than behavioral equivalence and should be recorded as such. fixes touching output signatures or rangeproof extra data are applicable and unported in full. fixes touching the sum validators map across directly, the equations being litecoin's with `K_i` and `E'` removed.

## not verified here

the output malleation is asserted from reading the validation and connect paths, not from an executed test. the wallet's stealth derivations (`Stealth.h`) were not reviewed against litecoin's addressing scheme. serialization compatibility beyond the feature bits named above was not checked.
