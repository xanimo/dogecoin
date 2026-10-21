# mweb crypto divergence from litecoin

documents where this port's ownership cryptography diverges from litecoin's mweb, what each signature commits to, the two balance equations, and which litecoin protections the port replaces, drops, or has not yet ported. it argues that the divergences are justified and shows how litecoin's fixes re-sort against this model; it does not establish that the scheme is sound, which is a different claim and needs review by someone other than its author. dogecoin references are to branch `mweb` at 394d8b6434 plus the three commits that close the output and carve-out gaps described below (0d1697b2d4, 324839f543, 5a76503519), litecoin references to `litecoin-project/litecoin` at 992c5272e157 (v0.21.5.6), paths under `src/libmw` unless noted.

## kernel signatures

the kernel signs the hash of its feature byte and every present optional field: fee, peg-in amount, peg-outs, lock height, stealth excess, extra data (`include/mw/models/tx/Kernel.h` `SerializeSigMessage`). the verification key is the excess itself reinterpreted as a public key (`libmw.cpp:56`). the excess is not part of the message; litecoin hashes it in (`src/models/tx/Kernel.cpp:98`). binding through the key gives the same effect, since re-attributing the message to a different excess requires a fresh signature under that excess, which requires its discrete log.

litecoin additionally weights the verification key when a stealth excess is present: the key becomes `X*H(X||X_s) + X_s` where `X` is the excess and `X_s` the stealth excess (`Kernel.cpp:60-72`), and the stealth excesses enter the stealth balance. the port has neither. a kernel carrying the stealth excess feature bit parses and the field is committed by the kernel signature, but its key signs nothing and enters no balance, so the field is wire-compatible and cryptographically inert. the wallet never sets it (`include/mw/wallet/TxBuilder.h:117-119` builds kernels with fee, peg-in and peg-out features only).

## input signatures

the input signs the hash of the entire input minus the signature: features, spent output id, commitment, input pubkey if present, output pubkey, extra data (`include/mw/models/tx/Input.h:71-81`). the verification key is the output pubkey alone (`libmw.cpp:48`). the stateful connect path then requires the claimed commitment and output pubkey to equal the spent output's commitment and one-time receiver key (`src/mweb/mweb_db.cpp:112-121`), so a valid spend proves control of the specific output referenced.

litecoin signs only features and output id and pushes the binding into the key instead: the verification key is the aggregate `K_agg = K_i + H(K_i||K_o)*K_o` of a fresh per-spend input key and the output's one-time key (`src/models/tx/Input.cpp:39-64`). the hash coefficient exists because `K_i` is attacker-chosen relative to `K_o`; without it, `K_i = K - K_o` lets a signer who knows only `k` satisfy the aggregate. the port's verification equation contains no attacker-chosen key, the single key being pinned to the spent output by consensus state, so there is nothing for a coefficient to defend and the aggregation is not needed.

what is dropped with it: litecoin's `K_i` is fresh randomness the spender feeds into the stealth balance. the port carries the field (stealth key feature bit) and commits it under the input signature, but nothing verifies against it and the wallet never sets it (`TxBuilder.h:95,97` pass a null `PublicKey`).

## output signatures

litecoin outputs carry a signature by the sender's ephemeral key over the commitment, sender pubkey, receiver pubkey, output message hash and rangeproof hash (`src/models/tx/Output.cpp:91-101`), batch-verified in consensus (`src/models/tx/TxBody.cpp:149-155`), and the rangeproof commits to the serialized output message as extra data (`Output.cpp:103-106`).

the port signs the same fields: `Output::GetSignatureMessage` hashes the commitment, both keys, the output message and the rangeproof hash (`include/mw/models/tx/Output.h:134`), `Stealth::Send` signs it with the ephemeral key whose public key is the output's sender key (`include/mw/wallet/Stealth.h:71`), `TxBuilder` signs every output it builds (`TxBuilder.h:118`), and consensus rejects an output with no sender key and verifies the signature one at a time rather than in a batch (`libmw.cpp:44,48`). the divergence that remains is the rangeproof: `Bulletproof::Verify` takes only the proof and commitment (`bulletproof.cpp:76-91`) and nothing commits the output message as extra data. the signature covers the message, so the malleation litecoin's extra data defends against is closed by a different route, and the two mechanisms are not interchangeable for anything that verifies proofs without the signature.

## balance equations

value: `sum(outputs) + (fees + pegouts)*H == sum(inputs) + sum(excesses) + pegins*H + kernel_offset*G`, checked as sum-to-zero with `secp256k1_pedersen_verify_tally` (`libmw.cpp:63-99`). this is litecoin's `KernelSumValidator` identity with the supply change folded into the `H` terms rather than a signed transparent commitment. a block validates the merged body against a single offset which is the scalar sum of its transactions' offsets (`libmw.cpp:302-322`), matching litecoin's header offset.

stealth: `sum(output sender keys) - sum(input owner keys) == stealth_offset*G` (`libmw.cpp:101-127`), where each input's owner key is the receiver one-time key of the output it spends. litecoin's equation is `sum(K_s) + sum(K_i) == sum(E') + x'*G + sum(K_o)` (`include/mw/consensus/StealthSumValidator.h:14`). remove the input stealth keys `K_i` and kernel stealth excesses `E'`, the two key classes the port does not use, and litecoin's equation reduces to the port's, so the port's stealth balance is the litecoin balance restricted to the keys that exist here. sender keys remain non-malleable under it: substituting a sender key or the offset requires the original sender's secret to compute the compensating delta.

## what this leaves open

output binding was the hole and is now closed. a relaying peer that rewrites an output's receiver key, key-exchange pubkey, view tag or masked value invalidates the sender signature, which consensus verifies, so the transaction is rejected rather than confirmed with the payment destroyed. what the rewrite could never do, then or now, is steal: spending needs the blind and an ecdh secret between keys the relay holds neither of, and substituting the sender key is what the stealth balance prevents.

the value-balance-only carve-outs were consensus, not test scaffolding, and are also closed. an input with no owner key is rejected rather than having its signature skipped (`libmw.cpp:59`), the stealth balance runs on every body rather than only those carrying a stealth key (`libmw.cpp:134`), and connect rejects a null claimed key instead of matching it against an output created without a receiver key (`src/mweb/mweb_db.cpp:117`). outputs spendable by anyone who knows the blind are no longer accepted by the network, not merely absent from what the wallet creates.

what is left is narrower than the above. the rangeproof carries no extra commit data, so a verifier that checks proofs without checking signatures sees an unbound message; `TxBuilder` derives a sender key by hashing the coin's blind when the caller supplies none, which is deterministic rather than ephemeral and is a stand-in for a wallet-supplied key; and the kernel stealth excess and input stealth key remain parsed, committed and inert, as described above.

the litecoin fix audit re-triages against this model. fixes touching input key aggregation or stealth-excess weighting have no port counterpart, which is a different not-applicable than behavioral equivalence and should be recorded as such. fixes touching output signatures or rangeproof extra data are applicable and unported in full. fixes touching the sum validators map across directly, the equations being litecoin's with `K_i` and `E'` removed.

## not verified here

the output malleation is no longer asserted from reading alone: `mweb_output_signature_binds_receiver_key` re-addresses a sent output and is rejected, and that test fails on the tree before these commits. the wallet's stealth derivations (`Stealth.h`) were not reviewed against litecoin's addressing scheme. serialization compatibility beyond the feature bits named above was not checked, and these commits change no serialized layout: the signature field was already on the wire, carrying a null signature.
