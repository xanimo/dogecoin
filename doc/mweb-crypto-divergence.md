# mweb crypto divergence from litecoin

documents where this port's ownership cryptography diverges from litecoin's mweb, what each signature commits to, the two balance equations, and which litecoin protections the port replaces, drops, or has not yet ported. it argues that the divergences are justified and shows how litecoin's fixes re-sort against this model; it does not establish that the scheme is sound, which is a different claim and needs review by someone other than its author. dogecoin references are to branch `mweb-consensus-hardening` at d2ce952d1a, litecoin references to `litecoin-project/litecoin` at 992c5272e157 (v0.21.5.6), paths under `src/libmw` unless noted. references name the enclosing symbol rather than a line number.

## kernel signatures

the kernel signs the hash of its feature byte and every present optional field: fee, peg-in amount, peg-outs, lock height, stealth excess, extra data (`include/mw/models/tx/Kernel.h` `SerializeSigMessage`). the verification key is the excess itself reinterpreted as a public key, weighted when a stealth excess is present (`libmw.cpp` `ValidateBodyCrypto`, see below). the excess is not part of the message; litecoin hashes it in (`Kernel::GetSignatureMessage`). binding through the key gives the same effect, since re-attributing the message to a different excess requires a fresh signature under that excess, which requires its discrete log.

litecoin additionally weights the verification key when a stealth excess is present: the key becomes `X*H(X||X_s) + X_s` where `X` is the excess and `X_s` the stealth excess (`Kernel::BuildSignedMsg`), and the stealth excesses enter the stealth balance. the port now has both (`mw/consensus/KernelKey.h` `KernelVerificationKey`, used by `ValidateBodyCrypto`), so a kernel carrying the feature bit is no longer inert: its signature must satisfy the weighted aggregate and its key is subtracted in the stealth balance. the coefficient is what makes it load-bearing, since a plain `X + X_s` is satisfied by knowledge of `k` alone once the signer picks `X_s = K - X`, which would close the stealth balance with a key nobody owns. removing the weighting from the verifier accepts exactly that signature, which is what `mweb_kernel_stealth_excess_requires_weighting` pins.

the bit is wallet-opt-in rather than always set: `TxBuilder::Build` takes a stealth blind and defaults it null, so a caller that does not ask for one builds the kernel it built before. a bit set with an all-zero key is rejected as non-canonical (`Kernel::HasCanonicalStealthExcessFeature`, enforced in `MWEB::Node::ContextualCheckBlock`), since that key is not a curve point and the weighted key cannot be built from it.

## input signatures

the input signs the hash of the entire input minus the signature: features, spent output id, commitment, input pubkey if present, output pubkey, extra data (`Input::SerializeSigMessage`). the verification key is the output pubkey alone (`libmw.cpp` `ValidateBodyCrypto`). the stateful connect path then requires the claimed commitment and output pubkey to equal the spent output's commitment and one-time receiver key (`CMWEBStateDB::ConnectBlock`), so a confirmed spend proves control of the specific output referenced. that check is connect-only: `MWEB::Node::CheckTransaction` runs `Transaction::Validate` and reaches mempool acceptance through the `CheckTransaction` call in `AcceptToMemoryPoolWorker`, where the signature is verified against whatever key the input declares and nothing compares it to a real output.

litecoin signs only features and output id, and when the stealth key bit is set pushes the binding into the key instead: the verification key becomes the aggregate `K_agg = K_i + H(K_i||K_o)*K_o` of a fresh per-spend input key and the output's one-time key (`Input::Create`). the hash coefficient exists because `K_i` is attacker-chosen relative to `K_o`; without it, `K_i = K - K_o` lets a signer who knows only `k` satisfy the aggregate.

that bit is optional upstream. `BuildSignedMsg` falls back to `K_o` alone when it is clear (`Input::BuildSignedMsg`), `TxBody::Validate` batch-verifies whatever each input builds and never requires it (`TxBody::Validate`), and `IsStandard` is `m_features < EXTRA_DATA_FEATURE_BIT`, so `features = 0x00` relays (`Input::IsStandard`). litecoin's wallet always sets the bit, its consensus does not. the port's key model is therefore not one litecoin would reject, it is litecoin's unset-bit branch, and the port signs strictly more under it: the commitment and the output pubkey are in the message where upstream's are not.

what carries it is the value balance, which runs everywhere `Transaction::Validate` runs. an input contributes the spent output's commitment `v*H + b*G`, and absorbing `b*G` into a kernel excess requires `b`. an attacker who does not know the blind cannot make the body balance whatever key the input declares, so the transaction dies at relay on the sum rather than on the key. a spender who does know the blind can declare a mismatched key, pass relay and fail at connect, which costs them a transaction and gains them nothing.

so the aggregation is not needed here, on two independent grounds: upstream consensus accepts the unset-bit key, and knowledge of the blind is required before the key question arises. the second is what the port would rest on if upstream ever made the bit mandatory, and it is the one to attack first.

what is dropped with it: litecoin's `K_i` is fresh randomness the spender feeds into the stealth balance. the port parses the field and would commit it under the input signature if the bit were set, but nothing verifies against it and the wallet never sets it (`TxBuilder::Build` passes a null `PublicKey`), so it is absent from both the message and the key.

## output signatures

litecoin outputs carry a signature by the sender's ephemeral key over the commitment, sender pubkey, receiver pubkey, output message hash and rangeproof hash (`Output::BuildSignedMsg`), batch-verified in consensus (`TxBody::Validate`), and the rangeproof commits to the serialized output message as extra data (`Output::BuildProofData`).

the port signs the same fields: `Output::GetSignatureMessage` hashes the commitment, both keys, the output message and the rangeproof hash (`Output::GetSignatureMessage`), `Stealth::Send` signs it with the ephemeral key whose public key is the output's sender key (`Stealth::Send`), `TxBuilder` signs every output it builds (`TxBuilder::Build`), and consensus rejects an output with no sender key and verifies the signature one at a time rather than in a batch (`ValidateBodyCrypto`). the divergence that remains is the rangeproof: `Bulletproof::Verify` takes only the proof and commitment (`Bulletproof::Verify`) and nothing commits the output message as extra data. the signature covers the message, so the malleation litecoin's extra data defends against is closed by a different route, and the two mechanisms are not interchangeable for anything that verifies proofs without the signature.

## balance equations

value: `sum(outputs) + (fees + pegouts)*H == sum(inputs) + sum(excesses) + pegins*H + kernel_offset*G`, checked as sum-to-zero with `secp256k1_pedersen_verify_tally` (`KernelSumValidator::Validate`). this is litecoin's `KernelSumValidator` identity with the supply change folded into the `H` terms rather than a signed transparent commitment. a block validates the merged body against a single offset which is the scalar sum of its transactions' offsets (`BlockBuilder::CombineOffsets`), matching litecoin's header offset.

stealth: `sum(output sender keys) - sum(input owner keys) - sum(kernel stealth excesses) == stealth_offset*G` (`StealthSumValidator::Validate`), where each input's owner key is the receiver one-time key of the output it spends. litecoin's equation is `sum(K_s) + sum(K_i) == sum(E') + x'*G + sum(K_o)` (litecoin's `StealthSumValidator`). remove the input stealth keys `K_i`, the one key class the port does not use, and litecoin's equation reduces to the port's, so the port's stealth balance is the litecoin balance restricted to the keys that exist here. sender keys remain non-malleable under it: substituting a sender key or the offset requires the original sender's secret to compute the compensating delta.

## error ordering

`ValidateBodyCrypto` checks range proofs, then output sender signatures, then
input owner signatures, then kernel signatures, then the two sums
(`ValidateBodyCrypto`). a body failing more than one rule reports the first in that
order, and splitting the sums into their own headers did not move them: they are
still last, in the same sequence.

`BlockBuilder::AddTransaction` runs only the two sums, with
no signature or range-proof check, because the staged set is re-checked as each
transaction is merged in and the miner has already validated each transaction at
mempool acceptance. a miner staging a body that is both unbalanced and badly
signed therefore sees "Body does not balance (inflation)" where connect-time
validation would have reported the signature failure first. litecoin runs its
sum validators from the same two places, so the divergence is in which rule the
port reaches first at staging, not in which bodies either accepts.

## what this leaves open

output binding was the hole and is now closed. a relaying peer that rewrites an output's receiver key, key-exchange pubkey, view tag or masked value invalidates the sender signature, which consensus verifies, so the transaction is rejected rather than confirmed with the payment destroyed. what the rewrite could never do, then or now, is steal: spending needs the blind and an ecdh secret between keys the relay holds neither of, and substituting the sender key is what the stealth balance prevents.

the value-balance-only carve-outs were consensus, not test scaffolding, and are also closed. an input with no owner key is rejected rather than having its signature skipped, the stealth balance runs on every body rather than only those carrying a stealth key (both in `ValidateBodyCrypto`), and connect rejects a null claimed key instead of matching it against an output created without a receiver key (`CMWEBStateDB::ConnectBlock`). outputs spendable by anyone who knows the blind are no longer accepted by the network, not merely absent from what the wallet creates.

what is left is narrower than the above. the rangeproof carries no extra commit data, so a verifier that checks proofs without checking signatures sees an unbound message; `TxBuilder` derives a sender key by hashing the coin's blind when the caller supplies none, which is deterministic rather than ephemeral and is a stand-in for a wallet-supplied key; and the input stealth key remains parsed, committed and inert, as described above.

the litecoin fix audit re-triages against this model. fixes touching input key aggregation have no port counterpart, which is a different not-applicable than behavioral equivalence and should be recorded as such; fixes touching stealth-excess weighting now do map across. fixes touching output signatures or rangeproof extra data are applicable and unported in full. fixes touching the sum validators map across directly, the equations being litecoin's with `K_i` removed.

## not verified here

the output malleation is no longer asserted from reading alone: `mweb_output_signature_binds_receiver_key` re-addresses a sent output and is rejected, and that test fails on the tree before these commits. the wallet's stealth derivations (`Stealth.h`) were not reviewed against litecoin's addressing scheme. serialization compatibility beyond the feature bits named above was not checked, and these commits change no serialized layout: the signature field was already on the wire, carrying a null signature.
