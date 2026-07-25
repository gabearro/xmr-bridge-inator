# Threshold Monero patches

This directory vendors
[`monero-oxide`](https://github.com/monero-oxide/monero-oxide) at commit
`946ec5f00ff071b129758ee8cba5528539fccfe4`.

Local changes are intentionally narrow:

- `monero-oxide/wallet/src/send/multisig.rs` and its export in `send/mod.rs` add a typed
  transaction-binding phase between FROSTLASS preprocessing and signature-share production. It
  fixes the exact aggregate key images (retained in original prepared-input order) and unsigned
  Monero transaction before the application authorizes release of a share.
- The same file extends every per-input round-one preprocess with a standalone Chaum-Pedersen
  proof that the published key-image share `xH` and the DKG verification share `xG` have the same
  discrete logarithm. Each proof uses an independent fresh nonce and is bound to a caller-supplied
  application context, participant, original input index, exact `OutputWithDecoys` serialization
  (including its ring), and the complete proof statement. Points must be canonical and
  torsion-free and the response scalar must be canonical. The typed binding API verifies every
  local and peer proof before aggregating any key image, and the private share-production path
  revalidates them before signing. The generic `TransactionSignMachine::sign` trait entry point
  deliberately fails closed; only `TransactionBoundSignMachine::release_signature_share` can
  invoke the private signing body after the exact transaction has been bound.
- `SignableTransaction::multisig_with_context` supplies that application binding. Threshold
  Monero passes its session-bound `SigningContext`, which already commits to the committee, signer
  set, wallet group key, session, and complete signable transaction. The upstream zero-context
  `multisig` compatibility entry point is intentionally removed; current code must provide an
  application context explicitly, and `multisig_with_context` rejects the all-zero sentinel.
- A successful bound machine exposes a domain-separated digest of the canonical full
  proof-bearing preprocess set, ordered by participant and including the proof context. The root
  adapter wraps the verified key images, unsigned transaction, context, and digest in the
  constructor-private `ProofVerifiedKeyImagePreview` receipt before any share may be released.

`THRESHOLD_MONERO_SOURCES.sha256` pins the vendored workspace manifests, the CLSAG/FROSTLASS
implementation, its local integration test, and the formalization artifacts. Run
`./verify-threshold-monero-sources.sh` from this directory after checkout and before building.

Keep this provenance file, hash manifest, verifier, and focused signing tests when rebasing the
vendored source. A deliberate rebase must update the upstream commit above and regenerate the
manifest in the same reviewed change.
