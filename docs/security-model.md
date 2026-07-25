# Security model

Threshold Monero is unaudited research software. This model states the intended boundaries of the
current clean-state implementation; it is not a security proof or a claim of public-network
readiness. The current source has not demonstrated transaction acceptance on Monero public testnet
or mainnet.

## Protected assets

The primary assets are:

- the distributed Monero private spend key and each epoch's secret share;
- one-use FROSTLASS nonces and signature-share payloads;
- epoch-scoped X25519 private keys, their bootstrap material, and decrypted AVSS evaluations;
- stable Ed25519 party signing seeds and QUIC private keys;
- the common private view key and the privacy information it reveals;
- certified allocation, handoff, scanner, consolidation, and chain state; and
- durable evidence needed to prevent rollback, replay, equivocation, nonce reuse, or competing
  signatures.

## Adversary and timing assumptions

The protocol is designed around an authenticated Byzantine committee with an explicit per-epoch
fault bound `f`. The adversary may corrupt up to that bound, send malformed or conflicting
messages, omit messages, relay out of order, replay old traffic, stop after any phase, and restart a
party from local state. The network may be asynchronous for an unbounded period but must eventually
become timely for liveness.

Safety is not supposed to depend on deadlines. Deadlines move a reducer or ROAST attempt to another
view only when durable evidence says that transition is safe.

The proactive model is mobile across epochs: the adversary may corrupt different parties over time,
but must learn fewer than the active threshold's shares from every one sharing. Retired shares,
nonce material, and receiver keys must be destroyed before later corruptions can recover them.
Software running on rollbackable storage cannot establish that destruction alone.

The implementation does not tolerate Byzantine behavior outside every boundary. In particular,
host kernels, filesystems, secret provisioning, certificate enrollment, wall-clock governance,
external monotonic anchors, and operator authorization remain deployment assumptions.

## Implemented safety boundaries

### Transport and identity

All party-to-party messages use mutually authenticated QUIC with exact certificate-leaf pinning.
The receiver checks the TLS identity, inner sender, recipient, network, operation family, request
identifier, canonical encoding, and bounded size. Portable Ed25519 envelopes authenticate consensus
votes and relayable consolidation contributions end to end.

HTTP is limited to health, operator initiation, and deposit-client reads/requests. It does not
transport signing rounds. Bearer tokens separate those roles but are admission controls, not
transaction policy or multi-person approval.

The stable Ed25519 signing seed and bootstrap X25519 secret are independently provisioned. The
signing seed cannot derive AVSS receiver keys. Except for a certified omission baseline, each
successor receiver secret is generated only when its rotation ceremony begins, durably persisted
and read back before its public key is advertised, and erased after certified cutover. The
configuration contains public bootstrap keys, not private or future epoch receiver secrets.
Configuration rejects leave-then-rejoin membership for the same party identity so a retired
bootstrap receiver key can never become an omission baseline again.

### DKG and proactive refresh

AVSS commitments make an invalid recipient evaluation detectable. Send/echo/ready prevents one
dealer from silently defining incompatible completed outputs for honest receivers. Common QUAL
orders one certified dealer set, and `n-f` activation acknowledgements bind one public epoch before
shares become active.

Every reshare uses fresh AVSS polynomials while preserving the group public key. Model each epoch's
nonconstant coefficients as independent variables and the secret as their one common constant. A
typed set containing strictly fewer than each epoch's threshold observations leaves that constant
undetermined, even across added, removed, or reindexed parties; a set reaching either threshold
reconstructs by design. The private-Regtest acceptance checks this statement by row rank using each
epoch's native FROST coordinates. Epoch, transition, commitment, and activation bindings separately
reject cross-epoch protocol messages. The privacy statement depends on fresh randomness from at
least one honest AVSS dealer per reshare and on securely erasing retired shares before the
adversary moves; deterministic acceptance cannot prove either entropy or physical erasure.

The fixed-interval refresh deadline is authenticated, stored, and restored. Every configured or
dynamic successor first certifies its target receiver-key selection. Target members advertise
fresh, durably read-back X25519 keys; target `n-f` advertisements are required, and at most target
`f` exact omission baselines may be selected. The source committee supplies the source `n-f`
Byzantine certificate, including when the target grows or shrinks. Persistent timers improve
continuity but do not manufacture quorum when too many members are offline.

### Epoch cutover

New shares are staged before activation. The service serializes activation, signing-share access,
deposit handoff, and old-share retirement. A retirement marker is bound to the certified successor,
and startup rechecks activation indexes and certificates. These controls prevent ordinary process
restart from reopening a locally retired epoch.

They do not prevent an operator from replacing the complete state volume with an older, internally
valid copy. Valuable deployments require an external monotonic or WORM anchor and explicit restore
governance.

### Deposits

Deposit allocation, history, permanence, and epoch handoff are certified committee state. Requests
are tenant-bound and idempotent. Indices are monotonic and never reused. An unused address expires
for client use after 30 days. A confirmed output becomes portable only after exact `n-f`
observation attestations and an independent `n-f` authenticated-index checkpoint. The resulting
output, one-time-key, and first-use aliases make the address permanent across restart and committee
handoff.

Before signing an individual observation attestation, each party resolves the exact certified
allocation and reproduces the output against its retained confirmed scanner. A complete `n-f`
certificate is sufficient for a lagging fresh joiner to import the portable fact, but does not by
itself make that output spendable: every consolidation signer still independently checks scanner
state, maturity, reorg handling, fee bounds, input identity, and destination.

### Consolidation signing

Consolidation uses one coordinator-free QUIC path:

- Byzantine agreement commits an exact intent before nonce release.
- Deterministic bounded ROAST views rotate proposers and signer subsets.
- Preprocess, key-image, signature-share, and candidate statements are portable and origin-signed.
- Nonce-session tombstones are persisted and read back before preprocessing is exposed.
- The exact outbound share binding is persisted as exposed before the share can be sent.
- Candidate bytes are independently validated against the certified Monero intent.
- Safe abandonment requires certified share-unexposed evidence plus a durable local fence.
- Evidence that a threshold of shares may exist makes the attempt non-abandonable.

These rules prefer a halted consolidation family over the risk of two signatures or nonce reuse.
They do not make arbitrary operator-supplied transactions eligible; only the certified deposit
sweep policy enters this lane.

## Persistence assumptions

Authenticated encrypted records, atomic replacement, canonical readback, monotonic revisions,
session tombstones, durable outboxes, and content-addressed archive heads protect against local
corruption and crash interruption. Startup verifies security-critical records before accepting
them.

The current binary accepts an empty state directory or its current exact authenticated formats.
State directories created by older builds must remain offline. Start with empty volumes and run DKG
from epoch zero; there is no in-place conversion procedure.

Local persistence does not by itself protect against:

- whole-volume rollback to an earlier valid state;
- copying a live share or view key before erasure;
- simultaneous use of cloned party state;
- malicious backups, hypervisors, kernels, or storage firmware; or
- indefinite growth without an operational retention and archive policy.

## Monero and daemon boundaries

The threshold key controls spending, but every party currently receives the same private view
scalar to scan deposits. A former member that retains it can continue recognizing incoming outputs
and decrypting amount metadata. Threshold scanning and view-key rotation are not implemented.

Party startup does not wait for `monerod`: identity/state restore, authenticated QUIC, DKG, QUAL,
key rotation, and proactive refresh remain live while chain RPC is absent. Each party has a
nonempty, bounded, globally unique endpoint set. Deposit operations connect lazily, verify network
plus genesis, discard a failed client, and rotate to the next endpoint on a later bounded worker
tick.

Chain observations become authority only through the existing party consensus predicates. Every
honest party reconstructs a proposed consolidation against its durable scanner and independently
re-queries its own daemon before admitting the value; `n-f` Byzantine agreement gates nonce
release. Canonical-inclusion, late-settlement, and abandonment values are likewise reproduced
against the local scanner before certification. Allocation itself has no chain premise. First-use
and output facts use a separate scanner-gated `n-f` observation certificate followed by an `n-f`
portable-index checkpoint; the statement binds the exact allocation, output identity, one-time
key, amount, block, confirmation horizon, depth, and active issuer. A highest-height claim from one
daemon therefore cannot authorize permanence or spending. This mechanism still assumes no more
than `f` faulty/eclipsed application validators and eventual convergence on one finalized Monero
chain.

The fault budget applies to the combined signer/observer domain: in any committee, at most `f`
identities may be Byzantine or have faulty/eclipsed chain observation. A Byzantine party and a
separately compromised honest party's daemon count as two faulty application validators. Honest
observers must eventually converge on the same finalized Monero chain for liveness. The Compose
laboratory gives every party a separate daemon process, volume, address, and RPC bridge, but all
seven follow one private-Regtest block producer; that producer is an explicit test-only common
mode, not a production trust model.

Deposits use Monero subaddresses and consolidation returns funds to the primary address. Some
Monero APIs call the primary address type a **legacy address**. That term describes the Monero
address format only; it does not mean old Threshold Monero state is accepted.

Auditable reserves remain TODO. A least-privilege auditor design should let viewing material
discover incoming outputs and verify balances without exposing the spend key, while clearly
documenting spent-output/key-image visibility and authenticating the chain height against which a
reserve statement is made.

## Availability limits

Liveness requires eventual synchrony, enough honest online parties for the applicable certificate,
available Monero chain data, and storage below configured bounds. A valid safety fence, unresolved
share exposure, missing handoff, conflicting daemon evidence, exhausted view budget, or tampered
record intentionally stops progress.

The seven-container Compose stack is a single-host laboratory. Its parties do not provide
independent administrative domains, secret custody, power, storage, clocks, or network paths.
Passing it demonstrates interoperability of that exact build on a private chain, not production
Byzantine tolerance.

## Required production work

Before valuable use, at minimum:

- obtain independent cryptographic and implementation audits;
- retain fresh adversarial and crash/restart evidence for the exact release build;
- establish acceptance on public testnet before considering any mainnet enablement;
- distribute operators, daemons, storage, clocks, and network paths across trust domains;
- add certificate enrollment, rotation, revocation, and hardware-backed key custody;
- anchor epochs, tombstones, and archive heads outside rollbackable party volumes;
- define verified erasure and disaster-recovery procedures;
- add independent transaction policy and human/business authorization;
- design private, Byzantine-aware scanning and reserve auditing; and
- monitor quorum health, refresh deadlines, scanner agreement, ROAST views, storage capacity, and
  failed-closed state continuously.
