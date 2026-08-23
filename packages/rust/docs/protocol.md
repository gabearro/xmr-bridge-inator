# Protocol architecture

This document describes the current clean-state protocol. Threshold Monero is experimental,
unaudited research software. Private Regtest is the sole release-acceptance target. Public
testnet/mainnet deployment and evidence are outside scope, and mainnet party mode is disabled.

## One persistent party

Every party runs the same long-lived state machine. A party owns:

- one stable Ed25519 signing seed and identity used to authenticate protocol statements;
- one exact-leaf-pinned mTLS QUIC endpoint for party-to-party traffic;
- an independently generated, epoch-scoped X25519 secret used to receive encrypted AVSS
  evaluations;
- zero or one active threshold spend-key share;
- durable AVSS, common-QUAL, activation, rotation, deposit, scanner, consensus, ROAST, nonce,
  outbox, and archive records; and
- a narrow HTTP listener for health, operator initiation, and deposit-client queries.

The runtime restores authenticated state, verifies it before use, drains durable outboxes, advances
expired consensus views, scans Monero, starts due refreshes, and retries eligible work until the
process is stopped. A completed one-shot acceptance client does not stop the party network.

## Configuration and identities

The scenario fixes the Monero network, stable party signing identities, one public genesis
bootstrap X25519 key per party, configured committee shapes and eligible successor rosters,
Byzantine fault bounds, refresh interval, deposit birth checkpoint, fee ceiling, and QUIC trust
roots. The signing seed and bootstrap X25519 secret are independent inputs: the stable seed derives
only Ed25519, never a receiver key. Each message is checked against locally reconstructed
configuration. Peer-supplied context is never accepted as a replacement for local trusted context.

QUIC authenticates both endpoints. Inner Ed25519 envelopes provide portable origin attribution for
consensus votes and consolidation contributions that may be relayed by another party. Canonical
bounded Postcard encoding, domain separation, operation families, sender/recipient checks, request
IDs, and replay indexes make cross-phase or cross-network reuse fail closed.

HTTP never carries AVSS, QUAL, activation, key rotation, deposit consensus, or Monero signing
rounds. Its supported public roles are:

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | Listener reachability only. |
| `GET /v1/status` | admin | Read local epoch, core readiness, and separate deposit-chain readiness. |
| `POST /v1/avss/start` | admin | Authorize an eligible local dealer to enter the configured transition. |
| `POST /v1/deposits/allocate` | deposits | Request or poll a tenant-bound certified deposit address. |
| `POST /v1/deposits/status` | deposits | Read allocation, expiry, observation, and permanence state. |
| `POST /v1/deposits/consolidations/status` | deposits | Read certified consolidation and chain status. |

Bearer admission does not authorize arbitrary spending. Consolidation eligibility is reconstructed
from certified wallet state and fixed local policy.

## DKG, resharing, and activation

### Epoch-zero DKG

Epoch zero is a distributed key generation. Its committee uses the configured bootstrap X25519
public keys. Every configured dealer samples a fresh bivariate polynomial, commits to it, encrypts
the receiver-specific evaluation to that receiver's X25519 key, and enters the AVSS
send/echo/ready machine. Recipients verify evaluations against the Feldman commitment. A partially
synchronous common-QUAL reducer chooses one certified dealer set, so honest parties aggregate the
same outputs into one threshold polynomial and public spend key.

No dealer chooses or learns the final secret. The final constant is the sum of qualified dealer
constants and each party learns only its own evaluation.

### Proactive resharing

Every later epoch uses distributed AVSS and common QUAL. For committee growth or shrink, eligible
old parties act as dealers: dealer `i` samples a fresh target-degree polynomial whose constant is
its old share, and the selected outputs are combined with old-polynomial Lagrange weights. For a
same-membership, same-threshold refresh, every dealer instead contributes a fresh full-degree
zero-constant polynomial; QUAL selects exactly `n-f` contributions and each receiver adds them to
its existing share. Both constructions produce a fresh polynomial with the original spend secret
as its constant.

This is DKG-like distributed generation of the new sharing: it uses independent AVSS instances and
common QUAL, and no single dealer can choose or reconstruct the result. It is not another
epoch-zero key generation because the constant is constrained to the existing distributed key.

The new verification-share polynomial must differ from the predecessor while the group public key
and key identifier remain unchanged. Messages, commitments, shares, certificates, and signing
sessions are bound to their exact epoch and transition. Evaluations from two refresh epochs are
points on different polynomials, and the protocol never accepts a mixed-epoch set for signing or
interpolation. Under independently randomized refresh polynomials, a collection containing fewer
than the threshold number of evaluations from each epoch does not determine the common constant;
interpolating mixed points as though they shared one polynomial matches it only with negligible
collision probability. Any threshold subset from one epoch reconstructs it by design. Proactive
security additionally assumes fewer than the threshold shares are exposed in every epoch and that
retired secret material cannot be recovered after erasure.

### Persistent fixed-interval refresh

Activation arms an authenticated deadline derived from the scenario's fixed refresh interval. The
deadline is stored with the active epoch and survives restart. When it becomes due, eligible
dealers autonomously begin the immediate successor transition; no client needs to keep scheduling
refreshes.

Because every successful refresh permanently commits a fresh receiver-key generation, ordinary
deployments enforce a minimum interval of one hour. Shorter intervals are accepted only when both
`demo_only` and private Regtest are selected, which keeps accelerated lifecycle tests available
without permitting an accidental unbounded production storage rate.

Every configured successor first runs receiver-key rotation, including committee growth, shrink,
and fixed-size/fixed-threshold refresh-or-reshare. The trusted scenario supplies the target
threshold and `desired_n` through `members`, plus a canonical `eligible_members` authentication
roster containing at least `desired_n + f_target` stable identities. Governance asserts that at
most `f_target` identities in the whole eligible roster are Byzantine; applying the bound only
after selection would not make arbitrary eligible substitution safe. If the certificate selects
the same identities, the successor uses the true zero-constant refresh branch described above;
eligible substitution uses resharing. The scenario does not precompute any successor receiver
secret. Bootstrap X25519 material is authoritative only for epoch zero.

When a ceremony begins, every responsive eligible identity independently generates its successor
X25519 secret, persists it, reads back the authenticated record, and only then signs an
advertisement. Eligible identities outside the source committee send their advertisements to the
source committee even though they cannot vote in that source epoch. The source committee uses a
source `n-f` Byzantine certificate to choose a set containing exactly `desired_n` advertisements.
Ordinarily a value must retain the maximum possible source overlap `P`. Only after the persisted
policy window expires may source parties sign a view-independent fallback statement; an exact
canonical `n_source-f_source` bundle permits the verifier-computed lower overlap `R`, while values
below `R`, early/partial bundles, and gratuitous bundles at `P` are invalid. The fallback deadline
and signed-vote outbox survive restart. Peer ingress stores votes but cannot make the local party
sign one.

The successor committee is constructed solely from those fresh advertised keys; an omitted
candidate is erased and receives no successor share. The policy cumulatively binds all configured
bootstrap and previously certified receiver keys, so none can be advertised again. A target-only
selected member can ingest and verify the certificate, including any fallback bundle, and join the
subsequent AVSS without source voting authority.

The certified public selection is the sole input to successor AVSS. Every selected party must load
the exact persisted fresh secret. Superseded private receiver keys are erased after certified
cutover, so a stable seed or static scenario file cannot reconstruct historical or future epoch
receiver secrets. A party that left or was omitted may be re-admitted under the same stable
identity in a later epoch only if it is eligible, generates and advertises another fresh key, and
is included in that epoch's exact certified selection.

After the configured chain ends, parties construct a same-threshold policy dynamically. All stable
scenario identities form its eligible roster, while `desired_n` remains the active committee size.
The same fresh-advertisement selection permits a responsive eligible identity to replace an omitted
member without carrying any receiver key between epochs.

After the successor activates, its own interval is armed. Thus a live network continues producing
fresh epochs until explicitly stopped or until it fails closed on missing quorum, corrupt state,
capacity limits, or exhausted counters.

### Common QUAL and activation

AVSS completion alone does not select the sharing. Parties propose certified dealer entries to a
bounded, rotating-view Byzantine reducer. Signed votes, timers, locks, decisions, and outbound
effects are persisted. Once the complete honest-leader proposal, admission, vote, delivery,
reducer, and durable-storage pipeline finishes before the deadline capped at
`64 * protocol_timeout_seconds`, a silent proposer can be bypassed by a later view.

The selected share is staged first. It becomes active only after `n-f` matching activation
acknowledgements bind the transition, transcript, public epoch, and activation digest. Cutover
leases prevent signing and share retirement from crossing an unresolved epoch boundary. Ordinarily
the old share remains until successor-bound signing obligations and the old deposit registry are
durably closed. Under the deposit-genesis publication fence, authenticated absence of any local
deposit snapshot may instead authorize immediate retirement; this prevents a never-initialized
deposit service from pinning obsolete threshold and X25519 material indefinitely.

That absence decision does not assume a delayed canonical deposit genesis can never appear. If one
does appear after retirement, the stable Ed25519 seed may derive a non-serializable
`RecoveryAndFenceOnly` capability bound to the exact certified transition, source committee, target
committee, activation, registry root, and fault bound. Its durable reducer policy permits only exact
quorum-backed pre-pin ledger recovery, independently certified ledger or observation checkpoints,
and the host-validated `HandoffFence`. It cannot originate a client request, raw observation,
consolidation, state export, or final `Handoff`. Installing the exact portable Fence revokes this
recovery authority; a separate committee-bound `HandoffOnly` capability may then attest only the
final Handoff. Neither stable capability reconstructs an erased threshold share or X25519 secret.

## Deposit ledger

A client submits an idempotent request bound to its authenticated tenant. Parties order the request
in the deposit consensus lane and return the same certified subaddress once committed. Allocation
indices are monotonic and are never reused.

An unused allocation remains available to its client for 30 days. Expiry does not recycle the
index. A matching confirmed output is proposed in a separate bounded observation lane. Individual
proposal and attestation messages are admitted only after the receiving party resolves the exact
certified allocation and reproduces the fact from its retained scanner. Exactly `n-f`
attestations certify the observation, and a second `n-f` checkpoint round atomically installs the
output, one-time-key binding, and permanent first-use record in the portable authenticated index.
Certified ledger/observation archive history and epoch handoff let a newly active committee recover
the mixed tip before it issues or consolidates anything.

An uncertified observation is rebound to the successor committee after handoff with all old-issuer
witnesses discarded, so attestations from different epochs cannot be combined. A fresh joiner can
import a ledger tip whose latest archive operation is an observation; pending observations are
consumed only when the imported portable record is the same semantic output fact, and otherwise
survive only when their exact allocation was imported.

That portable deposit-state import does not yet transfer authenticated ROAST archive history and
abandoned-family watch state. The current stable scope therefore requires at least one retained
old-committee member for ROAST late settlement across handoff. Fully disjoint successor support is
tracked in [TODO.md](../TODO.md).

Every party scans from the configured wallet birth checkpoint with the common private view scalar.
Scanner state handles confirmation depth, maturity, reorg rollback, exact output identity, and a
certified sweep high-water mark. A party whose local scanner cannot validate a proposed input set
does not sign it.

Deposit addresses are standard Monero subaddresses. Consolidation sends to the wallet's primary
address. Monero libraries may label that primary address type a **legacy address**; that is Monero
address-format terminology and does not denote support for old Threshold Monero state or protocols.

## BFT consolidation and FROSTLASS

There is one consolidation signing path. It runs over authenticated QUIC and has no distinguished
long-lived coordinator.

1. Parties independently derive an eligible sweep from certified allocation history, scanner
   state, confirmation/maturity policy, fee policy, and the primary-wallet destination.
2. Deposit consensus certifies one exact `ConsolidationIntent`, including the authorization,
   inputs, signing epoch, signer subset, Monero context, and ROAST slot, before any signing nonce is
   released.
3. A deterministic bounded ROAST plan rotates views and signer subsets. Any party can relay a
   portable origin-signed contribution; observing it no longer depends on one relay party.
4. Selected signers persist and read back a one-use session tombstone before revealing FROSTLASS
   preprocessing. The exact preprocessing set determines the proof-verified key-image material.
5. Key-image attestations are certified before a signer consumes the set. A signer persists and
   reads back `ShareExposed` with the exact payload binding before transmitting its signature share.
6. Parties independently assemble and validate candidate transaction bytes against the certified
   intent and Monero `Eventuality`. Byte-identical terminal attestations select the signed result.
7. Broadcast and confirmation state are tied to the exact transaction bytes and chain point.

Monero signing is transaction-specific. FROSTLASS supplies threshold key-image construction,
pseudo-output mask coordination, and one CLSAG per input. Ordinary Schnorr-message FROST is not a
substitute.

### Safe view change

A stalled view can be superseded only if doing so cannot create two signatures from reused nonce
material. Before any share exposure, parties may persist an abandonment fence and certify an exact
`ShareUnexposed` witness set. The certificate is checked against the selected signer set and fault
bound, including the possibility that Byzantine witnesses lie.

Once a local signature share may have escaped, state moves monotonically to `ShareExposed` or
threshold-exposed. Such a view is not treated as safely unused. If the protocol cannot obtain the
evidence needed to finish or to prove safe abandonment, it stops that family rather than risk a
competing attempt.

## Persistence and clean start

Secret-bearing records are authenticated and encrypted. Security-critical updates use atomic
replacement, readback capabilities, monotonic revisions, session tombstones, exact transition
indexes, and durable outboxes. Restart revalidates the active epoch, activation certificates,
refresh schedule, deposit registry, scanner state, attempt safety, and ROAST state before work
resumes.

The binary accepts only its current on-disk formats or an empty state directory. Do not point it at
volumes written by an older build. Keep such volumes offline for forensic analysis, create empty
volumes, and run epoch-zero DKG again. There is no in-place conversion procedure.

Authenticated local storage does not prevent a valid whole-volume rollback. A valuable deployment
needs an external monotonic or WORM anchor, controlled backup/restore governance, independent host
custody, and verified erasure of retired shares and encryption keys.

## Known boundaries

- The code and protocol have not been independently audited.
- Public-testnet and mainnet operation is outside this implementation's acceptance scope; the
  current source makes no public-network acceptance claim.
- Parties share one private view key. Each party has a distinct daemon route, but the combined
  signer/observer fault budget remains an important Byzantine-trust boundary.
- QUIC demo certificates, signing seeds, bootstrap X25519 secrets, bearer tokens, and view
  material are public fixtures.
- Liveness assumes the complete post-stabilization honest-leader proposal, admission, vote,
  delivery, reducer, and durable-storage pipeline finishes before the deadline capped at
  `64 * protocol_timeout_seconds`; safety must not depend on timeouts.
- Resource bounds can deliberately halt progress rather than permit unbounded state growth.
- Proactive security requires non-recoverable retirement, which software on a rollbackable host
  cannot prove by itself.
- Auditable reserves are not implemented. A future viewing-key auditor flow must document incoming
  output discovery, spent-output/key-image visibility, and authenticate the reported chain height
  without exposing the spend key.
