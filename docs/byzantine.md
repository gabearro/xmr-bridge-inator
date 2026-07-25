# Byzantine design and remaining risk

This document separates implemented Byzantine mechanisms from evidence still required. Threshold
Monero is unaudited research software. Neither this design nor a private-Regtest run establishes
public-testnet or mainnet readiness.

## Committee model

Each epoch commits an explicit committee of `n` parties, threshold `k`, and fault bound `f`. The
implementation requires:

```text
n >= 3f + 1
f < k <= n - 2f
consensus quorum = n - f
```

The adversary may control up to `f` committee identities, equivocate, omit, delay, replay, reorder,
or corrupt messages, stop at an adversarial phase, and restart from locally durable state. QUIC
provides authenticated channels, not honest behavior. Portable Ed25519 signatures make relayed
votes and contributions attributable.

Partial synchrony is required for liveness. Safety should hold during arbitrary delay; timeout only
changes which deterministic view is attempted.

## Safety invariants

The state machine is organized around these invariants:

1. One transition and one certified public epoch bind every active secret share.
2. Honest parties activate only an `n-f`-acknowledged result of one common-QUAL decision.
3. A successor preserves the Monero public spend key but uses a different share polynomial.
4. Epoch-tagged shares and commitments from different polynomials never form a valid signing or
   interpolation set.
5. No FROSTLASS nonce is released before an exact consolidation intent is certified.
6. A signature share cannot leave before its exact payload binding is durably marked exposed.
7. A possibly exposed attempt cannot be declared unused without a safe, certified abandonment
   proof; threshold-exposed evidence is never abandonable.
8. Candidate transaction bytes must satisfy the certified Monero intent independently at every
   accepting party.
9. Epoch retirement, deposit handoff, and signing closure are serialized and survive restart.
10. Peer protocol traffic uses authenticated QUIC; HTTP input cannot impersonate a peer round.

## Implemented mechanisms

| Area | Mechanism | Boundary |
| --- | --- | --- |
| AVSS | Bivariate Feldman commitments; encrypted recipient evaluations; signed send, echo, and ready; bounded canonical messages | Feldman commitments do not hide public coefficient commitments; host compromise still reveals local secrets. |
| Common QUAL | Rotating-view, partially synchronous Byzantine reducer with signed proposals/votes, locks, view-change proof, durable timers, decisions, and outboxes | This is a purpose-built reducer, not a general asynchronous common subset implementation. |
| DKG and reshare | Common dealer selection; distributed aggregation; immediate-successor epoch binding; unchanged group key on reshare | Proactive secrecy requires fewer than `k` exposed shares in every epoch and real erasure. |
| Activation | `n-f` matching acknowledgements and exact transition indexes; staged-before-active cutover | Competing external deployment roots require governance outside the process. |
| Receiver-key rotation | Target members durably persist and sign fresh X25519 advertisements; target `n-f` advertisements are selected by a source `n-f` BFT certificate | At most target `f` exact omission baselines can be used temporarily; full mobile-adversary hygiene prefers rotation by all members. |
| Refresh timer | Authenticated fixed-interval schedule restored on startup; configured then dynamic same-committee successors | An offline quorum or exhausted resource bound stops progress. |
| Deposits | BFT allocation, scanner-gated output observations, exact `n-f` observation certificates, independent `n-f` portable-index checkpoints, compact registry handoff, monotonic indices, and per-party daemon routes | Shared viewing material remains broad; a signer and its observer share one application-validation fault domain, and honest observers must converge on one finalized chain. |
| Consolidation | Pre-nonce BFT intent, coordinator-free all-to-all ROAST, portable origin signatures, deterministic bounded view/subset rotation | Intent eligibility still depends on the correctness of local scanner and Monero policy code. |
| Nonce/share safety | One-use tombstones; readback-gated nonce and share release; monotonic exposure state; certified safe abandonment | Whole-volume rollback can erase all local evidence unless externally anchored. |
| Terminal selection | Independent FROSTLASS and `Eventuality` validation; local scanner/daemon reproduction before n-f certificates; byte-identical signed candidate attestations; exact broadcast/confirmation binding | Honest observers must converge on one finalized Monero chain; public-network censorship and eclipse resistance remain deployment concerns. |
| Persistence | Authenticated encrypted records, atomic replacement, durable outboxes, bounded journals, content-addressed archive heads | Valid complete-volume rollback, cloning, backup leakage, and indefinite retention are operational problems. |

## Byzantine AVSS and epoch changes

A dealer can send an invalid evaluation, withhold it, or send different ciphertexts. Recipients
validate against one commitment matrix and use reliable-broadcast thresholds so an honest
completion is tied to one dealer output. Common QUAL considers only locally completed entries and
decides a canonical dealer set with an `n-f` certificate.

For epoch zero, qualified dealers contribute independent constants. For growth or shrink,
qualified old dealers contribute fresh polynomials whose constants are their old shares; Lagrange
weighting of the selected old dealers preserves the distributed secret. A same-committee refresh
instead selects exactly `n-f` independently verified zero-constant polynomials and adds them to the
existing sharing. Both paths use distributed AVSS and common QUAL rather than trusting one refresh
dealer.

Mixed-age collection does not produce the spend key. If an adversary learns fewer than `k`
evaluations of every epoch polynomial, pooling those evaluations leaves independent unknown
nonconstant coefficients for each epoch. Protocol verification also rejects an epoch/commitment
mismatch. If old shares remain recoverable after retirement, however, the mobile-adversary premise
is false and cumulative compromise may reach `k` shares of one old polynomial.

Membership can grow or shrink only through the immediate successor bound to the trusted active
epoch. Before any configured or dynamic successor AVSS, responsive target members generate,
persist, read back, and advertise fresh receiver keys. Joining members advertise to the source
committee; the source's `n-f` certificate must contain target `n-f` advertisements, with no more
than target `f` exact policy baselines for omissions. New members do not activate merely because
they advertised a key or received AVSS outputs; target `n-f` members must acknowledge the same
activation digest. Old members retain obligations until certified handoff and attempt closure make
retirement safe.

## Byzantine deposit state

Allocation, history, permanence, and handoff use the same family of rotating-view BFT consensus.
An allocation proposal commits the tenant binding, request identifier, subaddress index, address,
times, wallet, epoch, registry, and predecessor state. A party recomputes the value before voting.
One hostile proposer can consume time and bounded proposal space, but cannot alone certify a
conflicting address.

The scanner accepts only contiguous chain progress from its configured birth checkpoint. Reorg
handling removes observations above the common ancestor and invalidates affected sweep planning.
Input maturity, confirmation depth, exact output identity, already-spent state, destination, and
fee ceiling are checked locally before an intent can receive an honest vote.

An unused client allocation expires after 30 days and its index remains retired. Observation makes
the address permanent. New committees replay certified history before enabling issuance or
consolidation, so a member joining after resharing does not depend on one peer's unsigned local
record.

## Byzantine consolidation

Consolidation has no privileged long-lived relay. A deterministic slot names the BFT context and
rotates its proposer by view. After one exact intent commits, a bounded ROAST plan rotates signing
views and subsets. Every participant receives origin-signed preprocess, key-image, share, candidate,
and terminal evidence over QUIC and revalidates it against local certified state.

Byzantine behavior is handled as follows:

| Behavior | Response |
| --- | --- |
| Proposer omits or equivocates before intent commit | Signed vote rules prevent two honest commits; persisted timeout and view change select another proposer after synchrony. |
| Selected signer omits preprocessing | A later deterministic ROAST view may use another eligible subset without reusing the abandoned session. |
| Peer forges or relays another origin's contribution | Inner Ed25519 verification, sender binding, and replay/equivocation indexes reject it. |
| Peer proposes different key-image or signing context | Exact contribution-set and proof-verified key-image bindings fail validation. |
| Signer stops before its share can escape | Durable share-unexposed fencing plus an `n-f` certificate may authorize safe abandonment. |
| Signer stops after a share may escape | The attempt remains exposed and fails closed unless sufficient authentic contributions finish the same candidate. |
| Peer proposes different transaction bytes | Local Monero intent and `Eventuality` validation rejects them; terminal selection requires byte identity. |
| Party restarts during a round | Authenticated ROAST, consensus, nonce, exposure, outbox, and terminal state are restored and rechecked. |

The conservative exposed-share rule can sacrifice liveness. That is intentional: completing no
transaction is safer than signing two competing candidates with related nonce state.

## Faults beyond the configured bound

When more than `f` identities equivocate, quorum-intersection assumptions no longer apply. When too
many parties omit, the network cannot form `n-f` certificates. The code detects conflicting quorum
evidence where possible, rejects malformed state, and otherwise stops. It does not claim useful
safety or liveness after the committee assumption is violated.

Network authentication also does not prevent resource exhaustion by an enrolled Byzantine peer.
Message sizes, committees, live sessions, attempts, views, histories, and archives have hard bounds;
exceeding them fails closed. Production deployments still need connection, CPU, disk, and per-peer
rate controls.

## Persistence and rollback

Ordinary crash/restart is in scope. Atomic records and outboxes close the window where a security
decision changes but its network effects disappear. Nonce and share-release capabilities require
exact durable readback before sensitive bytes are exposed.

Complete-volume rollback is outside that guarantee. A valid older volume may omit a tombstone,
exposure marker, epoch, or certified head. An external monotonic/WORM record must bind at least the
active epoch, activation digest, nonce/exposure high-water state, registry head, and archive head.
Cloned volumes must never run as the same party identity.

The current executable requires empty state or the exact current state format. Older volumes must
be kept offline and a new deployment must start from epoch-zero DKG.

## Evidence and remaining work

The repository contains unit, integration, QUIC liveness, private-Regtest, restart, omission, and
consolidation fault campaigns. Their presence is not a passing result. A candidate build is green
only after a fresh clean-state run records the exact source/image digests, terminal markers, party
logs, daemon-accepted transaction bytes, and post-restart state checks.

Important work outside the completed protocol lane remains:

- run and retain the full current-source campaign after every security-relevant change;
- expand schedule variance, fuzzing, malformed-wire, disk-fault, reorg, and long-duration tests;
- obtain independent review of AVSS, common QUAL, abandonment math, and FROSTLASS integration;
- anchor state externally and define secure erasure, backup, restore, and clone-prevention policy;
- deploy independently administered and independently peered Monero observers within the combined
  signer/observer fault budget;
- reduce common private-view-key exposure and design auditable reserve reporting;
- add production certificate lifecycle, rate limiting, monitoring, and operator authorization; and
- demonstrate real accepted transactions on public testnet before any mainnet work.

Mainnet mode should remain disabled until those gates are deliberately reviewed and satisfied.
