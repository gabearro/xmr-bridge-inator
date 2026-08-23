# Byzantine design and remaining risk

This document separates implemented Byzantine mechanisms from evidence still required. Threshold
Monero is unaudited research software. Neither this design nor a private-Regtest run establishes
public-testnet or mainnet readiness.

## Committee model

Each epoch commits an explicit committee of `n` parties, threshold `k`, and fault bound `f`. The
implementation requires:

```text
n >= 3f + 1
2f < k <= n - 2f
consensus quorum = n - f
```

The strict `k > 2f` signing bound is checked when the scenario loads. It leaves enough honest
evidence to prove a selected attempt share-unexposed and move to another ROAST subset despite up to
`f` Byzantine witnesses and `f` selected omissions. A `k <= 2f` committee can retain threshold
cryptographic safety yet lose the liveness needed for certified safe abandonment, so configuration
rejects it rather than discovering that deadlock after nonce work begins.

The adversary may control up to `f` committee identities, equivocate, omit, delay, replay, reorder,
or corrupt messages, stop at an adversarial phase, and restart from locally durable state. QUIC
provides authenticated channels, not honest behavior. Portable Ed25519 signatures make relayed
votes and contributions attributable.

The bounded partial-synchrony assumption requires a complete post-stabilization honest-leader
view—including proposal admission, every required delivery, durable prevote/precommit processing,
and reducer/storage work—to finish before the deadline capped at
`64 * protocol_timeout_seconds`. Safety should hold during arbitrary delay; timeouts only change
which deterministic view is attempted. The implementation does not claim liveness when that
pipeline exceeds the configured ceiling.

## Safety invariants

The state machine is organized around these invariants:

1. One transition and one certified public epoch bind every active secret share.
2. Honest parties activate only an `n-f`-acknowledged result of one common-QUAL decision.
3. A successor preserves the Monero public spend key but uses a different share polynomial.
4. Protocol verification accepts shares and commitments only for one exact epoch polynomial; no
   protocol path treats mixed-epoch points as a valid signing or interpolation set.
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
| Receiver-key rotation | An eligible roster of at least `desired_n + f_target` stable identities durably persists and signs fresh X25519 advertisements; maximum source overlap is mandatory until an exact source `n-f_source` deadline authorization permits bounded fallback; an exact `desired_n` successor made solely from those advertisements is selected by source BFT | Governance must bound Byzantine identities across the whole eligible roster, not only the selected subset; omitted identities receive no successor share; secure erasure remains operational. |
| Refresh timer | Authenticated fixed-interval schedule restored on startup; configured then dynamic fixed-size/fixed-threshold successors with eligible-member substitution | An offline quorum or exhausted resource bound stops progress. |
| Deposits | BFT allocation, scanner-gated output observations, exact `n-f` observation certificates, independent `n-f` portable-index checkpoints, compact registry handoff, monotonic indices, and per-party daemon routes | Shared viewing material remains broad; a signer and its observer share one application-validation fault domain, and honest observers must converge on one finalized chain. |
| Consolidation | Pre-nonce BFT intent, coordinator-free all-to-all ROAST, portable origin signatures, deterministic bounded view/subset rotation | Intent eligibility still depends on the correctness of local scanner and Monero policy code. ROAST late settlement across committee handoff currently requires at least one retained old-committee member; authenticated transfer to a fully disjoint successor remains [TODO](../TODO.md). |
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
epoch. A fixed-size/fixed-threshold successor is a true zero-constant refresh only when the
certificate selects the same identities; eligible substitution instead invokes the reshare branch.
Before any configured or dynamic successor AVSS, responsive eligible identities generate,
persist, read back, and advertise fresh receiver keys. The eligibility roster contains at least
`desired_n + f` stable identities; identities outside the source committee advertise to that
committee, whose `n-f` certificate selects exactly `desired_n` advertisements. The successor is
formed solely from those fresh keys. The target bound is assumed over the whole eligible roster.
Before the immutable fallback deadline, verifiers require maximum source retention. After it,
exactly `n_source-f_source` context-bound source votes may relax retention only to the
fault-derived floor; the local scheduler, never message ingress, creates each party's vote.
Omitted identities receive no share and no bootstrap or source receiver key is carried forward. A
previously omitted or departed party may re-enter a later committee under the same stable identity
only by advertising another fresh key and being selected. New members do not activate merely
because they advertised a key or received AVSS outputs; target `n-f` members must acknowledge the
same activation digest. Old members ordinarily retain obligations until certified handoff and
attempt closure make retirement safe. An authenticated snapshot-absence decision under the
deposit-genesis publication fence is the narrow exception: it permits threshold-share and X25519
retirement without letting a never-initialized deposit service pin obsolete secret material.

If canonical source-epoch deposit genesis is published after that absence decision, the retired
party derives only a transition-bound `RecoveryAndFenceOnly` Ed25519 capability. The authority
digest commits the network, wallet, exact source and target committees and keys, activation,
registry root, and fault bound; the durable reducer independently stores the same digest. This
capability may vote only for exact quorum-backed pre-pin ledger recovery, independently certified
ledger or observation checkpoints, and the validated `HandoffFence`. It cannot create raw
observations, allocations, consolidation work, state exports, or the final `Handoff`. Once the
portable Fence is installed, the recovery authority disappears and a distinct committee-bound
`HandoffOnly` capability can attest only the final Handoff. Thus share erasure does not trade away
handoff liveness, and the stable signing seed does not become general historical protocol authority.

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
| Proposer omits or equivocates before intent commit | Signed vote rules prevent two honest commits; persisted timeout and view change select another proposer once the configured bounded-synchrony assumption holds. |
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
exceeding them fails closed. The runtime also bounds per-peer connections, request concurrency,
body bytes, and ingress rates. Production deployments still need capacity policy and monitoring for
CPU, disk, bandwidth, and those configured limits.

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
- expand protocol-level rate limiting and monitoring within the implemented network; and
- document the externally supplied deployment assumptions without implementing operator/HSM key
  custody in this repository.

Private Regtest is the sole release-acceptance gate. Public testnet/mainnet deployment and evidence,
including operator authorization, certificate operations, and HSM/key custody, are deployment-owner
responsibilities outside this implementation's scope. Mainnet party mode remains disabled.
