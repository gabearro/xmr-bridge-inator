# Threshold Monero

Experimental Rust implementation of distributed Monero spend-key generation, proactive share
refresh, dynamic committee resharing, and transaction-specific threshold CLSAG signing.

The implementation combines CKLS-style AVSS, a partially synchronous common-QUAL reducer,
distributed key generation, quorum-certified epoch activation, persistent key rotation, a durable
deposit ledger, and monero-oxide's FROSTLASS construction. Party-to-party protocols use mutually
authenticated QUIC. HTTP is limited to health, operator control, and deposit-client queries.

> **Security status:** research software; unaudited and unsuitable for valuable funds. Private
> Regtest is the sole release and interoperability acceptance target. Public testnet/mainnet
> deployment and evidence are intentionally outside this repository's scope, and mainnet party
> mode remains disabled. A Regtest pass does not establish Byzantine security, production privacy,
> rollback resistance, or operational readiness.

## Implemented components

| Area | Current implementation | Important boundary |
| --- | --- | --- |
| AVSS and DKG | Per-dealer bivariate Feldman commitments with signed, recipient-encrypted sends, echoes, and ready messages; common QUAL selects one dealer set under explicit `(n, k, f)` bounds | This is a CKLS-inspired specialization, not a proof of the whole service. Private evaluations must never be logged or published. |
| Proactive refresh | Fresh target-degree polynomials preserve the public spend key while changing every nonconstant coefficient; configured and dynamic fixed-size/fixed-threshold successors permit eligible-member substitution and therefore use refresh or reshare as appropriate | Mobile-adversary security still requires a non-rollbackable epoch fence and verifiable destruction of retired shares and encryption keys. |
| Receiver-key rotation | An eligible roster of at least `desired_n + f` stable identities persists fresh X25519 secrets before advertising them; the source committee certifies any exact `desired_n` subset made solely from those advertisements | Historical and bootstrap receiver keys are cumulatively forbidden. An omitted candidate is erased and receives no successor share. |
| Epoch activation | New shares are staged and activated only after an `n-f` certificate; exact transition indexes, cutover leases, and successor-bound retirement markers survive restart | Competing deployment roots and whole-volume rollback remain external governance concerns. |
| Persistent state machine | AVSS, QUAL, activation, key rotation, allocation, handoff, consolidation, scanner, and outbox state are durably checkpointed and retried while the process is live | Lifetime storage, garbage collection, WORM anchoring, and multi-host operations remain deployment work. |
| Transport | Canonical bounded Postcard frames over exact-leaf-pinned mTLS QUIC, bound to network, sender, recipient, operation, and request ID | Demo certificates are public fixtures. Enrollment, revocation, rate policy, and independent operators are not supplied. |
| Monero signing | Transaction-specific FROSTLASS/CLSAG with persistent one-use nonce tombstones, certified signing intent, all-to-all ROAST contributions, rotating views, and exact candidate validation | This is not ordinary message FROST. Once a signature share may have escaped, the attempt cannot be safely abandoned without the protocol's certified exposure rules. |
| Deposit service | Tenant-bound 30-day allocations, portable `n-f` first-use observation certificates, independent `n-f` index checkpoints, compact cross-epoch state, Monero scanning, and BFT consolidation to the primary wallet | The common view key and combined signer/observer fault domain remain boundaries. ROAST late-settlement continuity currently requires at least one retained old-committee member; authenticated ROAST transfer to a fully disjoint successor remains [TODO](TODO.md). |
| Local archive | Encrypted content-addressed ledger and registry artifacts behind compact authenticated heads | Complete-volume rollback still requires an external monotonic anchor. |
| Docker harness | Eight persistent parties, eight isolated official Monero observers, a separate private-Regtest producer, and fault campaigns | The producer is a test-only common mode; fresh current-source evidence is still required. |

The detailed protocol is in [docs/protocol.md](docs/protocol.md). See
[docs/security-model.md](docs/security-model.md) for trust boundaries,
[docs/byzantine.md](docs/byzantine.md) for the adversary model, and
[docs/docker.md](docs/docker.md) for the local harness.

## Clean-state requirement

The current binary accepts only the current authenticated on-disk formats or an empty state
directory. Do not start it against volumes created by an older build. Preserve old volumes only as
offline forensic artifacts, then initialize new empty volumes and run DKG from epoch zero.

For the disposable Compose project:

```sh
docker compose down --volumes --remove-orphans
docker compose build
docker compose up --detach --wait
```

Never delete volumes that may contain valuable or uniquely held key material. This repository does
not provide an in-place conversion procedure.

## Quick start

Prerequisites are Rust 1.89 or newer and Docker Engine or Docker Desktop with Compose 2.24.4 or
newer.

Run the Rust checks:

```sh
(cd vendor/monero-oxide && ./verify-threshold-monero-sources.sh)
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets
cargo build --locked --release
```

The signer Docker build, the campaign's `rust` mode, and every image-backed campaign mode run the
same pinned vendored Monero source verifier as a mandatory gate; a hash/provenance or fail-closed
signing-API mismatch stops the build or campaign before it can produce release evidence. The
standalone static `preflight` mode validates Compose and fixture topology without compiling or
verifying Rust sources.

Run the private-Regtest harness from empty volumes:

```sh
docker compose build
docker compose \
  -f compose.yaml \
  -f compose.acceptance-proactive-refresh-hold.yaml \
  up --detach --wait
docker compose \
  -f compose.yaml \
  -f compose.acceptance-proactive-refresh-hold.yaml \
  --profile acceptance run --rm e2e
```

The long-running services use named volumes and `restart: unless-stopped`. The one-shot acceptance
client drives the bounded scenario. The acceptance-only overlay holds each newly armed refresh
until that authenticated client releases the exact source epoch, preventing a 15-second deadline
from racing past the epoch under test. Ordinary `docker compose up --detach --wait` omits that
overlay: eligible parties autonomously start canonical epoch-zero DKG and continue serving and
advancing timers until the deployment is explicitly stopped.

The intended current lifecycle is:

```text
3-of-5 DKG
  -> certify, fund, and observe a deposit subaddress
  -> BFT consolidation to the primary wallet over QUIC
  -> BFT X25519 rotation and grow to 4-of-7 selected from eight eligible identities
  -> timer-driven BFT X25519 rotation and proactive refresh
  -> BFT X25519 rotation and shrink to 3-of-5 selected from six eligible identities with f=1
  -> continuing 3-of-5 timer-driven rotation and refresh-or-reshare from all eight identities
  -> threshold-sign and mine private-Regtest transactions
```

Under the full deposit/consolidation contract, the client allocates and funds a distinct deposit
after each activated successor epoch (grow, both fixed-size refreshes or reshares, shrink, and the first
dynamic refresh). Each successor's fresh shares must independently produce a byte-exact
FROSTLASS/CLSAG consolidation which the daemon accepts, mines, and confirms. The client also models
the adjacent sharings as independently randomized Shamir polynomials with one common constant. It
uses each epoch's native coordinates and exhausts every typed old/new observation set that remains
strictly below both thresholds, including added and removed parties, verifying by row rank that the
constant is not determined. Minimal sets reaching either epoch's threshold are separately required
to reconstruct, as they do by design. This evidence is conditional on fresh honest AVSS randomness
and secure erasure of retired shares; it is not a claim that a set already containing a threshold is
isolated.

The acceptance overlay durably holds each next refresh until the preceding epoch's signing check
is complete. An authenticated, source-epoch-bound release then restores the ordinary fixed
interval; production/default deployments never expose that control route and remain autonomous.
The acceptance client is likewise observer-only for ordinary epoch-zero startup: it waits on
authenticated status and records zero calls to `/v1/avss/start`. That route is used only by the two
explicit manual DKG crash-boundary campaigns.

The full `leader-down` Regtest case is the deterministic exact-refresh proof. With p1 stopped,
exactly seven responsive candidates remain for both adjacent 4-of-7 selections, so epoch 2 must
retain epoch 1's stable member IDs. Acceptance then verifies the authenticated history digest is
the zero-constant `Refresh` transition—not the `Reshare` digest—while `key_id` and group spend key
remain fixed, receiver and verification shares change, and those epoch-2 shares sign a real
daemon-accepted Regtest transaction.

This lifecycle is not claimed green until a fresh current-source run exits successfully and its
unique ordered terminal markers and exact daemon-returned transaction bytes are retained. Full
acceptance requires the initial production consolidation to consume exactly two distinct outputs
created in one mined deposit transaction so they mature simultaneously; the verifier checks a bijection from those certified
outputs to the transaction's two input rings. Epochs 1 through 5 then each retain a fresh
single-input successor transaction. For all six transactions, the resilience runner stores
canonical `.hex` and `.bin` files, the marker txid, an independently derived Monero txid, a
verifier transcript, and an ancillary SHA-256 over the binary. The verifier reads a file (or stdin)
instead of passing transaction hex through the process argument vector. Existing artifact
directories were produced by earlier source revisions and are historical diagnostics only.
Public-network transaction evidence is not a release requirement and is intentionally not
collected by this repository.

To stop without deleting state:

```sh
docker compose stop
```

For loopback-only debugging ports:

```sh
docker compose -f compose.yaml -f compose.debug.yaml up --detach --build --wait
```

## Run one party

A party has separate HTTP control and QUIC peer listeners. The deposit service additionally needs a
private view scalar and deposit bearer token.

```sh
cargo run --locked --release -- party \
  --party-id 1 \
  --admin-listen-addr 127.0.0.1:8080 \
  --quic-listen-addr 127.0.0.1:8443 \
  --quic-private-key-file ./p1-quic-key.der \
  --state-dir ./state/p1 \
  --signing-seed-file ./p1-signing-seed.hex \
  --bootstrap-x25519-secret-file ./p1-bootstrap-x25519-secret.hex \
  --admin-bearer-token-file ./admin-token.txt \
  --deposit-bearer-token-file ./deposit-token.txt \
  --deposit-view-key-file ./private-view-scalar.hex \
  --scenario ./scenario.json
```

For a genesis member, the signing seed and bootstrap X25519 secret are independent 32-byte values, each encoded as 64
hexadecimal characters. The signing seed derives only the stable Ed25519 identity; it never derives
an AVSS receiver key. The bootstrap X25519 secret must match the scenario's public bootstrap key
and is supplied only to epoch-zero DKG members; later joiners receive no bootstrap secret. Every successor receiver secret is generated when that
rotation ceremony begins, persisted and read back before advertisement, and erased after certified
cutover. A successor is formed solely from an exact `desired_n` set of fresh advertisements drawn
from its `eligible_members` roster; an omitted identity receives no share. An eligible party that
was omitted or left an earlier committee may be selected again under the same stable identity only
after generating, persisting, and advertising another fresh receiver key. No bootstrap or prior
epoch receiver key is carried forward. QUIC private keys are PKCS#8 DER. The scenario pins stable
identities, public genesis bootstrap keys, QUIC routes, TLS names and leaves, committee policy,
network, and wallet birth checkpoint. The maintained acceptance target is private Regtest only.
Public-network deployment policy, secrets, and operational key custody are supplied externally by
a deployment owner and are not implemented or tested here. Mainnet party mode is disabled.

## Network surfaces

Peer protocol messages are accepted only over QUIC. This includes AVSS, QUAL, activation, key
rotation, deposit consensus and bounded compact synchronization, certified consolidation intent,
ROAST preprocessing, key-image authorization, signature shares, candidate agreement, view
retirement, and terminal certificates. HTTP does not expose transaction-signing rounds.

The HTTP surface is deliberately narrow:

| Endpoint | Authentication | Meaning |
| --- | --- | --- |
| `GET /healthz` | none | The process listener is reachable; protocol completion is not implied. |
| `GET /v1/status` | admin bearer | Inspect local active/staged epoch, core readiness, and separate deposit-chain readiness. |
| `POST /v1/avss/start` | admin bearer | Authorize a configured dealer role; peer effects enter the durable QUIC outbox. |
| `POST /v1/deposits/allocate` | deposit bearer | Request or poll a tenant-bound certified deposit address. |
| `POST /v1/deposits/status` | deposit bearer | Read the certified allocation lifecycle. |
| `POST /v1/deposits/consolidations/status` | deposit bearer | Read certified consolidation and chain status. |

Bearer authentication is not spend policy. Production use would need independent authorization of
destinations, amounts, fees, rings, network, and business intent before a consolidation proposal is
eligible for BFT certification.

## BFT consolidation over QUIC

Consolidation has one protocol path:

1. Parties derive the exact sweep authorization and deterministic ROAST slot from certified wallet
   state.
2. A BFT reducer commits one `ConsolidationIntent` before any nonce is released.
3. Every selected signer persists and reads back a one-use session tombstone, then broadcasts its
   signed preprocessing contribution over QUIC.
4. The exact contribution set authorizes key-image material and signature-share release. Share
   exposure is durably recorded before transmission.
5. Parties validate candidate transaction bytes against the certified intent and Monero signing
   context before accepting a terminal result.
6. A stalled pre-share view may be superseded only through the certified share-unexposed and
   abandonment fence. A view with possible share exposure fails closed rather than creating a
   competing signature.

ROAST views and signer subsets are deterministic and bounded. No distinguished party is required
to remain the coordinator across views. Consensus deadlines, outboxes, ACKs, attempt safety, and
retirement evidence are persistent across ordinary process restart.

## Deposit addresses and Monero terminology

Clients receive standard Monero subaddresses derived from the unchanged threshold public spend key
and a common private view scalar. An unused allocation is client-visible for 30 days. Its index is
never reused, and any observed deposit makes the allocation permanent.

Consolidation sends mature outputs to the wallet's primary address. Monero libraries and RPCs may
call the primary address type a **legacy address**; that is Monero address-format terminology, not
support for old Threshold Monero state or wire formats. Client deposit addresses remain
subaddresses.

The common private view key can recognize receipts and decrypt amount metadata but cannot spend by
itself. It also creates a broad privacy domain: a removed member retaining the key can continue
tracking incoming activity. Threshold scanning and view-key rotation are not implemented.

Auditable reserves remain TODO. A future least-privilege auditor flow should use viewing material
to discover incoming outputs and verify balances without exposing the spend key, while documenting
spent-output/key-image visibility, authenticating the reported chain height, and adding private
Regtest evidence. No reserve proof exists today.

## What a private-Regtest pass would prove

A fresh passing run would show that the exact build can construct, threshold-sign, submit, mine, and
scan real serialized Monero transactions on its disposable chain. It would not prove:

- safety or liveness against every Byzantine schedule;
- recovery across every crash or stale-volume restore;
- rollback resistance without an external monotonic anchor;
- proactive security without verified erasure;
- public-network observer peer diversity or eclipse resistance beyond the combined signer/observer
  `f`-fault assumption;
- privacy of the replicated view key or operational metadata;
- an auditable reserve statement;
- public-testnet acceptance; or
- mainnet readiness.

## Monero-specific construction

Monero inputs require threshold key-image construction, pseudo-output mask coordination, and one
CLSAG per input. Generic Schnorr FROST cannot be substituted. This crate pins monero-oxide commit
`946ec5f00ff071b129758ee8cba5528539fccfe4` and uses its transaction-specific FROSTLASS machine:

- [FROSTLASS/CLSAG implementation](https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/wallet/src/send/multisig.rs)
- [FROSTLASS formalization and proof artifacts](https://github.com/monero-oxide/monero-oxide/tree/946ec5f00ff071b129758ee8cba5528539fccfe4/audits/FROSTLASS)

## References

- Cachin, Kursawe, Lysyanskaya, and Strobl,
  [*Asynchronous Verifiable Secret Sharing and Proactive Cryptosystems*](https://eprint.iacr.org/2002/134)
- Yin et al., [*HotStuff: BFT Consensus with Linearity and Responsiveness*](https://arxiv.org/abs/1803.05069)
- monero-oxide,
  [FROSTLASS formalization and proof directory](https://github.com/monero-oxide/monero-oxide/tree/946ec5f00ff071b129758ee8cba5528539fccfe4/audits/FROSTLASS)
- Monero, [`monerod` RPC reference](https://docs.getmonero.org/rpc-library/monerod-rpc/)

## License

MIT or Apache-2.0, at your option.
