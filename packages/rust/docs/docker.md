# Docker Compose laboratory

The Compose stack is a disposable single-host private-Regtest laboratory. It runs eight persistent
Threshold Monero parties, eight independently addressed observer `monerod` processes, one
test-only block producer, and an opt-in one-shot acceptance client. It is not a production
deployment and does not establish public-testnet or mainnet acceptance.

## Prerequisites

- Docker Engine or Docker Desktop with Compose 2.24.4 or newer
- OpenSSL and `xxd` for campaign source/transaction evidence
- enough disk for Rust/Monero image builds and named volumes
- UDP support for the internal QUIC network
- a clean source tree whose Rust checks have passed

The Monero image is built locally from the pinned version in `Dockerfile.monero`; the Compose file
sets `pull_policy: never` for locally named images. Party and Monero logs are size-bounded. The
base anchors also place CPU, memory, and PID ceilings on every signer, acceptance client, and
Monero daemon so a fresh-zero campaign cannot consume unbounded host resources.

## Clean-state rule

The current party binary accepts empty state or the current exact authenticated state formats. Do
not reuse party volumes created by an older build. Preserve any valuable or investigative volume
offline, then use a new Compose project or empty volumes and run DKG from epoch zero.

For the disposable default project only:

```sh
docker compose down --volumes --remove-orphans
docker compose build
docker compose up --detach --wait
```

`down --volumes` permanently removes the named Regtest chain and party state for that project.
Never run it against a deployment containing valuable or uniquely held key material.

## Build and start

First validate the Rust workspace:

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets
cargo build --locked --release
```

Build and start the persistent stack:

```sh
./docker/run-resilience-campaign.sh preflight
docker compose build
docker compose up --detach --wait
docker compose ps
```

The preflight is static: it renders the acceptance topology, validates the exact current scenario
shape and genesis-only secret distribution, checks persistent volumes/restart policy/healthchecks,
verifies the deterministic QUIC certificates, proves the deposit clock hook is absent from the base
stack, and separately renders its acceptance-only read-only-reader/single-writer overlay. It does
not build images or create, start, stop, or remove containers.

The base application has no host-published ports. Every daemon and party has its own named volume
and uses `restart: unless-stopped`. Parties continue running timers, QUIC retries, scanning,
refresh, deposit consensus, and eligible consolidation until explicitly stopped. Each eligible
epoch-zero party autonomously and idempotently starts only its own canonical DKG dealer role after
its QUIC runtime is live. In every ordinary acceptance case the one-shot client observes epoch zero
only through authenticated status reads and emits
`TM_ACCEPTANCE_AUTONOMOUS_GENESIS ... control=observe-only avss_start_calls=0`; it never calls
`POST /v1/avss/start`. Only the two explicit manual fault-gate cases use that operator route.

The current scenario schema is version 7. It pins each party's stable Ed25519 signing public key
and exactly one separately provisioned, genesis-only bootstrap X25519 public key. It also separates
each configured epoch's desired `members` count/threshold shape from its canonical
`eligible_members` roster. `members` is not a priority list: a certificate may select any exact
desired-size subset of fresh eligible advertisers.
It does not contain per-epoch receiver-key maps: epoch zero uses bootstrap keys, while every
successor is selected solely from receiver keys generated, persisted, advertised, and certified
during that transition's live key-rotation ceremony.

Start the bounded acceptance stack with its deterministic refresh-hold overlay, then run the
one-shot client:

```sh
docker compose \
  -f compose.yaml \
  -f compose.acceptance-proactive-refresh-hold.yaml \
  up --detach --wait
docker compose \
  -f compose.yaml \
  -f compose.acceptance-proactive-refresh-hold.yaml \
  --profile acceptance run --rm e2e
```

Treat that run as passing only if the command exits zero from a clean project and its log contains
the current unique terminal markers, including the exact daemon-returned serialized deposit
consolidation transaction. The resilience runner additionally decodes that hex to raw bytes and
hashes the binary. Historical artifact directories are diagnostics, not evidence for the current
source.

## Expected private-Regtest lifecycle

The current acceptance driver is intended to exercise:

```text
3-of-5 distributed key generation
  -> certified deposit subaddress allocation
  -> mine, observe, mature, and permanently retain the deposit
  -> BFT intent and coordinator-free QUIC/ROAST consolidation
  -> BFT receiver-key rotation and grow to 4-of-7 selected from eight eligible identities
  -> two fixed-interval, fixed-size/fixed-threshold refreshes or reshares
  -> BFT receiver-key rotation and shrink to 3-of-5 selected from six eligible identities with f=1
  -> continuing autonomous 3-of-5 rotation and refresh-or-reshare from all eight identities
  -> real serialized Monero signing, submission, mining, and scanning
```

The neutral all-epochs terminal marker is exactly:

```text
threshold Monero regtest accepted 3-of-5 -> 4-of-7 -> two scheduled 4-of-7 refreshes -> 3-of-5 resharing -> autonomous dynamic 3-of-5 refresh-or-reshare
```

Full acceptance performs that real signing check after every transition, not only with the
genesis shares. Distinct deposits under epochs 1 through 5 must each yield a byte-exact
FROSTLASS/CLSAG consolidation which the daemon accepts, mines, and confirms. Protocol-only and
allocation-only campaigns retain the neutral all-epochs lifecycle marker but intentionally do not
emit the successor-signing terminal marker.

The `leader-down` full-signing case supplies the deterministic true-refresh witness. Stopping p1
leaves exactly seven responsive identities for the adjacent epoch-1 and epoch-2 4-of-7 selections,
so their stable member IDs must be identical. The client independently derives the authenticated
epoch-history transition digest for `DealPurpose::Refresh`, proves that the same transition does
not match `DealPurpose::Reshare`, requires the same `key_id` and Monero group spend key, fresh
receiver keys, and a different verification-share polynomial, then signs and confirms the real
epoch-2 Regtest transaction. The runner retains this binding in
`exact-same-committee-refresh.env` alongside the canonical epoch-2 transaction artifact.

Every successor, configured or dynamic, certifies its target receiver-key selection before AVSS.
The configured epoch-4 shrink selects exactly five of six eligible identities. After the finite
chain, the dynamic policy retains `desired_n=5`, `k=3`, and `f=1` while all eight stable identities
are eligible; the rotation-omission campaign leaves seven responsive candidates. In general the
eligible roster has at least `desired_n + f` identities, and the successor consists of exactly
`desired_n` fresh advertisements. An omitted identity receives no share; it may re-enter a later
epoch only with another freshly generated, persisted, and selected receiver key. No bootstrap or
prior-epoch receiver key is carried forward. The refresh deadline belongs to persistent party
state. In the acceptance-only overlay, every new deadline is durably held until the authenticated
client releases that exact source epoch, then the ordinary configured interval elapses. Without
that overlay, the persistent party network remains fully autonomous and needs no client to trigger
refresh.

The focused `deposit-ttl` campaign uses `compose.acceptance-deposit-clock.yaml` to cross the
30-day unused-address boundary without waiting 30 wall-clock days. The overlay is absent from the
ordinary stack. It bind-mounts one initially empty directory read-only on p1-p8 and read-write only
on the one-shot E2E client. That client creates six strictly increasing canonical generations:
bootstrap, visibility of an unused allocation, visibility and real funding of a second allocation,
the unused allocation's final active second, its exact expiry second, and a later replacement
allocation. The pass contract requires `Active` at `expires_at - 1`, `Expired` with no returned
address or certificate at `expires_at`, strictly newer sequence/index and a different address for
the replacement, and `Permanent` retrieval of the funded allocation at its own expiry.
Consolidation is explicitly disabled so this case measures only allocation TTL semantics. The
runner archives every canonical clock generation and byte-compares generation six with the live
file; it also retains the exact funding transaction bytes and confirms those same bytes are mined
in the Regtest producer.

## Network layout

| Network | Members | Traffic |
| --- | --- | --- |
| `control` | parties and acceptance client | health, authenticated operator calls, deposit-client queries |
| `peer-quic` | parties only | all AVSS, QUAL, activation, rotation, deposit consensus, handoff, ROAST, and signing rounds over UDP/QUIC |
| `monero-rpc-p1` … `monero-rpc-p8` | exactly one party and its observer | isolated local chain queries and transaction publication |
| `monero-p2p` | block producer and eight observers | private fakechain block propagation |
| `monero-mining` | block producer and acceptance client | test-only mining and independent transaction verification |

These internal bridges organize endpoints but are not a complete container firewall: each party
joins several bridges and its listeners use wildcard container addresses. Peer identity is enforced
by QUIC mTLS and protocol bindings. Each signer receives a different admin and deposit bearer
capability, so compromising one signer does not authenticate HTTP requests to another party; the
acceptance client alone receives all sixteen public demo capabilities.

For local debugging, add the loopback-only overlay:

```sh
docker compose -f compose.yaml -f compose.debug.yaml up --detach --build --wait
```

It publishes party HTTP on `127.0.0.1:19001` through `19008`, party QUIC/UDP on `19401` through
`19408`, and the test block producer on `18081`. Do not use this overlay on a shared host.

Example p1 status request after assigning its demo admin token to a shell variable:

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${THRESHOLD_ADMIN_TOKEN}" \
  http://127.0.0.1:19001/v1/status
```

`GET /healthz` proves only that the HTTP listener is responsive. The Compose healthcheck instead
authenticates each party's own `/v1/status` capability and verifies its expected party ID plus
restored-ready flag. Epoch activation and transaction progress still require acceptance evidence.
`deposit_chain_ready` is a separate nullable field: it is absent when deposits are disabled,
`false` until a daemon has passed the pinned network/genesis probe (and again after an RPC
failure), and `true` only for the currently cached verified client.

Signer containers intentionally do not `depends_on` their observer. They restore state, bind QUIC,
and run DKG/QUAL/refresh even when chain RPC is unavailable; the deposit adapter connects and
verifies network/genesis on first use, then rotates through at most four unique endpoints after
failures. The eight demo observers have independent processes, storage, names, and RPC bridges.
They still follow one private-Regtest producer, so this topology tests one observer fault but does
not model public-network peer diversity. Production requires independently administered,
independently peered observers under the combined signer/observer `f`-fault assumption described
in [`security-model.md`](security-model.md#monero-and-daemon-boundaries).

## State and restart operations

Stop without deleting state:

```sh
docker compose stop
```

Resume the same current-build project:

```sh
docker compose start
docker compose ps
```

Restart one party while retaining its named volume:

```sh
docker compose restart p3
docker compose logs --since=5m p3
```

Ordinary restart should restore authenticated epochs, refresh deadlines, outboxes, deposit history,
scanner state, consensus views, nonce tombstones, and ROAST attempt safety. A whole-volume restore
to an earlier valid point is not protected by Compose or the application; production requires an
external monotonic/WORM anchor.

The `network-restart` campaign exercises the stronger whole-network persistence boundary from a
new project. It records every party's live epoch-4 public state and finite epoch-5 deadline, stops
all eight containers before the earliest deadline without removing their named volumes, leaves
them stopped until the latest deadline is overdue, then restarts the same container IDs from the
same volumes. The client is released only after at least `n-f` active epoch-5 members report one
identical public value with the original key identity and group spend key, fresh receiver keys,
and a fresh verification-share polynomial. It then allocates and funds a new deposit under epoch
5 and requires its byte-exact threshold-signed consolidation to be broadcast, mined, and
confirmed by the Regtest daemon. Container IDs/PIDs/volumes, source and successor statuses,
deadline/start timestamps, and the canonical transaction verifier output are retained as
source/image-bound campaign evidence.

Compact deposit catch-up uses candidate-bound encrypted pages and a 256 KiB authenticated spool
head. Each QUIC response and recovery step remains independently bounded, but there is no lifetime
page, object, or plaintext quota for an honest candidate. Verification, materialization, and
deletion advance through durable page-granular cursors, so a large archive resumes after restart
without rehydrating the full candidate in memory.

Useful diagnostics:

```sh
docker compose ps --all
docker compose logs --since=10m p1 p2 p3 p4 p5 p6 p7 p8
docker compose logs --since=10m monerod-miner monerod-p1 monerod-p2 monerod-p3 monerod-p4 monerod-p5 monerod-p6 monerod-p7 monerod-p8
docker compose config
```

## Fault and resilience campaigns

The runner creates a dedicated project and empty volumes for each Compose case. It never builds
images, so build once from the exact source first:

```sh
docker compose build
./docker/run-resilience-campaign.sh rust
./docker/run-resilience-campaign.sh clean
./docker/run-resilience-campaign.sh observer-byzantine
./docker/run-resilience-campaign.sh deposit-ttl
./docker/run-resilience-campaign.sh consolidation-silent
./docker/run-resilience-campaign.sh consolidation-bootstrap-silent
./docker/run-resilience-campaign.sh network-restart
./docker/run-resilience-campaign.sh all
```

`all` includes clean acceptance, a live signer whose observer forks/stalls/stops, AVSS
crash/restart, deposit restart, exact unused-deposit TTL/non-reuse/permanence boundaries, omission,
proposer stop, silent-QUAL, stopped-party, receiver-key rotation omission, a simultaneous all-party
stop across an overdue persisted refresh followed by a real post-restart consolidation, and
combined crash/omission cases. Each case writes bounded evidence under `artifacts/`. See
[resilience-campaign.md](resilience-campaign.md) and [faults.md](faults.md).

Only the two AVSS/QUAL crash cases combine the test-only manual-genesis overlay with the p3-only
protocol-fault-gate overlay. They prove an exact authenticated `DealerStarted` or `QualRoundZero`
hold survives SIGKILL/restart before explicit release. Clean startup and every other fault case
retain autonomous DKG, require the observer-only genesis marker, and never mount that admin route.

Use a longer bounded timeout only when the host is slow:

```sh
TM_CAMPAIGN_TIMEOUT_SECONDS=1800 ./docker/run-resilience-campaign.sh all
```

Keep one failed case running for inspection:

```sh
TM_CAMPAIGN_KEEP_RUNNING=1 ./docker/run-resilience-campaign.sh consolidation-silent
```

`TM_CAMPAIGN_KEEP_RUNNING=1` is valid for a single Compose case, not `all`.

## Demo secrets

Everything under `docker/demo-secrets/` and `docker/quic-pki/` is public deterministic test
material. The common private view scalar lets every laboratory party scan all deposits. Never use
these identities, TLS keys, bearer tokens, receiver keys, or view material outside disposable
Regtest.

Each party mounts its own `pN-signing-seed.hex`. Only genesis members p1-p5 mount an independent
`pN-bootstrap-x25519-secret.hex`; post-genesis-only p6-p8 receive no epoch-zero secret. Public
bootstrap sentinels remain in the version-7 scenario solely to make every such key permanently
ineligible for successor advertisements.
Future X25519 secrets are absent from both the scenario and demo-secret directory until the live
ceremony creates and durably stores them.

The following are external deployment-owner responsibilities. They are not implemented or tested
by this repository's Regtest acceptance gate:

- independently provisioned signing, bootstrap X25519, and QUIC keys;
- certificate enrollment, rotation, and revocation;
- separate administrative operators and hosts;
- secret-manager, hardware-backed, or HSM custody appropriate to the deployment;
- independently administered and independently peered Monero observers within the documented
  combined signer/observer fault budget;
- operational retention and capacity policy for the implemented portable n-f first-use/output
  certificates and authenticated archive data;
- external rollback anchors and tested restore governance;
- transaction-policy authorization beyond bearer admission; and
- monitoring for quorum, refresh, scanner, ROAST, storage, and failed-closed conditions.

## What a successful run does not prove

Even a fresh complete pass does not prove safety for every Byzantine schedule, verified erasure,
whole-volume rollback resistance, independent-host tolerance, privacy of the shared view key,
auditable reserves, public-testnet acceptance, or mainnet readiness. Mainnet party mode remains
disabled.
