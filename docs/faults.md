# Fault-injection guide

The fault harness exercises deterministic crash, omission, restart, consensus-view, refresh, and
consolidation schedules on disposable private Regtest. It is evidence generation, not a proof of
Byzantine correctness. Always run it from images built from the exact source under review.

## Safety

`docker/run-resilience-campaign.sh` uses dedicated project names beginning with
`threshold-monero-resilience-`. Before each Compose case it removes only that case's disposable
volumes, then records evidence under `artifacts/`. Do not rename a project to match a valuable
deployment and do not point the harness at production volumes.

The current binary requires empty volumes for a new build. Preserve older state offline for
forensics; do not use it as campaign input.

## Available modes

| Mode | Injected condition | Required outcome |
| --- | --- | --- |
| `rust` | No Compose fault; serial all-target Rust suite | Unit/integration suites exit zero under the runner's bounded contract. |
| `clean` | Fresh seven-party stack | Full deposit allocation, observation, permanence, BFT QUIC/ROAST consolidation, scheduled refresh, grow/shrink, dynamic refresh, and private-chain Monero acceptance complete. |
| `observer-byzantine` | Keep p1 live while monerod-p1 follows an isolated fork, stalls, then stops | Remaining n-f observation domains complete the full deposit, consolidation, and refresh lifecycle; p1 core readiness stays independent of chain RPC. |
| `avss-crash` | Abrupt p3 restart at the authenticated canonical `DealerStarted` hold | The exact held dealer outbox survives restart; only an authenticated release resumes replay and the full lifecycle. |
| `deposit-restart` | Abrupt p2 restart after deposit mining and before maturity | Scanner and deposit state recover; the same deposit becomes permanent and consolidates once eligible. |
| `consolidation-silent` | One selected signer omits during consolidation | A bounded ROAST view change selects a safe subset; one exact transaction is accepted and the peer later catches up. |
| `consolidation-bootstrap-silent` | The slot-zero intent proposer stops before bootstrap agreement | Consensus rotates to another proposer before nonce release; restart catches up to the same certified result. |
| `silent` | p1 HTTP stays healthy but p1 QUIC is unreachable | Protocol-only QUAL advances views and the remaining configured lifecycle completes within `f`. |
| `deposit-silent` | Same p1 QUIC omission with deposit allocation enabled | Address allocation, funding, observation, and permanence complete; consolidation is intentionally outside this case. |
| `leader-down` | p1 is stopped after initial healthy startup | Allocation plus later resharing/refresh epochs complete while one whole party is absent; consolidation is intentionally outside this case. |
| `rotation-silent` | p2 loses peer QUIC after the final configured epoch | At least `n-f` fresh receiver keys are certified and an autonomous dynamic refresh activates without p2. |
| `proactive-deadline` | Abrupt p2 SIGKILL/restart from its durable volume inside the exact finite 15-second refresh deadline | The held refresh schedule survives restart and the successor epoch activates only at or after the durable due time. |
| `qual-crash-silent` | p1 omission plus p3 crash/restart at authenticated undecided QUAL round zero | The exact held reducer/outbox survives restart; authenticated release resumes and completes within the configured fault bound. |
| `all` | Every mode above in runner order | Every independent clean-state case and its evidence contract succeeds. |

The historical mode name `leader-down` refers to stopping party p1 for a broad availability test.
Consolidation itself uses rotating consensus and ROAST views; no distinguished long-lived party is
required to drive it.

## Run campaigns

Build the exact local images first; the runner intentionally never builds:

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets
docker compose build
```

Run focused cases while developing:

```sh
./docker/run-resilience-campaign.sh clean
./docker/run-resilience-campaign.sh observer-byzantine
./docker/run-resilience-campaign.sh avss-crash
./docker/run-resilience-campaign.sh consolidation-silent
./docker/run-resilience-campaign.sh consolidation-bootstrap-silent
./docker/run-resilience-campaign.sh rotation-silent
```

Run the complete matrix before treating the source as green:

```sh
./docker/run-resilience-campaign.sh all
```

Default total case timeout is bounded. A slow host can request up to 1800 seconds:

```sh
TM_CAMPAIGN_TIMEOUT_SECONDS=1800 ./docker/run-resilience-campaign.sh all
```

Keep one case running after failure for manual inspection:

```sh
TM_CAMPAIGN_KEEP_RUNNING=1 ./docker/run-resilience-campaign.sh qual-crash-silent
```

Do not combine `TM_CAMPAIGN_KEEP_RUNNING=1` with `all`.

The base Compose stack starts canonical epoch-zero DKG autonomously. The runner uses
`compose.acceptance-manual-bootstrap.yaml` plus
`compose.acceptance-protocol-fault-gate.yaml` only for `avss-crash` and
`qual-crash-silent`. The p3-only gate persists and authenticates the exact session, epoch, boundary,
and boundary evidence; ingress, progress, outbox delivery, and ACK retirement stay frozen until
the runner proves the same record after restart and explicitly releases it. All other modes prove
the ordinary autonomous startup path.

## Manual omission overlay

`compose.byzantine-silent.yaml` binds p1's QUIC listener to container loopback while leaving its real
party process and HTTP health check alive. This isolates peer omission from process death without
granting a fault container Docker or `NET_ADMIN` access.

```sh
docker compose \
  -f compose.yaml \
  -f compose.byzantine-silent.yaml \
  up --detach --build --wait
```

Use the automated `silent` or `deposit-silent` mode for acceptance evidence; it records the exact
rendered topology and environment contract.

## Consolidation gates

The two consolidation fault modes add acceptance-only gates to all seven parties:

- `compose.acceptance-consolidation-gate.yaml` pauses a deterministic contribution point so the
  runner can make one selected signer unavailable and observe safe ROAST rotation.
- `compose.acceptance-consolidation-bootstrap-gate.yaml` pauses before the first intent proposal and
  also holds the replacement certificate before nonce creation, allowing the runner to stop and
  later restart the first proposer safely.

Party startup rejects these hooks outside demo-only Regtest, and mutations require ordinary admin
authentication. The overlays are test instruments and must never be included in a real deployment.

## Evidence to inspect

Each case directory should contain enough context to bind the result to the exact source and image.
Inspect at least:

- source and image digests;
- rendered Compose configuration and acceptance environment contract;
- `e2e.log` plus `required-markers.tsv`, which proves every required barrier and terminal marker is
  unique and records its log position;
- all party, observer-daemon, producer-daemon, and wallet logs;
- container state before and after injected stop/restart;
- peer-network membership around QUIC omission cases;
- the exact consolidation transaction identifier, canonical hex, decoded raw bytes, and binary
  SHA-256 reported as daemon accepted; and
- post-restart active epoch, activation digest, refresh schedule, and terminal consolidation state.

A health check is insufficient. It says only that a listener responds. A passing fault case must
show the protocol-specific terminal condition and no competing transaction, epoch, or allocation.

## Expected fail-closed behavior

Within `f`, omission should eventually rotate a consensus or ROAST view when safe. Corrupt,
conflicting, oversized, cross-network, cross-epoch, or unauthenticated messages should be rejected
without changing certified state.

Some faults must halt progress:

- more omissions than the certificate quorum can tolerate;
- conflicting evidence that violates the configured Byzantine assumption;
- a signature share that may have escaped without enough evidence to complete the same candidate;
- a missing deposit handoff or scanner disagreement about intended inputs;
- tampered authenticated storage or a non-current state format;
- exhausted bounded views, sessions, attempts, history, or storage; and
- a Monero reorg or daemon view that invalidates the intended chain point.

Do not weaken these stops merely to make a campaign continue. Add explicit certified recovery or a
new clean-state test instead.

## Coverage gaps

The deterministic matrix does not exhaust all schedules. Further work should add randomized
message schedules, corruption at every atomic write boundary, disk-full and permission faults,
long partitions, clock skew, deeper reorgs, independent-daemon disagreement, contribution
equivocation across many ROAST views, and multi-day refresh/retention runs.

No current fault artifact demonstrates public-testnet or mainnet acceptance, external rollback
resistance, secure erasure, independent-host operation, reserve auditing, or privacy of the common
view key.
