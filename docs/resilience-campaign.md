# Resilience acceptance campaign

The campaign binds crash, omission, restart, refresh, deposit, and consolidation evidence to one
exact source tree and set of locally built images. It is the final private-Regtest gate for a
candidate build; it is not a proof and it does not establish public-testnet or mainnet acceptance.

The BFT consolidation and completion/handoff design must be treated as an invariant under test until
the complete current-source campaign passes from empty volumes. Historical artifacts do not make a
changed source tree green.

## Clean-state policy

Every Compose mode creates a dedicated `threshold-monero-resilience-*` project and starts with empty
disposable volumes. The runner removes only that case's project volumes. The current executable is
not intended to open state created by an older build.

Never reuse the campaign project naming scheme for valuable state. Keep older volumes offline for
forensics and begin a new deployment with epoch-zero DKG.

## Preflight

The evidence runner also requires Docker Compose v2, OpenSSL, and `xxd` on the host.

Run all local Rust gates before building images:

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets
cargo build --locked --release
```

Then build once from the exact source under test:

```sh
docker compose build
docker compose \
  -f compose.yaml \
  -f compose.acceptance-proactive-refresh-hold.yaml \
  --profile acceptance config
```

Every campaign also applies `compose.acceptance-proactive-refresh-hold.yaml`. That demo-Regtest-only
overlay durably holds each newly armed schedule until the authenticated acceptance client releases
the exact source epoch, then preserves the scenario's ordinary fixed interval. This prevents the
15-second pacemaker from advancing beyond an exact epoch assertion while images and the one-shot
client start; the ordinary Compose topology remains autonomous.

The campaign runner never builds. This prevents a later case from silently testing another image.

## Campaign matrix

| Gate | Command | Evidence target |
| --- | --- | --- |
| Rust suite | `./docker/run-resilience-campaign.sh rust` | Serial all-target tests, including canonical wire bounds, replay/equivocation rejection, persistence readback, consensus safety, refresh scheduling, and Monero construction checks. |
| Honest private chain | `./docker/run-resilience-campaign.sh clean` | DKG, certified deposit, real BFT QUIC/ROAST consolidation, receiver-key-certified grow, fixed-interval refreshes, receiver-key-certified shrink, continuing dynamic refresh, and daemon-accepted serialized Monero transactions. |
| Byzantine observer | `./docker/run-resilience-campaign.sh observer-byzantine` | Keep p1 and QUIC live while its isolated observer mines a competing fakechain, stalls, then goes down; require full n-f deposit, consolidation, and refresh acceptance from the remaining observation domains. |
| AVSS crash | `./docker/run-resilience-campaign.sh avss-crash` | Arm p3 for the canonical epoch-zero `DealerStarted` boundary, prove its encrypted dealer outbox is durable and frozen, SIGKILL/restart it, prove the same hold survived, then release and complete. |
| Deposit restart | `./docker/run-resilience-campaign.sh deposit-restart` | Restart between deposit mining and maturity; scanner recovery, permanence, and one eligible consolidation. |
| ROAST omission | `./docker/run-resilience-campaign.sh consolidation-silent` | Selected-signer omission, safe view/subset rotation, one exact accepted transaction, and peer catch-up. |
| Intent proposer stop | `./docker/run-resilience-campaign.sh consolidation-bootstrap-silent` | Stop the first intent proposer before agreement; rotate before nonce release and converge after restart. |
| Silent QUIC peer | `./docker/run-resilience-campaign.sh silent` | p1 remains HTTP-healthy but cannot exchange QUIC; common QUAL and later protocol-only epochs progress within `f`. |
| Silent deposit peer | `./docker/run-resilience-campaign.sh deposit-silent` | Certified allocation, mining, observation, and permanence within `f`; consolidation deliberately excluded. |
| Whole-party stop | `./docker/run-resilience-campaign.sh leader-down` | Stop p1 while allocation and later epoch transitions continue; consolidation deliberately excluded. |
| Rotation omission | `./docker/run-resilience-campaign.sh rotation-silent` | Remove p2 from peer QUIC at the dynamic boundary; certify at least `n-f` fresh receiver keys and activate the successor. |
| Proactive refresh deadline | `./docker/run-resilience-campaign.sh proactive-deadline` | SIGKILL/restart p2 in place from its durable volume inside the exact finite 15-second refresh deadline; prove the held schedule survives restart and the successor activates only at or after the durable due time. |
| QUAL crash plus omission | `./docker/run-resilience-campaign.sh qual-crash-silent` | With p1 omitted, hold p3 at exact undecided QUAL round zero, prove the hold across SIGKILL/restart, then release and restore reducer/outbox liveness. |
| Complete gate | `./docker/run-resilience-campaign.sh all` | Run every independent clean-state case in the order enforced by the script. |

The historical `leader-down` mode name identifies a whole-party availability case. Consolidation
uses rotating BFT intent and ROAST views and must not depend on that one party.

Ordinary cases use the base stack's autonomous canonical epoch-zero DKG. Only `avss-crash` and
`qual-crash-silent` add `compose.acceptance-manual-bootstrap.yaml` and
`compose.acceptance-protocol-fault-gate.yaml`. The first gives the acceptance client deterministic
control of canonical DKG start. The second exposes an authenticated p3-only admin control which
durably binds either `DealerStarted` or `QualRoundZero`, freezes only that AVSS session under its
run lock, and requires an exact release after restart. Neither overlay is a normal deployment mode.

## Run strategy

During development, start with the smallest affected cases and then run `all`:

```sh
./docker/run-resilience-campaign.sh rust
./docker/run-resilience-campaign.sh consolidation-silent
./docker/run-resilience-campaign.sh consolidation-bootstrap-silent
./docker/run-resilience-campaign.sh rotation-silent
./docker/run-resilience-campaign.sh proactive-deadline
./docker/run-resilience-campaign.sh all
```

The default case timeout is bounded. On a slow host:

```sh
TM_CAMPAIGN_TIMEOUT_SECONDS=1800 ./docker/run-resilience-campaign.sh all
```

The marker timeout can be tuned within the runner's documented bound when startup is predictably
slow:

```sh
TM_CAMPAIGN_MARKER_TIMEOUT_SECONDS=300 \
  ./docker/run-resilience-campaign.sh consolidation-bootstrap-silent
```

For one failing case only:

```sh
TM_CAMPAIGN_KEEP_RUNNING=1 ./docker/run-resilience-campaign.sh deposit-restart
```

The keep-running option is rejected for `all`.

## Pass contract

A case passes only when all of its required conditions hold:

1. The runner verifies the rendered Compose topology and exact acceptance flags.
2. The expected fault barrier is reached before the runner changes process or network state.
3. Container evidence shows that the intended party or observer was actually forked, stalled,
   stopped, restarted, or detached.
4. The one-shot acceptance process exits zero inside the case timeout.
5. Every required barrier and terminal marker occurs exactly once and in protocol order after the
   injected fault, not merely before it.
6. Every asserted epoch has the expected committee, threshold, fault bound, unchanged group public
   key, fresh verification-share polynomial, and certified activation.
7. Deposit cases show the exact allocation, observation/permanence, and required handoff state.
8. Full consolidation cases show one certified intent, safe ROAST progress, and no competing
   terminal candidate, followed by exactly one byte-identical daemon-submitted and confirmed
   successor transaction for each epoch 1 through 5.
9. Restart cases show restored durable state rather than a clean process recomputation that lost
   security evidence.
10. The evidence bundle records the source and image identities used by the case.

An HTTP health response is never a protocol pass condition.

## Evidence bundle

By default the runner creates a timestamped directory under `artifacts/`. A caller may choose an
explicit location:

```sh
TM_CAMPAIGN_ARTIFACT_DIR=/absolute/path/to/evidence \
  ./docker/run-resilience-campaign.sh all
```

Retain at least:

- source-tree digest and dirty-state report;
- signer and Monero image identifiers;
- rendered Compose files and acceptance contract;
- command, environment bounds, start/end time, and exit status;
- complete bounded logs for all parties, all seven observers, the Regtest producer, and the
  acceptance client;
- process and network observations surrounding every injected fault;
- `required-markers.tsv`, containing the unique barrier and terminal-marker lines and their log
  positions;
- active epoch, activation, refresh, registry, scanner, and consolidation status after recovery; and
- exact transaction identifier plus `signed-transaction.hex`, decoded `signed-transaction.bin`,
  its binary SHA-256, and daemon acceptance/confirmation evidence;
- `successor-epoch-signed-transactions.tsv`, with exactly one complete transaction marker in
  strict order for each epoch 1 through 5 in full acceptance;
- `case-result.env`, which is written only after the evidence contract has passed.

Do not publish secrets or private evaluations with an evidence bundle. The repository's demo
secrets are already public, but a production-shaped campaign must redact real identities, bearer
tokens, view material, and secret-bearing state.

## Expected BFT observations

Within the configured fault bound:

- a silent QUAL or deposit-consensus proposer is replaced after its persistent view deadline;
- a stopped first consolidation-intent proposer is replaced before any nonce is released;
- a silent selected signer causes safe bounded ROAST rotation only while share-exposure evidence
  permits it;
- all-to-all origin-signed contributions remain usable after one relay party disappears;
- completion and epoch handoff converge from quorum-certified portable evidence rather than one
  party's availability;
- a due refresh survives restart and autonomously begins the immediate successor; and
- every configured or dynamic successor certifies target `n-f` receiver-key advertisements before
  AVSS using a source `n-f` Byzantine certificate.

When safe abandonment cannot be proved after possible share exposure, the expected behavior is a
halted consolidation family, not an unsafe retry.

## Failure triage

Classify a failed case before changing code:

- **environment:** Docker, disk, CPU, UDP, image, or Monero startup failure;
- **evidence contract:** wrong profile, missing gate, missing source/image binding, or marker emitted
  before the injected event;
- **liveness:** no progress despite eventual synchrony and enough honest online members;
- **safety:** conflicting certificate/candidate, nonce/share reuse, epoch mixing, or state accepted
  without required durable evidence;
- **persistence:** restart loses a timer, lock, outbox, tombstone, exposure fence, scanner point, or
  terminal record; or
- **policy:** scanner, fee, maturity, destination, network, or Monero validation differs across
  parties.

A safety or persistence failure blocks release. Do not reclassify it as flakiness without retaining
and explaining the exact evidence.

## Release interpretation

A fresh `all` pass would demonstrate that the exact build interoperates across this bounded
single-host private-Regtest matrix. It would not establish:

- every Byzantine schedule or more than `f` faults;
- whole-volume rollback resistance or verified erasure;
- independent operators, daemons, clocks, storage, or networks;
- privacy of the common private view key;
- auditable reserves;
- public-testnet acceptance; or
- mainnet readiness.

Public-testnet evidence must be collected separately with non-demo identities, TLS material,
secrets, independent daemons, exact accepted transaction bytes, and a documented chain checkpoint.
Mainnet party mode should remain disabled.
