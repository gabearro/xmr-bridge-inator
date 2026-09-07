# Resilience acceptance campaign

The campaign binds crash, omission, restart, refresh, deposit, and consolidation evidence to one
exact source tree and set of locally built images. It is the final private-Regtest gate for a
candidate build; it is not a proof and it does not establish public-testnet or mainnet acceptance.

The BFT consolidation and completion/handoff design must be treated as an invariant under test until
the complete current-source campaign passes from empty volumes. Historical artifacts do not make a
changed source tree green.

## Clean-state policy

By default, every Compose mode creates a dedicated `threshold-monero-resilience-*` project, removes
only that case's disposable project volumes, and starts empty. The current executable is not
intended to open state created by an older build.

To preserve a canonical case project for forensics while rerunning the case, set
`TM_CAMPAIGN_PROJECT_SUFFIX` to one through four lowercase ASCII letters or digits. The suffix is
appended to the case's project name. Suffixed runs are fail-closed: the runner refuses to start if
that exact project already has Compose-labeled containers, volumes, or networks, and never removes
volumes from the collided project. Choose a new suffix for each fresh run.

Never reuse the campaign project naming scheme for valuable state. Keep older volumes offline for
forensics and begin a new deployment with epoch-zero DKG.

## Preflight

The evidence runner also requires Docker Compose 2.24.4 or newer, OpenSSL, and `xxd` on the host.

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

Only `deposit-ttl` additionally applies `compose.acceptance-deposit-clock.yaml`. The base topology
contains neither clock environment variable nor mount. In the focused overlay, p1-p8 receive one
shared directory read-only and only the one-shot E2E process can atomically write its canonical
clock file. Party startup also gates this hook on deposits plus a demo-only private-Regtest
scenario. The static preflight renders both the ordinary and clock topologies and verifies that
the writer does not leak into a persistent service.

The campaign runner never builds. This prevents a later case from silently testing another image.
Before the Rust suite or any image-backed case proceeds, it executes the pinned vendored Monero
source verifier; the signer Docker build executes that verifier before Cargo as well. Full cases
then run the signer image's file-based canonical transaction verifier over the retained initial and
five successor binaries, so a hex-shape check or ancillary SHA-256 cannot stand in for Monero txid
derivation.

## Campaign matrix

| Gate | Command | Evidence target |
| --- | --- | --- |
| Rust suite | `./docker/run-resilience-campaign.sh rust` | Serial all-target tests, including canonical wire bounds, replay/equivocation rejection, persistence readback, consensus safety, refresh scheduling, and Monero construction checks. |
| Honest private chain | `./docker/run-resilience-campaign.sh clean` | DKG, one certified address funded by two distinct outputs mined together, a real two-input BFT QUIC/ROAST consolidation with exact ring mapping, receiver-key-certified grow/refresh/shrink, and five fresh daemon-accepted successor transactions. |
| Byzantine observer | `./docker/run-resilience-campaign.sh observer-byzantine` | Poll p1's observer and the producer to one exact common tip, isolate and fork it, hold the process stalled across at least two configured polling intervals, then stop it while p1 and QUIC stay live; require full n-f acceptance from the remaining observation domains. |
| AVSS crash | `./docker/run-resilience-campaign.sh avss-crash` | Arm p3 for the canonical epoch-zero `DealerStarted` boundary, prove its encrypted dealer outbox is durable and frozen, SIGKILL/restart it, prove the same hold survived, then release and complete. |
| Deposit restart | `./docker/run-resilience-campaign.sh deposit-restart` | Restart between deposit mining and maturity; scanner recovery, permanence, and one eligible consolidation. |
| Deposit TTL boundaries | `./docker/run-resilience-campaign.sh deposit-ttl` | Advance a private-Regtest-only canonical clock through exactly six generations; require an unused address to remain Active at `expires_at - 1`, become Expired with its address/certificate hidden at `expires_at`, never reuse its sequence/index/address, and keep a separately funded used address Permanent and retrievable at its own expiry. Consolidation is deliberately disabled. |
| ROAST omission | `./docker/run-resilience-campaign.sh consolidation-silent` | Selected-signer omission, safe view/subset rotation, and one exact accepted transaction; an authenticated durable latch binds settlement to that transaction and releases only after the omitted peer is demonstrably reattached to QUIC. |
| Intent proposer stop | `./docker/run-resilience-campaign.sh consolidation-bootstrap-silent` | Stop the first intent proposer before agreement; rotate before nonce release and converge after restart. |
| Silent QUIC peer | `./docker/run-resilience-campaign.sh silent` | p1 remains HTTP-healthy but cannot exchange QUIC; common QUAL and later protocol-only epochs progress within `f`. |
| Silent deposit peer | `./docker/run-resilience-campaign.sh deposit-silent` | Certified allocation, mining, observation, and permanence within `f`; consolidation deliberately excluded. |
| Whole-party stop + exact refresh | `./docker/run-resilience-campaign.sh leader-down` | Stop p1 while allocation and signing remain live; the only seven responsive candidates must form identical epoch-1/2 4-of-7 committees, whose authenticated history digest proves `Refresh` rather than `Reshare`, before a real epoch-2 transaction is signed and confirmed. |
| Rotation omission | `./docker/run-resilience-campaign.sh rotation-silent` | Parse one actual certified epoch-4 member from the held latch, remove that party from peer QUIC at the dynamic boundary, then certify and activate an exact 3-of-5 successor from fresh advertisements supplied by the seven responsive eligible identities. |
| Whole-network restart | `./docker/run-resilience-campaign.sh network-restart` | After epoch 4 activates, record every party's exact persisted epoch-5 deadline, stop all eight party containers while retaining their named volumes, keep them stopped until every deadline is overdue, restart all eight in place, require one common epoch-5 public value at `n-f`, then allocate, fund, threshold-sign, broadcast, mine, and confirm a fresh epoch-5 consolidation. |
| Proactive refresh deadline | `./docker/run-resilience-campaign.sh proactive-deadline` | Parse one actual certified source member from the held latch and SIGKILL/restart that party in place inside the exact finite 15-second deadline; prove the hold survives restart with no start event, then require its authenticated write-ahead start timestamp to be durably recorded at or after the bound due time before successor activation. |
| QUAL crash plus omission | `./docker/run-resilience-campaign.sh qual-crash-silent` | With p1 omitted, hold p3 at exact undecided QUAL round zero, prove the hold across SIGKILL/restart, then release and restore reducer/outbox liveness. |
| Complete gate | `./docker/run-resilience-campaign.sh all` | Run every independent clean-state case in the order enforced by the script. |

The historical `leader-down` mode name identifies a whole-party availability case. Its pass
contract includes full consolidation and signing: rotating BFT intent and ROAST views must finish
without depending on that one party. It also produces the deterministic same-committee proactive
refresh witness: identical stable IDs, unchanged `key_id` and group spend key, fresh receiver and
verification shares, an independently derived refresh-purpose transition digest distinct from the
reshare digest, and the canonical daemon-accepted epoch-2 transaction.

Ordinary cases use the base stack's autonomous canonical epoch-zero DKG. Only `avss-crash` and
`qual-crash-silent` add `compose.acceptance-manual-bootstrap.yaml` and
`compose.acceptance-protocol-fault-gate.yaml`. The first gives the acceptance client deterministic
control of canonical DKG start. The second exposes an authenticated p3-only admin control which
durably binds either `DealerStarted` or `QualRoundZero`, freezes only that AVSS session under its
run lock, and requires an exact release after restart. Neither overlay is a normal deployment mode.
Every other case requires an observer-only autonomous-genesis marker recording zero acceptance
client calls to `/v1/avss/start`.

## Run strategy

During development, start with the smallest affected cases and then run `all`:

```sh
./docker/run-resilience-campaign.sh rust
./docker/run-resilience-campaign.sh deposit-ttl
./docker/run-resilience-campaign.sh consolidation-silent
./docker/run-resilience-campaign.sh consolidation-bootstrap-silent
./docker/run-resilience-campaign.sh rotation-silent
./docker/run-resilience-campaign.sh network-restart
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

To rerun a case while retaining its canonical project volumes:

```sh
TM_CAMPAIGN_PROJECT_SUFFIX=r001 ./docker/run-resilience-campaign.sh deposit-restart
```

An explicitly empty suffix is invalid; leave the variable unset for the canonical destructive
clean-state behavior.

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
   The TTL case additionally proves both sides of the exact unused-expiry boundary, monotonic
   sequence/index/address non-reuse, and retrieval of a used address at its expiry.
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
- complete bounded logs for all parties, all eight observers, the Regtest producer, and the
  acceptance client;
- process and network observations surrounding every injected fault;
- `required-markers.tsv`, containing the unique barrier and terminal-marker lines and their log
  positions;
- active epoch, activation, refresh, registry, scanner, and consolidation status after recovery; and
- the initial two-input transaction's `signed-transaction.hex`, decoded
  `signed-transaction.bin`, expected and independently derived Monero txids, verifier transcript,
  ancillary binary SHA-256, and daemon acceptance/confirmation evidence;
- `successor-epoch-signed-transactions.tsv` plus
  `successor-epoch-signed-transactions/epoch-{1..5}/`, with exactly one ordered single-input
  transaction per epoch and canonical hex, binary, expected/derived txids, verifier transcript,
  SHA-256, and evidence metadata for each;
- for `leader-down`, `exact-same-committee-refresh.env`, which binds identical epoch-1/2 member
  IDs, `Refresh` purpose, unchanged key identity and group key, fresh receiver and verification
  shares, distinct refresh/reshare transition digests, and the epoch-2 transaction artifact;
- for `network-restart`, `network-restart-containers.tsv`, the source and successor status/evidence
  files, the restored proactive-start event, exact stop/overdue/restart timestamps, and the canonical
  post-restart epoch-5 transaction artifact;
- for `deposit-ttl`, all six files under `deposit-clock-generations/`, their manifest and exact
  final-file comparison, the four semantic markers, the one-output funding transaction hex/binary
  and SHA-256, plus the producer daemon's exact mined transaction bytes and block height;
- the unique `TM_ACCEPTANCE_MULTI_INPUT_CONSOLIDATION` marker, bound to the initial transaction
  only after both certified outputs map bijectively to its two input rings;
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
- `n-f` deposit replicas agree that an unused allocation is visible through `expires_at - 1`,
  hidden exactly at `expires_at`, and cannot return its sequence, subaddress index, or address to
  the allocation pool, while first-use evidence keeps a funded address permanent after expiry;
- a due refresh survives restart and autonomously begins the immediate successor; and
- after all party processes are simultaneously stopped across a persisted overdue deadline, an
  in-place restart restores one common successor at `n-f` and can threshold-sign a new transaction;
- the post-restart transaction is allocated and funded only after that common successor is observed,
  so a pre-restart signature cannot satisfy the persistence case; and
- every configured or dynamic successor uses a source `n-f` Byzantine certificate to select an
  exact `desired_n` committee solely from fresh eligible receiver-key advertisements before AVSS.

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

Public-network deployment and its evidence are outside this Regtest acceptance campaign. The
current source makes no public-testnet or mainnet readiness claim, and mainnet party mode should
remain disabled.
