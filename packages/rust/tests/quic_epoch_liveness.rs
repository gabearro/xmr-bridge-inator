use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    io::Cursor,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use curve25519_dalek::{
    Scalar as DalekScalar, constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY,
};
use monero_wallet::{
    WalletOutput,
    ed25519::{Commitment, Scalar},
    transaction::Timelock,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use reqwest::{Client, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use threshold_monero::{
    PartyId, SessionId,
    auth::{
        AuthRole, BEARER_AUTH_SCHEMA_VERSION, BearerAuthConfig, BearerAuthenticator,
        BearerCredentialConfig, bearer_token_digest,
    },
    avss::{AvssConfig, AvssDealer, AvssPayload, PrivateAvssMessage},
    compact_epoch_registry::CompactEpochRegistry,
    compact_registry_store::CompactRegistryStoreCheckpoint,
    config::{CommitteeSpec, Hex32, NetworkKind, Operation, Scenario, ScenarioParty},
    deposit_archive::{
        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT, CERTIFIED_LEDGER_ENTRY_ARTIFACT,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT, DepositArchiveStore,
        MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS,
    },
    deposit_consensus::{CommitCertificate, DepositConsensus},
    deposit_index::{DepositIndexBuilder, DepositIndexObjectId, DepositIndexReader},
    deposit_index_checkpoint::{
        DepositIndexCheckpointCandidate, DepositIndexCheckpointCertificate,
        DepositIndexCheckpointOperation, DepositIndexCheckpointStatement, PortableDepositIndexHead,
        deposit_index_checkpoint_consensus_context,
    },
    deposit_index_store::{DepositIndexStoreCheckpoint, VerifiedPortableIndexAdvance},
    deposit_ledger::{
        CertifiedDepositObservation, CertifiedLedgerEntry, DepositObservationStatement,
        LedgerRequestId, RequestBinding,
    },
    deposit_service::DepositAddressRequest,
    deposit_sync_stage::{DepositSyncSpoolAdmission, DepositSyncSpoolManager},
    deposit_sync_wire::{
        DepositSyncAdvertisement, DepositSyncContext, DepositSyncHeadRequest,
        DepositSyncHeadResponse, DepositSyncObject, DepositSyncObjectCapability,
        DepositSyncObjectPage, DepositSyncObjectPageRequest, DepositSyncObjectRef,
        DepositSyncReleaseAck, DepositSyncReleaseRequest, MAX_DEPOSIT_SYNC_REQUEST_OBJECTS,
    },
    deposit_wallet::{
        ChainPoint, DepositAddressDeriver, DepositWalletId, PersistedWalletOutput, ScannedBlock,
        WalletOutputId,
    },
    deposit_worker::{
        ChainFuture, ChainSourceError, DepositBlockScanResult, DepositChainSource,
        DepositOutputIndexBackend, DepositWorkerConfig, FetchedDepositBlock,
        FetchedDepositBlockEvidence, MoneroRpcLimits,
    },
    epoch_history::EpochHistoryParent,
    identity::{EpochEncryptionSecret, Identity},
    keys::EpochPublic,
    qual::{QualMessage, QualMessageBody},
    quic_runtime::{QuicRuntime, QuicRuntimeConfig},
    quic_transport::{
        DepositOperation, LocalTlsIdentity, PeerRequest, PeerResponse, PinnedPeerCertificate,
        QuicPeerEndpoint, QuicTransportConfig, RejectionCode, RequestId,
    },
    reconnecting_monero::ReconnectingMoneroDaemon,
    server::{
        AvssStartRequest, AvssStepResponse, AvssTransition, DealPurpose, DepositHttpResponse,
        DepositHttpStatus, PartyDepositConfig, PartyServer, PartyStatus, PeerMessageId,
        PendingPeerMessage, canonical_dkg_identity,
    },
    storage::{ShareStore, StoreError, WalletArtifactStore},
};
use tokio::{sync::Notify, task::JoinHandle, time::Instant};
use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

// These six black-box cases each create a multi-threaded QUIC runtime and assert real wall-clock
// protocol deadlines. Running the whole integration-test binary in parallel can create 44 Tokio
// workers and turn host scheduling contention into false liveness failures. Acquire this
// synchronous gate before constructing any runtime so only this resource-intensive binary is
// serial while the rest of the repository's tests remain parallel.
static QUIC_EPOCH_LIVENESS_TEST_GATE: StdMutex<()> = StdMutex::new(());

const ADMIN_TOKEN: &[u8] = b"quic-epoch-test-admin-token-0000000000000000";
const DEPOSIT_TOKEN: &[u8] = b"quic-epoch-test-deposit-token-000000000000";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
// Key-rotation views use the same 10-second base with exponential backoff. Reaching view two can
// require 10+20 seconds after the latest participant's independently persisted due time, before
// QUIC relay, AVSS, and activation work. Keep the ordinary request/test bound tight while giving
// the autonomous multi-view lifecycle a protocol-aligned envelope.
const AUTONOMOUS_EPOCH_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const LIVE_QUAL_TIMEOUT: Duration = Duration::from_secs(10);
const MANUAL_QUAL_TIMEOUT: Duration = Duration::from_millis(100);
const SILENT_LEADER_QUAL_TIMEOUT: Duration = Duration::from_millis(500);
const DEPOSIT_SYNC_TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const DEPOSIT_SYNC_TEST_SOURCE_TIMEOUT: Duration = Duration::from_secs(4);
const DEPOSIT_SYNC_TEST_TICK_TIMEOUT: Duration = Duration::from_secs(6);
// Every runtime gets an immediate compact-sync tick. The four replicas which are already advancing
// the live source quorum do not need to poll one another while this test constructs the archive;
// doing so only contends with the consensus reducers whose output they already share. The late
// replica retains a short recurring interval because its crash/resume and source-failover paths are
// the compact-sync behavior under test. In particular, its next tick releases the exact source pin
// after an adoption before the replica is intentionally stopped.
const DEPOSIT_SOURCE_SYNC_TEST_INTERVAL: Duration = Duration::from_secs(60 * 60);
const DEPOSIT_LATE_SYNC_TEST_INTERVAL: Duration = Duration::from_secs(2);
// The large-archive phase performs repeated durable frontier batches after every normal source
// runtime has stopped. Accelerate only that isolated late-replica poller; request, source-pin, and
// whole-tick deadlines remain unchanged and therefore retain their real failover semantics.
const DEPOSIT_LARGE_SYNC_TEST_INTERVAL: Duration = Duration::from_millis(20);
const DEPOSIT_LARGE_SYNC_PROGRESS_TIMEOUT: Duration = Duration::from_secs(120);
// A fresh failover lease must replay the complete source-bound graph. Its final compact-registry
// chain reveals one authenticated successor per response, and every cursor advance remains
// crash-safe, so this bound is intentionally larger than the first wide-page progress gate.
const DEPOSIT_LARGE_SYNC_IMPORT_TIMEOUT: Duration = Duration::from_secs(300);
const DEPOSIT_PROGRESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
// Observation publication includes scanner attestation, checkpoint BA, a separate n-f checkpoint
// witness round, and the final authenticated index/archive commit. BA may consume a complete
// configured 30-second view and one retry; witness publication and the final archive/index CAS
// then need their own execution budget instead of expiring while a live quorum is still advancing.
const DEPOSIT_CHECKPOINT_TEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct TlsMaterial {
    server_name: String,
    certificate: CertificateDer<'static>,
    private_key: Vec<u8>,
}

impl TlsMaterial {
    fn generate(party: PartyId) -> Self {
        let server_name = format!("p{}.quic-liveness.invalid", party.0);
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![server_name.clone()]).unwrap();
        Self {
            server_name,
            certificate: cert.der().clone(),
            private_key: signing_key.serialize_der(),
        }
    }

    fn local_identity(&self) -> LocalTlsIdentity {
        LocalTlsIdentity::new(
            vec![self.certificate.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key.clone())),
        )
        .unwrap()
    }

    fn pin(&self, party: PartyId) -> PinnedPeerCertificate {
        PinnedPeerCertificate {
            party,
            server_name: self.server_name.clone(),
            leaf_certificate: self.certificate.clone(),
        }
    }
}

struct RunningNode {
    runtime: Arc<QuicRuntime>,
    runtime_task: JoinHandle<Result<(), threshold_monero::quic_runtime::QuicRuntimeError>>,
    admin_task: JoinHandle<anyhow::Result<()>>,
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        // A failed assertion must not detach process-lifetime QUIC/HTTP tasks. In particular,
        // `PartyServer::serve` otherwise waits for the process signal handler and can make the
        // enclosing Tokio runtime block forever while unwinding a test failure.
        self.runtime.shutdown();
        self.runtime_task.abort();
        self.admin_task.abort();
    }
}

struct AbortOnDropTask<T>(JoinHandle<T>);

impl<T> AbortOnDropTask<T> {
    fn new(task: JoinHandle<T>) -> Self {
        Self(task)
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<T> {
        &mut self.0
    }

    fn abort(&self) {
        self.0.abort();
    }

    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct RunningEndpointTask {
    endpoint: Arc<QuicPeerEndpoint>,
    task: JoinHandle<()>,
}

impl Drop for RunningEndpointTask {
    fn drop(&mut self) {
        self.endpoint.close(b"test endpoint task dropped");
        self.task.abort();
    }
}

struct QuicAttachmentGuard(Arc<PartyServer>);

impl QuicAttachmentGuard {
    fn attach(server: Arc<PartyServer>) -> Self {
        server.mark_quic_runtime_attached().unwrap();
        Self(server)
    }
}

impl Drop for QuicAttachmentGuard {
    fn drop(&mut self) {
        self.0.mark_quic_runtime_detached();
    }
}

/// Bound the explicit production-stack Tokio runtime's failure cleanup.
///
/// Tokio's ordinary runtime drop waits indefinitely for blocking-pool work. The node-level Drop
/// above is the primary cleanup path; this outer guard is the last-resort bound for a panic while a
/// filesystem operation is already running on the blocking pool.
struct BoundedTestRuntime(Option<tokio::runtime::Runtime>);

impl BoundedTestRuntime {
    fn runtime(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("bounded test runtime was already shut down")
    }
}

impl Drop for BoundedTestRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(Duration::from_secs(5));
        }
    }
}

fn run_quic_epoch_liveness_test<F>(worker_threads: usize, thread_stack_size: Option<usize>, test: F)
where
    F: Future<Output = ()>,
{
    let _test_gate =
        QUIC_EPOCH_LIVENESS_TEST_GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(worker_threads).enable_all();
    if let Some(thread_stack_size) = thread_stack_size {
        builder.thread_stack_size(thread_stack_size);
    }
    let runtime = BoundedTestRuntime(Some(builder.build().unwrap()));
    runtime.runtime().block_on(test);
}

struct TestNode {
    party: PartyId,
    signing_seed: [u8; 32],
    bootstrap_x25519_secret: [u8; 32],
    state_directory: PathBuf,
    quic_address: SocketAddr,
    admin_address: SocketAddr,
    server: Option<Arc<PartyServer>>,
    running: Option<RunningNode>,
}

impl TestNode {
    fn server(&self) -> &Arc<PartyServer> {
        self.server.as_ref().expect("test node server is not installed")
    }

    async fn restore_server(&mut self, scenario: &Scenario) {
        drop(self.server.take().expect("test node server is not installed"));
        let bootstrap = scenario
            .genesis_committee()
            .unwrap()
            .member(self.party)
            .is_ok()
            .then_some(&self.bootstrap_x25519_secret);
        self.server = Some(
            PartyServer::new(
                self.party,
                scenario.clone(),
                self.state_directory.clone(),
                &self.signing_seed,
                bootstrap,
            )
            .await
            .expect("persisted party state did not restore"),
        );
    }

    fn start_runtime(
        &mut self,
        scenario: &Scenario,
        tls: &BTreeMap<PartyId, TlsMaterial>,
        authenticator: BearerAuthenticator,
    ) {
        self.start_runtime_with_qual_timeout(scenario, tls, authenticator, LIVE_QUAL_TIMEOUT);
    }

    fn start_runtime_with_qual_timeout(
        &mut self,
        scenario: &Scenario,
        tls: &BTreeMap<PartyId, TlsMaterial>,
        authenticator: BearerAuthenticator,
        qual_round_timeout: Duration,
    ) {
        assert!(self.running.is_none());
        let endpoint = endpoint_for(
            self.party,
            self.quic_address,
            scenario,
            tls,
            QuicTransportConfig {
                handshake_timeout: Duration::from_secs(3),
                stream_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(20),
                keep_alive_interval: Some(Duration::from_secs(1)),
                ..Default::default()
            },
        );
        let runtime = Arc::new(
            QuicRuntime::new(
                endpoint,
                self.server().clone(),
                QuicRuntimeConfig {
                    outbox_poll_interval: Duration::from_millis(25),
                    protocol_progress_interval: Duration::from_millis(20),
                    retry_initial: Duration::from_millis(20),
                    retry_maximum: Duration::from_millis(250),
                    qual_round_timeout: Some(qual_round_timeout),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        self.server().mark_quic_runtime_attached().unwrap();
        let runtime_task = tokio::spawn(runtime.clone().run());
        let server = self.server().clone();
        let address = self.admin_address;
        let admin_task = tokio::spawn(async move { server.serve(address, authenticator).await });
        self.running = Some(RunningNode { runtime, runtime_task, admin_task });
    }
}

/// Abort the listener/runtime futures without invoking the node's graceful-shutdown path.
///
/// This shared-process harness waits below for cancellation-shielded reducer publications so the
/// replacement can acquire the exclusive state lease. It therefore exercises restart from a
/// complete durable record, not termination inside a storage CAS. Storage tests cover the atomic
/// old-or-new record boundary; the Docker resilience campaign exercises actual process SIGKILL.
async fn crash_node(node: &mut TestNode) {
    let quic_address = node.quic_address;
    let mut tasks = node.running.take().expect("test node is not running");
    node.server().mark_quic_runtime_detached();
    tasks.runtime_task.abort();
    tasks.admin_task.abort();
    let _ = (&mut tasks.runtime_task).await;
    let _ = (&mut tasks.admin_task).await;
    // Aborting the outer runtime deliberately invokes no graceful-shutdown checkpoint. Quinn
    // connection/handshake tasks can nevertheless retain endpoint clones until transport closure
    // wakes them, so release that resource boundary explicitly and without a timing sleep.
    tasks.runtime.terminate_transport_after_task_abort().await;
    drop(tasks);
    // All parties share this test process, unlike the production one-process-per-party topology.
    // A reducer commit deliberately detached from a cancelled request may therefore retain the
    // old PartyServer for a few scheduler turns after the node runtime is aborted. Wait for that
    // cancellation-shielded publication to finish so the replacement can acquire the exclusive
    // state lease; this is intentionally not a simulation of termination inside that commit.
    tokio::time::timeout(Duration::from_secs(5), async {
        while Arc::strong_count(node.server()) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("runtime-abort restart left a detached party-state owner alive");
    wait_for_released_quic_socket(quic_address).await;
}

async fn wait_for_released_quic_socket(quic_address: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async move {
        loop {
            match std::net::UdpSocket::bind(quic_address) {
                Ok(probe) => {
                    drop(probe);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("cannot probe released QUIC address {quic_address}: {error}"),
            }
        }
    })
    .await
    .expect("node restart did not release the QUIC socket");
}

async fn stop_node(node: &mut TestNode) {
    let mut tasks = node.running.take().expect("test node is not running");
    node.server().mark_quic_runtime_detached();
    tasks.runtime.shutdown();
    tasks.admin_task.abort();
    tokio::time::timeout(Duration::from_secs(10), &mut tasks.runtime_task)
        .await
        .expect("party QUIC runtime ignored shutdown")
        .expect("party QUIC runtime task panicked")
        .expect("party QUIC runtime returned an error");
    let _ = (&mut tasks.admin_task).await;
    // The endpoint driver can outlive its final handle for a scheduler turn. Model process
    // socket teardown before rebinding this address, just as the abrupt-restart path does.
    drop(tasks);
    wait_for_released_quic_socket(node.quic_address).await;
}

async fn stop_all(nodes: &mut BTreeMap<PartyId, TestNode>) {
    let mut running = Vec::with_capacity(nodes.len());
    for node in nodes.values_mut() {
        if let Some(tasks) = node.running.take() {
            node.server().mark_quic_runtime_detached();
            tasks.runtime.shutdown();
            tasks.admin_task.abort();
            running.push((node.party, tasks));
        }
    }
    for (party, mut tasks) in running {
        let result = tokio::time::timeout(Duration::from_secs(10), &mut tasks.runtime_task)
            .await
            .unwrap_or_else(|_| panic!("party {party} QUIC runtime ignored shutdown"))
            .unwrap_or_else(|error| panic!("party {party} QUIC runtime task panicked: {error}"));
        result.unwrap_or_else(|error| {
            panic!("party {party} QUIC runtime returned an error: {error}")
        });
        let _ = (&mut tasks.admin_task).await;
    }
}

#[derive(Default)]
struct QualStats {
    messages: BTreeSet<PeerMessageId>,
    maximum_round: Option<u64>,
}

impl QualStats {
    fn observe(&mut self, message_id: PeerMessageId, wire_payload: &[u8]) {
        let message: QualMessage = postcard::from_bytes(wire_payload).unwrap();
        let round = match message.body {
            QualMessageBody::Proposal(proposal) => proposal.round,
            QualMessageBody::Vote(vote) => vote.round,
            QualMessageBody::RoundChange(change) => change.round,
            QualMessageBody::NewRound(new_round) => new_round.round,
        };
        self.messages.insert(message_id);
        self.maximum_round = Some(self.maximum_round.map_or(round, |found| found.max(round)));
    }
}

fn signing_seed(party: PartyId) -> [u8; 32] {
    let mut seed = [u8::try_from(party.0).unwrap().wrapping_mul(17); 32];
    seed[..2].copy_from_slice(&party.0.to_le_bytes());
    seed
}

fn bootstrap_x25519_secret(party: PartyId) -> [u8; 32] {
    let mut secret = [0x58; 32];
    secret[1..3].copy_from_slice(&party.0.to_le_bytes());
    secret[3..11].copy_from_slice(b"quiclive");
    secret
}

fn identity_from_explicit_secrets(
    party: PartyId,
    epoch: u64,
    signing_seed: &[u8; 32],
    x25519_secret: [u8; 32],
) -> Identity {
    let encryption_public_key =
        EncryptionPublicKey::from(&StaticSecret::from(x25519_secret)).to_bytes();
    let persisted = EpochEncryptionSecret::from_decrypted(
        party,
        epoch,
        encryption_public_key,
        Zeroizing::new(x25519_secret),
    )
    .unwrap();
    Identity::from_encryption_secret(
        party,
        epoch,
        signing_seed,
        Identity::signing_public_key_from_seed(signing_seed).unwrap(),
        encryption_public_key,
        &persisted,
    )
    .unwrap()
}

fn deposit_private_view_scalar() -> [u8; 32] {
    DalekScalar::from(7_u64).to_bytes()
}

fn mock_deposit_block(
    height: u64,
    hash: u8,
    parent: u8,
    outputs: Vec<PersistedWalletOutput>,
) -> FetchedDepositBlock {
    FetchedDepositBlock {
        block: ScannedBlock {
            point: ChainPoint::new(height, [hash; 32]).unwrap(),
            parent_hash: [parent; 32],
        },
        // Every simulated replica must observe one canonical header for a given block hash.
        // Wall-clock-derived timestamps can differ when replicas are advanced across a second
        // boundary, which correctly looks like a same-hash Byzantine header equivocation.
        timestamp: 1_700_000_000_u64.saturating_add(height),
        hardfork_version: 16,
        outputs,
        root_outputs: vec![],
    }
}

fn mock_confirmed_deposit_output(root_spend_key: [u8; 32]) -> PersistedWalletOutput {
    let key_offset = DalekScalar::from(9_u64);
    let root_spend_key = CompressedEdwardsY(root_spend_key).decompress().unwrap();
    let output_key = root_spend_key + (ED25519_BASEPOINT_POINT * key_offset);
    let commitment = Commitment::new(Scalar::from(DalekScalar::from(77_u64)), 10_000_000);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xD1; 32]);
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&99_u64.to_le_bytes());
    bytes.extend_from_slice(&output_key.compress().to_bytes());
    bytes.extend_from_slice(&key_offset.to_bytes());
    commitment.write(&mut bytes).unwrap();
    Timelock::None.write(&mut bytes).unwrap();
    bytes.push(1);
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(0);
    bytes.push(0);
    let mut reader = Cursor::new(bytes.as_slice());
    let output = WalletOutput::read(&mut reader).unwrap();
    assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
    PersistedWalletOutput::from_scanner(&output).unwrap()
}

#[derive(Clone)]
struct QuicDepositChain {
    latest: Arc<AtomicU64>,
    blocks: Arc<RwLock<BTreeMap<u64, FetchedDepositBlock>>>,
}

impl QuicDepositChain {
    fn genesis_only() -> Self {
        Self {
            latest: Arc::new(AtomicU64::new(0)),
            blocks: Arc::new(RwLock::new(BTreeMap::from([(
                0,
                mock_deposit_block(0, 0xA0, 0, vec![]),
            )]))),
        }
    }

    fn push_confirmed_deposit(&self, root_spend_key: [u8; 32]) {
        self.blocks.write().unwrap().insert(
            1,
            mock_deposit_block(1, 0xA1, 0xA0, vec![mock_confirmed_deposit_output(root_spend_key)]),
        );
        self.latest.store(1, Ordering::SeqCst);
    }
}

impl DepositChainSource for QuicDepositChain {
    fn latest_height(&self) -> ChainFuture<'_, u64> {
        Box::pin(async move { Ok(self.latest.load(Ordering::SeqCst)) })
    }

    fn block_hash(&self, height: u64) -> ChainFuture<'_, [u8; 32]> {
        Box::pin(async move {
            self.blocks
                .read()
                .unwrap()
                .get(&height)
                .map(|block| block.block.point.hash)
                .ok_or_else(|| ChainSourceError::Rpc(format!("missing mock block {height}")))
        })
    }

    fn scanned_block_evidence<'a>(
        &'a self,
        height: u64,
        _deriver: &'a DepositAddressDeriver,
        _output_index: &'a dyn DepositOutputIndexBackend,
        _portable_snapshot: [u8; 32],
        _resume: Option<threshold_monero::deposit_worker::DepositBlockScanCursor>,
    ) -> ChainFuture<'a, DepositBlockScanResult> {
        Box::pin(async move {
            let block = self
                .blocks
                .read()
                .unwrap()
                .get(&height)
                .cloned()
                .ok_or_else(|| ChainSourceError::Rpc(format!("missing mock block {height}")))?;
            Ok(DepositBlockScanResult::Complete(FetchedDepositBlockEvidence {
                block,
                transactions: vec![],
                transaction_key_images: vec![],
                transaction_key_images_complete: true,
            }))
        })
    }
}

fn deposit_config(
    chain: Arc<QuicDepositChain>,
    backend: Arc<ReconnectingMoneroDaemon>,
) -> PartyDepositConfig {
    PartyDepositConfig {
        private_view_scalar: Zeroizing::new(deposit_private_view_scalar()),
        birth_anchor: None,
        worker: DepositWorkerConfig {
            confirmation_depth: 1,
            request_timeout_millis: 250,
            ..Default::default()
        },
        chain_source: chain,
        consolidation_backend: backend.clone(),
        chain_readiness: backend.readiness(),
    }
}

fn scenario(
    root: &TempDir,
    admin_addresses: &BTreeMap<PartyId, SocketAddr>,
    tls: &BTreeMap<PartyId, TlsMaterial>,
) -> Scenario {
    let parties = (1_u16..=8)
        .map(|id| {
            let party = PartyId(id);
            let signing_seed = signing_seed(party);
            let bootstrap_x25519_secret = bootstrap_x25519_secret(party);
            let bootstrap_identity =
                identity_from_explicit_secrets(party, 0, &signing_seed, bootstrap_x25519_secret);
            ScenarioParty {
                id: party,
                admin_endpoint: format!("http://{}", admin_addresses[&party]).parse().unwrap(),
                // Endpoints are replaced with their bound ephemeral ports before validation.
                quic_endpoint: format!("quic://127.0.0.1:{}", 30_000 + id).parse().unwrap(),
                quic_server_name: tls[&party].server_name.clone(),
                quic_certificate_file: root.path().join(format!("p{id}-certificate.der")),
                monerod_rpc_urls: vec![
                    format!("http://127.0.0.1:{}", 40_000 + id).parse().unwrap(),
                ],
                signing_key: Hex32(bootstrap_identity.signing_public_key()),
                bootstrap_encryption_key: Hex32(bootstrap_identity.encryption_public_key()),
            }
        })
        .collect();
    Scenario {
        schema_version: threshold_monero::config::SCENARIO_SCHEMA_VERSION,
        demo_only: true,
        network: NetworkKind::Regtest,
        deposit_birth_anchor: None,
        acceptance_monerod_rpc_url: "http://127.0.0.1:18081".parse().unwrap(),
        parties,
        committees: vec![
            CommitteeSpec {
                epoch: 0,
                operation: Operation::Dkg,
                threshold: 3,
                fault_bound: 1,
                members: (1_u16..=5).map(PartyId).collect(),
                eligible_members: (1_u16..=5).map(PartyId).collect(),
            },
            CommitteeSpec {
                epoch: 1,
                operation: Operation::Reshare,
                threshold: 4,
                fault_bound: 1,
                members: (1_u16..=6).map(PartyId).collect(),
                eligible_members: (1_u16..=7).map(PartyId).collect(),
            },
            CommitteeSpec {
                epoch: 2,
                operation: Operation::Reshare,
                threshold: 3,
                fault_bound: 1,
                members: [PartyId(2), PartyId(3), PartyId(4), PartyId(6), PartyId(7)].into(),
                eligible_members: [
                    PartyId(2),
                    PartyId(3),
                    PartyId(4),
                    PartyId(6),
                    PartyId(7),
                    PartyId(8),
                ]
                .into(),
            },
        ],
        funding_blocks: 1,
        confirmation_blocks: 1,
        deposit_maximum_fee_atomic_units: 1_000_000_000,
        poll_interval_ms: 10,
        protocol_timeout_seconds: TEST_TIMEOUT.as_secs(),
        proactive_refresh_interval_seconds: 1,
    }
}

fn endpoint_for(
    party: PartyId,
    address: SocketAddr,
    scenario: &Scenario,
    tls: &BTreeMap<PartyId, TlsMaterial>,
    config: QuicTransportConfig,
) -> QuicPeerEndpoint {
    let peers = tls
        .iter()
        .filter(|(peer, _)| **peer != party)
        .map(|(peer, material)| material.pin(*peer))
        .collect::<Vec<_>>();
    QuicPeerEndpoint::bind(
        address,
        party,
        scenario.quic_network_id().unwrap(),
        tls[&party].local_identity(),
        peers,
        config,
    )
    .unwrap()
}

/// Build a second, independently randomized DealerSend under the exact production AVSS wire
/// domain. This is deliberately test-local Byzantine authority: the stable signing/X25519
/// identity belongs to `dealer`, while the polynomial is not the one durably retained by that
/// party's honest reducer.
fn seal_conflicting_refresh_dealer_send(
    identity: &Identity,
    transition: &AvssTransition,
    private: PrivateAvssMessage,
    rng: &mut ChaCha20Rng,
) -> threshold_monero::server::AvssWire {
    const AVSS_WIRE_VERSION: u16 = 2;

    assert_eq!(transition.purpose, DealPurpose::Refresh);
    let dealer = private.message.instance.dealer;
    assert_eq!(identity.party(), dealer);
    assert_eq!(private.message.instance.session, transition.session);
    assert_eq!(private.message.instance.receiver_committee, transition.target.digest());
    assert_eq!(private.message.instance.receiver_epoch, transition.target.epoch);
    assert_eq!(private.message.instance.threshold, transition.target.threshold);
    assert_eq!(private.message.instance.fault_bound, transition.fault_bound);
    assert!(matches!(&private.message.payload, AvssPayload::DealerSend(_)));
    transition.target.member(private.recipient).unwrap();

    let sequence = (u64::from(dealer.0) << 32) | u64::from(private.recipient.0);
    let mut binding = blake3::Hasher::new_derive_key("threshold-monero/avss-wire-aead/v2");
    binding.update(&[1]);
    binding.update(&transition.session.0);
    binding.update(&transition.key_id);
    binding.update(&transition.fault_bound.to_le_bytes());
    binding.update(&transition.old.as_ref().map_or([0; 32], |old| old.committee.digest()));
    binding.update(&transition.target.digest());
    binding.update(&dealer.0.to_le_bytes());
    binding.update(&dealer.0.to_le_bytes());
    binding.update(&private.recipient.0.to_le_bytes());
    binding.update(&sequence.to_le_bytes());
    for selected in &transition.eligible_dealers {
        binding.update(&selected.0.to_le_bytes());
    }
    let binding = *binding.finalize().as_bytes();

    let mut plaintext = postcard::to_allocvec(&private.message).unwrap();
    let encrypted = identity
        .encrypt_bound(
            &transition.target,
            transition.session,
            private.recipient,
            &binding,
            &plaintext,
            rng,
        )
        .unwrap();
    plaintext.zeroize();
    let payload = postcard::to_allocvec(&encrypted).unwrap();
    let old = transition.old.as_ref().expect("refresh omitted its source epoch");
    assert_ne!(old.committee.digest(), transition.target.digest());
    let envelope = identity
        .sign_envelope(&old.committee, transition.session, None, sequence, payload)
        .unwrap();
    threshold_monero::server::AvssWire {
        version: AVSS_WIRE_VERSION,
        dealer,
        recipient: private.recipient,
        envelope,
    }
}

async fn send_authenticated_peer_request(
    endpoint: &QuicPeerEndpoint,
    scenario: &Scenario,
    recipient: PartyId,
    request: PeerRequest,
) -> PeerResponse {
    let configured = scenario.party(recipient).unwrap();
    let remote = configured
        .quic_endpoint
        .socket_addrs(|| None)
        .unwrap()
        .into_iter()
        .next()
        .expect("test QUIC endpoint did not resolve");
    let connection = endpoint.connect(recipient, remote).await.unwrap();
    let request_id = RequestId::for_peer_request(
        endpoint.network_id(),
        endpoint.local_party(),
        recipient,
        &request,
    )
    .unwrap();
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let response = connection.request(request_id, request.clone()).await.unwrap();
        if matches!(
            &response,
            PeerResponse::Rejected {
                code: RejectionCode::Unavailable,
                retryable: true,
                message,
            } if message == "the identical authenticated request is already in flight"
        ) {
            assert!(
                Instant::now() < deadline,
                "identical authenticated request remained in flight past the test deadline"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        return response;
    }
}

/// Authenticated Byzantine peer which completes TLS but never answers a request stream.
///
/// In particular this models a low-ID epoch-history source returning just under the transport
/// deadline forever. Per-peer stream limits remain enforced by QUIC; honest peers must still
/// advance the core protocol pacemaker.
fn start_authenticated_blackhole(endpoint: QuicPeerEndpoint) -> RunningEndpointTask {
    let endpoint = Arc::new(endpoint);
    let listener = endpoint.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(connection) => {
                        connections.spawn(async move {
                            let mut held_requests = tokio::task::JoinSet::new();
                            loop {
                                match connection.accept_request().await {
                                    Ok(incoming) => {
                                        held_requests.spawn(async move {
                                            let _incoming = incoming;
                                            std::future::pending::<()>().await;
                                        });
                                    }
                                    Err(_) => break,
                                }
                            }
                            held_requests.abort_all();
                        });
                    }
                    Err(_) => break,
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        connections.abort_all();
    });
    RunningEndpointTask { endpoint, task }
}

#[derive(Default)]
struct OfflineDepositIndexReader {
    objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
}

impl DepositIndexReader for OfflineDepositIndexReader {
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, threshold_monero::deposit_index::DepositIndexError> {
        Ok(self.objects.get(&id).cloned())
    }
}

struct OfflineDepositSyncFixture {
    advertisement: DepositSyncAdvertisement,
    objects: BTreeMap<DepositSyncObjectRef, Vec<u8>>,
}

#[derive(serde::Serialize)]
struct OfflineDepositObservationAttestation {
    version: u16,
    wallet: DepositWalletId,
    allocation_sequence: u64,
    output: WalletOutputId,
    statement: [u8; 32],
}

fn offline_deposit_sync_mac_key(source: PartyId) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/quic-liveness-offline-sync-source/v1");
    hasher.update(&source.0.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn offline_deposit_sync_head_response(
    source: PartyId,
    requester: PartyId,
    fixture: &OfflineDepositSyncFixture,
) -> DepositSyncHeadResponse {
    let request =
        DepositSyncHeadRequest::new(fixture.advertisement.context(), source, requester).unwrap();
    DepositSyncHeadResponse::issue(
        request,
        fixture.advertisement.clone(),
        &offline_deposit_sync_mac_key(source),
    )
    .unwrap()
}

fn certify_offline_checkpoint_candidate(
    network: [u8; 32],
    registry: &CompactEpochRegistry,
    checkpoint_sequence: u64,
    previous_head: &PortableDepositIndexHead,
    candidate: DepositIndexCheckpointCandidate,
    identities: &BTreeMap<PartyId, Identity>,
) -> CommitCertificate {
    let context = deposit_index_checkpoint_consensus_context(
        network,
        registry,
        checkpoint_sequence,
        previous_head,
    )
    .unwrap();
    let value = candidate.to_consensus_value().unwrap();
    let mut reducers = identities
        .keys()
        .copied()
        .map(|party| (party, DepositConsensus::new(context.clone(), party).unwrap()))
        .collect::<BTreeMap<_, _>>();
    let mut queue = VecDeque::new();
    for (party, reducer) in &mut reducers {
        let step = reducer.start(&identities[party], value.clone()).unwrap();
        queue.extend(step.broadcast);
        if let Some(commit) = step.commit {
            return commit;
        }
    }
    while let Some(envelope) = queue.pop_front() {
        for (party, reducer) in &mut reducers {
            let step =
                reducer.handle_structurally_valid(&identities[party], envelope.clone()).unwrap();
            queue.extend(step.broadcast);
            if let Some(commit) = step.commit {
                return commit;
            }
        }
    }
    panic!("offline checkpoint consensus did not commit");
}

fn certify_offline_observation(
    registry: &CompactEpochRegistry,
    identities: &BTreeMap<PartyId, Identity>,
    statement: DepositObservationStatement,
) -> CertifiedDepositObservation {
    let payload = postcard::to_allocvec(&OfflineDepositObservationAttestation {
        version: 1,
        wallet: statement.wallet_id(),
        allocation_sequence: statement.allocation_sequence(),
        output: statement.output(),
        statement: statement.digest(),
    })
    .unwrap();
    let required = usize::from(
        registry.active().committee().n().checked_sub(registry.active().fault_bound()).unwrap(),
    );
    let attestations = identities
        .values()
        .take(required)
        .map(|identity| {
            identity
                .sign_envelope(
                    registry.active().committee(),
                    statement.session(),
                    None,
                    statement.allocation_sequence(),
                    payload.clone(),
                )
                .unwrap()
        })
        .collect();
    let observation = CertifiedDepositObservation { statement, attestations };
    observation.verify_active(registry).unwrap();
    observation
}

async fn collect_deposit_sync_objects(
    directory: &Path,
    party: PartyId,
    identity_seed: &[u8; 32],
    advertisement: &DepositSyncAdvertisement,
) -> BTreeMap<DepositSyncObjectRef, Vec<u8>> {
    let store = WalletArtifactStore::new(directory, party, identity_seed).unwrap();
    let request = DepositSyncHeadRequest::new(advertisement.context(), party, PartyId(5)).unwrap();
    let response = DepositSyncHeadResponse::issue(
        request,
        advertisement.clone(),
        &offline_deposit_sync_mac_key(party),
    )
    .unwrap();
    let mut pending = VecDeque::from(response.lease().root_targets().unwrap());
    let mut visited = BTreeSet::new();
    let mut objects = BTreeMap::new();
    while let Some(target) = pending.pop_front() {
        if !visited.insert(target) {
            continue;
        }
        let reference = target.reference();
        let artifact = store.load_artifact(reference.storage_reference().unwrap()).await.unwrap();
        let bytes = artifact.contents.into_bytes();
        let object = DepositSyncObject::new(reference, bytes.clone()).unwrap();
        pending.extend(object.authenticated_semantic_children(target).unwrap());
        if let Some(existing) = objects.insert(reference, bytes.clone()) {
            assert_eq!(existing, bytes, "one content address resolved to different plaintext");
        }
    }
    objects
}

fn authenticate_offline_deposit_sync_graph(
    source: PartyId,
    advertisement: &DepositSyncAdvertisement,
    objects: &BTreeMap<DepositSyncObjectRef, Vec<u8>>,
) {
    let request = DepositSyncHeadRequest::new(advertisement.context(), source, PartyId(5)).unwrap();
    let response = DepositSyncHeadResponse::issue(
        request,
        advertisement.clone(),
        &offline_deposit_sync_mac_key(source),
    )
    .unwrap();
    let mut pending = VecDeque::from(response.lease().root_targets().unwrap());
    let mut visited = BTreeSet::new();
    while let Some(target) = pending.pop_front() {
        if !visited.insert(target) {
            continue;
        }
        let reference = target.reference();
        let bytes = objects
            .get(&reference)
            .unwrap_or_else(|| panic!("offline fixture omitted reachable object {reference:?}"));
        let object = DepositSyncObject::new(reference, bytes.clone()).unwrap();
        pending.extend(object.authenticated_semantic_children(target).unwrap());
    }
}

async fn build_offline_large_archive_fixture(
    source_directory: &Path,
    fixture_directory: &Path,
    source_party: PartyId,
    identity_seed: &[u8; 32],
    observation_advertisement: &DepositSyncAdvertisement,
) -> Arc<OfflineDepositSyncFixture> {
    const LARGE_ARCHIVE_EVENTS: u64 = MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS as u64;
    const CHECKPOINT_SIGNING_TIME: u64 = 1_700_000_000;

    assert_eq!(observation_advertisement.certificate_archive().len(), 2);
    let registry = observation_advertisement.registry_archive().registry().clone();
    assert_eq!(registry.active().epoch(), 0);
    let identities = registry
        .active()
        .committee()
        .members
        .iter()
        .map(|member| {
            let seed = signing_seed(member.id);
            (
                member.id,
                identity_from_explicit_secrets(
                    member.id,
                    registry.active().epoch(),
                    &seed,
                    bootstrap_x25519_secret(member.id),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let network = observation_advertisement.context().network();
    let wallet = observation_advertisement.context().wallet();
    let mut objects = collect_deposit_sync_objects(
        source_directory,
        source_party,
        identity_seed,
        observation_advertisement,
    )
    .await;

    let ledger = objects
        .iter()
        .find_map(|(reference, bytes)| match reference {
            DepositSyncObjectRef::CertificateArchive(reference)
                if reference.kind() == CERTIFIED_LEDGER_ENTRY_ARTIFACT =>
            {
                Some(CertifiedLedgerEntry::from_bytes(bytes).unwrap())
            }
            _ => None,
        })
        .expect("live archive omitted its allocation certificate");
    let live_observation = objects
        .iter()
        .find_map(|(reference, bytes)| match reference {
            DepositSyncObjectRef::CertificateArchive(reference)
                if reference.kind() == CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT =>
            {
                Some(CertifiedDepositObservation::from_bytes(bytes).unwrap())
            }
            _ => None,
        })
        .expect("live archive omitted its observation certificate");
    let checkpoints = objects
        .iter()
        .filter_map(|(reference, bytes)| match reference {
            DepositSyncObjectRef::CertificateArchive(reference)
                if reference.kind() == DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT =>
            {
                let certificate = DepositIndexCheckpointCertificate::from_bytes(bytes).unwrap();
                Some((certificate.statement().sequence(), certificate))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(checkpoints.len(), 2);
    let verified_ledger_checkpoint =
        checkpoints[&1].verify_active(network, &registry, None, None, &ledger).unwrap();
    let mut verified_checkpoint = checkpoints[&2]
        .verify_active_deposit_observation(
            network,
            &registry,
            Some(&verified_ledger_checkpoint),
            &live_observation,
        )
        .unwrap();
    assert_eq!(observation_advertisement.checkpoint_certificate(), Some(&checkpoints[&2]));

    let fixture_artifacts =
        WalletArtifactStore::new(fixture_directory, source_party, identity_seed).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0xA7; 32]);
    for (object, bytes) in &objects {
        let reference = object.storage_reference().unwrap();
        let installed = fixture_artifacts
            .create_artifact(reference.wallet_id(), reference.kind(), bytes, &mut rng)
            .await
            .unwrap();
        assert_eq!(installed, reference);
    }
    let archive = DepositArchiveStore::new(fixture_directory, source_party, identity_seed).unwrap();
    let mut archive_head = observation_advertisement.certificate_archive();
    let mut index_reader = OfflineDepositIndexReader {
        objects: objects
            .iter()
            .filter_map(|(reference, bytes)| match reference {
                DepositSyncObjectRef::Index(id) => Some((*id, bytes.clone())),
                DepositSyncObjectRef::Registry(_) | DepositSyncObjectRef::CertificateArchive(_) => {
                    None
                }
            })
            .collect(),
    };
    let mut index_head = observation_advertisement.portable_index().to_index_head().unwrap();
    let mut latest_checkpoint = checkpoints[&2].clone();

    for checkpoint_sequence in 3..=LARGE_ARCHIVE_EVENTS {
        let tag = u8::try_from(checkpoint_sequence).unwrap();
        let observed_height = 10_000 + checkpoint_sequence;
        let statement = DepositObservationStatement::new(
            &registry,
            &ledger.statement,
            WalletOutputId { transaction: [tag; 32], index_in_transaction: checkpoint_sequence },
            [tag.wrapping_add(64); 32],
            checkpoint_sequence,
            10_000_000 + checkpoint_sequence,
            ChainPoint::new(observed_height, [tag.wrapping_add(1); 32]).unwrap(),
            CHECKPOINT_SIGNING_TIME + checkpoint_sequence,
            ChainPoint::new(observed_height + 9, [tag.wrapping_add(2); 32]).unwrap(),
            10,
        )
        .unwrap();
        let observation = certify_offline_observation(&registry, &identities, statement);
        let verified_observation = observation.verify_active(&registry).unwrap();
        let mut builder = DepositIndexBuilder::new(&index_reader, index_head.clone()).unwrap();
        assert!(
            builder.apply_verified_active_deposit_observation(&observation, &registry).unwrap()
        );
        let update = builder.finish().unwrap().unwrap();
        let transition = update
            .verify_deposit_observation_transition(&index_reader, &observation.statement)
            .unwrap();
        let statement = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            CHECKPOINT_SIGNING_TIME,
            network,
            &registry,
            Some(&verified_checkpoint),
            &observation,
            &transition,
        )
        .unwrap();
        assert_eq!(statement.sequence(), checkpoint_sequence);
        let selection = certify_offline_checkpoint_candidate(
            network,
            &registry,
            statement.sequence(),
            statement.previous_head(),
            DepositIndexCheckpointCandidate::DepositObservation(observation.clone()),
            &identities,
        );
        let required = usize::from(
            registry.active().committee().n().checked_sub(registry.active().fault_bound()).unwrap(),
        );
        let witnesses = identities
            .values()
            .take(required)
            .map(|identity| {
                identity
                    .sign_envelope(
                        registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence(),
                        statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let checkpoint = DepositIndexCheckpointCertificate::from_deposit_observation_witnesses(
            network,
            &registry,
            Some(&verified_checkpoint),
            &observation,
            statement,
            selection,
            witnesses,
        )
        .unwrap();
        let next_verified = checkpoint
            .verify_active_deposit_observation(
                network,
                &registry,
                Some(&verified_checkpoint),
                &observation,
            )
            .unwrap();
        let staged_observation = archive
            .stage_certified_deposit_observation(&observation, &verified_observation, &mut rng)
            .await
            .unwrap();
        let append = archive
            .append_deposit_observation_checkpoint(
                archive_head,
                staged_observation,
                &checkpoint,
                &next_verified,
                &mut rng,
            )
            .await
            .unwrap();
        assert!(append.appended);
        archive_head = append.head;
        for reference in BTreeSet::from([
            append.observation_artifact,
            append.checkpoint_artifact,
            append.event_artifact,
            append.head.segment_reference().unwrap(),
        ]) {
            let artifact = fixture_artifacts.load_artifact(reference).await.unwrap();
            objects.insert(
                DepositSyncObjectRef::CertificateArchive(reference),
                artifact.contents.into_bytes(),
            );
        }
        for (id, bytes) in update.staged_objects() {
            let reference = id.storage_reference();
            let installed = fixture_artifacts
                .create_artifact(reference.wallet_id(), reference.kind(), bytes, &mut rng)
                .await
                .unwrap();
            assert_eq!(installed, reference);
            index_reader.objects.insert(id, bytes.to_vec());
            objects.insert(DepositSyncObjectRef::Index(id), bytes.to_vec());
        }
        index_head = update.next_head().clone();
        verified_checkpoint = next_verified;
        latest_checkpoint = checkpoint;
    }

    assert_eq!(archive_head.len(), LARGE_ARCHIVE_EVENTS);
    let registry_checkpoint = CompactRegistryStoreCheckpoint::settled(
        wallet,
        observation_advertisement.registry_archive().clone(),
    )
    .unwrap();
    let portable_advance =
        VerifiedPortableIndexAdvance::from_certified_checkpoint(&verified_checkpoint).unwrap();
    let index_checkpoint =
        DepositIndexStoreCheckpoint::empty(wallet, source_party, registry.active().first_index())
            .unwrap()
            .adopt_verified_portable(&portable_advance)
            .unwrap();
    let advertisement = DepositSyncAdvertisement::from_checkpoints(
        observation_advertisement.context(),
        &registry_checkpoint,
        archive_head,
        &index_checkpoint,
        Some(latest_checkpoint),
    )
    .unwrap();
    assert_eq!(advertisement.certificate_archive().len(), LARGE_ARCHIVE_EVENTS);
    assert_eq!(advertisement.portable_index().through_sequence(), 1);
    authenticate_offline_deposit_sync_graph(source_party, &advertisement, &objects);
    Arc::new(OfflineDepositSyncFixture { advertisement, objects })
}

#[derive(Default)]
struct DepositSyncSourceProbe {
    advertisement: StdMutex<Option<DepositSyncAdvertisement>>,
    unique_objects: StdMutex<BTreeSet<DepositSyncObjectRef>>,
    manifests: StdMutex<Vec<Vec<DepositSyncObjectRef>>>,
    request_digests: StdMutex<Vec<[u8; 32]>>,
    rejections: StdMutex<Vec<String>>,
    first_object_request_at: StdMutex<Option<Instant>>,
    sync_head_requests: AtomicUsize,
    sync_object_requests: AtomicUsize,
    objects_since_head: AtomicUsize,
    maximum_objects_per_head: AtomicUsize,
    blocked: AtomicBool,
    blocked_notify: Notify,
}

impl DepositSyncSourceProbe {
    async fn wait_until_blocked(&self) {
        loop {
            if self.blocked.load(Ordering::Acquire) || !self.rejections.lock().unwrap().is_empty() {
                return;
            }
            let notified = self.blocked_notify.notified();
            if self.blocked.load(Ordering::Acquire) || !self.rejections.lock().unwrap().is_empty() {
                return;
            }
            notified.await;
        }
    }

    fn unique_objects(&self) -> BTreeSet<DepositSyncObjectRef> {
        self.unique_objects.lock().unwrap().clone()
    }

    fn manifests(&self) -> Vec<Vec<DepositSyncObjectRef>> {
        self.manifests.lock().unwrap().clone()
    }

    fn request_digests(&self) -> Vec<[u8; 32]> {
        self.request_digests.lock().unwrap().clone()
    }

    fn first_object_request_at(&self) -> Option<Instant> {
        self.first_object_request_at.lock().unwrap().as_ref().copied()
    }

    fn sync_head_requests(&self) -> usize {
        self.sync_head_requests.load(Ordering::Acquire)
    }

    fn sync_object_requests(&self) -> usize {
        self.sync_object_requests.load(Ordering::Acquire)
    }

    fn rejections(&self) -> Vec<String> {
        self.rejections.lock().unwrap().clone()
    }

    fn maximum_objects_per_head(&self) -> usize {
        self.maximum_objects_per_head.load(Ordering::Acquire)
    }
}

fn serve_offline_deposit_sync_request(
    source: PartyId,
    requester: PartyId,
    request: &PeerRequest,
    fixture: &OfflineDepositSyncFixture,
) -> Result<PeerResponse, String> {
    let mac_key = offline_deposit_sync_mac_key(source);
    let body = match request {
        PeerRequest::Deposit { operation: DepositOperation::SyncHead, body } => {
            let request = DepositSyncHeadRequest::from_bytes(source, requester, body)
                .map_err(|error| error.to_string())?;
            DepositSyncHeadResponse::issue(request, fixture.advertisement.clone(), &mac_key)
                .and_then(|response| response.to_bytes(request))
                .map_err(|error| error.to_string())?
        }
        PeerRequest::Deposit { operation: DepositOperation::SyncObjects, body } => {
            let request =
                DepositSyncObjectPageRequest::from_bytes(source, requester, &mac_key, body)
                    .map_err(|error| error.to_string())?;
            let mut objects = Vec::with_capacity(request.entries().len());
            let mut capabilities = Vec::new();
            for entry in request.entries().iter().copied() {
                let bytes = fixture
                    .objects
                    .get(&entry.reference())
                    .ok_or_else(|| format!("offline fixture omitted {:?}", entry.reference()))?;
                let object = DepositSyncObject::new(entry.reference(), bytes.clone())
                    .map_err(|error| error.to_string())?;
                for child in object
                    .authenticated_semantic_children(entry.target())
                    .map_err(|error| error.to_string())?
                {
                    capabilities.push(
                        DepositSyncObjectCapability::issue(
                            &mac_key,
                            request.lease(),
                            entry.target(),
                            child,
                        )
                        .map_err(|error| error.to_string())?,
                    );
                }
                objects.push(object);
            }
            let page =
                DepositSyncObjectPage::build(&request, objects.clone(), capabilities.clone())
                    .map_err(|error| {
                        let mut unique_edges = BTreeSet::new();
                        let duplicate_edges = capabilities
                            .iter()
                            .copied()
                            .filter_map(|capability| {
                                let edge = (capability.parent(), capability.child());
                                (!unique_edges.insert(edge)).then_some(edge)
                            })
                            .collect::<Vec<_>>();
                        let single_failures = request
                            .entries()
                            .iter()
                            .copied()
                            .zip(objects.iter().cloned())
                            .enumerate()
                            .filter_map(|(index, (entry, object))| {
                                let single_request =
                                    DepositSyncObjectPageRequest::new(request.lease(), vec![entry])
                                        .unwrap();
                                let single_capabilities = object
                                    .authenticated_semantic_children(entry.target())
                                    .unwrap()
                                    .into_iter()
                                    .map(|child| {
                                        DepositSyncObjectCapability::issue(
                                            &mac_key,
                                            request.lease(),
                                            entry.target(),
                                            child,
                                        )
                                        .unwrap()
                                    })
                                    .collect();
                                DepositSyncObjectPage::build(
                                    &single_request,
                                    vec![object],
                                    single_capabilities,
                                )
                                .err()
                                .map(|single_error| {
                                    (index, entry.target(), single_error.to_string())
                                })
                            })
                            .collect::<Vec<_>>();
                        let targets = request
                            .entries()
                            .iter()
                            .copied()
                            .map(|entry| entry.target())
                            .collect::<Vec<_>>();
                        let plaintext_bytes =
                            objects.iter().map(|object| object.bytes().len()).sum::<usize>();
                        format!(
                            "{error}; targets={targets:?}; plaintext_bytes={plaintext_bytes}; \
                         capabilities={}; duplicate_edges={duplicate_edges:?}; \
                         single_failures={single_failures:?}",
                            capabilities.len(),
                        )
                    })?;
            page.to_bytes(&request).map_err(|error| error.to_string())?
        }
        PeerRequest::Deposit { operation: DepositOperation::SyncRelease, body } => {
            let request = DepositSyncReleaseRequest::from_bytes(source, requester, &mac_key, body)
                .map_err(|error| error.to_string())?;
            DepositSyncReleaseAck::issue(request)
                .and_then(|acknowledgement| acknowledgement.to_bytes(request))
                .map_err(|error| error.to_string())?
        }
        _ => return Err("test source serves compact deposit sync only".to_owned()),
    };
    Ok(PeerResponse::Success { body })
}

/// Real mutually authenticated QUIC source with deterministic object-page instrumentation.
///
/// Once at least `stop_after_unique` distinct objects have been returned, the source holds the
/// next request which would add a new object. Receipt of that request proves the joining runtime
/// durably accepted the preceding page before the test models a process crash.
fn start_probed_sync_only_deposit_source(
    endpoint: QuicPeerEndpoint,
    fixture: Arc<OfflineDepositSyncFixture>,
    stop_after_unique: Option<usize>,
    probe: Arc<DepositSyncSourceProbe>,
) -> RunningEndpointTask {
    let source = endpoint.local_party();
    let endpoint = Arc::new(endpoint);
    let listener = endpoint.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(connection) => {
                        let fixture = fixture.clone();
                        let probe = probe.clone();
                        connections.spawn(async move {
                            let peer = connection.peer_party();
                            loop {
                                let incoming = match connection.accept_request().await {
                                    Ok(incoming) => match incoming.read_request().await {
                                        Ok(incoming) => incoming,
                                        Err(_) => break,
                                    },
                                    Err(_) => break,
                                };
                                let request = incoming.request().clone();
                                if matches!(
                                    request,
                                    PeerRequest::Deposit {
                                        operation: DepositOperation::SyncHead,
                                        ..
                                    }
                                ) {
                                    probe.sync_head_requests.fetch_add(1, Ordering::AcqRel);
                                }
                                if matches!(
                                    request,
                                    PeerRequest::Deposit {
                                        operation: DepositOperation::SyncObjects,
                                        ..
                                    }
                                ) {
                                    probe.sync_object_requests.fetch_add(1, Ordering::AcqRel);
                                    probe
                                        .first_object_request_at
                                        .lock()
                                        .unwrap()
                                        .get_or_insert_with(Instant::now);
                                }
                                let response = serve_offline_deposit_sync_request(
                                    source,
                                    peer,
                                    &request,
                                    &fixture,
                                )
                                .unwrap_or_else(|message| {
                                    if matches!(
                                        request,
                                        PeerRequest::Deposit {
                                            operation: DepositOperation::SyncHead
                                                | DepositOperation::SyncObjects
                                                | DepositOperation::SyncRelease,
                                            ..
                                        }
                                    ) {
                                        probe.rejections.lock().unwrap().push(message.clone());
                                        probe.blocked_notify.notify_waiters();
                                    }
                                    PeerResponse::Rejected {
                                        code: RejectionCode::InvalidRequest,
                                        retryable: false,
                                        message,
                                    }
                                });

                                match (&request, &response) {
                                    (
                                        PeerRequest::Deposit {
                                            operation: DepositOperation::SyncHead,
                                            body: request_body,
                                        },
                                        PeerResponse::Success { body },
                                    ) => {
                                        let request = DepositSyncHeadRequest::from_bytes(
                                            source,
                                            peer,
                                            request_body,
                                        )
                                        .unwrap();
                                        let advertisement = DepositSyncHeadResponse::from_bytes(
                                            request, body,
                                        )
                                        .unwrap()
                                        .advertisement()
                                        .clone();
                                        *probe.advertisement.lock().unwrap() = Some(advertisement);
                                        probe.objects_since_head.store(0, Ordering::Release);
                                    }
                                    (
                                        PeerRequest::Deposit {
                                            operation: DepositOperation::SyncObjects,
                                            body: request_body,
                                        },
                                        PeerResponse::Success { body },
                                    ) => {
                                        // The fixture handler authenticated every
                                        // source/requester-bound production capability before
                                        // returning success. This copy only binds instrumentation
                                        // to that exact canonical response.
                                        let page_request: DepositSyncObjectPageRequest =
                                            postcard::from_bytes(request_body).unwrap();
                                        page_request.validate().unwrap();
                                        let page =
                                            DepositSyncObjectPage::from_bytes(&page_request, body)
                                                .unwrap();
                                        let should_block = {
                                            let unique = probe.unique_objects.lock().unwrap();
                                            let adds_new = page.objects().iter().any(|object| {
                                                !unique.contains(&object.reference())
                                            });
                                            stop_after_unique.is_some_and(|limit| {
                                                unique.len() >= limit && adds_new
                                            })
                                        };
                                        if should_block {
                                            probe.blocked.store(true, Ordering::Release);
                                            probe.blocked_notify.notify_waiters();
                                            let _held = incoming;
                                            std::future::pending::<()>().await;
                                            unreachable!("held request is cancelled with endpoint");
                                        }
                                        // A cancelled stream is not a completed traversal page:
                                        // the client must retry that unchanged durable frontier.
                                        if incoming.respond(response).await.is_err() {
                                            break;
                                        }
                                        probe
                                            .request_digests
                                            .lock()
                                            .unwrap()
                                            .push(page_request.digest());
                                        let burst = probe
                                            .objects_since_head
                                            .fetch_add(page.objects().len(), Ordering::AcqRel)
                                            + page.objects().len();
                                        probe
                                            .maximum_objects_per_head
                                            .fetch_max(burst, Ordering::AcqRel);
                                        probe
                                            .manifests
                                            .lock()
                                            .unwrap()
                                            .push(
                                                page_request
                                                    .entries()
                                                    .iter()
                                                    .copied()
                                                    .map(|entry| entry.reference())
                                                    .collect(),
                                            );
                                        probe.unique_objects.lock().unwrap().extend(
                                            page.objects().iter().map(|object| object.reference()),
                                        );
                                        continue;
                                    }
                                    _ => {}
                                }
                                if incoming.respond(response).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                    Err(_) => break,
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        connections.abort_all();
    });
    RunningEndpointTask { endpoint, task }
}

fn start_deposit_runtime_on_endpoint(
    node: &mut TestNode,
    endpoint: QuicPeerEndpoint,
    authenticator: BearerAuthenticator,
    deposit_sync_interval: Duration,
) {
    assert!(node.running.is_none());
    let runtime = Arc::new(
        QuicRuntime::new(
            endpoint,
            node.server().clone(),
            QuicRuntimeConfig {
                outbox_poll_interval: Duration::from_millis(20),
                // Keep the test accelerated relative to production without creating a 50 Hz
                // convoy among scanner, consensus, history, and compact-state storage reducers.
                protocol_progress_interval: Duration::from_millis(100),
                // Keep compact synchronization independent from the 20 ms protocol workers, and
                // bound unreachable localhost peers tightly enough that an n-f test quorum does
                // not spend the entire liveness assertion in transport-only waits.
                deposit_sync_request_timeout: DEPOSIT_SYNC_TEST_REQUEST_TIMEOUT,
                deposit_sync_source_timeout: DEPOSIT_SYNC_TEST_SOURCE_TIMEOUT,
                deposit_sync_tick_timeout: DEPOSIT_SYNC_TEST_TICK_TIMEOUT,
                deposit_sync_interval,
                deposit_worker_interval: Duration::from_millis(100),
                retry_initial: Duration::from_millis(20),
                retry_maximum: Duration::from_millis(200),
                qual_round_timeout: Some(LIVE_QUAL_TIMEOUT),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    node.server().mark_quic_runtime_attached().unwrap();
    let runtime_task = tokio::spawn(runtime.clone().run());
    let server = node.server().clone();
    let admin_address = node.admin_address;
    let admin_task = tokio::spawn(async move { server.serve(admin_address, authenticator).await });
    node.running = Some(RunningNode { runtime, runtime_task, admin_task });
}

fn authenticator() -> BearerAuthenticator {
    BearerAuthenticator::from_config(BearerAuthConfig {
        schema_version: BEARER_AUTH_SCHEMA_VERSION,
        credentials: vec![
            BearerCredentialConfig {
                principal: "quic-test-admin".to_owned(),
                role: AuthRole::Admin,
                token_digest: Hex32(bearer_token_digest(ADMIN_TOKEN).unwrap()),
            },
            BearerCredentialConfig {
                principal: "quic-test-deposits".to_owned(),
                role: AuthRole::Deposits,
                token_digest: Hex32(bearer_token_digest(DEPOSIT_TOKEN).unwrap()),
            },
        ],
    })
    .unwrap()
}

fn current_time_millis() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

async fn wait_for_http(client: &Client, scenario: &Scenario) {
    let parties = scenario.parties.iter().map(|party| party.id).collect::<Vec<_>>();
    wait_for_http_parties(client, scenario, &parties).await;
}

async fn wait_for_http_parties(client: &Client, scenario: &Scenario, parties: &[PartyId]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    for party in parties {
        let configured = scenario.party(*party).unwrap();
        let endpoint = configured.admin_endpoint.join("/healthz").unwrap();
        loop {
            if client
                .get(endpoint.clone())
                .send()
                .await
                .is_ok_and(|response| response.status() == StatusCode::NO_CONTENT)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "party {} HTTP service did not start",
                configured.id
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

async fn post_start(
    client: &Client,
    scenario: &Scenario,
    party: PartyId,
    transition: &AvssTransition,
) {
    let endpoint = scenario.party(party).unwrap().admin_endpoint.join("/v1/avss/start").unwrap();
    let response = client
        .post(endpoint)
        .bearer_auth(std::str::from_utf8(ADMIN_TOKEN).unwrap())
        .json(&AvssStartRequest { transition: transition.clone() })
        .send()
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    assert!(
        status.is_success(),
        "party {party} start failed ({status}): {}",
        String::from_utf8_lossy(&bytes)
    );
    let step: AvssStepResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(step.party, party);
    assert_eq!(step.dealer, party);
}

async fn status(client: &Client, scenario: &Scenario, party: PartyId) -> PartyStatus {
    try_status(client, scenario, party).await.unwrap()
}

async fn try_status(
    client: &Client,
    scenario: &Scenario,
    party: PartyId,
) -> reqwest::Result<PartyStatus> {
    let endpoint = scenario.party(party).unwrap().admin_endpoint.join("/v1/status").unwrap();
    let response =
        client.get(endpoint).bearer_auth(std::str::from_utf8(ADMIN_TOKEN).unwrap()).send().await?;
    assert!(response.status().is_success());
    response.json().await
}

async fn status_before(
    client: &Client,
    scenario: &Scenario,
    party: PartyId,
    deadline: Instant,
) -> PartyStatus {
    // A lost status sample is not a failed epoch. Retry only timeouts within the caller's
    // unchanged phase deadline; authentication, HTTP, and decoding failures remain fatal.
    loop {
        let result = tokio::time::timeout_at(deadline, try_status(client, scenario, party))
            .await
            .unwrap_or_else(|_| panic!("party {party} status exceeded the phase deadline"));
        match result {
            Ok(observed) => return observed,
            Err(error) => assert!(error.is_timeout(), "party {party} status failed: {error}"),
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test]
async fn status_poll_retries_a_timeout_within_the_existing_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed_requests = requests.clone();
    let app = axum::Router::new().route(
        "/v1/status",
        axum::routing::get(move || {
            let requests = observed_requests.clone();
            async move {
                if requests.fetch_add(1, Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                axum::Json(serde_json::json!({
                    "party": 1, "ready": true, "deposit_ready": null,
                    "deposit_chain_ready": null, "active_epoch": null,
                    "staged_epochs": [], "epochs": [], "proactive_refresh": null,
                    "authenticated_quic_ingress": 0, "authenticated_quic_responses": 0
                }))
            }
        }),
    );
    let _server = AbortOnDropTask::new(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    }));
    let mut scenario: Scenario =
        serde_json::from_str(include_str!("../docker/configs/regtest-scenario.json")).unwrap();
    scenario.parties[0].admin_endpoint = format!("http://{address}").parse().unwrap();
    let client = Client::builder().timeout(Duration::from_millis(100)).build().unwrap();
    let observed =
        status_before(&client, &scenario, PartyId(1), Instant::now() + Duration::from_secs(3))
            .await;
    assert!(observed.ready);
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    requests.store(0, Ordering::SeqCst);
    let bounded = tokio::spawn(async move {
        status_before(&client, &scenario, PartyId(1), Instant::now() + Duration::from_millis(50))
            .await
    });
    let expired = tokio::time::timeout(Duration::from_secs(1), bounded)
        .await
        .expect("status polling ignored its phase deadline")
        .unwrap_err();
    assert!(expired.is_panic());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

async fn wait_for_exact_share_retirement_markers(
    store: &ShareStore,
    boundaries: &[(u64, [u8; 32], u64)],
    context: &str,
) {
    // Runtime signing authority is deliberately removed before its authenticated tombstone is
    // committed. A status response can therefore prove that a scalar is no longer usable while
    // the atomic replacement still exposes the complete predecessor ciphertext. Retry only that
    // safe state: absence, a wrong marker, or any authentication/context failure is not a
    // retirement and must never be hidden by this liveness poll.
    let deadline = Instant::now() + TEST_TIMEOUT;
    for &(epoch, committee, successor_epoch) in boundaries {
        loop {
            match store.load(epoch, committee).await {
                Err(StoreError::ShareRetired {
                    epoch: found_epoch,
                    successor_epoch: found_successor,
                }) if found_epoch == epoch && found_successor == successor_epoch => break,
                Ok(share) => drop(share),
                Err(error) => {
                    panic!(
                        "{context}: epoch {epoch} retirement expected successor \
                         {successor_epoch}, but durable storage returned {error}"
                    );
                }
            }
            assert!(
                Instant::now() < deadline,
                "{context}: epoch {epoch} still had an active encrypted share instead of the \
                 exact successor-{successor_epoch} retirement marker"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

async fn release_deposit_sync_head_response(
    server: &Arc<PartyServer>,
    requester: PartyId,
    response: &DepositSyncHeadResponse,
) {
    let release = DepositSyncReleaseRequest::new(response.lease()).unwrap();
    match server
        .handle_quic_peer_request(
            requester,
            PeerRequest::Deposit {
                operation: DepositOperation::SyncRelease,
                body: release.to_bytes().unwrap(),
            },
        )
        .await
    {
        PeerResponse::Success { body } => {
            DepositSyncReleaseAck::from_bytes(release, &body).unwrap();
        }
        PeerResponse::Rejected { code, retryable, message } => {
            panic!("deposit SyncRelease was rejected ({code:?}, retryable={retryable}): {message}");
        }
    }
}

async fn wait_for_deposit_sync_head_response(
    server: &Arc<PartyServer>,
    requester: PartyId,
    context: DepositSyncContext,
    expected: &DepositSyncAdvertisement,
    deadline: Instant,
) -> DepositSyncHeadResponse {
    loop {
        if let Some(response) = try_deposit_sync_head_response(server, requester, context).await {
            if response.advertisement() == expected {
                return response;
            }
            // Exact source-pin replay is causally prior to any newer moving head. Retire it and
            // retry instead of treating a crash-safe predecessor response as stale authority.
            release_deposit_sync_head_response(server, requester, &response).await;
        }
        assert!(Instant::now() < deadline, "source did not issue the expected advanced head");
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    }
}

async fn try_local_deposit_sync_advertisement(
    server: &Arc<PartyServer>,
    context: DepositSyncContext,
) -> Option<DepositSyncAdvertisement> {
    server.local_deposit_sync_advertisement(context).await.ok()
}

async fn try_deposit_sync_head_response(
    server: &Arc<PartyServer>,
    requester: PartyId,
    context: DepositSyncContext,
) -> Option<DepositSyncHeadResponse> {
    let request = DepositSyncHeadRequest::new(context, server.party_id(), requester)
        .expect("valid test peer");
    match server
        .handle_quic_peer_request(
            requester,
            PeerRequest::Deposit {
                operation: DepositOperation::SyncHead,
                body: request.to_bytes().unwrap(),
            },
        )
        .await
    {
        PeerResponse::Success { body } => {
            Some(DepositSyncHeadResponse::from_bytes(request, &body).unwrap())
        }
        PeerResponse::Rejected { retryable: true, .. } => None,
        PeerResponse::Rejected { code, retryable: false, message } => {
            panic!("deposit SyncHead was permanently rejected ({code:?}): {message}")
        }
    }
}

async fn deposit_http_request(
    client: &Client,
    scenario: &Scenario,
    party: PartyId,
    path: &str,
    request: DepositAddressRequest,
) -> Option<DepositHttpResponse> {
    let endpoint = scenario.party(party).unwrap().admin_endpoint.join(path).unwrap();
    let response = client
        .post(endpoint)
        .bearer_auth(std::str::from_utf8(DEPOSIT_TOKEN).unwrap())
        .json(&request)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json().await.ok()
}

async fn wait_for_permanent_deposit_http_response(
    client: &Client,
    scenario: &Scenario,
    party: PartyId,
    request: DepositAddressRequest,
    deadline: Instant,
    phase: &str,
) -> DepositHttpResponse {
    let mut last_successful_status = None;
    let mut unsuccessful_requests = 0_u64;
    loop {
        match deposit_http_request(client, scenario, party, "/v1/deposits/status", request).await {
            Some(response) if response.status == DepositHttpStatus::Permanent => return response,
            Some(response) => last_successful_status = Some(response.status),
            None => unsuccessful_requests = unsuccessful_requests.saturating_add(1),
        }
        assert!(
            Instant::now() < deadline,
            "{phase}: party {party} did not serve Permanent deposit status; \
             last_successful_status={last_successful_status:?}, \
             unsuccessful_requests={unsuccessful_requests}"
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    }
}

async fn sample_qual(
    nodes: &BTreeMap<PartyId, TestNode>,
    session: SessionId,
    stats: &mut QualStats,
) {
    for node in nodes.values() {
        for pending in node.server().pending_peer_messages(256).await {
            if let PendingPeerMessage::Qual { id, request } = pending
                && id.session() == session
            {
                stats.observe(id, &request.wire.envelope.payload);
            }
        }
    }
}

async fn wait_for_active(
    client: &Client,
    scenario: &Scenario,
    nodes: &BTreeMap<PartyId, TestNode>,
    transition: &AvssTransition,
    stats: &mut QualStats,
) -> EpochPublic {
    let parties = transition.target.members.iter().map(|member| member.id).collect::<Vec<_>>();
    wait_for_active_parties(client, scenario, nodes, transition, &parties, stats).await
}

async fn wait_for_active_parties(
    client: &Client,
    scenario: &Scenario,
    nodes: &BTreeMap<PartyId, TestNode>,
    transition: &AvssTransition,
    parties: &[PartyId],
    stats: &mut QualStats,
) -> EpochPublic {
    wait_for_active_parties_with_timeout(
        client,
        scenario,
        nodes,
        transition,
        parties,
        stats,
        TEST_TIMEOUT,
    )
    .await
}

async fn wait_for_active_parties_with_timeout(
    client: &Client,
    scenario: &Scenario,
    nodes: &BTreeMap<PartyId, TestNode>,
    transition: &AvssTransition,
    parties: &[PartyId],
    stats: &mut QualStats,
    timeout: Duration,
) -> EpochPublic {
    let deadline = Instant::now() + timeout;
    let mut last_statuses = BTreeMap::new();
    loop {
        sample_qual(nodes, transition.session, stats).await;
        let mut public = None;
        let mut ready = true;
        for party in parties {
            transition.target.member(*party).expect("observed party is outside target committee");
            let observed = status_before(client, scenario, *party, deadline).await;
            last_statuses.insert(*party, (observed.active_epoch, observed.staged_epochs.clone()));
            if observed.active_epoch != Some(transition.target.epoch) {
                ready = false;
                continue;
            }
            let found = observed
                .epochs
                .iter()
                .find(|epoch| epoch.epoch == transition.target.epoch)
                .expect("active epoch omitted public metadata")
                .public
                .clone();
            found.validate().unwrap();
            if let Some(expected) = &public {
                assert_eq!(expected, &found, "target parties activated different public values");
            } else {
                public = Some(found);
            }
        }
        if ready && !parties.is_empty() {
            return public.expect("empty target committee");
        }
        if Instant::now() >= deadline {
            let mut pending = BTreeMap::new();
            let mut pending_avss = BTreeMap::new();
            let mut protocols = BTreeMap::new();
            for (party, node) in nodes {
                let mut counts = [0_usize; 3];
                let mut avss = Vec::new();
                for message in node.server().pending_peer_messages(256).await {
                    if message.id().session() != transition.session {
                        continue;
                    }
                    match message {
                        PendingPeerMessage::Avss { id, request } => {
                            counts[0] += 1;
                            avss.push((
                                id.recipient(),
                                request.wire.dealer,
                                request.wire.envelope.from,
                                request.wire.envelope.sequence,
                            ));
                        }
                        PendingPeerMessage::Qual { .. } => counts[1] += 1,
                        PendingPeerMessage::ActivationAck { .. } => counts[2] += 1,
                    }
                }
                pending.insert(*party, counts);
                pending_avss.insert(*party, avss);
                protocols.insert(
                    *party,
                    node.server().protocol_session_status(transition.session).await,
                );
            }
            panic!(
                "epoch {} did not activate; statuses={last_statuses:?}, protocols={protocols:?}, pending [avss,qual,ack]={pending:?}, pending AVSS [recipient,dealer,from,sequence]={pending_avss:?}, observed_qual_messages={}, maximum_round={:?}",
                transition.target.epoch,
                stats.messages.len(),
                stats.maximum_round,
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_selected_autonomous_epoch(
    client: &Client,
    scenario: &Scenario,
    nodes: &BTreeMap<PartyId, TestNode>,
    eligible: &[PartyId],
    desired_n: u16,
    fault_bound: u16,
    epoch: u64,
) -> (EpochPublic, BTreeSet<PartyId>) {
    assert!(fault_bound < desired_n);
    let required_active = desired_n - fault_bound;
    let deadline = Instant::now() + AUTONOMOUS_EPOCH_TIMEOUT;
    let mut last_statuses = BTreeMap::new();
    // Latch witnesses because a valid fixed-interval successor can already be active by the time
    // a peer is polled again. A witness is never silently replaced with a conflicting value.
    let mut activated = BTreeMap::<PartyId, EpochPublic>::new();
    loop {
        let mut active_epochs = BTreeMap::new();
        for party in eligible {
            let observed = status_before(client, scenario, *party, deadline).await;
            active_epochs.insert(*party, observed.active_epoch);
            last_statuses.insert(
                *party,
                (
                    observed.active_epoch,
                    observed.staged_epochs.clone(),
                    observed.proactive_refresh.clone(),
                ),
            );
            if observed.active_epoch == Some(epoch) {
                let public = observed
                    .epochs
                    .iter()
                    .find(|candidate| candidate.epoch == epoch)
                    .expect("active selected epoch omitted public metadata")
                    .public
                    .clone();
                public.validate().unwrap();
                if let Some(previous) = activated.insert(*party, public.clone()) {
                    assert_eq!(
                        previous, public,
                        "party {party} exposed conflicting public values for epoch {epoch}"
                    );
                }
            }
        }
        if let Some(selected) = activated.values().find(|candidate| {
            candidate.committee.n() == desired_n
                && candidate
                    .committee
                    .members
                    .iter()
                    .filter(|member| activated.get(&member.id) == Some(*candidate))
                    .count()
                    >= usize::from(required_active)
        }) {
            let selected = (*selected).clone();
            selected.committee.validate_async_security_with_faults(fault_bound).unwrap();
            let selected_ids =
                selected.committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
            for (party, active) in &activated {
                assert_eq!(
                    active, &selected,
                    "party {party} activated a conflicting value for selected epoch {epoch}"
                );
                assert!(
                    selected_ids.contains(party),
                    "omitted eligible party {party} activated a successor share"
                );
            }
            for omitted in eligible.iter().filter(|party| !selected_ids.contains(party)) {
                assert_ne!(
                    active_epochs.get(omitted),
                    Some(&Some(epoch)),
                    "omitted eligible party activated a successor share"
                );
            }
            let witnesses = activated
                .iter()
                .filter_map(|(party, active)| (active == &selected).then_some(*party))
                .collect::<BTreeSet<_>>();
            assert!(
                witnesses.len() >= usize::from(required_active),
                "selected epoch lacks the required active Byzantine quorum"
            );
            return (selected, witnesses);
        }
        if Instant::now() >= deadline {
            let mut pending_rotation = BTreeMap::new();
            let mut pending_protocol = BTreeMap::new();
            let network_id = scenario.quic_network_id().unwrap();
            for party in eligible {
                let pending = nodes[party]
                    .server()
                    .pending_key_rotation_peer_messages(usize::MAX)
                    .await
                    .into_iter()
                    .map(|message| {
                        let request = PeerRequest::key_rotation(&message.wire).unwrap();
                        let request_id = RequestId::for_peer_request(
                            network_id,
                            *party,
                            message.id.recipient,
                            &request,
                        )
                        .unwrap();
                        (request_id, message.target_epoch, message.id.recipient, message.id.kind)
                    })
                    .collect::<Vec<_>>();
                pending_rotation.insert(*party, pending);
                let pending = nodes[party]
                    .server()
                    .pending_peer_messages(usize::MAX)
                    .await
                    .into_iter()
                    .map(|message| {
                        let id = message.id();
                        let request = message.to_quic_request().unwrap();
                        let request_id = RequestId::for_peer_request(
                            network_id,
                            *party,
                            id.recipient(),
                            &request,
                        )
                        .unwrap();
                        (request_id, id, message.transition_epoch(), message.causal_sequence())
                    })
                    .collect::<Vec<_>>();
                pending_protocol.insert(*party, pending);
            }
            panic!(
                "selected autonomous epoch {epoch} did not activate; \
                 statuses={last_statuses:?}, pending key rotation \
                 [request_id,target_epoch,recipient,kind]={pending_rotation:?}, \
                 pending protocol [request_id,id,transition_epoch,causal_sequence]=\
                 {pending_protocol:?}"
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[test]
fn deposit_enabled_party_starts_core_quic_while_monerod_is_unavailable() {
    run_quic_epoch_liveness_test(
        4,
        None,
        deposit_enabled_party_starts_core_quic_while_monerod_is_unavailable_body(),
    );
}

async fn deposit_enabled_party_starts_core_quic_while_monerod_is_unavailable_body() {
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_test_writer().try_init();
    }
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=8)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();
    let mut admin_addresses = BTreeMap::new();
    let mut admin_reservations = Vec::new();
    for id in 1_u16..=8 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(PartyId(id), listener.local_addr().unwrap());
        admin_reservations.push(listener);
    }
    let scenario = scenario(&root, &admin_addresses, &tls);
    drop(admin_reservations);

    let daemon = Arc::new(
        ReconnectingMoneroDaemon::new(
            // The discard port is intentionally not served. Construction must not perform I/O.
            ["http://127.0.0.1:9"],
            NetworkKind::Regtest,
            MoneroRpcLimits { request_timeout: Duration::from_millis(100), ..Default::default() },
        )
        .unwrap(),
    );
    let server_scenario = scenario.clone();
    let server_state = root.path().join("daemon-independent-party");
    let server_daemon = daemon.clone();
    let restore = Box::pin(async move {
        PartyServer::new_with_deposits(
            PartyId(1),
            server_scenario,
            server_state,
            &signing_seed(PartyId(1)),
            &bootstrap_x25519_secret(PartyId(1)),
            PartyDepositConfig {
                private_view_scalar: Zeroizing::new(
                    curve25519_dalek::Scalar::from(7_u64).to_bytes(),
                ),
                birth_anchor: None,
                worker: DepositWorkerConfig { request_timeout_millis: 100, ..Default::default() },
                chain_source: server_daemon.clone(),
                consolidation_backend: server_daemon.clone(),
                chain_readiness: server_daemon.readiness(),
            },
        )
        .await
    });
    let mut restore_task = AbortOnDropTask::new(tokio::spawn(restore));
    let server = tokio::time::timeout(Duration::from_secs(2), restore_task.handle_mut())
        .await
        .expect("party restore waited for an unavailable Monero daemon")
        .expect("party restore task panicked")
        .expect("deposit-enabled party restore failed");
    assert!(!daemon.is_ready(), "party startup unexpectedly contacted monerod");
    let admin_server = server.clone();
    let admin_address = admin_addresses[&PartyId(1)];
    let mut admin_task = AbortOnDropTask::new(tokio::spawn(async move {
        admin_server.serve(admin_address, authenticator()).await
    }));
    let client = Client::builder().timeout(Duration::from_secs(2)).build().unwrap();
    wait_for_http_parties(&client, &scenario, &[PartyId(1)]).await;
    let observed = status(&client, &scenario, PartyId(1)).await;
    assert!(
        !observed.ready,
        "HTTP-only startup was reported ready before the authenticated QUIC runtime attached"
    );
    assert_eq!(
        observed.deposit_ready,
        Some(false),
        "an uninitialized deposit runtime was reported as locally ready"
    );
    assert_eq!(observed.deposit_chain_ready, Some(false));

    let endpoint = endpoint_for(
        PartyId(1),
        "127.0.0.1:0".parse().unwrap(),
        &scenario,
        &tls,
        QuicTransportConfig {
            handshake_timeout: Duration::from_millis(100),
            stream_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    );
    let runtime = Arc::new(
        QuicRuntime::new(
            endpoint,
            server.clone(),
            QuicRuntimeConfig {
                protocol_progress_interval: Duration::from_millis(20),
                deposit_worker_interval: Duration::from_millis(20),
                epoch_history_request_timeout: Duration::from_millis(50),
                epoch_history_source_timeout: Duration::from_millis(100),
                epoch_history_sync_timeout: Duration::from_millis(150),
                retry_initial: Duration::from_millis(20),
                retry_maximum: Duration::from_millis(100),
                // Shutdown closes the endpoint while every inbound accept is pending. A transport
                // task must not carry this Byzantine-handshake backoff into the graceful runtime
                // drain; the three-second assertion below would deterministically fail without
                // transport-only handshake cancellation.
                accept_error_delay: Duration::from_secs(60 * 60),
                // Unreachable peers can consume QUIC's approximately three-second closing
                // period. Bound only that transport drain, not authoritative reducer work.
                transport_shutdown_grace: Duration::from_millis(250),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let attachment = QuicAttachmentGuard::attach(server.clone());
    let observed = status(&client, &scenario, PartyId(1)).await;
    assert!(observed.ready, "core readiness was coupled to monerod");
    assert_eq!(observed.deposit_ready, Some(false));
    assert_eq!(observed.deposit_chain_ready, Some(false));
    let mut runtime_task = AbortOnDropTask::new(tokio::spawn(Box::pin(runtime.clone().run())));
    assert!(
        server.start_canonical_genesis_if_eligible().await.unwrap(),
        "eligible genesis dealer did not start while monerod was absent"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!runtime_task.is_finished(), "core QUIC runtime stopped with monerod unavailable");

    runtime.shutdown();
    drop(attachment);
    tokio::time::timeout(Duration::from_secs(3), runtime_task.handle_mut())
        .await
        .expect("core runtime did not stop after explicit shutdown")
        .expect("core runtime task panicked")
        .expect("core runtime returned an error");
    admin_task.abort();
    let _ = admin_task.handle_mut().await;
}

#[test]
fn empty_deposit_replica_syncs_mixed_observation_tip_over_quic_and_survives_restart() {
    // Deposit-enabled parties activate the epoch-zero genesis and then drive the deep deposit
    // genesis/allocation reducers on the QUIC pacemaker's task. Those reducers are sized for the
    // production 16 MiB worker stack (`PARTY_RUNTIME_THREAD_STACK_BYTES` in `main`); the default
    // 2 MiB `#[tokio::test]` worker stack overflows partway through `DepositService::ensure_genesis`.
    // Build the runtime explicitly with the production stack size so this test exercises the real
    // activation path rather than aborting on a stack overflow the deployed binary never hits.
    run_quic_epoch_liveness_test(8, Some(16 * 1024 * 1024), async {
        if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
            let _ = tracing_subscriber::fmt().with_env_filter(filter).with_test_writer().try_init();
        }
        tokio::spawn(empty_deposit_replica_body()).await.unwrap();
    });
}

async fn empty_deposit_replica_body() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=8)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();
    let mut admin_listeners = BTreeMap::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=8 {
        let party = PartyId(id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(party, listener.local_addr().unwrap());
        admin_listeners.insert(party, listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    scenario.committees.truncate(1);
    // This test exercises the five-member epoch-zero committee plus the one reserve candidate
    // required by the n+f key-rotation eligibility invariant. Leaving the two later grow-only
    // parties in the route table makes every accelerated history pacemaker probe needless,
    // intentionally nonexistent endpoints.
    scenario.parties.retain(|party| party.id.0 <= 6);
    scenario.proactive_refresh_interval_seconds = 3_600;
    // Preserve real timeout/view-change semantics while keeping the 128-event localhost archive
    // fixture bounded. Production scenarios retain their configured consensus timeout.
    scenario.protocol_timeout_seconds = 3;
    let original_network = scenario.quic_network_id().unwrap();

    let mut endpoints = BTreeMap::new();
    let mut quic_addresses = BTreeMap::new();
    for id in 1_u16..=5 {
        let party = PartyId(id);
        let endpoint = endpoint_for(
            party,
            "127.0.0.1:0".parse().unwrap(),
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        );
        quic_addresses.insert(party, endpoint.local_addr().unwrap());
        endpoints.insert(party, endpoint);
    }
    for configured in &mut scenario.parties {
        if let Some(address) = quic_addresses.get(&configured.id) {
            configured.quic_endpoint = format!("quic://{address}").parse().unwrap();
        }
    }
    scenario.validate().unwrap();
    assert_eq!(scenario.quic_network_id().unwrap(), original_network);
    drop(admin_listeners);

    let chains = (1_u16..=5)
        .map(|id| (PartyId(id), Arc::new(QuicDepositChain::genesis_only())))
        .collect::<BTreeMap<_, _>>();
    let backends = (1_u16..=5)
        .map(|id| {
            let backend = ReconnectingMoneroDaemon::new(
                ["http://127.0.0.1:9"],
                NetworkKind::Regtest,
                MoneroRpcLimits {
                    request_timeout: Duration::from_millis(100),
                    ..Default::default()
                },
            )
            .unwrap();
            (PartyId(id), Arc::new(backend))
        })
        .collect::<BTreeMap<_, _>>();

    let mut nodes = BTreeMap::new();
    for id in 1_u16..=5 {
        let party = PartyId(id);
        let signing_seed = signing_seed(party);
        let bootstrap_x25519_secret = bootstrap_x25519_secret(party);
        let bootstrap = scenario
            .genesis_committee()
            .unwrap()
            .member(party)
            .is_ok()
            .then_some(&bootstrap_x25519_secret);
        let state_directory = root.path().join(format!("deposit-sync-party-{id}"));
        let server = PartyServer::new_with_deposits(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            bootstrap,
            deposit_config(chains[&party].clone(), backends[&party].clone()),
        )
        .await
        .unwrap();
        let mut node = TestNode {
            party,
            signing_seed,
            bootstrap_x25519_secret,
            state_directory,
            quic_address: quic_addresses[&party],
            admin_address: admin_addresses[&party],
            server: Some(server),
            running: None,
        };
        start_deposit_runtime_on_endpoint(
            &mut node,
            endpoints.remove(&party).unwrap(),
            authenticator(),
            if id <= 4 {
                DEPOSIT_SOURCE_SYNC_TEST_INTERVAL
            } else {
                DEPOSIT_LATE_SYNC_TEST_INTERVAL
            },
        );
        nodes.insert(party, node);
    }

    // Disable HTTP keep-alive pooling for this client. Aborting the axum serve future does not
    // abort every already-spawned connection task; a pooled connection could therefore retain an
    // `Arc<PartyServer>` clone of the router state, pinning that party's `PartyStateLease` past the
    // intended stop and blocking reconstruction from acquiring the exclusive writer lease.
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http_parties(&client, &scenario, &(1_u16..=5).map(PartyId).collect::<Vec<_>>()).await;
    let initial = scenario.genesis_committee().unwrap();
    let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
    let dkg = AvssTransition {
        purpose: DealPurpose::Dkg,
        session,
        key_id,
        fault_bound: 1,
        history_parent: EpochHistoryParent::genesis(scenario.quic_network_id().unwrap(), key_id)
            .unwrap(),
        old: None,
        target: initial,
        eligible_dealers: vec![],
    };
    for dealer in 1_u16..=5 {
        post_start(&client, &scenario, PartyId(dealer), &dkg).await;
    }
    let mut dkg_stats = QualStats::default();
    let epoch_zero = wait_for_active(&client, &scenario, &nodes, &dkg, &mut dkg_stats).await;

    let deriver = DepositAddressDeriver::new(
        NetworkKind::Regtest,
        epoch_zero.group_key_bytes(),
        &Zeroizing::new(deposit_private_view_scalar()),
    )
    .unwrap();
    let sync_context =
        DepositSyncContext::new(scenario.quic_network_id().unwrap(), deriver.wallet_id()).unwrap();
    let empty_deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if try_local_deposit_sync_advertisement(nodes[&PartyId(5)].server(), sync_context)
            .await
            .is_some_and(|advertisement| {
                advertisement.certificate_archive().is_empty()
                    && advertisement.portable_index().through_sequence() == 0
            })
        {
            break;
        }
        assert!(
            Instant::now() < empty_deadline,
            "party 5 did not initialize an empty deposit replica"
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    }

    // Party 5 now has an authenticated epoch-zero share and an exactly empty deposit snapshot.
    // Stop it before any allocation exists. The remaining four parties are exactly the n-f source
    // quorum and can certify both the allocation and the later confirmed-output observation.
    let mut late = nodes.remove(&PartyId(5)).unwrap();
    stop_node(&mut late).await;
    let request = DepositAddressRequest {
        request: LedgerRequestId([0x91; 32]),
        binding: RequestBinding([0x92; 32]),
    };
    let ledger_deadline = Instant::now() + TEST_TIMEOUT;
    let ledger_advertisement = loop {
        let _ =
            deposit_http_request(&client, &scenario, PartyId(1), "/v1/deposits/allocate", request)
                .await;
        if let Some(advertisement) =
            try_local_deposit_sync_advertisement(nodes[&PartyId(1)].server(), sync_context).await
            && advertisement.certificate_archive().len() == 1
            && advertisement.portable_index().through_sequence() == 1
            && advertisement.checkpoint_certificate().is_some_and(|certificate| {
                matches!(
                    certificate.statement().operation(),
                    DepositIndexCheckpointOperation::Ledger { .. }
                )
            })
        {
            break advertisement;
        }
        assert!(
            Instant::now() < ledger_deadline,
            "source quorum did not certify allocation ledger sequence one"
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    };
    let ledger_portable = ledger_advertisement.portable_index().clone();

    // Bring party 5 back while the source tip is still the sequence-one ledger checkpoint. This
    // first adoption proves that sync transferred the complete prefix (including the allocation
    // certificate) and rebuilt party 5's non-authoritative direct route for that exact certified
    // statement. Allocation release is deliberately scheduled 60 seconds ahead, so the
    // authenticated response remains Pending while this test drives the checkpoint lifecycle.
    drop(late.server.take().unwrap());
    late.server = Some(
        PartyServer::new_with_deposits(
            PartyId(5),
            scenario.clone(),
            late.state_directory.clone(),
            &late.signing_seed,
            &late.bootstrap_x25519_secret,
            deposit_config(chains[&PartyId(5)].clone(), backends[&PartyId(5)].clone()),
        )
        .await
        .unwrap(),
    );
    start_deposit_runtime_on_endpoint(
        &mut late,
        endpoint_for(
            PartyId(5),
            quic_addresses[&PartyId(5)],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        authenticator(),
        DEPOSIT_LATE_SYNC_TEST_INTERVAL,
    );
    wait_for_http_parties(&client, &scenario, &[PartyId(5)]).await;
    let ledger_import_deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let imported = try_local_deposit_sync_advertisement(late.server(), sync_context).await;
        let active =
            deposit_http_request(&client, &scenario, PartyId(5), "/v1/deposits/status", request)
                .await;
        if imported.as_ref().is_some_and(|advertisement| {
            advertisement.certificate_archive().len() == 1
                && advertisement.portable_index() == &ledger_portable
        }) && active.as_ref().is_some_and(|response| {
            let schedule_is_authenticated =
                response.allocation_issuer.as_ref().is_some_and(|issuer| {
                    issuer.validate().is_ok()
                        && issuer.issuer() == response.serving_registry.active()
                }) && response.serving_registry.validate().is_ok()
                    && response
                        .created_at
                        .zip(response.expires_at)
                        .is_some_and(|(created, expires)| expires > created);
            schedule_is_authenticated
                && match response.status {
                    DepositHttpStatus::Pending => {
                        response.address.is_none() && response.certificate.is_none()
                    }
                    DepositHttpStatus::Active => {
                        response.address.is_some() && response.certificate.is_some()
                    }
                    _ => false,
                }
        }) {
            break;
        }
        assert!(
            Instant::now() < ledger_import_deadline,
            "party 5 did not adopt and serve the sequence-one allocation prefix: \
             imported={:?}, response={:?}",
            imported.as_ref().map(|advertisement| (
                advertisement.certificate_archive().len(),
                advertisement.portable_index().through_sequence(),
                advertisement.portable_index() == &ledger_portable,
            )),
            active.as_ref().map(|response| (
                &response.status,
                response.allocation_issuer.is_some(),
                response.created_at,
                response.expires_at,
            ))
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    }
    // Adoption durably queues the exact source-pin release, and the following compact-sync tick
    // transmits and acknowledges it. Let that causally required tick complete before simulating an
    // offline replica; otherwise a later direct request from the same authenticated party must
    // correctly resume the still-pinned sequence-one snapshot.
    tokio::time::sleep(DEPOSIT_LATE_SYNC_TEST_INTERVAL * 2).await;
    stop_node(&mut late).await;

    // Advance only the source quorum. Party 5 now has a nonempty sequence-one archive and remains
    // offline until the source has certified the observation-only checkpoint at archive sequence
    // two, while the ledger sequence/head remain unchanged.
    for chain in chains.iter().filter_map(|(party, chain)| (party.0 <= 4).then_some(chain)) {
        chain.push_confirmed_deposit(epoch_zero.group_key_bytes());
    }
    let observation_deadline = Instant::now() + DEPOSIT_CHECKPOINT_TEST_TIMEOUT;
    let observation_advertisement = loop {
        // The live scanner and consensus pacemakers must carry this transition themselves.
        // Calling the same reducers again from the test creates an artificial storage convoy and
        // does not model a persistent deployment.
        if let Some(advertisement) =
            try_local_deposit_sync_advertisement(nodes[&PartyId(1)].server(), sync_context).await
            && advertisement.certificate_archive().len() == 2
            && advertisement.portable_index().through_sequence() == 1
            && advertisement.checkpoint_certificate().is_some_and(|certificate| {
                matches!(
                    certificate.statement().operation(),
                    DepositIndexCheckpointOperation::DepositObservation { .. }
                )
            })
        {
            break advertisement;
        }
        assert!(
            Instant::now() < observation_deadline,
            "source quorum did not finalize the observation-only checkpoint"
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    };
    let observation_checkpoint =
        observation_advertisement.checkpoint_certificate().unwrap().clone();
    assert_eq!(observation_checkpoint.statement().sequence(), 2);
    assert_eq!(observation_checkpoint.statement().ledger_sequence(), 1);
    assert_eq!(
        observation_checkpoint.statement().resulting_head(),
        observation_advertisement.portable_index()
    );
    assert_eq!(
        observation_advertisement.certificate_archive().len(),
        observation_checkpoint.statement().sequence()
    );
    assert_eq!(
        observation_advertisement.portable_index().ledger_head(),
        ledger_portable.ledger_head()
    );
    assert_eq!(
        observation_advertisement.portable_index().next_index(),
        ledger_portable.next_index()
    );
    assert_ne!(observation_advertisement.portable_index().digest(), ledger_portable.digest());
    // A requester which stopped after adoption may still own the exact predecessor pin. Resume
    // and release that authenticated head before asking the source to issue its advanced head;
    // skipping directly to the moving tip would violate crash-safe source-pin semantics.
    let observation_head = wait_for_deposit_sync_head_response(
        nodes[&PartyId(1)].server(),
        PartyId(5),
        sync_context,
        &observation_advertisement,
        Instant::now() + DEPOSIT_CHECKPOINT_TEST_TIMEOUT,
    )
    .await;
    release_deposit_sync_head_response(nodes[&PartyId(1)].server(), PartyId(5), &observation_head)
        .await;

    // Party 5 crashed immediately after its first adoption. A source may have durably released
    // its live pin while the requester had not yet committed the matching ACK. Replay every exact
    // requester-side intent through the original source key before those live sources are replaced
    // by the detached large-archive fixture. This is the same idempotent recovery a restarted
    // runtime performs, made explicit so the later test-only capability keys cannot collide with
    // an older source-bound lease.
    let late_spools = DepositSyncSpoolManager::new(
        &late.state_directory,
        PartyId(5),
        &late.signing_seed,
        scenario.quic_network_id().unwrap(),
    )
    .unwrap();
    for release in late_spools.pending_releases(sync_context).await.unwrap() {
        let source = release.source();
        let response = nodes[&source]
            .server()
            .handle_quic_peer_request(
                PartyId(5),
                PeerRequest::Deposit {
                    operation: DepositOperation::SyncRelease,
                    body: release.to_bytes().unwrap(),
                },
            )
            .await;
        let body = match response {
            PeerResponse::Success { body } => body,
            PeerResponse::Rejected { code, retryable, message } => panic!(
                "source {source} rejected persisted SyncRelease recovery \
                 ({code:?}, retryable={retryable}): {message}"
            ),
        };
        let acknowledgement = DepositSyncReleaseAck::from_bytes(release, &body).unwrap();
        late_spools.acknowledge_release(acknowledgement).await.unwrap();
    }
    assert!(
        late_spools.pending_releases(sync_context).await.unwrap().is_empty(),
        "requester retained a source-bound release after its exact ACK committed"
    );
    drop(late_spools);

    // Fill one complete archive segment without serializing 126 otherwise independent live BA
    // rounds through the localhost pacemaker. The fixture starts from the exact live event-two
    // graph above, signs distinct confirmed-output observations and checkpoint consensus with the
    // real epoch-zero identities, verifies every index transition, and appends through the
    // production archive store. Only this setup is offline; all compact-sync, crash, failover, CAS,
    // and restart behavior below remains the real mutually authenticated QUIC path.
    const LARGE_ARCHIVE_EVENTS: u64 = MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS as u64;
    let offline_fixture = build_offline_large_archive_fixture(
        &nodes[&PartyId(1)].state_directory,
        &root.path().join("offline-large-deposit-archive"),
        PartyId(1),
        &nodes[&PartyId(1)].signing_seed,
        &observation_advertisement,
    )
    .await;
    let large_advertisement = offline_fixture.advertisement.clone();
    assert_eq!(large_advertisement.certificate_archive().len(), LARGE_ARCHIVE_EVENTS);

    // Stop every normal source runtime so none can replay its retained live observation outbox.
    // The scripted endpoints below serve only authenticated SyncHead/SyncObjects/SyncRelease.
    stop_all(&mut nodes).await;
    let primary_large_sync_source = PartyId(2);
    let failover_large_sync_source = PartyId(3);
    let first_source_probe = Arc::new(DepositSyncSourceProbe::default());
    let mut first_sync_source = start_probed_sync_only_deposit_source(
        endpoint_for(
            primary_large_sync_source,
            quic_addresses[&primary_large_sync_source],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        offline_fixture.clone(),
        Some(129),
        first_source_probe.clone(),
    );

    drop(late.server.take().unwrap());
    late.server = Some(
        PartyServer::new_with_deposits(
            PartyId(5),
            scenario.clone(),
            late.state_directory.clone(),
            &late.signing_seed,
            &late.bootstrap_x25519_secret,
            deposit_config(chains[&PartyId(5)].clone(), backends[&PartyId(5)].clone()),
        )
        .await
        .unwrap(),
    );
    // A reconstructed deposit service publishes its authenticated snapshot into the live runtime
    // on the first protocol pacemaker tick. Claims must be seeded before that runtime starts, so
    // run the same local initializer explicitly rather than racing its immediate compact-sync
    // tick against the second source claim below.
    late.server().progress_deposit_allocation_consensus(current_time_millis()).await.unwrap();
    // Persist two independently authenticated claims before starting the downloader. This makes
    // the second claim's source active under the f+1 gate while retaining the first claim's exact
    // standby lease across the crash cut below.
    let (_, restored_sync_context) =
        late.server().deposit_sync_sources().await.unwrap().expect("party 5 is an active member");
    assert_eq!(restored_sync_context, sync_context);
    let failover_head = offline_deposit_sync_head_response(
        failover_large_sync_source,
        PartyId(5),
        &offline_fixture,
    );
    assert!(matches!(
        late.server()
            .admit_deposit_sync_spool(&failover_head, failover_large_sync_source)
            .await
            .unwrap(),
        DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
    ));
    let primary_head =
        offline_deposit_sync_head_response(primary_large_sync_source, PartyId(5), &offline_fixture);
    assert!(matches!(
        late.server()
            .admit_deposit_sync_spool(&primary_head, primary_large_sync_source)
            .await
            .unwrap(),
        DepositSyncSpoolAdmission::Admitted { supporters, .. } if supporters.len() == 2
    ));
    start_deposit_runtime_on_endpoint(
        &mut late,
        endpoint_for(
            PartyId(5),
            quic_addresses[&PartyId(5)],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        authenticator(),
        DEPOSIT_LARGE_SYNC_TEST_INTERVAL,
    );
    wait_for_http_parties(&client, &scenario, &[PartyId(5)]).await;

    if tokio::time::timeout(
        DEPOSIT_LARGE_SYNC_PROGRESS_TIMEOUT,
        first_source_probe.wait_until_blocked(),
    )
    .await
    .is_err()
    {
        panic!(
            "first QUIC source did not carry the durable stage past object 128: \
             unique_objects={}, object_requests={}, head_requests={}, first_object_request={:?}, \
             source_rejections={:?}",
            first_source_probe.unique_objects().len(),
            first_source_probe.sync_object_requests(),
            first_source_probe.sync_head_requests(),
            first_source_probe.first_object_request_at(),
            first_source_probe.rejections(),
        );
    }
    assert!(
        first_source_probe.blocked.load(Ordering::Acquire),
        "first QUIC source rejected an authenticated compact-sync request: {:?}",
        first_source_probe.rejections(),
    );
    let first_source_objects = first_source_probe.unique_objects();
    assert!(first_source_objects.len() >= 129, "source blocked before returning object 129");
    let cold_manifests = first_source_probe.manifests();
    assert!(!cold_manifests.is_empty());
    assert!(
        cold_manifests.len() >= 3,
        "large cold sync did not persist and request at least three distinct frontier pages"
    );
    let cold_request_digests = first_source_probe.request_digests();
    assert_eq!(
        cold_request_digests.iter().copied().collect::<BTreeSet<_>>().len(),
        cold_request_digests.len(),
        "durable frontier reused an exact request digest across sibling continuations"
    );
    assert!(
        cold_manifests.len() <= first_source_objects.len() + 1,
        "source retransmitted an authenticated parent instead of retaining sibling capabilities"
    );
    assert!(
        first_source_probe.maximum_objects_per_head() >= 2,
        "healthy compact sync still advanced only one object per scheduler tick"
    );

    // The held next-new-object request proves party 5 processed the preceding response. Abort the
    // process without a graceful reducer checkpoint and stop the primary source. After restart,
    // the durable frontier remains pinned to that exact source until its bounded deadline expires;
    // only then may the spool manager reset it for the independently authenticated standby lease.
    crash_node(&mut late).await;
    first_sync_source.endpoint.close(b"restart after durable object 129");
    tokio::time::timeout(Duration::from_secs(5), &mut first_sync_source.task)
        .await
        .expect("first sync source ignored endpoint shutdown")
        .expect("first sync source task panicked");

    let second_source_probe = Arc::new(DepositSyncSourceProbe::default());
    let mut second_sync_source = start_probed_sync_only_deposit_source(
        endpoint_for(
            failover_large_sync_source,
            quic_addresses[&failover_large_sync_source],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        offline_fixture,
        None,
        second_source_probe.clone(),
    );

    drop(late.server.take().unwrap());
    late.server = Some(
        PartyServer::new_with_deposits(
            PartyId(5),
            scenario.clone(),
            late.state_directory.clone(),
            &late.signing_seed,
            &late.bootstrap_x25519_secret,
            deposit_config(chains[&PartyId(5)].clone(), backends[&PartyId(5)].clone()),
        )
        .await
        .unwrap(),
    );
    let failover_started = Instant::now();
    start_deposit_runtime_on_endpoint(
        &mut late,
        endpoint_for(
            PartyId(5),
            quic_addresses[&PartyId(5)],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        authenticator(),
        DEPOSIT_LARGE_SYNC_TEST_INTERVAL,
    );
    wait_for_http_parties(&client, &scenario, &[PartyId(5)]).await;

    // Restart recovery reauthenticates the last maximum-width durable page, waits out the exact
    // primary-source pin, then traverses the complete source-specific graph before appending the
    // remaining objects. Give this repeated durable-batch phase the same bound as the cold pass;
    // the source-timeout assertion below still rejects premature failover.
    let import_deadline = Instant::now() + DEPOSIT_LARGE_SYNC_IMPORT_TIMEOUT;
    let imported = loop {
        if let Some(advertisement) =
            try_local_deposit_sync_advertisement(late.server(), sync_context).await
            && advertisement.certificate_archive().len() == LARGE_ARCHIVE_EVENTS
        {
            break advertisement;
        }
        assert!(
            Instant::now() < import_deadline,
            "party 5 did not resume and atomically adopt the large archive over failover QUIC: \
             unique_objects={}, object_requests={}, head_requests={}, first_object_request={:?}, \
             maximum_objects_per_head={}, manifests={:?}, source_rejections={:?}",
            second_source_probe.unique_objects().len(),
            second_source_probe.sync_object_requests(),
            second_source_probe.sync_head_requests(),
            second_source_probe.first_object_request_at(),
            second_source_probe.maximum_objects_per_head(),
            second_source_probe.manifests().iter().map(Vec::len).collect::<Vec<_>>(),
            second_source_probe.rejections(),
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    };
    assert_eq!(imported.portable_index(), large_advertisement.portable_index());
    assert_eq!(imported.certificate_archive(), large_advertisement.certificate_archive());
    assert_eq!(imported.checkpoint_certificate(), large_advertisement.checkpoint_certificate());
    let failover_first_request = second_source_probe
        .first_object_request_at()
        .expect("failover source served no object request");
    assert_eq!(
        second_source_probe.sync_head_requests(),
        0,
        "restart requested a fresh failover SyncHead instead of reopening durable ExactClaims authority"
    );
    assert!(
        failover_first_request.saturating_duration_since(failover_started)
            >= DEPOSIT_SYNC_TEST_SOURCE_TIMEOUT,
        "durable source pin failed over before the primary source exhausted its complete deadline"
    );
    let resumed_manifests = second_source_probe.manifests();
    assert!(!resumed_manifests.is_empty(), "failover source served no resumed object request");
    let resumed_request_digests = second_source_probe.request_digests();
    assert_eq!(
        resumed_request_digests.iter().copied().collect::<BTreeSet<_>>().len(),
        resumed_request_digests.len(),
        "source-specific restart reused an exact request digest"
    );
    assert!(
        resumed_manifests
            .iter()
            .all(|manifest| !manifest.is_empty()
                && manifest.len() <= MAX_DEPOSIT_SYNC_REQUEST_OBJECTS),
        "source-specific traversal exceeded its bounded authenticated page width"
    );
    assert!(
        resumed_manifests.iter().any(|manifest| manifest.len() > 1),
        "large source traversal never exercised authenticated multi-object batching"
    );
    let resumed_objects = resumed_manifests.iter().flatten().copied().collect::<Vec<_>>();
    assert_eq!(
        resumed_objects.len(),
        second_source_probe.unique_objects().len(),
        "full source traversal retransmitted an object instead of consuming its continuation once"
    );
    assert_eq!(
        resumed_objects.iter().copied().collect::<BTreeSet<_>>().len(),
        resumed_objects.len(),
        "full source traversal requested an authenticated object more than once"
    );
    assert!(
        second_source_probe.maximum_objects_per_head() >= 8,
        "healthy source did not consume the bounded multi-page scheduler budget"
    );
    assert!(
        second_source_probe
            .unique_objects()
            .iter()
            .any(|reference| !first_source_objects.contains(reference)),
        "source-specific failover made no progress beyond the durable object set"
    );
    assert_eq!(chains[&PartyId(5)].latest.load(Ordering::SeqCst), 0);
    assert!(
        !late.server().deposit_sync_candidate_is_successor(&imported).await.unwrap(),
        "an advertisement equal to the imported archive unexpectedly planned another download"
    );
    let permanent = wait_for_permanent_deposit_http_response(
        &client,
        &scenario,
        PartyId(5),
        request,
        Instant::now() + DEPOSIT_CHECKPOINT_TEST_TIMEOUT,
        "large archive import",
    )
    .await;
    assert_eq!(permanent.status, DepositHttpStatus::Permanent);

    // Abort both party futures, reconstruct from the authenticated large checkpoint, and prove
    // the final live-state CAS and allocation permanence survive without a local scan.
    crash_node(&mut late).await;
    drop(late.server.take().unwrap());
    // Inspect the staging namespace only after releasing the live server's process-owned Redb
    // handle. Redb deliberately rejects opening one database twice in a process; a second manager
    // while the server is live would test unsupported concurrent ownership rather than persisted
    // cleanup.
    let spools = DepositSyncSpoolManager::new(
        &late.state_directory,
        PartyId(5),
        &late.signing_seed,
        scenario.quic_network_id().unwrap(),
    )
    .unwrap();
    assert!(
        spools.candidate_state(&imported).await.unwrap().is_none(),
        "successful live-state CAS left its non-authoritative staging journal behind"
    );
    drop(spools);
    late.server = Some(
        PartyServer::new_with_deposits(
            PartyId(5),
            scenario.clone(),
            late.state_directory.clone(),
            &late.signing_seed,
            &late.bootstrap_x25519_secret,
            deposit_config(chains[&PartyId(5)].clone(), backends[&PartyId(5)].clone()),
        )
        .await
        .unwrap(),
    );
    start_deposit_runtime_on_endpoint(
        &mut late,
        endpoint_for(
            PartyId(5),
            quic_addresses[&PartyId(5)],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        authenticator(),
        DEPOSIT_LATE_SYNC_TEST_INTERVAL,
    );
    wait_for_http_parties(&client, &scenario, &[PartyId(5)]).await;
    let restored_deadline = Instant::now() + DEPOSIT_CHECKPOINT_TEST_TIMEOUT;
    let restored = loop {
        if let Some(advertisement) =
            try_local_deposit_sync_advertisement(late.server(), sync_context).await
        {
            break advertisement;
        }
        assert!(
            Instant::now() < restored_deadline,
            "restarted party 5 did not republish its authenticated large deposit snapshot"
        );
        tokio::time::sleep(DEPOSIT_PROGRESS_POLL_INTERVAL).await;
    };
    assert_eq!(restored.portable_index(), large_advertisement.portable_index());
    assert_eq!(restored.certificate_archive(), large_advertisement.certificate_archive());
    assert_eq!(restored.checkpoint_certificate(), large_advertisement.checkpoint_certificate());
    let restored_permanent = wait_for_permanent_deposit_http_response(
        &client,
        &scenario,
        PartyId(5),
        request,
        Instant::now() + DEPOSIT_CHECKPOINT_TEST_TIMEOUT,
        "large archive restart",
    )
    .await;
    assert_eq!(restored_permanent.status, DepositHttpStatus::Permanent);

    stop_node(&mut late).await;
    second_sync_source.endpoint.close(b"test complete");
    tokio::time::timeout(Duration::from_secs(5), &mut second_sync_source.task)
        .await
        .expect("sync-only source ignored endpoint shutdown")
        .expect("sync-only source task panicked");
}

#[test]
fn durable_avss_duplicate_and_malformed_replays_are_atomic_across_restart() {
    run_quic_epoch_liveness_test(
        4,
        None,
        durable_avss_duplicate_and_malformed_replays_are_atomic_across_restart_body(),
    );
}

async fn durable_avss_duplicate_and_malformed_replays_are_atomic_across_restart_body() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=8)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();
    let mut listeners = Vec::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=8 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(PartyId(id), listener.local_addr().unwrap());
        listeners.push(listener);
    }
    let scenario = scenario(&root, &admin_addresses, &tls);
    drop(listeners);

    let dealer = PartyServer::new(
        PartyId(1),
        scenario.clone(),
        root.path().join("replay-party-1"),
        &signing_seed(PartyId(1)),
        &bootstrap_x25519_secret(PartyId(1)),
    )
    .await
    .unwrap();
    let receiver_directory = root.path().join("replay-party-2");
    let receiver = PartyServer::new(
        PartyId(2),
        scenario.clone(),
        receiver_directory.clone(),
        &signing_seed(PartyId(2)),
        &bootstrap_x25519_secret(PartyId(2)),
    )
    .await
    .unwrap();
    let admin_server = dealer.clone();
    let mut admin_task = AbortOnDropTask::new(tokio::spawn(async move {
        admin_server.serve(admin_addresses[&PartyId(1)], authenticator()).await
    }));
    let client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    wait_for_http_parties(&client, &scenario, &[PartyId(1)]).await;

    let committee = scenario.genesis_committee().unwrap();
    let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
    let transition = AvssTransition {
        purpose: DealPurpose::Dkg,
        session,
        key_id,
        fault_bound: 1,
        history_parent: EpochHistoryParent::genesis(scenario.quic_network_id().unwrap(), key_id)
            .unwrap(),
        old: None,
        target: committee,
        eligible_dealers: vec![],
    };
    post_start(&client, &scenario, PartyId(1), &transition).await;
    let pending = dealer
        .pending_peer_messages(256)
        .await
        .into_iter()
        .find(|message| {
            message.id().session() == transition.session
                && message.id().recipient() == PartyId(2)
                && matches!(message, PendingPeerMessage::Avss { .. })
        })
        .expect("dealer did not durably enqueue party 2's AVSS message");
    let request = pending.to_quic_request().unwrap();

    assert_eq!(
        receiver.handle_quic_peer_request(PartyId(1), request.clone()).await,
        PeerResponse::Success { body: vec![] }
    );
    let accepted = receiver
        .protocol_session_status(transition.session)
        .await
        .expect("fresh AVSS delivery was not persisted");
    assert_eq!(
        receiver.handle_quic_peer_request(PartyId(1), request.clone()).await,
        PeerResponse::Success { body: vec![] },
        "exact live duplicate was not idempotent"
    );
    assert_eq!(receiver.protocol_session_status(transition.session).await, Some(accepted.clone()));

    let wrong_tls_party = receiver.handle_quic_peer_request(PartyId(3), request.clone()).await;
    assert!(matches!(
        wrong_tls_party,
        PeerResponse::Rejected { code: RejectionCode::InvalidRequest, retryable: false, .. }
    ));
    assert_eq!(receiver.protocol_session_status(transition.session).await, Some(accepted.clone()));

    let mut malformed = request.clone();
    let PeerRequest::Avss { body, .. } = &mut malformed else {
        panic!("pending AVSS effect encoded as another QUIC operation")
    };
    body.push(0);
    assert!(matches!(
        receiver.handle_quic_peer_request(PartyId(1), malformed).await,
        PeerResponse::Rejected { code: RejectionCode::InvalidRequest, retryable: false, .. }
    ));
    assert_eq!(receiver.protocol_session_status(transition.session).await, Some(accepted.clone()));

    drop(receiver);
    let restored = PartyServer::new(
        PartyId(2),
        scenario,
        receiver_directory,
        &signing_seed(PartyId(2)),
        &bootstrap_x25519_secret(PartyId(2)),
    )
    .await
    .expect("receiver failed to restore its durable AVSS replay cache");
    assert_eq!(restored.protocol_session_status(transition.session).await, Some(accepted.clone()));
    assert_eq!(
        restored.handle_quic_peer_request(PartyId(1), request).await,
        PeerResponse::Success { body: vec![] },
        "exact replay after restart was not idempotent"
    );
    assert_eq!(restored.protocol_session_status(transition.session).await, Some(accepted));

    admin_task.abort();
    let _ = admin_task.handle_mut().await;
}

#[test]
fn abrupt_runtime_restart_during_qual_survives_a_silent_round_zero_leader() {
    run_quic_epoch_liveness_test(
        8,
        None,
        abrupt_runtime_restart_during_qual_survives_a_silent_round_zero_leader_body(),
    );
}

async fn abrupt_runtime_restart_during_qual_survives_a_silent_round_zero_leader_body() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=8)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();

    let mut admin_listeners = Vec::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=8 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(PartyId(id), listener.local_addr().unwrap());
        admin_listeners.push(listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    let original_network = scenario.quic_network_id().unwrap();
    let mut quic_addresses = BTreeMap::new();
    let mut quic_reservations = Vec::new();
    for id in 1_u16..=8 {
        let endpoint = endpoint_for(
            PartyId(id),
            "127.0.0.1:0".parse().unwrap(),
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        );
        quic_addresses.insert(PartyId(id), endpoint.local_addr().unwrap());
        quic_reservations.push(endpoint);
    }
    for configured in &mut scenario.parties {
        configured.quic_endpoint =
            format!("quic://{}", quic_addresses[&configured.id]).parse().unwrap();
    }
    scenario.validate().unwrap();
    assert_eq!(scenario.quic_network_id().unwrap(), original_network);
    drop(quic_reservations);
    drop(admin_listeners);

    let mut blackhole = start_authenticated_blackhole(endpoint_for(
        PartyId(1),
        quic_addresses[&PartyId(1)],
        &scenario,
        &tls,
        QuicTransportConfig::default(),
    ));

    let mut nodes = BTreeMap::new();
    for id in 1_u16..=7 {
        let party = PartyId(id);
        let signing_seed = signing_seed(party);
        let bootstrap_x25519_secret = bootstrap_x25519_secret(party);
        let bootstrap = scenario
            .genesis_committee()
            .unwrap()
            .member(party)
            .is_ok()
            .then_some(&bootstrap_x25519_secret);
        let state_directory = root.path().join(format!("silent-party-{id}"));
        let server = PartyServer::new(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            bootstrap,
        )
        .await
        .unwrap();
        nodes.insert(
            party,
            TestNode {
                party,
                signing_seed,
                bootstrap_x25519_secret,
                state_directory,
                quic_address: quic_addresses[&party],
                admin_address: admin_addresses[&party],
                server: Some(server),
                running: None,
            },
        );
    }
    // Party 1 authenticates at QUIC but never answers any stream. It is both the deterministic
    // round-zero leader and the lowest-ID history source. History pulls therefore remain pending
    // while the independently scheduled core pacemaker must still rotate QUAL views.
    for party in (2_u16..=7).map(PartyId) {
        nodes.get_mut(&party).unwrap().start_runtime_with_qual_timeout(
            &scenario,
            &tls,
            authenticator(),
            SILENT_LEADER_QUAL_TIMEOUT,
        );
    }
    let responsive = (2_u16..=7).map(PartyId).collect::<Vec<_>>();
    // Process-style reconstruction below requires the HTTP router's final `Arc<PartyServer>` to
    // disappear before the replacement acquires its exclusive state lease. Disable pooled idle
    // connections so dropping this client closes every server-side connection task promptly.
    let mut client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http_parties(&client, &scenario, &responsive).await;

    let committee = scenario.genesis_committee().unwrap();
    let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
    let transition = AvssTransition {
        purpose: DealPurpose::Dkg,
        session,
        key_id,
        fault_bound: 1,
        history_parent: EpochHistoryParent::genesis(scenario.quic_network_id().unwrap(), key_id)
            .unwrap(),
        old: None,
        target: committee,
        eligible_dealers: vec![],
    };
    for dealer in (2_u16..=5).map(PartyId) {
        post_start(&client, &scenario, dealer, &transition).await;
    }

    let qual_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if nodes[&PartyId(3)]
            .server()
            .protocol_session_status(transition.session)
            .await
            .is_some_and(|observed| {
                observed.qual_started
                    && observed.qual_round == Some(0)
                    && !observed.qual_decided
                    && !observed.finalized
            })
        {
            break;
        }
        assert!(Instant::now() < qual_deadline, "party 3 never durably entered QUAL round zero");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Remove pooled HTTP connections before abruptly cancelling both long-running party futures.
    // No runtime shutdown method or server grace period is invoked.
    drop(client);
    crash_node(nodes.get_mut(&PartyId(3)).unwrap()).await;
    nodes.get_mut(&PartyId(3)).unwrap().restore_server(&scenario).await;
    let restored = nodes[&PartyId(3)]
        .server()
        .protocol_session_status(transition.session)
        .await
        .expect("abrupt runtime restart lost the live QUAL session");
    assert!(restored.qual_started);
    assert_eq!(restored.qual_round, Some(0));
    assert!(!restored.qual_decided);
    assert!(!restored.finalized);
    nodes.get_mut(&PartyId(3)).unwrap().start_runtime_with_qual_timeout(
        &scenario,
        &tls,
        authenticator(),
        SILENT_LEADER_QUAL_TIMEOUT,
    );
    client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http_parties(&client, &scenario, &[PartyId(3)]).await;

    let target_responsive = [PartyId(2), PartyId(3), PartyId(4), PartyId(5)];
    let mut stats = QualStats::default();
    let round_advance_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        sample_qual(&nodes, transition.session, &mut stats).await;
        let mut persisted_round_one = false;
        for party in target_responsive {
            persisted_round_one |= nodes[&party]
                .server()
                .protocol_session_status(transition.session)
                .await
                .is_some_and(|observed| observed.qual_round.is_some_and(|round| round >= 1));
        }
        if persisted_round_one {
            break;
        }
        assert!(
            Instant::now() < round_advance_deadline,
            "no honest party persisted QUAL round one after the silent-leader timeout"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let epoch = wait_for_active_parties(
        &client,
        &scenario,
        &nodes,
        &transition,
        &target_responsive,
        &mut stats,
    )
    .await;
    assert_eq!(epoch.committee.epoch, 0);
    assert!(
        stats.maximum_round.is_some_and(|round| round >= 1),
        "silent round-zero leader did not produce an observed persisted round advance"
    );
    assert!(stats.messages.len() <= 12 * 5 * 5, "QUAL retry state grew without bound");

    drop(client);
    stop_all(&mut nodes).await;
    blackhole.endpoint.close(b"test complete");
    tokio::time::timeout(Duration::from_secs(5), &mut blackhole.task)
        .await
        .expect("authenticated blackhole ignored endpoint shutdown")
        .expect("authenticated blackhole task panicked");
}

#[test]
fn scheduled_refresh_survives_authenticated_avss_equivocation_and_honest_restart_over_quic() {
    run_quic_epoch_liveness_test(
        8,
        None,
        scheduled_refresh_survives_authenticated_avss_equivocation_and_honest_restart_over_quic_body(
        ),
    );
}

async fn scheduled_refresh_survives_authenticated_avss_equivocation_and_honest_restart_over_quic_body()
 {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let root = tempfile::tempdir().unwrap();
    let mut tls = (1_u16..=8)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();

    let mut admin_listeners = BTreeMap::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=8 {
        let party = PartyId(id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(party, listener.local_addr().unwrap());
        admin_listeners.insert(party, listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    scenario.parties.retain(|party| party.id.0 <= 6);
    scenario.committees.truncate(1);
    scenario.committees[0].threshold = 3;
    scenario.committees[0].members = (1_u16..=5).map(PartyId).collect();
    scenario.committees[0].eligible_members = (1_u16..=5).map(PartyId).collect();
    scenario.proactive_refresh_interval_seconds = 5;
    tls.retain(|party, _| party.0 <= 6);
    let original_network = scenario.quic_network_id().unwrap();

    let mut initial_endpoints = BTreeMap::new();
    let mut quic_addresses = BTreeMap::new();
    for id in 1_u16..=6 {
        let party = PartyId(id);
        let endpoint = endpoint_for(
            party,
            "127.0.0.1:0".parse().unwrap(),
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        );
        quic_addresses.insert(party, endpoint.local_addr().unwrap());
        initial_endpoints.insert(party, endpoint);
    }
    for configured in &mut scenario.parties {
        if let Some(address) = quic_addresses.get(&configured.id) {
            configured.quic_endpoint = format!("quic://{address}").parse().unwrap();
        }
    }
    scenario.validate().unwrap();
    assert_eq!(scenario.quic_network_id().unwrap(), original_network);
    drop(admin_listeners);

    // A deliberately coarse outbox cadence leaves a deterministic observation window after the
    // certified receiver-key rotation launches AVSS. The protocol pacemakers remain production
    // code; only transport batching is slowed for the fault injection.
    let mut nodes = BTreeMap::new();
    for id in 1_u16..=6 {
        let party = PartyId(id);
        let signing_seed = signing_seed(party);
        let bootstrap_x25519_secret = bootstrap_x25519_secret(party);
        let bootstrap = scenario
            .genesis_committee()
            .unwrap()
            .member(party)
            .is_ok()
            .then_some(&bootstrap_x25519_secret);
        let state_directory = root.path().join(format!("equivocation-party-{id}"));
        let server = PartyServer::new(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            bootstrap,
        )
        .await
        .unwrap();
        let endpoint = initial_endpoints.remove(&party).unwrap();
        let runtime = Arc::new(
            QuicRuntime::new(
                endpoint,
                server.clone(),
                QuicRuntimeConfig {
                    outbox_poll_interval: Duration::from_millis(500),
                    protocol_progress_interval: Duration::from_millis(20),
                    retry_initial: Duration::from_millis(20),
                    retry_maximum: Duration::from_millis(250),
                    qual_round_timeout: Some(LIVE_QUAL_TIMEOUT),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        server.mark_quic_runtime_attached().unwrap();
        let runtime_task = tokio::spawn(runtime.clone().run());
        let server_for_http = server.clone();
        let admin_address = admin_addresses[&party];
        let admin_task =
            tokio::spawn(
                async move { server_for_http.serve(admin_address, authenticator()).await },
            );
        nodes.insert(
            party,
            TestNode {
                party,
                signing_seed,
                bootstrap_x25519_secret,
                state_directory,
                quic_address: quic_addresses[&party],
                admin_address,
                server: Some(server),
                running: Some(RunningNode { runtime, runtime_task, admin_task }),
            },
        );
    }

    let mut client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    let initial_parties = (1_u16..=5).map(PartyId).collect::<Vec<_>>();
    wait_for_http_parties(&client, &scenario, &initial_parties).await;
    let committee = scenario.genesis_committee().unwrap();
    assert_eq!(committee.n(), 5);
    assert_eq!(committee.threshold, 3);
    committee.validate_async_security_with_faults(1).unwrap();
    let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
    let dkg = AvssTransition {
        purpose: DealPurpose::Dkg,
        session,
        key_id,
        fault_bound: 1,
        history_parent: EpochHistoryParent::genesis(scenario.quic_network_id().unwrap(), key_id)
            .unwrap(),
        old: None,
        target: committee,
        eligible_dealers: vec![],
    };
    for dealer in (1_u16..=5).map(PartyId) {
        post_start(&client, &scenario, dealer, &dkg).await;
    }
    let mut dkg_stats = QualStats::default();
    let epoch_zero = wait_for_active(&client, &scenario, &nodes, &dkg, &mut dkg_stats).await;

    let refresh_schedule = status(&client, &scenario, PartyId(1))
        .await
        .proactive_refresh
        .expect("epoch zero did not arm its fixed refresh");
    assert_eq!(refresh_schedule.source_epoch, 0);
    assert_eq!(refresh_schedule.target_epoch, Some(1));
    let refresh_due = refresh_schedule.due_unix_ms.expect("fixed refresh omitted its deadline");

    // The fixed deadline first drives a full receiver-key BA. Capture party 1 only after that
    // certificate has materialized the canonical same-committee refresh and its honest dealer
    // message is durable. The coarse relay cadence gives this fixture a capture opportunity, but
    // the live relay may still win the race; the exact-request helper then waits for that
    // in-flight durable application before the conflicting branch is sent.
    let capture_deadline = Instant::now() + TEST_TIMEOUT;
    let (refresh, honest_dealer_requests) = loop {
        let mut transition = None;
        let mut requests = BTreeMap::new();
        for pending in nodes[&PartyId(1)].server().pending_peer_messages(256).await {
            let PendingPeerMessage::Avss { request, .. } = &pending else {
                continue;
            };
            if request.transition.target.epoch != 1
                || request.transition.purpose != DealPurpose::Refresh
            {
                continue;
            }
            if let Some(found) = &transition {
                assert_eq!(found, &request.transition);
            } else {
                transition = Some(request.transition.clone());
            }
            let recipient = pending.id().recipient();
            if matches!(recipient, PartyId(2) | PartyId(3)) {
                requests.insert(recipient, pending.to_quic_request().unwrap());
            }
        }
        if let Some(transition) = transition
            && requests.len() == 2
        {
            break (transition, requests);
        }
        assert!(
            Instant::now() < capture_deadline,
            "fixed deadline did not durably launch party 1's same-committee refresh"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    assert!(current_time_millis() >= refresh_due);
    assert_eq!(refresh.old.as_ref(), Some(&epoch_zero));
    assert_eq!(refresh.target.threshold, epoch_zero.committee.threshold);
    assert_eq!(
        refresh.target.members.iter().map(|member| member.id).collect::<Vec<_>>(),
        epoch_zero.committee.members.iter().map(|member| member.id).collect::<Vec<_>>()
    );
    assert!(
        refresh.target.members.iter().all(|member| {
            member.encryption_key != epoch_zero.committee.member(member.id).unwrap().encryption_key
        }),
        "fixed refresh reused an epoch-zero receiver key"
    );

    // Party 1 now equivocates through a second endpoint authenticated by the same stable identity.
    // Its ordinary process remains live, so this case isolates Byzantine same-slot behavior from
    // an unrelated transport-partition fault.
    let honest = [PartyId(2), PartyId(3), PartyId(4), PartyId(5)];
    let honest_started_deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let mut all_started = true;
        for party in honest {
            all_started &=
                nodes[&party].server().protocol_session_status(refresh.session).await.is_some();
        }
        if all_started {
            break;
        }
        assert!(
            Instant::now() < honest_started_deadline,
            "honest n-f parties did not enter the certified refresh"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let byzantine_identity = identity_from_explicit_secrets(
        PartyId(1),
        0,
        &nodes[&PartyId(1)].signing_seed,
        nodes[&PartyId(1)].bootstrap_x25519_secret,
    );
    assert_eq!(
        byzantine_identity.encryption_public_key(),
        epoch_zero.committee.member(PartyId(1)).unwrap().encryption_key
    );
    let avss_config = AvssConfig {
        session: refresh.session,
        dealer: PartyId(1),
        receivers: refresh.target.clone(),
        fault_bound: refresh.fault_bound,
    };
    let conflicting_dealer =
        AvssDealer::random_zero_constant(avss_config, &mut ChaCha20Rng::from_seed([0xB2; 32]))
            .unwrap();
    let conflicting_messages = conflicting_dealer.private_messages().unwrap();
    let conflicting_commitment = conflicting_messages[0].message.commitment_digest;
    assert!(conflicting_messages.iter().all(|message| {
        message.message.commitment_digest == conflicting_commitment
            && matches!(&message.message.payload, AvssPayload::DealerSend(_))
    }));

    let byzantine_endpoint = endpoint_for(
        PartyId(1),
        "127.0.0.1:0".parse().unwrap(),
        &scenario,
        &tls,
        QuicTransportConfig::default(),
    );
    let mut replay_after_restart = None;
    for recipient in [PartyId(2), PartyId(3)] {
        let conflicting_private = conflicting_messages
            .iter()
            .find(|message| message.recipient == recipient)
            .unwrap()
            .clone();
        let mut conflicting_rng =
            ChaCha20Rng::from_seed([0xD0_u8.wrapping_add(u8::try_from(recipient.0).unwrap()); 32]);
        let conflicting_wire = seal_conflicting_refresh_dealer_send(
            &byzantine_identity,
            &refresh,
            conflicting_private,
            &mut conflicting_rng,
        );
        let first_request = honest_dealer_requests[&recipient].clone();
        let conflicting_request = PeerRequest::Avss {
            operation: threshold_monero::quic_transport::AvssOperation::Deliver,
            body: postcard::to_allocvec(&threshold_monero::server::AvssDeliverRequest {
                transition: refresh.clone(),
                wire: conflicting_wire,
            })
            .unwrap(),
        };
        assert_ne!(first_request, conflicting_request);
        assert_eq!(
            send_authenticated_peer_request(
                &byzantine_endpoint,
                &scenario,
                recipient,
                first_request.clone(),
            )
            .await,
            PeerResponse::Success { body: vec![] },
            "honest receiver rejected the first valid Byzantine dealer slot"
        );
        assert!(
            matches!(
                send_authenticated_peer_request(
                    &byzantine_endpoint,
                    &scenario,
                    recipient,
                    conflicting_request.clone(),
                )
                .await,
                PeerResponse::Rejected { code: RejectionCode::Conflict, retryable: false, .. }
            ),
            "honest receiver accepted a second commitment for one authenticated dealer slot"
        );
        if recipient == PartyId(3) {
            replay_after_restart = Some((first_request, conflicting_request));
        }
    }

    // Crash an honest receiver after it durably accepted one branch and rejected the other.
    // Exact replay must remain idempotent, while the conflicting signed branch remains rejected
    // after reconstructing the reducer and QUIC listener from authenticated storage.
    drop(client);
    crash_node(nodes.get_mut(&PartyId(3)).unwrap()).await;
    nodes.get_mut(&PartyId(3)).unwrap().restore_server(&scenario).await;
    nodes.get_mut(&PartyId(3)).unwrap().start_runtime(&scenario, &tls, authenticator());
    client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http_parties(&client, &scenario, &[PartyId(3)]).await;
    let (first_replay, conflicting_replay) = replay_after_restart.unwrap();
    assert_eq!(
        send_authenticated_peer_request(&byzantine_endpoint, &scenario, PartyId(3), first_replay,)
            .await,
        PeerResponse::Success { body: vec![] },
        "restart lost the exact accepted Byzantine AVSS replay"
    );
    assert!(matches!(
        send_authenticated_peer_request(
            &byzantine_endpoint,
            &scenario,
            PartyId(3),
            conflicting_replay,
        )
        .await,
        PeerResponse::Rejected { code: RejectionCode::Conflict, retryable: false, .. }
    ));
    byzantine_endpoint.close(b"Byzantine injection complete");
    byzantine_endpoint.wait_idle().await;

    // The honest n-f receivers still complete AVSS, decide one QUAL value, activate one successor,
    // and preserve the DKG constant term despite the authenticated same-slot equivocation.
    // This one deadline spans a real transport restart and the still-pending AVSS drain before
    // QUAL gets its first full 10-second view. Keep it bounded, but allow one production-default
    // 30-second outbound attempt plus the 10+20-second QUAL view schedule and activation relay.
    let mut refresh_stats = QualStats::default();
    let epoch_one = wait_for_active_parties_with_timeout(
        &client,
        &scenario,
        &nodes,
        &refresh,
        &honest,
        &mut refresh_stats,
        AUTONOMOUS_EPOCH_TIMEOUT,
    )
    .await;
    assert_eq!(epoch_one.committee, refresh.target);
    assert_eq!(epoch_one.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_one.key_id, epoch_zero.key_id);
    assert_ne!(epoch_one.verification_shares, epoch_zero.verification_shares);

    let mut certified_history = None;
    for party in honest {
        let retirement_deadline = Instant::now() + TEST_TIMEOUT;
        let observed = loop {
            let observed = status_before(&client, &scenario, party, retirement_deadline).await;
            let installed = observed.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>();
            if observed.active_epoch == Some(1) && installed == vec![1] {
                break observed;
            }
            assert!(
                Instant::now() < retirement_deadline,
                "party {party} did not retire the predecessor after successor activation; active={:?}, installed={installed:?}",
                observed.active_epoch
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        assert_eq!(observed.active_epoch, Some(1));
        assert!(observed.staged_epochs.is_empty(), "party {party} retained a competing successor");
        assert_eq!(
            observed.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>(),
            vec![1],
            "party {party} installed more than the one certified successor"
        );
        assert_eq!(observed.epochs[0].public, epoch_one);
        if let Some(expected) = &certified_history {
            assert_eq!(
                &observed.epochs[0].history_link, expected,
                "party {party} installed another transcript-bound activation"
            );
        } else {
            certified_history = Some(observed.epochs[0].history_link);
        }
        match nodes[&party].server().protocol_session_status(refresh.session).await {
            Some(session) => assert!(
                session.secret_compacted,
                "activated refresh retained uncompacted secret reducer state"
            ),
            None => assert!(
                nodes[&party]
                    .server()
                    .protocol_transition_is_durably_closed(&refresh)
                    .await
                    .unwrap(),
                "activated refresh omitted both its compacted reducer and authenticated closure"
            ),
        }
        let next = observed.proactive_refresh.expect("successor did not arm its next refresh");
        assert_eq!(next.source_epoch, 1);
        assert_eq!(next.target_epoch, Some(2));
        assert!(
            next.due_unix_ms.is_some_and(|due| due > refresh_due),
            "successor retained the predecessor's fixed refresh deadline"
        );
    }

    drop(client);
    stop_all(&mut nodes).await;
}

#[test]
fn persistent_quic_grow_shrink_restart_gates_qual_and_never_uses_http_peer_relay() {
    run_quic_epoch_liveness_test(
        8,
        None,
        persistent_quic_grow_shrink_restart_gates_qual_and_never_uses_http_peer_relay_body(),
    );
}

async fn persistent_quic_grow_shrink_restart_gates_qual_and_never_uses_http_peer_relay_body() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=8)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();

    // Hold all admin ports until every address has been embedded in the scenario.
    let mut admin_listeners = BTreeMap::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=8 {
        let party = PartyId(id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(party, listener.local_addr().unwrap());
        admin_listeners.insert(party, listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    // Exercise several autonomous epochs on a short real clock while leaving a finite observation
    // window after an n-f activation quorum. A one-second dwell lets the next receiver-key round
    // legitimately retire a source-only member before this black-box test can sample the certified
    // predecessor, which tests scheduler throughput rather than epoch safety or persistence.
    scenario.proactive_refresh_interval_seconds = 5;
    let original_network = scenario.quic_network_id().unwrap();

    // QUIC routing is deployment metadata, so endpoints can bind ephemeral ports without changing
    // the cryptographic network ID.
    let mut initial_endpoints = BTreeMap::new();
    let mut quic_addresses = BTreeMap::new();
    for id in 1_u16..=8 {
        let party = PartyId(id);
        let endpoint = endpoint_for(
            party,
            "127.0.0.1:0".parse().unwrap(),
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        );
        quic_addresses.insert(party, endpoint.local_addr().unwrap());
        initial_endpoints.insert(party, endpoint);
    }
    for configured in &mut scenario.parties {
        configured.quic_endpoint =
            format!("quic://{}", quic_addresses[&configured.id]).parse().unwrap();
    }
    scenario.validate().unwrap();
    assert_eq!(scenario.quic_network_id().unwrap(), original_network);
    drop(admin_listeners);

    let mut nodes = BTreeMap::new();
    for id in 1_u16..=8 {
        let party = PartyId(id);
        let signing_seed = signing_seed(party);
        let bootstrap_x25519_secret = bootstrap_x25519_secret(party);
        let bootstrap = scenario
            .genesis_committee()
            .unwrap()
            .member(party)
            .is_ok()
            .then_some(&bootstrap_x25519_secret);
        let state_directory = root.path().join(format!("party-{id}"));
        let server = PartyServer::new(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            bootstrap,
        )
        .await
        .unwrap();
        let endpoint = initial_endpoints.remove(&party).unwrap();
        let runtime = Arc::new(
            QuicRuntime::new(
                endpoint,
                server.clone(),
                QuicRuntimeConfig {
                    outbox_poll_interval: Duration::from_millis(25),
                    protocol_progress_interval: Duration::from_millis(20),
                    retry_initial: Duration::from_millis(20),
                    retry_maximum: Duration::from_millis(250),
                    qual_round_timeout: Some(LIVE_QUAL_TIMEOUT),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        server.mark_quic_runtime_attached().unwrap();
        let runtime_task = tokio::spawn(runtime.clone().run());
        let server_for_http = server.clone();
        let admin_address = admin_addresses[&party];
        let admin_task =
            tokio::spawn(
                async move { server_for_http.serve(admin_address, authenticator()).await },
            );
        nodes.insert(
            party,
            TestNode {
                party,
                signing_seed,
                bootstrap_x25519_secret,
                state_directory,
                quic_address: quic_addresses[&party],
                admin_address,
                server: Some(server),
                running: Some(RunningNode { runtime, runtime_task, admin_task }),
            },
        );
    }

    // Process-style reconstruction below requires the HTTP router's final `Arc<PartyServer>` to
    // disappear before the replacement acquires its exclusive state lease. Disable pooled idle
    // connections so dropping this client closes every server-side connection task promptly.
    let mut client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http(&client, &scenario).await;

    // Live peer delivery routes do not exist on HTTP. Only operator start/status remain.
    for removed_peer_path in [
        "/v1/avss/deliver",
        "/v1/qual/deliver",
        "/v1/qual/advance",
        "/v1/epoch/activation-ack",
        "/v1/epoch/activate",
        "/v1/epoch/retire",
    ] {
        let endpoint =
            scenario.party(PartyId(1)).unwrap().admin_endpoint.join(removed_peer_path).unwrap();
        let response = client
            .post(endpoint)
            .bearer_auth(std::str::from_utf8(ADMIN_TOKEN).unwrap())
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "removed peer HTTP route exists");
    }

    let initial = scenario.genesis_committee().unwrap();
    let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
    let dkg = AvssTransition {
        purpose: DealPurpose::Dkg,
        session,
        key_id,
        fault_bound: 1,
        history_parent: EpochHistoryParent::genesis(scenario.quic_network_id().unwrap(), key_id)
            .unwrap(),
        old: None,
        target: initial,
        eligible_dealers: vec![],
    };
    for dealer in 1_u16..=5 {
        post_start(&client, &scenario, PartyId(dealer), &dkg).await;
    }
    let mut dkg_stats = QualStats::default();
    let epoch_zero = wait_for_active(&client, &scenario, &nodes, &dkg, &mut dkg_stats).await;
    assert_eq!(dkg_stats.maximum_round, Some(0));

    let grow_policy = scenario
        .configured_key_rotation_target_shape(&epoch_zero.committee)
        .unwrap()
        .expect("configured grow policy is absent");
    assert_eq!(grow_policy.target_epoch(), 1);
    assert_eq!(grow_policy.target_fault_bound(), 1);
    assert_eq!(grow_policy.eligible().threshold, 4);
    assert_eq!(
        grow_policy.eligible().members.iter().map(|member| member.id).collect::<Vec<_>>(),
        (1_u16..=7).map(PartyId).collect::<Vec<_>>()
    );
    let grow_schedule = status(&client, &scenario, PartyId(1))
        .await
        .proactive_refresh
        .expect("epoch zero did not persist its configured grow deadline");
    assert_eq!(grow_schedule.source_epoch, 0);
    assert_eq!(grow_schedule.target_epoch, Some(1));
    let grow_due = grow_schedule.due_unix_ms.expect("configured grow deadline is absent");

    // Let the just-decided epoch-zero QUAL fully drain before exercising the overdue grow tick.
    // Activation only requires an n-f PREVOTE/PRECOMMIT quorum, so the last decider can still hold
    // undelivered epoch-zero QUAL retries the instant `wait_for_active` returns. Draining them here
    // keeps the no-QUAL assertion below scoped to grow-ceremony state rather than epoch-zero
    // residue that a restart would faithfully restore.
    let drain_deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let mut pending = false;
        for node in nodes.values() {
            pending |= node
                .server()
                .pending_peer_messages(256)
                .await
                .iter()
                .any(|message| matches!(message, PendingPeerMessage::Qual { .. }));
        }
        if !pending {
            break;
        }
        assert!(
            Instant::now() < drain_deadline,
            "epoch-zero QUAL did not drain before the grow ceremony"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Stop the entire network before the configured deadline and reconstruct every party from its
    // authenticated state. This proves a process restart cannot reset the proactive epoch clock.
    // The first overdue tick is deliberately run without transport: it must durably start only
    // receiver-key rotation and cannot emit QUAL before a target committee is certified.
    drop(client);
    stop_all(&mut nodes).await;
    let overdue_wait = grow_due.saturating_sub(current_time_millis()).saturating_add(100);
    tokio::time::sleep(Duration::from_millis(overdue_wait)).await;
    for node in nodes.values_mut() {
        node.restore_server(&scenario).await;
    }
    nodes[&PartyId(1)]
        .server()
        .progress_protocols(current_time_millis(), MANUAL_QUAL_TIMEOUT)
        .await
        .unwrap();
    assert!(
        !nodes[&PartyId(1)].server().pending_key_rotation_peer_messages(256).await.is_empty(),
        "overdue configured grow did not durably start receiver-key rotation"
    );
    let mut premature_qual = false;
    for node in nodes.values() {
        premature_qual |= node
            .server()
            .pending_peer_messages(256)
            .await
            .iter()
            .any(|message| matches!(message, PendingPeerMessage::Qual { .. }));
    }
    assert!(
        !premature_qual,
        "QUAL was emitted before the configured grow target committee was certified"
    );

    // Rebind every endpoint at its original route. Joining parties learn the certified target over
    // QUIC and advertise independently generated receiver keys; no future encryption key existed
    // in the scenario or before this ceremony.
    for node in nodes.values_mut() {
        node.start_runtime(&scenario, &tls, authenticator());
    }
    client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http(&client, &scenario).await;

    let grow_parties =
        grow_policy.eligible().members.iter().map(|member| member.id).collect::<Vec<_>>();
    let (epoch_one, epoch_one_witnesses) = wait_for_selected_autonomous_epoch(
        &client,
        &scenario,
        &nodes,
        &grow_parties,
        grow_policy.desired_n(),
        grow_policy.target_fault_bound(),
        1,
    )
    .await;
    assert_eq!(epoch_one.committee.threshold, 4);
    assert_eq!(epoch_one.committee.n(), grow_policy.desired_n());
    let grow_fresh_keys = epoch_one
        .committee
        .members
        .iter()
        .filter(|member| {
            member.encryption_key
                != grow_policy.eligible().member(member.id).unwrap().encryption_key
        })
        .count();
    assert_eq!(grow_fresh_keys, usize::from(grow_policy.desired_n()));
    assert_eq!(epoch_one.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_one.key_id, epoch_zero.key_id);

    // Parties 1 and 5 are excluded from the configured shrink eligibility, and a six-of-seven
    // grow committee must contain at least one of them. Prove that the selected retiree actually
    // activated epoch one before using its disk as evidence for both 0->1 and 1->2 retirement.
    // Committee membership alone is insufficient because activation intentionally returns after
    // n-f witnesses.
    let two_boundary_candidates = [PartyId(1), PartyId(5)]
        .into_iter()
        .filter(|party| epoch_one.committee.member(*party).is_ok())
        .collect::<Vec<_>>();
    assert!(
        !two_boundary_candidates.is_empty(),
        "six-of-seven grow omitted both configured shrink-ineligible retirement candidates"
    );
    let mut retired_party =
        two_boundary_candidates.iter().copied().find(|party| epoch_one_witnesses.contains(party));
    let ownership_deadline = Instant::now() + TEST_TIMEOUT;
    while retired_party.is_none() {
        for party in &two_boundary_candidates {
            let observed = status_before(&client, &scenario, *party, ownership_deadline).await;
            if let Some(observed_epoch) = observed.epochs.iter().find(|epoch| epoch.epoch == 1) {
                assert_eq!(
                    observed_epoch.public, epoch_one,
                    "retirement candidate {party} installed a conflicting epoch-one value"
                );
                retired_party = Some(*party);
                break;
            }
            // Status snapshots the share map before `active_epoch`. Retirement removes them in
            // the same order, so this narrow observation can only occur while retirement is
            // between share-map removal and clearing the active marker. The candidate therefore
            // owned epoch one; the exact committee-bound tombstones below remain the
            // authoritative durable assertion.
            if observed.active_epoch == Some(1) {
                retired_party = Some(*party);
                break;
            }
        }
        if retired_party.is_some() {
            break;
        }
        assert!(
            Instant::now() < ownership_deadline,
            "no shrink-ineligible grow member proved ownership of an epoch-one share"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let retired_party = retired_party.expect("retirement candidate loop exited without a witness");

    let shrink_policy = scenario
        .configured_key_rotation_target_shape(&epoch_one.committee)
        .unwrap()
        .expect("configured shrink policy is absent");
    assert_eq!(shrink_policy.target_epoch(), 2);
    assert_eq!(shrink_policy.target_fault_bound(), 1);
    assert_eq!(shrink_policy.eligible().threshold, 3);
    let shrink_parties =
        shrink_policy.eligible().members.iter().map(|member| member.id).collect::<Vec<_>>();
    assert_eq!(
        shrink_parties,
        [PartyId(2), PartyId(3), PartyId(4), PartyId(6), PartyId(7), PartyId(8)]
    );
    let (epoch_two, _) = wait_for_selected_autonomous_epoch(
        &client,
        &scenario,
        &nodes,
        &shrink_parties,
        shrink_policy.desired_n(),
        shrink_policy.target_fault_bound(),
        2,
    )
    .await;
    assert_eq!(epoch_two.committee.threshold, 3);
    assert_eq!(epoch_two.committee.n(), shrink_policy.desired_n());
    let shrink_fresh_keys = epoch_two
        .committee
        .members
        .iter()
        .filter(|member| {
            member.encryption_key
                != shrink_policy.eligible().member(member.id).unwrap().encryption_key
        })
        .count();
    assert_eq!(shrink_fresh_keys, usize::from(shrink_policy.desired_n()));
    assert_eq!(epoch_two.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_two.key_id, epoch_zero.key_id);

    // Crash one certificate-selected current member before the first deadline so dynamic key
    // rotation must substitute an eligible spare.
    assert!(scenario.committee_spec(3).is_err());
    assert!(scenario.committee_spec(4).is_err());
    let silent_party = epoch_two.committee.members.last().unwrap().id;
    crash_node(nodes.get_mut(&silent_party).unwrap()).await;

    let epoch_two_parties =
        epoch_two.committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
    let old_only_grow_parties = epoch_one
        .committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| !epoch_two_parties.contains(party))
        .collect::<Vec<_>>();
    assert!(
        !old_only_grow_parties.is_empty(),
        "shrink selected every grow source and exercised no source-only retirement"
    );
    assert!(
        old_only_grow_parties.contains(&retired_party),
        "the witnessed two-boundary retiree unexpectedly joined the shrink committee"
    );
    let retirement_deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_retirement_statuses = BTreeMap::new();
    loop {
        let mut obsolete_shares_erased = true;
        for party in &old_only_grow_parties {
            let observed = status_before(&client, &scenario, *party, retirement_deadline).await;
            last_retirement_statuses.insert(
                *party,
                (
                    observed.active_epoch,
                    observed.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>(),
                    observed.proactive_refresh.clone(),
                ),
            );
            // The next fixed interval can already select an old member as an eligible spare.
            // Such a party legitimately holds a fresh epoch-three share while this loop observes
            // it; require only that every pre-shrink share has become unusable.
            obsolete_shares_erased &=
                observed.active_epoch.is_none_or(|epoch| epoch >= epoch_two.committee.epoch)
                    && observed.epochs.iter().all(|epoch| epoch.epoch >= epoch_two.committee.epoch);
        }
        if obsolete_shares_erased {
            break;
        }
        assert!(
            Instant::now() < retirement_deadline,
            "old-only grow members retained obsolete active or historical secret shares: \
             {last_retirement_statuses:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Retirement leaves an authenticated non-secret marker at every obsolete epoch path the
    // removed party actually owned. A fresh store must reject those shares and must not find the
    // former encrypted records in the recoverable quarantine used by older builds.
    let retired_store = ShareStore::new(
        &nodes[&retired_party].state_directory,
        retired_party,
        &nodes[&retired_party].signing_seed,
    )
    .unwrap();
    let retired_boundaries =
        [(0, epoch_zero.committee.digest(), 1), (1, epoch_one.committee.digest(), 2)];
    wait_for_exact_share_retirement_markers(
        &retired_store,
        &retired_boundaries,
        "configured grow/shrink retirement",
    )
    .await;
    for (epoch, committee, _) in retired_boundaries {
        assert!(
            !tokio::fs::try_exists(
                nodes[&retired_party]
                    .state_directory
                    .join("retired")
                    .join(format!("epoch-{epoch}.{}.share", hex::encode(committee)))
            )
            .await
            .unwrap()
        );
    }

    // The fixed-interval scheduler, rather than an operator start request or a finite list of
    // targets, drives a real dynamic key rotation with an eligible spare substitution.
    let eligible_refresh_parties = nodes
        .iter()
        .filter_map(|(party, node)| node.running.is_some().then_some(*party))
        .collect::<Vec<_>>();
    let (epoch_three, epoch_three_witnesses) = wait_for_selected_autonomous_epoch(
        &client,
        &scenario,
        &nodes,
        &eligible_refresh_parties,
        5,
        1,
        3,
    )
    .await;
    assert_eq!(epoch_three.committee.threshold, 3);
    assert_eq!(epoch_three.committee.n(), 5);
    epoch_three.committee.validate_async_security_with_faults(1).unwrap();
    assert!(
        epoch_three.committee.member(silent_party).is_err(),
        "dynamic refresh retained the certificate-selected party whose process was absent"
    );
    assert!(
        epoch_three.committee.members.iter().any(|member| !epoch_two_parties.contains(&member.id)),
        "dynamic refresh did not substitute an eligible live member"
    );
    assert_eq!(epoch_three.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_three.key_id, epoch_zero.key_id);
    assert_ne!(epoch_three.verification_shares, epoch_two.verification_shares);
    let epoch_three_probe =
        *epoch_three_witnesses.first().expect("selected epoch three has no active quorum member");
    let after_three = status(&client, &scenario, epoch_three_probe)
        .await
        .proactive_refresh
        .expect("epoch three did not persist its next refresh deadline");
    assert_eq!(after_three.source_epoch, 3);
    assert_eq!(after_three.target_epoch, Some(4));
    let due_four = after_three.due_unix_ms.expect("epoch four deadline is absent");

    // Stop every remaining process before the next refresh and do not restart until its durable
    // deadline is overdue. Reconstruct every live quorum member from disk; the first progress
    // tick on all five epoch-three committee members must resume exactly the persisted
    // epoch-three-to-four operation rather than re-arming the interval from wall-clock startup
    // time.
    drop(client);
    stop_all(&mut nodes).await;
    let overdue_wait = due_four.saturating_sub(current_time_millis()).saturating_add(100);
    tokio::time::sleep(Duration::from_millis(overdue_wait)).await;
    let live_refresh_parties =
        epoch_three.committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
    for party in &live_refresh_parties {
        nodes.get_mut(party).unwrap().restore_server(&scenario).await;
        nodes.get_mut(party).unwrap().start_runtime(&scenario, &tls, authenticator());
    }
    client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http_parties(&client, &scenario, &live_refresh_parties).await;

    let (epoch_four, epoch_four_witnesses) = wait_for_selected_autonomous_epoch(
        &client,
        &scenario,
        &nodes,
        &live_refresh_parties,
        5,
        1,
        4,
    )
    .await;
    assert_eq!(epoch_four.committee.threshold, 3);
    assert_eq!(epoch_four.committee.n(), 5);
    epoch_four.committee.validate_async_security_with_faults(1).unwrap();
    let epoch_four_fault_bound = 1_u16;
    let live_refresh_set = live_refresh_parties.iter().copied().collect::<BTreeSet<_>>();
    let live_epoch_four_members = epoch_four
        .committee
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| live_refresh_set.contains(party))
        .collect::<BTreeSet<_>>();
    assert!(
        live_epoch_four_members.len()
            >= usize::from(epoch_four.committee.n() - epoch_four_fault_bound),
        "fixed-size successor omitted more than the tolerated unavailable member"
    );
    assert!(
        epoch_four
            .committee
            .members
            .iter()
            .filter(|member| !live_refresh_set.contains(&member.id))
            .count()
            <= usize::from(epoch_four_fault_bound),
        "fixed-size successor selected more unavailable candidates than its fault bound"
    );
    assert_eq!(epoch_four.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_four.key_id, epoch_zero.key_id);
    assert_ne!(epoch_four.verification_shares, epoch_three.verification_shares);
    let epoch_four_probe =
        *epoch_four_witnesses.first().expect("selected epoch four has no active quorum member");
    let after_four = status(&client, &scenario, epoch_four_probe)
        .await
        .proactive_refresh
        .expect("epoch four did not arm another dynamic refresh");
    assert_eq!(after_four.source_epoch, 4);
    assert_eq!(after_four.target_epoch, Some(5));
    let due_five = after_four.due_unix_ms.expect("epoch five deadline is absent");
    assert!(due_five > due_four, "successor deadline did not advance monotonically");
    assert!(
        current_time_millis() < due_five,
        "overdue restart cascaded immediately through more than one refresh epoch"
    );

    let refreshed_party = epoch_four
        .committee
        .members
        .iter()
        .map(|member| member.id)
        .find(|party| {
            epoch_four_witnesses.contains(party)
                && epoch_two.committee.member(*party).is_ok()
                && epoch_three.committee.member(*party).is_ok()
        })
        .expect("successive live committees have no member with both retirement boundaries");
    let refreshed_store = ShareStore::new(
        &nodes[&refreshed_party].state_directory,
        refreshed_party,
        &nodes[&refreshed_party].signing_seed,
    )
    .unwrap();
    let refreshed_boundaries =
        [(2, epoch_two.committee.digest(), 3), (3, epoch_three.committee.digest(), 4)];
    wait_for_exact_share_retirement_markers(
        &refreshed_store,
        &refreshed_boundaries,
        "fixed-interval refresh retirement",
    )
    .await;

    // This is a bounded test-only stop, not a protocol terminal committee. It leaves the durable
    // epoch-four schedule armed for epoch five and proves the implementation has no finite target.
    drop(client);
    stop_all(&mut nodes).await;

    // A true process-style reconstruction authenticates the tombstones and does not reload an
    // obsolete share into the signing map. A current refresh member resumes at epoch four.
    let observer_parties = eligible_refresh_parties
        .iter()
        .copied()
        .filter(|party| epoch_four.committee.member(*party).is_err())
        .collect::<Vec<_>>();
    assert!(
        observer_parties.len() >= 2,
        "dynamic refresh did not leave the expected observer capacity"
    );
    let observer_party = observer_parties[0];
    nodes.get_mut(&observer_party).unwrap().restore_server(&scenario).await;
    nodes.get_mut(&refreshed_party).unwrap().restore_server(&scenario).await;
    nodes.get_mut(&observer_party).unwrap().start_runtime(&scenario, &tls, authenticator());
    nodes.get_mut(&refreshed_party).unwrap().start_runtime(&scenario, &tls, authenticator());
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    wait_for_http_parties(&client, &scenario, &[observer_party, refreshed_party]).await;
    let restored_status = status(&client, &scenario, observer_party).await;
    assert_eq!(restored_status.active_epoch, None);
    assert!(restored_status.epochs.is_empty());
    let refreshed_status = status(&client, &scenario, refreshed_party).await;
    assert_eq!(refreshed_status.active_epoch, Some(4));
    assert_eq!(
        refreshed_status.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>(),
        vec![4]
    );
    drop(client);
    stop_all(&mut nodes).await;
}
