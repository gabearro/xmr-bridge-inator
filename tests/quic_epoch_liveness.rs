use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
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
    config::{CommitteeSpec, Hex32, NetworkKind, Operation, Scenario, ScenarioParty},
    deposit_index_checkpoint::DepositIndexCheckpointOperation,
    deposit_ledger::{LedgerRequestId, RequestBinding},
    deposit_service::DepositAddressRequest,
    deposit_sync_wire::{DepositSyncAdvertisement, DepositSyncContext, DepositSyncHeadRequest},
    deposit_wallet::{ChainPoint, DepositAddressDeriver, PersistedWalletOutput, ScannedBlock},
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
        QuicPeerEndpoint, QuicTransportConfig, RejectionCode,
    },
    reconnecting_monero::ReconnectingMoneroDaemon,
    server::{
        AvssStartRequest, AvssStepResponse, AvssTransition, DealPurpose, DepositHttpResponse,
        DepositHttpStatus, PartyDepositConfig, PartyServer, PartyStatus, PeerMessageId,
        PendingPeerMessage, canonical_dkg_identity,
    },
    storage::{ShareStore, StoreError},
};
use tokio::{task::JoinHandle, time::Instant};
use x25519_dalek::{PublicKey as EncryptionPublicKey, StaticSecret};
use zeroize::Zeroizing;

const ADMIN_TOKEN: &[u8] = b"quic-epoch-test-admin-token-0000000000000000";
const DEPOSIT_TOKEN: &[u8] = b"quic-epoch-test-deposit-token-000000000000";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const LIVE_QUAL_TIMEOUT: Duration = Duration::from_secs(10);
const MANUAL_QUAL_TIMEOUT: Duration = Duration::from_millis(100);
const SILENT_LEADER_QUAL_TIMEOUT: Duration = Duration::from_millis(500);

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
        self.server = Some(
            PartyServer::new(
                self.party,
                scenario.clone(),
                self.state_directory.clone(),
                &self.signing_seed,
                &self.bootstrap_x25519_secret,
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

/// Drop the listener/runtime futures without giving either one a graceful-shutdown checkpoint.
/// Every reducer mutation which survives this boundary must therefore already be in the encrypted
/// protocol store, matching the process semantics of SIGKILL rather than SIGTERM.
async fn crash_node(node: &mut TestNode) {
    let quic_address = node.quic_address;
    let tasks = node.running.take().expect("test node is not running");
    node.server().mark_quic_runtime_detached();
    tasks.runtime_task.abort();
    tasks.admin_task.abort();
    let _ = tasks.runtime_task.await;
    let _ = tasks.admin_task.await;
    // Aborting the outer runtime deliberately gives reducers no graceful-shutdown checkpoint.
    // Quinn connection/handshake tasks can nevertheless retain endpoint clones until transport
    // closure wakes them. A real SIGKILL releases those process-owned descriptors before exec of
    // the replacement, so model that resource boundary explicitly and without a timing sleep.
    tasks.runtime.terminate_transport_after_task_abort().await;
    drop(tasks.runtime);
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
    .expect("simulated SIGKILL did not release the QUIC socket");
}

async fn stop_node(node: &mut TestNode) {
    let tasks = node.running.take().expect("test node is not running");
    node.server().mark_quic_runtime_detached();
    tasks.runtime.shutdown();
    tasks.admin_task.abort();
    tokio::time::timeout(Duration::from_secs(10), tasks.runtime_task)
        .await
        .expect("party QUIC runtime ignored shutdown")
        .expect("party QUIC runtime task panicked")
        .expect("party QUIC runtime returned an error");
    let _ = tasks.admin_task.await;
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
    for (party, tasks) in running {
        let result = tokio::time::timeout(Duration::from_secs(10), tasks.runtime_task)
            .await
            .unwrap_or_else(|_| panic!("party {party} QUIC runtime ignored shutdown"))
            .unwrap_or_else(|error| panic!("party {party} QUIC runtime task panicked: {error}"));
        result.unwrap_or_else(|error| {
            panic!("party {party} QUIC runtime returned an error: {error}")
        });
        let _ = tasks.admin_task.await;
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
        timestamp: current_time_seconds().saturating_add(3_600).saturating_add(height),
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
    let parties = (1_u16..=7)
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
                old_dealers: vec![],
            },
            CommitteeSpec {
                epoch: 1,
                operation: Operation::Reshare,
                threshold: 4,
                fault_bound: 1,
                members: (1_u16..=6).map(PartyId).collect(),
                eligible_members: (1_u16..=7).map(PartyId).collect(),
                old_dealers: (1_u16..=5).map(PartyId).collect(),
            },
            CommitteeSpec {
                epoch: 2,
                operation: Operation::Reshare,
                threshold: 2,
                fault_bound: 1,
                members: [PartyId(2), PartyId(4), PartyId(6), PartyId(7)].into(),
                eligible_members: [PartyId(2), PartyId(3), PartyId(4), PartyId(6), PartyId(7)]
                    .into(),
                old_dealers: (1_u16..=6).map(PartyId).collect(),
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

/// Authenticated Byzantine peer which completes TLS but never answers a request stream.
///
/// In particular this models a low-ID epoch-history source returning just under the transport
/// deadline forever. Per-peer stream limits remain enforced by QUIC; honest peers must still
/// advance the core protocol pacemaker.
fn start_authenticated_blackhole(
    endpoint: QuicPeerEndpoint,
) -> (Arc<QuicPeerEndpoint>, JoinHandle<()>) {
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
    (endpoint, task)
}

fn start_sync_only_deposit_source(
    endpoint: QuicPeerEndpoint,
    server: Arc<PartyServer>,
) -> (Arc<QuicPeerEndpoint>, JoinHandle<()>) {
    server.mark_quic_runtime_attached().unwrap();
    let endpoint = Arc::new(endpoint);
    let listener = endpoint.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(connection) => {
                        let server = server.clone();
                        connections.spawn(async move {
                            let peer = connection.peer_party();
                            loop {
                                let incoming = match connection.accept_request().await {
                                    Ok(incoming) => incoming,
                                    Err(_) => break,
                                };
                                let request = incoming.request().clone();
                                let response = if matches!(
                                    request,
                                    PeerRequest::Deposit {
                                        operation: DepositOperation::SyncHead
                                            | DepositOperation::SyncObjects,
                                        ..
                                    }
                                ) {
                                    server.handle_quic_peer_request(peer, request).await
                                } else {
                                    PeerResponse::Rejected {
                                        code: RejectionCode::Unavailable,
                                        retryable: true,
                                        message: "test source serves compact deposit sync only"
                                            .to_owned(),
                                    }
                                };
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
        server.mark_quic_runtime_detached();
    });
    (endpoint, task)
}

fn start_deposit_runtime_on_endpoint(
    node: &mut TestNode,
    endpoint: QuicPeerEndpoint,
    authenticator: BearerAuthenticator,
) {
    assert!(node.running.is_none());
    let runtime = Arc::new(
        QuicRuntime::new(
            endpoint,
            node.server().clone(),
            QuicRuntimeConfig {
                outbox_poll_interval: Duration::from_millis(20),
                protocol_progress_interval: Duration::from_millis(20),
                deposit_worker_interval: Duration::from_millis(20),
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

fn current_time_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
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
    let endpoint = scenario.party(party).unwrap().admin_endpoint.join("/v1/status").unwrap();
    let response = client
        .get(endpoint)
        .bearer_auth(std::str::from_utf8(ADMIN_TOKEN).unwrap())
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    response.json().await.unwrap()
}

async fn try_deposit_sync_advertisement(
    server: &Arc<PartyServer>,
    requester: PartyId,
    request: DepositSyncHeadRequest,
) -> Option<DepositSyncAdvertisement> {
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
            Some(DepositSyncAdvertisement::from_bytes(request, &body).unwrap())
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
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_statuses = BTreeMap::new();
    loop {
        sample_qual(nodes, transition.session, stats).await;
        let mut public = None;
        let mut ready = true;
        for party in parties {
            transition.target.member(*party).expect("observed party is outside target committee");
            let observed = status(client, scenario, *party).await;
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
            let mut protocols = BTreeMap::new();
            for (party, node) in nodes {
                let mut counts = [0_usize; 3];
                for message in node.server().pending_peer_messages(256).await {
                    if message.id().session() != transition.session {
                        continue;
                    }
                    match message {
                        PendingPeerMessage::Avss { .. } => counts[0] += 1,
                        PendingPeerMessage::Qual { .. } => counts[1] += 1,
                        PendingPeerMessage::ActivationAck { .. } => counts[2] += 1,
                    }
                }
                pending.insert(*party, counts);
                protocols.insert(
                    *party,
                    node.server().protocol_session_status(transition.session).await,
                );
            }
            panic!(
                "epoch {} did not activate; statuses={last_statuses:?}, protocols={protocols:?}, pending [avss,qual,ack]={pending:?}, observed_qual_messages={}, maximum_round={:?}",
                transition.target.epoch,
                stats.messages.len(),
                stats.maximum_round,
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Wait for a timer-created successor. Configuration contributes only a membership/threshold
/// policy; receiver-key rotation certifies the complete committee before AVSS starts. Agreement
/// on the returned `EpochPublic` therefore proves every observed party accepted the same rotation
/// decision for both configured and same-layout dynamic successors.
async fn wait_for_autonomous_epoch(
    client: &Client,
    scenario: &Scenario,
    parties: &[PartyId],
    epoch: u64,
) -> EpochPublic {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut last_statuses = BTreeMap::new();
    loop {
        let mut public = None;
        let mut ready = true;
        for party in parties {
            let observed = status(client, scenario, *party).await;
            last_statuses.insert(
                *party,
                (
                    observed.active_epoch,
                    observed.staged_epochs.clone(),
                    observed.proactive_refresh.clone(),
                ),
            );
            if observed.active_epoch != Some(epoch) {
                ready = false;
                continue;
            }
            let found = observed
                .epochs
                .iter()
                .find(|candidate| candidate.epoch == epoch)
                .expect("active dynamic epoch omitted public metadata")
                .public
                .clone();
            found.validate().unwrap();
            if let Some(expected) = &public {
                assert_eq!(
                    expected, &found,
                    "autonomous successor parties activated different public values"
                );
            } else {
                public = Some(found);
            }
        }
        if ready && !parties.is_empty() {
            return public.expect("autonomous target party set is empty");
        }
        assert!(
            Instant::now() < deadline,
            "autonomous epoch {epoch} did not activate; statuses={last_statuses:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deposit_enabled_party_starts_core_quic_while_monerod_is_unavailable() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=7)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();
    let mut admin_addresses = BTreeMap::new();
    let mut admin_reservations = Vec::new();
    for id in 1_u16..=7 {
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
    let server = tokio::time::timeout(Duration::from_secs(2), tokio::spawn(restore))
        .await
        .expect("party restore waited for an unavailable Monero daemon")
        .expect("party restore task panicked")
        .expect("deposit-enabled party restore failed");
    assert!(!daemon.is_ready(), "party startup unexpectedly contacted monerod");
    let admin_server = server.clone();
    let admin_address = admin_addresses[&PartyId(1)];
    let admin_task =
        tokio::spawn(async move { admin_server.serve(admin_address, authenticator()).await });
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
                ..Default::default()
            },
        )
        .unwrap(),
    );
    server.mark_quic_runtime_attached().unwrap();
    let observed = status(&client, &scenario, PartyId(1)).await;
    assert!(observed.ready, "core readiness was coupled to monerod");
    assert_eq!(observed.deposit_ready, Some(false));
    assert_eq!(observed.deposit_chain_ready, Some(false));
    let runtime_task = tokio::spawn(Box::pin(runtime.clone().run()));
    assert!(
        server.start_canonical_genesis_if_eligible().await.unwrap(),
        "eligible genesis dealer did not start while monerod was absent"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!runtime_task.is_finished(), "core QUIC runtime stopped with monerod unavailable");

    runtime.shutdown();
    server.mark_quic_runtime_detached();
    tokio::time::timeout(Duration::from_secs(3), runtime_task)
        .await
        .expect("core runtime did not stop after explicit shutdown")
        .expect("core runtime task panicked")
        .expect("core runtime returned an error");
    admin_task.abort();
    let _ = admin_task.await;
}

#[test]
fn empty_deposit_replica_syncs_mixed_observation_tip_over_quic_and_survives_restart() {
    // Deposit-enabled parties activate the epoch-zero genesis and then drive the deep deposit
    // genesis/allocation reducers on the QUIC pacemaker's task. Those reducers are sized for the
    // production 16 MiB worker stack (`PARTY_RUNTIME_THREAD_STACK_BYTES` in `main`); the default
    // 2 MiB `#[tokio::test]` worker stack overflows partway through `DepositService::ensure_genesis`.
    // Build the runtime explicitly with the production stack size so this test exercises the real
    // activation path rather than aborting on a stack overflow the deployed binary never hits.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async { tokio::spawn(empty_deposit_replica_body()).await.unwrap() });
}

async fn empty_deposit_replica_body() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=7)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();
    let mut admin_listeners = BTreeMap::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=7 {
        let party = PartyId(id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(party, listener.local_addr().unwrap());
        admin_listeners.insert(party, listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    scenario.committees.truncate(1);
    scenario.proactive_refresh_interval_seconds = 3_600;
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
        let state_directory = root.path().join(format!("deposit-sync-party-{id}"));
        let server = PartyServer::new_with_deposits(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            &bootstrap_x25519_secret,
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
        );
        nodes.insert(party, node);
    }

    let client = Client::builder().timeout(Duration::from_secs(3)).build().unwrap();
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
    let head_request = DepositSyncHeadRequest::new(sync_context).unwrap();
    let empty_deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if try_deposit_sync_advertisement(nodes[&PartyId(5)].server(), PartyId(1), head_request)
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
        tokio::time::sleep(POLL_INTERVAL).await;
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
        for node in nodes.values() {
            node.server()
                .progress_deposit_allocation_consensus(
                    u64::try_from(
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        if let Some(advertisement) =
            try_deposit_sync_advertisement(nodes[&PartyId(1)].server(), PartyId(2), head_request)
                .await
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
        tokio::time::sleep(POLL_INTERVAL).await;
    };
    let ledger_portable = ledger_advertisement.portable_index().clone();

    for chain in chains.iter().filter_map(|(party, chain)| (party.0 <= 4).then_some(chain)) {
        chain.push_confirmed_deposit(epoch_zero.group_key_bytes());
    }
    let observation_deadline = Instant::now() + TEST_TIMEOUT;
    let observation_advertisement = loop {
        for node in nodes.values() {
            let _ = node.server().tick_deposit_worker().await;
        }
        for _ in 0..4 {
            for node in nodes.values() {
                node.server()
                    .progress_deposit_allocation_consensus(current_time_millis())
                    .await
                    .unwrap();
            }
        }
        if let Some(advertisement) =
            try_deposit_sync_advertisement(nodes[&PartyId(1)].server(), PartyId(2), head_request)
                .await
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
        tokio::time::sleep(POLL_INTERVAL).await;
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

    // Stop every normal source runtime so none can replay its retained live observation outbox.
    // A source-1 endpoint below serves only authenticated SyncHead/SyncObjects requests. Thus the
    // empty replica can reach archive sequence two only through the compact QUIC sync protocol.
    stop_all(&mut nodes).await;
    let (sync_source_endpoint, sync_source_task) = start_sync_only_deposit_source(
        endpoint_for(
            PartyId(1),
            quic_addresses[&PartyId(1)],
            &scenario,
            &tls,
            QuicTransportConfig::default(),
        ),
        nodes[&PartyId(1)].server().clone(),
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
    );
    wait_for_http_parties(&client, &scenario, &[PartyId(5)]).await;

    let import_deadline = Instant::now() + TEST_TIMEOUT;
    let imported = loop {
        if let Some(advertisement) =
            try_deposit_sync_advertisement(late.server(), PartyId(1), head_request).await
            && advertisement.certificate_archive().len() == 2
        {
            break advertisement;
        }
        assert!(
            Instant::now() < import_deadline,
            "empty party 5 did not adopt the mixed observation-tip archive over QUIC"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    };
    assert_eq!(imported.portable_index(), observation_advertisement.portable_index());
    assert_eq!(imported.certificate_archive(), observation_advertisement.certificate_archive());
    assert_eq!(
        imported.checkpoint_certificate(),
        observation_advertisement.checkpoint_certificate()
    );
    assert_eq!(chains[&PartyId(5)].latest.load(Ordering::SeqCst), 0);
    assert!(
        late.server().deposit_sync_head_request().await.unwrap().is_none(),
        "imported party still considers its compact state empty"
    );
    let permanent =
        deposit_http_request(&client, &scenario, PartyId(5), "/v1/deposits/status", request)
            .await
            .expect("imported allocation is absent from party 5");
    assert_eq!(permanent.status, DepositHttpStatus::Permanent);

    // Abort both party futures, reconstruct from the authenticated mixed checkpoint, and prove the
    // observation authority and permanence survive without a scanner ever seeing block one.
    crash_node(&mut late).await;
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
    );
    wait_for_http_parties(&client, &scenario, &[PartyId(5)]).await;
    let restored =
        try_deposit_sync_advertisement(late.server(), PartyId(1), head_request).await.unwrap();
    assert_eq!(restored.portable_index(), observation_advertisement.portable_index());
    assert_eq!(restored.certificate_archive(), observation_advertisement.certificate_archive());
    assert_eq!(
        restored.checkpoint_certificate(),
        observation_advertisement.checkpoint_certificate()
    );
    let restored_permanent =
        deposit_http_request(&client, &scenario, PartyId(5), "/v1/deposits/status", request)
            .await
            .expect("restored allocation is absent from party 5");
    assert_eq!(restored_permanent.status, DepositHttpStatus::Permanent);

    stop_node(&mut late).await;
    sync_source_endpoint.close(b"test complete");
    tokio::time::timeout(Duration::from_secs(5), sync_source_task)
        .await
        .expect("sync-only source ignored endpoint shutdown")
        .expect("sync-only source task panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_avss_duplicate_and_malformed_replays_are_atomic_across_restart() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=7)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();
    let mut listeners = Vec::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=7 {
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
    let admin_task = tokio::spawn(async move {
        admin_server.serve(admin_addresses[&PartyId(1)], authenticator()).await
    });
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
    let _ = admin_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sigkill_style_restart_during_qual_survives_a_silent_round_zero_leader() {
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=7)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();

    let mut admin_listeners = Vec::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=7 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(PartyId(id), listener.local_addr().unwrap());
        admin_listeners.push(listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    let original_network = scenario.quic_network_id().unwrap();
    let mut quic_addresses = BTreeMap::new();
    let mut quic_reservations = Vec::new();
    for id in 1_u16..=7 {
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

    let (blackhole_endpoint, blackhole_task) = start_authenticated_blackhole(endpoint_for(
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
        let state_directory = root.path().join(format!("silent-party-{id}"));
        let server = PartyServer::new(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            &bootstrap_x25519_secret,
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
    let mut client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
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
        .expect("SIGKILL-style restart lost the live QUAL session");
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
    client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
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

    stop_all(&mut nodes).await;
    blackhole_endpoint.close(b"test complete");
    tokio::time::timeout(Duration::from_secs(5), blackhole_task)
        .await
        .expect("authenticated blackhole ignored endpoint shutdown")
        .expect("authenticated blackhole task panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn persistent_quic_grow_shrink_restart_gates_qual_and_never_uses_http_peer_relay() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let root = tempfile::tempdir().unwrap();
    let tls = (1_u16..=7)
        .map(|id| (PartyId(id), TlsMaterial::generate(PartyId(id))))
        .collect::<BTreeMap<_, _>>();

    // Hold all admin ports until every address has been embedded in the scenario.
    let mut admin_listeners = BTreeMap::new();
    let mut admin_addresses = BTreeMap::new();
    for id in 1_u16..=7 {
        let party = PartyId(id);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        admin_addresses.insert(party, listener.local_addr().unwrap());
        admin_listeners.insert(party, listener);
    }
    let mut scenario = scenario(&root, &admin_addresses, &tls);
    let original_network = scenario.quic_network_id().unwrap();

    // QUIC routing is deployment metadata, so endpoints can bind ephemeral ports without changing
    // the cryptographic network ID.
    let mut initial_endpoints = BTreeMap::new();
    let mut quic_addresses = BTreeMap::new();
    for id in 1_u16..=7 {
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
    for id in 1_u16..=7 {
        let party = PartyId(id);
        let signing_seed = signing_seed(party);
        let bootstrap_x25519_secret = bootstrap_x25519_secret(party);
        let state_directory = root.path().join(format!("party-{id}"));
        let server = PartyServer::new(
            party,
            scenario.clone(),
            state_directory.clone(),
            &signing_seed,
            &bootstrap_x25519_secret,
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

    let mut client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    wait_for_http(&client, &scenario).await;

    // Live peer delivery routes do not exist on HTTP. Only operator start/status remain.
    for legacy_path in [
        "/v1/avss/deliver",
        "/v1/qual/deliver",
        "/v1/qual/advance",
        "/v1/epoch/activation-ack",
        "/v1/epoch/activate",
        "/v1/epoch/retire",
    ] {
        let endpoint =
            scenario.party(PartyId(1)).unwrap().admin_endpoint.join(legacy_path).unwrap();
        let response = client
            .post(endpoint)
            .bearer_auth(std::str::from_utf8(ADMIN_TOKEN).unwrap())
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "legacy peer HTTP route exists");
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
        .configured_key_rotation_target_policy(&epoch_zero.committee)
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
    client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    wait_for_http(&client, &scenario).await;

    let grow_parties = (1_u16..=7).map(PartyId).collect::<Vec<_>>();
    let epoch_one = wait_for_autonomous_epoch(&client, &scenario, &grow_parties, 1).await;
    assert_eq!(epoch_one.committee.threshold, 4);
    assert_eq!(
        epoch_one.committee.members.iter().map(|member| member.id).collect::<Vec<_>>(),
        grow_parties
    );
    let grow_fresh_keys = epoch_one
        .committee
        .members
        .iter()
        .filter(|member| {
            member.encryption_key
                != grow_policy.eligible().member(member.id).unwrap().encryption_key
        })
        .count();
    assert!(
        grow_fresh_keys >= usize::from(epoch_one.committee.n() - grow_policy.target_fault_bound()),
        "certified grow committee did not replace target n-f receiver keys"
    );
    assert_eq!(epoch_one.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_one.key_id, epoch_zero.key_id);

    let shrink_policy = scenario
        .configured_key_rotation_target_policy(&epoch_one.committee)
        .unwrap()
        .expect("configured shrink policy is absent");
    assert_eq!(shrink_policy.target_epoch(), 2);
    assert_eq!(shrink_policy.target_fault_bound(), 1);
    assert_eq!(shrink_policy.eligible().threshold, 2);
    let shrink_parties = [PartyId(2), PartyId(4), PartyId(6), PartyId(7)];
    assert_eq!(
        shrink_policy.eligible().members.iter().map(|member| member.id).collect::<Vec<_>>(),
        shrink_parties
    );
    let epoch_two = wait_for_autonomous_epoch(&client, &scenario, &shrink_parties, 2).await;
    assert_eq!(epoch_two.committee.threshold, 2);
    assert_eq!(
        epoch_two.committee.members.iter().map(|member| member.id).collect::<Vec<_>>(),
        shrink_parties
    );
    let shrink_fresh_keys = epoch_two
        .committee
        .members
        .iter()
        .filter(|member| {
            member.encryption_key
                != shrink_policy.eligible().member(member.id).unwrap().encryption_key
        })
        .count();
    assert!(
        shrink_fresh_keys
            >= usize::from(epoch_two.committee.n() - shrink_policy.target_fault_bound()),
        "certified shrink committee did not replace target n-f receiver keys"
    );
    assert_eq!(epoch_two.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_two.key_id, epoch_zero.key_id);

    // Party 7 is a current `f=1` committee member, not an observer from an obsolete epoch. Crash it
    // before the first deadline so both dynamic key rotation and zero-share AVSS must complete with
    // one silent advertiser/dealer/observer. No epoch after two exists in static configuration.
    assert!(scenario.committee_spec(3).is_err());
    assert!(scenario.committee_spec(4).is_err());
    crash_node(nodes.get_mut(&PartyId(7)).unwrap()).await;

    let retirement_deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let mut retired = true;
        for party in [PartyId(1), PartyId(3), PartyId(5)] {
            let observed = status(&client, &scenario, party).await;
            retired &= observed.active_epoch.is_none() && observed.epochs.is_empty();
        }
        if retired {
            break;
        }
        assert!(
            Instant::now() < retirement_deadline,
            "old-only grow members retained active or historical secret shares"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    // Retirement leaves an authenticated non-secret marker at each obsolete epoch path. A fresh
    // store instance must reject both shares and must not find the former encrypted share in the
    // recoverable quarantine used by older builds.
    let retired_party = PartyId(1);
    let retired_store = ShareStore::new(
        &nodes[&retired_party].state_directory,
        retired_party,
        &nodes[&retired_party].signing_seed,
    )
    .unwrap();
    for (epoch, committee, successor_epoch) in
        [(0, epoch_zero.committee.digest(), 1), (1, epoch_one.committee.digest(), 2)]
    {
        assert!(matches!(
            retired_store.load(epoch, committee).await,
            Err(StoreError::ShareRetired {
                epoch: found_epoch,
                successor_epoch: found_successor,
            }) if found_epoch == epoch && found_successor == successor_epoch
        ));
    }
    assert!(
        !tokio::fs::try_exists(
            nodes[&retired_party]
                .state_directory
                .join("retired")
                .join(format!("epoch-0.{}.share", hex::encode(epoch_zero.committee.digest())))
        )
        .await
        .unwrap()
    );

    // The fixed-interval scheduler, rather than an operator start request or a finite list of
    // targets, drives a real dynamic key rotation followed by an n-f zero-constant refresh.
    let live_refresh_parties = [PartyId(2), PartyId(4), PartyId(6)];
    let epoch_three = wait_for_autonomous_epoch(&client, &scenario, &live_refresh_parties, 3).await;
    assert_eq!(epoch_three.committee.threshold, 2);
    assert_eq!(epoch_three.committee.n(), 4);
    epoch_three.committee.validate_async_security_with_faults(1).unwrap();
    assert_eq!(epoch_three.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_three.key_id, epoch_zero.key_id);
    assert_ne!(epoch_three.verification_shares, epoch_two.verification_shares);
    let after_three = status(&client, &scenario, PartyId(2))
        .await
        .proactive_refresh
        .expect("epoch three did not persist its next refresh deadline");
    assert_eq!(after_three.source_epoch, 3);
    assert_eq!(after_three.target_epoch, Some(4));
    let due_four = after_three.due_unix_ms.expect("epoch four deadline is absent");

    // Stop every remaining process before the next refresh and do not restart until its durable
    // deadline is overdue. Reconstruct all three live quorum members from disk; the first progress
    // tick must resume exactly the persisted epoch-three-to-four operation rather than re-arming
    // the interval from wall-clock startup time.
    stop_all(&mut nodes).await;
    let overdue_wait = due_four.saturating_sub(current_time_millis()).saturating_add(100);
    tokio::time::sleep(Duration::from_millis(overdue_wait)).await;
    for party in live_refresh_parties {
        nodes.get_mut(&party).unwrap().restore_server(&scenario).await;
        nodes.get_mut(&party).unwrap().start_runtime(&scenario, &tls, authenticator());
    }
    client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    wait_for_http_parties(&client, &scenario, &live_refresh_parties).await;

    let epoch_four = wait_for_autonomous_epoch(&client, &scenario, &live_refresh_parties, 4).await;
    assert_eq!(epoch_four.committee.threshold, 2);
    assert_eq!(epoch_four.committee.n(), 4);
    epoch_four.committee.validate_async_security_with_faults(1).unwrap();
    assert_eq!(epoch_four.group_key_bytes(), epoch_zero.group_key_bytes());
    assert_eq!(epoch_four.key_id, epoch_zero.key_id);
    assert_ne!(epoch_four.verification_shares, epoch_three.verification_shares);
    let after_four = status(&client, &scenario, PartyId(2))
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

    // This is a bounded test-only stop, not a protocol terminal committee. It leaves the durable
    // epoch-four schedule armed for epoch five and proves the implementation has no finite target.
    stop_all(&mut nodes).await;

    let refreshed_store = ShareStore::new(
        &nodes[&PartyId(2)].state_directory,
        PartyId(2),
        &nodes[&PartyId(2)].signing_seed,
    )
    .unwrap();
    for (epoch, committee, successor_epoch) in
        [(2, epoch_two.committee.digest(), 3), (3, epoch_three.committee.digest(), 4)]
    {
        assert!(matches!(
            refreshed_store.load(epoch, committee).await,
            Err(StoreError::ShareRetired {
                epoch: found_epoch,
                successor_epoch: found_successor,
            }) if found_epoch == epoch && found_successor == successor_epoch
        ));
    }

    // A true process-style reconstruction authenticates the tombstones and does not reload an
    // obsolete share into the signing map. A current refresh member resumes at epoch four.
    nodes.get_mut(&retired_party).unwrap().restore_server(&scenario).await;
    nodes.get_mut(&PartyId(2)).unwrap().restore_server(&scenario).await;
    nodes.get_mut(&retired_party).unwrap().start_runtime(&scenario, &tls, authenticator());
    nodes.get_mut(&PartyId(2)).unwrap().start_runtime(&scenario, &tls, authenticator());
    let client = Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
    wait_for_http_parties(&client, &scenario, &[retired_party, PartyId(2)]).await;
    let restored_status = status(&client, &scenario, retired_party).await;
    assert_eq!(restored_status.active_epoch, None);
    assert!(restored_status.epochs.is_empty());
    let refreshed_status = status(&client, &scenario, PartyId(2)).await;
    assert_eq!(refreshed_status.active_epoch, Some(4));
    assert_eq!(
        refreshed_status.epochs.iter().map(|epoch| epoch.epoch).collect::<Vec<_>>(),
        vec![4]
    );
    stop_all(&mut nodes).await;
}
