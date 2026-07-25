//! Persistent QUIC supervisor for one party.
//!
//! The protocol reducers own durable effects. This module owns only live transport concerns:
//! authenticated connection serving, DNS route resolution, bounded concurrency, reconnect
//! backoff, and removal of durable outbox entries after a correlated success response.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::{
    sync::{Mutex, Notify, Semaphore},
    task::JoinSet,
    time::{self, Instant, MissedTickBehavior},
};

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId},
    compact_epoch_registry::COMPACT_REGISTRY_INDEX_DEPTH,
    compact_registry_archive::{
        CompactRegistryArchiveError, CompactRegistryIndexStep, CompactRegistryObjectReader,
        CompactRegistryObjectRef, compact_registry_index_step,
    },
    config::{ConfigError, Scenario},
    deposit_archive::DepositArchiveOperation,
    deposit_consensus::{ConsensusMessageBody, decode_consensus_message},
    deposit_consolidation_wire::{
        ByzantineConsensusBody, ByzantineConsolidationWireMessage, ByzantineDeliveryId,
        ByzantineRelayAck,
    },
    deposit_index::{
        DepositIndexError, DepositIndexObjectId, DepositIndexReader, PortableStateQuery,
        PortableStateRecord, lookup_portable_state, next_portable_state_query_object,
        verify_portable_index_object,
    },
    deposit_service::DepositPeerMessageId,
    deposit_sync_wire::{
        DepositSyncAdvertisement, DepositSyncHeadRequest, DepositSyncObject, DepositSyncObjectPage,
        DepositSyncObjectPageRequest, DepositSyncObjectRef, MAX_DEPOSIT_SYNC_PAGE_OBJECTS,
        MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES, VerifiedDepositCheckpointArtifacts,
        decode_certified_deposit_observation_artifact, decode_deposit_index_checkpoint_artifact,
    },
    epoch_history::{
        EpochHistoryCatchupManifest, EpochHistoryCatchupQuery, EpochHistoryCatchupReply,
        EpochHistoryObjectRef, MAX_EPOCH_HISTORY_CHUNK_BYTES,
        MAX_EPOCH_HISTORY_REQUESTS_PER_SOURCE, MAX_HOT_EPOCH_HISTORY_ENTRIES,
    },
    key_rotation::{KeyRotationDeliveryKind, KeyRotationMessageId, PendingKeyRotationMessage},
    quic_transport::{
        AuthenticatedPeerConnection, DepositOperation, EpochOperation, PeerRequest, PeerResponse,
        QuicPeerEndpoint, QuicTransportError, RejectionCode, RequestId,
    },
    server::{PartyServer, PeerMessageId, PendingEpochPeerMessage},
};

const MAX_BATCH_SIZE: usize = 16 * 1024;
const MAX_RUNTIME_CONCURRENCY: usize = 4096;
const MAX_RUNTIME_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MIN_QUAL_ROUND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_EPOCH_HISTORY_ADVANCES_PER_TICK: usize = 4;
const MAX_DEPOSIT_SYNC_OBJECT_ADVANCES_PER_SOURCE: usize = 384;
const MAX_EPOCH_MESSAGE_CACHE_ENTRIES: usize =
    (MAX_HOT_EPOCH_HISTORY_ENTRIES as usize + 2) * MAX_COMMITTEE_MEMBERS;
const MAX_INBOUND_REQUEST_CACHE_ENTRIES_PER_PEER: usize = 1_024;

/// Runtime-only limits. They do not affect committee or transcript identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicRuntimeConfig {
    pub outbox_poll_interval: Duration,
    pub outbox_batch_size: usize,
    pub max_outbound_requests: usize,
    pub max_outbound_requests_per_peer: usize,
    pub max_inbound_connections: usize,
    pub max_inbound_handshakes: usize,
    pub max_inbound_connections_per_peer: usize,
    pub max_inbound_requests_per_connection: usize,
    pub max_inbound_requests: usize,
    pub max_inbound_requests_per_peer: usize,
    pub inbound_peer_rate_interval: Duration,
    pub max_inbound_connections_per_peer_per_interval: usize,
    pub max_inbound_requests_per_peer_per_interval: usize,
    pub retry_initial: Duration,
    pub retry_maximum: Duration,
    pub accept_error_delay: Duration,
    pub protocol_progress_interval: Duration,
    /// Deadline for one authenticated epoch-history request, independently of the transport
    /// stream timeout.
    pub epoch_history_request_timeout: Duration,
    /// Total deadline and request budget for one source in a raced history catch-up attempt.
    pub epoch_history_source_timeout: Duration,
    /// Total deadline for all sources and all bounded successor advances in one catch-up tick.
    pub epoch_history_sync_timeout: Duration,
    /// Maximum peers raced for one history successor. This must be greater than every configured
    /// committee fault bound, while keeping concurrent artifact memory statically bounded.
    pub max_epoch_history_raced_sources: usize,
    pub deposit_worker_interval: Duration,
    /// Base wall-clock timeout for one volatile FROSTLASS attempt before the durable Byzantine
    /// pacemaker advances to a fresh ROAST view/session.
    pub consolidation_attempt_timeout: Duration,
    /// `None` derives a temporary timeout from the scenario polling interval.
    pub qual_round_timeout: Option<Duration>,
}

impl Default for QuicRuntimeConfig {
    fn default() -> Self {
        Self {
            outbox_poll_interval: Duration::from_millis(100),
            outbox_batch_size: 256,
            max_outbound_requests: 64,
            max_outbound_requests_per_peer: 4,
            max_inbound_connections: 128,
            max_inbound_handshakes: 16,
            max_inbound_connections_per_peer: 4,
            max_inbound_requests_per_connection: 32,
            max_inbound_requests: 256,
            max_inbound_requests_per_peer: 32,
            inbound_peer_rate_interval: Duration::from_secs(1),
            max_inbound_connections_per_peer_per_interval: 16,
            max_inbound_requests_per_peer_per_interval: 256,
            retry_initial: Duration::from_millis(100),
            retry_maximum: Duration::from_secs(30),
            accept_error_delay: Duration::from_millis(100),
            protocol_progress_interval: Duration::from_millis(500),
            epoch_history_request_timeout: Duration::from_secs(5),
            epoch_history_source_timeout: Duration::from_secs(20),
            epoch_history_sync_timeout: Duration::from_secs(30),
            max_epoch_history_raced_sources: 4,
            deposit_worker_interval: Duration::from_secs(5),
            consolidation_attempt_timeout: Duration::from_secs(60),
            qual_round_timeout: None,
        }
    }
}

impl QuicRuntimeConfig {
    fn validate(self) -> Result<Self, QuicRuntimeError> {
        // A poll must expose at least one causal predecessor for every possible recipient.
        // Otherwise a permanently silent low-id peer can occupy the deterministic prefix on
        // every poll and starve healthy peers forever.
        if self.outbox_batch_size < MAX_COMMITTEE_MEMBERS || self.outbox_batch_size > MAX_BATCH_SIZE
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "outbox_batch_size must be in 10..=16384",
            ));
        }
        if self.max_outbound_requests == 0
            || self.max_outbound_requests > MAX_RUNTIME_CONCURRENCY
            || self.max_outbound_requests_per_peer == 0
            || self.max_outbound_requests_per_peer > self.max_outbound_requests
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "outbound concurrency must be nonzero, bounded, and per-peer <= global",
            ));
        }
        if self.max_inbound_connections == 0
            || self.max_inbound_connections > MAX_RUNTIME_CONCURRENCY
            || self.max_inbound_handshakes == 0
            || self.max_inbound_handshakes > self.max_inbound_connections
            || self.max_inbound_connections_per_peer == 0
            || self.max_inbound_connections_per_peer >= self.max_inbound_connections
            || self.max_inbound_requests_per_connection == 0
            || self.max_inbound_requests_per_connection > MAX_RUNTIME_CONCURRENCY
            || self.max_inbound_requests == 0
            || self.max_inbound_requests > MAX_RUNTIME_CONCURRENCY
            || self.max_inbound_requests_per_peer == 0
            || self.max_inbound_requests_per_peer >= self.max_inbound_requests
            || self.max_inbound_connections_per_peer_per_interval == 0
            || self.max_inbound_connections_per_peer_per_interval > MAX_BATCH_SIZE
            || self.max_inbound_requests_per_peer_per_interval == 0
            || self.max_inbound_requests_per_peer_per_interval > MAX_BATCH_SIZE
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "inbound limits and peer rates must be nonzero and bounded, with per-peer concurrency below total",
            ));
        }
        for duration in [
            self.outbox_poll_interval,
            self.retry_initial,
            self.retry_maximum,
            self.accept_error_delay,
            self.protocol_progress_interval,
            self.inbound_peer_rate_interval,
            self.epoch_history_request_timeout,
            self.epoch_history_source_timeout,
            self.epoch_history_sync_timeout,
            self.deposit_worker_interval,
            self.consolidation_attempt_timeout,
        ] {
            if duration.is_zero() || duration > MAX_RUNTIME_TIMEOUT {
                return Err(QuicRuntimeError::InvalidConfiguration(
                    "runtime durations must be positive and no greater than one hour",
                ));
            }
        }
        if self.retry_initial > self.retry_maximum {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "retry_initial cannot exceed retry_maximum",
            ));
        }
        if self.epoch_history_request_timeout > self.epoch_history_source_timeout
            || self.epoch_history_source_timeout > self.epoch_history_sync_timeout
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "epoch-history request timeout must be <= source timeout <= sync timeout",
            ));
        }
        if self.max_epoch_history_raced_sources == 0
            || self.max_epoch_history_raced_sources > MAX_COMMITTEE_MEMBERS
            || self.max_epoch_history_raced_sources > self.max_outbound_requests
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "epoch-history race width must be nonzero and no greater than committee/global request bounds",
            ));
        }
        if self
            .qual_round_timeout
            .is_some_and(|timeout| timeout.is_zero() || timeout > MAX_RUNTIME_TIMEOUT)
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "qual_round_timeout must be positive and no greater than one hour",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Error)]
pub enum QuicRuntimeError {
    #[error("invalid QUIC runtime configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("scenario configuration failed: {0}")]
    Scenario(#[from] ConfigError),
    #[error("QUIC endpoint belongs to party {endpoint}, but server belongs to party {server}")]
    WrongLocalParty { endpoint: PartyId, server: PartyId },
    #[error("QUIC endpoint was bound to a different network/configuration trust domain")]
    WrongNetwork,
    #[error("the QUIC runtime is already running")]
    AlreadyRunning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerRoute {
    host: String,
    port: u16,
}

impl PeerRoute {
    async fn resolve(&self) -> io::Result<Vec<SocketAddr>> {
        let addresses = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await?
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "QUIC route resolved no addresses",
            ));
        }
        Ok(addresses)
    }
}

fn peer_routes(
    scenario: &Scenario,
    local_party: PartyId,
) -> Result<BTreeMap<PartyId, PeerRoute>, ConfigError> {
    let mut routes = BTreeMap::new();
    for party in &scenario.parties {
        if party.id == local_party {
            continue;
        }
        let host = party
            .quic_endpoint
            .host_str()
            .ok_or(ConfigError::InvalidQuicEndpoint(party.id))?
            .to_owned();
        let port = party
            .quic_endpoint
            .port()
            .filter(|port| *port != 0)
            .ok_or(ConfigError::InvalidQuicEndpoint(party.id))?;
        routes.insert(party.id, PeerRoute { host, port });
    }
    Ok(routes)
}

#[derive(Debug)]
struct RetryState {
    failures: u32,
    next_attempt: Instant,
}

impl RetryState {
    fn new(now: Instant) -> Self {
        Self { failures: 0, next_attempt: now }
    }

    fn ready(&self, now: Instant) -> bool {
        now >= self.next_attempt
    }

    fn success(&mut self, now: Instant) {
        self.failures = 0;
        self.next_attempt = now;
    }

    fn failure(
        &mut self,
        now: Instant,
        party: PartyId,
        initial: Duration,
        maximum: Duration,
    ) -> Duration {
        self.failures = self.failures.saturating_add(1);
        let shift = self.failures.saturating_sub(1).min(31);
        let scale = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let base = initial.saturating_mul(scale).min(maximum);

        // Stable party-specific jitter avoids synchronized reconnect waves without relying on a
        // process-global RNG or persisting transport-only state.
        let mut material = [0_u8; 6];
        material[..2].copy_from_slice(&party.0.to_le_bytes());
        material[2..].copy_from_slice(&self.failures.to_le_bytes());
        let digest = blake3::hash(&material);
        let percentage = 75_u128 + u128::from(digest.as_bytes()[0] % 51);
        let nanos = base
            .as_nanos()
            .saturating_mul(percentage)
            .checked_div(100)
            .unwrap_or(base.as_nanos())
            .max(1)
            .min(maximum.as_nanos())
            .min(u128::from(u64::MAX));
        let delay = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
        self.next_attempt = now + delay;
        delay
    }
}

#[derive(Default)]
struct EpochMessageCache {
    known: BTreeSet<RequestId>,
    delivered: BTreeSet<RequestId>,
}

impl EpochMessageCache {
    fn reconcile(&mut self, current: BTreeSet<RequestId>) {
        debug_assert!(current.len() <= MAX_EPOCH_MESSAGE_CACHE_ENTRIES);
        self.delivered.retain(|key| current.contains(key));
        self.known = current;
    }

    fn mark_delivered(&mut self, key: RequestId) {
        // A completion racing hot-history compaction is deliberately forgotten. Cold entries are
        // served through history pull and must not repopulate this hot-only cache.
        if self.known.contains(&key) {
            self.delivered.insert(key);
        }
    }
}

enum CachedInboundRequestState {
    InFlight,
    Complete,
}

struct CachedInboundRequest {
    fingerprint: [u8; 32],
    touched: u64,
    state: CachedInboundRequestState,
}

enum InboundRequestAdmission {
    Execute,
    Respond(PeerResponse),
}

#[derive(Default)]
struct InboundRequestCache {
    entries: BTreeMap<RequestId, CachedInboundRequest>,
    clock: u64,
}

impl InboundRequestCache {
    fn lock(cache: &StdMutex<Self>) -> StdMutexGuard<'_, Self> {
        cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_touch(&mut self) -> u64 {
        if self.clock == u64::MAX {
            for entry in self.entries.values_mut() {
                entry.touched = 0;
            }
            self.clock = 0;
        }
        self.clock += 1;
        self.clock
    }

    fn admit(&mut self, request_id: RequestId, fingerprint: [u8; 32]) -> InboundRequestAdmission {
        let touched = self.next_touch();
        if let Some(entry) = self.entries.get_mut(&request_id) {
            entry.touched = touched;
            if entry.fingerprint != fingerprint {
                return InboundRequestAdmission::Respond(request_id_conflict_response());
            }
            if matches!(&entry.state, CachedInboundRequestState::InFlight) {
                return InboundRequestAdmission::Respond(request_in_flight_response());
            }
            entry.state = CachedInboundRequestState::InFlight;
            return InboundRequestAdmission::Execute;
        }

        if self.entries.len() == MAX_INBOUND_REQUEST_CACHE_ENTRIES_PER_PEER {
            let removable = self
                .entries
                .iter()
                .filter_map(|(key, entry)| {
                    matches!(&entry.state, CachedInboundRequestState::Complete)
                        .then_some((*key, entry.touched))
                })
                .min_by_key(|(_, touched)| *touched)
                .map(|(key, _)| key);
            let Some(removable) = removable else {
                return InboundRequestAdmission::Respond(request_cache_exhausted_response());
            };
            self.remove(removable);
        }
        self.entries.insert(
            request_id,
            CachedInboundRequest {
                fingerprint,
                touched,
                state: CachedInboundRequestState::InFlight,
            },
        );
        InboundRequestAdmission::Execute
    }

    fn complete(&mut self, request_id: RequestId, fingerprint: [u8; 32], _response: &PeerResponse) {
        if !self.entries.get(&request_id).is_some_and(|entry| {
            entry.fingerprint == fingerprint
                && matches!(&entry.state, CachedInboundRequestState::InFlight)
        }) {
            return;
        }
        // Reducer readiness and sync advertisements are mutable. Retain only the body binding,
        // never a response: an exact retry re-enters the durable idempotent reducer.
        if let Some(entry) = self.entries.get_mut(&request_id) {
            entry.state = CachedInboundRequestState::Complete;
        }
    }

    fn remove(&mut self, request_id: RequestId) {
        self.entries.remove(&request_id);
    }

    fn remove_in_flight(&mut self, request_id: RequestId, fingerprint: [u8; 32]) {
        if self.entries.get(&request_id).is_some_and(|entry| {
            entry.fingerprint == fingerprint
                && matches!(&entry.state, CachedInboundRequestState::InFlight)
        }) {
            self.remove(request_id);
        }
    }
}

struct InboundRequestExecution {
    cache: Arc<StdMutex<InboundRequestCache>>,
    request_id: RequestId,
    fingerprint: [u8; 32],
    complete: bool,
}

impl InboundRequestExecution {
    fn new(
        cache: Arc<StdMutex<InboundRequestCache>>,
        request_id: RequestId,
        fingerprint: [u8; 32],
    ) -> Self {
        Self { cache, request_id, fingerprint, complete: false }
    }

    fn complete(mut self, response: &PeerResponse) {
        InboundRequestCache::lock(&self.cache).complete(
            self.request_id,
            self.fingerprint,
            response,
        );
        self.complete = true;
    }
}

impl Drop for InboundRequestExecution {
    fn drop(&mut self) {
        if !self.complete {
            InboundRequestCache::lock(&self.cache)
                .remove_in_flight(self.request_id, self.fingerprint);
        }
    }
}

fn inbound_request_fingerprint(request: &PeerRequest) -> anyhow::Result<[u8; 32]> {
    let bytes = postcard::to_allocvec(request)?;
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/quic-inbound-request-body/v1");
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn request_id_conflict_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::Conflict,
        retryable: false,
        message: "request id was reused for a different authenticated request body".to_owned(),
    }
}

fn request_in_flight_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::Unavailable,
        retryable: true,
        message: "the identical authenticated request is already in flight".to_owned(),
    }
}

fn request_cache_exhausted_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "the authenticated peer has too many distinct requests in flight".to_owned(),
    }
}

fn retain_live_retry_states(
    retries: &mut BTreeMap<RequestId, RetryState>,
    live: &BTreeSet<RequestId>,
    in_flight: &BTreeSet<RequestId>,
) {
    retries.retain(|key, _| live.contains(key) || in_flight.contains(key));
}

struct FixedWindowRate {
    started: Instant,
    used: usize,
}

impl FixedWindowRate {
    fn new(now: Instant) -> Self {
        Self { started: now, used: 0 }
    }

    fn try_admit(&mut self, now: Instant, interval: Duration, limit: usize) -> bool {
        if now.duration_since(self.started) >= interval {
            self.started = now;
            self.used = 0;
        }
        if self.used >= limit {
            return false;
        }
        self.used += 1;
        true
    }
}

struct InboundPeerState {
    request_permits: Arc<Semaphore>,
    connection_rate: Mutex<FixedWindowRate>,
    request_rate: Mutex<FixedWindowRate>,
    request_cache: Arc<StdMutex<InboundRequestCache>>,
}

impl InboundPeerState {
    fn new(request_concurrency: usize) -> Self {
        let now = Instant::now();
        Self {
            request_permits: Arc::new(Semaphore::new(request_concurrency)),
            connection_rate: Mutex::new(FixedWindowRate::new(now)),
            request_rate: Mutex::new(FixedWindowRate::new(now)),
            request_cache: Arc::new(StdMutex::new(InboundRequestCache::default())),
        }
    }

    async fn admit_connection(&self, config: QuicRuntimeConfig) -> bool {
        self.connection_rate.lock().await.try_admit(
            Instant::now(),
            config.inbound_peer_rate_interval,
            config.max_inbound_connections_per_peer_per_interval,
        )
    }

    async fn admit_request(&self, config: QuicRuntimeConfig) -> bool {
        self.request_rate.lock().await.try_admit(
            Instant::now(),
            config.inbound_peer_rate_interval,
            config.max_inbound_requests_per_peer_per_interval,
        )
    }
}

fn inbound_rate_limited_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated peer ingress rate limit exceeded".to_owned(),
    }
}

fn inbound_concurrency_limited_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated peer ingress concurrency limit exceeded".to_owned(),
    }
}

struct CachedConnection {
    generation: u64,
    connection: AuthenticatedPeerConnection,
}

#[derive(Clone)]
struct ConnectionLease {
    generation: u64,
    connection: AuthenticatedPeerConnection,
}

struct ConnectionSlot {
    generation: u64,
    cached: Option<CachedConnection>,
}

struct PeerState {
    party: PartyId,
    route: PeerRoute,
    connection: Mutex<ConnectionSlot>,
    retry: Mutex<RetryState>,
    permits: Arc<Semaphore>,
}

impl PeerState {
    fn new(party: PartyId, route: PeerRoute, concurrency: usize) -> Self {
        Self {
            party,
            route,
            connection: Mutex::new(ConnectionSlot { generation: 0, cached: None }),
            retry: Mutex::new(RetryState::new(Instant::now())),
            permits: Arc::new(Semaphore::new(concurrency)),
        }
    }

    async fn ready(&self, now: Instant) -> bool {
        self.retry.lock().await.ready(now)
    }

    async fn connection(
        &self,
        endpoint: &QuicPeerEndpoint,
    ) -> Option<anyhow::Result<ConnectionLease>> {
        if !self.ready(Instant::now()).await {
            return None;
        }
        let mut slot = self.connection.lock().await;
        if !self.ready(Instant::now()).await {
            return None;
        }
        if let Some(cached) = &slot.cached {
            return Some(Ok(ConnectionLease {
                generation: cached.generation,
                connection: cached.connection.clone(),
            }));
        }

        let addresses = match self.route.resolve().await {
            Ok(addresses) => addresses,
            Err(error) => return Some(Err(error).context("cannot resolve QUIC peer route")),
        };
        let mut last_error = None;
        for address in addresses {
            match endpoint.connect(self.party, address).await {
                Ok(connection) => {
                    slot.generation = slot.generation.saturating_add(1);
                    let generation = slot.generation;
                    slot.cached =
                        Some(CachedConnection { generation, connection: connection.clone() });
                    return Some(Ok(ConnectionLease { generation, connection }));
                }
                Err(error) => last_error = Some(error),
            }
        }
        Some(Err(match last_error {
            Some(error) => anyhow!(error).context("all resolved QUIC addresses failed"),
            None => anyhow!("QUIC route resolved no usable addresses"),
        }))
    }

    async fn transport_failure(
        &self,
        generation: Option<u64>,
        config: QuicRuntimeConfig,
    ) -> Duration {
        if let Some(generation) = generation {
            let mut slot = self.connection.lock().await;
            if slot.cached.as_ref().is_some_and(|cached| cached.generation == generation) {
                slot.cached = None;
            }
        }
        self.retry.lock().await.failure(
            Instant::now(),
            self.party,
            config.retry_initial,
            config.retry_maximum,
        )
    }

    async fn transport_success(&self) {
        self.retry.lock().await.success(Instant::now());
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DurableMessageId {
    Protocol(PeerMessageId),
    Deposit(DepositPeerMessageId),
    ByzantineConsolidation(ByzantineDeliveryId),
    KeyRotation(KeyRotationMessageId),
}

#[derive(Clone)]
enum AcceptanceTarget {
    Durable(DurableMessageId),
    Epoch(RequestId),
}

#[derive(Clone)]
struct RelayWork {
    key: RequestId,
    recipient: PartyId,
    request: PeerRequest,
    target: AcceptanceTarget,
}

struct AttemptResult {
    work: RelayWork,
    disposition: DeliveryDisposition,
}

/// Outcome of trying to open a single delivery stream for one durable outbox item.
enum ScheduleOutcome {
    /// A delivery task was spawned for the item.
    Scheduled,
    /// The item is not currently eligible (backing off, missing route, or the peer connection is
    /// backing off / at its per-peer concurrency limit). Other items may still be scheduled.
    Skipped,
    /// The global outbound concurrency budget is exhausted; no further items can be scheduled this
    /// poll.
    GlobalPermitExhausted,
}

enum DeliveryDisposition {
    Accepted,
    /// The authenticated receiver has said this exact immutable effect can never be applied. It
    /// is safe to retire the durable item; retaining it only creates a permanent retry storm.
    TerminalRejection(String),
    Deferred(String),
}

/// Runtime-only, source-scoped cache for one atomic compact deposit adoption.
///
/// Nothing in this map becomes live protocol state. The service receives the complete candidate
/// only after every required root/path and exact checkpoint ledger certificate has authenticated.
#[derive(Default)]
struct DepositSyncDownload {
    objects: BTreeMap<DepositSyncObjectRef, DepositSyncObject>,
}

impl DepositSyncDownload {
    fn insert_page(&mut self, page: &DepositSyncObjectPage) -> anyhow::Result<()> {
        for object in page.objects() {
            if let Some(existing) = self.objects.insert(object.reference(), object.clone()) {
                anyhow::ensure!(
                    existing == *object,
                    "deposit sync source equivocated for one content reference"
                );
            }
        }
        Ok(())
    }

    fn contains(&self, reference: DepositSyncObjectRef) -> bool {
        self.objects.contains_key(&reference)
    }

    fn bytes(&self, reference: DepositSyncObjectRef) -> Option<&[u8]> {
        self.objects.get(&reference).map(DepositSyncObject::bytes)
    }

    fn registry_manifest_for_epoch(
        &self,
        advertisement: &DepositSyncAdvertisement,
        epoch: u64,
    ) -> anyhow::Result<Option<Vec<DepositSyncObjectRef>>> {
        let head = advertisement.registry_archive();
        let root = head.index_root_reference();
        let mut reference = root;
        let mut semantic_hash = head.registry_id().index_root();
        let mut depth = 0_u8;
        let mut manifest =
            Vec::with_capacity(usize::from(COMPACT_REGISTRY_INDEX_DEPTH).saturating_add(3));
        loop {
            let wire_reference = DepositSyncObjectRef::Registry(reference);
            anyhow::ensure!(
                !manifest.contains(&wire_reference),
                "compact-registry path contains a cycle"
            );
            manifest.push(wire_reference);
            let Some(bytes) = self.bytes(wire_reference) else {
                return Ok(Some(manifest));
            };
            match compact_registry_index_step(
                advertisement.context().wallet(),
                epoch,
                depth,
                semantic_hash,
                reference,
                bytes,
            )? {
                CompactRegistryIndexStep::Branch { next: Some(next), next_semantic_hash } => {
                    reference = next;
                    semantic_hash = next_semantic_hash;
                    depth =
                        depth.checked_add(1).context("compact-registry path depth exhausted")?;
                }
                CompactRegistryIndexStep::Branch { next: None, .. } => {
                    anyhow::bail!("advertised compact registry omits required epoch {epoch}");
                }
                CompactRegistryIndexStep::Leaf { link, witness, .. } => {
                    let link = DepositSyncObjectRef::Registry(link);
                    manifest.push(link);
                    if let Some(witness) = witness {
                        manifest.push(DepositSyncObjectRef::Registry(witness));
                    }
                    if manifest.iter().copied().any(|candidate| !self.contains(candidate)) {
                        return Ok(Some(manifest));
                    }
                    return Ok(None);
                }
            }
        }
    }

    fn registry_manifest(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<Option<Vec<DepositSyncObjectRef>>> {
        let head = advertisement.registry_archive();
        let active = head.registry().active_epoch();
        if let Some(manifest) = self.registry_manifest_for_epoch(advertisement, active)? {
            return Ok(Some(manifest));
        }
        if let Some(parent) = active.checked_sub(1)
            && let Some(manifest) = self.registry_manifest_for_epoch(advertisement, parent)?
        {
            return Ok(Some(manifest));
        }
        head.verify_bounded(self)?;
        Ok(None)
    }

    fn path_to_missing_index_object(
        &self,
        wallet: crate::deposit_wallet::DepositWalletId,
        root: DepositIndexObjectId,
        missing: DepositIndexObjectId,
    ) -> anyhow::Result<Vec<DepositSyncObjectRef>> {
        let mut stack = vec![(root, vec![root])];
        let mut visited = BTreeSet::new();
        while let Some((candidate, path)) = stack.pop() {
            if !visited.insert(candidate) {
                continue;
            }
            if candidate == missing {
                return Ok(path.into_iter().map(DepositSyncObjectRef::Index).collect());
            }
            let Some(bytes) = self.bytes(DepositSyncObjectRef::Index(candidate)) else {
                continue;
            };
            let verified = verify_portable_index_object(wallet, candidate, bytes)?;
            for child in verified.children().iter().copied().rev() {
                let mut child_path = path.clone();
                child_path.push(child);
                if child == missing {
                    return Ok(child_path.into_iter().map(DepositSyncObjectRef::Index).collect());
                }
                if self.contains(DepositSyncObjectRef::Index(child)) {
                    stack.push((child, child_path));
                }
            }
        }
        anyhow::bail!("next portable-index object is detached from its advertised root")
    }

    fn index_manifest(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<Option<Vec<DepositSyncObjectRef>>> {
        let portable = advertisement.portable_index();
        if portable.through_sequence() == 0 {
            return Ok(None);
        }
        let head = portable.to_index_head()?;
        let root = head.root().context("non-genesis portable index omitted its root")?;
        let query = PortableStateQuery::Sequence(portable.through_sequence());
        if let Some(missing) = next_portable_state_query_object(self, &head, query)? {
            return Ok(Some(self.path_to_missing_index_object(
                portable.wallet_id(),
                root,
                missing,
            )?));
        }
        let Some(PortableStateRecord::Statement(statement)) =
            lookup_portable_state(self, &head, query)?
        else {
            anyhow::bail!("portable checkpoint omits its terminal ledger statement");
        };
        anyhow::ensure!(
            statement.sequence == portable.through_sequence()
                && statement.digest() == portable.ledger_head(),
            "portable checkpoint terminal statement differs from its ledger anchor"
        );
        Ok(None)
    }

    fn archive_manifest(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<Option<Vec<DepositSyncObjectRef>>> {
        let archive = advertisement.certificate_archive();
        if archive.is_empty() {
            return Ok(None);
        }
        let event = archive
            .event_reference()
            .context("nonempty certificate archive omitted its event root")?;
        let segment = archive
            .segment_reference()
            .context("nonempty certificate archive omitted its segment root")?;
        let mut manifest = vec![
            DepositSyncObjectRef::CertificateArchive(event),
            DepositSyncObjectRef::CertificateArchive(segment),
        ];
        if manifest.iter().copied().any(|reference| !self.contains(reference)) {
            return Ok(Some(manifest));
        }

        let event_bytes = self
            .bytes(DepositSyncObjectRef::CertificateArchive(event))
            .context("downloaded checkpoint event disappeared")?;
        let artifacts =
            VerifiedDepositCheckpointArtifacts::from_checkpoint_event(advertisement, event_bytes)?;
        let operation = match artifacts.operation() {
            DepositArchiveOperation::Ledger => artifacts.ledger_reference(advertisement)?,
            DepositArchiveOperation::DepositObservation => {
                artifacts.observation_artifact(advertisement)?.reference()
            }
        };
        let checkpoint = artifacts.checkpoint_artifact(advertisement)?.reference();
        manifest.push(DepositSyncObjectRef::CertificateArchive(operation));
        manifest.push(DepositSyncObjectRef::CertificateArchive(checkpoint));
        Ok(manifest.iter().copied().any(|reference| !self.contains(reference)).then_some(manifest))
    }

    fn next_request(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<Option<DepositSyncObjectPageRequest>> {
        let references = if let Some(references) = self.registry_manifest(advertisement)? {
            Some(references)
        } else if let Some(references) = self.index_manifest(advertisement)? {
            Some(references)
        } else {
            self.archive_manifest(advertisement)?
        };
        references
            .map(|references| {
                DepositSyncObjectPageRequest::new(
                    advertisement,
                    references,
                    u16::try_from(MAX_DEPOSIT_SYNC_PAGE_OBJECTS)
                        .expect("deposit sync page object bound fits u16"),
                    u32::try_from(MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES)
                        .expect("deposit sync page byte bound fits u32"),
                )
            })
            .transpose()
            .map_err(Into::into)
    }

    fn checkpoint_artifacts(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<Option<VerifiedDepositCheckpointArtifacts>> {
        let archive = advertisement.certificate_archive();
        let Some(reference) = archive.event_reference() else {
            anyhow::ensure!(archive.is_empty(), "certificate archive event root is inconsistent");
            return Ok(None);
        };
        let bytes = self
            .bytes(DepositSyncObjectRef::CertificateArchive(reference))
            .context("checkpoint archive event was not downloaded")?;
        Ok(Some(VerifiedDepositCheckpointArtifacts::from_checkpoint_event(advertisement, bytes)?))
    }

    fn into_objects(self) -> Vec<DepositSyncObject> {
        self.objects.into_values().collect()
    }
}

impl CompactRegistryObjectReader for DepositSyncDownload {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        Ok(self
            .objects
            .get(&DepositSyncObjectRef::Registry(reference))
            .map(|object| object.bytes().to_vec()))
    }
}

impl DepositIndexReader for DepositSyncDownload {
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        Ok(self.objects.get(&DepositSyncObjectRef::Index(id)).map(|object| object.bytes().to_vec()))
    }
}

/// Long-lived party-to-party network runtime.
pub struct QuicRuntime {
    endpoint: Arc<QuicPeerEndpoint>,
    server: Arc<PartyServer>,
    network_id: [u8; 32],
    config: QuicRuntimeConfig,
    qual_round_timeout: Duration,
    peers: BTreeMap<PartyId, Arc<PeerState>>,
    outbound_permits: Arc<Semaphore>,
    inbound_request_permits: Arc<Semaphore>,
    inbound_peers: BTreeMap<PartyId, Arc<InboundPeerState>>,
    work_retries: Mutex<BTreeMap<RequestId, RetryState>>,
    epoch_history_retries: Mutex<BTreeMap<PartyId, RetryState>>,
    epoch_history_source_cursor: AtomicUsize,
    deposit_sync_source_cursor: AtomicUsize,
    ack_retry: Mutex<RetryState>,
    epoch_message_cache: Mutex<EpochMessageCache>,
    shutdown: AtomicBool,
    running: AtomicBool,
    shutdown_notify: Notify,
}

impl std::fmt::Debug for QuicRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuicRuntime")
            .field("party", &self.server.party_id())
            .field("local_addr", &self.endpoint.local_addr().ok())
            .field("peers", &self.peers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl QuicRuntime {
    /// Construct a runtime around an already-bound mutually authenticated endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid runtime/scenario limits or when the endpoint's local party or
    /// trust-domain identifier differs from the durable party server.
    pub fn new(
        endpoint: QuicPeerEndpoint,
        server: Arc<PartyServer>,
        config: QuicRuntimeConfig,
    ) -> Result<Self, QuicRuntimeError> {
        let config = config.validate()?;
        server.scenario().validate()?;
        let required_history_race_width = server
            .scenario()
            .committees
            .iter()
            .map(|committee| usize::from(committee.fault_bound).saturating_add(1))
            .max()
            .unwrap_or(1);
        if config.max_epoch_history_raced_sources < required_history_race_width {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "epoch-history race width must exceed every configured committee fault bound",
            ));
        }
        if endpoint.local_party() != server.party_id() {
            return Err(QuicRuntimeError::WrongLocalParty {
                endpoint: endpoint.local_party(),
                server: server.party_id(),
            });
        }
        let network_id = server.scenario().quic_network_id()?;
        if endpoint.network_id() != network_id {
            return Err(QuicRuntimeError::WrongNetwork);
        }
        let routes = peer_routes(server.scenario(), server.party_id())?;
        let peers: BTreeMap<PartyId, Arc<PeerState>> = routes
            .into_iter()
            .map(|(party, route)| {
                (
                    party,
                    Arc::new(PeerState::new(party, route, config.max_outbound_requests_per_peer)),
                )
            })
            .collect();
        let epoch_history_retries =
            peers.keys().copied().map(|party| (party, RetryState::new(Instant::now()))).collect();
        let inbound_peers = peers
            .keys()
            .copied()
            .map(|party| {
                (party, Arc::new(InboundPeerState::new(config.max_inbound_requests_per_peer)))
            })
            .collect();
        let qual_round_timeout = config
            .qual_round_timeout
            .unwrap_or_else(|| derived_qual_round_timeout(server.scenario().poll_interval_ms));
        Ok(Self {
            endpoint: Arc::new(endpoint),
            server,
            network_id,
            config,
            qual_round_timeout,
            peers,
            outbound_permits: Arc::new(Semaphore::new(config.max_outbound_requests)),
            inbound_request_permits: Arc::new(Semaphore::new(config.max_inbound_requests)),
            inbound_peers,
            work_retries: Mutex::new(BTreeMap::new()),
            epoch_history_retries: Mutex::new(epoch_history_retries),
            epoch_history_source_cursor: AtomicUsize::new(0),
            deposit_sync_source_cursor: AtomicUsize::new(0),
            ack_retry: Mutex::new(RetryState::new(Instant::now())),
            epoch_message_cache: Mutex::new(EpochMessageCache::default()),
            shutdown: AtomicBool::new(false),
            running: AtomicBool::new(false),
            shutdown_notify: Notify::new(),
        })
    }

    /// Run inbound serving, durable relay, and autonomous protocol progress until shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`QuicRuntimeError::AlreadyRunning`] if this runtime has already been started.
    pub async fn run(self: Arc<Self>) -> Result<(), QuicRuntimeError> {
        if self.running.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
        {
            return Err(QuicRuntimeError::AlreadyRunning);
        }
        // These loops are independent, long-lived reducers. Keep each future behind an allocation
        // boundary so `run` does not embed every loop's state machine inline in one enormous
        // concrete future. They remain cooperatively polled by this task, preserving cancellation
        // and panic behavior while making the runtime safe to pass directly to `tokio::spawn`.
        let accept = Box::pin(self.clone().accept_loop());
        let relay = Box::pin(self.clone().relay_loop());
        let protocol_progress = Box::pin(self.clone().protocol_progress_loop());
        let epoch_history_sync = Box::pin(self.clone().epoch_history_sync_loop());
        let deposit_allocation = Box::pin(self.clone().deposit_allocation_progress_loop());
        let deposit_worker = Box::pin(self.clone().deposit_worker_loop());
        tokio::join!(
            accept,
            relay,
            protocol_progress,
            epoch_history_sync,
            deposit_allocation,
            deposit_worker
        );
        self.endpoint.wait_idle().await;
        Ok(())
    }

    /// Stop accepting and initiating traffic. Already-dispatched reducer calls and durable ACK
    /// checkpoints are allowed to finish.
    pub fn shutdown(&self) {
        self.request_shutdown();
    }

    /// Tear down only the QUIC endpoint after the task running [`Self::run`] has already been
    /// aborted.
    ///
    /// This is intentionally separate from [`Self::shutdown`]: a SIGKILL-style harness must not
    /// give reducers or durable outbox ACKs another scheduling opportunity, but it still has to
    /// model the operating system synchronously closing process-owned sockets before starting the
    /// replacement process. Calling this while `run` is live is a misuse; ordinary callers should
    /// use `shutdown` and await the runtime task instead.
    pub async fn terminate_transport_after_task_abort(&self) {
        debug_assert!(
            self.running.load(Ordering::Acquire),
            "transport-only termination requires a runtime which was started first"
        );
        self.endpoint.close(b"simulated process termination");
        self.endpoint.wait_idle().await;
    }

    fn request_shutdown(&self) {
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            self.endpoint.close(b"party runtime shutdown");
            self.shutdown_notify.notify_waiters();
        }
    }

    async fn wait_for_shutdown(&self) {
        if self.shutdown.load(Ordering::Acquire) {
            return;
        }
        let notified = self.shutdown_notify.notified();
        if self.shutdown.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }

    async fn accept_loop(self: Arc<Self>) {
        let inbound_slots = Arc::new(Semaphore::new(self.config.max_inbound_connections));
        let handshake_slots = Arc::new(Semaphore::new(self.config.max_inbound_handshakes));
        let mut handshakes = JoinSet::new();
        let mut connections = JoinSet::new();
        let mut connections_per_peer = BTreeMap::<PartyId, usize>::new();
        loop {
            while !self.shutdown.load(Ordering::Acquire) {
                let Ok(inbound_permit) = inbound_slots.clone().try_acquire_owned() else {
                    break;
                };
                let Ok(handshake_permit) = handshake_slots.clone().try_acquire_owned() else {
                    drop(inbound_permit);
                    break;
                };
                let endpoint = self.endpoint.clone();
                let delay = self.config.accept_error_delay;
                handshakes.spawn(async move {
                    let result = endpoint.accept().await;
                    if result.is_err() {
                        // Bound invalid-handshake churn without serializing unrelated handshakes.
                        time::sleep(delay).await;
                    }
                    drop(handshake_permit);
                    (inbound_permit, result)
                });
            }
            tokio::select! {
                () = self.wait_for_shutdown() => break,
                Some(result) = handshakes.join_next(), if !handshakes.is_empty() => {
                    match result {
                        Ok((inbound_permit, Ok(connection))) => {
                            let peer = connection.peer_party();
                            let Some(inbound_peer) = self.inbound_peers.get(&peer) else {
                                connection.close(b"authenticated peer has no runtime state");
                                drop(inbound_permit);
                                continue;
                            };
                            if !inbound_peer.admit_connection(self.config).await {
                                tracing::warn!(%peer, "closing rate-limited authenticated QUIC connection");
                                connection.close(b"per-peer connection rate limit");
                                drop(inbound_permit);
                                continue;
                            }
                            let active = connections_per_peer.entry(peer).or_default();
                            if *active >= self.config.max_inbound_connections_per_peer {
                                tracing::warn!(%peer, limit = self.config.max_inbound_connections_per_peer, "closing excess authenticated QUIC connection");
                                connection.close(b"per-peer connection limit");
                                drop(inbound_permit);
                            } else {
                                *active += 1;
                                let runtime = self.clone();
                                connections.spawn(async move {
                                    runtime.serve_connection(connection).await;
                                    (peer, inbound_permit)
                                });
                            }
                        }
                        Ok((_permit, Err(QuicTransportError::EndpointClosed))) => {
                            self.request_shutdown();
                            break;
                        }
                        Ok((_permit, Err(error))) => {
                            tracing::warn!(party = %self.server.party_id(), %error, "QUIC peer handshake rejected");
                        }
                        Err(error) => {
                            tracing::error!(party = %self.server.party_id(), %error, "QUIC handshake task panicked");
                        }
                    }
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    match result {
                        Ok((peer, _permit)) => decrement_peer_connections(&mut connections_per_peer, peer),
                        Err(error) => {
                            tracing::error!(party = %self.server.party_id(), %error, "QUIC connection task panicked");
                        }
                    }
                }
            }
        }
        while let Some(result) = handshakes.join_next().await {
            if let Err(error) = result {
                tracing::error!(party = %self.server.party_id(), %error, "QUIC handshake task panicked during shutdown");
            }
        }
        while let Some(result) = connections.join_next().await {
            match result {
                Ok((peer, _permit)) => decrement_peer_connections(&mut connections_per_peer, peer),
                Err(error) => {
                    tracing::error!(party = %self.server.party_id(), %error, "QUIC connection task panicked during shutdown");
                }
            }
        }
    }

    async fn serve_connection(self: Arc<Self>, connection: AuthenticatedPeerConnection) {
        let peer = connection.peer_party();
        let Some(inbound_peer) = self.inbound_peers.get(&peer).cloned() else {
            connection.close(b"authenticated peer has no runtime state");
            return;
        };
        let request_cache = inbound_peer.request_cache.clone();
        let mut requests = JoinSet::new();
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => break,
                incoming = connection.accept_request(), if requests.len() < self.config.max_inbound_requests_per_connection => {
                    match incoming {
                        Ok(incoming) => {
                            let server = self.server.clone();
                            let request_cache = request_cache.clone();
                            let inbound_peer = inbound_peer.clone();
                            let global_permits = self.inbound_request_permits.clone();
                            let config = self.config;
                            requests.spawn(async move {
                                let request_id = incoming.request_id();
                                if !inbound_peer.admit_request(config).await {
                                    if let Err(error) =
                                        incoming.respond(inbound_rate_limited_response()).await
                                    {
                                        tracing::warn!(%peer, %error, "failed to send QUIC rate-limit response");
                                    }
                                    return;
                                }
                                let Ok(_peer_permit) =
                                    inbound_peer.request_permits.clone().try_acquire_owned()
                                else {
                                    if let Err(error) = incoming
                                        .respond(inbound_concurrency_limited_response())
                                        .await
                                    {
                                        tracing::warn!(%peer, %error, "failed to send QUIC concurrency-limit response");
                                    }
                                    return;
                                };
                                let Ok(_global_permit) = global_permits.try_acquire_owned() else {
                                    if let Err(error) = incoming
                                        .respond(inbound_concurrency_limited_response())
                                        .await
                                    {
                                        tracing::warn!(%peer, %error, "failed to send QUIC concurrency-limit response");
                                    }
                                    return;
                                };
                                let request = incoming.request().clone();
                                let fingerprint = match inbound_request_fingerprint(&request) {
                                    Ok(fingerprint) => fingerprint,
                                    Err(error) => {
                                        tracing::warn!(%peer, %request_id, %error, "cannot fingerprint canonical QUIC request");
                                        let response = PeerResponse::Rejected {
                                            code: RejectionCode::InvalidRequest,
                                            retryable: false,
                                            message: "canonical request fingerprint failed".to_owned(),
                                        };
                                        if let Err(error) = incoming.respond(response).await {
                                            tracing::warn!(%peer, %error, "failed to send QUIC peer response");
                                        }
                                        return;
                                    }
                                };
                                let admission = {
                                    InboundRequestCache::lock(&request_cache)
                                        .admit(request_id, fingerprint)
                                };
                                match admission {
                                    InboundRequestAdmission::Respond(response) => {
                                        if let Err(error) = incoming.respond(response).await {
                                            tracing::warn!(%peer, %error, "failed to send cached QUIC peer response");
                                        }
                                        return;
                                    }
                                    InboundRequestAdmission::Execute => {}
                                }
                                let execution = InboundRequestExecution::new(
                                    request_cache,
                                    request_id,
                                    fingerprint,
                                );
                                let response = server.handle_quic_peer_request(peer, request).await;
                                execution.complete(&response);
                                if let Err(error) = incoming.respond(response).await {
                                    tracing::warn!(%peer, %error, "failed to send QUIC peer response");
                                }
                            });
                        }
                        Err(error) => {
                            tracing::debug!(%peer, %error, "QUIC peer connection closed");
                            break;
                        }
                    }
                }
                Some(result) = requests.join_next(), if !requests.is_empty() => {
                    if let Err(error) = result {
                        tracing::error!(%peer, %error, "QUIC request task panicked");
                    }
                }
            }
        }
        connection.close(b"connection handler stopped");
        while let Some(result) = requests.join_next().await {
            if let Err(error) = result {
                tracing::error!(%peer, %error, "QUIC request task panicked during shutdown");
            }
        }
    }

    async fn protocol_progress_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.protocol_progress_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    let now = u64::try_from(now).unwrap_or(u64::MAX);
                    if let Err(error) =
                        Box::pin(self.server.progress_protocols(now, self.qual_round_timeout)).await
                    {
                        tracing::error!(party = %self.server.party_id(), %error, "autonomous protocol progress failed; will retry");
                    }
                }
            }
        }
    }

    /// Deposit allocation can contend on deposit-specific storage and must never delay the
    /// AVSS/QUAL/key-rotation/proactive-refresh pacemaker.
    async fn deposit_allocation_progress_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.protocol_progress_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    let now = u64::try_from(now).unwrap_or(u64::MAX);
                    if let Err(error) =
                        Box::pin(self.server.progress_deposit_allocation_consensus(now)).await
                    {
                        tracing::warn!(party = %self.server.party_id(), %error, "deposit allocation consensus progress failed; durable state will retry");
                    }
                }
            }
        }
    }

    /// Catch-up is deliberately a separate pacemaker. A slow or Byzantine history source cannot
    /// hold the core protocol timer future, and every tick has an independent total deadline.
    async fn epoch_history_sync_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.protocol_progress_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    let synchronization = time::timeout(
                        self.config.epoch_history_sync_timeout,
                        Box::pin(self.synchronize_epoch_history()),
                    );
                    tokio::select! {
                        () = self.wait_for_shutdown() => return,
                        result = synchronization => match result {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => tracing::warn!(
                                party = %self.server.party_id(),
                                %error,
                                "epoch-history synchronization failed closed; will retry"
                            ),
                            Err(_) => tracing::warn!(
                                party = %self.server.party_id(),
                                timeout_millis = self.config.epoch_history_sync_timeout.as_millis(),
                                "epoch-history synchronization exhausted its total deadline; will retry"
                            ),
                        }
                    }
                }
            }
        }
    }

    async fn synchronize_epoch_history(self: &Arc<Self>) -> anyhow::Result<()> {
        for _ in 0..MAX_EPOCH_HISTORY_ADVANCES_PER_TICK {
            let parent = Box::pin(self.server.epoch_history_catchup_parent()).await?;
            let query = EpochHistoryCatchupQuery::next(parent)?;
            if !Box::pin(self.race_epoch_history_successor(parent, query)).await? {
                break;
            }
        }
        Ok(())
    }

    async fn race_epoch_history_successor(
        self: &Arc<Self>,
        parent: crate::epoch_history::EpochHistoryParent,
        query: EpochHistoryCatchupQuery,
    ) -> anyhow::Result<bool> {
        let mut sources = self.ready_epoch_history_sources().await;
        if sources.is_empty() {
            return Ok(false);
        }
        let rotation =
            self.epoch_history_source_cursor.fetch_add(1, Ordering::Relaxed) % sources.len();
        sources.rotate_left(rotation);
        sources.truncate(self.config.max_epoch_history_raced_sources);

        // All eligible sources race within independent request/source budgets. A low-id source
        // which is silent, slow, or returns malformed bytes cannot pin the source loop.
        let mut candidates = JoinSet::new();
        for source in sources {
            let runtime = self.clone();
            let query = query.clone();
            candidates.spawn(async move {
                let result = time::timeout(
                    runtime.config.epoch_history_source_timeout,
                    Box::pin(runtime.fetch_epoch_history_candidate(source, parent, query)),
                )
                .await
                .map_err(|_| anyhow!("epoch-history source exhausted its total deadline"))
                .and_then(std::convert::identity);
                (source, result)
            });
        }

        while let Some(result) = candidates.join_next().await {
            let (source, candidate) = match result {
                Ok(result) => result,
                Err(error) => {
                    tracing::error!(%error, "epoch-history source task panicked");
                    continue;
                }
            };
            let (manifest, activation, rotation) = match candidate {
                Ok(Some(candidate)) => candidate,
                Ok(None) => {
                    self.epoch_history_source_success(source).await;
                    continue;
                }
                Err(error) => {
                    self.epoch_history_source_failure(source).await;
                    tracing::warn!(%source, %error, "authenticated epoch-history source rejected");
                    continue;
                }
            };
            if let Err(error) = Box::pin(
                self.server.apply_epoch_history_catchup(source, manifest, activation, rotation),
            )
            .await
            {
                // All semantic validation occurs before the durable append. Isolating this
                // source prevents a Byzantine peer from starving later honest sources. A local
                // storage failure remains fail-closed and is retried on a later tick.
                self.epoch_history_source_failure(source).await;
                tracing::warn!(%source, %error, "epoch-history successor failed verification or durable append");
                continue;
            }
            self.epoch_history_source_success(source).await;
            candidates.abort_all();
            return Ok(true);
        }
        Ok(false)
    }

    async fn fetch_epoch_history_candidate(
        self: &Arc<Self>,
        source: PartyId,
        parent: crate::epoch_history::EpochHistoryParent,
        query: EpochHistoryCatchupQuery,
    ) -> anyhow::Result<Option<(EpochHistoryCatchupManifest, Vec<u8>, Option<Vec<u8>>)>> {
        let mut remaining_requests = MAX_EPOCH_HISTORY_REQUESTS_PER_SOURCE;
        let response = Box::pin(self.bounded_epoch_history_rpc(
            source,
            query.clone(),
            &mut remaining_requests,
        ))
        .await?
        .context("epoch-history source is unavailable")?;
        let PeerResponse::Success { body } = response else {
            anyhow::bail!("epoch-history source rejected its immediate successor");
        };
        let reply: EpochHistoryCatchupReply = decode_canonical_postcard(&body)?;
        reply.validate_for_query(&query)?;
        let EpochHistoryCatchupReply::Next { manifest, .. } = reply else {
            anyhow::bail!("epoch-history source returned another response kind");
        };
        let Some(manifest) = manifest else {
            return Ok(None);
        };
        anyhow::ensure!(
            manifest.parent() == parent,
            "epoch-history source returned a non-successor manifest"
        );
        let activation = Box::pin(self.fetch_epoch_history_object(
            source,
            manifest,
            manifest.activation_certificate(),
            &mut remaining_requests,
        ))
        .await?;
        let rotation = match manifest.key_rotation_certificate() {
            Some(reference) => Some(
                Box::pin(self.fetch_epoch_history_object(
                    source,
                    manifest,
                    reference,
                    &mut remaining_requests,
                ))
                .await?,
            ),
            None => None,
        };
        Ok(Some((manifest, activation, rotation)))
    }

    async fn fetch_epoch_history_object(
        self: &Arc<Self>,
        source: PartyId,
        manifest: EpochHistoryCatchupManifest,
        reference: EpochHistoryObjectRef,
        remaining_requests: &mut usize,
    ) -> anyhow::Result<Vec<u8>> {
        let total =
            usize::try_from(reference.plaintext_len()).context("history object length overflow")?;
        let mut contents = Vec::with_capacity(total);
        while contents.len() < total {
            let offset = u64::try_from(contents.len()).context("history object offset overflow")?;
            let expected_bytes =
                total.saturating_sub(contents.len()).min(MAX_EPOCH_HISTORY_CHUNK_BYTES as usize);
            let maximum_bytes =
                u32::try_from(expected_bytes).context("history chunk length overflow")?;
            let query =
                EpochHistoryCatchupQuery::object_chunk(manifest, reference, offset, maximum_bytes)?;
            let response =
                Box::pin(self.bounded_epoch_history_rpc(source, query.clone(), remaining_requests))
                    .await?
                    .context("epoch-history object source is unavailable")?;
            let PeerResponse::Success { body } = response else {
                anyhow::bail!("epoch-history object source rejected a reachable chunk");
            };
            let reply: EpochHistoryCatchupReply = decode_canonical_postcard(&body)?;
            reply.validate_for_query(&query)?;
            let EpochHistoryCatchupReply::ObjectChunk {
                reference: actual,
                offset: actual_offset,
                total_bytes,
                bytes,
                ..
            } = reply
            else {
                anyhow::bail!("epoch-history object source returned another response kind");
            };
            anyhow::ensure!(
                actual == reference
                    && actual_offset == offset
                    && total_bytes == reference.plaintext_len(),
                "epoch-history object chunk context differs"
            );
            anyhow::ensure!(
                bytes.len() == expected_bytes,
                "epoch-history source returned a short non-final chunk"
            );
            contents.extend_from_slice(&bytes);
        }
        anyhow::ensure!(contents.len() == total, "epoch-history object exceeded its manifest");
        reference.verify_contents(&contents)?;
        Ok(contents)
    }

    async fn bounded_epoch_history_rpc(
        self: &Arc<Self>,
        source: PartyId,
        query: EpochHistoryCatchupQuery,
        remaining_requests: &mut usize,
    ) -> anyhow::Result<Option<PeerResponse>> {
        anyhow::ensure!(
            *remaining_requests > 0,
            "epoch-history source exhausted its request budget"
        );
        *remaining_requests -= 1;
        time::timeout(
            self.config.epoch_history_request_timeout,
            Box::pin(self.epoch_history_rpc(source, query)),
        )
        .await
        .map_err(|_| anyhow!("epoch-history request deadline exceeded"))?
    }

    async fn ready_epoch_history_sources(&self) -> Vec<PartyId> {
        let now = Instant::now();
        self.epoch_history_retries
            .lock()
            .await
            .iter()
            .filter_map(|(party, retry)| retry.ready(now).then_some(*party))
            .collect()
    }

    async fn epoch_history_source_failure(&self, source: PartyId) {
        if let Some(retry) = self.epoch_history_retries.lock().await.get_mut(&source) {
            retry.failure(
                Instant::now(),
                source,
                self.config.retry_initial,
                self.config.retry_maximum,
            );
        }
    }

    async fn epoch_history_source_success(&self, source: PartyId) {
        if let Some(retry) = self.epoch_history_retries.lock().await.get_mut(&source) {
            retry.success(Instant::now());
        }
    }

    async fn epoch_history_rpc(
        self: &Arc<Self>,
        source: PartyId,
        query: EpochHistoryCatchupQuery,
    ) -> anyhow::Result<Option<PeerResponse>> {
        let body = postcard::to_allocvec(&query)?;
        let peer = self.peers.get(&source).context("epoch-history source has no QUIC route")?;
        if !peer.ready(Instant::now()).await {
            return Ok(None);
        }
        let Ok(_global_permit) = self.outbound_permits.clone().try_acquire_owned() else {
            return Ok(None);
        };
        let Ok(_peer_permit) = peer.permits.clone().try_acquire_owned() else {
            return Ok(None);
        };
        let Some(connection) = peer.connection(&self.endpoint).await else {
            return Ok(None);
        };
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                let delay = peer.transport_failure(None, self.config).await;
                tracing::debug!(%source, ?delay, %error, "epoch-history connection deferred");
                return Ok(None);
            }
        };
        let request = PeerRequest::Epoch { operation: EpochOperation::History, body };
        let request_id =
            RequestId::for_peer_request(self.network_id, self.server.party_id(), source, &request)?;
        match connection.connection.request(request_id, request).await {
            Ok(response) => {
                self.server.record_authenticated_quic_response();
                peer.transport_success().await;
                Ok(Some(response))
            }
            Err(error) => {
                let delay = peer.transport_failure(Some(connection.generation), self.config).await;
                tracing::debug!(%source, ?delay, %error, "epoch-history pull deferred");
                Ok(None)
            }
        }
    }

    async fn deposit_worker_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.deposit_worker_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    if let Err(error) = Box::pin(self.synchronize_deposit_state()).await {
                        tracing::warn!(party = %self.server.party_id(), %error, "compact deposit synchronization failed; issuance remains closed");
                    }
                    let (scanner, consolidation) = run_independent_deposit_steps(
                        || Box::pin(self.server.tick_deposit_worker()),
                        || Box::pin(self.server.progress_deposit_consolidation_once(
                            self.config.consolidation_attempt_timeout,
                        )),
                    ).await;
                    if let Err(error) = scanner {
                        tracing::warn!(party = %self.server.party_id(), %error, "deposit scanner tick failed; durable state will retry");
                    }
                    if let Err(error) = consolidation {
                        tracing::warn!(party = %self.server.party_id(), %error, "deposit consolidation progress failed; durable state will retry");
                    }
                }
            }
        }
    }

    async fn synchronize_deposit_state(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some((mut sources, request)) =
            Box::pin(self.server.deposit_sync_head_request()).await?
        else {
            return Ok(());
        };
        let start = self.deposit_sync_source_cursor.fetch_add(1, Ordering::Relaxed) % sources.len();
        sources.rotate_left(start);
        for source in sources {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            match Box::pin(self.attempt_deposit_sync_source(source, request)).await {
                Ok(true) => {
                    tracing::info!(%source, "atomically adopted compact deposit checkpoint");
                    return Ok(());
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%source, %error, "authenticated compact deposit source rejected");
                }
            }
        }
        Ok(())
    }

    async fn attempt_deposit_sync_source(
        self: &Arc<Self>,
        source: PartyId,
        head_request: DepositSyncHeadRequest,
    ) -> anyhow::Result<bool> {
        let head_body = head_request.to_bytes()?;
        let Some(response) =
            self.deposit_sync_rpc(source, DepositOperation::SyncHead, head_body).await?
        else {
            return Ok(false);
        };
        let body = successful_deposit_sync_body(source, DepositOperation::SyncHead, response)?;
        let advertisement = DepositSyncAdvertisement::from_bytes(head_request, &body)?;
        let Some(initial_request) = self.server.deposit_sync_plan(&advertisement).await? else {
            return Ok(false);
        };

        let mut download = DepositSyncDownload::default();
        self.fetch_deposit_sync_manifest(source, &advertisement, initial_request, &mut download)
            .await?;
        let mut advances = 1_usize;
        while let Some(request) = download.next_request(&advertisement)? {
            anyhow::ensure!(
                advances < MAX_DEPOSIT_SYNC_OBJECT_ADVANCES_PER_SOURCE,
                "compact deposit source exceeded its bounded object-path request budget"
            );
            self.fetch_deposit_sync_manifest(source, &advertisement, request, &mut download)
                .await?;
            advances += 1;
        }

        if let Some(artifacts) = download.checkpoint_artifacts(&advertisement)? {
            let checkpoint_artifact = artifacts.checkpoint_artifact(&advertisement)?;
            let checkpoint_bytes = download
                .bytes(DepositSyncObjectRef::CertificateArchive(checkpoint_artifact.reference()))
                .context("checkpoint certificate artifact was not downloaded")?;
            let _checkpoint = decode_deposit_index_checkpoint_artifact(
                &advertisement,
                checkpoint_artifact,
                checkpoint_bytes,
            )?;
            match artifacts.operation() {
                DepositArchiveOperation::Ledger => {
                    let ledger_reference = artifacts.ledger_reference(&advertisement)?;
                    let ledger_bytes = download
                        .bytes(DepositSyncObjectRef::CertificateArchive(ledger_reference))
                        .context("certified ledger entry was not downloaded")?;
                    ledger_reference.verify_contents(ledger_bytes)?;
                    let ledger =
                        crate::deposit_ledger::CertifiedLedgerEntry::from_bytes(ledger_bytes)?;
                    anyhow::ensure!(
                        ledger.statement.wallet == advertisement.context().wallet(),
                        "certified ledger entry belongs to another wallet"
                    );
                }
                DepositArchiveOperation::DepositObservation => {
                    let observation_artifact = artifacts.observation_artifact(&advertisement)?;
                    let observation_bytes = download
                        .bytes(DepositSyncObjectRef::CertificateArchive(
                            observation_artifact.reference(),
                        ))
                        .context("certified deposit observation was not downloaded")?;
                    let _observation = decode_certified_deposit_observation_artifact(
                        &advertisement,
                        observation_artifact,
                        observation_bytes,
                    )?;
                }
            }
        }
        self.server.adopt_deposit_sync_candidate(advertisement, download.into_objects()).await
    }

    async fn fetch_deposit_sync_manifest(
        self: &Arc<Self>,
        source: PartyId,
        advertisement: &DepositSyncAdvertisement,
        mut request: DepositSyncObjectPageRequest,
        download: &mut DepositSyncDownload,
    ) -> anyhow::Result<()> {
        loop {
            let body = request.to_bytes(advertisement)?;
            let response = self
                .deposit_sync_rpc(source, DepositOperation::SyncObjects, body)
                .await?
                .context("compact deposit object source is unavailable")?;
            let body =
                successful_deposit_sync_body(source, DepositOperation::SyncObjects, response)?;
            let page = DepositSyncObjectPage::from_bytes(&request, advertisement, &body)?;
            download.insert_page(&page)?;
            let Some(cursor) = page.next_cursor() else {
                return Ok(());
            };
            request = request.with_cursor(advertisement, cursor)?;
        }
    }

    async fn deposit_sync_rpc(
        self: &Arc<Self>,
        source: PartyId,
        operation: DepositOperation,
        body: Vec<u8>,
    ) -> anyhow::Result<Option<PeerResponse>> {
        anyhow::ensure!(
            matches!(operation, DepositOperation::SyncHead | DepositOperation::SyncObjects),
            "non-sync deposit operation routed through compact pull RPC"
        );
        let peer = self.peers.get(&source).context("compact deposit source has no QUIC route")?;
        if !peer.ready(Instant::now()).await {
            return Ok(None);
        }
        let Ok(_global_permit) = self.outbound_permits.clone().try_acquire_owned() else {
            return Ok(None);
        };
        let Ok(_peer_permit) = peer.permits.clone().try_acquire_owned() else {
            return Ok(None);
        };
        let Some(connection) = peer.connection(&self.endpoint).await else {
            return Ok(None);
        };
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                let delay = peer.transport_failure(None, self.config).await;
                tracing::debug!(%source, ?delay, %error, "compact deposit connection deferred");
                return Ok(None);
            }
        };
        let request = PeerRequest::Deposit { operation, body };
        let request_id =
            RequestId::for_peer_request(self.network_id, self.server.party_id(), source, &request)?;
        match connection.connection.request(request_id, request).await {
            Ok(response) => {
                self.server.record_authenticated_quic_response();
                peer.transport_success().await;
                Ok(Some(response))
            }
            Err(error) => {
                let delay = peer.transport_failure(Some(connection.generation), self.config).await;
                tracing::debug!(%source, ?delay, %error, "compact deposit pull deferred");
                Ok(None)
            }
        }
    }

    async fn relay_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.outbox_poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut tasks = JoinSet::new();
        let mut in_flight = BTreeSet::new();
        let mut accepted = BTreeMap::<DurableMessageId, RequestId>::new();

        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => break,
                _ = interval.tick() => {
                    Box::pin(self.flush_durable_acks(&mut accepted, &mut in_flight)).await;
                    Box::pin(self.schedule_pending(&mut tasks, &mut in_flight)).await;
                }
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    Box::pin(self.collect_attempt(result, &mut accepted, &mut in_flight)).await;
                    while let Some(result) = tasks.try_join_next() {
                        Box::pin(self.collect_attempt(result, &mut accepted, &mut in_flight)).await;
                    }
                    if tasks.is_empty() {
                        Box::pin(self.flush_durable_acks(&mut accepted, &mut in_flight)).await;
                    }
                }
            }
        }
        while let Some(result) = tasks.join_next().await {
            Box::pin(self.collect_attempt(result, &mut accepted, &mut in_flight)).await;
        }
        Box::pin(self.flush_durable_acks(&mut accepted, &mut in_flight)).await;
    }

    async fn schedule_pending(
        self: &Arc<Self>,
        tasks: &mut JoinSet<AttemptResult>,
        in_flight: &mut BTreeSet<RequestId>,
    ) {
        let mut work = Vec::new();
        let mut live_retry_keys = BTreeSet::new();
        // Epoch transitions span three independently persisted outboxes. Select only the
        // earliest causal item across all three for each recipient on a poll: a QUIC stream for
        // AVSS/QUAL/activation must never overtake the key-rotation certificate which makes the
        // dynamic committee locally admissible. Keeping the predecessor selected while it is in
        // flight or backing off also prevents a later poll from opening a competing stream.
        let mut earliest_transition = BTreeMap::new();
        for pending in self.server.pending_peer_messages(self.config.outbox_batch_size).await {
            let id = pending.id();
            let transition_epoch = pending.transition_epoch();
            let causal_sequence = pending.causal_sequence();
            match pending.to_quic_request() {
                Ok(request) => {
                    let key = match RequestId::for_peer_request(
                        self.network_id,
                        self.server.party_id(),
                        id.recipient(),
                        &request,
                    ) {
                        Ok(key) => key,
                        Err(error) => {
                            let fallback = durable_retry_fallback_id(self.network_id, id);
                            live_retry_keys.insert(fallback);
                            self.work_failure(fallback).await;
                            tracing::error!(message = ?id, %error, "cannot bind durable QUIC outbox item to its authenticated route");
                            continue;
                        }
                    };
                    live_retry_keys.insert(key);
                    retain_earliest_transition_work(
                        &mut earliest_transition,
                        transition_epoch,
                        causal_sequence,
                        RelayWork {
                            key,
                            recipient: id.recipient(),
                            request,
                            target: AcceptanceTarget::Durable(DurableMessageId::Protocol(id)),
                        },
                    );
                }
                Err(error) => {
                    let fallback = durable_retry_fallback_id(self.network_id, id);
                    live_retry_keys.insert(fallback);
                    self.work_failure(fallback).await;
                    tracing::error!(message = ?id, %error, "cannot encode durable QUIC outbox item");
                }
            }
        }

        // Deposit ledger effects are globally ordered. Keep at most the earliest sequence and
        // causal phase in flight for each recipient; otherwise a fast Attest stream can overtake
        // its proposal and turn an ordinary network race into an UnknownSlot rejection.
        let mut earliest_deposit = BTreeMap::new();
        for pending in
            self.server.pending_deposit_peer_messages(self.config.outbox_batch_size).await
        {
            let recipient = pending.recipient();
            let request = pending.to_quic_request();
            let key = match RequestId::for_peer_request(
                self.network_id,
                self.server.party_id(),
                recipient,
                &request,
            ) {
                Ok(key) => key,
                Err(error) => {
                    let fallback = pending.id.request_id(self.network_id);
                    live_retry_keys.insert(fallback);
                    self.work_failure(fallback).await;
                    tracing::error!(message = ?pending.id, %error, "cannot bind durable deposit item to its authenticated route");
                    continue;
                }
            };
            live_retry_keys.insert(key);
            let candidate = match deposit_pending_causal_key(&pending) {
                Ok(candidate) => candidate,
                Err(error) => {
                    self.work_failure(key).await;
                    tracing::error!(message = ?pending.id, %error, "cannot order durable deposit outbox item");
                    continue;
                }
            };
            let replace = earliest_deposit.get(&recipient).is_none_or(
                |current: &crate::deposit_service::PendingDepositPeerMessage| {
                    // Every entry admitted into this map already passed the same decoder. If the
                    // retained value somehow stops decoding, replacing it is safer than letting
                    // a poison predecessor starve this recipient forever.
                    match deposit_pending_causal_key(current) {
                        Ok(current) => candidate < current,
                        Err(_) => true,
                    }
                },
            );
            if replace {
                earliest_deposit.insert(recipient, pending);
            }
        }
        for pending in earliest_deposit.into_values() {
            let id = pending.id;
            let request = pending.to_quic_request();
            let key = match RequestId::for_peer_request(
                self.network_id,
                self.server.party_id(),
                pending.recipient(),
                &request,
            ) {
                Ok(key) => key,
                Err(error) => {
                    let fallback = id.request_id(self.network_id);
                    self.work_failure(fallback).await;
                    tracing::error!(message = ?id, %error, "cannot bind selected deposit item to its authenticated route");
                    continue;
                }
            };
            let target = if id.operation() == DepositOperation::Consolidation {
                let PeerRequest::Deposit { body, .. } = &request else {
                    unreachable!("deposit outbox always produces a deposit request")
                };
                match ByzantineConsolidationWireMessage::decode(body)
                    .and_then(|wire| wire.delivery_id())
                {
                    Ok(delivery) => AcceptanceTarget::Durable(
                        DurableMessageId::ByzantineConsolidation(delivery),
                    ),
                    Err(error) => {
                        self.work_failure(key).await;
                        tracing::error!(message = ?id, %error, "cannot decode durable Byzantine consolidation outbox item");
                        continue;
                    }
                }
            } else {
                AcceptanceTarget::Durable(DurableMessageId::Deposit(id))
            };
            work.push(RelayWork { key, recipient: pending.recipient(), request, target });
        }

        // A key advertisement is a causal predecessor of the consensus messages which select it.
        // Use at most the earliest pending phase per recipient on each poll so independent QUIC
        // streams cannot make a later vote overtake the advertisement required to validate it.
        let mut earliest_key_rotation = BTreeMap::new();
        for pending in
            self.server.pending_key_rotation_peer_messages(self.config.outbox_batch_size).await
        {
            let recipient = pending.id.recipient;
            let candidate = key_rotation_delivery_order(
                pending.target_epoch,
                pending.id.kind,
                pending.id.digest,
            );
            let replace = earliest_key_rotation.get(&recipient).is_none_or(
                |current: &PendingKeyRotationMessage| {
                    candidate
                        < key_rotation_delivery_order(
                            current.target_epoch,
                            current.id.kind,
                            current.id.digest,
                        )
                },
            );
            if replace {
                earliest_key_rotation.insert(recipient, pending);
            }
        }
        for pending in earliest_key_rotation.into_values() {
            let id = pending.id;
            match PeerRequest::key_rotation(&pending.wire) {
                Ok(request) => {
                    let key = match RequestId::for_peer_request(
                        self.network_id,
                        self.server.party_id(),
                        id.recipient,
                        &request,
                    ) {
                        Ok(key) => key,
                        Err(error) => {
                            let fallback = key_rotation_retry_fallback_id(self.network_id, id);
                            live_retry_keys.insert(fallback);
                            self.work_failure(fallback).await;
                            tracing::error!(message = ?id, %error, "cannot bind key-rotation item to its authenticated route");
                            continue;
                        }
                    };
                    live_retry_keys.insert(key);
                    retain_earliest_transition_work(
                        &mut earliest_transition,
                        pending.target_epoch,
                        0,
                        RelayWork {
                            key,
                            recipient: id.recipient,
                            request,
                            target: AcceptanceTarget::Durable(DurableMessageId::KeyRotation(id)),
                        },
                    );
                }
                Err(error) => {
                    let fallback = key_rotation_retry_fallback_id(self.network_id, id);
                    live_retry_keys.insert(fallback);
                    self.work_failure(fallback).await;
                    tracing::error!(message = ?id, %error, "cannot encode durable key-rotation QUIC outbox item");
                }
            }
        }

        // Advance past every observed record, including a poison record which a peer permanently
        // rejects. The server exposes only its bounded hot-history suffix, so replace the runtime
        // cache with that exact set on every successful enumeration instead of retaining one key
        // per lifetime epoch.
        match self.server.pending_epoch_peer_messages(MAX_EPOCH_MESSAGE_CACHE_ENTRIES).await {
            Ok(messages) if messages.len() <= MAX_EPOCH_MESSAGE_CACHE_ENTRIES => {
                let mut keyed = Vec::with_capacity(messages.len());
                for pending in messages {
                    match RequestId::for_peer_request(
                        self.network_id,
                        self.server.party_id(),
                        pending.recipient(),
                        &pending.request,
                    ) {
                        Ok(key) => keyed.push((pending, key)),
                        Err(error) => {
                            let fallback = pending.request_id(self.network_id);
                            live_retry_keys.insert(fallback);
                            self.work_failure(fallback).await;
                            tracing::error!(epoch = pending.id.epoch, recipient = %pending.id.recipient, %error, "cannot bind epoch gossip to its authenticated route");
                        }
                    }
                }
                let current = keyed.iter().map(|(_, key)| *key).collect::<BTreeSet<_>>();
                live_retry_keys.extend(current.iter().copied());
                let mut cache = self.epoch_message_cache.lock().await;
                cache.reconcile(current);
                for (pending, key) in keyed {
                    if !cache.delivered.contains(&key) {
                        retain_earliest_transition_work(
                            &mut earliest_transition,
                            pending.id.epoch,
                            0,
                            epoch_work(pending, key),
                        );
                    }
                }
            }
            Ok(messages) => {
                tracing::error!(
                    party = %self.server.party_id(),
                    actual = messages.len(),
                    maximum = MAX_EPOCH_MESSAGE_CACHE_ENTRIES,
                    "server exceeded the bounded hot epoch-message suffix"
                );
            }
            Err(error) => {
                tracing::error!(party = %self.server.party_id(), %error, "cannot enumerate epoch certificate gossip; will retry");
            }
        }
        // Retry entries are transport-only backoff state. If one durable enumeration failed,
        // forgetting its old backoff is safe: the underlying durable item remains authoritative
        // and will simply be eligible immediately when enumeration recovers.
        self.prune_work_retries(&live_retry_keys, in_flight).await;

        // Deposit ledger effects are already at most one causal item per recipient; schedule them
        // directly. Global-permit exhaustion ends the whole poll.
        for work in work {
            match self.try_schedule_work(work, tasks, in_flight).await {
                ScheduleOutcome::Scheduled | ScheduleOutcome::Skipped => {}
                ScheduleOutcome::GlobalPermitExhausted => return,
            }
        }

        // Transition effects span several outboxes but share a per-recipient causal fence: prefer
        // the earliest item, yet fall through to a later one when the earliest is only transiently
        // ineligible so a backing-off predecessor cannot permanently starve the activation
        // acknowledgement queued behind it.
        for (_recipient, candidates) in earliest_transition {
            for (_order, work) in candidates {
                // An in-flight earliest item is already occupying this recipient's single stream;
                // never open a competing one, and never let a successor overtake it.
                if in_flight.contains(&work.key) {
                    break;
                }
                match self.try_schedule_work(work, tasks, in_flight).await {
                    // Scheduled the causally-first eligible item: this recipient is served.
                    ScheduleOutcome::Scheduled => break,
                    // The earliest item is backing off; try the next causal candidate.
                    ScheduleOutcome::Skipped => {}
                    ScheduleOutcome::GlobalPermitExhausted => return,
                }
            }
        }
    }

    /// Attempt to open a single delivery stream for one durable outbox item. Returns whether the
    /// item was scheduled, skipped because it is not currently eligible (backing off, no route, or
    /// the peer connection is backing off / at its per-peer concurrency limit), or could not be
    /// scheduled because the global outbound concurrency budget is exhausted.
    async fn try_schedule_work(
        self: &Arc<Self>,
        work: RelayWork,
        tasks: &mut JoinSet<AttemptResult>,
        in_flight: &mut BTreeSet<RequestId>,
    ) -> ScheduleOutcome {
        if in_flight.contains(&work.key) || !self.work_ready(work.key).await {
            return ScheduleOutcome::Skipped;
        }
        if work.recipient != self.server.party_id() {
            let Some(peer) = self.peers.get(&work.recipient) else {
                tracing::error!(recipient = %work.recipient, "durable outbox has no configured QUIC route");
                self.work_failure(work.key).await;
                return ScheduleOutcome::Skipped;
            };
            if !peer.ready(Instant::now()).await {
                return ScheduleOutcome::Skipped;
            }
        }

        let Ok(global_permit) = self.outbound_permits.clone().try_acquire_owned() else {
            return ScheduleOutcome::GlobalPermitExhausted;
        };
        let peer_permit = if work.recipient == self.server.party_id() {
            None
        } else {
            let peer = self.peers[&work.recipient].clone();
            let Ok(permit) = peer.permits.clone().try_acquire_owned() else {
                return ScheduleOutcome::Skipped;
            };
            Some(permit)
        };
        in_flight.insert(work.key);
        let runtime = self.clone();
        tasks.spawn(async move {
            let _global_permit = global_permit;
            let _peer_permit = peer_permit;
            runtime.attempt(work).await
        });
        ScheduleOutcome::Scheduled
    }

    async fn attempt(self: Arc<Self>, work: RelayWork) -> AttemptResult {
        let response = if work.recipient == self.server.party_id() {
            self.server.handle_local_peer_request(work.request.clone()).await
        } else {
            let peer = self.peers[&work.recipient].clone();
            let Some(connection) = peer.connection(&self.endpoint).await else {
                return AttemptResult {
                    work,
                    disposition: DeliveryDisposition::Deferred(
                        "peer reconnect is backing off".into(),
                    ),
                };
            };
            let connection = match connection {
                Ok(connection) => connection,
                Err(error) => {
                    let delay = peer.transport_failure(None, self.config).await;
                    self.work_failure(work.key).await;
                    eprintln!("CONNDBG p{} ->connect p{} FAIL: {error:#}", self.server.party_id().0, work.recipient.0);
                    return AttemptResult {
                        work,
                        disposition: DeliveryDisposition::Deferred(format!(
                            "QUIC connection failed ({delay:?} retry): {error:#}"
                        )),
                    };
                }
            };
            match connection.connection.request(work.key, work.request.clone()).await {
                Ok(response) => {
                    self.server.record_authenticated_quic_response();
                    peer.transport_success().await;
                    response
                }
                Err(error) => {
                    let delay =
                        peer.transport_failure(Some(connection.generation), self.config).await;
                    self.work_failure(work.key).await;
                    return AttemptResult {
                        work,
                        disposition: DeliveryDisposition::Deferred(format!(
                            "QUIC request failed ({delay:?} retry): {error}"
                        )),
                    };
                }
            }
        };

        let disposition = classify_peer_response_for_request(
            &work.request,
            response,
            |request_body, response_body| {
                self.server.validate_byzantine_consolidation_ack(
                    work.recipient,
                    request_body,
                    response_body,
                )
            },
        );
        if disposition_requires_backoff(&work.request, &disposition) {
            self.work_failure(work.key).await;
        } else {
            self.work_success(work.key).await;
        }
        AttemptResult { work, disposition }
    }

    async fn collect_attempt(
        &self,
        result: Result<AttemptResult, tokio::task::JoinError>,
        accepted: &mut BTreeMap<DurableMessageId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
    ) {
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                tracing::error!(%error, "QUIC relay task panicked");
                return;
            }
        };
        let key_rotation_ack_authorized = key_rotation_response_authorizes_ack(&result.disposition);
        let byzantine_ack_authorized =
            byzantine_consolidation_response_authorizes_ack(&result.disposition);
        let protocol_evidence_ack_authorized =
            protocol_evidence_response_authorizes_ack(&result.disposition);
        let terminal_rejection = match result.disposition {
            DeliveryDisposition::Accepted => None,
            DeliveryDisposition::TerminalRejection(error) => Some(error),
            DeliveryDisposition::Deferred(error) => {
                tracing::warn!(recipient = %result.work.recipient, request_id = %result.work.key, %error, "QUIC durable delivery deferred");
                in_flight.remove(&result.work.key);
                return;
            }
        };
        // A rotation outbox identifier commits to immutable protocol content. Never destroy that
        // evidence merely because one peer returned a non-retryable rejection: only a successful
        // reducer response proves the recipient durably accepted the exact content. The rejection
        // may become acceptable after the peer catches up to the rotation context, so retain and
        // back off the item.
        if matches!(
            &result.work.target,
            AcceptanceTarget::Durable(DurableMessageId::KeyRotation(_))
        ) && !key_rotation_ack_authorized
        {
            let error = terminal_rejection.expect("checked above");
            tracing::warn!(recipient = %result.work.recipient, request_id = %result.work.key, %error, "retaining rejected key-rotation outbox item until a successful durable response");
            in_flight.remove(&result.work.key);
            return;
        }
        // The same rule is stricter for ROAST: the only Accepted disposition is produced after
        // decoding and byte-for-byte verifying ByzantineRelayAck. A terminal-looking transport
        // rejection is not reducer evidence and must never be converted into a locally fabricated
        // acknowledgement, or an adversarial receiver could make us erase an immutable witness.
        if matches!(
            &result.work.target,
            AcceptanceTarget::Durable(DurableMessageId::ByzantineConsolidation(_))
        ) && !byzantine_ack_authorized
        {
            let error = terminal_rejection.expect("deferred dispositions returned above");
            tracing::warn!(recipient = %result.work.recipient, request_id = %result.work.key, %error, "retaining rejected Byzantine consolidation evidence until an exact typed ACK");
            in_flight.remove(&result.work.key);
            return;
        }
        // AVSS, QUAL, and epoch-transition messages are immutable protocol evidence too. A peer
        // may reject them until its local deadline or causal predecessor catches up; that
        // rejection must never erase this sender's exact durable item.
        if request_requires_positive_ack(&result.work.request) && !protocol_evidence_ack_authorized
        {
            let error = terminal_rejection.expect("deferred dispositions returned above");
            tracing::warn!(recipient = %result.work.recipient, request_id = %result.work.key, %error, "retaining rejected protocol evidence until a successful durable response");
            in_flight.remove(&result.work.key);
            return;
        }
        if let Some(error) = terminal_rejection {
            tracing::warn!(recipient = %result.work.recipient, request_id = %result.work.key, %error, "retiring terminally rejected QUIC outbox item");
        }
        match result.work.target {
            AcceptanceTarget::Durable(id) => {
                accepted.insert(id, result.work.key);
            }
            AcceptanceTarget::Epoch(key) => {
                self.epoch_message_cache.lock().await.mark_delivered(key);
                in_flight.remove(&result.work.key);
            }
        }
    }

    async fn flush_durable_acks(
        &self,
        accepted: &mut BTreeMap<DurableMessageId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
    ) {
        if accepted.is_empty() {
            return;
        }
        if !self.ack_retry.lock().await.ready(Instant::now()) {
            return;
        }
        let protocol_ids = accepted
            .keys()
            .filter_map(|id| match id {
                DurableMessageId::Protocol(id) => Some(*id),
                DurableMessageId::Deposit(_)
                | DurableMessageId::ByzantineConsolidation(_)
                | DurableMessageId::KeyRotation(_) => None,
            })
            .collect::<Vec<_>>();
        let deposit_ids = accepted
            .keys()
            .filter_map(|id| match id {
                DurableMessageId::Deposit(id) => Some(*id),
                DurableMessageId::Protocol(_)
                | DurableMessageId::ByzantineConsolidation(_)
                | DurableMessageId::KeyRotation(_) => None,
            })
            .collect::<Vec<_>>();
        let byzantine_consolidation_acks = accepted
            .keys()
            .filter_map(|id| match id {
                DurableMessageId::ByzantineConsolidation(delivery) => Some(*delivery),
                DurableMessageId::Protocol(_)
                | DurableMessageId::Deposit(_)
                | DurableMessageId::KeyRotation(_) => None,
            })
            .collect::<Vec<_>>();
        let key_rotation_ids = accepted
            .keys()
            .filter_map(|id| match id {
                DurableMessageId::KeyRotation(id) => Some(*id),
                DurableMessageId::Protocol(_)
                | DurableMessageId::Deposit(_)
                | DurableMessageId::ByzantineConsolidation(_) => None,
            })
            .collect::<Vec<_>>();
        let checkpoint = async {
            self.server.acknowledge_peer_messages(&protocol_ids).await?;
            self.server.acknowledge_deposit_peer_messages(&deposit_ids).await?;
            for delivery in byzantine_consolidation_acks {
                let acknowledgement = ByzantineRelayAck::new(delivery.recipient(), delivery)?;
                self.server.acknowledge_byzantine_consolidation(acknowledgement).await?;
            }
            self.server.acknowledge_key_rotation_peer_messages(&key_rotation_ids).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match checkpoint {
            Ok(()) => {
                self.ack_retry.lock().await.success(Instant::now());
                for key in accepted.values() {
                    in_flight.remove(key);
                }
                accepted.clear();
            }
            Err(error) => {
                self.ack_retry.lock().await.failure(
                    Instant::now(),
                    self.server.party_id(),
                    self.config.retry_initial,
                    self.config.retry_maximum,
                );
                tracing::error!(party = %self.server.party_id(), %error, "cannot durably acknowledge successful QUIC deliveries; outbox remains pending");
            }
        }
    }

    async fn work_ready(&self, key: RequestId) -> bool {
        self.work_retries.lock().await.get(&key).is_none_or(|retry| retry.ready(Instant::now()))
    }

    async fn prune_work_retries(
        &self,
        live: &BTreeSet<RequestId>,
        in_flight: &BTreeSet<RequestId>,
    ) {
        let mut retries = self.work_retries.lock().await;
        retain_live_retry_states(&mut retries, live, in_flight);
    }

    async fn work_failure(&self, key: RequestId) {
        self.work_retries
            .lock()
            .await
            .entry(key)
            .or_insert_with(|| RetryState::new(Instant::now()))
            .failure(
                Instant::now(),
                self.server.party_id(),
                self.config.retry_initial,
                self.config.retry_maximum,
            );
    }

    async fn work_success(&self, key: RequestId) {
        self.work_retries.lock().await.remove(&key);
    }
}

fn successful_deposit_sync_body(
    source: PartyId,
    operation: DepositOperation,
    response: PeerResponse,
) -> anyhow::Result<Vec<u8>> {
    match response {
        PeerResponse::Success { body } => Ok(body),
        PeerResponse::Rejected { code, retryable, message } => {
            anyhow::bail!(
                "party {source} rejected {operation:?} ({code:?}, retryable={retryable}): {message}"
            )
        }
    }
}

/// Scanner/RPC availability must not gate already-durable BA/ROAST timers and relays. New sweep
/// preparation still fails closed inside consolidation progress when its backend is unavailable,
/// while an existing family can continue view changes after a transient scanner failure.
async fn run_independent_deposit_steps<
    Scan,
    ScanFuture,
    Consolidate,
    ConsolidateFuture,
    ScanError,
    ConsolidateError,
>(
    scan: Scan,
    consolidate: Consolidate,
) -> (Result<(), ScanError>, Result<(), ConsolidateError>)
where
    Scan: FnOnce() -> ScanFuture,
    ScanFuture: Future<Output = Result<(), ScanError>>,
    Consolidate: FnOnce() -> ConsolidateFuture,
    ConsolidateFuture: Future<Output = Result<(), ConsolidateError>>,
{
    let scanner = scan().await;
    let consolidation = consolidate().await;
    (scanner, consolidation)
}

/// Local-only retry key for a poison item which could not produce a canonical `PeerRequest`.
/// Successfully encoded transport work always uses [`RequestId::for_peer_request`].
fn durable_retry_fallback_id(network_id: [u8; 32], id: PeerMessageId) -> RequestId {
    let (tag, session, recipient, digest) = match id {
        PeerMessageId::Avss { session, recipient, digest } => (0_u8, session, recipient, digest),
        PeerMessageId::Qual { session, recipient, digest } => (1_u8, session, recipient, digest),
        PeerMessageId::ActivationAck { session, recipient, digest } => {
            (2_u8, session, recipient, digest)
        }
    };
    let mut material = Vec::with_capacity(67);
    material.push(tag);
    material.extend_from_slice(&session.0);
    material.extend_from_slice(&recipient.0.to_le_bytes());
    material.extend_from_slice(&digest);
    RequestId::derive(network_id, b"durable-peer-outbox/v1", &material)
}

/// Local-only retry key for a key-rotation item which failed canonical request encoding.
fn key_rotation_retry_fallback_id(network_id: [u8; 32], id: KeyRotationMessageId) -> RequestId {
    let mut material = Vec::with_capacity(32 + 2 + 1 + 8 + 32);
    material.extend_from_slice(&id.context);
    material.extend_from_slice(&id.recipient.0.to_le_bytes());
    match id.kind {
        KeyRotationDeliveryKind::Advertisement => material.push(0),
        KeyRotationDeliveryKind::Proposal { view } => {
            material.push(1);
            material.extend_from_slice(&view.to_le_bytes());
        }
        KeyRotationDeliveryKind::Prevote { view } => {
            material.push(2);
            material.extend_from_slice(&view.to_le_bytes());
        }
        KeyRotationDeliveryKind::Precommit { view } => {
            material.push(3);
            material.extend_from_slice(&view.to_le_bytes());
        }
        KeyRotationDeliveryKind::ViewChange { target_view } => {
            material.push(4);
            material.extend_from_slice(&target_view.to_le_bytes());
        }
        KeyRotationDeliveryKind::ViewCertificate { target_view } => {
            material.push(5);
            material.extend_from_slice(&target_view.to_le_bytes());
        }
        KeyRotationDeliveryKind::Certificate => material.push(6),
    }
    material.extend_from_slice(&id.digest);
    RequestId::derive(network_id, b"key-rotation-outbox/v1", &material)
}

fn derived_qual_round_timeout(poll_interval_ms: u64) -> Duration {
    Duration::from_millis(poll_interval_ms.saturating_mul(32)).max(MIN_QUAL_ROUND_TIMEOUT)
}

fn decrement_peer_connections(counts: &mut BTreeMap<PartyId, usize>, peer: PartyId) {
    if let Some(count) = counts.get_mut(&peer) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&peer);
        }
    }
}

type DepositPendingCausalPrefix = (u64, u8, [u8; 32], u64, u8, u64, u8, u8);
type DepositPendingCausalKey = (DepositPendingCausalPrefix, DepositPeerMessageId);

fn byzantine_causal_prefix(
    sequence: u64,
    family: [u8; 32],
    outer_view: u64,
    kind: crate::deposit_consolidation_wire::ByzantineDeliveryKind,
    inner_consensus: Option<(u64, u8)>,
) -> DepositPendingCausalPrefix {
    let (stage, inner_view, inner_phase) =
        inner_consensus.map(|(view, phase)| (0, view, phase)).unwrap_or((1, 0, 0));
    (
        sequence,
        DepositOperation::Consolidation.causal_priority(),
        family,
        outer_view,
        stage,
        inner_view,
        inner_phase,
        kind.causal_priority(),
    )
}

/// Total per-recipient order for the shared durable deposit outbox.
///
/// The generic ledger sequence/operation prefix keeps allocation and completion effects ordered.
/// Byzantine consolidation then needs its own inner order: its identifiers are content addressed,
/// so sorting only by `DepositPeerMessageId` could send a signature share before the certified
/// intent or preprocess which makes that share admissible. A receiver would correctly reject the
/// share, but the rejected lowest hash would remain the chosen predecessor forever.
fn deposit_pending_causal_key(
    pending: &crate::deposit_service::PendingDepositPeerMessage,
) -> anyhow::Result<DepositPendingCausalKey> {
    let operation = pending.id.operation();
    if operation != DepositOperation::Consolidation {
        return Ok((
            (pending.id.sequence(), deposit_operation_priority(operation), [0; 32], 0, 0, 0, 0, 0),
            pending.id,
        ));
    }

    let wire = ByzantineConsolidationWireMessage::decode(&pending.body)?;
    anyhow::ensure!(
        !matches!(wire, ByzantineConsolidationWireMessage::Ack(_)),
        "a Byzantine acknowledgement cannot enter the request outbox"
    );
    let delivery = wire.delivery_id()?;
    let inner_consensus = match &wire {
        ByzantineConsolidationWireMessage::Consensus(message) => match message.body() {
            ByzantineConsensusBody::Message(envelope) => {
                let decoded = decode_consensus_message(message.context(), envelope)?;
                match decoded.body {
                    // View-change witnesses are a causal predecessor of the proposal for their
                    // target view, even though their signed wire-sequence discriminant is last.
                    ConsensusMessageBody::ViewChange(change) => Some((change.target_view, 0)),
                    ConsensusMessageBody::Proposal(proposal) => Some((proposal.view, 1)),
                    ConsensusMessageBody::Prevote(vote) => Some((vote.view, 2)),
                    ConsensusMessageBody::Precommit(vote) => Some((vote.view, 3)),
                }
            }
            ByzantineConsensusBody::ViewCertificate(certificate) => {
                Some((certificate.target_view(), 0))
            }
        },
        ByzantineConsolidationWireMessage::CertifiedIntent(_)
        | ByzantineConsolidationWireMessage::Preprocess(_)
        | ByzantineConsolidationWireMessage::KeyImageBinding(_)
        | ByzantineConsolidationWireMessage::Share(_)
        | ByzantineConsolidationWireMessage::Candidate(_) => None,
        ByzantineConsolidationWireMessage::Ack(_) => unreachable!("ACK was rejected above"),
    };
    Ok((
        byzantine_causal_prefix(
            pending.id.sequence(),
            delivery.family(),
            delivery.view(),
            delivery.kind(),
            inner_consensus,
        ),
        pending.id,
    ))
}

const fn deposit_operation_priority(operation: DepositOperation) -> u8 {
    operation.causal_priority()
}

fn classify_peer_response(response: PeerResponse) -> DeliveryDisposition {
    match response {
        PeerResponse::Success { .. } => DeliveryDisposition::Accepted,
        PeerResponse::Rejected { code, retryable, message } => {
            let rejection =
                format!("peer rejected request ({code:?}, retryable={retryable}): {message}");
            if retryable {
                DeliveryDisposition::Deferred(rejection)
            } else {
                DeliveryDisposition::TerminalRejection(rejection)
            }
        }
    }
}

/// Protocol-evidence outboxes need affirmative reducer acceptance. A receiver's rejection is
/// diagnostic only and cannot authorize local deletion, regardless of its retryable bit.
const fn request_requires_positive_ack(request: &PeerRequest) -> bool {
    matches!(
        request,
        PeerRequest::Avss { .. }
            | PeerRequest::Qual { .. }
            | PeerRequest::Epoch { .. }
            | PeerRequest::KeyRotation { .. }
            | PeerRequest::Deposit { operation: DepositOperation::Consolidation, .. }
    )
}

const fn disposition_requires_backoff(
    request: &PeerRequest,
    disposition: &DeliveryDisposition,
) -> bool {
    matches!(disposition, DeliveryDisposition::Deferred(_))
        || (matches!(disposition, DeliveryDisposition::TerminalRejection(_))
            && request_requires_positive_ack(request))
}

/// Byzantine consolidation evidence is retired only by its typed, exact delivery ACK. A plain
/// transport success is deliberately insufficient: otherwise a receiver could acknowledge a
/// different family/view/contribution while causing the sender to discard immutable relay work.
/// The typed decoder replaces this conservative branch once the canonical ROAST wire is routed.
fn classify_peer_response_for_request<F>(
    request: &PeerRequest,
    response: PeerResponse,
    validate_byzantine_ack: F,
) -> DeliveryDisposition
where
    F: FnOnce(&[u8], &[u8]) -> anyhow::Result<()>,
{
    if let PeerRequest::Deposit { operation: DepositOperation::Consolidation, body: request_body } =
        request
        && let PeerResponse::Success { body: response_body } = &response
    {
        return match validate_byzantine_ack(request_body, response_body) {
            Ok(()) => DeliveryDisposition::Accepted,
            Err(error) => DeliveryDisposition::Deferred(format!(
                "Byzantine consolidation delivery returned an invalid typed acknowledgement: {error:#}"
            )),
        };
    }
    classify_peer_response(response)
}

/// Key-rotation outbox entries carry protocol evidence: a rejection, including a non-retryable
/// one, never authorizes deletion.
const fn key_rotation_response_authorizes_ack(disposition: &DeliveryDisposition) -> bool {
    matches!(disposition, DeliveryDisposition::Accepted)
}

/// Only an exact typed ACK (classified as Accepted above) can retire Byzantine evidence.
const fn byzantine_consolidation_response_authorizes_ack(
    disposition: &DeliveryDisposition,
) -> bool {
    matches!(disposition, DeliveryDisposition::Accepted)
}

/// Immutable protocol evidence is retired only after successful durable reduction.
const fn protocol_evidence_response_authorizes_ack(disposition: &DeliveryDisposition) -> bool {
    matches!(disposition, DeliveryDisposition::Accepted)
}

fn epoch_work(pending: PendingEpochPeerMessage, key: RequestId) -> RelayWork {
    RelayWork {
        key,
        recipient: pending.recipient(),
        request: pending.request,
        target: AcceptanceTarget::Epoch(key),
    }
}

/// Semantic key-rotation order within one target epoch. A proposal for a newly entered view is
/// admissible only after its view-change evidence. Sorting by the outer QUIC operation or enum
/// discriminant would put `Proposal(v)` before `ViewChange(v)` and can make a retryable
/// `FutureView` rejection starve its own prerequisite forever.
const fn key_rotation_delivery_order(
    target_epoch: u64,
    kind: KeyRotationDeliveryKind,
    digest: [u8; 32],
) -> (u64, u64, u8, [u8; 32]) {
    let (view, phase) = kind.relay_order();
    (target_epoch, view, phase, digest)
}

/// Cross-outbox causal rank for one dynamic epoch transition. Lower values must be durably
/// accepted first. AVSS/QUAL reducers still validate their own fine-grained rounds; this rank is
/// the coarse prerequisite fence shared by otherwise independent QUIC streams.
const fn transition_work_priority(request: &PeerRequest) -> u8 {
    match request {
        PeerRequest::KeyRotation { operation, .. } => operation.causal_priority(),
        PeerRequest::Avss { .. } => 10,
        PeerRequest::Qual { .. } => 20,
        PeerRequest::Epoch {
            operation: crate::quic_transport::EpochOperation::Acknowledge,
            ..
        } => 30,
        PeerRequest::Epoch {
            operation: crate::quic_transport::EpochOperation::Activate, ..
        } => 40,
        PeerRequest::Epoch { operation: crate::quic_transport::EpochOperation::Retire, .. } => 50,
        PeerRequest::Epoch {
            operation: crate::quic_transport::EpochOperation::Observe, ..
        } => 60,
        PeerRequest::Epoch {
            operation: crate::quic_transport::EpochOperation::History, ..
        } => u8::MAX,
        PeerRequest::Deposit { .. } => u8::MAX,
    }
}

fn decode_canonical_postcard<T>(bytes: &[u8]) -> anyhow::Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)?;
    anyhow::ensure!(trailing.is_empty(), "QUIC response has trailing bytes");
    anyhow::ensure!(
        postcard::to_allocvec(&value)? == bytes,
        "QUIC response is not canonically encoded"
    );
    Ok(value)
}

type TransitionOrder = (u64, u8, u64, RequestId);

/// Retain every pending transition effect for each recipient, keyed by its causal order. The relay
/// prefers the causally-earliest item per recipient, but keeping the full ordered set lets the
/// scheduler fall through to a later item when the earliest is only transiently ineligible (for
/// example a QUAL delivery backing off after a peer that has already finalized rejected it). The
/// earliest item stays in the durable outbox and keeps retrying; the fall-through only prevents a
/// backing-off predecessor from permanently starving an activation acknowledgement behind it, which
/// would otherwise wedge the n-f activation quorum. Reducers still validate their own fine-grained
/// ordering, so delivering a successor ahead of a stalled predecessor is at worst extra retryable
/// rejection churn, never a safety violation.
fn retain_earliest_transition_work(
    pending: &mut BTreeMap<PartyId, BTreeMap<TransitionOrder, RelayWork>>,
    epoch: u64,
    causal_sequence: u64,
    work: RelayWork,
) {
    debug_assert!(!matches!(&work.request, PeerRequest::Deposit { .. }));
    let order = (epoch, transition_work_priority(&work.request), causal_sequence, work.key);
    pending.entry(work.recipient).or_default().insert(order, work);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::SessionId;

    fn transition_test_work(recipient: PartyId, key_byte: u8, request: PeerRequest) -> RelayWork {
        let key = RequestId::from_bytes([key_byte; 32]);
        RelayWork { key, recipient, request, target: AcceptanceTarget::Epoch(key) }
    }

    fn request_id_for_counter(counter: u64) -> RequestId {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&counter.to_le_bytes());
        RequestId::from_bytes(bytes)
    }

    #[test]
    fn same_request_id_with_a_different_body_conflicts_instead_of_replaying_success() {
        let request_id = RequestId::from_bytes([0xA1; 32]);
        let original = PeerRequest::Epoch { operation: EpochOperation::Observe, body: vec![0x11] };
        let equivocation =
            PeerRequest::Epoch { operation: EpochOperation::Observe, body: vec![0x22] };
        let original_fingerprint = inbound_request_fingerprint(&original).unwrap();
        let equivocation_fingerprint = inbound_request_fingerprint(&equivocation).unwrap();
        assert_ne!(original_fingerprint, equivocation_fingerprint);

        let mut cache = InboundRequestCache::default();
        assert!(matches!(
            cache.admit(request_id, original_fingerprint),
            InboundRequestAdmission::Execute
        ));
        let success = PeerResponse::Success { body: vec![0xAC] };
        cache.complete(request_id, original_fingerprint, &success);

        assert!(matches!(
            cache.admit(request_id, equivocation_fingerprint),
            InboundRequestAdmission::Respond(PeerResponse::Rejected {
                code: RejectionCode::Conflict,
                retryable: false,
                ..
            })
        ));
        assert!(matches!(
            cache.admit(request_id, original_fingerprint),
            InboundRequestAdmission::Execute
        ));
    }

    #[test]
    fn retryable_and_success_responses_are_both_reexecuted() {
        let request_id = RequestId::from_bytes([0xA2; 32]);
        let request =
            PeerRequest::Epoch { operation: EpochOperation::Acknowledge, body: vec![0x31] };
        let fingerprint = inbound_request_fingerprint(&request).unwrap();
        let mut cache = InboundRequestCache::default();

        assert!(matches!(cache.admit(request_id, fingerprint), InboundRequestAdmission::Execute));
        cache.complete(
            request_id,
            fingerprint,
            &PeerResponse::Rejected {
                code: RejectionCode::Unavailable,
                retryable: true,
                message: "refresh is not due yet".to_owned(),
            },
        );
        assert!(matches!(cache.admit(request_id, fingerprint), InboundRequestAdmission::Execute));

        let success = PeerResponse::Success { body: vec![0x41] };
        cache.complete(request_id, fingerprint, &success);
        assert!(matches!(cache.admit(request_id, fingerprint), InboundRequestAdmission::Execute));
    }

    #[test]
    fn cancelled_inbound_execution_releases_its_in_flight_marker() {
        let request_id = RequestId::from_bytes([0xA3; 32]);
        let fingerprint = [0xB4; 32];
        let cache = Arc::new(StdMutex::new(InboundRequestCache::default()));
        assert!(matches!(
            InboundRequestCache::lock(&cache).admit(request_id, fingerprint),
            InboundRequestAdmission::Execute
        ));
        drop(InboundRequestExecution::new(cache.clone(), request_id, fingerprint));
        assert!(matches!(
            InboundRequestCache::lock(&cache).admit(request_id, fingerprint),
            InboundRequestAdmission::Execute
        ));
    }

    #[test]
    fn inbound_request_cache_remains_entry_bounded() {
        let mut cache = InboundRequestCache::default();
        for counter in 0..u64::try_from(MAX_INBOUND_REQUEST_CACHE_ENTRIES_PER_PEER * 4).unwrap() {
            let request_id = request_id_for_counter(counter);
            let fingerprint = *blake3::hash(&counter.to_le_bytes()).as_bytes();
            assert!(matches!(
                cache.admit(request_id, fingerprint),
                InboundRequestAdmission::Execute
            ));
            cache.complete(
                request_id,
                fingerprint,
                &PeerResponse::Success { body: vec![0x55; 8 * 1024] },
            );
            assert!(cache.entries.len() <= MAX_INBOUND_REQUEST_CACHE_ENTRIES_PER_PEER);
        }
    }

    #[test]
    fn authenticated_peer_rate_windows_are_independent_and_reset() {
        let now = Instant::now();
        let interval = Duration::from_secs(1);
        let mut noisy = FixedWindowRate::new(now);
        let mut honest = FixedWindowRate::new(now);
        assert!(noisy.try_admit(now, interval, 2));
        assert!(noisy.try_admit(now, interval, 2));
        assert!(!noisy.try_admit(now, interval, 2));
        assert!(honest.try_admit(now, interval, 2));
        assert!(noisy.try_admit(now + interval, interval, 2));
    }

    #[test]
    fn one_peer_cannot_consume_the_global_inbound_request_budget() {
        let noisy = InboundPeerState::new(2);
        let honest = InboundPeerState::new(2);
        let global = Arc::new(Semaphore::new(4));
        let _noisy_peer_one = noisy.request_permits.clone().try_acquire_owned().unwrap();
        let _noisy_global_one = global.clone().try_acquire_owned().unwrap();
        let _noisy_peer_two = noisy.request_permits.clone().try_acquire_owned().unwrap();
        let _noisy_global_two = global.clone().try_acquire_owned().unwrap();
        assert!(noisy.request_permits.clone().try_acquire_owned().is_err());

        let _honest_peer = honest.request_permits.clone().try_acquire_owned().unwrap();
        let _honest_global = global.clone().try_acquire_owned().unwrap();
    }

    #[test]
    fn epoch_and_retry_caches_do_not_grow_with_lifetime_epoch_count() {
        let mut epoch_cache = EpochMessageCache::default();
        let hot_width = MAX_COMMITTEE_MEMBERS * 64;
        let mut retries = BTreeMap::new();
        let now = Instant::now();
        for epoch in 0_u64..5_000 {
            let first = epoch.saturating_sub(63);
            let current = (first..=epoch)
                .flat_map(|hot_epoch| {
                    (0..MAX_COMMITTEE_MEMBERS).map(move |recipient| {
                        request_id_for_counter(
                            hot_epoch
                                .saturating_mul(u64::try_from(MAX_COMMITTEE_MEMBERS).unwrap())
                                .saturating_add(u64::try_from(recipient).unwrap()),
                        )
                    })
                })
                .collect::<BTreeSet<_>>();
            epoch_cache.reconcile(current.clone());
            for key in &current {
                epoch_cache.mark_delivered(*key);
                retries.entry(*key).or_insert_with(|| RetryState::new(now));
            }
            retain_live_retry_states(&mut retries, &current, &BTreeSet::new());
            assert!(epoch_cache.known.len() <= hot_width);
            assert!(epoch_cache.delivered.len() <= hot_width);
            assert!(retries.len() <= hot_width);
        }
    }

    #[test]
    fn transition_scheduler_cannot_send_activation_before_key_rotation_or_qual_before_avss() {
        use crate::quic_transport::{
            AvssOperation, EpochOperation, KeyRotationOperation, QualOperation,
        };

        let recipient = PartyId(2);
        let mut pending = BTreeMap::new();
        // Insert in the adversarial arrival order which previously opened independent streams.
        retain_earliest_transition_work(
            &mut pending,
            1,
            0,
            transition_test_work(
                recipient,
                1,
                PeerRequest::Epoch { operation: EpochOperation::Activate, body: vec![1] },
            ),
        );
        retain_earliest_transition_work(
            &mut pending,
            1,
            2,
            transition_test_work(
                recipient,
                2,
                PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![2] },
            ),
        );
        retain_earliest_transition_work(
            &mut pending,
            1,
            1,
            transition_test_work(
                recipient,
                3,
                PeerRequest::Avss { operation: AvssOperation::Deliver, body: vec![3] },
            ),
        );
        retain_earliest_transition_work(
            &mut pending,
            1,
            0,
            transition_test_work(
                recipient,
                4,
                PeerRequest::KeyRotation {
                    operation: KeyRotationOperation::Certificate,
                    body: vec![4],
                },
            ),
        );
        let selected = pending
            .get(&recipient)
            .expect("one recipient must retain its items")
            .values()
            .next()
            .expect("recipient retains the causally-earliest item first");
        assert!(matches!(
            &selected.request,
            PeerRequest::KeyRotation { operation: KeyRotationOperation::Certificate, .. }
        ));

        pending.clear();
        retain_earliest_transition_work(
            &mut pending,
            1,
            8,
            transition_test_work(
                recipient,
                5,
                PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![5] },
            ),
        );
        retain_earliest_transition_work(
            &mut pending,
            1,
            4,
            transition_test_work(
                recipient,
                6,
                PeerRequest::Avss { operation: AvssOperation::Deliver, body: vec![6] },
            ),
        );
        let selected = pending
            .get(&recipient)
            .expect("one recipient must retain its items")
            .values()
            .next()
            .expect("recipient retains the causally-earliest item first");
        assert!(matches!(&selected.request, PeerRequest::Avss { .. }));

        pending.clear();
        retain_earliest_transition_work(
            &mut pending,
            1,
            12,
            transition_test_work(
                recipient,
                1,
                PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![9] },
            ),
        );
        retain_earliest_transition_work(
            &mut pending,
            1,
            8,
            transition_test_work(
                recipient,
                9,
                PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![10] },
            ),
        );
        let selected = pending
            .get(&recipient)
            .expect("one recipient must retain its items")
            .values()
            .next()
            .expect("recipient retains the causally-earliest item first");
        assert_eq!(selected.key, RequestId::from_bytes([9; 32]));

        pending.clear();
        retain_earliest_transition_work(
            &mut pending,
            2,
            0,
            transition_test_work(
                recipient,
                7,
                PeerRequest::KeyRotation {
                    operation: KeyRotationOperation::Certificate,
                    body: vec![7],
                },
            ),
        );
        retain_earliest_transition_work(
            &mut pending,
            1,
            0,
            transition_test_work(
                recipient,
                8,
                PeerRequest::Epoch { operation: EpochOperation::Activate, body: vec![8] },
            ),
        );
        let selected = pending
            .get(&recipient)
            .expect("one recipient must retain its items")
            .values()
            .next()
            .expect("recipient retains the causally-earliest item first");
        assert!(matches!(
            &selected.request,
            PeerRequest::Epoch { operation: EpochOperation::Activate, .. }
        ));
    }

    #[test]
    fn key_rotation_view_evidence_precedes_the_new_view_proposal() {
        let digest = [0x91; 32];
        assert!(
            key_rotation_delivery_order(
                7,
                KeyRotationDeliveryKind::ViewChange { target_view: 4 },
                digest,
            ) < key_rotation_delivery_order(
                7,
                KeyRotationDeliveryKind::Proposal { view: 4 },
                digest,
            )
        );
        assert!(
            key_rotation_delivery_order(
                7,
                KeyRotationDeliveryKind::ViewCertificate { target_view: 4 },
                digest,
            ) < key_rotation_delivery_order(
                7,
                KeyRotationDeliveryKind::Proposal { view: 4 },
                digest,
            )
        );
        assert!(
            key_rotation_delivery_order(7, KeyRotationDeliveryKind::Proposal { view: 4 }, digest,)
                < key_rotation_delivery_order(
                    7,
                    KeyRotationDeliveryKind::Prevote { view: 4 },
                    digest,
                )
        );
    }

    #[test]
    fn retry_backoff_is_bounded_and_party_jittered() {
        let now = Instant::now();
        let mut first = RetryState::new(now);
        let mut second = RetryState::new(now);
        let initial = Duration::from_millis(100);
        let maximum = Duration::from_secs(2);
        let first_delay = first.failure(now, PartyId(1), initial, maximum);
        let second_delay = second.failure(now, PartyId(2), initial, maximum);
        assert_ne!(first_delay, second_delay);
        for _ in 0..100 {
            assert!(first.failure(now, PartyId(1), initial, maximum) <= maximum);
        }
    }

    #[test]
    fn durable_retry_fallback_ids_bind_network_kind_recipient_and_message_kind() {
        let session = SessionId([7; 32]);
        let digest = [9; 32];
        let avss = PeerMessageId::Avss { session, recipient: PartyId(1), digest };
        let qual = PeerMessageId::Qual { session, recipient: PartyId(1), digest };
        let another_recipient = PeerMessageId::Avss { session, recipient: PartyId(2), digest };

        let id = durable_retry_fallback_id([1; 32], avss);
        assert_eq!(id, durable_retry_fallback_id([1; 32], avss));
        assert_ne!(id, durable_retry_fallback_id([2; 32], avss));
        assert_ne!(id, durable_retry_fallback_id([1; 32], qual));
        assert_ne!(id, durable_retry_fallback_id([1; 32], another_recipient));
    }

    #[test]
    fn key_rotation_retry_fallback_ids_bind_context_recipient_slot_and_content() {
        let original = KeyRotationMessageId {
            context: [3; 32],
            recipient: PartyId(2),
            kind: KeyRotationDeliveryKind::Prevote { view: 7 },
            digest: [5; 32],
        };
        let id = key_rotation_retry_fallback_id([1; 32], original);
        assert_eq!(id, key_rotation_retry_fallback_id([1; 32], original));
        assert_ne!(id, key_rotation_retry_fallback_id([2; 32], original));
        assert_ne!(
            id,
            key_rotation_retry_fallback_id(
                [1; 32],
                KeyRotationMessageId { context: [4; 32], ..original },
            )
        );
        assert_ne!(
            id,
            key_rotation_retry_fallback_id(
                [1; 32],
                KeyRotationMessageId { recipient: PartyId(3), ..original }
            )
        );
        assert_ne!(
            id,
            key_rotation_retry_fallback_id(
                [1; 32],
                KeyRotationMessageId {
                    kind: KeyRotationDeliveryKind::Prevote { view: 8 },
                    ..original
                }
            )
        );
        assert_ne!(
            id,
            key_rotation_retry_fallback_id(
                [1; 32],
                KeyRotationMessageId { digest: [6; 32], ..original },
            )
        );
    }

    #[test]
    fn key_rotation_outbox_ack_requires_a_success_response() {
        assert!(key_rotation_response_authorizes_ack(&DeliveryDisposition::Accepted));
        assert!(!key_rotation_response_authorizes_ack(&DeliveryDisposition::TerminalRejection(
            "permanent-looking rejection".into()
        )));
        assert!(!key_rotation_response_authorizes_ack(&DeliveryDisposition::Deferred(
            "retryable rejection".into()
        )));
    }

    #[test]
    fn runtime_limits_reject_unbounded_or_zero_values() {
        let invalid = QuicRuntimeConfig { outbox_batch_size: 0, ..Default::default() };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            outbox_batch_size: MAX_COMMITTEE_MEMBERS - 1,
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            max_outbound_requests: 2,
            max_outbound_requests_per_peer: 3,
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            max_inbound_requests: 2,
            max_inbound_requests_per_peer: 2,
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            max_inbound_requests_per_peer_per_interval: 0,
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            epoch_history_request_timeout: Duration::from_secs(3),
            epoch_history_source_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid =
            QuicRuntimeConfig { max_epoch_history_raced_sources: 0, ..Default::default() };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));
    }

    #[test]
    fn default_qual_timeout_cannot_race_normal_avss_fanout() {
        assert_eq!(derived_qual_round_timeout(1), Duration::from_secs(10));
        assert_eq!(derived_qual_round_timeout(1_000), Duration::from_secs(32));
    }

    #[tokio::test]
    async fn transient_scanner_failure_does_not_freeze_consolidation_progress() {
        let progressed = AtomicBool::new(false);
        let (scanner, consolidation) = run_independent_deposit_steps(
            || async { Err::<(), _>("temporary daemon failure") },
            || async {
                progressed.store(true, Ordering::Release);
                Ok::<(), &str>(())
            },
        )
        .await;
        assert_eq!(scanner, Err("temporary daemon failure"));
        assert_eq!(consolidation, Ok(()));
        assert!(progressed.load(Ordering::Acquire));
    }

    #[test]
    fn only_retryable_peer_rejections_remain_in_the_outbox() {
        let terminal = classify_peer_response(PeerResponse::Rejected {
            code: crate::quic_transport::RejectionCode::Conflict,
            retryable: false,
            message: "AVSS session is already finalized".into(),
        });
        assert!(matches!(terminal, DeliveryDisposition::TerminalRejection(_)));

        let deferred = classify_peer_response(PeerResponse::Rejected {
            code: crate::quic_transport::RejectionCode::Unavailable,
            retryable: true,
            message: "dealer has not locally completed AVSS".into(),
        });
        assert!(matches!(deferred, DeliveryDisposition::Deferred(_)));
    }

    #[test]
    fn generic_success_cannot_retire_byzantine_consolidation_evidence() {
        let request =
            PeerRequest::Deposit { operation: DepositOperation::Consolidation, body: vec![0x41] };
        let disposition = classify_peer_response_for_request(
            &request,
            PeerResponse::Success { body: Vec::new() },
            |_, _| anyhow::bail!("missing typed acknowledgement"),
        );
        assert!(matches!(disposition, DeliveryDisposition::Deferred(_)));
        let accepted = classify_peer_response_for_request(
            &request,
            PeerResponse::Success { body: vec![0xAC] },
            |request, response| {
                anyhow::ensure!(request == [0x41] && response == [0xAC]);
                Ok(())
            },
        );
        assert!(matches!(accepted, DeliveryDisposition::Accepted));
    }

    #[test]
    fn terminal_rejection_cannot_retire_byzantine_consolidation_evidence() {
        let request =
            PeerRequest::Deposit { operation: DepositOperation::Consolidation, body: vec![0x51] };
        assert!(request_requires_positive_ack(&request));
        let disposition = classify_peer_response_for_request(
            &request,
            PeerResponse::Rejected {
                code: crate::quic_transport::RejectionCode::Conflict,
                retryable: false,
                message: "receiver claims the ROAST view conflicts".into(),
            },
            |_, _| anyhow::bail!("a rejection has no typed acknowledgement"),
        );
        assert!(matches!(&disposition, DeliveryDisposition::TerminalRejection(_)));
        assert!(!byzantine_consolidation_response_authorizes_ack(&disposition));
        assert!(byzantine_consolidation_response_authorizes_ack(&DeliveryDisposition::Accepted));
    }

    #[test]
    fn avss_qual_and_epoch_evidence_require_positive_ack() {
        for request in [
            PeerRequest::Avss {
                operation: crate::quic_transport::AvssOperation::Deliver,
                body: vec![0x71],
            },
            PeerRequest::Qual {
                operation: crate::quic_transport::QualOperation::Deliver,
                body: vec![0x72],
            },
            PeerRequest::Epoch {
                operation: crate::quic_transport::EpochOperation::Activate,
                body: vec![0x73],
            },
        ] {
            assert!(request_requires_positive_ack(&request));
            let rejection = DeliveryDisposition::TerminalRejection("receiver is early".into());
            assert!(disposition_requires_backoff(&request, &rejection));
            assert!(!protocol_evidence_response_authorizes_ack(&rejection));
        }
        assert!(protocol_evidence_response_authorizes_ack(&DeliveryDisposition::Accepted));
    }

    #[test]
    fn authenticated_terminal_evidence_rejection_advances_the_retry_clock() {
        use crate::quic_transport::KeyRotationOperation;

        let rejected = DeliveryDisposition::TerminalRejection("peer is behind".into());
        let consolidation =
            PeerRequest::Deposit { operation: DepositOperation::Consolidation, body: vec![0x61] };
        let rotation = PeerRequest::KeyRotation {
            operation: KeyRotationOperation::Certificate,
            body: vec![0x62],
        };
        assert!(disposition_requires_backoff(&consolidation, &rejected));
        assert!(disposition_requires_backoff(&rotation, &rejected));

        let now = Instant::now();
        let mut retry = RetryState::new(now);
        let delay =
            retry.failure(now, PartyId(2), Duration::from_millis(100), Duration::from_secs(1));
        assert_eq!(retry.failures, 1);
        assert!(!retry.ready(now));
        assert!(retry.ready(now + delay));
    }

    #[test]
    fn consolidation_round_precedes_its_same_slot_completion_statement() {
        assert!(
            deposit_operation_priority(DepositOperation::Consolidation)
                < deposit_operation_priority(DepositOperation::ConsolidationCompletion)
        );
        assert!(
            deposit_operation_priority(DepositOperation::ConsolidationCompletion)
                < deposit_operation_priority(DepositOperation::Attest)
        );
    }

    #[test]
    fn byzantine_consolidation_delivery_phases_have_a_strict_causal_order() {
        use crate::deposit_consolidation_wire::ByzantineDeliveryKind;

        let ordered = [
            ByzantineDeliveryKind::ConsensusMessage,
            ByzantineDeliveryKind::ViewCertificate,
            ByzantineDeliveryKind::CertifiedIntent,
            ByzantineDeliveryKind::Preprocess,
            ByzantineDeliveryKind::KeyImageBinding,
            ByzantineDeliveryKind::Share,
            ByzantineDeliveryKind::Candidate,
        ];
        for phases in ordered.windows(2) {
            assert!(
                phases[0].causal_priority() < phases[1].causal_priority(),
                "{:?} must be delivered before {:?}",
                phases[0],
                phases[1]
            );
        }
    }

    #[test]
    fn target_view_certificate_precedes_the_laggers_proposal() {
        use crate::deposit_consolidation_wire::ByzantineDeliveryKind;

        let family = [0x71; 32];
        let certificate = byzantine_causal_prefix(
            19,
            family,
            2,
            ByzantineDeliveryKind::ViewCertificate,
            Some((1, 0)),
        );
        let proposal = byzantine_causal_prefix(
            19,
            family,
            2,
            ByzantineDeliveryKind::ConsensusMessage,
            Some((1, 1)),
        );
        assert!(certificate < proposal);

        let previous_precommit = byzantine_causal_prefix(
            19,
            family,
            2,
            ByzantineDeliveryKind::ConsensusMessage,
            Some((0, 3)),
        );
        assert!(previous_precommit < certificate);
    }

    #[test]
    fn allocation_consensus_precedes_statement_and_attestation_effects() {
        let ordered = [
            DepositOperation::ClientRequest,
            DepositOperation::ConsensusProposal,
            DepositOperation::ConsensusMessage,
            DepositOperation::ConsensusCertificate,
            DepositOperation::Allocate,
            DepositOperation::Attest,
            DepositOperation::Certificate,
        ];
        for pair in ordered.windows(2) {
            assert!(
                deposit_operation_priority(pair[0]) < deposit_operation_priority(pair[1]),
                "{:?} must be relayed before {:?}",
                pair[0],
                pair[1]
            );
        }
    }
}
