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
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::{
    sync::{Mutex, Notify, Semaphore},
    task::{Id as TaskId, JoinError, JoinSet},
    time::{self, Instant, MissedTickBehavior},
};

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId},
    config::{ConfigError, Scenario},
    deposit_archive::DepositArchiveEvent,
    deposit_consolidation_wire::{
        ByzantineConsolidationWireMessage, ByzantineDeliveryId, ByzantineRelayAck,
    },
    deposit_prefix_collection_store::{
        DepositPrefixCollectionStatus, DepositPrefixCollectionStoreError,
    },
    deposit_service::{
        DepositCausalLane, DepositPeerMessageId, DepositServiceError,
        DepositStateExportSealWorkLocator, DepositStateExportSealWorkRoute,
        DepositStateImportWorkLocator, DepositSyncAdoptionFailureClass,
    },
    deposit_state_export_store::DepositStateExportSealWorkKind,
    deposit_state_import_store::{DepositStateImportStoreError, DepositStateImportWorkKind},
    deposit_state_transfer_wire::{
        DepositStateExportHeadRequest, DepositStateExportHeadResponse,
        DepositStateExportObjectsResponse, DepositStateExportReleaseAck,
        DepositStateTransferContext,
    },
    deposit_sync_stage::{
        DepositSyncPrefixSupportWork, DepositSyncSpoolAdmission, DepositSyncSpoolPhase,
        DepositSyncSpoolStore, DepositSyncVariantRejection,
    },
    deposit_sync_support::{DepositSyncPrefixSupportProgress, DepositSyncSupportRequest},
    deposit_sync_wire::{
        DepositSyncAdvertisement, DepositSyncAnchorLease, DepositSyncContext,
        DepositSyncHeadRequest, DepositSyncHeadResponse, DepositSyncObjectPage,
        DepositSyncObjectPageRequest, DepositSyncObjectRequestEntry, DepositSyncReleaseAck,
        DepositSyncTraversalTarget, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES,
        MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES, MAX_DEPOSIT_SYNC_REQUEST_OBJECTS,
        MAX_DEPOSIT_SYNC_WIRE_BYTES,
    },
    epoch_history::{
        EpochHistoryCatchupManifest, EpochHistoryCatchupQuery, EpochHistoryCatchupReply,
        EpochHistoryObjectRef, MAX_EPOCH_HISTORY_CHUNK_BYTES,
        MAX_EPOCH_HISTORY_REQUESTS_PER_SOURCE, MAX_HOT_EPOCH_HISTORY_ENTRIES,
    },
    key_rotation::{KeyRotationDeliveryKind, KeyRotationMessageId, PendingKeyRotationMessage},
    quic_transport::{
        AuthenticatedPeerConnection, DepositOperation, EpochOperation, PeerRequest, PeerResponse,
        QuicPeerEndpoint, QuicResponseProvenance, QuicTransportError, RejectionCode, RequestId,
    },
    server::{
        ByzantineConsolidationAckExpectation, CertifiedDepositStateTransferWorkContext,
        PartyServer, PeerMessageId, PendingEpochPeerMessage,
    },
    storage::DepositStateTransferIntentsMetadata,
};

const MAX_BATCH_SIZE: usize = 16 * 1024;
const MIN_OUTBOX_BATCH_SIZE: usize = MAX_COMMITTEE_MEMBERS * DepositCausalLane::COUNT;
const MAX_RUNTIME_CONCURRENCY: usize = 4096;
const MAX_RUNTIME_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MIN_QUAL_ROUND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_EPOCH_HISTORY_ADVANCES_PER_TICK: usize = 4;
const MAX_EPOCH_MESSAGE_CACHE_ENTRIES: usize =
    (MAX_HOT_EPOCH_HISTORY_ENTRIES as usize + 2) * MAX_COMMITTEE_MEMBERS;
const MAX_INBOUND_REQUEST_CACHE_ENTRIES_PER_PEER: usize = 1_024;
const STATE_TRANSFER_INTENT_SNAPSHOT_VERSION: u16 = 1;
// Every non-sync deposit route can enter durable wallet state. One bounded body per authenticated
// identity may wait in the fair endpoint-wide queue; only the selected request may enter the
// service's capacity-one mutation boundary.
const MAX_CONCURRENT_MUTATING_DEPOSIT_REQUESTS: usize = 1;
const MAX_CONCURRENT_DEPOSIT_SYNC_OBJECT_REQUESTS: usize = 1;
const MAX_CONCURRENT_DEPOSIT_PREFIX_SUPPORT_SCANS: usize = 1;
const MAX_CONCURRENT_DEPOSIT_SYNC_CONTROL_REQUESTS: usize = 1;
// Head and exact-lease Release are tiny liveness controls. Give each authenticated identity one
// shared queued slot and rate it independently of operator-tunable ordinary ingress. One FIFO
// endpoint execution lane prevents otherwise-concurrent control handlers from forming a convoy on
// the service's single mutable wallet/index state.
const MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL: usize = 8;
const DEPOSIT_SYNC_CONTROL_RATE_INTERVAL: Duration = Duration::from_secs(1);
const MAX_DEPOSIT_SYNC_REQUESTS_PER_TICK: usize = 64;
const MAX_DEPOSIT_SYNC_PAGES_PER_TICK: usize = 32;
const MAX_DEPOSIT_SYNC_OBJECTS_PER_TICK: usize = 64;
const MAX_DEPOSIT_SYNC_WIRE_BYTES_PER_TICK: usize = 8 * MAX_DEPOSIT_SYNC_WIRE_BYTES;
const DEPOSIT_SYNC_COOPERATIVE_YIELD_PAGES: usize = 4;
const MAX_CERTIFIED_EXPORT_RELEASES_PER_DRAIN: usize = 1;
const RESERVED_RELAY_OUTBOUND_REQUESTS: usize = 1;
// One authenticated peer may occupy at most one transport-maximum (8 MiB) request body at a
// time. The global budget admits eight such peers concurrently, leaving honest-peer headroom
// above the largest supported committee fault bound without letting the count-based request
// limit turn into a multi-gibibyte allocation.
const MAX_INBOUND_BODY_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
const MAX_INBOUND_BODY_BYTES: usize = 8 * MAX_INBOUND_BODY_BYTES_PER_PEER;

/// Compare only the consensus authority of two compact deposit heads.
///
/// Exact registry/archive roots and checkpoint witness subsets are deliberately party-local
/// audit artifacts. They may differ even when both advertisements prove the same registry,
/// checkpoint decision, and portable index state.
fn deposit_sync_heads_are_semantically_equal(
    left: &DepositSyncAdvertisement,
    right: &DepositSyncAdvertisement,
) -> bool {
    let same_checkpoint_decision =
        match (left.checkpoint_certificate(), right.checkpoint_certificate()) {
            (None, None) => true,
            (Some(left), Some(right)) => left.has_same_witness_independent_decision(right),
            (None, Some(_)) | (Some(_), None) => false,
        };
    left.context() == right.context()
        && left.registry_id() == right.registry_id()
        && left.certificate_archive().len() == right.certificate_archive().len()
        && left.portable_index() == right.portable_index()
        && same_checkpoint_decision
}

/// Run one ordinary scanner tick plus bounded immediate allocation-backfill follow-ups.
///
/// Each `tick` owns and completes its durable reducer cut before returning. The cooperative yield
/// and shutdown checks happen only between those cuts, so shutdown can neither cancel an entered
/// persistence operation nor make a historical backfill wait one full runtime interval per block.
async fn run_bounded_deposit_scanner_burst<Tick, TickFuture, Shutdown, Error>(
    maximum_ticks: usize,
    mut tick: Tick,
    shutdown_requested: Shutdown,
) -> Result<usize, Error>
where
    Tick: FnMut() -> TickFuture,
    TickFuture: Future<Output = Result<bool, Error>>,
    Shutdown: Fn() -> bool,
{
    debug_assert!(maximum_ticks > 0);
    let mut completed = 0;
    while completed < maximum_ticks {
        let allocation_backfill_pending = tick().await?;
        completed += 1;
        if !allocation_backfill_pending || completed == maximum_ticks {
            break;
        }
        if shutdown_requested() {
            break;
        }
        tokio::task::yield_now().await;
        if shutdown_requested() {
            break;
        }
    }
    Ok(completed)
}

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
    /// Maximum time an authenticated peer may occupy one outbound relay stream.
    pub outbound_request_timeout: Duration,
    /// Maximum transport-only drain after every authoritative reducer loop has stopped.
    pub transport_shutdown_grace: Duration,
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
    /// Total transport deadline for one compact-deposit RPC.
    pub deposit_sync_request_timeout: Duration,
    /// Maximum time one availability source may occupy a compact-deposit tick. Verified pages
    /// remain staged when this expires, so the next source/tick resumes rather than restarts.
    pub deposit_sync_source_timeout: Duration,
    /// Total availability work admitted by one compact-deposit tick. It must fit one head-request
    /// deadline plus one complete pinned-source deadline so a different peer's head response can
    /// never make the durable source look faulty. Source rotation remains bounded and fair when a
    /// Byzantine source deliberately consumes its complete budget.
    pub deposit_sync_tick_timeout: Duration,
    /// Independent compact-state synchronization cadence. Scanner, consensus, consolidation, and
    /// publication progress may need a short worker interval, but multiplying full-state probes
    /// by that cadence can create a recovery convoy across the honest quorum.
    pub deposit_sync_interval: Duration,
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
            outbound_request_timeout: Duration::from_secs(30),
            transport_shutdown_grace: Duration::from_secs(5),
            protocol_progress_interval: Duration::from_millis(500),
            epoch_history_request_timeout: Duration::from_secs(5),
            epoch_history_source_timeout: Duration::from_secs(20),
            epoch_history_sync_timeout: Duration::from_secs(30),
            max_epoch_history_raced_sources: 4,
            deposit_sync_request_timeout: Duration::from_secs(5),
            deposit_sync_source_timeout: Duration::from_secs(20),
            deposit_sync_tick_timeout: Duration::from_secs(30),
            deposit_sync_interval: Duration::from_secs(5),
            deposit_worker_interval: Duration::from_secs(5),
            consolidation_attempt_timeout: Duration::from_secs(60),
            qual_round_timeout: None,
        }
    }
}

impl QuicRuntimeConfig {
    fn validate(self) -> Result<Self, QuicRuntimeError> {
        // A poll must expose one predecessor for every possible recipient and independent deposit
        // causal namespace. Otherwise a large ledger backlog can hide checkpoint progress, or a
        // silent low-id peer can hide all work for healthy higher-id recipients.
        if self.outbox_batch_size < MIN_OUTBOX_BATCH_SIZE || self.outbox_batch_size > MAX_BATCH_SIZE
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "outbox_batch_size must be in 150..=16384",
            ));
        }
        if self.max_outbound_requests <= RESERVED_RELAY_OUTBOUND_REQUESTS
            || self.max_outbound_requests > MAX_RUNTIME_CONCURRENCY
            || self.max_outbound_requests_per_peer <= RESERVED_RELAY_OUTBOUND_REQUESTS
            || self.max_outbound_requests_per_peer > self.max_outbound_requests
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "outbound concurrency must reserve one relay slot globally and per peer, remain bounded, and have per-peer <= global",
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
            self.outbound_request_timeout,
            self.transport_shutdown_grace,
            self.protocol_progress_interval,
            self.inbound_peer_rate_interval,
            self.epoch_history_request_timeout,
            self.epoch_history_source_timeout,
            self.epoch_history_sync_timeout,
            self.deposit_sync_request_timeout,
            self.deposit_sync_source_timeout,
            self.deposit_sync_tick_timeout,
            self.deposit_sync_interval,
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
        let minimum_deposit_sync_tick =
            self.deposit_sync_request_timeout.checked_add(self.deposit_sync_source_timeout).ok_or(
                QuicRuntimeError::InvalidConfiguration("deposit-sync deadline sum overflowed"),
            )?;
        if self.deposit_sync_request_timeout > self.deposit_sync_source_timeout
            || minimum_deposit_sync_tick > self.deposit_sync_tick_timeout
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "deposit-sync request timeout must be <= source timeout and request + source must fit within the tick timeout",
            ));
        }
        if self.max_epoch_history_raced_sources == 0
            || self.max_epoch_history_raced_sources > MAX_COMMITTEE_MEMBERS
            || self.max_epoch_history_raced_sources
                > sync_request_capacity(self.max_outbound_requests)
                    .expect("outbound width was validated above")
        {
            return Err(QuicRuntimeError::InvalidConfiguration(
                "epoch-history race width must be nonzero and fit within committee/global sync request bounds",
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

fn sync_request_capacity(total: usize) -> Option<usize> {
    total.checked_sub(RESERVED_RELAY_OUTBOUND_REQUESTS).filter(|capacity| *capacity != 0)
}

/// Require one bounded outbox poll to expose every recipient/lane predecessor in this scenario.
///
/// The generic configuration range retains a deployment-independent floor. Startup adds this
/// scenario-sized bound because the stable identity roster may be larger than any one committee.
fn validate_scenario_outbox_batch_size(
    outbox_batch_size: usize,
    scenario_parties: usize,
) -> Result<(), QuicRuntimeError> {
    let required = scenario_parties.checked_mul(DepositCausalLane::COUNT).ok_or(
        QuicRuntimeError::InvalidConfiguration(
            "scenario party/lane outbox coverage bound overflowed",
        ),
    )?;
    if required > MAX_BATCH_SIZE {
        return Err(QuicRuntimeError::InvalidConfiguration(
            "scenario party/lane outbox coverage exceeds the runtime batch limit",
        ));
    }
    if outbox_batch_size < required {
        return Err(QuicRuntimeError::InvalidConfiguration(
            "outbox_batch_size is smaller than the scenario party/lane coverage bound",
        ));
    }
    Ok(())
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

fn try_acquire_deposit_sync_objects_peer_slot(
    permits: &Arc<Semaphore>,
    is_deposit_sync_objects: bool,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, PeerResponse> {
    if !is_deposit_sync_objects {
        return Ok(None);
    }
    permits
        .clone()
        .try_acquire_owned()
        .map(Some)
        .map_err(|_| deposit_sync_objects_peer_busy_response())
}

fn validate_deposit_sync_objects_body_len(
    is_deposit_sync_objects: bool,
    body_len: usize,
) -> Result<(), PeerResponse> {
    if is_deposit_sync_objects && body_len > MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES {
        return Err(deposit_sync_objects_body_too_large_response());
    }
    Ok(())
}

/// Large certified-transition routes need a cheap authenticated-history check before body
/// admission. `ExportRelease` is deliberately excluded: its exact lease MAC is storage-only
/// authority and must remain releasable after either endpoint leaves the committee.
const fn deposit_state_transfer_requires_history_authorization(
    operation: DepositOperation,
) -> bool {
    matches!(
        operation,
        DepositOperation::PostHandoffExportSealRequest
            | DepositOperation::PostHandoffExportSealVote
            | DepositOperation::PostHandoffExportSealCertificate
            | DepositOperation::ExportHead
            | DepositOperation::ExportObjects
            | DepositOperation::StateImportedAck
            | DepositOperation::StateImportedCertificate
    )
}

async fn acquire_deposit_sync_objects_execution_permit(
    permits: &Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        () = shutdown => None,
        permit = permits.clone().acquire_owned() => permit.ok(),
    }
}

fn try_acquire_deposit_prefix_support_peer_slot(
    permits: &Arc<Semaphore>,
    is_deposit_prefix_support_scan: bool,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, PeerResponse> {
    if !is_deposit_prefix_support_scan {
        return Ok(None);
    }
    permits
        .clone()
        .try_acquire_owned()
        .map(Some)
        .map_err(|_| deposit_prefix_support_peer_busy_response())
}

async fn acquire_deposit_prefix_support_execution_permit(
    permits: &Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        () = shutdown => None,
        permit = permits.clone().acquire_owned() => permit.ok(),
    }
}

/// One nonblocking queued slot per authenticated peer, shared by `SyncHead` and `SyncRelease`.
fn try_acquire_deposit_sync_control_peer_slot(
    peer: &Arc<Semaphore>,
    is_deposit_sync_control: bool,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, PeerResponse> {
    if !is_deposit_sync_control {
        return Ok(None);
    }
    peer.clone().try_acquire_owned().map(Some).map_err(|_| deposit_sync_control_busy_response())
}

/// FIFO execution capacity for tiny deposit-sync control reducers.
///
/// Each waiter already owns its authenticated peer's sole control slot. Waiting here therefore
/// consumes only one bounded control body per identity, and shutdown cancels the wait before any
/// authoritative reducer is dispatched.
async fn acquire_deposit_sync_control_execution_permit(
    permits: &Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        () = shutdown => None,
        permit = permits.clone().acquire_owned() => permit.ok(),
    }
}

const fn requires_deposit_mutation_admission(
    deposit_operation: Option<DepositOperation>,
    is_deposit_object_read: bool,
    is_deposit_prefix_support_scan: bool,
    is_deposit_sync_control: bool,
) -> bool {
    deposit_operation.is_some()
        && !is_deposit_object_read
        && !is_deposit_prefix_support_scan
        && !is_deposit_sync_control
}

/// Mirror the receiver's dedicated read/control routes before opening an outbound stream.
///
/// Every other deposit operation may enter durable wallet state and must share the receiver-width
/// mutable lane. In particular, `ExportHead` creates a durable lease and `ExportRelease` mutates
/// certified-transfer state; neither is an immutable read.
const fn deposit_operation_requires_mutation_admission(operation: DepositOperation) -> bool {
    !matches!(
        operation,
        DepositOperation::SyncHead
            | DepositOperation::SyncObjects
            | DepositOperation::SyncRelease
            | DepositOperation::PrefixSupportStart
            | DepositOperation::PrefixSupportContinue
            | DepositOperation::ExportObjects
    )
}

const fn peer_request_requires_deposit_mutation_admission(request: &PeerRequest) -> bool {
    matches!(
        request,
        PeerRequest::Deposit { operation, .. }
            if deposit_operation_requires_mutation_admission(*operation)
    )
}

const fn mutable_deposit_relay_is_admitted(
    state_transfer_preflight_complete: bool,
    request: &PeerRequest,
) -> bool {
    state_transfer_preflight_complete || !peer_request_requires_deposit_mutation_admission(request)
}

const fn requires_ordinary_inbound_execution_admission(
    requires_deposit_mutation_admission: bool,
    is_deposit_object_read: bool,
    is_deposit_prefix_support_scan: bool,
    is_deposit_sync_control: bool,
) -> bool {
    !requires_deposit_mutation_admission
        && !is_deposit_object_read
        && !is_deposit_prefix_support_scan
        && !is_deposit_sync_control
}

/// Reserve one pre-body mutable request for an authenticated identity.
///
/// The slot is shared across every connection authenticated as that peer and remains live through
/// response completion. Mutable bodies are subsequently charged to the ordinary weighted byte
/// budget, so at most one bounded body per fixed peer identity can wait for the fair endpoint-wide
/// execution lane.
fn try_acquire_deposit_mutation_peer_slot(
    peer: &Arc<Semaphore>,
    required: bool,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, PeerResponse> {
    if !required {
        return Ok(None);
    }
    peer.clone().try_acquire_owned().map(Some).map_err(|_| deposit_mutation_busy_response())
}

/// FIFO endpoint execution capacity for mutable deposit reducers.
///
/// Callers enter this queue only after receiving a complete, transport-authenticated body while
/// retaining their peer slot and weighted body permits. The peer slot bounds the queue to one body
/// per fixed authenticated identity, the byte semaphores bound total queued memory, and shutdown
/// cancels waiting work before any authoritative reducer is dispatched.
async fn acquire_deposit_mutation_execution_permit(
    permits: &Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        () = shutdown => None,
        permit = permits.clone().acquire_owned() => permit.ok(),
    }
}

/// Every endpoint-wide deposit execution boundary held by one admitted request.
///
/// These permits serialize reducer execution, not response delivery. Keeping them in one bundle
/// makes it impossible for a cached or fresh response path to return only some dedicated lanes
/// before awaiting requester-controlled QUIC flow-control credit.
struct DepositEndpointExecutionPermits {
    mutation: Option<tokio::sync::OwnedSemaphorePermit>,
    sync_objects: Option<tokio::sync::OwnedSemaphorePermit>,
    prefix_support: Option<tokio::sync::OwnedSemaphorePermit>,
    sync_control: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// Await response I/O only after returning every endpoint-wide deposit execution boundary.
///
/// Per-peer slots remain owned by the request task through response completion, so an identity
/// cannot reacquire ahead of an already-queued peer. Weighted request-body permits are returned by
/// the caller after the reducer no longer owns the body.
async fn respond_after_releasing_deposit_execution<F>(
    permits: DepositEndpointExecutionPermits,
    response: F,
) -> F::Output
where
    F: Future,
{
    let DepositEndpointExecutionPermits { mutation, sync_objects, prefix_support, sync_control } =
        permits;
    drop((mutation, sync_objects, prefix_support, sync_control));
    response.await
}

/// Ordinary inbound capacity acquired before a conforming sender transmits its request body.
///
/// Both acquisitions are nonblocking. A saturated peer or endpoint therefore receives a v8
/// pre-body rejection without allocating or decoding the declared body, and a failed global
/// acquisition immediately returns the already-acquired peer permit.
#[derive(Debug)]
struct InboundRequestExecutionPermits {
    _peer: tokio::sync::OwnedSemaphorePermit,
    _global: tokio::sync::OwnedSemaphorePermit,
}

fn try_acquire_inbound_request_execution_permits(
    peer: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
    required: bool,
) -> Result<Option<InboundRequestExecutionPermits>, PeerResponse> {
    if !required {
        return Ok(None);
    }
    let peer =
        peer.clone().try_acquire_owned().map_err(|_| inbound_concurrency_limited_response())?;
    let global =
        global.clone().try_acquire_owned().map_err(|_| inbound_concurrency_limited_response())?;
    Ok(Some(InboundRequestExecutionPermits { _peer: peer, _global: global }))
}

/// Weighted body capacity reserved from the authenticated prelude before body admission.
///
/// The permits remain live through reducer execution while the decoded body is allocated, then
/// are released before the response is sent. Acquiring peer capacity first prevents one identity
/// from consuming global capacity, while a failed global acquisition immediately returns that
/// partial permit.
#[derive(Debug)]
struct InboundRequestBodyPermits {
    _peer: tokio::sync::OwnedSemaphorePermit,
    _global: tokio::sync::OwnedSemaphorePermit,
}

fn try_acquire_inbound_request_body_permits(
    peer: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
    body_len: usize,
) -> Result<InboundRequestBodyPermits, PeerResponse> {
    let body_len = u32::try_from(body_len).map_err(|_| inbound_body_capacity_limited_response())?;
    let peer = peer
        .clone()
        .try_acquire_many_owned(body_len)
        .map_err(|_| inbound_body_capacity_limited_response())?;
    let global = global
        .clone()
        .try_acquire_many_owned(body_len)
        .map_err(|_| inbound_body_capacity_limited_response())?;
    Ok(InboundRequestBodyPermits { _peer: peer, _global: global })
}

fn deposit_sync_objects_peer_busy_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated peer already has a deposit SyncObjects request outstanding"
            .to_owned(),
    }
}

fn deposit_sync_objects_body_too_large_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::InvalidRequest,
        retryable: false,
        message: format!(
            "deposit SyncObjects request body exceeds the {MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES}-byte protocol limit"
        ),
    }
}

fn deposit_prefix_support_peer_busy_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated requester already has a deposit prefix-support scan outstanding"
            .to_owned(),
    }
}

fn deposit_sync_control_busy_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated deposit sync control lane is busy".to_owned(),
    }
}

fn deposit_sync_control_rate_limited_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated peer deposit sync control rate limit exceeded".to_owned(),
    }
}

fn deposit_mutation_busy_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated peer already has a mutable deposit request outstanding".to_owned(),
    }
}

/// Suppress only sources whose earlier ordinary lease has not returned an exact typed Release
/// acknowledgement. Returns `true` when pending certified work exists but every source is
/// causally blocked.
fn retain_certified_export_heads_without_ordinary_release(
    heads: &mut Vec<DepositStateExportHeadRequest>,
    ordinary_release_barriers: &BTreeSet<PartyId>,
) -> bool {
    let had_pending = !heads.is_empty();
    heads.retain(|request| !ordinary_release_barriers.contains(&request.source()));
    had_pending && heads.is_empty()
}

fn inbound_body_capacity_limited_response() -> PeerResponse {
    PeerResponse::Rejected {
        code: RejectionCode::ResourceExhausted,
        retryable: true,
        message: "authenticated request body capacity is saturated".to_owned(),
    }
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
    body_permits: Arc<Semaphore>,
    deposit_mutation_slot: Arc<Semaphore>,
    deposit_sync_objects_slot: Arc<Semaphore>,
    deposit_prefix_support_slot: Arc<Semaphore>,
    deposit_sync_control_slot: Arc<Semaphore>,
    connection_rate: Mutex<FixedWindowRate>,
    request_rate: Mutex<FixedWindowRate>,
    deposit_sync_control_rate: Mutex<FixedWindowRate>,
    request_cache: Arc<StdMutex<InboundRequestCache>>,
}

impl InboundPeerState {
    fn new(request_concurrency: usize) -> Self {
        let now = Instant::now();
        Self {
            request_permits: Arc::new(Semaphore::new(request_concurrency)),
            body_permits: Arc::new(Semaphore::new(MAX_INBOUND_BODY_BYTES_PER_PEER)),
            deposit_mutation_slot: Arc::new(Semaphore::new(1)),
            deposit_sync_objects_slot: Arc::new(Semaphore::new(1)),
            deposit_prefix_support_slot: Arc::new(Semaphore::new(1)),
            deposit_sync_control_slot: Arc::new(Semaphore::new(1)),
            connection_rate: Mutex::new(FixedWindowRate::new(now)),
            request_rate: Mutex::new(FixedWindowRate::new(now)),
            deposit_sync_control_rate: Mutex::new(FixedWindowRate::new(now)),
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

    async fn admit_deposit_sync_control(&self) -> bool {
        self.deposit_sync_control_rate.lock().await.try_admit(
            Instant::now(),
            DEPOSIT_SYNC_CONTROL_RATE_INTERVAL,
            MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL,
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
    sync_permits: Arc<Semaphore>,
}

impl PeerState {
    fn new(party: PartyId, route: PeerRoute, concurrency: usize) -> Self {
        let reserved_class_concurrency = sync_request_capacity(concurrency)
            .expect("validated per-peer outbound width reserves one relay request");
        Self {
            party,
            route,
            connection: Mutex::new(ConnectionSlot { generation: 0, cached: None }),
            retry: Mutex::new(RetryState::new(Instant::now())),
            permits: Arc::new(Semaphore::new(concurrency)),
            sync_permits: Arc::new(Semaphore::new(reserved_class_concurrency)),
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

    async fn request_connection_failure(
        &self,
        generation: u64,
        error: &crate::quic_transport::QuicTransportError,
        config: QuicRuntimeConfig,
    ) -> Option<Duration> {
        if error.is_connection_lost() {
            Some(self.transport_failure(Some(generation), config).await)
        } else {
            None
        }
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

async fn checkpoint_ack_family<F>(
    durable_ids: &[DurableMessageId],
    accepted: &mut BTreeMap<DurableMessageId, RequestId>,
    in_flight: &mut BTreeSet<RequestId>,
    checkpoint: F,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    if durable_ids.is_empty() {
        return Ok(());
    }
    // A batch routine may durably checkpoint a prefix before reporting a later failure. Retain
    // the complete family batch in that case: every underlying ACK operation is idempotent, and
    // replaying the successful prefix is the only safe way to preserve the failed suffix.
    checkpoint.await?;
    for id in durable_ids {
        if let Some(key) = accepted.remove(id) {
            in_flight.remove(&key);
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum AcceptanceTarget {
    Durable(DurableMessageId),
    Epoch(RequestId),
}

#[derive(Clone)]
enum RelayResponseExpectation {
    Generic,
    ByzantineConsolidation(ByzantineConsolidationAckExpectation),
}

#[derive(Clone)]
struct RelayWork {
    key: RequestId,
    recipient: PartyId,
    request: PeerRequest,
    target: AcceptanceTarget,
    response_expectation: RelayResponseExpectation,
    requires_positive_ack: bool,
    /// Present only for durable mutable-deposit work. The lane is transport metadata used to
    /// advance the recipient's volatile fair scheduler after a stream is actually spawned.
    deposit_causal_lane: Option<DepositCausalLane>,
}

struct CompletedRelayWork {
    key: RequestId,
    recipient: PartyId,
    target: AcceptanceTarget,
    requires_positive_ack: bool,
}

struct AttemptResult {
    work: CompletedRelayWork,
    disposition: DeliveryDisposition,
}

fn take_scheduled_attempt_key<T>(
    scheduled: &mut BTreeMap<TaskId, RequestId>,
    result: &Result<(TaskId, T), JoinError>,
) -> Option<RequestId> {
    let task_id = match result {
        Ok((task_id, _)) => *task_id,
        Err(error) => error.id(),
    };
    scheduled.remove(&task_id)
}

fn reconcile_joined_attempt<T>(
    scheduled: &mut BTreeMap<TaskId, RequestId>,
    in_flight: &mut BTreeSet<RequestId>,
    result: &Result<(TaskId, T), JoinError>,
) -> Option<RequestId> {
    let scheduled_key = take_scheduled_attempt_key(scheduled, result);
    if result.is_err()
        && let Some(key) = scheduled_key
    {
        in_flight.remove(&key);
    }
    scheduled_key
}

#[cfg(test)]
async fn outbound_request_with_deadline<F, T>(
    timeout: Duration,
    request: F,
) -> Result<T, time::error::Elapsed>
where
    F: Future<Output = T>,
{
    time::timeout(timeout, request).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundOperationEnd {
    Shutdown,
    Deadline,
}

async fn outbound_operation_until<F, T>(
    deadline: Instant,
    shutdown: impl Future<Output = ()>,
    operation: F,
) -> Result<T, OutboundOperationEnd>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        () = shutdown => Err(OutboundOperationEnd::Shutdown),
        () = time::sleep_until(deadline) => Err(OutboundOperationEnd::Deadline),
        result = operation => Ok(result),
    }
}

/// One sync-only request admitted beneath both the shared and per-peer relay reservations.
///
/// Sync admission permits are acquired before the ordinary concurrency permits and every
/// acquisition is non-blocking. A history/deposit pull therefore never occupies an ordinary
/// global or peer slot while queued behind another sync request.
struct OutboundSyncAdmission {
    _global_sync: tokio::sync::OwnedSemaphorePermit,
    _peer_sync: tokio::sync::OwnedSemaphorePermit,
    _global: tokio::sync::OwnedSemaphorePermit,
    _peer: tokio::sync::OwnedSemaphorePermit,
}

fn try_acquire_outbound_sync_admission(
    global_sync: &Arc<Semaphore>,
    peer_sync: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
    peer: &Arc<Semaphore>,
) -> Option<OutboundSyncAdmission> {
    let global_sync = global_sync.clone().try_acquire_owned().ok()?;
    let peer_sync = peer_sync.clone().try_acquire_owned().ok()?;
    let global = global.clone().try_acquire_owned().ok()?;
    let peer = peer.clone().try_acquire_owned().ok()?;
    Some(OutboundSyncAdmission {
        _global_sync: global_sync,
        _peer_sync: peer_sync,
        _global: global,
        _peer: peer,
    })
}

/// FIFO sync-class admission under one absolute transport deadline.
///
/// Acquisitions use the same global-class, peer-class, global-ordinary, peer-ordinary order as
/// nonblocking sync admission. Partial reservations are owned by this future and therefore release
/// automatically on shutdown or deadline cancellation.
async fn acquire_outbound_sync_admission_until(
    global_sync: &Arc<Semaphore>,
    peer_sync: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
    peer: &Arc<Semaphore>,
    deadline: Instant,
    shutdown: impl Future<Output = ()>,
) -> Option<OutboundSyncAdmission> {
    if deadline <= Instant::now() {
        return None;
    }
    let deadline_elapsed = time::sleep_until(deadline);
    tokio::pin!(deadline_elapsed);
    tokio::pin!(shutdown);

    let global_sync = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        () = &mut deadline_elapsed => return None,
        permit = global_sync.clone().acquire_owned() => permit.ok()?,
    };
    let peer_sync = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        () = &mut deadline_elapsed => return None,
        permit = peer_sync.clone().acquire_owned() => permit.ok()?,
    };
    let global = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        () = &mut deadline_elapsed => return None,
        permit = global.clone().acquire_owned() => permit.ok()?,
    };
    let peer = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        () = &mut deadline_elapsed => return None,
        permit = peer.clone().acquire_owned() => permit.ok()?,
    };
    Some(OutboundSyncAdmission {
        _global_sync: global_sync,
        _peer_sync: peer_sync,
        _global: global,
        _peer: peer,
    })
}

/// FIFO reciprocal sync admission for an already-started state-transfer attempt.
///
/// The phase deadline gates queue entry only. Once queued, shutdown is the sole cancellation
/// source; expiring the shorter request deadline would surrender FIFO priority just before a
/// legally longer durable relay releases its bounded slot.
async fn acquire_outbound_sync_admission_for_transfer(
    global_sync: &Arc<Semaphore>,
    peer_sync: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
    peer: &Arc<Semaphore>,
    shutdown: impl Future<Output = ()>,
) -> Option<OutboundSyncAdmission> {
    tokio::pin!(shutdown);
    let global_sync = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        permit = global_sync.clone().acquire_owned() => permit.ok()?,
    };
    let peer_sync = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        permit = peer_sync.clone().acquire_owned() => permit.ok()?,
    };
    let global = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        permit = global.clone().acquire_owned() => permit.ok()?,
    };
    let peer = tokio::select! {
        biased;
        () = &mut shutdown => return None,
        permit = peer.clone().acquire_owned() => permit.ok()?,
    };
    Some(OutboundSyncAdmission {
        _global_sync: global_sync,
        _peer_sync: peer_sync,
        _global: global,
        _peer: peer,
    })
}

/// One durable relay admitted to the work-conserving ordinary stream budget.
///
/// State-transfer requests queue FIFO on these same semaphores after acquiring their sync-class
/// permits. Tokio assigns released permits to queued waiters before a polling relay can acquire
/// them with `try_acquire_owned`, so a second relay-only reservation would reduce narrow-peer
/// throughput without strengthening the transfer waiter.
struct OutboundRelayAdmission {
    _global: tokio::sync::OwnedSemaphorePermit,
    _peer: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundRelayAdmissionError {
    GlobalExhausted,
    PeerExhausted,
}

fn try_acquire_outbound_relay_admission(
    global: &Arc<Semaphore>,
    peer: &Arc<Semaphore>,
) -> Result<OutboundRelayAdmission, OutboundRelayAdmissionError> {
    let global = global
        .clone()
        .try_acquire_owned()
        .map_err(|_| OutboundRelayAdmissionError::GlobalExhausted)?;
    let peer =
        peer.clone().try_acquire_owned().map_err(|_| OutboundRelayAdmissionError::PeerExhausted)?;
    Ok(OutboundRelayAdmission { _global: global, _peer: peer })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutboundDepositMutationSlotError {
    Busy,
    Cancelled,
    UnknownRecipient,
    GenerationExhausted,
}

/// Match the receiver's one mutable pre-body slot for this authenticated sender.
///
/// The permit is acquired before any shared stream capacity and is held through response
/// completion. Dedicated immutable read/control routes bypass it.
fn try_acquire_outbound_deposit_mutation_slot(
    slots: &BTreeMap<PartyId, Arc<Semaphore>>,
    recipient: PartyId,
    operation: Option<DepositOperation>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, OutboundDepositMutationSlotError> {
    if !operation.is_some_and(deposit_operation_requires_mutation_admission) {
        return Ok(None);
    }
    let slot = slots.get(&recipient).ok_or(OutboundDepositMutationSlotError::UnknownRecipient)?;
    slot.clone().try_acquire_owned().map(Some).map_err(|_| OutboundDepositMutationSlotError::Busy)
}

async fn acquire_outbound_deposit_mutation_slot_until(
    slots: &BTreeMap<PartyId, Arc<Semaphore>>,
    recipient: PartyId,
    operation: DepositOperation,
    deadline: Instant,
    shutdown: impl Future<Output = ()>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, OutboundDepositMutationSlotError> {
    if !deposit_operation_requires_mutation_admission(operation) {
        return Ok(None);
    }
    let slot =
        slots.get(&recipient).ok_or(OutboundDepositMutationSlotError::UnknownRecipient)?.clone();
    if deadline <= Instant::now() {
        return Err(OutboundDepositMutationSlotError::Cancelled);
    }
    tokio::select! {
        biased;
        () = shutdown => Err(OutboundDepositMutationSlotError::Cancelled),
        () = time::sleep_until(deadline) => Err(OutboundDepositMutationSlotError::Cancelled),
        permit = slot.acquire_owned() => permit
            .map(Some)
            .map_err(|_| OutboundDepositMutationSlotError::Cancelled),
    }
}

/// Await the shared recipient slot for one sequential background state-transfer RPC.
///
/// Tokio's semaphore wait queue is FIFO, so once this bounded waiter is queued, a frequently
/// polling durable relay cannot steal the next released permit with `try_acquire_owned`. The phase
/// deadline gates entry into the queue but does not expire FIFO priority: a legal durable relay may
/// hold the slot longer than the shorter transport-request timeout. Runtime shutdown still cancels
/// the queue entry before transport dispatch.
async fn acquire_outbound_deposit_mutation_slot_for_transfer(
    slots: &BTreeMap<PartyId, Arc<Semaphore>>,
    recipient: PartyId,
    operation: DepositOperation,
    started_before: Instant,
    shutdown: impl Future<Output = ()>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, OutboundDepositMutationSlotError> {
    if !deposit_operation_requires_mutation_admission(operation) {
        return Ok(None);
    }
    if started_before <= Instant::now() {
        return Err(OutboundDepositMutationSlotError::Cancelled);
    }
    acquire_outbound_deposit_mutation_slot_after_transfer_start(
        slots, recipient, operation, shutdown,
    )
    .await
}

/// Await a recipient slot after an outer transfer deadline has already admitted this attempt.
///
/// The deadline is deliberately not rechecked here: an earlier bounded relay may legally retain
/// the slot beyond the transfer tick. Surrendering this FIFO waiter at that point would recreate
/// refill starvation.
async fn acquire_outbound_deposit_mutation_slot_after_transfer_start(
    slots: &BTreeMap<PartyId, Arc<Semaphore>>,
    recipient: PartyId,
    operation: DepositOperation,
    shutdown: impl Future<Output = ()>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, OutboundDepositMutationSlotError> {
    if !deposit_operation_requires_mutation_admission(operation) {
        return Ok(None);
    }
    let slot =
        slots.get(&recipient).ok_or(OutboundDepositMutationSlotError::UnknownRecipient)?.clone();
    tokio::select! {
        biased;
        () = shutdown => Err(OutboundDepositMutationSlotError::Cancelled),
        permit = slot.acquire_owned() => permit
            .map(Some)
            .map_err(|_| OutboundDepositMutationSlotError::Cancelled),
    }
}

struct LocalDepositMutationAdmission {
    _recipient: Option<tokio::sync::OwnedSemaphorePermit>,
    _endpoint: Option<tokio::sync::OwnedSemaphorePermit>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum StateTransferReservationScope {
    ExportRelease([u8; 32]),
    ExportHead([u8; 32]),
    ExportObjects([u8; 32]),
    ExportSeal(u64),
    StateImportAcknowledgement(u64),
    StateImportCertificate(u64),
}

/// Persistable subset of certified transfer scopes.
///
/// `ExportObjects` is an immutable recovery request. It receives state-transfer transport
/// priority, but never occupies a mutable recipient lane and therefore cannot be represented in
/// the durable in-doubt journal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum DurableStateTransferReservationScope {
    ExportRelease([u8; 32]),
    ExportHead([u8; 32]),
    ExportSeal(u64),
    StateImportAcknowledgement(u64),
    StateImportCertificate(u64),
}

impl DurableStateTransferReservationScope {
    const fn runtime(self) -> StateTransferReservationScope {
        match self {
            Self::ExportRelease(digest) => StateTransferReservationScope::ExportRelease(digest),
            Self::ExportHead(digest) => StateTransferReservationScope::ExportHead(digest),
            Self::ExportSeal(epoch) => StateTransferReservationScope::ExportSeal(epoch),
            Self::StateImportAcknowledgement(epoch) => {
                StateTransferReservationScope::StateImportAcknowledgement(epoch)
            }
            Self::StateImportCertificate(epoch) => {
                StateTransferReservationScope::StateImportCertificate(epoch)
            }
        }
    }
}

impl TryFrom<StateTransferReservationScope> for DurableStateTransferReservationScope {
    type Error = anyhow::Error;

    fn try_from(scope: StateTransferReservationScope) -> Result<Self, Self::Error> {
        Ok(match scope {
            StateTransferReservationScope::ExportRelease(digest) => Self::ExportRelease(digest),
            StateTransferReservationScope::ExportHead(digest) => Self::ExportHead(digest),
            StateTransferReservationScope::ExportSeal(epoch) => Self::ExportSeal(epoch),
            StateTransferReservationScope::StateImportAcknowledgement(epoch) => {
                Self::StateImportAcknowledgement(epoch)
            }
            StateTransferReservationScope::StateImportCertificate(epoch) => {
                Self::StateImportCertificate(epoch)
            }
            StateTransferReservationScope::ExportObjects(_) => {
                anyhow::bail!(
                    "immutable export-object work cannot create a durable transfer intent"
                )
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StateTransferReservationKey {
    recipient: PartyId,
    request_id: RequestId,
}

struct StateTransferRequestReservation {
    scope: StateTransferReservationScope,
    generation: u64,
    retry: RetryState,
}

fn state_transfer_reservation_is_absent_from_census(
    key: StateTransferReservationKey,
    reservation: &StateTransferRequestReservation,
    scope: StateTransferReservationScope,
    active: &BTreeSet<StateTransferReservationKey>,
    census_watermark: u64,
) -> bool {
    reservation.scope == scope
        && reservation.generation <= census_watermark
        && !active.contains(&key)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DurableStateTransferIntent {
    recipient: PartyId,
    request_id: [u8; 32],
    scope: DurableStateTransferReservationScope,
    created_generation: u64,
}

impl DurableStateTransferIntent {
    const fn key(self) -> StateTransferReservationKey {
        StateTransferReservationKey {
            recipient: self.recipient,
            request_id: RequestId::from_bytes(self.request_id),
        }
    }

    const fn runtime_scope(self) -> StateTransferReservationScope {
        self.scope.runtime()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DurableStateTransferIntentSnapshot {
    version: u16,
    network_id: [u8; 32],
    local_party: PartyId,
    high_water_generation: u64,
    entries: Vec<DurableStateTransferIntent>,
}

struct LoadedStateTransferIntentSnapshot {
    metadata: DepositStateTransferIntentsMetadata,
    high_water_generation: u64,
    entries: BTreeMap<PartyId, DurableStateTransferIntent>,
}

fn decode_state_transfer_intent_snapshot(
    bytes: &[u8],
    network_id: [u8; 32],
    local_party: PartyId,
    configured_parties: &BTreeSet<PartyId>,
) -> anyhow::Result<(u64, BTreeMap<PartyId, DurableStateTransferIntent>)> {
    let snapshot = decode_canonical_postcard::<DurableStateTransferIntentSnapshot>(bytes)?;
    anyhow::ensure!(
        snapshot.version == STATE_TRANSFER_INTENT_SNAPSHOT_VERSION
            && snapshot.network_id == network_id
            && snapshot.local_party == local_party,
        "durable state-transfer intents have the wrong current-format context"
    );
    anyhow::ensure!(
        configured_parties.contains(&local_party),
        "local party is absent from the configured transfer-intent roster"
    );
    anyhow::ensure!(
        snapshot.entries.len() <= configured_parties.len().saturating_sub(1),
        "durable state-transfer intents exceed the configured remote-party bound"
    );
    if snapshot.high_water_generation == 0 {
        anyhow::ensure!(
            snapshot.entries.is_empty(),
            "generation-zero state-transfer intents are nonempty"
        );
    }

    let mut entries = BTreeMap::new();
    let mut generations = BTreeSet::new();
    let mut previous_recipient = None;
    for entry in snapshot.entries {
        anyhow::ensure!(
            entry.recipient != local_party && configured_parties.contains(&entry.recipient),
            "durable state-transfer intent has an unconfigured or local recipient"
        );
        anyhow::ensure!(
            previous_recipient.is_none_or(|previous| previous < entry.recipient),
            "durable state-transfer intents are not strictly recipient-sorted"
        );
        anyhow::ensure!(
            entry.created_generation != 0
                && entry.created_generation <= snapshot.high_water_generation,
            "durable state-transfer intent has an invalid creation generation"
        );
        anyhow::ensure!(
            generations.insert(entry.created_generation),
            "durable state-transfer intents reuse a creation generation"
        );
        anyhow::ensure!(
            entry.request_id != [0_u8; 32],
            "durable state-transfer intent has a zero request identifier"
        );
        match entry.scope {
            DurableStateTransferReservationScope::ExportRelease(digest)
            | DurableStateTransferReservationScope::ExportHead(digest) => {
                anyhow::ensure!(
                    digest != [0_u8; 32],
                    "durable state-transfer intent has a zero context digest"
                );
            }
            DurableStateTransferReservationScope::ExportSeal(epoch)
            | DurableStateTransferReservationScope::StateImportAcknowledgement(epoch)
            | DurableStateTransferReservationScope::StateImportCertificate(epoch) => {
                anyhow::ensure!(epoch != 0, "durable state-transfer intent has epoch zero");
            }
        }
        previous_recipient = Some(entry.recipient);
        let replaced = entries.insert(entry.recipient, entry);
        anyhow::ensure!(
            replaced.is_none(),
            "durable state-transfer intent recipient is duplicated"
        );
    }
    Ok((snapshot.high_water_generation, entries))
}

fn encode_state_transfer_intent_snapshot(
    network_id: [u8; 32],
    local_party: PartyId,
    high_water_generation: u64,
    entries: &BTreeMap<PartyId, DurableStateTransferIntent>,
) -> anyhow::Result<Vec<u8>> {
    let snapshot = DurableStateTransferIntentSnapshot {
        version: STATE_TRANSFER_INTENT_SNAPSHOT_VERSION,
        network_id,
        local_party,
        high_water_generation,
        entries: entries.values().copied().collect(),
    };
    Ok(postcard::to_allocvec(&snapshot)?)
}

#[derive(Default)]
struct StateTransferReservations {
    exact: BTreeMap<StateTransferReservationKey, StateTransferRequestReservation>,
    /// One owned mutable-lane permit projects the nonempty exact-key set for each recipient.
    /// Durable relay scheduling observes this projection through the same recipient semaphore.
    recipients: BTreeMap<PartyId, tokio::sync::OwnedSemaphorePermit>,
}

impl StateTransferReservations {
    fn remove_exact(&mut self, key: StateTransferReservationKey) -> bool {
        let removed = self.exact.remove(&key).is_some();
        if removed && !self.exact.keys().any(|candidate| candidate.recipient == key.recipient) {
            self.recipients.remove(&key.recipient);
        }
        removed
    }

    fn record_failure(
        &mut self,
        key: StateTransferReservationKey,
        now: Instant,
        initial: Duration,
        maximum: Duration,
    ) -> Option<Duration> {
        self.exact
            .get_mut(&key)
            .map(|reservation| reservation.retry.failure(now, key.recipient, initial, maximum))
    }
}

/// Serializes exact retries for one recipient through the caller's durable receipt checkpoint.
///
/// The runtime-live recipient reservation itself lives in `StateTransferReservations`; dropping
/// this guard only allows another state-transfer attempt to inspect/reuse it.
struct StateTransferAttemptAdmission {
    _attempt: tokio::sync::OwnedSemaphorePermit,
    /// `true` when this dispatch is retrying an intent left in doubt by an earlier transport
    /// attempt. A response to this dispatch cannot by itself prove that earlier execution stopped.
    retries_in_doubt_intent: bool,
}

impl StateTransferAttemptAdmission {
    const fn is_fresh(&self) -> bool {
        !self.retries_in_doubt_intent
    }

    const fn may_retire_on_authenticated_rejection(
        &self,
        provenance: QuicResponseProvenance,
    ) -> bool {
        self.is_fresh() && matches!(provenance, QuicResponseProvenance::RejectedBeforeBody)
    }
}

struct DepositRpcResponse {
    response: PeerResponse,
    response_provenance: Option<QuicResponseProvenance>,
    reservation: Option<StateTransferReservationKey>,
    _state_transfer_attempt: Option<StateTransferAttemptAdmission>,
}

impl DepositRpcResponse {
    fn into_parts(
        self,
    ) -> (
        PeerResponse,
        Option<QuicResponseProvenance>,
        Option<StateTransferReservationKey>,
        Option<StateTransferAttemptAdmission>,
    ) {
        (self.response, self.response_provenance, self.reservation, self._state_transfer_attempt)
    }
}

/// Serialize one loopback deposit request with both outbound and inbound mutation boundaries.
///
/// `preacquired_recipient` is used only by durable self relay work whose scheduler already owns
/// the self recipient slot. State-transfer callers pass `None` and queue FIFO. Once admitted, the
/// caller must let the authoritative local reducer finish; cancellation applies only while
/// waiting for the two transport/runtime boundaries.
async fn acquire_local_deposit_mutation_admission(
    slots: &BTreeMap<PartyId, Arc<Semaphore>>,
    local_party: PartyId,
    endpoint: &Arc<Semaphore>,
    operation: DepositOperation,
    preacquired_recipient: Option<tokio::sync::OwnedSemaphorePermit>,
    started_before: Instant,
    expire_while_waiting: bool,
    recipient_shutdown: impl Future<Output = ()>,
    endpoint_shutdown: impl Future<Output = ()>,
) -> Result<LocalDepositMutationAdmission, OutboundDepositMutationSlotError> {
    if started_before <= Instant::now() {
        return Err(OutboundDepositMutationSlotError::Cancelled);
    }
    if !deposit_operation_requires_mutation_admission(operation) {
        debug_assert!(preacquired_recipient.is_none());
        return Ok(LocalDepositMutationAdmission { _recipient: None, _endpoint: None });
    }
    let recipient = match preacquired_recipient {
        Some(permit) => Some(permit),
        None if expire_while_waiting => {
            acquire_outbound_deposit_mutation_slot_until(
                slots,
                local_party,
                operation,
                started_before,
                recipient_shutdown,
            )
            .await?
        }
        None => {
            acquire_outbound_deposit_mutation_slot_for_transfer(
                slots,
                local_party,
                operation,
                started_before,
                recipient_shutdown,
            )
            .await?
        }
    };
    let endpoint = if expire_while_waiting {
        acquire_deposit_mutation_execution_permit(endpoint, async {
            tokio::select! {
                biased;
                () = endpoint_shutdown => {}
                () = time::sleep_until(started_before) => {}
            }
        })
        .await
    } else {
        acquire_deposit_mutation_execution_permit(endpoint, endpoint_shutdown).await
    }
    .ok_or(OutboundDepositMutationSlotError::Cancelled)?;
    Ok(LocalDepositMutationAdmission { _recipient: recipient, _endpoint: Some(endpoint) })
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

/// The two independently causal relay classes which share the global outbound request budget.
///
/// Work within each class retains its existing ordering fence. This cursor only decides which
/// class receives the next free global permit, preventing an always-populated direct/deposit
/// outbox from consuming every permit before epoch-transition work is considered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayLane {
    Direct,
    Transition,
}

impl RelayLane {
    const fn other(self) -> Self {
        match self {
            Self::Direct => Self::Transition,
            Self::Transition => Self::Direct,
        }
    }
}

#[derive(Debug)]
struct RelayLaneCursor {
    preferred: RelayLane,
}

impl Default for RelayLaneCursor {
    fn default() -> Self {
        // Give epoch progress the first permit after startup. A successful transition admission
        // immediately hands the next turn to direct/deposit work.
        Self { preferred: RelayLane::Transition }
    }
}

impl RelayLaneCursor {
    const fn scheduling_order(&self) -> [RelayLane; 2] {
        [self.preferred, self.preferred.other()]
    }

    fn record_scheduled(&mut self, lane: RelayLane) {
        self.preferred = lane.other();
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DirectSemanticLane {
    ActivationAck,
    Deposit,
}

type ActivationAckOrder = (u64, u64);

#[derive(Default)]
struct DirectRecipientWork {
    activation_acks: BTreeMap<ActivationAckOrder, BTreeMap<PeerMessageId, RelayWork>>,
    deposits: BTreeMap<DepositCausalLane, RelayWork>,
}

/// Stable two-level direct-work successor state.
///
/// Recipients rotate by stable party identifier rather than an offset into a changing vector.
/// Within each recipient, successful admissions alternate semantic activation/deposit classes.
/// Activation work has its own epoch/acknowledgement-sequence successor and deposit work retains
/// its existing causal-lane successor. Backed-off candidates never advance any cursor.
#[derive(Debug, Default)]
struct DirectWorkCursor {
    recipient: Option<PartyId>,
    semantic_lane: BTreeMap<PartyId, DirectSemanticLane>,
    activation_ack: BTreeMap<PartyId, ActivationAckOrder>,
    activation_ack_exact: BTreeMap<PartyId, (ActivationAckOrder, PeerMessageId)>,
}

impl DirectWorkCursor {
    fn semantic_order(&self, recipient: PartyId) -> [DirectSemanticLane; 2] {
        match self.semantic_lane.get(&recipient) {
            Some(DirectSemanticLane::ActivationAck) => {
                [DirectSemanticLane::Deposit, DirectSemanticLane::ActivationAck]
            }
            Some(DirectSemanticLane::Deposit) | None => {
                [DirectSemanticLane::ActivationAck, DirectSemanticLane::Deposit]
            }
        }
    }

    fn record_scheduled(&mut self, recipient: PartyId, lane: DirectSemanticLane) {
        self.recipient = Some(recipient);
        self.semantic_lane.insert(recipient, lane);
    }
}

enum RelayLaneOutcome {
    /// One item from this lane acquired a global permit.
    Scheduled,
    /// Every currently enumerated item in this lane was absent or transiently ineligible.
    Exhausted,
    /// No global permit was available. The lane cursor must remain unchanged so this lane keeps
    /// first claim on the next permit released by an earlier request.
    GlobalPermitExhausted,
}

enum DeliveryDisposition {
    Accepted,
    /// The authenticated receiver has said this exact immutable effect can never be applied. It
    /// is safe to retire the durable item; retaining it only creates a permanent retry storm.
    TerminalRejection(String),
    Deferred(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositSyncSourceOutcome {
    UnavailableOrStale,
    PendingSupport,
    Progressed,
    Settled,
    Adopted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertifiedDepositTransferDisposition {
    /// No durable certified-transfer work exists, so ordinary moving-tip sync may run.
    Idle,
    /// At least one exact durable item remains or transport work exhausted this tick.
    Pending,
    /// A wallet/registry authority phase changed; reconstruct it on the next tick.
    Reload,
}

/// The wallet's exact source-export marker, not a remote fanout receipt, is the local causal
/// boundary. Before it clears, every seal-lane retry may contribute to the freeze. Afterwards,
/// already journaled votes and certificates remain durable background work: requiring every
/// remote source to acknowledge a vote would turn target import into an all-parties barrier.
const fn export_seal_work_is_causal(
    local_freeze_pending: bool,
    kind: DepositStateExportSealWorkKind,
) -> bool {
    local_freeze_pending || matches!(kind, DepositStateExportSealWorkKind::SourceRequest)
}

// A concurrent durable vote/receipt may retire a locator after its census. Leave transport
// reservations for the next authenticated census; this is not an acknowledgement of its reply.
fn completed_export_work(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<DepositServiceError>(),
        Some(DepositServiceError::StateExportWorkAlreadyComplete)
    )
}

fn export_seal_phase_blocks_target_import(
    local_freeze_pending: bool,
    kinds: impl IntoIterator<Item = DepositStateExportSealWorkKind>,
) -> bool {
    local_freeze_pending || kinds.into_iter().any(|kind| export_seal_work_is_causal(false, kind))
}

/// Target acknowledgements may still form the local `n-f` availability certificate. Once the
/// journal exposes only certificate deliveries, finalization is already durable and fanout cannot
/// delay ordinary synchronization.
const fn state_import_work_is_causal(kind: DepositStateImportWorkKind) -> bool {
    matches!(kind, DepositStateImportWorkKind::AcknowledgementDelivery)
}

fn state_import_phase_blocks_ordinary_sync(
    kinds: impl IntoIterator<Item = DepositStateImportWorkKind>,
) -> bool {
    kinds.into_iter().any(state_import_work_is_causal)
}

fn state_import_work_needs_reload(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<DepositServiceError>(),
        Some(
            DepositServiceError::InvalidProtocolState
                | DepositServiceError::StorageRevisionMismatch
                | DepositServiceError::StateImportStore(
                    DepositStateImportStoreError::WorkAlreadyComplete
                )
        )
    )
}

// Only durable completion proves a census locator absent; generic reload errors do not.
fn completed_state_import_work(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<DepositServiceError>(),
        Some(DepositServiceError::StateImportStore(
            DepositStateImportStoreError::WorkAlreadyComplete
        ))
    )
}

fn deposit_state_transfer_background_budget(
    interval: Duration,
    request_timeout: Duration,
) -> Option<Duration> {
    let stagger_budget = interval / 4;
    (!stagger_budget.is_zero()).then_some(stagger_budget.min(request_timeout))
}

fn deposit_state_transfer_background_start(cursor: &AtomicUsize, work_len: usize) -> usize {
    debug_assert_ne!(work_len, 0);
    cursor.fetch_add(1, Ordering::Relaxed) % work_len
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositStateTransferBackgroundLane {
    ExportSealFanout,
    ImportedCertificate,
}

impl DepositStateTransferBackgroundLane {
    const fn other(self) -> Self {
        match self {
            Self::ExportSealFanout => Self::ImportedCertificate,
            Self::ImportedCertificate => Self::ExportSealFanout,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositStateTransferBackgroundScope {
    Current,
    Historical,
}

impl DepositStateTransferBackgroundScope {
    const fn other(self) -> Self {
        match self {
            Self::Current => Self::Historical,
            Self::Historical => Self::Current,
        }
    }
}

fn deposit_state_transfer_background_scope_order(
    cursor: &AtomicUsize,
) -> [DepositStateTransferBackgroundScope; 2] {
    let preferred = if cursor.fetch_add(1, Ordering::Relaxed) % 2 == 0 {
        DepositStateTransferBackgroundScope::Current
    } else {
        DepositStateTransferBackgroundScope::Historical
    };
    [preferred, preferred.other()]
}

/// Select one retained state-import target, newest first, without scanning the history prefix.
fn rotating_historical_state_import_epoch(active_epoch: u64, cursor: u64) -> Option<u64> {
    let historical_epochs = active_epoch.checked_sub(1)?;
    (historical_epochs != 0).then(|| historical_epochs - cursor % historical_epochs)
}

/// Stable descending successor for ready in-doubt historical epochs.
///
/// The cursor stores an epoch identity, not an offset into a changing set, so one Byzantine epoch
/// entering/leaving backoff cannot reinterpret every later epoch's turn.
fn historical_reserved_epoch_after(candidates: &BTreeSet<u64>, last: u64) -> Option<u64> {
    if last != 0
        && let Some(epoch) = candidates.range(..last).next_back()
    {
        return Some(*epoch);
    }
    candidates.last().copied()
}

/// Advances the historical epoch probe on every exit unless an exact receipt was committed.
///
/// Holding this guard across the selected epoch's async work also covers propagated errors and
/// task cancellation, so a corrupt or unavailable retained epoch cannot monopolize future ticks.
struct HistoricalStateImportEpochProbe<'a> {
    cursor: &'a AtomicU64,
    advance_on_drop: bool,
}

impl<'a> HistoricalStateImportEpochProbe<'a> {
    fn new(cursor: &'a AtomicU64) -> Self {
        Self { cursor, advance_on_drop: true }
    }

    fn receipt_committed(mut self) {
        self.advance_on_drop = false;
    }
}

impl Drop for HistoricalStateImportEpochProbe<'_> {
    fn drop(&mut self) {
        if self.advance_on_drop {
            self.cursor.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CertifiedDepositSourcePosition {
    Installing { request: [u8; 32] },
    Active { revision: u64, checkpoint: [u8; 32] },
}

#[derive(Clone, Copy, Debug)]
struct CertifiedDepositSourceProgress {
    context: DepositStateTransferContext,
    source: PartyId,
    position: CertifiedDepositSourcePosition,
    last_progress: Instant,
}

#[derive(Debug)]
enum DepositPrefixSupportFetchOutcome {
    Complete(DepositSyncSupportRequest),
    /// The shared tick deadline or bounded work budget was reached. Keep the exact stage attempt.
    BudgetExhausted,
    /// The sole pinned serving source was unavailable or returned a retryable rejection.
    SourceUnavailable,
}

#[derive(Debug)]
enum DepositPrefixSupportPageFetchOutcome {
    Complete(DepositSyncObjectPage),
    BudgetExhausted,
    SourceUnavailable,
}

#[derive(Debug, Error)]
enum DepositPrefixSupportFetchError {
    #[error("pinned prefix-support source returned invalid authenticated data: {message}")]
    InvalidSource { rejection: DepositSyncVariantRejection, message: String },
    #[error("local prefix-support processing failed: {0}")]
    Local(String),
}

impl DepositPrefixSupportFetchError {
    fn cryptographic(error: impl std::fmt::Display) -> Self {
        Self::InvalidSource {
            rejection: DepositSyncVariantRejection::CryptographicInvalid,
            message: error.to_string(),
        }
    }

    fn semantic(error: impl std::fmt::Display) -> Self {
        Self::InvalidSource {
            rejection: DepositSyncVariantRejection::SemanticInvalid,
            message: error.to_string(),
        }
    }

    fn local(error: impl std::fmt::Display) -> Self {
        Self::Local(error.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositSyncAdmissionAuthority {
    ExactClaims,
    StablePrefix,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DepositSyncTickWork {
    requests: usize,
    pages: usize,
    objects: usize,
    wire_bytes: usize,
}

impl DepositSyncTickWork {
    fn may_request(self, request_wire_bytes: usize) -> bool {
        self.requests < MAX_DEPOSIT_SYNC_REQUESTS_PER_TICK
            && self.pages < MAX_DEPOSIT_SYNC_PAGES_PER_TICK
            && self.objects < MAX_DEPOSIT_SYNC_OBJECTS_PER_TICK
            && request_wire_bytes <= MAX_DEPOSIT_SYNC_WIRE_BYTES_PER_TICK
            && self.wire_bytes
                <= MAX_DEPOSIT_SYNC_WIRE_BYTES_PER_TICK
                    .saturating_sub(request_wire_bytes)
                    .saturating_sub(MAX_DEPOSIT_SYNC_WIRE_BYTES)
    }

    fn may_request_objects(self, request_wire_bytes: usize, object_count: usize) -> bool {
        object_count != 0
            && object_count <= MAX_DEPOSIT_SYNC_OBJECTS_PER_TICK.saturating_sub(self.objects)
            && self.may_request(request_wire_bytes)
    }

    fn record_request(&mut self, wire_bytes: usize) -> anyhow::Result<()> {
        self.requests =
            self.requests.checked_add(1).context("deposit sync request budget exhausted")?;
        self.record_wire_bytes(wire_bytes)?;
        Ok(())
    }

    fn record_page(
        &mut self,
        page: &DepositSyncObjectPage,
        wire_bytes: usize,
    ) -> anyhow::Result<()> {
        self.record_object_page(page.objects().len(), wire_bytes)
    }

    fn record_object_page(&mut self, object_count: usize, wire_bytes: usize) -> anyhow::Result<()> {
        self.pages = self.pages.checked_add(1).context("deposit sync page budget exhausted")?;
        self.objects = self
            .objects
            .checked_add(object_count)
            .context("deposit sync object budget exhausted")?;
        anyhow::ensure!(
            self.pages <= MAX_DEPOSIT_SYNC_PAGES_PER_TICK
                && self.objects <= MAX_DEPOSIT_SYNC_OBJECTS_PER_TICK,
            "deposit sync peer exceeded the per-tick page or object budget"
        );
        self.record_wire_bytes(wire_bytes)?;
        Ok(())
    }

    fn record_wire_bytes(&mut self, wire_bytes: usize) -> anyhow::Result<()> {
        self.wire_bytes = self
            .wire_bytes
            .checked_add(wire_bytes)
            .context("deposit sync byte budget exhausted")?;
        anyhow::ensure!(
            self.wire_bytes <= MAX_DEPOSIT_SYNC_WIRE_BYTES_PER_TICK,
            "deposit sync peer exceeded the per-tick wire-byte budget"
        );
        Ok(())
    }

    const fn progressed(self) -> bool {
        self.pages != 0
    }
}

/// Pause the network-work clock across one finite authenticated local preflight.
///
/// Callers must not span transport waits or peer-controlled response validation with this timer:
/// adding only known-local elapsed time preserves every previously consumed portion of the tick.
fn shift_deposit_sync_deadline_past_local_work(
    tick_deadline: Instant,
    local_work_started: Instant,
    local_work_finished: Instant,
) -> Option<Instant> {
    tick_deadline.checked_add(local_work_finished.saturating_duration_since(local_work_started))
}

fn bounded_deposit_rpc_deadline(
    source_deadline: Instant,
    request_timeout: Duration,
    now: Instant,
) -> Option<Instant> {
    if now >= source_deadline {
        return None;
    }
    Some(
        now.checked_add(request_timeout)
            .map_or(source_deadline, |deadline| deadline.min(source_deadline)),
    )
}

const DEPOSIT_SYNC_FRONTIER_VERSION: u16 = 3;

/// Durable, source-bound depth-first work frontier.
///
/// Entries are stored in reverse traversal order so the vector's tail is the next work. A request
/// removes a bounded tail prefix and the authenticated children returned for that batch are pushed
/// in reverse deterministic order. This retains depth-first memory behavior while allowing the
/// wire's complete 64-object page width; a breadth-first queue could otherwise make a large HAMT
/// exceed the durable cursor bound despite every individual path being shallow.
///
/// Every retained non-root entry contains the exact source-issued parent/child capability. Typed
/// traversal targets are monotonic in depth, epoch, or archive ordinal, so removing completed
/// entries does not require an unbounded visited set to exclude cycles. Targets concurrently
/// completed or already pending are deduplicated before the successor cursor is committed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct DepositSyncFrontier {
    version: u16,
    lease: DepositSyncAnchorLease,
    pending: Vec<DepositSyncObjectRequestEntry>,
    complete: bool,
}

impl DepositSyncFrontier {
    fn fresh(lease: DepositSyncAnchorLease) -> anyhow::Result<Self> {
        let roots = lease.root_targets()?;
        anyhow::ensure!(!roots.is_empty(), "deposit sync advertisement has no object roots");
        let pending = roots
            .into_iter()
            .rev()
            .map(|root| DepositSyncObjectRequestEntry::advertised_root(lease, root))
            .collect::<Result<Vec<_>, _>>()?;
        let frontier =
            Self { version: DEPOSIT_SYNC_FRONTIER_VERSION, lease, pending, complete: false };
        frontier.validate_shape()?;
        frontier.to_bytes()?;
        Ok(frontier)
    }

    fn from_checkpoint(lease: DepositSyncAnchorLease, bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.is_empty() {
            return Self::fresh(lease);
        }
        anyhow::ensure!(
            bytes.len() <= crate::deposit_sync_stage::MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit sync traversal frontier exceeds its durable bound"
        );
        let (frontier, trailing) = postcard::take_from_bytes::<Self>(bytes)?;
        anyhow::ensure!(
            trailing.is_empty()
                && postcard::to_allocvec(&frontier)?.as_slice() == bytes
                && frontier.version == DEPOSIT_SYNC_FRONTIER_VERSION
                && frontier.lease == lease,
            "deposit sync frontier is non-canonical or bound to another lease"
        );
        frontier.validate_shape()?;
        Ok(frontier)
    }

    fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == DEPOSIT_SYNC_FRONTIER_VERSION
                && self.complete == self.pending.is_empty(),
            "deposit sync frontier has an inconsistent completion marker"
        );
        let mut targets = BTreeSet::new();
        for entry in &self.pending {
            DepositSyncObjectPageRequest::new(self.lease, vec![*entry])?;
            anyhow::ensure!(
                targets.insert(entry.target()),
                "deposit sync frontier contains duplicate pending work"
            );
        }
        Ok(())
    }

    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_shape()?;
        let bytes = postcard::to_allocvec(self)?;
        anyhow::ensure!(
            bytes.len() <= crate::deposit_sync_stage::MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit sync traversal frontier exceeds its durable bound"
        );
        Ok(bytes)
    }

    fn request(&self) -> anyhow::Result<Option<DepositSyncObjectPageRequest>> {
        if self.complete {
            return Ok(None);
        }
        self.validate_shape()?;
        let mut entries =
            Vec::with_capacity(self.pending.len().min(MAX_DEPOSIT_SYNC_REQUEST_OBJECTS));
        let mut references = BTreeSet::new();
        let mut request = None;
        for entry in self.pending.iter().rev().take(MAX_DEPOSIT_SYNC_REQUEST_OBJECTS).copied() {
            // The durable spool keys objects by reference and rejects duplicate references in one
            // atomic merge even when two semantic positions differ. Preserve traversal order and
            // leave the second position for the next request.
            if !references.insert(entry.reference()) {
                break;
            }
            let mut candidate = entries.clone();
            candidate.push(entry);
            match DepositSyncObjectPageRequest::new(self.lease, candidate) {
                Ok(candidate_request) if candidate_request.to_bytes().is_ok() => {
                    entries.push(entry);
                    request = Some(candidate_request);
                }
                Ok(_) | Err(_) if request.is_some() => break,
                Ok(_) => {
                    anyhow::bail!("deposit sync frontier entry exceeds the wire request bound")
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Some(request.context("incomplete deposit sync frontier omitted its current work")?))
    }

    fn apply_page(&mut self, page: &DepositSyncObjectPage) -> anyhow::Result<()> {
        let request =
            self.request()?.context("deposit sync frontier omitted its current request")?;
        page.validate_for(&request)?;
        let request_entries = request.entries();
        anyhow::ensure!(
            request_entries.len() <= self.pending.len()
                && self.pending.iter().rev().take(request_entries.len()).eq(request_entries.iter()),
            "deposit sync page differs from the durable traversal frontier"
        );

        let remaining = self.pending.len() - request_entries.len();
        let mut retained_targets = self.pending[..remaining]
            .iter()
            .map(|entry| entry.target())
            .chain(request_entries.iter().map(|entry| entry.target()))
            .collect::<BTreeSet<_>>();
        let mut child_entries = Vec::new();
        for (entry, object) in request_entries.iter().zip(page.objects()) {
            anyhow::ensure!(
                object.reference() == entry.reference(),
                "deposit sync page differs from its traversal entry"
            );
            let mut children = object.authenticated_semantic_children(entry.target())?;
            // Segment predecessors form the lifetime-length chain. Visit all bounded event
            // siblings first, then tail-call the predecessor so archive depth stays bounded.
            if matches!(children.first(), Some(DepositSyncTraversalTarget::ArchiveSegment { .. })) {
                children.rotate_left(1);
            }
            for child in children {
                let mut matching = page.capabilities().iter().copied().filter(|capability| {
                    capability.parent() == entry.target() && capability.child() == child
                });
                let capability = matching
                    .next()
                    .context("deposit sync page omitted a required child capability")?;
                anyhow::ensure!(
                    matching.next().is_none(),
                    "deposit sync page duplicated a child capability"
                );
                if retained_targets.insert(child) {
                    child_entries.push(DepositSyncObjectRequestEntry::authorized(capability));
                }
            }
        }
        anyhow::ensure!(
            child_entries.len() <= MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES,
            "deposit sync object exceeds the bounded continuation width"
        );
        let mut successor = self.clone();
        successor.pending.truncate(remaining);
        successor.pending.extend(child_entries.into_iter().rev());
        successor.complete = successor.pending.is_empty();
        // Validate the complete successor before changing the live cursor. The caller then commits
        // this cursor and every object in the page in one durable spool transaction.
        successor.to_bytes()?;
        *self = successor;
        Ok(())
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
    outbound_sync_permits: Arc<Semaphore>,
    outbound_deposit_mutation_slots: BTreeMap<PartyId, Arc<Semaphore>>,
    state_transfer_attempt_slots: BTreeMap<PartyId, Arc<Semaphore>>,
    state_transfer_reservations: Mutex<StateTransferReservations>,
    state_transfer_intent_snapshot: Mutex<Option<LoadedStateTransferIntentSnapshot>>,
    state_transfer_reservation_generation: AtomicU64,
    state_transfer_intents_loaded: AtomicBool,
    mutable_deposit_relay_ready: AtomicBool,
    inbound_request_permits: Arc<Semaphore>,
    inbound_body_permits: Arc<Semaphore>,
    deposit_mutation_permits: Arc<Semaphore>,
    deposit_sync_objects_permits: Arc<Semaphore>,
    deposit_prefix_support_permits: Arc<Semaphore>,
    deposit_sync_control_permits: Arc<Semaphore>,
    inbound_peers: BTreeMap<PartyId, Arc<InboundPeerState>>,
    work_retries: Mutex<BTreeMap<RequestId, RetryState>>,
    epoch_history_retries: Mutex<BTreeMap<PartyId, RetryState>>,
    certified_deposit_source_progress: Mutex<Option<CertifiedDepositSourceProgress>>,
    epoch_history_source_cursor: AtomicUsize,
    deposit_sync_source_cursor: AtomicUsize,
    deposit_sync_release_cursor: AtomicUsize,
    deposit_state_transfer_cursor: AtomicUsize,
    deposit_state_transfer_background_scope_cursor: AtomicUsize,
    deposit_state_transfer_background_lane_cursor: AtomicUsize,
    deposit_state_transfer_background_export_cursor: AtomicUsize,
    deposit_state_transfer_background_import_cursor: AtomicUsize,
    historical_state_import_epoch_cursor: AtomicU64,
    historical_state_import_reserved_epoch_cursor: AtomicU64,
    historical_state_import_work_cursor: AtomicUsize,
    deposit_prefix_collection_cursor: AtomicUsize,
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
        validate_scenario_outbox_batch_size(
            config.outbox_batch_size,
            server.scenario().parties.len(),
        )?;
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
        let outbound_deposit_mutation_slots = server
            .scenario()
            .parties
            .iter()
            .map(|party| (party.id, Arc::new(Semaphore::new(1))))
            .collect::<BTreeMap<_, _>>();
        let state_transfer_attempt_slots = server
            .scenario()
            .parties
            .iter()
            .map(|party| (party.id, Arc::new(Semaphore::new(1))))
            .collect();
        let inbound_peers = peers
            .keys()
            .copied()
            .map(|party| {
                (party, Arc::new(InboundPeerState::new(config.max_inbound_requests_per_peer)))
            })
            .collect::<BTreeMap<_, _>>();
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
            outbound_sync_permits: Arc::new(Semaphore::new(
                sync_request_capacity(config.max_outbound_requests)
                    .expect("validated outbound width reserves one relay permit"),
            )),
            outbound_deposit_mutation_slots,
            state_transfer_attempt_slots,
            state_transfer_reservations: Mutex::new(StateTransferReservations::default()),
            state_transfer_intent_snapshot: Mutex::new(None),
            state_transfer_reservation_generation: AtomicU64::new(0),
            state_transfer_intents_loaded: AtomicBool::new(false),
            mutable_deposit_relay_ready: AtomicBool::new(false),
            inbound_request_permits: Arc::new(Semaphore::new(config.max_inbound_requests)),
            inbound_body_permits: Arc::new(Semaphore::new(MAX_INBOUND_BODY_BYTES)),
            deposit_mutation_permits: Arc::new(Semaphore::new(
                MAX_CONCURRENT_MUTATING_DEPOSIT_REQUESTS,
            )),
            deposit_sync_objects_permits: Arc::new(Semaphore::new(
                MAX_CONCURRENT_DEPOSIT_SYNC_OBJECT_REQUESTS,
            )),
            deposit_prefix_support_permits: Arc::new(Semaphore::new(
                MAX_CONCURRENT_DEPOSIT_PREFIX_SUPPORT_SCANS,
            )),
            deposit_sync_control_permits: Arc::new(Semaphore::new(
                MAX_CONCURRENT_DEPOSIT_SYNC_CONTROL_REQUESTS,
            )),
            inbound_peers,
            work_retries: Mutex::new(BTreeMap::new()),
            epoch_history_retries: Mutex::new(epoch_history_retries),
            certified_deposit_source_progress: Mutex::new(None),
            epoch_history_source_cursor: AtomicUsize::new(0),
            deposit_sync_source_cursor: AtomicUsize::new(0),
            deposit_sync_release_cursor: AtomicUsize::new(0),
            deposit_state_transfer_cursor: AtomicUsize::new(0),
            deposit_state_transfer_background_scope_cursor: AtomicUsize::new(0),
            deposit_state_transfer_background_lane_cursor: AtomicUsize::new(0),
            deposit_state_transfer_background_export_cursor: AtomicUsize::new(0),
            deposit_state_transfer_background_import_cursor: AtomicUsize::new(0),
            historical_state_import_epoch_cursor: AtomicU64::new(0),
            historical_state_import_reserved_epoch_cursor: AtomicU64::new(0),
            historical_state_import_work_cursor: AtomicUsize::new(0),
            deposit_prefix_collection_cursor: AtomicUsize::new(0),
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
        let state_transfer_intents = Box::pin(self.clone().state_transfer_intent_restore_loop());
        let deposit_sync = Box::pin(self.clone().deposit_sync_loop());
        let historical_state_import = Box::pin(self.clone().historical_deposit_state_import_loop());
        let deposit_retention_gc = Box::pin(self.clone().deposit_retention_gc_loop());
        let deposit_scanner = Box::pin(self.clone().deposit_scanner_loop());
        let deposit_consolidation = Box::pin(self.clone().deposit_consolidation_loop());
        let deposit_publication = Box::pin(self.clone().deposit_publication_loop());
        let deposit_pacemakers = Box::pin(run_deposit_pacemakers(
            deposit_sync,
            historical_state_import,
            deposit_retention_gc,
            deposit_scanner,
            deposit_consolidation,
            deposit_publication,
        ));
        tokio::join!(
            accept,
            relay,
            protocol_progress,
            epoch_history_sync,
            deposit_allocation,
            state_transfer_intents,
            deposit_pacemakers
        );
        if time::timeout(self.config.transport_shutdown_grace, self.endpoint.wait_idle())
            .await
            .is_err()
        {
            tracing::warn!(
                party = %self.server.party_id(),
                grace_millis = self.config.transport_shutdown_grace.as_millis(),
                "QUIC endpoint exceeded its transport-only shutdown grace"
            );
        }
        Ok(())
    }

    async fn state_transfer_intent_restore_loop(self: Arc<Self>) {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return;
            }
            match self.restore_state_transfer_intents().await {
                Ok(()) => {
                    self.wait_for_shutdown().await;
                    return;
                }
                Err(error) => {
                    self.state_transfer_intents_loaded.store(false, Ordering::Release);
                    self.mutable_deposit_relay_ready.store(false, Ordering::Release);
                    tracing::error!(
                        party = %self.server.party_id(),
                        %error,
                        "durable state-transfer intents are unavailable; mutable deposit relays remain fenced"
                    );
                    tokio::select! {
                        biased;
                        () = self.wait_for_shutdown() => return,
                        () = time::sleep(self.config.retry_initial) => {}
                    }
                }
            }
        }
    }

    async fn restore_state_transfer_intents(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.state_transfer_intents_loaded.load(Ordering::Acquire),
            "state-transfer intents were already restored"
        );
        let local_party = self.server.party_id();
        let configured_parties =
            self.server.scenario().parties.iter().map(|party| party.id).collect::<BTreeSet<_>>();
        let durable = match self.server.load_deposit_state_transfer_intents().await? {
            Some(durable) => durable,
            None => {
                let empty = encode_state_transfer_intent_snapshot(
                    self.network_id,
                    local_party,
                    0,
                    &BTreeMap::new(),
                )?;
                let metadata =
                    self.server.save_deposit_state_transfer_intents(None, &empty).await?;
                let durable = self
                    .server
                    .load_deposit_state_transfer_intents()
                    .await?
                    .context("new state-transfer intent snapshot disappeared after readback")?;
                anyhow::ensure!(
                    durable.metadata == metadata && durable.state.as_bytes() == empty.as_slice(),
                    "new state-transfer intent snapshot differs after authenticated readback"
                );
                durable
            }
        };
        anyhow::ensure!(
            durable.metadata.network_id == self.network_id,
            "state-transfer intent storage returned another network"
        );
        let (high_water_generation, entries) = decode_state_transfer_intent_snapshot(
            durable.state.as_bytes(),
            self.network_id,
            local_party,
            &configured_parties,
        )?;

        let mut recipient_permits = BTreeMap::new();
        let mut exact = BTreeMap::new();
        let now = Instant::now();
        for entry in entries.values().copied() {
            let slot = self
                .outbound_deposit_mutation_slots
                .get(&entry.recipient)
                .context("durable state-transfer intent has no recipient lane")?;
            let permit = slot
                .clone()
                .try_acquire_owned()
                .context("durable state-transfer recipient lane was occupied before restore")?;
            let previous = recipient_permits.insert(entry.recipient, permit);
            anyhow::ensure!(previous.is_none(), "durable state-transfer recipient was duplicated");
            let previous = exact.insert(
                entry.key(),
                StateTransferRequestReservation {
                    scope: entry.runtime_scope(),
                    generation: entry.created_generation,
                    retry: RetryState::new(now),
                },
            );
            anyhow::ensure!(previous.is_none(), "durable state-transfer request was duplicated");
        }

        let mut reservations = self.state_transfer_reservations.lock().await;
        anyhow::ensure!(
            reservations.exact.is_empty() && reservations.recipients.is_empty(),
            "state-transfer work started before durable intent restore"
        );
        reservations.exact = exact;
        reservations.recipients = recipient_permits;
        drop(reservations);
        let mut snapshot = self.state_transfer_intent_snapshot.lock().await;
        anyhow::ensure!(snapshot.is_none(), "state-transfer intent snapshot was already published");
        *snapshot = Some(LoadedStateTransferIntentSnapshot {
            metadata: durable.metadata,
            high_water_generation,
            entries,
        });
        self.state_transfer_reservation_generation.store(high_water_generation, Ordering::Release);
        self.state_transfer_intents_loaded.store(true, Ordering::Release);
        if high_water_generation != u64::MAX {
            self.mutable_deposit_relay_ready.store(true, Ordering::Release);
        }
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
        // Handshake tasks have not dispatched an authoritative reducer and therefore carry no
        // durable work which shutdown must preserve. In particular, an `endpoint.close()` wakes
        // every pending accept with `EndpointClosed`; those tasks would otherwise enter the
        // configured invalid-handshake backoff before this natural drain, delaying shutdown by as
        // much as an hour.
        handshakes.abort_all();
        while let Some(result) = handshakes.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
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
                            let runtime = self.clone();
                            let server = self.server.clone();
                            let request_cache = request_cache.clone();
                            let inbound_peer = inbound_peer.clone();
                            let global_permits = self.inbound_request_permits.clone();
                            let global_body_permits = self.inbound_body_permits.clone();
                            let deposit_mutation_permits =
                                self.deposit_mutation_permits.clone();
                            let deposit_sync_objects_permits =
                                self.deposit_sync_objects_permits.clone();
                            let deposit_prefix_support_permits =
                                self.deposit_prefix_support_permits.clone();
                            let deposit_sync_control_permits =
                                self.deposit_sync_control_permits.clone();
                            let config = self.config;
                            requests.spawn(async move {
                                let request_id = incoming.request_id();
                                let body_len = incoming.body_len();
                                let is_deposit_sync_objects =
                                    incoming.is_deposit_sync_objects();
                                let is_deposit_object_read = incoming.is_deposit_object_read();
                                let is_deposit_prefix_support_scan =
                                    incoming.is_deposit_prefix_support_scan();
                                let is_deposit_sync_control =
                                    incoming.is_deposit_sync_control();
                                let is_deposit_sync_state_read =
                                    incoming.is_deposit_sync_state_read();
                                let deposit_operation = incoming.deposit_operation();
                                let requires_deposit_mutation_admission =
                                    requires_deposit_mutation_admission(
                                        deposit_operation,
                                        is_deposit_object_read,
                                        is_deposit_prefix_support_scan,
                                        is_deposit_sync_control,
                                    );
                                let requires_ordinary_inbound_execution_admission =
                                    requires_ordinary_inbound_execution_admission(
                                        requires_deposit_mutation_admission,
                                        is_deposit_object_read,
                                        is_deposit_prefix_support_scan,
                                        is_deposit_sync_control,
                                    );
                                if let Err(response) = validate_deposit_sync_objects_body_len(
                                    is_deposit_sync_objects,
                                    body_len,
                                ) {
                                    if let Err(error) =
                                        incoming.reject_before_body(response).await
                                    {
                                        tracing::warn!(
                                            %peer,
                                            %error,
                                            "failed to send QUIC oversized SyncObjects response"
                                        );
                                    }
                                    return;
                                }
                                // The peer slot is shared across all of this authenticated
                                // identity's connections. Holding it from the accepted prelude
                                // through response completion leaves at most one bounded body
                                // queued per peer and prevents a flooder from placing multiple
                                // FIFO waiters ahead of another identity.
                                let _deposit_sync_objects_peer_slot =
                                    match try_acquire_deposit_sync_objects_peer_slot(
                                        &inbound_peer.deposit_sync_objects_slot,
                                        is_deposit_object_read,
                                    ) {
                                        Ok(permit) => permit,
                                        Err(response) => {
                                            if let Err(error) =
                                                incoming.reject_before_body(response).await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC SyncObjects peer-slot response"
                                                );
                                            }
                                            return;
                                        }
                                    };
                                // A start or continuation may advance at most one bounded archive
                                // step. Sharing this slot across every connection authenticated as
                                // the requester prevents parallel cursors or a FIFO flood.
                                let _deposit_prefix_support_peer_slot =
                                    match try_acquire_deposit_prefix_support_peer_slot(
                                        &inbound_peer.deposit_prefix_support_slot,
                                        is_deposit_prefix_support_scan,
                                    ) {
                                        Ok(permit) => permit,
                                        Err(response) => {
                                            if let Err(error) =
                                                incoming.reject_before_body(response).await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC prefix-support peer-slot response"
                                                );
                                            }
                                            return;
                                        }
                                    };
                                if !is_deposit_sync_control
                                    && !inbound_peer.admit_request(config).await
                                {
                                    if let Err(error) =
                                        incoming
                                            .reject_before_body(inbound_rate_limited_response())
                                            .await
                                    {
                                        tracing::warn!(%peer, %error, "failed to send QUIC rate-limit response");
                                    }
                                    return;
                                }
                                if is_deposit_sync_control
                                    && !inbound_peer.admit_deposit_sync_control().await
                                {
                                    if let Err(error) = incoming
                                        .reject_before_body(
                                            deposit_sync_control_rate_limited_response(),
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            %peer,
                                            %error,
                                            "failed to send QUIC deposit-sync control rate-limit response"
                                        );
                                    }
                                    return;
                                }
                                // Head and Release share one queued slot across every connection
                                // for this identity. It remains live through the later FIFO
                                // execution wait, typed reducer, and response completion.
                                let _deposit_sync_control_peer_slot =
                                    match try_acquire_deposit_sync_control_peer_slot(
                                        &inbound_peer.deposit_sync_control_slot,
                                        is_deposit_sync_control,
                                    ) {
                                        Ok(permits) => permits,
                                        Err(response) => {
                                            if let Err(error) =
                                                incoming.reject_before_body(response).await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC deposit-sync control lane response"
                                                );
                                            }
                                            return;
                                        }
                                    };
                                if is_deposit_sync_state_read {
                                    match server.deposit_sync_state_read_authorized(peer).await {
                                        Ok(true) => {}
                                        Ok(false) => {
                                            if let Err(error) = incoming
                                                .reject_before_body(PeerResponse::Rejected {
                                                    code: RejectionCode::Unauthorized,
                                                    retryable: false,
                                                    message: "authenticated peer is not in the current deposit committee".to_owned(),
                                                })
                                                .await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC deposit-sync membership rejection"
                                                );
                                            }
                                            return;
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                %peer,
                                                %error,
                                                "could not authorize QUIC deposit-sync state read"
                                            );
                                            if let Err(response_error) = incoming
                                                .reject_before_body(PeerResponse::Rejected {
                                                    code: RejectionCode::Unavailable,
                                                    retryable: true,
                                                    message: "deposit synchronization authority is unavailable".to_owned(),
                                                })
                                                .await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %response_error,
                                                    "failed to send QUIC deposit-sync availability rejection"
                                                );
                                            }
                                            return;
                                        }
                                    }
                                }
                                if let Some(operation) = deposit_operation.filter(|operation| {
                                    deposit_state_transfer_requires_history_authorization(*operation)
                                }) {
                                    match server
                                        .deposit_state_transfer_peer_authorized(peer, operation)
                                        .await
                                    {
                                        Ok(true) => {}
                                        Ok(false) => {
                                            if let Err(error) = incoming
                                                .reject_before_body(PeerResponse::Rejected {
                                                    code: RejectionCode::Unauthorized,
                                                    retryable: false,
                                                    message: "authenticated peer is not in the certified deposit-transition committee union".to_owned(),
                                                })
                                                .await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC deposit-state-transfer membership rejection"
                                                );
                                            }
                                            return;
                                        }
                                        Err(error) => {
                                            tracing::warn!(
                                                %peer,
                                                %error,
                                                "could not authorize QUIC deposit-state-transfer prelude"
                                            );
                                            if let Err(response_error) = incoming
                                                .reject_before_body(PeerResponse::Rejected {
                                                    code: RejectionCode::Unavailable,
                                                    retryable: true,
                                                    message: "certified deposit-transition authority is unavailable".to_owned(),
                                                })
                                                .await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %response_error,
                                                    "failed to send QUIC deposit-state-transfer availability rejection"
                                                );
                                            }
                                            return;
                                        }
                                    }
                                }
                                // Admit at most one mutable body per authenticated identity before
                                // accepting bytes. The endpoint-wide reducer permit is deliberately
                                // acquired only after the complete body is charged and read: a
                                // Byzantine slow sender can therefore occupy only its own slot and
                                // bounded byte budget, never the global mutation boundary.
                                let _deposit_mutation_peer_slot =
                                    match try_acquire_deposit_mutation_peer_slot(
                                        &inbound_peer.deposit_mutation_slot,
                                        requires_deposit_mutation_admission,
                                    ) {
                                        Ok(permits) => permits,
                                        Err(response) => {
                                            if let Err(error) =
                                                incoming.reject_before_body(response).await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC deposit-mutation capacity response"
                                                );
                                            }
                                            return;
                                        }
                                    };
                                // Mutable deposits and the three dedicated read/control families
                                // already have one fixed authenticated-identity slot plus a fair
                                // endpoint execution lane. None may occupy ordinary global ingress
                                // while reading a body or returning a response.
                                let _request_execution_permits =
                                    match try_acquire_inbound_request_execution_permits(
                                        &inbound_peer.request_permits,
                                        &global_permits,
                                        requires_ordinary_inbound_execution_admission,
                                    ) {
                                        Ok(permits) => permits,
                                        Err(response) => {
                                            if let Err(error) =
                                                incoming.reject_before_body(response).await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC concurrency-limit response"
                                                );
                                            }
                                            return;
                                        }
                                    };
                                // Control bodies have exact route-specific caps (256 bytes for
                                // Head and 2 KiB for Release), one live slot per authenticated
                                // identity, and a dedicated endpoint semaphore. Charging them to
                                // the ordinary weighted body pool would let unrelated 8 MiB
                                // traffic suppress the liveness path.
                                let _request_body_permits = if is_deposit_sync_control {
                                    None
                                } else {
                                    match try_acquire_inbound_request_body_permits(
                                        &inbound_peer.body_permits,
                                        &global_body_permits,
                                        body_len,
                                    ) {
                                        Ok(permits) => Some(permits),
                                        Err(response) => {
                                            if let Err(error) =
                                                incoming.reject_before_body(response).await
                                            {
                                                tracing::warn!(
                                                    %peer,
                                                    %error,
                                                    "failed to send QUIC body-capacity response"
                                                );
                                            }
                                            return;
                                        }
                                    }
                                };
                                // Decode under weighted body permits before entering a special
                                // global execution queue. Each authenticated peer has one slot,
                                // and the global byte permits bound queued full start witnesses.
                                let incoming = match incoming.read_request().await {
                                    Ok(incoming) => incoming,
                                    Err(error) => {
                                        tracing::warn!(
                                            %peer,
                                            %request_id,
                                            body_len,
                                            %error,
                                            "failed to read admitted QUIC request body"
                                        );
                                        return;
                                    }
                                };
                                let deposit_mutation_execution_permit =
                                    if requires_deposit_mutation_admission {
                                        let Some(permit) =
                                            acquire_deposit_mutation_execution_permit(
                                                &deposit_mutation_permits,
                                                runtime.wait_for_shutdown(),
                                            )
                                            .await
                                        else {
                                            // No authoritative reducer has been dispatched. Every
                                            // pre-body and byte reservation drops with this task.
                                            return;
                                        };
                                        Some(permit)
                                    } else {
                                        None
                                    };
                                let deposit_sync_objects_execution_permit =
                                    if is_deposit_object_read {
                                        let Some(permit) =
                                            acquire_deposit_sync_objects_execution_permit(
                                                &deposit_sync_objects_permits,
                                                runtime.wait_for_shutdown(),
                                            )
                                            .await
                                        else {
                                            // Closing the endpoint wakes the sender. Dropping this
                                            // task releases its peer slot and body reservations,
                                            // so shutdown cannot strand a FIFO waiter.
                                            return;
                                        };
                                        Some(permit)
                                    } else {
                                        None
                                    };
                                let deposit_prefix_support_execution_permit =
                                    if is_deposit_prefix_support_scan {
                                        let Some(permit) =
                                            acquire_deposit_prefix_support_execution_permit(
                                                &deposit_prefix_support_permits,
                                                runtime.wait_for_shutdown(),
                                            )
                                            .await
                                        else {
                                            return;
                                        };
                                        Some(permit)
                                    } else {
                                        None
                                    };
                                let deposit_sync_control_execution_permit =
                                    if is_deposit_sync_control {
                                        let Some(permit) =
                                            acquire_deposit_sync_control_execution_permit(
                                                &deposit_sync_control_permits,
                                                runtime.wait_for_shutdown(),
                                            )
                                            .await
                                        else {
                                            return;
                                        };
                                        Some(permit)
                                    } else {
                                        None
                                    };
                                let deposit_execution_permits =
                                    DepositEndpointExecutionPermits {
                                        mutation: deposit_mutation_execution_permit,
                                        sync_objects: deposit_sync_objects_execution_permit,
                                        prefix_support: deposit_prefix_support_execution_permit,
                                        sync_control: deposit_sync_control_execution_permit,
                                    };
                                let (request, responder) =
                                    incoming.into_request_and_responder();
                                // Transport validation recomputed this identifier from the exact
                                // canonical route/body bytes. Reusing it avoids hashing or
                                // serializing the attacker-sized body a third time.
                                let fingerprint = request_id.to_bytes();
                                let admission = {
                                    InboundRequestCache::lock(&request_cache)
                                        .admit(request_id, fingerprint)
                                };
                                match admission {
                                    InboundRequestAdmission::Respond(response) => {
                                        drop(request);
                                        drop(_request_body_permits);
                                        if let Err(error) =
                                            respond_after_releasing_deposit_execution(
                                                deposit_execution_permits,
                                                responder.respond(response),
                                            )
                                            .await
                                        {
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
                                // PartyServer's typed SyncObjects decoder is the post-decode hook
                                // for lease and active-member/source-pin authorization. Transport
                                // fairness deliberately grants no authority by itself.
                                let response = server.handle_quic_peer_request(peer, request).await;
                                execution.complete(&response);
                                drop(_request_body_permits);
                                let response_result =
                                    respond_after_releasing_deposit_execution(
                                        deposit_execution_permits,
                                        responder.respond(response),
                                    )
                                    .await;
                                if let Err(error) = response_result {
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
                    let now = match self.server.deposit_clock_sample() {
                        Ok(sample) => sample.unix_millis,
                        Err(error) => {
                            tracing::warn!(
                                party = %self.server.party_id(),
                                %error,
                                "deposit clock sample failed closed; allocation consensus will retry"
                            );
                            continue;
                        }
                    };
                    if let Err(error) =
                        Box::pin(self.server.progress_deposit_allocation_consensus(now)).await
                    {
                        tracing::warn!(
                            target: "threshold_monero::deposit_progress_retry",
                            party = %self.server.party_id(),
                            %error,
                            "deposit allocation consensus progress failed; durable state will retry"
                        );
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
        let Some(_admission) = try_acquire_outbound_sync_admission(
            &self.outbound_sync_permits,
            &peer.sync_permits,
            &self.outbound_permits,
            &peer.permits,
        ) else {
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
        match connection
            .connection
            .request_with_timeout(request_id, request, self.config.epoch_history_request_timeout)
            .await
        {
            Ok(response) => {
                self.server.record_authenticated_quic_response();
                peer.transport_success().await;
                Ok(Some(response))
            }
            Err(error) => {
                let connection_retry = peer
                    .request_connection_failure(connection.generation, &error, self.config)
                    .await;
                tracing::debug!(%source, ?connection_retry, %error, "epoch-history pull deferred");
                Ok(None)
            }
        }
    }

    async fn deposit_sync_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.deposit_sync_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    // Every network wait inside the tick carries an absolute deadline and observes
                    // shutdown itself. Once a durable reducer has been entered, however, it must
                    // be allowed to finish its CAS/readback instead of being cancelled by an
                    // outer timeout or shutdown branch. This is especially important for the
                    // certified handoff path, whose next tick reconstructs authority only from a
                    // completed journal transition.
                    let started = Instant::now();
                    match Box::pin(self.synchronize_deposit_state()).await {
                        Ok(()) => {}
                        Err(error) => {
                            tracing::warn!(party = %self.server.party_id(), error = %format_args!("{error:#}"), "compact deposit synchronization failed; issuance remains closed");
                        }
                    }
                    let elapsed = started.elapsed();
                    if elapsed > self.config.deposit_sync_tick_timeout {
                        tracing::warn!(
                            party = %self.server.party_id(),
                            ?elapsed,
                            configured_tick_budget = ?self.config.deposit_sync_tick_timeout,
                            "compact deposit synchronization completed beyond its network-work budget"
                        );
                    }
                }
            }
        }
    }

    /// Best-effort terminal certificate retries which never gate the current sync pacemaker.
    ///
    /// The half-period stagger gives current synchronization the first scheduling opportunity.
    /// Current and historical work alternate first claim on each tick. Each turn admits at most one
    /// current export/import certificate retry and at most one retained historical target epoch
    /// while separate cursors rotate lanes and recipients. Aggregate network wait is capped at one
    /// quarter-period, so a silent recipient releases the shared sync permit before the next tick
    /// without permanently starving either scope. Finite authenticated local recovery and receipt
    /// CAS work pauses that network clock and is always allowed to finish.
    async fn historical_deposit_state_import_loop(self: Arc<Self>) {
        let first = Instant::now() + self.config.deposit_sync_interval / 2;
        let mut interval = time::interval_at(first, self.config.deposit_sync_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    let Some(retry_budget) = deposit_state_transfer_background_budget(
                        self.config.deposit_sync_interval,
                        self.config.deposit_sync_request_timeout,
                    ) else {
                        tracing::warn!(
                            party = %self.server.party_id(),
                            "deposit state-transfer background retry budget is below timer resolution"
                        );
                        continue;
                    };
                    let Some(mut deadline) = Instant::now().checked_add(retry_budget)
                    else {
                        tracing::warn!(
                            party = %self.server.party_id(),
                            "background state-transfer retry deadline overflowed"
                        );
                        continue;
                    };
                    let mut work = DepositSyncTickWork::default();
                    for scope in deposit_state_transfer_background_scope_order(
                        &self.deposit_state_transfer_background_scope_cursor,
                    ) {
                        if Instant::now() >= deadline {
                            break;
                        }
                        let progress = match scope {
                            DepositStateTransferBackgroundScope::Current => self
                                .progress_current_deposit_state_transfer_background(
                                    &mut deadline,
                                    &mut work,
                                )
                                .await,
                            DepositStateTransferBackgroundScope::Historical => self
                                .progress_historical_deposit_state_import_transport(
                                    &mut deadline,
                                    &mut work,
                                )
                                .await,
                        };
                        if let Err(error) = progress {
                            tracing::warn!(
                                party = %self.server.party_id(),
                                ?scope,
                                %error,
                                "terminal state-transfer background fanout failed; current synchronization remains live"
                            );
                        }
                    }
                }
            }
        }
    }

    async fn deposit_retention_gc_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.deposit_worker_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    if let Err(error) =
                        Box::pin(self.server.progress_deposit_retention_gc_batch()).await
                    {
                        tracing::warn!(
                            party = %self.server.party_id(),
                            %error,
                            "deposit retention GC batch failed; durable queue will retry"
                        );
                    }
                }
            }
        }
    }

    async fn deposit_scanner_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.deposit_worker_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    let server = Arc::clone(&self.server);
                    let runtime = Arc::clone(&self);
                    let maximum_ticks = server.deposit_worker_backfill_burst_limit();
                    // Every selected tick owns its durable reducer through CAS/readback. Shutdown
                    // is observed only between ticks instead of cancelling an entered mutation.
                    if let Err(error) = Box::pin(run_bounded_deposit_scanner_burst(
                        maximum_ticks,
                        move || {
                            let server = Arc::clone(&server);
                            async move { Box::pin(server.tick_deposit_worker()).await }
                        },
                        move || runtime.shutdown.load(Ordering::Acquire),
                    ))
                    .await
                    {
                        tracing::warn!(
                            party = %self.server.party_id(),
                            error = %format_args!("{error:#}"),
                            "deposit scanner tick failed; durable state will retry"
                        );
                    }
                }
            }
        }
    }

    async fn deposit_consolidation_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.deposit_worker_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    if let Err(error) = Box::pin(
                        self.server.progress_deposit_consolidation_once(
                            self.config.consolidation_attempt_timeout,
                        ),
                    )
                    .await
                    {
                        tracing::warn!(party = %self.server.party_id(), %error, "deposit consolidation progress failed; durable state will retry");
                    }
                }
            }
        }
    }

    async fn deposit_publication_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.deposit_worker_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => return,
                _ = interval.tick() => {
                    if let Err(error) =
                        Box::pin(self.server.publish_deposit_consolidations_once()).await
                    {
                        tracing::warn!(party = %self.server.party_id(), %error, "deposit transaction publication failed; exact certified bytes will retry");
                    }
                }
            }
        }
    }

    async fn certified_deposit_source_stalled(
        &self,
        context: DepositStateTransferContext,
        source: PartyId,
        position: CertifiedDepositSourcePosition,
    ) -> bool {
        let now = Instant::now();
        let mut progress = self.certified_deposit_source_progress.lock().await;
        match *progress {
            Some(current)
                if current.context == context
                    && current.source == source
                    && current.position == position =>
            {
                now.saturating_duration_since(current.last_progress)
                    >= self.config.deposit_sync_source_timeout
            }
            _ => {
                *progress = Some(CertifiedDepositSourceProgress {
                    context,
                    source,
                    position,
                    last_progress: now,
                });
                false
            }
        }
    }

    async fn clear_certified_deposit_source_progress(&self) {
        *self.certified_deposit_source_progress.lock().await = None;
    }

    fn state_transfer_reservation_key(
        &self,
        recipient: PartyId,
        operation: DepositOperation,
        body: Vec<u8>,
    ) -> anyhow::Result<(StateTransferReservationKey, PeerRequest)> {
        let request = PeerRequest::Deposit { operation, body };
        let request_id = RequestId::for_peer_request(
            self.network_id,
            self.server.party_id(),
            recipient,
            &request,
        )?;
        Ok((StateTransferReservationKey { recipient, request_id }, request))
    }

    fn state_transfer_census_watermark(&self) -> u64 {
        self.state_transfer_reservation_generation.load(Ordering::Acquire)
    }

    /// Persist one exact intent-snapshot successor before exposing its corresponding live cut.
    ///
    /// Atomic replacement may install the successor and still report a parent-directory fsync or
    /// readback error. Retrying the identical expected metadata and bytes is the only safe way to
    /// distinguish that uncertain success from a pre-write failure. The storage layer recognizes
    /// exactly that immediate successor and fsyncs it again before returning success.
    async fn save_state_transfer_intent_successor(
        &self,
        expected: DepositStateTransferIntentsMetadata,
        encoded: &[u8],
        fence_ordinary_relays_on_error: bool,
        operation: &'static str,
    ) -> anyhow::Result<DepositStateTransferIntentsMetadata> {
        let mut retry_delay = self.config.retry_initial;
        loop {
            match self.server.save_deposit_state_transfer_intents(Some(expected), encoded).await {
                Ok(metadata) => return Ok(metadata),
                Err(error) => {
                    if fence_ordinary_relays_on_error {
                        self.mutable_deposit_relay_ready.store(false, Ordering::Release);
                    }
                    tracing::error!(
                        party = %self.server.party_id(),
                        %error,
                        retry_millis = retry_delay.as_millis(),
                        %operation,
                        "durable state-transfer intent CAS is unresolved"
                    );
                    tokio::select! {
                        biased;
                        () = self.wait_for_shutdown() => {
                            return Err(anyhow!(
                                "shutdown interrupted {operation} after an unresolved durable intent CAS: {error}"
                            ));
                        }
                        () = time::sleep(retry_delay) => {}
                    }
                    retry_delay = retry_delay.saturating_mul(2).min(self.config.retry_maximum);
                }
            }
        }
    }

    /// Mark one exact remote transfer journal entry in-doubt before transport dispatch.
    ///
    /// Exact retries share the map entry and per-recipient reservation. A different current or
    /// background entry for that recipient waits until ACK or authoritative census retires the
    /// exact in-doubt key. The attempt semaphore stays with the RPC result through typed receipt
    /// validation and durable acknowledgement, preventing duplicate reducers from racing that
    /// checkpoint.
    async fn acquire_state_transfer_reservation(
        &self,
        key: StateTransferReservationKey,
        scope: StateTransferReservationScope,
        operation: DepositOperation,
        started_before: Instant,
    ) -> Result<Option<StateTransferAttemptAdmission>, OutboundDepositMutationSlotError> {
        debug_assert!(deposit_operation_requires_mutation_admission(operation));
        if started_before <= Instant::now()
            || !self.state_transfer_intents_loaded.load(Ordering::Acquire)
        {
            return Err(OutboundDepositMutationSlotError::Cancelled);
        }
        let attempt_slot = self
            .state_transfer_attempt_slots
            .get(&key.recipient)
            .ok_or(OutboundDepositMutationSlotError::UnknownRecipient)?
            .clone();
        let attempt = tokio::select! {
            biased;
            () = self.wait_for_shutdown() => {
                return Err(OutboundDepositMutationSlotError::Cancelled);
            }
            permit = attempt_slot.acquire_owned() => {
                permit.map_err(|_| OutboundDepositMutationSlotError::Cancelled)?
            }
        };

        {
            let reservations = self.state_transfer_reservations.lock().await;
            if let Some(existing) = reservations.exact.get(&key) {
                if existing.scope != scope {
                    tracing::error!(
                        recipient = %key.recipient,
                        request_id = ?key.request_id,
                        ?scope,
                        existing_scope = ?existing.scope,
                        "exact state-transfer request changed durable reconciliation scope"
                    );
                    return Err(OutboundDepositMutationSlotError::Cancelled);
                }
                debug_assert!(reservations.recipients.contains_key(&key.recipient));
                if !existing.retry.ready(Instant::now()) {
                    return Ok(None);
                }
                return Ok(Some(StateTransferAttemptAdmission {
                    _attempt: attempt,
                    retries_in_doubt_intent: true,
                }));
            }
            if reservations.recipients.contains_key(&key.recipient) {
                // An earlier reducer may still be executing after its sender timed out. Never
                // overtake that ambiguity with a different state-transfer body; exact retries
                // reuse the existing key, while other current/background work waits for ACK or
                // authoritative census retirement.
                return Err(OutboundDepositMutationSlotError::Busy);
            }
        }

        let recipient_permit = acquire_outbound_deposit_mutation_slot_after_transfer_start(
            &self.outbound_deposit_mutation_slots,
            key.recipient,
            operation,
            self.wait_for_shutdown(),
        )
        .await?
        .expect("mutable state-transfer operation acquires a recipient permit");

        let durable_scope = match DurableStateTransferReservationScope::try_from(scope) {
            Ok(scope) => scope,
            Err(error) => {
                self.mutable_deposit_relay_ready.store(false, Ordering::Release);
                tracing::error!(
                    recipient = %key.recipient,
                    request_id = ?key.request_id,
                    ?scope,
                    %error,
                    "mutable state-transfer request has no durable intent representation"
                );
                return Err(OutboundDepositMutationSlotError::Cancelled);
            }
        };
        let mut snapshot_guard = self.state_transfer_intent_snapshot.lock().await;
        let Some(snapshot) = snapshot_guard.as_mut() else {
            tracing::error!(
                recipient = %key.recipient,
                request_id = ?key.request_id,
                "state-transfer intent gate opened without a loaded durable snapshot"
            );
            self.state_transfer_intents_loaded.store(false, Ordering::Release);
            self.mutable_deposit_relay_ready.store(false, Ordering::Release);
            return Err(OutboundDepositMutationSlotError::Cancelled);
        };
        if snapshot.entries.contains_key(&key.recipient) {
            tracing::error!(
                recipient = %key.recipient,
                request_id = ?key.request_id,
                "durable state-transfer intent is missing its live recipient reservation"
            );
            self.state_transfer_intents_loaded.store(false, Ordering::Release);
            self.mutable_deposit_relay_ready.store(false, Ordering::Release);
            return Err(OutboundDepositMutationSlotError::Cancelled);
        }
        let Some(generation) = snapshot.high_water_generation.checked_add(1) else {
            self.mutable_deposit_relay_ready.store(false, Ordering::Release);
            return Err(OutboundDepositMutationSlotError::GenerationExhausted);
        };
        let mut durable_entries = snapshot.entries.clone();
        let previous = durable_entries.insert(
            key.recipient,
            DurableStateTransferIntent {
                recipient: key.recipient,
                request_id: key.request_id.to_bytes(),
                scope: durable_scope,
                created_generation: generation,
            },
        );
        debug_assert!(previous.is_none());
        let encoded = match encode_state_transfer_intent_snapshot(
            self.network_id,
            self.server.party_id(),
            generation,
            &durable_entries,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.mutable_deposit_relay_ready.store(false, Ordering::Release);
                tracing::error!(
                    recipient = %key.recipient,
                    request_id = ?key.request_id,
                    %error,
                    "failed to encode a durable state-transfer intent"
                );
                return Err(OutboundDepositMutationSlotError::Cancelled);
            }
        };
        let metadata = match self
            .save_state_transfer_intent_successor(
                snapshot.metadata,
                &encoded,
                true,
                "state-transfer reservation",
            )
            .await
        {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::error!(
                    recipient = %key.recipient,
                    request_id = ?key.request_id,
                    %error,
                    "failed to durably reserve a state-transfer recipient"
                );
                return Err(OutboundDepositMutationSlotError::Cancelled);
            }
        };
        snapshot.metadata = metadata;
        snapshot.high_water_generation = generation;
        snapshot.entries = durable_entries;
        self.state_transfer_reservation_generation.store(generation, Ordering::Release);
        self.mutable_deposit_relay_ready.store(
            generation != u64::MAX && self.state_transfer_intents_loaded.load(Ordering::Acquire),
            Ordering::Release,
        );
        drop(snapshot_guard);

        let mut reservations = self.state_transfer_reservations.lock().await;
        debug_assert!(!reservations.recipients.contains_key(&key.recipient));
        let previous_recipient = reservations.recipients.insert(key.recipient, recipient_permit);
        debug_assert!(previous_recipient.is_none());
        let previous = reservations.exact.insert(
            key,
            StateTransferRequestReservation {
                scope,
                generation,
                retry: RetryState::new(Instant::now()),
            },
        );
        debug_assert!(previous.is_none());
        Ok(Some(StateTransferAttemptAdmission {
            _attempt: attempt,
            retries_in_doubt_intent: false,
        }))
    }

    async fn state_transfer_reservation_failure(
        &self,
        key: StateTransferReservationKey,
    ) -> Option<Duration> {
        self.state_transfer_reservations.lock().await.record_failure(
            key,
            Instant::now(),
            self.config.retry_initial,
            self.config.retry_maximum,
        )
    }

    /// Release one exact in-doubt transport key after remote execution is no longer ambiguous.
    ///
    /// Protocol journal completion is an independent decision. A valid source-request ACK, for
    /// example, resolves transport execution while its locator remains pending until the
    /// receiver's separately durable vote arrives.
    async fn complete_state_transfer_reservation(
        &self,
        key: StateTransferReservationKey,
    ) -> anyhow::Result<()> {
        let mut snapshot_guard = self.state_transfer_intent_snapshot.lock().await;
        let snapshot = snapshot_guard
            .as_mut()
            .context("state-transfer intent snapshot is unavailable during durable completion")?;
        let durable = snapshot.entries.get(&key.recipient).copied().context(
            "authenticated transfer response completed an unknown recipient reservation",
        )?;
        anyhow::ensure!(
            durable.key() == key,
            "authenticated transfer response completed a different request reservation"
        );
        let mut durable_entries = snapshot.entries.clone();
        durable_entries.remove(&key.recipient);
        let encoded = encode_state_transfer_intent_snapshot(
            self.network_id,
            self.server.party_id(),
            snapshot.high_water_generation,
            &durable_entries,
        )?;
        let metadata = self
            .save_state_transfer_intent_successor(
                snapshot.metadata,
                &encoded,
                false,
                "state-transfer reservation retirement",
            )
            .await
            .context("failed to durably retire a state-transfer reservation")?;
        snapshot.metadata = metadata;
        snapshot.entries = durable_entries;
        drop(snapshot_guard);

        let removed = self.state_transfer_reservations.lock().await.remove_exact(key);
        anyhow::ensure!(
            removed,
            "authenticated transfer response completed an unknown live reservation"
        );
        Ok(())
    }

    /// Retire the optional durable transport cut after an authenticated terminal response.
    ///
    /// Callers must validate a successful response's typed receipt and commit any required local
    /// protocol effect first. Rejections use [`Self::handle_authenticated_state_transfer_rejection`]
    /// because only locally observed pre-body admission can prove that a fresh request was never
    /// dispatched.
    async fn retire_state_transfer_intent_after_authenticated_response(
        &self,
        reservation: Option<StateTransferReservationKey>,
    ) -> anyhow::Result<()> {
        if let Some(reservation) = reservation {
            self.complete_state_transfer_reservation(reservation).await?;
        }
        Ok(())
    }

    /// Resolve an authenticated rejection without erasing ambiguity from an earlier dispatch.
    ///
    /// Only a locally observed pre-body rejection of the first attempt proves that its exact body
    /// was never dispatched, so the freshly created transport cut may be retired while the protocol
    /// locator stays pending. Once a body was admitted, or any earlier transport attempt became
    /// ambiguous, a peer-controlled rejection cannot resolve the cut. It remains fenced until an
    /// exact typed receipt or an authoritative protocol census resolves it.
    async fn handle_authenticated_state_transfer_rejection(
        &self,
        reservation: Option<StateTransferReservationKey>,
        attempt: Option<&StateTransferAttemptAdmission>,
        provenance: Option<QuicResponseProvenance>,
    ) -> anyhow::Result<()> {
        match (reservation, attempt, provenance) {
            (None, None, _) => Ok(()),
            (Some(reservation), Some(attempt), Some(provenance))
                if attempt.may_retire_on_authenticated_rejection(provenance) =>
            {
                self.complete_state_transfer_reservation(reservation).await
            }
            (Some(_), Some(_), Some(_)) => Ok(()),
            _ => anyhow::bail!(
                "state-transfer rejection reservation, attempt, and provenance presence differs"
            ),
        }
    }

    /// Clear a newly created cut when its body definitely never entered a QUIC stream. An exact
    /// retry reuses an already in-doubt cut, so failure to dispatch that retry cannot resolve the
    /// earlier execution and only advances its bounded backoff.
    async fn handle_state_transfer_deadline_before_dispatch(
        &self,
        reservation: StateTransferReservationKey,
        attempt: &StateTransferAttemptAdmission,
    ) -> anyhow::Result<()> {
        if attempt.is_fresh() {
            self.complete_state_transfer_reservation(reservation).await
        } else {
            self.state_transfer_reservation_failure(reservation).await;
            Ok(())
        }
    }

    async fn state_transfer_census_recipients(
        &self,
        census_watermark: u64,
    ) -> BTreeMap<StateTransferReservationScope, BTreeSet<PartyId>> {
        // The watermark is published before the volatile cut. Read its durable snapshot so a
        // reservation in that publication gap cannot be omitted from reconstruction.
        let snapshot = self.state_transfer_intent_snapshot.lock().await;
        let mut recipients = BTreeMap::<_, BTreeSet<_>>::new();
        if let Some(snapshot) = snapshot.as_ref() {
            for intent in snapshot.entries.values() {
                if intent.created_generation <= census_watermark {
                    recipients.entry(intent.runtime_scope()).or_default().insert(intent.recipient);
                }
            }
        }
        recipients
    }

    async fn state_transfer_reservation_scopes(&self) -> BTreeSet<StateTransferReservationScope> {
        self.state_transfer_reservations
            .lock()
            .await
            .exact
            .values()
            .map(|reservation| reservation.scope)
            .collect()
    }

    async fn ready_historical_state_import_reservation_epochs(
        &self,
        active_epoch: u64,
    ) -> BTreeSet<u64> {
        let now = Instant::now();
        self.state_transfer_reservations
            .lock()
            .await
            .exact
            .values()
            .filter_map(|reservation| match reservation.scope {
                StateTransferReservationScope::StateImportCertificate(epoch)
                    if epoch < active_epoch && reservation.retry.ready(now) =>
                {
                    Some(epoch)
                }
                _ => None,
            })
            .collect()
    }

    /// Reconcile volatile in-doubt keys against one complete authoritative journal census.
    ///
    /// A concurrent attempt owns the recipient's attempt slot and is retained. Otherwise only
    /// exact keys absent from this successful census are removed. Reconstruction may omit
    /// recipients with no reservation at the watermark: a later reservation cannot be retired by
    /// this census. Every candidate recipient still requires its complete authenticated census.
    /// A partial/failed enumeration must never call this method.
    async fn reconcile_state_transfer_scope(
        &self,
        scope: StateTransferReservationScope,
        active: &BTreeSet<StateTransferReservationKey>,
        census_watermark: u64,
    ) -> anyhow::Result<()> {
        let candidates = {
            let reservations = self.state_transfer_reservations.lock().await;
            reservations
                .exact
                .iter()
                .filter_map(|(key, reservation)| {
                    state_transfer_reservation_is_absent_from_census(
                        *key,
                        reservation,
                        scope,
                        active,
                        census_watermark,
                    )
                    .then_some(*key)
                })
                .collect::<Vec<_>>()
        };
        for key in candidates {
            let Some(attempt_slot) = self.state_transfer_attempt_slots.get(&key.recipient) else {
                continue;
            };
            let Ok(_attempt) = attempt_slot.clone().try_acquire_owned() else {
                continue;
            };
            let still_absent =
                self.state_transfer_reservations.lock().await.exact.get(&key).is_some_and(
                    |reservation| {
                        state_transfer_reservation_is_absent_from_census(
                            key,
                            reservation,
                            scope,
                            active,
                            census_watermark,
                        )
                    },
                );
            if still_absent {
                self.complete_state_transfer_reservation(key).await?;
            }
        }
        Ok(())
    }

    async fn reconcile_current_export_seal_reservations(
        &self,
        pending: &[DepositStateExportSealWorkLocator],
        census_watermark: u64,
    ) -> anyhow::Result<()> {
        let scopes = self
            .state_transfer_census_recipients(census_watermark)
            .await
            .into_iter()
            .filter(|(scope, _)| matches!(scope, StateTransferReservationScope::ExportSeal(_)))
            .collect::<BTreeMap<_, _>>();
        if scopes.is_empty() {
            return Ok(());
        }
        let mut active =
            BTreeMap::<StateTransferReservationScope, BTreeSet<StateTransferReservationKey>>::new();
        for locator in pending {
            let scope = StateTransferReservationScope::ExportSeal(locator.target_epoch());
            let recipient = DepositStateExportSealWorkRoute::from_locator(*locator)?.recipient();
            if !scopes.get(&scope).is_some_and(|recipients| recipients.contains(&recipient)) {
                continue;
            }
            let reconstructed =
                match self.server.reconstruct_deposit_state_export_seal_work(*locator).await {
                    Ok(work) => work,
                    Err(error) if completed_export_work(&error) => continue,
                    Err(error) => return Err(error),
                };
            let route = reconstructed.route();
            let (key, _) = self.state_transfer_reservation_key(
                route.recipient(),
                route.operation(),
                reconstructed.body().to_vec(),
            )?;
            active.entry(scope).or_default().insert(key);
        }
        let empty = BTreeSet::new();
        for scope in scopes.into_keys() {
            self.reconcile_state_transfer_scope(
                scope,
                active.get(&scope).unwrap_or(&empty),
                census_watermark,
            )
            .await?;
        }
        Ok(())
    }

    /// Reconcile a complete authenticated current-target StateImported journal census.
    ///
    /// A certificate may migrate into retained historical storage after the target advances.
    /// Therefore this census retires certificate reservations only for its exact current target;
    /// older certificate scopes remain reserved until their own historical census proves absence.
    async fn reconcile_current_state_import_reservations(
        &self,
        pending: &[DepositStateImportWorkLocator],
        target_epoch: Option<u64>,
        census_watermark: u64,
    ) -> anyhow::Result<()> {
        let Some(target_epoch) = target_epoch else {
            return Ok(());
        };
        let scopes = self
            .state_transfer_census_recipients(census_watermark)
            .await
            .into_iter()
            .filter(|(scope, _)| {
                matches!(scope, StateTransferReservationScope::StateImportAcknowledgement(_))
                    || *scope == StateTransferReservationScope::StateImportCertificate(target_epoch)
            })
            .collect::<BTreeMap<_, _>>();
        if scopes.is_empty() {
            return Ok(());
        }
        let mut active =
            BTreeMap::<StateTransferReservationScope, BTreeSet<StateTransferReservationKey>>::new();
        for locator in pending {
            let scope = match locator.kind() {
                DepositStateImportWorkKind::AcknowledgementDelivery => {
                    StateTransferReservationScope::StateImportAcknowledgement(
                        locator.target_epoch(),
                    )
                }
                DepositStateImportWorkKind::CertificateDelivery => {
                    anyhow::ensure!(
                        locator.target_epoch() == target_epoch,
                        "current StateImported certificate census crossed its target epoch"
                    );
                    StateTransferReservationScope::StateImportCertificate(target_epoch)
                }
            };
            if !scopes
                .get(&scope)
                .is_some_and(|recipients| recipients.contains(&locator.recipient()))
            {
                continue;
            }
            let reconstructed =
                match self.server.reconstruct_deposit_state_import_work(*locator).await {
                    Ok(work) => work,
                    Err(error) if completed_state_import_work(&error) => continue,
                    Err(error) => return Err(error),
                };
            let route = reconstructed.route();
            let (key, _) = self.state_transfer_reservation_key(
                route.recipient(),
                route.operation(),
                reconstructed.body().to_vec(),
            )?;
            active.entry(scope).or_default().insert(key);
        }
        let empty = BTreeSet::new();
        for scope in scopes.into_keys() {
            self.reconcile_state_transfer_scope(
                scope,
                active.get(&scope).unwrap_or(&empty),
                census_watermark,
            )
            .await?;
        }
        Ok(())
    }

    async fn reconcile_historical_state_import_reservations(
        &self,
        target_epoch: u64,
        pending: &[DepositStateImportWorkLocator],
        census_watermark: u64,
    ) -> anyhow::Result<()> {
        let scope = StateTransferReservationScope::StateImportCertificate(target_epoch);
        let scopes = self.state_transfer_census_recipients(census_watermark).await;
        let Some(recipients) = scopes.get(&scope) else {
            return Ok(());
        };
        let mut active = BTreeSet::new();
        for locator in pending {
            anyhow::ensure!(
                locator.target_epoch() == target_epoch
                    && locator.kind() == DepositStateImportWorkKind::CertificateDelivery,
                "historical state-import census crossed its exact epoch/certificate scope"
            );
            if !recipients.contains(&locator.recipient()) {
                continue;
            }
            let reconstructed = match self
                .server
                .reconstruct_historical_deposit_state_import_certificate_work(*locator)
                .await
            {
                Ok(work) => work,
                Err(error) if completed_state_import_work(&error) => continue,
                Err(error) => return Err(error),
            };
            let route = reconstructed.route();
            let (key, _) = self.state_transfer_reservation_key(
                route.recipient(),
                route.operation(),
                reconstructed.body().to_vec(),
            )?;
            active.insert(key);
        }
        self.reconcile_state_transfer_scope(scope, &active, census_watermark).await?;
        Ok(())
    }

    async fn drain_deposit_state_export_releases(
        self: &Arc<Self>,
        context: CertifiedDepositStateTransferWorkContext,
        tick_deadline: Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<bool> {
        let census_watermark = self.state_transfer_census_watermark();
        let mut pending = self.server.pending_deposit_state_export_releases(context).await?;
        let scope = StateTransferReservationScope::ExportRelease(context.context().digest());
        let reservation_scopes = self
            .state_transfer_reservation_scopes()
            .await
            .into_iter()
            .filter(|scope| matches!(scope, StateTransferReservationScope::ExportRelease(_)))
            .collect::<BTreeSet<_>>();
        if !reservation_scopes.is_empty() {
            let mut active = BTreeSet::new();
            let empty = BTreeSet::new();
            for request in &pending {
                let source = request.lease().source();
                let (key, _) = self.state_transfer_reservation_key(
                    source,
                    DepositOperation::ExportRelease,
                    request.to_bytes()?,
                )?;
                active.insert(key);
            }
            for reservation_scope in reservation_scopes {
                self.reconcile_state_transfer_scope(
                    reservation_scope,
                    if reservation_scope == scope { &active } else { &empty },
                    census_watermark,
                )
                .await?;
            }
        }
        if pending.is_empty() {
            return Ok(false);
        }
        let start =
            self.deposit_sync_release_cursor.fetch_add(1, Ordering::Relaxed) % pending.len();
        pending.rotate_left(start);
        for request in pending.into_iter().take(MAX_CERTIFIED_EXPORT_RELEASES_PER_DRAIN) {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= tick_deadline {
                return Ok(true);
            }
            let source = request.lease().source();
            let body = request.to_bytes()?;
            if !work_budget.may_request(body.len()) {
                return Ok(true);
            }
            work_budget.record_request(body.len())?;
            let Some(response) = self
                .deposit_state_transfer_rpc(
                    source,
                    DepositOperation::ExportRelease,
                    body,
                    tick_deadline,
                    scope,
                )
                .await?
            else {
                continue;
            };
            let (response, provenance, reservation, attempt) = response.into_parts();
            match response {
                PeerResponse::Success { body } => {
                    work_budget.record_wire_bytes(body.len())?;
                    let acknowledgement =
                        match DepositStateExportReleaseAck::from_bytes(request, &body) {
                            Ok(acknowledgement) => acknowledgement,
                            Err(error) => {
                                tracing::warn!(
                                    %source,
                                    %error,
                                    "certified export source returned an invalid release receipt"
                                );
                                continue;
                            }
                        };
                    self.server
                        .acknowledge_deposit_state_export_release(context, request, acknowledgement)
                        .await?;
                    self.retire_state_transfer_intent_after_authenticated_response(reservation)
                        .await?;
                }
                PeerResponse::Rejected { code, retryable, message } => {
                    self.handle_authenticated_state_transfer_rejection(
                        reservation,
                        attempt.as_ref(),
                        provenance,
                    )
                    .await?;
                    tracing::debug!(
                        %source,
                        ?code,
                        retryable,
                        %message,
                        "certified export release protocol work retained after peer rejection"
                    );
                }
            }
        }
        Ok(!self.server.pending_deposit_state_export_releases(context).await?.is_empty())
    }

    /// A completed earlier import can retire unused head intents while the next source seal is
    /// still pending. Reconcile those exact cuts before the seal gate, or they can occupy the
    /// very recipient lanes needed to collect its missing votes.
    async fn reconcile_export_head_reservations(
        &self,
        context: DepositStateTransferContext,
        heads: &[DepositStateExportHeadRequest],
        census_watermark: u64,
    ) -> anyhow::Result<()> {
        let scope = StateTransferReservationScope::ExportHead(context.digest());
        if !self.state_transfer_census_recipients(census_watermark).await.contains_key(&scope) {
            return Ok(());
        }
        let mut active = BTreeSet::new();
        for request in heads {
            anyhow::ensure!(
                request.context() == context,
                "export-head census crossed its wallet context"
            );
            let (key, _) = self.state_transfer_reservation_key(
                request.source(),
                DepositOperation::ExportHead,
                request.to_bytes()?,
            )?;
            active.insert(key);
        }
        self.reconcile_state_transfer_scope(scope, &active, census_watermark).await
    }

    async fn progress_deposit_state_export_download(
        self: &Arc<Self>,
        context: CertifiedDepositStateTransferWorkContext,
        ordinary_release_barriers: &BTreeSet<PartyId>,
        tick_deadline: Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<CertifiedDepositTransferDisposition> {
        let census_watermark = self.state_transfer_census_watermark();
        let mut heads = self.server.pending_deposit_state_export_heads(context).await?;
        let scope = StateTransferReservationScope::ExportHead(context.context().digest());
        self.reconcile_export_head_reservations(context.context(), &heads, census_watermark)
            .await?;
        if retain_certified_export_heads_without_ordinary_release(
            &mut heads,
            ordinary_release_barriers,
        ) {
            // The source still owns this requester's earlier ordinary pin. Only its exact typed
            // Release ACK may clear that causal barrier; implicit replacement would race an
            // ordinary object read and violate retain-until-release.
            self.clear_certified_deposit_source_progress().await;
            return Ok(CertifiedDepositTransferDisposition::Pending);
        }
        if !heads.is_empty() {
            let start =
                self.deposit_state_transfer_cursor.fetch_add(1, Ordering::Relaxed) % heads.len();
            heads.rotate_left(start);
            for request in heads {
                if self.shutdown.load(Ordering::Acquire) || Instant::now() >= tick_deadline {
                    return Ok(CertifiedDepositTransferDisposition::Pending);
                }
                let source = request.source();
                let request_body = request.to_bytes()?;
                if !work_budget.may_request(request_body.len()) {
                    return Ok(CertifiedDepositTransferDisposition::Pending);
                }
                work_budget.record_request(request_body.len())?;
                let response = self
                    .deposit_state_transfer_rpc(
                        source,
                        DepositOperation::ExportHead,
                        request_body,
                        tick_deadline,
                        scope,
                    )
                    .await?;
                let Some(response) = response else {
                    continue;
                };
                let (response, provenance, reservation, attempt) = response.into_parts();
                match response {
                    PeerResponse::Success { body } => {
                        work_budget.record_wire_bytes(body.len())?;
                        let response =
                            match DepositStateExportHeadResponse::from_bytes(request, &body) {
                                Ok(response) => response,
                                Err(error) => {
                                    tracing::warn!(
                                        %source,
                                        %error,
                                        "certified export source returned an invalid Head response"
                                    );
                                    continue;
                                }
                            };
                        if let Err(error) = self
                            .server
                            .accept_deposit_state_export_head(context, request, &response)
                            .await
                        {
                            tracing::warn!(
                                %source,
                                %error,
                                "certified export source returned a Head without valid archived authority"
                            );
                            continue;
                        }
                        self.retire_state_transfer_intent_after_authenticated_response(reservation)
                            .await?;
                        self.clear_certified_deposit_source_progress().await;
                        return Ok(CertifiedDepositTransferDisposition::Reload);
                    }
                    PeerResponse::Rejected { code, retryable, message } => {
                        self.handle_authenticated_state_transfer_rejection(
                            reservation,
                            attempt.as_ref(),
                            provenance,
                        )
                        .await?;
                        tracing::debug!(
                            %source,
                            ?code,
                            retryable,
                            %message,
                            "certified export Head protocol work retained after peer rejection"
                        );
                    }
                }
            }

            if let Some(checkpoint) =
                self.server.deposit_state_export_installing_checkpoint(context).await?
            {
                let stalled = self
                    .certified_deposit_source_stalled(
                        checkpoint.context(),
                        checkpoint.source(),
                        CertifiedDepositSourcePosition::Installing {
                            request: checkpoint.request_digest(),
                        },
                    )
                    .await;
                if stalled {
                    self.server
                        .fail_installing_deposit_state_export_source(context, checkpoint)
                        .await?;
                    self.clear_certified_deposit_source_progress().await;
                    return Ok(CertifiedDepositTransferDisposition::Reload);
                }
            } else {
                // No source has won the durable selection race yet.
                self.clear_certified_deposit_source_progress().await;
            }
            return Ok(CertifiedDepositTransferDisposition::Pending);
        }

        loop {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= tick_deadline {
                return Ok(CertifiedDepositTransferDisposition::Pending);
            }
            let Some(request) = self.server.pending_deposit_state_export_objects(context).await?
            else {
                if self.server.promote_completed_deposit_state_export(context).await? {
                    self.clear_certified_deposit_source_progress().await;
                    return Ok(CertifiedDepositTransferDisposition::Reload);
                }
                if self.server.deposit_state_export_download_checkpoint(context).await?.is_some()
                    || self
                        .server
                        .deposit_state_export_installing_checkpoint(context)
                        .await?
                        .is_some()
                {
                    return Ok(CertifiedDepositTransferDisposition::Pending);
                }
                self.clear_certified_deposit_source_progress().await;
                return Ok(CertifiedDepositTransferDisposition::Idle);
            };
            let source = request.source();
            let checkpoint =
                self.server
                    .deposit_state_export_download_checkpoint(context)
                    .await?
                    .context("certified export object request has no durable checkpoint")?;
            let checkpoint_digest = checkpoint.digest()?;
            if self
                .certified_deposit_source_stalled(
                    request.context(),
                    source,
                    CertifiedDepositSourcePosition::Active {
                        revision: checkpoint.revision(),
                        checkpoint: checkpoint_digest,
                    },
                )
                .await
            {
                self.server.fail_active_deposit_state_export_source(context, &checkpoint).await?;
                self.clear_certified_deposit_source_progress().await;
                return Ok(CertifiedDepositTransferDisposition::Reload);
            }

            let request_body = request.to_bytes()?;
            if !work_budget.may_request(request_body.len()) {
                return Ok(CertifiedDepositTransferDisposition::Pending);
            }
            work_budget.record_request(request_body.len())?;
            let response = self
                .deposit_state_transfer_rpc(
                    source,
                    DepositOperation::ExportObjects,
                    request_body,
                    tick_deadline,
                    StateTransferReservationScope::ExportObjects(context.context().digest()),
                )
                .await?;
            let Some(response) = response else {
                return Ok(CertifiedDepositTransferDisposition::Pending);
            };
            let (response, _provenance, _reservation, _attempt) = response.into_parts();
            let body = match response {
                PeerResponse::Success { body } => body,
                PeerResponse::Rejected { code, retryable, message } => {
                    tracing::debug!(
                        %source,
                        ?code,
                        retryable,
                        %message,
                        "certified export Objects retained after peer rejection"
                    );
                    return Ok(CertifiedDepositTransferDisposition::Pending);
                }
            };
            work_budget.record_wire_bytes(body.len())?;
            let response = match DepositStateExportObjectsResponse::from_bytes(&request, &body) {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        %source,
                        %error,
                        "certified export source returned an invalid Objects response"
                    );
                    return Ok(CertifiedDepositTransferDisposition::Pending);
                }
            };
            work_budget.record_object_page(response.objects().len(), 0)?;
            if let Err(error) =
                self.server.merge_deposit_state_export_objects(context, &request, &response).await
            {
                tracing::warn!(
                    %source,
                    %error,
                    "certified export object page failed authenticated merge"
                );
                return Ok(CertifiedDepositTransferDisposition::Pending);
            }
            if work_budget.pages % DEPOSIT_SYNC_COOPERATIVE_YIELD_PAGES == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    async fn progress_deposit_state_import_transport(
        self: &Arc<Self>,
        mut tick_deadline: Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<(CertifiedDepositTransferDisposition, bool)> {
        let census_watermark = self.state_transfer_census_watermark();
        let census_started = Instant::now();
        let census_result = self.server.pending_deposit_state_import_work().await;
        tick_deadline = self.exclude_local_deposit_sync_work(tick_deadline, census_started)?;
        let census = match census_result {
            Ok(census) => census,
            Err(error)
                if matches!(
                    error.downcast_ref::<DepositServiceError>(),
                    Some(
                        DepositServiceError::NotInitialized
                            | DepositServiceError::ColdImportAwaitingCertificate
                    )
                ) =>
            {
                return Ok((CertifiedDepositTransferDisposition::Idle, false));
            }
            Err(error) => return Err(error),
        };
        let target_epoch = census.target_epoch();
        let finalized = census.finalized();
        let mut pending = census.into_pending();
        let reconciliation_started = Instant::now();
        self.reconcile_current_state_import_reservations(&pending, target_epoch, census_watermark)
            .await?;
        tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, reconciliation_started)?;
        pending.retain(|locator| state_import_work_is_causal(locator.kind()));
        if pending.is_empty() {
            return Ok((CertifiedDepositTransferDisposition::Idle, finalized));
        }
        let start =
            self.deposit_state_transfer_cursor.fetch_add(1, Ordering::Relaxed) % pending.len();
        pending.rotate_left(start);

        for locator in pending {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= tick_deadline {
                return Ok((CertifiedDepositTransferDisposition::Pending, false));
            }
            let reconstruction_started = Instant::now();
            let reconstructed =
                match self.server.reconstruct_deposit_state_import_work(locator).await {
                    Ok(reconstructed) => reconstructed,
                    Err(error) if state_import_work_needs_reload(&error) => {
                        return Ok((CertifiedDepositTransferDisposition::Reload, false));
                    }
                    Err(error) => return Err(error),
                };
            tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, reconstruction_started)?;
            let route = reconstructed.route();
            let operation = route.operation();
            let recipient = route.recipient();
            let scope = match operation {
                DepositOperation::StateImportedAck => {
                    StateTransferReservationScope::StateImportAcknowledgement(
                        locator.target_epoch(),
                    )
                }
                DepositOperation::StateImportedCertificate => {
                    StateTransferReservationScope::StateImportCertificate(locator.target_epoch())
                }
                _ => anyhow::bail!("state-import journal reconstructed a non-import operation"),
            };
            let body = reconstructed.body().to_vec();
            if !work_budget.may_request(body.len()) {
                return Ok((CertifiedDepositTransferDisposition::Pending, false));
            }
            work_budget.record_request(body.len())?;
            let local_delivery_started = (recipient == self.server.party_id()).then(Instant::now);
            let response = self
                .deposit_state_transfer_rpc(recipient, operation, body, tick_deadline, scope)
                .await?;
            if let Some(local_delivery_started) = local_delivery_started {
                tick_deadline =
                    self.exclude_local_deposit_sync_work(tick_deadline, local_delivery_started)?;
            }
            let Some(response) = response else {
                continue;
            };
            let (response, provenance, reservation, attempt) = response.into_parts();
            match response {
                PeerResponse::Success { body } => {
                    work_budget.record_wire_bytes(body.len())?;
                    let acknowledgement_started = Instant::now();
                    let acknowledgement = self
                        .server
                        .acknowledge_deposit_state_import_work(locator, recipient, &body)
                        .await;
                    tick_deadline = self
                        .exclude_local_deposit_sync_work(tick_deadline, acknowledgement_started)?;
                    if let Err(error) = acknowledgement {
                        if matches!(
                            error.downcast_ref::<DepositServiceError>(),
                            Some(
                                DepositServiceError::InvalidPeerMessage
                                    | DepositServiceError::StateTransferWire(_)
                            )
                        ) {
                            tracing::warn!(
                                %recipient,
                                ?operation,
                                %error,
                                "StateImported peer returned an invalid typed receipt; retaining work"
                            );
                            continue;
                        }
                        if state_import_work_needs_reload(&error) {
                            return Ok((CertifiedDepositTransferDisposition::Reload, false));
                        }
                        return Err(error);
                    }
                    self.retire_state_transfer_intent_after_authenticated_response(reservation)
                        .await?;
                }
                PeerResponse::Rejected { code, retryable, message } => {
                    self.handle_authenticated_state_transfer_rejection(
                        reservation,
                        attempt.as_ref(),
                        provenance,
                    )
                    .await?;
                    tracing::debug!(
                        %recipient,
                        ?operation,
                        ?code,
                        retryable,
                        %message,
                        "StateImported protocol work retained after peer rejection"
                    );
                }
            }
        }

        let census = self.server.pending_deposit_state_import_work().await?;
        let finalized = census.finalized();
        let pending = census.into_pending();
        if !state_import_phase_blocks_ordinary_sync(pending.iter().map(|locator| locator.kind())) {
            Ok((CertifiedDepositTransferDisposition::Idle, finalized))
        } else {
            Ok((CertifiedDepositTransferDisposition::Pending, false))
        }
    }

    /// Retry at most one post-freeze export vote or certificate without owning the current sync
    /// disposition. The exact locator remains durable until its typed receipt is committed.
    async fn progress_background_deposit_state_export_fanout(
        self: &Arc<Self>,
        network_deadline: &mut Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<bool> {
        let pending_started = Instant::now();
        let census_watermark = self.state_transfer_census_watermark();
        let pending_result = self.server.pending_deposit_state_export_seal_work().await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, pending_started)?;
        let mut pending = match pending_result {
            Ok(pending) => pending,
            Err(error)
                if matches!(
                    error.downcast_ref::<DepositServiceError>(),
                    Some(
                        DepositServiceError::NotInitialized
                            | DepositServiceError::ColdImportAwaitingCertificate
                    )
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let reconciliation_started = Instant::now();
        self.reconcile_current_export_seal_reservations(&pending, census_watermark).await?;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, reconciliation_started)?;
        let freeze_started = Instant::now();
        let freeze_pending = self.server.deposit_state_export_freeze_pending().await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, freeze_started)?;
        if freeze_pending? {
            return Ok(false);
        }
        pending.retain(|locator| !export_seal_work_is_causal(false, locator.kind()));
        if pending.is_empty() {
            return Ok(false);
        }
        let start = deposit_state_transfer_background_start(
            &self.deposit_state_transfer_background_export_cursor,
            pending.len(),
        );
        pending.rotate_left(start);
        let locator = pending[0];
        if self.shutdown.load(Ordering::Acquire) || Instant::now() >= *network_deadline {
            return Ok(false);
        }
        let reconstruction_started = Instant::now();
        let reconstructed = self.server.reconstruct_deposit_state_export_seal_work(locator).await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, reconstruction_started)?;
        let reconstructed = match reconstructed {
            Ok(work) => work,
            Err(error) if completed_export_work(&error) => return Ok(true),
            Err(error) => return Err(error),
        };
        let route = reconstructed.route();
        let operation = route.operation();
        let recipient = route.recipient();
        let scope = StateTransferReservationScope::ExportSeal(locator.target_epoch());
        let body = reconstructed.body().to_vec();
        if !work_budget.may_request(body.len()) {
            return Ok(false);
        }
        work_budget.record_request(body.len())?;
        let local_delivery_started = (recipient == self.server.party_id()).then(Instant::now);
        let response = self
            .deposit_state_transfer_rpc(recipient, operation, body, *network_deadline, scope)
            .await?;
        if let Some(local_delivery_started) = local_delivery_started {
            *network_deadline =
                self.exclude_local_deposit_sync_work(*network_deadline, local_delivery_started)?;
        }
        let Some(response) = response else {
            return Ok(true);
        };
        let (response, provenance, reservation, attempt) = response.into_parts();
        match response {
            PeerResponse::Success { body } => {
                work_budget.record_wire_bytes(body.len())?;
                let acknowledgement_started = Instant::now();
                let acknowledgement = self
                    .server
                    .acknowledge_deposit_state_export_seal_work(locator, recipient, &body)
                    .await;
                *network_deadline = self
                    .exclude_local_deposit_sync_work(*network_deadline, acknowledgement_started)?;
                if let Err(error) = acknowledgement {
                    if completed_export_work(&error) {
                        return Ok(true);
                    }
                    if matches!(
                        error.downcast_ref::<DepositServiceError>(),
                        Some(
                            DepositServiceError::InvalidPeerMessage
                                | DepositServiceError::StateTransferWire(_)
                        )
                    ) {
                        tracing::warn!(
                            %recipient,
                            %error,
                            "background export-certificate peer returned an invalid typed receipt"
                        );
                        return Ok(true);
                    }
                    return Err(error);
                }
                self.retire_state_transfer_intent_after_authenticated_response(reservation).await?;
            }
            PeerResponse::Rejected { code, retryable, message } => {
                self.handle_authenticated_state_transfer_rejection(
                    reservation,
                    attempt.as_ref(),
                    provenance,
                )
                .await?;
                tracing::debug!(
                    %recipient,
                    ?code,
                    retryable,
                    %message,
                    "background export seal protocol work retained after peer rejection"
                );
            }
        }
        Ok(true)
    }

    /// Retry at most one post-finalization StateImported certificate without delaying ordinary
    /// moving-tip synchronization.
    async fn progress_background_state_imported_certificate(
        self: &Arc<Self>,
        network_deadline: &mut Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<bool> {
        let pending_started = Instant::now();
        let census_watermark = self.state_transfer_census_watermark();
        let pending_result = self.server.pending_deposit_state_import_work().await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, pending_started)?;
        let census = match pending_result {
            Ok(census) => census,
            Err(error)
                if matches!(
                    error.downcast_ref::<DepositServiceError>(),
                    Some(
                        DepositServiceError::NotInitialized
                            | DepositServiceError::ColdImportAwaitingCertificate
                    )
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let target_epoch = census.target_epoch();
        let mut pending = census.into_pending();
        let reconciliation_started = Instant::now();
        self.reconcile_current_state_import_reservations(&pending, target_epoch, census_watermark)
            .await?;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, reconciliation_started)?;
        pending.retain(|locator| {
            matches!(locator.kind(), DepositStateImportWorkKind::CertificateDelivery)
        });
        if pending.is_empty() {
            return Ok(false);
        }
        let start = deposit_state_transfer_background_start(
            &self.deposit_state_transfer_background_import_cursor,
            pending.len(),
        );
        pending.rotate_left(start);
        let locator = pending[0];
        if self.shutdown.load(Ordering::Acquire) || Instant::now() >= *network_deadline {
            return Ok(false);
        }
        let reconstruction_started = Instant::now();
        let reconstructed = self.server.reconstruct_deposit_state_import_work(locator).await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, reconstruction_started)?;
        let reconstructed = match reconstructed {
            Ok(reconstructed) => reconstructed,
            Err(error) if state_import_work_needs_reload(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        let route = reconstructed.route();
        let operation = route.operation();
        let recipient = route.recipient();
        let scope = StateTransferReservationScope::StateImportCertificate(locator.target_epoch());
        let body = reconstructed.body().to_vec();
        if !work_budget.may_request(body.len()) {
            return Ok(false);
        }
        work_budget.record_request(body.len())?;
        let local_delivery_started = (recipient == self.server.party_id()).then(Instant::now);
        let response = self
            .deposit_state_transfer_rpc(recipient, operation, body, *network_deadline, scope)
            .await?;
        if let Some(local_delivery_started) = local_delivery_started {
            *network_deadline =
                self.exclude_local_deposit_sync_work(*network_deadline, local_delivery_started)?;
        }
        let Some(response) = response else {
            return Ok(true);
        };
        let (response, provenance, reservation, attempt) = response.into_parts();
        match response {
            PeerResponse::Success { body } => {
                work_budget.record_wire_bytes(body.len())?;
                let acknowledgement_started = Instant::now();
                let acknowledgement = self
                    .server
                    .acknowledge_deposit_state_import_work(locator, recipient, &body)
                    .await;
                *network_deadline = self
                    .exclude_local_deposit_sync_work(*network_deadline, acknowledgement_started)?;
                if let Err(error) = acknowledgement {
                    if matches!(
                        error.downcast_ref::<DepositServiceError>(),
                        Some(
                            DepositServiceError::InvalidPeerMessage
                                | DepositServiceError::StateTransferWire(_)
                        )
                    ) || state_import_work_needs_reload(&error)
                    {
                        tracing::warn!(
                            %recipient,
                            %error,
                            "background StateImported certificate receipt raced durable authority"
                        );
                        return Ok(true);
                    }
                    return Err(error);
                }
                self.retire_state_transfer_intent_after_authenticated_response(reservation).await?;
            }
            PeerResponse::Rejected { code, retryable, message } => {
                self.handle_authenticated_state_transfer_rejection(
                    reservation,
                    attempt.as_ref(),
                    provenance,
                )
                .await?;
                tracing::debug!(
                    %recipient,
                    ?code,
                    retryable,
                    %message,
                    "background StateImported certificate protocol work retained after peer rejection"
                );
            }
        }
        Ok(true)
    }

    /// Give post-freeze export and terminal import fanout one bounded background turn.
    ///
    /// The lane cursor advances before any network wait, so one silent export recipient cannot
    /// also starve StateImported fanout on the next staggered tick.
    async fn progress_current_deposit_state_transfer_background(
        self: &Arc<Self>,
        network_deadline: &mut Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<()> {
        let preferred =
            if self.deposit_state_transfer_background_lane_cursor.fetch_add(1, Ordering::Relaxed)
                % 2
                == 0
            {
                DepositStateTransferBackgroundLane::ExportSealFanout
            } else {
                DepositStateTransferBackgroundLane::ImportedCertificate
            };
        for lane in [preferred, preferred.other()] {
            let attempted = match lane {
                DepositStateTransferBackgroundLane::ExportSealFanout => {
                    self.progress_background_deposit_state_export_fanout(
                        network_deadline,
                        work_budget,
                    )
                    .await?
                }
                DepositStateTransferBackgroundLane::ImportedCertificate => {
                    self.progress_background_state_imported_certificate(
                        network_deadline,
                        work_budget,
                    )
                    .await?
                }
            };
            if attempted || Instant::now() >= *network_deadline {
                break;
            }
        }
        Ok(())
    }

    /// Retry one exact historical installed-certificate journal without affecting current-sync
    /// disposition. A successful receipt keeps the selected epoch hot for the next recipient;
    /// an idle or unreachable epoch advances the O(1) round-robin probe.
    async fn progress_historical_deposit_state_import_transport(
        self: &Arc<Self>,
        network_deadline: &mut Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<()> {
        let active_epoch_started = Instant::now();
        let active_epoch_result = self.server.deposit_state_import_active_epoch().await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, active_epoch_started)?;
        let active_epoch = match active_epoch_result {
            Ok(Some(epoch)) => epoch,
            Ok(None) => return Ok(()),
            Err(error)
                if matches!(
                    error.downcast_ref::<DepositServiceError>(),
                    Some(
                        DepositServiceError::NotInitialized
                            | DepositServiceError::ColdImportAwaitingCertificate
                    )
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let cursor = self.historical_state_import_epoch_cursor.load(Ordering::Relaxed);
        let ordinary_epoch = rotating_historical_state_import_epoch(active_epoch, cursor);
        let ready_reserved =
            self.ready_historical_state_import_reservation_epochs(active_epoch).await;
        let reserved_cursor =
            self.historical_state_import_reserved_epoch_cursor.load(Ordering::Acquire);
        let reserved_epoch = historical_reserved_epoch_after(&ready_reserved, reserved_cursor);
        if let Some(epoch) = reserved_epoch {
            self.historical_state_import_reserved_epoch_cursor.store(epoch, Ordering::Release);
        }
        let Some(target_epoch) = reserved_epoch.or(ordinary_epoch) else {
            return Ok(());
        };
        let epoch_probe =
            HistoricalStateImportEpochProbe::new(&self.historical_state_import_epoch_cursor);
        let pending_started = Instant::now();
        let census_watermark = self.state_transfer_census_watermark();
        let pending_result = self
            .server
            .pending_historical_deposit_state_import_certificate_work(target_epoch)
            .await;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, pending_started)?;
        let mut pending = match pending_result {
            Ok(pending) => pending,
            Err(error)
                if matches!(
                    error.downcast_ref::<DepositServiceError>(),
                    Some(
                        DepositServiceError::NotInitialized
                            | DepositServiceError::ColdImportAwaitingCertificate
                            | DepositServiceError::InvalidProtocolState
                            | DepositServiceError::StorageRevisionMismatch
                    )
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let reconciliation_started = Instant::now();
        self.reconcile_historical_state_import_reservations(
            target_epoch,
            &pending,
            census_watermark,
        )
        .await?;
        *network_deadline =
            self.exclude_local_deposit_sync_work(*network_deadline, reconciliation_started)?;
        if pending.is_empty() {
            return Ok(());
        }
        let start = self.historical_state_import_work_cursor.fetch_add(1, Ordering::Relaxed)
            % pending.len();
        pending.rotate_left(start);

        for locator in pending {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= *network_deadline {
                return Ok(());
            }
            let reconstruction_started = Instant::now();
            let reconstruction = self
                .server
                .reconstruct_historical_deposit_state_import_certificate_work(locator)
                .await;
            *network_deadline =
                self.exclude_local_deposit_sync_work(*network_deadline, reconstruction_started)?;
            let reconstructed = match reconstruction {
                Ok(reconstructed) => reconstructed,
                Err(error)
                    if matches!(
                        error.downcast_ref::<DepositServiceError>(),
                        Some(
                            DepositServiceError::InvalidProtocolState
                                | DepositServiceError::StorageRevisionMismatch
                        )
                    ) =>
                {
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let route = reconstructed.route();
            let operation = route.operation();
            let recipient = route.recipient();
            anyhow::ensure!(
                operation == DepositOperation::StateImportedCertificate,
                "historical state-import journal reconstructed non-certificate work"
            );
            let body = reconstructed.body().to_vec();
            if !work_budget.may_request(body.len()) {
                return Ok(());
            }
            work_budget.record_request(body.len())?;
            let local_delivery_started = (recipient == self.server.party_id()).then(Instant::now);
            let response = self
                .deposit_state_transfer_rpc(
                    recipient,
                    operation,
                    body,
                    *network_deadline,
                    StateTransferReservationScope::StateImportCertificate(target_epoch),
                )
                .await?;
            if let Some(local_delivery_started) = local_delivery_started {
                *network_deadline = self
                    .exclude_local_deposit_sync_work(*network_deadline, local_delivery_started)?;
            }
            let Some(response) = response else {
                continue;
            };
            let (response, provenance, reservation, attempt) = response.into_parts();
            match response {
                PeerResponse::Success { body } => {
                    work_budget.record_wire_bytes(body.len())?;
                    let acknowledgement_started = Instant::now();
                    let acknowledgement = self
                        .server
                        .acknowledge_historical_deposit_state_import_certificate_work(
                            locator, recipient, &body,
                        )
                        .await;
                    *network_deadline = self.exclude_local_deposit_sync_work(
                        *network_deadline,
                        acknowledgement_started,
                    )?;
                    if let Err(error) = acknowledgement {
                        if matches!(
                            error.downcast_ref::<DepositServiceError>(),
                            Some(
                                DepositServiceError::InvalidPeerMessage
                                    | DepositServiceError::StateTransferWire(_)
                            )
                        ) {
                            tracing::warn!(
                                %recipient,
                                %target_epoch,
                                %error,
                                "historical StateImported peer returned an invalid typed receipt"
                            );
                            continue;
                        }
                        if matches!(
                            error.downcast_ref::<DepositServiceError>(),
                            Some(
                                DepositServiceError::InvalidProtocolState
                                    | DepositServiceError::StorageRevisionMismatch
                            )
                        ) {
                            return Ok(());
                        }
                        return Err(error);
                    }
                    self.retire_state_transfer_intent_after_authenticated_response(reservation)
                        .await?;
                    // Keep this epoch selected while it is making progress so a large committee
                    // does not wait for a complete history rotation between successful receipts.
                    epoch_probe.receipt_committed();
                    return Ok(());
                }
                PeerResponse::Rejected { code, retryable, message } => {
                    self.handle_authenticated_state_transfer_rejection(
                        reservation,
                        attempt.as_ref(),
                        provenance,
                    )
                    .await?;
                    tracing::debug!(
                        %recipient,
                        %target_epoch,
                        ?code,
                        retryable,
                        %message,
                        "historical StateImported certificate protocol work retained after peer rejection"
                    );
                }
            }
        }

        // Dropping `epoch_probe` rotates epochs because no exact receipt was committed.
        Ok(())
    }

    async fn progress_certified_deposit_state_transfer(
        self: &Arc<Self>,
        mut tick_deadline: Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<CertifiedDepositTransferDisposition> {
        let head_census_started = Instant::now();
        let census_watermark = self.state_transfer_census_watermark();
        if self
            .state_transfer_census_recipients(census_watermark)
            .await
            .keys()
            .any(|scope| matches!(scope, StateTransferReservationScope::ExportHead(_)))
            && let Some(context) =
                self.server.certified_deposit_state_transfer_work_context().await?
        {
            let heads = self.server.pending_deposit_state_export_heads(context).await?;
            self.reconcile_export_head_reservations(context.context(), &heads, census_watermark)
                .await?;
        }
        tick_deadline = self.exclude_local_deposit_sync_work(tick_deadline, head_census_started)?;
        match self
            .progress_deposit_state_export_seal(&mut tick_deadline, work_budget)
            .await
            .context("export seal progress")?
        {
            CertifiedDepositTransferDisposition::Idle => {}
            disposition => {
                // Seal work owns this tick, so an already selected download source had no fair
                // opportunity to make progress. Grant it a fresh bounded liveness window once the
                // causally prior journal drains.
                self.clear_certified_deposit_source_progress().await;
                return Ok(disposition);
            }
        }
        let context_started = Instant::now();
        let context = self
            .server
            .certified_deposit_state_transfer_work_context()
            .await
            .context("certified transfer context")?;
        tick_deadline = self.exclude_local_deposit_sync_work(tick_deadline, context_started)?;
        let Some(context) = context else {
            self.clear_certified_deposit_source_progress().await;
            return Ok(CertifiedDepositTransferDisposition::Idle);
        };
        let transfer = context.context();
        // Once an export is installed, its target ACKs are causal work. Competing source
        // archives must not keep those ACKs behind another, unnecessary download.
        let import_started = Instant::now();
        let import_requests_before = work_budget.requests;
        let (import_disposition, import_finalized) = self
            .progress_deposit_state_import_transport(tick_deadline, work_budget)
            .await
            .context("installed export acknowledgement progress")?;
        match import_disposition {
            CertifiedDepositTransferDisposition::Idle => {
                if work_budget.requests == import_requests_before {
                    tick_deadline =
                        self.exclude_local_deposit_sync_work(tick_deadline, import_started)?;
                }
            }
            disposition => {
                self.clear_certified_deposit_source_progress().await;
                return Ok(disposition);
            }
        }
        let ordinary_context = DepositSyncContext::new(transfer.network(), transfer.wallet())?;
        let ordinary_release_barriers =
            self.drain_deposit_sync_releases(ordinary_context, tick_deadline, work_budget).await?;
        let _ =
            self.drain_deposit_state_export_releases(context, tick_deadline, work_budget).await?;
        // Finality comes from the authenticated installed journal, wallet certificate, and
        // retention tombstone, never from an empty ACK queue. Competing exports are obsolete.
        if import_finalized {
            self.clear_certified_deposit_source_progress().await;
            return Ok(CertifiedDepositTransferDisposition::Idle);
        }
        let disposition = self
            .progress_deposit_state_export_download(
                context,
                &ordinary_release_barriers,
                tick_deadline,
                work_budget,
            )
            .await
            .context("certified export download")?;
        let _ =
            self.drain_deposit_state_export_releases(context, tick_deadline, work_budget).await?;
        match disposition {
            CertifiedDepositTransferDisposition::Idle => self
                .progress_deposit_state_import_transport(tick_deadline, work_budget)
                .await
                .map(|(disposition, _)| disposition)
                .context("certified state import"),
            disposition => Ok(disposition),
        }
    }

    /// Drain the predecessor export-seal journal before ordinary moving-tip synchronization.
    ///
    /// Only small durable locators survive a network wait. Request bodies and transition
    /// authority are reconstructed immediately before dispatch, and the typed response is
    /// revalidated against freshly reconstructed authority before its locator can be retired.
    async fn progress_deposit_state_export_seal(
        self: &Arc<Self>,
        tick_deadline: &mut Instant,
        work_budget: &mut DepositSyncTickWork,
    ) -> anyhow::Result<CertifiedDepositTransferDisposition> {
        let census_watermark = self.state_transfer_census_watermark();
        let pending_started = Instant::now();
        let pending_result = self.server.pending_deposit_state_export_seal_work().await;
        *tick_deadline = self.exclude_local_deposit_sync_work(*tick_deadline, pending_started)?;
        let mut pending = match pending_result {
            Ok(pending) => pending,
            Err(error)
                if matches!(
                    error.downcast_ref::<DepositServiceError>(),
                    Some(
                        DepositServiceError::NotInitialized
                            | DepositServiceError::ColdImportAwaitingCertificate
                    )
                ) =>
            {
                // A target-only cold import owns no predecessor seal outbox. Its durable head
                // intent is progressed by the certified download phase.
                return Ok(CertifiedDepositTransferDisposition::Idle);
            }
            Err(error) => return Err(error),
        };
        let reconciliation_started = Instant::now();
        self.reconcile_current_export_seal_reservations(&pending, census_watermark).await?;
        *tick_deadline =
            self.exclude_local_deposit_sync_work(*tick_deadline, reconciliation_started)?;
        let freeze_started = Instant::now();
        let local_freeze_pending = self.server.deposit_state_export_freeze_pending().await?;
        *tick_deadline = self.exclude_local_deposit_sync_work(*tick_deadline, freeze_started)?;
        pending.retain(|locator| export_seal_work_is_causal(local_freeze_pending, locator.kind()));
        if pending.is_empty() {
            return Ok(if local_freeze_pending {
                CertifiedDepositTransferDisposition::Pending
            } else {
                CertifiedDepositTransferDisposition::Idle
            });
        }
        let start =
            self.deposit_state_transfer_cursor.fetch_add(1, Ordering::Relaxed) % pending.len();
        pending.rotate_left(start);

        for locator in pending {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= *tick_deadline {
                return Ok(CertifiedDepositTransferDisposition::Pending);
            }
            let reconstruction_started = Instant::now();
            let reconstructed =
                self.server.reconstruct_deposit_state_export_seal_work(locator).await;
            *tick_deadline =
                self.exclude_local_deposit_sync_work(*tick_deadline, reconstruction_started)?;
            let reconstructed = match reconstructed {
                Ok(work) => work,
                Err(error) if completed_export_work(&error) => continue,
                Err(error) => return Err(error),
            };
            let route = reconstructed.route();
            let operation = route.operation();
            let recipient = route.recipient();
            let scope = StateTransferReservationScope::ExportSeal(locator.target_epoch());
            let body = reconstructed.body().to_vec();
            if !work_budget.may_request(body.len()) {
                return Ok(CertifiedDepositTransferDisposition::Pending);
            }
            work_budget.record_request(body.len())?;

            let local_delivery_started = (recipient == self.server.party_id()).then(Instant::now);
            let response = self
                .deposit_state_transfer_rpc(recipient, operation, body, *tick_deadline, scope)
                .await?;
            if let Some(local_delivery_started) = local_delivery_started {
                *tick_deadline =
                    self.exclude_local_deposit_sync_work(*tick_deadline, local_delivery_started)?;
            }
            let Some(response) = response else {
                continue;
            };
            let (response, provenance, reservation, attempt) = response.into_parts();
            match response {
                PeerResponse::Success { body } => {
                    work_budget.record_wire_bytes(body.len())?;
                    let acknowledgement_started = Instant::now();
                    let acknowledgement = self
                        .server
                        .acknowledge_deposit_state_export_seal_work(locator, recipient, &body)
                        .await;
                    *tick_deadline = self
                        .exclude_local_deposit_sync_work(*tick_deadline, acknowledgement_started)?;
                    if let Err(error) = acknowledgement {
                        if completed_export_work(&error) {
                            continue;
                        }
                        if matches!(
                            error.downcast_ref::<DepositServiceError>(),
                            Some(
                                DepositServiceError::InvalidPeerMessage
                                    | DepositServiceError::StateTransferWire(_)
                            )
                        ) {
                            tracing::warn!(
                                %recipient,
                                ?operation,
                                %error,
                                "certified deposit peer returned an invalid typed receipt; retaining work"
                            );
                            continue;
                        }
                        return Err(error);
                    }
                    // Source-request ACK validation intentionally leaves its protocol locator
                    // pending until the receiver's separately durable vote arrives. It still
                    // resolves this exact transport execution, so release the recipient lane.
                    self.retire_state_transfer_intent_after_authenticated_response(reservation)
                        .await?;
                    if operation == DepositOperation::PostHandoffExportSealCertificate {
                        // Local installation or a certificate-fanout CAS can change the next
                        // reconstructible authority phase. Never retain the old process token.
                        return Ok(CertifiedDepositTransferDisposition::Reload);
                    }
                }
                PeerResponse::Rejected { code, retryable, message } => {
                    // Rejection never tombstones protocol work. It retires a fresh attempt's cut,
                    // but cannot resolve an earlier ambiguous execution merely because its exact
                    // retry was rejected Busy/InFlight or by the reducer.
                    self.handle_authenticated_state_transfer_rejection(
                        reservation,
                        attempt.as_ref(),
                        provenance,
                    )
                    .await?;
                    tracing::debug!(
                        %recipient,
                        ?operation,
                        ?code,
                        retryable,
                        %message,
                        "certified deposit state-transfer protocol work retained after peer rejection"
                    );
                }
            }
        }

        let pending = self.server.pending_deposit_state_export_seal_work().await?;
        let local_freeze_pending = self.server.deposit_state_export_freeze_pending().await?;
        if !export_seal_phase_blocks_target_import(
            local_freeze_pending,
            pending.iter().map(|locator| locator.kind()),
        ) {
            Ok(CertifiedDepositTransferDisposition::Idle)
        } else {
            Ok(CertifiedDepositTransferDisposition::Pending)
        }
    }

    fn exclude_local_deposit_sync_work(
        &self,
        tick_deadline: Instant,
        local_work_started: Instant,
    ) -> anyhow::Result<Instant> {
        shift_deposit_sync_deadline_past_local_work(
            tick_deadline,
            local_work_started,
            Instant::now(),
        )
        .context("compact deposit network-work deadline exhausted")
    }

    async fn synchronize_deposit_state(self: &Arc<Self>) -> anyhow::Result<()> {
        let mut tick_deadline = Instant::now()
            .checked_add(self.config.deposit_sync_tick_timeout)
            .context("compact deposit tick deadline exhausted")?;
        let mut work = DepositSyncTickWork::default();
        let certified_preflight_started = Instant::now();
        let certified_requests_before = work.requests;
        match self.progress_certified_deposit_state_transfer(tick_deadline, &mut work).await? {
            CertifiedDepositTransferDisposition::Idle => {
                if work.requests == certified_requests_before {
                    tick_deadline = self.exclude_local_deposit_sync_work(
                        tick_deadline,
                        certified_preflight_started,
                    )?;
                }
            }
            CertifiedDepositTransferDisposition::Pending
            | CertifiedDepositTransferDisposition::Reload => return Ok(()),
        }
        let source_preflight_started = Instant::now();
        let Some((mut sources, context)) = Box::pin(self.server.deposit_sync_sources()).await?
        else {
            return Ok(());
        };
        tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, source_preflight_started)?;
        let _ = self.drain_deposit_sync_releases(context, tick_deadline, &mut work).await?;
        let admission_preflight_started = Instant::now();
        let local = Box::pin(self.server.local_deposit_sync_advertisement(context)).await?;
        let discarded = self.server.deposit_sync_spools().discard_stale_against(&local).await?;
        if discarded != 0 {
            self.server.reconcile_deposit_sync_lifetimes_after_stage_mutation().await?;
            tracing::info!(
                party = %self.server.party_id(),
                discarded,
                "removed state-dominated durable deposit sync candidates"
            );
        }
        if let Some(admission) =
            self.server.resume_deposit_sync_exact_admission(context, &local).await?
        {
            tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, admission_preflight_started)?;
            tracing::trace!(
                party = %self.server.party_id(),
                "resuming durable exact compact deposit admission"
            );
            match self
                .progress_deposit_sync_admission(admission, None, tick_deadline, &mut work)
                .await?
            {
                DepositSyncSourceOutcome::Adopted => {
                    tracing::info!(
                        party = %self.server.party_id(),
                        "atomically adopted restart-resumed exact compact deposit checkpoint"
                    );
                }
                DepositSyncSourceOutcome::UnavailableOrStale
                | DepositSyncSourceOutcome::PendingSupport
                | DepositSyncSourceOutcome::Progressed
                | DepositSyncSourceOutcome::Settled => {}
            }
            return Ok(());
        }
        if let Some(admission) =
            self.server.resume_deposit_sync_prefix_admission(context, &local).await?
        {
            tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, admission_preflight_started)?;
            match self
                .progress_deposit_sync_admission(admission, None, tick_deadline, &mut work)
                .await?
            {
                DepositSyncSourceOutcome::Adopted => {
                    tracing::info!(
                        party = %self.server.party_id(),
                        "atomically adopted stable-prefix compact deposit checkpoint"
                    );
                }
                DepositSyncSourceOutcome::UnavailableOrStale
                | DepositSyncSourceOutcome::PendingSupport
                | DepositSyncSourceOutcome::Progressed
                | DepositSyncSourceOutcome::Settled => {}
            }
            return Ok(());
        }
        if let Some(prefix_work) =
            self.server.deposit_sync_prefix_support_work(context, &local).await?
        {
            tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, admission_preflight_started)?;
            match self
                .progress_deposit_prefix_collection(prefix_work, tick_deadline, &mut work)
                .await?
            {
                DepositSyncSourceOutcome::Adopted => {
                    tracing::info!(
                        party = %self.server.party_id(),
                        "atomically adopted newly certified stable-prefix compact deposit checkpoint"
                    );
                }
                DepositSyncSourceOutcome::UnavailableOrStale
                | DepositSyncSourceOutcome::PendingSupport
                | DepositSyncSourceOutcome::Progressed
                | DepositSyncSourceOutcome::Settled => {}
            }
            return Ok(());
        }
        tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, admission_preflight_started)?;
        let pending_releases =
            self.drain_deposit_sync_releases(context, tick_deadline, &mut work).await?;
        sources.retain(|source| !pending_releases.contains(source));
        if sources.is_empty() {
            return Ok(());
        }
        let start = self.deposit_sync_source_cursor.fetch_add(1, Ordering::Relaxed) % sources.len();
        sources.rotate_left(start);
        for source in sources {
            let now = Instant::now();
            if self.shutdown.load(Ordering::Acquire) || now >= tick_deadline {
                break;
            }
            match Box::pin(self.attempt_deposit_sync_source(
                source,
                context,
                &local,
                tick_deadline,
                &mut work,
            ))
            .await
            {
                Ok(DepositSyncSourceOutcome::Adopted) => {
                    tracing::info!(%source, "atomically adopted compact deposit checkpoint");
                    return Ok(());
                }
                Ok(DepositSyncSourceOutcome::Settled | DepositSyncSourceOutcome::Progressed) => {
                    return Ok(());
                }
                Ok(
                    DepositSyncSourceOutcome::UnavailableOrStale
                    | DepositSyncSourceOutcome::PendingSupport,
                ) => {}
                Err(error) => {
                    tracing::warn!(%source, %error, "authenticated compact deposit source rejected");
                }
            }
        }
        Ok(())
    }

    async fn drain_deposit_sync_releases(
        self: &Arc<Self>,
        context: crate::deposit_sync_wire::DepositSyncContext,
        tick_deadline: Instant,
        work: &mut DepositSyncTickWork,
    ) -> anyhow::Result<BTreeSet<PartyId>> {
        let mut releases = self.server.deposit_sync_spools().pending_releases(context).await?;
        if releases.is_empty() {
            return Ok(BTreeSet::new());
        }
        let start =
            self.deposit_sync_release_cursor.fetch_add(1, Ordering::Relaxed) % releases.len();
        releases.rotate_left(start);
        for request in releases {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= tick_deadline {
                break;
            }
            let source = request.source();
            let body = match request.to_bytes() {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(
                        %source,
                        %error,
                        "durable compact-state release intent is malformed; retaining it"
                    );
                    continue;
                }
            };
            if !work.may_request(body.len()) {
                break;
            }
            if let Err(error) = work.record_request(body.len()) {
                tracing::warn!(%source, %error, "compact-state release exhausted tick budget");
                break;
            }
            let source_deadline = Instant::now()
                .checked_add(self.config.deposit_sync_request_timeout)
                .map_or(tick_deadline, |deadline| deadline.min(tick_deadline));
            let response = match self
                .deposit_sync_rpc(source, DepositOperation::SyncRelease, body, source_deadline)
                .await
            {
                Ok(Some(response)) => response,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        %source,
                        %error,
                        "authenticated compact-state release source unavailable; retaining intent"
                    );
                    continue;
                }
            };
            let body =
                match successful_deposit_sync_body(source, DepositOperation::SyncRelease, response)
                {
                    Ok(body) => body,
                    Err(error) => {
                        tracing::warn!(
                            %source,
                            %error,
                            "authenticated compact-state release was rejected; retaining intent"
                        );
                        continue;
                    }
                };
            if let Err(error) = work.record_wire_bytes(body.len()) {
                tracing::warn!(
                    %source,
                    %error,
                    "compact-state release response exceeded the shared tick budget"
                );
                break;
            }
            let acknowledgement = match DepositSyncReleaseAck::from_bytes(request, &body) {
                Ok(acknowledgement) => acknowledgement,
                Err(error) => {
                    tracing::warn!(
                        %source,
                        %error,
                        "authenticated compact-state release ACK is malformed; retaining intent"
                    );
                    continue;
                }
            };
            if let Err(error) =
                self.server.deposit_sync_spools().acknowledge_release(acknowledgement).await
            {
                tracing::warn!(
                    %source,
                    %error,
                    "compact-state release ACK could not be committed; retaining intent"
                );
            }
        }
        Ok(self
            .server
            .deposit_sync_spools()
            .pending_releases(context)
            .await?
            .into_iter()
            .map(|request| request.source())
            .collect())
    }

    async fn attempt_deposit_sync_source(
        self: &Arc<Self>,
        source: PartyId,
        context: crate::deposit_sync_wire::DepositSyncContext,
        local: &DepositSyncAdvertisement,
        tick_deadline: Instant,
        work: &mut DepositSyncTickWork,
    ) -> anyhow::Result<DepositSyncSourceOutcome> {
        let request_preflight_started = Instant::now();
        let head_request = DepositSyncHeadRequest::new(context, source, self.server.party_id())?;
        let head_body = head_request.to_bytes()?;
        if !work.may_request(head_body.len()) {
            return Ok(DepositSyncSourceOutcome::PendingSupport);
        }
        let tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, request_preflight_started)?;
        let head_deadline = Instant::now()
            .checked_add(self.config.deposit_sync_source_timeout)
            .map_or(tick_deadline, |deadline| deadline.min(tick_deadline));
        work.record_request(head_body.len())?;
        let Some(response) = self
            .deposit_sync_rpc(source, DepositOperation::SyncHead, head_body, head_deadline)
            .await?
        else {
            return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
        };
        let body = successful_deposit_sync_body(source, DepositOperation::SyncHead, response)?;
        work.record_wire_bytes(body.len())?;
        let head_response = DepositSyncHeadResponse::from_bytes(head_request, &body)?;
        let admission_preflight_started = Instant::now();
        let advertisement = head_response.advertisement();
        let is_successor =
            match self.server.deposit_sync_candidate_is_successor(&advertisement).await {
                Ok(is_successor) => is_successor,
                Err(error) => {
                    // No stage owns this newly issued source pin yet. Retain its exact release before
                    // propagating a local-target race or validation failure.
                    self.server
                        .deposit_sync_spools()
                        .enqueue_unadmitted_release(&head_response)
                        .await?;
                    self.server.reconcile_deposit_sync_lifetimes_after_stage_mutation().await?;
                    return Err(error);
                }
            };
        if !is_successor {
            // An exact crash-after-CAS retry reaches this branch. The authenticated local head,
            // not elapsed time, authorizes removal of its now-redundant staging anchor.
            self.server.deposit_sync_spools().enqueue_unadmitted_release(&head_response).await?;
            self.server.deposit_sync_spools().discard(advertisement).await?;
            return Ok(if deposit_sync_heads_are_semantically_equal(advertisement, local) {
                DepositSyncSourceOutcome::Settled
            } else {
                DepositSyncSourceOutcome::UnavailableOrStale
            });
        }

        let admission = self.server.admit_deposit_sync_spool(&head_response, source).await?;
        let tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, admission_preflight_started)?;
        self.progress_deposit_sync_admission(admission, Some(source), tick_deadline, work).await
    }

    async fn progress_deposit_sync_admission(
        self: &Arc<Self>,
        admission: DepositSyncSpoolAdmission,
        polled_source: Option<PartyId>,
        tick_deadline: Instant,
        work: &mut DepositSyncTickWork,
    ) -> anyhow::Result<DepositSyncSourceOutcome> {
        let local_preflight_started = Instant::now();
        let (spool, preferred_source, supporters, authority) = match admission {
            DepositSyncSpoolAdmission::Pending { supporters, required } => {
                tracing::debug!(
                    ?polled_source,
                    supporters,
                    required,
                    "deposit sync candidate awaits authenticated f+1 source support"
                );
                return Ok(DepositSyncSourceOutcome::PendingSupport);
            }
            DepositSyncSpoolAdmission::SamplingRoundComplete { round } => {
                tracing::debug!(
                    ?polled_source,
                    round,
                    "deposit sync sampling round found no f+1 exact family; releases are durable"
                );
                return Ok(DepositSyncSourceOutcome::PendingSupport);
            }
            DepositSyncSpoolAdmission::PrefixSupportRequired { round, work: prefix_work } => {
                tracing::debug!(
                    source = %prefix_work.response().lease().source(),
                    round,
                    "deposit sync exact-tip sampling selected a durable stable-prefix attempt"
                );
                return Box::pin(self.progress_deposit_prefix_collection(
                    prefix_work,
                    tick_deadline,
                    work,
                ))
                .await;
            }
            DepositSyncSpoolAdmission::Standby { spool, preferred_source } => {
                let Some(preferred_source) = preferred_source else {
                    return Ok(DepositSyncSourceOutcome::PendingSupport);
                };
                (spool, preferred_source, None, DepositSyncAdmissionAuthority::ExactClaims)
            }
            DepositSyncSpoolAdmission::Admitted { spool, source, supporters } => {
                if let Some(polled_source) = polled_source {
                    anyhow::ensure!(
                        polled_source == source,
                        "polled source differs from the exact durable admission source"
                    );
                }
                (spool, source, Some(supporters), DepositSyncAdmissionAuthority::ExactClaims)
            }
            DepositSyncSpoolAdmission::AdmittedPrefix {
                spool,
                source: serving_source,
                endorsers,
                ..
            } => {
                tracing::debug!(
                    source = %serving_source,
                    endorsers = endorsers.len(),
                    "deposit sync candidate admitted by stable-prefix certificate"
                );
                // Prefix endorsers certify semantic inclusion only. The stage owns exactly one
                // serving lease, and failure handling must release/rotate that source alone.
                (spool, serving_source, None, DepositSyncAdmissionAuthority::StablePrefix)
            }
        };
        let head_response = spool.head_response(self.server.party_id()).await?;
        let advertisement = head_response.advertisement().clone();
        let download_source = head_response.lease().source();
        anyhow::ensure!(
            preferred_source == download_source,
            "durable deposit sync lease differs from the manager-pinned source"
        );
        if let Some(supporters) = supporters {
            anyhow::ensure!(
                supporters.contains(&download_source),
                "deposit sync fetch source is outside the admitted supporter set"
            );
        }
        if !self.server.deposit_sync_candidate_is_successor(&advertisement).await? {
            self.server.deposit_sync_spools().enqueue_unadmitted_release(&head_response).await?;
            self.server.deposit_sync_spools().discard(&advertisement).await?;
            return Ok(DepositSyncSourceOutcome::Settled);
        }
        let durable_phase = spool.stats().await?.phase;
        if durable_phase == DepositSyncSpoolPhase::Downloading {
            let mut checkpoint = spool.download_checkpoint().await?;
            let mut frontier =
                DepositSyncFrontier::from_checkpoint(head_response.lease(), checkpoint.cursor())?;
            let tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, local_preflight_started)?;
            let full_source_deadline = Instant::now()
                .checked_add(self.config.deposit_sync_source_timeout)
                .context("compact deposit source deadline exhausted")?;
            let source_deadline = full_source_deadline.min(tick_deadline);
            let may_fail_at_deadline = full_source_deadline <= tick_deadline;
            loop {
                if Instant::now() >= source_deadline {
                    if work.progressed() {
                        return Ok(DepositSyncSourceOutcome::Progressed);
                    }
                    if may_fail_at_deadline {
                        self.server
                            .deposit_sync_spools()
                            .fail_download_source(
                                &advertisement,
                                download_source,
                                checkpoint.revision(),
                                checkpoint.digest()?,
                            )
                            .await?;
                        return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
                    }
                    return Ok(DepositSyncSourceOutcome::PendingSupport);
                }
                let Some(request) = frontier.request()? else {
                    break;
                };
                let request_body = request.to_bytes()?;
                tracing::trace!(
                    party = %self.server.party_id(),
                    source = %download_source,
                    checkpoint_revision = checkpoint.revision(),
                    requested_objects = request.entries().len(),
                    request_bytes = request_body.len(),
                    "reconstructed compact deposit object frontier request"
                );
                if !work.may_request_objects(request_body.len(), request.entries().len()) {
                    if work.progressed() {
                        return Ok(DepositSyncSourceOutcome::Progressed);
                    }
                    tokio::select! {
                        () = self.wait_for_shutdown() => {
                            return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
                        }
                        () = time::sleep_until(source_deadline) => {}
                    }
                    continue;
                }
                work.record_request(request_body.len())?;
                let page = self
                    .fetch_deposit_sync_page(
                        download_source,
                        &request,
                        request_body,
                        &spool,
                        source_deadline,
                    )
                    .await;
                let Some((page, wire_bytes)) = (match page {
                    Ok(page) => page,
                    Err(error) => {
                        self.server
                            .deposit_sync_spools()
                            .fail_download_source(
                                &advertisement,
                                download_source,
                                checkpoint.revision(),
                                checkpoint.digest()?,
                            )
                            .await?;
                        return Err(error);
                    }
                }) else {
                    let remaining = source_deadline.saturating_duration_since(Instant::now());
                    time::sleep(remaining.min(Duration::from_millis(25))).await;
                    continue;
                };
                if let Err(error) = frontier.apply_page(&page) {
                    self.server
                        .deposit_sync_spools()
                        .fail_download_source(
                            &advertisement,
                            download_source,
                            checkpoint.revision(),
                            checkpoint.digest()?,
                        )
                        .await?;
                    return Err(error);
                }
                let next_frontier = match frontier.to_bytes() {
                    Ok(frontier) => frontier,
                    Err(error) => {
                        self.server
                            .deposit_sync_spools()
                            .fail_download_source(
                                &advertisement,
                                download_source,
                                checkpoint.revision(),
                                checkpoint.digest()?,
                            )
                            .await?;
                        return Err(error.context(
                            "authenticated deposit graph exceeded its durable continuation bound",
                        ));
                    }
                };
                let next_checkpoint =
                    checkpoint.successor(DepositSyncSpoolPhase::Downloading, next_frontier)?;
                spool
                    .merge_page(
                        request.digest(),
                        page.digest(),
                        page.objects(),
                        next_checkpoint.revision(),
                        next_checkpoint.cursor(),
                    )
                    .await?;
                checkpoint = next_checkpoint;
                work.record_page(&page, wire_bytes)?;
                tracing::trace!(
                    party = %self.server.party_id(),
                    source = %download_source,
                    checkpoint_revision = checkpoint.revision(),
                    merged_objects = page.objects().len(),
                    "committed compact deposit object frontier page"
                );
                if work.pages % DEPOSIT_SYNC_COOPERATIVE_YIELD_PAGES == 0 {
                    tokio::task::yield_now().await;
                }
            }
        } else {
            anyhow::ensure!(
                matches!(
                    durable_phase,
                    DepositSyncSpoolPhase::Frozen
                        | DepositSyncSpoolPhase::Verifying
                        | DepositSyncSpoolPhase::Verified
                        | DepositSyncSpoolPhase::Materializing
                        | DepositSyncSpoolPhase::ReadyToCas
                ),
                "durable deposit sync spool cannot resume from phase {durable_phase:?}"
            );
        }
        let adoption = self
            .server
            .adopt_deposit_sync_candidate(advertisement.clone(), Arc::clone(&spool))
            .await;
        match adoption {
            Ok(Some(_import_marker)) => {
                self.server.finish_deposit_sync_adoption().await?;
                Ok(DepositSyncSourceOutcome::Adopted)
            }
            Ok(None) => Ok(DepositSyncSourceOutcome::Settled),
            Err(error) => {
                if error.downcast_ref::<DepositServiceError>().is_some_and(|error| {
                    error.deposit_sync_adoption_failure_class()
                        == DepositSyncAdoptionFailureClass::RejectExactVariant
                }) {
                    let failed = spool.checkpoint().await?;
                    match authority {
                        DepositSyncAdmissionAuthority::ExactClaims => {
                            self.server
                                .deposit_sync_spools()
                                .reject_exact_variant(
                                    &advertisement,
                                    download_source,
                                    failed.revision(),
                                    failed.digest()?,
                                    DepositSyncVariantRejection::SemanticInvalid,
                                )
                                .await?;
                        }
                        DepositSyncAdmissionAuthority::StablePrefix => {
                            self.server
                                .deposit_sync_spools()
                                .reject_prefix_variant(
                                    &advertisement,
                                    download_source,
                                    failed.revision(),
                                    failed.digest()?,
                                    DepositSyncVariantRejection::SemanticInvalid,
                                )
                                .await?;
                        }
                    }
                }
                Err(error)
            }
        }
    }

    async fn progress_deposit_prefix_collection(
        self: &Arc<Self>,
        prefix_work: DepositSyncPrefixSupportWork,
        tick_deadline: Instant,
        work: &mut DepositSyncTickWork,
    ) -> anyhow::Result<DepositSyncSourceOutcome> {
        let local_preflight_started = Instant::now();
        let mut status =
            self.server.begin_or_resume_deposit_prefix_collection(&prefix_work, None).await?;
        let mut tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, local_preflight_started)?;
        if status.is_none() {
            let full_source_deadline = Instant::now()
                .checked_add(self.config.deposit_sync_source_timeout)
                .context("prefix-support source deadline exhausted")?;
            let source_deadline = full_source_deadline.min(tick_deadline);
            let source_timeout_is_authoritative = full_source_deadline <= tick_deadline;
            let request = match self
                .fetch_deposit_sync_prefix_support_request(
                    &prefix_work,
                    source_deadline,
                    source_timeout_is_authoritative,
                    work,
                )
                .await
            {
                Ok(DepositPrefixSupportFetchOutcome::Complete(request)) => request,
                Ok(DepositPrefixSupportFetchOutcome::BudgetExhausted) => {
                    return Ok(if work.progressed() {
                        DepositSyncSourceOutcome::Progressed
                    } else {
                        DepositSyncSourceOutcome::PendingSupport
                    });
                }
                Ok(DepositPrefixSupportFetchOutcome::SourceUnavailable) => {
                    self.server.discard_deposit_sync_prefix_support(&prefix_work).await?;
                    return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
                }
                Err(DepositPrefixSupportFetchError::InvalidSource { rejection, message }) => {
                    tracing::warn!(
                        source = %prefix_work.response().lease().source(),
                        %message,
                        ?rejection,
                        "permanently rejected invalid pinned prefix-support source"
                    );
                    self.server.reject_deposit_sync_prefix_support(&prefix_work, rejection).await?;
                    return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
                }
                Err(DepositPrefixSupportFetchError::Local(message)) => {
                    anyhow::bail!("local prefix-support request construction failed: {message}");
                }
            };
            let durable_update_started = Instant::now();
            status = match self
                .server
                .begin_or_resume_deposit_prefix_collection(&prefix_work, Some(request))
                .await
            {
                Ok(status) => status,
                Err(error) if deposit_prefix_collection_error_is_source_invalid(&error) => {
                    tracing::warn!(
                        source = %prefix_work.response().lease().source(),
                        %error,
                        "permanently rejected invalid prefix-support terminal artifact"
                    );
                    self.server
                        .reject_deposit_sync_prefix_support(
                            &prefix_work,
                            DepositSyncVariantRejection::CryptographicInvalid,
                        )
                        .await?;
                    return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
                }
                Err(error) => return Err(error),
            };
            tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, durable_update_started)?;
        }

        match status.context("prefix-support collection was not installed")? {
            DepositPrefixCollectionStatus::Certified(certificate) => {
                let promotion_started = Instant::now();
                let admission = self
                    .server
                    .promote_deposit_sync_prefix_support(&prefix_work, &certificate)
                    .await?;
                tick_deadline =
                    self.exclude_local_deposit_sync_work(tick_deadline, promotion_started)?;
                return self
                    .progress_deposit_sync_admission(admission, None, tick_deadline, work)
                    .await;
            }
            DepositPrefixCollectionStatus::Admitted { .. } => {
                anyhow::bail!(
                    "requester prefix journal is admitted while its stage remains collecting"
                );
            }
            DepositPrefixCollectionStatus::Abandoned { .. } => {
                self.server.discard_deposit_sync_prefix_support(&prefix_work).await?;
                return Ok(DepositSyncSourceOutcome::UnavailableOrStale);
            }
            DepositPrefixCollectionStatus::Collecting { .. } => {}
        }

        let pending_read_started = Instant::now();
        let mut pending = self
            .server
            .pending_deposit_prefix_collection_requests(&prefix_work, MAX_COMMITTEE_MEMBERS)
            .await?
            .context("durable prefix collection disappeared while collecting")?;
        tick_deadline =
            self.exclude_local_deposit_sync_work(tick_deadline, pending_read_started)?;
        if pending.is_empty() {
            anyhow::bail!("prefix collection has no pending requests and no certificate");
        }
        let start =
            self.deposit_prefix_collection_cursor.fetch_add(1, Ordering::Relaxed) % pending.len();
        pending.rotate_left(start);

        for request in pending {
            if self.shutdown.load(Ordering::Acquire) || Instant::now() >= tick_deadline {
                break;
            }
            if !work.may_request(request.body().len()) {
                break;
            }
            work.record_request(request.body().len())?;

            let response = if request.peer() == self.server.party_id() {
                let permits = Arc::clone(&self.deposit_prefix_support_permits);
                let shutdown_or_deadline = async {
                    tokio::select! {
                        () = self.wait_for_shutdown() => {}
                        () = time::sleep_until(tick_deadline) => {}
                    }
                };
                let Some(_permit) =
                    acquire_deposit_prefix_support_execution_permit(&permits, shutdown_or_deadline)
                        .await
                else {
                    break;
                };
                match self
                    .server
                    .handle_local_deposit_prefix_support_request(
                        request.operation(),
                        request.body().to_vec(),
                    )
                    .await
                {
                    Ok(body) => Some(PeerResponse::Success { body }),
                    Err(error) => {
                        tracing::debug!(
                            peer = %request.peer(),
                            %error,
                            "local member did not advance this prefix-support attempt"
                        );
                        None
                    }
                }
            } else {
                self.deposit_sync_rpc(
                    request.peer(),
                    request.operation(),
                    request.body().to_vec(),
                    tick_deadline,
                )
                .await?
            };
            let Some(response) = response else {
                continue;
            };
            let body = match response {
                PeerResponse::Success { body } => body,
                PeerResponse::Rejected { code, retryable, message } => {
                    tracing::debug!(
                        peer = %request.peer(),
                        ?code,
                        retryable,
                        %message,
                        "prefix endorser rejected one exact scan request"
                    );
                    continue;
                }
            };
            work.record_wire_bytes(body.len())?;
            let progress = match DepositSyncPrefixSupportProgress::from_bytes(&body) {
                Ok(progress) => progress,
                Err(error) => {
                    tracing::warn!(
                        peer = %request.peer(),
                        %error,
                        "ignored malformed authenticated prefix-support progress"
                    );
                    continue;
                }
            };
            let status = match self
                .server
                .record_deposit_prefix_collection_progress(
                    &prefix_work,
                    request.peer(),
                    request.operation(),
                    request.body(),
                    &progress,
                )
                .await
            {
                Ok(status) => status,
                Err(error) if deposit_prefix_collection_error_is_peer_invalid(&error) => {
                    tracing::warn!(
                        peer = %request.peer(),
                        %error,
                        "ignored invalid authenticated prefix-support progress"
                    );
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let DepositPrefixCollectionStatus::Certified(certificate) = status {
                let promotion_started = Instant::now();
                let admission = self
                    .server
                    .promote_deposit_sync_prefix_support(&prefix_work, &certificate)
                    .await?;
                tick_deadline =
                    self.exclude_local_deposit_sync_work(tick_deadline, promotion_started)?;
                return self
                    .progress_deposit_sync_admission(admission, None, tick_deadline, work)
                    .await;
            }
        }

        let certificate_read_started = Instant::now();
        if let Some(certificate) =
            self.server.deposit_prefix_collection_certificate(&prefix_work).await?
        {
            let admission =
                self.server.promote_deposit_sync_prefix_support(&prefix_work, &certificate).await?;
            tick_deadline =
                self.exclude_local_deposit_sync_work(tick_deadline, certificate_read_started)?;
            return self
                .progress_deposit_sync_admission(admission, None, tick_deadline, work)
                .await;
        }
        Ok(if work.progressed() {
            DepositSyncSourceOutcome::Progressed
        } else {
            DepositSyncSourceOutcome::PendingSupport
        })
    }

    /// Fetch the only source artifact absent from `SyncHead` after the stage has durably taken
    /// ownership of the lease. The first page authenticates the advertised archive-segment root;
    /// its exact child capability then authorizes the terminal event page.
    async fn fetch_deposit_sync_prefix_support_request(
        self: &Arc<Self>,
        support: &DepositSyncPrefixSupportWork,
        source_deadline: Instant,
        source_timeout_is_authoritative: bool,
        work: &mut DepositSyncTickWork,
    ) -> Result<DepositPrefixSupportFetchOutcome, DepositPrefixSupportFetchError> {
        let response = support.response();
        let statement = support.statement();
        let lease = response.lease();
        let terminal_ordinal = statement.checkpoint_sequence().checked_sub(1).ok_or_else(|| {
            DepositPrefixSupportFetchError::semantic(
                "prefix-support terminal checkpoint sequence is zero",
            )
        })?;
        let terminal_target = DepositSyncTraversalTarget::ArchiveEvent {
            reference: statement.terminal_event(),
            expected_ordinal: terminal_ordinal,
        };
        let segment_reference = statement.anchor().certificate_segment_root().ok_or_else(|| {
            DepositPrefixSupportFetchError::semantic(
                "prefix-support statement has no archive-segment root",
            )
        })?;
        let mut matching_roots = lease
            .root_targets()
            .map_err(DepositPrefixSupportFetchError::cryptographic)?
            .into_iter()
            .filter(|target| {
                matches!(
                    target,
                    DepositSyncTraversalTarget::ArchiveSegment { reference, .. }
                        if *reference == segment_reference
                )
            });
        let segment_target = matching_roots.next().ok_or_else(|| {
            DepositPrefixSupportFetchError::semantic(
                "lease does not advertise the terminal archive segment",
            )
        })?;
        if matching_roots.next().is_some() {
            return Err(DepositPrefixSupportFetchError::semantic(
                "lease advertises the terminal archive segment more than once",
            ));
        }

        let segment_request = DepositSyncObjectPageRequest::new(
            lease,
            vec![
                DepositSyncObjectRequestEntry::advertised_root(lease, segment_target)
                    .map_err(DepositPrefixSupportFetchError::cryptographic)?,
            ],
        )
        .map_err(DepositPrefixSupportFetchError::cryptographic)?;
        let segment_page = match self
            .fetch_unstaged_deposit_sync_page(
                response.lease().source(),
                &segment_request,
                source_deadline,
                source_timeout_is_authoritative,
                work,
            )
            .await?
        {
            DepositPrefixSupportPageFetchOutcome::Complete(page) => page,
            DepositPrefixSupportPageFetchOutcome::BudgetExhausted => {
                return Ok(DepositPrefixSupportFetchOutcome::BudgetExhausted);
            }
            DepositPrefixSupportPageFetchOutcome::SourceUnavailable => {
                return Ok(DepositPrefixSupportFetchOutcome::SourceUnavailable);
            }
        };
        if segment_page.objects().len() != 1
            || segment_page.objects()[0].reference() != segment_target.reference()
        {
            return Err(DepositPrefixSupportFetchError::cryptographic(
                "prefix-support segment page returned the wrong root object",
            ));
        }
        let mut matching_capabilities =
            segment_page.capabilities().iter().copied().filter(|capability| {
                capability.parent() == segment_target && capability.child() == terminal_target
            });
        let terminal_capability = matching_capabilities.next().ok_or_else(|| {
            DepositPrefixSupportFetchError::cryptographic(
                "terminal archive event is absent from its authenticated segment",
            )
        })?;
        if matching_capabilities.next().is_some() {
            return Err(DepositPrefixSupportFetchError::cryptographic(
                "terminal archive event capability is duplicated",
            ));
        }

        let event_request = DepositSyncObjectPageRequest::new(
            lease,
            vec![DepositSyncObjectRequestEntry::authorized(terminal_capability)],
        )
        .map_err(DepositPrefixSupportFetchError::cryptographic)?;
        let event_page = match self
            .fetch_unstaged_deposit_sync_page(
                response.lease().source(),
                &event_request,
                source_deadline,
                source_timeout_is_authoritative,
                work,
            )
            .await?
        {
            DepositPrefixSupportPageFetchOutcome::Complete(page) => page,
            DepositPrefixSupportPageFetchOutcome::BudgetExhausted => {
                return Ok(DepositPrefixSupportFetchOutcome::BudgetExhausted);
            }
            DepositPrefixSupportPageFetchOutcome::SourceUnavailable => {
                return Ok(DepositPrefixSupportFetchOutcome::SourceUnavailable);
            }
        };
        if event_page.objects().len() != 1
            || event_page.objects()[0].reference() != terminal_target.reference()
        {
            return Err(DepositPrefixSupportFetchError::cryptographic(
                "prefix-support event page returned the wrong object",
            ));
        }
        let terminal_event = DepositArchiveEvent::from_bytes(event_page.objects()[0].bytes())
            .map_err(DepositPrefixSupportFetchError::cryptographic)?;
        let terminal_checkpoint = response
            .advertisement()
            .checkpoint_certificate()
            .ok_or_else(|| {
                DepositPrefixSupportFetchError::semantic(
                    "prefix-support head has no terminal checkpoint certificate",
                )
            })?
            .clone();
        let request =
            DepositSyncSupportRequest::new(statement.clone(), terminal_event, terminal_checkpoint)
                .map_err(DepositPrefixSupportFetchError::cryptographic)?;
        Ok(DepositPrefixSupportFetchOutcome::Complete(request))
    }

    async fn fetch_unstaged_deposit_sync_page(
        self: &Arc<Self>,
        source: PartyId,
        request: &DepositSyncObjectPageRequest,
        source_deadline: Instant,
        source_timeout_is_authoritative: bool,
        work: &mut DepositSyncTickWork,
    ) -> Result<DepositPrefixSupportPageFetchOutcome, DepositPrefixSupportFetchError> {
        if Instant::now() >= source_deadline {
            return Ok(if source_timeout_is_authoritative {
                DepositPrefixSupportPageFetchOutcome::SourceUnavailable
            } else {
                DepositPrefixSupportPageFetchOutcome::BudgetExhausted
            });
        }
        let request_body =
            request.to_bytes().map_err(DepositPrefixSupportFetchError::cryptographic)?;
        if !work.may_request(request_body.len()) {
            return Ok(DepositPrefixSupportPageFetchOutcome::BudgetExhausted);
        }
        work.record_request(request_body.len()).map_err(DepositPrefixSupportFetchError::local)?;
        let response = match self
            .deposit_sync_rpc(source, DepositOperation::SyncObjects, request_body, source_deadline)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) | Err(_) => {
                return Ok(DepositPrefixSupportPageFetchOutcome::SourceUnavailable);
            }
        };
        let body = match response {
            PeerResponse::Success { body } => body,
            PeerResponse::Rejected { retryable: true, .. } => {
                return Ok(DepositPrefixSupportPageFetchOutcome::SourceUnavailable);
            }
            PeerResponse::Rejected { code, retryable: false, message } => {
                return Err(DepositPrefixSupportFetchError::semantic(format!(
                    "party {source} rejected pinned SyncObjects ({code:?}): {message}"
                )));
            }
        };
        work.record_wire_bytes(body.len()).map_err(DepositPrefixSupportFetchError::local)?;
        let page = DepositSyncObjectPage::from_bytes(request, &body)
            .map_err(DepositPrefixSupportFetchError::cryptographic)?;
        Ok(DepositPrefixSupportPageFetchOutcome::Complete(page))
    }

    async fn fetch_deposit_sync_page(
        self: &Arc<Self>,
        source: PartyId,
        request: &DepositSyncObjectPageRequest,
        body: Vec<u8>,
        spool: &DepositSyncSpoolStore,
        source_deadline: Instant,
    ) -> anyhow::Result<Option<(DepositSyncObjectPage, usize)>> {
        if Instant::now() >= source_deadline {
            return Ok(None);
        }
        // Exact O(1) reads catch a local membership-index fork before a repeated request is sent.
        for entry in request.entries() {
            if let Some(existing) = spool.load_object(entry.reference())? {
                anyhow::ensure!(
                    existing.reference() == entry.reference(),
                    "deposit sync spool returned the wrong content address"
                );
            }
        }
        let Some(response) = self
            .deposit_sync_rpc(source, DepositOperation::SyncObjects, body, source_deadline)
            .await?
        else {
            return Ok(None);
        };
        let body = match response {
            PeerResponse::Success { body } => body,
            PeerResponse::Rejected { code, retryable: true, message } => {
                tracing::debug!(
                    %source,
                    ?code,
                    %message,
                    "deposit sync source temporarily rejected SyncObjects"
                );
                return Ok(None);
            }
            PeerResponse::Rejected { code, retryable: false, message } => {
                anyhow::bail!(
                    "party {source} rejected deposit SyncObjects \
                     ({code:?}, retryable=false): {message}"
                );
            }
        };
        let wire_bytes = body.len();
        Ok(Some((DepositSyncObjectPage::from_bytes(request, &body)?, wire_bytes)))
    }

    async fn deposit_sync_rpc(
        self: &Arc<Self>,
        source: PartyId,
        operation: DepositOperation,
        body: Vec<u8>,
        source_deadline: Instant,
    ) -> anyhow::Result<Option<PeerResponse>> {
        anyhow::ensure!(
            matches!(
                operation,
                DepositOperation::SyncHead
                    | DepositOperation::SyncObjects
                    | DepositOperation::SyncRelease
                    | DepositOperation::PrefixSupportStart
                    | DepositOperation::PrefixSupportContinue
            ),
            "non-sync deposit operation routed through compact pull RPC"
        );
        Ok(self
            .deposit_rpc(source, operation, body, source_deadline, None)
            .await?
            .map(|response| response.response))
    }

    async fn dispatch_local_deposit_request(
        self: &Arc<Self>,
        operation: DepositOperation,
        body: Vec<u8>,
        started_before: Instant,
        preacquired_recipient: Option<tokio::sync::OwnedSemaphorePermit>,
        expire_while_waiting: bool,
    ) -> anyhow::Result<Option<PeerResponse>> {
        let _admission = match acquire_local_deposit_mutation_admission(
            &self.outbound_deposit_mutation_slots,
            self.server.party_id(),
            &self.deposit_mutation_permits,
            operation,
            preacquired_recipient,
            started_before,
            expire_while_waiting,
            self.wait_for_shutdown(),
            self.wait_for_shutdown(),
        )
        .await
        {
            Ok(admission) => admission,
            Err(
                OutboundDepositMutationSlotError::Busy
                | OutboundDepositMutationSlotError::Cancelled,
            ) => return Ok(None),
            Err(
                OutboundDepositMutationSlotError::UnknownRecipient
                | OutboundDepositMutationSlotError::GenerationExhausted,
            ) => {
                anyhow::bail!("local party has no outbound deposit mutation slot");
            }
        };
        Ok(Some(
            self.server.handle_local_peer_request(PeerRequest::Deposit { operation, body }).await,
        ))
    }

    async fn deposit_state_transfer_rpc(
        self: &Arc<Self>,
        peer_party: PartyId,
        operation: DepositOperation,
        body: Vec<u8>,
        deadline: Instant,
        scope: StateTransferReservationScope,
    ) -> anyhow::Result<Option<DepositRpcResponse>> {
        anyhow::ensure!(
            matches!(
                operation,
                DepositOperation::PostHandoffExportSealRequest
                    | DepositOperation::PostHandoffExportSealVote
                    | DepositOperation::PostHandoffExportSealCertificate
                    | DepositOperation::ExportHead
                    | DepositOperation::ExportObjects
                    | DepositOperation::ExportRelease
                    | DepositOperation::StateImportedAck
                    | DepositOperation::StateImportedCertificate
            ),
            "non-transfer deposit operation routed through certified state-transfer RPC"
        );
        if peer_party == self.server.party_id() {
            Ok(self
                .dispatch_local_deposit_request(operation, body, deadline, None, false)
                .await?
                .map(|response| DepositRpcResponse {
                    response,
                    response_provenance: None,
                    reservation: None,
                    _state_transfer_attempt: None,
                }))
        } else {
            self.deposit_rpc(peer_party, operation, body, deadline, Some(scope)).await
        }
    }

    /// Shared bounded QUIC request machinery for ordinary and certified deposit synchronization.
    ///
    /// The caller supplies an absolute phase deadline. This layer adds the per-request cap and
    /// observes shutdown while waiting on admission or transport; durable reducers run after it
    /// returns.
    async fn deposit_rpc(
        self: &Arc<Self>,
        source: PartyId,
        operation: DepositOperation,
        body: Vec<u8>,
        source_deadline: Instant,
        transfer_scope: Option<StateTransferReservationScope>,
    ) -> anyhow::Result<Option<DepositRpcResponse>> {
        let peer = self.peers.get(&source).context("compact deposit source has no QUIC route")?;
        let complete_after_admission = transfer_scope.is_some();
        let request = PeerRequest::Deposit { operation, body };
        let request_id =
            RequestId::for_peer_request(self.network_id, self.server.party_id(), source, &request)?;
        let reservation_key = (complete_after_admission
            && deposit_operation_requires_mutation_admission(operation))
        .then_some(StateTransferReservationKey { recipient: source, request_id });
        let phase_bounded_deadline = if complete_after_admission {
            if source_deadline <= Instant::now() {
                return Ok(None);
            }
            None
        } else {
            let Some(deadline) = bounded_deposit_rpc_deadline(
                source_deadline,
                self.config.deposit_sync_request_timeout,
                Instant::now(),
            ) else {
                return Ok(None);
            };
            Some(deadline)
        };
        if !peer.ready(Instant::now()).await {
            return Ok(None);
        }
        // Certified state-transfer RPCs queue through every stream boundary. Relay requests use
        // nonblocking ordinary admission, so Tokio's FIFO waiter assignment prevents refill
        // starvation without sacrificing one permanent relay slot.
        let admission = if complete_after_admission {
            acquire_outbound_sync_admission_for_transfer(
                &self.outbound_sync_permits,
                &peer.sync_permits,
                &self.outbound_permits,
                &peer.permits,
                self.wait_for_shutdown(),
            )
            .await
        } else {
            acquire_outbound_sync_admission_until(
                &self.outbound_sync_permits,
                &peer.sync_permits,
                &self.outbound_permits,
                &peer.permits,
                phase_bounded_deadline.expect("ordinary RPC deadline is present"),
                self.wait_for_shutdown(),
            )
            .await
        };
        let Some(_admission) = admission else {
            return Ok(None);
        };
        let request_deadline = if complete_after_admission {
            Instant::now()
                .checked_add(self.config.deposit_sync_request_timeout)
                .context("deposit RPC request deadline overflowed")?
        } else {
            phase_bounded_deadline.expect("ordinary RPC deadline is present")
        };
        let Some(connect_timeout) = request_deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        let connection = tokio::select! {
            () = self.wait_for_shutdown() => return Ok(None),
            connection = time::timeout(
                connect_timeout,
                peer.connection(&self.endpoint),
            ) => connection,
        };
        let connection = match connection {
            Ok(connection) => connection,
            Err(_) => {
                let delay = peer.transport_failure(None, self.config).await;
                tracing::debug!(%source, ?delay, "compact deposit connection exhausted its request deadline");
                return Ok(None);
            }
        };
        let Some(connection) = connection else {
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
        // Persist the exact mutable cut only after readiness, outbound admission, and connection
        // establishment. From this point through a terminal authenticated response, the
        // map-owned recipient permit prevents ordinary or competing transfer work from overtaking
        // an execution whose dispatch may become ambiguous. Exact retries reuse the cut.
        let state_transfer_attempt = if let Some(key) = reservation_key {
            match self
                .acquire_state_transfer_reservation(
                    key,
                    transfer_scope.expect("state-transfer scope is present"),
                    operation,
                    source_deadline,
                )
                .await
            {
                Ok(Some(admission)) => Some(admission),
                Ok(None)
                | Err(
                    OutboundDepositMutationSlotError::Busy
                    | OutboundDepositMutationSlotError::Cancelled,
                ) => return Ok(None),
                Err(
                    OutboundDepositMutationSlotError::UnknownRecipient
                    | OutboundDepositMutationSlotError::GenerationExhausted,
                ) => {
                    anyhow::bail!(
                        "deposit RPC recipient {source} has no transfer reservation slot"
                    );
                }
            }
        } else {
            debug_assert!(
                !complete_after_admission
                    || !deposit_operation_requires_mutation_admission(operation)
            );
            None
        };
        let Some(stream_timeout) = request_deadline.checked_duration_since(Instant::now()) else {
            if let Some(key) = reservation_key {
                let attempt = state_transfer_attempt
                    .as_ref()
                    .context("durable state-transfer reservation lacks its attempt admission")?;
                self.handle_state_transfer_deadline_before_dispatch(key, attempt).await?;
            }
            tracing::debug!(%source, "compact deposit request exhausted its deadline before stream dispatch");
            return Ok(None);
        };
        let response = tokio::select! {
            () = self.wait_for_shutdown() => return Ok(None),
            response = time::timeout(
                stream_timeout,
                connection
                    .connection
                    .request_with_timeout_outcome(request_id, request, stream_timeout),
            ) => response,
        };
        match response {
            Err(_) => {
                if let Some(key) = reservation_key {
                    self.state_transfer_reservation_failure(key).await;
                }
                tracing::debug!(%source, "compact deposit request exhausted its transport deadline");
                Ok(None)
            }
            Ok(Ok(outcome)) => {
                self.server.record_authenticated_quic_response();
                peer.transport_success().await;
                let (response, response_provenance) = outcome.into_parts();
                // A wire-level Success is not yet a valid receipt. Retain bounded backoff until
                // the caller validates the typed body, commits any protocol effect, and retires
                // this independent transport cut. A malformed Success remains ambiguous.
                if let Some(key) = reservation_key {
                    self.state_transfer_reservation_failure(key).await;
                }
                Ok(Some(DepositRpcResponse {
                    response,
                    response_provenance: Some(response_provenance),
                    reservation: reservation_key,
                    _state_transfer_attempt: state_transfer_attempt,
                }))
            }
            Ok(Err(error)) => {
                let connection_retry = peer
                    .request_connection_failure(connection.generation, &error, self.config)
                    .await;
                if let Some(key) = reservation_key {
                    self.state_transfer_reservation_failure(key).await;
                }
                tracing::debug!(%source, ?connection_retry, %error, "compact deposit pull deferred");
                Ok(None)
            }
        }
    }

    async fn relay_loop(self: Arc<Self>) {
        let mut interval = time::interval(self.config.outbox_poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut tasks = JoinSet::new();
        let mut scheduled = BTreeMap::new();
        let mut in_flight = BTreeSet::new();
        let mut accepted = BTreeMap::<DurableMessageId, RequestId>::new();
        let mut lane_cursor = RelayLaneCursor::default();
        let mut direct_cursor = DirectWorkCursor::default();
        let mut transition_cursor = BTreeMap::new();
        let mut deposit_cursor = BTreeMap::new();
        let mut active_deposit_recipients = BTreeMap::new();

        loop {
            tokio::select! {
                () = self.wait_for_shutdown() => break,
                _ = interval.tick() => {
                    Box::pin(self.flush_durable_acks(&mut accepted, &mut in_flight)).await;
                    Box::pin(self.schedule_pending(
                        &mut tasks,
                        &mut scheduled,
                        &mut in_flight,
                        &mut lane_cursor,
                        &mut direct_cursor,
                        &mut transition_cursor,
                        &mut deposit_cursor,
                        &mut active_deposit_recipients,
                    )).await;
                }
                Some(result) = tasks.join_next_with_id(), if !tasks.is_empty() => {
                    Box::pin(self.collect_attempt(result, &mut scheduled, &mut accepted, &mut in_flight)).await;
                    while let Some(result) = tasks.try_join_next_with_id() {
                        Box::pin(self.collect_attempt(result, &mut scheduled, &mut accepted, &mut in_flight)).await;
                    }
                    if tasks.is_empty() {
                        Box::pin(self.flush_durable_acks(&mut accepted, &mut in_flight)).await;
                    }
                }
            }
        }
        while let Some(result) = tasks.join_next_with_id().await {
            Box::pin(self.collect_attempt(result, &mut scheduled, &mut accepted, &mut in_flight))
                .await;
        }
        Box::pin(self.flush_durable_acks(&mut accepted, &mut in_flight)).await;
    }

    async fn schedule_pending(
        self: &Arc<Self>,
        tasks: &mut JoinSet<AttemptResult>,
        scheduled: &mut BTreeMap<TaskId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
        lane_cursor: &mut RelayLaneCursor,
        direct_cursor: &mut DirectWorkCursor,
        transition_cursor: &mut BTreeMap<PartyId, TransitionOrder>,
        deposit_cursor: &mut BTreeMap<PartyId, DepositCausalLane>,
        active_deposit_recipients: &mut BTreeMap<PartyId, RequestId>,
    ) {
        // Accepted durable items deliberately remain in `in_flight` until their local outbox ACK
        // commits. Track their recipient independently of the current outbox enumeration: terminal
        // handoff/compaction may hide the active candidate before that ACK, but must not expose a
        // same-recipient successor early.
        reconcile_active_deposit_recipients(active_deposit_recipients, in_flight);
        let mut direct_work = BTreeMap::<PartyId, DirectRecipientWork>::new();
        let mut live_retry_keys = BTreeSet::new();
        // Epoch transitions span three independently persisted outboxes. Select only the
        // earliest causal item across all three for each recipient on a poll: a QUIC stream for
        // AVSS/QUAL/activation must never overtake the key-rotation certificate which makes the
        // dynamic committee locally admissible. Keeping the predecessor selected while it is in
        // flight or backing off also prevents a later poll from opening a competing stream.
        //
        // Activation acknowledgements are the one transition effect that is NOT part of this causal
        // chain: a party signs its acknowledgement only after it has locally staged the epoch, and a
        // recipient accepts it only once the recipient has independently staged the same epoch. The
        // acknowledgement therefore has no delivery-ordering dependency on this sender's AVSS/QUAL
        // messages to the same recipient. Fencing it behind those messages (which a peer that has
        // already finalized permanently rejects, so they linger in the outbox and keep retrying)
        // starves the acknowledgement of the recipient's single transition stream and can wedge the
        // n-f activation quorum. Schedule acknowledgements on their own independent stream instead.
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
                    let relay = RelayWork {
                        key,
                        recipient: id.recipient(),
                        requires_positive_ack: request_requires_positive_ack(&request),
                        request,
                        target: AcceptanceTarget::Durable(DurableMessageId::Protocol(id)),
                        response_expectation: RelayResponseExpectation::Generic,
                        deposit_causal_lane: None,
                    };
                    if matches!(id, PeerMessageId::ActivationAck { .. }) {
                        let order = (transition_epoch, causal_sequence);
                        let exact = direct_work
                            .entry(id.recipient())
                            .or_default()
                            .activation_acks
                            .entry(order)
                            .or_default();
                        if let std::collections::btree_map::Entry::Vacant(entry) = exact.entry(id) {
                            entry.insert(relay);
                        } else {
                            tracing::error!(
                                recipient = %id.recipient(),
                                epoch = transition_epoch,
                                sequence = causal_sequence,
                                ?id,
                                "durable activation acknowledgement duplicated its exact identity"
                            );
                        }
                    } else {
                        retain_earliest_transition_work(
                            &mut earliest_transition,
                            transition_epoch,
                            causal_sequence,
                            relay,
                        );
                    }
                }
                Err(error) => {
                    let fallback = durable_retry_fallback_id(self.network_id, id);
                    live_retry_keys.insert(fallback);
                    self.work_failure(fallback).await;
                    tracing::error!(message = ?id, %error, "cannot encode durable QUIC outbox item");
                }
            }
        }

        // Deposit effects are causally ordered across each complete reducer namespace. A client
        // request is admitted before its eventual ledger sequence is known, so fencing only equal
        // numeric sequences would let a later proposal overtake the origin proof which makes it
        // admissible at the receiver. Ledger BA and portable-index checkpoint BA are independent
        // namespaces and can legitimately overlap while replicas finalize at different speeds.
        // The durable outbox therefore carries an authenticated namespace and the relay selects
        // exactly one causal predecessor per (recipient, namespace).
        let mut earliest_deposit = BTreeMap::new();
        for pending in
            self.server.pending_deposit_peer_messages(self.config.outbox_batch_size).await
        {
            let id = pending.id;
            let recipient = pending.recipient();
            let causal_lane = pending.causal_lane();
            let causal = pending.causal_key();
            let prepared = if id.operation() == DepositOperation::Consolidation {
                let wire = match ByzantineConsolidationWireMessage::decode(&pending.body) {
                    Ok(wire) => wire,
                    Err(error) => {
                        let fallback = id.request_id(self.network_id);
                        live_retry_keys.insert(fallback);
                        self.work_failure(fallback).await;
                        tracing::error!(message = ?id, %error, "cannot decode durable Byzantine consolidation outbox item");
                        continue;
                    }
                };
                let delivery = match wire.delivery_id() {
                    Ok(delivery) => delivery,
                    Err(error) => {
                        let fallback = id.request_id(self.network_id);
                        live_retry_keys.insert(fallback);
                        self.work_failure(fallback).await;
                        tracing::error!(message = ?id, %error, "cannot identify durable Byzantine consolidation outbox item");
                        continue;
                    }
                };
                let response_expectation = match self
                    .server
                    .prepare_byzantine_consolidation_ack_expectation(recipient, &wire)
                {
                    Ok(expectation) => {
                        RelayResponseExpectation::ByzantineConsolidation(expectation)
                    }
                    Err(error) => {
                        let fallback = id.request_id(self.network_id);
                        live_retry_keys.insert(fallback);
                        self.work_failure(fallback).await;
                        tracing::error!(message = ?id, %error, "cannot validate durable Byzantine consolidation outbox route");
                        continue;
                    }
                };
                (
                    causal,
                    AcceptanceTarget::Durable(DurableMessageId::ByzantineConsolidation(delivery)),
                    response_expectation,
                )
            } else {
                (
                    causal,
                    AcceptanceTarget::Durable(DurableMessageId::Deposit(id)),
                    RelayResponseExpectation::Generic,
                )
            };
            let request = pending.into_quic_request();
            let key = match RequestId::for_peer_request(
                self.network_id,
                self.server.party_id(),
                recipient,
                &request,
            ) {
                Ok(key) => key,
                Err(error) => {
                    let fallback = id.request_id(self.network_id);
                    live_retry_keys.insert(fallback);
                    self.work_failure(fallback).await;
                    tracing::error!(message = ?id, %error, "cannot bind durable deposit item to its authenticated route");
                    continue;
                }
            };
            live_retry_keys.insert(key);
            let relay = RelayWork {
                key,
                recipient,
                requires_positive_ack: request_requires_positive_ack(&request),
                deposit_causal_lane: peer_request_requires_deposit_mutation_admission(&request)
                    .then_some(causal_lane),
                request,
                target: prepared.1,
                response_expectation: prepared.2,
            };
            let lane = deposit_relay_lane(id, causal_lane);
            retain_earliest_deposit_relay(&mut earliest_deposit, lane, prepared.0, relay);
        }
        for ((recipient, lane), (_, relay)) in earliest_deposit {
            if let Some(relay_lane) = relay.deposit_causal_lane {
                debug_assert_eq!(relay_lane, lane);
                if active_deposit_recipients.contains_key(&recipient) {
                    continue;
                }
            }
            direct_work.entry(recipient).or_default().deposits.insert(lane, relay);
        }
        // Direct scheduling below exposes at most one successful candidate per recipient per poll.
        // Its semantic-class cursor alternates activation ACKs and deposit work, while the deposit
        // cursor rotates the complete fixed causal-lane order (including bounded per-origin client
        // lanes). Backoff in either class falls through to the other without advancing a cursor.

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
                            requires_positive_ack: request_requires_positive_ack(&request),
                            request,
                            target: AcceptanceTarget::Durable(DurableMessageId::KeyRotation(id)),
                            response_expectation: RelayResponseExpectation::Generic,
                            deposit_causal_lane: None,
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

        // Activation acknowledgements and deposit effects have no cross-lane dependency on
        // key-rotation/AVSS/QUAL delivery, but they share its global semaphore. Use stable
        // recipient and semantic successors so changing candidate membership cannot reinterpret a
        // numeric vector offset or starve a continuously ready class.
        let mut direct = direct_recipients_after(direct_work, direct_cursor.recipient).into_iter();
        transition_cursor.retain(|recipient, _| earliest_transition.contains_key(recipient));
        let mut transitions = earliest_transition.into_iter();
        let mut direct_exhausted = false;
        let mut transitions_exhausted = false;
        loop {
            let mut scheduled_one = false;
            for lane in lane_cursor.scheduling_order() {
                let outcome = match lane {
                    RelayLane::Direct if direct_exhausted => continue,
                    RelayLane::Transition if transitions_exhausted => continue,
                    RelayLane::Direct => {
                        self.try_schedule_next_direct(
                            &mut direct,
                            tasks,
                            scheduled,
                            in_flight,
                            direct_cursor,
                            deposit_cursor,
                            active_deposit_recipients,
                        )
                        .await
                    }
                    RelayLane::Transition => {
                        self.try_schedule_next_transition(
                            &mut transitions,
                            tasks,
                            scheduled,
                            in_flight,
                            transition_cursor,
                        )
                        .await
                    }
                };
                match outcome {
                    RelayLaneOutcome::Scheduled => {
                        lane_cursor.record_scheduled(lane);
                        scheduled_one = true;
                        break;
                    }
                    RelayLaneOutcome::Exhausted => match lane {
                        RelayLane::Direct => direct_exhausted = true,
                        RelayLane::Transition => transitions_exhausted = true,
                    },
                    RelayLaneOutcome::GlobalPermitExhausted => return,
                }
            }
            if !scheduled_one {
                return;
            }
        }
    }

    async fn try_schedule_next_direct<I>(
        self: &Arc<Self>,
        work: &mut I,
        tasks: &mut JoinSet<AttemptResult>,
        scheduled: &mut BTreeMap<TaskId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
        cursor: &mut DirectWorkCursor,
        deposit_cursor: &mut BTreeMap<PartyId, DepositCausalLane>,
        active_deposit_recipients: &mut BTreeMap<PartyId, RequestId>,
    ) -> RelayLaneOutcome
    where
        I: Iterator<Item = (PartyId, DirectRecipientWork)>,
    {
        for (recipient, mut candidates) in work {
            for semantic_lane in cursor.semantic_order(recipient) {
                match semantic_lane {
                    DirectSemanticLane::ActivationAck => {
                        let activation_acks = std::mem::take(&mut candidates.activation_acks);
                        for (order, exact_candidates) in activation_ack_candidates_after(
                            activation_acks,
                            cursor.activation_ack.get(&recipient).copied(),
                        ) {
                            let exact_cursor = cursor
                                .activation_ack_exact
                                .get(&recipient)
                                .and_then(|(cursor_order, exact)| {
                                    (*cursor_order == order).then_some(*exact)
                                });
                            for (exact, work) in activation_ack_exact_candidates_after(
                                exact_candidates,
                                exact_cursor,
                            ) {
                                match self
                                    .try_schedule_work(work, tasks, scheduled, in_flight)
                                    .await
                                {
                                    ScheduleOutcome::Scheduled => {
                                        cursor.record_scheduled(
                                            recipient,
                                            DirectSemanticLane::ActivationAck,
                                        );
                                        cursor.activation_ack.insert(recipient, order);
                                        cursor
                                            .activation_ack_exact
                                            .insert(recipient, (order, exact));
                                        return RelayLaneOutcome::Scheduled;
                                    }
                                    ScheduleOutcome::Skipped => {}
                                    ScheduleOutcome::GlobalPermitExhausted => {
                                        return RelayLaneOutcome::GlobalPermitExhausted;
                                    }
                                }
                            }
                        }
                    }
                    DirectSemanticLane::Deposit => {
                        let deposits = std::mem::take(&mut candidates.deposits);
                        for (lane, work) in deposit_relay_candidates_after(
                            deposits,
                            deposit_cursor.get(&recipient).copied(),
                        ) {
                            let active_update =
                                work.deposit_causal_lane.map(|_| (work.recipient, work.key));
                            match self.try_schedule_work(work, tasks, scheduled, in_flight).await {
                                ScheduleOutcome::Scheduled => {
                                    cursor.record_scheduled(recipient, DirectSemanticLane::Deposit);
                                    deposit_cursor.insert(recipient, lane);
                                    if let Some((recipient, key)) = active_update {
                                        let previous =
                                            active_deposit_recipients.insert(recipient, key);
                                        debug_assert!(
                                            previous.is_none(),
                                            "scheduled concurrent mutable deposit relays for one recipient"
                                        );
                                    }
                                    return RelayLaneOutcome::Scheduled;
                                }
                                ScheduleOutcome::Skipped => {}
                                ScheduleOutcome::GlobalPermitExhausted => {
                                    return RelayLaneOutcome::GlobalPermitExhausted;
                                }
                            }
                        }
                    }
                }
            }
        }
        RelayLaneOutcome::Exhausted
    }

    async fn try_schedule_next_transition<I>(
        self: &Arc<Self>,
        recipients: &mut I,
        tasks: &mut JoinSet<AttemptResult>,
        scheduled: &mut BTreeMap<TaskId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
        cursor: &mut BTreeMap<PartyId, TransitionOrder>,
    ) -> RelayLaneOutcome
    where
        I: Iterator<Item = (PartyId, BTreeMap<TransitionOrder, RelayWork>)>,
    {
        // Transition effects span several outboxes but share a per-recipient causal fence. Only
        // one transition stream is admitted for a recipient at a time. Between completed
        // attempts, rotate the first candidate durably: otherwise several permanently rejected
        // historical AVSS/QUAL items with staggered retry timers can ensure that one is always
        // ready, starving every current-epoch key advertisement forever. Reducers still enforce
        // exact causal prerequisites, so a rotated successor can only be accepted when its
        // predecessor is already durable; an early arrival remains retryable evidence.
        for (recipient, candidates) in recipients {
            if candidates.values().any(|work| in_flight.contains(&work.key)) {
                continue;
            }
            for (order, work) in
                transition_candidates_after(candidates, cursor.get(&recipient).copied())
            {
                match self.try_schedule_work(work, tasks, scheduled, in_flight).await {
                    ScheduleOutcome::Scheduled => {
                        cursor.insert(recipient, order);
                        return RelayLaneOutcome::Scheduled;
                    }
                    ScheduleOutcome::Skipped => {}
                    ScheduleOutcome::GlobalPermitExhausted => {
                        return RelayLaneOutcome::GlobalPermitExhausted;
                    }
                }
            }
        }
        RelayLaneOutcome::Exhausted
    }

    /// Attempt to open a single delivery stream for one durable outbox item. Returns whether the
    /// item was scheduled, skipped because it is not currently eligible (backing off, no route, or
    /// the peer connection is backing off / at its per-peer concurrency limit), or could not be
    /// scheduled because the global outbound concurrency budget is exhausted.
    async fn try_schedule_work(
        self: &Arc<Self>,
        work: RelayWork,
        tasks: &mut JoinSet<AttemptResult>,
        scheduled: &mut BTreeMap<TaskId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
    ) -> ScheduleOutcome {
        if in_flight.contains(&work.key)
            || !mutable_deposit_relay_is_admitted(
                self.mutable_deposit_relay_ready.load(Ordering::Acquire),
                &work.request,
            )
            || !self.work_ready(work.key).await
        {
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
        let (deposit_mutation_slot, relay_admission) = if work.recipient == self.server.party_id() {
            // Loopback work owns no transport stream. The attempt acquires the self recipient
            // and endpoint mutation lanes together immediately before local dispatch.
            (None, None)
        } else {
            let deposit_operation = match &work.request {
                PeerRequest::Deposit { operation, .. } => Some(*operation),
                _ => None,
            };
            let deposit_mutation_slot = match try_acquire_outbound_deposit_mutation_slot(
                &self.outbound_deposit_mutation_slots,
                work.recipient,
                deposit_operation,
            ) {
                Ok(slot) => slot,
                Err(
                    OutboundDepositMutationSlotError::Busy
                    | OutboundDepositMutationSlotError::Cancelled,
                ) => {
                    return ScheduleOutcome::Skipped;
                }
                Err(
                    OutboundDepositMutationSlotError::UnknownRecipient
                    | OutboundDepositMutationSlotError::GenerationExhausted,
                ) => {
                    tracing::error!(
                        recipient = %work.recipient,
                        "durable deposit outbox has no outbound mutation slot"
                    );
                    self.work_failure(work.key).await;
                    return ScheduleOutcome::Skipped;
                }
            };
            let peer = self.peers[&work.recipient].clone();
            let relay_admission =
                match try_acquire_outbound_relay_admission(&self.outbound_permits, &peer.permits) {
                    Ok(admission) => admission,
                    Err(OutboundRelayAdmissionError::GlobalExhausted) => {
                        return ScheduleOutcome::GlobalPermitExhausted;
                    }
                    Err(OutboundRelayAdmissionError::PeerExhausted) => {
                        return ScheduleOutcome::Skipped;
                    }
                };
            (deposit_mutation_slot, Some(relay_admission))
        };
        // The durable startup/overflow gate may fail closed while readiness and semaphore
        // acquisition above are awaiting. Recheck only after every ordinary relay guard is owned
        // and immediately before publishing the request as in flight; returning here drops all
        // guards without leaking one mutable request across the transition.
        if !mutable_deposit_relay_is_admitted(
            self.mutable_deposit_relay_ready.load(Ordering::Acquire),
            &work.request,
        ) {
            return ScheduleOutcome::Skipped;
        }
        in_flight.insert(work.key);
        let key = work.key;
        let runtime = self.clone();
        let attempt_deadline = Instant::now()
            .checked_add(self.config.outbound_request_timeout)
            .expect("validated outbound timeout fits Tokio Instant");
        let task = tasks.spawn(async move {
            let _relay_admission = relay_admission;
            runtime.attempt(work, deposit_mutation_slot, attempt_deadline).await
        });
        let previous = scheduled.insert(task.id(), key);
        debug_assert!(previous.is_none(), "Tokio reused an active relay task identifier");
        ScheduleOutcome::Scheduled
    }

    async fn attempt(
        self: Arc<Self>,
        work: RelayWork,
        deposit_mutation_slot: Option<tokio::sync::OwnedSemaphorePermit>,
        attempt_deadline: Instant,
    ) -> AttemptResult {
        let RelayWork {
            key,
            recipient,
            request,
            target,
            response_expectation,
            requires_positive_ack,
            deposit_causal_lane: _,
        } = work;
        let completed = CompletedRelayWork { key, recipient, target, requires_positive_ack };
        let response = if recipient == self.server.party_id() {
            match request {
                PeerRequest::Deposit { operation, body } => {
                    match self
                        .dispatch_local_deposit_request(
                            operation,
                            body,
                            attempt_deadline,
                            deposit_mutation_slot,
                            true,
                        )
                        .await
                    {
                        Ok(Some(response)) => response,
                        Ok(None) => {
                            let shutting_down = self.shutdown.load(Ordering::Acquire);
                            if !shutting_down {
                                self.work_failure(key).await;
                            }
                            return AttemptResult {
                                work: completed,
                                disposition: DeliveryDisposition::Deferred(if shutting_down {
                                    "party runtime is shutting down".into()
                                } else {
                                    "local deposit admission exhausted the relay deadline".into()
                                }),
                            };
                        }
                        Err(error) => {
                            self.work_failure(key).await;
                            return AttemptResult {
                                work: completed,
                                disposition: DeliveryDisposition::Deferred(format!(
                                    "local deposit dispatch failed: {error:#}"
                                )),
                            };
                        }
                    }
                }
                request => {
                    debug_assert!(deposit_mutation_slot.is_none());
                    self.server.handle_local_peer_request(request).await
                }
            }
        } else {
            // The authenticated recipient slot and reciprocal relay admission are owned by the
            // enclosing task and remain live through this complete bounded attempt.
            let _deposit_mutation_slot = deposit_mutation_slot;
            let peer = self.peers[&recipient].clone();
            let connection = match outbound_operation_until(
                attempt_deadline,
                self.wait_for_shutdown(),
                peer.connection(&self.endpoint),
            )
            .await
            {
                Ok(connection) => connection,
                Err(OutboundOperationEnd::Shutdown) => {
                    return AttemptResult {
                        work: completed,
                        disposition: DeliveryDisposition::Deferred(
                            "party runtime is shutting down".into(),
                        ),
                    };
                }
                Err(OutboundOperationEnd::Deadline) => {
                    let delay = peer.transport_failure(None, self.config).await;
                    self.work_failure(key).await;
                    return AttemptResult {
                        work: completed,
                        disposition: DeliveryDisposition::Deferred(format!(
                            "QUIC connection exhausted the whole-attempt deadline \
                             ({delay:?} retry)"
                        )),
                    };
                }
            };
            let Some(connection) = connection else {
                return AttemptResult {
                    work: completed,
                    disposition: DeliveryDisposition::Deferred(
                        "peer reconnect is backing off".into(),
                    ),
                };
            };
            let connection = match connection {
                Ok(connection) => connection,
                Err(error) => {
                    let delay = peer.transport_failure(None, self.config).await;
                    self.work_failure(key).await;
                    return AttemptResult {
                        work: completed,
                        disposition: DeliveryDisposition::Deferred(format!(
                            "QUIC connection failed ({delay:?} retry): {error:#}"
                        )),
                    };
                }
            };
            let Some(request_timeout) = attempt_deadline.checked_duration_since(Instant::now())
            else {
                self.work_failure(key).await;
                return AttemptResult {
                    work: completed,
                    disposition: DeliveryDisposition::Deferred(format!(
                        "QUIC relay exhausted its whole-attempt deadline after {:?}",
                        self.config.outbound_request_timeout,
                    )),
                };
            };
            let request = connection.connection.request_with_timeout(key, request, request_timeout);
            match outbound_operation_until(attempt_deadline, self.wait_for_shutdown(), request)
                .await
            {
                Ok(Ok(response)) => {
                    self.server.record_authenticated_quic_response();
                    peer.transport_success().await;
                    response
                }
                Ok(Err(error)) => {
                    let connection_retry = peer
                        .request_connection_failure(connection.generation, &error, self.config)
                        .await;
                    self.work_failure(key).await;
                    return AttemptResult {
                        work: completed,
                        disposition: DeliveryDisposition::Deferred(format!(
                            "QUIC request failed (connection retry {connection_retry:?}): {error}"
                        )),
                    };
                }
                Err(OutboundOperationEnd::Shutdown) => {
                    return AttemptResult {
                        work: completed,
                        disposition: DeliveryDisposition::Deferred(
                            "party runtime is shutting down".into(),
                        ),
                    };
                }
                Err(OutboundOperationEnd::Deadline) => {
                    self.work_failure(key).await;
                    return AttemptResult {
                        work: completed,
                        disposition: DeliveryDisposition::Deferred(format!(
                            "QUIC relay exhausted its whole-attempt deadline after {:?}",
                            self.config.outbound_request_timeout,
                        )),
                    };
                }
            }
        };

        let disposition = classify_peer_response_for_expectation(&response_expectation, response);
        if disposition_requires_backoff(requires_positive_ack, &disposition) {
            self.work_failure(key).await;
        } else {
            self.work_success(key).await;
        }
        AttemptResult { work: completed, disposition }
    }

    async fn collect_attempt(
        &self,
        result: Result<(TaskId, AttemptResult), JoinError>,
        scheduled: &mut BTreeMap<TaskId, RequestId>,
        accepted: &mut BTreeMap<DurableMessageId, RequestId>,
        in_flight: &mut BTreeSet<RequestId>,
    ) {
        let scheduled_key = reconcile_joined_attempt(scheduled, in_flight, &result);
        let result = match result {
            Ok((_task_id, result)) => {
                if let Some(scheduled_key) = scheduled_key
                    && scheduled_key != result.work.key
                {
                    in_flight.remove(&scheduled_key);
                    self.work_failure(scheduled_key).await;
                    tracing::error!(
                        request_id = %result.work.key,
                        scheduled_request_id = %scheduled_key,
                        "QUIC relay task completed under the wrong request identifier"
                    );
                }
                result
            }
            Err(error) => {
                if let Some(key) = scheduled_key {
                    self.work_failure(key).await;
                    tracing::error!(%error, request_id = %key, "QUIC relay task failed");
                } else {
                    tracing::error!(%error, "unregistered QUIC relay task failed");
                }
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
                if error.starts_with("peer rejected request")
                    && matches!(
                        &result.work.target,
                        AcceptanceTarget::Durable(DurableMessageId::Deposit(_))
                    )
                {
                    tracing::warn!(
                        target: "threshold_monero::quic_peer_deferred_rejection",
                        recipient = %result.work.recipient,
                        request_id = %result.work.key,
                        target = ?result.work.target,
                        %error,
                        "authenticated peer deferred durable QUIC delivery"
                    );
                } else {
                    tracing::warn!(
                        target: "threshold_monero::quic_delivery_deferred",
                        recipient = %result.work.recipient,
                        request_id = %result.work.key,
                        target = ?result.work.target,
                        %error,
                        "QUIC durable delivery deferred"
                    );
                }
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
        if result.work.requires_positive_ack && !protocol_evidence_ack_authorized {
            let error = terminal_rejection.expect("deferred dispositions returned above");
            tracing::warn!(
                recipient = %result.work.recipient,
                request_id = %result.work.key,
                target = ?result.work.target,
                %error,
                "retaining rejected protocol evidence until a successful durable response"
            );
            in_flight.remove(&result.work.key);
            return;
        }
        if let Some(error) = terminal_rejection {
            tracing::warn!(
                target: "threshold_monero::quic_delivery_rejection",
                recipient = %result.work.recipient,
                request_id = %result.work.key,
                target = ?result.work.target,
                %error,
                "retiring terminally rejected QUIC outbox item"
            );
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
        let protocol_durable_ids =
            protocol_ids.iter().copied().map(DurableMessageId::Protocol).collect::<Vec<_>>();
        let deposit_durable_ids =
            deposit_ids.iter().copied().map(DurableMessageId::Deposit).collect::<Vec<_>>();
        let byzantine_durable_ids = byzantine_consolidation_acks
            .iter()
            .copied()
            .map(DurableMessageId::ByzantineConsolidation)
            .collect::<Vec<_>>();
        let key_rotation_durable_ids =
            key_rotation_ids.iter().copied().map(DurableMessageId::KeyRotation).collect::<Vec<_>>();

        let mut checkpoint_failed = false;
        if let Err(error) = checkpoint_ack_family(
            &protocol_durable_ids,
            accepted,
            in_flight,
            self.server.acknowledge_peer_messages(&protocol_ids),
        )
        .await
        {
            checkpoint_failed = true;
            tracing::error!(party = %self.server.party_id(), family = "protocol", %error, "cannot durably acknowledge successful QUIC delivery family; family remains pending");
        }
        if let Err(error) = checkpoint_ack_family(
            &deposit_durable_ids,
            accepted,
            in_flight,
            self.server.acknowledge_deposit_peer_messages(&deposit_ids),
        )
        .await
        {
            checkpoint_failed = true;
            tracing::error!(party = %self.server.party_id(), family = "deposit", %error, "cannot durably acknowledge successful QUIC delivery family; family remains pending");
        }
        let byzantine_checkpoint = async {
            for delivery in &byzantine_consolidation_acks {
                let acknowledgement = ByzantineRelayAck::new(delivery.recipient(), *delivery)?;
                self.server.acknowledge_byzantine_consolidation(acknowledgement).await?;
            }
            Ok::<(), anyhow::Error>(())
        };
        if let Err(error) =
            checkpoint_ack_family(&byzantine_durable_ids, accepted, in_flight, byzantine_checkpoint)
                .await
        {
            checkpoint_failed = true;
            tracing::error!(party = %self.server.party_id(), family = "Byzantine consolidation", %error, "cannot durably acknowledge successful QUIC delivery family; family remains pending");
        }
        if let Err(error) = checkpoint_ack_family(
            &key_rotation_durable_ids,
            accepted,
            in_flight,
            self.server.acknowledge_key_rotation_peer_messages(&key_rotation_ids),
        )
        .await
        {
            checkpoint_failed = true;
            tracing::error!(party = %self.server.party_id(), family = "key rotation", %error, "cannot durably acknowledge successful QUIC delivery family; family remains pending");
        }

        let now = Instant::now();
        let mut ack_retry = self.ack_retry.lock().await;
        if checkpoint_failed {
            ack_retry.failure(
                now,
                self.server.party_id(),
                self.config.retry_initial,
                self.config.retry_maximum,
            );
        } else {
            ack_retry.success(now);
            debug_assert!(accepted.is_empty(), "successful ACK families left accepted work behind");
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

fn deposit_prefix_collection_error_is_peer_invalid(error: &anyhow::Error) -> bool {
    let Some(DepositServiceError::DepositPrefixCollection(error)) =
        error.downcast_ref::<DepositServiceError>()
    else {
        return false;
    };
    matches!(
        error,
        DepositPrefixCollectionStoreError::Support(_)
            | DepositPrefixCollectionStoreError::Wire(_)
            | DepositPrefixCollectionStoreError::Committee(_)
            | DepositPrefixCollectionStoreError::Transport(_)
            | DepositPrefixCollectionStoreError::WrongPeer
            | DepositPrefixCollectionStoreError::WrongOperation
            | DepositPrefixCollectionStoreError::StaleRequest
            | DepositPrefixCollectionStoreError::RevisionRollback
    )
}

fn deposit_prefix_collection_error_is_source_invalid(error: &anyhow::Error) -> bool {
    if deposit_prefix_collection_error_is_peer_invalid(error) {
        return true;
    }
    matches!(
        error.downcast_ref::<DepositServiceError>(),
        Some(
            DepositServiceError::DepositSyncSupport(_)
                | DepositServiceError::DepositIndexCheckpoint(_)
                | DepositServiceError::DepositPrefixCollection(
                    DepositPrefixCollectionStoreError::WrongAuthority
                )
        )
    )
}

/// Keep availability, retention GC, scanner, BA/ROAST, and publication futures independently
/// pollable for their entire lifetime. A single `join!` inside a tick would run them concurrently
/// only once, then let one stuck RPC prevent every other pacemaker from reaching its next interval.
async fn run_deposit_pacemakers<Sync, HistoricalImport, RetentionGc, Scan, Consolidate, Publish>(
    synchronization: Sync,
    historical_import: HistoricalImport,
    retention_gc: RetentionGc,
    scanner: Scan,
    consolidation: Consolidate,
    publication: Publish,
) where
    Sync: Future<Output = ()>,
    HistoricalImport: Future<Output = ()>,
    RetentionGc: Future<Output = ()>,
    Scan: Future<Output = ()>,
    Consolidate: Future<Output = ()>,
    Publish: Future<Output = ()>,
{
    tokio::join!(
        synchronization,
        historical_import,
        retention_gc,
        scanner,
        consolidation,
        publication
    );
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
        KeyRotationDeliveryKind::FallbackVote => material.push(1),
        KeyRotationDeliveryKind::Proposal { view } => {
            material.push(2);
            material.extend_from_slice(&view.to_le_bytes());
        }
        KeyRotationDeliveryKind::Prevote { view } => {
            material.push(3);
            material.extend_from_slice(&view.to_le_bytes());
        }
        KeyRotationDeliveryKind::Precommit { view } => {
            material.push(4);
            material.extend_from_slice(&view.to_le_bytes());
        }
        KeyRotationDeliveryKind::ViewChange { target_view } => {
            material.push(5);
            material.extend_from_slice(&target_view.to_le_bytes());
        }
        KeyRotationDeliveryKind::ViewCertificate { target_view } => {
            material.push(6);
            material.extend_from_slice(&target_view.to_le_bytes());
        }
        KeyRotationDeliveryKind::Certificate => material.push(7),
    }
    material.extend_from_slice(&id.digest);
    RequestId::derive(network_id, b"key-rotation-outbox/v2", &material)
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

type DepositRelayLane = (PartyId, DepositCausalLane);

const fn deposit_relay_lane(
    id: DepositPeerMessageId,
    causal_lane: DepositCausalLane,
) -> DepositRelayLane {
    (id.recipient(), causal_lane)
}

/// Return one recipient's lane-causal predecessors in bounded round-robin order.
///
/// `DepositCausalLane` has a fixed deployment-independent protocol prefix and at most one
/// ClientRequest lane per bounded scenario party. Rotating strictly after the last successfully
/// admitted lane therefore gives every continuously ready protocol or client lane a turn within
/// `DepositCausalLane::COUNT` successful admissions. A missing prior lane still identifies the
/// correct insertion point, and reaching the end wraps to the earliest live lane.
fn deposit_relay_candidates_after<T>(
    candidates: BTreeMap<DepositCausalLane, T>,
    cursor: Option<DepositCausalLane>,
) -> Vec<(DepositCausalLane, T)> {
    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    if let Some(cursor) = cursor {
        let start = ordered.partition_point(|(lane, _)| *lane <= cursor);
        ordered.rotate_left(start);
    }
    ordered
}

fn direct_recipients_after<T>(
    candidates: BTreeMap<PartyId, T>,
    cursor: Option<PartyId>,
) -> Vec<(PartyId, T)> {
    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    if let Some(cursor) = cursor {
        let start = ordered.partition_point(|(recipient, _)| *recipient <= cursor);
        ordered.rotate_left(start);
    }
    ordered
}

fn activation_ack_candidates_after<T>(
    candidates: BTreeMap<ActivationAckOrder, T>,
    cursor: Option<ActivationAckOrder>,
) -> Vec<(ActivationAckOrder, T)> {
    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    if let Some(cursor) = cursor {
        let start = ordered.partition_point(|(order, _)| *order <= cursor);
        ordered.rotate_left(start);
    }
    ordered
}

fn activation_ack_exact_candidates_after<T>(
    candidates: BTreeMap<PeerMessageId, T>,
    cursor: Option<PeerMessageId>,
) -> Vec<(PeerMessageId, T)> {
    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    if let Some(cursor) = cursor {
        let start = ordered.partition_point(|(id, _)| *id <= cursor);
        ordered.rotate_left(start);
    }
    ordered
}

fn reconcile_active_deposit_recipients(
    active: &mut BTreeMap<PartyId, RequestId>,
    in_flight: &BTreeSet<RequestId>,
) {
    active.retain(|_, key| in_flight.contains(key));
}

fn retain_earliest_deposit_relay<K: Copy + Ord, T>(
    earliest: &mut BTreeMap<DepositRelayLane, (K, T)>,
    lane: DepositRelayLane,
    causal: K,
    relay: T,
) {
    let replace = earliest.get(&lane).is_none_or(|(current, _)| causal < *current);
    if replace {
        earliest.insert(lane, (causal, relay));
    }
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
    requires_positive_ack: bool,
    disposition: &DeliveryDisposition,
) -> bool {
    matches!(disposition, DeliveryDisposition::Deferred(_))
        || (matches!(disposition, DeliveryDisposition::TerminalRejection(_))
            && requires_positive_ack)
}

fn classify_peer_response_for_expectation(
    expectation: &RelayResponseExpectation,
    response: PeerResponse,
) -> DeliveryDisposition {
    if let RelayResponseExpectation::ByzantineConsolidation(expectation) = expectation
        && let PeerResponse::Success { body } = &response
    {
        return match expectation.validate_response(body) {
            Ok(()) => DeliveryDisposition::Accepted,
            Err(error) => DeliveryDisposition::Deferred(format!(
                "Byzantine consolidation delivery returned an invalid typed acknowledgement: {error:#}"
            )),
        };
    }
    classify_peer_response(response)
}

/// Byzantine consolidation evidence is retired only by its typed, exact delivery ACK. A plain
/// transport success is deliberately insufficient: otherwise a receiver could acknowledge a
/// different family/view/contribution while causing the sender to discard immutable relay work.
/// The typed decoder replaces this conservative branch once the canonical ROAST wire is routed.
#[cfg(test)]
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
    let requires_positive_ack = request_requires_positive_ack(&pending.request);
    RelayWork {
        key,
        recipient: pending.recipient(),
        request: pending.request,
        target: AcceptanceTarget::Epoch(key),
        response_expectation: RelayResponseExpectation::Generic,
        requires_positive_ack,
        deposit_causal_lane: None,
    }
}

/// Semantic key-rotation order within one target epoch. A proposal embeds the exact verified
/// view-change certificate for a future view and is the only message which can initialize an
/// absent reducer, so it precedes the standalone evidence it already carries.
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

/// Return one recipient's durable transition candidates in round-robin causal order.
///
/// The cursor records only a public ordering key and is bounded by the configured party set. If
/// its prior item was acknowledged or compacted, the first greater live item still follows it;
/// reaching the end wraps to the causally earliest retained item.
fn transition_candidates_after(
    candidates: BTreeMap<TransitionOrder, RelayWork>,
    cursor: Option<TransitionOrder>,
) -> Vec<(TransitionOrder, RelayWork)> {
    let mut ordered = candidates.into_iter().collect::<Vec<_>>();
    if let Some(cursor) = cursor {
        let start = ordered.partition_point(|(order, _)| *order <= cursor);
        ordered.rotate_left(start);
    }
    ordered
}

/// Retain every pending transition effect for each recipient, keyed by its causal order. The relay
/// starts at the causally earliest item, then remembers each successful admission and rotates
/// across the full retained set on later polls. This prevents permanently rejected historical
/// evidence from starving current work while still retrying every immutable item. Reducers validate
/// their own fine-grained ordering, so delivering a successor ahead of a stalled predecessor is at
/// worst extra retryable rejection churn, never a safety violation.
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
    use rand_core::OsRng;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::{
        committee::{Committee, Member, SessionId},
        compact_registry_archive::{
            CompactRegistryArchiveError, CompactRegistryArchiveHead, CompactRegistryObjectReader,
            CompactRegistryObjectRef, PendingCompactRegistryMutation,
            prepare_compact_registry_append, prepare_compact_registry_genesis,
            verify_compact_registry_object,
        },
        compact_registry_store::CompactRegistryStoreCheckpoint,
        config::{CommitteeSpec, Hex32, NetworkKind, Operation, ScenarioParty},
        deposit_archive::{
            DepositArchiveHead, DepositArchiveStore, DepositArtifactChunkRequest,
            MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES,
        },
        deposit_index::{
            DepositIndexBuilder, DepositIndexError, DepositIndexHead, DepositIndexObjectId,
            DepositIndexReader,
        },
        deposit_index_checkpoint::{
            DepositIndexCheckpointCandidate, DepositIndexCheckpointCertificate,
            DepositIndexCheckpointStatement, PortableDepositIndexHead,
            VerifiedDepositIndexCheckpoint, certify_checkpoint_candidate_for_test,
        },
        deposit_index_store::{DepositIndexStoreCheckpoint, VerifiedPortableIndexAdvance},
        deposit_ledger::{CertifiedLedgerEntry, LedgerStatement, VerifiedEntry},
        deposit_state_export::DepositHandoffStateBinding,
        deposit_sync_wire::{DepositSyncContext, DepositSyncObjectRef},
        deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
        quic_transport::{LocalTlsIdentity, PinnedPeerCertificate, QuicTransportConfig},
        storage::WalletArtifactRef,
    };

    type DepositSyncFrontierObjectMap = BTreeMap<DepositSyncObjectRef, Vec<u8>>;
    type DepositSyncFrontierFixture =
        (DepositSyncAnchorLease, [u8; 32], DepositSyncFrontierObjectMap);

    const STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY: PartyId = PartyId(1);

    struct StateTransferIntentTestTls {
        server_name: String,
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
    }

    impl StateTransferIntentTestTls {
        fn generate(party: PartyId) -> Self {
            let server_name = format!("intent-p{}.threshold-monero.invalid", party.0);
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

    fn state_transfer_intent_test_signing_seed(party: PartyId) -> [u8; 32] {
        let mut seed = [0x41; 32];
        seed[..2].copy_from_slice(&party.0.to_le_bytes());
        seed[2..10].copy_from_slice(b"intentEd");
        seed
    }

    fn state_transfer_intent_test_x25519_secret(party: PartyId) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..3].copy_from_slice(&party.0.to_le_bytes());
        secret[3..11].copy_from_slice(b"intentDh");
        secret
    }

    fn state_transfer_intent_test_scenario(
        root: &tempfile::TempDir,
        tls: &BTreeMap<PartyId, StateTransferIntentTestTls>,
    ) -> Scenario {
        let parties = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                let signing_seed = state_transfer_intent_test_signing_seed(party);
                let identity = Identity::from_test_secrets(
                    party,
                    0,
                    &signing_seed,
                    state_transfer_intent_test_x25519_secret(party),
                )
                .unwrap();
                ScenarioParty {
                    id: party,
                    admin_endpoint: format!("http://127.0.0.1:{}", 31_000 + id).parse().unwrap(),
                    quic_endpoint: format!("quic://127.0.0.1:{}", 32_000 + id).parse().unwrap(),
                    quic_server_name: tls[&party].server_name.clone(),
                    quic_certificate_file: root.path().join(format!("intent-p{id}.der")),
                    monerod_rpc_urls: vec![
                        format!("http://127.0.0.1:{}", 33_000 + id).parse().unwrap(),
                    ],
                    signing_key: Hex32(identity.signing_public_key()),
                    bootstrap_encryption_key: Hex32(identity.encryption_public_key()),
                }
            })
            .collect::<Vec<_>>();
        let members = (1_u16..=4).map(PartyId).collect::<Vec<_>>();
        Scenario {
            schema_version: crate::config::SCENARIO_SCHEMA_VERSION,
            demo_only: true,
            network: NetworkKind::Regtest,
            deposit_birth_anchor: None,
            acceptance_monerod_rpc_url: "http://127.0.0.1:18081".parse().unwrap(),
            parties,
            committees: vec![CommitteeSpec {
                epoch: 0,
                operation: Operation::Dkg,
                threshold: 1,
                fault_bound: 0,
                members: members.clone(),
                eligible_members: members,
            }],
            funding_blocks: 1,
            confirmation_blocks: 1,
            deposit_maximum_fee_atomic_units: 1_000_000_000,
            poll_interval_ms: 10,
            protocol_timeout_seconds: 10,
            proactive_refresh_interval_seconds: 86_400,
        }
    }

    fn state_transfer_intent_test_endpoint(
        scenario: &Scenario,
        tls: &BTreeMap<PartyId, StateTransferIntentTestTls>,
    ) -> QuicPeerEndpoint {
        QuicPeerEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY,
            scenario.quic_network_id().unwrap(),
            tls[&STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY].local_identity(),
            tls.iter()
                .filter(|(party, _)| **party != STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY)
                .map(|(party, material)| material.pin(*party)),
            QuicTransportConfig::default(),
        )
        .unwrap()
    }

    struct StateTransferIntentRuntimeFixture {
        root: tempfile::TempDir,
        scenario: Scenario,
        tls: BTreeMap<PartyId, StateTransferIntentTestTls>,
        signing_seed: [u8; 32],
        bootstrap_x25519_secret: [u8; 32],
        server: Arc<PartyServer>,
        runtime: Arc<QuicRuntime>,
    }

    impl StateTransferIntentRuntimeFixture {
        async fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let tls = (1_u16..=4)
                .map(|id| {
                    let party = PartyId(id);
                    (party, StateTransferIntentTestTls::generate(party))
                })
                .collect::<BTreeMap<_, _>>();
            let scenario = state_transfer_intent_test_scenario(&root, &tls);
            scenario.validate().unwrap();
            let signing_seed =
                state_transfer_intent_test_signing_seed(STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY);
            let bootstrap_x25519_secret =
                state_transfer_intent_test_x25519_secret(STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY);
            let server = Box::pin(PartyServer::new(
                STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY,
                scenario.clone(),
                root.path().join("party-1"),
                &signing_seed,
                &bootstrap_x25519_secret,
            ))
            .await
            .unwrap();
            let runtime = Arc::new(
                QuicRuntime::new(
                    state_transfer_intent_test_endpoint(&scenario, &tls),
                    server.clone(),
                    QuicRuntimeConfig::default(),
                )
                .unwrap(),
            );
            Self { root, scenario, tls, signing_seed, bootstrap_x25519_secret, server, runtime }
        }

        fn configured_parties(&self) -> BTreeSet<PartyId> {
            self.scenario.parties.iter().map(|party| party.id).collect()
        }

        async fn durable_entries(&self) -> (u64, BTreeMap<PartyId, DurableStateTransferIntent>) {
            let durable = self.server.load_deposit_state_transfer_intents().await.unwrap().unwrap();
            decode_state_transfer_intent_snapshot(
                durable.state.as_bytes(),
                self.scenario.quic_network_id().unwrap(),
                STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY,
                &self.configured_parties(),
            )
            .unwrap()
        }

        async fn restart(self) -> Self {
            let Self {
                root,
                scenario,
                tls,
                signing_seed,
                bootstrap_x25519_secret,
                server,
                runtime,
            } = self;
            drop(runtime);
            drop(server);

            let server = Box::pin(PartyServer::new(
                STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY,
                scenario.clone(),
                root.path().join("party-1"),
                &signing_seed,
                &bootstrap_x25519_secret,
            ))
            .await
            .unwrap();
            let runtime = Arc::new(
                QuicRuntime::new(
                    state_transfer_intent_test_endpoint(&scenario, &tls),
                    server.clone(),
                    QuicRuntimeConfig::default(),
                )
                .unwrap(),
            );
            Self { root, scenario, tls, signing_seed, bootstrap_x25519_secret, server, runtime }
        }
    }

    fn state_transfer_intent_test_snapshot_bytes(
        network_id: [u8; 32],
        local_party: PartyId,
        high_water_generation: u64,
        entries: Vec<DurableStateTransferIntent>,
    ) -> Vec<u8> {
        postcard::to_allocvec(&DurableStateTransferIntentSnapshot {
            version: STATE_TRANSFER_INTENT_SNAPSHOT_VERSION,
            network_id,
            local_party,
            high_water_generation,
            entries,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn allocation_backfill_burst_is_bounded_and_stops_when_settled() {
        let bounded_ticks = Arc::new(AtomicUsize::new(0));
        let tick_counter = Arc::clone(&bounded_ticks);
        let completed = run_bounded_deposit_scanner_burst(
            4,
            move || {
                let tick_counter = Arc::clone(&tick_counter);
                async move {
                    tick_counter.fetch_add(1, Ordering::AcqRel);
                    Ok::<bool, ()>(true)
                }
            },
            || false,
        )
        .await
        .unwrap();
        assert_eq!(completed, 4);
        assert_eq!(bounded_ticks.load(Ordering::Acquire), 4);

        let settling_ticks = Arc::new(AtomicUsize::new(0));
        let tick_counter = Arc::clone(&settling_ticks);
        let completed = run_bounded_deposit_scanner_burst(
            8,
            move || {
                let tick_counter = Arc::clone(&tick_counter);
                async move {
                    let completed = tick_counter.fetch_add(1, Ordering::AcqRel) + 1;
                    Ok::<bool, ()>(completed < 3)
                }
            },
            || false,
        )
        .await
        .unwrap();
        assert_eq!(completed, 3);
        assert_eq!(settling_ticks.load(Ordering::Acquire), 3);
    }

    #[tokio::test]
    async fn allocation_backfill_burst_observes_shutdown_between_durable_ticks() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_after_tick = Arc::clone(&shutdown);
        let shutdown_probe = Arc::clone(&shutdown);
        let ticks = Arc::new(AtomicUsize::new(0));
        let tick_counter = Arc::clone(&ticks);
        let completed = run_bounded_deposit_scanner_burst(
            8,
            move || {
                let shutdown = Arc::clone(&shutdown_after_tick);
                let tick_counter = Arc::clone(&tick_counter);
                async move {
                    tick_counter.fetch_add(1, Ordering::AcqRel);
                    shutdown.store(true, Ordering::Release);
                    Ok::<bool, ()>(true)
                }
            },
            move || shutdown_probe.load(Ordering::Acquire),
        )
        .await
        .unwrap();
        assert_eq!(completed, 1);
        assert_eq!(ticks.load(Ordering::Acquire), 1);
    }

    #[test]
    fn local_preflight_shift_preserves_consumed_network_time_and_work_caps() {
        let origin = Instant::now();
        let deadline = origin + Duration::from_secs(6);
        let local_started = origin + Duration::from_secs(2);
        let local_finished = local_started + Duration::from_secs(10);
        let exhausted = DepositSyncTickWork {
            requests: MAX_DEPOSIT_SYNC_REQUESTS_PER_TICK,
            pages: MAX_DEPOSIT_SYNC_PAGES_PER_TICK,
            objects: MAX_DEPOSIT_SYNC_OBJECTS_PER_TICK,
            wire_bytes: MAX_DEPOSIT_SYNC_WIRE_BYTES_PER_TICK,
        };

        let shifted =
            shift_deposit_sync_deadline_past_local_work(deadline, local_started, local_finished)
                .unwrap();

        assert_eq!(shifted.saturating_duration_since(local_finished), Duration::from_secs(4));
        assert_eq!(
            exhausted,
            DepositSyncTickWork {
                requests: MAX_DEPOSIT_SYNC_REQUESTS_PER_TICK,
                pages: MAX_DEPOSIT_SYNC_PAGES_PER_TICK,
                objects: MAX_DEPOSIT_SYNC_OBJECTS_PER_TICK,
                wire_bytes: MAX_DEPOSIT_SYNC_WIRE_BYTES_PER_TICK,
            }
        );
        assert!(!exhausted.may_request(1), "deadline accounting must not refund work capacity");
    }

    #[test]
    fn consecutive_local_preflight_shifts_preserve_all_intervening_network_time() {
        let origin = Instant::now();
        let deadline = origin + Duration::from_secs(6);

        // One second of network work precedes the first three-second local preflight.
        let first_started = origin + Duration::from_secs(1);
        let first_finished = first_started + Duration::from_secs(3);
        let shifted_once =
            shift_deposit_sync_deadline_past_local_work(deadline, first_started, first_finished)
                .unwrap();
        assert_eq!(shifted_once.saturating_duration_since(first_finished), Duration::from_secs(5));

        // A second network second remains consumed when another finite local preflight is paused.
        let second_started = first_finished + Duration::from_secs(1);
        let second_finished = second_started + Duration::from_secs(5);
        let shifted_twice = shift_deposit_sync_deadline_past_local_work(
            shifted_once,
            second_started,
            second_finished,
        )
        .unwrap();
        assert_eq!(
            shifted_twice.saturating_duration_since(second_finished),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn causal_seal_local_phases_do_not_refund_network_time() {
        let origin = Instant::now();
        let budget = Duration::from_secs(30);
        let mut deadline = origin + budget;
        let mut now = origin;
        // Census, freeze recovery, reconstruction, and receipt persistence can each take
        // longer than a network tick. Only the two simulated remote waits consume its budget.
        for phase in 0..4 {
            let started = now;
            now += Duration::from_secs(45);
            deadline = shift_deposit_sync_deadline_past_local_work(deadline, started, now).unwrap();
            if phase < 2 {
                now += Duration::from_secs(7);
            }
        }
        assert_eq!(deadline.duration_since(now), Duration::from_secs(16));
        assert_eq!(bounded_deposit_rpc_deadline(deadline, budget, now), Some(deadline));
        assert!(bounded_deposit_rpc_deadline(deadline, budget, deadline).is_none());
    }

    #[test]
    fn background_local_preflight_past_initial_deadline_still_admits_one_bounded_rpc() {
        let interval = Duration::from_secs(8);
        let request_timeout = Duration::from_secs(30);
        let retry_budget =
            deposit_state_transfer_background_budget(interval, request_timeout).unwrap();
        let origin = Instant::now();
        let initial_deadline = origin + retry_budget;
        let local_finished = origin + Duration::from_secs(5);
        assert!(local_finished > initial_deadline);

        let shifted =
            shift_deposit_sync_deadline_past_local_work(initial_deadline, origin, local_finished)
                .unwrap();
        let rpc_deadline =
            bounded_deposit_rpc_deadline(shifted, request_timeout, local_finished).unwrap();

        assert_eq!(
            rpc_deadline.saturating_duration_since(local_finished),
            retry_budget,
            "finite local recovery must preserve the complete background network budget",
        );
        assert!(
            bounded_deposit_rpc_deadline(shifted, request_timeout, rpc_deadline).is_none(),
            "one silent RPC which reaches the turn deadline must exhaust that turn",
        );
    }

    #[test]
    fn silent_background_rpc_stays_bounded_and_next_turn_rotates_recipient() {
        let interval = Duration::from_secs(8);
        let request_timeout = Duration::from_secs(30);
        let retry_budget =
            deposit_state_transfer_background_budget(interval, request_timeout).unwrap();
        let origin = Instant::now();
        let turn_deadline = origin + retry_budget;
        let silent_rpc_deadline =
            bounded_deposit_rpc_deadline(turn_deadline, request_timeout, origin).unwrap();
        let recipients = AtomicUsize::new(0);

        assert_eq!(silent_rpc_deadline, turn_deadline);
        assert_eq!(deposit_state_transfer_background_start(&recipients, 3), 0);
        assert!(
            bounded_deposit_rpc_deadline(turn_deadline, request_timeout, silent_rpc_deadline,)
                .is_none(),
            "a silent peer may consume no more than the quarter-period network budget",
        );
        assert_eq!(
            deposit_state_transfer_background_start(&recipients, 3),
            1,
            "the next background turn must advance past the silent recipient",
        );
    }

    #[derive(Default)]
    struct FrontierRegistryObjects(BTreeMap<CompactRegistryObjectRef, Vec<u8>>);

    impl FrontierRegistryObjects {
        fn install(&mut self, pending: &PendingCompactRegistryMutation) {
            self.0.extend(
                pending
                    .staged_objects()
                    .iter()
                    .map(|object| (object.reference(), object.contents().to_vec())),
            );
        }
    }

    impl CompactRegistryObjectReader for FrontierRegistryObjects {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            Ok(self.0.get(&reference).cloned())
        }
    }

    #[derive(Default)]
    struct EmptyFrontierIndexReader;

    impl DepositIndexReader for EmptyFrontierIndexReader {
        fn load_index_object(
            &self,
            _id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(None)
        }
    }

    struct PreparedBranchingDepositSyncFrontier {
        context: DepositSyncContext,
        wallet: DepositWalletId,
        registry: CompactRegistryStoreCheckpoint,
        index: DepositIndexStoreCheckpoint,
        ledger: Box<CertifiedLedgerEntry>,
        verified_ledger: VerifiedEntry,
        checkpoint: Box<DepositIndexCheckpointCertificate>,
        verified_checkpoint: Box<VerifiedDepositIndexCheckpoint>,
        objects: DepositSyncFrontierObjectMap,
    }

    fn frontier_identity(tag: u8, epoch: u64) -> Identity {
        let signing_seed = [tag.wrapping_add(11); 32];
        let mut encryption_secret = [tag.wrapping_add(12); 32];
        encryption_secret[0] ^= u8::try_from(epoch).unwrap();
        Identity::from_test_secrets(PartyId(1), epoch, &signing_seed, encryption_secret).unwrap()
    }

    fn frontier_committee(epoch: u64, identity: &Identity) -> Committee {
        Committee {
            epoch,
            threshold: 1,
            members: vec![Member {
                id: identity.party(),
                signing_key: identity.signing_public_key(),
                encryption_key: identity.encryption_public_key(),
            }],
        }
        .canonicalized()
        .unwrap()
    }

    fn collect_reachable_frontier_registry_objects(
        head: &CompactRegistryArchiveHead,
        reader: &FrontierRegistryObjects,
    ) -> DepositSyncFrontierObjectMap {
        let mut pending = vec![head.index_root_reference()];
        let mut objects = BTreeMap::new();
        while let Some(reference) = pending.pop() {
            let object_reference = DepositSyncObjectRef::Registry(reference);
            if objects.contains_key(&object_reference) {
                continue;
            }
            let bytes = reader.load(reference).unwrap().expect("reachable registry object");
            let verified = verify_compact_registry_object(reference, &bytes).unwrap();
            pending.extend(verified.children().iter().copied());
            objects.insert(object_reference, bytes);
        }
        objects
    }

    fn prepare_branching_deposit_sync_frontier(
        tag: u8,
    ) -> Box<PreparedBranchingDepositSyncFrontier> {
        const SOURCE: PartyId = PartyId(1);

        let wallet = DepositWalletId([tag; 32]);
        let network = [tag.wrapping_add(1); 32];
        let context = DepositSyncContext::new(network, wallet).unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let initial_index = DepositIndexHead::empty_portable(wallet, first_index).unwrap();
        let source_portable = PortableDepositIndexHead::from_head(&initial_index).unwrap();
        let source_identity = frontier_identity(tag, 0);
        let source_committee = frontier_committee(0, &source_identity);
        let source_identities = BTreeMap::from([(SOURCE, source_identity)]);
        let key_id = [tag.wrapping_add(2); 32];
        let group_key = [tag.wrapping_add(3); 32];
        let source_target = VerifiedRegistryHandoffTarget::for_test(
            source_committee.clone(),
            0,
            [tag.wrapping_add(4); 32],
            [tag.wrapping_add(5); 32],
            wallet,
            key_id,
            group_key,
        )
        .unwrap();
        let source_pending =
            prepare_compact_registry_genesis(&source_target, first_index, source_portable.digest())
                .unwrap();
        let source_head = source_pending.proposed_head().clone();
        let source_registry = source_head.registry().clone();
        let mut registry_objects = FrontierRegistryObjects::default();
        registry_objects.install(&source_pending);

        let target_identity = frontier_identity(tag, 1);
        let target = VerifiedRegistryHandoffTarget::for_test(
            frontier_committee(1, &target_identity),
            0,
            [tag.wrapping_add(6); 32],
            [tag.wrapping_add(7); 32],
            wallet,
            key_id,
            group_key,
        )
        .unwrap();
        let source_state = DepositHandoffStateBinding::new(
            Some([tag.wrapping_add(8); 32]),
            source_portable.clone(),
        )
        .unwrap();
        let statement = LedgerStatement::handoff(
            &source_registry,
            source_portable.through_sequence().checked_add(1).unwrap(),
            source_portable.ledger_head(),
            source_state,
            &target,
            source_portable.next_index(),
        )
        .unwrap();
        let attestation = source_identities[&SOURCE]
            .sign_envelope(
                &source_committee,
                statement.slot_session(),
                None,
                statement.sequence,
                statement.attestation_payload().unwrap(),
            )
            .unwrap();
        let ledger = Box::new(CertifiedLedgerEntry { statement, attestations: vec![attestation] });
        let verified_ledger = ledger.verify_active(&source_registry, None).unwrap();
        let handoff = ledger.registry_handoff_certificate(&source_registry).unwrap();

        let index_reader = EmptyFrontierIndexReader;
        let mut preflight_builder =
            DepositIndexBuilder::new(&index_reader, initial_index.clone()).unwrap();
        let preflight = preflight_builder.preflight_ledger_statement(&ledger.statement).unwrap();
        let mut index_builder = DepositIndexBuilder::new(&index_reader, initial_index).unwrap();
        assert!(
            index_builder.apply_verified_active_entry(&ledger, &source_registry, None).unwrap()
        );
        let update = index_builder.finish().unwrap().unwrap();
        let checkpoint_statement = DepositIndexCheckpointStatement::for_transition(
            1,
            network,
            &source_registry,
            None,
            None,
            &ledger,
            &preflight,
            &update,
            &index_reader,
        )
        .unwrap();
        let selection = certify_checkpoint_candidate_for_test(
            network,
            &source_registry,
            checkpoint_statement.sequence(),
            checkpoint_statement.previous_head(),
            DepositIndexCheckpointCandidate::Ledger(ledger.as_ref().clone()),
            &source_identities,
        );
        let checkpoint_witness = source_identities[&SOURCE]
            .sign_envelope(
                source_registry.active().committee(),
                checkpoint_statement.slot_session(),
                None,
                checkpoint_statement.sequence(),
                checkpoint_statement.to_bytes().unwrap(),
            )
            .unwrap();
        let checkpoint = Box::new(
            DepositIndexCheckpointCertificate::from_witnesses(
                network,
                &source_registry,
                None,
                None,
                &ledger,
                checkpoint_statement,
                selection,
                vec![checkpoint_witness],
            )
            .unwrap(),
        );
        let verified_checkpoint = Box::new(
            checkpoint.verify_active(network, &source_registry, None, None, &ledger).unwrap(),
        );
        let portable_advance =
            VerifiedPortableIndexAdvance::from_certified_checkpoint(&verified_checkpoint).unwrap();
        let index = DepositIndexStoreCheckpoint::empty(wallet, SOURCE, first_index)
            .unwrap()
            .adopt_verified_portable(&portable_advance)
            .unwrap();

        let target_pending = prepare_compact_registry_append(
            &source_head,
            &target,
            handoff,
            &source_portable,
            &registry_objects,
        )
        .unwrap();
        let target_head = target_pending.proposed_head().clone();
        registry_objects.install(&target_pending);
        let registry =
            CompactRegistryStoreCheckpoint::settled(wallet, target_head.clone()).unwrap();
        let mut objects =
            collect_reachable_frontier_registry_objects(&target_head, &registry_objects);
        objects.extend(
            update
                .staged_objects()
                .map(|(id, bytes)| (DepositSyncObjectRef::Index(id), bytes.to_vec())),
        );

        Box::new(PreparedBranchingDepositSyncFrontier {
            context,
            wallet,
            registry,
            index,
            ledger,
            verified_ledger,
            checkpoint,
            verified_checkpoint,
            objects,
        })
    }

    async fn load_frontier_archive_object(
        archive: &DepositArchiveStore,
        reference: WalletArtifactRef,
    ) -> Vec<u8> {
        let length = usize::try_from(reference.plaintext_len()).unwrap();
        assert!(length <= MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES);
        let request =
            DepositArtifactChunkRequest::new(reference, 0, u32::try_from(length).unwrap()).unwrap();
        let chunk = archive.artifact_chunk(request).await.unwrap();
        assert!(chunk.complete);
        chunk.bytes
    }

    fn branching_deposit_sync_frontier_fixture(
        tag: u8,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DepositSyncFrontierFixture>>> {
        Box::pin(async move {
            let mut prepared = prepare_branching_deposit_sync_frontier(tag);
            let archive_directory = tempfile::tempdir().unwrap();
            let archive =
                DepositArchiveStore::new(archive_directory.path(), PartyId(1), &[tag; 32]).unwrap();
            let mut rng = OsRng;
            let staged = archive
                .stage_certified_ledger_entry(&prepared.ledger, &prepared.verified_ledger, &mut rng)
                .await
                .unwrap();
            let append = archive
                .append_ledger_checkpoint(
                    DepositArchiveHead::empty(prepared.wallet).unwrap(),
                    staged,
                    &prepared.checkpoint,
                    &prepared.verified_checkpoint,
                    &mut rng,
                )
                .await
                .unwrap();
            assert!(append.appended);
            for reference in [
                append.head.segment_reference().unwrap(),
                append.event_artifact,
                append.entry_artifact,
                append.checkpoint_artifact,
            ] {
                let bytes = load_frontier_archive_object(&archive, reference).await;
                assert!(
                    prepared
                        .objects
                        .insert(DepositSyncObjectRef::CertificateArchive(reference), bytes)
                        .is_none()
                );
            }

            let advertisement = DepositSyncAdvertisement::from_checkpoints(
                prepared.context,
                &prepared.registry,
                append.head,
                &prepared.index,
                Some(prepared.checkpoint.as_ref().clone()),
            )
            .unwrap();
            let request =
                DepositSyncHeadRequest::new(prepared.context, PartyId(1), PartyId(2)).unwrap();
            let mac_key = [tag.wrapping_add(9); 32];
            let response =
                DepositSyncHeadResponse::issue(request, advertisement, &mac_key).unwrap();
            let objects = std::mem::take(&mut prepared.objects);
            (response.lease(), mac_key, objects)
        })
    }

    fn deposit_sync_frontier_fixture(
        tag: u8,
    ) -> (
        DepositSyncAnchorLease,
        [u8; 32],
        BTreeMap<crate::deposit_sync_wire::DepositSyncObjectRef, Vec<u8>>,
    ) {
        let wallet = DepositWalletId([tag; 32]);
        let context =
            crate::deposit_sync_wire::DepositSyncContext::new([tag.wrapping_add(64); 32], wallet)
                .unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let index = DepositIndexStoreCheckpoint::empty(wallet, PartyId(1), first_index).unwrap();
        let portable = PortableDepositIndexHead::from_head(index.portable_head()).unwrap();
        let committee = Committee {
            epoch: 0,
            threshold: 1,
            members: vec![Member {
                id: PartyId(1),
                signing_key: [tag.wrapping_add(1); 32],
                encryption_key: [tag.wrapping_add(2); 32],
            }],
        };
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            0,
            [tag.wrapping_add(3); 32],
            [tag.wrapping_add(4); 32],
            wallet,
            [tag.wrapping_add(5); 32],
            [tag.wrapping_add(6); 32],
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, first_index, portable.digest()).unwrap();
        let registry =
            CompactRegistryStoreCheckpoint::settled(wallet, pending.proposed_head().clone())
                .unwrap();
        let advertisement = DepositSyncAdvertisement::from_checkpoints(
            context,
            &registry,
            DepositArchiveHead::empty(wallet).unwrap(),
            &index,
            None,
        )
        .unwrap();
        let request = DepositSyncHeadRequest::new(context, PartyId(1), PartyId(2)).unwrap();
        let mac_key = [tag.wrapping_add(7); 32];
        let response = DepositSyncHeadResponse::issue(request, advertisement, &mac_key).unwrap();
        let objects = pending
            .staged_objects()
            .iter()
            .map(|object| {
                (
                    crate::deposit_sync_wire::DepositSyncObjectRef::Registry(object.reference()),
                    object.contents().to_vec(),
                )
            })
            .collect();
        (response.lease(), mac_key, objects)
    }

    fn build_deposit_sync_frontier_page(
        request: &DepositSyncObjectPageRequest,
        mac_key: &[u8; 32],
        objects: &DepositSyncFrontierObjectMap,
    ) -> (DepositSyncObjectPage, bool) {
        let mut page_objects = Vec::with_capacity(request.entries().len());
        let mut capabilities = Vec::new();
        let mut saw_siblings = false;
        for entry in request.entries() {
            let object = crate::deposit_sync_wire::DepositSyncObject::new(
                entry.reference(),
                objects[&entry.reference()].clone(),
            )
            .unwrap();
            let children = object.authenticated_semantic_children(entry.target()).unwrap();
            saw_siblings |= children.len() >= 2;
            capabilities.extend(children.into_iter().map(|child| {
                crate::deposit_sync_wire::DepositSyncObjectCapability::issue(
                    mac_key,
                    request.lease(),
                    entry.target(),
                    child,
                )
                .unwrap()
            }));
            page_objects.push(object);
        }
        (DepositSyncObjectPage::build(request, page_objects, capabilities).unwrap(), saw_siblings)
    }

    #[tokio::test]
    async fn deposit_sync_frontier_batches_each_parent_exactly_once_across_restart() {
        let (lease, mac_key, objects) = branching_deposit_sync_frontier_fixture(0x31).await;
        assert_eq!(lease.anchor().registry_active_epoch(), 1);
        let mut frontier = DepositSyncFrontier::fresh(lease).unwrap();
        let mut request_digests = BTreeSet::new();
        let mut requested_targets = BTreeSet::new();
        let mut page_count = 0_usize;
        let mut max_batch = 0_usize;
        let mut saw_siblings = false;

        while let Some(request) = frontier.request().unwrap() {
            page_count += 1;
            max_batch = max_batch.max(request.entries().len());
            assert!(request_digests.insert(request.digest()), "frontier reused an exact request");
            for entry in request.entries() {
                assert!(
                    requested_targets.insert(entry.target()),
                    "frontier fetched one semantic target more than once"
                );
            }
            let (page, page_saw_siblings) =
                build_deposit_sync_frontier_page(&request, &mac_key, &objects);
            saw_siblings |= page_saw_siblings;
            frontier.apply_page(&page).unwrap();

            // Every page is a crash cut: only the authenticated cursor survives.
            let checkpoint = frontier.to_bytes().unwrap();
            frontier = DepositSyncFrontier::from_checkpoint(lease, &checkpoint).unwrap();
        }
        assert!(frontier.complete);
        assert!(saw_siblings, "fixture did not exercise a multi-child continuation");
        assert!(max_batch > 1, "frontier never used the wire's batched object request");
        assert_eq!(request_digests.len(), page_count);
        assert!(
            page_count < requested_targets.len(),
            "batching did not reduce the number of durable page merges"
        );
    }

    #[tokio::test]
    async fn deposit_sync_frontier_rejects_tampered_cursor_and_stale_page() {
        let (lease, _, _) = deposit_sync_frontier_fixture(0x41);
        let (other_lease, _, _) = deposit_sync_frontier_fixture(0x42);
        let frontier = DepositSyncFrontier::fresh(lease).unwrap();
        let canonical = frontier.to_bytes().unwrap();

        assert!(DepositSyncFrontier::from_checkpoint(other_lease, &canonical).is_err());
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(DepositSyncFrontier::from_checkpoint(lease, &trailing).is_err());

        let mut duplicate = frontier.clone();
        duplicate.pending.push(*duplicate.pending.last().unwrap());
        let duplicate = postcard::to_allocvec(&duplicate).unwrap();
        assert!(DepositSyncFrontier::from_checkpoint(lease, &duplicate).is_err());

        let mut inconsistent_completion = frontier.clone();
        inconsistent_completion.complete = true;
        let inconsistent_completion = postcard::to_allocvec(&inconsistent_completion).unwrap();
        assert!(DepositSyncFrontier::from_checkpoint(lease, &inconsistent_completion).is_err());

        let (lease, mac_key, objects) = branching_deposit_sync_frontier_fixture(0x43).await;
        let mut stale_frontier = DepositSyncFrontier::fresh(lease).unwrap();
        let request = stale_frontier.request().unwrap().unwrap();
        let (page, _) = build_deposit_sync_frontier_page(&request, &mac_key, &objects);
        stale_frontier.pending.swap(0, 1);
        let tampered = stale_frontier.clone();
        assert!(
            stale_frontier.apply_page(&page).is_err(),
            "a page bound to another deterministic frontier order was accepted"
        );
        assert_eq!(
            stale_frontier, tampered,
            "a rejected page mutated the durable traversal frontier"
        );
    }

    #[tokio::test]
    async fn deposit_sync_frontier_restart_is_request_for_request_equivalent() {
        let (lease, mac_key, objects) = branching_deposit_sync_frontier_fixture(0x44).await;
        let mut uninterrupted = DepositSyncFrontier::fresh(lease).unwrap();
        let mut restarted = uninterrupted.clone();

        loop {
            let uninterrupted_request = uninterrupted.request().unwrap();
            let restarted_request = restarted.request().unwrap();
            assert_eq!(uninterrupted_request, restarted_request);
            let Some(request) = uninterrupted_request else {
                break;
            };
            let (page, _) = build_deposit_sync_frontier_page(&request, &mac_key, &objects);
            uninterrupted.apply_page(&page).unwrap();
            restarted.apply_page(&page).unwrap();
            let checkpoint = restarted.to_bytes().unwrap();
            restarted = DepositSyncFrontier::from_checkpoint(lease, &checkpoint).unwrap();
            assert_eq!(uninterrupted, restarted);
        }
        assert!(uninterrupted.complete);
        assert_eq!(uninterrupted.to_bytes().unwrap(), restarted.to_bytes().unwrap());
    }

    fn transition_test_work(recipient: PartyId, key_byte: u8, request: PeerRequest) -> RelayWork {
        let key = RequestId::from_bytes([key_byte; 32]);
        RelayWork {
            key,
            recipient,
            requires_positive_ack: request_requires_positive_ack(&request),
            request,
            target: AcceptanceTarget::Epoch(key),
            response_expectation: RelayResponseExpectation::Generic,
            deposit_causal_lane: None,
        }
    }

    fn request_id_for_counter(counter: u64) -> RequestId {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&counter.to_le_bytes());
        RequestId::from_bytes(bytes)
    }

    #[test]
    fn same_request_id_with_a_different_body_conflicts_instead_of_replaying_success() {
        let request_id = RequestId::from_bytes([0xA1; 32]);
        // The authenticated transport normally makes the fingerprint equal the recomputed
        // request identifier. Distinct values exercise the cache's defense-in-depth conflict
        // branch directly.
        let original_fingerprint = [0x11; 32];
        let equivocation_fingerprint = [0x22; 32];
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
        let fingerprint = request_id.to_bytes();
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

    #[tokio::test]
    async fn panicked_relay_task_recovers_its_in_flight_request_id() {
        let request_id = RequestId::from_bytes([0xA4; 32]);
        let mut tasks = JoinSet::<()>::new();
        let task = tasks.spawn(async {
            panic!("intentional relay-task panic");
        });
        let mut scheduled = BTreeMap::from([(task.id(), request_id)]);
        let mut in_flight = BTreeSet::from([request_id]);

        let result = tasks.join_next_with_id().await.expect("relay task must complete");
        assert!(result.is_err());
        let recovered = reconcile_joined_attempt(&mut scheduled, &mut in_flight, &result)
            .expect("panicked task must remain correlated to its request");
        assert_eq!(recovered, request_id);
        assert!(in_flight.is_empty());
        assert!(scheduled.is_empty());
    }

    #[tokio::test]
    async fn outbound_request_deadline_releases_global_and_peer_permits() {
        let global = Arc::new(Semaphore::new(1));
        let peer = Arc::new(Semaphore::new(1));

        let result = {
            let _global_permit = global.clone().try_acquire_owned().unwrap();
            let _peer_permit = peer.clone().try_acquire_owned().unwrap();
            outbound_request_with_deadline(Duration::ZERO, std::future::pending::<()>()).await
        };

        assert!(result.is_err(), "a non-responsive stream must exhaust its deadline");
        assert!(global.clone().try_acquire_owned().is_ok());
        assert!(peer.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn failed_partial_ack_batch_does_not_pin_a_successful_unrelated_family() {
        let session = SessionId([0xC1; 32]);
        let first_protocol = DurableMessageId::Protocol(PeerMessageId::Avss {
            session,
            recipient: PartyId(2),
            digest: [0xC2; 32],
        });
        let second_protocol = DurableMessageId::Protocol(PeerMessageId::Qual {
            session,
            recipient: PartyId(2),
            digest: [0xC3; 32],
        });
        let deposit = DurableMessageId::Deposit(DepositPeerMessageId::derive(
            crate::deposit_wallet::DepositWalletId([0xC4; 32]),
            7,
            PartyId(3),
            DepositOperation::Attest,
            b"independent deposit ACK",
        ));
        let first_request = RequestId::from_bytes([0xC5; 32]);
        let second_request = RequestId::from_bytes([0xC6; 32]);
        let deposit_request = RequestId::from_bytes([0xC7; 32]);
        let mut accepted = BTreeMap::from([
            (first_protocol, first_request),
            (second_protocol, second_request),
            (deposit, deposit_request),
        ]);
        let mut in_flight = BTreeSet::from([first_request, second_request, deposit_request]);
        let durable = Arc::new(StdMutex::new(BTreeSet::new()));
        let protocol_family = vec![first_protocol, second_protocol];
        let deposit_family = vec![deposit];

        let partial_store = durable.clone();
        let partial = async move {
            partial_store.lock().unwrap().insert(first_protocol);
            Err::<(), anyhow::Error>(anyhow::anyhow!(
                "injected failure after the first protocol checkpoint"
            ))
        };
        assert!(
            checkpoint_ack_family(&protocol_family, &mut accepted, &mut in_flight, partial,)
                .await
                .is_err()
        );
        assert!(accepted.contains_key(&first_protocol));
        assert!(accepted.contains_key(&second_protocol));
        assert!(in_flight.contains(&first_request));
        assert!(in_flight.contains(&second_request));

        let deposit_store = durable.clone();
        checkpoint_ack_family(&deposit_family, &mut accepted, &mut in_flight, async move {
            deposit_store.lock().unwrap().insert(deposit);
            Ok(())
        })
        .await
        .unwrap();
        assert!(!accepted.contains_key(&deposit));
        assert!(!in_flight.contains(&deposit_request));

        let retry_store = durable.clone();
        checkpoint_ack_family(&protocol_family, &mut accepted, &mut in_flight, async move {
            let mut durable = retry_store.lock().unwrap();
            assert!(
                !durable.insert(first_protocol),
                "replayed checkpoint prefix must be idempotent"
            );
            durable.insert(second_protocol);
            Ok(())
        })
        .await
        .unwrap();

        assert!(accepted.is_empty());
        assert!(in_flight.is_empty());
        assert_eq!(
            durable.lock().unwrap().clone(),
            BTreeSet::from([first_protocol, second_protocol, deposit])
        );
    }

    #[test]
    fn sync_admission_reserves_one_global_slot_for_relay_work() {
        let global_width = 4;
        let peer_width = 2;
        let global = Arc::new(Semaphore::new(global_width));
        let global_sync = Arc::new(Semaphore::new(sync_request_capacity(global_width).unwrap()));
        let peers = (0..4)
            .map(|_| {
                (
                    Arc::new(Semaphore::new(peer_width)),
                    Arc::new(Semaphore::new(sync_request_capacity(peer_width).unwrap())),
                )
            })
            .collect::<Vec<_>>();

        let admissions = peers[..3]
            .iter()
            .map(|(peer, peer_sync)| {
                try_acquire_outbound_sync_admission(&global_sync, peer_sync, &global, peer)
                    .expect("three sync requests fit below the global reservation")
            })
            .collect::<Vec<_>>();
        assert_eq!(global.available_permits(), RESERVED_RELAY_OUTBOUND_REQUESTS);
        assert!(
            try_acquire_outbound_sync_admission(&global_sync, &peers[3].1, &global, &peers[3].0,)
                .is_none(),
            "a fourth sync request must not consume the reserved global slot"
        );
        let relay = global.clone().try_acquire_owned();
        assert!(relay.is_ok(), "relay work retains one global permit");
        drop(admissions);
    }

    #[test]
    fn sync_admission_reserves_one_peer_slot_for_relay_work() {
        let global_width = 8;
        let peer_width = 3;
        let global = Arc::new(Semaphore::new(global_width));
        let global_sync = Arc::new(Semaphore::new(sync_request_capacity(global_width).unwrap()));
        let peer = Arc::new(Semaphore::new(peer_width));
        let peer_sync = Arc::new(Semaphore::new(sync_request_capacity(peer_width).unwrap()));

        let first =
            try_acquire_outbound_sync_admission(&global_sync, &peer_sync, &global, &peer).unwrap();
        let second =
            try_acquire_outbound_sync_admission(&global_sync, &peer_sync, &global, &peer).unwrap();
        assert_eq!(peer.available_permits(), RESERVED_RELAY_OUTBOUND_REQUESTS);
        assert!(
            try_acquire_outbound_sync_admission(&global_sync, &peer_sync, &global, &peer).is_none(),
            "a third sync request must not consume the reserved peer slot"
        );

        let relay_global = global.clone().try_acquire_owned();
        let relay_peer = peer.clone().try_acquire_owned();
        assert!(relay_global.is_ok());
        assert!(relay_peer.is_ok(), "relay work retains one permit for this peer");
        drop((first, second));
    }

    #[test]
    fn denied_sync_admission_never_occupies_an_ordinary_global_permit() {
        let global_width = 3;
        let peer_width = 2;
        let global = Arc::new(Semaphore::new(global_width));
        let global_sync = Arc::new(Semaphore::new(sync_request_capacity(global_width).unwrap()));
        let peer = Arc::new(Semaphore::new(peer_width));
        let peer_sync = Arc::new(Semaphore::new(sync_request_capacity(peer_width).unwrap()));
        let held_peer_sync = peer_sync.clone().try_acquire_owned().unwrap();
        let before = global.available_permits();

        assert!(
            try_acquire_outbound_sync_admission(&global_sync, &peer_sync, &global, &peer).is_none()
        );
        assert_eq!(
            global.available_permits(),
            before,
            "sync-only reservations are checked before ordinary global capacity"
        );
        drop(held_peer_sync);
    }

    #[tokio::test]
    async fn queued_transfer_sync_admission_beats_replenished_relays_work_conservingly() {
        let global_sync = Arc::new(Semaphore::new(1));
        let peer_sync = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(2));
        let peer = Arc::new(Semaphore::new(2));
        let mut global_incumbents = vec![
            global.clone().try_acquire_owned().unwrap(),
            global.clone().try_acquire_owned().unwrap(),
        ];
        let mut peer_incumbents = vec![
            peer.clone().try_acquire_owned().unwrap(),
            peer.clone().try_acquire_owned().unwrap(),
        ];

        let waiter_global_sync = global_sync.clone();
        let waiter_peer_sync = peer_sync.clone();
        let waiter_global = global.clone();
        let waiter_peer = peer.clone();
        let mut waiter = tokio::spawn(async move {
            acquire_outbound_sync_admission_for_transfer(
                &waiter_global_sync,
                &waiter_peer_sync,
                &waiter_global,
                &waiter_peer,
                std::future::pending(),
            )
            .await
        });
        tokio::task::yield_now().await;

        drop(global_incumbents.pop().unwrap());
        tokio::task::yield_now().await;
        for _ in 0..32 {
            assert!(
                matches!(
                    try_acquire_outbound_relay_admission(&global, &peer),
                    Err(OutboundRelayAdmissionError::GlobalExhausted)
                ),
                "a polling relay stole the global permit assigned to the FIFO transfer waiter",
            );
        }

        drop(peer_incumbents.pop().unwrap());
        let admission = time::timeout(Duration::from_secs(1), &mut waiter)
            .await
            .expect("FIFO transfer admission remained phase-locked")
            .expect("transfer waiter task failed")
            .expect("transfer waiter was unexpectedly cancelled");
        assert_eq!(global.available_permits(), 0);
        assert_eq!(peer.available_permits(), 0);
        drop(admission);
        assert_eq!(global.available_permits(), 1);
        assert_eq!(peer.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_transfer_sync_wait_releases_every_partial_permit() {
        let global_sync = Arc::new(Semaphore::new(1));
        let peer_sync = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(1));
        let peer = Arc::new(Semaphore::new(1));
        let peer_incumbent = peer.clone().try_acquire_owned().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let waiter_global_sync = global_sync.clone();
        let waiter_peer_sync = peer_sync.clone();
        let waiter_global = global.clone();
        let waiter_peer = peer.clone();
        let waiter = tokio::spawn(async move {
            acquire_outbound_sync_admission_for_transfer(
                &waiter_global_sync,
                &waiter_peer_sync,
                &waiter_global,
                &waiter_peer,
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(global_sync.available_permits(), 0);
        assert_eq!(peer_sync.available_permits(), 0);
        assert_eq!(global.available_permits(), 0);

        shutdown_tx.send(()).unwrap();
        assert!(
            waiter.await.unwrap().is_none(),
            "shutdown must cancel a partially admitted transfer waiter"
        );
        assert_eq!(global_sync.available_permits(), 1);
        assert_eq!(peer_sync.available_permits(), 1);
        assert_eq!(global.available_permits(), 1);
        drop(peer_incumbent);
        assert_eq!(peer.available_permits(), 1);
    }

    #[tokio::test]
    async fn complete_relay_attempt_deadline_releases_mutation_and_stream_permits() {
        let recipient = PartyId(2);
        let slots = BTreeMap::from([(recipient, Arc::new(Semaphore::new(1)))]);
        let mutation = try_acquire_outbound_deposit_mutation_slot(
            &slots,
            recipient,
            Some(DepositOperation::Attest),
        )
        .unwrap()
        .unwrap();
        let global = Arc::new(Semaphore::new(1));
        let peer = Arc::new(Semaphore::new(1));
        let relay = try_acquire_outbound_relay_admission(&global, &peer).unwrap();

        let outcome = {
            let _mutation = mutation;
            let _relay = relay;
            outbound_operation_until(
                Instant::now() + Duration::from_millis(20),
                std::future::pending(),
                std::future::pending::<()>(),
            )
            .await
        };
        assert_eq!(outcome, Err(OutboundOperationEnd::Deadline));
        assert_eq!(slots[&recipient].available_permits(), 1);
        assert_eq!(global.available_permits(), 1);
        assert_eq!(peer.available_permits(), 1);
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
    fn deposit_sync_control_rate_is_small_peer_local_and_resets() {
        assert_eq!(MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL, 8);
        assert_eq!(DEPOSIT_SYNC_CONTROL_RATE_INTERVAL, Duration::from_secs(1));
        let now = Instant::now();
        let interval = DEPOSIT_SYNC_CONTROL_RATE_INTERVAL;
        let mut noisy = FixedWindowRate::new(now);
        let mut honest = FixedWindowRate::new(now);

        for _ in 0..MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL {
            assert!(noisy.try_admit(
                now,
                interval,
                MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL,
            ));
        }
        assert!(!noisy.try_admit(
            now,
            interval,
            MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL,
        ));
        assert!(honest.try_admit(
            now,
            interval,
            MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL,
        ));
        assert!(noisy.try_admit(
            now + interval,
            interval,
            MAX_DEPOSIT_SYNC_CONTROL_REQUESTS_PER_PEER_PER_INTERVAL,
        ));
    }

    #[test]
    fn ordinary_release_barrier_suppresses_only_its_certified_export_source() {
        let context =
            DepositStateTransferContext::new([0x91; 32], DepositWalletId([0x92; 32])).unwrap();
        let request = |source: PartyId, nonce: u8| {
            DepositStateExportHeadRequest::new(context, [0x93; 32], source, PartyId(1), [nonce; 32])
                .unwrap()
        };
        let mut heads = vec![request(PartyId(2), 2), request(PartyId(3), 3)];
        let barriers = BTreeSet::from([PartyId(2)]);
        assert!(!retain_certified_export_heads_without_ordinary_release(&mut heads, &barriers));
        assert_eq!(
            heads.iter().map(|head| head.source()).collect::<Vec<_>>(),
            vec![PartyId(3)],
            "an unrelated predecessor must remain eligible",
        );

        let mut blocked = vec![request(PartyId(2), 4)];
        assert!(retain_certified_export_heads_without_ordinary_release(&mut blocked, &barriers,));
        assert!(blocked.is_empty());
    }

    #[test]
    fn sync_head_and_release_share_one_queued_slot_per_peer() {
        let peer_a = Arc::new(Semaphore::new(1));
        let peer_b = Arc::new(Semaphore::new(1));

        assert!(try_acquire_deposit_sync_control_peer_slot(&peer_a, false).unwrap().is_none(),);
        let head = try_acquire_deposit_sync_control_peer_slot(&peer_a, true)
            .unwrap()
            .expect("SyncHead acquires the peer's combined control slot");
        assert_eq!(peer_a.available_permits(), 0);

        assert_eq!(
            try_acquire_deposit_sync_control_peer_slot(&peer_a, true).unwrap_err(),
            deposit_sync_control_busy_response(),
            "SyncRelease cannot overlap SyncHead for the same identity",
        );

        let release = try_acquire_deposit_sync_control_peer_slot(&peer_b, true)
            .unwrap()
            .expect("another identity may queue one control request");

        drop((head, release));
        assert_eq!(peer_a.available_permits(), 1);
        assert_eq!(peer_b.available_permits(), 1);
    }

    #[tokio::test]
    async fn deposit_sync_control_execution_is_fifo_and_shutdown_cancellable() {
        assert_eq!(MAX_CONCURRENT_DEPOSIT_SYNC_CONTROL_REQUESTS, 1);
        let global = Arc::new(Semaphore::new(MAX_CONCURRENT_DEPOSIT_SYNC_CONTROL_REQUESTS));
        let incumbent = global.clone().acquire_owned().await.unwrap();

        let first_global = global.clone();
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            first_started_tx.send(()).unwrap();
            acquire_deposit_sync_control_execution_permit(
                &first_global,
                std::future::pending::<()>(),
            )
            .await
        });
        first_started_rx.await.unwrap();
        tokio::task::yield_now().await;

        let second_global = global.clone();
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            second_started_tx.send(()).unwrap();
            acquire_deposit_sync_control_execution_permit(
                &second_global,
                std::future::pending::<()>(),
            )
            .await
        });
        second_started_rx.await.unwrap();
        tokio::task::yield_now().await;

        drop(incumbent);
        let first_permit = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("first FIFO waiter remained blocked")
            .unwrap()
            .expect("first FIFO waiter was cancelled");
        assert!(!second.is_finished(), "second waiter bypassed the first FIFO waiter");
        drop(first_permit);
        let second_permit = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second FIFO waiter remained blocked")
            .unwrap()
            .expect("second FIFO waiter was cancelled");
        drop(second_permit);
        assert_eq!(global.available_permits(), 1);

        let incumbent = global.clone().acquire_owned().await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let cancelled_global = global.clone();
        let cancelled = tokio::spawn(async move {
            acquire_deposit_sync_control_execution_permit(&cancelled_global, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        tokio::task::yield_now().await;
        shutdown_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), cancelled)
                .await
                .expect("shutdown did not cancel the FIFO waiter")
                .unwrap()
                .is_none(),
        );
        drop(incumbent);
        assert_eq!(global.available_permits(), 1);
    }

    #[test]
    fn deposit_mutation_peer_slot_is_nonblocking_and_route_optional() {
        let peer = Arc::new(Semaphore::new(1));
        let incumbent = try_acquire_deposit_mutation_peer_slot(&peer, true)
            .unwrap()
            .expect("the first mutable body is admitted");
        assert_eq!(peer.available_permits(), 0);

        let response = try_acquire_deposit_mutation_peer_slot(&peer, true).unwrap_err();
        assert_eq!(response, deposit_mutation_busy_response());
        assert!(matches!(
            response,
            PeerResponse::Rejected { code: RejectionCode::ResourceExhausted, retryable: true, .. }
        ));
        assert!(
            try_acquire_deposit_mutation_peer_slot(&peer, false).unwrap().is_none(),
            "non-mutation routes never touch the peer slot",
        );

        drop(incumbent);
        assert_eq!(peer.available_permits(), 1);
        drop(
            try_acquire_deposit_mutation_peer_slot(&peer, true)
                .unwrap()
                .expect("the peer may retry after its earlier request finishes"),
        );
        assert_eq!(peer.available_permits(), 1);
    }

    #[tokio::test]
    async fn slow_mutation_body_leaves_ordinary_and_mutation_global_capacity_available() {
        assert_eq!(MAX_CONCURRENT_MUTATING_DEPOSIT_REQUESTS, 1);
        let peer_a = Arc::new(Semaphore::new(1));
        let peer_b = Arc::new(Semaphore::new(1));
        let peer_a_ordinary = Arc::new(Semaphore::new(1));
        let ordinary_peer = Arc::new(Semaphore::new(1));
        let ordinary_global = Arc::new(Semaphore::new(1));
        let peer_a_body = Arc::new(Semaphore::new(8));
        let peer_b_body = Arc::new(Semaphore::new(8));
        let global_body = Arc::new(Semaphore::new(16));
        let global = Arc::new(Semaphore::new(MAX_CONCURRENT_MUTATING_DEPOSIT_REQUESTS));

        let slow_peer_slot = try_acquire_deposit_mutation_peer_slot(&peer_a, true)
            .unwrap()
            .expect("peer A admits one body");
        let slow_body =
            try_acquire_inbound_request_body_permits(&peer_a_body, &global_body, 8).unwrap();
        let mutation_route = requires_deposit_mutation_admission(
            Some(DepositOperation::Attest),
            false,
            false,
            false,
        );
        assert!(mutation_route);
        assert!(
            try_acquire_inbound_request_execution_permits(
                &peer_a_ordinary,
                &ordinary_global,
                requires_ordinary_inbound_execution_admission(mutation_route, false, false, false,),
            )
            .unwrap()
            .is_none(),
            "a slow mutable body must bypass ordinary ingress capacity",
        );
        assert_eq!(ordinary_global.available_permits(), 1);
        assert!(
            requires_ordinary_inbound_execution_admission(false, false, false, false),
            "an ordinary non-deposit route still requires ordinary ingress admission",
        );
        let ordinary_execution =
            try_acquire_inbound_request_execution_permits(&ordinary_peer, &ordinary_global, true)
                .unwrap()
                .expect("ordinary work remains admissible beside the slow mutable body");
        assert_eq!(ordinary_global.available_permits(), 0);
        drop(ordinary_execution);
        assert_eq!(ordinary_global.available_permits(), 1);
        assert_eq!(
            global.available_permits(),
            1,
            "a body which has not finished reading must not reserve reducer execution",
        );

        let ready_peer_slot = try_acquire_deposit_mutation_peer_slot(&peer_b, true)
            .unwrap()
            .expect("peer B admits one independent body");
        let ready_body =
            try_acquire_inbound_request_body_permits(&peer_b_body, &global_body, 8).unwrap();
        let execution = acquire_deposit_mutation_execution_permit(&global, std::future::pending())
            .await
            .expect("peer B can execute while peer A is still sending");
        assert_eq!(global.available_permits(), 0);

        drop((execution, ready_body, ready_peer_slot, slow_body, slow_peer_slot));
        assert_eq!(peer_a.available_permits(), 1);
        assert_eq!(peer_b.available_permits(), 1);
        assert_eq!(peer_a_ordinary.available_permits(), 1);
        assert_eq!(ordinary_peer.available_permits(), 1);
        assert_eq!(ordinary_global.available_permits(), 1);
        assert_eq!(global_body.available_permits(), 16);
        assert_eq!(global.available_permits(), 1);
    }

    #[tokio::test]
    async fn deposit_mutation_execution_is_fifo_and_shutdown_cancellable() {
        assert_eq!(MAX_CONCURRENT_MUTATING_DEPOSIT_REQUESTS, 1);
        let global = Arc::new(Semaphore::new(MAX_CONCURRENT_MUTATING_DEPOSIT_REQUESTS));
        let incumbent = global.clone().acquire_owned().await.unwrap();

        let first_global = global.clone();
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            first_started_tx.send(()).unwrap();
            acquire_deposit_mutation_execution_permit(&first_global, std::future::pending::<()>())
                .await
        });
        first_started_rx.await.unwrap();
        tokio::task::yield_now().await;

        let second_global = global.clone();
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            second_started_tx.send(()).unwrap();
            acquire_deposit_mutation_execution_permit(&second_global, std::future::pending::<()>())
                .await
        });
        second_started_rx.await.unwrap();
        tokio::task::yield_now().await;

        drop(incumbent);
        let first_permit = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("first FIFO mutation waiter remained blocked")
            .unwrap()
            .expect("first FIFO mutation waiter was cancelled");
        assert!(!second.is_finished(), "second mutation waiter bypassed the first");
        drop(first_permit);
        let second_permit = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second FIFO mutation waiter remained blocked")
            .unwrap()
            .expect("second FIFO mutation waiter was cancelled");
        drop(second_permit);
        assert_eq!(global.available_permits(), 1);

        let incumbent = global.clone().acquire_owned().await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let cancelled_global = global.clone();
        let cancelled = tokio::spawn(async move {
            acquire_deposit_mutation_execution_permit(&cancelled_global, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });
        tokio::task::yield_now().await;
        shutdown_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), cancelled)
                .await
                .expect("shutdown did not cancel the mutation waiter")
                .unwrap()
                .is_none(),
        );
        drop(incumbent);
        assert_eq!(global.available_permits(), 1);
    }

    #[tokio::test]
    async fn deposit_execution_releases_every_endpoint_lane_before_response_io() {
        let mutation = Arc::new(Semaphore::new(1));
        let sync_objects = Arc::new(Semaphore::new(1));
        let prefix_support = Arc::new(Semaphore::new(1));
        let sync_control = Arc::new(Semaphore::new(1));
        let permits = DepositEndpointExecutionPermits {
            mutation: acquire_deposit_mutation_execution_permit(&mutation, std::future::pending())
                .await,
            sync_objects: acquire_deposit_sync_objects_execution_permit(
                &sync_objects,
                std::future::pending(),
            )
            .await,
            prefix_support: acquire_deposit_prefix_support_execution_permit(
                &prefix_support,
                std::future::pending(),
            )
            .await,
            sync_control: acquire_deposit_sync_control_execution_permit(
                &sync_control,
                std::future::pending(),
            )
            .await,
        };
        for lane in [&mutation, &sync_objects, &prefix_support, &sync_control] {
            assert_eq!(lane.available_permits(), 0);
        }

        let (response_started_tx, response_started_rx) = tokio::sync::oneshot::channel();
        let (response_finish_tx, response_finish_rx) = tokio::sync::oneshot::channel();
        let response =
            tokio::spawn(respond_after_releasing_deposit_execution(permits, async move {
                response_started_tx.send(()).unwrap();
                let _ = response_finish_rx.await;
            }));
        response_started_rx.await.unwrap();

        let successors =
            [mutation.clone(), sync_objects.clone(), prefix_support.clone(), sync_control.clone()]
                .map(|lane| {
                    lane.try_acquire_owned()
                        .expect("response I/O must not retain any endpoint deposit execution lane")
                });
        assert!(!response.is_finished(), "the simulated response should still be blocked");
        drop(successors);
        response_finish_tx.send(()).unwrap();
        response.await.unwrap();
        for lane in [&mutation, &sync_objects, &prefix_support, &sync_control] {
            assert_eq!(lane.available_permits(), 1);
        }
    }

    #[test]
    fn outbound_deposit_mutation_slot_is_per_recipient_and_matches_receiver_routes() {
        let recipient_two = PartyId(2);
        let recipient_three = PartyId(3);
        let slots = BTreeMap::from([
            (recipient_two, Arc::new(Semaphore::new(1))),
            (recipient_three, Arc::new(Semaphore::new(1))),
        ]);

        let recipient_two_permit = try_acquire_outbound_deposit_mutation_slot(
            &slots,
            recipient_two,
            Some(DepositOperation::Attest),
        )
        .unwrap()
        .expect("the first mutable request must acquire its recipient slot");
        assert!(matches!(
            try_acquire_outbound_deposit_mutation_slot(
                &slots,
                recipient_two,
                Some(DepositOperation::Certificate),
            ),
            Err(OutboundDepositMutationSlotError::Busy),
        ));

        let recipient_three_permit = try_acquire_outbound_deposit_mutation_slot(
            &slots,
            recipient_three,
            Some(DepositOperation::Certificate),
        )
        .unwrap()
        .expect("a different recipient has an independent mutation slot");

        for operation in [
            DepositOperation::SyncHead,
            DepositOperation::SyncObjects,
            DepositOperation::SyncRelease,
            DepositOperation::PrefixSupportStart,
            DepositOperation::PrefixSupportContinue,
            DepositOperation::ExportObjects,
        ] {
            assert!(
                try_acquire_outbound_deposit_mutation_slot(&slots, recipient_two, Some(operation),)
                    .unwrap()
                    .is_none(),
                "{operation:?} must bypass the saturated mutation slot",
            );
        }
        for operation in [DepositOperation::ExportHead, DepositOperation::ExportRelease] {
            assert!(matches!(
                try_acquire_outbound_deposit_mutation_slot(&slots, recipient_two, Some(operation),),
                Err(OutboundDepositMutationSlotError::Busy),
            ));
        }
        assert!(
            try_acquire_outbound_deposit_mutation_slot(&slots, recipient_two, None)
                .unwrap()
                .is_none(),
            "non-deposit requests must bypass the mutation slot",
        );
        assert!(matches!(
            try_acquire_outbound_deposit_mutation_slot(
                &slots,
                PartyId(4),
                Some(DepositOperation::Attest),
            ),
            Err(OutboundDepositMutationSlotError::UnknownRecipient),
        ));

        drop(recipient_two_permit);
        drop(
            try_acquire_outbound_deposit_mutation_slot(
                &slots,
                recipient_two,
                Some(DepositOperation::Attest),
            )
            .unwrap()
            .expect("completion must release the recipient slot"),
        );
        drop(recipient_three_permit);
        assert_eq!(slots[&recipient_two].available_permits(), 1);
        assert_eq!(slots[&recipient_three].available_permits(), 1);
    }

    #[test]
    fn durable_state_transfer_snapshot_is_canonical_and_context_bound() {
        let network_id = [0xA1; 32];
        let local_party = STATE_TRANSFER_INTENT_TEST_LOCAL_PARTY;
        let configured_parties = (1_u16..=4).map(PartyId).collect::<BTreeSet<PartyId>>();
        let first = DurableStateTransferIntent {
            recipient: PartyId(2),
            request_id: [0xB1; 32],
            scope: DurableStateTransferReservationScope::ExportHead([0xC1; 32]),
            created_generation: 1,
        };
        let second = DurableStateTransferIntent {
            recipient: PartyId(3),
            request_id: [0xB2; 32],
            scope: DurableStateTransferReservationScope::StateImportCertificate(7),
            created_generation: 2,
        };
        let entries = BTreeMap::from([(first.recipient, first), (second.recipient, second)]);

        let encoded =
            encode_state_transfer_intent_snapshot(network_id, local_party, 2, &entries).unwrap();
        let (high_water_generation, decoded) = decode_state_transfer_intent_snapshot(
            &encoded,
            network_id,
            local_party,
            &configured_parties,
        )
        .unwrap();
        assert_eq!(high_water_generation, 2);
        assert_eq!(decoded, entries);
        assert_eq!(
            encode_state_transfer_intent_snapshot(
                network_id,
                local_party,
                high_water_generation,
                &decoded,
            )
            .unwrap(),
            encoded,
            "a decoded snapshot must have one canonical re-encoding",
        );

        assert!(
            decode_state_transfer_intent_snapshot(
                &encoded,
                [0xA2; 32],
                local_party,
                &configured_parties,
            )
            .is_err(),
            "the authenticated network context must be exact",
        );
        assert!(
            decode_state_transfer_intent_snapshot(
                &encoded,
                network_id,
                PartyId(4),
                &configured_parties,
            )
            .is_err(),
            "the authenticated local-party context must be exact",
        );

        let wrong_version = postcard::to_allocvec(&DurableStateTransferIntentSnapshot {
            version: STATE_TRANSFER_INTENT_SNAPSHOT_VERSION + 1,
            network_id,
            local_party,
            high_water_generation: 2,
            entries: vec![first, second],
        })
        .unwrap();
        assert!(
            decode_state_transfer_intent_snapshot(
                &wrong_version,
                network_id,
                local_party,
                &configured_parties,
            )
            .is_err(),
        );

        for invalid in [
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                2,
                vec![second, first],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                2,
                vec![first, first],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent { recipient: local_party, ..first }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent { recipient: PartyId(9), ..first }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent { created_generation: 0, ..first }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent { created_generation: 2, ..first }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent { request_id: [0; 32], ..first }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent {
                    scope: DurableStateTransferReservationScope::ExportHead([0; 32]),
                    ..first
                }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                1,
                vec![DurableStateTransferIntent {
                    scope: DurableStateTransferReservationScope::StateImportCertificate(0),
                    ..first
                }],
            ),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                2,
                vec![first, DurableStateTransferIntent { created_generation: 1, ..second }],
            ),
            state_transfer_intent_test_snapshot_bytes(network_id, local_party, 0, vec![first]),
            state_transfer_intent_test_snapshot_bytes(
                network_id,
                local_party,
                4,
                vec![first, first, second, second],
            ),
        ] {
            assert!(
                decode_state_transfer_intent_snapshot(
                    &invalid,
                    network_id,
                    local_party,
                    &configured_parties,
                )
                .is_err(),
                "a noncanonical or semantically invalid snapshot was accepted",
            );
        }

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(
            decode_state_transfer_intent_snapshot(
                &trailing,
                network_id,
                local_party,
                &configured_parties,
            )
            .is_err(),
            "trailing bytes must not survive canonical decoding",
        );
        assert!(
            DurableStateTransferReservationScope::try_from(
                StateTransferReservationScope::ExportObjects([0xD1; 32]),
            )
            .is_err(),
            "immutable object reads must never enter the durable mutable-intent journal",
        );
    }

    #[tokio::test]
    async fn retired_export_head_census_unlocks_next_seal_without_clearing_live_head() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let context = DepositStateTransferContext::new(
            fixture.runtime.network_id,
            crate::deposit_wallet::DepositWalletId([0xc1; 32]),
        )
        .unwrap();
        let heads = [PartyId(2), PartyId(3)].map(|source| {
            DepositStateExportHeadRequest::new(context, [0xc2; 32], source, PartyId(1), [0xc3; 32])
                .unwrap()
        });
        let scope = StateTransferReservationScope::ExportHead(context.digest());
        for head in &heads {
            let (key, _) = fixture
                .runtime
                .state_transfer_reservation_key(
                    head.source(),
                    DepositOperation::ExportHead,
                    head.to_bytes().unwrap(),
                )
                .unwrap();
            drop(
                fixture
                    .runtime
                    .acquire_state_transfer_reservation(
                        key,
                        scope,
                        DepositOperation::ExportHead,
                        Instant::now() + Duration::from_secs(10),
                    )
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let watermark = fixture.runtime.state_transfer_census_watermark();
        let (seal_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(
                PartyId(2),
                DepositOperation::PostHandoffExportSealRequest,
                vec![0xc4],
            )
            .unwrap();
        fixture
            .runtime
            .reconcile_export_head_reservations(context, &heads, watermark)
            .await
            .unwrap();
        assert!(matches!(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    seal_key,
                    StateTransferReservationScope::ExportSeal(3),
                    DepositOperation::PostHandoffExportSealRequest,
                    Instant::now() + Duration::from_secs(10)
                )
                .await,
            Err(OutboundDepositMutationSlotError::Busy)
        ));

        let wrong_context = DepositStateTransferContext::new(
            fixture.runtime.network_id,
            crate::deposit_wallet::DepositWalletId([0xc5; 32]),
        )
        .unwrap();
        let wrong_head = DepositStateExportHeadRequest::new(
            wrong_context,
            [0xc2; 32],
            PartyId(2),
            PartyId(1),
            [0xc3; 32],
        )
        .unwrap();
        assert!(
            fixture
                .runtime
                .reconcile_export_head_reservations(context, &[wrong_head], watermark)
                .await
                .is_err()
        );
        assert_eq!(fixture.durable_entries().await.1.len(), 2);

        // Only an authoritative census after protocol-journal retirement can release the cut.
        // The next epoch's seal can then use party 2 while party 3's live head remains fenced.
        fixture
            .runtime
            .reconcile_export_head_reservations(context, &heads[1..], watermark)
            .await
            .unwrap();
        assert_eq!(
            fixture.durable_entries().await.1.keys().copied().collect::<Vec<_>>(),
            vec![PartyId(3)]
        );
        drop(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    seal_key,
                    StateTransferReservationScope::ExportSeal(3),
                    DepositOperation::PostHandoffExportSealRequest,
                    Instant::now() + Duration::from_secs(10),
                )
                .await
                .unwrap()
                .expect("retired head still blocks the next source seal"),
        );
        let (_, durable) = fixture.durable_entries().await;
        assert_eq!(
            durable[&PartyId(2)].runtime_scope(),
            StateTransferReservationScope::ExportSeal(3)
        );
        assert_eq!(durable[&PartyId(3)].runtime_scope(), scope);
    }

    #[tokio::test]
    async fn durable_state_transfer_restart_restores_exact_recipient_fence() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportHead([0x71; 32]);
        let operation = DepositOperation::ExportHead;
        let (key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0x72, 0x73])
            .unwrap();

        assert!(
            !fixture.runtime.state_transfer_intents_loaded.load(Ordering::Acquire)
                && !fixture.runtime.mutable_deposit_relay_ready.load(Ordering::Acquire),
        );
        assert!(matches!(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    key,
                    scope,
                    operation,
                    Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(OutboundDepositMutationSlotError::Cancelled),
        ));

        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        assert!(fixture.runtime.state_transfer_intents_loaded.load(Ordering::Acquire));
        assert!(fixture.runtime.mutable_deposit_relay_ready.load(Ordering::Acquire));
        let admission = fixture
            .runtime
            .acquire_state_transfer_reservation(
                key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("the first exact transfer intent must be admitted after durable reservation");
        drop(admission);
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
        );
        {
            let reservations = fixture.runtime.state_transfer_reservations.lock().await;
            let reserved = reservations.exact.get(&key).unwrap();
            assert_eq!(reserved.scope, scope);
            assert_eq!(reserved.generation, 1);
            assert!(reservations.recipients.contains_key(&recipient));
        }
        let metadata_before_restart =
            fixture.server.load_deposit_state_transfer_intents().await.unwrap().unwrap().metadata;
        let (generation, durable) = fixture.durable_entries().await;
        assert_eq!(generation, 1);
        assert_eq!(durable[&recipient].key(), key);

        let fixture = fixture.restart().await;
        assert!(
            !fixture.runtime.state_transfer_intents_loaded.load(Ordering::Acquire)
                && !fixture.runtime.mutable_deposit_relay_ready.load(Ordering::Acquire),
        );
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            1,
            "the volatile fence must be reconstructed only after authenticated restore",
        );
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        assert!(fixture.runtime.state_transfer_intents_loaded.load(Ordering::Acquire));
        assert!(fixture.runtime.mutable_deposit_relay_ready.load(Ordering::Acquire));
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
            "restart must project the durable exact intent back into the recipient semaphore",
        );
        {
            let reservations = fixture.runtime.state_transfer_reservations.lock().await;
            assert_eq!(reservations.exact.len(), 1);
            assert_eq!(reservations.exact[&key].scope, scope);
            assert!(reservations.recipients.contains_key(&recipient));
        }

        let exact_retry = fixture
            .runtime
            .acquire_state_transfer_reservation(
                key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("the exact persisted key must remain retryable");
        assert!(
            !exact_retry.is_fresh(),
            "a restored intent must preserve its earlier execution ambiguity"
        );
        fixture.runtime.state_transfer_reservation_failure(key).await;
        fixture
            .runtime
            .handle_authenticated_state_transfer_rejection(
                Some(key),
                Some(&exact_retry),
                Some(QuicResponseProvenance::RejectedBeforeBody),
            )
            .await
            .unwrap();
        drop(exact_retry);
        assert_eq!(fixture.durable_entries().await.1[&recipient].key(), key);
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
            "a pre-body rejection of a recovered exact retry cannot resolve the prior dispatch"
        );
        let metadata_after_exact_retry =
            fixture.server.load_deposit_state_transfer_intents().await.unwrap().unwrap().metadata;
        assert_eq!(
            metadata_after_exact_retry, metadata_before_restart,
            "an exact retry must reuse the durable reservation without another CAS",
        );

        let (different_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0x74])
            .unwrap();
        assert_ne!(different_key, key);
        assert!(matches!(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    different_key,
                    scope,
                    operation,
                    Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(OutboundDepositMutationSlotError::Busy),
        ));
        assert_eq!(
            fixture.server.load_deposit_state_transfer_intents().await.unwrap().unwrap().metadata,
            metadata_before_restart,
            "a conflicting body for the same recipient must not mutate the durable journal",
        );
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&PartyId(3)].available_permits(),
            1,
            "one restored recipient fence must not consume another party's lane",
        );
    }

    #[tokio::test]
    async fn durable_state_transfer_clear_failure_keeps_recipient_fenced() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportRelease([0x81; 32]);
        let operation = DepositOperation::ExportRelease;
        let (key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0x82])
            .unwrap();
        let admission = fixture
            .runtime
            .acquire_state_transfer_reservation(
                key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("the transfer intent must be admitted");
        drop(admission);

        let correct_metadata = {
            let mut snapshot = fixture.runtime.state_transfer_intent_snapshot.lock().await;
            let snapshot = snapshot.as_mut().unwrap();
            let correct = snapshot.metadata;
            snapshot.metadata.snapshot_hash[0] ^= 0xFF;
            correct
        };
        fixture.runtime.shutdown.store(true, Ordering::Release);
        assert!(
            fixture.runtime.complete_state_transfer_reservation(key).await.is_err(),
            "shutdown must terminate the deliberately unresolved forged-metadata CAS",
        );
        fixture.runtime.shutdown.store(false, Ordering::Release);

        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
            "an unresolved durable clear must keep the recipient lane fenced",
        );
        {
            let reservations = fixture.runtime.state_transfer_reservations.lock().await;
            assert!(reservations.exact.contains_key(&key));
            assert!(reservations.recipients.contains_key(&recipient));
        }
        let (generation, durable) = fixture.durable_entries().await;
        assert_eq!(generation, 1);
        assert_eq!(durable[&recipient].key(), key);

        fixture.runtime.state_transfer_intent_snapshot.lock().await.as_mut().unwrap().metadata =
            correct_metadata;
        fixture.runtime.complete_state_transfer_reservation(key).await.unwrap();
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            1,
            "the recipient lane may reopen only after the durable tombstone succeeds",
        );
        assert!(!fixture.runtime.state_transfer_reservations.lock().await.exact.contains_key(&key),);
        let (generation, durable) = fixture.durable_entries().await;
        assert_eq!(generation, 1, "clearing an intent must preserve the rollback fence");
        assert!(durable.is_empty());
    }

    #[tokio::test]
    async fn empty_current_import_census_retires_only_exact_target_certificate() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let operation = DepositOperation::StateImportedCertificate;

        let old_recipient = PartyId(2);
        let (old_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(old_recipient, operation, vec![0x91])
            .unwrap();
        drop(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    old_key,
                    StateTransferReservationScope::StateImportCertificate(10),
                    operation,
                    Instant::now() + Duration::from_secs(1),
                )
                .await
                .unwrap()
                .expect("the historical certificate intent must be admitted"),
        );

        let current_recipient = PartyId(3);
        let (current_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(current_recipient, operation, vec![0x92])
            .unwrap();
        drop(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    current_key,
                    StateTransferReservationScope::StateImportCertificate(11),
                    operation,
                    Instant::now() + Duration::from_secs(1),
                )
                .await
                .unwrap()
                .expect("the current certificate intent must be admitted"),
        );
        let census_watermark = fixture.runtime.state_transfer_census_watermark();
        assert_eq!(census_watermark, 2);

        let post_census_recipient = PartyId(4);
        let (post_census_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(post_census_recipient, operation, vec![0x93])
            .unwrap();
        drop(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    post_census_key,
                    StateTransferReservationScope::StateImportCertificate(11),
                    operation,
                    Instant::now() + Duration::from_secs(1),
                )
                .await
                .unwrap()
                .expect("the post-census certificate intent must be admitted"),
        );
        assert_eq!(fixture.runtime.state_transfer_census_watermark(), 3);

        let expected_routes = BTreeMap::from([
            (
                StateTransferReservationScope::StateImportCertificate(10),
                BTreeSet::from([old_recipient]),
            ),
            (
                StateTransferReservationScope::StateImportCertificate(11),
                BTreeSet::from([current_recipient]),
            ),
        ]);
        assert_eq!(
            fixture.runtime.state_transfer_census_recipients(census_watermark).await,
            expected_routes,
            "reconstruction must exclude unrelated recipients and post-census reservations",
        );
        let unpublished = fixture
            .runtime
            .state_transfer_reservations
            .lock()
            .await
            .exact
            .remove(&current_key)
            .unwrap();
        assert_eq!(
            fixture.runtime.state_transfer_census_recipients(census_watermark).await,
            expected_routes,
            "a durable reservation must remain visible before its volatile publication",
        );
        fixture
            .runtime
            .state_transfer_reservations
            .lock()
            .await
            .exact
            .insert(current_key, unpublished);
        fixture
            .runtime
            .reconcile_state_transfer_scope(
                StateTransferReservationScope::StateImportCertificate(11),
                &BTreeSet::from([current_key]),
                census_watermark,
            )
            .await
            .unwrap();
        assert_eq!(fixture.durable_entries().await.1.len(), 3, "an exact live key must survive");

        fixture
            .runtime
            .reconcile_current_state_import_reservations(&[], Some(11), census_watermark)
            .await
            .unwrap();
        {
            let reservations = fixture.runtime.state_transfer_reservations.lock().await;
            assert!(reservations.exact.contains_key(&old_key));
            assert!(!reservations.exact.contains_key(&current_key));
            assert!(reservations.exact.contains_key(&post_census_key));
        }
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&old_recipient].available_permits(),
            0,
        );
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&current_recipient].available_permits(),
            1,
        );
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&post_census_recipient]
                .available_permits(),
            0,
            "a reservation newer than the census watermark must survive",
        );
        let (generation, durable) = fixture.durable_entries().await;
        assert_eq!(generation, 3);
        assert_eq!(
            durable.keys().copied().collect::<BTreeSet<_>>(),
            [old_recipient, post_census_recipient].into_iter().collect::<BTreeSet<_>>()
        );

        fixture
            .runtime
            .reconcile_current_state_import_reservations(&[], None, u64::MAX)
            .await
            .unwrap();
        assert!(
            fixture
                .runtime
                .state_transfer_reservations
                .lock()
                .await
                .exact
                .contains_key(&post_census_key),
            "a census without an authenticated current target must be a no-op",
        );

        fixture
            .runtime
            .reconcile_current_state_import_reservations(
                &[],
                Some(11),
                fixture.runtime.state_transfer_census_watermark(),
            )
            .await
            .unwrap();
        {
            let reservations = fixture.runtime.state_transfer_reservations.lock().await;
            assert!(reservations.exact.contains_key(&old_key));
            assert!(!reservations.exact.contains_key(&post_census_key));
        }
        let (generation, durable) = fixture.durable_entries().await;
        assert_eq!(generation, 3);
        assert_eq!(durable.keys().copied().collect::<Vec<_>>(), vec![old_recipient]);
        assert_eq!(
            fixture.runtime.state_transfer_census_recipients(u64::MAX).await,
            BTreeMap::from([(
                StateTransferReservationScope::StateImportCertificate(10),
                BTreeSet::from([old_recipient]),
            )]),
        );
    }

    #[test]
    fn startup_preflight_gate_blocks_only_ordinary_mutable_deposit_relays() {
        let mutable = PeerRequest::Deposit { operation: DepositOperation::Attest, body: vec![1] };
        let immutable =
            PeerRequest::Deposit { operation: DepositOperation::ExportObjects, body: vec![2] };
        let transition = PeerRequest::Epoch { operation: EpochOperation::Activate, body: vec![3] };

        assert!(!mutable_deposit_relay_is_admitted(false, &mutable));
        assert!(mutable_deposit_relay_is_admitted(false, &immutable));
        assert!(mutable_deposit_relay_is_admitted(false, &transition));
        assert!(mutable_deposit_relay_is_admitted(true, &mutable));
    }

    #[tokio::test]
    async fn queued_state_transfer_slot_beats_replenished_relay_attempts() {
        let recipient = PartyId(2);
        let slots = Arc::new(BTreeMap::from([(recipient, Arc::new(Semaphore::new(1)))]));
        let incumbent = try_acquire_outbound_deposit_mutation_slot(
            &slots,
            recipient,
            Some(DepositOperation::Attest),
        )
        .unwrap()
        .expect("the incumbent relay acquires the recipient");

        let waiter_slots = slots.clone();
        let mut waiter = tokio::spawn(async move {
            acquire_outbound_deposit_mutation_slot_until(
                &waiter_slots,
                recipient,
                DepositOperation::ExportHead,
                Instant::now() + Duration::from_secs(1),
                std::future::pending::<()>(),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiter).await.is_err(),
            "the state-transfer waiter did not queue behind the incumbent",
        );

        drop(incumbent);
        for _ in 0..32 {
            assert!(
                matches!(
                    try_acquire_outbound_deposit_mutation_slot(
                        &slots,
                        recipient,
                        Some(DepositOperation::Certificate),
                    ),
                    Err(OutboundDepositMutationSlotError::Busy),
                ),
                "a replenished relay bypassed the earlier FIFO state-transfer waiter",
            );
        }
        let transfer_permit = tokio::time::timeout(Duration::from_secs(1), &mut waiter)
            .await
            .expect("the queued state transfer did not acquire the released recipient slot")
            .expect("the state-transfer waiter task failed")
            .expect("the state-transfer admission was cancelled")
            .expect("ExportHead unexpectedly bypassed mutation admission");
        drop(transfer_permit);
        drop(
            try_acquire_outbound_deposit_mutation_slot(
                &slots,
                recipient,
                Some(DepositOperation::Certificate),
            )
            .unwrap()
            .expect("relay admission resumes after state transfer completion"),
        );

        let held = slots[&recipient].clone().try_acquire_owned().unwrap();
        assert!(matches!(
            acquire_outbound_deposit_mutation_slot_until(
                &slots,
                recipient,
                DepositOperation::ExportRelease,
                Instant::now() + Duration::from_secs(1),
                std::future::ready(()),
            )
            .await,
            Err(OutboundDepositMutationSlotError::Cancelled),
        ));
        drop(held);
    }

    #[tokio::test]
    async fn queued_state_transfer_priority_survives_its_old_phase_deadline() {
        let recipient = PartyId(2);
        let slots = Arc::new(BTreeMap::from([(recipient, Arc::new(Semaphore::new(1)))]));
        let incumbent = slots[&recipient].clone().try_acquire_owned().unwrap();
        let started_before = Instant::now() + Duration::from_millis(20);
        let waiter_slots = slots.clone();
        let mut waiter = tokio::spawn(async move {
            acquire_outbound_deposit_mutation_slot_for_transfer(
                &waiter_slots,
                recipient,
                DepositOperation::ExportHead,
                started_before,
                std::future::pending(),
            )
            .await
        });
        tokio::task::yield_now().await;
        time::sleep(Duration::from_millis(40)).await;
        assert!(
            !waiter.is_finished(),
            "the admitted FIFO waiter expired at the obsolete phase deadline"
        );

        drop(incumbent);
        for _ in 0..16 {
            assert!(
                slots[&recipient].clone().try_acquire_owned().is_err(),
                "relay polling bypassed the nonexpiring transfer waiter"
            );
        }
        let transfer = time::timeout(Duration::from_secs(1), &mut waiter)
            .await
            .expect("nonexpiring transfer waiter did not acquire")
            .expect("transfer waiter task failed")
            .expect("transfer waiter was cancelled")
            .expect("ExportHead unexpectedly bypassed mutation admission");
        drop(transfer);
        assert_eq!(slots[&recipient].available_permits(), 1);
    }

    #[tokio::test]
    async fn loopback_mutation_admission_uses_recipient_and_endpoint_without_double_acquire() {
        let local = PartyId(1);
        let slots = BTreeMap::from([(local, Arc::new(Semaphore::new(1)))]);
        let endpoint = Arc::new(Semaphore::new(1));
        let admission = acquire_local_deposit_mutation_admission(
            &slots,
            local,
            &endpoint,
            DepositOperation::ExportHead,
            None,
            Instant::now() + Duration::from_secs(1),
            false,
            std::future::pending(),
            std::future::pending(),
        )
        .await
        .expect("loopback transfer acquires both mutable boundaries");
        assert_eq!(slots[&local].available_permits(), 0);
        assert_eq!(endpoint.available_permits(), 0);
        drop(admission);

        let preacquired = slots[&local].clone().try_acquire_owned().unwrap();
        let admission = acquire_local_deposit_mutation_admission(
            &slots,
            local,
            &endpoint,
            DepositOperation::Certificate,
            Some(preacquired),
            Instant::now() + Duration::from_secs(1),
            true,
            std::future::pending(),
            std::future::pending(),
        )
        .await
        .expect("durable loopback relay reuses its scheduler-owned recipient permit");
        assert_eq!(slots[&local].available_permits(), 0);
        assert_eq!(endpoint.available_permits(), 0);
        drop(admission);
        assert_eq!(slots[&local].available_permits(), 1);
        assert_eq!(endpoint.available_permits(), 1);
    }

    #[test]
    fn in_doubt_exact_keys_keep_relay_excluded_until_ack_or_scope_census() {
        let first_recipient = PartyId(2);
        let second_recipient = PartyId(3);
        let historical_recipient = PartyId(4);
        let first_slot = Arc::new(Semaphore::new(1));
        let second_slot = Arc::new(Semaphore::new(1));
        let historical_slot = Arc::new(Semaphore::new(1));
        let first = StateTransferReservationKey {
            recipient: first_recipient,
            request_id: RequestId::from_bytes([0xA1; 32]),
        };
        let second = StateTransferReservationKey {
            recipient: second_recipient,
            request_id: RequestId::from_bytes([0xA2; 32]),
        };
        let other_epoch = StateTransferReservationKey {
            recipient: historical_recipient,
            request_id: RequestId::from_bytes([0xA3; 32]),
        };
        let first_scope = StateTransferReservationScope::ExportSeal(7);
        let other_scope = StateTransferReservationScope::StateImportCertificate(6);
        let now = Instant::now();
        let mut reservations = StateTransferReservations::default();
        reservations
            .recipients
            .insert(first_recipient, first_slot.clone().try_acquire_owned().unwrap());
        reservations
            .recipients
            .insert(second_recipient, second_slot.clone().try_acquire_owned().unwrap());
        reservations
            .recipients
            .insert(historical_recipient, historical_slot.clone().try_acquire_owned().unwrap());
        for (generation, key, scope) in
            [(1, first, first_scope), (2, second, first_scope), (3, other_epoch, other_scope)]
        {
            reservations.exact.insert(
                key,
                StateTransferRequestReservation { scope, generation, retry: RetryState::new(now) },
            );
        }

        // Model timeout and repeated retryable Busy responses: stream-class guards have already
        // dropped, but the exact recipient projection and all journal identities remain.
        for _ in 0..4 {
            let retry = &mut reservations.exact.get_mut(&first).unwrap().retry;
            retry.failure(
                Instant::now(),
                first_recipient,
                Duration::from_millis(1),
                Duration::from_secs(1),
            );
            assert!(first_slot.clone().try_acquire_owned().is_err());
            assert!(reservations.exact.contains_key(&first));
        }

        // An exact durable ACK releases only its recipient.
        assert!(reservations.remove_exact(first));
        drop(first_slot.clone().try_acquire_owned().unwrap());
        assert!(second_slot.clone().try_acquire_owned().is_err());
        assert!(reservations.exact.contains_key(&second));

        // A complete census for epoch seven proves only its absent key stale. It must not clear a
        // retained historical epoch or release the recipient projection prematurely.
        assert!(state_transfer_reservation_is_absent_from_census(
            second,
            reservations.exact.get(&second).unwrap(),
            first_scope,
            &BTreeSet::new(),
            u64::MAX,
        ));
        assert!(reservations.remove_exact(second));
        assert!(!reservations.exact.contains_key(&second));
        assert!(reservations.exact.contains_key(&other_epoch));
        drop(second_slot.clone().try_acquire_owned().unwrap());
        assert!(historical_slot.clone().try_acquire_owned().is_err());

        assert!(reservations.remove_exact(other_epoch));
        let relay = historical_slot
            .clone()
            .try_acquire_owned()
            .expect("the last exact tombstone releases relay admission");
        drop(relay);
        assert_eq!(historical_slot.available_permits(), 1);
    }

    #[test]
    fn stale_state_transfer_census_cannot_remove_a_newer_exact_reservation() {
        let recipient = PartyId(2);
        let slot = Arc::new(Semaphore::new(1));
        let key = StateTransferReservationKey {
            recipient,
            request_id: RequestId::from_bytes([0xB1; 32]),
        };
        let scope = StateTransferReservationScope::ExportSeal(9);
        let mut reservations = StateTransferReservations::default();
        reservations.recipients.insert(recipient, slot.clone().try_acquire_owned().unwrap());
        reservations.exact.insert(
            key,
            StateTransferRequestReservation {
                scope,
                generation: 2,
                retry: RetryState::new(Instant::now()),
            },
        );

        assert!(!state_transfer_reservation_is_absent_from_census(
            key,
            reservations.exact.get(&key).unwrap(),
            scope,
            &BTreeSet::new(),
            1,
        ));
        assert!(
            reservations.exact.contains_key(&key),
            "an older authoritative snapshot erased a post-snapshot transfer intent"
        );
        assert!(slot.clone().try_acquire_owned().is_err());

        assert!(state_transfer_reservation_is_absent_from_census(
            key,
            reservations.exact.get(&key).unwrap(),
            scope,
            &BTreeSet::new(),
            2,
        ));
        assert!(reservations.remove_exact(key));
        assert!(!reservations.exact.contains_key(&key));
        drop(slot.clone().try_acquire_owned().unwrap());
    }

    #[test]
    fn malformed_wire_success_retains_exact_reservation_with_backoff() {
        let recipient = PartyId(2);
        let slot = Arc::new(Semaphore::new(1));
        let key = StateTransferReservationKey {
            recipient,
            request_id: RequestId::from_bytes([0xB2; 32]),
        };
        let scope = StateTransferReservationScope::ExportHead([0xB3; 32]);
        let mut reservations = StateTransferReservations::default();
        reservations.recipients.insert(recipient, slot.clone().try_acquire_owned().unwrap());
        reservations.exact.insert(
            key,
            StateTransferRequestReservation {
                scope,
                generation: 1,
                retry: RetryState::new(Instant::now()),
            },
        );

        let delay = reservations
            .record_failure(key, Instant::now(), Duration::from_secs(1), Duration::from_secs(10))
            .expect("wire response belongs to the exact in-doubt key");
        assert!(!delay.is_zero());
        assert!(!reservations.exact[&key].retry.ready(Instant::now()));
        assert!(slot.clone().try_acquire_owned().is_err());
        assert!(
            reservations.exact.contains_key(&key),
            "wire-level Success cannot retire work before typed validation and durable ACK"
        );
    }

    #[tokio::test]
    async fn source_request_ack_releases_recipient_lane_for_reciprocal_vote() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportSeal(7);
        let (request_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(
                recipient,
                DepositOperation::PostHandoffExportSealRequest,
                vec![0xC1],
            )
            .unwrap();
        let request_attempt = fixture
            .runtime
            .acquire_state_transfer_reservation(
                request_key,
                scope,
                DepositOperation::PostHandoffExportSealRequest,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("source request acquires its durable recipient cut");

        // A valid request ACK does not tombstone its protocol locator, but transport completion
        // must be independent so the reciprocal LocalVote can use this same recipient lane.
        fixture
            .runtime
            .retire_state_transfer_intent_after_authenticated_response(Some(request_key))
            .await
            .unwrap();
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            1,
        );
        assert!(fixture.runtime.state_transfer_reservations.lock().await.exact.is_empty());
        assert!(fixture.durable_entries().await.1.is_empty());
        drop(request_attempt);

        let (vote_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(
                recipient,
                DepositOperation::PostHandoffExportSealVote,
                vec![0xC2],
            )
            .unwrap();
        let vote_attempt = fixture
            .runtime
            .acquire_state_transfer_reservation(
                vote_key,
                scope,
                DepositOperation::PostHandoffExportSealVote,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("reciprocal vote must not deadlock behind the acknowledged request");
        drop(vote_attempt);
    }

    #[tokio::test]
    async fn fresh_authenticated_rejection_releases_transport_intent_for_protocol_retry() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportHead([0xD1; 32]);
        let operation = DepositOperation::ExportHead;
        let (rejected_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xD2])
            .unwrap();
        let rejected_attempt = fixture
            .runtime
            .acquire_state_transfer_reservation(
                rejected_key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("rejected request acquires its durable transport cut");
        assert!(
            rejected_attempt
                .may_retire_on_authenticated_rejection(QuicResponseProvenance::RejectedBeforeBody,),
            "the first pre-body-rejected attempt has no execution ambiguity"
        );

        fixture
            .runtime
            .handle_authenticated_state_transfer_rejection(
                Some(rejected_key),
                Some(&rejected_attempt),
                Some(QuicResponseProvenance::RejectedBeforeBody),
            )
            .await
            .unwrap();
        assert!(fixture.runtime.state_transfer_reservations.lock().await.exact.is_empty());
        assert!(fixture.durable_entries().await.1.is_empty());
        drop(rejected_attempt);

        let (retry_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xD3])
            .unwrap();
        let retry_attempt = fixture
            .runtime
            .acquire_state_transfer_reservation(
                retry_key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("retained protocol work may issue a different exact retry after rejection");
        drop(retry_attempt);
    }

    #[tokio::test]
    async fn authenticated_rejection_of_exact_retry_retains_in_doubt_intent_with_backoff() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportHead([0xD4; 32]);
        let operation = DepositOperation::ExportHead;
        let (key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xD5])
            .unwrap();
        let first = fixture
            .runtime
            .acquire_state_transfer_reservation(
                key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("first transfer attempt creates the durable cut");
        assert!(first.is_fresh());
        drop(first); // Model a transport timeout after dispatch.

        let retry = fixture
            .runtime
            .acquire_state_transfer_reservation(
                key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("the exact in-doubt request remains retryable");
        assert!(
            !retry
                .may_retire_on_authenticated_rejection(QuicResponseProvenance::RejectedBeforeBody,),
            "the retry must remember the earlier ambiguous execution"
        );
        let delay = fixture
            .runtime
            .state_transfer_reservation_failure(key)
            .await
            .expect("authenticated Busy/InFlight response backs off the exact intent");
        assert!(!delay.is_zero());
        fixture
            .runtime
            .handle_authenticated_state_transfer_rejection(
                Some(key),
                Some(&retry),
                Some(QuicResponseProvenance::RejectedBeforeBody),
            )
            .await
            .unwrap();
        drop(retry);

        {
            let reservations = fixture.runtime.state_transfer_reservations.lock().await;
            assert!(reservations.exact.contains_key(&key));
            assert!(reservations.recipients.contains_key(&recipient));
            assert!(
                !reservations.exact[&key].retry.ready(Instant::now()),
                "retryable rejection must preserve bounded backoff"
            );
        }
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
            "the prior ambiguous execution must keep the recipient lane fenced"
        );
        assert_eq!(fixture.durable_entries().await.1[&recipient].key(), key);

        let (different_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xD6])
            .unwrap();
        assert!(matches!(
            fixture
                .runtime
                .acquire_state_transfer_reservation(
                    different_key,
                    scope,
                    operation,
                    Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(OutboundDepositMutationSlotError::Busy),
        ));
    }

    #[tokio::test]
    async fn postbody_rejection_retains_even_a_fresh_state_transfer_intent() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportHead([0xDA; 32]);
        let operation = DepositOperation::ExportHead;
        let (key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xDB])
            .unwrap();
        let attempt = fixture
            .runtime
            .acquire_state_transfer_reservation(
                key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("first transfer attempt creates the durable cut");
        assert!(attempt.is_fresh());
        assert!(
            !attempt.may_retire_on_authenticated_rejection(QuicResponseProvenance::AfterBody),
            "a peer-controlled post-body response cannot prove the reducer did not commit"
        );

        let delay = fixture
            .runtime
            .state_transfer_reservation_failure(key)
            .await
            .expect("post-body rejection backs off the ambiguous intent");
        assert!(!delay.is_zero());
        fixture
            .runtime
            .handle_authenticated_state_transfer_rejection(
                Some(key),
                Some(&attempt),
                Some(QuicResponseProvenance::AfterBody),
            )
            .await
            .unwrap();
        drop(attempt);

        let reservations = fixture.runtime.state_transfer_reservations.lock().await;
        assert!(reservations.exact.contains_key(&key));
        assert!(!reservations.exact[&key].retry.ready(Instant::now()));
        drop(reservations);
        assert_eq!(fixture.durable_entries().await.1[&recipient].key(), key);
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
        );
    }

    #[tokio::test]
    async fn predispatch_deadline_clears_only_a_fresh_state_transfer_intent() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let scope = StateTransferReservationScope::ExportRelease([0xD7; 32]);
        let operation = DepositOperation::ExportRelease;
        let (fresh_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xD8])
            .unwrap();
        let fresh = fixture
            .runtime
            .acquire_state_transfer_reservation(
                fresh_key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("fresh intent is durably reserved");
        fixture
            .runtime
            .handle_state_transfer_deadline_before_dispatch(fresh_key, &fresh)
            .await
            .unwrap();
        drop(fresh);
        assert!(fixture.runtime.state_transfer_reservations.lock().await.exact.is_empty());
        assert!(fixture.durable_entries().await.1.is_empty());

        let (retry_key, _) = fixture
            .runtime
            .state_transfer_reservation_key(recipient, operation, vec![0xD9])
            .unwrap();
        let first = fixture
            .runtime
            .acquire_state_transfer_reservation(
                retry_key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("first attempt creates another durable cut");
        drop(first); // Model the earlier request becoming transport-ambiguous.
        let retry = fixture
            .runtime
            .acquire_state_transfer_reservation(
                retry_key,
                scope,
                operation,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap()
            .expect("exact retry reuses the in-doubt cut");
        fixture
            .runtime
            .handle_state_transfer_deadline_before_dispatch(retry_key, &retry)
            .await
            .unwrap();
        drop(retry);

        let reservations = fixture.runtime.state_transfer_reservations.lock().await;
        assert!(reservations.exact.contains_key(&retry_key));
        assert!(!reservations.exact[&retry_key].retry.ready(Instant::now()));
        drop(reservations);
        assert_eq!(fixture.durable_entries().await.1[&recipient].key(), retry_key);
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            0,
        );
    }

    #[tokio::test]
    async fn peer_not_ready_creates_no_durable_state_transfer_intent() {
        let fixture = StateTransferIntentRuntimeFixture::new().await;
        fixture.runtime.restore_state_transfer_intents().await.unwrap();
        let recipient = PartyId(2);
        let peer = fixture.runtime.peers.get(&recipient).unwrap();
        peer.retry.lock().await.failure(
            Instant::now(),
            recipient,
            Duration::from_secs(10),
            Duration::from_secs(10),
        );
        assert!(!peer.ready(Instant::now()).await);

        let response = fixture
            .runtime
            .deposit_rpc(
                recipient,
                DepositOperation::ExportHead,
                vec![0xE1],
                Instant::now() + Duration::from_secs(1),
                Some(StateTransferReservationScope::ExportHead([0xE2; 32])),
            )
            .await
            .unwrap();
        assert!(response.is_none());
        assert!(fixture.runtime.state_transfer_reservations.lock().await.exact.is_empty());
        assert!(fixture.durable_entries().await.1.is_empty());
        assert_eq!(
            fixture.runtime.outbound_deposit_mutation_slots[&recipient].available_permits(),
            1,
        );
    }

    #[test]
    fn dedicated_deposit_read_lanes_bypass_mutation_admission() {
        let peer = Arc::new(Semaphore::new(1));
        let _held_peer = peer.clone().try_acquire_owned().unwrap();

        let dedicated_routes = [
            (None, false, false, false),
            (Some(DepositOperation::SyncObjects), true, false, false),
            (Some(DepositOperation::ExportObjects), true, false, false),
            (Some(DepositOperation::PrefixSupportStart), false, true, false),
            (Some(DepositOperation::PrefixSupportContinue), false, true, false),
            (Some(DepositOperation::SyncHead), false, false, true),
            (Some(DepositOperation::SyncRelease), false, false, true),
        ];
        for (operation, object_read, prefix_support, sync_control) in dedicated_routes {
            let required = requires_deposit_mutation_admission(
                operation,
                object_read,
                prefix_support,
                sync_control,
            );
            assert!(!required);
            assert!(
                try_acquire_deposit_mutation_peer_slot(&peer, required).unwrap().is_none(),
                "a dedicated read/control route must not touch the saturated mutation lane",
            );
        }

        assert!(requires_deposit_mutation_admission(
            Some(DepositOperation::Attest),
            false,
            false,
            false,
        ));
        assert!(
            requires_deposit_mutation_admission(
                Some(DepositOperation::ExportHead),
                false,
                false,
                false,
            ),
            "ExportHead creates a durable source lease and remains a mutation",
        );
        assert!(
            requires_deposit_mutation_admission(
                Some(DepositOperation::ExportRelease),
                false,
                false,
                false,
            ),
            "certified-export release has no independent sync-control lane",
        );
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
    fn inbound_execution_capacity_rejects_synchronously_and_releases_partial_admission() {
        let first_peer = Arc::new(Semaphore::new(1));
        let second_peer = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(2));

        let first = try_acquire_inbound_request_execution_permits(&first_peer, &global, true)
            .unwrap()
            .unwrap();
        assert_eq!(first_peer.available_permits(), 0);
        assert_eq!(global.available_permits(), 1);
        assert_eq!(
            try_acquire_inbound_request_execution_permits(&first_peer, &global, true).unwrap_err(),
            inbound_concurrency_limited_response(),
        );
        assert_eq!(
            global.available_permits(),
            1,
            "a peer-local rejection must not consume global capacity"
        );

        let second = try_acquire_inbound_request_execution_permits(&second_peer, &global, true)
            .unwrap()
            .unwrap();
        assert_eq!(global.available_permits(), 0);
        drop(first);
        assert_eq!(first_peer.available_permits(), 1);
        assert_eq!(global.available_permits(), 1);

        let third_peer = Arc::new(Semaphore::new(1));
        let third = try_acquire_inbound_request_execution_permits(&third_peer, &global, true)
            .unwrap()
            .unwrap();
        assert_eq!(global.available_permits(), 0);
        let available_before = first_peer.available_permits();
        assert_eq!(
            try_acquire_inbound_request_execution_permits(&first_peer, &global, true).unwrap_err(),
            inbound_concurrency_limited_response(),
        );
        assert_eq!(
            first_peer.available_permits(),
            available_before,
            "a failed global acquisition must immediately return its peer permit"
        );

        drop((second, third));
        assert_eq!(global.available_permits(), 2);
    }

    #[test]
    fn inbound_body_capacity_is_weighted_exact_and_releases_partial_admission() {
        assert_eq!(MAX_INBOUND_BODY_BYTES_PER_PEER, 8 * 1024 * 1024);
        assert_eq!(MAX_INBOUND_BODY_BYTES, 8 * MAX_INBOUND_BODY_BYTES_PER_PEER);

        let production_peer = Arc::new(Semaphore::new(MAX_INBOUND_BODY_BYTES_PER_PEER));
        let production_global = Arc::new(Semaphore::new(MAX_INBOUND_BODY_BYTES));
        let maximum = try_acquire_inbound_request_body_permits(
            &production_peer,
            &production_global,
            MAX_INBOUND_BODY_BYTES_PER_PEER,
        )
        .expect("one exact transport-maximum body must fit");
        assert_eq!(production_peer.available_permits(), 0);
        assert_eq!(
            production_global.available_permits(),
            MAX_INBOUND_BODY_BYTES - MAX_INBOUND_BODY_BYTES_PER_PEER
        );
        drop(maximum);

        let first_peer = Arc::new(Semaphore::new(8));
        let second_peer = Arc::new(Semaphore::new(8));
        let third_peer = Arc::new(Semaphore::new(8));
        let global = Arc::new(Semaphore::new(12));

        let first = try_acquire_inbound_request_body_permits(&first_peer, &global, 8).unwrap();
        assert_eq!(first_peer.available_permits(), 0, "the exact peer boundary must fit");
        assert_eq!(global.available_permits(), 4);
        assert_eq!(
            try_acquire_inbound_request_body_permits(&first_peer, &global, 1).unwrap_err(),
            inbound_body_capacity_limited_response(),
        );
        assert_eq!(
            global.available_permits(),
            4,
            "a peer-local byte rejection must not consume global capacity"
        );

        let second = try_acquire_inbound_request_body_permits(&second_peer, &global, 4).unwrap();
        assert_eq!(global.available_permits(), 0, "the exact global boundary must fit");
        let third_before = third_peer.available_permits();
        assert_eq!(
            try_acquire_inbound_request_body_permits(&third_peer, &global, 1).unwrap_err(),
            inbound_body_capacity_limited_response(),
        );
        assert_eq!(
            third_peer.available_permits(),
            third_before,
            "a failed global byte acquisition must return its peer reservation"
        );

        drop(second);
        assert_eq!(global.available_permits(), 4);
        drop(first);
        assert_eq!(first_peer.available_permits(), 8);
        assert_eq!(global.available_permits(), 12);

        let zero = try_acquire_inbound_request_body_permits(&third_peer, &global, 0).unwrap();
        assert_eq!(third_peer.available_permits(), 8);
        assert_eq!(global.available_permits(), 12);
        drop(zero);

        if let Ok(oversized) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(
                try_acquire_inbound_request_body_permits(&third_peer, &global, oversized)
                    .unwrap_err(),
                inbound_body_capacity_limited_response(),
            );
        }
        assert_eq!(third_peer.available_permits(), 8);
        assert_eq!(global.available_permits(), 12);
    }

    #[tokio::test]
    async fn sync_objects_execution_is_peer_bounded_fifo_fair_and_route_independent() {
        assert_eq!(MAX_CONCURRENT_DEPOSIT_SYNC_OBJECT_REQUESTS, 1);
        assert_eq!(MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES, 128 * 1024);
        assert!(
            MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES <= MAX_INBOUND_BODY_BYTES_PER_PEER,
            "one protocol-bounded queued body fits its authenticated peer's body budget",
        );

        let global = Arc::new(Semaphore::new(MAX_CONCURRENT_DEPOSIT_SYNC_OBJECT_REQUESTS));
        let peer_a = Arc::new(Semaphore::new(1));
        let peer_b = Arc::new(Semaphore::new(1));
        assert!(
            try_acquire_deposit_sync_objects_peer_slot(&peer_a, false).unwrap().is_none(),
            "ordinary routes do not acquire the SyncObjects peer lane",
        );

        let active_a = try_acquire_deposit_sync_objects_peer_slot(&peer_a, true)
            .unwrap()
            .expect("peer A acquires its sole outstanding-request slot");
        let execution_a =
            acquire_deposit_sync_objects_execution_permit(&global, std::future::pending())
                .await
                .expect("peer A acquires the global execution permit");
        assert_eq!(global.available_permits(), 0);

        let active_b = try_acquire_deposit_sync_objects_peer_slot(&peer_b, true)
            .unwrap()
            .expect("peer B may hold one decoded body while peer A executes");
        let (b_queued_tx, b_queued_rx) = tokio::sync::oneshot::channel();
        let global_for_b = global.clone();
        let queued_b = tokio::spawn(async move {
            b_queued_tx.send(()).unwrap();
            acquire_deposit_sync_objects_execution_permit(&global_for_b, std::future::pending())
                .await
        });
        b_queued_rx.await.unwrap();
        tokio::task::yield_now().await;

        for _ in 0..8 {
            let Err(response) = try_acquire_deposit_sync_objects_peer_slot(&peer_a, true) else {
                panic!("peer A must not enqueue a second SyncObjects request");
            };
            assert_eq!(response, deposit_sync_objects_peer_busy_response());
            assert!(matches!(
                response,
                PeerResponse::Rejected {
                    code: RejectionCode::ResourceExhausted,
                    retryable: true,
                    ..
                }
            ));
        }

        assert!(
            try_acquire_deposit_sync_objects_peer_slot(&peer_a, false).unwrap().is_none(),
            "an active SyncObjects request still does not gate another protocol family",
        );

        drop((execution_a, active_a));
        let retry_a = try_acquire_deposit_sync_objects_peer_slot(&peer_a, true)
            .unwrap()
            .expect("peer A may retry after its prior response releases the peer slot");
        let (a_queued_tx, a_queued_rx) = tokio::sync::oneshot::channel();
        let global_for_a = global.clone();
        let queued_retry_a = tokio::spawn(async move {
            a_queued_tx.send(()).unwrap();
            acquire_deposit_sync_objects_execution_permit(&global_for_a, std::future::pending())
                .await
        });
        a_queued_rx.await.unwrap();
        tokio::task::yield_now().await;

        let execution_b = time::timeout(Duration::from_secs(1), queued_b)
            .await
            .expect("peer B's earlier FIFO waiter must be granted")
            .unwrap()
            .expect("the global semaphore remains open");
        assert!(
            !queued_retry_a.is_finished(),
            "peer A's retry must not reacquire ahead of already-queued peer B",
        );
        drop((execution_b, active_b));
        let execution_retry_a = time::timeout(Duration::from_secs(1), queued_retry_a)
            .await
            .expect("peer A retry proceeds after peer B")
            .unwrap()
            .expect("the global semaphore remains open");
        drop((execution_retry_a, retry_a));
        assert_eq!(global.available_permits(), MAX_CONCURRENT_DEPOSIT_SYNC_OBJECT_REQUESTS);
    }

    #[tokio::test]
    async fn prefix_support_execution_is_one_scan_per_requester_and_fifo_fair() {
        assert_eq!(MAX_CONCURRENT_DEPOSIT_PREFIX_SUPPORT_SCANS, 1);
        let global = Arc::new(Semaphore::new(MAX_CONCURRENT_DEPOSIT_PREFIX_SUPPORT_SCANS));
        let requester_a = Arc::new(Semaphore::new(1));
        let requester_b = Arc::new(Semaphore::new(1));
        assert!(
            try_acquire_deposit_prefix_support_peer_slot(&requester_a, false).unwrap().is_none(),
            "ordinary routes do not acquire the prefix-support scan lane",
        );

        let active_a = try_acquire_deposit_prefix_support_peer_slot(&requester_a, true)
            .unwrap()
            .expect("requester A acquires its single scan slot");
        let execution_a =
            acquire_deposit_prefix_support_execution_permit(&global, std::future::pending())
                .await
                .expect("requester A acquires global scan execution");
        assert_eq!(
            try_acquire_deposit_prefix_support_peer_slot(&requester_a, true).unwrap_err(),
            deposit_prefix_support_peer_busy_response(),
        );

        let active_b = try_acquire_deposit_prefix_support_peer_slot(&requester_b, true)
            .unwrap()
            .expect("requester B may queue one bounded scan step");
        let global_for_b = global.clone();
        let queued_b = tokio::spawn(async move {
            acquire_deposit_prefix_support_execution_permit(&global_for_b, std::future::pending())
                .await
        });
        tokio::task::yield_now().await;

        drop((execution_a, active_a));
        let retry_a = try_acquire_deposit_prefix_support_peer_slot(&requester_a, true)
            .unwrap()
            .expect("requester A may submit its next persisted revision");
        let global_for_retry = global.clone();
        let queued_retry_a = tokio::spawn(async move {
            acquire_deposit_prefix_support_execution_permit(
                &global_for_retry,
                std::future::pending(),
            )
            .await
        });

        let execution_b = time::timeout(Duration::from_secs(1), queued_b)
            .await
            .expect("requester B's earlier waiter must run")
            .unwrap()
            .expect("global support semaphore remains open");
        assert!(!queued_retry_a.is_finished(), "requester A cannot reacquire ahead of requester B");
        drop((execution_b, active_b));
        let execution_retry_a = time::timeout(Duration::from_secs(1), queued_retry_a)
            .await
            .expect("requester A's next revision eventually runs")
            .unwrap()
            .expect("global support semaphore remains open");
        drop((execution_retry_a, retry_a));
        assert_eq!(global.available_permits(), MAX_CONCURRENT_DEPOSIT_PREFIX_SUPPORT_SCANS);
    }

    #[tokio::test]
    async fn sync_objects_oversize_prelude_and_shutdown_release_every_reservation() {
        let peer = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(1));
        let peer_body = Arc::new(Semaphore::new(MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES));
        let global_body = Arc::new(Semaphore::new(MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES));

        assert_eq!(
            validate_deposit_sync_objects_body_len(true, MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES + 1,),
            Err(deposit_sync_objects_body_too_large_response()),
        );
        assert!(
            validate_deposit_sync_objects_body_len(
                false,
                MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES + 1,
            )
            .is_ok(),
            "the route-specific cap must not constrain ordinary protocols",
        );
        assert_eq!(peer.available_permits(), 1, "oversize prelude allocated no peer slot");
        assert_eq!(
            global_body.available_permits(),
            MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES,
            "oversize prelude allocated no body",
        );

        let execution = global.clone().acquire_owned().await.unwrap();
        let peer_slot = try_acquire_deposit_sync_objects_peer_slot(&peer, true)
            .unwrap()
            .expect("queued request acquires its peer slot");
        let body = try_acquire_inbound_request_body_permits(
            &peer_body,
            &global_body,
            MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES,
        )
        .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let global_for_waiter = global.clone();
        let waiter = tokio::spawn(async move {
            acquire_deposit_sync_objects_execution_permit(&global_for_waiter, async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        tokio::task::yield_now().await;
        shutdown_tx.send(()).unwrap();
        assert!(
            time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("shutdown wakes the queued execution waiter")
                .unwrap()
                .is_none()
        );

        drop((body, peer_slot, execution));
        assert_eq!(peer.available_permits(), 1);
        assert_eq!(peer_body.available_permits(), MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES,);
        assert_eq!(global_body.available_permits(), MAX_DEPOSIT_SYNC_OBJECT_REQUEST_BYTES,);
        assert_eq!(global.available_permits(), 1);
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
    fn transition_cursor_gives_current_work_a_bounded_turn_among_rejected_history() {
        use crate::quic_transport::{KeyRotationOperation, QualOperation};

        let recipient = PartyId(2);
        let mut pending = BTreeMap::new();
        // More historical poison items than fit between the runtime's poll and retry maxima can
        // keep at least one old item ready on every poll. Without a persistent cursor, the current
        // advertisement below is never selected.
        for slot in 0_u8..12 {
            retain_earliest_transition_work(
                &mut pending,
                1,
                u64::from(slot),
                transition_test_work(
                    recipient,
                    slot.saturating_add(1),
                    PeerRequest::Qual { operation: QualOperation::Deliver, body: vec![slot] },
                ),
            );
        }
        retain_earliest_transition_work(
            &mut pending,
            2,
            0,
            transition_test_work(
                recipient,
                0xF0,
                PeerRequest::KeyRotation {
                    operation: KeyRotationOperation::Advertisement,
                    body: vec![0xF0],
                },
            ),
        );
        let candidates = pending.remove(&recipient).unwrap();
        let expected = candidates.len();
        let mut cursor = None;
        let mut admitted = Vec::new();
        for _ in 0..expected {
            let (order, work) =
                transition_candidates_after(candidates.clone(), cursor).into_iter().next().unwrap();
            cursor = Some(order);
            admitted.push(work.key);
        }

        assert_eq!(admitted.len(), expected);
        assert_eq!(admitted.iter().copied().collect::<BTreeSet<_>>().len(), expected);
        assert!(
            admitted.contains(&RequestId::from_bytes([0xF0; 32])),
            "current-epoch key rotation was starved by retained historical evidence"
        );
        let wrapped =
            transition_candidates_after(candidates.clone(), cursor).into_iter().next().unwrap().1;
        assert_eq!(wrapped.key, candidates.values().next().unwrap().key);
    }

    #[test]
    fn sustained_direct_work_and_transitions_share_outbound_capacity() {
        let mut cursor = RelayLaneCursor::default();
        let mut admitted = Vec::new();
        for _ in 0..64 {
            let lane = cursor.scheduling_order()[0];
            admitted.push(lane);
            cursor.record_scheduled(lane);
        }

        assert_eq!(admitted.first(), Some(&RelayLane::Transition));
        assert!(
            admitted.windows(2).all(|pair| pair == [RelayLane::Transition, RelayLane::Direct]
                || pair == [RelayLane::Direct, RelayLane::Transition]),
            "continuously ready relay classes must alternate successful admissions"
        );
        assert_eq!(
            admitted.iter().filter(|lane| **lane == RelayLane::Direct).count(),
            admitted.iter().filter(|lane| **lane == RelayLane::Transition).count()
        );
    }

    #[test]
    fn active_deposit_recipient_survives_candidate_compaction_until_local_ack() {
        let recipient = PartyId(2);
        let key = RequestId::from_bytes([0xD2; 32]);
        let mut active = BTreeMap::from([(recipient, key)]);
        let mut in_flight = BTreeSet::from([key]);

        // The current durable enumeration may no longer contain the accepted item. Recipient
        // occupancy is reconciled from the ACK-owned in-flight key, not inferred from candidates.
        reconcile_active_deposit_recipients(&mut active, &in_flight);
        assert_eq!(active.get(&recipient), Some(&key));

        in_flight.remove(&key);
        reconcile_active_deposit_recipients(&mut active, &in_flight);
        assert!(
            active.is_empty(),
            "the recipient becomes eligible only after local durable ACK retirement",
        );
    }

    #[test]
    fn mutable_deposit_lane_round_robin_bounds_protocol_and_client_delay() {
        let lanes = [
            DepositCausalLane::Ledger,
            DepositCausalLane::Checkpoint,
            DepositCausalLane::Observation,
            DepositCausalLane::Consolidation,
            DepositCausalLane::Auxiliary,
            DepositCausalLane::ClientRequest(PartyId(1)),
            DepositCausalLane::ClientRequest(PartyId(3)),
        ];
        let candidates = lanes.into_iter().map(|lane| (lane, ())).collect::<BTreeMap<_, _>>();
        let mut cursor = None;
        let mut admitted = Vec::new();

        // Model continuously replenished predecessors in every live lane. Recording only the
        // successfully selected lane must visit the entire fixed ordering before wrapping.
        for _ in 0..lanes.len() * 2 {
            let lane = deposit_relay_candidates_after(candidates.clone(), cursor)
                .into_iter()
                .next()
                .expect("the continuously populated recipient has one candidate")
                .0;
            admitted.push(lane);
            cursor = Some(lane);
        }
        assert_eq!(&admitted[..lanes.len()], &lanes);
        assert_eq!(&admitted[lanes.len()..], &lanes);
        assert_eq!(
            admitted[..lanes.len()].iter().copied().collect::<BTreeSet<_>>().len(),
            lanes.len(),
            "no replenished lane may consume a second turn before every live lane gets one",
        );

        let after_clients = deposit_relay_candidates_after(
            candidates.clone(),
            Some(DepositCausalLane::ClientRequest(PartyId(3))),
        );
        assert_eq!(
            after_clients.first().map(|(lane, ())| *lane),
            Some(DepositCausalLane::Ledger),
            "bounded client gossip must wrap to protocol work",
        );
        let after_protocol =
            deposit_relay_candidates_after(candidates, Some(DepositCausalLane::Auxiliary));
        assert_eq!(
            after_protocol.first().map(|(lane, ())| *lane),
            Some(DepositCausalLane::ClientRequest(PartyId(1))),
            "continuous protocol work must still yield a bounded client turn",
        );
    }

    #[test]
    fn colliding_activation_ack_order_rotates_exact_ids_without_starvation() {
        fn activation_ack_id(marker: u8) -> PeerMessageId {
            PeerMessageId::ActivationAck {
                session: SessionId([marker; 32]),
                recipient: PartyId(2),
                digest: [marker; 32],
            }
        }

        let first = activation_ack_id(1);
        let second = activation_ack_id(2);
        let candidates = BTreeMap::from([(first, ()), (second, ())]);

        assert_eq!(
            activation_ack_exact_candidates_after(candidates.clone(), Some(first))
                .first()
                .map(|(id, ())| *id),
            Some(second),
        );
        assert_eq!(
            activation_ack_exact_candidates_after(candidates.clone(), Some(second))
                .first()
                .map(|(id, ())| *id),
            Some(first),
        );

        // Backoff skips do not advance the exact cursor. Even if the first identity remains
        // perpetually ineligible, scanning the full nested bucket still reaches the ready
        // competing/superseded identity on every poll.
        let mut cursor = Some(second);
        for _ in 0..32 {
            let selected = activation_ack_exact_candidates_after(candidates.clone(), cursor)
                .into_iter()
                .find(|(id, ())| *id != first)
                .expect("a backed-off exact identity must not hide its ready sibling")
                .0;
            assert_eq!(selected, second);
            cursor = Some(selected);
        }
    }

    #[test]
    fn narrow_direct_capacity_rotates_across_replenished_deposit_lanes() {
        let lanes = [
            (PartyId(1), DepositCausalLane::Ledger),
            (PartyId(1), DepositCausalLane::Checkpoint),
            (PartyId(1), DepositCausalLane::Observation),
            (PartyId(2), DepositCausalLane::Ledger),
            (PartyId(2), DepositCausalLane::Checkpoint),
            (PartyId(3), DepositCausalLane::Consolidation),
        ];
        let mut cursor = DirectWorkCursor::default();
        let mut deposit_cursor = BTreeMap::new();
        let mut admitted = BTreeSet::new();

        // Model a width-two runtime whose first lanes are immediately replenished after every
        // successful durable ACK. Reconstructing the same fixed enumeration on each poll must still
        // give every later recipient/lane a permit.
        for _ in 0..4 {
            let pending = lanes.into_iter().fold(
                BTreeMap::<PartyId, BTreeMap<DepositCausalLane, ()>>::new(),
                |mut pending, (recipient, lane)| {
                    pending.entry(recipient).or_default().insert(lane, ());
                    pending
                },
            );
            for (recipient, candidates) in
                direct_recipients_after(pending, cursor.recipient).into_iter().take(2)
            {
                let lane = deposit_relay_candidates_after(
                    candidates,
                    deposit_cursor.get(&recipient).copied(),
                )
                .into_iter()
                .next()
                .expect("each reconstructed recipient has a live lane")
                .0;
                admitted.insert((recipient, lane));
                deposit_cursor.insert(recipient, lane);
                cursor.record_scheduled(recipient, DirectSemanticLane::Deposit);
            }
        }

        assert_eq!(admitted, BTreeSet::from(lanes));
    }

    #[test]
    fn saturated_global_budget_preserves_the_transition_turn() {
        let mut cursor = RelayLaneCursor::default();
        assert_eq!(cursor.scheduling_order()[0], RelayLane::Transition);

        // A poll which finds the global semaphore exhausted does not call `record_scheduled`.
        // Repeating that outcome must therefore keep transitions first until capacity returns.
        for _ in 0..32 {
            assert_eq!(cursor.scheduling_order()[0], RelayLane::Transition);
        }

        cursor.record_scheduled(RelayLane::Transition);
        assert_eq!(cursor.scheduling_order()[0], RelayLane::Direct);
        cursor.record_scheduled(RelayLane::Direct);
        assert_eq!(cursor.scheduling_order()[0], RelayLane::Transition);
    }

    #[test]
    fn unavailable_preferred_lane_does_not_block_the_other_lane() {
        let mut cursor = RelayLaneCursor::default();

        // Production falls through to the second entry when the preferred iterator is exhausted.
        for _ in 0..16 {
            let fallback = cursor.scheduling_order()[1];
            assert_eq!(fallback, RelayLane::Direct);
            cursor.record_scheduled(fallback);
            assert_eq!(cursor.scheduling_order()[0], RelayLane::Transition);
        }

        // As soon as transition work becomes ready it still owns the next admission, after which
        // direct work regains preference.
        cursor.record_scheduled(RelayLane::Transition);
        assert_eq!(cursor.scheduling_order()[0], RelayLane::Direct);
    }

    #[test]
    fn self_contained_key_rotation_proposal_precedes_standalone_view_evidence() {
        let digest = [0x91; 32];
        assert!(
            key_rotation_delivery_order(7, KeyRotationDeliveryKind::Proposal { view: 4 }, digest,)
                < key_rotation_delivery_order(
                    7,
                    KeyRotationDeliveryKind::ViewChange { target_view: 4 },
                    digest,
                )
        );
        assert!(
            key_rotation_delivery_order(7, KeyRotationDeliveryKind::Proposal { view: 4 }, digest,)
                < key_rotation_delivery_order(
                    7,
                    KeyRotationDeliveryKind::ViewCertificate { target_view: 4 },
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
    fn certified_state_transfer_preludes_are_history_gated_except_storage_only_release() {
        for operation in [
            DepositOperation::PostHandoffExportSealRequest,
            DepositOperation::PostHandoffExportSealVote,
            DepositOperation::PostHandoffExportSealCertificate,
            DepositOperation::ExportHead,
            DepositOperation::ExportObjects,
            DepositOperation::StateImportedAck,
            DepositOperation::StateImportedCertificate,
        ] {
            assert!(
                deposit_state_transfer_requires_history_authorization(operation),
                "{operation:?} must be rejected before body admission for an unrelated peer",
            );
        }
        assert!(
            !deposit_state_transfer_requires_history_authorization(DepositOperation::ExportRelease),
            "an exact lease release remains valid after committee removal",
        );
        assert!(
            !deposit_state_transfer_requires_history_authorization(DepositOperation::SyncHead),
            "ordinary sync has its separate current-committee admission gate",
        );
        assert!(
            !deposit_state_transfer_requires_history_authorization(DepositOperation::SyncRelease),
            "the exact ordinary-sync lease MAC remains release authority after committee removal",
        );
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
    fn scenario_identity_count_sets_a_checked_dynamic_outbox_bound() {
        let configured_parties = MAX_COMMITTEE_MEMBERS + 1;
        let required = configured_parties.checked_mul(DepositCausalLane::COUNT).unwrap();
        assert!(
            required > MIN_OUTBOX_BATCH_SIZE,
            "an identity roster larger than one maximum committee needs a larger poll",
        );

        let generic_minimum =
            QuicRuntimeConfig { outbox_batch_size: MIN_OUTBOX_BATCH_SIZE, ..Default::default() }
                .validate()
                .expect("the deployment-independent minimum remains generically valid");
        assert!(matches!(
            validate_scenario_outbox_batch_size(
                generic_minimum.outbox_batch_size,
                configured_parties,
            ),
            Err(QuicRuntimeError::InvalidConfiguration(_)),
        ));
        assert!(
            validate_scenario_outbox_batch_size(required, configured_parties).is_ok(),
            "the exact scenario-sized coverage bound must be accepted",
        );

        let parties_above_capacity = MAX_BATCH_SIZE / DepositCausalLane::COUNT + 1;
        assert!(matches!(
            validate_scenario_outbox_batch_size(MAX_BATCH_SIZE, parties_above_capacity),
            Err(QuicRuntimeError::InvalidConfiguration(_)),
        ));
        let overflowing_parties = usize::MAX / DepositCausalLane::COUNT + 1;
        assert!(matches!(
            validate_scenario_outbox_batch_size(MAX_BATCH_SIZE, overflowing_parties),
            Err(QuicRuntimeError::InvalidConfiguration(_)),
        ));
    }

    #[test]
    fn runtime_limits_reject_unbounded_or_zero_values() {
        let minimum_reserved = QuicRuntimeConfig {
            max_outbound_requests: 2,
            max_outbound_requests_per_peer: 2,
            max_epoch_history_raced_sources: 1,
            ..Default::default()
        };
        assert!(minimum_reserved.validate().is_ok());

        let invalid = QuicRuntimeConfig { outbox_batch_size: 0, ..Default::default() };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            outbox_batch_size: MIN_OUTBOX_BATCH_SIZE - 1,
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
            max_outbound_requests: 1,
            max_outbound_requests_per_peer: 1,
            max_epoch_history_raced_sources: 1,
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            max_outbound_requests: 4,
            max_outbound_requests_per_peer: 1,
            max_epoch_history_raced_sources: 3,
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            max_outbound_requests: 4,
            max_outbound_requests_per_peer: 2,
            max_epoch_history_raced_sources: 4,
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

        let invalid =
            QuicRuntimeConfig { outbound_request_timeout: Duration::ZERO, ..Default::default() };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid =
            QuicRuntimeConfig { deposit_sync_interval: Duration::ZERO, ..Default::default() };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            epoch_history_request_timeout: Duration::from_secs(3),
            epoch_history_source_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            deposit_sync_request_timeout: Duration::from_secs(3),
            deposit_sync_source_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid = QuicRuntimeConfig {
            deposit_sync_request_timeout: Duration::from_secs(2),
            deposit_sync_source_timeout: Duration::from_secs(4),
            deposit_sync_tick_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));

        let invalid =
            QuicRuntimeConfig { max_epoch_history_raced_sources: 0, ..Default::default() };
        assert!(matches!(invalid.validate(), Err(QuicRuntimeError::InvalidConfiguration(_))));
    }

    #[test]
    fn only_durable_completed_export_work_is_a_benign_census_race() {
        assert!(completed_export_work(
            &anyhow::Error::new(DepositServiceError::StateExportWorkAlreadyComplete)
                .context("reconstruct export work")
        ));
        for error in [
            DepositServiceError::InvalidPeerMessage,
            DepositServiceError::StorageRevisionMismatch,
            DepositServiceError::StateExportStore(
                "post-handoff export work is already durably complete".into(),
            ),
        ] {
            assert!(!completed_export_work(&error.into()));
        }
    }

    #[test]
    fn only_durable_completed_import_work_is_a_benign_census_race() {
        assert!(completed_state_import_work(
            &anyhow::Error::new(DepositServiceError::StateImportStore(
                DepositStateImportStoreError::WorkAlreadyComplete
            ))
            .context("reconstruct import work")
        ));
        for error in [
            DepositServiceError::InvalidPeerMessage,
            DepositServiceError::InvalidProtocolState,
            DepositServiceError::StorageRevisionMismatch,
            DepositServiceError::StateImportStore(DepositStateImportStoreError::InvalidWorkLocator),
        ] {
            assert!(!completed_state_import_work(&error.into()));
        }
    }

    #[test]
    fn default_qual_timeout_cannot_race_normal_avss_fanout() {
        assert_eq!(derived_qual_round_timeout(1), Duration::from_secs(10));
        assert_eq!(derived_qual_round_timeout(1_000), Duration::from_secs(32));
    }

    #[test]
    fn exact_export_freeze_not_terminal_fanout_gates_target_import() {
        let certificate = DepositStateExportSealWorkKind::CertificateDelivery;
        assert!(
            export_seal_phase_blocks_target_import(true, [certificate]),
            "the durable local freeze marker remains causal even if a certificate already exists",
        );
        assert!(
            !export_seal_phase_blocks_target_import(false, [certificate, certificate]),
            "silent certificate recipients cannot hold target import after the exact seal+pin freeze",
        );
        assert!(
            export_seal_phase_blocks_target_import(
                false,
                [DepositStateExportSealWorkKind::SourceRequest],
            ),
            "source vote collection remains causal",
        );
        assert!(
            !export_seal_phase_blocks_target_import(
                false,
                [DepositStateExportSealWorkKind::LocalVote],
            ),
            "a silent source cannot gate local import on receipt of an already journaled vote",
        );
        for kind in [certificate, DepositStateExportSealWorkKind::LocalVote] {
            assert!(export_seal_work_is_causal(true, kind));
            assert!(
                !export_seal_work_is_causal(false, kind),
                "post-freeze retries belong to background fanout"
            );
        }
    }

    #[test]
    fn state_import_ack_collection_not_terminal_fanout_gates_ordinary_sync() {
        assert!(state_import_work_needs_reload(
            &DepositServiceError::StateImportStore(
                DepositStateImportStoreError::WorkAlreadyComplete
            )
            .into()
        ));
        assert!(!state_import_work_needs_reload(&DepositServiceError::InvalidPeerMessage.into()));
        assert!(state_import_phase_blocks_ordinary_sync([
            DepositStateImportWorkKind::AcknowledgementDelivery,
        ]));
        assert!(
            !state_import_phase_blocks_ordinary_sync([
                DepositStateImportWorkKind::CertificateDelivery,
                DepositStateImportWorkKind::CertificateDelivery,
            ]),
            "a silent terminal-certificate recipient cannot hold ordinary synchronization",
        );
    }

    #[test]
    fn background_fanout_releases_sync_capacity_before_the_next_current_tick() {
        let interval = Duration::from_secs(8);
        assert_eq!(
            deposit_state_transfer_background_budget(interval, Duration::from_secs(30)),
            Some(Duration::from_secs(2)),
        );
        assert_eq!(
            deposit_state_transfer_background_budget(interval, Duration::from_millis(500)),
            Some(Duration::from_millis(500)),
        );
        assert!(
            deposit_state_transfer_background_budget(interval, Duration::from_secs(30)).unwrap()
                < interval / 2,
        );
    }

    #[test]
    fn alternating_background_lanes_rotate_every_recipient_independently() {
        let export = AtomicUsize::new(0);
        let imported = AtomicUsize::new(0);
        let mut export_order = Vec::new();
        let mut imported_order = Vec::new();
        for _ in 0..4 {
            export_order.push(deposit_state_transfer_background_start(&export, 4));
            imported_order.push(deposit_state_transfer_background_start(&imported, 4));
        }
        assert_eq!(export_order, [0, 1, 2, 3]);
        assert_eq!(imported_order, [0, 1, 2, 3]);
    }

    #[test]
    fn current_and_historical_background_scopes_alternate_first_claim() {
        let cursor = AtomicUsize::new(0);
        assert_eq!(
            deposit_state_transfer_background_scope_order(&cursor),
            [
                DepositStateTransferBackgroundScope::Current,
                DepositStateTransferBackgroundScope::Historical,
            ],
        );
        assert_eq!(
            deposit_state_transfer_background_scope_order(&cursor),
            [
                DepositStateTransferBackgroundScope::Historical,
                DepositStateTransferBackgroundScope::Current,
            ],
            "a silent current recipient may consume one turn but cannot starve historical fanout",
        );
        assert_eq!(
            deposit_state_transfer_background_scope_order(&cursor),
            [
                DepositStateTransferBackgroundScope::Current,
                DepositStateTransferBackgroundScope::Historical,
            ],
        );
    }

    #[tokio::test]
    async fn blocked_publication_does_not_freeze_consolidation_pacemaker() {
        let publication_entered = Arc::new(Semaphore::new(0));
        let publication_release = Arc::new(Semaphore::new(0));
        let consolidation_progressed = Arc::new(Semaphore::new(0));
        let pacemakers = {
            let publication_entered = Arc::clone(&publication_entered);
            let publication_release = Arc::clone(&publication_release);
            let consolidation_progressed = Arc::clone(&consolidation_progressed);
            tokio::spawn(run_deposit_pacemakers(
                async {},
                async {},
                async {},
                async {},
                async move {
                    consolidation_progressed.add_permits(1);
                },
                async move {
                    publication_entered.add_permits(1);
                    publication_release.acquire().await.unwrap().forget();
                },
            ))
        };
        time::timeout(Duration::from_secs(1), publication_entered.acquire())
            .await
            .expect("publication future did not enter")
            .unwrap()
            .forget();
        time::timeout(Duration::from_secs(1), consolidation_progressed.acquire())
            .await
            .expect("consolidation pacemaker was gated by publication")
            .unwrap()
            .forget();
        publication_release.add_permits(1);
        time::timeout(Duration::from_secs(1), pacemakers)
            .await
            .expect("released pacemakers did not finish")
            .unwrap();
    }

    #[tokio::test]
    async fn blocked_background_fanout_does_not_freeze_current_sync_pacemaker() {
        let background_entered = Arc::new(Semaphore::new(0));
        let background_release = Arc::new(Semaphore::new(0));
        let current_progressed = Arc::new(Semaphore::new(0));
        let pacemakers = {
            let background_entered = Arc::clone(&background_entered);
            let background_release = Arc::clone(&background_release);
            let current_progressed = Arc::clone(&current_progressed);
            tokio::spawn(run_deposit_pacemakers(
                async move {
                    current_progressed.add_permits(1);
                },
                async move {
                    background_entered.add_permits(1);
                    background_release.acquire().await.unwrap().forget();
                },
                async {},
                async {},
                async {},
                async {},
            ))
        };
        time::timeout(Duration::from_secs(1), background_entered.acquire())
            .await
            .expect("background fanout future did not enter")
            .unwrap()
            .forget();
        time::timeout(Duration::from_secs(1), current_progressed.acquire())
            .await
            .expect("current sync pacemaker was gated by background fanout")
            .unwrap()
            .forget();
        background_release.add_permits(1);
        time::timeout(Duration::from_secs(1), pacemakers)
            .await
            .expect("released pacemakers did not finish")
            .unwrap();
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
            assert!(disposition_requires_backoff(
                request_requires_positive_ack(&request),
                &rejection
            ));
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
        assert!(disposition_requires_backoff(
            request_requires_positive_ack(&consolidation),
            &rejected
        ));
        assert!(disposition_requires_backoff(request_requires_positive_ack(&rotation), &rejected));

        let now = Instant::now();
        let mut retry = RetryState::new(now);
        let delay =
            retry.failure(now, PartyId(2), Duration::from_millis(100), Duration::from_secs(1));
        assert_eq!(retry.failures, 1);
        assert!(!retry.ready(now));
        assert!(retry.ready(now + delay));
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

    #[tokio::test]
    async fn deposit_scheduler_isolates_request_origins_from_consensus_and_each_other() {
        fn selected_relays(
            durable: &BTreeMap<DepositPeerMessageId, (DepositCausalLane, u8)>,
        ) -> BTreeMap<DepositRelayLane, (u8, DepositPeerMessageId)> {
            let mut selected = BTreeMap::new();
            for (&id, &(causal_lane, causal_rank)) in durable {
                retain_earliest_deposit_relay(
                    &mut selected,
                    deposit_relay_lane(id, causal_lane),
                    causal_rank,
                    id,
                );
            }
            selected
        }

        let wallet = DepositWalletId([0x91; 32]);
        let recipient = PartyId(2);
        let request = DepositPeerMessageId::derive(
            wallet,
            2,
            recipient,
            DepositOperation::ClientRequest,
            b"first request from origin one",
        );
        let later_same_origin = DepositPeerMessageId::derive(
            wallet,
            3,
            recipient,
            DepositOperation::ClientRequest,
            b"later request from origin one",
        );
        let independent_origin = DepositPeerMessageId::derive(
            wallet,
            1,
            recipient,
            DepositOperation::ClientRequest,
            b"request from origin three",
        );
        let proposal = DepositPeerMessageId::derive(
            wallet,
            5,
            recipient,
            DepositOperation::ConsensusProposal,
            b"later ledger proposal",
        );
        let checkpoint = DepositPeerMessageId::derive(
            wallet,
            2,
            recipient,
            DepositOperation::IndexCheckpointCertificate,
            b"independent checkpoint certificate",
        );

        let ledger_lane = (recipient, DepositCausalLane::Ledger);
        let checkpoint_lane = (recipient, DepositCausalLane::Checkpoint);
        let request_lane = (recipient, DepositCausalLane::ClientRequest(PartyId(1)));
        let independent_request_lane = (recipient, DepositCausalLane::ClientRequest(PartyId(3)));
        let mut durable = BTreeMap::from([
            (request, (DepositCausalLane::ClientRequest(PartyId(1)), 0)),
            (later_same_origin, (DepositCausalLane::ClientRequest(PartyId(1)), 1)),
            (independent_origin, (DepositCausalLane::ClientRequest(PartyId(3)), 0)),
            (proposal, (DepositCausalLane::Ledger, 1)),
            (checkpoint, (DepositCausalLane::Checkpoint, 0)),
        ]);

        let selected = selected_relays(&durable);
        assert_eq!(selected.len(), 4);
        assert_eq!(
            selected.get(&request_lane).unwrap().1,
            request,
            "one request origin must retain its own durable causal order",
        );
        assert_eq!(selected.get(&independent_request_lane).unwrap().1, independent_origin);
        assert_eq!(selected.get(&ledger_lane).unwrap().1, proposal);
        assert_eq!(
            selected.get(&checkpoint_lane).unwrap().1,
            checkpoint,
            "the independent checkpoint lane must remain launchable",
        );
        assert!(
            selected.values().all(|(_, id)| *id != later_same_origin),
            "a later request from the same origin must wait for its durable predecessor",
        );

        // An authenticated remote success is not enough to advance the lane: the accepted item
        // remains both durable and in flight until the local outbox ACK transaction commits.
        let durable_request = DurableMessageId::Deposit(request);
        let transport_request = request.request_id([0x92; 32]);
        let mut accepted = BTreeMap::from([(durable_request, transport_request)]);
        let mut in_flight = BTreeSet::from([transport_request]);
        assert_eq!(selected_relays(&durable).get(&request_lane).unwrap().1, request);

        let ack_family = [durable_request];
        assert!(
            checkpoint_ack_family(
                &ack_family,
                &mut accepted,
                &mut in_flight,
                std::future::ready(Err(anyhow::anyhow!("injected local durable ACK failure"))),
            )
            .await
            .is_err()
        );
        assert!(accepted.contains_key(&durable_request));
        assert!(in_flight.contains(&transport_request));
        assert_eq!(
            selected_relays(&durable).get(&request_lane).unwrap().1,
            request,
            "a failed local ACK must keep the predecessor selected",
        );
        assert_eq!(
            selected_relays(&durable).get(&ledger_lane).unwrap().1,
            proposal,
            "a retryable request rejection must not fence ledger consensus",
        );
        assert_eq!(
            selected_relays(&durable).get(&independent_request_lane).unwrap().1,
            independent_origin,
            "one malicious origin must not fence another origin's request gossip",
        );

        checkpoint_ack_family(&ack_family, &mut accepted, &mut in_flight, async {
            assert_eq!(
                durable.remove(&request),
                Some((DepositCausalLane::ClientRequest(PartyId(1)), 0))
            );
            Ok(())
        })
        .await
        .unwrap();

        assert!(accepted.is_empty());
        assert!(in_flight.is_empty());
        let selected = selected_relays(&durable);
        assert_eq!(
            selected.get(&request_lane).unwrap().1,
            later_same_origin,
            "only committed local ACK removal may expose the next request from one origin",
        );
        assert_eq!(selected.get(&ledger_lane).unwrap().1, proposal);
        assert_eq!(
            selected.get(&checkpoint_lane).unwrap().1,
            checkpoint,
            "advancing the ledger lane must not consume checkpoint work",
        );
    }

    #[test]
    fn historical_state_import_scheduler_is_bounded_and_rotates_newest_first() {
        assert_eq!(rotating_historical_state_import_epoch(0, 0), None);
        assert_eq!(rotating_historical_state_import_epoch(1, 0), None);
        assert_eq!(rotating_historical_state_import_epoch(2, 0), Some(1));

        let selected = (0..10)
            .map(|cursor| rotating_historical_state_import_epoch(5, cursor).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(selected, vec![4, 3, 2, 1, 4, 3, 2, 1, 4, 3]);
        assert!(
            selected.iter().all(|epoch| *epoch != 0 && *epoch < 5),
            "the O(1) selector must never probe genesis or the current target"
        );
    }

    #[test]
    fn ready_in_doubt_historical_epochs_use_stable_successor_fairness() {
        let epochs = BTreeSet::from([2_u64, 5, 9]);
        let mut cursor = 0;
        let mut selected = Vec::new();
        for _ in 0..6 {
            let epoch = historical_reserved_epoch_after(&epochs, cursor).unwrap();
            selected.push(epoch);
            cursor = epoch;
        }
        assert_eq!(selected, vec![9, 5, 2, 9, 5, 2]);

        let backed_off = BTreeSet::from([2_u64, 9]);
        assert_eq!(
            historical_reserved_epoch_after(&backed_off, 9),
            Some(2),
            "a Byzantine newest epoch in backoff cannot monopolize the reserved cursor",
        );
        assert_eq!(
            historical_reserved_epoch_after(&backed_off, 2),
            Some(9),
            "removing a candidate never reinterprets the stable epoch successor",
        );
    }

    #[test]
    fn historical_epoch_probe_advances_on_every_no_receipt_exit() {
        fn propagated_error(cursor: &AtomicU64) -> Result<(), ()> {
            let _probe = HistoricalStateImportEpochProbe::new(cursor);
            Err(())?;
            Ok(())
        }

        let cursor = AtomicU64::new(7);
        assert_eq!(propagated_error(&cursor), Err(()));
        assert_eq!(cursor.load(Ordering::Relaxed), 8);

        {
            let _probe = HistoricalStateImportEpochProbe::new(&cursor);
        }
        assert_eq!(cursor.load(Ordering::Relaxed), 9);

        HistoricalStateImportEpochProbe::new(&cursor).receipt_committed();
        assert_eq!(
            cursor.load(Ordering::Relaxed),
            9,
            "an exact committed receipt keeps its epoch hot for the next recipient"
        );
    }
}
