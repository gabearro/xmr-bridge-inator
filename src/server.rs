//! Persistent one-party protocol state machines and their local HTTP control adapter.
//!
//! Party-to-party delivery is exclusively exposed through the typed QUIC adapter. HTTP retains
//! health, status, transition initiation, and transaction-signing coordination only.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::Context as _;
use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, State},
    http::{Request, StatusCode, header::WWW_AUTHENTICATE},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tower_http::trace::TraceLayer;
use zeroize::Zeroizing;

use crate::{
    auth::{AllowedRoles, AuthError, AuthenticatedPrincipal, BearerAuthenticator},
    avss::{
        AvssConfig, AvssDealer, AvssOutput, AvssParty, AvssPayload, PrivateAvssMessage,
        preflight_avss_resources,
    },
    committee::{Committee, Member, PartyId, SessionId},
    compact_epoch_registry::CompactEpochRegistry,
    config::{NetworkKind, Operation, Scenario},
    deposit_consensus::ConsensusError,
    deposit_consolidation::{AttemptBinding, ConsolidationId, TransactionAuthorization},
    deposit_consolidation_wire::{
        ByzantineConsolidationWireMessage, ConsolidationAttemptWireBinding, ConsolidationWireError,
        PortableSignedTransactionAttestation, SignedPreprocessContribution,
        SignedShareContribution,
    },
    deposit_ledger::{
        CertifiedLedgerEntry, LedgerError, LedgerPayload, LedgerRequestId, RequestBinding,
    },
    deposit_service::{
        ByzantineConsolidationAction, DepositAddressRequest, DepositAddressResponse,
        DepositAddressStatus, DepositAllocateWire, DepositAttestationWire, DepositCertificateWire,
        DepositClientRequestWire, DepositConsensusWire, DepositObservationAttestationWire,
        DepositObservationCertificateWire, DepositObservationWire, DepositPeerMessageId,
        DepositService, DepositServiceError, DurableDepositObservationEvidence,
        MAX_CONSOLIDATION_ABANDONMENT_MESSAGE_BYTES, PendingDepositPeerMessage,
        PersistedSweepRelease, PublicConsolidationStatus, deposit_request_id_for_binding,
    },
    deposit_sync_wire::{
        DepositIndexCheckpointAttestWire, DepositIndexCheckpointCertificateWire,
        DepositObservationIndexCheckpointAttestWire,
        DepositObservationIndexCheckpointCertificateWire, DepositSyncAdvertisement,
        DepositSyncHeadRequest, DepositSyncObject, DepositSyncObjectPageRequest,
    },
    deposit_wallet::{
        CanonicalDepositAddress, ChainPoint, SignedSweepTransaction, SweepId, WalletOutputId,
    },
    deposit_worker::{
        DepositChainSource, DepositConsolidationBackend, DepositWorkerConfig, DepositWorkerError,
    },
    epoch_history::{
        AvssSuccessorSupersession, EpochHistoryCatchupManifest, EpochHistoryCatchupQuery,
        EpochHistoryCatchupReply, EpochHistoryEntryInput, EpochHistoryIndexStep, EpochHistoryLink,
        EpochHistoryObjectReader, EpochHistoryObjectRef, EpochHistoryParent, EpochHistoryPolicy,
        EpochHistoryState, epoch_history_index_step,
    },
    identity::{EncryptedPayload, EpochEncryptionSecret, Identity, SignedEnvelope},
    key_rotation::{
        KeyRotationCertificate, KeyRotationContext, KeyRotationError, KeyRotationMessageId,
        KeyRotationRound, KeyRotationTargetPolicy, KeyRotationWire, PendingKeyRotationMessage,
        VerifiedRegistryHandoffTarget, eligibility_reference_key,
        pending_key_rotation_advertisements, pending_key_rotation_certificate,
    },
    keys::{
        EpochPublic, EpochShare, aggregate_dkg_subset, aggregate_proactive_reshare_from_public,
        aggregate_zero_share_refresh,
    },
    qual::{
        EquivocationEvidence, ProofOfLockCertificate, QualConfig, QualConsensus, QualDecision,
        QualEntry, QualMessage, QualMessageBody, QualStep, VotePhase,
    },
    quic_transport::{
        AvssOperation, DepositOperation, EpochOperation, KeyRotationOperation, PeerRequest,
        PeerResponse, QualOperation, RejectionCode,
    },
    reconnecting_monero::DepositChainReadiness,
    signing::{
        AwaitingAuthorization, AwaitingCommitments, AwaitingShares, CanonicalSignerSet,
        FrostlassSigner,
    },
    storage::{
        ActivationTransitionKey, MAX_SESSION_STATE_BYTES, PartyStateLease, ProtocolStore,
        ShareRetirement, ShareStore, StoreError, SweepSigningNonceClaim, WalletArtifactStore,
        WalletId, WalletSnapshotStore,
    },
};

const AVSS_WIRE_VERSION: u16 = 2;
const QUAL_WIRE_VERSION: u16 = 4;
const MAX_LIVE_AVSS_RUNS: usize = 64;
const MAX_LIVE_SIGNING_SESSIONS: usize = 64;
const MAX_BYZANTINE_CONSOLIDATION_ACTIONS_PER_TICK: usize = 4_096;
const MAX_PEER_OUTBOX_SNAPSHOT: usize = 256;
const MAX_QUAL_BACKOFF_TIMEOUT_MS: u64 = 60 * 60 * 1_000;
const PROACTIVE_REFRESH_SCHEDULE_VERSION: u16 = 4;
const EPOCH_HISTORY_HOT_ENTRIES: u16 = 64;
const MAX_CURRENT_EPOCH_RECORDS: usize = EPOCH_HISTORY_HOT_ENTRIES as usize + 2;
const ACCEPTANCE_CONSOLIDATION_GATE_VERSION: u16 = 1;
const ACCEPTANCE_CONSOLIDATION_GATE_ENV: &str = "TM_ACCEPTANCE_ENABLE_CONSOLIDATION_GATE";
const ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_VERSION: u16 = 1;
const ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_ENV: &str =
    "TM_ACCEPTANCE_ENABLE_CONSOLIDATION_BOOTSTRAP_GATE";
const ACCEPTANCE_PROTOCOL_FAULT_GATE_VERSION: u16 = 1;
const ACCEPTANCE_PROTOCOL_FAULT_GATE_ENV: &str = "TM_ACCEPTANCE_ENABLE_PROTOCOL_FAULT_GATE";
const ACCEPTANCE_PROACTIVE_REFRESH_HOLD_ENV: &str = "TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH";
const ACCEPTANCE_DRIVER_LATCH_VERSION: u16 = 1;
const ACCEPTANCE_DEPOSIT_CHECKPOINT_GATE_VERSION: u16 = 1;
/// Reserved persisted deadline used only by the demo-Regtest acceptance hold. A release replaces
/// it with `release_time + configured_interval`; ordinary deployments can never create it.
const ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS: u64 = u64::MAX;

#[derive(Clone, Debug)]
struct CertifiedKeyRotation {
    context: KeyRotationContext,
    certificate: KeyRotationCertificate,
    target: Committee,
}

#[derive(Clone, Debug)]
struct LiveKeyRotation {
    round: KeyRotationRound,
    revision: u64,
}

#[derive(Clone, Debug)]
struct JoiningKeyRotation {
    context: KeyRotationContext,
    pending_advertisements: BTreeMap<KeyRotationMessageId, PendingKeyRotationMessage>,
}

#[derive(Clone, Default)]
struct LoadedEpochHistoryObjects(BTreeMap<EpochHistoryObjectRef, Vec<u8>>);

impl EpochHistoryObjectReader for LoadedEpochHistoryObjects {
    fn load(
        &self,
        reference: EpochHistoryObjectRef,
    ) -> Result<Option<Vec<u8>>, crate::epoch_history::EpochHistoryError> {
        Ok(self.0.get(&reference).cloned())
    }
}

/// Opt-in deposit-wallet dependencies. The view scalar is retained only by the deposit service.
/// The chain source must fail closed until it has verified network/genesis; production uses the
/// lazy reconnecting adapter so core protocol startup does not depend on RPC availability.
pub struct PartyDepositConfig {
    pub private_view_scalar: Zeroizing<[u8; 32]>,
    pub birth_anchor: Option<ChainPoint>,
    pub worker: DepositWorkerConfig,
    pub chain_source: Arc<dyn DepositChainSource>,
    pub consolidation_backend: Arc<dyn DepositConsolidationBackend>,
    pub chain_readiness: DepositChainReadiness,
}

impl std::fmt::Debug for PartyDepositConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartyDepositConfig")
            .field("private_view_scalar", &"[REDACTED]")
            .field("birth_anchor", &self.birth_anchor)
            .field("worker", &self.worker)
            .field("chain_source", &"dyn DepositChainSource")
            .field("consolidation_backend", &"dyn DepositConsolidationBackend")
            .field("chain_ready", &self.chain_readiness.is_ready())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DealPurpose {
    Dkg,
    /// Fixed-interval, same-committee refresh using zero-constant AVSS contributions.
    Refresh,
    /// Old-share redistribution for a changed membership and/or threshold.
    Reshare,
}

/// Public transition context repeated on every AVSS request. Parties reconstruct and validate this
/// value from their local scenario instead of trusting a coordinator-provided committee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssTransition {
    pub purpose: DealPurpose,
    pub session: SessionId,
    pub key_id: [u8; 32],
    /// Explicitly transcript-bound Byzantine receiver bound.
    pub fault_bound: u16,
    /// Exact authenticated history tip extended by this DKG/reshare. Epoch zero uses the
    /// network/key-specific genesis anchor; resharing uses the certified predecessor link root.
    pub history_parent: EpochHistoryParent,
    pub old: Option<EpochPublic>,
    pub target: Committee,
    /// Canonical set of dealers eligible to start AVSS. For DKG this is empty and the target
    /// committee is implicitly eligible. Refresh names every current member and QUAL selects
    /// exactly `n-f`; resharing names the configured old-epoch candidates and QUAL selects the
    /// exact old threshold.
    pub eligible_dealers: Vec<PartyId>,
}

/// Scenario-bound epoch-zero key and session identifiers. A deployment has exactly one admissible
/// DKG namespace, preventing an eligible Byzantine dealer from filling durable state with fresh
/// but otherwise valid session IDs.
pub fn canonical_dkg_identity(scenario: &Scenario) -> anyhow::Result<([u8; 32], SessionId)> {
    let committee = scenario.genesis_committee()?;
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/canonical-dkg-key/v1");
    hasher.update(&scenario.quic_network_id()?);
    hasher.update(&committee.digest());
    let key_id = *hasher.finalize().as_bytes();
    let session = SessionId::derive(b"threshold-monero/canonical-dkg-session/v1", &key_id);
    Ok((key_id, session))
}

/// Construct the only epoch-zero DKG transition accepted by this deployment.
///
/// Keeping this constructor beside the server-side validator ensures autonomous bootstrap and the
/// acceptance driver cannot accidentally start different genesis namespaces.
pub fn canonical_dkg_transition(scenario: &Scenario) -> anyhow::Result<AvssTransition> {
    let target = scenario.genesis_committee()?;
    let fault_bound = scenario.committee_spec(0)?.fault_bound;
    let (key_id, session) = canonical_dkg_identity(scenario)?;
    Ok(AvssTransition {
        purpose: DealPurpose::Dkg,
        session,
        key_id,
        fault_bound,
        history_parent: EpochHistoryParent::genesis(scenario.quic_network_id()?, key_id)?,
        old: None,
        target,
        eligible_dealers: Vec::new(),
    })
}

fn epoch_history_wallet_id(network: [u8; 32], key_id: [u8; 32]) -> WalletId {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/epoch-history-storage-namespace/v1");
    hasher.update(&network);
    hasher.update(&key_id);
    WalletId(*hasher.finalize().as_bytes())
}

/// The only admissible resharing session for one authenticated predecessor and configured target.
pub fn canonical_reshare_session(
    old: &EpochPublic,
    target: &Committee,
    history_parent: EpochHistoryParent,
) -> anyhow::Result<SessionId> {
    let mut material = Vec::with_capacity(128);
    material.extend_from_slice(&old.activation_digest()?);
    material.extend_from_slice(&old.key_id);
    material.extend_from_slice(&target.digest());
    material.extend_from_slice(&history_parent.transition_binding()?);
    Ok(SessionId::derive(b"threshold-monero/canonical-reshare-session/v3", &material))
}

/// The only admissible zero-constant refresh session for one authenticated predecessor/target.
pub fn canonical_refresh_session(
    old: &EpochPublic,
    target: &Committee,
    history_parent: EpochHistoryParent,
) -> anyhow::Result<SessionId> {
    let mut material = Vec::with_capacity(128);
    material.extend_from_slice(&old.activation_digest()?);
    material.extend_from_slice(&old.key_id);
    material.extend_from_slice(&target.digest());
    material.extend_from_slice(&history_parent.transition_binding()?);
    Ok(SessionId::derive(b"threshold-monero/canonical-zero-refresh-session/v1", &material))
}

fn same_refresh_layout(old: &Committee, target: &Committee) -> bool {
    old.threshold == target.threshold
        && old.n() == target.n()
        && old.members.iter().all(|old_member| {
            target
                .member(old_member.id)
                .is_ok_and(|target_member| target_member.signing_key == old_member.signing_key)
        })
}

fn dynamic_avss_transition(
    old: &EpochPublic,
    target: Committee,
    fault_bound: u16,
    history_parent: EpochHistoryParent,
) -> anyhow::Result<AvssTransition> {
    old.validate()?;
    target.validate_async_security_with_faults(fault_bound)?;
    anyhow::ensure!(
        old.committee.epoch.checked_add(1) == Some(target.epoch),
        "dynamic AVSS target is not the immediate successor"
    );
    anyhow::ensure!(
        same_refresh_layout(&old.committee, &target),
        "automatic dynamic refresh must preserve membership, signing identities, and threshold"
    );
    anyhow::ensure!(
        target.threshold >= 2,
        "proactive zero-refresh requires threshold at least two"
    );
    let eligible_dealers = old.committee.members.iter().map(|member| member.id).collect();
    Ok(AvssTransition {
        purpose: DealPurpose::Refresh,
        session: canonical_refresh_session(old, &target, history_parent)?,
        key_id: old.key_id,
        fault_bound,
        history_parent,
        old: Some(old.clone()),
        target,
        eligible_dealers,
    })
}

/// One independently encrypted, authenticated AVSS message. `recipient` is only a routing hint;
/// the AEAD associated data and decrypted AVSS payload both bind the actual receiver.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssWire {
    pub version: u16,
    pub dealer: PartyId,
    pub recipient: PartyId,
    pub envelope: SignedEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssStartRequest {
    pub transition: AvssTransition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssDeliverRequest {
    pub transition: AvssTransition,
    pub wire: AvssWire,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssStepResponse {
    pub party: PartyId,
    pub dealer: PartyId,
    pub completed: bool,
    /// Transferable n-f qualification evidence. Present once this receiver has completed the
    /// named dealer instance; the envelope is signed under the target committee.
    pub completion: Option<SignedEnvelope>,
    pub outbound: Vec<AvssWire>,
    /// QUAL effects triggered by a late local AVSS completion after consensus has started.
    pub qual: Option<QualStepResponse>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QualWire {
    pub version: u16,
    pub envelope: SignedEnvelope,
    /// Exact signed PREVOTE witnesses named by a proposal or round-change proof of lock. Empty for
    /// votes, new-round certificates, and unlocked messages. The outer QUIC/TLS identity
    /// authenticates only the carrier; every embedded envelope is independently verified against
    /// the target committee.
    pub proof_of_lock_witnesses: Vec<SignedEnvelope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QualDeliverRequest {
    pub transition: AvssTransition,
    pub wire: QualWire,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QualStepResponse {
    pub party: PartyId,
    /// Active voting round after this step. A timeout request does not change this value.
    pub round: u64,
    pub decision: Option<QualDecision>,
    pub outbound: Vec<QualWire>,
    /// Byzantine equivocations authenticated by this exact reducer step.
    pub evidence: Vec<EquivocationEvidence>,
    /// Present only when an authenticated n-f new-round certificate changed the active round.
    pub entered_round: Option<u64>,
    /// Present only when this step emitted a monotonically higher local round-change request.
    pub requested_round: Option<u64>,
    pub duplicate: bool,
    pub changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssCompletion {
    pub version: u16,
    pub transition: [u8; 32],
    pub session: SessionId,
    pub receiver: PartyId,
    pub dealer: PartyId,
    pub commitment_digest: crate::avss::CommitmentDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActivationStatement {
    pub version: u16,
    pub session: SessionId,
    pub key_id: [u8; 32],
    pub epoch: u64,
    pub committee: [u8; 32],
    pub activation_digest: [u8; 32],
    pub avss_transcript_digest: [u8; 32],
    pub history_link: EpochHistoryLink,
}

/// One target member's durable, broadcast activation acknowledgement delivered peer-to-peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivationAckDeliverRequest {
    pub transition: AvssTransition,
    pub acknowledgement: SignedEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActivationValue {
    pub epoch: u64,
    pub public: EpochPublic,
    pub activation_digest: [u8; 32],
    pub avss_transcript_digest: [u8; 32],
    pub history_link: EpochHistoryLink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivateEpochRequest {
    pub transition: AvssTransition,
    pub value: ActivationValue,
    pub acknowledgements: Vec<SignedEnvelope>,
}

pub type RetireEpochRequest = ActivateEpochRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallResponse {
    pub party: PartyId,
    pub epoch: u64,
    pub public: EpochPublic,
    pub activation_digest: [u8; 32],
    /// Common digest of the transition and every accepted dealer commitment matrix.
    pub avss_transcript_digest: [u8; 32],
    /// Witness-independent, quorum-signed result root used by the next transition.
    pub history_link: EpochHistoryLink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochStatus {
    pub epoch: u64,
    pub public: EpochPublic,
    pub history_link: EpochHistoryLink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyStatus {
    pub party: PartyId,
    /// Core state was restored and the control plane is serving. Chain RPC is reported
    /// independently so deposit degradation cannot mark the threshold protocol dead.
    pub ready: bool,
    /// The durable deposit registry has an initialized, locally usable epoch. This is independent
    /// of whether a Monero RPC client is currently reachable.
    pub deposit_ready: Option<bool>,
    pub deposit_chain_ready: Option<bool>,
    pub active_epoch: Option<u64>,
    pub staged_epochs: Vec<u64>,
    pub epochs: Vec<EpochStatus>,
    pub proactive_refresh: Option<ProactiveRefreshStatus>,
    /// Runtime-only count of mutually authenticated remote requests accepted by this process.
    pub authenticated_quic_ingress: u64,
    /// Runtime-only count of responses received over mutually authenticated outbound connections.
    pub authenticated_quic_responses: u64,
}

/// Public, non-secret status for the persisted proactive-refresh pacemaker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProactiveRefreshStatus {
    pub source_epoch: u64,
    pub target_epoch: Option<u64>,
    pub due_unix_ms: Option<u64>,
}

/// HTTP representation keeps the caller's tenant-local idempotency key distinct from the
/// globally certified ledger key. A client can therefore validate the embedded certificate
/// without allowing another authenticated principal to occupy its namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositHttpResponse {
    pub request: LedgerRequestId,
    pub certified_request: LedgerRequestId,
    pub status: DepositHttpStatus,
    pub address: Option<CanonicalDepositAddress>,
    pub certificate: Option<CertifiedLedgerEntry>,
    /// Bounded, activation-certificate-root-bound authority for `certificate`.
    pub issuer_registry: Option<CompactEpochRegistry>,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub leader: PartyId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositHttpStatus {
    Syncing,
    Pending,
    Active,
    Expired,
    Permanent,
}

/// Tenant-isolated public consolidation history for one allocation request. Exact transaction
/// bytes remain off this API; clients can fetch them by the committed transaction id from Monero.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositConsolidationStatusResponse {
    pub request: LedgerRequestId,
    pub certified_request: LedgerRequestId,
    pub consolidations: Vec<PublicConsolidationStatus>,
}

/// Read-only diagnostics for one durable AVSS/QUAL session. This intentionally exposes counts and
/// phase markers rather than secret shares, commitments, or signed protocol payloads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolSessionStatus {
    pub session: SessionId,
    pub completed_outputs: usize,
    pub qual_started: bool,
    pub qual_round: Option<u64>,
    pub qual_decided: bool,
    pub finalized: bool,
    pub pending_avss: usize,
    pub pending_qual: usize,
    pub pending_activation_ack: usize,
}

/// Non-secret host status for one consolidation signing session. A closed session has an
/// authenticated permanent ProtocolStore tombstone and can never create another nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationSessionStatus {
    AwaitingCommitments,
    AwaitingAuthorization,
    AwaitingShares,
    Closed,
}

/// Explicit, authenticated acceptance-only control for the pre-nonce consolidation fault gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceConsolidationGateAction {
    Arm,
    Status,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceConsolidationGateState {
    Disarmed,
    Armed,
    Held,
    Released,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AcceptanceConsolidationGateRequest {
    pub action: AcceptanceConsolidationGateAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceConsolidationGateResponse {
    pub party: PartyId,
    pub state: AcceptanceConsolidationGateState,
    pub authorization: Option<ConsolidationId>,
    pub roast_view: Option<u64>,
}

/// Acceptance-only control for the boundary after local preparation and before initial intent BA.
#[derive(Clone, Debug, Deserialize)]
pub struct AcceptanceConsolidationBootstrapGateRequest {
    pub action: AcceptanceConsolidationGateAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceConsolidationBootstrapGateResponse {
    pub party: PartyId,
    pub state: AcceptanceConsolidationGateState,
    pub sweep: Option<SweepId>,
    pub bootstrap_ba_view: Option<u64>,
    pub proposer: Option<PartyId>,
    pub prepared_intent_digest: Option<[u8; 32]>,
}

/// Authenticated acceptance-only release for one exact active refresh schedule. The source epoch
/// prevents a delayed/retried client request from releasing a later schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceProactiveRefreshReleaseRequest {
    pub source_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceProactiveRefreshReleaseResponse {
    pub party: PartyId,
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub due_unix_ms: u64,
}

/// Private-Regtest-only driver barriers. Each binding is supplied by the acceptance client from
/// the exact protocol event it has reached; authenticated status/release requests must repeat it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceDriverLatchKind {
    ObserverFork,
    DynamicRotationOmission,
    ProactiveDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceDriverLatchRequest {
    pub action: AcceptanceConsolidationGateAction,
    pub kind: AcceptanceDriverLatchKind,
    pub binding: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceDriverLatchResponse {
    pub party: PartyId,
    pub state: AcceptanceConsolidationGateState,
    pub kind: Option<AcceptanceDriverLatchKind>,
    pub binding: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceDepositCheckpointGateRequest {
    pub action: AcceptanceConsolidationGateAction,
    pub output: WalletOutputId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceDepositCheckpointGateResponse {
    pub party: PartyId,
    pub state: AcceptanceConsolidationGateState,
    pub output: Option<WalletOutputId>,
    pub evidence: Option<DurableDepositObservationEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AcceptanceDriverLatch {
    version: u16,
    state: AcceptanceConsolidationGateState,
    kind: Option<AcceptanceDriverLatchKind>,
    binding: Option<[u8; 32]>,
}

impl Default for AcceptanceDriverLatch {
    fn default() -> Self {
        Self {
            version: ACCEPTANCE_DRIVER_LATCH_VERSION,
            state: AcceptanceConsolidationGateState::Disarmed,
            kind: None,
            binding: None,
        }
    }
}

impl AcceptanceDriverLatch {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCEPTANCE_DRIVER_LATCH_VERSION,
            "unsupported acceptance driver latch version"
        );
        match self.state {
            AcceptanceConsolidationGateState::Disarmed => anyhow::ensure!(
                self.kind.is_none() && self.binding.is_none(),
                "disarmed acceptance driver latch retained a binding"
            ),
            AcceptanceConsolidationGateState::Held | AcceptanceConsolidationGateState::Released => {
                anyhow::ensure!(
                    self.kind.is_some() && self.binding.is_some_and(|binding| binding != [0; 32]),
                    "active acceptance driver latch lacks its exact binding"
                )
            }
            AcceptanceConsolidationGateState::Armed => {
                anyhow::bail!("acceptance driver latch cannot retain an unheld armed state")
            }
        }
        Ok(())
    }

    fn response(&self, party: PartyId) -> AcceptanceDriverLatchResponse {
        AcceptanceDriverLatchResponse {
            party,
            state: self.state,
            kind: self.kind,
            binding: self.binding,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AcceptanceDepositCheckpointGate {
    version: u16,
    state: AcceptanceConsolidationGateState,
    output: Option<WalletOutputId>,
    evidence: Option<DurableDepositObservationEvidence>,
}

impl Default for AcceptanceDepositCheckpointGate {
    fn default() -> Self {
        Self {
            version: ACCEPTANCE_DEPOSIT_CHECKPOINT_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Disarmed,
            output: None,
            evidence: None,
        }
    }
}

impl AcceptanceDepositCheckpointGate {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCEPTANCE_DEPOSIT_CHECKPOINT_GATE_VERSION,
            "unsupported acceptance deposit checkpoint gate version"
        );
        match self.state {
            AcceptanceConsolidationGateState::Disarmed => anyhow::ensure!(
                self.output.is_none() && self.evidence.is_none(),
                "disarmed acceptance deposit checkpoint gate retained evidence"
            ),
            AcceptanceConsolidationGateState::Held | AcceptanceConsolidationGateState::Released => {
                let output =
                    self.output.context("acceptance deposit checkpoint gate lacks its output")?;
                let evidence = self
                    .evidence
                    .as_ref()
                    .context("acceptance deposit checkpoint gate lacks its durable evidence")?;
                anyhow::ensure!(
                    output.transaction != [0; 32]
                        && evidence.output.output() == output
                        && evidence.portable_index_digest != [0; 32]
                        && evidence.checkpoint_statement_digest != [0; 32]
                        && evidence.checkpoint_sequence != 0,
                    "acceptance deposit checkpoint gate has invalid durable evidence"
                );
            }
            AcceptanceConsolidationGateState::Armed => {
                anyhow::bail!("acceptance deposit checkpoint gate cannot retain an armed state")
            }
        }
        Ok(())
    }

    fn response(&self, party: PartyId) -> AcceptanceDepositCheckpointGateResponse {
        AcceptanceDepositCheckpointGateResponse {
            party,
            state: self.state,
            output: self.output,
            evidence: self.evidence.clone(),
        }
    }
}

/// Exact durable protocol boundary used only by the private-Regtest crash campaigns.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceProtocolFaultBoundary {
    DealerStarted,
    QualRoundZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceProtocolFaultGateRequest {
    pub action: AcceptanceConsolidationGateAction,
    pub session: SessionId,
    pub epoch: u64,
    pub boundary: AcceptanceProtocolFaultBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceProtocolFaultGateResponse {
    pub party: PartyId,
    pub state: AcceptanceConsolidationGateState,
    pub session: Option<SessionId>,
    pub epoch: Option<u64>,
    pub boundary: Option<AcceptanceProtocolFaultBoundary>,
    pub dealer: Option<PartyId>,
    pub qual_round: Option<u64>,
}

/// Encrypted one-shot acceptance record. `Armed` binds the requested canonical transition before
/// it exists. `Held` is written only while the corresponding AVSS run lock is held and after the
/// exact run snapshot has survived authenticated readback. `Released` retains the evidence so a
/// delayed request cannot release a different transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AcceptanceProtocolFaultGate {
    version: u16,
    state: AcceptanceConsolidationGateState,
    session: Option<SessionId>,
    epoch: Option<u64>,
    boundary: Option<AcceptanceProtocolFaultBoundary>,
    dealer: Option<PartyId>,
    qual_round: Option<u64>,
}

impl Default for AcceptanceProtocolFaultGate {
    fn default() -> Self {
        Self {
            version: ACCEPTANCE_PROTOCOL_FAULT_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Disarmed,
            session: None,
            epoch: None,
            boundary: None,
            dealer: None,
            qual_round: None,
        }
    }
}

impl AcceptanceProtocolFaultGate {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCEPTANCE_PROTOCOL_FAULT_GATE_VERSION,
            "unsupported acceptance protocol fault gate version"
        );
        let binding = match (self.session, self.epoch, self.boundary) {
            (Some(session), Some(epoch), Some(boundary)) => Some((session, epoch, boundary)),
            (None, None, None) => None,
            _ => anyhow::bail!("acceptance protocol fault gate has a partial binding"),
        };
        match self.state {
            AcceptanceConsolidationGateState::Disarmed => {
                anyhow::ensure!(
                    binding.is_none() && self.dealer.is_none() && self.qual_round.is_none(),
                    "disarmed acceptance protocol fault gate retained state"
                );
            }
            AcceptanceConsolidationGateState::Armed => {
                anyhow::ensure!(
                    binding.is_some() && self.dealer.is_none() && self.qual_round.is_none(),
                    "armed acceptance protocol fault gate has invalid evidence"
                );
            }
            AcceptanceConsolidationGateState::Held | AcceptanceConsolidationGateState::Released => {
                let (_, _, boundary) =
                    binding.context("held/released acceptance protocol gate lacks its binding")?;
                match boundary {
                    AcceptanceProtocolFaultBoundary::DealerStarted => {
                        anyhow::ensure!(
                            self.dealer.is_some_and(|dealer| dealer.0 != 0)
                                && self.qual_round.is_none(),
                            "dealer-start gate lacks its exact durable dealer evidence"
                        );
                    }
                    AcceptanceProtocolFaultBoundary::QualRoundZero => {
                        anyhow::ensure!(
                            self.dealer.is_none() && self.qual_round == Some(0),
                            "QUAL gate lacks its exact durable round-zero evidence"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn binding(&self) -> Option<(SessionId, u64, AcceptanceProtocolFaultBoundary)> {
        Some((self.session?, self.epoch?, self.boundary?))
    }

    fn blocks_session(&self, session: SessionId) -> bool {
        self.session == Some(session)
            && (self.state == AcceptanceConsolidationGateState::Held
                || (self.state == AcceptanceConsolidationGateState::Armed
                    && self.boundary == Some(AcceptanceProtocolFaultBoundary::DealerStarted)))
    }

    fn response(&self, party: PartyId) -> AcceptanceProtocolFaultGateResponse {
        AcceptanceProtocolFaultGateResponse {
            party,
            state: self.state,
            session: self.session,
            epoch: self.epoch,
            boundary: self.boundary,
            dealer: self.dealer,
            qual_round: self.qual_round,
        }
    }
}

/// Encrypted acceptance-gate snapshot. This is deliberately outside protocol safety state: the
/// only legal `Held` transition occurs after a certified view-zero reservation is already durable
/// and before the server consumes its one-shot nonce capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AcceptanceConsolidationGate {
    version: u16,
    state: AcceptanceConsolidationGateState,
    authorization: Option<ConsolidationId>,
    roast_view: Option<u64>,
}

impl Default for AcceptanceConsolidationGate {
    fn default() -> Self {
        Self {
            version: ACCEPTANCE_CONSOLIDATION_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Disarmed,
            authorization: None,
            roast_view: None,
        }
    }
}

impl AcceptanceConsolidationGate {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCEPTANCE_CONSOLIDATION_GATE_VERSION,
            "unsupported acceptance consolidation gate version"
        );
        let has_binding = self.authorization.is_some() && self.roast_view.is_some();
        match self.state {
            AcceptanceConsolidationGateState::Held => {
                anyhow::ensure!(has_binding, "held consolidation gate lacks its exact view");
                anyhow::ensure!(
                    self.roast_view == Some(0),
                    "acceptance consolidation gate may hold only ROAST view zero"
                );
            }
            AcceptanceConsolidationGateState::Disarmed
            | AcceptanceConsolidationGateState::Armed
            | AcceptanceConsolidationGateState::Released => {
                anyhow::ensure!(
                    !has_binding && self.authorization.is_none() && self.roast_view.is_none(),
                    "inactive consolidation gate retained a view binding"
                );
            }
        }
        Ok(())
    }

    fn response(&self, party: PartyId) -> AcceptanceConsolidationGateResponse {
        AcceptanceConsolidationGateResponse {
            party,
            state: self.state,
            authorization: self.authorization,
            roast_view: self.roast_view,
        }
    }
}

/// Encrypted acceptance-only snapshot for the pre-bootstrap-BA fault boundary. Unlike the ROAST
/// gate this never retains a nonce/release capability: the service must split preparation from BA
/// emission, persist the former, and call the hold hook before creating any proposal or vote.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AcceptanceConsolidationBootstrapGate {
    version: u16,
    state: AcceptanceConsolidationGateState,
    sweep: Option<SweepId>,
    bootstrap_ba_view: Option<u64>,
    proposer: Option<PartyId>,
    prepared_intent_digest: Option<[u8; 32]>,
}

impl Default for AcceptanceConsolidationBootstrapGate {
    fn default() -> Self {
        Self {
            version: ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Disarmed,
            sweep: None,
            bootstrap_ba_view: None,
            proposer: None,
            prepared_intent_digest: None,
        }
    }
}

impl AcceptanceConsolidationBootstrapGate {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_VERSION,
            "unsupported acceptance consolidation bootstrap gate version"
        );
        match self.state {
            AcceptanceConsolidationGateState::Held => {
                anyhow::ensure!(
                    self.sweep.is_some_and(|sweep| sweep.0 != [0; 32])
                        && self.bootstrap_ba_view == Some(0)
                        && self.proposer.is_some_and(|proposer| proposer.0 != 0)
                        && self.prepared_intent_digest.is_some_and(|digest| digest != [0; 32]),
                    "held consolidation bootstrap gate lacks its exact slot-zero binding"
                );
            }
            AcceptanceConsolidationGateState::Disarmed
            | AcceptanceConsolidationGateState::Armed
            | AcceptanceConsolidationGateState::Released => {
                anyhow::ensure!(
                    self.sweep.is_none()
                        && self.bootstrap_ba_view.is_none()
                        && self.proposer.is_none()
                        && self.prepared_intent_digest.is_none(),
                    "inactive consolidation bootstrap gate retained a BA binding"
                );
            }
        }
        Ok(())
    }

    fn response(&self, party: PartyId) -> AcceptanceConsolidationBootstrapGateResponse {
        AcceptanceConsolidationBootstrapGateResponse {
            party,
            state: self.state,
            sweep: self.sweep,
            bootstrap_ba_view: self.bootstrap_ba_view,
            proposer: self.proposer,
            prepared_intent_digest: self.prepared_intent_digest,
        }
    }
}

#[derive(Debug)]
struct ConsolidationSigningRuntime {
    authorization: TransactionAuthorization,
    attempt: AttemptBinding,
    /// Exact outer attempt binding. In Byzantine consolidation the historical `leader` field is
    /// only the deterministic relay seed for this ROAST view; it grants no signing or completion
    /// authority. Every portable contribution is independently authenticated by its origin.
    binding: ConsolidationAttemptWireBinding,
    sweep: SweepId,
    started_at: tokio::time::Instant,
    /// Exact authenticated ProtocolStore tombstone purpose which permanently burned this
    /// session before its FROSTLASS preprocess was created.
    nonce_tombstone_purpose: Vec<u8>,
    phase: ConsolidationSignPhase,
}

#[derive(Debug)]
struct HeldByzantineConsolidationRelease {
    family: [u8; 32],
    view: u64,
    binding: ConsolidationAttemptWireBinding,
    release: PersistedSweepRelease,
}

#[derive(Debug)]
enum ConsolidationSignPhase {
    Commitments {
        state: AwaitingCommitments,
        preprocess: SignedPreprocessContribution,
    },
    /// The exact unsigned transaction and aggregate key images are fixed, but no CLSAG share has
    /// been calculated. This state remains linear and volatile until the service durably accepts
    /// the all-selected-party key-image binding certificate and pins it to the sweep family.
    Authorization {
        state: AwaitingAuthorization,
    },
    Shares {
        state: AwaitingShares,
        share: SignedShareContribution,
    },
}

fn validate_live_consolidation_binding(
    runtime: &ConsolidationSigningRuntime,
    binding: &ConsolidationAttemptWireBinding,
) -> anyhow::Result<()> {
    anyhow::ensure!(runtime.authorization.id() == binding.consolidation_id());
    anyhow::ensure!(runtime.authorization.digest() == binding.authorization_digest());
    anyhow::ensure!(runtime.attempt == *binding.attempt());
    anyhow::ensure!(runtime.binding == *binding);
    anyhow::ensure!(runtime.sweep == runtime.authorization.sweep_id());
    Ok(())
}

/// Keep volatile FROSTLASS state to a rolling window while retaining every durable tombstone,
/// portable contribution and transaction candidate in `DepositService`.
///
/// With ten parties and `f = 3`, a fixed honest party belongs to 84 of the 120 deterministic
/// `n-f` subsets. Retaining every timed-out nonce machine would therefore hit the process-wide
/// live-session cap before the schedule reaches an all-honest subset. A successor view is allowed
/// to evict its family's older machines only after the service has durably certified that view;
/// late candidates for evicted views remain valid because they carry their own signed bytes.
fn retain_current_consolidation_view(
    live: &mut HashMap<SessionId, ConsolidationSigningRuntime>,
    authorization: crate::deposit_consolidation::ConsolidationId,
    current_attempt: u64,
) -> Vec<(SessionId, Vec<u8>)> {
    let mut retired = Vec::new();
    live.retain(|session, runtime| {
        let should_retire = runtime.authorization.id() == authorization
            && runtime.attempt.attempt() < current_attempt;
        if should_retire {
            retired.push((*session, runtime.nonce_tombstone_purpose.clone()));
        }
        !should_retire
    });
    retired.sort_unstable_by_key(|(session, _)| *session);
    retired
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AvssRun {
    transition: AvssTransition,
    /// Set only after the exact activation certificate is durable and every plaintext AVSS
    /// polynomial/share intermediate has been removed from both RAM and the encrypted snapshot.
    /// Certified catch-up retains ciphertext and public evidence, never a recoverable scalar.
    secret_compacted: bool,
    receivers: BTreeMap<PartyId, AvssParty>,
    outputs: BTreeMap<PartyId, AvssOutput>,
    /// A dealer start is idempotent. Reusing its exact encrypted outbox also prevents a retry from
    /// accidentally creating a second polynomial for the same logical dealer slot.
    dealer_outbound: Option<Vec<AvssWire>>,
    /// Exact delivery retries return the original effects, so losing an HTTP response cannot
    /// strand the coordinator's relay queue.
    delivery_responses: BTreeMap<(PartyId, u64), CachedAvssResponse>,
    /// Target-committee agreement over the availability-certified dealer set.
    qual: Option<QualConsensus>,
    qual_start_response: Option<QualStepResponse>,
    /// Latest authenticated delivery response per sender and semantic message kind. This is
    /// bounded by five slots per committee member independently of attacker-chosen round numbers.
    qual_delivery_responses: BTreeMap<(PartyId, QualWireKind), CachedQualResponse>,
    /// One bounded retry record for the latest explicit/autonomous pacemaker request.
    qual_advance_response: Option<CachedQualAdvanceResponse>,
    /// Latest exact signed wire per sender and semantic kind. The reducer buffers metadata only;
    /// retaining these bounded envelopes lets a future round promote authenticated PREVOTEs and
    /// proof-of-lock witness bundles after restart.
    qual_signed_wires: BTreeMap<(PartyId, QualWireKind), ArchivedQualWire>,
    /// Bounded authenticated PREVOTEs for the reducer's current round. This is at most one
    /// envelope per target voter and is replaced (not accumulated) when the round advances.
    qual_current_prevotes: QualPrevoteArchive,
    /// Exact canonical n-f witness bundle for the reducer's highest valid value. It survives
    /// round changes and restarts so any later honest leader can carry a portable proof of lock.
    qual_valid_witnesses: Option<QualProofWitnessBundle>,
    /// Wall-clock start of the current pacemaker request window. A timeout advances
    /// `requested_round`; only an authenticated n-f NewRound changes the reducer's active round.
    /// Safety never depends on this timestamp.
    qual_round_started_unix_ms: u64,
    /// Monotonic persisted backoff. It never resets within a transition, so after GST an honest
    /// round eventually receives a window longer than the unknown network delay.
    qual_timeout_exponent: u8,
    /// Locally generated messages remain here until their destination returns 2xx and that ACK is
    /// checkpointed. Because these maps live in the same encrypted snapshot as the reducers, a
    /// process crash cannot create a state transition whose network effects are forgotten.
    pending_avss: BTreeMap<(PartyId, [u8; 32]), AvssWire>,
    pending_qual: BTreeMap<(PartyId, [u8; 32]), QualWire>,
    pending_activation_ack: BTreeMap<(PartyId, [u8; 32]), SignedEnvelope>,
    activation_acknowledgements: BTreeMap<PartyId, SignedEnvelope>,
    finalized: Option<InstallResponse>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct QualPrevoteArchive {
    round: u64,
    envelopes: BTreeMap<PartyId, SignedEnvelope>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct QualProofWitnessBundle {
    proof: ProofOfLockCertificate,
    envelopes: Vec<SignedEnvelope>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
enum QualWireKind {
    Proposal,
    Prevote,
    Precommit,
    RoundChange,
    NewRound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ArchivedQualWire {
    round: u64,
    wire: QualWire,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedAvssResponse {
    wire_digest: [u8; 32],
    response: AvssStepResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedQualResponse {
    round: u64,
    wire_digest: [u8; 32],
    response: QualStepResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedQualAdvanceResponse {
    prior_requested_round: u64,
    target_round: u64,
    response: QualStepResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DurableSessionState {
    Avss(AvssRun),
}

/// Borrowed encoder matching `DurableSessionState`'s canonical enum layout without cloning the
/// secret-bearing AVSS reducer before sealing it.
#[derive(Serialize)]
enum DurableSessionStateRef<'a> {
    Avss(&'a AvssRun),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ActivationCertificateRecord {
    transition: AvssTransition,
    value: ActivationValue,
    acknowledgements: Vec<SignedEnvelope>,
}

/// Authenticated local pacemaker state. Safety is certificate-driven; this wall-clock record only
/// decides when an honest dealer is willing to release its next independently randomized AVSS
/// polynomial. It is bound to the exact source activation so a stale schedule cannot trigger from
/// a restored or competing epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProactiveRefreshSchedule {
    version: u16,
    source_epoch: u64,
    source_activation: [u8; 32],
    target_epoch: Option<u64>,
    due_unix_ms: Option<u64>,
    /// Persisted key-rotation pacemaker anchor. It is absent until the fixed due-time gate creates
    /// the current successor's certified receiver-key rotation reducer.
    rotation_view: Option<u64>,
    rotation_view_started_unix_ms: Option<u64>,
    rotation_timeout_exponent: u8,
    /// Highest contiguous immutable key-rotation certificate accepted by each peer. A successful
    /// ACK for epoch k implies that peer could verify the predecessor chain through k.
    rotation_certificate_delivered_through: BTreeMap<PartyId, u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyRotationPacemakerUpdate {
    PreserveExponent,
    AdvanceTimeout,
}

#[derive(Debug)]
struct StagedEpoch {
    transition: AvssTransition,
    share: EpochShare,
    response: InstallResponse,
}

/// Stable handle returned with a durable peer message. A transport may acknowledge it only after
/// the authenticated remote party has durably accepted the corresponding protocol message.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PeerMessageId {
    Avss { session: SessionId, recipient: PartyId, digest: [u8; 32] },
    Qual { session: SessionId, recipient: PartyId, digest: [u8; 32] },
    ActivationAck { session: SessionId, recipient: PartyId, digest: [u8; 32] },
}

/// Stable identifier for replayable hot-suffix epoch-certificate gossip. Older certificates are
/// served through authenticated epoch-history pull after their duplicate current-volume records
/// are compacted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochPeerMessageId {
    pub epoch: u64,
    pub activation_digest: [u8; 32],
    pub recipient: PartyId,
    pub operation: EpochOperation,
}

#[derive(Clone, Debug)]
pub struct PendingEpochPeerMessage {
    pub id: EpochPeerMessageId,
    pub request: PeerRequest,
}

impl PendingEpochPeerMessage {
    #[must_use]
    pub fn recipient(&self) -> PartyId {
        self.id.recipient
    }

    #[must_use]
    pub fn request_id(&self, network_id: [u8; 32]) -> crate::quic_transport::RequestId {
        let mut material = Vec::with_capacity(43);
        material.extend_from_slice(&self.id.epoch.to_le_bytes());
        material.extend_from_slice(&self.id.activation_digest);
        material.extend_from_slice(&self.id.recipient.0.to_le_bytes());
        material.push(match self.id.operation {
            EpochOperation::Acknowledge => 0,
            EpochOperation::Activate => 1,
            EpochOperation::Retire => 2,
            EpochOperation::Observe => 3,
            EpochOperation::History => 4,
        });
        crate::quic_transport::RequestId::derive(
            network_id,
            b"epoch-certificate-gossip/v1",
            &material,
        )
    }
}

fn epoch_certificate_routes(
    local_party: PartyId,
    scenario_parties: &[PartyId],
    target: &Committee,
    old: Option<&Committee>,
) -> Vec<(PartyId, EpochOperation)> {
    let local_is_transition_peer = target.member(local_party).is_ok()
        || old.is_some_and(|committee| committee.member(local_party).is_ok());
    let mut routes = Vec::new();
    if local_is_transition_peer {
        routes.extend(
            target
                .members
                .iter()
                .filter(|member| member.id != local_party)
                .map(|member| (member.id, EpochOperation::Activate)),
        );
        if let Some(old) = old {
            routes.extend(
                old.members
                    .iter()
                    .filter(|member| member.id != local_party)
                    .map(|member| (member.id, EpochOperation::Retire)),
            );
        }
    }

    let target_parties = target.members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
    let old_parties = old
        .map(|committee| committee.members.iter().map(|member| member.id).collect::<BTreeSet<_>>())
        .unwrap_or_default();
    routes.extend(
        scenario_parties
            .iter()
            .copied()
            .filter(|party| {
                *party != local_party
                    && !target_parties.contains(party)
                    && !old_parties.contains(party)
            })
            .map(|party| (party, EpochOperation::Observe)),
    );
    routes
}

impl PeerMessageId {
    #[must_use]
    pub fn session(self) -> SessionId {
        match self {
            Self::Avss { session, .. }
            | Self::Qual { session, .. }
            | Self::ActivationAck { session, .. } => session,
        }
    }

    #[must_use]
    pub fn recipient(self) -> PartyId {
        match self {
            Self::Avss { recipient, .. }
            | Self::Qual { recipient, .. }
            | Self::ActivationAck { recipient, .. } => recipient,
        }
    }
}

/// Protocol-agnostic durable peer-outbox item. The network adapter decides how to carry the typed
/// request (QUIC, an in-memory test link, and so on); reducer code never owns transport retries.
#[derive(Clone, Debug)]
pub enum PendingPeerMessage {
    Avss { id: PeerMessageId, request: AvssDeliverRequest },
    Qual { id: PeerMessageId, request: QualDeliverRequest },
    ActivationAck { id: PeerMessageId, request: ActivationAckDeliverRequest },
}

impl PendingPeerMessage {
    #[must_use]
    pub fn id(&self) -> PeerMessageId {
        match self {
            Self::Avss { id, .. } | Self::Qual { id, .. } | Self::ActivationAck { id, .. } => *id,
        }
    }

    /// Successor epoch whose reducer owns this durable message.
    #[must_use]
    pub fn transition_epoch(&self) -> u64 {
        match self {
            Self::Avss { request, .. } => request.transition.target.epoch,
            Self::Qual { request, .. } => request.transition.target.epoch,
            Self::ActivationAck { request, .. } => request.transition.target.epoch,
        }
    }

    /// Signed logical sequence within the transition reducer. QUAL uses this to keep an old
    /// round's proposal/votes ahead of a future-round payload; AVSS uses its dealer/kind sequence.
    #[must_use]
    pub fn causal_sequence(&self) -> u64 {
        match self {
            Self::Avss { request, .. } => request.wire.envelope.sequence,
            Self::Qual { request, .. } => request.wire.envelope.sequence,
            Self::ActivationAck { request, .. } => request.acknowledgement.sequence,
        }
    }

    /// Encode the typed durable effect into the canonical opaque body expected by the QUIC peer
    /// transport. The stable [`PeerMessageId`] remains the transport retry/ACK handle.
    pub fn to_quic_request(&self) -> Result<PeerRequest, postcard::Error> {
        Ok(match self {
            Self::Avss { request, .. } => PeerRequest::Avss {
                operation: AvssOperation::Deliver,
                body: postcard::to_allocvec(request)?,
            },
            Self::Qual { request, .. } => PeerRequest::Qual {
                operation: QualOperation::Deliver,
                body: postcard::to_allocvec(request)?,
            },
            Self::ActivationAck { request, .. } => PeerRequest::Epoch {
                operation: EpochOperation::Acknowledge,
                body: postcard::to_allocvec(request)?,
            },
        })
    }
}

pub struct PartyServer {
    party: PartyId,
    scenario: Scenario,
    /// Process-lifetime exclusive ownership of every mutable store for this party. This must be
    /// retained by the server rather than merely fencing construction: independent servers
    /// writing the same authenticated CAS namespaces would otherwise both believe they own the
    /// next revision.
    _state_lease: PartyStateLease,
    /// Stable Ed25519 identity plus the exact epoch X25519 key. Dynamic entries are inserted only
    /// after their secret has reached authenticated storage (and, once decided, after promotion
    /// against the locally durable key-rotation certificate).
    identities: StdRwLock<BTreeMap<u64, Arc<Identity>>>,
    /// Epoch identities removed from the active lookup before durable erasure. Existing Arc
    /// leases may finish, but no caller can acquire a new clone while retirement retries.
    retiring_identities: StdRwLock<BTreeMap<u64, Option<Arc<Identity>>>>,
    /// Stable Ed25519 material. This seed never derives an AVSS receiver key.
    signing_seed: Zeroizing<[u8; 32]>,
    /// Construction sets this only after every authenticated local record has been restored and
    /// cross-checked. QUIC attachment is tracked separately so status cannot claim readiness
    /// merely because the HTTP listener is serving.
    restored_ready: AtomicBool,
    quic_runtime_attached: AtomicBool,
    authenticated_quic_ingress: AtomicU64,
    authenticated_quic_responses: AtomicU64,
    store: ShareStore,
    protocol_store: ProtocolStore,
    epoch_history_snapshots: WalletSnapshotStore,
    epoch_history_artifacts: WalletArtifactStore,
    epoch_history_wallet: WalletId,
    epoch_history: RwLock<EpochHistoryState>,
    /// Locally durable, fully verified dynamic committee chain keyed by target epoch.
    certified_key_rotations: StdRwLock<BTreeMap<u64, CertifiedKeyRotation>>,
    /// At most one source-to-successor key-rotation reducer may be live. Its revision is the exact
    /// monotonic ProtocolStore CAS position and includes the retry outbox.
    key_rotation: Mutex<Option<LiveKeyRotation>>,
    /// A target-only joining member has no source-consensus reducer. Its independently signed
    /// advertisement fanout is regenerated from the durable candidate after restart and retained
    /// until a source certificate arrives.
    joining_key_rotation: Mutex<Option<JoiningKeyRotation>>,
    deposit: Option<Arc<DepositService>>,
    deposit_chain_readiness: Option<DepositChainReadiness>,
    /// Public epochs learned from validated, durable activation certificates, including epochs
    /// for which this party never held a signing share. Deposit handoff replay needs this on
    /// removed and newly joining parties alike.
    deposit_targets: RwLock<BTreeMap<u64, EpochPublic>>,
    /// Witness-independent root of the exact durable activation certificate/history entry which
    /// authorized each deposit target. Compact-registry capabilities are never reconstructed from
    /// `EpochPublic` alone.
    deposit_target_roots: RwLock<BTreeMap<u64, [u8; 32]>>,
    deposit_recovered_epochs: Mutex<BTreeSet<u64>>,
    epochs: RwLock<BTreeMap<u64, EpochShare>>,
    active_epoch: RwLock<Option<u64>>,
    staged: RwLock<BTreeMap<u64, StagedEpoch>>,
    activations: RwLock<BTreeMap<u64, InstallResponse>>,
    /// Witness-independent certified epoch links. This synchronous map lets untrusted AVSS/QUAL
    /// bodies be rejected for a wrong history parent before allocating reducer state.
    history_links: StdRwLock<BTreeMap<u64, EpochHistoryLink>>,
    proactive_refresh_schedule: Mutex<Option<ProactiveRefreshSchedule>>,
    /// Serializes every schedule read-modify-write across encrypted storage and RAM publication.
    proactive_refresh_schedule_mutation: Mutex<()>,
    /// Demo-Regtest-only acceptance hold. Each newly activated epoch persists the reserved
    /// `u64::MAX` deadline until an authenticated exact-source release re-arms the ordinary fixed
    /// interval. The default/production path is always autonomous.
    acceptance_proactive_refresh_hold_enabled: bool,
    /// General authenticated driver latch and exact deposit-checkpoint crash gate are exposed only
    /// under the same private-Regtest acceptance overlay as the proactive hold.
    acceptance_driver_latch: Mutex<AcceptanceDriverLatch>,
    acceptance_deposit_checkpoint_gate: Mutex<AcceptanceDepositCheckpointGate>,
    /// Serialize duplicate activation/retirement certificate deliveries across the pacemaker and
    /// QUIC handlers so only one task can consume a staged share.
    epoch_transition: Mutex<()>,
    /// Exact transition digests backed by fully verified, durable activation certificates.
    /// Certified runs may retain peer-directed catch-up messages for an offline honest target,
    /// but they no longer consume the bounded live-reducer budget or pacemaker work.
    certified_avss_sessions: RwLock<BTreeMap<SessionId, [u8; 32]>>,
    avss: Mutex<BTreeMap<SessionId, AvssRun>>,
    peer_outbox_cursor: Mutex<usize>,
    /// Non-serializable FROST machines for live consolidation attempts. Durable service records
    /// own every wire response and recovery decision; restart burns these machines and continues
    /// only through a new attempt/session.
    consolidation_signing: Mutex<HashMap<SessionId, ConsolidationSigningRuntime>>,
    /// Serialize scanner rollback/quarantine with volatile consolidation state transitions.
    consolidation_transition: Mutex<()>,
    /// Set only after every attempt restored from the service snapshot has an authenticated
    /// ProtocolStore closure. This prevents restart from recreating a nonce for a Released record.
    consolidation_closures_restored: Mutex<bool>,
    /// Demo-regtest-only, explicitly enabled acceptance barrier. The durable state lets a process
    /// restart remain held after view zero is certified instead of accidentally releasing a nonce.
    acceptance_consolidation_gate_enabled: bool,
    acceptance_consolidation_gate: Mutex<AcceptanceConsolidationGate>,
    /// Demo-regtest-only barrier after daemon-validated local preparation and before slot-zero BA.
    acceptance_consolidation_bootstrap_gate_enabled: bool,
    acceptance_consolidation_bootstrap_gate: Mutex<AcceptanceConsolidationBootstrapGate>,
    /// Private-Regtest-only crash boundary for the canonical DKG session. The gate is independent
    /// of protocol safety state but is authenticated, restart-durable, and checked under the AVSS
    /// run lock so a held session cannot leak or retire one queued effect.
    acceptance_protocol_fault_gate_enabled: bool,
    acceptance_protocol_fault_gate: Mutex<AcceptanceProtocolFaultGate>,
    held_byzantine_consolidation_release: Mutex<Option<HeldByzantineConsolidationRelease>>,
}

impl std::fmt::Debug for PartyServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartyServer").field("party", &self.party).finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct ApiError(anyhow::Error);

impl<E> From<E> for ApiError
where
    E: Into<anyhow::Error>,
{
    fn from(value: E) -> Self {
        Self(value.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        tracing::warn!(error = %self.0, "party request rejected");
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": self.0.to_string() })))
            .into_response()
    }
}

fn live_predecessor_epochs(epochs: impl IntoIterator<Item = u64>, old_epoch: u64) -> Vec<u64> {
    epochs.into_iter().filter(|epoch| *epoch < old_epoch).collect()
}

fn acceptance_consolidation_gate_allowed(scenario: &Scenario, explicitly_enabled: bool) -> bool {
    explicitly_enabled && scenario.demo_only && scenario.network == NetworkKind::Regtest
}

fn acceptance_protocol_fault_gate_storage_key(
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<(SessionId, [u8; 32])> {
    let mut session_hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/acceptance/protocol-fault-gate/session/v1",
    );
    session_hasher.update(&network_id);
    session_hasher.update(&party.0.to_le_bytes());
    let session = SessionId(*session_hasher.finalize().as_bytes());
    anyhow::ensure!(session.0 != [0; 32], "acceptance protocol fault gate session is invalid");

    let mut context_hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/acceptance/protocol-fault-gate/context/v1",
    );
    context_hasher.update(&network_id);
    context_hasher.update(&party.0.to_le_bytes());
    Ok((session, *context_hasher.finalize().as_bytes()))
}

async fn restore_acceptance_protocol_fault_gate(
    store: &ProtocolStore,
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<AcceptanceProtocolFaultGate> {
    let (session, context) = acceptance_protocol_fault_gate_storage_key(network_id, party)?;
    if !tokio::fs::try_exists(store.session_state_path(session, context)).await? {
        return Ok(AcceptanceProtocolFaultGate::default());
    }
    let bytes = store.load_session_state(session, context).await?;
    let gate: AcceptanceProtocolFaultGate = decode_canonical_postcard(bytes.as_bytes())?;
    gate.validate()?;
    Ok(gate)
}

fn acceptance_driver_latch_storage_key(
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<(SessionId, [u8; 32])> {
    let mut session_hasher =
        blake3::Hasher::new_derive_key("threshold-monero/acceptance/driver-latch/session/v1");
    session_hasher.update(&network_id);
    session_hasher.update(&party.0.to_le_bytes());
    let session = SessionId(*session_hasher.finalize().as_bytes());
    anyhow::ensure!(session.0 != [0; 32], "acceptance driver latch session is invalid");
    let mut context_hasher =
        blake3::Hasher::new_derive_key("threshold-monero/acceptance/driver-latch/context/v1");
    context_hasher.update(&network_id);
    context_hasher.update(&party.0.to_le_bytes());
    Ok((session, *context_hasher.finalize().as_bytes()))
}

async fn restore_acceptance_driver_latch(
    store: &ProtocolStore,
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<AcceptanceDriverLatch> {
    let (session, context) = acceptance_driver_latch_storage_key(network_id, party)?;
    if !tokio::fs::try_exists(store.session_state_path(session, context)).await? {
        return Ok(AcceptanceDriverLatch::default());
    }
    let bytes = store.load_session_state(session, context).await?;
    let latch: AcceptanceDriverLatch = decode_canonical_postcard(bytes.as_bytes())?;
    latch.validate()?;
    Ok(latch)
}

fn acceptance_deposit_checkpoint_gate_storage_key(
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<(SessionId, [u8; 32])> {
    let mut session_hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/acceptance/deposit-checkpoint-gate/session/v1",
    );
    session_hasher.update(&network_id);
    session_hasher.update(&party.0.to_le_bytes());
    let session = SessionId(*session_hasher.finalize().as_bytes());
    anyhow::ensure!(session.0 != [0; 32], "acceptance deposit checkpoint gate session is invalid");
    let mut context_hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/acceptance/deposit-checkpoint-gate/context/v1",
    );
    context_hasher.update(&network_id);
    context_hasher.update(&party.0.to_le_bytes());
    Ok((session, *context_hasher.finalize().as_bytes()))
}

async fn restore_acceptance_deposit_checkpoint_gate(
    store: &ProtocolStore,
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<AcceptanceDepositCheckpointGate> {
    let (session, context) = acceptance_deposit_checkpoint_gate_storage_key(network_id, party)?;
    if !tokio::fs::try_exists(store.session_state_path(session, context)).await? {
        return Ok(AcceptanceDepositCheckpointGate::default());
    }
    let bytes = store.load_session_state(session, context).await?;
    let gate: AcceptanceDepositCheckpointGate = decode_canonical_postcard(bytes.as_bytes())?;
    gate.validate()?;
    Ok(gate)
}

fn acceptance_consolidation_gate_storage_key(
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<(SessionId, [u8; 32])> {
    let mut session_hasher =
        blake3::Hasher::new_derive_key("threshold-monero/acceptance/consolidation-gate/session/v1");
    session_hasher.update(&network_id);
    session_hasher.update(&party.0.to_le_bytes());
    let session = SessionId(*session_hasher.finalize().as_bytes());
    anyhow::ensure!(session.0 != [0; 32], "acceptance gate session is invalid");

    let mut context_hasher =
        blake3::Hasher::new_derive_key("threshold-monero/acceptance/consolidation-gate/context/v1");
    context_hasher.update(&network_id);
    context_hasher.update(&party.0.to_le_bytes());
    Ok((session, *context_hasher.finalize().as_bytes()))
}

async fn restore_acceptance_consolidation_gate(
    store: &ProtocolStore,
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<AcceptanceConsolidationGate> {
    let (session, context) = acceptance_consolidation_gate_storage_key(network_id, party)?;
    if !tokio::fs::try_exists(store.session_state_path(session, context)).await? {
        return Ok(AcceptanceConsolidationGate::default());
    }
    let bytes = store.load_session_state(session, context).await?;
    let gate: AcceptanceConsolidationGate = decode_canonical_postcard(bytes.as_bytes())?;
    gate.validate()?;
    Ok(gate)
}

fn acceptance_consolidation_bootstrap_gate_storage_key(
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<(SessionId, [u8; 32])> {
    let mut session_hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/acceptance/consolidation-bootstrap-gate/session/v1",
    );
    session_hasher.update(&network_id);
    session_hasher.update(&party.0.to_le_bytes());
    let session = SessionId(*session_hasher.finalize().as_bytes());
    anyhow::ensure!(
        session.0 != [0; 32],
        "acceptance consolidation bootstrap gate session is invalid"
    );

    let mut context_hasher = blake3::Hasher::new_derive_key(
        "threshold-monero/acceptance/consolidation-bootstrap-gate/context/v1",
    );
    context_hasher.update(&network_id);
    context_hasher.update(&party.0.to_le_bytes());
    Ok((session, *context_hasher.finalize().as_bytes()))
}

async fn restore_acceptance_consolidation_bootstrap_gate(
    store: &ProtocolStore,
    network_id: [u8; 32],
    party: PartyId,
) -> anyhow::Result<AcceptanceConsolidationBootstrapGate> {
    let (session, context) =
        acceptance_consolidation_bootstrap_gate_storage_key(network_id, party)?;
    if !tokio::fs::try_exists(store.session_state_path(session, context)).await? {
        return Ok(AcceptanceConsolidationBootstrapGate::default());
    }
    let bytes = store.load_session_state(session, context).await?;
    let gate: AcceptanceConsolidationBootstrapGate = decode_canonical_postcard(bytes.as_bytes())?;
    gate.validate()?;
    Ok(gate)
}

impl PartyServer {
    /// Acquire a consolidation-only lease for the deposit registry's still-authoritative epoch.
    /// During threshold activation the global signing epoch may advance before the old-quorum
    /// handoff can finish, but DepositService keeps the old registry and exact released attempt
    /// durable. Generic signing never uses this exception.
    async fn lock_deposit_signing_share(
        &self,
        epoch: u64,
    ) -> anyhow::Result<(tokio::sync::MutexGuard<'_, ()>, EpochShare)> {
        let transition = self.epoch_transition.lock().await;
        let deposit = self.deposit.as_ref().context("deposit wallet service is not enabled")?;
        anyhow::ensure!(
            deposit.active_epoch().await? == epoch,
            "released consolidation epoch is no longer authorized by the deposit registry"
        );
        let share = self
            .epochs
            .read()
            .await
            .get(&epoch)
            .cloned()
            .context("deposit-authorized consolidation share is not retained")?;
        Ok((transition, share))
    }

    /// Refuse to advance across a transition while an even older local share is still live.
    ///
    /// Activation and retirement certificates are independently gossiped. Without this fence a
    /// fast `e -> e + 1` transition can overtake the retrying retirement for `e - 1 -> e`. Once an
    /// old-only party retires `e`, its active marker is cleared and the delayed retirement for
    /// `e - 1` can no longer prove that it extends the active chain, permanently retaining the
    /// oldest secret. The epoch-transition mutex held by both callers makes this check atomic with
    /// the subsequent activation or retirement mutation.
    async fn ensure_live_predecessors_retired(&self, old_epoch: u64) -> anyhow::Result<()> {
        let live_predecessors =
            live_predecessor_epochs(self.epochs.read().await.keys().copied(), old_epoch);
        anyhow::ensure!(
            live_predecessors.is_empty(),
            "live predecessor epoch shares remain before epoch {old_epoch}: {live_predecessors:?}"
        );
        Ok(())
    }

    /// Destroy every volatile signing machine which can still contain a clone of `epoch`'s
    /// threshold scalar before the corresponding `EpochShare` is removed from RAM or disk.
    ///
    /// Callers must first certify the portable deposit handoff, then hold the consolidation and
    /// epoch transition locks in that order. The handoff proves that old-epoch obligations no
    /// longer need a local linear signer; the exact service closure plus authenticated
    /// ProtocolStore tombstone proves that dropping each nonce machine cannot make its session
    /// reusable. Generic demo signers do not retain an epoch tag, so every such machine is
    /// conservatively destroyed at any retirement boundary.
    async fn drain_retiring_epoch_signers(
        &self,
        _consolidation_transition: &tokio::sync::MutexGuard<'_, ()>,
        _epoch_transition: &tokio::sync::MutexGuard<'_, ()>,
        epoch: u64,
    ) -> anyhow::Result<usize> {
        self.assert_retiring_epoch_avss_secret_compacted(epoch).await?;
        let retiring = {
            let live = self.consolidation_signing.lock().await;
            live.iter()
                .filter(|(_, runtime)| runtime.attempt.epoch() == epoch)
                .map(|(session, runtime)| (*session, runtime.nonce_tombstone_purpose.clone()))
                .collect::<BTreeMap<_, _>>()
        };

        if !retiring.is_empty() {
            let deposit = self
                .deposit
                .as_ref()
                .context("old-epoch consolidation signer exists without the deposit service")?;
            let closures = deposit
                .consolidation_session_closures()
                .await?
                .into_iter()
                .map(|closure| (closure.session, closure.purpose))
                .collect::<BTreeMap<_, _>>();
            for (session, expected_purpose) in &retiring {
                // A cutover may already have compacted the old coordinator record after its
                // portable completion became part of the terminal handoff. If the public closure
                // remains, it must match; in either case the authenticated permanent nonce
                // tombstone below is the exact session-closure proof required for erasure.
                if let Some(durable_purpose) = closures.get(session) {
                    anyhow::ensure!(
                        durable_purpose == expected_purpose,
                        "retiring consolidation signer differs from its durable service closure"
                    );
                }
                let tombstone = self.protocol_store.load_session_tombstone(*session).await?;
                anyhow::ensure!(
                    tombstone.purpose() == expected_purpose,
                    "retiring consolidation signer has another authenticated nonce tombstone"
                );
            }
        }

        let retired = {
            let mut live = self.consolidation_signing.lock().await;
            let sessions = retiring.keys().copied().collect::<Vec<_>>();
            let mut retired = Vec::with_capacity(sessions.len());
            for session in sessions {
                let runtime = live
                    .remove(&session)
                    .context("retiring consolidation signer disappeared during fenced drain")?;
                anyhow::ensure!(runtime.attempt.epoch() == epoch);
                retired.push(runtime);
            }
            anyhow::ensure!(
                live.values().all(|runtime| runtime.attempt.epoch() != epoch),
                "old-epoch consolidation signer survived the retirement drain"
            );
            retired
        };
        let retired_count = retired.len();
        // Dropping the linear signing states releases their `ThresholdKeys`; its secret core is
        // held in `Zeroizing` storage and is erased when the final machine clone is destroyed.
        drop(retired);

        let mut held = self.held_byzantine_consolidation_release.lock().await;
        if held.as_ref().is_some_and(|release| release.binding.attempt().epoch() == epoch) {
            held.take();
        }
        Ok(retired_count)
    }

    pub async fn new(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<std::path::PathBuf>,
        signing_seed: &[u8; 32],
        bootstrap_x25519_secret: &[u8; 32],
    ) -> anyhow::Result<Arc<Self>> {
        let acceptance_gate_requested =
            std::env::var(ACCEPTANCE_CONSOLIDATION_GATE_ENV).as_deref() == Ok("1");
        let acceptance_bootstrap_gate_requested =
            std::env::var(ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_ENV).as_deref() == Ok("1");
        let acceptance_protocol_fault_gate_requested =
            std::env::var(ACCEPTANCE_PROTOCOL_FAULT_GATE_ENV).as_deref() == Ok("1");
        let acceptance_proactive_refresh_hold_requested =
            std::env::var(ACCEPTANCE_PROACTIVE_REFRESH_HOLD_ENV).as_deref() == Ok("1");
        Box::pin(Self::new_inner(
            party,
            scenario,
            state_directory.into(),
            signing_seed,
            bootstrap_x25519_secret,
            None,
            acceptance_gate_requested,
            acceptance_bootstrap_gate_requested,
            acceptance_protocol_fault_gate_requested,
            acceptance_proactive_refresh_hold_requested,
        ))
        .await
    }

    /// Construct a party with the durable deposit-address state machine enabled.
    pub async fn new_with_deposits(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<std::path::PathBuf>,
        signing_seed: &[u8; 32],
        bootstrap_x25519_secret: &[u8; 32],
        deposit: PartyDepositConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let acceptance_gate_requested =
            std::env::var(ACCEPTANCE_CONSOLIDATION_GATE_ENV).as_deref() == Ok("1");
        let acceptance_bootstrap_gate_requested =
            std::env::var(ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_ENV).as_deref() == Ok("1");
        let acceptance_protocol_fault_gate_requested =
            std::env::var(ACCEPTANCE_PROTOCOL_FAULT_GATE_ENV).as_deref() == Ok("1");
        let acceptance_proactive_refresh_hold_requested =
            std::env::var(ACCEPTANCE_PROACTIVE_REFRESH_HOLD_ENV).as_deref() == Ok("1");
        Box::pin(Self::new_inner(
            party,
            scenario,
            state_directory.into(),
            signing_seed,
            bootstrap_x25519_secret,
            Some(deposit),
            acceptance_gate_requested,
            acceptance_bootstrap_gate_requested,
            acceptance_protocol_fault_gate_requested,
            acceptance_proactive_refresh_hold_requested,
        ))
        .await
    }

    async fn new_inner(
        party: PartyId,
        scenario: Scenario,
        state_directory: std::path::PathBuf,
        signing_seed: &[u8; 32],
        bootstrap_x25519_secret: &[u8; 32],
        deposit_config: Option<PartyDepositConfig>,
        acceptance_gate_requested: bool,
        acceptance_bootstrap_gate_requested: bool,
        acceptance_protocol_fault_gate_requested: bool,
        acceptance_proactive_refresh_hold_requested: bool,
    ) -> anyhow::Result<Arc<Self>> {
        scenario.validate()?;
        let configured = scenario.party(party)?;
        anyhow::ensure!(
            Identity::signing_public_key_from_seed(signing_seed)? == configured.signing_key.0,
            "signing seed does not match the configured stable Ed25519 key"
        );
        let configured_bootstrap = EpochEncryptionSecret::from_decrypted(
            party,
            0,
            configured.bootstrap_encryption_key.0,
            Zeroizing::new(*bootstrap_x25519_secret),
        )
        .context("bootstrap X25519 secret does not match the configured public key")?;
        // Acquire the exclusive writer lease after all pure configuration checks and before
        // opening or probing any mutable store. `PartyServer` retains it for the lifetime of the
        // final Arc, so cloned request handlers cannot accidentally release the fence early.
        let state_lease = PartyStateLease::acquire(&state_directory, party).await?;
        let store = ShareStore::new(&state_directory, party, signing_seed)?;
        let protocol_store = ProtocolStore::new(&state_directory, party, signing_seed)?;
        let epoch_history_snapshots =
            WalletSnapshotStore::new(&state_directory, party, signing_seed)?;
        let epoch_history_artifacts =
            WalletArtifactStore::new(&state_directory, party, signing_seed)?;
        let (history_key_id, _) = canonical_dkg_identity(&scenario)?;
        let epoch_history_wallet =
            epoch_history_wallet_id(scenario.quic_network_id()?, history_key_id);
        let epoch_history = if tokio::fs::try_exists(
            epoch_history_snapshots.wallet_snapshot_path(epoch_history_wallet),
        )
        .await?
        {
            let snapshot = epoch_history_snapshots.load_snapshot(epoch_history_wallet).await?;
            let state = EpochHistoryState::from_bytes(snapshot.state.as_bytes())?;
            anyhow::ensure!(
                state.revision() == snapshot.metadata.revision
                    && state.network() == scenario.quic_network_id()?
                    && state.key_id() == history_key_id,
                "epoch-history snapshot context/revision differs"
            );
            state
        } else {
            let state = EpochHistoryState::new(
                scenario.quic_network_id()?,
                history_key_id,
                EpochHistoryPolicy::new(EPOCH_HISTORY_HOT_ENTRIES)?,
            )?;
            epoch_history_snapshots
                .save_snapshot(
                    epoch_history_wallet,
                    state.revision(),
                    &state.to_bytes()?,
                    &mut OsRng,
                )
                .await?;
            state
        };
        let mut identities = BTreeMap::new();
        let genesis = scenario.genesis_committee()?;
        if let Ok(genesis_member) = genesis.member(party)
            && protocol_store
                .load_epoch_identity_retirement(0, genesis_member.encryption_key)
                .await?
                .is_none()
        {
            let capability = protocol_store
                .persist_epoch_advertisement_identity(
                    &configured_bootstrap,
                    signing_seed,
                    genesis_member.signing_key,
                    genesis_member.encryption_key,
                    &mut OsRng,
                )
                .await?;
            identities.insert(0, capability.into_identity());
        }
        let deposit_chain_readiness =
            deposit_config.as_ref().map(|config| config.chain_readiness.clone());
        let deposit = deposit_config
            .map(|config| match config.birth_anchor {
                Some(anchor) => DepositService::new_with_birth_anchor_and_consolidation_backend(
                    party,
                    scenario.clone(),
                    state_directory.clone(),
                    signing_seed,
                    config.private_view_scalar,
                    anchor,
                    config.worker,
                    config.chain_source,
                    config.consolidation_backend,
                ),
                None => DepositService::new_with_consolidation_backend(
                    party,
                    scenario.clone(),
                    state_directory.clone(),
                    signing_seed,
                    config.private_view_scalar,
                    config.worker,
                    config.chain_source,
                    config.consolidation_backend,
                ),
            })
            .transpose()?;
        let acceptance_consolidation_gate_enabled =
            acceptance_consolidation_gate_allowed(&scenario, acceptance_gate_requested);
        let acceptance_consolidation_gate = if acceptance_consolidation_gate_enabled {
            restore_acceptance_consolidation_gate(
                &protocol_store,
                scenario.quic_network_id()?,
                party,
            )
            .await?
        } else {
            AcceptanceConsolidationGate::default()
        };
        let acceptance_consolidation_bootstrap_gate_enabled =
            acceptance_consolidation_gate_allowed(&scenario, acceptance_bootstrap_gate_requested);
        let acceptance_consolidation_bootstrap_gate =
            if acceptance_consolidation_bootstrap_gate_enabled {
                restore_acceptance_consolidation_bootstrap_gate(
                    &protocol_store,
                    scenario.quic_network_id()?,
                    party,
                )
                .await?
            } else {
                AcceptanceConsolidationBootstrapGate::default()
            };
        let acceptance_protocol_fault_gate_enabled = acceptance_consolidation_gate_allowed(
            &scenario,
            acceptance_protocol_fault_gate_requested,
        );
        anyhow::ensure!(
            !acceptance_protocol_fault_gate_requested || acceptance_protocol_fault_gate_enabled,
            "acceptance protocol fault gate requires a demo-only Regtest scenario"
        );
        let restored_acceptance_protocol_fault_gate = restore_acceptance_protocol_fault_gate(
            &protocol_store,
            scenario.quic_network_id()?,
            party,
        )
        .await?;
        if !acceptance_protocol_fault_gate_enabled {
            anyhow::ensure!(
                !matches!(
                    restored_acceptance_protocol_fault_gate.state,
                    AcceptanceConsolidationGateState::Armed
                        | AcceptanceConsolidationGateState::Held
                ),
                "persisted acceptance protocol fault gate requires \
                 TM_ACCEPTANCE_ENABLE_PROTOCOL_FAULT_GATE=1"
            );
        }
        let acceptance_protocol_fault_gate = if acceptance_protocol_fault_gate_enabled {
            restored_acceptance_protocol_fault_gate
        } else {
            AcceptanceProtocolFaultGate::default()
        };
        let acceptance_proactive_refresh_hold_enabled = acceptance_consolidation_gate_allowed(
            &scenario,
            acceptance_proactive_refresh_hold_requested,
        );
        let acceptance_driver_latch =
            restore_acceptance_driver_latch(&protocol_store, scenario.quic_network_id()?, party)
                .await?;
        let acceptance_deposit_checkpoint_gate = restore_acceptance_deposit_checkpoint_gate(
            &protocol_store,
            scenario.quic_network_id()?,
            party,
        )
        .await?;
        if !acceptance_proactive_refresh_hold_enabled {
            anyhow::ensure!(
                acceptance_driver_latch.state != AcceptanceConsolidationGateState::Held
                    && acceptance_deposit_checkpoint_gate.state
                        != AcceptanceConsolidationGateState::Held,
                "held acceptance campaign gate requires \
                 TM_ACCEPTANCE_HOLD_PROACTIVE_REFRESH=1"
            );
        }
        let server = Arc::new(Self {
            party,
            scenario,
            _state_lease: state_lease,
            identities: StdRwLock::new(
                identities
                    .into_iter()
                    .map(|(epoch, identity)| (epoch, Arc::new(identity)))
                    .collect(),
            ),
            retiring_identities: StdRwLock::new(BTreeMap::new()),
            signing_seed: Zeroizing::new(*signing_seed),
            restored_ready: AtomicBool::new(false),
            quic_runtime_attached: AtomicBool::new(false),
            authenticated_quic_ingress: AtomicU64::new(0),
            authenticated_quic_responses: AtomicU64::new(0),
            store,
            protocol_store,
            epoch_history_snapshots,
            epoch_history_artifacts,
            epoch_history_wallet,
            epoch_history: RwLock::new(epoch_history),
            certified_key_rotations: StdRwLock::new(BTreeMap::new()),
            key_rotation: Mutex::new(None),
            joining_key_rotation: Mutex::new(None),
            deposit,
            deposit_chain_readiness,
            deposit_targets: RwLock::new(BTreeMap::new()),
            deposit_target_roots: RwLock::new(BTreeMap::new()),
            deposit_recovered_epochs: Mutex::new(BTreeSet::new()),
            epochs: RwLock::new(BTreeMap::new()),
            active_epoch: RwLock::new(None),
            staged: RwLock::new(BTreeMap::new()),
            activations: RwLock::new(BTreeMap::new()),
            history_links: StdRwLock::new(BTreeMap::new()),
            proactive_refresh_schedule: Mutex::new(None),
            proactive_refresh_schedule_mutation: Mutex::new(()),
            acceptance_proactive_refresh_hold_enabled,
            acceptance_driver_latch: Mutex::new(acceptance_driver_latch),
            acceptance_deposit_checkpoint_gate: Mutex::new(acceptance_deposit_checkpoint_gate),
            epoch_transition: Mutex::new(()),
            certified_avss_sessions: RwLock::new(BTreeMap::new()),
            avss: Mutex::new(BTreeMap::new()),
            peer_outbox_cursor: Mutex::new(0),
            consolidation_signing: Mutex::new(HashMap::new()),
            consolidation_transition: Mutex::new(()),
            consolidation_closures_restored: Mutex::new(false),
            acceptance_consolidation_gate_enabled,
            acceptance_consolidation_gate: Mutex::new(acceptance_consolidation_gate),
            acceptance_consolidation_bootstrap_gate_enabled,
            acceptance_consolidation_bootstrap_gate: Mutex::new(
                acceptance_consolidation_bootstrap_gate,
            ),
            acceptance_protocol_fault_gate_enabled,
            acceptance_protocol_fault_gate: Mutex::new(acceptance_protocol_fault_gate),
            held_byzantine_consolidation_release: Mutex::new(None),
        });
        // Restoration spans several independent durable reducers and has a deliberately large
        // debug future. Keep that future behind one allocation boundary so its state is not
        // embedded recursively in every constructor caller's async frame.
        Box::pin(server.restore_durable_state()).await?;
        server.validate_restored_acceptance_protocol_fault_gate().await?;
        server.restored_ready.store(true, Ordering::Release);
        Ok(server)
    }

    #[must_use]
    pub fn party_id(&self) -> PartyId {
        self.party
    }

    #[must_use]
    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    /// Mark that the authenticated QUIC runtime has been constructed around this exact restored
    /// server. The production entrypoint calls this before exposing HTTP status.
    pub fn mark_quic_runtime_attached(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.restored_ready.load(Ordering::Acquire),
            "cannot attach QUIC before durable state restoration"
        );
        self.quic_runtime_attached.store(true, Ordering::Release);
        Ok(())
    }

    /// Clear readiness as soon as the attached QUIC runtime exits or fails.
    pub fn mark_quic_runtime_detached(&self) {
        self.quic_runtime_attached.store(false, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.restored_ready.load(Ordering::Acquire)
            && self.quic_runtime_attached.load(Ordering::Acquire)
    }

    /// Durably start this party's canonical epoch-zero dealer, when it is eligible.
    ///
    /// The AVSS reducer and outbox make this exactly idempotent across process restarts. Calling
    /// this after QUIC has been bound removes any dependency on an external HTTP acceptance
    /// driver while preserving an explicit operator policy switch in `main`.
    pub async fn start_canonical_genesis_if_eligible(self: &Arc<Self>) -> anyhow::Result<bool> {
        let transition = canonical_dkg_transition(&self.scenario)?;
        if !expected_avss_dealers(&transition).contains(&self.party) {
            return Ok(false);
        }
        let _ = avss_start(State(self.clone()), Json(AvssStartRequest { transition }))
            .await
            .map_err(|error| error.0)?;
        Ok(true)
    }

    async fn persist_acceptance_driver_latch(
        &self,
        latch: &AcceptanceDriverLatch,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.acceptance_proactive_refresh_hold_enabled,
            "acceptance driver latch is disabled"
        );
        latch.validate()?;
        let (session, context) =
            acceptance_driver_latch_storage_key(self.scenario.quic_network_id()?, self.party)?;
        let encoded = postcard::to_allocvec(latch)?;
        self.protocol_store.save_session_state(session, context, &encoded, &mut OsRng).await?;
        let bytes = self.protocol_store.load_session_state(session, context).await?;
        let restored: AcceptanceDriverLatch = decode_canonical_postcard(bytes.as_bytes())?;
        restored.validate()?;
        anyhow::ensure!(restored == *latch, "acceptance driver latch readback differs");
        Ok(())
    }

    async fn update_acceptance_driver_latch(
        &self,
        request: AcceptanceDriverLatchRequest,
    ) -> anyhow::Result<AcceptanceDriverLatchResponse> {
        anyhow::ensure!(
            self.acceptance_proactive_refresh_hold_enabled,
            "acceptance driver latch is disabled"
        );
        anyhow::ensure!(request.binding != [0; 32], "acceptance driver binding is invalid");
        let mut latch = self.acceptance_driver_latch.lock().await;
        latch.validate()?;
        if latch.state == AcceptanceConsolidationGateState::Held
            || latch.state == AcceptanceConsolidationGateState::Released
        {
            anyhow::ensure!(
                latch.kind == Some(request.kind) && latch.binding == Some(request.binding),
                "acceptance driver request differs from the durable latch"
            );
        }
        let candidate = match request.action {
            AcceptanceConsolidationGateAction::Status => None,
            AcceptanceConsolidationGateAction::Arm => {
                if latch.state == AcceptanceConsolidationGateState::Held {
                    None
                } else {
                    Some(AcceptanceDriverLatch {
                        version: ACCEPTANCE_DRIVER_LATCH_VERSION,
                        state: AcceptanceConsolidationGateState::Held,
                        kind: Some(request.kind),
                        binding: Some(request.binding),
                    })
                }
            }
            AcceptanceConsolidationGateAction::Release => {
                anyhow::ensure!(
                    latch.state == AcceptanceConsolidationGateState::Held
                        || latch.state == AcceptanceConsolidationGateState::Released,
                    "acceptance driver latch cannot release before it is held"
                );
                (latch.state != AcceptanceConsolidationGateState::Released).then(|| {
                    AcceptanceDriverLatch {
                        state: AcceptanceConsolidationGateState::Released,
                        ..latch.clone()
                    }
                })
            }
        };
        if let Some(candidate) = candidate {
            self.persist_acceptance_driver_latch(&candidate).await?;
            *latch = candidate;
        }
        Ok(latch.response(self.party))
    }

    async fn persist_acceptance_deposit_checkpoint_gate(
        &self,
        gate: &AcceptanceDepositCheckpointGate,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.acceptance_proactive_refresh_hold_enabled,
            "acceptance deposit checkpoint gate is disabled"
        );
        gate.validate()?;
        let (session, context) = acceptance_deposit_checkpoint_gate_storage_key(
            self.scenario.quic_network_id()?,
            self.party,
        )?;
        let encoded = postcard::to_allocvec(gate)?;
        self.protocol_store.save_session_state(session, context, &encoded, &mut OsRng).await?;
        let bytes = self.protocol_store.load_session_state(session, context).await?;
        let restored: AcceptanceDepositCheckpointGate =
            decode_canonical_postcard(bytes.as_bytes())?;
        restored.validate()?;
        anyhow::ensure!(restored == *gate, "acceptance deposit checkpoint gate readback differs");
        Ok(())
    }

    async fn update_acceptance_deposit_checkpoint_gate(
        &self,
        request: AcceptanceDepositCheckpointGateRequest,
    ) -> anyhow::Result<AcceptanceDepositCheckpointGateResponse> {
        anyhow::ensure!(
            self.acceptance_proactive_refresh_hold_enabled,
            "acceptance deposit checkpoint gate is disabled"
        );
        anyhow::ensure!(
            request.output.transaction != [0; 32],
            "acceptance deposit checkpoint output is invalid"
        );
        let deposit = self.deposit.as_ref().context("deposit wallet service is not enabled")?;
        let mut gate = self.acceptance_deposit_checkpoint_gate.lock().await;
        gate.validate()?;
        if gate.state == AcceptanceConsolidationGateState::Held
            || gate.state == AcceptanceConsolidationGateState::Released
        {
            anyhow::ensure!(
                gate.output == Some(request.output),
                "acceptance deposit checkpoint request names another output"
            );
        }
        let current = match request.action {
            AcceptanceConsolidationGateAction::Arm | AcceptanceConsolidationGateAction::Release => {
                Some(deposit.durable_deposit_observation_evidence(request.output).await?.context(
                    "exact deposit output is not yet under an authenticated portable checkpoint",
                )?)
            }
            AcceptanceConsolidationGateAction::Status
                if gate.state == AcceptanceConsolidationGateState::Held =>
            {
                Some(deposit.durable_deposit_observation_evidence(request.output).await?.context(
                    "held deposit output is no longer under an authenticated portable checkpoint",
                )?)
            }
            AcceptanceConsolidationGateAction::Status => None,
        };
        if let (Some(stored), Some(current)) = (gate.evidence.as_ref(), current.as_ref()) {
            anyhow::ensure!(
                stored == current,
                "current deposit checkpoint evidence differs from the durable crash barrier"
            );
        }
        let candidate = match request.action {
            AcceptanceConsolidationGateAction::Status => None,
            AcceptanceConsolidationGateAction::Arm => {
                if gate.state == AcceptanceConsolidationGateState::Held {
                    None
                } else {
                    Some(AcceptanceDepositCheckpointGate {
                        version: ACCEPTANCE_DEPOSIT_CHECKPOINT_GATE_VERSION,
                        state: AcceptanceConsolidationGateState::Held,
                        output: Some(request.output),
                        evidence: current,
                    })
                }
            }
            AcceptanceConsolidationGateAction::Release => {
                anyhow::ensure!(
                    gate.state == AcceptanceConsolidationGateState::Held
                        || gate.state == AcceptanceConsolidationGateState::Released,
                    "acceptance deposit checkpoint gate cannot release before it is held"
                );
                (gate.state != AcceptanceConsolidationGateState::Released).then(|| {
                    AcceptanceDepositCheckpointGate {
                        state: AcceptanceConsolidationGateState::Released,
                        ..gate.clone()
                    }
                })
            }
        };
        if let Some(candidate) = candidate {
            self.persist_acceptance_deposit_checkpoint_gate(&candidate).await?;
            *gate = candidate;
        }
        Ok(gate.response(self.party))
    }

    async fn persist_acceptance_consolidation_gate(
        &self,
        gate: &AcceptanceConsolidationGate,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.acceptance_consolidation_gate_enabled,
            "acceptance consolidation gate is disabled"
        );
        gate.validate()?;
        let (session, context) = acceptance_consolidation_gate_storage_key(
            self.scenario.quic_network_id()?,
            self.party,
        )?;
        let encoded = postcard::to_allocvec(gate)?;
        self.protocol_store.save_session_state(session, context, &encoded, &mut OsRng).await?;
        let restored = self.protocol_store.load_session_state(session, context).await?;
        let restored: AcceptanceConsolidationGate = decode_canonical_postcard(restored.as_bytes())?;
        restored.validate()?;
        anyhow::ensure!(restored == *gate, "acceptance consolidation gate readback differs");
        Ok(())
    }

    async fn update_acceptance_consolidation_gate(
        &self,
        action: AcceptanceConsolidationGateAction,
    ) -> anyhow::Result<AcceptanceConsolidationGateResponse> {
        anyhow::ensure!(
            self.acceptance_consolidation_gate_enabled,
            "acceptance consolidation gate is disabled"
        );
        let mut gate = self.acceptance_consolidation_gate.lock().await;
        gate.validate()?;
        let candidate = match action {
            AcceptanceConsolidationGateAction::Status => None,
            AcceptanceConsolidationGateAction::Arm => {
                if gate.state == AcceptanceConsolidationGateState::Held
                    || gate.state == AcceptanceConsolidationGateState::Armed
                {
                    None
                } else {
                    Some(AcceptanceConsolidationGate {
                        state: AcceptanceConsolidationGateState::Armed,
                        ..Default::default()
                    })
                }
            }
            AcceptanceConsolidationGateAction::Release => {
                if gate.state == AcceptanceConsolidationGateState::Released {
                    None
                } else {
                    Some(AcceptanceConsolidationGate {
                        state: AcceptanceConsolidationGateState::Released,
                        ..Default::default()
                    })
                }
            }
        };
        if let Some(candidate) = candidate {
            self.persist_acceptance_consolidation_gate(&candidate).await?;
            *gate = candidate;
        }
        Ok(gate.response(self.party))
    }

    /// Cross the acceptance-only barrier after view zero is durably certified and reserved, but
    /// before consuming the local nonce authorization. Returning `true` requires the caller to
    /// retain the durable release and stop the consolidation pacemaker until admin release.
    async fn hold_acceptance_consolidation_view_if_armed(
        &self,
        authorization: ConsolidationId,
        roast_view: u64,
    ) -> anyhow::Result<bool> {
        if !self.acceptance_consolidation_gate_enabled {
            return Ok(false);
        }
        let mut gate = self.acceptance_consolidation_gate.lock().await;
        gate.validate()?;
        match gate.state {
            AcceptanceConsolidationGateState::Armed => {
                anyhow::ensure!(
                    roast_view == 0,
                    "acceptance consolidation gate missed certified view zero"
                );
                let held = AcceptanceConsolidationGate {
                    version: ACCEPTANCE_CONSOLIDATION_GATE_VERSION,
                    state: AcceptanceConsolidationGateState::Held,
                    authorization: Some(authorization),
                    roast_view: Some(roast_view),
                };
                self.persist_acceptance_consolidation_gate(&held).await?;
                *gate = held;
                Ok(true)
            }
            AcceptanceConsolidationGateState::Held => {
                anyhow::ensure!(
                    gate.authorization == Some(authorization)
                        && gate.roast_view == Some(roast_view),
                    "acceptance consolidation gate is held for another certified view"
                );
                Ok(true)
            }
            AcceptanceConsolidationGateState::Disarmed
            | AcceptanceConsolidationGateState::Released => Ok(false),
        }
    }

    async fn acceptance_consolidation_gate_is_held(&self) -> bool {
        self.acceptance_consolidation_gate_enabled
            && self.acceptance_consolidation_gate.lock().await.state
                == AcceptanceConsolidationGateState::Held
    }

    async fn persist_acceptance_consolidation_bootstrap_gate(
        &self,
        gate: &AcceptanceConsolidationBootstrapGate,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.acceptance_consolidation_bootstrap_gate_enabled,
            "acceptance consolidation bootstrap gate is disabled"
        );
        gate.validate()?;
        let (session, context) = acceptance_consolidation_bootstrap_gate_storage_key(
            self.scenario.quic_network_id()?,
            self.party,
        )?;
        let encoded = postcard::to_allocvec(gate)?;
        self.protocol_store.save_session_state(session, context, &encoded, &mut OsRng).await?;
        let restored = self.protocol_store.load_session_state(session, context).await?;
        let restored: AcceptanceConsolidationBootstrapGate =
            decode_canonical_postcard(restored.as_bytes())?;
        restored.validate()?;
        anyhow::ensure!(
            restored == *gate,
            "acceptance consolidation bootstrap gate readback differs"
        );
        Ok(())
    }

    async fn update_acceptance_consolidation_bootstrap_gate(
        &self,
        action: AcceptanceConsolidationGateAction,
    ) -> anyhow::Result<AcceptanceConsolidationBootstrapGateResponse> {
        anyhow::ensure!(
            self.acceptance_consolidation_bootstrap_gate_enabled,
            "acceptance consolidation bootstrap gate is disabled"
        );
        let mut gate = self.acceptance_consolidation_bootstrap_gate.lock().await;
        gate.validate()?;
        let candidate = match action {
            AcceptanceConsolidationGateAction::Status => None,
            AcceptanceConsolidationGateAction::Arm => {
                if matches!(
                    gate.state,
                    AcceptanceConsolidationGateState::Armed
                        | AcceptanceConsolidationGateState::Held
                ) {
                    None
                } else {
                    Some(AcceptanceConsolidationBootstrapGate {
                        state: AcceptanceConsolidationGateState::Armed,
                        ..Default::default()
                    })
                }
            }
            AcceptanceConsolidationGateAction::Release => {
                if gate.state == AcceptanceConsolidationGateState::Released {
                    None
                } else {
                    Some(AcceptanceConsolidationBootstrapGate {
                        state: AcceptanceConsolidationGateState::Released,
                        ..Default::default()
                    })
                }
            }
        };
        if let Some(candidate) = candidate {
            self.persist_acceptance_consolidation_bootstrap_gate(&candidate).await?;
            *gate = candidate;
        }
        Ok(gate.response(self.party))
    }

    /// Persist the demo barrier after local preparation/daemon validation but before the service
    /// emits any initial consensus proposal, vote, certificate, or outbox body.
    async fn hold_acceptance_consolidation_bootstrap_if_armed(
        &self,
        sweep: SweepId,
        bootstrap_ba_view: u64,
        proposer: PartyId,
        prepared_intent_digest: [u8; 32],
        committee: &Committee,
    ) -> anyhow::Result<bool> {
        if !self.acceptance_consolidation_bootstrap_gate_enabled {
            return Ok(false);
        }
        committee.validate()?;
        committee.member(proposer)?;
        anyhow::ensure!(sweep.0 != [0; 32], "bootstrap gate sweep is zero");
        anyhow::ensure!(
            prepared_intent_digest != [0; 32],
            "bootstrap gate prepared-intent digest is zero"
        );
        let mut gate = self.acceptance_consolidation_bootstrap_gate.lock().await;
        gate.validate()?;
        match gate.state {
            AcceptanceConsolidationGateState::Armed => {
                anyhow::ensure!(
                    bootstrap_ba_view == 0,
                    "acceptance consolidation bootstrap gate missed BA view zero"
                );
                let held = AcceptanceConsolidationBootstrapGate {
                    version: ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_VERSION,
                    state: AcceptanceConsolidationGateState::Held,
                    sweep: Some(sweep),
                    bootstrap_ba_view: Some(bootstrap_ba_view),
                    proposer: Some(proposer),
                    prepared_intent_digest: Some(prepared_intent_digest),
                };
                self.persist_acceptance_consolidation_bootstrap_gate(&held).await?;
                *gate = held;
                Ok(true)
            }
            AcceptanceConsolidationGateState::Held => {
                anyhow::ensure!(
                    gate.sweep == Some(sweep)
                        && gate.bootstrap_ba_view == Some(bootstrap_ba_view)
                        && gate.proposer == Some(proposer)
                        && gate.prepared_intent_digest == Some(prepared_intent_digest),
                    "acceptance consolidation bootstrap gate is held for another BA candidate"
                );
                Ok(true)
            }
            AcceptanceConsolidationGateState::Disarmed
            | AcceptanceConsolidationGateState::Released => Ok(false),
        }
    }

    async fn acceptance_consolidation_bootstrap_gate_is_held(&self) -> bool {
        self.acceptance_consolidation_bootstrap_gate_enabled
            && self.acceptance_consolidation_bootstrap_gate.lock().await.state
                == AcceptanceConsolidationGateState::Held
    }

    async fn persist_acceptance_protocol_fault_gate(
        &self,
        gate: &AcceptanceProtocolFaultGate,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.acceptance_protocol_fault_gate_enabled,
            "acceptance protocol fault gate is disabled"
        );
        gate.validate()?;
        let (session, context) = acceptance_protocol_fault_gate_storage_key(
            self.scenario.quic_network_id()?,
            self.party,
        )?;
        let encoded = postcard::to_allocvec(gate)?;
        self.protocol_store.save_session_state(session, context, &encoded, &mut OsRng).await?;
        let restored = self.protocol_store.load_session_state(session, context).await?;
        let restored: AcceptanceProtocolFaultGate = decode_canonical_postcard(restored.as_bytes())?;
        restored.validate()?;
        anyhow::ensure!(restored == *gate, "acceptance protocol fault gate readback differs");
        Ok(())
    }

    fn validate_acceptance_protocol_fault_binding(
        &self,
        session: SessionId,
        epoch: u64,
    ) -> anyhow::Result<()> {
        let transition = canonical_dkg_transition(&self.scenario)?;
        anyhow::ensure!(
            epoch == 0 && transition.target.epoch == epoch && transition.session == session,
            "acceptance protocol fault gate must bind the canonical epoch-zero DKG"
        );
        transition.target.member(self.party)?;
        Ok(())
    }

    async fn update_acceptance_protocol_fault_gate(
        &self,
        request: AcceptanceProtocolFaultGateRequest,
    ) -> anyhow::Result<AcceptanceProtocolFaultGateResponse> {
        anyhow::ensure!(
            self.acceptance_protocol_fault_gate_enabled,
            "acceptance protocol fault gate is disabled"
        );
        self.validate_acceptance_protocol_fault_binding(request.session, request.epoch)?;
        let requested = (request.session, request.epoch, request.boundary);
        let mut gate = self.acceptance_protocol_fault_gate.lock().await;
        gate.validate()?;
        if let Some(existing) = gate.binding() {
            anyhow::ensure!(
                existing == requested,
                "acceptance protocol fault gate is bound to another transition or boundary"
            );
        }
        let candidate = match request.action {
            AcceptanceConsolidationGateAction::Status => None,
            AcceptanceConsolidationGateAction::Arm => match gate.state {
                AcceptanceConsolidationGateState::Disarmed => Some(AcceptanceProtocolFaultGate {
                    version: ACCEPTANCE_PROTOCOL_FAULT_GATE_VERSION,
                    state: AcceptanceConsolidationGateState::Armed,
                    session: Some(request.session),
                    epoch: Some(request.epoch),
                    boundary: Some(request.boundary),
                    dealer: None,
                    qual_round: None,
                }),
                AcceptanceConsolidationGateState::Armed
                | AcceptanceConsolidationGateState::Held
                | AcceptanceConsolidationGateState::Released => None,
            },
            AcceptanceConsolidationGateAction::Release => match gate.state {
                AcceptanceConsolidationGateState::Held => {
                    let mut released = gate.clone();
                    released.state = AcceptanceConsolidationGateState::Released;
                    Some(released)
                }
                AcceptanceConsolidationGateState::Released => None,
                AcceptanceConsolidationGateState::Disarmed
                | AcceptanceConsolidationGateState::Armed => {
                    anyhow::bail!(
                        "acceptance protocol fault gate cannot release before its durable boundary"
                    )
                }
            },
        };
        if let Some(candidate) = candidate {
            self.persist_acceptance_protocol_fault_gate(&candidate).await?;
            *gate = candidate;
        }
        Ok(gate.response(self.party))
    }

    fn validate_acceptance_protocol_fault_boundary(
        &self,
        run: &AvssRun,
        boundary: AcceptanceProtocolFaultBoundary,
    ) -> anyhow::Result<(Option<PartyId>, Option<u64>)> {
        anyhow::ensure!(
            run.transition.target.epoch == 0,
            "acceptance protocol fault gate may hold only epoch zero"
        );
        match boundary {
            AcceptanceProtocolFaultBoundary::DealerStarted => {
                anyhow::ensure!(
                    run.dealer_outbound.is_some(),
                    "acceptance dealer-start boundary lacks its durable dealer outbox"
                );
                anyhow::ensure!(
                    run.qual_start_response.is_none(),
                    "acceptance dealer-start gate missed the pre-QUAL boundary"
                );
                Ok((Some(self.party), None))
            }
            AcceptanceProtocolFaultBoundary::QualRoundZero => {
                let qual =
                    run.qual.as_ref().context("acceptance QUAL boundary lacks its reducer")?;
                anyhow::ensure!(
                    run.qual_start_response.is_some()
                        && qual.round() == 0
                        && qual.decision().is_none()
                        && run.finalized.is_none(),
                    "acceptance QUAL gate missed undecided round zero"
                );
                Ok((None, Some(0)))
            }
        }
    }

    /// Called with the AVSS run lock held immediately after authenticated readback of that exact
    /// run. A successful transition to `Held` therefore linearizes before outbox selection,
    /// ingress, progress, or ACK retirement can acquire the same run lock.
    async fn hold_acceptance_protocol_fault_gate_if_boundary(
        &self,
        run: &AvssRun,
    ) -> anyhow::Result<bool> {
        if !self.acceptance_protocol_fault_gate_enabled {
            return Ok(false);
        }
        let mut gate = self.acceptance_protocol_fault_gate.lock().await;
        gate.validate()?;
        let Some((session, epoch, boundary)) = gate.binding() else {
            return Ok(false);
        };
        if session != run.transition.session || epoch != run.transition.target.epoch {
            return Ok(false);
        }
        match gate.state {
            AcceptanceConsolidationGateState::Armed => {
                let boundary_reached = match boundary {
                    AcceptanceProtocolFaultBoundary::DealerStarted => run.dealer_outbound.is_some(),
                    AcceptanceProtocolFaultBoundary::QualRoundZero => {
                        run.qual_start_response.is_some()
                    }
                };
                if !boundary_reached {
                    return Ok(false);
                }
                let (dealer, qual_round) =
                    self.validate_acceptance_protocol_fault_boundary(run, boundary)?;
                let held = AcceptanceProtocolFaultGate {
                    version: ACCEPTANCE_PROTOCOL_FAULT_GATE_VERSION,
                    state: AcceptanceConsolidationGateState::Held,
                    session: Some(session),
                    epoch: Some(epoch),
                    boundary: Some(boundary),
                    dealer,
                    qual_round,
                };
                self.persist_acceptance_protocol_fault_gate(&held).await?;
                *gate = held;
                Ok(true)
            }
            AcceptanceConsolidationGateState::Held => {
                let (dealer, qual_round) =
                    self.validate_acceptance_protocol_fault_boundary(run, boundary)?;
                anyhow::ensure!(
                    gate.dealer == dealer && gate.qual_round == qual_round,
                    "held acceptance protocol fault evidence differs from its AVSS run"
                );
                Ok(true)
            }
            AcceptanceConsolidationGateState::Disarmed
            | AcceptanceConsolidationGateState::Released => Ok(false),
        }
    }

    async fn validate_restored_acceptance_protocol_fault_gate(&self) -> anyhow::Result<()> {
        if !self.acceptance_protocol_fault_gate_enabled {
            return Ok(());
        }
        let runs = self.avss.lock().await;
        let gate = self.acceptance_protocol_fault_gate.lock().await;
        gate.validate()?;
        if gate.state != AcceptanceConsolidationGateState::Held {
            return Ok(());
        }
        let (session, epoch, boundary) =
            gate.binding().context("held acceptance protocol fault gate lacks its binding")?;
        self.validate_acceptance_protocol_fault_binding(session, epoch)?;
        let run = runs
            .get(&session)
            .context("held acceptance protocol fault gate lacks its durable AVSS run")?;
        let (dealer, qual_round) =
            self.validate_acceptance_protocol_fault_boundary(run, boundary)?;
        anyhow::ensure!(
            gate.dealer == dealer && gate.qual_round == qual_round,
            "restored acceptance protocol fault evidence differs from its AVSS run"
        );
        Ok(())
    }

    /// Snapshot deposit-ledger effects without removing them. The QUIC runtime durably ACKs each
    /// identifier only after the authenticated recipient reports success.
    pub async fn pending_deposit_peer_messages(
        &self,
        limit: usize,
    ) -> Vec<PendingDepositPeerMessage> {
        match &self.deposit {
            Some(deposit) => deposit.pending_peer_messages(limit).await,
            None => Vec::new(),
        }
    }

    pub async fn acknowledge_deposit_peer_messages(
        &self,
        acknowledgements: &[DepositPeerMessageId],
    ) -> anyhow::Result<()> {
        if acknowledgements.is_empty() {
            return Ok(());
        }
        self.deposit
            .as_ref()
            .context("deposit wallet service is not enabled")?
            .acknowledge_peer_messages(acknowledgements)
            .await?;
        Ok(())
    }

    /// Validate the exact typed acknowledgement returned on an authenticated QUIC response.
    /// Generic success bytes can never retire Byzantine consolidation evidence.
    pub(crate) fn validate_byzantine_consolidation_ack(
        &self,
        authenticated_recipient: PartyId,
        request_body: &[u8],
        response_body: &[u8],
    ) -> anyhow::Result<()> {
        let request = ByzantineConsolidationWireMessage::decode(request_body)?;
        anyhow::ensure!(
            !matches!(request, ByzantineConsolidationWireMessage::Ack(_)),
            "a Byzantine consolidation ACK cannot be sent as durable request work"
        );
        request.validate_authenticated_route(self.party, authenticated_recipient)?;
        let expected = request.delivery_id()?;
        anyhow::ensure!(
            expected.relay() == self.party && expected.recipient() == authenticated_recipient,
            "Byzantine consolidation delivery ID differs from its QUIC route"
        );
        let epoch = match &request {
            ByzantineConsolidationWireMessage::Consensus(message) => {
                message.slot().committee().epoch
            }
            ByzantineConsolidationWireMessage::CertifiedIntent(message) => {
                message.binding().attempt().epoch()
            }
            ByzantineConsolidationWireMessage::Preprocess(message) => {
                message.binding().attempt().epoch()
            }
            ByzantineConsolidationWireMessage::KeyImageBinding(message) => {
                message.binding().attempt().epoch()
            }
            ByzantineConsolidationWireMessage::Share(message) => {
                message.binding().attempt().epoch()
            }
            ByzantineConsolidationWireMessage::Candidate(message) => {
                message.binding().attempt().epoch()
            }
            ByzantineConsolidationWireMessage::Ack(_) => unreachable!("rejected above"),
        };
        let (committee, fault_bound) = self.trusted_committee_and_fault_bound(epoch)?;
        if let ByzantineConsolidationWireMessage::Consensus(message) = &request {
            anyhow::ensure!(message.slot().committee() == &committee);
            anyhow::ensure!(message.slot().fault_bound() == fault_bound);
            message.slot().verify_context(message.context())?;
            for attachment in message.attachments() {
                let binding = attachment.binding();
                anyhow::ensure!(binding.attempt().epoch() == epoch);
                anyhow::ensure!(binding.attempt().committee_digest() == committee.digest());
                anyhow::ensure!(binding.attempt().threshold() == committee.threshold);
            }
        }
        let acknowledgement = ByzantineConsolidationWireMessage::decode(response_body)?;
        acknowledgement.validate_authenticated_route_in_committee(
            authenticated_recipient,
            self.party,
            &committee,
        )?;
        let ByzantineConsolidationWireMessage::Ack(acknowledgement) = acknowledgement else {
            anyhow::bail!("Byzantine consolidation success omitted its typed ACK")
        };
        acknowledgement.verify_expected(&committee, expected)?;
        Ok(())
    }

    /// Atomically checkpoint the reducer relay ACK and retire its exact generic outbox body.
    pub(crate) async fn acknowledge_byzantine_consolidation(
        &self,
        acknowledgement: crate::deposit_consolidation_wire::ByzantineRelayAck,
    ) -> anyhow::Result<()> {
        let authenticated_sender = acknowledgement.route().from;
        self.deposit
            .as_ref()
            .context("deposit wallet service is not enabled")?
            .acknowledge_byzantine_consolidation(authenticated_sender, acknowledgement)
            .await?;
        Ok(())
    }

    /// Snapshot the one live key-rotation reducer's durable outbox. Reading is non-destructive;
    /// the QUIC relay may checkpoint an identifier only after authenticated remote acceptance.
    pub async fn pending_key_rotation_peer_messages(
        &self,
        limit: usize,
    ) -> Vec<PendingKeyRotationMessage> {
        if limit == 0 {
            return Vec::new();
        }
        let live_pending = self
            .key_rotation
            .lock()
            .await
            .as_ref()
            .map_or_else(Vec::new, |runtime| runtime.round.pending_messages(limit));
        let joining_pending =
            self.joining_key_rotation.lock().await.as_ref().map_or_else(Vec::new, |joining| {
                joining.pending_advertisements.values().take(limit).cloned().collect::<Vec<_>>()
            });
        let mut pending = Vec::new();
        let mut blocked_recipients = BTreeSet::new();
        let rotations = match self.certified_key_rotations.read() {
            Ok(rotations) => rotations.values().cloned().collect::<Vec<_>>(),
            Err(_) => return pending,
        };
        let delivered = self
            .proactive_refresh_schedule
            .lock()
            .await
            .as_ref()
            .map(|schedule| schedule.rotation_certificate_delivered_through.clone())
            .unwrap_or_default();
        for rotation in rotations {
            for recipient in rotation.context.participants() {
                if recipient == self.party
                    || blocked_recipients.contains(&recipient)
                    || delivered
                        .get(&recipient)
                        .is_some_and(|epoch| *epoch >= rotation.context.target_epoch())
                {
                    continue;
                }
                let Ok(message) = pending_key_rotation_certificate(
                    &rotation.context,
                    &rotation.certificate,
                    recipient,
                ) else {
                    continue;
                };
                if !pending.iter().any(|existing| existing.id == message.id) {
                    blocked_recipients.insert(recipient);
                    pending.push(message);
                    if pending.len() == limit {
                        return pending;
                    }
                }
            }
        }
        // An undelivered predecessor certificate is required to validate every later dynamic
        // advertisement/AVSS transition. Suppress newer live work for that recipient until its
        // certificate succeeds, independent of operation-level causal priority.
        for message in joining_pending.into_iter().chain(live_pending) {
            if !blocked_recipients.contains(&message.id.recipient)
                && !pending.iter().any(|existing| existing.id == message.id)
            {
                pending.push(message);
                if pending.len() == limit {
                    break;
                }
            }
        }
        pending
    }

    /// Durably remove exact key-rotation effects after successful QUIC delivery. A failed CAS
    /// leaves the in-memory image unchanged, deliberately causing replay on the next relay pass.
    pub async fn acknowledge_key_rotation_peer_messages(
        &self,
        acknowledgements: &[KeyRotationMessageId],
    ) -> anyhow::Result<()> {
        if acknowledgements.is_empty() {
            return Ok(());
        }
        {
            let acknowledged = acknowledgements.iter().copied().collect::<BTreeSet<_>>();
            let mut joining = self.joining_key_rotation.lock().await;
            if let Some(joining) = joining.as_mut() {
                joining.pending_advertisements.retain(|id, _| !acknowledged.contains(id));
            }
        }
        {
            let mut live = self.key_rotation.lock().await;
            if let Some(runtime) = live.as_mut() {
                let mut next = runtime.round.clone();
                let current = acknowledgements
                    .iter()
                    .copied()
                    .filter(|acknowledgement| {
                        acknowledgement.context == runtime.round.context().digest()
                    })
                    .collect::<Vec<_>>();
                if next.acknowledge(&current)? != 0 {
                    let revision = runtime
                        .revision
                        .checked_add(1)
                        .context("key-rotation revision exhausted")?;
                    self.protocol_store
                        .save_key_rotation_round(next.context(), revision, &next, &mut OsRng)
                        .await?;
                    runtime.round = next;
                    runtime.revision = revision;
                }
            }
        }
        let rotations = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
            .values()
            .cloned()
            .map(|rotation| (rotation.context.digest(), rotation))
            .collect::<BTreeMap<_, _>>();
        let mut delivered_updates = BTreeMap::<PartyId, u64>::new();
        for acknowledgement in acknowledgements {
            if let Some(rotation) = rotations.get(&acknowledgement.context) {
                let expected = pending_key_rotation_certificate(
                    &rotation.context,
                    &rotation.certificate,
                    acknowledgement.recipient,
                );
                if expected.as_ref().is_ok_and(|message| message.id == *acknowledgement) {
                    delivered_updates
                        .entry(acknowledgement.recipient)
                        .and_modify(|epoch| *epoch = (*epoch).max(rotation.context.target_epoch()))
                        .or_insert(rotation.context.target_epoch());
                }
            }
        }
        if !delivered_updates.is_empty() {
            let _schedule_mutation = self.proactive_refresh_schedule_mutation.lock().await;
            let mut schedule = self
                .proactive_refresh_schedule
                .lock()
                .await
                .clone()
                .context("key-rotation certificate ACK lacks a proactive schedule")?;
            for (party, epoch) in delivered_updates {
                schedule
                    .rotation_certificate_delivered_through
                    .entry(party)
                    .and_modify(|current| *current = (*current).max(epoch))
                    .or_insert(epoch);
            }
            anyhow::ensure!(
                schedule.rotation_certificate_delivered_through.len()
                    <= self.scenario.parties.len(),
                "key-rotation delivery cursor exceeds the configured party set"
            );
            self.persist_proactive_refresh_schedule_locked(schedule).await?;
        }
        Ok(())
    }

    /// Close every attempt restored without its non-serializable FROST machine. The service
    /// values are public commitments only; idempotent `save_session_tombstone` never grants the
    /// fresh receipt required to create a nonce.
    async fn restore_consolidation_session_closures(
        &self,
        _transition: &tokio::sync::MutexGuard<'_, ()>,
        deposit: &DepositService,
    ) -> anyhow::Result<()> {
        let mut restored = self.consolidation_closures_restored.lock().await;
        let closures = deposit.consolidation_session_closures().await?;
        let closed_sessions =
            closures.iter().map(|closure| closure.session).collect::<BTreeSet<_>>();
        for closure in &closures {
            self.protocol_store
                .save_session_tombstone(closure.session, &closure.purpose, &mut OsRng)
                .await?;
        }
        // Re-run this after every durable consensus mutation. Completion BA may atomically burn a
        // newer attempt after startup, so a one-shot restore flag would leave its volatile signer
        // alive. Only exact newly closed sessions are erased; unrelated live attempts continue.
        self.consolidation_signing
            .lock()
            .await
            .retain(|session, _| !closed_sessions.contains(session));
        *restored = true;
        Ok(())
    }

    /// Cross the permanent nonce boundary for one service-persisted consolidation release.
    ///
    /// Every validation which can fail without consuming nonce authority is completed before the
    /// create-new tombstone claim. Once storage returns `Created`, any later error burns this
    /// attempt and recovery must use a new session. An exact existing tombstone never reaches
    /// `FrostlassSigner::start_in_session`.
    async fn start_persisted_consolidation_signer(
        &self,
        _transition: &tokio::sync::MutexGuard<'_, ()>,
        release: PersistedSweepRelease,
        binding: ConsolidationAttemptWireBinding,
    ) -> anyhow::Result<Option<(SessionId, SignedPreprocessContribution)>> {
        let PersistedSweepRelease { authorization, attempt, prepared, nonce_authorization, .. } =
            release;
        let session = attempt.session();
        let sweep = authorization.sweep_id();
        anyhow::ensure!(prepared.plan().id == sweep, "released consolidation sweep differs");
        anyhow::ensure!(prepared.plan().epoch == attempt.epoch(), "released epoch differs");
        anyhow::ensure!(
            authorization.digest() != [0_u8; 32] && authorization.id().0 != [0_u8; 32],
            "released consolidation authorization is invalid"
        );
        anyhow::ensure!(binding.consolidation_id() == authorization.id());
        anyhow::ensure!(binding.authorization_digest() == authorization.digest());
        anyhow::ensure!(binding.attempt() == &attempt);
        let (_epoch_transition, share) = self.lock_deposit_signing_share(attempt.epoch()).await?;
        share.validate()?;
        anyhow::ensure!(share.committee.digest() == attempt.committee_digest());
        anyhow::ensure!(share.committee.threshold == attempt.threshold());
        anyhow::ensure!(share.activation_digest()? == attempt.activation_digest());
        anyhow::ensure!(share.group_key_bytes() == attempt.root_group_key());
        let signer_set = CanonicalSignerSet::new(
            &share.committee,
            self.party,
            attempt.signers().iter().copied(),
        )?;
        anyhow::ensure!(signer_set.parties() == attempt.signers());

        anyhow::ensure!(
            !self.avss.lock().await.contains_key(&session),
            "session is already used by AVSS"
        );
        {
            let live = self.consolidation_signing.lock().await;
            anyhow::ensure!(
                !live.contains_key(&session),
                "consolidation signing session is already live"
            );
            anyhow::ensure!(
                live.len() < MAX_LIVE_SIGNING_SESSIONS,
                "too many live consolidation signing sessions"
            );
        }

        // Key conversion and deterministic transaction extraction cannot consume the service
        // capability. Perform both before the irreversible storage claim.
        let threshold_keys = share.to_threshold_keys()?;
        let transaction = prepared.into_transaction();
        let tombstone = nonce_authorization.session_tombstone();
        anyhow::ensure!(tombstone.session() == session, "nonce tombstone session differs");
        let nonce_tombstone_purpose = tombstone.purpose().to_vec();
        let nonce_claim = self
            .protocol_store
            .claim_sweep_signing_nonce_boundary(
                authorization.wallet_id(),
                sweep,
                attempt.attempt(),
                session,
                attempt.worker_intent_digest(),
                tombstone.purpose(),
                &mut OsRng,
            )
            .await?;
        let SweepSigningNonceClaim::Fresh { family: family_receipt, session: session_claim } =
            nonce_claim
        else {
            // A crash after the family claim but before nonce creation permanently burns this
            // deterministic attempt. The fused store boundary has closed its exact session too;
            // let the durable ROAST pacemaker move forward without reconstructing a signer.
            return Ok(None);
        };
        let family_record = family_receipt.record();
        anyhow::ensure!(family_record.wallet() == authorization.wallet_id());
        anyhow::ensure!(family_record.sweep() == sweep);
        anyhow::ensure!(family_record.attempt() == attempt.attempt());
        anyhow::ensure!(family_record.session() == session);
        anyhow::ensure!(family_record.intent_digest() == attempt.worker_intent_digest());
        anyhow::ensure!(
            family_record.tombstone_purpose_digest() == tombstone.purpose_digest(),
            "sweep signing high-water tombstone purpose differs"
        );
        let expected_authorization = authorization.digest();
        let expected_attempt = attempt.clone();
        let committee = share.committee.clone();
        let signers = attempt.signers().to_vec();
        let group_key = attempt.root_group_key();
        let started = nonce_authorization.consume_after_tombstone(
            session_claim,
            |consolidation, authorization_digest, authorized_attempt, worker| {
                anyhow::ensure!(consolidation == authorization.id());
                anyhow::ensure!(authorization_digest == expected_authorization);
                anyhow::ensure!(authorized_attempt == &expected_attempt);
                anyhow::ensure!(worker.sweep() == sweep);
                anyhow::ensure!(worker.session() == session);
                anyhow::ensure!(worker.signing_context() == attempt.signing_context());
                anyhow::ensure!(worker.group_key() == group_key);
                anyhow::ensure!(worker.intent_digest() == attempt.worker_intent_digest());
                FrostlassSigner::start_in_session(
                    transaction,
                    threshold_keys,
                    &committee,
                    self.party,
                    signers,
                    group_key,
                    session,
                    &mut OsRng,
                )
                .map_err(Into::into)
            },
        )??;
        drop(family_receipt);
        let (state, preprocess) = started;
        anyhow::ensure!(state.context().into_bytes() == attempt.signing_context());
        anyhow::ensure!(preprocess.context().into_bytes() == attempt.signing_context());
        let preprocess = SignedPreprocessContribution::sign(
            self.identity(attempt.epoch())?.as_ref(),
            &committee,
            self.scenario.quic_network_id()?,
            binding.clone(),
            preprocess,
        )?;
        let runtime = ConsolidationSigningRuntime {
            authorization,
            attempt,
            binding,
            sweep,
            started_at: tokio::time::Instant::now(),
            nonce_tombstone_purpose,
            phase: ConsolidationSignPhase::Commitments { state, preprocess: preprocess.clone() },
        };
        let mut live = self.consolidation_signing.lock().await;
        anyhow::ensure!(
            live.len() < MAX_LIVE_SIGNING_SESSIONS && !live.contains_key(&session),
            "consolidation signing session raced another local start"
        );
        live.insert(session, runtime);
        drop(live);
        drop(_epoch_transition);
        Ok(Some((session, preprocess)))
    }

    async fn deposit_issuance_is_synchronized(&self) -> anyhow::Result<bool> {
        let Some(deposit) = &self.deposit else {
            return Ok(false);
        };
        Ok(deposit.deposit_sync_ready().await?)
    }

    /// Build one fresh compact-state pull request and its authenticated source set.
    ///
    /// A source response is never trusted by identity alone: candidate adoption re-verifies the
    /// advertised registry, index checkpoint, and ledger certificate before one snapshot CAS.
    pub async fn deposit_sync_head_request(
        &self,
    ) -> anyhow::Result<Option<(Vec<PartyId>, DepositSyncHeadRequest)>> {
        let Some(deposit) = &self.deposit else {
            return Ok(None);
        };
        Box::pin(self.ensure_deposit_initialized()).await?;
        if Box::pin(deposit.deposit_sync_ready()).await? {
            return Ok(None);
        }
        let active = Box::pin(self.active_epoch_public()).await?;
        let sources = active
            .committee
            .members
            .iter()
            .filter_map(|member| (member.id != self.party).then_some(member.id))
            .collect::<Vec<_>>();
        anyhow::ensure!(!sources.is_empty(), "no remote deposit sync source is configured");
        let request = DepositSyncHeadRequest::new(Box::pin(deposit.deposit_sync_context()).await?)?;
        Ok(Some((sources, request)))
    }

    /// Ask the deposit service whether the advertised candidate can advance this replica and, if
    /// so, return its first finite root-connected object manifest.
    pub async fn deposit_sync_plan(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<Option<DepositSyncObjectPageRequest>> {
        let deposit = self.deposit.as_ref().context("deposit wallet service is not enabled")?;
        let target = self.verified_deposit_sync_target(advertisement).await?;
        Ok(deposit.deposit_sync_plan(advertisement, &target).await?)
    }

    /// Install a completely downloaded and independently verified compact candidate atomically.
    pub async fn adopt_deposit_sync_candidate(
        &self,
        advertisement: DepositSyncAdvertisement,
        objects: Vec<DepositSyncObject>,
    ) -> anyhow::Result<bool> {
        let deposit = self.deposit.as_ref().context("deposit wallet service is not enabled")?;
        let target = self.verified_deposit_sync_target(&advertisement).await?;
        let adopted = deposit.adopt_deposit_sync_candidate(advertisement, objects, &target).await?;
        if adopted {
            let epoch = deposit.active_epoch().await?;
            self.recover_deposit_epoch(epoch).await?;
            self.reconcile_deposit_targets_allow_gap().await?;
        }
        Ok(adopted)
    }

    /// Reconstruct a non-serializable compact-registry authority exclusively from this host's
    /// durable activation history. No committee, fault bound, or activation root supplied by the
    /// sync peer participates in this decision.
    async fn verified_deposit_sync_target(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> anyhow::Result<VerifiedRegistryHandoffTarget> {
        let deposit = self.deposit.as_ref().context("deposit wallet service is not enabled")?;
        let advertised_epoch = advertisement.registry_archive().registry().active_epoch();
        let active = self.active_epoch_public().await?;
        anyhow::ensure!(
            active.committee.epoch == advertised_epoch,
            "deposit sync registry does not target the locally active certified epoch"
        );
        let (target, source) = {
            let targets = self.deposit_targets.read().await;
            let target = targets
                .get(&advertised_epoch)
                .cloned()
                .context("deposit sync target is absent from durable activation history")?;
            let source = match advertised_epoch.checked_sub(1) {
                None => None,
                Some(epoch) => Some(targets.get(&epoch).cloned().context(
                    "deposit sync predecessor is absent from durable activation history",
                )?),
            };
            (target, source)
        };
        anyhow::ensure!(
            target == active,
            "deposit sync target differs from the locally active activation certificate"
        );
        let (committee, fault_bound) = self.trusted_committee_and_fault_bound(advertised_epoch)?;
        anyhow::ensure!(
            committee == target.committee,
            "deposit sync target differs from certified committee governance"
        );
        let certified_root = self.certified_deposit_target_root(advertised_epoch).await?;
        Ok(deposit
            .verify_registry_handoff_target(source.as_ref(), &target, fault_bound, certified_root)
            .await?)
    }

    /// Advance the durable allocation-consensus lane independently of scanner availability.
    /// Consensus timeouts and view changes are protocol liveness work, so a stale or unavailable
    /// Monero daemon must not prevent the current committee from replacing a silent leader.
    pub async fn progress_deposit_allocation_consensus(
        &self,
        now_unix_ms: u64,
    ) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        // Each of these reducers has a substantial concrete async state machine. Keep their
        // storage behind explicit allocation boundaries so the always-live QUIC pacemaker does
        // not need a worker-stack-sized parent future merely to poll this orchestration method.
        match Box::pin(self.ensure_deposit_initialized()).await {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<DepositServiceError>()
                    .is_some_and(|error| matches!(error, DepositServiceError::NotInitialized)) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let epoch = Box::pin(deposit.active_epoch()).await?;
        let identity = self.identity(epoch)?;
        Box::pin(deposit.progress_consolidation_abandonment_observations(identity.as_ref()))
            .await?;
        Box::pin(deposit.progress_allocation_consensus(now_unix_ms, identity.as_ref())).await?;
        Box::pin(self.reconcile_deposit_targets_allow_gap()).await
    }

    /// Run one scanner tick. A configured service remains dormant before the epoch-zero
    /// activation certificate exists, and a missing handoff pauses issuance without pausing
    /// observation of already-issued addresses.
    pub async fn tick_deposit_worker(&self) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        match self.ensure_deposit_initialized().await {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<DepositServiceError>()
                    .is_some_and(|error| matches!(error, DepositServiceError::NotInitialized)) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        self.progress_deposit_state().await?;
        let _transition = self.consolidation_transition.lock().await;
        self.restore_consolidation_session_closures(&_transition, deposit).await?;
        let outcome = deposit.tick_worker().await?;
        // The service quarantine is already durable. Drop every matching linear machine before
        // any fallible cross-store closure work so no error path can unblock with an orphan nonce.
        let mut removed_purposes = BTreeMap::new();
        {
            let mut live = self.consolidation_signing.lock().await;
            for session in &outcome.invalidated_consolidation_sessions {
                if let Some(runtime) = live.remove(session) {
                    removed_purposes.insert(*session, runtime.nonce_tombstone_purpose);
                }
            }
        }
        let closures = deposit
            .consolidation_session_closures()
            .await?
            .into_iter()
            .map(|closure| (closure.session, closure.purpose))
            .collect::<BTreeMap<_, _>>();
        for session in outcome.invalidated_consolidation_sessions {
            let purpose = closures
                .get(&session)
                .context("invalidated consolidation session lacks a durable closure")?;
            if let Some(expected_purpose) = removed_purposes.get(&session) {
                anyhow::ensure!(
                    expected_purpose == purpose,
                    "invalidated consolidation session has another tombstone purpose"
                );
            }
            // This idempotent path carries no create-new receipt. It closes the crash gap where
            // the service persisted Released/Quarantined but the process died before FROST start.
            self.protocol_store.save_session_tombstone(session, purpose, &mut OsRng).await?;
        }
        Ok(())
    }

    async fn start_byzantine_consolidation_release(
        &self,
        transition: &tokio::sync::MutexGuard<'_, ()>,
        deposit: &DepositService,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        release: PersistedSweepRelease,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(family != [0; 32], "Byzantine consolidation family is zero");
        anyhow::ensure!(view.checked_add(1) == Some(binding.attempt().attempt()));
        anyhow::ensure!(release.authorization.id() == binding.consolidation_id());
        anyhow::ensure!(release.attempt == *binding.attempt());

        // A durably certified successor view is the rolling-window boundary. Retire old volatile
        // machines before admitting the new nonce so n=10/f=3 can traverse all 120 subsets even
        // though one party is selected in 84 of them and the process cap is 64.
        let retired = {
            let mut live = self.consolidation_signing.lock().await;
            retain_current_consolidation_view(
                &mut live,
                release.authorization.id(),
                release.attempt.attempt(),
            )
        };
        for (session, expected_purpose) in retired {
            let tombstone = self.protocol_store.load_session_tombstone(session).await?;
            anyhow::ensure!(
                tombstone.purpose() == expected_purpose,
                "retired ROAST view has another nonce tombstone purpose"
            );
        }

        // A failed service CAS after nonce creation must not make the next pacemaker tick try to
        // mint the same nonce again. Reuse only the exact already-live preprocess; later phases
        // prove that preprocess persistence already succeeded and need no Release replay.
        let existing_phase = {
            let live = self.consolidation_signing.lock().await;
            live.get(&binding.attempt().session())
                .map(|runtime| {
                    validate_live_consolidation_binding(runtime, &binding)?;
                    Ok::<Option<SignedPreprocessContribution>, anyhow::Error>(
                        match &runtime.phase {
                            ConsolidationSignPhase::Commitments { preprocess, .. } => {
                                Some(preprocess.clone())
                            }
                            ConsolidationSignPhase::Authorization { .. }
                            | ConsolidationSignPhase::Shares { .. } => None,
                        },
                    )
                })
                .transpose()?
        };
        match existing_phase {
            Some(Some(preprocess)) => {
                deposit.record_byzantine_preprocess(family, view, preprocess).await?;
                return Ok(());
            }
            Some(None) => return Ok(()),
            None => {}
        }

        let Some((session, preprocess)) =
            self.start_persisted_consolidation_signer(transition, release, binding).await?
        else {
            return Ok(());
        };
        deposit.record_byzantine_preprocess(family, view, preprocess).await?;
        anyhow::ensure!(
            self.consolidation_signing.lock().await.contains_key(&session),
            "fresh ROAST signer disappeared before preprocess persistence"
        );
        Ok(())
    }

    async fn apply_byzantine_contribution_set(
        &self,
        deposit: &DepositService,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        preprocesses: Option<Vec<SignedPreprocessContribution>>,
        shares: Option<Vec<SignedShareContribution>>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(family != [0; 32], "Byzantine consolidation family is zero");
        anyhow::ensure!(view.checked_add(1) == Some(binding.attempt().attempt()));
        let session = binding.attempt().session();
        let (committee, _) = self.trusted_committee_and_fault_bound(binding.attempt().epoch())?;
        let network = self.scenario.quic_network_id()?;

        if let Some(preprocesses) = preprocesses {
            let mut by_sender = BTreeMap::new();
            for contribution in preprocesses {
                contribution.verify(&committee, network, &binding)?;
                anyhow::ensure!(
                    binding.attempt().signers().binary_search(&contribution.sender()).is_ok(),
                    "ROAST preprocess sender is outside the certified subset"
                );
                anyhow::ensure!(
                    by_sender.insert(contribution.sender(), contribution).is_none(),
                    "duplicate ROAST preprocess sender"
                );
            }
            anyhow::ensure!(
                by_sender.len() == binding.attempt().signers().len()
                    && binding
                        .attempt()
                        .signers()
                        .iter()
                        .all(|party| by_sender.contains_key(party)),
                "ROAST preprocess set is incomplete"
            );

            // Historical terminal contribution sets are durable no-ops after volatile signer
            // retirement. Do not require a deliberately erased epoch identity unless this party
            // still owns the exact live linear machine.
            if !self.consolidation_signing.lock().await.contains_key(&session) {
                return Ok(());
            }
            // Acquire the epoch identity before consuming that linear state. Retirement fencing
            // can make this fail, but must never make an already-bound machine vanish.
            let identity = self.identity(binding.attempt().epoch())?;
            let runtime = self.consolidation_signing.lock().await.remove(&session);
            if let Some(runtime) = runtime {
                validate_live_consolidation_binding(&runtime, &binding)?;
                let ConsolidationSigningRuntime {
                    authorization,
                    attempt,
                    binding: runtime_binding,
                    sweep,
                    started_at,
                    nonce_tombstone_purpose,
                    phase,
                } = runtime;
                match phase {
                    ConsolidationSignPhase::Commitments { state, preprocess } => {
                        anyhow::ensure!(
                            by_sender.get(&self.party) == Some(&preprocess),
                            "durable ROAST set changed the local preprocess"
                        );
                        let peers = binding
                            .attempt()
                            .signers()
                            .iter()
                            .filter(|party| **party != self.party)
                            .map(|party| {
                                let contribution = by_sender
                                    .get(party)
                                    .context("missing certified ROAST preprocess")?;
                                Ok((*party, contribution.preprocess().clone()))
                            })
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        let state = state.bind_transaction_bound(peers)?;
                        let result = deposit
                            .record_local_byzantine_key_image_preview(
                                family,
                                view,
                                &binding,
                                identity.as_ref(),
                                state.proof_verified_preview(),
                            )
                            .await;
                        // Retain the transaction-bound machine even when its durable attestation
                        // CAS fails. Replaying the exact complete preprocess set retries only the
                        // attestation; it can neither replace the preview nor release a share.
                        self.consolidation_signing.lock().await.insert(
                            session,
                            ConsolidationSigningRuntime {
                                authorization,
                                attempt,
                                binding: runtime_binding,
                                sweep,
                                started_at,
                                nonce_tombstone_purpose,
                                phase: ConsolidationSignPhase::Authorization { state },
                            },
                        );
                        result?;
                    }
                    ConsolidationSignPhase::Authorization { state } => {
                        let result = deposit
                            .record_local_byzantine_key_image_preview(
                                family,
                                view,
                                &binding,
                                identity.as_ref(),
                                state.proof_verified_preview(),
                            )
                            .await;
                        self.consolidation_signing.lock().await.insert(
                            session,
                            ConsolidationSigningRuntime {
                                authorization,
                                attempt,
                                binding: runtime_binding,
                                sweep,
                                started_at,
                                nonce_tombstone_purpose,
                                phase: ConsolidationSignPhase::Authorization { state },
                            },
                        );
                        result?;
                    }
                    ConsolidationSignPhase::Shares { state, share } => {
                        self.consolidation_signing.lock().await.insert(
                            session,
                            ConsolidationSigningRuntime {
                                authorization,
                                attempt,
                                binding: runtime_binding,
                                sweep,
                                started_at,
                                nonce_tombstone_purpose,
                                phase: ConsolidationSignPhase::Shares {
                                    state,
                                    share: share.clone(),
                                },
                            },
                        );
                        deposit.record_byzantine_share(family, view, share).await?;
                    }
                }
            }
        }

        if let Some(shares) = shares {
            let mut by_sender = BTreeMap::new();
            for contribution in shares {
                contribution.verify(&committee, network, &binding)?;
                anyhow::ensure!(
                    binding.attempt().signers().binary_search(&contribution.sender()).is_ok(),
                    "ROAST share sender is outside the certified subset"
                );
                anyhow::ensure!(
                    by_sender.insert(contribution.sender(), contribution).is_none(),
                    "duplicate ROAST share sender"
                );
            }
            anyhow::ensure!(
                by_sender.len() == binding.attempt().signers().len()
                    && binding
                        .attempt()
                        .signers()
                        .iter()
                        .all(|party| by_sender.contains_key(party)),
                "ROAST share set is incomplete"
            );
            let Some(runtime) = self.consolidation_signing.lock().await.remove(&session) else {
                // A non-selected relay or a restarted party still persists and forwards the set;
                // it simply has no linear FROST machine with which to aggregate it.
                return Ok(());
            };
            validate_live_consolidation_binding(&runtime, &binding)?;
            let ConsolidationSignPhase::Shares { state, share } = runtime.phase else {
                // Receiving a full share set before the local ShareExposed boundary cannot make
                // this party skip round one. Burn this local machine; the durable pacemaker will
                // select a fresh session while other valid aggregators may still finish.
                return Ok(());
            };
            anyhow::ensure!(
                by_sender.get(&self.party) == Some(&share),
                "durable ROAST set changed the local signature share"
            );
            let peers = binding
                .attempt()
                .signers()
                .iter()
                .filter(|party| **party != self.party)
                .map(|party| {
                    let contribution =
                        by_sender.get(party).context("missing certified ROAST share")?;
                    Ok((*party, contribution.share().clone()))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let transaction = state.complete_bound(peers)?;
            let transaction = SignedSweepTransaction::from_transaction(&transaction, None)?;
            let attestation = PortableSignedTransactionAttestation::sign(
                self.identity(binding.attempt().epoch())?.as_ref(),
                &committee,
                network,
                binding,
                transaction,
            )?;
            // Exact transaction bytes become durable before candidate gossip is exposed.
            deposit.record_byzantine_candidate(family, view, attestation).await?;
        }
        Ok(())
    }

    /// Cross the key-image authorization boundary for one exact ROAST view.
    ///
    /// The linear signer remains in `Authorization` until the service verifies the all-selected
    /// attestation certificate against its API-unforgeable preview and durably pins the resulting
    /// family key images. Only that successful readback permits calculating a CLSAG share.
    async fn apply_byzantine_key_image_authorization(
        &self,
        deposit: &DepositService,
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        certificate: crate::deposit_consolidation_wire::PortableKeyImageBindingCertificate,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(family != [0; 32], "Byzantine consolidation family is zero");
        anyhow::ensure!(view.checked_add(1) == Some(binding.attempt().attempt()));
        let session = binding.attempt().session();
        let (committee, _) = self.trusted_committee_and_fault_bound(binding.attempt().epoch())?;
        let network = self.scenario.quic_network_id()?;
        if !self.consolidation_signing.lock().await.contains_key(&session) {
            // Non-selected and restarted parties still persist/relay the portable certificate,
            // but have no volatile linear signing machine from which a share could be released.
            return Ok(());
        }
        let identity = self.identity(binding.attempt().epoch())?;
        let runtime = self
            .consolidation_signing
            .lock()
            .await
            .remove(&session)
            .context("live consolidation signer disappeared under the transition fence")?;
        validate_live_consolidation_binding(&runtime, &binding)?;
        let ConsolidationSigningRuntime {
            authorization,
            attempt,
            binding: runtime_binding,
            sweep,
            started_at,
            nonce_tombstone_purpose,
            phase,
        } = runtime;

        match phase {
            ConsolidationSignPhase::Authorization { state } => {
                let authorization_result = deposit
                    .authorize_byzantine_key_images(
                        family,
                        view,
                        &binding,
                        state.proof_verified_preview(),
                        &certificate,
                    )
                    .await;
                if let Err(error) = authorization_result {
                    self.consolidation_signing.lock().await.insert(
                        session,
                        ConsolidationSigningRuntime {
                            authorization,
                            attempt,
                            binding: runtime_binding,
                            sweep,
                            started_at,
                            nonce_tombstone_purpose,
                            phase: ConsolidationSignPhase::Authorization { state },
                        },
                    );
                    return Err(error.into());
                }

                let (state, share) = state.release_bound_signature_share()?;
                let share = SignedShareContribution::sign(
                    identity.as_ref(),
                    &committee,
                    network,
                    binding,
                    share,
                )?;
                self.consolidation_signing.lock().await.insert(
                    session,
                    ConsolidationSigningRuntime {
                        authorization,
                        attempt,
                        binding: runtime_binding,
                        sweep,
                        started_at,
                        nonce_tombstone_purpose,
                        phase: ConsolidationSignPhase::Shares { state, share: share.clone() },
                    },
                );
                // `record_byzantine_share` first persists ShareExposed with the exact payload and
                // refuses to enqueue a relay unless the same worker key-image pin is still live.
                deposit.record_byzantine_share(family, view, share).await?;
            }
            ConsolidationSignPhase::Shares { state, share } => {
                // Idempotent action replay after a service/outbox failure. This phase is reachable
                // only through the successful authorization path above.
                self.consolidation_signing.lock().await.insert(
                    session,
                    ConsolidationSigningRuntime {
                        authorization,
                        attempt,
                        binding: runtime_binding,
                        sweep,
                        started_at,
                        nonce_tombstone_purpose,
                        phase: ConsolidationSignPhase::Shares { state, share: share.clone() },
                    },
                );
                deposit.record_byzantine_share(family, view, share).await?;
            }
            ConsolidationSignPhase::Commitments { state, preprocess } => {
                self.consolidation_signing.lock().await.insert(
                    session,
                    ConsolidationSigningRuntime {
                        authorization,
                        attempt,
                        binding: runtime_binding,
                        sweep,
                        started_at,
                        nonce_tombstone_purpose,
                        phase: ConsolidationSignPhase::Commitments { state, preprocess },
                    },
                );
                anyhow::bail!("key-image certificate arrived before local preprocess binding");
            }
        }
        Ok(())
    }

    async fn apply_byzantine_consolidation_action(
        &self,
        transition: &tokio::sync::MutexGuard<'_, ()>,
        deposit: &DepositService,
        action: ByzantineConsolidationAction,
    ) -> anyhow::Result<(bool, Vec<ByzantineConsolidationAction>)> {
        match action {
            ByzantineConsolidationAction::BootstrapPrepared {
                sweep,
                slot,
                outer_view,
                bootstrap_ba_view,
                proposer,
                binding,
                prepared_intent_digest,
                continuation,
            } => {
                anyhow::ensure!(sweep.0 != [0; 32], "bootstrap sweep is zero");
                anyhow::ensure!(slot != [0; 32], "bootstrap consensus slot is zero");
                anyhow::ensure!(outer_view == 0, "bootstrap action is not outer view zero");
                anyhow::ensure!(outer_view.checked_add(1) == Some(binding.attempt().attempt()));
                anyhow::ensure!(bootstrap_ba_view == 0, "bootstrap action is not BA view zero");
                anyhow::ensure!(prepared_intent_digest != [0; 32]);
                anyhow::ensure!(continuation.slot() == slot);
                anyhow::ensure!(continuation.prepared_intent_digest() == prepared_intent_digest);
                let epoch = binding.attempt().epoch();
                let (committee, _) = self.trusted_committee_and_fault_bound(epoch)?;
                anyhow::ensure!(binding.attempt().committee_digest() == committee.digest());
                anyhow::ensure!(binding.attempt().threshold() == committee.threshold);
                committee.member(proposer)?;
                if self
                    .hold_acceptance_consolidation_bootstrap_if_armed(
                        sweep,
                        bootstrap_ba_view,
                        proposer,
                        prepared_intent_digest,
                        &committee,
                    )
                    .await?
                {
                    return Ok((true, Vec::new()));
                }
                let follow_up = deposit
                    .continue_byzantine_bootstrap(
                        self.identity(epoch)?.as_ref(),
                        continuation,
                        unix_time_millis()?,
                    )
                    .await?;
                return Ok((false, follow_up));
            }
            ByzantineConsolidationAction::Release { family, view, binding, release } => {
                if self
                    .hold_acceptance_consolidation_view_if_armed(release.authorization.id(), view)
                    .await?
                {
                    let mut held = self.held_byzantine_consolidation_release.lock().await;
                    anyhow::ensure!(held.is_none(), "another acceptance release is already held");
                    *held =
                        Some(HeldByzantineConsolidationRelease { family, view, binding, release });
                    return Ok((true, Vec::new()));
                }
                self.start_byzantine_consolidation_release(
                    transition, deposit, family, view, binding, release,
                )
                .await?;
            }
            ByzantineConsolidationAction::CompleteContributionSet {
                family,
                view,
                binding,
                preprocesses,
                shares,
            } => {
                self.apply_byzantine_contribution_set(
                    deposit,
                    family,
                    view,
                    binding,
                    preprocesses,
                    shares,
                )
                .await?;
            }
            ByzantineConsolidationAction::AuthorizeKeyImages {
                family,
                view,
                binding,
                certificate,
            } => {
                self.apply_byzantine_key_image_authorization(
                    deposit,
                    family,
                    view,
                    binding,
                    certificate,
                )
                .await?;
            }
            ByzantineConsolidationAction::BroadcastCandidate {
                family,
                view,
                sweep,
                binding,
                attestation,
            } => {
                anyhow::ensure!(family != [0; 32], "Byzantine consolidation family is zero");
                anyhow::ensure!(view.checked_add(1) == Some(binding.attempt().attempt()));
                anyhow::ensure!(attestation.binding().attempt() == &binding);
                deposit.record_byzantine_candidate(family, view, attestation).await?;
                let active_epoch = deposit.active_epoch().await?;
                anyhow::ensure!(
                    active_epoch == binding.attempt().epoch(),
                    "signed consolidation survived an unresolved epoch cutover"
                );
                match deposit
                    .propose_consolidation_completion(sweep, self.identity(active_epoch)?.as_ref())
                    .await
                {
                    Ok(()) | Err(DepositServiceError::NotLeader(_)) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            ByzantineConsolidationAction::RetireView { family, view, binding, signing_session } => {
                anyhow::ensure!(family != [0; 32], "Byzantine consolidation family is zero");
                anyhow::ensure!(view.checked_add(1) == Some(binding.attempt().attempt()));
                anyhow::ensure!(signing_session == binding.attempt().session());
                if let Some(runtime) =
                    self.consolidation_signing.lock().await.remove(&signing_session)
                {
                    validate_live_consolidation_binding(&runtime, &binding)?;
                    let tombstone =
                        self.protocol_store.load_session_tombstone(signing_session).await?;
                    anyhow::ensure!(
                        tombstone.purpose() == runtime.nonce_tombstone_purpose,
                        "retired ROAST action differs from its nonce tombstone"
                    );
                }
            }
        }
        Ok((false, Vec::new()))
    }

    /// Advance coordinator-free Byzantine consolidation. Every intent view is committed by its
    /// own durable consensus lane before nonce release; deterministic `n-f` subsets and fresh
    /// sessions replace silent selected signers without granting authority to a fixed member.
    pub async fn progress_deposit_consolidation_once(
        &self,
        attempt_timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!attempt_timeout.is_zero(), "consolidation timeout must be positive");
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        // The consolidation reducers below are each ~quarter-megabyte async frames. This method is
        // driven on the deposit worker's tokio task, whose worker thread has only the default 2 MiB
        // stack (production's 16 MiB `PARTY_RUNTIME_THREAD_STACK_BYTES` is not in force under bare
        // `#[tokio::test]`). Awaiting the reducers inline stacks every construction temporary into
        // one multi-megabyte poll frame; route the large ones through non-async boxing shims so only
        // an eight-byte pointer stays live here per await.
        self.boxed_ensure_deposit_initialized().await?;
        let transition = self.consolidation_transition.lock().await;
        self.restore_consolidation_session_closures(&transition, deposit).await?;

        // Recover the crash boundary after exact signed bytes were adopted but before the current
        // ledger leader reserved their completion statement. This runs before publication and
        // before either acceptance gate, and is idempotent across every restart/tick.
        let signed_sweeps = deposit.signed_sweeps_awaiting_completion().await?;
        if !signed_sweeps.is_empty() {
            let active_identity = self.identity(deposit.active_epoch().await?)?;
            for sweep in signed_sweeps {
                match boxed_propose_consolidation_completion(
                    deposit,
                    sweep,
                    active_identity.as_ref(),
                )
                .await
                {
                    Ok(()) | Err(DepositServiceError::NotLeader(_)) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }

        // Any party with a globally certified completion may safely publish the exact bytes.
        // Repeating after an RPC/CAS crash is intentionally idempotent.
        for sweep in deposit.certified_sweeps_awaiting_publish().await? {
            deposit.publish_certified_consolidation(sweep).await?;
        }

        // While either acceptance barrier is held, neither bootstrap BA nor the later nonce/view
        // pacemaker may advance. The driver releases survivors only after isolating the selected
        // peer, making the resulting recovery causally attributable to that omission.
        if self.acceptance_consolidation_bootstrap_gate_is_held().await
            || self.acceptance_consolidation_gate_is_held().await
        {
            return Ok(());
        }

        // A held one-shot capability is intentionally volatile. If this process restarted while
        // held, the service sees the durable released/tombstoned attempt and certifies a fresh view
        // after admin release; it never reconstructs the lost nonce authorization.
        if let Some(held) = self.held_byzantine_consolidation_release.lock().await.take() {
            self.start_byzantine_consolidation_release(
                &transition,
                deposit,
                held.family,
                held.view,
                held.binding,
                held.release,
            )
            .await?;
        }

        let epoch = deposit.active_epoch().await?;
        let identity = self.identity(epoch)?;
        let now_ms = unix_time_millis()?;
        let base_timeout_ms = u64::try_from(attempt_timeout.as_millis())
            .context("consolidation timeout exceeds u64 milliseconds")?;
        let actions = boxed_progress_byzantine_consolidations(
            deposit,
            identity.as_ref(),
            now_ms,
            base_timeout_ms,
        )
        .await?;
        let mut actions = VecDeque::from(actions);
        let mut applied = 0_usize;
        while let Some(action) = actions.pop_front() {
            anyhow::ensure!(
                applied < MAX_BYZANTINE_CONSOLIDATION_ACTIONS_PER_TICK,
                "Byzantine consolidation action cascade exceeded its fixed bound"
            );
            applied += 1;
            let (stop, follow_up) = self
                .boxed_apply_byzantine_consolidation_action(&transition, deposit, action)
                .await?;
            if stop {
                break;
            }
            actions.extend(follow_up);
        }
        Ok(())
    }

    async fn remember_certified_deposit_target(
        &self,
        value: &ActivationValue,
    ) -> anyhow::Result<[u8; 32]> {
        value.public.validate()?;
        anyhow::ensure!(
            value.epoch == value.public.committee.epoch
                && value.activation_digest == value.public.activation_digest()?,
            "deposit target differs from its certified activation value"
        );
        let certified_root = value.history_link.root()?;
        anyhow::ensure!(certified_root != [0_u8; 32], "certified deposit target root is zero");
        {
            let mut targets = self.deposit_targets.write().await;
            if let Some(existing) = targets.get(&value.epoch) {
                anyhow::ensure!(
                    existing == &value.public,
                    "deposit epoch is already bound to another public value"
                );
            } else {
                targets.insert(value.epoch, value.public.clone());
            }
        }
        let mut roots = self.deposit_target_roots.write().await;
        if let Some(existing) = roots.get(&value.epoch) {
            anyhow::ensure!(
                *existing == certified_root,
                "deposit epoch is already bound to another certified activation root"
            );
        } else {
            roots.insert(value.epoch, certified_root);
        }
        Ok(certified_root)
    }

    async fn certified_deposit_target_root(&self, epoch: u64) -> anyhow::Result<[u8; 32]> {
        self.deposit_target_roots.read().await.get(&epoch).copied().with_context(|| {
            format!("deposit epoch {epoch} lacks its certified activation-history root")
        })
    }

    async fn ensure_deposit_initialized(&self) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        let active = match deposit.active_epoch().await {
            Ok(epoch) => epoch,
            Err(DepositServiceError::NotInitialized) => {
                let Some(root) = self.deposit_targets.read().await.get(&0).cloned() else {
                    return Err(DepositServiceError::NotInitialized.into());
                };
                let certified_root = self.certified_deposit_target_root(0).await?;
                deposit.ensure_genesis(&root, certified_root).await?;
                0
            }
            Err(error) => return Err(error.into()),
        };
        self.recover_deposit_epoch(active).await?;
        Ok(())
    }

    async fn recover_deposit_epoch(&self, epoch: u64) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        let mut recovered = self.deposit_recovered_epochs.lock().await;
        if recovered.contains(&epoch) {
            return Ok(());
        }
        let identity = {
            let identities = self
                .identities
                .read()
                .map_err(|_| anyhow::anyhow!("identity registry lock is poisoned"))?;
            identities
                .get(&epoch)
                .or_else(|| identities.values().next())
                .cloned()
                .context("missing local identity for deposit recovery")?
        };
        deposit.recover_peer_messages(&identity, unix_time_seconds()?).await?;
        recovered.insert(epoch);
        Ok(())
    }

    /// Apply every contiguous certified deposit handoff for which this host has authenticated
    /// successor activation data. The first missing certificate is deliberately an error so QUIC
    /// delivery remains retryable and client allocation stays closed during the gap.
    async fn reconcile_deposit_targets(&self) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        self.ensure_deposit_initialized().await?;
        loop {
            let active = deposit.active_epoch().await?;
            let successor = active.checked_add(1).context("deposit epoch counter is exhausted")?;
            let Some(target) = self.deposit_targets.read().await.get(&successor).cloned() else {
                break;
            };
            let certified_root = self.certified_deposit_target_root(successor).await?;
            let Some(old) = self.deposit_targets.read().await.get(&active).cloned() else {
                anyhow::bail!("deposit source epoch is absent from certified activation history");
            };
            self.prepare_deposit_handoff(&old, &target, certified_root).await?;
            self.progress_certified_deposit_handoff(&old, &target, certified_root).await?;
            deposit.apply_certified_handoff(&old, &target, certified_root).await?;
            self.recover_deposit_epoch(target.committee.epoch).await?;
        }
        Ok(())
    }

    async fn reconcile_deposit_targets_allow_gap(&self) -> anyhow::Result<()> {
        match self.reconcile_deposit_targets().await {
            Ok(()) => Ok(()),
            Err(error) if is_expected_deposit_reconciliation_gap(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn prepare_deposit_handoff(
        &self,
        old: &EpochPublic,
        target: &EpochPublic,
        certified_root: [u8; 32],
    ) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        // A target-only joiner has no authority to sign the terminal old-epoch ledger entry and
        // may not have the epoch-zero history yet. Threshold activation remains independent;
        // deposit issuance stays closed until authenticated history bootstrap catches up.
        if old.committee.member(self.party).is_err() {
            return Ok(());
        }
        self.ensure_deposit_initialized().await?;
        if deposit.active_epoch().await? >= target.committee.epoch {
            return Ok(());
        }
        // An older certified transition must be replayed first. This closes issuance rather than
        // constructing a fresh registry or signing a handoff from the wrong issuer window.
        if deposit.active_epoch().await? != old.committee.epoch {
            Box::pin(self.reconcile_deposit_targets()).await?;
        }
        anyhow::ensure!(
            deposit.active_epoch().await? == old.committee.epoch,
            "deposit registry has not reached the resharing source epoch"
        );
        let identity = self.identity(old.committee.epoch)?;
        match deposit
            .begin_handoff(old, target, certified_root, unix_time_millis()?, &identity)
            .await
        {
            Ok(()) | Err(DepositServiceError::ConsolidationNotPortable) => {
                // `begin_handoff` persists the exact target before the retryable quiescence
                // outcome. A nonce-bearing consolidation may continue with its already acquired
                // old-epoch lease, while every new deposit/consolidation start is durably fenced
                // by `pending_handoff`. It cannot start or sign the handoff consensus lane.
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// Start or resume the terminal old-quorum lane only after the exact successor activation
    /// certificate and history root are durable on this host.
    async fn progress_certified_deposit_handoff(
        &self,
        old: &EpochPublic,
        target: &EpochPublic,
        certified_root: [u8; 32],
    ) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        if old.committee.member(self.party).is_err() {
            return Ok(());
        }
        self.ensure_deposit_initialized().await?;
        if deposit.active_epoch().await? >= target.committee.epoch {
            return Ok(());
        }
        anyhow::ensure!(
            self.certified_deposit_target_root(target.committee.epoch).await? == certified_root,
            "deposit successor root differs from durable activation history"
        );
        let identity = self.identity(old.committee.epoch)?;
        match deposit
            .progress_certified_handoff(old, target, certified_root, unix_time_millis()?, &identity)
            .await
        {
            Ok(())
            | Err(DepositServiceError::NotLeader(_))
            | Err(DepositServiceError::ConsolidationNotPortable) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Prove that every portable old-epoch deposit obligation has crossed its terminal handoff
    /// before destroying the signing share which can authorize it. `begin_handoff` alone is not
    /// sufficient: the old quorum certificate must already be durable and applicable locally.
    async fn certify_deposit_handoff_before_share_retirement(
        &self,
        old: &EpochPublic,
        target: &EpochPublic,
        certified_root: [u8; 32],
    ) -> anyhow::Result<()> {
        // Each deposit-handoff segment below is an independent multi-hundred-kilobyte async frame.
        // Debug lowering does not overlap the per-await construction temporaries, so awaiting them
        // inline reserves one full segment coroutine per await and inflates this poll frame past a
        // megabyte. A call-site `Box::pin` does not help: the segment future is still *constructed*
        // in this frame before it is boxed. Route each segment through a non-async helper that
        // builds and boxes the future in its own frame (the same mechanism as `new -> new_inner`),
        // leaving only an eight-byte pointer live here per await.
        self.boxed_prepare_deposit_handoff(old, target, certified_root).await?;
        self.boxed_progress_certified_deposit_handoff(old, target, certified_root).await?;
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        boxed_apply_certified_handoff(deposit, old, target, certified_root).await?;
        self.boxed_recover_deposit_epoch(target.committee.epoch).await?;
        Ok(())
    }

    // Non-async boxing shims for the deposit-handoff segments above. Each constructs its segment
    // future and moves it to the heap inside this shim's own frame, which is popped before the
    // caller awaits the returned pointer, so a caller that drives several segments in sequence
    // never reserves more than one eight-byte pointer per await. See the note in
    // `certify_deposit_handoff_before_share_retirement` for the underlying debug-lowering rationale.
    fn boxed_prepare_deposit_handoff<'a>(
        &'a self,
        old: &'a EpochPublic,
        target: &'a EpochPublic,
        certified_root: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(self.prepare_deposit_handoff(old, target, certified_root))
    }

    fn boxed_progress_certified_deposit_handoff<'a>(
        &'a self,
        old: &'a EpochPublic,
        target: &'a EpochPublic,
        certified_root: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(self.progress_certified_deposit_handoff(old, target, certified_root))
    }

    fn boxed_recover_deposit_epoch(
        &self,
        epoch: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(self.recover_deposit_epoch(epoch))
    }

    fn boxed_ensure_deposit_initialized(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(self.ensure_deposit_initialized())
    }

    fn boxed_progress_deposit_state(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(self.progress_deposit_state())
    }

    fn boxed_reconcile_deposit_targets_allow_gap(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(self.reconcile_deposit_targets_allow_gap())
    }

    #[allow(clippy::type_complexity)]
    fn boxed_apply_byzantine_consolidation_action<'a, 'g>(
        &'a self,
        transition: &'a tokio::sync::MutexGuard<'g, ()>,
        deposit: &'a DepositService,
        action: ByzantineConsolidationAction,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = anyhow::Result<(bool, Vec<ByzantineConsolidationAction>)>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(self.apply_byzantine_consolidation_action(transition, deposit, action))
    }

    async fn progress_deposit_state(&self) -> anyhow::Result<()> {
        let Some(deposit) = &self.deposit else {
            return Ok(());
        };
        self.boxed_ensure_deposit_initialized().await?;
        let active = deposit.active_epoch().await?;
        let Some(successor) = active.checked_add(1) else {
            return Ok(());
        };
        let targets = self.deposit_targets.read().await;
        let Some(old) = targets.get(&active).cloned() else {
            return Ok(());
        };
        let Some(target) = targets.get(&successor).cloned() else {
            return Ok(());
        };
        drop(targets);
        let certified_root = self.certified_deposit_target_root(successor).await?;
        // Each deposit segment below is a ~quarter-megabyte async frame; drive them through the
        // non-async boxing shims so this progress path does not stack every segment's construction
        // temporary into one multi-megabyte poll frame. See
        // `certify_deposit_handoff_before_share_retirement` for the debug-lowering rationale.
        self.boxed_prepare_deposit_handoff(&old, &target, certified_root).await?;
        self.boxed_progress_certified_deposit_handoff(&old, &target, certified_root).await?;
        self.boxed_reconcile_deposit_targets_allow_gap().await
    }

    /// Snapshot non-secret liveness state for tests and operator diagnostics.
    pub async fn protocol_session_status(
        &self,
        session: SessionId,
    ) -> Option<ProtocolSessionStatus> {
        let runs = self.avss.lock().await;
        let run = runs.get(&session)?;
        Some(ProtocolSessionStatus {
            session,
            completed_outputs: run.outputs.len(),
            qual_started: run.qual_start_response.is_some(),
            qual_round: run.qual.as_ref().map(QualConsensus::round),
            qual_decided: run.qual.as_ref().and_then(QualConsensus::decision).is_some(),
            finalized: run.finalized.is_some(),
            pending_avss: run.pending_avss.len(),
            pending_qual: run.pending_qual.len(),
            pending_activation_ack: run.pending_activation_ack.len(),
        })
    }

    /// Inspect only the volatile phase marker or authenticated permanent closure for a
    /// consolidation session; no nonce, share, transaction, or private wallet data is exposed.
    pub async fn consolidation_session_status(
        &self,
        session: SessionId,
    ) -> anyhow::Result<Option<ConsolidationSessionStatus>> {
        if let Some(runtime) = self.consolidation_signing.lock().await.get(&session) {
            return Ok(Some(match runtime.phase {
                ConsolidationSignPhase::Commitments { .. } => {
                    ConsolidationSessionStatus::AwaitingCommitments
                }
                ConsolidationSignPhase::Authorization { .. } => {
                    ConsolidationSessionStatus::AwaitingAuthorization
                }
                ConsolidationSignPhase::Shares { .. } => ConsolidationSessionStatus::AwaitingShares,
            }));
        }
        if tokio::fs::try_exists(self.protocol_store.session_tombstone_path(session)).await? {
            drop(self.protocol_store.load_session_tombstone(session).await?);
            return Ok(Some(ConsolidationSessionStatus::Closed));
        }
        Ok(None)
    }

    async fn active_epoch_public(&self) -> anyhow::Result<EpochPublic> {
        let epoch = self.active_epoch.read().await.context("party has no active epoch")?;
        self.activations
            .read()
            .await
            .get(&epoch)
            .map(|activation| activation.public.clone())
            .context("active epoch lacks activation metadata")
    }

    fn identity_from_epoch_secret(
        &self,
        secret: &EpochEncryptionSecret,
        signing_key: [u8; 32],
        encryption_key: [u8; 32],
    ) -> anyhow::Result<Identity> {
        Ok(Identity::from_encryption_secret(
            self.party,
            secret.epoch(),
            &self.signing_seed,
            signing_key,
            encryption_key,
            secret,
        )?)
    }

    async fn persist_key_rotation_view_anchor(
        &self,
        context: &KeyRotationContext,
        view: u64,
        started_unix_ms: u64,
        update: KeyRotationPacemakerUpdate,
    ) -> anyhow::Result<()> {
        let _schedule_mutation = self.proactive_refresh_schedule_mutation.lock().await;
        self.persist_key_rotation_view_anchor_locked(context, view, started_unix_ms, update).await
    }

    async fn persist_key_rotation_view_anchor_locked(
        &self,
        context: &KeyRotationContext,
        view: u64,
        started_unix_ms: u64,
        update: KeyRotationPacemakerUpdate,
    ) -> anyhow::Result<()> {
        let mut schedule = self
            .proactive_refresh_schedule
            .lock()
            .await
            .clone()
            .context("dynamic key rotation has no durable proactive schedule")?;
        anyhow::ensure!(
            schedule.source_epoch == context.source().epoch
                && schedule.source_activation == context.source_activation()
                && schedule.target_epoch == Some(context.target_epoch()),
            "key-rotation pacemaker differs from its proactive schedule"
        );
        anyhow::ensure!(
            schedule.due_unix_ms.is_some_and(|due| started_unix_ms >= due),
            "key-rotation view began before the proactive deadline"
        );
        match update {
            KeyRotationPacemakerUpdate::PreserveExponent => {
                if schedule.rotation_view == Some(view) {
                    // Duplicate ingress and restart recovery must not move a live view's deadline.
                    return Ok(());
                }
                anyhow::ensure!(
                    schedule.rotation_view.is_none_or(|anchored| view > anchored),
                    "key-rotation view anchor regressed"
                );
                schedule.rotation_view = Some(view);
                schedule.rotation_view_started_unix_ms = Some(
                    schedule
                        .rotation_view_started_unix_ms
                        .map_or(started_unix_ms, |previous| previous.max(started_unix_ms)),
                );
            }
            KeyRotationPacemakerUpdate::AdvanceTimeout => {
                anyhow::ensure!(
                    schedule.rotation_view == Some(view)
                        && schedule.rotation_view_started_unix_ms.is_some(),
                    "key-rotation timeout differs from its anchored view"
                );
                schedule.rotation_view_started_unix_ms = Some(
                    schedule
                        .rotation_view_started_unix_ms
                        .expect("presence was checked above")
                        .max(started_unix_ms),
                );
                schedule.rotation_timeout_exponent =
                    schedule.rotation_timeout_exponent.saturating_add(1);
            }
        }
        self.persist_proactive_refresh_schedule_locked(schedule).await
    }

    async fn ensure_key_rotation_started(
        self: &Arc<Self>,
        source: &EpochPublic,
        now_unix_ms: u64,
    ) -> anyhow::Result<()> {
        let context = self
            .key_rotation_context_for_source(source)?
            .context("active epoch does not admit receiver-key rotation")?;
        let source_member = context.source().member(self.party).ok();
        let target_member = context.target_policy().eligible().member(self.party).ok();
        anyhow::ensure!(
            source_member.is_some() || target_member.is_some(),
            "party is not a source or target member for receiver-key rotation"
        );

        if source_member.is_some() {
            let existing_view = {
                let live = self.key_rotation.lock().await;
                if let Some(runtime) = live.as_ref() {
                    anyhow::ensure!(
                        runtime.round.context() == &context,
                        "another key-rotation round is still live"
                    );
                    Some(runtime.round.view())
                } else {
                    None
                }
            };
            if let Some(view) = existing_view {
                let schedule = self
                    .proactive_refresh_schedule
                    .lock()
                    .await
                    .clone()
                    .context("key rotation has no durable proactive schedule")?;
                if schedule.rotation_view != Some(view)
                    || schedule.rotation_view_started_unix_ms.is_none()
                {
                    self.persist_key_rotation_view_anchor(
                        &context,
                        view,
                        now_unix_ms,
                        KeyRotationPacemakerUpdate::PreserveExponent,
                    )
                    .await?;
                }
                return Ok(());
            }
        } else {
            let joining = self.joining_key_rotation.lock().await;
            if let Some(joining) = joining.as_ref() {
                anyhow::ensure!(
                    joining.context == context,
                    "another joining key rotation is still live"
                );
                return Ok(());
            }
        }

        let target_capability = match target_member {
            Some(member) => Some(
                self.protocol_store
                    .load_or_create_epoch_advertisement_identity(
                        context.target_epoch(),
                        &self.signing_seed,
                        member.signing_key,
                        &mut OsRng,
                    )
                    .await?,
            ),
            None => None,
        };

        if source_member.is_none() {
            let capability = target_capability
                .as_ref()
                .context("joining target lacks advertisement identity")?;
            let pending = pending_key_rotation_advertisements(&context, capability)?
                .into_iter()
                .map(|message| (message.id, message))
                .collect();
            let mut joining = self.joining_key_rotation.lock().await;
            anyhow::ensure!(joining.is_none(), "joining key-rotation start raced another start");
            *joining = Some(JoiningKeyRotation { context, pending_advertisements: pending });
            return Ok(());
        }

        // Preserve the authenticated source record until the handoff is certified. Successor
        // selection itself can only use the independently persisted advertised candidate.
        let source_identity = self.identity(context.source().epoch)?;
        self.protocol_store
            .save_epoch_identity_secret(&source_identity.export_encryption_secret(), &mut OsRng)
            .await?;
        drop(source_identity);

        let runtime =
            if let Some(stored) = self.protocol_store.load_key_rotation_round(&context).await? {
                if let Some(capability) = target_capability.as_ref() {
                    anyhow::ensure!(
                        stored.round.advertised_key(self.party)?
                            == Some(capability.identity().encryption_public_key()),
                        "restored key-rotation round differs from the durable local candidate"
                    );
                } else {
                    anyhow::ensure!(
                        stored.round.advertised_key(self.party)?.is_none(),
                        "source-only party restored an impossible target advertisement"
                    );
                }
                LiveKeyRotation { round: stored.round, revision: stored.metadata.revision }
            } else {
                let mut round = KeyRotationRound::new(context.clone(), self.party)?;
                if let Some(capability) = target_capability.as_ref() {
                    round.advertise(capability)?;
                }
                let metadata = self
                    .protocol_store
                    .save_key_rotation_round(&context, 0, &round, &mut OsRng)
                    .await?;
                LiveKeyRotation { round, revision: metadata.revision }
            };
        let certificate = runtime.round.certificate();
        {
            let mut live = self.key_rotation.lock().await;
            anyhow::ensure!(live.is_none(), "key-rotation start raced another local start");
            *live = Some(runtime);
        }
        self.persist_key_rotation_view_anchor(
            &context,
            self.key_rotation
                .lock()
                .await
                .as_ref()
                .context("key rotation disappeared after start")?
                .round
                .view(),
            now_unix_ms,
            KeyRotationPacemakerUpdate::PreserveExponent,
        )
        .await?;
        if let Some(certificate) = certificate {
            self.finalize_certified_key_rotation(context, certificate, true).await?;
        }
        Ok(())
    }

    async fn finalize_certified_key_rotation(
        self: &Arc<Self>,
        context: KeyRotationContext,
        certificate: KeyRotationCertificate,
        launch_avss: bool,
    ) -> anyhow::Result<()> {
        let target = certificate.verify(&context)?;
        self.protocol_store
            .save_key_rotation_certificate(&context, &certificate, &mut OsRng)
            .await?;
        if let Ok(target_member) = target.member(self.party) {
            let candidate = self
                .protocol_store
                .load_or_create_epoch_identity_secret(context.target_epoch(), &mut OsRng)
                .await?;
            let promoted = self
                .protocol_store
                .promote_certified_epoch_identity_secret(
                    &context,
                    &certificate,
                    &candidate,
                    &mut OsRng,
                )
                .await?;
            let identity = self.identity_from_epoch_secret(
                &promoted,
                target_member.signing_key,
                target_member.encryption_key,
            )?;
            self.install_certified_or_matching_identity(context.target_epoch(), identity, true)?;
        }
        self.register_certified_key_rotation(context.clone(), certificate)?;
        {
            let mut joining = self.joining_key_rotation.lock().await;
            if joining.as_ref().is_some_and(|pending| pending.context == context) {
                joining.take();
            }
        }

        if !launch_avss || context.source().member(self.party).is_err() {
            return Ok(());
        }
        let source = self.active_epoch_public().await?;
        anyhow::ensure!(
            source.committee.digest() == context.source().digest()
                && source.activation_digest()? == context.source_activation(),
            "certified key rotation does not extend the active epoch"
        );
        let transition = self
            .configured_proactive_refresh_transition(&source)?
            .context("certified receiver-key rotation did not materialize successor AVSS")?;
        anyhow::ensure!(
            transition.target.digest() == target.digest(),
            "certified AVSS target differs from receiver-key rotation"
        );
        if expected_avss_dealers(&transition).contains(&self.party) {
            let already_started = self.avss.lock().await.contains_key(&transition.session);
            if !already_started {
                let _ = avss_start(State(self.clone()), Json(AvssStartRequest { transition }))
                    .await
                    .map_err(|error| error.0)?;
            }
        }
        Ok(())
    }

    async fn retire_key_rotation_after_activation(
        &self,
        activated: &EpochPublic,
    ) -> anyhow::Result<()> {
        let rotation = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
            .get(&activated.committee.epoch)
            .cloned();
        let Some(rotation) = rotation else {
            return Ok(());
        };
        anyhow::ensure!(
            rotation.target.digest() == activated.committee.digest(),
            "activated committee differs from its key-rotation certificate"
        );

        let rotation_key = crate::storage::KeyRotationRoundKey {
            target_epoch: rotation.context.target_epoch(),
            context_digest: rotation.context.digest(),
        };
        if tokio::fs::try_exists(self.protocol_store.key_rotation_round_path(rotation_key)).await? {
            self.protocol_store
                .retire_key_rotation_round(&rotation.context, &rotation.certificate, &mut OsRng)
                .await?;
        }
        {
            let mut live = self.key_rotation.lock().await;
            match live.as_ref() {
                Some(runtime) if runtime.round.context() == &rotation.context => {
                    anyhow::ensure!(
                        runtime.round.certificate().as_ref() == Some(&rotation.certificate),
                        "activated key rotation differs from the live reducer"
                    );
                    live.take();
                }
                Some(_) => anyhow::bail!("another key-rotation round is live at activation"),
                None => {}
            }
        }
        {
            let mut joining = self.joining_key_rotation.lock().await;
            if joining.as_ref().is_some_and(|pending| pending.context == rotation.context) {
                joining.take();
            }
        }
        Ok(())
    }

    /// Erase the retired X25519 source key only after `retire_epoch` has certified the old-quorum
    /// deposit handoff. The stable signing identity remains available through the successor, so
    /// portable old-epoch obligations cannot be stranded by an eager encryption-key retirement.
    async fn retire_key_rotation_source_identity_after_handoff(
        &self,
        activated: &EpochPublic,
    ) -> anyhow::Result<()> {
        let rotation = {
            let rotations = self
                .certified_key_rotations
                .read()
                .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
            rotations.get(&activated.committee.epoch).cloned()
        };
        let Some(rotation) = rotation else {
            return Ok(());
        };
        let Ok(source_member) = rotation.context.source().member(self.party) else {
            // A target-only joiner has no predecessor receiver secret to erase.
            return Ok(());
        };
        anyhow::ensure!(
            rotation
                .target
                .member(self.party)
                .map_or(true, |target| target.encryption_key != source_member.encryption_key),
            "certified successor illegally carried a source receiver key"
        );
        self.drain_epoch_identity_arcs(&BTreeSet::from([rotation.context.source().epoch])).await?;
        self.protocol_store
            .retire_epoch_identity_secret(&rotation.context, &rotation.certificate, &mut OsRng)
            .await?;
        Ok(())
    }

    async fn scheduled_key_rotation_source(&self) -> anyhow::Result<EpochPublic> {
        let schedule = self
            .proactive_refresh_schedule
            .lock()
            .await
            .clone()
            .context("key rotation has no durable proactive schedule")?;
        let source = if let Some(source) = self
            .activations
            .read()
            .await
            .get(&schedule.source_epoch)
            .map(|activation| activation.public.clone())
        {
            source
        } else {
            self.deposit_targets
                .read()
                .await
                .get(&schedule.source_epoch)
                .cloned()
                .context("key-rotation source activation is unavailable")?
        };
        anyhow::ensure!(
            source.activation_digest()? == schedule.source_activation,
            "key-rotation source differs from its durable schedule"
        );
        Ok(source)
    }

    async fn handle_key_rotation_wire(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        wire: KeyRotationWire,
        now_unix_ms: u64,
    ) -> anyhow::Result<()> {
        if let KeyRotationWire::Certificate(certificate) = &wire {
            let rotations = self
                .certified_key_rotations
                .read()
                .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
                .values()
                .cloned()
                .collect::<Vec<_>>();
            if rotations.iter().any(|rotation| {
                rotation.certificate == *certificate
                    && certificate.verify(&rotation.context).is_ok()
            }) {
                // Immutable certificate gossip remains idempotent after reducer retirement and
                // across any number of later epoch activations.
                return Ok(());
            }
        }
        let source = self.scheduled_key_rotation_source().await?;
        let context = self
            .key_rotation_context_for_source(&source)?
            .context("active epoch does not admit receiver-key rotation")?;
        let current_source_certificate = match &wire {
            KeyRotationWire::Certificate(certificate) => {
                anyhow::ensure!(
                    context.is_participant(authenticated_party),
                    "key-rotation certificate sender is not a transition participant"
                );
                certificate.verify(&context)?;
                true
            }
            _ => false,
        };
        let schedule = self
            .proactive_refresh_schedule
            .lock()
            .await
            .clone()
            .context("key rotation has no durable proactive schedule")?;
        anyhow::ensure!(
            schedule.source_epoch == source.committee.epoch
                && schedule.source_activation == source.activation_digest()?
                && schedule.target_epoch == Some(context.target_epoch()),
            "key rotation differs from its durable proactive schedule"
        );
        let due_unix_ms = schedule.due_unix_ms.context("key rotation has no deadline")?;
        anyhow::ensure!(
            due_unix_ms != ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS,
            "key rotation is not due yet: proactive refresh is held for exact-epoch acceptance"
        );
        anyhow::ensure!(
            current_source_certificate || now_unix_ms >= due_unix_ms,
            "key rotation is not due yet"
        );
        if let KeyRotationWire::Certificate(certificate) = &wire {
            return self.finalize_certified_key_rotation(context, certificate.clone(), true).await;
        }
        context.source().member(self.party)?;
        self.ensure_key_rotation_started(&source, now_unix_ms.max(due_unix_ms)).await?;
        let identity = self.identity(context.source().epoch)?;
        let (certificate, entered_view) = {
            let mut live = self.key_rotation.lock().await;
            let runtime = live.as_mut().context("key rotation is not initialized")?;
            anyhow::ensure!(runtime.round.context() == &context, "key-rotation context changed");
            let before = runtime.round.clone();
            let before_view = before.view();
            let step = runtime.round.handle_wire(authenticated_party, wire, &identity)?;
            if runtime.round != before {
                let revision =
                    runtime.revision.checked_add(1).context("key-rotation revision exhausted")?;
                if let Err(error) = self
                    .protocol_store
                    .save_key_rotation_round(&context, revision, &runtime.round, &mut OsRng)
                    .await
                {
                    runtime.round = before;
                    return Err(error.into());
                }
                runtime.revision = revision;
            }
            let entered_view =
                (runtime.round.view() != before_view).then_some(runtime.round.view());
            (step.committed.or_else(|| runtime.round.certificate()), entered_view)
        };
        drop(identity);
        if let Some(view) = entered_view {
            self.persist_key_rotation_view_anchor(
                &context,
                view,
                now_unix_ms,
                KeyRotationPacemakerUpdate::PreserveExponent,
            )
            .await?;
        }
        if let Some(certificate) = certificate {
            self.finalize_certified_key_rotation(context, certificate, true).await?;
        }
        Ok(())
    }

    /// Apply one mutually authenticated peer request to this party's durable reducers.
    ///
    /// The QUIC layer has already enforced frame/body limits and bound `authenticated_party` to a
    /// pinned leaf certificate. This adapter performs exact canonical protocol decoding and binds
    /// the TLS identity to the inner signed sender before invoking the same handlers used by the
    /// typed protocol handlers. Handler output is intentionally omitted: any generated AVSS or
    /// QUAL effects were atomically added to the durable peer outbox before success is returned.
    pub async fn handle_quic_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        request: PeerRequest,
    ) -> PeerResponse {
        self.authenticated_quic_ingress.fetch_add(1, Ordering::AcqRel);
        // Peer dispatch spans every protocol reducer and consequently has a large concrete
        // future. Erase that storage here so neither an inbound QUIC task nor durable loopback
        // relay embeds the entire dispatch state machine in its own worker-stack poll path.
        match Box::pin(self.dispatch_peer_request(authenticated_party, request, false)).await {
            Ok(body) => PeerResponse::Success { body },
            Err(error) => quic_peer_rejection(error),
        }
    }

    pub(crate) fn record_authenticated_quic_response(&self) {
        self.authenticated_quic_responses.fetch_add(1, Ordering::AcqRel);
    }

    /// Apply one durable loopback effect without manufacturing a network identity. Only AVSS and
    /// QUAL messages whose signed inner sender is this party are accepted. Keeping this path
    /// separate from [`Self::handle_quic_peer_request`] prevents a transport bug from treating a
    /// self-issued message as evidence of a mutually authenticated remote connection.
    pub async fn handle_local_peer_request(self: &Arc<Self>, request: PeerRequest) -> PeerResponse {
        if matches!(
            request,
            PeerRequest::Epoch { operation: EpochOperation::Activate | EpochOperation::Retire, .. }
        ) {
            return PeerResponse::Rejected {
                code: RejectionCode::InvalidRequest,
                retryable: false,
                message: "epoch loopback requests are not enabled".to_owned(),
            };
        }
        match Box::pin(self.dispatch_peer_request(self.party, request, true)).await {
            Ok(body) => PeerResponse::Success { body },
            Err(error) => quic_peer_rejection(error),
        }
    }

    async fn dispatch_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        request: PeerRequest,
        allow_local: bool,
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            allow_local == (authenticated_party == self.party),
            "peer dispatch locality does not match the authenticated party"
        );
        anyhow::ensure!(
            allow_local || authenticated_party != self.party,
            "peer request cannot authenticate as self"
        );
        self.scenario.party(authenticated_party)?;
        match request {
            PeerRequest::Avss { operation: AvssOperation::Deliver, body } => {
                Box::pin(self.dispatch_avss_peer_request(authenticated_party, body)).await
            }
            PeerRequest::Qual { operation: QualOperation::Deliver, body } => {
                Box::pin(self.dispatch_qual_peer_request(authenticated_party, body)).await
            }
            PeerRequest::Epoch { operation, body } => {
                Box::pin(self.dispatch_epoch_peer_request(authenticated_party, operation, body))
                    .await
            }
            PeerRequest::KeyRotation { operation, body } => {
                Box::pin(self.dispatch_key_rotation_peer_request(
                    authenticated_party,
                    operation,
                    body,
                ))
                .await
            }
            PeerRequest::Deposit { operation, body } => {
                Box::pin(self.dispatch_deposit_peer_request(authenticated_party, operation, body))
                    .await
            }
        }
    }

    async fn dispatch_avss_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        body: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let request: AvssDeliverRequest = decode_canonical_postcard(&body)?;
        validate_avss_transition(self, &request.transition)?;
        ensure_relevant_transition_peer(authenticated_party, &request.transition)?;
        anyhow::ensure!(
            request.wire.envelope.from == authenticated_party,
            "TLS party differs from the inner AVSS sender"
        );
        let _response =
            avss_deliver(State(self.clone()), Json(request)).await.map_err(|error| error.0)?;
        Ok(Vec::new())
    }

    async fn dispatch_qual_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        body: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let request: QualDeliverRequest = decode_canonical_postcard(&body)?;
        validate_avss_transition(self, &request.transition)?;
        anyhow::ensure!(
            request.transition.target.member(authenticated_party).is_ok(),
            "QUAL TLS party is not a target-committee peer"
        );
        anyhow::ensure!(
            request.wire.envelope.from == authenticated_party,
            "TLS party differs from the inner QUAL sender"
        );
        let _response =
            qual_deliver(State(self.clone()), Json(request)).await.map_err(|error| error.0)?;
        Ok(Vec::new())
    }

    async fn dispatch_epoch_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        operation: EpochOperation,
        body: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        match operation {
            EpochOperation::Acknowledge => {
                let request: ActivationAckDeliverRequest = decode_canonical_postcard(&body)?;
                validate_avss_transition(self, &request.transition)?;
                request.transition.target.member(authenticated_party)?;
                anyhow::ensure!(
                    request.acknowledgement.from == authenticated_party,
                    "TLS party differs from the inner activation acknowledgement sender"
                );
                boxed_activation_ack_deliver(self.clone(), request).await?;
                Ok(Vec::new())
            }
            EpochOperation::Activate => {
                let request: ActivateEpochRequest = decode_canonical_postcard(&body)?;
                validate_avss_transition(self, &request.transition)?;
                ensure_relevant_transition_peer(authenticated_party, &request.transition)?;
                let _response = boxed_activate_epoch(State(self.clone()), Json(request))
                    .await
                    .map_err(|error| error.0)?;
                Ok(Vec::new())
            }
            EpochOperation::Retire => {
                let request: RetireEpochRequest = decode_canonical_postcard(&body)?;
                validate_avss_transition(self, &request.transition)?;
                ensure_relevant_transition_peer(authenticated_party, &request.transition)?;
                let _status = boxed_retire_epoch(State(self.clone()), Json(request))
                    .await
                    .map_err(|error| error.0)?;
                Ok(Vec::new())
            }
            EpochOperation::Observe => {
                let request: ActivateEpochRequest = decode_canonical_postcard(&body)?;
                anyhow::ensure!(
                    request.transition.target.member(self.party).is_err()
                        && request
                            .transition
                            .old
                            .as_ref()
                            .is_none_or(|old| old.committee.member(self.party).is_err()),
                    "transition participant must install or retire through its stateful epoch operation"
                );
                boxed_observe_epoch_certificate(self, request).await?;
                Ok(Vec::new())
            }
            EpochOperation::History => {
                let query: EpochHistoryCatchupQuery = decode_canonical_postcard(&body)?;
                let reply = self.handle_epoch_history_query(authenticated_party, query).await?;
                Ok(postcard::to_allocvec(&reply)?)
            }
        }
    }

    async fn dispatch_key_rotation_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        operation: KeyRotationOperation,
        body: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let wire = operation.decode_wire(&body)?;
        self.handle_key_rotation_wire(authenticated_party, wire, unix_time_millis()?).await?;
        Ok(Vec::new())
    }

    async fn dispatch_deposit_peer_request(
        self: &Arc<Self>,
        authenticated_party: PartyId,
        operation: DepositOperation,
        body: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        let deposit = self.deposit.as_ref().context("deposit wallet service is not enabled")?;
        Box::pin(self.ensure_deposit_initialized()).await?;
        let mut response_body = Vec::new();
        match operation {
            DepositOperation::Allocate => {
                let wire: DepositAllocateWire = decode_canonical_postcard(&body)?;
                anyhow::ensure!(
                    matches!(&wire.statement.payload, LedgerPayload::Allocation(_)),
                    "deposit operation differs from its statement payload"
                );
                let identity = self.identity(wire.statement.issuer_epoch)?;
                deposit
                    .handle_allocate(authenticated_party, wire, unix_time_seconds()?, &identity)
                    .await?;
            }
            DepositOperation::Handoff | DepositOperation::ConsolidationCompletion => {
                let wire: DepositAllocateWire = decode_canonical_postcard(&body)?;
                anyhow::ensure!(
                    matches!(
                        (operation, &wire.statement.payload),
                        (DepositOperation::Handoff, LedgerPayload::HandoffFence(_))
                            | (DepositOperation::Handoff, LedgerPayload::Handoff(_))
                            | (
                                DepositOperation::ConsolidationCompletion,
                                LedgerPayload::ConsolidationCompletion(_)
                            )
                            | (
                                DepositOperation::ConsolidationCompletion,
                                LedgerPayload::ConsolidationAbandonment(_)
                            )
                            | (
                                DepositOperation::ConsolidationCompletion,
                                LedgerPayload::LateConsolidationSettlement(_)
                            )
                    ),
                    "deposit operation differs from its statement payload"
                );
                let identity = self.identity(wire.statement.issuer_epoch)?;
                let transition = self.consolidation_transition.lock().await;
                deposit
                    .handle_allocate(authenticated_party, wire, unix_time_seconds()?, &identity)
                    .await?;
                self.restore_consolidation_session_closures(&transition, deposit).await?;
            }
            DepositOperation::Attest => {
                let wire: DepositAttestationWire = decode_canonical_postcard(&body)?;
                let identity = self.identity(wire.statement.issuer_epoch)?;
                let transition = self.consolidation_transition.lock().await;
                deposit
                    .handle_attestation(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
                self.restore_consolidation_session_closures(&transition, deposit).await?;
            }
            DepositOperation::Certificate => {
                let wire: DepositCertificateWire = decode_canonical_postcard(&body)?;
                let identity = self.identity(wire.entry.statement.issuer_epoch)?;
                let transition = self.consolidation_transition.lock().await;
                deposit
                    .handle_certificate(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
                self.restore_consolidation_session_closures(&transition, deposit).await?;
            }
            DepositOperation::DepositObservation => {
                let wire: DepositObservationWire = decode_canonical_postcard(&body)?;
                let identity = self.identity(wire.statement.issuer_epoch())?;
                deposit
                    .handle_deposit_observation(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::DepositObservationAttest => {
                let wire: DepositObservationAttestationWire = decode_canonical_postcard(&body)?;
                let identity = self.identity(wire.statement.issuer_epoch())?;
                deposit
                    .handle_deposit_observation_attestation(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::DepositObservationCertificate => {
                let wire: DepositObservationCertificateWire = decode_canonical_postcard(&body)?;
                let identity = self.identity(wire.observation.statement.issuer_epoch())?;
                deposit
                    .handle_deposit_observation_certificate(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::IndexCheckpointAttest => {
                let wire = DepositIndexCheckpointAttestWire::from_bytes(&body)?;
                let identity = self.identity(wire.statement().context().epoch())?;
                deposit
                    .handle_index_checkpoint_attest(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::IndexCheckpointCertificate => {
                let wire = DepositIndexCheckpointCertificateWire::from_bytes(&body)?;
                deposit
                    .handle_index_checkpoint_certificate(
                        authenticated_party,
                        wire,
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::DepositObservationIndexCheckpointAttest => {
                let wire = DepositObservationIndexCheckpointAttestWire::from_bytes(&body)?;
                let identity = self.identity(wire.statement().context().epoch())?;
                deposit
                    .handle_deposit_observation_index_checkpoint_attest(
                        authenticated_party,
                        wire,
                        identity.as_ref(),
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::DepositObservationIndexCheckpointCertificate => {
                let wire = DepositObservationIndexCheckpointCertificateWire::from_bytes(&body)?;
                deposit
                    .handle_deposit_observation_index_checkpoint_certificate(
                        authenticated_party,
                        wire,
                        unix_time_seconds()?,
                    )
                    .await?;
            }
            DepositOperation::SyncHead => {
                let request = DepositSyncHeadRequest::from_bytes(&body)?;
                let advertisement = deposit.deposit_sync_advertisement(request.context()).await?;
                response_body = advertisement.to_bytes(request)?;
            }
            DepositOperation::SyncObjects => {
                let context = DepositSyncObjectPageRequest::context_from_bytes(&body)?;
                let advertisement = deposit.deposit_sync_advertisement(context).await?;
                let request = DepositSyncObjectPageRequest::from_bytes(&advertisement, &body)?;
                let page = deposit
                    .serve_deposit_sync_objects(authenticated_party, &advertisement, &request)
                    .await?;
                response_body = page.to_bytes(&request, &advertisement)?;
            }
            DepositOperation::Consolidation => {
                let wire = ByzantineConsolidationWireMessage::decode(&body)?;
                wire.validate_authenticated_route(authenticated_party, self.party)?;
                anyhow::ensure!(
                    !matches!(wire, ByzantineConsolidationWireMessage::Ack(_)),
                    "Byzantine consolidation ACK is a response body, not a request"
                );
                let _transition = self.consolidation_transition.lock().await;
                let acknowledgement = match deposit
                    .acknowledge_sealed_byzantine_consolidation(authenticated_party, &wire)
                    .await?
                {
                    Some(acknowledgement) => acknowledgement,
                    None => {
                        self.restore_consolidation_session_closures(&_transition, deposit).await?;
                        let epoch = match &wire {
                            ByzantineConsolidationWireMessage::Consensus(message) => {
                                message.slot().committee().epoch
                            }
                            ByzantineConsolidationWireMessage::CertifiedIntent(message) => {
                                message.binding().attempt().epoch()
                            }
                            ByzantineConsolidationWireMessage::Preprocess(message) => {
                                message.binding().attempt().epoch()
                            }
                            ByzantineConsolidationWireMessage::KeyImageBinding(message) => {
                                message.binding().attempt().epoch()
                            }
                            ByzantineConsolidationWireMessage::Share(message) => {
                                message.binding().attempt().epoch()
                            }
                            ByzantineConsolidationWireMessage::Candidate(message) => {
                                message.binding().attempt().epoch()
                            }
                            ByzantineConsolidationWireMessage::Ack(_) => {
                                unreachable!("rejected")
                            }
                        };
                        let identity = self.identity(epoch)?;
                        deposit
                            .accept_byzantine_consolidation(
                                identity.as_ref(),
                                authenticated_party,
                                wire,
                                unix_time_millis()?,
                            )
                            .await?
                    }
                };
                self.restore_consolidation_session_closures(&_transition, deposit).await?;
                // Service success proves the exact effect survived snapshot readback.
                // Only this typed full-delivery ACK may retire the sender's outbox item.
                response_body = ByzantineConsolidationWireMessage::Ack(acknowledgement).encode()?;
            }
            DepositOperation::ClientRequest => {
                let wire: DepositClientRequestWire = decode_canonical_postcard(&body)?;
                let epoch = deposit.active_epoch().await?;
                deposit
                    .handle_client_request(
                        authenticated_party,
                        wire,
                        unix_time_millis()?,
                        self.identity(epoch)?.as_ref(),
                    )
                    .await?;
            }
            DepositOperation::ConsolidationAbandonment => {
                anyhow::ensure!(
                    body.len() <= MAX_CONSOLIDATION_ABANDONMENT_MESSAGE_BYTES,
                    "consolidation abandonment message exceeds its hard bound"
                );
                let epoch = deposit.active_epoch().await?;
                let transition = self.consolidation_transition.lock().await;
                deposit
                    .accept_consolidation_abandonment_observation(
                        self.identity(epoch)?.as_ref(),
                        authenticated_party,
                        &body,
                    )
                    .await?;
                self.restore_consolidation_session_closures(&transition, deposit).await?;
            }
            operation @ (DepositOperation::ConsensusProposal
            | DepositOperation::ConsensusMessage
            | DepositOperation::ConsensusCertificate) => {
                let wire: DepositConsensusWire = decode_canonical_postcard(&body)?;
                let epoch = deposit.active_epoch().await?;
                let transition = self.consolidation_transition.lock().await;
                deposit
                    .handle_consensus(
                        authenticated_party,
                        operation,
                        wire,
                        unix_time_millis()?,
                        self.identity(epoch)?.as_ref(),
                    )
                    .await?;
                // Completion BA can atomically burn a newer attempt. Reconcile permanent
                // high-water/session closures and erase any volatile signer before this
                // gate admits another signing message.
                self.restore_consolidation_session_closures(&transition, deposit).await?;
            }
        }
        // The operation above has already crossed its durable reducer boundary. Retry the exact
        // same idempotent successor hook, but do not turn the expected absence of the next n-f
        // handoff certificate into a negative ACK for the accepted operation.
        if !matches!(operation, DepositOperation::SyncHead | DepositOperation::SyncObjects) {
            Box::pin(self.reconcile_deposit_targets_allow_gap()).await?;
        }
        Ok(response_body)
    }

    pub async fn serve(
        self: Arc<Self>,
        listen: SocketAddr,
        authenticator: BearerAuthenticator,
    ) -> anyhow::Result<()> {
        let app = self.clone().http_router(authenticator);
        let listener = tokio::net::TcpListener::bind(listen).await?;
        tracing::info!(%listen, "party control service listening");
        let result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await;
        result?;
        Ok(())
    }

    fn http_router(self: Arc<Self>, authenticator: BearerAuthenticator) -> Router {
        let mut admin = Router::new()
            .route("/v1/status", get(status))
            .route("/v1/avss/start", post(avss_start));
        if self.acceptance_consolidation_gate_enabled {
            admin = admin
                .route("/v1/acceptance/consolidation-gate", post(acceptance_consolidation_gate));
        }
        if self.acceptance_consolidation_bootstrap_gate_enabled {
            admin = admin.route(
                "/v1/acceptance/consolidation-bootstrap-gate",
                post(acceptance_consolidation_bootstrap_gate),
            );
        }
        if self.acceptance_protocol_fault_gate_enabled {
            admin = admin
                .route("/v1/acceptance/protocol-fault-gate", post(acceptance_protocol_fault_gate));
        }
        if self.acceptance_proactive_refresh_hold_enabled {
            admin = admin
                .route(
                    "/v1/acceptance/proactive-refresh/release",
                    post(acceptance_proactive_refresh_release),
                )
                .route("/v1/acceptance/driver-latch", post(acceptance_driver_latch))
                .route(
                    "/v1/acceptance/deposit-checkpoint-gate",
                    post(acceptance_deposit_checkpoint_gate),
                );
        }
        admin =
            admin.route_layer(middleware::from_fn_with_state(authenticator.clone(), require_admin));
        let mut app = Router::new()
            .route("/healthz", get(health))
            .merge(admin)
            .layer(TraceLayer::new_for_http());
        if self.deposit.is_some() {
            let deposits = Router::new()
                .route("/v1/deposits/allocate", post(deposit_allocate))
                .route("/v1/deposits/status", post(deposit_status))
                .route("/v1/deposits/consolidations/status", post(deposit_consolidation_status))
                .route_layer(middleware::from_fn_with_state(authenticator, require_deposits));
            app = app.merge(deposits);
        }
        app.with_state(self)
    }

    fn identity(&self, epoch: u64) -> anyhow::Result<Arc<Identity>> {
        let retiring = self
            .retiring_identities
            .read()
            .map_err(|_| anyhow::anyhow!("retiring identity registry lock is poisoned"))?;
        anyhow::ensure!(!retiring.contains_key(&epoch), "epoch identity is retiring");
        let identity = self
            .identities
            .read()
            .map_err(|_| anyhow::anyhow!("identity registry lock is poisoned"))?
            .get(&epoch)
            .cloned()
            .context("missing epoch identity")?;
        drop(retiring);
        Ok(identity)
    }

    /// Stop new identity leases, then wait a bounded number of scheduler turns for every
    /// pre-existing Arc lease to drain. A busy epoch stays in `retiring_identities` and is never
    /// reinserted into the active registry; permanent storage erasure is retried by certificate
    /// gossip only after the final in-process secret owner has been dropped.
    async fn drain_epoch_identity_arcs(&self, epochs: &BTreeSet<u64>) -> anyhow::Result<()> {
        {
            let mut retiring = self
                .retiring_identities
                .write()
                .map_err(|_| anyhow::anyhow!("retiring identity registry lock is poisoned"))?;
            let mut active = self
                .identities
                .write()
                .map_err(|_| anyhow::anyhow!("identity registry lock is poisoned"))?;
            for epoch in epochs {
                if !retiring.contains_key(epoch) {
                    retiring.insert(*epoch, active.remove(epoch));
                }
            }
        }

        const IDENTITY_DRAIN_YIELDS: usize = 128;
        for _ in 0..IDENTITY_DRAIN_YIELDS {
            let pending = {
                let mut retiring = self
                    .retiring_identities
                    .write()
                    .map_err(|_| anyhow::anyhow!("retiring identity registry lock is poisoned"))?;
                let mut pending = 0_usize;
                for epoch in epochs {
                    let Some(identity) = retiring.remove(epoch) else {
                        continue;
                    };
                    let Some(identity) = identity else {
                        retiring.insert(*epoch, None);
                        continue;
                    };
                    match Arc::try_unwrap(identity) {
                        Ok(identity) => {
                            drop(identity);
                            retiring.insert(*epoch, None);
                        }
                        Err(identity) => {
                            pending = pending.saturating_add(1);
                            retiring.insert(*epoch, Some(identity));
                        }
                    }
                }
                pending
            };
            if pending == 0 {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
        let retiring = self
            .retiring_identities
            .read()
            .map_err(|_| anyhow::anyhow!("retiring identity registry lock is poisoned"))?;
        let pending = epochs
            .iter()
            .filter_map(|epoch| {
                retiring.get(epoch).and_then(|identity| {
                    identity
                        .as_ref()
                        .map(|identity| (*epoch, Arc::strong_count(identity).saturating_sub(1)))
                })
            })
            .collect::<Vec<_>>();
        anyhow::bail!("epoch identity leases are still live during retirement: {pending:?}")
    }

    fn install_certified_or_matching_identity(
        &self,
        epoch: u64,
        identity: Identity,
        certified_replacement: bool,
    ) -> anyhow::Result<Arc<Identity>> {
        anyhow::ensure!(identity.party() == self.party && identity.encryption_epoch() == epoch);
        let retiring = self
            .retiring_identities
            .read()
            .map_err(|_| anyhow::anyhow!("retiring identity registry lock is poisoned"))?;
        anyhow::ensure!(
            !retiring.contains_key(&epoch),
            "cannot install an identity whose epoch is retiring"
        );
        let mut identities = self
            .identities
            .write()
            .map_err(|_| anyhow::anyhow!("identity registry lock is poisoned"))?;
        if let Some(existing) = identities.get(&epoch) {
            anyhow::ensure!(
                existing.signing_public_key() == identity.signing_public_key(),
                "certified identity changed the stable signing key"
            );
            if existing.encryption_public_key() == identity.encryption_public_key() {
                return Ok(existing.clone());
            }
            anyhow::ensure!(
                certified_replacement,
                "uncertified dynamic identity conflicts with the installed candidate"
            );
        }
        let identity = Arc::new(identity);
        identities.insert(epoch, identity.clone());
        drop(identities);
        drop(retiring);
        Ok(identity)
    }

    fn trusted_committee_and_fault_bound(&self, epoch: u64) -> anyhow::Result<(Committee, u16)> {
        if epoch == 0 {
            return Ok((
                self.scenario.genesis_committee()?,
                self.scenario.committee_spec(0)?.fault_bound,
            ));
        }
        let rotations = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
        let rotation = rotations.get(&epoch).with_context(|| {
            format!("epoch {epoch} lacks a locally durable key-rotation certificate")
        })?;
        Ok((rotation.target.clone(), rotation.context.target_fault_bound()))
    }

    fn key_rotation_context_for_source(
        &self,
        source: &EpochPublic,
    ) -> anyhow::Result<Option<KeyRotationContext>> {
        source.validate()?;
        let target_epoch =
            source.committee.epoch.checked_add(1).context("key-rotation epoch exhausted")?;
        let (trusted_source, source_fault_bound) =
            self.trusted_committee_and_fault_bound(source.committee.epoch)?;
        anyhow::ensure!(
            trusted_source.digest() == source.committee.digest(),
            "key-rotation source committee differs from the certified chain"
        );
        let target_policy = if let Some(configured) =
            self.scenario.configured_key_rotation_target_policy(&source.committee)?
        {
            configured
        } else {
            let eligible = Committee {
                epoch: target_epoch,
                threshold: source.committee.threshold,
                members: self
                    .scenario
                    .parties
                    .iter()
                    .map(|party| Member {
                        id: party.id,
                        signing_key: party.signing_key.0,
                        encryption_key: eligibility_reference_key(
                            target_epoch,
                            party.id,
                            party.signing_key.0,
                        ),
                    })
                    .collect(),
            };
            KeyRotationTargetPolicy::new(
                &source.committee,
                eligible,
                source.committee.n(),
                source_fault_bound,
            )?
        };
        Ok(Some(KeyRotationContext::new(
            self.scenario.quic_network_id()?,
            source.committee.clone(),
            source.activation_digest()?,
            source_fault_bound,
            target_policy,
        )?))
    }

    fn register_certified_key_rotation(
        &self,
        context: KeyRotationContext,
        certificate: KeyRotationCertificate,
    ) -> anyhow::Result<Committee> {
        let target = certificate.verify(&context)?;
        let mut rotations = self
            .certified_key_rotations
            .write()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
        if let Some(existing) = rotations.get(&context.target_epoch()) {
            anyhow::ensure!(
                existing.context == context
                    && existing.target == target
                    && existing.certificate.semantic_digest(&existing.context)?
                        == certificate.semantic_digest(&context)?,
                "dynamic epoch is certified by another key-rotation decision"
            );
        } else {
            rotations.insert(
                context.target_epoch(),
                CertifiedKeyRotation { context, certificate, target: target.clone() },
            );
        }
        Ok(target)
    }

    fn validate_committee(&self, supplied: &Committee) -> anyhow::Result<()> {
        // `Committee::digest` assumes a previously validated canonical committee. Peer-supplied
        // transition bodies are untrusted even after mTLS authentication, so reject malformed
        // structure before either digest can reach that invariant.
        supplied.validate()?;
        let (expected, _) = self.trusted_committee_and_fault_bound(supplied.epoch)?;
        anyhow::ensure!(expected.digest() == supplied.digest(), "committee differs from scenario");
        Ok(())
    }

    async fn ensure_reshare_source_certified(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<()> {
        let Some(old) = transition.old.as_ref() else {
            return Ok(());
        };
        if self
            .activations
            .read()
            .await
            .get(&old.committee.epoch)
            .is_some_and(|activation| activation.public == *old)
        {
            return Ok(());
        }
        let activation_digest = old.activation_digest()?;
        let path =
            self.protocol_store.activation_certificate_path(old.committee.epoch, activation_digest);
        if tokio::fs::try_exists(path).await? {
            let bytes = self
                .protocol_store
                .load_activation_certificate(old.committee.epoch, activation_digest)
                .await?;
            let record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
            validate_avss_transition(self, &record.transition)?;
            verify_activation_certificate(
                self,
                &record.transition,
                &record.value,
                &record.acknowledgements,
            )?;
            anyhow::ensure!(record.value.public == *old, "reshare source certificate differs");
            return Ok(());
        }
        anyhow::bail!(
            "reshare source epoch lacks a locally durable authenticated activation certificate"
        )
    }

    /// Reconstruct the certified dynamic committee/identity chain before validating activation
    /// records or AVSS snapshots which may refer to those epochs. Every accepted registry entry
    /// comes from an immutable local certificate verified against the already trusted predecessor.
    async fn reconcile_certified_identity_retirements(
        &self,
        rotations: &[CertifiedKeyRotation],
    ) -> anyhow::Result<()> {
        let mut retired_epochs = BTreeSet::new();
        for rotation in rotations {
            let Ok(source_member) = rotation.context.source().member(self.party) else {
                continue;
            };
            anyhow::ensure!(
                rotation
                    .target
                    .member(self.party)
                    .map_or(true, |target| target.encryption_key != source_member.encryption_key),
                "certified receiver-key rotation carried a source key"
            );
            if let Some(retirement) = self
                .protocol_store
                .load_epoch_identity_retirement(
                    rotation.context.source().epoch,
                    source_member.encryption_key,
                )
                .await?
            {
                self.protocol_store.verify_epoch_identity_retirement(
                    retirement,
                    &rotation.context,
                    &rotation.certificate,
                )?;
                retired_epochs.insert(retirement.epoch);
            }
        }
        if !retired_epochs.is_empty() {
            self.drain_epoch_identity_arcs(&retired_epochs).await?;
        }
        Ok(())
    }

    async fn restore_authenticated_epoch_history(
        &self,
    ) -> anyhow::Result<Vec<ActivationCertificateRecord>> {
        let state = self.epoch_history.read().await.clone();
        let mut loaded = self.preload_epoch_history_reader(&state, None).await?;
        state.verify_restart(&loaded)?;

        // The single cold-boundary entry supplies the trusted committee/link checkpoint needed to
        // validate the bounded hot suffix without replaying the complete cold prefix.
        if let Some(boundary_epoch) = state.cold_through() {
            self.preload_epoch_history_index_path(&state, boundary_epoch, true, &mut loaded)
                .await?;
            let boundary = state
                .lookup(boundary_epoch, &loaded)?
                .context("epoch-history cold boundary disappeared")?;
            let bytes = self
                .load_epoch_history_object(boundary.activation_certificate(), &mut loaded)
                .await?;
            let record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
            let rotation = match boundary.key_rotation_certificate() {
                Some(reference) => {
                    Some(self.load_epoch_history_object(reference, &mut loaded).await?)
                }
                None => None,
            };
            self.register_history_key_rotation(&record, rotation.as_deref(), true)?;
            anyhow::ensure!(
                record.value.epoch == boundary_epoch
                    && record.value.history_link == boundary.consensus_link(),
                "epoch-history cold boundary certificate differs from its entry"
            );
            verify_activation_certificate(
                self,
                &record.transition,
                &record.value,
                &record.acknowledgements,
            )?;
            self.remember_certified_history_link(boundary.consensus_link())?;
        }

        let mut records = Vec::with_capacity(state.hot_entries().len());
        for entry in state.hot_entries() {
            let bytes =
                self.load_epoch_history_object(entry.activation_certificate(), &mut loaded).await?;
            let record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
            let rotation = match entry.key_rotation_certificate() {
                Some(reference) => {
                    Some(self.load_epoch_history_object(reference, &mut loaded).await?)
                }
                None => None,
            };
            self.register_history_key_rotation(&record, rotation.as_deref(), false)?;
            validate_avss_transition(self, &record.transition)?;
            verify_activation_certificate(
                self,
                &record.transition,
                &record.value,
                &record.acknowledgements,
            )?;
            anyhow::ensure!(
                record.value.epoch == entry.epoch()
                    && record.value.history_link == entry.consensus_link()
                    && record.value.activation_digest == entry.activation_digest()
                    && avss_transition_digest(&record.transition)? == entry.transition_digest(),
                "epoch-history hot activation differs from its authenticated entry"
            );
            self.remember_certified_history_link(entry.consensus_link())?;
            records.push(record);
        }
        Ok(records)
    }

    async fn restore_certified_key_rotation_chain(self: &Arc<Self>) -> anyhow::Result<()> {
        let history_records = self.restore_authenticated_epoch_history().await?;
        let certificate_keys = self
            .protocol_store
            .key_rotation_certificates_bounded(MAX_CURRENT_EPOCH_RECORDS)
            .await?;
        let mut remaining = certificate_keys.into_iter().collect::<BTreeSet<_>>();

        let known = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for rotation in known {
            let key = crate::storage::KeyRotationRoundKey {
                target_epoch: rotation.context.target_epoch(),
                context_digest: rotation.context.digest(),
            };
            if remaining.remove(&key) {
                let durable = self
                    .protocol_store
                    .load_key_rotation_certificate(&rotation.context)
                    .await?
                    .context("enumerated key-rotation certificate disappeared")?;
                anyhow::ensure!(
                    durable.semantic_digest(&rotation.context)?
                        == rotation.certificate.semantic_digest(&rotation.context)?,
                    "current key-rotation certificate differs from epoch history"
                );
            }
        }

        // At most one terminal rotation may be certified while its activation is still pending.
        if !remaining.is_empty() {
            anyhow::ensure!(
                remaining.len() == 1,
                "multiple unactivated key-rotation certificates are retained"
            );
            let source = history_records
                .last()
                .map(|record| record.value.public.clone())
                .context("unactivated key rotation lacks an authenticated source activation")?;
            let context = self
                .key_rotation_context_for_source(&source)?
                .context("retained key rotation is not the configured immediate successor")?;
            let expected = crate::storage::KeyRotationRoundKey {
                target_epoch: context.target_epoch(),
                context_digest: context.digest(),
            };
            anyhow::ensure!(
                remaining.remove(&expected),
                "retained key-rotation certificate is forked or non-contiguous"
            );
            let certificate = self
                .protocol_store
                .load_key_rotation_certificate(&context)
                .await?
                .context("enumerated terminal key-rotation certificate disappeared")?;
            self.register_certified_key_rotation(context, certificate)?;
        }
        anyhow::ensure!(remaining.is_empty(), "key-rotation certificate set has a gap or fork");

        let restored_rotations = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for rotation in &restored_rotations {
            let Ok(member) = rotation.target.member(self.party) else {
                continue;
            };
            if self
                .protocol_store
                .load_epoch_identity_retirement(rotation.target.epoch, member.encryption_key)
                .await?
                .is_some()
            {
                continue;
            }
            self.finalize_certified_key_rotation(
                rotation.context.clone(),
                rotation.certificate.clone(),
                false,
            )
            .await?;
        }
        self.reconcile_certified_identity_retirements(&restored_rotations).await?;
        Ok(())
    }

    async fn restore_live_key_rotation_for_active_epoch(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some(active_epoch) = *self.active_epoch.read().await else {
            return Ok(());
        };
        let source = self
            .activations
            .read()
            .await
            .get(&active_epoch)
            .map(|activation| activation.public.clone())
            .context("active epoch lacks activation metadata")?;
        let Some(context) = self.key_rotation_context_for_source(&source)? else {
            return Ok(());
        };
        let stored = match self.protocol_store.load_key_rotation_round(&context).await {
            Ok(stored) => stored,
            Err(StoreError::KeyRotationRoundRetired(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let Some(stored) = stored else {
            return Ok(());
        };
        anyhow::ensure!(self.key_rotation.lock().await.is_none(), "multiple live key rotations");

        let certificate = stored.round.certificate();
        *self.key_rotation.lock().await =
            Some(LiveKeyRotation { round: stored.round, revision: stored.metadata.revision });
        if let Some(certificate) = certificate {
            // Save/promote first: only a certificate-selected fresh candidate can become active.
            self.finalize_certified_key_rotation(context, certificate, false).await?;
        } else {
            let advertised_key = self
                .key_rotation
                .lock()
                .await
                .as_ref()
                .context("restored key rotation disappeared")?
                .round
                .advertised_key(self.party)?;
            if let Ok(target_member) = context.target_policy().eligible().member(self.party) {
                let expected_key = advertised_key
                    .context("restored overlap round lacks the local advertisement")?;
                let secret = self
                    .protocol_store
                    .load_epoch_identity_secret(context.target_epoch(), expected_key)
                    .await?
                    .context("restored key-rotation round lost its target identity secret")?;
                anyhow::ensure!(
                    target_member.signing_key == context.source().member(self.party)?.signing_key
                        && secret.public_key() == expected_key,
                    "restored overlap advertisement changed its identity"
                );
            } else {
                anyhow::ensure!(
                    advertised_key.is_none(),
                    "restored source-only round contains a local target advertisement"
                );
            }
        }
        Ok(())
    }

    // Each restoration phase below is constructed inside its own non-async helper frame (which is
    // popped before its boxed future is awaited) rather than as an inline `Box::pin(async { .. })`.
    // Inline blocks are still *built* in `restore_durable_state`'s own frame, so debug lowering
    // stacks every phase's spill space into one frame that can exhaust an ordinary 2 MiB Tokio
    // worker stack before the first I/O poll. Routing each phase through a helper leaves only an
    // eight-byte pointer per phase live in the driver.
    fn restore_durable_certificate_records(
        self: &Arc<Self>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = anyhow::Result<
                        Vec<(
                            crate::storage::ActivationCertificateKey,
                            ActivationCertificateRecord,
                        )>,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            self.restore_certified_key_rotation_chain().await?;
            let maximum = MAX_CURRENT_EPOCH_RECORDS;
            let mut keys = self.protocol_store.activation_certificates_bounded(maximum).await?;
            keys.sort_unstable_by_key(|key| key.epoch);
            let mut records = Vec::with_capacity(keys.len());
            let mut expected_indexes = BTreeMap::<ActivationTransitionKey, [u8; 32]>::new();
            let mut certified_epochs = BTreeSet::new();
            let mut certified_avss_sessions = BTreeMap::new();
            for key in keys {
                let bytes = self
                    .protocol_store
                    .load_activation_certificate(key.epoch, key.activation_digest)
                    .await?;
                let record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
                validate_avss_transition(self, &record.transition)?;
                anyhow::ensure!(record.value.epoch == key.epoch, "activation file epoch differs");
                anyhow::ensure!(
                    record.value.activation_digest == key.activation_digest,
                    "activation file digest differs"
                );
                verify_activation_certificate(
                    self,
                    &record.transition,
                    &record.value,
                    &record.acknowledgements,
                )?;
                self.remember_certified_history_link(record.value.history_link)?;
                let transition_key = ActivationTransitionKey {
                    epoch: record.transition.target.epoch,
                    transition_digest: avss_transition_digest(&record.transition)?,
                };
                anyhow::ensure!(
                    certified_epochs.insert(key.epoch),
                    "multiple durable activation certificates exist for epoch {}",
                    key.epoch
                );
                anyhow::ensure!(
                    expected_indexes.insert(transition_key, key.activation_digest).is_none(),
                    "multiple durable activation certificates exist for one transition"
                );
                anyhow::ensure!(
                    certified_avss_sessions
                        .insert(record.transition.session, transition_key.transition_digest)
                        .is_none(),
                    "multiple durable activation certificates use one AVSS session"
                );
                records.push((key, record));
            }

            // A crash after the current certificate fsync may lack its index. Authenticate every
            // retained certificate and every present index before creating that one missing entry;
            // malformed, dangling, extra, or conflicting metadata is never repaired implicitly.
            let existing_indexes =
                self.protocol_store.activation_transition_indexes_bounded(maximum).await?;
            let mut existing_by_transition = BTreeMap::new();
            for (transition, activation_digest) in existing_indexes {
                anyhow::ensure!(
                    existing_by_transition.insert(transition, activation_digest).is_none(),
                    "duplicate durable activation transition index"
                );
                anyhow::ensure!(
                    expected_indexes.get(&transition) == Some(&activation_digest),
                    "durable activation transition index is orphaned or conflicts with its certificate"
                );
            }
            for (transition, activation_digest) in &expected_indexes {
                if !existing_by_transition.contains_key(transition) {
                    self.protocol_store
                        .ensure_activation_transition_index(
                            *transition,
                            *activation_digest,
                            &mut OsRng,
                        )
                        .await?;
                }
            }
            let rebuilt_indexes = self
                .protocol_store
                .activation_transition_indexes_bounded(maximum)
                .await?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            anyhow::ensure!(
                rebuilt_indexes == expected_indexes,
                "durable activation transition index audit differs from verified certificates"
            );
            // Close the current write-order crash window: the indexed certificate is authoritative,
            // but the epoch-history snapshot may still be one revision behind. Replay only the
            // unique contiguous verified suffix before restoring any AVSS/session state.
            for (_, record) in &records {
                let tip = self.epoch_history.read().await.tip_epoch();
                if tip.is_none_or(|tip| record.value.epoch > tip) {
                    let expected = tip.map_or(Ok(0), |tip| {
                        tip.checked_add(1).context("epoch-history number exhausted")
                    })?;
                    anyhow::ensure!(
                        record.value.epoch == expected,
                        "retained activation certificates do not form a contiguous history suffix"
                    );
                    let encoded = postcard::to_allocvec(record)?;
                    self.persist_epoch_history_activation(
                        &record.transition,
                        &record.value,
                        &encoded,
                    )
                    .await?;
                }
            }
            let cold_through = self.epoch_history.read().await.cold_through();
            if let Some(cold) = cold_through {
                for (key, _) in &records {
                    if key.epoch <= cold {
                        self.prune_hot_epoch_records_after_history_cas(key.epoch).await?;
                    }
                }
            }
            certified_avss_sessions.retain(|session, _| {
                records.iter().any(|(_, record)| {
                    record.transition.session == *session
                        && cold_through.is_none_or(|cold| record.value.epoch > cold)
                })
            });
            // Only the fully authenticated certificate/index audit above may exempt a retained
            // catch-up run from the live reducer bound. The cache is reconstructed from permanent
            // evidence on every restart and never from session-state fields supplied by a peer.
            *self.certified_avss_sessions.write().await = certified_avss_sessions;
            // Rewrite every still-retained certified reducer before replaying any predecessor
            // share retirement. This closes the crash case where the activation certificate
            // reached disk but the process stopped before its plaintext snapshot was compacted.
            for (_, record) in &records {
                self.compact_certified_avss_transition(&record.transition).await?;
            }
            Ok::<_, anyhow::Error>(records)
        })
    }

    async fn restore_durable_state(self: &Arc<Self>) -> anyhow::Result<()> {
        let records = self.restore_durable_certificate_records().await?;
        self.restore_durable_certificate_replay_retirements(records).await?;
        self.restore_durable_sessions_and_gates().await?;

        let restored_terminal_rotation = self.key_rotation.lock().await.as_ref().and_then(|live| {
            live.round.certificate().map(|certificate| (live.round.context().clone(), certificate))
        });
        if let Some((context, certificate)) = restored_terminal_rotation {
            Box::pin(self.finalize_certified_key_rotation(context, certificate, true)).await?;
        }
        if self.deposit.is_some() && self.deposit_targets.read().await.contains_key(&0) {
            Box::pin(self.ensure_deposit_initialized()).await?;
            if let Err(error) = Box::pin(self.reconcile_deposit_targets()).await
                && !error.downcast_ref::<DepositServiceError>().is_some_and(|error| {
                    matches!(error, DepositServiceError::CertifiedHandoffUnavailable(_))
                })
            {
                return Err(error.context("cannot restore the certified deposit epoch chain"));
            }
        }
        Box::pin(self.restore_proactive_refresh_schedule(unix_time_millis()?)).await
    }

    // Certificate-replay retirement, kept under the same global lock order as the live path. This
    // matters for in-process restore tests and future reload support even though ordinary
    // construction has not exposed the Arc to background tasks yet.
    fn restore_durable_certificate_replay_retirements(
        self: &Arc<Self>,
        records: Vec<(crate::storage::ActivationCertificateKey, ActivationCertificateRecord)>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let consolidation_transition = self.consolidation_transition.lock().await;
            let epoch_transition = self.epoch_transition.lock().await;
            for (key, record) in records {
                let certified_root = self.remember_certified_deposit_target(&record.value).await?;
                if let Some(old) = &record.transition.old {
                    self.deposit_targets
                        .write()
                        .await
                        .entry(old.committee.epoch)
                        .or_insert_with(|| old.clone());
                }

                let local_target = record.transition.target.member(self.party).is_ok();
                let mut successor_ready = !local_target;
                if local_target && tokio::fs::try_exists(self.store.share_path(key.epoch)).await? {
                    if let Some(share) = self
                        .store
                        .load_if_active(key.epoch, record.transition.target.digest())
                        .await?
                    {
                        anyhow::ensure!(
                            share.public() == record.value.public,
                            "activated share differs from its certificate"
                        );
                        let response = InstallResponse {
                            party: self.party,
                            epoch: key.epoch,
                            public: record.value.public.clone(),
                            activation_digest: record.value.activation_digest,
                            avss_transcript_digest: record.value.avss_transcript_digest,
                            history_link: record.value.history_link,
                        };
                        self.epochs.write().await.insert(key.epoch, share);
                        self.activations.write().await.insert(key.epoch, response);
                        successor_ready = true;
                    }
                }

                // A durable valid successor certificate is also a durable retirement intent. An
                // overlapping party additionally proves the successor share is installed before the
                // old share is touched. The portable deposit gate runs first because an in-flight
                // old-epoch sweep may still need that share; after it succeeds, remove the old share
                // from the in-memory signing set before destroying the durable record.
                if successor_ready
                    && let Some(old) = &record.transition.old
                    && old.committee.member(self.party).is_ok()
                {
                    match self
                        .certify_deposit_handoff_before_share_retirement(
                            old,
                            &record.value.public,
                            certified_root,
                        )
                        .await
                    {
                        Ok(()) => {
                            self.drain_retiring_epoch_signers(
                                &consolidation_transition,
                                &epoch_transition,
                                old.committee.epoch,
                            )
                            .await?;
                            self.epochs.write().await.remove(&old.committee.epoch);
                            self.activations.write().await.remove(&old.committee.epoch);
                            if tokio::fs::try_exists(self.store.share_path(old.committee.epoch))
                                .await?
                            {
                                self.store
                                    .retire_share(ShareRetirement::for_certified_successor(
                                        old.committee.epoch,
                                        old.committee.digest(),
                                        record.value.epoch,
                                        record.value.activation_digest,
                                    )?)
                                    .await?;
                            }
                            self.retire_key_rotation_source_identity_after_handoff(
                                &record.value.public,
                            )
                            .await?;
                        }
                        Err(error) => {
                            tracing::warn!(
                                party = %self.party,
                                old_epoch = old.committee.epoch,
                                successor_epoch = record.value.epoch,
                                %error,
                                "retaining the obsolete share until all portable old-epoch obligations are certified"
                            );
                        }
                    }
                }
            }

            let active_epoch = self.epochs.read().await.keys().next_back().copied();
            *self.active_epoch.write().await = active_epoch;
            drop(epoch_transition);
            drop(consolidation_transition);

            if let Some(active_epoch) = active_epoch {
                let activated_dynamic = self
                    .deposit_targets
                    .read()
                    .await
                    .iter()
                    .filter(|(epoch, _)| **epoch <= active_epoch)
                    .map(|(_, public)| public.clone())
                    .collect::<Vec<_>>();
                for public in activated_dynamic {
                    self.retire_key_rotation_after_activation(&public).await?;
                }
            }

            Box::pin(self.restore_live_key_rotation_for_active_epoch()).await?;
            Ok::<(), anyhow::Error>(())
        })
    }

    // AVSS/session-state and acceptance-gate restoration phase.
    fn restore_durable_sessions_and_gates(
        self: &Arc<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async move {
            let (acceptance_gate_session, acceptance_gate_context) =
                acceptance_consolidation_gate_storage_key(
                    self.scenario.quic_network_id()?,
                    self.party,
                )?;
            let (acceptance_bootstrap_gate_session, acceptance_bootstrap_gate_context) =
                acceptance_consolidation_bootstrap_gate_storage_key(
                    self.scenario.quic_network_id()?,
                    self.party,
                )?;
            let (acceptance_protocol_gate_session, acceptance_protocol_gate_context) =
                acceptance_protocol_fault_gate_storage_key(
                    self.scenario.quic_network_id()?,
                    self.party,
                )?;
            let (acceptance_driver_latch_session, acceptance_driver_latch_context) =
                acceptance_driver_latch_storage_key(self.scenario.quic_network_id()?, self.party)?;
            let (acceptance_deposit_checkpoint_session, acceptance_deposit_checkpoint_context) =
                acceptance_deposit_checkpoint_gate_storage_key(
                    self.scenario.quic_network_id()?,
                    self.party,
                )?;
            for key in self.protocol_store.session_states().await? {
                if (key.session == acceptance_gate_session
                    && key.context_digest == acceptance_gate_context)
                    || (key.session == acceptance_bootstrap_gate_session
                        && key.context_digest == acceptance_bootstrap_gate_context)
                    || (key.session == acceptance_protocol_gate_session
                        && key.context_digest == acceptance_protocol_gate_context)
                    || (key.session == acceptance_driver_latch_session
                        && key.context_digest == acceptance_driver_latch_context)
                    || (key.session == acceptance_deposit_checkpoint_session
                        && key.context_digest == acceptance_deposit_checkpoint_context)
                {
                    // Dedicated acceptance records share ProtocolStore's opaque encrypted blob
                    // machinery but are not AVSS reducers. They were fully decoded before
                    // PartyServer construction. The protocol crash gate separately fails closed
                    // above if an Armed/Held record is restored without its explicit demo flag;
                    // inert records are authenticated here and excluded from AVSS decoding.
                    drop(
                        self.protocol_store
                            .load_session_state(key.session, key.context_digest)
                            .await?,
                    );
                    continue;
                }
                let bytes =
                    self.protocol_store.load_session_state(key.session, key.context_digest).await?;
                let DurableSessionState::Avss(run) = decode_postcard_exact(&bytes)?;
                anyhow::ensure!(
                    run.transition.session == key.session,
                    "AVSS state session differs"
                );
                anyhow::ensure!(
                    avss_transition_digest(&run.transition)? == key.context_digest,
                    "AVSS state context differs"
                );
                validate_avss_transition(self, &run.transition)?;
                self.ensure_reshare_source_certified(&run.transition).await?;
                validate_qual_witness_state(self, &run)?;
                let tombstoned = tokio::fs::try_exists(
                    self.protocol_store.session_tombstone_path(run.transition.session),
                )
                .await?;
                if tombstoned {
                    let tombstone =
                        self.protocol_store.load_session_tombstone(run.transition.session).await?;
                    let superseded = decode_superseded_avss_tombstone_purpose(tombstone.purpose())?;
                    if tombstone.purpose() == avss_tombstone_purpose(&run.transition)? {
                        anyhow::ensure!(
                            self.transition_has_durable_activation_certificate(&run.transition)
                                .await?,
                            "AVSS tombstone lacks a durable activation certificate"
                        );
                    } else if let Some(closure) = superseded {
                        self.verify_superseded_avss_closure(&run.transition, closure).await?;
                    } else {
                        anyhow::bail!("AVSS tombstone differs from its durable transition");
                    }
                    anyhow::ensure!(
                        self.transition_has_durable_activation_certificate(&run.transition).await?,
                        "AVSS tombstone lacks a durable activation certificate"
                    );
                    // Complete the crash-interrupted half of retire_transition_session. The
                    // activation certificate was persisted before this tombstone could be written;
                    // the remaining AVSS snapshot can contain dealer evaluations and must not be
                    // archived under a recoverable long-lived storage key.
                    self.protocol_store
                        .destroy_tombstoned_session_state(
                            run.transition.session,
                            key.context_digest,
                        )
                        .await?;
                    continue;
                }
                if let Some(response) = &run.finalized
                    && !self.activations.read().await.contains_key(&response.epoch)
                    && run.transition.target.member(self.party).is_ok()
                    && tokio::fs::try_exists(self.store.share_path(response.epoch)).await?
                {
                    if let Some(share) = self
                        .store
                        .load_if_active(response.epoch, run.transition.target.digest())
                        .await?
                    {
                        anyhow::ensure!(share.public() == response.public, "staged share differs");
                        self.staged.write().await.insert(
                            response.epoch,
                            StagedEpoch {
                                transition: run.transition.clone(),
                                share,
                                response: response.clone(),
                            },
                        );
                    }
                }
                let certified = self.certified_avss_sessions.read().await.clone();
                let mut runs = self.avss.lock().await;
                ensure_avss_live_capacity(&runs, &certified, &run.transition, MAX_LIVE_AVSS_RUNS)
                    .context("durable AVSS session count exceeds the live bound")?;
                anyhow::ensure!(
                    runs.insert(key.session, run).is_none(),
                    "duplicate durable AVSS session"
                );
            }
            Ok::<(), anyhow::Error>(())
        })
    }

    async fn persist_avss_run(&self, run: &AvssRun) -> anyhow::Result<()> {
        validate_avss_secret_compaction(run)?;
        validate_qual_witness_state(self, run)?;
        let context = avss_transition_digest(&run.transition)?;
        let encoded = encode_durable_avss_run(run)?;
        self.protocol_store
            .save_session_state(run.transition.session, context, &encoded, &mut OsRng)
            .await?;
        Ok(())
    }

    async fn ensure_avss_run_durable(&self, run: &AvssRun) -> anyhow::Result<()> {
        let tombstone_path = self.protocol_store.session_tombstone_path(run.transition.session);
        if tokio::fs::try_exists(&tombstone_path).await? {
            anyhow::ensure!(
                run.finalized.is_some(),
                "non-terminal AVSS state is permanently tombstoned"
            );
            self.save_avss_tombstone(&run.transition).await?;
            return Ok(());
        }
        self.persist_avss_run(run).await?;
        Ok(())
    }

    async fn save_avss_tombstone(&self, transition: &AvssTransition) -> anyhow::Result<()> {
        let tombstone = avss_tombstone_purpose(transition)?;
        self.protocol_store
            .save_session_tombstone(transition.session, &tombstone, &mut OsRng)
            .await?;
        Ok(())
    }

    async fn ensure_avss_session_open(&self, session: SessionId) -> anyhow::Result<()> {
        let path = self.protocol_store.session_tombstone_path(session);
        if tokio::fs::try_exists(path).await? {
            // Authenticate the record before treating it as authoritative. This also prevents a
            // corrupt or attacker-created path from poisoning the in-memory session table.
            drop(self.protocol_store.load_session_tombstone(session).await?);
            anyhow::bail!("AVSS session is permanently tombstoned");
        }
        Ok(())
    }

    /// Load and cryptographically verify the permanent activation record for one exact
    /// transition. A distinct transition at the same epoch is not evidence for this caller.
    async fn durable_activation_record_for_transition(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<Option<ActivationCertificateRecord>> {
        let transition_key = ActivationTransitionKey {
            epoch: transition.target.epoch,
            transition_digest: avss_transition_digest(transition)?,
        };
        let Some(indexed) =
            self.protocol_store.load_activation_certificate_for_transition(transition_key).await?
        else {
            let state = self.epoch_history.read().await.clone();
            if state.tip_epoch().is_none_or(|tip| transition.target.epoch > tip) {
                return Ok(None);
            }
            let Some((entry, mut loaded)) =
                self.epoch_history_entry(&state, transition.target.epoch).await?
            else {
                return Ok(None);
            };
            if entry.transition_digest() != transition_key.transition_digest {
                return Ok(None);
            }
            let bytes =
                self.load_epoch_history_object(entry.activation_certificate(), &mut loaded).await?;
            let record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
            let rotation = match entry.key_rotation_certificate() {
                Some(reference) => {
                    Some(self.load_epoch_history_object(reference, &mut loaded).await?)
                }
                None => None,
            };
            self.register_history_key_rotation(&record, rotation.as_deref(), true)?;
            anyhow::ensure!(
                record.transition == *transition
                    && record.value.history_link == entry.consensus_link(),
                "archived activation transition differs from the requested transition"
            );
            verify_activation_certificate(
                self,
                &record.transition,
                &record.value,
                &record.acknowledgements,
            )?;
            return Ok(Some(record));
        };
        let record: ActivationCertificateRecord = decode_postcard_exact(&indexed.certificate)?;
        anyhow::ensure!(record.value.epoch == indexed.key.epoch, "activation file epoch differs");
        anyhow::ensure!(
            record.value.activation_digest == indexed.key.activation_digest,
            "activation file digest differs"
        );
        anyhow::ensure!(
            avss_transition_digest(&record.transition)? == transition_key.transition_digest
                && record.transition == *transition,
            "indexed activation transition differs from the requested transition"
        );
        validate_avss_transition(self, &record.transition)?;
        verify_activation_certificate(
            self,
            &record.transition,
            &record.value,
            &record.acknowledgements,
        )?;
        Ok(Some(record))
    }

    async fn verify_superseded_avss_closure(
        &self,
        transition: &AvssTransition,
        closure: AvssSuccessorSupersession,
    ) -> anyhow::Result<()> {
        let transition_digest = avss_transition_digest(transition)?;
        anyhow::ensure!(
            closure.predecessor_session() == transition.session.0
                && closure.predecessor_transition() == transition_digest
                && closure.predecessor_epoch() == transition.target.epoch,
            "AVSS supersession tombstone differs from the replayed transition"
        );
        let state = self.epoch_history.read().await.clone();
        let (successor, mut loaded) = self
            .epoch_history_entry(&state, closure.successor_epoch())
            .await?
            .context("AVSS supersession successor is absent from authenticated history")?;
        anyhow::ensure!(
            successor.predecessor_supersession() == Some(closure)
                && successor.previous_root() == closure.predecessor_entry_root(),
            "AVSS supersession tombstone is not committed by its successor history entry"
        );
        let bytes =
            self.load_epoch_history_object(successor.activation_certificate(), &mut loaded).await?;
        let successor_record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
        let rotation = match successor.key_rotation_certificate() {
            Some(reference) => Some(self.load_epoch_history_object(reference, &mut loaded).await?),
            None => None,
        };
        self.register_history_key_rotation(&successor_record, rotation.as_deref(), true)?;
        verify_activation_certificate(
            self,
            &successor_record.transition,
            &successor_record.value,
            &successor_record.acknowledgements,
        )?;
        anyhow::ensure!(
            successor_record.value.history_link == successor.consensus_link()
                && successor_record.value.activation_digest == closure.successor_activation(),
            "AVSS supersession successor certificate differs from its closure"
        );
        anyhow::ensure!(
            self.transition_has_durable_activation_certificate(transition).await?,
            "AVSS supersession predecessor activation is unavailable"
        );
        Ok(())
    }

    /// Authenticate the permanent close marker and its corresponding activation certificate.
    /// Absence is deliberately distinct from invalid evidence: an unknown or not-yet-closed
    /// session must remain retryable, while a conflicting/corrupt tombstone fails terminally.
    async fn closed_transition_activation_record(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<Option<ActivationCertificateRecord>> {
        let path = self.protocol_store.session_tombstone_path(transition.session);
        if !tokio::fs::try_exists(path).await? {
            return Ok(None);
        }
        let tombstone = self.protocol_store.load_session_tombstone(transition.session).await?;
        let superseded = decode_superseded_avss_tombstone_purpose(tombstone.purpose())?;
        if tombstone.purpose() == avss_tombstone_purpose(transition)? {
            // The exact current finalization purpose is anchored by the predecessor activation
            // record loaded below.
        } else if let Some(closure) = superseded {
            self.verify_superseded_avss_closure(transition, closure).await?;
        } else {
            anyhow::bail!("AVSS tombstone differs from the replayed transition");
        }
        let record = self
            .durable_activation_record_for_transition(transition)
            .await?
            .context("AVSS tombstone lacks a durable activation certificate")?;
        Ok(Some(record))
    }

    async fn transition_has_durable_activation_certificate(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<bool> {
        Ok(self.durable_activation_record_for_transition(transition).await?.is_some())
    }

    /// Retire a certified transition only after every target-directed durable effect was accepted.
    /// In particular, an activation certificate from n-f parties must not erase the AVSS/QUAL
    /// catch-up path for a slower honest target outside that first quorum.
    ///
    /// Closing deletes the current-volume AVSS snapshot because its dealer outbox is decryptable
    /// secret material, but it is not a production forward-erasure proof: retained/re-derived
    /// epoch X25519 keys can decrypt captured network ciphertext, while CoW snapshots, backups,
    /// and crash dumps can retain the deleted snapshot. That boundary needs externally erased
    /// per-epoch KMS/HSM keys plus a monotonic rollback anchor.
    async fn retire_transition_session_if_drained(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<bool> {
        if !self.transition_has_durable_activation_certificate(transition).await? {
            return Ok(false);
        }
        let context = avss_transition_digest(transition)?;
        // Serialize retirement against session creation and reducer checkpoints. Otherwise a
        // request could pass the tombstone check, lose a race with retirement, then leave an
        // undurable in-memory run after its snapshot write is correctly rejected.
        let mut runs = self.avss.lock().await;
        let Some(run) = runs.get(&transition.session) else {
            return Ok(true);
        };
        anyhow::ensure!(run.transition == *transition, "session was bound to another transition");
        if !peer_outbox_is_empty(run) {
            return Ok(false);
        }
        // Old-only resharing dealers never execute target finalization. The durable activation
        // certificate checked above authorizes permanently closing their now-drained session too.
        let tombstone = avss_tombstone_purpose(transition)?;
        self.protocol_store
            .close_session_state(transition.session, context, &tombstone, &mut OsRng)
            .await?;
        runs.remove(&transition.session);
        Ok(true)
    }

    /// Snapshot a bounded prefix of the durable peer outbox. Items remain pending across any
    /// number of calls and process restarts until [`Self::acknowledge_peer_messages`] succeeds.
    pub async fn pending_peer_messages(&self, limit: usize) -> Vec<PendingPeerMessage> {
        let limit = limit.min(MAX_PEER_OUTBOX_SNAPSHOT);
        if limit == 0 {
            return Vec::new();
        }
        let runs = self.avss.lock().await;
        let protocol_fault_gate = self.acceptance_protocol_fault_gate.lock().await.clone();
        let total = runs
            .iter()
            .filter(|(session, _)| !protocol_fault_gate.blocks_session(**session))
            .map(|(_, run)| {
                run.pending_avss
                    .len()
                    .saturating_add(run.pending_qual.len())
                    .saturating_add(run.pending_activation_ack.len())
            })
            .sum::<usize>();
        if total == 0 {
            return Vec::new();
        }
        let take = limit.min(total);
        let mut cursor = self.peer_outbox_cursor.lock().await;
        let start = *cursor % total;
        *cursor = start.saturating_add(take) % total;
        drop(cursor);

        let mut batch = Vec::with_capacity(take);
        let mut index = 0_usize;
        for (session, run) in runs.iter() {
            if protocol_fault_gate.blocks_session(*session) {
                continue;
            }
            for (key, wire) in &run.pending_avss {
                let distance = index.saturating_add(total).saturating_sub(start) % total;
                if distance < take {
                    let id =
                        PeerMessageId::Avss { session: *session, recipient: key.0, digest: key.1 };
                    batch.push(PendingPeerMessage::Avss {
                        id,
                        request: AvssDeliverRequest {
                            transition: run.transition.clone(),
                            wire: wire.clone(),
                        },
                    });
                }
                index = index.saturating_add(1);
            }
            for (key, wire) in &run.pending_qual {
                let distance = index.saturating_add(total).saturating_sub(start) % total;
                if distance < take {
                    let id =
                        PeerMessageId::Qual { session: *session, recipient: key.0, digest: key.1 };
                    batch.push(PendingPeerMessage::Qual {
                        id,
                        request: QualDeliverRequest {
                            transition: run.transition.clone(),
                            wire: wire.clone(),
                        },
                    });
                }
                index = index.saturating_add(1);
            }
            for (key, acknowledgement) in &run.pending_activation_ack {
                let distance = index.saturating_add(total).saturating_sub(start) % total;
                if distance < take {
                    let id = PeerMessageId::ActivationAck {
                        session: *session,
                        recipient: key.0,
                        digest: key.1,
                    };
                    batch.push(PendingPeerMessage::ActivationAck {
                        id,
                        request: ActivationAckDeliverRequest {
                            transition: run.transition.clone(),
                            acknowledgement: acknowledgement.clone(),
                        },
                    });
                }
                index = index.saturating_add(1);
            }
        }
        batch
    }

    /// Durably remove peer messages after transport-level remote acceptance or an authenticated
    /// terminal rejection of the immutable effect. Duplicate ACKs and ACKs racing with terminal
    /// session retirement are harmless. A failed checkpoint restores the in-memory outbox,
    /// deliberately causing idempotent retransmission.
    pub async fn acknowledge_peer_messages(
        &self,
        acknowledgements: &[PeerMessageId],
    ) -> anyhow::Result<()> {
        let mut by_session = BTreeMap::<SessionId, Vec<PeerMessageId>>::new();
        for acknowledgement in acknowledgements {
            by_session.entry(acknowledgement.session()).or_default().push(*acknowledgement);
        }

        let mut runs = self.avss.lock().await;
        let protocol_fault_gate = self.acceptance_protocol_fault_gate.lock().await.clone();
        let mut retirement_candidates = Vec::new();
        for (session, acknowledgements) in by_session {
            if protocol_fault_gate.blocks_session(session) {
                continue;
            }
            let Some(run) = runs.get_mut(&session) else {
                // Activation/retirement may safely discard a no-longer-needed session while a
                // relay request is in flight.
                continue;
            };
            let before = run.clone();
            let mut changed = false;
            for acknowledgement in acknowledgements {
                changed |= match acknowledgement {
                    PeerMessageId::Avss { recipient, digest, .. } => {
                        run.pending_avss.remove(&(recipient, digest)).is_some()
                    }
                    PeerMessageId::Qual { recipient, digest, .. } => {
                        run.pending_qual.remove(&(recipient, digest)).is_some()
                    }
                    PeerMessageId::ActivationAck { recipient, digest, .. } => {
                        run.pending_activation_ack.remove(&(recipient, digest)).is_some()
                    }
                };
            }
            if changed && let Err(error) = self.ensure_avss_run_durable(run).await {
                // Never acknowledge only in RAM. Restoring the pre-ACK image deliberately causes
                // an idempotent retransmission if the durable checkpoint failed.
                *run = before;
                return Err(error.context(format!(
                    "cannot checkpoint durable peer outbox ACK for session {session}"
                )));
            }
            if changed && peer_outbox_is_empty(run) {
                retirement_candidates.push(run.transition.clone());
            }
        }
        drop(runs);
        for transition in retirement_candidates {
            self.retire_transition_session_if_drained(&transition).await?;
        }
        Ok(())
    }

    /// Enumerate a bounded, replayable set of activation/retirement certificate messages for the
    /// QUIC relay. The certificate records themselves are permanent authenticated storage, so a
    /// process restart naturally retries every record. The relay may keep an in-memory delivered
    /// cache to avoid steady-state traffic, but must never treat that cache as authoritative.
    pub async fn pending_epoch_peer_messages(
        &self,
        limit: usize,
    ) -> anyhow::Result<Vec<PendingEpochPeerMessage>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let scenario_parties =
            self.scenario.parties.iter().map(|party| party.id).collect::<Vec<_>>();
        let mut messages = Vec::new();
        for key in
            self.protocol_store.activation_certificates_bounded(MAX_CURRENT_EPOCH_RECORDS).await?
        {
            let bytes = self
                .protocol_store
                .load_activation_certificate(key.epoch, key.activation_digest)
                .await?;
            let record: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
            validate_avss_transition(self, &record.transition)?;
            verify_activation_certificate(
                self,
                &record.transition,
                &record.value,
                &record.acknowledgements,
            )?;
            anyhow::ensure!(
                record.value.epoch == key.epoch
                    && record.value.activation_digest == key.activation_digest,
                "activation gossip key differs from its certificate"
            );
            let request = ActivateEpochRequest {
                transition: record.transition.clone(),
                value: record.value,
                acknowledgements: record.acknowledgements,
            };
            let body = postcard::to_allocvec(&request)?;
            for (recipient, operation) in epoch_certificate_routes(
                self.party,
                &scenario_parties,
                &request.transition.target,
                request.transition.old.as_ref().map(|old| &old.committee),
            ) {
                messages.push(PendingEpochPeerMessage {
                    id: EpochPeerMessageId {
                        epoch: key.epoch,
                        activation_digest: key.activation_digest,
                        recipient,
                        operation,
                    },
                    request: PeerRequest::Epoch { operation, body: body.clone() },
                });
                if messages.len() >= limit {
                    return Ok(messages);
                }
            }
        }
        Ok(messages)
    }

    fn configured_proactive_refresh_transition(
        &self,
        source: &EpochPublic,
    ) -> anyhow::Result<Option<AvssTransition>> {
        source.validate()?;
        let history_parent = self.certified_history_parent(source)?;
        let target_epoch =
            source.committee.epoch.checked_add(1).context("proactive refresh epoch exhausted")?;
        let Some(context) = self.key_rotation_context_for_source(source)? else {
            return Ok(None);
        };
        let rotations = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
        let Some(rotation) = rotations.get(&target_epoch) else {
            // Every configured or dynamic successor first certifies its receiver-key selection.
            return Ok(None);
        };
        anyhow::ensure!(rotation.context == context, "receiver-key rotation context differs");
        let target = rotation.certificate.verify(&rotation.context)?;
        anyhow::ensure!(
            target.digest() == rotation.target.digest(),
            "receiver-key rotation target differs from its registered certificate"
        );
        drop(rotations);

        if same_refresh_layout(&source.committee, &target) {
            if let Ok(specification) = self.scenario.committee_spec(target_epoch) {
                anyhow::ensure!(
                    specification.operation == Operation::Reshare,
                    "configured zero-refresh target is not a reshare successor"
                );
                anyhow::ensure!(
                    context.source_fault_bound() == context.target_fault_bound(),
                    "same-layout proactive refresh changed the Byzantine fault bound"
                );
            }
            anyhow::ensure!(
                target.threshold >= 2,
                "proactive zero-refresh requires threshold at least two"
            );
            return Ok(Some(dynamic_avss_transition(
                source,
                target,
                context.target_fault_bound(),
                history_parent,
            )?));
        }

        let eligible_dealers = if let Ok(specification) = self.scenario.committee_spec(target_epoch)
        {
            anyhow::ensure!(
                specification.operation == Operation::Reshare,
                "configured resharing target is not a reshare successor"
            );
            specification
                .old_dealers
                .iter()
                .copied()
                .filter(|party| source.committee.member(*party).is_ok())
                .collect()
        } else {
            source.committee.members.iter().map(|member| member.id).collect()
        };
        Ok(Some(AvssTransition {
            purpose: DealPurpose::Reshare,
            session: canonical_reshare_session(source, &target, history_parent)?,
            key_id: source.key_id,
            fault_bound: context.target_fault_bound(),
            history_parent,
            old: Some(source.clone()),
            target,
            eligible_dealers,
        }))
    }

    fn certified_history_parent(&self, source: &EpochPublic) -> anyhow::Result<EpochHistoryParent> {
        source.validate()?;
        let links = self
            .history_links
            .read()
            .map_err(|_| anyhow::anyhow!("epoch-history registry lock is poisoned"))?;
        let link = links
            .get(&source.committee.epoch)
            .copied()
            .context("source epoch lacks a certified history link")?;
        anyhow::ensure!(
            link.key_id() == source.key_id
                && link.activation_digest() == source.activation_digest()?,
            "source epoch history link differs from its public activation"
        );
        link.successor_parent().map_err(Into::into)
    }

    fn remember_certified_history_link(&self, link: EpochHistoryLink) -> anyhow::Result<()> {
        let mut links = self
            .history_links
            .write()
            .map_err(|_| anyhow::anyhow!("epoch-history registry lock is poisoned"))?;
        if let Some(existing) = links.get(&link.epoch()) {
            anyhow::ensure!(*existing == link, "epoch is certified on another history fork");
        } else {
            links.insert(link.epoch(), link);
        }
        Ok(())
    }

    fn key_rotation_semantic_digest(&self, target_epoch: u64) -> anyhow::Result<Option<[u8; 32]>> {
        let rotations = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
        rotations
            .get(&target_epoch)
            .map(|rotation| {
                rotation.certificate.semantic_digest(&rotation.context).map_err(Into::into)
            })
            .transpose()
    }

    async fn load_epoch_history_object(
        &self,
        reference: EpochHistoryObjectRef,
        loaded: &mut LoadedEpochHistoryObjects,
    ) -> anyhow::Result<Vec<u8>> {
        if let Some(contents) = loaded.0.get(&reference) {
            return Ok(contents.clone());
        }
        let artifact =
            self.epoch_history_artifacts.load_artifact(reference.storage_reference()?).await?;
        reference.verify_contents(artifact.contents.as_bytes())?;
        let contents = artifact.contents.into_bytes();
        loaded.0.insert(reference, contents.clone());
        Ok(contents)
    }

    async fn preload_epoch_history_index_path(
        &self,
        state: &EpochHistoryState,
        epoch: u64,
        require_leaf: bool,
        loaded: &mut LoadedEpochHistoryObjects,
    ) -> anyhow::Result<()> {
        let Some(mut reference) = state.cold_index_root() else {
            anyhow::ensure!(!require_leaf, "epoch-history cold index is absent");
            return Ok(());
        };
        for depth in 0..=crate::epoch_history::EPOCH_HISTORY_INDEX_DEPTH {
            let contents = self.load_epoch_history_object(reference, loaded).await?;
            match epoch_history_index_step(state.network(), epoch, depth, reference, &contents)? {
                EpochHistoryIndexStep::Branch { next: Some(next) } => reference = next,
                EpochHistoryIndexStep::Branch { next: None } => {
                    anyhow::ensure!(!require_leaf, "epoch is absent from the cold history index");
                    return Ok(());
                }
                EpochHistoryIndexStep::Leaf { entry, .. } => {
                    self.load_epoch_history_object(entry, loaded).await?;
                    return Ok(());
                }
            }
        }
        anyhow::bail!("epoch-history index path exceeded its fixed depth")
    }

    async fn preload_epoch_history_reader(
        &self,
        state: &EpochHistoryState,
        insertion_epoch: Option<u64>,
    ) -> anyhow::Result<LoadedEpochHistoryObjects> {
        let mut loaded = LoadedEpochHistoryObjects::default();
        for reference in state.hot_object_references() {
            self.load_epoch_history_object(reference, &mut loaded).await?;
        }
        if let Some(cold) = state.cold_through() {
            self.preload_epoch_history_index_path(state, cold, true, &mut loaded).await?;
        }
        if let Some(epoch) = insertion_epoch {
            self.preload_epoch_history_index_path(state, epoch, false, &mut loaded).await?;
        }
        Ok(loaded)
    }

    async fn epoch_history_entry(
        &self,
        state: &EpochHistoryState,
        epoch: u64,
    ) -> anyhow::Result<Option<(crate::epoch_history::EpochHistoryEntry, LoadedEpochHistoryObjects)>>
    {
        let mut loaded = self.preload_epoch_history_reader(state, None).await?;
        if state.cold_through().is_some_and(|cold| epoch <= cold) {
            self.preload_epoch_history_index_path(state, epoch, true, &mut loaded).await?;
        }
        let entry = state.lookup(epoch, &loaded)?;
        Ok(entry.map(|entry| (entry, loaded)))
    }

    async fn handle_epoch_history_query(
        &self,
        authenticated_party: PartyId,
        query: EpochHistoryCatchupQuery,
    ) -> anyhow::Result<EpochHistoryCatchupReply> {
        self.scenario.party(authenticated_party)?;
        query.validate()?;
        let state = self.epoch_history.read().await.clone();
        match query {
            EpochHistoryCatchupQuery::Next { parent, .. } => {
                anyhow::ensure!(
                    parent.network() == state.network() && parent.key_id() == state.key_id(),
                    "epoch-history pull parent belongs to another trust domain"
                );
                match parent.epoch() {
                    None => {
                        anyhow::ensure!(
                            parent == EpochHistoryParent::genesis(state.network(), state.key_id())?,
                            "epoch-history pull genesis parent differs"
                        );
                    }
                    Some(epoch) => {
                        let (entry, _) = self
                            .epoch_history_entry(&state, epoch)
                            .await?
                            .context("epoch-history pull parent is not on the local chain")?;
                        anyhow::ensure!(
                            entry.consensus_link().successor_parent()? == parent,
                            "epoch-history pull parent is on another fork"
                        );
                    }
                }
                let next_epoch = parent
                    .epoch()
                    .map_or(Ok(0), |epoch| epoch.checked_add(1).context("epoch exhausted"))?;
                let manifest = self
                    .epoch_history_entry(&state, next_epoch)
                    .await?
                    .map(|(entry, _)| entry.catchup_manifest())
                    .transpose()?;
                EpochHistoryCatchupReply::next(manifest, state.parent()?).map_err(Into::into)
            }
            EpochHistoryCatchupQuery::ObjectChunk {
                manifest,
                reference,
                offset,
                maximum_bytes,
                ..
            } => {
                let epoch = manifest.link().epoch();
                let (entry, mut loaded) = self
                    .epoch_history_entry(&state, epoch)
                    .await?
                    .context("epoch-history object manifest is no longer reachable")?;
                anyhow::ensure!(
                    entry.catchup_manifest()? == manifest,
                    "epoch-history object manifest differs from the authenticated local entry"
                );
                let contents = self.load_epoch_history_object(reference, &mut loaded).await?;
                let start =
                    usize::try_from(offset).context("epoch-history chunk offset overflow")?;
                let maximum =
                    usize::try_from(maximum_bytes).context("epoch-history chunk bound overflow")?;
                let end = start.saturating_add(maximum).min(contents.len());
                anyhow::ensure!(start < end, "epoch-history chunk range is empty");
                EpochHistoryCatchupReply::object_chunk(
                    reference,
                    offset,
                    contents[start..end].to_vec(),
                )
                .map_err(Into::into)
            }
        }
    }

    /// Current authenticated parent used by the QUIC history puller.
    pub async fn epoch_history_catchup_parent(&self) -> anyhow::Result<EpochHistoryParent> {
        self.epoch_history.read().await.parent().map_err(Into::into)
    }

    fn history_key_rotation_context(
        &self,
        record: &ActivationCertificateRecord,
        allow_authenticated_checkpoint_source: bool,
    ) -> anyhow::Result<KeyRotationContext> {
        let source = record
            .transition
            .old
            .as_ref()
            .context("key-rotated activation omitted its source epoch")?;
        let context = match self.key_rotation_context_for_source(source) {
            Ok(Some(context)) => context,
            Ok(None) => anyhow::bail!("activation has no receiver-key rotation policy"),
            Err(error) if !allow_authenticated_checkpoint_source => return Err(error),
            Err(_) => {
                // The authenticated cold-history boundary is a local trust checkpoint. Its
                // predecessor rotation may already have been deliberately compacted, so recover
                // the source fault policy from immutable governance when configured, or from the
                // invariant same-layout dynamic refresh policy otherwise. This exception is
                // never available to peer catch-up or ordinary hot-history validation.
                source.validate()?;
                let source_fault_bound = if let Ok(specification) =
                    self.scenario.committee_spec(source.committee.epoch)
                {
                    specification.fault_bound
                } else {
                    anyhow::ensure!(
                        same_refresh_layout(&source.committee, &record.transition.target),
                        "unconfigured history checkpoint changed committee layout"
                    );
                    record.transition.fault_bound
                };
                source.committee.validate_async_security_with_faults(source_fault_bound)?;
                let target_policy = if let Some(configured) =
                    self.scenario.configured_key_rotation_target_policy(&source.committee)?
                {
                    configured
                } else {
                    let target_epoch = source
                        .committee
                        .epoch
                        .checked_add(1)
                        .context("history checkpoint target epoch exhausted")?;
                    let eligible = Committee {
                        epoch: target_epoch,
                        threshold: source.committee.threshold,
                        members: self
                            .scenario
                            .parties
                            .iter()
                            .map(|party| Member {
                                id: party.id,
                                signing_key: party.signing_key.0,
                                encryption_key: eligibility_reference_key(
                                    target_epoch,
                                    party.id,
                                    party.signing_key.0,
                                ),
                            })
                            .collect(),
                    };
                    KeyRotationTargetPolicy::new(
                        &source.committee,
                        eligible,
                        source.committee.n(),
                        source_fault_bound,
                    )?
                };
                KeyRotationContext::new(
                    self.scenario.quic_network_id()?,
                    source.committee.clone(),
                    source.activation_digest()?,
                    source_fault_bound,
                    target_policy,
                )?
            }
        };
        anyhow::ensure!(
            context.target_epoch() == record.value.epoch
                && context.target_fault_bound() == record.transition.fault_bound,
            "activation differs from its receiver-key rotation policy"
        );
        Ok(context)
    }

    fn register_history_key_rotation(
        &self,
        record: &ActivationCertificateRecord,
        certificate_bytes: Option<&[u8]>,
        allow_authenticated_checkpoint_source: bool,
    ) -> anyhow::Result<()> {
        match (record.value.history_link.key_rotation_digest(), certificate_bytes) {
            (None, None) => {
                anyhow::ensure!(
                    record.value.epoch == 0
                        && record.transition.purpose == DealPurpose::Dkg
                        && record.transition.old.is_none(),
                    "non-genesis epoch history omitted its receiver-key rotation certificate"
                );
                Ok(())
            }
            (Some(expected_digest), Some(bytes)) => {
                let context = self
                    .history_key_rotation_context(record, allow_authenticated_checkpoint_source)?;
                let certificate = KeyRotationCertificate::decode(&context, bytes)?;
                let target = certificate.verify(&context)?;
                anyhow::ensure!(
                    target.digest() == record.transition.target.digest()
                        && record.value.public.committee.digest() == target.digest()
                        && certificate.semantic_digest(&context)? == expected_digest,
                    "epoch-history key rotation differs from its activation"
                );
                self.register_certified_key_rotation(context, certificate)?;
                Ok(())
            }
            _ => anyhow::bail!(
                "epoch-history activation and key-rotation certificate presence differ"
            ),
        }
    }

    /// Verify and append one immediate successor reconstructed from bounded QUIC object chunks.
    ///
    /// This path deliberately records public activation history only. A member which did not
    /// complete AVSS cannot manufacture a signing share from a certificate.
    pub async fn apply_epoch_history_catchup(
        self: &Arc<Self>,
        authenticated_source: PartyId,
        manifest: EpochHistoryCatchupManifest,
        activation_certificate: Vec<u8>,
        key_rotation_certificate: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.scenario.party(authenticated_source)?;
        manifest.activation_certificate().verify_contents(&activation_certificate)?;
        match (manifest.key_rotation_certificate(), key_rotation_certificate.as_deref()) {
            (Some(reference), Some(bytes)) => reference.verify_contents(bytes)?,
            (None, None) => {}
            _ => anyhow::bail!("epoch-history catch-up object set differs from its manifest"),
        }

        let _epoch_transition = self.epoch_transition.lock().await;
        let expected_parent = self.epoch_history.read().await.parent()?;
        anyhow::ensure!(
            manifest.parent() == expected_parent,
            "epoch-history catch-up no longer extends the local tip"
        );
        let record: ActivationCertificateRecord = decode_postcard_exact(&activation_certificate)?;
        anyhow::ensure!(
            record.value.history_link == manifest.link()
                && record.transition.history_parent == manifest.parent()
                && record.value.epoch == manifest.link().epoch()
                && avss_transition_digest(&record.transition)?
                    == manifest.link().transition_digest(),
            "epoch-history activation differs from its successor manifest"
        );
        if record.value.epoch == 0 {
            anyhow::ensure!(
                record.transition.old.is_none(),
                "epoch-zero history catch-up unexpectedly carries a predecessor"
            );
        } else {
            let history = self.epoch_history.read().await.clone();
            let predecessor_epoch = record.value.epoch - 1;
            let (predecessor, mut loaded) = self
                .epoch_history_entry(&history, predecessor_epoch)
                .await?
                .context("epoch-history catch-up predecessor disappeared")?;
            let predecessor_bytes = self
                .load_epoch_history_object(predecessor.activation_certificate(), &mut loaded)
                .await?;
            let predecessor_record: ActivationCertificateRecord =
                decode_postcard_exact(&predecessor_bytes)?;
            anyhow::ensure!(
                record.transition.old.as_ref() == Some(&predecessor_record.value.public)
                    && predecessor.consensus_link().successor_parent()? == manifest.parent(),
                "epoch-history catch-up source epoch differs from the authenticated predecessor"
            );
        }
        self.register_history_key_rotation(&record, key_rotation_certificate.as_deref(), false)?;
        validate_avss_transition(self, &record.transition)?;
        verify_activation_certificate(
            self,
            &record.transition,
            &record.value,
            &record.acknowledgements,
        )?;
        self.persist_activation_certificate(
            &record.transition,
            &record.value,
            &record.acknowledgements,
        )
        .await?;
        self.remember_certified_deposit_target(&record.value).await?;
        if let Some(old) = &record.transition.old {
            self.deposit_targets
                .write()
                .await
                .entry(old.committee.epoch)
                .or_insert_with(|| old.clone());
        }
        Ok(())
    }

    async fn persist_epoch_history_activation(
        &self,
        transition: &AvssTransition,
        value: &ActivationValue,
        activation_certificate: &[u8],
    ) -> anyhow::Result<()> {
        let mut state = self.epoch_history.write().await;
        if state.tip_epoch() == Some(value.epoch) {
            let tip = state.hot_entries().last().context("epoch-history tip lacks a hot entry")?;
            anyhow::ensure!(
                tip.consensus_link() == value.history_link
                    && tip.transition_digest() == avss_transition_digest(transition)?,
                "durable epoch-history tip conflicts with the activation retry"
            );
            return Ok(());
        }
        let expected_epoch = state.tip_epoch().map_or(Ok(0), |epoch| {
            epoch.checked_add(1).context("epoch-history number exhausted")
        })?;
        anyhow::ensure!(
            value.epoch == expected_epoch && transition.history_parent == state.parent()?,
            "activation does not immediately extend the durable epoch-history tip"
        );

        let insertion_epoch = (state.hot_entries().len()
            >= usize::from(state.policy().hot_entries()))
        .then(|| state.cold_through().map_or(0, |epoch| epoch.saturating_add(1)));
        let mut loaded = self.preload_epoch_history_reader(&state, insertion_epoch).await?;

        let predecessor_supersession = if value.epoch == 0 {
            None
        } else {
            let predecessor = state
                .lookup(value.epoch - 1, &loaded)?
                .context("epoch-history predecessor is unavailable")?;
            let predecessor_bytes = self
                .load_epoch_history_object(predecessor.activation_certificate(), &mut loaded)
                .await?;
            let predecessor_record: ActivationCertificateRecord =
                decode_postcard_exact(&predecessor_bytes)?;
            let old = transition.old.as_ref().context("successor transition omitted old epoch")?;
            anyhow::ensure!(
                predecessor_record.value.epoch + 1 == value.epoch
                    && predecessor_record.value.public == *old
                    && predecessor_record.value.public.key_id == value.public.key_id
                    && predecessor_record.value.public.group_key_bytes()
                        == value.public.group_key_bytes()
                    && predecessor_record.value.history_link.root()?
                        == transition.history_parent.root(),
                "successor cannot supersede a non-immediate, forked, or key-changing predecessor"
            );
            let predecessor_session = predecessor_record.transition.session;
            let predecessor_transition = avss_transition_digest(&predecessor_record.transition)?;
            let outbox_digests = self
                .avss
                .lock()
                .await
                .get(&predecessor_session)
                .map(|run| {
                    anyhow::ensure!(
                        avss_transition_digest(&run.transition)? == predecessor_transition,
                        "predecessor AVSS reducer belongs to another transition"
                    );
                    Ok(run.pending_avss.keys().map(|(_, digest)| *digest).collect::<Vec<_>>())
                })
                .transpose()?
                .unwrap_or_default();
            Some(AvssSuccessorSupersession::new(
                value.epoch - 1,
                predecessor.root()?,
                predecessor_transition,
                predecessor_session.0,
                value.epoch,
                value.activation_digest,
                &outbox_digests,
            )?)
        };

        let key_rotation_certificate = self
            .certified_key_rotations
            .read()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
            .get(&value.epoch)
            .map(|rotation| rotation.certificate.encode(&rotation.context))
            .transpose()?;
        let pending = state.prepare_append(
            EpochHistoryEntryInput {
                epoch: value.epoch,
                parent: transition.history_parent,
                transition_digest: avss_transition_digest(transition)?,
                activation_digest: value.activation_digest,
                avss_transcript_digest: value.avss_transcript_digest,
                key_rotation_digest: value.history_link.key_rotation_digest(),
                activation_certificate: activation_certificate.to_vec(),
                key_rotation_certificate,
                predecessor_supersession,
            },
            &loaded,
        )?;
        anyhow::ensure!(
            pending
                .staged_objects()
                .iter()
                .find(|object| {
                    object.reference().kind()
                        == crate::epoch_history::EpochHistoryObjectKind::ActivationCertificate
                })
                .is_some(),
            "epoch-history mutation omitted its exact activation artifact"
        );

        for object in pending.staged_objects() {
            let storage_reference = object.reference().storage_reference()?;
            let installed = self
                .epoch_history_artifacts
                .create_artifact(
                    storage_reference.wallet_id(),
                    storage_reference.kind(),
                    object.contents(),
                    &mut OsRng,
                )
                .await?;
            anyhow::ensure!(
                installed == storage_reference,
                "epoch-history artifact store returned another content address"
            );
            loaded.0.insert(object.reference(), object.contents().to_vec());
        }
        let verified = pending.verify_staged(&loaded)?;
        let next_bytes = verified.next_state_bytes().to_vec();
        let metadata = self
            .epoch_history_snapshots
            .save_snapshot(
                self.epoch_history_wallet,
                verified.next_state().revision(),
                &next_bytes,
                &mut OsRng,
            )
            .await?;
        anyhow::ensure!(
            metadata.revision == verified.next_state().revision(),
            "epoch-history snapshot revision differs after CAS"
        );
        let readback =
            self.epoch_history_snapshots.load_snapshot(self.epoch_history_wallet).await?;
        anyhow::ensure!(
            readback.state.as_bytes() == next_bytes.as_slice(),
            "epoch-history CAS readback differs"
        );
        let cleanup = verified.authorize_cleanup(readback.state.as_bytes())?;
        *state = EpochHistoryState::from_bytes(readback.state.as_bytes())?;
        drop(state);

        for closure in cleanup.superseded_avss() {
            self.close_superseded_avss_transition(*closure).await?;
        }
        // Cold activation/index and key-rotation duplicates are pruned only after this exact head
        // CAS. Independent retirement, identity, nonce, and high-water records are never touched.
        for epoch in cleanup.coldified_epochs() {
            self.prune_hot_epoch_records_after_history_cas(*epoch).await?;
        }
        Ok(())
    }

    async fn close_superseded_avss_transition(
        &self,
        closure: AvssSuccessorSupersession,
    ) -> anyhow::Result<()> {
        let session = SessionId(closure.predecessor_session());
        let normal_purpose = {
            let mut purpose = b"avss-finalized/v2/".to_vec();
            purpose.extend_from_slice(&closure.predecessor_transition());
            purpose
        };
        let path = self.protocol_store.session_tombstone_path(session);
        if tokio::fs::try_exists(&path).await? {
            let existing = self.protocol_store.load_session_tombstone(session).await?;
            if existing.purpose() == normal_purpose {
                self.avss.lock().await.remove(&session);
                return Ok(());
            }
        }
        let purpose = superseded_avss_tombstone_purpose(closure)?;
        self.protocol_store
            .close_session_state(session, closure.predecessor_transition(), &purpose, &mut OsRng)
            .await?;
        self.avss.lock().await.remove(&session);
        Ok(())
    }

    async fn prune_hot_epoch_records_after_history_cas(&self, epoch: u64) -> anyhow::Result<()> {
        // Resolve and authenticate the exact cold entry/artifacts again after the head CAS. This
        // direct-key cleanup cannot enumerate or touch retirement, identity, nonce, or high-water
        // stores.
        let state = self.epoch_history.read().await.clone();
        anyhow::ensure!(
            state.cold_through().is_some_and(|cold| epoch <= cold),
            "epoch-history cleanup attempted before cold-index commitment"
        );
        let (entry, mut loaded) = self
            .epoch_history_entry(&state, epoch)
            .await?
            .context("cold epoch disappeared before duplicate cleanup")?;
        let activation_bytes =
            self.load_epoch_history_object(entry.activation_certificate(), &mut loaded).await?;
        let record: ActivationCertificateRecord = decode_postcard_exact(&activation_bytes)?;
        let rotation_bytes = match entry.key_rotation_certificate() {
            Some(reference) => Some(self.load_epoch_history_object(reference, &mut loaded).await?),
            None => None,
        };
        self.register_history_key_rotation(&record, rotation_bytes.as_deref(), true)?;
        verify_activation_certificate(
            self,
            &record.transition,
            &record.value,
            &record.acknowledgements,
        )?;
        anyhow::ensure!(
            record.value.epoch == epoch
                && record.value.history_link == entry.consensus_link()
                && record.value.activation_digest == entry.activation_digest(),
            "cold epoch artifact differs from its authenticated history entry"
        );
        let transition_key =
            ActivationTransitionKey { epoch, transition_digest: entry.transition_digest() };
        self.protocol_store
            .destroy_archived_activation_records(transition_key, record.value.activation_digest)
            .await?;
        if rotation_bytes.is_some() {
            let context = self.history_key_rotation_context(&record, true)?;
            self.protocol_store.destroy_archived_key_rotation_certificate(&context).await?;
        }
        self.history_links
            .write()
            .map_err(|_| anyhow::anyhow!("epoch-history registry lock is poisoned"))?
            .retain(|linked_epoch, _| *linked_epoch >= epoch);
        self.certified_key_rotations
            .write()
            .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?
            .retain(|target_epoch, _| *target_epoch >= epoch);
        self.certified_avss_sessions.write().await.remove(&record.transition.session);
        Ok(())
    }

    fn proactive_refresh_schedule_for(
        &self,
        source: &EpochPublic,
        now_unix_ms: u64,
    ) -> anyhow::Result<ProactiveRefreshSchedule> {
        let interval_ms = self
            .scenario
            .proactive_refresh_interval_seconds
            .checked_mul(1_000)
            .context("proactive refresh interval overflow")?;
        let context = self.key_rotation_context_for_source(source)?;
        let target_epoch = context
            .as_ref()
            .filter(|context| context.is_participant(self.party))
            .map(KeyRotationContext::target_epoch);
        let due_unix_ms = target_epoch
            .map(|_| {
                if self.acceptance_proactive_refresh_hold_enabled {
                    Ok(ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS)
                } else {
                    now_unix_ms
                        .checked_add(interval_ms)
                        .context("proactive refresh deadline overflow")
                }
            })
            .transpose()?;
        Ok(ProactiveRefreshSchedule {
            version: PROACTIVE_REFRESH_SCHEDULE_VERSION,
            source_epoch: source.committee.epoch,
            source_activation: source.activation_digest()?,
            target_epoch,
            due_unix_ms,
            rotation_view: None,
            rotation_view_started_unix_ms: None,
            rotation_timeout_exponent: 0,
            rotation_certificate_delivered_through: BTreeMap::new(),
        })
    }

    async fn persist_proactive_refresh_schedule(
        &self,
        schedule: ProactiveRefreshSchedule,
    ) -> anyhow::Result<()> {
        let _mutation = self.proactive_refresh_schedule_mutation.lock().await;
        self.persist_proactive_refresh_schedule_locked(schedule).await
    }

    async fn persist_proactive_refresh_schedule_locked(
        &self,
        schedule: ProactiveRefreshSchedule,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            schedule.version == PROACTIVE_REFRESH_SCHEDULE_VERSION,
            "unsupported proactive refresh schedule version"
        );
        anyhow::ensure!(
            schedule.target_epoch.is_some() == schedule.due_unix_ms.is_some(),
            "proactive refresh target/deadline presence differs"
        );
        anyhow::ensure!(
            schedule.rotation_view.is_some() == schedule.rotation_view_started_unix_ms.is_some(),
            "key-rotation view/deadline presence differs"
        );
        anyhow::ensure!(
            schedule.rotation_view.is_some() || schedule.rotation_timeout_exponent == 0,
            "inactive key-rotation pacemaker has a timeout exponent"
        );
        anyhow::ensure!(
            schedule.rotation_certificate_delivered_through.len() <= self.scenario.parties.len(),
            "key-rotation delivery cursor exceeds the configured party set"
        );
        for recipient in schedule.rotation_certificate_delivered_through.keys() {
            self.scenario.party(*recipient)?;
            anyhow::ensure!(
                *recipient != self.party,
                "key-rotation delivery cursor contains the local party"
            );
        }
        if let Some(target_epoch) = schedule.target_epoch {
            anyhow::ensure!(
                schedule.source_epoch.checked_add(1) == Some(target_epoch),
                "proactive refresh target is not the immediate successor"
            );
            anyhow::ensure!(
                schedule.due_unix_ms.is_some_and(|deadline| deadline != 0),
                "proactive refresh deadline must not be zero"
            );
            if schedule.due_unix_ms == Some(ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS) {
                anyhow::ensure!(
                    self.acceptance_proactive_refresh_hold_enabled,
                    "acceptance-held proactive refresh schedule requires its demo-Regtest gate"
                );
                anyhow::ensure!(
                    schedule.rotation_view.is_none()
                        && schedule.rotation_view_started_unix_ms.is_none()
                        && schedule.rotation_timeout_exponent == 0,
                    "acceptance-held proactive refresh schedule already started key rotation"
                );
            }
        }
        let encoded = postcard::to_allocvec(&schedule)?;
        self.protocol_store
            .save_proactive_refresh_schedule(self.scenario.quic_network_id()?, &encoded, &mut OsRng)
            .await?;
        *self.proactive_refresh_schedule.lock().await = Some(schedule);
        Ok(())
    }

    async fn arm_proactive_refresh_for_activation(
        &self,
        source: &EpochPublic,
        now_unix_ms: u64,
    ) -> anyhow::Result<()> {
        let _schedule_mutation = self.proactive_refresh_schedule_mutation.lock().await;
        let mut schedule = self.proactive_refresh_schedule_for(source, now_unix_ms)?;
        if let Some(existing) = self.proactive_refresh_schedule.lock().await.clone() {
            schedule.rotation_certificate_delivered_through =
                existing.rotation_certificate_delivered_through;
        }
        if self.proactive_refresh_schedule.lock().await.as_ref().is_some_and(|existing| {
            existing.version == schedule.version
                && existing.source_epoch == schedule.source_epoch
                && existing.source_activation == schedule.source_activation
                && existing.target_epoch == schedule.target_epoch
                && existing.target_epoch.is_some() == existing.due_unix_ms.is_some()
        }) {
            // Activation/certificate delivery is at-least-once. Never move an already armed
            // deadline forward when retrying the same certified activation after an I/O error.
            return Ok(());
        }
        self.persist_proactive_refresh_schedule_locked(schedule).await
    }

    /// Authenticate the one write-order state in which the successor's schedule reached stable
    /// storage immediately before its activation certificate. The saved deadline belongs to that
    /// already staged successor and must survive restart unchanged; accepting only the adjacent
    /// epoch number would let an unrelated authenticated local blob suppress or move the active
    /// predecessor's refresh clock.
    async fn authenticate_pending_successor_schedule(
        &self,
        predecessor: &EpochPublic,
        schedule: &ProactiveRefreshSchedule,
    ) -> anyhow::Result<()> {
        let successor_epoch = predecessor
            .committee
            .epoch
            .checked_add(1)
            .context("pending successor epoch exhausted")?;
        anyhow::ensure!(
            schedule.source_epoch == successor_epoch,
            "pending successor schedule is not adjacent to the active epoch"
        );

        let (transition, response) = {
            let staged = self.staged.read().await;
            let staged = staged
                .get(&successor_epoch)
                .context("pending successor schedule lacks its restored staged share")?;
            staged.share.validate()?;
            anyhow::ensure!(
                staged.share.public() == staged.response.public,
                "pending successor staged share differs from its finalized public value"
            );
            anyhow::ensure!(
                staged.transition.old.as_ref() == Some(predecessor),
                "pending successor transition differs from the active predecessor"
            );
            anyhow::ensure!(
                staged.response.epoch == successor_epoch
                    && staged.response.activation_digest == schedule.source_activation
                    && staged.response.public.activation_digest()? == schedule.source_activation,
                "pending successor schedule differs from its staged activation"
            );
            anyhow::ensure!(
                staged.response.public.key_id == predecessor.key_id
                    && staged.response.public.group_key_bytes() == predecessor.group_key_bytes(),
                "pending successor staged value changes the threshold key"
            );
            (staged.transition.clone(), staged.response.clone())
        };
        let expected_transition = self
            .configured_proactive_refresh_transition(predecessor)?
            .context("pending successor schedule lacks its certified transition")?;
        anyhow::ensure!(
            transition == expected_transition,
            "pending successor schedule is bound to another certified transition"
        );

        {
            let runs = self.avss.lock().await;
            let run = runs
                .get(&transition.session)
                .context("pending successor schedule lacks its restored finalized AVSS run")?;
            anyhow::ensure!(
                run.transition == transition && run.finalized.as_ref() == Some(&response),
                "pending successor AVSS finalization differs from its staged share"
            );
            anyhow::ensure!(
                !run.secret_compacted,
                "uncertified pending successor AVSS state was already compacted"
            );
            for (party, acknowledgement) in &run.activation_acknowledgements {
                anyhow::ensure!(
                    *party == acknowledgement.from,
                    "pending successor activation acknowledgement map key differs"
                );
            }
            let acknowledgements =
                run.activation_acknowledgements.values().cloned().collect::<Vec<_>>();
            verify_activation_certificate(
                self,
                &transition,
                &activation_value(&response),
                &acknowledgements,
            )?;
        }

        let due =
            schedule.due_unix_ms.context("pending successor schedule has no fixed deadline")?;
        let interval_ms = self
            .scenario
            .proactive_refresh_interval_seconds
            .checked_mul(1_000)
            .context("proactive refresh interval overflow")?;
        let armed_at = due
            .checked_sub(interval_ms)
            .context("pending successor deadline predates one refresh interval")?;
        let mut expected = self.proactive_refresh_schedule_for(&response.public, armed_at)?;
        expected.rotation_certificate_delivered_through =
            schedule.rotation_certificate_delivered_through.clone();
        anyhow::ensure!(
            *schedule == expected,
            "pending successor schedule differs from its exact staged activation deadline"
        );
        Ok(())
    }

    async fn restore_proactive_refresh_schedule(&self, now_unix_ms: u64) -> anyhow::Result<()> {
        let active_source = if let Some(active_epoch) = *self.active_epoch.read().await {
            Some(
                self.activations
                    .read()
                    .await
                    .get(&active_epoch)
                    .map(|activation| activation.public.clone())
                    .context("active epoch lacks activation metadata")?,
            )
        } else {
            None
        };
        let network_id = self.scenario.quic_network_id()?;
        let Some(encoded) = self.protocol_store.load_proactive_refresh_schedule(network_id).await?
        else {
            anyhow::ensure!(
                active_source.is_none(),
                "active certified epoch lacks its durable proactive-refresh schedule"
            );
            // A target-only joiner persists the observed source certificate before arming its
            // first local schedule. If the process stops in that narrow window, reconstruct the
            // only still-pending certified source instead of silently losing autonomous join
            // progress forever.
            let observed = self.deposit_targets.read().await.values().cloned().collect::<Vec<_>>();
            let mut joining_source = None;
            for source in observed.iter().rev() {
                let Some(context) = self.key_rotation_context_for_source(source)? else {
                    continue;
                };
                if context.target_policy().eligible().member(self.party).is_ok()
                    && !observed.iter().any(|known| known.committee.epoch == context.target_epoch())
                {
                    joining_source = Some(source.clone());
                    break;
                }
            }
            if let Some(source) = joining_source {
                let schedule = self.proactive_refresh_schedule_for(&source, now_unix_ms)?;
                return self.persist_proactive_refresh_schedule(schedule).await;
            }
            *self.proactive_refresh_schedule.lock().await = None;
            return Ok(());
        };
        let schedule: ProactiveRefreshSchedule = decode_postcard_exact(&encoded)?;
        anyhow::ensure!(
            postcard::to_allocvec(&schedule)? == encoded.as_ref(),
            "proactive refresh schedule is not canonical"
        );
        anyhow::ensure!(
            schedule.rotation_certificate_delivered_through.len() <= self.scenario.parties.len(),
            "persisted key-rotation delivery cursor exceeds the configured party set"
        );
        if schedule.due_unix_ms == Some(ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS) {
            anyhow::ensure!(
                self.acceptance_proactive_refresh_hold_enabled,
                "persisted acceptance-held proactive refresh schedule requires its demo-Regtest gate"
            );
        }
        for recipient in schedule.rotation_certificate_delivered_through.keys() {
            self.scenario.party(*recipient)?;
            anyhow::ensure!(
                *recipient != self.party,
                "persisted key-rotation delivery cursor contains the local party"
            );
        }
        let source = match active_source.as_ref() {
            Some(source) => source.clone(),
            None => {
                let targets = self.deposit_targets.read().await;
                if schedule
                    .target_epoch
                    .is_some_and(|target_epoch| targets.contains_key(&target_epoch))
                {
                    // A source-only removed party, or a joiner which never obtained the target
                    // share, retains no authority after the successor certificate is observed.
                    *self.proactive_refresh_schedule.lock().await = None;
                    return Ok(());
                }
                let source = targets
                    .get(&schedule.source_epoch)
                    .cloned()
                    .context("observer refresh schedule lacks its certified source epoch")?;
                let context = self
                    .key_rotation_context_for_source(&source)?
                    .context("observer refresh schedule has no successor policy")?;
                anyhow::ensure!(
                    context.target_policy().eligible().member(self.party).is_ok(),
                    "party without an active share is not a joining target member"
                );
                source
            }
        };
        let expected = self.proactive_refresh_schedule_for(&source, now_unix_ms)?;
        let matches_active = schedule.version == PROACTIVE_REFRESH_SCHEDULE_VERSION
            && schedule.source_epoch == expected.source_epoch
            && schedule.source_activation == expected.source_activation
            && schedule.target_epoch == expected.target_epoch
            && schedule.target_epoch.is_some() == schedule.due_unix_ms.is_some();
        if !matches_active {
            // Current-version activation writes the successor schedule before publishing the
            // activation certificate. A crash in that narrow window leaves an authenticated
            // schedule for active+1 while the predecessor remains active. Preserve that exact
            // deadline only when the restored finalized AVSS run, staged share, and activation
            // quorum authenticate the successor; reject every other mismatch.
            let adjacent_current_write = active_source.is_some()
                && expected.source_epoch.checked_add(1) == Some(schedule.source_epoch);
            anyhow::ensure!(
                adjacent_current_write,
                "proactive refresh schedule differs from the active certified epoch"
            );
            self.authenticate_pending_successor_schedule(&source, &schedule).await?;
            *self.proactive_refresh_schedule.lock().await = Some(schedule);
            return Ok(());
        }
        if let Some(target_epoch) = schedule.target_epoch {
            anyhow::ensure!(
                schedule.source_epoch.checked_add(1) == Some(target_epoch),
                "proactive refresh schedule skips an epoch"
            );
            anyhow::ensure!(
                schedule.due_unix_ms.is_some_and(|deadline| deadline != 0),
                "proactive refresh schedule has an invalid deadline"
            );
        }
        anyhow::ensure!(
            schedule.rotation_view.is_some() == schedule.rotation_view_started_unix_ms.is_some(),
            "persisted key-rotation pacemaker is incomplete"
        );
        if let Some(started) = schedule.rotation_view_started_unix_ms {
            anyhow::ensure!(
                schedule.due_unix_ms.is_some_and(|due| started >= due),
                "key-rotation view began before the proactive deadline"
            );
        } else {
            anyhow::ensure!(
                schedule.rotation_timeout_exponent == 0,
                "inactive key-rotation pacemaker has a timeout exponent"
            );
        }
        *self.proactive_refresh_schedule.lock().await = Some(schedule);
        Ok(())
    }

    /// Release the acceptance-only hold for one exact source epoch and re-arm its ordinary fixed
    /// interval from the authenticated operator request time. Repeating the same request is
    /// idempotent and never moves the deadline; a delayed request for an older epoch fails closed.
    async fn release_acceptance_proactive_refresh_hold(
        &self,
        source_epoch: u64,
        now_unix_ms: u64,
    ) -> anyhow::Result<AcceptanceProactiveRefreshReleaseResponse> {
        anyhow::ensure!(
            self.acceptance_proactive_refresh_hold_enabled,
            "acceptance proactive-refresh hold is disabled"
        );
        let _schedule_mutation = self.proactive_refresh_schedule_mutation.lock().await;
        let mut schedule = self
            .proactive_refresh_schedule
            .lock()
            .await
            .clone()
            .context("acceptance proactive-refresh release has no durable schedule")?;
        anyhow::ensure!(
            schedule.source_epoch == source_epoch,
            "acceptance proactive-refresh release names stale source epoch {source_epoch}; current source is {}",
            schedule.source_epoch
        );
        let target_epoch =
            schedule.target_epoch.context("acceptance proactive-refresh schedule has no target")?;
        anyhow::ensure!(
            source_epoch.checked_add(1) == Some(target_epoch),
            "acceptance proactive-refresh target is not the immediate successor"
        );
        let source = self.scheduled_key_rotation_source().await?;
        anyhow::ensure!(
            source.committee.epoch == source_epoch
                && source.activation_digest()? == schedule.source_activation,
            "acceptance proactive-refresh release differs from its certified source"
        );
        let context = self
            .key_rotation_context_for_source(&source)?
            .context("acceptance proactive-refresh source has no successor policy")?;
        anyhow::ensure!(
            context.target_epoch() == target_epoch && context.is_participant(self.party),
            "party is not a participant in the held proactive-refresh transition"
        );

        let due_unix_ms = schedule.due_unix_ms.context("held proactive refresh has no deadline")?;
        if due_unix_ms == ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS {
            anyhow::ensure!(
                schedule.rotation_view.is_none()
                    && schedule.rotation_view_started_unix_ms.is_none()
                    && schedule.rotation_timeout_exponent == 0,
                "held proactive refresh already started key rotation"
            );
            let interval_ms = self
                .scenario
                .proactive_refresh_interval_seconds
                .checked_mul(1_000)
                .context("proactive refresh interval overflow")?;
            let released_due = now_unix_ms
                .checked_add(interval_ms)
                .context("released proactive refresh deadline overflow")?;
            anyhow::ensure!(
                released_due != ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS,
                "released proactive refresh deadline collides with the held marker"
            );
            schedule.due_unix_ms = Some(released_due);
            self.persist_proactive_refresh_schedule_locked(schedule.clone()).await?;
        }
        let due_unix_ms =
            schedule.due_unix_ms.context("released proactive refresh has no deadline")?;
        Ok(AcceptanceProactiveRefreshReleaseResponse {
            party: self.party,
            source_epoch,
            target_epoch,
            due_unix_ms,
        })
    }

    async fn start_due_proactive_refresh(self: &Arc<Self>, now_unix_ms: u64) -> anyhow::Result<()> {
        let Some(schedule) = self.proactive_refresh_schedule.lock().await.clone() else {
            return Ok(());
        };
        let (Some(target_epoch), Some(due_unix_ms)) = (schedule.target_epoch, schedule.due_unix_ms)
        else {
            return Ok(());
        };
        if due_unix_ms == ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS {
            anyhow::ensure!(
                self.acceptance_proactive_refresh_hold_enabled,
                "acceptance-held proactive refresh schedule requires its demo-Regtest gate"
            );
            return Ok(());
        }
        if now_unix_ms < due_unix_ms {
            return Ok(());
        }
        if let Some(active_epoch) = *self.active_epoch.read().await
            && active_epoch != schedule.source_epoch
        {
            anyhow::ensure!(
                active_epoch.checked_add(1) == Some(schedule.source_epoch),
                "proactive refresh deadline belongs to a non-adjacent inactive epoch"
            );
            let predecessor = self
                .activations
                .read()
                .await
                .get(&active_epoch)
                .map(|activation| activation.public.clone())
                .context("pending successor schedule lacks active predecessor metadata")?;
            self.authenticate_pending_successor_schedule(&predecessor, &schedule).await?;
            // The finalized AVSS run below will retry activation in this same progress pass. Do
            // not start the successor's next key rotation until that share is actually active.
            return Ok(());
        }
        let source = self.scheduled_key_rotation_source().await?;
        anyhow::ensure!(
            source.activation_digest()? == schedule.source_activation,
            "proactive refresh source activation differs from its schedule"
        );
        let context = self
            .key_rotation_context_for_source(&source)?
            .context("scheduled proactive refresh target is no longer configured")?;
        anyhow::ensure!(
            context.target_epoch() == target_epoch && context.is_participant(self.party),
            "scheduled receiver-key target changed or no longer includes this party"
        );
        if context.source().member(self.party).is_ok() {
            anyhow::ensure!(
                *self.active_epoch.read().await == Some(schedule.source_epoch),
                "source-member refresh deadline belongs to a stale active epoch"
            );
        }
        let transition = self.configured_proactive_refresh_transition(&source)?;
        if transition.is_none() {
            self.ensure_key_rotation_started(&source, now_unix_ms).await?;
            return Ok(());
        }
        let transition = transition.expect("transition presence was checked above");
        anyhow::ensure!(
            transition.target.epoch == target_epoch,
            "scheduled proactive refresh target changed"
        );
        if !expected_avss_dealers(&transition).contains(&self.party) {
            return Ok(());
        }
        let already_started = self
            .avss
            .lock()
            .await
            .get(&transition.session)
            .is_some_and(|run| run.dealer_outbound.is_some());
        if already_started {
            return Ok(());
        }
        let _response = avss_start(State(self.clone()), Json(AvssStartRequest { transition }))
            .await
            .map_err(|error| error.0)?;
        tracing::info!(
            party = %self.party,
            source_epoch = schedule.source_epoch,
            target_epoch,
            due_unix_ms,
            "started scheduled proactive share refresh"
        );
        Ok(())
    }

    /// Reject early or stale zero-refresh traffic before it can allocate a reducer or elicit an
    /// honest vote. Immutable traffic for an already certified transition remains replayable
    /// after the schedule advances to the successor.
    async fn ensure_refresh_due_for_live_ingress(
        &self,
        transition: &AvssTransition,
        now_unix_ms: u64,
    ) -> anyhow::Result<()> {
        if transition.purpose != DealPurpose::Refresh {
            return Ok(());
        }
        if let Some(expected) =
            self.certified_avss_sessions.read().await.get(&transition.session).copied()
        {
            anyhow::ensure!(
                expected == avss_transition_digest(transition)?,
                "certified refresh session is bound to another transition"
            );
            return Ok(());
        }
        let old = transition.old.as_ref().context("zero refresh omitted its source epoch")?;
        let schedule = self
            .proactive_refresh_schedule
            .lock()
            .await
            .clone()
            .context("zero refresh has no durable fixed-interval schedule")?;
        anyhow::ensure!(
            schedule.source_epoch == old.committee.epoch
                && schedule.source_activation == old.activation_digest()?
                && schedule.target_epoch == Some(transition.target.epoch),
            "zero refresh differs from the active durable schedule"
        );
        let due = schedule.due_unix_ms.context("zero refresh schedule has no deadline")?;
        anyhow::ensure!(now_unix_ms >= due, "zero refresh is not due yet");
        if old.committee.member(self.party).is_ok() {
            anyhow::ensure!(
                *self.active_epoch.read().await == Some(old.committee.epoch),
                "zero refresh source is not the active epoch"
            );
        } else {
            transition.target.member(self.party)?;
        }
        Ok(())
    }

    async fn progress_key_rotation_view_change(
        self: &Arc<Self>,
        now_unix_ms: u64,
        base_timeout_ms: u64,
    ) -> anyhow::Result<()> {
        let _schedule_mutation = self.proactive_refresh_schedule_mutation.lock().await;
        let Some(schedule) = self.proactive_refresh_schedule.lock().await.clone() else {
            return Ok(());
        };
        let (Some(anchor_view), Some(view_started)) =
            (schedule.rotation_view, schedule.rotation_view_started_unix_ms)
        else {
            return Ok(());
        };
        let mut live = self.key_rotation.lock().await;
        let Some(runtime) = live.as_mut() else {
            return Ok(());
        };
        if runtime.round.certificate().is_some() {
            return Ok(());
        }
        let context = runtime.round.context().clone();
        let current_view = runtime.round.view();
        if current_view != anchor_view {
            anyhow::ensure!(
                current_view > anchor_view,
                "live key-rotation view regressed behind its durable pacemaker"
            );
            self.persist_key_rotation_view_anchor_locked(
                &context,
                current_view,
                now_unix_ms,
                KeyRotationPacemakerUpdate::PreserveExponent,
            )
            .await?;
            return Ok(());
        }
        let deadline = view_started.saturating_add(qual_backoff_timeout_ms(
            base_timeout_ms,
            schedule.rotation_timeout_exponent,
        ));
        if now_unix_ms < deadline {
            return Ok(());
        }
        let identity = self.identity(context.source().epoch)?;
        let before = runtime.round.clone();
        if let Err(error) = runtime.round.request_view_change(&identity) {
            if error == KeyRotationError::ConsensusNotReady {
                return Ok(());
            }
            return Err(error.into());
        }
        if runtime.round == before {
            return Ok(());
        }
        let revision =
            runtime.revision.checked_add(1).context("key-rotation revision exhausted")?;
        // Write the monotonic timeout anchor before the corresponding local view-change vote.
        // A crash between these writes may conservatively retain a longer timeout without the
        // vote, but can never restore a shorter timeout around an already durable vote.
        if let Err(error) = self
            .persist_key_rotation_view_anchor_locked(
                &context,
                current_view,
                now_unix_ms,
                KeyRotationPacemakerUpdate::AdvanceTimeout,
            )
            .await
        {
            runtime.round = before;
            return Err(error);
        }
        if let Err(error) = self
            .protocol_store
            .save_key_rotation_round(&context, revision, &runtime.round, &mut OsRng)
            .await
        {
            runtime.round = before;
            return Err(error.into());
        }
        runtime.revision = revision;
        Ok(())
    }

    /// Drive coordinator-free liveness for every durable AVSS session.
    ///
    /// The clock controls only leader rotation; all safety decisions remain certificate-based.
    /// A decided QUAL value is finalized from local AVSS outputs, staged durably, and followed by
    /// a signed activation acknowledgement in the same durable outbox checkpoint.
    pub async fn progress_protocols(
        self: &Arc<Self>,
        now_unix_ms: u64,
        qual_round_timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!qual_round_timeout.is_zero(), "QUAL round timeout must be positive");
        self.start_due_proactive_refresh(now_unix_ms).await?;
        let base_timeout_ms = u64::try_from(qual_round_timeout.as_millis())
            .context("QUAL round timeout does not fit u64 milliseconds")?;
        self.progress_key_rotation_view_change(now_unix_ms, base_timeout_ms).await?;
        let certified = self.certified_avss_sessions.read().await.clone();
        let sessions = {
            let runs = self.avss.lock().await;
            let mut live = Vec::new();
            for (session, run) in runs.iter() {
                if !avss_run_is_certified(*session, run, &certified)? {
                    live.push(*session);
                }
            }
            live
        };

        for session in sessions {
            let mut activate = None;
            // A zero refresh consumes the active predecessor share during aggregation. Taking the
            // epoch fence before the AVSS reducer prevents a concurrent certified handoff from
            // erasing that share while this transition is being staged.
            let _epoch_transition = self.epoch_transition.lock().await;
            {
                let mut runs = self.avss.lock().await;
                let Some(run) = runs.get_mut(&session) else {
                    continue;
                };
                if self.hold_acceptance_protocol_fault_gate_if_boundary(run).await? {
                    continue;
                }
                if self.acceptance_protocol_fault_gate.lock().await.blocks_session(session) {
                    continue;
                }
                if run.finalized.is_none() {
                    let before = run.clone();
                    if start_qual_if_needed(self, run)?.is_some()
                        && let Err(error) = self.persist_avss_run(run).await
                    {
                        *run = before;
                        return Err(error.context("cannot checkpoint autonomous QUAL start"));
                    }
                    if self.hold_acceptance_protocol_fault_gate_if_boundary(run).await? {
                        continue;
                    }
                }
                if run.finalized.is_none()
                    && run.qual_start_response.is_some()
                    && run.qual.as_ref().is_some_and(|qual| qual.decision().is_none())
                    && qual_round_expired(
                        run.qual_round_started_unix_ms,
                        now_unix_ms,
                        qual_backoff_timeout_ms(base_timeout_ms, run.qual_timeout_exponent),
                    )
                {
                    let before = run.clone();
                    let retained = run.qual_valid_witnesses.clone();
                    let qual = run.qual.as_mut().expect("QUAL presence was checked above");
                    let prior_requested_round = qual.requested_round();
                    let step = qual.advance_round()?;
                    let response =
                        make_qual_response(self, &run.transition, qual, step, retained.as_ref())?;
                    update_qual_witness_state(self, run, None, &response.outbound)?;
                    let transition = run.transition.clone();
                    enqueue_qual_outbound(run, &transition, &response.outbound)?;
                    let target_round = response
                        .requested_round
                        .context("QUAL timeout did not emit a round-change request")?;
                    anyhow::ensure!(
                        prior_requested_round.checked_add(1) == Some(target_round),
                        "QUAL timeout request did not advance monotonically"
                    );
                    apply_qual_pacemaker_step(run, &response, now_unix_ms)?;
                    run.qual_advance_response = Some(CachedQualAdvanceResponse {
                        prior_requested_round,
                        target_round,
                        response,
                    });
                    if let Err(error) = self.persist_avss_run(run).await {
                        *run = before;
                        return Err(
                            error.context("cannot checkpoint autonomous QUAL round advance")
                        );
                    }
                }

                let decision = run.qual.as_ref().and_then(QualConsensus::decision).cloned();
                if run.finalized.is_none()
                    && let Some(decision) = decision
                {
                    let before = run.clone();
                    decision.certificate.value.validate(&qual_config(&run.transition)?)?;
                    let selected = decision
                        .certificate
                        .value
                        .entries
                        .iter()
                        .map(|entry| entry.dealer)
                        .collect::<Vec<_>>();
                    let mut selected_outputs = BTreeMap::new();
                    for entry in &decision.certificate.value.entries {
                        let output = run.outputs.get(&entry.dealer).with_context(|| {
                            format!(
                                "local AVSS output for decided dealer {} is unavailable",
                                entry.dealer
                            )
                        })?;
                        anyhow::ensure!(
                            output.commitment_digest == entry.commitment,
                            "local AVSS output differs from the QUAL decision"
                        );
                        selected_outputs.insert(entry.dealer, output.clone());
                    }
                    let transcript = avss_transcript_digest(&run.transition, &selected_outputs)?;
                    let outputs =
                        selected_outputs.values().map(AvssOutput::dealer_output).collect();
                    let refresh_source = zero_refresh_source_share(self, &run.transition).await?;
                    let share = aggregate_avss_outputs(
                        &run.transition,
                        self.party,
                        &selected,
                        outputs,
                        refresh_source.as_ref(),
                    )?;
                    let response = self.stage(run.transition.clone(), share, transcript).await?;
                    let value = activation_value(&response);
                    let acknowledgement =
                        sign_activation_acknowledgement(self, &run.transition, &value)?;
                    let digest =
                        *blake3::hash(&postcard::to_allocvec(&acknowledgement)?).as_bytes();
                    for member in &run.transition.target.members {
                        if member.id != self.party {
                            run.pending_activation_ack
                                .insert((member.id, digest), acknowledgement.clone());
                        }
                    }
                    run.activation_acknowledgements.insert(self.party, acknowledgement);
                    run.finalized = Some(response);
                    if let Err(error) = self.persist_avss_run(run).await {
                        *run = before;
                        return Err(error.context("cannot checkpoint autonomous AVSS finalization"));
                    }
                }

                if let Some(response) = &run.finalized {
                    let quorum =
                        usize::from(run.transition.target.n() - run.transition.fault_bound);
                    if run.activation_acknowledgements.len() >= quorum {
                        activate = Some(ActivateEpochRequest {
                            transition: run.transition.clone(),
                            value: activation_value(response),
                            acknowledgements: run
                                .activation_acknowledgements
                                .values()
                                .cloned()
                                .collect(),
                        });
                    }
                }
            }
            drop(_epoch_transition);
            if let Some(request) = activate {
                let _response = activate_epoch(State(self.clone()), Json(request))
                    .await
                    .map_err(|error| error.0)?;
            }
        }
        Ok(())
    }

    async fn persist_activation_certificate(
        &self,
        transition: &AvssTransition,
        value: &ActivationValue,
        acknowledgements: &[SignedEnvelope],
    ) -> anyhow::Result<()> {
        validate_avss_transition(self, transition)?;
        verify_activation_certificate(self, transition, value, acknowledgements)?;
        let history = self.epoch_history.read().await.clone();
        if history.tip_epoch().is_some_and(|tip| value.epoch <= tip) {
            let (entry, _) = self
                .epoch_history_entry(&history, value.epoch)
                .await?
                .context("certified historical epoch is absent from epoch history")?;
            anyhow::ensure!(
                entry.consensus_link() == value.history_link
                    && entry.transition_digest() == avss_transition_digest(transition)?
                    && entry.activation_digest() == value.activation_digest,
                "activation retry conflicts with authenticated epoch history"
            );
            return Ok(());
        }
        let mut acknowledgements = acknowledgements.to_vec();
        acknowledgements.sort_unstable_by_key(|acknowledgement| acknowledgement.from);
        let record = ActivationCertificateRecord {
            transition: transition.clone(),
            value: value.clone(),
            acknowledgements,
        };
        let encoded = postcard::to_allocvec(&record)?;
        let transition_key = ActivationTransitionKey {
            epoch: value.epoch,
            transition_digest: avss_transition_digest(transition)?,
        };
        if self.accept_existing_activation_certificate(transition_key, transition, value).await? {
            let durable = self
                .protocol_store
                .load_activation_certificate(value.epoch, value.activation_digest)
                .await?;
            self.persist_epoch_history_activation(transition, value, durable.as_bytes()).await?;
            self.remember_certified_history_link(value.history_link)?;
            self.remember_certified_avss_transition(transition).await?;
            return Ok(());
        }
        match self
            .protocol_store
            .save_indexed_activation_certificate(
                value.epoch,
                transition_key.transition_digest,
                value.activation_digest,
                &encoded,
                &mut OsRng,
            )
            .await
        {
            Ok(()) => {
                self.persist_epoch_history_activation(transition, value, &encoded).await?;
                self.remember_certified_history_link(value.history_link)?;
                self.remember_certified_avss_transition(transition).await
            }
            Err(StoreError::ActivationCertificateConflict { .. }) => {
                anyhow::ensure!(
                    self.accept_existing_activation_certificate(transition_key, transition, value)
                        .await?,
                    "activation certificate publication raced without a durable winner"
                );
                let durable = self
                    .protocol_store
                    .load_activation_certificate(value.epoch, value.activation_digest)
                    .await?;
                self.persist_epoch_history_activation(transition, value, durable.as_bytes())
                    .await?;
                self.remember_certified_history_link(value.history_link)?;
                self.remember_certified_avss_transition(transition).await
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Cache only the exact transition digest whose activation certificate is already durable
    /// and fully verified. The durable record remains authoritative; this cache is rebuilt and
    /// reauthenticated during startup before any retained session is classified as certified.
    async fn remember_certified_avss_transition(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<()> {
        let digest = avss_transition_digest(transition)?;
        let mut certified = self.certified_avss_sessions.write().await;
        if let Some(existing) = certified.get(&transition.session) {
            anyhow::ensure!(
                *existing == digest,
                "AVSS session is certified for another transition"
            );
        } else {
            certified.insert(transition.session, digest);
        }
        drop(certified);
        self.compact_certified_avss_transition(transition).await?;
        Ok(())
    }

    /// Replace one certificate-finalized AVSS snapshot with a read-back-verified public/ciphertext
    /// catch-up form. This runs before activation/retirement may erase the predecessor share.
    async fn compact_certified_avss_transition(
        &self,
        transition: &AvssTransition,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            self.transition_has_durable_activation_certificate(transition).await?,
            "AVSS secret compaction lacks its durable activation certificate"
        );
        let context = avss_transition_digest(transition)?;
        let path = self.protocol_store.session_state_path(transition.session, context);
        let mut runs = self.avss.lock().await;
        let live = runs.get(&transition.session);
        if live.is_none() && !tokio::fs::try_exists(&path).await? {
            return Ok(false);
        }

        let mut candidate = if let Some(live) = live {
            anyhow::ensure!(live.transition == *transition, "certified AVSS session changed");
            live.clone()
        } else {
            let bytes = self.protocol_store.load_session_state(transition.session, context).await?;
            let DurableSessionState::Avss(run) = decode_postcard_exact(bytes.as_bytes())?;
            anyhow::ensure!(run.transition == *transition, "certified AVSS snapshot changed");
            run
        };
        if !candidate.secret_compacted {
            compact_avss_secret_state(&mut candidate);
        }
        validate_avss_secret_compaction(&candidate)?;
        validate_qual_witness_state(self, &candidate)?;
        let expected = encode_durable_avss_run(&candidate)?;
        self.protocol_store
            .save_session_state(transition.session, context, &expected, &mut OsRng)
            .await?;
        let readback = self.protocol_store.load_session_state(transition.session, context).await?;
        anyhow::ensure!(
            readback.as_bytes() == expected.as_slice(),
            "AVSS secret compaction readback differs from the persisted snapshot"
        );
        let DurableSessionState::Avss(durable) = decode_postcard_exact(readback.as_bytes())?;
        anyhow::ensure!(durable.transition == *transition);
        validate_avss_secret_compaction(&durable)?;
        validate_qual_witness_state(self, &durable)?;
        if let Some(live) = runs.get_mut(&transition.session) {
            *live = durable;
        }
        Ok(true)
    }

    async fn assert_retiring_epoch_avss_secret_compacted(&self, epoch: u64) -> anyhow::Result<()> {
        let references_epoch = |run: &AvssRun| {
            run.transition.target.epoch == epoch
                || run.transition.old.as_ref().is_some_and(|old| old.committee.epoch == epoch)
        };
        let certified = self.certified_avss_sessions.read().await.clone();
        {
            let runs = self.avss.lock().await;
            for run in runs.values().filter(|run| references_epoch(run)) {
                anyhow::ensure!(
                    certified.get(&run.transition.session)
                        == Some(&avss_transition_digest(&run.transition)?),
                    "retiring epoch is still referenced by an uncertified AVSS reducer"
                );
                validate_avss_secret_compaction(run)?;
                anyhow::ensure!(
                    run.secret_compacted,
                    "retiring epoch is still referenced by plaintext AVSS state in RAM"
                );
            }
        }

        let (gate_session, gate_context) = acceptance_consolidation_gate_storage_key(
            self.scenario.quic_network_id()?,
            self.party,
        )?;
        let (bootstrap_session, bootstrap_context) =
            acceptance_consolidation_bootstrap_gate_storage_key(
                self.scenario.quic_network_id()?,
                self.party,
            )?;
        for key in self.protocol_store.session_states().await? {
            if (key.session == gate_session && key.context_digest == gate_context)
                || (key.session == bootstrap_session && key.context_digest == bootstrap_context)
            {
                continue;
            }
            let bytes =
                self.protocol_store.load_session_state(key.session, key.context_digest).await?;
            let DurableSessionState::Avss(run) = decode_postcard_exact(bytes.as_bytes())?;
            if !references_epoch(&run) {
                continue;
            }
            anyhow::ensure!(
                self.transition_has_durable_activation_certificate(&run.transition).await?,
                "retiring epoch is still referenced by an uncertified durable AVSS reducer"
            );
            validate_avss_secret_compaction(&run)?;
            anyhow::ensure!(
                run.secret_compacted,
                "retiring epoch is still referenced by plaintext AVSS state on disk"
            );
        }
        Ok(())
    }

    /// Preserve the first fully verified certificate representation for a semantic transition
    /// and value. Different valid acknowledgement subsets need not rewrite permanent bytes.
    async fn accept_existing_activation_certificate(
        &self,
        transition_key: ActivationTransitionKey,
        transition: &AvssTransition,
        value: &ActivationValue,
    ) -> anyhow::Result<bool> {
        let path =
            self.protocol_store.activation_certificate_path(value.epoch, value.activation_digest);
        if !tokio::fs::try_exists(path).await? {
            return Ok(false);
        }
        let bytes = self
            .protocol_store
            .load_activation_certificate(value.epoch, value.activation_digest)
            .await?;
        let existing: ActivationCertificateRecord = decode_postcard_exact(&bytes)?;
        anyhow::ensure!(
            existing.transition == *transition && existing.value == *value,
            "activation certificate key is already bound to another transition or value"
        );
        validate_avss_transition(self, &existing.transition)?;
        verify_activation_certificate(
            self,
            &existing.transition,
            &existing.value,
            &existing.acknowledgements,
        )?;
        self.protocol_store
            .ensure_activation_transition_index(transition_key, value.activation_digest, &mut OsRng)
            .await?;
        Ok(true)
    }

    async fn stage(
        &self,
        transition: AvssTransition,
        share: EpochShare,
        avss_transcript_digest: [u8; 32],
    ) -> anyhow::Result<InstallResponse> {
        share.validate()?;
        let activation_digest = share.activation_digest()?;
        let history_link = EpochHistoryLink::new(
            self.scenario.quic_network_id()?,
            share.key_id,
            share.committee.epoch,
            transition.history_parent.root(),
            avss_transition_digest(&transition)?,
            activation_digest,
            avss_transcript_digest,
            self.key_rotation_semantic_digest(share.committee.epoch)?,
        )?;
        let response = InstallResponse {
            party: self.party,
            epoch: share.committee.epoch,
            public: share.public(),
            activation_digest,
            avss_transcript_digest,
            history_link,
        };
        if let Some(existing) = self.activations.read().await.get(&share.committee.epoch) {
            anyhow::ensure!(
                existing.public == response.public
                    && existing.activation_digest == response.activation_digest
                    && existing.avss_transcript_digest == response.avss_transcript_digest
                    && existing.history_link == response.history_link,
                "another epoch value is already active"
            );
            return Ok(existing.clone());
        }
        let mut staged = self.staged.write().await;
        if let Some(existing) = staged.get(&share.committee.epoch) {
            anyhow::ensure!(
                existing.response.public == response.public
                    && existing.response.activation_digest == response.activation_digest
                    && existing.response.avss_transcript_digest == avss_transcript_digest
                    && existing.response.history_link == response.history_link,
                "another epoch value is already staged"
            );
            return Ok(existing.response.clone());
        }
        // Check for a competing staged value before replacing the epoch-named share file.
        self.store.save(&share, &mut OsRng).await?;
        staged.insert(
            share.committee.epoch,
            StagedEpoch { transition, share, response: response.clone() },
        );
        Ok(response)
    }
}

fn decode_canonical_postcard<T>(body: &[u8]) -> anyhow::Result<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let value = decode_postcard_exact(body)?;
    anyhow::ensure!(
        postcard::to_allocvec(&value)? == body,
        "peer request body is not canonical postcard"
    );
    Ok(value)
}

fn ensure_relevant_transition_peer(
    authenticated_party: PartyId,
    transition: &AvssTransition,
) -> anyhow::Result<()> {
    let target = transition.target.member(authenticated_party).is_ok();
    let old = transition
        .old
        .as_ref()
        .is_some_and(|old| old.committee.member(authenticated_party).is_ok());
    anyhow::ensure!(target || old, "TLS party is not a peer in either transition committee");
    Ok(())
}

fn is_expected_deposit_reconciliation_gap(error: &anyhow::Error) -> bool {
    error.downcast_ref::<DepositServiceError>().is_some_and(|error| {
        matches!(
            error,
            DepositServiceError::CertifiedHandoffUnavailable(_)
                | DepositServiceError::NotInitialized
        )
    })
}

fn quic_peer_rejection(error: anyhow::Error) -> PeerResponse {
    let deposit_classification =
        error.downcast_ref::<DepositServiceError>().map(classify_deposit_rejection);
    let rotation_retryable = error.downcast_ref::<KeyRotationError>().is_some_and(|error| {
        matches!(
            error,
            KeyRotationError::ConsensusNotReady
                | KeyRotationError::Consensus(
                    ConsensusError::NotStarted | ConsensusError::FutureView { .. }
                )
        )
    });
    let mut message = error.to_string();
    // Stay comfortably below the transport's hard rejection-body limit, including UTF-8 input.
    const MAX_MESSAGE_BYTES: usize = 2048;
    if message.len() > MAX_MESSAGE_BYTES {
        let mut end = MAX_MESSAGE_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    let lower = message.to_ascii_lowercase();
    let (code, retryable) = if let Some(classification) = deposit_classification {
        classification
    } else if rotation_retryable {
        (RejectionCode::Unavailable, true)
    } else if lower.contains("too many live") {
        (RejectionCode::ResourceExhausted, true)
    } else if lower.contains("unknown avss session")
        || lower.contains("not started")
        || lower.contains("future round")
        || lower.contains("round differs")
        || lower.contains("has not locally completed")
        || lower.contains("uncertified dealer")
        || lower.contains("not staged")
        || lower.contains("neither staged nor active")
        || lower.contains("must activate the successor")
        || lower.contains("does not extend the active epoch")
        || lower.contains("live predecessor epoch shares remain")
        || lower.contains("source epoch lacks a locally durable authenticated activation")
        || lower.contains("lacks a locally durable key-rotation certificate")
        || lower.contains("dynamic avss target lacks its durable key-rotation certificate")
        || lower.contains("zero refresh is not due yet")
        || lower.contains("key rotation is not due yet")
        || lower.contains("key rotation has no durable proactive schedule")
        || lower.contains("acceptance protocol fault gate is held")
    {
        (RejectionCode::Unavailable, true)
    } else if lower.contains("i/o")
        || lower.contains("cannot checkpoint")
        || lower.contains("failed to persist")
    {
        (RejectionCode::Internal, true)
    } else if lower.contains("tombstone")
        || lower.contains("equivocat")
        || lower.contains("another transition")
        || lower.contains("already finalized")
    {
        (RejectionCode::Conflict, false)
    } else {
        (RejectionCode::InvalidRequest, false)
    };
    PeerResponse::Rejected { code, retryable, message }
}

fn classify_deposit_rejection(error: &DepositServiceError) -> (RejectionCode, bool) {
    match error {
        DepositServiceError::NotInitialized
        | DepositServiceError::MissingScannerAnchor
        | DepositServiceError::WrongEpoch
        | DepositServiceError::CertifiedHandoffUnavailable(_)
        | DepositServiceError::WrongRegistry
        | DepositServiceError::UnknownSlot(_)
        | DepositServiceError::StaleConsolidationCandidate
        | DepositServiceError::HandoffPending
        | DepositServiceError::ConsolidationNotPortable
        | DepositServiceError::ConsolidationCompletionMismatch
        | DepositServiceError::ConsolidationNotCertified
        | DepositServiceError::ConsensusUnavailable
        | DepositServiceError::Consensus(
            ConsensusError::NotStarted | ConsensusError::FutureView { .. },
        )
        | DepositServiceError::ConsolidationWire(ConsolidationWireError::Worker(
            DepositWorkerError::StaleSweepPlan,
        ))
        | DepositServiceError::Worker(
            DepositWorkerError::StaleSweepPlan
            | DepositWorkerError::PendingEvents(_)
            | DepositWorkerError::AllocationBackfillRequired
            | DepositWorkerError::DaemonBehindAnchor { .. }
            | DepositWorkerError::DaemonBehindState { .. },
        ) => (RejectionCode::Unavailable, true),
        DepositServiceError::Ledger(
            LedgerError::Gap { .. }
            | LedgerError::RegistryMismatch
            | LedgerError::UnknownOrInactiveEpoch
            | LedgerError::RevisionMismatch
            | LedgerError::TerminalAdmissionRequired,
        ) => (RejectionCode::Unavailable, true),
        DepositServiceError::TooManyPendingSlots
        | DepositServiceError::TooManyPendingObservations
        | DepositServiceError::ConsensusRequestPoolFull
        | DepositServiceError::OutboxFull => (RejectionCode::ResourceExhausted, true),
        DepositServiceError::Io(_)
        | DepositServiceError::Storage(_)
        | DepositServiceError::StorageRevisionMismatch
        | DepositServiceError::ChainSource(_)
        | DepositServiceError::ConsolidationBackendUnavailable
        | DepositServiceError::Worker(
            DepositWorkerError::ChainSource(_)
            | DepositWorkerError::Daemon(_)
            | DepositWorkerError::RequestTimeout { .. }
            | DepositWorkerError::AnchorMismatch(_)
            | DepositWorkerError::AllocationBackfillBranchChanged
            | DepositWorkerError::PersistenceMismatch,
        ) => (RejectionCode::Internal, true),
        DepositServiceError::SlotConflict(_)
        | DepositServiceError::RequestEquivocation
        | DepositServiceError::RequestAlreadyReserved
        | DepositServiceError::AttestationEquivocation(_)
        | DepositServiceError::ObservationEquivocation
        | DepositServiceError::OutboxEquivocation
        | DepositServiceError::ConsolidationWireEquivocation
        | DepositServiceError::ConsolidationRecoveryHistoryIncomplete
        | DepositServiceError::ConsolidationRecoveryRequired
        | DepositServiceError::ConsolidationRoundClosed => (RejectionCode::Conflict, false),
        _ => (RejectionCode::InvalidRequest, false),
    }
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn acceptance_consolidation_gate(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AcceptanceConsolidationGateRequest>,
) -> Result<Json<AcceptanceConsolidationGateResponse>, ApiError> {
    Ok(Json(server.update_acceptance_consolidation_gate(request.action).await?))
}

async fn acceptance_consolidation_bootstrap_gate(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AcceptanceConsolidationBootstrapGateRequest>,
) -> Result<Json<AcceptanceConsolidationBootstrapGateResponse>, ApiError> {
    Ok(Json(server.update_acceptance_consolidation_bootstrap_gate(request.action).await?))
}

async fn acceptance_protocol_fault_gate(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AcceptanceProtocolFaultGateRequest>,
) -> Result<Json<AcceptanceProtocolFaultGateResponse>, ApiError> {
    Ok(Json(server.update_acceptance_protocol_fault_gate(request).await?))
}

async fn acceptance_proactive_refresh_release(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AcceptanceProactiveRefreshReleaseRequest>,
) -> Result<Json<AcceptanceProactiveRefreshReleaseResponse>, ApiError> {
    Ok(Json(
        server
            .release_acceptance_proactive_refresh_hold(request.source_epoch, unix_time_millis()?)
            .await?,
    ))
}

async fn acceptance_driver_latch(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AcceptanceDriverLatchRequest>,
) -> Result<Json<AcceptanceDriverLatchResponse>, ApiError> {
    Ok(Json(server.update_acceptance_driver_latch(request).await?))
}

async fn acceptance_deposit_checkpoint_gate(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AcceptanceDepositCheckpointGateRequest>,
) -> Result<Json<AcceptanceDepositCheckpointGateResponse>, ApiError> {
    Ok(Json(server.update_acceptance_deposit_checkpoint_gate(request).await?))
}

async fn require_admin(
    State(authenticator): State<BearerAuthenticator>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match authenticator.authorize_headers(request.headers(), AllowedRoles::ADMIN) {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => auth_rejection(error),
    }
}

async fn require_deposits(
    State(authenticator): State<BearerAuthenticator>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match authenticator.authorize_headers(request.headers(), AllowedRoles::ADMIN_OR_DEPOSITS) {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => auth_rejection(error),
    }
}

fn auth_rejection(error: AuthError) -> Response {
    let status = if error == AuthError::Forbidden {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    };
    tracing::warn!(%error, "control request authorization rejected");
    let mut response =
        (status, Json(serde_json::json!({ "error": error.to_string() }))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, "Bearer".parse().expect("static header is valid"));
    }
    response
}

async fn status(State(server): State<Arc<PartyServer>>) -> Result<Json<PartyStatus>, ApiError> {
    let epochs_guard = server.epochs.read().await;
    let epochs = {
        let links = server
            .history_links
            .read()
            .map_err(|_| anyhow::anyhow!("epoch-history registry lock is poisoned"))?;
        epochs_guard
            .iter()
            .map(|(epoch, share)| {
                Ok(EpochStatus {
                    epoch: *epoch,
                    public: share.public(),
                    history_link: *links
                        .get(epoch)
                        .context("active epoch lacks its certified history link")?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    drop(epochs_guard);
    let active_epoch = *server.active_epoch.read().await;
    let staged_epochs = server.staged.read().await.keys().copied().collect();
    let proactive_refresh =
        server.proactive_refresh_schedule.lock().await.as_ref().map(|schedule| {
            ProactiveRefreshStatus {
                source_epoch: schedule.source_epoch,
                target_epoch: schedule.target_epoch,
                due_unix_ms: schedule.due_unix_ms,
            }
        });
    // Status is a local observation endpoint. Full issuance synchronization performs bounded
    // Monero daemon RPC and belongs only on an allocation/worker path, never on liveness checks.
    let deposit_ready = server.deposit.as_ref().map(|deposit| deposit.local_runtime_ready());
    Ok(Json(PartyStatus {
        party: server.party,
        ready: server.is_ready(),
        deposit_ready,
        deposit_chain_ready: server
            .deposit_chain_readiness
            .as_ref()
            .map(DepositChainReadiness::is_ready),
        active_epoch,
        staged_epochs,
        epochs,
        proactive_refresh,
        authenticated_quic_ingress: server.authenticated_quic_ingress.load(Ordering::Acquire),
        authenticated_quic_responses: server.authenticated_quic_responses.load(Ordering::Acquire),
    }))
}

async fn deposit_allocate(
    State(server): State<Arc<PartyServer>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<DepositAddressRequest>,
) -> Result<Response, ApiError> {
    server.reconcile_deposit_targets().await?;
    let deposit = server.deposit.as_ref().context("deposit wallet service is not enabled")?;
    let deposit_epoch = deposit.active_epoch().await?;
    let signing_epoch =
        server.active_epoch.read().await.context("party has no active signing epoch")?;
    api_ensure(
        deposit_epoch == signing_epoch,
        "deposit issuance is paused until the certified epoch handoff is applied",
    )?;
    api_ensure(
        server.deposit_issuance_is_synchronized().await?,
        "deposit issuance is paused until n-f authenticated peers agree on the ledger tip",
    )?;
    let external_request = request.request;
    let request = tenant_deposit_request(&principal, request)?;
    let response = deposit
        .submit_allocation_request(
            request,
            unix_time_millis()?,
            server.identity(signing_epoch)?.as_ref(),
        )
        .await?;
    let issuer_registry = deposit.active_registry().await?;
    Ok(deposit_http_response(external_request, response, issuer_registry).into_response())
}

async fn deposit_status(
    State(server): State<Arc<PartyServer>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<DepositAddressRequest>,
) -> Result<Response, ApiError> {
    server.ensure_deposit_initialized().await?;
    let deposit = server.deposit.as_ref().context("deposit wallet service is not enabled")?;
    let external_request = request.request;
    let request = tenant_deposit_request(&principal, request)?;
    let response = deposit.address_status(request, unix_time_seconds()?).await?;
    let issuer_registry = deposit.active_registry().await?;
    Ok(deposit_http_response(external_request, response, issuer_registry).into_response())
}

async fn deposit_consolidation_status(
    State(server): State<Arc<PartyServer>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Json(request): Json<DepositAddressRequest>,
) -> Result<Json<DepositConsolidationStatusResponse>, ApiError> {
    server.ensure_deposit_initialized().await?;
    let deposit = server.deposit.as_ref().context("deposit wallet service is not enabled")?;
    let external_request = request.request;
    let certified_request = tenant_deposit_request(&principal, request)?.request;
    let consolidations =
        deposit.public_consolidation_statuses_for_request(certified_request).await?;
    Ok(Json(DepositConsolidationStatusResponse {
        request: external_request,
        certified_request,
        consolidations,
    }))
}

fn tenant_deposit_request(
    principal: &AuthenticatedPrincipal,
    supplied: DepositAddressRequest,
) -> anyhow::Result<DepositAddressRequest> {
    let mut binding_hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-http-tenant-binding/v2");
    binding_hasher.update(&(principal.name.len() as u64).to_le_bytes());
    binding_hasher.update(principal.name.as_bytes());
    binding_hasher.update(&supplied.request.0);
    binding_hasher.update(&supplied.binding.0);
    let binding = RequestBinding(*binding_hasher.finalize().as_bytes());
    Ok(DepositAddressRequest { request: deposit_request_id_for_binding(binding), binding })
}

fn deposit_http_response(
    external_request: LedgerRequestId,
    response: DepositAddressResponse,
    issuer_registry: CompactEpochRegistry,
) -> (StatusCode, Json<DepositHttpResponse>) {
    let syncing = response.status == DepositAddressStatus::Syncing;
    let response = DepositHttpResponse {
        request: external_request,
        certified_request: response.request,
        status: match response.status {
            DepositAddressStatus::Syncing => DepositHttpStatus::Syncing,
            DepositAddressStatus::Pending => DepositHttpStatus::Pending,
            DepositAddressStatus::Active => DepositHttpStatus::Active,
            DepositAddressStatus::Expired => DepositHttpStatus::Expired,
            DepositAddressStatus::Permanent => DepositHttpStatus::Permanent,
        },
        // A stale scanner must never leak an address or a certificate through an accidentally
        // populated service response. Clients can retry this same tenant-local idempotency key.
        address: (!syncing).then_some(response.address).flatten(),
        certificate: (!syncing).then_some(response.certificate).flatten(),
        issuer_registry: (!syncing).then_some(issuer_registry),
        created_at: (!syncing).then_some(response.created_at).flatten(),
        expires_at: (!syncing).then_some(response.expires_at).flatten(),
        leader: response.leader,
    };
    let status = if syncing { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK };
    (status, Json(response))
}

async fn avss_start(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AvssStartRequest>,
) -> Result<Json<AvssStepResponse>, ApiError> {
    validate_avss_transition(&server, &request.transition)?;
    server.ensure_reshare_source_certified(&request.transition).await?;
    server.ensure_refresh_due_for_live_ingress(&request.transition, unix_time_millis()?).await?;
    let expected = expected_avss_dealers(&request.transition);
    api_ensure(expected.contains(&server.party), "local party is not an AVSS dealer")?;

    // Retirement takes consolidation_transition -> epoch_transition -> AVSS/signing state.
    // Acquire the same epoch-before-AVSS suffix here and retain it until the dealer's encrypted
    // outbound is durably checkpointed. The start therefore linearizes wholly before retirement,
    // or observes the retired/missing old share without ever cloning its scalar into a dealer.
    let _epoch_transition = server.epoch_transition.lock().await;
    let certified = server.certified_avss_sessions.read().await.clone();
    let mut runs = server.avss.lock().await;
    if let Some(run) = runs.get(&request.transition.session) {
        api_ensure(
            run.transition == request.transition,
            "session was bound to another transition",
        )?;
        if run.secret_compacted {
            validate_avss_secret_compaction(run)?;
            return Ok(Json(AvssStepResponse {
                party: server.party,
                dealer: server.party,
                completed: false,
                completion: None,
                outbound: Vec::new(),
                qual: None,
            }));
        }
        if let Some(outbound) = &run.dealer_outbound {
            let response = AvssStepResponse {
                party: server.party,
                dealer: server.party,
                completed: false,
                completion: None,
                outbound: outbound.clone(),
                qual: None,
            };
            server.ensure_avss_run_durable(run).await?;
            server.hold_acceptance_protocol_fault_gate_if_boundary(run).await?;
            return Ok(Json(response));
        }
        api_ensure(run.finalized.is_none(), "AVSS session is already finalized")?;
    } else {
        server.ensure_avss_session_open(request.transition.session).await?;
    }

    let config = avss_config(&server, &request.transition, server.party)?;
    let dealer = match request.transition.purpose {
        DealPurpose::Dkg => AvssDealer::random(config, &mut OsRng)?,
        DealPurpose::Refresh => {
            let old = request.transition.old.as_ref().context("zero refresh omitted old epoch")?;
            api_ensure(
                *server.active_epoch.read().await == Some(old.committee.epoch),
                "zero refresh source is not the active epoch",
            )?;
            let epochs = server.epochs.read().await;
            let old_share =
                epochs.get(&old.committee.epoch).context("old share is not installed")?;
            api_ensure(old_share.public() == *old, "old public metadata differs")?;
            // A timed same-committee refresh never deals the old scalar. Each current member
            // contributes an independently randomized zero sharing which is added only after
            // exact n-f QUAL.
            AvssDealer::random_zero_constant(config, &mut OsRng)?
        }
        DealPurpose::Reshare => {
            let old = request.transition.old.as_ref().context("reshare omitted old epoch")?;
            api_ensure(
                *server.active_epoch.read().await == Some(old.committee.epoch),
                "reshare source is not the active epoch",
            )?;
            let old_share = server
                .epochs
                .read()
                .await
                .get(&old.committee.epoch)
                .cloned()
                .context("old share is not installed")?;
            api_ensure(old_share.public() == *old, "old public metadata differs")?;
            // The interpolation subset is not known until availability certificates have been
            // agreed. Deal the raw old share; recipients weight every coefficient after selection.
            AvssDealer::random_with_constant(config, old_share.secret_share(), &mut OsRng)?
        }
    };
    let outbound = dealer
        .private_messages()?
        .into_iter()
        .map(|message| seal_avss_message(&server, &request.transition, server.party, message))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let inserted = !runs.contains_key(&request.transition.session);
    if inserted {
        ensure_avss_live_capacity(&runs, &certified, &request.transition, MAX_LIVE_AVSS_RUNS)?;
        runs.insert(request.transition.session, new_avss_run(&server, request.transition.clone())?);
    }
    let run = runs.get_mut(&request.transition.session).expect("AVSS run was inserted above");
    api_ensure(run.transition == request.transition, "session was bound to another transition")?;
    let before = run.clone();
    let qual = start_qual_if_needed(&server, run)?;
    run.dealer_outbound = Some(outbound.clone());
    enqueue_avss_outbound(run, &outbound)?;
    if let Err(error) = server.persist_avss_run(run).await {
        if inserted {
            runs.remove(&request.transition.session);
        } else {
            *runs.get_mut(&request.transition.session).expect("AVSS run remains present") = before;
        }
        return Err(error.into());
    }
    server.hold_acceptance_protocol_fault_gate_if_boundary(run).await?;
    Ok(Json(AvssStepResponse {
        party: server.party,
        dealer: server.party,
        completed: false,
        completion: None,
        outbound,
        qual,
    }))
}

async fn avss_deliver(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<AvssDeliverRequest>,
) -> Result<Json<AvssStepResponse>, ApiError> {
    validate_avss_transition(&server, &request.transition)?;
    server.ensure_reshare_source_certified(&request.transition).await?;
    server.ensure_refresh_due_for_live_ingress(&request.transition, unix_time_millis()?).await?;
    request.transition.target.member(server.party)?;
    api_ensure(request.wire.version == AVSS_WIRE_VERSION, "unsupported AVSS wire version")?;
    api_ensure(request.wire.recipient == server.party, "AVSS wire is for another party")?;
    api_ensure(
        expected_avss_dealers(&request.transition).contains(&request.wire.dealer),
        "unexpected AVSS dealer",
    )?;

    let wire_digest = avss_wire_digest(&request.wire)?;
    let logical_key = (request.wire.envelope.from, request.wire.envelope.sequence);
    // Authenticate and decrypt before allocating an in-memory/durable session slot. Invalid input
    // must not be able to leave a provisional run that poisons later legitimate creation.
    let message = open_avss_wire(&server, &request.transition, &request.wire)?;
    let certified = server.certified_avss_sessions.read().await.clone();
    let mut runs = server.avss.lock().await;
    api_ensure(
        !server
            .acceptance_protocol_fault_gate
            .lock()
            .await
            .blocks_session(request.transition.session),
        "acceptance protocol fault gate is held",
    )?;
    let inserted = !runs.contains_key(&request.transition.session);
    if inserted {
        server.ensure_avss_session_open(request.transition.session).await?;
        ensure_avss_live_capacity(&runs, &certified, &request.transition, MAX_LIVE_AVSS_RUNS)?;
        runs.insert(request.transition.session, new_avss_run(&server, request.transition.clone())?);
    }
    let run = runs.get_mut(&request.transition.session).expect("AVSS run was inserted above");
    api_ensure(run.transition == request.transition, "session was bound to another transition")?;
    if let Some(cached) = run.delivery_responses.get(&logical_key) {
        api_ensure(cached.wire_digest == wire_digest, "AVSS logical slot equivocated")?;
        let response = cached.response.clone();
        server.ensure_avss_run_durable(run).await?;
        server.hold_acceptance_protocol_fault_gate_if_boundary(run).await?;
        return Ok(Json(response));
    }
    if run.secret_compacted {
        validate_avss_secret_compaction(run)?;
        return Ok(Json(AvssStepResponse {
            party: server.party,
            dealer: request.wire.dealer,
            completed: false,
            completion: None,
            outbound: Vec::new(),
            qual: None,
        }));
    }
    api_ensure(run.finalized.is_none(), "AVSS session is already finalized")?;

    let before = run.clone();
    let sender = request.wire.envelope.from;
    let dealer = request.wire.dealer;
    let state = run.receivers.entry(dealer).or_insert(AvssParty::new(
        avss_config(&server, &request.transition, dealer)?,
        server.party,
    )?);
    let step = state.handle(sender, message)?;
    let outbound = step
        .outbound
        .into_iter()
        .map(|message| seal_avss_message(&server, &request.transition, server.party, message))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut qual_response = None;
    if let Some(output) = step.completed {
        if let Err(error) = validate_completed_avss_output(&request.transition, dealer, &output) {
            if inserted {
                runs.remove(&request.transition.session);
            } else {
                *run = before;
            }
            return Err(error.into());
        }
        let retained = run.qual_valid_witnesses.clone();
        let certification_response = {
            let qual = run.qual.as_mut().context("target AVSS run omitted QUAL state")?;
            let qual_step =
                qual.certify(QualEntry { dealer, commitment: output.commitment_digest })?;
            make_qual_response(&server, &request.transition, qual, qual_step, retained.as_ref())?
        };
        update_qual_witness_state(&server, run, None, &certification_response.outbound)?;
        apply_qual_pacemaker_step(run, &certification_response, unix_time_millis()?)?;
        run.outputs.insert(dealer, output);
        qual_response = start_qual_if_needed(&server, run)?.or(Some(certification_response));
    }
    let completion = run
        .outputs
        .get(&dealer)
        .map(|output| sign_avss_completion(&server, &request.transition, output))
        .transpose()?;
    let completed = completion.is_some();
    let response = AvssStepResponse {
        party: server.party,
        dealer,
        completed,
        completion,
        outbound,
        qual: qual_response,
    };
    enqueue_avss_outbound(run, &response.outbound)?;
    if let Some(qual) = &response.qual {
        enqueue_qual_outbound(run, &request.transition, &qual.outbound)?;
    }
    run.delivery_responses
        .insert(logical_key, CachedAvssResponse { wire_digest, response: response.clone() });
    if let Err(error) = server.persist_avss_run(run).await {
        if inserted {
            runs.remove(&request.transition.session);
        } else {
            *runs.get_mut(&request.transition.session).expect("AVSS run remains present") = before;
        }
        return Err(error.into());
    }
    server.hold_acceptance_protocol_fault_gate_if_boundary(run).await?;
    Ok(Json(response))
}

/// Check purpose-specific AVSS constants before local availability certification.
///
/// Refresh accepts only a publicly verifiable zero constant. Redistribution accepts only the
/// dealer's exact old verification share. Delaying either check until final aggregation would let
/// a valid-but-wrong commitment enter an irrevocable QUAL and destroy liveness.
fn validate_completed_avss_output(
    transition: &AvssTransition,
    dealer: PartyId,
    output: &AvssOutput,
) -> anyhow::Result<()> {
    anyhow::ensure!(output.instance.dealer == dealer, "AVSS output dealer differs");
    match (&transition.purpose, &transition.old) {
        (DealPurpose::Dkg, None) => Ok(()),
        (DealPurpose::Refresh, Some(_)) => {
            anyhow::ensure!(
                output.x_axis_commitment.has_zero_constant()?,
                "zero-refresh dealer AVSS constant is not zero"
            );
            Ok(())
        }
        (DealPurpose::Reshare, Some(old)) => {
            let expected = old
                .verification_shares
                .get(&dealer)
                .context("resharing dealer is absent from old verification shares")?;
            let supplied = output
                .x_axis_commitment
                .coefficients
                .first()
                .context("resharing AVSS output has no constant commitment")?;
            anyhow::ensure!(
                supplied == expected,
                "resharing dealer AVSS constant differs from its old verification share"
            );
            Ok(())
        }
        _ => anyhow::bail!("AVSS purpose and old epoch are inconsistent"),
    }
}

async fn zero_refresh_source_share(
    server: &PartyServer,
    transition: &AvssTransition,
) -> anyhow::Result<Option<EpochShare>> {
    if transition.purpose != DealPurpose::Refresh {
        return Ok(None);
    }
    let old = transition.old.as_ref().context("zero refresh omitted old epoch")?;
    anyhow::ensure!(
        *server.active_epoch.read().await == Some(old.committee.epoch),
        "zero refresh source is not the active epoch"
    );
    let source = server
        .epochs
        .read()
        .await
        .get(&old.committee.epoch)
        .cloned()
        .context("zero refresh source share is not installed")?;
    anyhow::ensure!(source.public() == *old, "zero refresh source public metadata differs");
    Ok(Some(source))
}

fn aggregate_avss_outputs(
    transition: &AvssTransition,
    local_party: PartyId,
    selected: &[PartyId],
    outputs: Vec<crate::keys::DealerOutput>,
    refresh_source: Option<&EpochShare>,
) -> anyhow::Result<EpochShare> {
    Ok(match (&transition.purpose, &transition.old) {
        (DealPurpose::Dkg, None) => aggregate_dkg_subset(
            transition.key_id,
            transition.target.clone(),
            local_party,
            transition.fault_bound,
            selected,
            outputs,
        )?,
        (DealPurpose::Refresh, Some(old)) => {
            let source = refresh_source.context("zero refresh omitted its local source share")?;
            anyhow::ensure!(source.public() == *old, "zero refresh source metadata changed");
            aggregate_zero_share_refresh(
                source,
                transition.target.clone(),
                local_party,
                transition.fault_bound,
                selected,
                outputs,
            )?
        }
        (DealPurpose::Reshare, Some(old)) => aggregate_proactive_reshare_from_public(
            old,
            transition.target.clone(),
            local_party,
            selected,
            outputs,
        )?,
        _ => anyhow::bail!("AVSS purpose and old epoch are inconsistent"),
    })
}

async fn qual_deliver(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<QualDeliverRequest>,
) -> Result<Json<QualStepResponse>, ApiError> {
    validate_avss_transition(&server, &request.transition)?;
    server.ensure_refresh_due_for_live_ingress(&request.transition, unix_time_millis()?).await?;
    request.transition.target.member(server.party)?;
    api_ensure(request.wire.version == QUAL_WIRE_VERSION, "unsupported QUAL wire version")?;
    let digest = qual_wire_digest(&request.wire)?;
    let (sender, message) = open_qual_wire(&server, &request.transition, &request.wire)?;
    let (message_round, message_kind) = qual_message_metadata(&message)?;
    validate_qual_message_structure(&request.transition, sender, &message)?;
    let logical_key = (sender, message_kind);
    let verified_proof = match qual_message_proof_of_lock(&message) {
        Some((carrying_round, proof)) => {
            verify_qual_proof_witnesses(
                &server,
                &request.transition,
                carrying_round,
                proof,
                &request.wire.proof_of_lock_witnesses,
            )?;
            Some(proof.clone())
        }
        None => None,
    };
    let mut runs = server.avss.lock().await;
    api_ensure(
        !server
            .acceptance_protocol_fault_gate
            .lock()
            .await
            .blocks_session(request.transition.session),
        "acceptance protocol fault gate is held",
    )?;
    let Some(run) = runs.get_mut(&request.transition.session) else {
        drop(runs);
        server
            .closed_transition_activation_record(&request.transition)
            .await?
            .context("unknown AVSS session")?;
        return Ok(Json(QualStepResponse {
            party: server.party,
            round: message_round,
            decision: None,
            outbound: Vec::new(),
            evidence: Vec::new(),
            entered_round: None,
            requested_round: None,
            duplicate: true,
            changed: false,
        }));
    };
    api_ensure(run.transition == request.transition, "session was bound to another transition")?;
    if run.secret_compacted {
        validate_avss_secret_compaction(run)?;
        return Ok(Json(QualStepResponse {
            party: server.party,
            round: message_round,
            decision: None,
            outbound: Vec::new(),
            evidence: Vec::new(),
            entered_round: None,
            requested_round: None,
            duplicate: true,
            changed: false,
        }));
    }
    if let Some(cached) = run.qual_delivery_responses.get(&logical_key) {
        if cached.round > message_round {
            let response = make_qual_noop_response(
                &server,
                run.qual.as_ref().context("target AVSS run omitted QUAL state")?,
            );
            server.ensure_avss_run_durable(run).await?;
            return Ok(Json(response));
        }
        if cached.round == message_round {
            api_ensure(cached.wire_digest == digest, "QUAL logical slot equivocated")?;
            server.ensure_avss_run_durable(run).await?;
            return Ok(Json(cached.response.clone()));
        }
    }
    api_ensure(run.finalized.is_none(), "AVSS session is already finalized")?;
    let before = run.clone();
    let step = {
        let qual = run.qual.as_mut().context("target AVSS run omitted QUAL state")?;
        if let Some(expected) = verified_proof {
            qual.handle_with_proof_of_lock_verifier(sender, message, |candidate| {
                candidate == &expected
            })
        } else {
            qual.handle(sender, message)
        }
    };
    let step = match step {
        Ok(step) => step,
        Err(error) => {
            *run = before;
            return Err(error.into());
        }
    };
    if let Err(error) = update_qual_witness_state(&server, run, Some(&request.wire), &[]) {
        *run = before;
        return Err(error.into());
    }
    let retained = run.qual_valid_witnesses.clone();
    let response = {
        let qual = run.qual.as_ref().context("target AVSS run omitted QUAL state")?;
        make_qual_response(&server, &request.transition, qual, step, retained.as_ref())
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            *run = before;
            return Err(error.into());
        }
    };
    if let Err(error) = update_qual_witness_state(&server, run, None, &response.outbound) {
        *run = before;
        return Err(error.into());
    }
    enqueue_qual_outbound(run, &request.transition, &response.outbound)?;
    run.qual_delivery_responses.insert(
        logical_key,
        CachedQualResponse {
            round: message_round,
            wire_digest: digest,
            response: response.clone(),
        },
    );
    apply_qual_pacemaker_step(run, &response, unix_time_millis()?)?;
    if let Err(error) = server.persist_avss_run(run).await {
        *run = before;
        return Err(error.into());
    }
    server.hold_acceptance_protocol_fault_gate_if_boundary(run).await?;
    Ok(Json(response))
}

/// Run every context/structure/leader check independently of mutable reducer state. Live delivery
/// applies the same fence before its post-decision no-op path; after compaction, the exact
/// transition tombstone and activation certificate replace local dealer-availability state.
fn validate_qual_message_structure(
    transition: &AvssTransition,
    sender: PartyId,
    message: &QualMessage,
) -> anyhow::Result<u64> {
    let config = qual_config(transition)?;
    config.committee().member(sender)?;
    anyhow::ensure!(message.context == config.digest(), "QUAL context differs");
    let round = match &message.body {
        QualMessageBody::Proposal(proposal) => {
            proposal.value.validate(&config)?;
            let zero_based = proposal.round % u64::from(config.committee().n());
            let leader_index = u16::try_from(zero_based + 1)
                .context("QUAL leader index exceeds committee bound")?;
            anyhow::ensure!(
                config.committee().party_for_frost_index(leader_index)? == sender,
                "QUAL proposal did not come from the round leader"
            );
            if let Some(proof) = &proposal.proof_of_lock {
                proof.validate_structure(&config, proposal.round, &proposal.value)?;
            }
            proposal.round
        }
        QualMessageBody::Vote(vote) => vote.round,
        QualMessageBody::RoundChange(change) => {
            anyhow::ensure!(change.round > 0, "QUAL round-change target must be positive");
            if let Some(proof) = &change.proof_of_lock {
                proof.validate_structure(&config, change.round, &proof.value)?;
            }
            change.round
        }
        QualMessageBody::NewRound(new_round) => {
            anyhow::ensure!(
                new_round.round == new_round.certificate.round
                    && new_round.round == new_round.proposal.round,
                "QUAL new-round components differ"
            );
            new_round.certificate.validate_structure(&config)?;
            new_round.proposal.value.validate(&config)?;
            let zero_based = new_round.round % u64::from(config.committee().n());
            let leader_index = u16::try_from(zero_based + 1)
                .context("QUAL leader index exceeds committee bound")?;
            anyhow::ensure!(
                config.committee().party_for_frost_index(leader_index)? == sender,
                "QUAL new-round did not come from the target leader"
            );
            let highest = new_round.certificate.highest_proof_of_lock()?;
            match (&highest, &new_round.proposal.proof_of_lock) {
                (None, None) => {}
                (Some(expected), Some(actual))
                    if expected == actual && new_round.proposal.value == expected.value => {}
                _ => anyhow::bail!(
                    "QUAL new-round proposal differs from its highest certified proof of lock"
                ),
            }
            new_round.round
        }
    };
    Ok(round)
}

fn sign_activation_acknowledgement(
    server: &PartyServer,
    transition: &AvssTransition,
    value: &ActivationValue,
) -> anyhow::Result<SignedEnvelope> {
    let statement = activation_statement(value, transition.session);
    server
        .identity(value.epoch)?
        .sign_envelope(
            &transition.target,
            transition.session,
            None,
            activation_sequence(value.epoch),
            postcard::to_allocvec(&statement)?,
        )
        .map_err(Into::into)
}

// Non-async boxing shims for the epoch operations. Each of these reducers is an independent
// multi-hundred-kilobyte async frame; `dispatch_epoch_peer_request` selects exactly one per call.
// Constructing them inline (even behind a call-site `Box::pin`) reserves one full reducer frame per
// arm because debug lowering does not overlap the construction temporaries, inflating the dispatch
// poll frame past a megabyte. Building and boxing each reducer inside its own shim frame keeps only
// an eight-byte pointer live in the dispatcher.
fn boxed_activation_ack_deliver(
    server: Arc<PartyServer>,
    request: ActivationAckDeliverRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>> {
    Box::pin(activation_ack_deliver(server, request))
}

fn boxed_activate_epoch(
    server: State<Arc<PartyServer>>,
    request: Json<ActivateEpochRequest>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Json<InstallResponse>, ApiError>> + Send>,
> {
    Box::pin(activate_epoch(server, request))
}

fn boxed_retire_epoch(
    server: State<Arc<PartyServer>>,
    request: Json<RetireEpochRequest>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StatusCode, ApiError>> + Send>> {
    Box::pin(retire_epoch(server, request))
}

fn boxed_observe_epoch_certificate<'a>(
    server: &'a Arc<PartyServer>,
    request: ActivateEpochRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(observe_epoch_certificate(server, request))
}

fn boxed_retire_local_predecessor_after_activation<'a>(
    server: &'a Arc<PartyServer>,
    request: &'a ActivateEpochRequest,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ApiError>> + Send + 'a>> {
    Box::pin(retire_local_predecessor_after_activation(server, request))
}

async fn activation_ack_deliver(
    server: Arc<PartyServer>,
    request: ActivationAckDeliverRequest,
) -> anyhow::Result<()> {
    validate_avss_transition(&server, &request.transition)?;
    request.transition.target.member(server.party)?;
    validate_activation_acknowledgement_context(
        &server,
        &request.transition,
        &request.acknowledgement,
    )?;
    let epoch = request.transition.target.epoch;
    let (value, closed_replay) = if let Some(staged) = server.staged.read().await.get(&epoch) {
        anyhow::ensure!(staged.transition == request.transition, "staged transition differs");
        (activation_value(&staged.response), false)
    } else if let Some(active) = server.activations.read().await.get(&epoch).cloned() {
        (activation_value(&active), false)
    } else if let Some(record) =
        server.closed_transition_activation_record(&request.transition).await?
    {
        (record.value, true)
    } else {
        anyhow::bail!("target epoch is neither staged nor active");
    };
    verify_activation_acknowledgement(
        &server,
        &request.transition,
        &value,
        &request.acknowledgement,
    )?;

    if closed_replay {
        return Ok(());
    }

    if server.activations.read().await.contains_key(&epoch) {
        return Ok(());
    }

    let certificate = {
        let mut runs = server.avss.lock().await;
        anyhow::ensure!(
            !server
                .acceptance_protocol_fault_gate
                .lock()
                .await
                .blocks_session(request.transition.session),
            "acceptance protocol fault gate is held"
        );
        let Some(run) = runs.get_mut(&request.transition.session) else {
            drop(runs);
            let record = server
                .closed_transition_activation_record(&request.transition)
                .await?
                .context("unknown AVSS session")?;
            anyhow::ensure!(
                record.value == value,
                "closed activation value differs from the acknowledged value"
            );
            return Ok(());
        };
        anyhow::ensure!(
            run.transition == request.transition,
            "session was bound to another transition"
        );
        anyhow::ensure!(run.finalized.is_some(), "target epoch is not staged by the AVSS session");
        let sender = request.acknowledgement.from;
        if let Some(previous) = run.activation_acknowledgements.get(&sender) {
            anyhow::ensure!(previous == &request.acknowledgement, "activation signer equivocated");
        } else {
            let before = run.clone();
            run.activation_acknowledgements.insert(sender, request.acknowledgement);
            if let Err(error) = server.persist_avss_run(run).await {
                *run = before;
                return Err(error.context("cannot checkpoint activation acknowledgement"));
            }
        }
        let quorum = usize::from(request.transition.target.n() - request.transition.fault_bound);
        (run.activation_acknowledgements.len() >= quorum).then(|| ActivateEpochRequest {
            transition: request.transition.clone(),
            value: value.clone(),
            acknowledgements: run.activation_acknowledgements.values().cloned().collect(),
        })
    };

    if let Some(certificate) = certificate {
        let _response =
            activate_epoch(State(server), Json(certificate)).await.map_err(|error| error.0)?;
    }
    Ok(())
}

fn validate_activation_acknowledgement_context(
    server: &PartyServer,
    transition: &AvssTransition,
    acknowledgement: &SignedEnvelope,
) -> anyhow::Result<()> {
    Identity::verify_envelope(&transition.target, server.party, acknowledgement)?;
    anyhow::ensure!(acknowledgement.to.is_none(), "activation acknowledgement must be broadcast");
    anyhow::ensure!(acknowledgement.session == transition.session, "activation session differs");
    anyhow::ensure!(
        acknowledgement.sequence == activation_sequence(transition.target.epoch),
        "activation logical sequence differs"
    );
    let statement: ActivationStatement = decode_postcard_exact(&acknowledgement.payload)?;
    anyhow::ensure!(
        statement.version == 1
            && statement.session == transition.session
            && statement.key_id == transition.key_id
            && statement.epoch == transition.target.epoch
            && statement.committee == transition.target.digest(),
        "activation acknowledgement context differs"
    );
    Ok(())
}

fn verify_activation_acknowledgement(
    server: &PartyServer,
    transition: &AvssTransition,
    value: &ActivationValue,
    acknowledgement: &SignedEnvelope,
) -> anyhow::Result<()> {
    validate_activation_acknowledgement_context(server, transition, acknowledgement)?;
    let statement: ActivationStatement = decode_postcard_exact(&acknowledgement.payload)?;
    anyhow::ensure!(
        statement == activation_statement(value, transition.session),
        "activation acknowledgement value differs"
    );
    Ok(())
}

async fn observe_epoch_certificate(
    server: &Arc<PartyServer>,
    request: ActivateEpochRequest,
) -> anyhow::Result<()> {
    validate_avss_transition(server, &request.transition)?;
    verify_activation_certificate(
        server,
        &request.transition,
        &request.value,
        &request.acknowledgements,
    )?;
    // Observation is deliberately passive: stable certificate storage and public deposit history
    // only. It never creates, installs, or retires a threshold share.
    server
        .persist_activation_certificate(
            &request.transition,
            &request.value,
            &request.acknowledgements,
        )
        .await?;
    server.remember_certified_deposit_target(&request.value).await?;
    let mut targets = server.deposit_targets.write().await;
    if let Some(old) = request.transition.old {
        targets.entry(old.committee.epoch).or_insert(old);
    }
    drop(targets);
    if server
        .key_rotation_context_for_source(&request.value.public)?
        .is_some_and(|context| context.target_policy().eligible().member(server.party).is_ok())
    {
        server
            .arm_proactive_refresh_for_activation(&request.value.public, unix_time_millis()?)
            .await?;
    }
    if let Err(error) = server.progress_deposit_state().await {
        tracing::debug!(party = %server.party, epoch = request.value.epoch, %error, "passive deposit history observation remains fail-closed");
    }
    Ok(())
}

/// Complete the local half of a certified resharing transition without depending on an epoch
/// certificate making a pointless QUIC round trip back to its issuer. The activation caller must
/// release both transition locks before entering here because [`retire_epoch`] reacquires them in
/// the global consolidation-then-epoch order.
async fn retire_local_predecessor_after_activation(
    server: &Arc<PartyServer>,
    request: &ActivateEpochRequest,
) -> Result<(), ApiError> {
    let Some(old) = request.transition.old.as_ref() else {
        return Ok(());
    };
    if old.committee.member(server.party).is_err() {
        return Ok(());
    }
    boxed_retire_epoch(State(server.clone()), Json(request.clone())).await?;
    Ok(())
}

async fn activate_epoch(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<ActivateEpochRequest>,
) -> Result<Json<InstallResponse>, ApiError> {
    validate_avss_transition(&server, &request.transition)?;
    request.transition.target.member(server.party)?;
    // Authenticate the supplied effect before consulting retryable local ordering state. A
    // malformed certificate is terminal even when this party has not staged the transition.
    verify_activation_certificate(
        &server,
        &request.transition,
        &request.value,
        &request.acknowledgements,
    )?;
    let epoch = request.transition.target.epoch;
    // Consolidation progress starts with this lock and then leases an epoch share. Preserve that
    // order at cutover so activation cannot deadlock a nonce start or let it cross the handoff
    // fence using a predecessor share.
    let _consolidation_transition = server.consolidation_transition.lock().await;
    let _epoch_transition = server.epoch_transition.lock().await;
    let (response, closed_replay) =
        if let Some(active) = server.activations.read().await.get(&epoch).cloned() {
            (active, false)
        } else if let Some(staged) = server.staged.read().await.get(&epoch) {
            api_ensure(staged.transition == request.transition, "staged transition differs")?;
            (staged.response.clone(), false)
        } else if let Some(record) =
            server.closed_transition_activation_record(&request.transition).await?
        {
            // A closed session proves protocol finality; the authenticated retirement marker
            // additionally proves this local target share was installed and later made unusable.
            // Without it this may be a current transition whose in-memory state needs recovery,
            // not a historical no-op.
            server
                .store
                .load_retirement(epoch, request.transition.target.digest())
                .await?
                .context("target epoch is not staged")?;
            api_ensure(
                record.value == request.value,
                "historical activation value differs from its durable certificate",
            )?;
            (
                InstallResponse {
                    party: server.party,
                    epoch: record.value.epoch,
                    public: record.value.public,
                    activation_digest: record.value.activation_digest,
                    avss_transcript_digest: record.value.avss_transcript_digest,
                    history_link: record.value.history_link,
                },
                true,
            )
        } else {
            return Err(ApiError(anyhow::anyhow!("target epoch is not staged")));
        };
    api_ensure(
        activation_value(&response) == request.value,
        "activation value differs from local staged state",
    )?;

    if closed_replay {
        server.remember_certified_deposit_target(&request.value).await?;
        return Ok(Json(response));
    }

    if server.activations.read().await.contains_key(&epoch) {
        server.remember_certified_deposit_target(&request.value).await?;
        if let Err(error) = server.boxed_progress_deposit_state().await {
            tracing::warn!(party = %server.party, epoch, %error, "deposit epoch catch-up remains fail-closed");
        }
        server.retire_transition_session_if_drained(&request.transition).await?;
        drop(_epoch_transition);
        drop(_consolidation_transition);
        boxed_retire_local_predecessor_after_activation(&server, &request).await?;
        return Ok(Json(response));
    }
    if let Some(old) = &request.transition.old {
        server.ensure_live_predecessors_retired(old.committee.epoch).await?;
    }
    let expected_previous = match &request.transition.old {
        None => None,
        Some(old) if old.committee.member(server.party).is_ok() => Some(old.committee.epoch),
        Some(_) => None,
    };
    api_ensure(
        *server.active_epoch.read().await == expected_previous,
        "activation does not extend the active epoch",
    )?;
    {
        let staged = server.staged.read().await;
        let staged = staged.get(&epoch).context("target epoch is not staged")?;
        api_ensure(
            activation_value(&staged.response) == request.value,
            "staged activation response changed",
        )?;
    }
    // Persist the successor deadline before publishing the activation certificate. Durable-state
    // restoration treats a valid certificate plus the staged share as active, so certificate-first
    // ordering would leave a crash window in which restart silently reset the refresh clock.
    // Retrying the same activation preserves this exact deadline.
    server.arm_proactive_refresh_for_activation(&request.value.public, unix_time_millis()?).await?;
    let certified_root = request.value.history_link.root()?;
    if let Some(old) = &request.transition.old {
        // Close deposit/consolidation ingress on the exact successor before its activation
        // certificate can become durable. `prepare_deposit_handoff` accepts only the one
        // post-checkpoint retry condition: an already released nonce-bearing consolidation may
        // finish under its old-epoch scoped signing lease.
        server.boxed_prepare_deposit_handoff(old, &request.value.public, certified_root).await?;
    }
    // The certificate reaches stable storage before the share becomes usable for signing.
    server
        .persist_activation_certificate(
            &request.transition,
            &request.value,
            &request.acknowledgements,
        )
        .await?;
    server.remember_certified_deposit_target(&request.value).await?;
    if let Some(old) = &request.transition.old {
        server
            .deposit_targets
            .write()
            .await
            .entry(old.committee.epoch)
            .or_insert_with(|| old.clone());
    } else {
        if let Err(error) = server.boxed_ensure_deposit_initialized().await {
            tracing::warn!(party = %server.party, epoch, %error, "deposit genesis initialization deferred; issuance remains closed");
        }
    }
    let staged =
        server.staged.write().await.remove(&epoch).context("target epoch is not staged")?;
    server.epochs.write().await.insert(epoch, staged.share);
    *server.active_epoch.write().await = Some(epoch);
    server.activations.write().await.insert(epoch, response.clone());
    server.retire_key_rotation_after_activation(&request.value.public).await?;
    if let Err(error) = server.boxed_progress_deposit_state().await {
        tracing::warn!(party = %server.party, epoch, %error, "deposit epoch catch-up deferred; issuance remains closed");
    }
    server.retire_transition_session_if_drained(&request.transition).await?;
    // The successor share and its activation certificate have both survived durable readback at
    // this point. Retire this party's predecessor directly; peer certificate routes deliberately
    // exclude self and therefore cannot be the trigger for local crypto-erasure.
    drop(_epoch_transition);
    drop(_consolidation_transition);
    boxed_retire_local_predecessor_after_activation(&server, &request).await?;
    Ok(Json(response))
}

async fn retire_epoch(
    State(server): State<Arc<PartyServer>>,
    Json(request): Json<RetireEpochRequest>,
) -> Result<StatusCode, ApiError> {
    validate_avss_transition(&server, &request.transition)?;
    let old = request.transition.old.as_ref().context("DKG has no prior epoch to retire")?;
    old.committee.member(server.party)?;
    let consolidation_transition = server.consolidation_transition.lock().await;
    let _epoch_transition = server.epoch_transition.lock().await;
    request.value.public.validate()?;
    api_ensure(request.value.epoch == request.transition.target.epoch, "retirement epoch differs")?;
    api_ensure(
        request.value.public.committee.digest() == request.transition.target.digest(),
        "retirement target committee differs",
    )?;
    api_ensure(request.value.public.key_id == old.key_id, "retirement key id differs")?;
    api_ensure(
        request.value.activation_digest == request.value.public.activation_digest()?,
        "retirement activation digest is invalid",
    )?;
    api_ensure(
        request.value.public.group_key_bytes() == old.group_key_bytes(),
        "retirement certificate changes the group key",
    )?;
    verify_activation_certificate(
        &server,
        &request.transition,
        &request.value,
        &request.acknowledgements,
    )?;

    let expected_retirement = ShareRetirement::for_certified_successor(
        old.committee.epoch,
        old.committee.digest(),
        request.value.epoch,
        request.value.activation_digest,
    )?;
    if let Some(retirement) =
        server.store.load_retirement(old.committee.epoch, old.committee.digest()).await?
    {
        // The share marker is the durable proof that all pre-retirement gates (including the
        // portable deposit handoff) completed. Pair it with the fully revalidated permanent
        // activation record before acknowledging an old replay after a later epoch advanced.
        api_ensure(
            retirement == expected_retirement,
            "historical share retirement context differs",
        )?;
        let record = server
            .durable_activation_record_for_transition(&request.transition)
            .await?
            .context("retired share lacks a durable activation certificate")?;
        api_ensure(
            record.value == request.value,
            "historical retirement value differs from its durable certificate",
        )?;
        server
            .drain_retiring_epoch_signers(
                &consolidation_transition,
                &_epoch_transition,
                old.committee.epoch,
            )
            .await?;
        server.retire_key_rotation_source_identity_after_handoff(&request.value.public).await?;
        return Ok(StatusCode::NO_CONTENT);
    }

    server.ensure_live_predecessors_retired(old.committee.epoch).await?;
    if request.transition.target.member(server.party).is_ok() {
        api_ensure(
            *server.active_epoch.read().await == Some(request.transition.target.epoch),
            "overlapping member must activate the successor before retiring the old epoch",
        )?;
    }

    // A removed party durably records the new epoch before making its obsolete share unusable.
    // For an overlapping member, the assertion above additionally proves the successor share was
    // installed. The old share stays installed until every old-epoch portable obligation is
    // certified, because an in-flight consolidation must not be stranded by retirement.
    server
        .persist_activation_certificate(
            &request.transition,
            &request.value,
            &request.acknowledgements,
        )
        .await?;
    let certified_root = server.remember_certified_deposit_target(&request.value).await?;
    server.deposit_targets.write().await.entry(old.committee.epoch).or_insert_with(|| old.clone());

    // A proposed handoff is not enough: do not destroy the sole old-epoch authorization until
    // this party has durably applied the old quorum's terminal ledger certificate. The QUIC
    // rejection remains retryable and permanent activation-certificate gossip will call us again.
    server
        .certify_deposit_handoff_before_share_retirement(old, &request.value.public, certified_root)
        .await?;
    server
        .drain_retiring_epoch_signers(
            &consolidation_transition,
            &_epoch_transition,
            old.committee.epoch,
        )
        .await?;
    server.epochs.write().await.remove(&old.committee.epoch);
    server.activations.write().await.remove(&old.committee.epoch);
    let mut active_epoch = server.active_epoch.write().await;
    if *active_epoch == Some(old.committee.epoch) {
        *active_epoch = None;
    }
    drop(active_epoch);
    if tokio::fs::try_exists(server.store.share_path(old.committee.epoch)).await? {
        server.store.retire_share(expected_retirement).await?;
    }
    server.retire_key_rotation_source_identity_after_handoff(&request.value.public).await?;

    if let Err(error) = server.progress_deposit_state().await {
        tracing::warn!(party = %server.party, epoch = request.value.epoch, %error, "deposit epoch catch-up deferred after share retirement");
    }
    server.retire_transition_session_if_drained(&request.transition).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Non-async boxing shim for the deposit apply-handoff segment, mirroring the `boxed_*` helpers on
/// `PartyServer`: the ~quarter-megabyte segment future is built and boxed inside this frame so the
/// caller keeps only a pointer live across its await.
fn boxed_apply_certified_handoff<'a>(
    deposit: &'a DepositService,
    old: &'a EpochPublic,
    target: &'a EpochPublic,
    certified_root: [u8; 32],
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DepositServiceError>> + Send + 'a>>
{
    Box::pin(deposit.apply_certified_handoff(old, target, certified_root))
}

/// Non-async boxing shim for the consolidation-completion proposal segment (a ~quarter-megabyte
/// async frame) so a driver that proposes several sweeps in a loop keeps only a pointer live.
fn boxed_propose_consolidation_completion<'a>(
    deposit: &'a DepositService,
    sweep: SweepId,
    identity: &'a Identity,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DepositServiceError>> + Send + 'a>>
{
    Box::pin(deposit.propose_consolidation_completion(sweep, identity))
}

/// Non-async boxing shim for the Byzantine-consolidation progress segment, keeping its
/// ~quarter-megabyte construction temporary out of the caller's poll frame.
fn boxed_progress_byzantine_consolidations<'a>(
    deposit: &'a DepositService,
    identity: &'a Identity,
    now_ms: u64,
    base_timeout_ms: u64,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<Vec<ByzantineConsolidationAction>, DepositServiceError>,
            > + Send
            + 'a,
    >,
> {
    Box::pin(deposit.progress_byzantine_consolidations(identity, now_ms, base_timeout_ms))
}

fn activation_value(response: &InstallResponse) -> ActivationValue {
    ActivationValue {
        epoch: response.epoch,
        public: response.public.clone(),
        activation_digest: response.activation_digest,
        avss_transcript_digest: response.avss_transcript_digest,
        history_link: response.history_link,
    }
}

fn activation_statement(value: &ActivationValue, session: SessionId) -> ActivationStatement {
    ActivationStatement {
        version: 1,
        session,
        key_id: value.public.key_id,
        epoch: value.epoch,
        committee: value.public.committee.digest(),
        activation_digest: value.activation_digest,
        avss_transcript_digest: value.avss_transcript_digest,
        history_link: value.history_link,
    }
}

fn verify_activation_certificate(
    server: &PartyServer,
    transition: &AvssTransition,
    value: &ActivationValue,
    acknowledgements: &[SignedEnvelope],
) -> anyhow::Result<()> {
    anyhow::ensure!(value.epoch == transition.target.epoch, "activation epoch differs");
    anyhow::ensure!(value.public.committee.digest() == transition.target.digest());
    anyhow::ensure!(value.public.key_id == transition.key_id, "activation key id differs");
    anyhow::ensure!(value.activation_digest == value.public.activation_digest()?);
    let expected_history_link = EpochHistoryLink::new(
        server.scenario.quic_network_id()?,
        transition.key_id,
        value.epoch,
        transition.history_parent.root(),
        avss_transition_digest(transition)?,
        value.activation_digest,
        value.avss_transcript_digest,
        server.key_rotation_semantic_digest(value.epoch)?,
    )?;
    anyhow::ensure!(
        value.history_link == expected_history_link,
        "activation history link differs from its semantic transition/value"
    );
    let expected = activation_statement(value, transition.session);
    let quorum = usize::from(transition.target.n() - transition.fault_bound);
    let mut acknowledged = BTreeSet::new();
    for envelope in acknowledgements {
        Identity::verify_envelope(&transition.target, server.party, envelope)?;
        anyhow::ensure!(envelope.to.is_none(), "activation acknowledgement must be broadcast");
        anyhow::ensure!(envelope.session == transition.session, "activation session differs");
        anyhow::ensure!(
            envelope.sequence == activation_sequence(value.epoch),
            "activation logical sequence differs"
        );
        let statement: ActivationStatement = postcard::from_bytes(&envelope.payload)?;
        anyhow::ensure!(
            postcard::to_allocvec(&statement)? == envelope.payload,
            "activation acknowledgement has trailing bytes"
        );
        anyhow::ensure!(statement == expected, "activation acknowledgement value differs");
        anyhow::ensure!(acknowledged.insert(envelope.from), "duplicate activation signer");
    }
    anyhow::ensure!(acknowledged.len() >= quorum, "activation certificate lacks an n-f quorum");
    Ok(())
}

fn activation_sequence(epoch: u64) -> u64 {
    0xA_C71_0000_0000_0000_u64 | (epoch & 0x0000_FFFF_FFFF_FFFF)
}

fn qual_sequence(message: &QualMessage) -> anyhow::Result<u64> {
    let (round, kind) = qual_message_metadata(message)?;
    let kind_tag = match kind {
        QualWireKind::Proposal => 0_u64,
        QualWireKind::Prevote => 1,
        QualWireKind::Precommit => 2,
        QualWireKind::RoundChange => 3,
        QualWireKind::NewRound => 4,
    };
    anyhow::ensure!(round <= 0x0001_FFFF_FFFF_FFFF, "QUAL round exceeds wire bound");
    Ok(0x5100_0000_0000_0000_u64 | (round << 3) | kind_tag)
}

fn qual_message_metadata(message: &QualMessage) -> anyhow::Result<(u64, QualWireKind)> {
    let metadata = match &message.body {
        QualMessageBody::Proposal(proposal) => (proposal.round, QualWireKind::Proposal),
        QualMessageBody::Vote(vote) => (
            vote.round,
            match vote.phase {
                VotePhase::Prevote => QualWireKind::Prevote,
                VotePhase::Precommit => QualWireKind::Precommit,
            },
        ),
        QualMessageBody::RoundChange(change) => (change.round, QualWireKind::RoundChange),
        QualMessageBody::NewRound(new_round) => (new_round.round, QualWireKind::NewRound),
    };
    anyhow::ensure!(metadata.0 <= 0x0001_FFFF_FFFF_FFFF, "QUAL round exceeds wire bound");
    Ok(metadata)
}

fn qual_message_proof_of_lock(message: &QualMessage) -> Option<(u64, &ProofOfLockCertificate)> {
    match &message.body {
        QualMessageBody::Proposal(proposal) => {
            proposal.proof_of_lock.as_ref().map(|proof| (proposal.round, proof))
        }
        QualMessageBody::RoundChange(change) => {
            change.proof_of_lock.as_ref().map(|proof| (change.round, proof))
        }
        QualMessageBody::Vote(_) | QualMessageBody::NewRound(_) => None,
    }
}

fn seal_qual_message(
    server: &PartyServer,
    transition: &AvssTransition,
    message: QualMessage,
    retained: Option<&QualProofWitnessBundle>,
) -> anyhow::Result<QualWire> {
    let proof_of_lock_witnesses = match qual_message_proof_of_lock(&message) {
        Some((carrying_round, proof)) => {
            let retained = retained
                .context("QUAL message carries a proof of lock without durable signed witnesses")?;
            anyhow::ensure!(
                retained.proof == *proof,
                "QUAL retained POL differs from outbound message"
            );
            verify_qual_proof_witnesses(
                server,
                transition,
                carrying_round,
                proof,
                &retained.envelopes,
            )?;
            retained.envelopes.clone()
        }
        None => Vec::new(),
    };
    let sequence = qual_sequence(&message)?;
    let envelope = server.identity(transition.target.epoch)?.sign_envelope(
        &transition.target,
        transition.session,
        None,
        sequence,
        postcard::to_allocvec(&message)?,
    )?;
    Ok(QualWire { version: QUAL_WIRE_VERSION, envelope, proof_of_lock_witnesses })
}

fn open_qual_wire(
    server: &PartyServer,
    transition: &AvssTransition,
    wire: &QualWire,
) -> anyhow::Result<(PartyId, QualMessage)> {
    anyhow::ensure!(wire.version == QUAL_WIRE_VERSION, "unsupported QUAL wire version");
    Identity::verify_envelope(&transition.target, server.party, &wire.envelope)?;
    anyhow::ensure!(wire.envelope.to.is_none(), "QUAL message must be broadcast");
    anyhow::ensure!(wire.envelope.session == transition.session, "QUAL session differs");
    let message: QualMessage = decode_postcard_exact(&wire.envelope.payload)?;
    anyhow::ensure!(wire.envelope.sequence == qual_sequence(&message)?, "QUAL sequence differs");
    if qual_message_proof_of_lock(&message).is_none() {
        anyhow::ensure!(
            wire.proof_of_lock_witnesses.is_empty(),
            "QUAL message without a POL carries witness envelopes"
        );
    }
    Ok((wire.envelope.from, message))
}

fn verify_qual_prevote_envelope(
    server: &PartyServer,
    transition: &AvssTransition,
    envelope: &SignedEnvelope,
    expected_voter: PartyId,
    expected_vote: crate::qual::QualVote,
) -> anyhow::Result<()> {
    Identity::verify_envelope(&transition.target, server.party, envelope)?;
    anyhow::ensure!(envelope.from == expected_voter, "QUAL POL witness voter differs");
    anyhow::ensure!(envelope.to.is_none(), "QUAL POL witness must be broadcast");
    anyhow::ensure!(envelope.session == transition.session, "QUAL POL witness session differs");
    let message: QualMessage = decode_postcard_exact(&envelope.payload)?;
    anyhow::ensure!(
        message.context == qual_config(transition)?.digest(),
        "QUAL POL witness context differs"
    );
    anyhow::ensure!(
        message.body == QualMessageBody::Vote(expected_vote),
        "QUAL POL witness is not the named PREVOTE"
    );
    anyhow::ensure!(envelope.sequence == qual_sequence(&message)?, "QUAL POL sequence differs");
    Ok(())
}

fn verify_qual_proof_witnesses(
    server: &PartyServer,
    transition: &AvssTransition,
    carrying_round: u64,
    proof: &ProofOfLockCertificate,
    witnesses: &[SignedEnvelope],
) -> anyhow::Result<()> {
    proof.validate_structure(&qual_config(transition)?, carrying_round, &proof.value)?;
    anyhow::ensure!(
        witnesses.len() == proof.voters.len(),
        "QUAL POL witness count differs from its canonical voter set"
    );
    let expected_vote = proof.expected_prevote();
    for (voter, envelope) in proof.voters.iter().copied().zip(witnesses) {
        verify_qual_prevote_envelope(server, transition, envelope, voter, expected_vote)?;
    }
    Ok(())
}

fn make_qual_response(
    server: &PartyServer,
    transition: &AvssTransition,
    qual: &QualConsensus,
    step: QualStep,
    retained: Option<&QualProofWitnessBundle>,
) -> anyhow::Result<QualStepResponse> {
    let QualStep {
        broadcast,
        decision,
        evidence,
        entered_round,
        requested_round,
        duplicate,
        changed,
    } = step;
    let outbound = broadcast
        .into_iter()
        .map(|message| seal_qual_message(server, transition, message, retained))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(QualStepResponse {
        party: server.party,
        round: qual.round(),
        decision: decision.or_else(|| qual.decision().cloned()),
        outbound,
        evidence,
        entered_round,
        requested_round,
        duplicate,
        changed,
    })
}

fn make_qual_noop_response(server: &PartyServer, qual: &QualConsensus) -> QualStepResponse {
    QualStepResponse {
        party: server.party,
        round: qual.round(),
        decision: qual.decision().cloned(),
        outbound: Vec::new(),
        evidence: Vec::new(),
        entered_round: None,
        requested_round: None,
        duplicate: true,
        changed: false,
    }
}

fn apply_qual_pacemaker_step(
    run: &mut AvssRun,
    response: &QualStepResponse,
    now_unix_ms: u64,
) -> anyhow::Result<()> {
    let qual = run.qual.as_ref().context("target AVSS run omitted QUAL state")?;
    anyhow::ensure!(response.round == qual.round(), "QUAL response active round differs");
    if let Some(entered_round) = response.entered_round {
        anyhow::ensure!(
            entered_round == qual.round(),
            "QUAL entered-round metadata differs from reducer"
        );
    }
    if let Some(requested_round) = response.requested_round {
        anyhow::ensure!(
            requested_round == qual.requested_round(),
            "QUAL requested-round metadata differs from reducer"
        );
        run.qual_timeout_exponent = run.qual_timeout_exponent.saturating_add(1);
    }
    if response.entered_round.is_some() || response.requested_round.is_some() {
        run.qual_round_started_unix_ms = now_unix_ms;
    }
    Ok(())
}

fn archive_qual_wire(
    server: &PartyServer,
    run: &mut AvssRun,
    wire: &QualWire,
) -> anyhow::Result<()> {
    let Some(qual) = run.qual.as_ref() else {
        anyhow::bail!("QUAL wire cannot be retained by a non-voter AVSS run");
    };
    let (sender, message) = open_qual_wire(server, &run.transition, wire)?;
    validate_qual_message_structure(&run.transition, sender, &message)?;
    let (round, kind) = qual_message_metadata(&message)?;
    if let Some((carrying_round, proof)) = qual_message_proof_of_lock(&message) {
        verify_qual_proof_witnesses(
            server,
            &run.transition,
            carrying_round,
            proof,
            &wire.proof_of_lock_witnesses,
        )?;
    }
    let key = (sender, kind);
    if let Some(previous) = run.qual_signed_wires.get(&key) {
        if previous.round > round {
            return Ok(());
        }
        if previous.round == round {
            anyhow::ensure!(previous.wire == *wire, "same-round QUAL signed wire changed");
            return Ok(());
        }
    }
    run.qual_signed_wires.insert(key, ArchivedQualWire { round, wire: wire.clone() });
    anyhow::ensure!(
        run.qual_signed_wires.len() <= usize::from(qual.config().committee().n()) * 5,
        "QUAL signed-wire archive exceeds its fixed committee bound"
    );
    Ok(())
}

fn record_current_qual_prevote(
    server: &PartyServer,
    run: &mut AvssRun,
    envelope: &SignedEnvelope,
) -> anyhow::Result<()> {
    let Some(qual) = run.qual.as_ref() else {
        anyhow::bail!("QUAL witness cannot be retained by a non-voter AVSS run");
    };
    let message: QualMessage = decode_postcard_exact(&envelope.payload)?;
    let QualMessageBody::Vote(vote) = message.body else {
        return Ok(());
    };
    if vote.phase != VotePhase::Prevote {
        return Ok(());
    }
    if vote.round != qual.round() {
        return Ok(());
    }
    verify_qual_prevote_envelope(server, &run.transition, envelope, envelope.from, vote)?;
    if run.qual_current_prevotes.round != qual.round() {
        run.qual_current_prevotes =
            QualPrevoteArchive { round: qual.round(), envelopes: BTreeMap::new() };
    }
    if let Some(previous) = run.qual_current_prevotes.envelopes.get(&envelope.from) {
        anyhow::ensure!(previous == envelope, "QUAL PREVOTE signer equivocated");
    } else {
        run.qual_current_prevotes.envelopes.insert(envelope.from, envelope.clone());
    }
    anyhow::ensure!(
        run.qual_current_prevotes.envelopes.len() <= usize::from(run.transition.target.n()),
        "QUAL PREVOTE archive exceeds the committee"
    );
    Ok(())
}

fn promote_current_qual_prevotes(server: &PartyServer, run: &mut AvssRun) -> anyhow::Result<()> {
    let round = run.qual.as_ref().context("target AVSS run omitted QUAL state")?.round();
    if run.qual_current_prevotes.round != round {
        run.qual_current_prevotes = QualPrevoteArchive { round, envelopes: BTreeMap::new() };
    }
    let candidates = run
        .qual_signed_wires
        .iter()
        .filter(|((_, kind), archived)| *kind == QualWireKind::Prevote && archived.round == round)
        .map(|(_, archived)| archived.wire.envelope.clone())
        .collect::<Vec<_>>();
    for envelope in candidates {
        record_current_qual_prevote(server, run, &envelope)?;
    }
    Ok(())
}

fn refresh_qual_valid_witnesses(server: &PartyServer, run: &mut AvssRun) -> anyhow::Result<()> {
    let Some(qual) = run.qual.as_ref() else {
        anyhow::ensure!(
            run.qual_valid_witnesses.is_none()
                && run.qual_current_prevotes.envelopes.is_empty()
                && run.qual_signed_wires.is_empty(),
            "non-voter AVSS run retained QUAL witnesses"
        );
        return Ok(());
    };
    let Some(valid) = qual.valid().cloned() else {
        return Ok(());
    };
    if run.qual_valid_witnesses.as_ref().is_some_and(|retained| retained.proof.round > valid.round)
    {
        anyhow::bail!("retained QUAL POL is newer than the reducer's valid certificate");
    }
    let voters = valid.voters.iter().copied().take(qual.config().quorum()).collect::<Vec<_>>();
    let proof = ProofOfLockCertificate {
        round: valid.round,
        value: valid.value.clone(),
        voters: voters.clone(),
    };
    if let Some(previous) = &run.qual_valid_witnesses
        && previous.proof == proof
    {
        return Ok(());
    }
    let mut promoted = None;
    if run.qual_current_prevotes.round == proof.round {
        let envelopes = voters
            .iter()
            .map(|voter| run.qual_current_prevotes.envelopes.get(voter).cloned())
            .collect::<Option<Vec<_>>>();
        if let Some(envelopes) = envelopes {
            promoted = Some(envelopes);
        }
    }
    if promoted.is_none() {
        for archived in run.qual_signed_wires.values() {
            let message: QualMessage = decode_postcard_exact(&archived.wire.envelope.payload)?;
            let Some((carrying_round, candidate)) = qual_message_proof_of_lock(&message) else {
                continue;
            };
            if candidate != &proof {
                continue;
            }
            verify_qual_proof_witnesses(
                server,
                &run.transition,
                carrying_round,
                candidate,
                &archived.wire.proof_of_lock_witnesses,
            )?;
            promoted = Some(archived.wire.proof_of_lock_witnesses.clone());
            break;
        }
    }
    let Some(envelopes) = promoted else {
        // The reducer can set `valid` from a PREVOTE quorum that includes this party's own
        // PREVOTE before that outbound wire has been sealed and archived: the deliver path
        // refreshes once after archiving only the accepted wire (so `make_qual_response` can read
        // the retained bundle) and again after archiving the freshly sealed outbound. In that
        // first window a self-voted quorum is not yet reconstructable. Leaving the retained bundle
        // unchanged and letting the second refresh promote it keeps the party live instead of
        // rejecting the wire that just advanced it. A genuinely required proof of lock is still
        // enforced at emission time by `seal_qual_message`, which fails loudly if an outbound
        // message carries a POL without durable signed witnesses.
        return Ok(());
    };
    let carrying_round = proof.round.checked_add(1).context("QUAL POL round exhausted")?;
    verify_qual_proof_witnesses(server, &run.transition, carrying_round, &proof, &envelopes)?;
    run.qual_valid_witnesses = Some(QualProofWitnessBundle { proof, envelopes });
    Ok(())
}

fn update_qual_witness_state(
    server: &PartyServer,
    run: &mut AvssRun,
    accepted: Option<&QualWire>,
    outbound: &[QualWire],
) -> anyhow::Result<()> {
    if let Some(wire) = accepted {
        archive_qual_wire(server, run, wire)?;
    }
    for wire in outbound {
        archive_qual_wire(server, run, wire)?;
    }
    promote_current_qual_prevotes(server, run)?;
    refresh_qual_valid_witnesses(server, run)
}

fn validate_qual_witness_state(server: &PartyServer, run: &AvssRun) -> anyhow::Result<()> {
    anyhow::ensure!(
        run.pending_qual.len() <= usize::from(run.transition.target.n()) * 5,
        "durable QUAL outbox exceeds its fixed committee bound"
    );
    let mut pending_slots = BTreeSet::new();
    for ((recipient, digest), wire) in &run.pending_qual {
        run.transition.target.member(*recipient)?;
        anyhow::ensure!(
            qual_wire_digest(wire)? == *digest,
            "durable QUAL outbox digest differs from its exact wire"
        );
        let (sender, message) = open_qual_wire(server, &run.transition, wire)?;
        anyhow::ensure!(sender == server.party, "durable QUAL outbox contains a foreign sender");
        validate_qual_message_structure(&run.transition, sender, &message)?;
        if let Some((carrying_round, proof)) = qual_message_proof_of_lock(&message) {
            verify_qual_proof_witnesses(
                server,
                &run.transition,
                carrying_round,
                proof,
                &wire.proof_of_lock_witnesses,
            )?;
        }
        let (_, kind) = qual_message_metadata(&message)?;
        anyhow::ensure!(
            pending_slots.insert((*recipient, kind)),
            "durable QUAL outbox retained a superseded semantic slot"
        );
    }
    let Some(qual) = run.qual.as_ref() else {
        anyhow::ensure!(
            run.qual_current_prevotes.envelopes.is_empty()
                && run.qual_valid_witnesses.is_none()
                && run.qual_signed_wires.is_empty()
                && run.qual_delivery_responses.is_empty()
                && run.qual_advance_response.is_none(),
            "non-voter durable AVSS state contains QUAL witnesses"
        );
        return Ok(());
    };
    let committee_size = usize::from(run.transition.target.n());
    anyhow::ensure!(
        run.qual_signed_wires.len() <= committee_size * 5,
        "durable QUAL signed-wire archive exceeds its fixed committee bound"
    );
    for ((sender, kind), archived) in &run.qual_signed_wires {
        let (opened_sender, message) = open_qual_wire(server, &run.transition, &archived.wire)?;
        validate_qual_message_structure(&run.transition, opened_sender, &message)?;
        let (round, opened_kind) = qual_message_metadata(&message)?;
        anyhow::ensure!(
            opened_sender == *sender && opened_kind == *kind && round == archived.round,
            "durable QUAL signed-wire archive key differs from its exact wire"
        );
        if let Some((carrying_round, proof)) = qual_message_proof_of_lock(&message) {
            verify_qual_proof_witnesses(
                server,
                &run.transition,
                carrying_round,
                proof,
                &archived.wire.proof_of_lock_witnesses,
            )?;
        }
    }
    anyhow::ensure!(
        run.qual_delivery_responses.len() <= committee_size * 5,
        "durable QUAL delivery cache exceeds its fixed committee bound"
    );
    for ((sender, _), cached) in &run.qual_delivery_responses {
        run.transition.target.member(*sender)?;
        anyhow::ensure!(
            cached.response.party == server.party,
            "durable QUAL cached response belongs to another local party"
        );
    }
    if let Some(cached) = &run.qual_advance_response {
        anyhow::ensure!(
            cached.prior_requested_round.checked_add(1) == Some(cached.target_round)
                && cached.response.requested_round == Some(cached.target_round)
                && cached.response.party == server.party,
            "durable QUAL advance retry record is inconsistent"
        );
    }
    anyhow::ensure!(
        run.qual_current_prevotes.round == qual.round(),
        "durable QUAL PREVOTE archive round differs from reducer"
    );
    anyhow::ensure!(
        run.qual_current_prevotes.envelopes.len() <= usize::from(run.transition.target.n()),
        "durable QUAL PREVOTE archive exceeds the committee"
    );
    for (voter, envelope) in &run.qual_current_prevotes.envelopes {
        let message: QualMessage = decode_postcard_exact(&envelope.payload)?;
        let QualMessageBody::Vote(vote) = message.body else {
            anyhow::bail!("durable QUAL PREVOTE archive contains a non-vote");
        };
        anyhow::ensure!(
            vote.phase == VotePhase::Prevote && vote.round == qual.round(),
            "durable QUAL PREVOTE archive contains the wrong round or phase"
        );
        verify_qual_prevote_envelope(server, &run.transition, envelope, *voter, vote)?;
    }
    match (qual.valid(), &run.qual_valid_witnesses) {
        (None, None) => {}
        (Some(valid), Some(retained)) => {
            let voters =
                valid.voters.iter().copied().take(qual.config().quorum()).collect::<Vec<_>>();
            anyhow::ensure!(
                retained.proof.round == valid.round
                    && retained.proof.value == valid.value
                    && retained.proof.voters == voters,
                "durable QUAL POL witnesses differ from the reducer's highest valid certificate"
            );
            let proposal_round =
                retained.proof.round.checked_add(1).context("durable QUAL POL round exhausted")?;
            verify_qual_proof_witnesses(
                server,
                &run.transition,
                proposal_round,
                &retained.proof,
                &retained.envelopes,
            )?;
        }
        _ => anyhow::bail!("durable QUAL reducer and POL witness state disagree"),
    }
    Ok(())
}

fn qual_wire_digest(wire: &QualWire) -> anyhow::Result<[u8; 32]> {
    Ok(*blake3::hash(&postcard::to_allocvec(wire)?).as_bytes())
}

fn decode_postcard_exact<T>(bytes: &[u8]) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let (value, remaining) = postcard::take_from_bytes(bytes)?;
    anyhow::ensure!(remaining.is_empty(), "durable record has trailing bytes");
    Ok(value)
}

/// Canonically encode one bounded durable AVSS run before entering the storage layer.
///
/// Committee/transition preflight keeps this allocation bounded. The exact check remains here so
/// schema growth or an overlooked retained map cannot create a run which is intrinsically
/// impossible for `ProtocolStore` to persist and recover.
fn encode_durable_avss_run(run: &AvssRun) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    validate_avss_secret_compaction(run)?;
    let encoded = Zeroizing::new(postcard::to_allocvec(&DurableSessionStateRef::Avss(run))?);
    anyhow::ensure!(
        encoded.len() <= MAX_SESSION_STATE_BYTES,
        "canonical AVSS session needs {} bytes; maximum is {}",
        encoded.len(),
        MAX_SESSION_STATE_BYTES
    );
    Ok(encoded)
}

fn validate_avss_transition(
    server: &PartyServer,
    transition: &AvssTransition,
) -> anyhow::Result<()> {
    server.validate_committee(&transition.target)?;
    let dealer_count = match transition.purpose {
        DealPurpose::Dkg => transition.target.members.len(),
        DealPurpose::Refresh | DealPurpose::Reshare => transition.eligible_dealers.len(),
    };
    preflight_avss_resources(&transition.target, dealer_count)?;
    anyhow::ensure!(transition.key_id != [0; 32], "AVSS key id must not be zero");
    anyhow::ensure!(
        transition.history_parent.network() == server.scenario.quic_network_id()?
            && transition.history_parent.key_id() == transition.key_id,
        "AVSS history parent belongs to another network or key"
    );
    let static_spec = server.scenario.committee_spec(transition.target.epoch).ok();
    let (_, trusted_fault_bound) =
        server.trusted_committee_and_fault_bound(transition.target.epoch)?;
    anyhow::ensure!(transition.fault_bound == trusted_fault_bound, "AVSS fault bound differs");
    transition.target.validate_async_security_with_faults(transition.fault_bound)?;
    let mut selected = transition.eligible_dealers.clone();
    selected.sort_unstable();
    anyhow::ensure!(
        selected == transition.eligible_dealers,
        "eligible AVSS dealers must be canonical"
    );
    anyhow::ensure!(
        selected.iter().copied().collect::<BTreeSet<_>>().len() == selected.len(),
        "eligible AVSS dealers contain a duplicate"
    );
    match (transition.purpose, &transition.old) {
        (DealPurpose::Dkg, None) => {
            anyhow::ensure!(transition.target.epoch == 0, "DKG must create epoch zero");
            anyhow::ensure!(selected.is_empty(), "DKG cannot select old dealers");
            let (key_id, session) = canonical_dkg_identity(&server.scenario)?;
            let genesis = EpochHistoryParent::genesis(server.scenario.quic_network_id()?, key_id)?;
            anyhow::ensure!(
                transition.key_id == key_id
                    && transition.session == session
                    && transition.history_parent == genesis,
                "DKG key/session differs from the scenario-bound transition identity"
            );
        }
        (DealPurpose::Refresh, Some(old)) => {
            old.validate()?;
            anyhow::ensure!(
                old.committee.threshold >= 2 && transition.target.threshold >= 2,
                "proactive zero-refresh requires threshold at least two"
            );
            let (expected_old, old_fault_bound) =
                server.trusted_committee_and_fault_bound(old.committee.epoch)?;
            anyhow::ensure!(
                old.committee.digest() == expected_old.digest(),
                "zero-refresh source committee differs from scenario"
            );
            anyhow::ensure!(
                old.key_id == transition.key_id,
                "zero-refresh key id differs from its source"
            );
            anyhow::ensure!(
                old_fault_bound == transition.fault_bound,
                "zero refresh changed the current committee's fault bound"
            );
            let links = server
                .history_links
                .read()
                .map_err(|_| anyhow::anyhow!("epoch-history registry lock is poisoned"))?;
            let certified_parent = links
                .get(&old.committee.epoch)
                .copied()
                .context("zero-refresh source lacks a certified history link")?
                .successor_parent()?;
            anyhow::ensure!(
                transition.history_parent == certified_parent,
                "zero-refresh history parent differs from the certified source"
            );
            drop(links);
            anyhow::ensure!(
                transition.session
                    == canonical_refresh_session(
                        old,
                        &transition.target,
                        transition.history_parent,
                    )?,
                "zero-refresh session differs from the certified source/target"
            );
            anyhow::ensure!(
                old.committee.epoch.checked_add(1) == Some(transition.target.epoch),
                "zero refresh must advance exactly one epoch"
            );
            anyhow::ensure!(
                same_refresh_layout(&old.committee, &transition.target),
                "zero refresh changed membership, signing identities, or threshold"
            );
            if let Some(specification) = static_spec {
                anyhow::ensure!(
                    specification.operation == Operation::Reshare,
                    "zero-refresh target is not configured as a successor"
                );
            }
            let rotations = server
                .certified_key_rotations
                .read()
                .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
            let rotation = rotations
                .get(&transition.target.epoch)
                .context("zero-refresh target lacks its receiver-key certificate")?;
            anyhow::ensure!(
                rotation.context.source().digest() == old.committee.digest()
                    && rotation.context.source_activation() == old.activation_digest()?
                    && rotation.context.target_epoch() == transition.target.epoch
                    && rotation.context.target_fault_bound() == transition.fault_bound
                    && rotation.certificate.verify(&rotation.context)?.digest()
                        == transition.target.digest(),
                "zero-refresh transition differs from receiver-key certification"
            );
            let mut expected =
                old.committee.members.iter().map(|member| member.id).collect::<Vec<_>>();
            expected.sort_unstable();
            anyhow::ensure!(
                selected == expected,
                "zero refresh must admit every current committee dealer"
            );
        }
        (DealPurpose::Reshare, Some(old)) => {
            old.validate()?;
            let (expected_old, old_fault_bound) =
                server.trusted_committee_and_fault_bound(old.committee.epoch)?;
            anyhow::ensure!(
                old.committee.digest() == expected_old.digest(),
                "old committee differs from scenario"
            );
            anyhow::ensure!(old.key_id == transition.key_id, "reshare key id differs");
            let links = server
                .history_links
                .read()
                .map_err(|_| anyhow::anyhow!("epoch-history registry lock is poisoned"))?;
            let certified_parent = links
                .get(&old.committee.epoch)
                .copied()
                .context("reshare source lacks a certified history link")?
                .successor_parent()?;
            anyhow::ensure!(
                transition.history_parent == certified_parent,
                "reshare history parent differs from the certified source"
            );
            drop(links);
            anyhow::ensure!(
                transition.session
                    == canonical_reshare_session(
                        old,
                        &transition.target,
                        transition.history_parent,
                    )?,
                "reshare session differs from the certified source/target transition identity"
            );
            anyhow::ensure!(
                old.committee.epoch.checked_add(1) == Some(transition.target.epoch),
                "reshare must advance exactly one epoch"
            );
            anyhow::ensure!(
                !same_refresh_layout(&old.committee, &transition.target),
                "same-committee successor must use zero-refresh, not old-share redistribution"
            );
            let mut configured: Vec<PartyId> = if let Some(specification) = static_spec {
                anyhow::ensure!(
                    specification.operation == Operation::Reshare,
                    "resharing target is not configured as a successor"
                );
                specification
                    .old_dealers
                    .iter()
                    .copied()
                    .filter(|party| old.committee.member(*party).is_ok())
                    .collect()
            } else {
                old.committee.members.iter().map(|member| member.id).collect()
            };
            configured.sort_unstable();
            anyhow::ensure!(
                selected == configured,
                "selected old dealer set differs from scenario"
            );
            anyhow::ensure!(
                selected.len()
                    >= usize::from(old.committee.threshold.saturating_add(old_fault_bound)),
                "reshare dealer candidates cannot survive the configured old-committee faults"
            );
            anyhow::ensure!(
                selected.len() <= usize::from(old.committee.n()),
                "too many reshare dealer candidates"
            );
            for dealer in &selected {
                old.committee.member(*dealer)?;
            }
            let rotations = server
                .certified_key_rotations
                .read()
                .map_err(|_| anyhow::anyhow!("key-rotation registry lock is poisoned"))?;
            let rotation = rotations
                .get(&transition.target.epoch)
                .context("resharing target lacks its receiver-key certificate")?;
            anyhow::ensure!(
                rotation.context.source().digest() == old.committee.digest()
                    && rotation.context.source_activation() == old.activation_digest()?
                    && rotation.context.target_epoch() == transition.target.epoch
                    && rotation.context.target_fault_bound() == transition.fault_bound
                    && rotation.certificate.verify(&rotation.context)?.digest()
                        == transition.target.digest(),
                "resharing transition differs from receiver-key certification"
            );
        }
        _ => anyhow::bail!("AVSS purpose and old epoch are inconsistent"),
    }
    Ok(())
}

fn expected_avss_dealers(transition: &AvssTransition) -> BTreeSet<PartyId> {
    match transition.purpose {
        DealPurpose::Dkg => transition.target.members.iter().map(|member| member.id).collect(),
        DealPurpose::Refresh | DealPurpose::Reshare => {
            transition.eligible_dealers.iter().copied().collect()
        }
    }
}

fn qual_config(transition: &AvssTransition) -> anyhow::Result<QualConfig> {
    let digest = avss_transition_digest(transition)?;
    Ok(match (&transition.purpose, &transition.old) {
        (DealPurpose::Dkg, None) => QualConfig::dkg(
            transition.session,
            digest,
            transition.target.clone(),
            transition.fault_bound,
        )?,
        (DealPurpose::Refresh, Some(_)) => QualConfig::refresh(
            transition.session,
            digest,
            transition.target.clone(),
            transition.fault_bound,
        )?,
        (DealPurpose::Reshare, Some(old)) => QualConfig::reshare(
            transition.session,
            digest,
            transition.target.clone(),
            transition.fault_bound,
            old.committee.threshold,
            transition.eligible_dealers.clone(),
        )?,
        _ => anyhow::bail!("AVSS purpose and old epoch are inconsistent"),
    })
}

fn new_avss_run(server: &PartyServer, transition: AvssTransition) -> anyhow::Result<AvssRun> {
    let qual = if transition.target.member(server.party).is_ok() {
        Some(QualConsensus::new(qual_config(&transition)?, server.party)?)
    } else {
        None
    };
    Ok(AvssRun {
        transition,
        secret_compacted: false,
        receivers: BTreeMap::new(),
        outputs: BTreeMap::new(),
        dealer_outbound: None,
        delivery_responses: BTreeMap::new(),
        qual,
        qual_start_response: None,
        qual_delivery_responses: BTreeMap::new(),
        qual_advance_response: None,
        qual_signed_wires: BTreeMap::new(),
        qual_current_prevotes: QualPrevoteArchive { round: 0, envelopes: BTreeMap::new() },
        qual_valid_witnesses: None,
        qual_round_started_unix_ms: unix_time_millis()?,
        qual_timeout_exponent: 0,
        pending_avss: BTreeMap::new(),
        pending_qual: BTreeMap::new(),
        pending_activation_ack: BTreeMap::new(),
        activation_acknowledgements: BTreeMap::new(),
        finalized: None,
    })
}

fn unix_time_millis() -> anyhow::Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time precedes the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("Unix timestamp does not fit u64 milliseconds")
}

fn unix_time_seconds() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time precedes the Unix epoch")?
        .as_secs())
}

/// A sample older than the persisted round start is either a concurrent-start observation or a
/// wall-clock rollback. Neither is evidence that the request window timed out. A later progress
/// tick retries after the clock catches up; requesting another round immediately would create
/// unnecessary skew even though it cannot change the active round without an n-f certificate.
fn qual_round_expired(started_unix_ms: u64, now_unix_ms: u64, timeout_ms: u64) -> bool {
    now_unix_ms.checked_sub(started_unix_ms).is_some_and(|elapsed| elapsed >= timeout_ms)
}

fn qual_backoff_timeout_ms(base_timeout_ms: u64, exponent: u8) -> u64 {
    let multiplier = 1_u64.checked_shl(u32::from(exponent).min(63)).unwrap_or(u64::MAX);
    base_timeout_ms.saturating_mul(multiplier).min(MAX_QUAL_BACKOFF_TIMEOUT_MS)
}

fn avss_run_is_certified(
    session: SessionId,
    run: &AvssRun,
    certified: &BTreeMap<SessionId, [u8; 32]>,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        run.transition.session == session,
        "AVSS run map key differs from its transition session"
    );
    let Some(expected) = certified.get(&session) else {
        return Ok(false);
    };
    anyhow::ensure!(
        avss_transition_digest(&run.transition)? == *expected,
        "certified AVSS session is bound to another transition"
    );
    Ok(true)
}

fn compact_avss_secret_state(run: &mut AvssRun) {
    // `AvssParty`, `DealerPolynomials`, `CrossValues`, and `AvssOutput` ultimately own
    // `ScalarBytes`, whose Drop implementation zeroizes its backing bytes. Clear every owning
    // container instead of retaining a certificate-finalized reducer indefinitely.
    run.receivers.clear();
    run.outputs.clear();
    run.dealer_outbound = None;
    run.delivery_responses.clear();

    // QUAL values and signatures are public, but the live reducer and delivery replay caches are no
    // longer needed after the immutable activation certificate. The durable peer outboxes below
    // remain sufficient for lagging-recipient catch-up and exact ACK retirement.
    run.qual = None;
    run.qual_start_response = None;
    run.qual_delivery_responses.clear();
    run.qual_advance_response = None;
    run.qual_signed_wires.clear();
    run.qual_current_prevotes = QualPrevoteArchive { round: 0, envelopes: BTreeMap::new() };
    run.qual_valid_witnesses = None;
    run.qual_round_started_unix_ms = 0;
    run.qual_timeout_exponent = 0;
    run.secret_compacted = true;
}

fn validate_avss_secret_compaction(run: &AvssRun) -> anyhow::Result<()> {
    if !run.secret_compacted {
        return Ok(());
    }
    anyhow::ensure!(
        run.receivers.is_empty()
            && run.outputs.is_empty()
            && run.dealer_outbound.is_none()
            && run.delivery_responses.is_empty()
            && run.qual.is_none()
            && run.qual_start_response.is_none()
            && run.qual_delivery_responses.is_empty()
            && run.qual_advance_response.is_none()
            && run.qual_signed_wires.is_empty()
            && run.qual_current_prevotes.envelopes.is_empty()
            && run.qual_valid_witnesses.is_none(),
        "secret-compacted AVSS state retained a plaintext reducer or replay cache"
    );
    Ok(())
}

/// Enforce the live reducer bound without charging immutable, certificate-finalized catch-up
/// state against it. The candidate itself may already be certified (for example when a target
/// comes back after first receiving the permanent activation certificate), so its exact context
/// is classified before deciding whether another live slot is required.
fn ensure_avss_live_capacity(
    runs: &BTreeMap<SessionId, AvssRun>,
    certified: &BTreeMap<SessionId, [u8; 32]>,
    candidate: &AvssTransition,
    maximum: usize,
) -> anyhow::Result<()> {
    let mut live = 0_usize;
    for (session, run) in runs {
        if !avss_run_is_certified(*session, run, certified)? {
            live = live.saturating_add(1);
        }
    }
    let candidate_certified = match certified.get(&candidate.session) {
        Some(expected) => {
            anyhow::ensure!(
                avss_transition_digest(candidate)? == *expected,
                "certified AVSS candidate is bound to another transition"
            );
            true
        }
        None => false,
    };
    anyhow::ensure!(candidate_certified || live < maximum, "too many live AVSS sessions");
    Ok(())
}

fn peer_outbox_is_empty(run: &AvssRun) -> bool {
    run.pending_avss.is_empty()
        && run.pending_qual.is_empty()
        && run.pending_activation_ack.is_empty()
}

fn enqueue_avss_outbound(run: &mut AvssRun, outbound: &[AvssWire]) -> anyhow::Result<()> {
    for wire in outbound {
        let key = (wire.recipient, avss_wire_digest(wire)?);
        if let Some(existing) = run.pending_avss.get(&key) {
            anyhow::ensure!(existing == wire, "AVSS outbox digest collision");
        } else {
            run.pending_avss.insert(key, wire.clone());
        }
    }
    Ok(())
}

fn enqueue_qual_outbound(
    run: &mut AvssRun,
    transition: &AvssTransition,
    outbound: &[QualWire],
) -> anyhow::Result<()> {
    for wire in outbound {
        anyhow::ensure!(wire.version == QUAL_WIRE_VERSION, "unsupported outbound QUAL wire");
        let message: QualMessage = decode_postcard_exact(&wire.envelope.payload)?;
        let (round, kind) = qual_message_metadata(&message)?;
        anyhow::ensure!(
            wire.envelope.sequence == qual_sequence(&message)?,
            "outbound QUAL sequence differs"
        );
        transition.target.member(wire.envelope.from)?;
        let digest = qual_wire_digest(wire)?;
        for member in &transition.target.members {
            let mut superseded = Vec::new();
            let mut already_covered = false;
            for ((recipient, previous_digest), previous) in &run.pending_qual {
                if *recipient != member.id {
                    continue;
                }
                let previous_message: QualMessage =
                    decode_postcard_exact(&previous.envelope.payload)?;
                let (previous_round, previous_kind) = qual_message_metadata(&previous_message)?;
                if previous_kind != kind {
                    continue;
                }
                anyhow::ensure!(
                    previous.envelope.from == wire.envelope.from,
                    "QUAL outbox mixed semantic-slot senders"
                );
                if previous_round < round {
                    superseded.push((*recipient, *previous_digest));
                } else if previous_round == round {
                    anyhow::ensure!(
                        previous == wire,
                        "same-round QUAL outbox semantic slot changed"
                    );
                    already_covered = true;
                } else {
                    already_covered = true;
                }
            }
            for key in superseded {
                run.pending_qual.remove(&key);
            }
            if already_covered {
                continue;
            }
            let key = (member.id, digest);
            if let Some(existing) = run.pending_qual.get(&key) {
                anyhow::ensure!(existing == wire, "QUAL outbox digest collision");
            } else {
                run.pending_qual.insert(key, wire.clone());
            }
        }
        anyhow::ensure!(
            run.pending_qual.len() <= transition.target.members.len() * 5,
            "QUAL outbox exceeds its fixed committee bound"
        );
    }
    Ok(())
}

fn qual_start_threshold(transition: &AvssTransition) -> anyhow::Result<usize> {
    match (&transition.purpose, &transition.old) {
        (DealPurpose::Dkg, None) => Ok(usize::from(transition.target.n() - transition.fault_bound)),
        (DealPurpose::Refresh, Some(_)) => {
            Ok(usize::from(transition.target.n() - transition.fault_bound))
        }
        (DealPurpose::Reshare, Some(old)) => Ok(usize::from(old.committee.threshold)),
        _ => anyhow::bail!("AVSS purpose and old epoch are inconsistent"),
    }
}

fn qual_has_start_quorum(
    transition: &AvssTransition,
    completed_outputs: usize,
) -> anyhow::Result<bool> {
    Ok(completed_outputs >= qual_start_threshold(transition)?)
}

/// Start the pacemaker only after the local party can validate a leader proposal. Starting QUAL
/// when an AVSS run is merely allocated lets the short round timer race the substantially slower
/// encrypted AVSS fanout, causing honest parties to enter permanently phase-shifted rounds.
fn start_qual_if_needed(
    server: &PartyServer,
    run: &mut AvssRun,
) -> anyhow::Result<Option<QualStepResponse>> {
    if run.qual_start_response.is_some() || run.qual.is_none() {
        return Ok(None);
    }
    if !qual_has_start_quorum(&run.transition, run.outputs.len())? {
        return Ok(None);
    }
    let retained = run.qual_valid_witnesses.clone();
    let qual = run.qual.as_mut().expect("QUAL presence was checked above");
    let step = qual.start()?;
    let response = make_qual_response(server, &run.transition, qual, step, retained.as_ref())?;
    update_qual_witness_state(server, run, None, &response.outbound)?;
    let transition = run.transition.clone();
    enqueue_qual_outbound(run, &transition, &response.outbound)?;
    run.qual_round_started_unix_ms = unix_time_millis()?;
    run.qual_start_response = Some(response.clone());
    Ok(Some(response))
}

fn avss_config(
    _server: &PartyServer,
    transition: &AvssTransition,
    dealer: PartyId,
) -> anyhow::Result<AvssConfig> {
    anyhow::ensure!(expected_avss_dealers(transition).contains(&dealer), "unexpected AVSS dealer");
    Ok(AvssConfig {
        session: transition.session,
        dealer,
        receivers: transition.target.clone(),
        fault_bound: transition.fault_bound,
    })
}

fn avss_kind(payload: &AvssPayload) -> u8 {
    match payload {
        AvssPayload::DealerSend(_) => 0,
        AvssPayload::Echo(_) => 1,
        AvssPayload::Ready(_) => 2,
    }
}

fn avss_sequence(dealer: PartyId, kind: u8, recipient: PartyId) -> u64 {
    (u64::from(dealer.0) << 32) | (u64::from(kind) << 16) | u64::from(recipient.0)
}

fn avss_aead_binding(
    transition: &AvssTransition,
    dealer: PartyId,
    sender: PartyId,
    recipient: PartyId,
    sequence: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/avss-wire-aead/v2");
    hasher.update(&[match transition.purpose {
        DealPurpose::Dkg => 0,
        DealPurpose::Refresh => 1,
        DealPurpose::Reshare => 2,
    }]);
    hasher.update(&transition.session.0);
    hasher.update(&transition.key_id);
    hasher.update(&transition.fault_bound.to_le_bytes());
    hasher.update(&transition.old.as_ref().map_or([0; 32], |old| old.committee.digest()));
    hasher.update(&transition.target.digest());
    hasher.update(&dealer.0.to_le_bytes());
    hasher.update(&sender.0.to_le_bytes());
    hasher.update(&recipient.0.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());
    for selected in &transition.eligible_dealers {
        hasher.update(&selected.0.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn seal_avss_message(
    server: &PartyServer,
    transition: &AvssTransition,
    sender: PartyId,
    private: PrivateAvssMessage,
) -> anyhow::Result<AvssWire> {
    let dealer = private.message.instance.dealer;
    anyhow::ensure!(
        private.message.instance == avss_config(server, transition, dealer)?.instance_id()
    );
    transition.target.member(private.recipient)?;
    let kind = avss_kind(&private.message.payload);
    let dealer_send = matches!(&private.message.payload, AvssPayload::DealerSend(_));
    let authentication_committee = if dealer_send {
        anyhow::ensure!(sender == dealer, "DealerSend sender differs from dealer");
        transition.old.as_ref().map_or(&transition.target, |old| &old.committee)
    } else {
        transition.target.member(sender)?;
        &transition.target
    };
    let sequence = avss_sequence(dealer, kind, private.recipient);
    let binding = avss_aead_binding(transition, dealer, sender, private.recipient, sequence);
    let identity = server.identity(authentication_committee.epoch)?;
    let mut plaintext = postcard::to_allocvec(&private.message)?;
    let encrypted = identity.encrypt_bound(
        &transition.target,
        transition.session,
        private.recipient,
        &binding,
        &plaintext,
        &mut OsRng,
    )?;
    use zeroize::Zeroize;
    plaintext.zeroize();
    let payload = postcard::to_allocvec(&encrypted)?;
    // An old-only dealer cannot address a new-only receiver in an old-committee envelope. The
    // signed ciphertext and its AEAD binding still name the new receiver, so `None` is safe here.
    let to = if authentication_committee.digest() == transition.target.digest() {
        Some(private.recipient)
    } else {
        None
    };
    let envelope = identity.sign_envelope(
        authentication_committee,
        transition.session,
        to,
        sequence,
        payload,
    )?;
    Ok(AvssWire { version: AVSS_WIRE_VERSION, dealer, recipient: private.recipient, envelope })
}

fn open_avss_wire(
    server: &PartyServer,
    transition: &AvssTransition,
    wire: &AvssWire,
) -> anyhow::Result<crate::avss::AvssMessage> {
    anyhow::ensure!(wire.envelope.session == transition.session, "AVSS envelope session differs");
    let old_auth = transition.old.as_ref().is_some_and(|old| {
        wire.envelope.epoch == old.committee.epoch
            && wire.envelope.committee == old.committee.digest()
    });
    let authentication_committee = if old_auth {
        transition.old.as_ref().map(|old| &old.committee).context("missing old committee")?
    } else {
        &transition.target
    };
    if old_auth {
        anyhow::ensure!(
            wire.envelope.from == wire.dealer,
            "only the dealer may use old authentication"
        );
        anyhow::ensure!(
            wire.envelope.to.is_none(),
            "transition DealerSend must use broadcast routing"
        );
    } else {
        anyhow::ensure!(wire.envelope.to == Some(server.party), "AVSS envelope recipient differs");
    }
    Identity::verify_envelope(authentication_committee, server.party, &wire.envelope)?;
    let encrypted: EncryptedPayload = postcard::from_bytes(&wire.envelope.payload)?;
    anyhow::ensure!(
        postcard::to_allocvec(&encrypted)? == wire.envelope.payload,
        "AVSS ciphertext has trailing or noncanonical bytes"
    );
    let binding = avss_aead_binding(
        transition,
        wire.dealer,
        wire.envelope.from,
        server.party,
        wire.envelope.sequence,
    );
    let sender_key = authentication_committee.member(wire.envelope.from)?.encryption_key;
    let mut plaintext = server.identity(transition.target.epoch)?.decrypt_from_key_bound(
        &transition.target,
        transition.session,
        wire.envelope.from,
        sender_key,
        &binding,
        &encrypted,
    )?;
    let message: crate::avss::AvssMessage = postcard::from_bytes(&plaintext)?;
    anyhow::ensure!(
        postcard::to_allocvec(&message)? == plaintext,
        "AVSS plaintext has trailing or noncanonical bytes"
    );
    use zeroize::Zeroize;
    plaintext.zeroize();
    anyhow::ensure!(message.instance.dealer == wire.dealer, "AVSS dealer binding differs");
    let kind = avss_kind(&message.payload);
    anyhow::ensure!(
        wire.envelope.sequence == avss_sequence(wire.dealer, kind, server.party),
        "AVSS logical sequence differs"
    );
    match &message.payload {
        AvssPayload::DealerSend(_) => {
            anyhow::ensure!(wire.envelope.from == wire.dealer, "DealerSend sender differs");
            anyhow::ensure!(
                old_auth == transition.old.is_some(),
                "DealerSend used the wrong authentication epoch"
            );
        }
        AvssPayload::Echo(_) | AvssPayload::Ready(_) => {
            anyhow::ensure!(!old_auth, "Echo/Ready used old-committee authentication");
            transition.target.member(wire.envelope.from)?;
        }
    }
    Ok(message)
}

fn avss_wire_digest(wire: &AvssWire) -> anyhow::Result<[u8; 32]> {
    let encoded = postcard::to_allocvec(wire)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn avss_transition_digest(transition: &AvssTransition) -> anyhow::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/avss-transition/v3");
    hasher.update(&[match transition.purpose {
        DealPurpose::Dkg => 0,
        DealPurpose::Refresh => 1,
        DealPurpose::Reshare => 2,
    }]);
    hasher.update(&transition.session.0);
    hasher.update(&transition.key_id);
    hasher.update(&transition.fault_bound.to_le_bytes());
    hasher.update(&transition.history_parent.transition_binding()?);
    hasher.update(&transition.old.as_ref().map_or(Ok([0; 32]), EpochPublic::activation_digest)?);
    hasher.update(&transition.target.digest());
    for dealer in &transition.eligible_dealers {
        hasher.update(&dealer.0.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn avss_tombstone_purpose(transition: &AvssTransition) -> anyhow::Result<Vec<u8>> {
    let mut purpose = b"avss-finalized/v3/".to_vec();
    purpose.extend_from_slice(&avss_transition_digest(transition)?);
    Ok(purpose)
}

const SUPERSEDED_AVSS_TOMBSTONE_PREFIX: &[u8] = b"avss-superseded/v1/";

fn superseded_avss_tombstone_purpose(
    closure: AvssSuccessorSupersession,
) -> anyhow::Result<Vec<u8>> {
    let mut purpose = SUPERSEDED_AVSS_TOMBSTONE_PREFIX.to_vec();
    purpose.extend_from_slice(&postcard::to_allocvec(&closure)?);
    anyhow::ensure!(
        purpose.len() <= crate::storage::MAX_SESSION_TOMBSTONE_PURPOSE_BYTES,
        "superseded AVSS closure exceeds the tombstone bound"
    );
    Ok(purpose)
}

fn decode_superseded_avss_tombstone_purpose(
    purpose: &[u8],
) -> anyhow::Result<Option<AvssSuccessorSupersession>> {
    let Some(encoded) = purpose.strip_prefix(SUPERSEDED_AVSS_TOMBSTONE_PREFIX) else {
        return Ok(None);
    };
    Ok(Some(decode_postcard_exact(encoded)?))
}

fn completion_sequence(dealer: PartyId) -> u64 {
    0xA_C05_0000_0000_0000_u64 | u64::from(dealer.0)
}

fn sign_avss_completion(
    server: &PartyServer,
    transition: &AvssTransition,
    output: &AvssOutput,
) -> anyhow::Result<SignedEnvelope> {
    let completion = AvssCompletion {
        version: 1,
        transition: avss_transition_digest(transition)?,
        session: transition.session,
        receiver: server.party,
        dealer: output.instance.dealer,
        commitment_digest: output.commitment_digest,
    };
    server
        .identity(transition.target.epoch)?
        .sign_envelope(
            &transition.target,
            transition.session,
            None,
            completion_sequence(output.instance.dealer),
            postcard::to_allocvec(&completion)?,
        )
        .map_err(Into::into)
}

fn avss_transcript_digest(
    transition: &AvssTransition,
    outputs: &BTreeMap<PartyId, AvssOutput>,
) -> anyhow::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/avss-transcript/v2");
    hasher.update(&[match transition.purpose {
        DealPurpose::Dkg => 0,
        DealPurpose::Refresh => 1,
        DealPurpose::Reshare => 2,
    }]);
    hasher.update(&transition.session.0);
    hasher.update(&transition.key_id);
    hasher.update(&transition.fault_bound.to_le_bytes());
    hasher.update(&transition.old.as_ref().map_or(Ok([0; 32]), EpochPublic::activation_digest)?);
    hasher.update(&transition.target.digest());
    for selected in &transition.eligible_dealers {
        hasher.update(&selected.0.to_le_bytes());
    }
    for (dealer, output) in outputs {
        hasher.update(&dealer.0.to_le_bytes());
        hasher.update(&output.commitment_digest.0);
    }
    Ok(*hasher.finalize().as_bytes())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("installing Ctrl-C handler failed");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM handler failed")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

fn api_ensure(condition: bool, message: &'static str) -> Result<(), ApiError> {
    if condition { Ok(()) } else { Err(ApiError(anyhow::anyhow!(message))) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{
            AuthRole, BEARER_AUTH_SCHEMA_VERSION, BearerAuthConfig, BearerCredentialConfig,
            bearer_token_digest,
        },
        committee::{MAX_COMMITTEE_MEMBERS, MAX_COMMITTEE_THRESHOLD, Member},
        compact_registry_archive::prepare_compact_registry_genesis,
        config::{CommitteeSpec, Hex32, Operation, ScenarioParty},
        deposit_consensus::{
            ConsensusMessageBody, ViewChange, ViewChangeCertificate, sign_consensus_message,
        },
        deposit_index::DepositIndexHead,
        deposit_ledger::{LedgerPayload, LedgerStatement, genesis_head},
        deposit_wallet::{DepositAddressDeriver, DepositSubaddressIndex},
        deposit_worker::MoneroRpcLimits,
        key_rotation::VerifiedRegistryHandoffTarget,
        keys::{
            PointBytes, SecretPolynomial, aggregate_dkg, aggregate_proactive_reshare,
            make_dkg_output, make_proactive_reshare_polynomial,
        },
        qual::{QualNewRound, QualProposal, QualRoundChange, QualValue, RoundChangeCertificate},
        reconnecting_monero::ReconnectingMoneroDaemon,
    };
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};

    fn committee(epoch: u64, members: u16, threshold: u16) -> Committee {
        Committee {
            epoch,
            threshold,
            members: (1..=members)
                .map(|id| Member {
                    id: PartyId(id),
                    signing_key: [u8::try_from(id).unwrap(); 32],
                    encryption_key: [u8::try_from(id.saturating_add(20)).unwrap(); 32],
                })
                .collect(),
        }
    }

    fn test_qual_wire(transition: &AvssTransition, message: QualMessage) -> QualWire {
        QualWire {
            version: QUAL_WIRE_VERSION,
            envelope: SignedEnvelope {
                version: 1,
                committee: transition.target.digest(),
                epoch: transition.target.epoch,
                session: transition.session,
                from: PartyId(1),
                to: None,
                sequence: qual_sequence(&message).unwrap(),
                payload: postcard::to_allocvec(&message).unwrap(),
                signature: [0x51; 64],
            },
            proof_of_lock_witnesses: Vec::new(),
        }
    }

    fn test_qual_transition() -> AvssTransition {
        let target = committee(0, 4, 2);
        AvssTransition {
            purpose: DealPurpose::Dkg,
            session: SessionId([0x52; 32]),
            key_id: [0x53; 32],
            fault_bound: 1,
            history_parent: EpochHistoryParent::genesis([0x54; 32], [0x53; 32]).unwrap(),
            old: None,
            target,
            eligible_dealers: Vec::new(),
        }
    }

    #[test]
    fn qual_v4_sequence_has_distinct_three_bit_semantic_kinds() {
        let transition = test_qual_transition();
        let config = qual_config(&transition).unwrap();
        let value = QualValue {
            session: transition.session,
            epoch: transition.target.epoch,
            committee: transition.target.digest(),
            context: config.digest(),
            entries: Vec::new(),
        };
        let round = 9;
        let messages = [
            QualMessage {
                context: config.digest(),
                body: QualMessageBody::Proposal(QualProposal {
                    round,
                    value: value.clone(),
                    proof_of_lock: None,
                }),
            },
            QualMessage {
                context: config.digest(),
                body: QualMessageBody::Vote(crate::qual::QualVote {
                    round,
                    phase: VotePhase::Prevote,
                    value: None,
                }),
            },
            QualMessage {
                context: config.digest(),
                body: QualMessageBody::Vote(crate::qual::QualVote {
                    round,
                    phase: VotePhase::Precommit,
                    value: None,
                }),
            },
            QualMessage {
                context: config.digest(),
                body: QualMessageBody::RoundChange(QualRoundChange { round, proof_of_lock: None }),
            },
            QualMessage {
                context: config.digest(),
                body: QualMessageBody::NewRound(QualNewRound {
                    round,
                    certificate: RoundChangeCertificate { round, witnesses: Vec::new() },
                    proposal: QualProposal { round, value, proof_of_lock: None },
                }),
            },
        ];
        let sequences = messages.iter().map(qual_sequence).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            sequences,
            (0_u64..5)
                .map(|kind| 0x5100_0000_0000_0000_u64 | (round << 3) | kind)
                .collect::<Vec<_>>()
        );
        assert_eq!(sequences.iter().copied().collect::<BTreeSet<_>>().len(), 5);
    }

    #[test]
    fn qual_outbox_keeps_only_latest_round_per_kind_and_recipient() {
        let transition = test_qual_transition();
        let context = qual_config(&transition).unwrap().digest();
        let round_change = |round| {
            test_qual_wire(
                &transition,
                QualMessage {
                    context,
                    body: QualMessageBody::RoundChange(QualRoundChange {
                        round,
                        proof_of_lock: None,
                    }),
                },
            )
        };
        let mut run = new_avss_run_for_test(transition.clone());
        let first = round_change(1);
        enqueue_qual_outbound(&mut run, &transition, std::slice::from_ref(&first)).unwrap();
        assert_eq!(run.pending_qual.len(), transition.target.members.len());

        let second = round_change(2);
        enqueue_qual_outbound(&mut run, &transition, std::slice::from_ref(&second)).unwrap();
        assert_eq!(run.pending_qual.len(), transition.target.members.len());
        assert!(run.pending_qual.values().all(|wire| wire == &second));

        enqueue_qual_outbound(&mut run, &transition, &[first]).unwrap();
        assert_eq!(run.pending_qual.len(), transition.target.members.len());
        assert!(run.pending_qual.values().all(|wire| wire == &second));

        let prevote = |round| {
            test_qual_wire(
                &transition,
                QualMessage {
                    context,
                    body: QualMessageBody::Vote(crate::qual::QualVote {
                        round,
                        phase: VotePhase::Prevote,
                        value: None,
                    }),
                },
            )
        };
        let old_prevote = prevote(3);
        let latest_prevote = prevote(4);
        enqueue_qual_outbound(&mut run, &transition, &[old_prevote]).unwrap();
        enqueue_qual_outbound(&mut run, &transition, std::slice::from_ref(&latest_prevote))
            .unwrap();
        assert_eq!(run.pending_qual.len(), transition.target.members.len() * 2);
        assert_eq!(
            run.pending_qual.values().filter(|wire| *wire == &latest_prevote).count(),
            transition.target.members.len()
        );
    }

    #[test]
    fn qual_pacemaker_persists_requested_round_without_phase_shifting() {
        let transition = test_qual_transition();
        let mut run = new_avss_run_for_test(transition);
        let qual = run.qual.as_mut().unwrap();
        qual.start().unwrap();
        let step = qual.advance_round().unwrap();
        assert_eq!(qual.round(), 0);
        assert_eq!(qual.requested_round(), 1);
        assert_eq!(step.entered_round, None);
        assert_eq!(step.requested_round, Some(1));
        let response = QualStepResponse {
            party: PartyId(1),
            round: qual.round(),
            decision: step.decision,
            outbound: Vec::new(),
            evidence: step.evidence,
            entered_round: step.entered_round,
            requested_round: step.requested_round,
            duplicate: step.duplicate,
            changed: step.changed,
        };

        apply_qual_pacemaker_step(&mut run, &response, 123_456).unwrap();
        assert_eq!(run.qual.as_ref().unwrap().round(), 0);
        assert_eq!(run.qual.as_ref().unwrap().requested_round(), 1);
        assert_eq!(run.qual_round_started_unix_ms, 123_456);
        assert_eq!(run.qual_timeout_exponent, 1);
    }

    fn new_avss_run_for_test(transition: AvssTransition) -> AvssRun {
        AvssRun {
            qual: Some(QualConsensus::new(qual_config(&transition).unwrap(), PartyId(1)).unwrap()),
            transition,
            secret_compacted: false,
            receivers: BTreeMap::new(),
            outputs: BTreeMap::new(),
            dealer_outbound: None,
            delivery_responses: BTreeMap::new(),
            qual_start_response: None,
            qual_delivery_responses: BTreeMap::new(),
            qual_advance_response: None,
            qual_signed_wires: BTreeMap::new(),
            qual_current_prevotes: QualPrevoteArchive { round: 0, envelopes: BTreeMap::new() },
            qual_valid_witnesses: None,
            qual_round_started_unix_ms: 0,
            qual_timeout_exponent: 0,
            pending_avss: BTreeMap::new(),
            pending_qual: BTreeMap::new(),
            pending_activation_ack: BTreeMap::new(),
            activation_acknowledgements: BTreeMap::new(),
            finalized: None,
        }
    }

    fn signing_scenario(network: NetworkKind, demo_only: bool, identity: &Identity) -> Scenario {
        Scenario {
            schema_version: crate::config::SCENARIO_SCHEMA_VERSION,
            demo_only,
            network,
            deposit_birth_anchor: None,
            acceptance_monerod_rpc_url: "http://127.0.0.1:18081".parse().unwrap(),
            parties: vec![ScenarioParty {
                id: PartyId(1),
                admin_endpoint: "http://127.0.0.1:28080".parse().unwrap(),
                quic_endpoint: "quic://127.0.0.1:28443".parse().unwrap(),
                quic_server_name: "p1.threshold-monero.invalid".to_owned(),
                quic_certificate_file: "/tmp/threshold-monero-test-p1.der".into(),
                monerod_rpc_urls: vec!["http://127.0.0.1:28081".parse().unwrap()],
                signing_key: Hex32(identity.signing_public_key()),
                bootstrap_encryption_key: Hex32(identity.encryption_public_key()),
            }],
            committees: vec![CommitteeSpec {
                epoch: 0,
                operation: Operation::Dkg,
                threshold: 1,
                fault_bound: 0,
                members: vec![PartyId(1)],
                eligible_members: vec![PartyId(1)],
                old_dealers: Vec::new(),
            }],
            funding_blocks: 61,
            confirmation_blocks: 1,
            deposit_maximum_fee_atomic_units: 1_000_000_000,
            poll_interval_ms: 10,
            protocol_timeout_seconds: 10,
            proactive_refresh_interval_seconds: 86_400,
        }
    }

    fn admin_authenticator() -> BearerAuthenticator {
        const ADMIN_TOKEN: &[u8; 32] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        BearerAuthenticator::from_config(BearerAuthConfig {
            schema_version: BEARER_AUTH_SCHEMA_VERSION,
            credentials: vec![BearerCredentialConfig {
                principal: "operator".to_owned(),
                role: AuthRole::Admin,
                token_digest: Hex32(bearer_token_digest(ADMIN_TOKEN).unwrap()),
            }],
        })
        .unwrap()
    }

    #[test]
    fn acceptance_consolidation_gate_is_demo_regtest_only() {
        let identity = Identity::from_test_secrets(PartyId(1), 0, &[0x40; 32], [0xC0; 32]).unwrap();
        let mut scenario = signing_scenario(NetworkKind::Regtest, true, &identity);
        assert!(acceptance_consolidation_gate_allowed(&scenario, true));
        assert!(!acceptance_consolidation_gate_allowed(&scenario, false));

        scenario.demo_only = false;
        assert!(!acceptance_consolidation_gate_allowed(&scenario, true));
        scenario.demo_only = true;
        scenario.network = NetworkKind::Testnet;
        assert!(!acceptance_consolidation_gate_allowed(&scenario, true));
        scenario.network = NetworkKind::Mainnet;
        assert!(!acceptance_consolidation_gate_allowed(&scenario, true));
    }

    #[tokio::test]
    async fn party_server_retains_the_exclusive_state_lease_until_its_last_arc_drops() {
        let party = PartyId(1);
        let signing_seed = [0x41; 32];
        let bootstrap_x25519_secret = [0xC1; 32];
        let identity =
            Identity::from_test_secrets(party, 0, &signing_seed, bootstrap_x25519_secret).unwrap();
        let scenario = signing_scenario(NetworkKind::Regtest, true, &identity);
        let state = tempfile::tempdir().unwrap();

        let first = PartyServer::new(
            party,
            scenario.clone(),
            state.path(),
            &signing_seed,
            &bootstrap_x25519_secret,
        )
        .await
        .unwrap();
        let retained_clone = first.clone();
        drop(first);
        let error = PartyServer::new(
            party,
            scenario.clone(),
            state.path(),
            &signing_seed,
            &bootstrap_x25519_secret,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<StoreError>(),
            Some(StoreError::PartyStateLeaseHeld { party: held, .. }) if *held == party
        ));

        drop(retained_clone);
        PartyServer::new(party, scenario, state.path(), &signing_seed, &bootstrap_x25519_secret)
            .await
            .expect("the lease must be reacquirable after the final server Arc drops");
    }

    #[tokio::test]
    async fn acceptance_consolidation_gate_snapshot_is_authenticated_and_restart_safe() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x91; 32];
        let party = PartyId(3);
        let network = [0x92; 32];
        let store = ProtocolStore::new(directory.path(), party, &seed).unwrap();
        let (session, context) = acceptance_consolidation_gate_storage_key(network, party).unwrap();
        let held = AcceptanceConsolidationGate {
            version: ACCEPTANCE_CONSOLIDATION_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Held,
            authorization: Some(ConsolidationId([0x93; 32])),
            roast_view: Some(0),
        };
        held.validate().unwrap();
        let bytes = postcard::to_allocvec(&held).unwrap();
        store.save_session_state(session, context, &bytes, &mut OsRng).await.unwrap();

        let restarted = ProtocolStore::new(directory.path(), party, &seed).unwrap();
        assert_eq!(
            restore_acceptance_consolidation_gate(&restarted, network, party).await.unwrap(),
            held
        );
        assert!(
            restore_acceptance_consolidation_gate(&restarted, [0x94; 32], party).await.unwrap()
                == AcceptanceConsolidationGate::default()
        );
    }

    #[tokio::test]
    async fn acceptance_protocol_fault_gate_snapshot_binds_exact_restart_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x71; 32];
        let party = PartyId(3);
        let network = [0x72; 32];
        let transition = SessionId([0x73; 32]);
        let store = ProtocolStore::new(directory.path(), party, &seed).unwrap();
        let (session, context) =
            acceptance_protocol_fault_gate_storage_key(network, party).unwrap();
        let held = AcceptanceProtocolFaultGate {
            version: ACCEPTANCE_PROTOCOL_FAULT_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Held,
            session: Some(transition),
            epoch: Some(0),
            boundary: Some(AcceptanceProtocolFaultBoundary::QualRoundZero),
            dealer: None,
            qual_round: Some(0),
        };
        held.validate().unwrap();
        let bytes = postcard::to_allocvec(&held).unwrap();
        store.save_session_state(session, context, &bytes, &mut OsRng).await.unwrap();

        let restarted = ProtocolStore::new(directory.path(), party, &seed).unwrap();
        assert_eq!(
            restore_acceptance_protocol_fault_gate(&restarted, network, party).await.unwrap(),
            held
        );
        assert_eq!(
            restore_acceptance_protocol_fault_gate(&restarted, [0x74; 32], party).await.unwrap(),
            AcceptanceProtocolFaultGate::default()
        );
    }

    #[tokio::test]
    async fn acceptance_bootstrap_gate_snapshot_is_authenticated_and_restart_safe() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x81; 32];
        let party = PartyId(2);
        let network = [0x82; 32];
        let store = ProtocolStore::new(directory.path(), party, &seed).unwrap();
        let (session, context) =
            acceptance_consolidation_bootstrap_gate_storage_key(network, party).unwrap();
        let held = AcceptanceConsolidationBootstrapGate {
            version: ACCEPTANCE_CONSOLIDATION_BOOTSTRAP_GATE_VERSION,
            state: AcceptanceConsolidationGateState::Held,
            sweep: Some(SweepId([0x83; 32])),
            bootstrap_ba_view: Some(0),
            proposer: Some(PartyId(1)),
            prepared_intent_digest: Some([0x84; 32]),
        };
        held.validate().unwrap();
        let bytes = postcard::to_allocvec(&held).unwrap();
        store.save_session_state(session, context, &bytes, &mut OsRng).await.unwrap();

        let restarted = ProtocolStore::new(directory.path(), party, &seed).unwrap();
        assert_eq!(
            restore_acceptance_consolidation_bootstrap_gate(&restarted, network, party)
                .await
                .unwrap(),
            held
        );
        assert_eq!(
            restore_acceptance_consolidation_bootstrap_gate(&restarted, [0x85; 32], party)
                .await
                .unwrap(),
            AcceptanceConsolidationBootstrapGate::default()
        );
    }

    #[tokio::test]
    async fn held_bootstrap_gate_stops_progress_and_survives_party_restart() {
        let directory = tempfile::tempdir().unwrap();
        let signing_seed = [0x86; 32];
        let bootstrap_x25519_secret = [0xC6; 32];
        let identity =
            Identity::from_test_secrets(PartyId(1), 0, &signing_seed, bootstrap_x25519_secret)
                .unwrap();
        let scenario = signing_scenario(NetworkKind::Regtest, true, &identity);
        let committee = scenario.genesis_committee().unwrap();
        let server = PartyServer::new_inner(
            PartyId(1),
            scenario.clone(),
            directory.path().to_path_buf(),
            &signing_seed,
            &bootstrap_x25519_secret,
            None,
            false,
            true,
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            server
                .update_acceptance_consolidation_bootstrap_gate(
                    AcceptanceConsolidationGateAction::Arm,
                )
                .await
                .unwrap()
                .state,
            AcceptanceConsolidationGateState::Armed
        );
        let sweep = SweepId([0x87; 32]);
        let prepared_intent_digest = [0x88; 32];
        assert!(
            server
                .hold_acceptance_consolidation_bootstrap_if_armed(
                    sweep,
                    0,
                    PartyId(2),
                    prepared_intent_digest,
                    &committee,
                )
                .await
                .is_err()
        );
        assert!(
            server
                .hold_acceptance_consolidation_bootstrap_if_armed(
                    sweep,
                    0,
                    PartyId(1),
                    prepared_intent_digest,
                    &committee,
                )
                .await
                .unwrap()
        );
        assert!(server.acceptance_consolidation_bootstrap_gate_is_held().await);
        assert!(server.consolidation_signing.lock().await.is_empty());
        drop(server);

        let restarted = PartyServer::new_inner(
            PartyId(1),
            scenario,
            directory.path().to_path_buf(),
            &signing_seed,
            &bootstrap_x25519_secret,
            None,
            false,
            true,
            false,
            false,
        )
        .await
        .unwrap();
        let status = restarted
            .update_acceptance_consolidation_bootstrap_gate(
                AcceptanceConsolidationGateAction::Status,
            )
            .await
            .unwrap();
        assert_eq!(status.state, AcceptanceConsolidationGateState::Held);
        assert_eq!(status.sweep, Some(sweep));
        assert_eq!(status.bootstrap_ba_view, Some(0));
        assert_eq!(status.proposer, Some(PartyId(1)));
        assert_eq!(status.prepared_intent_digest, Some(prepared_intent_digest));
        assert!(restarted.acceptance_consolidation_bootstrap_gate_is_held().await);
        assert_eq!(
            restarted
                .update_acceptance_consolidation_bootstrap_gate(
                    AcceptanceConsolidationGateAction::Release,
                )
                .await
                .unwrap()
                .state,
            AcceptanceConsolidationGateState::Released
        );
        assert!(!restarted.acceptance_consolidation_bootstrap_gate_is_held().await);
    }

    #[tokio::test]
    async fn held_acceptance_gate_creates_no_signer_and_survives_party_restart() {
        let directory = tempfile::tempdir().unwrap();
        let signing_seed = [0x95; 32];
        let bootstrap_x25519_secret = [0xD5; 32];
        let identity =
            Identity::from_test_secrets(PartyId(1), 0, &signing_seed, bootstrap_x25519_secret)
                .unwrap();
        let scenario = signing_scenario(NetworkKind::Regtest, true, &identity);
        let server = PartyServer::new_inner(
            PartyId(1),
            scenario.clone(),
            directory.path().to_path_buf(),
            &signing_seed,
            &bootstrap_x25519_secret,
            None,
            true,
            false,
            false,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            server
                .update_acceptance_consolidation_gate(AcceptanceConsolidationGateAction::Arm)
                .await
                .unwrap()
                .state,
            AcceptanceConsolidationGateState::Armed
        );
        let authorization = ConsolidationId([0x96; 32]);
        assert!(
            server.hold_acceptance_consolidation_view_if_armed(authorization, 0).await.unwrap()
        );
        assert!(server.acceptance_consolidation_gate_is_held().await);
        assert!(server.consolidation_signing.lock().await.is_empty());
        drop(server);

        let restarted = PartyServer::new_inner(
            PartyId(1),
            scenario,
            directory.path().to_path_buf(),
            &signing_seed,
            &bootstrap_x25519_secret,
            None,
            true,
            false,
            false,
            false,
        )
        .await
        .unwrap();
        let status = restarted
            .update_acceptance_consolidation_gate(AcceptanceConsolidationGateAction::Status)
            .await
            .unwrap();
        assert_eq!(status.state, AcceptanceConsolidationGateState::Held);
        assert_eq!(status.authorization, Some(authorization));
        assert_eq!(status.roast_view, Some(0));
        assert!(restarted.consolidation_signing.lock().await.is_empty());
        assert_eq!(
            restarted
                .update_acceptance_consolidation_gate(AcceptanceConsolidationGateAction::Release)
                .await
                .unwrap()
                .state,
            AcceptanceConsolidationGateState::Released
        );
        assert!(!restarted.acceptance_consolidation_gate_is_held().await);
    }

    #[tokio::test]
    async fn obsolete_generic_http_signing_routes_are_never_mounted() {
        const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let signing_seed = [0x42; 32];
        let bootstrap_x25519_secret = [0xC2; 32];
        let identity =
            Identity::from_test_secrets(PartyId(1), 0, &signing_seed, bootstrap_x25519_secret)
                .unwrap();
        let scenario = signing_scenario(NetworkKind::Regtest, true, &identity);
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            PartyId(1),
            scenario,
            state.path(),
            &signing_seed,
            &bootstrap_x25519_secret,
        )
        .await
        .unwrap();

        let app = server.http_router(admin_authenticator());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        for route in ["preprocess", "share", "complete"] {
            let response = client
                .post(format!("http://{address}/v1/sign/{route}"))
                .bearer_auth(ADMIN_TOKEN)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND, "route {route}");
        }
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn status_reports_uninitialized_deposits_without_waiting_for_monerod() {
        let signing_seed = [0x43; 32];
        let bootstrap_x25519_secret = [0xC3; 32];
        let identity =
            Identity::from_test_secrets(PartyId(1), 0, &signing_seed, bootstrap_x25519_secret)
                .unwrap();
        let scenario = signing_scenario(NetworkKind::Regtest, true, &identity);
        let daemon = Arc::new(
            ReconnectingMoneroDaemon::new(
                ["http://192.0.2.1:18081"],
                NetworkKind::Regtest,
                MoneroRpcLimits {
                    request_timeout: std::time::Duration::from_secs(30),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new_with_deposits(
            PartyId(1),
            scenario,
            state.path(),
            &signing_seed,
            &bootstrap_x25519_secret,
            PartyDepositConfig {
                private_view_scalar: Zeroizing::new(Scalar::from(7_u64).to_bytes()),
                birth_anchor: None,
                worker: DepositWorkerConfig::default(),
                chain_source: daemon.clone(),
                consolidation_backend: daemon.clone(),
                chain_readiness: daemon.readiness(),
            },
        )
        .await
        .unwrap();
        server.mark_quic_runtime_attached().unwrap();

        let Json(observed) =
            tokio::time::timeout(std::time::Duration::from_millis(100), status(State(server)))
                .await
                .expect("status waited for the configured 30-second daemon deadline")
                .expect("an uninitialized deposit runtime made status fail");

        assert!(observed.ready, "core readiness must remain independent of deposits");
        assert_eq!(observed.deposit_ready, Some(false));
        assert_eq!(observed.deposit_chain_ready, Some(false));
        assert!(!daemon.is_ready(), "status unexpectedly connected to monerod");
    }

    #[test]
    fn roast_schedule_reaches_an_all_honest_last_subset_with_adversarial_party_ids() {
        let committee = committee(0, 10, 4);
        // Byzantine operators occupy the three lowest identifiers, placing the only all-honest
        // `n-f` subset at the very end of lexicographic enumeration.
        let faulty = BTreeSet::from([PartyId(1), PartyId(2), PartyId(3)]);
        let honest = committee
            .members
            .iter()
            .map(|member| member.id)
            .filter(|party| !faulty.contains(party))
            .collect::<Vec<_>>();
        let mut all_honest_view = None;
        let mut selected_per_party = BTreeMap::<PartyId, usize>::new();
        for view in 0_u64..120 {
            let signers =
                crate::consolidation_roast::deterministic_roast_signers(&committee, 3, view)
                    .unwrap();
            for signer in &signers {
                *selected_per_party.entry(*signer).or_default() += 1;
            }
            if signers == honest {
                all_honest_view = Some(view);
            }
        }
        assert_eq!(all_honest_view, Some(119));
        assert_eq!(selected_per_party.len(), 10);
        assert!(selected_per_party.values().all(|selected| *selected == 84));
        assert!(selected_per_party.values().any(|selected| *selected > MAX_LIVE_SIGNING_SESSIONS));
    }

    #[test]
    fn epoch_transition_fence_detects_only_still_live_older_shares() {
        assert_eq!(live_predecessor_epochs([0, 1], 1), [0]);
        assert_eq!(live_predecessor_epochs([1], 1), Vec::<u64>::new());
        assert_eq!(live_predecessor_epochs([1, 2], 1), Vec::<u64>::new());
    }

    #[test]
    fn maximum_accepted_avss_run_has_a_deliverable_persistent_encoding() {
        let target =
            committee(0, u16::try_from(MAX_COMMITTEE_MEMBERS).unwrap(), MAX_COMMITTEE_THRESHOLD);
        target.validate_async_security_with_faults(0).unwrap();
        let transition = AvssTransition {
            purpose: DealPurpose::Dkg,
            session: SessionId([0x31; 32]),
            key_id: [0x32; 32],
            fault_bound: 0,
            history_parent: EpochHistoryParent::genesis([0x33; 32], [0x32; 32]).unwrap(),
            old: None,
            target: target.clone(),
            eligible_dealers: Vec::new(),
        };
        let bounds = preflight_avss_resources(&target, MAX_COMMITTEE_MEMBERS).unwrap();
        assert!(bounds.maximum_persisted_session_bytes <= MAX_SESSION_STATE_BYTES);

        let receivers = target
            .members
            .iter()
            .map(|member| {
                let config = AvssConfig {
                    session: transition.session,
                    dealer: member.id,
                    receivers: target.clone(),
                    fault_bound: 0,
                };
                (member.id, AvssParty::new(config, PartyId(1)).unwrap())
            })
            .collect();
        let run = AvssRun {
            transition: transition.clone(),
            secret_compacted: false,
            receivers,
            outputs: BTreeMap::new(),
            dealer_outbound: None,
            delivery_responses: BTreeMap::new(),
            qual: Some(QualConsensus::new(qual_config(&transition).unwrap(), PartyId(1)).unwrap()),
            qual_start_response: None,
            qual_delivery_responses: BTreeMap::new(),
            qual_advance_response: None,
            qual_signed_wires: BTreeMap::new(),
            qual_current_prevotes: QualPrevoteArchive { round: 0, envelopes: BTreeMap::new() },
            qual_valid_witnesses: None,
            qual_round_started_unix_ms: 0,
            qual_timeout_exponent: 0,
            pending_avss: BTreeMap::new(),
            pending_qual: BTreeMap::new(),
            pending_activation_ack: BTreeMap::new(),
            activation_acknowledgements: BTreeMap::new(),
            finalized: None,
        };
        let encoded = encode_durable_avss_run(&run).unwrap();
        assert!(encoded.len() <= MAX_SESSION_STATE_BYTES);
        assert!(encoded.len() <= bounds.maximum_persisted_session_bytes);
    }

    #[test]
    fn certified_avss_compaction_erases_plaintext_shares_and_keeps_pending_ciphertext() {
        let target = committee(0, 4, 2);
        let transition = AvssTransition {
            purpose: DealPurpose::Dkg,
            session: SessionId([0x35; 32]),
            key_id: [0x36; 32],
            fault_bound: 1,
            history_parent: EpochHistoryParent::genesis([0x34; 32], [0x36; 32]).unwrap(),
            old: None,
            target: target.clone(),
            eligible_dealers: Vec::new(),
        };
        let polynomial = SecretPolynomial::random(target.threshold, &mut OsRng).unwrap();
        let dealer = make_dkg_output(PartyId(1), &polynomial, &target, PartyId(1)).unwrap();
        let plaintext_share = dealer.share.0;
        let output = AvssOutput {
            instance: crate::avss::AvssInstanceId {
                session: transition.session,
                dealer: PartyId(1),
                receiver_committee: target.digest(),
                receiver_epoch: target.epoch,
                threshold: target.threshold,
                fault_bound: transition.fault_bound,
            },
            recipient: PartyId(1),
            share: dealer.share.clone(),
            x_axis_commitment: dealer.commitment.clone(),
            commitment_digest: crate::avss::CommitmentDigest([0x37; 32]),
            ready_senders: BTreeSet::from([PartyId(1), PartyId(2), PartyId(3)]),
        };
        let pending_wire = AvssWire {
            version: AVSS_WIRE_VERSION,
            dealer: PartyId(1),
            recipient: PartyId(2),
            envelope: SignedEnvelope {
                version: 1,
                committee: target.digest(),
                epoch: target.epoch,
                session: transition.session,
                from: PartyId(1),
                to: Some(PartyId(2)),
                sequence: 7,
                payload: vec![0xA1, 0xA2, 0xA3],
                signature: [0xA4; 64],
            },
        };
        let pending_key = (PartyId(2), [0x38; 32]);
        let mut run = AvssRun {
            transition,
            secret_compacted: false,
            receivers: BTreeMap::new(),
            outputs: BTreeMap::new(),
            dealer_outbound: None,
            delivery_responses: BTreeMap::new(),
            qual: None,
            qual_start_response: None,
            qual_delivery_responses: BTreeMap::new(),
            qual_advance_response: None,
            qual_signed_wires: BTreeMap::new(),
            qual_current_prevotes: QualPrevoteArchive { round: 0, envelopes: BTreeMap::new() },
            qual_valid_witnesses: None,
            qual_round_started_unix_ms: 0,
            qual_timeout_exponent: 0,
            pending_avss: BTreeMap::new(),
            pending_qual: BTreeMap::new(),
            pending_activation_ack: BTreeMap::new(),
            activation_acknowledgements: BTreeMap::new(),
            finalized: None,
        };
        run.outputs.insert(PartyId(1), output);
        run.pending_avss.insert(pending_key, pending_wire.clone());
        let before = encode_durable_avss_run(&run).unwrap();
        assert!(before.windows(32).any(|window| window == plaintext_share));

        compact_avss_secret_state(&mut run);
        validate_avss_secret_compaction(&run).unwrap();
        assert_eq!(run.pending_avss.get(&pending_key), Some(&pending_wire));
        let compacted = encode_durable_avss_run(&run).unwrap();
        assert!(
            !compacted.windows(32).any(|window| window == plaintext_share),
            "secret-compacted durable AVSS retained a plaintext ScalarBytes value"
        );
        let DurableSessionState::Avss(restored) =
            decode_postcard_exact::<DurableSessionState>(&compacted).unwrap();
        validate_avss_secret_compaction(&restored).unwrap();
        assert_eq!(restored.pending_avss.get(&pending_key), Some(&pending_wire));
    }

    #[test]
    fn certified_catch_up_runs_do_not_consume_the_live_avss_bound() {
        let target = committee(0, 4, 2);
        let make_run = |domain: u8, index: usize| {
            let mut material = vec![domain];
            material.extend_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            let transition = AvssTransition {
                purpose: DealPurpose::Dkg,
                session: SessionId(*blake3::hash(&material).as_bytes()),
                key_id: [0xA5; 32],
                fault_bound: 1,
                history_parent: EpochHistoryParent::genesis([0xA6; 32], [0xA5; 32]).unwrap(),
                old: None,
                target: target.clone(),
                eligible_dealers: Vec::new(),
            };
            AvssRun {
                transition,
                secret_compacted: false,
                receivers: BTreeMap::new(),
                outputs: BTreeMap::new(),
                dealer_outbound: None,
                delivery_responses: BTreeMap::new(),
                qual: None,
                qual_start_response: None,
                qual_delivery_responses: BTreeMap::new(),
                qual_advance_response: None,
                qual_signed_wires: BTreeMap::new(),
                qual_current_prevotes: QualPrevoteArchive { round: 0, envelopes: BTreeMap::new() },
                qual_valid_witnesses: None,
                qual_round_started_unix_ms: 0,
                qual_timeout_exponent: 0,
                pending_avss: BTreeMap::new(),
                pending_qual: BTreeMap::new(),
                pending_activation_ack: BTreeMap::new(),
                activation_acknowledgements: BTreeMap::new(),
                finalized: None,
            }
        };

        let mut runs = BTreeMap::new();
        let mut certified = BTreeMap::new();
        for index in 0..=MAX_LIVE_AVSS_RUNS {
            let run = make_run(1, index);
            certified
                .insert(run.transition.session, avss_transition_digest(&run.transition).unwrap());
            runs.insert(run.transition.session, run);
        }
        for index in 0..MAX_LIVE_AVSS_RUNS {
            let run = make_run(2, index);
            runs.insert(run.transition.session, run);
        }

        let certified_candidate = make_run(3, 0).transition;
        certified.insert(
            certified_candidate.session,
            avss_transition_digest(&certified_candidate).unwrap(),
        );
        ensure_avss_live_capacity(&runs, &certified, &certified_candidate, MAX_LIVE_AVSS_RUNS)
            .expect("a certified late-catch-up run does not need a live reducer slot");

        let live_candidate = make_run(4, 0).transition;
        assert!(
            ensure_avss_live_capacity(&runs, &certified, &live_candidate, MAX_LIVE_AVSS_RUNS,)
                .unwrap_err()
                .to_string()
                .contains("too many live AVSS sessions")
        );

        let removed_live = make_run(2, 0).transition.session;
        runs.remove(&removed_live).unwrap();
        ensure_avss_live_capacity(&runs, &certified, &live_candidate, MAX_LIVE_AVSS_RUNS)
            .expect("one freed live slot admits one uncertified reducer");

        let certified_session = make_run(1, 0).transition.session;
        certified.get_mut(&certified_session).unwrap()[0] ^= 1;
        assert!(
            ensure_avss_live_capacity(&runs, &certified, &live_candidate, MAX_LIVE_AVSS_RUNS,)
                .unwrap_err()
                .to_string()
                .contains("bound to another transition")
        );
    }

    #[test]
    fn qual_starts_only_after_locally_validatable_avss_output_quorum() {
        let dkg = AvssTransition {
            purpose: DealPurpose::Dkg,
            session: SessionId([1; 32]),
            key_id: [2; 32],
            fault_bound: 2,
            history_parent: EpochHistoryParent::genesis([1; 32], [2; 32]).unwrap(),
            old: None,
            target: committee(0, 7, 4),
            eligible_dealers: vec![],
        };
        assert!(!qual_has_start_quorum(&dkg, 4).unwrap());
        assert!(qual_has_start_quorum(&dkg, 5).unwrap());

        let old_committee = committee(0, 5, 3);
        let reshare = AvssTransition {
            purpose: DealPurpose::Reshare,
            session: SessionId([3; 32]),
            key_id: [4; 32],
            fault_bound: 2,
            history_parent: EpochHistoryParent::genesis([1; 32], [4; 32]).unwrap(),
            old: Some(EpochPublic {
                key_id: [4; 32],
                committee: old_committee,
                verification_shares: BTreeMap::new(),
                group_key: PointBytes([0; 32]),
            }),
            target: committee(1, 7, 4),
            eligible_dealers: vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
        };
        assert!(!qual_has_start_quorum(&reshare, 2).unwrap());
        assert!(qual_has_start_quorum(&reshare, 3).unwrap());
    }

    #[test]
    fn outside_epoch_observers_never_emit_transition_role_messages() {
        let target = committee(0, 5, 3);
        let scenario_parties = (1_u16..=7).map(PartyId).collect::<Vec<_>>();

        let observer_routes =
            epoch_certificate_routes(PartyId(6), &scenario_parties, &target, None);
        assert_eq!(observer_routes, vec![(PartyId(7), EpochOperation::Observe)]);
        assert!(observer_routes.iter().all(|(_, operation)| *operation == EpochOperation::Observe));

        let member_routes = epoch_certificate_routes(PartyId(1), &scenario_parties, &target, None);
        assert_eq!(
            member_routes,
            vec![
                (PartyId(2), EpochOperation::Activate),
                (PartyId(3), EpochOperation::Activate),
                (PartyId(4), EpochOperation::Activate),
                (PartyId(5), EpochOperation::Activate),
                (PartyId(6), EpochOperation::Observe),
                (PartyId(7), EpochOperation::Observe),
            ]
        );
    }

    #[test]
    fn qual_pacemaker_does_not_expire_a_round_started_after_its_clock_sample() {
        assert!(!qual_round_expired(10_001, 10_000, 1_000));
        assert!(!qual_round_expired(10_000, 10_999, 1_000));
        assert!(qual_round_expired(10_000, 11_000, 1_000));
        assert_eq!(qual_backoff_timeout_ms(1_000, 0), 1_000);
        assert_eq!(qual_backoff_timeout_ms(1_000, 3), 8_000);
        assert_eq!(qual_backoff_timeout_ms(1_000, u8::MAX), MAX_QUAL_BACKOFF_TIMEOUT_MS);
    }

    #[test]
    fn tenant_request_ids_are_isolated_and_retries_are_stable() {
        let supplied = DepositAddressRequest {
            request: LedgerRequestId([0x41; 32]),
            binding: RequestBinding([0x52; 32]),
        };
        let alice = AuthenticatedPrincipal {
            name: "alice".to_owned(),
            role: crate::auth::AuthRole::Deposits,
        };
        let bob = AuthenticatedPrincipal {
            name: "bob".to_owned(),
            role: crate::auth::AuthRole::Deposits,
        };

        let alice_first = tenant_deposit_request(&alice, supplied).unwrap();
        let alice_retry = tenant_deposit_request(&alice, supplied).unwrap();
        let bob_first = tenant_deposit_request(&bob, supplied).unwrap();
        let alice_changed_binding = tenant_deposit_request(
            &alice,
            DepositAddressRequest {
                request: supplied.request,
                binding: RequestBinding([0x53; 32]),
            },
        )
        .unwrap();
        assert_eq!(alice_first, alice_retry, "one tenant's retry must be idempotent");
        assert_ne!(alice_first.request, bob_first.request);
        assert_ne!(alice_first.binding, bob_first.binding);
        assert_ne!(
            alice_first.request, alice_changed_binding.request,
            "changing a client binding must select another internal request id"
        );
        assert_ne!(alice_first.binding, alice_changed_binding.binding);
        assert_ne!(alice_first.request, supplied.request);
        assert_ne!(bob_first.request, supplied.request);
        assert_eq!(alice_first.request, deposit_request_id_for_binding(alice_first.binding));
        assert_eq!(bob_first.request, deposit_request_id_for_binding(bob_first.binding));
    }

    #[test]
    fn tenant_request_isolation_produces_independent_verified_certificates() {
        let supplied = DepositAddressRequest {
            request: LedgerRequestId([0x41; 32]),
            binding: RequestBinding([0x52; 32]),
        };
        let alice = AuthenticatedPrincipal {
            name: "alice".to_owned(),
            role: crate::auth::AuthRole::Deposits,
        };
        let bob = AuthenticatedPrincipal {
            name: "bob".to_owned(),
            role: crate::auth::AuthRole::Deposits,
        };
        let alice_request = tenant_deposit_request(&alice, supplied).unwrap();
        let bob_request = tenant_deposit_request(&bob, supplied).unwrap();

        let identities = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                let signing_seed = [u8::try_from(id).unwrap(); 32];
                let x25519_secret = [u8::try_from(id).unwrap().wrapping_add(0x40); 32];
                let identity =
                    Identity::from_test_secrets(party, 0, &signing_seed, x25519_secret).unwrap();
                (party, identity)
            })
            .collect::<BTreeMap<_, _>>();
        let committee = Committee {
            epoch: 0,
            threshold: 2,
            members: identities
                .values()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let portable = DepositIndexHead::empty_portable(deriver.wallet_id(), first_index).unwrap();
        let authority = VerifiedRegistryHandoffTarget::for_test(
            committee.clone(),
            1,
            [0x61; 32],
            [0x62; 32],
            deriver.wallet_id(),
            [0x63; 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&authority, first_index, portable.digest()).unwrap();
        let registry = pending.proposed_head().registry().clone();
        let mut next_sequence = 1_u64;
        let mut head = genesis_head(deriver.wallet_id());
        let mut next_index = first_index;
        let mut certify = |request: DepositAddressRequest| {
            let address = deriver.derive(next_index);
            let statement = LedgerStatement::allocation(
                &registry,
                next_sequence,
                head,
                request.request,
                request.binding,
                address.clone(),
                ChainPoint::new(0, [0x64; 32]).unwrap(),
                1_800_000_000,
            )
            .unwrap();
            let payload = statement.attestation_payload().unwrap();
            let mut attestations = identities
                .values()
                .take(3)
                .map(|identity| {
                    identity
                        .sign_envelope(
                            &committee,
                            statement.slot_session(),
                            None,
                            statement.sequence,
                            payload.clone(),
                        )
                        .unwrap()
                })
                .collect::<Vec<_>>();
            attestations.sort_by_key(|envelope| envelope.from);
            let certificate = CertifiedLedgerEntry { statement, attestations };
            certificate.verify_active(&registry, None).unwrap();
            next_sequence = next_sequence.checked_add(1).unwrap();
            head = certificate.statement.digest();
            next_index =
                DepositSubaddressIndex::new(0, next_index.address().checked_add(1).unwrap())
                    .unwrap();
            (address, certificate)
        };

        let (alice_address, alice_certificate) = certify(alice_request);
        let (bob_address, bob_certificate) = certify(bob_request);
        assert_ne!(alice_request.request, bob_request.request);
        assert_ne!(alice_address, bob_address);
        assert_ne!(alice_certificate.statement.digest(), bob_certificate.statement.digest());
        assert_eq!(
            tenant_deposit_request(&alice, supplied).unwrap(),
            alice_request,
            "Alice's retry must resolve to her existing certified request"
        );
        assert_eq!(
            tenant_deposit_request(&bob, supplied).unwrap(),
            bob_request,
            "Bob's retry must resolve to his existing certified request"
        );
        assert!(matches!(
            &alice_certificate.statement.payload,
            LedgerPayload::Allocation(allocation) if allocation.request == alice_request.request
        ));
        assert!(matches!(
            &bob_certificate.statement.payload,
            LedgerPayload::Allocation(allocation) if allocation.request == bob_request.request
        ));
    }

    #[test]
    fn quic_rejections_distinguish_ordering_from_terminal_effects() {
        let not_certified = quic_peer_rejection(anyhow::anyhow!(
            "dealer 3 has not locally completed the named AVSS instance"
        ));
        assert!(matches!(
            not_certified,
            PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(anyhow::anyhow!(
                "live predecessor epoch shares remain before epoch 1: [0]"
            )),
            PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(anyhow::anyhow!(
                "epoch 2 lacks a locally durable key-rotation certificate"
            )),
            PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(anyhow::anyhow!("zero refresh is not due yet")),
            PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
        ));

        for message in [
            "message is from stale round 4; current round is 5",
            "AVSS session is already finalized",
            "key-rotation certificate signature is invalid",
        ] {
            assert!(matches!(
                quic_peer_rejection(anyhow::anyhow!(message)),
                PeerResponse::Rejected { retryable: false, .. }
            ));
        }

        for error in [
            DepositServiceError::HandoffPending,
            DepositServiceError::ConsolidationNotPortable,
            DepositServiceError::ConsolidationNotCertified,
            DepositServiceError::ConsolidationCompletionMismatch,
            DepositServiceError::StaleConsolidationCandidate,
            DepositServiceError::ConsensusUnavailable,
            DepositServiceError::Consensus(ConsensusError::NotStarted),
            DepositServiceError::Consensus(ConsensusError::FutureView { message: 2, current: 1 }),
            DepositServiceError::Ledger(LedgerError::TerminalAdmissionRequired),
            DepositServiceError::Worker(DepositWorkerError::AllocationBackfillRequired),
        ] {
            assert!(matches!(
                quic_peer_rejection(error.into()),
                PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
            ));
        }

        assert!(matches!(
            quic_peer_rejection(DepositServiceError::InvalidPeerMessage.into()),
            PeerResponse::Rejected { code: RejectionCode::InvalidRequest, retryable: false, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(DepositServiceError::ConsensusRequestPoolFull.into()),
            PeerResponse::Rejected { code: RejectionCode::ResourceExhausted, retryable: true, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(DepositServiceError::TooManyPendingObservations.into()),
            PeerResponse::Rejected { code: RejectionCode::ResourceExhausted, retryable: true, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(DepositServiceError::ConsolidationWireEquivocation.into()),
            PeerResponse::Rejected { code: RejectionCode::Conflict, retryable: false, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(DepositServiceError::ConsolidationRecoveryRequired.into()),
            PeerResponse::Rejected { code: RejectionCode::Conflict, retryable: false, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(DepositServiceError::ConsolidationRoundClosed.into()),
            PeerResponse::Rejected { code: RejectionCode::Conflict, retryable: false, .. }
        ));
    }

    #[test]
    fn quic_rejection_retries_scanner_lag_but_rejects_malformed_sweep() {
        assert!(matches!(
            quic_peer_rejection(
                DepositServiceError::ConsolidationWire(ConsolidationWireError::Worker(
                    DepositWorkerError::StaleSweepPlan
                ),)
                .into()
            ),
            PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
        ));
        assert!(matches!(
            quic_peer_rejection(
                DepositServiceError::ConsolidationWire(ConsolidationWireError::Worker(
                    DepositWorkerError::InvalidPreparedSweep
                ),)
                .into()
            ),
            PeerResponse::Rejected { code: RejectionCode::InvalidRequest, retryable: false, .. }
        ));
    }

    #[test]
    fn post_accept_deposit_reconciliation_swallows_only_expected_certificate_gaps() {
        for error in [
            DepositServiceError::NotInitialized,
            DepositServiceError::CertifiedHandoffUnavailable(2),
        ] {
            assert!(is_expected_deposit_reconciliation_gap(&error.into()));
        }
        for error in [
            DepositServiceError::WrongRegistry,
            DepositServiceError::InvalidProtocolState,
            DepositServiceError::StorageRevisionMismatch,
        ] {
            assert!(!is_expected_deposit_reconciliation_gap(&error.into()));
        }
    }

    fn historical_replay_seed(party: PartyId) -> [u8; 32] {
        let mut seed = [u8::try_from(party.0).unwrap().wrapping_mul(29); 32];
        seed[..2].copy_from_slice(&party.0.to_le_bytes());
        seed
    }

    fn historical_replay_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut material = [0_u8; 10];
        material[..2].copy_from_slice(&party.0.to_le_bytes());
        material[2..].copy_from_slice(&epoch.to_le_bytes());
        blake3::derive_key("threshold-monero/server-test-independent-x25519-secret/v1", &material)
    }

    fn historical_replay_scenario() -> Scenario {
        let parties = (1_u16..=2)
            .map(|id| {
                let party = PartyId(id);
                let signing_seed = historical_replay_seed(party);
                let bootstrap = Identity::from_test_secrets(
                    party,
                    0,
                    &signing_seed,
                    historical_replay_x25519_secret(party, 0),
                )
                .unwrap();
                ScenarioParty {
                    id: party,
                    admin_endpoint: format!("http://127.0.0.1:{}", 31_000 + id).parse().unwrap(),
                    quic_endpoint: format!("quic://127.0.0.1:{}", 32_000 + id).parse().unwrap(),
                    quic_server_name: format!("p{id}.historical-replay.invalid"),
                    quic_certificate_file: format!("/tmp/historical-replay-p{id}.der").into(),
                    monerod_rpc_urls: vec![
                        format!("http://127.0.0.1:{}", 33_000 + id).parse().unwrap(),
                    ],
                    signing_key: Hex32(bootstrap.signing_public_key()),
                    bootstrap_encryption_key: Hex32(bootstrap.encryption_public_key()),
                }
            })
            .collect();
        Scenario {
            schema_version: crate::config::SCENARIO_SCHEMA_VERSION,
            demo_only: true,
            network: NetworkKind::Regtest,
            deposit_birth_anchor: None,
            acceptance_monerod_rpc_url: "http://127.0.0.1:18081".parse().unwrap(),
            parties,
            committees: vec![
                CommitteeSpec {
                    epoch: 0,
                    operation: Operation::Dkg,
                    threshold: 1,
                    fault_bound: 0,
                    members: vec![PartyId(1)],
                    eligible_members: vec![PartyId(1)],
                    old_dealers: vec![],
                },
                CommitteeSpec {
                    epoch: 1,
                    operation: Operation::Reshare,
                    threshold: 2,
                    fault_bound: 0,
                    members: vec![PartyId(1), PartyId(2)],
                    eligible_members: vec![PartyId(1), PartyId(2)],
                    old_dealers: vec![PartyId(1)],
                },
                CommitteeSpec {
                    epoch: 2,
                    operation: Operation::Reshare,
                    threshold: 1,
                    fault_bound: 0,
                    members: vec![PartyId(1)],
                    eligible_members: vec![PartyId(1)],
                    old_dealers: vec![PartyId(1), PartyId(2)],
                },
            ],
            funding_blocks: 1,
            confirmation_blocks: 1,
            deposit_maximum_fee_atomic_units: 1_000_000_000,
            poll_interval_ms: 10,
            protocol_timeout_seconds: 10,
            proactive_refresh_interval_seconds: 86_400,
        }
    }

    fn activation_witness_scenario() -> Scenario {
        let parties = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                let signing_seed = historical_replay_seed(party);
                let identity = Identity::from_test_secrets(
                    party,
                    0,
                    &signing_seed,
                    historical_replay_x25519_secret(party, 0),
                )
                .unwrap();
                ScenarioParty {
                    id: party,
                    admin_endpoint: format!("http://127.0.0.1:{}", 37_000 + id).parse().unwrap(),
                    quic_endpoint: format!("quic://127.0.0.1:{}", 38_000 + id).parse().unwrap(),
                    quic_server_name: format!("p{id}.activation-witness.invalid"),
                    quic_certificate_file: format!("/tmp/activation-witness-p{id}.der").into(),
                    monerod_rpc_urls: vec![
                        format!("http://127.0.0.1:{}", 39_000 + id).parse().unwrap(),
                    ],
                    signing_key: Hex32(identity.signing_public_key()),
                    bootstrap_encryption_key: Hex32(identity.encryption_public_key()),
                }
            })
            .collect();
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
                threshold: 2,
                fault_bound: 1,
                members: (1_u16..=4).map(PartyId).collect(),
                eligible_members: (1_u16..=4).map(PartyId).collect(),
                old_dealers: Vec::new(),
            }],
            funding_blocks: 1,
            confirmation_blocks: 1,
            deposit_maximum_fee_atomic_units: 1_000_000_000,
            poll_interval_ms: 10,
            protocol_timeout_seconds: 10,
            proactive_refresh_interval_seconds: 86_400,
        }
    }

    fn proactive_refresh_scenario() -> Scenario {
        let mut scenario = activation_witness_scenario();
        scenario.parties.push(activation_witness_extra_party(PartyId(5)));
        scenario.committees.push(CommitteeSpec {
            epoch: 1,
            operation: Operation::Reshare,
            threshold: 2,
            fault_bound: 1,
            members: (1_u16..=4).map(PartyId).collect(),
            eligible_members: (1_u16..=5).map(PartyId).collect(),
            old_dealers: (1_u16..=4).map(PartyId).collect(),
        });
        scenario.proactive_refresh_interval_seconds = 1;
        scenario.validate().unwrap();
        scenario
    }

    /// A proactive-refresh scenario whose successor keeps the full four-member committee (a genuine
    /// share refresh, `desired_n = 4`) and enrolls a fifth stable identity as an eligible spare.
    ///
    /// The eligible-target policy's `desired_n + target_fault_bound` Byzantine-liveness floor needs
    /// at least five eligible identities for a four-member successor at `f = 1`; the spare can
    /// replace a single silent candidate without carrying any source/bootstrap receiver key. Unlike
    /// [`proactive_refresh_scenario`] — whose callers certify an exact `desired_n = 3` advertisement
    /// set — the refresh-hold and certified-undrained restore tests exercise only the schedule and
    /// restore paths, so they run against this spare-backed five-eligible pool.
    fn proactive_refresh_spare_eligible_scenario() -> Scenario {
        let mut scenario = activation_witness_scenario();
        scenario.parties.push(activation_witness_extra_party(PartyId(5)));
        scenario.committees.push(CommitteeSpec {
            epoch: 1,
            operation: Operation::Reshare,
            threshold: 2,
            fault_bound: 1,
            members: (1_u16..=4).map(PartyId).collect(),
            eligible_members: (1_u16..=5).map(PartyId).collect(),
            old_dealers: (1_u16..=4).map(PartyId).collect(),
        });
        scenario.proactive_refresh_interval_seconds = 1;
        scenario.validate().unwrap();
        scenario
    }

    /// Build one additional deterministic scenario party beyond the four `activation_witness`
    /// members, mirroring their exact stable-key derivation so the eligibility reference key
    /// resolves identically. The party is enrolled only as an eligible spare and is never a genesis
    /// committee member or desired successor.
    fn activation_witness_extra_party(party: PartyId) -> ScenarioParty {
        let signing_seed = historical_replay_seed(party);
        let identity = Identity::from_test_secrets(
            party,
            0,
            &signing_seed,
            historical_replay_x25519_secret(party, 0),
        )
        .unwrap();
        ScenarioParty {
            id: party,
            admin_endpoint: format!("http://127.0.0.1:{}", 37_000 + party.0).parse().unwrap(),
            quic_endpoint: format!("quic://127.0.0.1:{}", 38_000 + party.0).parse().unwrap(),
            quic_server_name: format!("p{}.activation-witness.invalid", party.0),
            quic_certificate_file: format!("/tmp/activation-witness-p{}.der", party.0).into(),
            monerod_rpc_urls: vec![
                format!("http://127.0.0.1:{}", 39_000 + party.0).parse().unwrap(),
            ],
            signing_key: Hex32(identity.signing_public_key()),
            bootstrap_encryption_key: Hex32(identity.encryption_public_key()),
        }
    }

    async fn new_refresh_hold_test_server(
        local: PartyId,
        scenario: Scenario,
        state_directory: std::path::PathBuf,
        hold_enabled: bool,
    ) -> anyhow::Result<Arc<PartyServer>> {
        // Poll restoration on a normal Tokio worker stack instead of nesting its debug frames
        // beneath the much larger end-to-end persistence test future.
        let restore = Box::pin(async move {
            let signing_seed = historical_replay_seed(local);
            let bootstrap_x25519_secret = historical_replay_x25519_secret(local, 0);
            PartyServer::new_inner(
                local,
                scenario,
                state_directory,
                &signing_seed,
                &bootstrap_x25519_secret,
                None,
                false,
                false,
                false,
                hold_enabled,
            )
            .await
        });
        Ok(tokio::spawn(restore).await??)
    }

    fn dynamic_refresh_scenario() -> Scenario {
        let mut scenario = activation_witness_scenario();
        // The dynamic tests carry no epoch-1 committee spec, so `key_rotation_context_for_source`
        // takes the policy fallback: the eligible pool is every scenario party and `desired_n` is
        // the four-member source size. The tightened `desired_n + f` floor needs a fifth stable
        // identity, enrolled here as an eligible spare that never joins the source committee.
        scenario.parties.push(activation_witness_extra_party(PartyId(5)));
        scenario.proactive_refresh_interval_seconds = 1;
        scenario.validate().unwrap();
        scenario
    }

    fn proactive_epoch_zero_share(scenario: &Scenario, recipient: PartyId) -> EpochShare {
        let committee = scenario.genesis_committee().unwrap();
        let (key_id, _) = canonical_dkg_identity(scenario).unwrap();
        let outputs = committee
            .members
            .iter()
            .map(|member| {
                let polynomial = SecretPolynomial::random(committee.threshold, &mut OsRng).unwrap();
                make_dkg_output(member.id, &polynomial, &committee, recipient).unwrap()
            })
            .collect();
        aggregate_dkg(key_id, committee, recipient, outputs).unwrap()
    }

    async fn install_proactive_epoch_zero(server: &Arc<PartyServer>, share: &EpochShare) {
        let scenario = server.scenario();
        let (key_id, session) = canonical_dkg_identity(scenario).unwrap();
        let transition = AvssTransition {
            purpose: DealPurpose::Dkg,
            session,
            key_id,
            fault_bound: scenario.committee_spec(0).unwrap().fault_bound,
            history_parent: EpochHistoryParent::genesis(
                scenario.quic_network_id().unwrap(),
                key_id,
            )
            .unwrap(),
            old: None,
            target: scenario.genesis_committee().unwrap(),
            eligible_dealers: Vec::new(),
        };
        let certificate = historical_activation_request(&transition, share.public(), 0xD0, None);
        server
            .persist_activation_certificate(
                &certificate.transition,
                &certificate.value,
                &certificate.acknowledgements,
            )
            .await
            .unwrap();
        server.store.save(share, &mut OsRng).await.unwrap();
        server.epochs.write().await.insert(0, share.clone());
        *server.active_epoch.write().await = Some(0);
        server.activations.write().await.insert(
            0,
            InstallResponse {
                party: server.party,
                epoch: 0,
                public: certificate.value.public,
                activation_digest: certificate.value.activation_digest,
                avss_transcript_digest: certificate.value.avss_transcript_digest,
                history_link: certificate.value.history_link,
            },
        );
    }

    fn historical_activation_request(
        transition: &AvssTransition,
        public: EpochPublic,
        transcript_byte: u8,
        key_rotation_digest: Option<[u8; 32]>,
    ) -> ActivateEpochRequest {
        let activation_digest = public.activation_digest().unwrap();
        let history_link = EpochHistoryLink::new(
            transition.history_parent.network(),
            transition.key_id,
            transition.target.epoch,
            transition.history_parent.root(),
            avss_transition_digest(transition).unwrap(),
            activation_digest,
            [transcript_byte; 32],
            key_rotation_digest,
        )
        .unwrap();
        let value = ActivationValue {
            epoch: public.committee.epoch,
            activation_digest,
            public,
            avss_transcript_digest: [transcript_byte; 32],
            history_link,
        };
        let statement = activation_statement(&value, transition.session);
        let payload = postcard::to_allocvec(&statement).unwrap();
        let acknowledgements = transition
            .target
            .members
            .iter()
            .map(|member| {
                Identity::from_test_secrets(
                    member.id,
                    transition.target.epoch,
                    &historical_replay_seed(member.id),
                    historical_replay_x25519_secret(member.id, transition.target.epoch),
                )
                .unwrap()
                .sign_envelope(
                    &transition.target,
                    transition.session,
                    None,
                    activation_sequence(value.epoch),
                    payload.clone(),
                )
                .unwrap()
            })
            .collect();
        ActivateEpochRequest { transition: transition.clone(), value, acknowledgements }
    }

    #[tokio::test]
    async fn certified_undrained_avss_run_restores_without_pacemaker_work_and_drains() {
        let scenario = proactive_refresh_spare_eligible_scenario();
        let local = PartyId(1);
        let silent = PartyId(4);
        let state = tempfile::tempdir().unwrap();
        let signing_seed = historical_replay_seed(local);
        let bootstrap_x25519_secret = historical_replay_x25519_secret(local, 0);
        let server = boxed_party_server_new(
            local,
            scenario.clone(),
            state.path(),
            &signing_seed,
            &bootstrap_x25519_secret,
        )
        .await
        .unwrap();
        let share = proactive_epoch_zero_share(&scenario, local);
        let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
        let transition = AvssTransition {
            purpose: DealPurpose::Dkg,
            session,
            key_id,
            fault_bound: scenario.committee_spec(0).unwrap().fault_bound,
            history_parent: EpochHistoryParent::genesis(
                scenario.quic_network_id().unwrap(),
                key_id,
            )
            .unwrap(),
            old: None,
            target: scenario.genesis_committee().unwrap(),
            eligible_dealers: Vec::new(),
        };
        let certificate = historical_activation_request(&transition, share.public(), 0xC7, None);
        server
            .persist_activation_certificate(
                &transition,
                &certificate.value,
                &certificate.acknowledgements,
            )
            .await
            .unwrap();
        server.store.save(&share, &mut OsRng).await.unwrap();
        // A certified active epoch with a configured successor persists its proactive-refresh
        // clock as part of activation; restore fails closed without it. Arm the ordinary fixed
        // interval far enough ahead of the restored `now = 1` tick that no key-rotation pacemaker
        // work is triggered, isolating this test to the certified AVSS run's undrained drain path.
        server.arm_proactive_refresh_for_activation(&share.public(), 0).await.unwrap();

        let mut run = new_avss_run(&server, transition.clone()).unwrap();
        run.finalized = Some(InstallResponse {
            party: local,
            epoch: certificate.value.epoch,
            public: certificate.value.public.clone(),
            activation_digest: certificate.value.activation_digest,
            avss_transcript_digest: certificate.value.avss_transcript_digest,
            history_link: certificate.value.history_link,
        });
        run.activation_acknowledgements = certificate
            .acknowledgements
            .iter()
            .cloned()
            .map(|acknowledgement| (acknowledgement.from, acknowledgement))
            .collect();
        let local_acknowledgement = certificate
            .acknowledgements
            .iter()
            .find(|acknowledgement| acknowledgement.from == local)
            .unwrap()
            .clone();
        let acknowledgement_digest =
            *blake3::hash(&postcard::to_allocvec(&local_acknowledgement).unwrap()).as_bytes();
        run.pending_activation_ack.insert((silent, acknowledgement_digest), local_acknowledgement);
        server.persist_avss_run(&run).await.unwrap();
        server.avss.lock().await.insert(session, run);
        drop(server);

        let restarted = boxed_party_server_new(
            local,
            scenario.clone(),
            state.path(),
            &signing_seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        assert_eq!(*restarted.active_epoch.read().await, Some(0));
        let before = restarted.protocol_session_status(session).await.unwrap();
        assert!(before.finalized);
        assert_eq!(before.pending_activation_ack, 1);
        let pending_before = restarted
            .pending_peer_messages(usize::MAX)
            .await
            .into_iter()
            .map(|message| message.id())
            .collect::<Vec<_>>();
        assert_eq!(pending_before.len(), 1);

        drive_protocols(&restarted, 1, std::time::Duration::from_millis(10)).await.unwrap();
        assert_eq!(
            restarted.protocol_session_status(session).await.unwrap().pending_activation_ack,
            1,
            "a certified catch-up run must not be driven through activation on every tick"
        );
        assert_eq!(
            restarted
                .pending_peer_messages(usize::MAX)
                .await
                .into_iter()
                .map(|message| message.id())
                .collect::<Vec<_>>(),
            pending_before,
            "certification must retain the exact silent-recipient outbox across restart"
        );

        restarted.acknowledge_peer_messages(&pending_before).await.unwrap();
        assert!(restarted.protocol_session_status(session).await.is_none());
        assert!(
            tokio::fs::try_exists(restarted.protocol_store.session_tombstone_path(session))
                .await
                .unwrap()
        );
        drop(restarted);

        let restarted_again = boxed_party_server_new(
            local,
            scenario,
            state.path(),
            &signing_seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        assert!(restarted_again.protocol_session_status(session).await.is_none());
        assert!(restarted_again.pending_peer_messages(usize::MAX).await.is_empty());
    }

    fn historical_target_identities(context: &KeyRotationContext) -> Vec<Identity> {
        context
            .target_policy()
            .eligible()
            .members
            .iter()
            .map(|member| {
                Identity::from_test_secrets(
                    member.id,
                    context.target_epoch(),
                    &historical_replay_seed(member.id),
                    historical_replay_x25519_secret(member.id, context.target_epoch()),
                )
                .unwrap()
            })
            .collect()
    }

    fn historical_advertisement_capability(
        identity: &Identity,
    ) -> crate::identity::PersistedKeyAdvertisementIdentity {
        let secret = identity.export_encryption_secret();
        let durable_identity = Identity::from_test_secrets(
            identity.party(),
            identity.encryption_epoch(),
            &historical_replay_seed(identity.party()),
            *secret.secret_bytes(),
        )
        .unwrap();
        let mut durable_material = Vec::with_capacity(42);
        durable_material.extend_from_slice(&identity.party().0.to_le_bytes());
        durable_material.extend_from_slice(&identity.encryption_epoch().to_le_bytes());
        durable_material.extend_from_slice(&identity.encryption_public_key());
        durable_identity
            .after_durable_encryption_readback(blake3::derive_key(
                "threshold-monero/server-test-durable-key-advertisement/v1",
                &durable_material,
            ))
            .unwrap()
    }

    fn key_rotation_view_certificate(
        context: &KeyRotationContext,
        from_view: u64,
        target_view: u64,
        witnesses: &[PartyId],
    ) -> ViewChangeCertificate {
        let consensus = context.consensus_context().unwrap();
        let witnesses = witnesses
            .iter()
            .map(|party| {
                let identity = Identity::from_test_secrets(
                    *party,
                    context.source().epoch,
                    &historical_replay_seed(*party),
                    historical_replay_x25519_secret(*party, context.source().epoch),
                )
                .unwrap();
                sign_consensus_message(
                    &consensus,
                    &identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view,
                        target_view,
                        highest_prepared: None,
                    }),
                )
                .unwrap()
            })
            .collect();
        ViewChangeCertificate::from_witnesses(&consensus, target_view, witnesses).unwrap()
    }

    fn certified_key_rotation_for_roles(
        context: &KeyRotationContext,
        target_identities: &[Identity],
        advertisers: &[PartyId],
        witnesses: &[PartyId],
    ) -> KeyRotationCertificate {
        let advertisements = advertisers
            .iter()
            .map(|party| {
                let identity =
                    target_identities.iter().find(|identity| identity.party() == *party).unwrap();
                let capability = historical_advertisement_capability(identity);
                crate::key_rotation::sign_key_advertisement(context, &capability).unwrap()
            })
            .collect();
        let value = crate::key_rotation::KeyRotationValue::new(context, advertisements).unwrap();
        let value = value.to_consensus_value(context).unwrap();
        let consensus = context.consensus_context().unwrap();
        let witnesses = witnesses
            .iter()
            .map(|party| {
                let identity = Identity::from_test_secrets(
                    *party,
                    context.source().epoch,
                    &historical_replay_seed(*party),
                    historical_replay_x25519_secret(*party, context.source().epoch),
                )
                .unwrap();
                crate::deposit_consensus::sign_consensus_message(
                    &consensus,
                    &identity,
                    crate::deposit_consensus::ConsensusMessageBody::Precommit(
                        crate::deposit_consensus::Vote { view: 0, value: value.digest() },
                    ),
                )
                .unwrap()
            })
            .collect();
        let commit = crate::deposit_consensus::CommitCertificate::from_witnesses(
            &consensus, 0, value, witnesses,
        )
        .unwrap();
        KeyRotationCertificate::from_commit(context, commit).unwrap()
    }

    async fn install_historical_key_rotation(
        server: &Arc<PartyServer>,
        source: &EpochPublic,
        advertisers: &[PartyId],
        witnesses: &[PartyId],
    ) -> (KeyRotationContext, KeyRotationCertificate, Committee) {
        let context = server.key_rotation_context_for_source(source).unwrap().unwrap();
        let identities = historical_target_identities(&context);
        let certificate =
            certified_key_rotation_for_roles(&context, &identities, advertisers, witnesses);
        let target = certificate.verify(&context).unwrap();
        if let Some(identity) = identities.iter().find(|identity| {
            identity.party() == server.party
                && target
                    .member(server.party)
                    .is_ok_and(|member| member.encryption_key == identity.encryption_public_key())
        }) {
            server
                .protocol_store
                .save_epoch_identity_secret(&identity.export_encryption_secret(), &mut OsRng)
                .await
                .unwrap();
        }
        server
            .finalize_certified_key_rotation(context.clone(), certificate.clone(), false)
            .await
            .unwrap();
        (context, certificate, target)
    }

    #[tokio::test]
    async fn proactive_refresh_starts_at_the_exact_persisted_deadline_and_is_idempotent() {
        let scenario = proactive_refresh_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let share = proactive_epoch_zero_share(&scenario, local);
        install_proactive_epoch_zero(&server, &share).await;
        let source = share.public();
        install_historical_key_rotation(
            &server,
            &source,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
            &[PartyId(1), PartyId(2), PartyId(3)],
        )
        .await;
        let transition = server
            .configured_proactive_refresh_transition(&source)
            .unwrap()
            .expect("same-committee successor must arm the pacemaker");
        assert_eq!(transition.purpose, DealPurpose::Refresh);
        assert_eq!(
            transition.eligible_dealers,
            source.committee.members.iter().map(|member| member.id).collect::<Vec<_>>()
        );
        assert!(matches!(qual_config(&transition).unwrap().mode(), crate::qual::QualMode::Refresh));

        const ARMED_AT: u64 = 40_000;
        const DUE: u64 = ARMED_AT + 1_000;
        server.arm_proactive_refresh_for_activation(&source, ARMED_AT).await.unwrap();
        server.arm_proactive_refresh_for_activation(&source, ARMED_AT + 500_000).await.unwrap();
        assert_eq!(
            server.proactive_refresh_schedule.lock().await.clone(),
            Some(ProactiveRefreshSchedule {
                version: PROACTIVE_REFRESH_SCHEDULE_VERSION,
                source_epoch: 0,
                source_activation: source.activation_digest().unwrap(),
                target_epoch: Some(1),
                due_unix_ms: Some(DUE),
                rotation_view: None,
                rotation_view_started_unix_ms: None,
                rotation_timeout_exponent: 0,
                rotation_certificate_delivered_through: BTreeMap::new(),
            })
        );

        server.progress_protocols(DUE - 1, std::time::Duration::from_millis(10)).await.unwrap();
        assert!(!server.avss.lock().await.contains_key(&transition.session));
        assert!(
            server
                .ensure_refresh_due_for_live_ingress(&transition, DUE - 1)
                .await
                .unwrap_err()
                .to_string()
                .contains("not due yet")
        );

        server.progress_protocols(DUE, std::time::Duration::from_millis(10)).await.unwrap();
        let first = server
            .avss
            .lock()
            .await
            .get(&transition.session)
            .and_then(|run| run.dealer_outbound.clone())
            .expect("the due tick must durably create exactly one dealer polynomial");
        let local_wire =
            first.iter().find(|wire| wire.recipient == local).expect("local DealerSend");
        let local_message = open_avss_wire(&server, &transition, local_wire).unwrap();
        assert!(
            local_message.commitment.x_axis_commitment().unwrap().has_zero_constant().unwrap(),
            "fixed-interval refresh must deal a verifiable zero-constant contribution"
        );

        let mut redistribution = transition.clone();
        redistribution.purpose = DealPurpose::Reshare;
        redistribution.session =
            canonical_reshare_session(&source, &redistribution.target, transition.history_parent)
                .unwrap();
        assert!(
            validate_avss_transition(&server, &redistribution)
                .unwrap_err()
                .to_string()
                .contains("must use zero-refresh"),
            "same-layout old-share redistribution must not overlap scheduled refresh"
        );
        let mut wrong_session = transition.clone();
        wrong_session.session = redistribution.session;
        assert!(
            validate_avss_transition(&server, &wrong_session)
                .unwrap_err()
                .to_string()
                .contains("session differs")
        );

        server
            .progress_protocols(DUE + 50_000, std::time::Duration::from_millis(10))
            .await
            .unwrap();
        let repeated = server
            .avss
            .lock()
            .await
            .get(&transition.session)
            .and_then(|run| run.dealer_outbound.clone())
            .unwrap();
        assert_eq!(first, repeated, "later ticks must reuse the exact encrypted dealer outbox");
        assert_eq!(
            server
                .avss
                .lock()
                .await
                .values()
                .filter(|run| {
                    run.transition.old.as_ref().is_some_and(|old| {
                        old.committee.epoch == source.committee.epoch
                            && run.transition.target.epoch == transition.target.epoch
                    })
                })
                .count(),
            1,
            "one source/target epoch pair may have only one live refresh reducer"
        );
    }

    #[tokio::test]
    async fn acceptance_refresh_hold_is_durable_exact_and_rearms_the_fixed_interval_once() {
        let scenario = proactive_refresh_spare_eligible_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        let server =
            new_refresh_hold_test_server(local, scenario.clone(), state.path().to_path_buf(), true)
                .await
                .unwrap();
        let share = proactive_epoch_zero_share(&scenario, local);
        install_proactive_epoch_zero(&server, &share).await;
        let source = share.public();
        server.arm_proactive_refresh_for_activation(&source, 40_000).await.unwrap();
        assert_eq!(
            server
                .proactive_refresh_schedule
                .lock()
                .await
                .as_ref()
                .and_then(|schedule| schedule.due_unix_ms),
            Some(ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS)
        );
        server
            .progress_protocols(
                ACCEPTANCE_PROACTIVE_REFRESH_HELD_DUE_UNIX_MS,
                std::time::Duration::from_millis(10),
            )
            .await
            .unwrap();
        assert!(server.key_rotation.lock().await.is_none());
        drop(server);

        let error = new_refresh_hold_test_server(
            local,
            scenario.clone(),
            state.path().to_path_buf(),
            false,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("persisted acceptance-held proactive refresh schedule requires"),
            "{error}"
        );

        let restarted =
            new_refresh_hold_test_server(local, scenario.clone(), state.path().to_path_buf(), true)
                .await
                .unwrap();
        let stale = restarted
            .release_acceptance_proactive_refresh_hold(1, 50_000)
            .await
            .unwrap_err()
            .to_string();
        assert!(stale.contains("stale source epoch 1"), "{stale}");

        const RELEASED_AT: u64 = 50_000;
        const EXPECTED_DUE: u64 = RELEASED_AT + 1_000;
        let released =
            restarted.release_acceptance_proactive_refresh_hold(0, RELEASED_AT).await.unwrap();
        assert_eq!(
            released,
            AcceptanceProactiveRefreshReleaseResponse {
                party: local,
                source_epoch: 0,
                target_epoch: 1,
                due_unix_ms: EXPECTED_DUE,
            }
        );
        let repeated = restarted
            .release_acceptance_proactive_refresh_hold(0, RELEASED_AT + 500_000)
            .await
            .unwrap();
        assert_eq!(repeated, released, "an authenticated retry must not move the deadline");
        drop(restarted);

        let restarted_after_release =
            new_refresh_hold_test_server(local, scenario, state.path().to_path_buf(), true)
                .await
                .unwrap();
        assert_eq!(
            restarted_after_release
                .proactive_refresh_schedule
                .lock()
                .await
                .as_ref()
                .and_then(|schedule| schedule.due_unix_ms),
            Some(EXPECTED_DUE),
            "the released fixed deadline must remain exact across restart"
        );
    }

    #[tokio::test]
    async fn threshold_one_scheduled_refresh_is_rejected_as_a_noop() {
        let local = PartyId(1);
        let seed = historical_replay_seed(local);
        let source_identity =
            Identity::from_test_secrets(local, 0, &seed, historical_replay_x25519_secret(local, 0))
                .unwrap();
        let mut scenario = signing_scenario(NetworkKind::Regtest, true, &source_identity);
        scenario.committees.push(CommitteeSpec {
            epoch: 1,
            operation: Operation::Reshare,
            threshold: 1,
            fault_bound: 0,
            members: vec![local],
            eligible_members: vec![local],
            old_dealers: vec![local],
        });
        scenario.proactive_refresh_interval_seconds = 1;
        scenario.validate().unwrap();
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let epoch_zero = proactive_epoch_zero_share(&scenario, local);
        let epoch_zero_public = epoch_zero.public();
        install_proactive_epoch_zero(&server, &epoch_zero).await;
        install_historical_key_rotation(&server, &epoch_zero_public, &[local], &[local]).await;
        assert!(
            server
                .configured_proactive_refresh_transition(&epoch_zero_public)
                .unwrap_err()
                .to_string()
                .contains("threshold at least two"),
            "a 1-of-1 zero polynomial cannot provide proactive share isolation"
        );
    }

    #[tokio::test]
    async fn dynamic_rotation_ingress_is_retryable_before_the_persisted_due_time() {
        let scenario = dynamic_refresh_scenario();
        let local = PartyId(1);
        let peer = PartyId(2);
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let share = proactive_epoch_zero_share(&scenario, local);
        install_proactive_epoch_zero(&server, &share).await;
        let source = share.public();
        const ARMED_AT: u64 = 10_000;
        const DUE: u64 = ARMED_AT + 1_000;
        server.arm_proactive_refresh_for_activation(&source, ARMED_AT).await.unwrap();

        let context = server.key_rotation_context_for_source(&source).unwrap().unwrap();
        let peer_target = Identity::from_test_secrets(
            peer,
            context.target_epoch(),
            &historical_replay_seed(peer),
            historical_replay_x25519_secret(peer, context.target_epoch()),
        )
        .unwrap();
        let peer_capability = historical_advertisement_capability(&peer_target);
        let wire = crate::key_rotation::sign_key_advertisement(&context, &peer_capability).unwrap();
        let request = PeerRequest::key_rotation(&KeyRotationWire::Advertisement(wire)).unwrap();
        let response = server
            .handle_key_rotation_wire(
                peer,
                match request {
                    PeerRequest::KeyRotation { operation, body } => {
                        operation.decode_wire(&body).unwrap()
                    }
                    _ => unreachable!(),
                },
                DUE - 1,
            )
            .await
            .unwrap_err();
        assert!(response.to_string().contains("not due yet"));
        assert!(server.key_rotation.lock().await.is_none());

        drive_protocols(&server, DUE, std::time::Duration::from_millis(50)).await.unwrap();
        let live = server.key_rotation.lock().await;
        let live = live.as_ref().expect("due tick must start key rotation");
        assert_eq!(live.round.context(), &context);
        assert_eq!(live.revision, 0);
    }

    #[tokio::test]
    async fn dynamic_rotation_round_and_view_anchor_restore_exactly() {
        let scenario = dynamic_refresh_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        const ARMED_AT: u64 = 20_000;
        const DUE: u64 = ARMED_AT + 1_000;
        let context;
        let before;
        {
            let server = PartyServer::new(
                local,
                scenario.clone(),
                state.path(),
                &historical_replay_seed(local),
                &historical_replay_x25519_secret(local, 0),
            )
            .await
            .unwrap();
            let share = proactive_epoch_zero_share(&scenario, local);
            install_proactive_epoch_zero(&server, &share).await;
            let source = share.public();
            context = server.key_rotation_context_for_source(&source).unwrap().unwrap();
            server.arm_proactive_refresh_for_activation(&source, ARMED_AT).await.unwrap();
            drive_protocols(&server, DUE, std::time::Duration::from_millis(50)).await.unwrap();
            before = server.key_rotation.lock().await.as_ref().unwrap().round.encode().unwrap();
            let schedule = server.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(0));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(DUE));
        }

        let restarted = PartyServer::new(
            local,
            scenario,
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        {
            let live = restarted.key_rotation.lock().await;
            let live = live.as_ref().expect("durable key-rotation round must restore");
            assert_eq!(live.round.context(), &context);
            assert_eq!(live.round.encode().unwrap(), before);
            assert_eq!(live.revision, 0);
        }
        let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
        assert_eq!(schedule.rotation_view, Some(0));
        assert_eq!(schedule.rotation_view_started_unix_ms, Some(DUE));
    }

    /// Drive one autonomous protocol tick without inflating the caller's stack frame.
    ///
    /// `PartyServer::progress_protocols` lowers to a ~265 KiB future. A test that drives several
    /// servers across many ticks would otherwise materialize one such 265 KiB temporary per call
    /// site directly inside its own async poll frame — debug builds do not overlap those slots, so
    /// the frame grows past the default 2 MiB test-thread stack and the first server construction
    /// overflows the guard page. Building the large future inside this dedicated, non-async frame
    /// and handing it back already `Box::pin`ned keeps only an 8-byte pointer in the caller: the
    /// heavy temporary lives here and is reclaimed the moment the boxed future is returned.
    fn drive_protocols<'a>(
        server: &'a Arc<PartyServer>,
        now_unix_ms: u64,
        qual_round_timeout: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + 'a>> {
        Box::pin(server.progress_protocols(now_unix_ms, qual_round_timeout))
    }

    /// Construct a `PartyServer` inside this helper's own frame so the multi-megabyte
    /// construction future lives on the heap rather than being materialized in the
    /// caller's poll frame. Restart-heavy tests await `PartyServer::new` several times;
    /// because debug async lowering does not overlap per-await temporaries, awaiting the
    /// bare future at the call site statically reserves one copy per await and overflows
    /// the default 2 MiB test-thread stack. See `drive_protocols` for the same pattern.
    fn boxed_party_server_new<'a>(
        party: PartyId,
        scenario: Scenario,
        state_directory: &'a std::path::Path,
        signing_seed: &'a [u8; 32],
        bootstrap_x25519_secret: &'a [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Arc<PartyServer>>> + 'a>>
    {
        Box::pin(PartyServer::new(
            party,
            scenario,
            state_directory.to_path_buf(),
            signing_seed,
            bootstrap_x25519_secret,
        ))
    }

    #[tokio::test]
    async fn dynamic_rotation_backoff_survives_views_and_restart_until_delta_is_synchronous() {
        let scenario = dynamic_refresh_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        const ARMED_AT: u64 = 30_000;
        const DUE: u64 = ARMED_AT + 1_000;
        const BASE_TIMEOUT_MS: u64 = 1_000;
        const STABLE_DELTA_MS: u64 = 3_000;

        let server = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let share = proactive_epoch_zero_share(&scenario, local);
        install_proactive_epoch_zero(&server, &share).await;
        let source = share.public();
        let context = server.key_rotation_context_for_source(&source).unwrap().unwrap();
        let target_identities = historical_target_identities(&context);
        server.arm_proactive_refresh_for_activation(&source, ARMED_AT).await.unwrap();
        drive_protocols(&server, DUE, std::time::Duration::from_millis(BASE_TIMEOUT_MS))
            .await
            .unwrap();

        // The local durable advertisement plus three authenticated remote advertisements fills the
        // four-member selected committee and starts BA without relying on transport timing in this
        // deterministic-clock test.
        for peer in [PartyId(2), PartyId(3), PartyId(4)] {
            let target =
                target_identities.iter().find(|identity| identity.party() == peer).unwrap();
            let advertisement = crate::key_rotation::sign_key_advertisement(
                &context,
                &historical_advertisement_capability(target),
            )
            .unwrap();
            server
                .handle_key_rotation_wire(peer, KeyRotationWire::Advertisement(advertisement), DUE)
                .await
                .unwrap();
        }

        let first_timeout = DUE + BASE_TIMEOUT_MS;
        drive_protocols(&server, first_timeout, std::time::Duration::from_millis(BASE_TIMEOUT_MS))
            .await
            .unwrap();
        {
            let schedule = server.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(0));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(first_timeout));
            assert_eq!(schedule.rotation_timeout_exponent, 1);
        }

        // With Δ larger than the base timeout, the first portable view certificate arrives only
        // after the local view-change request. Entering the new view must carry exponent one.
        let view_one_started = first_timeout + STABLE_DELTA_MS;
        server
            .handle_key_rotation_wire(
                PartyId(2),
                KeyRotationWire::ViewCertificate(key_rotation_view_certificate(
                    &context,
                    0,
                    1,
                    &[PartyId(1), PartyId(2), PartyId(3)],
                )),
                view_one_started,
            )
            .await
            .unwrap();
        {
            let schedule = server.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(1));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(view_one_started));
            assert_eq!(
                schedule.rotation_timeout_exponent, 1,
                "entering a BA view must not restart exponential backoff"
            );
        }
        drop(server);

        let restarted = PartyServer::new(
            local,
            scenario,
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        {
            let live = restarted.key_rotation.lock().await;
            assert_eq!(live.as_ref().unwrap().round.view(), 1);
        }
        {
            let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(1));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(view_one_started));
            assert_eq!(
                schedule.rotation_timeout_exponent, 1,
                "restart must retain the exact durable exponent and deadline"
            );
        }

        // Recreate the exact cross-file crash window where the round snapshot entered view one
        // before its schedule anchor was replaced. Recovery may move the anchor forward, but must
        // carry the already accumulated exponent instead of silently returning to the base delay.
        let mut interrupted_anchor =
            restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
        interrupted_anchor.rotation_view = Some(0);
        interrupted_anchor.rotation_view_started_unix_ms = Some(first_timeout);
        restarted.persist_proactive_refresh_schedule(interrupted_anchor).await.unwrap();
        drop(restarted);
        let restarted = PartyServer::new(
            local,
            dynamic_refresh_scenario(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        drive_protocols(
            &restarted,
            view_one_started,
            std::time::Duration::from_millis(BASE_TIMEOUT_MS),
        )
        .await
        .unwrap();
        {
            let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(1));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(view_one_started));
            assert_eq!(
                schedule.rotation_timeout_exponent, 1,
                "crash-window re-anchoring must preserve the monotonic exponent"
            );
        }

        let view_one_deadline = view_one_started + qual_backoff_timeout_ms(BASE_TIMEOUT_MS, 1);
        drive_protocols(
            &restarted,
            view_one_deadline - 1,
            std::time::Duration::from_millis(BASE_TIMEOUT_MS),
        )
        .await
        .unwrap();
        assert_eq!(
            restarted
                .proactive_refresh_schedule
                .lock()
                .await
                .as_ref()
                .unwrap()
                .rotation_timeout_exponent,
            1,
            "the restored deadline must not fire one millisecond early"
        );
        drive_protocols(
            &restarted,
            view_one_deadline,
            std::time::Duration::from_millis(BASE_TIMEOUT_MS),
        )
        .await
        .unwrap();
        {
            let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(1));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(view_one_deadline));
            assert_eq!(schedule.rotation_timeout_exponent, 2);
        }

        let view_two_started = view_one_deadline + STABLE_DELTA_MS;
        restarted
            .handle_key_rotation_wire(
                PartyId(2),
                KeyRotationWire::ViewCertificate(key_rotation_view_certificate(
                    &context,
                    1,
                    2,
                    &[PartyId(1), PartyId(2), PartyId(3)],
                )),
                view_two_started,
            )
            .await
            .unwrap();
        {
            let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(2));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(view_two_started));
            assert_eq!(
                schedule.rotation_timeout_exponent, 2,
                "a second BA view entry must preserve the accumulated backoff"
            );
        }

        // At exponent two the four-second timeout exceeds Δ. A portable commit arriving after
        // exactly Δ is therefore accepted before another view-change request can be emitted.
        assert!(
            qual_backoff_timeout_ms(BASE_TIMEOUT_MS, 2) > STABLE_DELTA_MS,
            "the fixture must reach an eventually synchronous timeout"
        );
        let commit_arrival = view_two_started + STABLE_DELTA_MS;
        drive_protocols(
            &restarted,
            commit_arrival,
            std::time::Duration::from_millis(BASE_TIMEOUT_MS),
        )
        .await
        .unwrap();
        {
            let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
            assert_eq!(schedule.rotation_view, Some(2));
            assert_eq!(schedule.rotation_view_started_unix_ms, Some(view_two_started));
            assert_eq!(
                schedule.rotation_timeout_exponent, 2,
                "the enlarged timeout must leave a full Δ-sized commit window"
            );
        }
        let certificate = certified_key_rotation_for_roles(
            &context,
            &target_identities,
            &[PartyId(2), PartyId(3), PartyId(4), PartyId(5)],
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        restarted
            .handle_key_rotation_wire(
                PartyId(2),
                KeyRotationWire::Certificate(certificate.clone()),
                commit_arrival,
            )
            .await
            .unwrap();
        let rotations = restarted.certified_key_rotations.read().unwrap();
        let committed =
            rotations.get(&context.target_epoch()).expect("eventual synchrony must permit commit");
        assert_eq!(committed.context, context);
        assert_eq!(committed.certificate, certificate);
    }

    #[tokio::test]
    async fn omitted_identity_aliases_are_erased_on_a_later_fresh_rotation_and_stay_retired() {
        let scenario = dynamic_refresh_scenario();
        let local = PartyId(4);
        let state = tempfile::tempdir().unwrap();
        let seed = historical_replay_seed(local);
        let server = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let share = proactive_epoch_zero_share(&scenario, local);
        install_proactive_epoch_zero(&server, &share).await;
        let source = share.public();
        // Persist the genesis DKG session state so the epoch-one activation below can durably
        // supersede it; without the live predecessor session the history CAS has nothing to close.
        let (genesis_key_id, genesis_session) = canonical_dkg_identity(&scenario).unwrap();
        let genesis_run = new_avss_run(
            &server,
            AvssTransition {
                purpose: DealPurpose::Dkg,
                session: genesis_session,
                key_id: genesis_key_id,
                fault_bound: scenario.committee_spec(0).unwrap().fault_bound,
                history_parent: EpochHistoryParent::genesis(
                    scenario.quic_network_id().unwrap(),
                    genesis_key_id,
                )
                .unwrap(),
                old: None,
                target: scenario.genesis_committee().unwrap(),
                eligible_dealers: Vec::new(),
            },
        )
        .unwrap();
        server.persist_avss_run(&genesis_run).await.unwrap();
        server.arm_proactive_refresh_for_activation(&source, 10_000).await.unwrap();
        let source_identity = server.identity(0).unwrap();
        let source_encryption_key = source_identity.encryption_public_key();
        server
            .protocol_store
            .save_epoch_identity_secret(&source_identity.export_encryption_secret(), &mut OsRng)
            .await
            .unwrap();
        drop(source_identity);

        let context_one = server.key_rotation_context_for_source(&source).unwrap().unwrap();
        // Every selected member, including the local party, rotates to an independently fresh
        // epoch-one receiver key; a successor may never carry a source key forward.
        let epoch_one_identities = (1_u16..=4)
            .map(|party| {
                let party = PartyId(party);
                Identity::from_test_secrets(
                    party,
                    1,
                    &historical_replay_seed(party),
                    historical_replay_x25519_secret(party, 1),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate_one = certified_key_rotation_for_roles(
            &context_one,
            &epoch_one_identities,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        server
            .protocol_store
            .save_epoch_identity_secret(
                &epoch_one_identities[3].export_encryption_secret(),
                &mut OsRng,
            )
            .await
            .unwrap();
        server
            .finalize_certified_key_rotation(context_one.clone(), certificate_one.clone(), false)
            .await
            .unwrap();
        let first_for_one = server
            .pending_key_rotation_peer_messages(usize::MAX)
            .await
            .into_iter()
            .find(|message| message.id.recipient == PartyId(1))
            .expect("the first immutable certificate must remain retryable");
        assert_eq!(first_for_one.id.context, context_one.digest());
        server.acknowledge_key_rotation_peer_messages(&[first_for_one.id]).await.unwrap();
        assert!(
            server
                .pending_key_rotation_peer_messages(usize::MAX)
                .await
                .into_iter()
                .all(|message| message.id.recipient != PartyId(1)),
            "a durable certificate ACK must suppress its exact replay"
        );
        let target_one = certificate_one.verify(&context_one).unwrap();
        // The local party stays in the successor with an independently fresh epoch-one receiver
        // key; its retired epoch-zero label is the alias erased by the later key-changing link.
        let epoch_one_local_key = epoch_one_identities[3].encryption_public_key();
        assert_ne!(epoch_one_local_key, source_encryption_key);
        assert_eq!(target_one.member(local).unwrap().encryption_key, epoch_one_local_key);
        assert_eq!(server.identity(1).unwrap().encryption_public_key(), epoch_one_local_key);

        let mut public_one = source.clone();
        public_one.committee = target_one.clone();
        public_one.validate().unwrap();
        let rearmed = server.proactive_refresh_schedule_for(&public_one, 20_000).unwrap();
        assert_eq!(rearmed.source_epoch, 1);
        assert_eq!(rearmed.target_epoch, Some(2));
        assert_eq!(rearmed.due_unix_ms, Some(21_000));
        let transition_one = dynamic_avss_transition(
            &source,
            target_one,
            1,
            server.certified_history_parent(&source).unwrap(),
        )
        .unwrap();
        let activation_one = historical_activation_request(
            &transition_one,
            public_one.clone(),
            0xE1,
            Some(certificate_one.semantic_digest(&context_one).unwrap()),
        );
        server
            .persist_activation_certificate(
                &transition_one,
                &activation_one.value,
                &activation_one.acknowledgements,
            )
            .await
            .unwrap();
        server.retire_key_rotation_source_identity_after_handoff(&public_one).await.unwrap();
        assert!(server.identity(0).is_err());
        assert_eq!(server.identity(1).unwrap().encryption_public_key(), epoch_one_local_key);
        let carried_retirement = server
            .protocol_store
            .load_epoch_identity_retirement(0, source_encryption_key)
            .await
            .unwrap()
            .expect("the epoch-zero source label must be permanently retired after handoff");
        assert_eq!(carried_retirement.successor_epoch, 1);
        server
            .protocol_store
            .verify_epoch_identity_retirement(carried_retirement, &context_one, &certificate_one)
            .unwrap();

        let context_two = server.key_rotation_context_for_source(&public_one).unwrap().unwrap();
        let epoch_two_identities = (1_u16..=4)
            .map(|party| {
                let party = PartyId(party);
                Identity::from_test_secrets(
                    party,
                    2,
                    &historical_replay_seed(party),
                    historical_replay_x25519_secret(party, 2),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate_two = certified_key_rotation_for_roles(
            &context_two,
            &epoch_two_identities,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        server
            .protocol_store
            .save_epoch_identity_secret(
                &epoch_two_identities[3].export_encryption_secret(),
                &mut OsRng,
            )
            .await
            .unwrap();
        server
            .finalize_certified_key_rotation(context_two.clone(), certificate_two.clone(), false)
            .await
            .unwrap();
        let catch_up = server.pending_key_rotation_peer_messages(usize::MAX).await;
        assert_eq!(
            catch_up.iter().find(|message| message.id.recipient == PartyId(1)).unwrap().id.context,
            context_two.digest(),
            "an ACKed peer advances to the next immutable certificate"
        );
        for blocked in [PartyId(2), PartyId(3)] {
            assert_eq!(
                catch_up.iter().find(|message| message.id.recipient == blocked).unwrap().id.context,
                context_one.digest(),
                "an unACKed predecessor must causally block newer rotation traffic"
            );
        }
        let target_two = certificate_two.verify(&context_two).unwrap();
        assert_ne!(target_two.member(local).unwrap().encryption_key, source_encryption_key);
        let mut public_two = public_one;
        public_two.committee = target_two;
        public_two.validate().unwrap();

        server.retire_key_rotation_source_identity_after_handoff(&public_two).await.unwrap();
        assert_eq!(
            server
                .protocol_store
                .load_epoch_identity_retirement(0, source_encryption_key)
                .await
                .unwrap(),
            Some(carried_retirement),
            "a later key change must preserve the earlier link-bound marker"
        );
        let final_retirement = server
            .protocol_store
            .load_epoch_identity_retirement(1, epoch_one_local_key)
            .await
            .unwrap()
            .expect("the last active alias must be retired by the key-changing link");
        assert_eq!(final_retirement.successor_epoch, 2);
        server
            .protocol_store
            .verify_epoch_identity_retirement(final_retirement, &context_two, &certificate_two)
            .unwrap();
        assert!(server.identity(0).is_err());
        assert!(server.identity(1).is_err());
        assert_eq!(
            server.identity(2).unwrap().encryption_public_key(),
            epoch_two_identities[3].encryption_public_key()
        );
        drop(server);

        let restarted = PartyServer::new(
            local,
            scenario,
            state.path(),
            &seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        assert!(restarted.identity(0).is_err());
        assert!(restarted.identity(1).is_err());
        assert_eq!(
            restarted.identity(2).unwrap().encryption_public_key(),
            epoch_two_identities[3].encryption_public_key()
        );
        let replay = restarted.pending_key_rotation_peer_messages(usize::MAX).await;
        assert_eq!(
            replay.iter().find(|message| message.id.recipient == PartyId(1)).unwrap().id.context,
            context_two.digest(),
            "the per-peer certificate cursor must survive restart"
        );
        assert_eq!(
            replay.iter().find(|message| message.id.recipient == PartyId(2)).unwrap().id.context,
            context_one.digest()
        );
    }

    #[tokio::test]
    async fn proactive_refresh_restart_preserves_deadline_and_overdue_start() {
        let scenario = proactive_refresh_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        let source;
        const ARMED_AT: u64 = 70_000;
        const DUE: u64 = ARMED_AT + 1_000;
        {
            let server = PartyServer::new(
                local,
                scenario.clone(),
                state.path(),
                &historical_replay_seed(local),
                &historical_replay_x25519_secret(local, 0),
            )
            .await
            .unwrap();
            let share = proactive_epoch_zero_share(&scenario, local);
            source = share.public();
            install_proactive_epoch_zero(&server, &share).await;
            install_historical_key_rotation(
                &server,
                &source,
                &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
                &[PartyId(1), PartyId(2), PartyId(3)],
            )
            .await;
            server.arm_proactive_refresh_for_activation(&source, ARMED_AT).await.unwrap();
        }

        let restarted = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let schedule = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
        assert_eq!(schedule.due_unix_ms, Some(DUE));
        let transition =
            restarted.configured_proactive_refresh_transition(&source).unwrap().unwrap();
        restarted.progress_protocols(DUE - 1, std::time::Duration::from_millis(10)).await.unwrap();
        assert!(!restarted.avss.lock().await.contains_key(&transition.session));
        restarted.progress_protocols(DUE + 1, std::time::Duration::from_millis(10)).await.unwrap();
        let before_restart = restarted
            .avss
            .lock()
            .await
            .get(&transition.session)
            .and_then(|run| run.dealer_outbound.clone())
            .unwrap();
        drop(restarted);

        let restarted_again = PartyServer::new(
            local,
            scenario,
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        restarted_again
            .progress_protocols(DUE + 100_000, std::time::Duration::from_millis(10))
            .await
            .unwrap();
        let after_restart = restarted_again
            .avss
            .lock()
            .await
            .get(&transition.session)
            .and_then(|run| run.dealer_outbound.clone())
            .unwrap();
        assert_eq!(before_restart, after_restart);
        let runs = restarted_again.avss.lock().await;
        assert_eq!(runs.len(), 1, "one overdue deadline created more than one refresh reducer");
        assert!(runs.contains_key(&transition.session));
        drop(runs);
        let still_armed = restarted_again.proactive_refresh_schedule.lock().await.clone().unwrap();
        assert_eq!(still_armed.source_epoch, source.committee.epoch);
        assert_eq!(still_armed.target_epoch, Some(transition.target.epoch));
        assert_eq!(
            still_armed.due_unix_ms,
            Some(DUE),
            "overdue retry moved the persisted deadline forward"
        );
    }

    #[tokio::test]
    async fn proactive_refresh_restart_preserves_an_authenticated_pre_certificate_successor_deadline()
     {
        let scenario = proactive_refresh_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        const SUCCESSOR_ARMED_AT: u64 = 90_000;
        const SUCCESSOR_DUE: u64 = SUCCESSOR_ARMED_AT + 1_000;
        {
            let server = boxed_party_server_new(
                local,
                scenario.clone(),
                state.path(),
                &historical_replay_seed(local),
                &historical_replay_x25519_secret(local, 0),
            )
            .await
            .unwrap();
            let old_share = proactive_epoch_zero_share(&scenario, local);
            install_proactive_epoch_zero(&server, &old_share).await;
            let (rotation_context, rotation_certificate, target) = install_historical_key_rotation(
                &server,
                &old_share.public(),
                &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
                &[PartyId(1), PartyId(2), PartyId(3)],
            )
            .await;
            server.arm_proactive_refresh_for_activation(&old_share.public(), 80_000).await.unwrap();
            let mut schedule = server.proactive_refresh_schedule.lock().await.clone().unwrap();
            schedule.rotation_certificate_delivered_through.insert(PartyId(2), 1);
            server.persist_proactive_refresh_schedule(schedule).await.unwrap();

            // Model the certificate-safe ordering: the successor's next schedule was persisted,
            // then the process crashed before publishing the successor activation certificate. The
            // restored staged share and finalized AVSS quorum authenticate this exact write window.
            let transition = server
                .configured_proactive_refresh_transition(&old_share.public())
                .unwrap()
                .unwrap();
            let selected = transition
                .eligible_dealers
                .iter()
                .copied()
                .take(usize::from(target.n() - transition.fault_bound))
                .collect::<Vec<_>>();
            let outputs = selected
                .iter()
                .map(|dealer| {
                    let polynomial =
                        SecretPolynomial::random_zero_constant(target.threshold, &mut OsRng)
                            .unwrap();
                    make_dkg_output(*dealer, &polynomial, &target, local).unwrap()
                })
                .collect();
            let successor_share = aggregate_zero_share_refresh(
                &old_share,
                target,
                local,
                transition.fault_bound,
                &selected,
                outputs,
            )
            .unwrap();
            let response =
                server.stage(transition.clone(), successor_share, [0xE2; 32]).await.unwrap();
            let activation = historical_activation_request(
                &transition,
                response.public.clone(),
                0xE2,
                Some(rotation_certificate.semantic_digest(&rotation_context).unwrap()),
            );
            assert_eq!(activation_value(&response), activation.value);
            let mut run = new_avss_run(&server, transition.clone()).unwrap();
            run.finalized = Some(response.clone());
            run.activation_acknowledgements = activation
                .acknowledgements
                .into_iter()
                .map(|acknowledgement| (acknowledgement.from, acknowledgement))
                .collect();
            server.persist_avss_run(&run).await.unwrap();
            server.avss.lock().await.insert(transition.session, run);

            server
                .arm_proactive_refresh_for_activation(&response.public, SUCCESSOR_ARMED_AT)
                .await
                .unwrap();
            assert_eq!(
                server.proactive_refresh_schedule.lock().await.clone().unwrap().due_unix_ms,
                Some(SUCCESSOR_DUE)
            );
        }

        let restarted = boxed_party_server_new(
            local,
            scenario.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        assert_eq!(*restarted.active_epoch.read().await, Some(0));
        let reconciled = restarted.proactive_refresh_schedule.lock().await.clone().unwrap();
        assert_eq!(reconciled.source_epoch, 1);
        assert_eq!(reconciled.target_epoch, Some(2));
        assert_eq!(
            reconciled.due_unix_ms,
            Some(SUCCESSOR_DUE),
            "pre-certificate restart moved the staged successor's exact deadline"
        );
        assert_eq!(
            reconciled.rotation_certificate_delivered_through.get(&PartyId(2)),
            Some(&1),
            "adjacent activation crash recovery must not roll back certificate ACK cursors"
        );

        drive_protocols(&restarted, SUCCESSOR_DUE, std::time::Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(*restarted.active_epoch.read().await, Some(1));
        assert_eq!(
            restarted.proactive_refresh_schedule.lock().await.as_ref().unwrap().due_unix_ms,
            Some(SUCCESSOR_DUE),
            "activation retry moved the already persisted successor deadline"
        );
    }

    #[tokio::test]
    async fn proactive_refresh_restart_rejects_an_unstaged_adjacent_successor_schedule() {
        let scenario = proactive_refresh_scenario();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        {
            let server = PartyServer::new(
                local,
                scenario.clone(),
                state.path(),
                &historical_replay_seed(local),
                &historical_replay_x25519_secret(local, 0),
            )
            .await
            .unwrap();
            let old_share = proactive_epoch_zero_share(&scenario, local);
            install_proactive_epoch_zero(&server, &old_share).await;
            let (_, _, target) = install_historical_key_rotation(
                &server,
                &old_share.public(),
                &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
                &[PartyId(1), PartyId(2), PartyId(3)],
            )
            .await;

            // An adjacent epoch number and a valid public shape are insufficient. Without the
            // restored finalized AVSS run and its staged local share, this is not the activation
            // write-order crash window and restart must reject it.
            let mut unstaged_successor = old_share.public();
            unstaged_successor.committee = target;
            unstaged_successor.validate().unwrap();
            server.arm_proactive_refresh_for_activation(&unstaged_successor, 90_000).await.unwrap();
        }

        let error = PartyServer::new(
            local,
            scenario,
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .err()
        .expect("an unstaged adjacent successor schedule restored");
        assert!(
            error.to_string().contains("lacks its restored staged share"),
            "unexpected fail-closed recovery error: {error}"
        );
    }

    #[tokio::test]
    async fn proactive_refresh_schedules_configured_reconfiguration_and_requires_fresh_refresh_keys()
     {
        let local = PartyId(1);
        let base = proactive_refresh_scenario();
        let source_share = proactive_epoch_zero_share(&base, local);
        let source = source_share.public();
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            local,
            base.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        install_proactive_epoch_zero(&server, &source_share).await;
        let (_, _, refreshed_target) = install_historical_key_rotation(
            &server,
            &source,
            &[PartyId(1), PartyId(2), PartyId(3), PartyId(4)],
            &[PartyId(1), PartyId(2), PartyId(3)],
        )
        .await;
        assert!(server.configured_proactive_refresh_transition(&source).unwrap().is_some());
        assert_eq!(
            refreshed_target
                .members
                .iter()
                .filter(|member| {
                    source
                        .committee
                        .member(member.id)
                        .is_ok_and(|old| old.encryption_key != member.encryption_key)
                })
                .count(),
            4,
            "every same-committee refresh advertisement must select an independently fresh key"
        );

        // The configured shrink pops the last member and drops the fault bound, giving epoch one an
        // explicit three-member target backed by the five-identity eligible pool. It is a distinct
        // committee configuration, so it derives its own genesis identity and source share.
        let mut membership_change = base.clone();
        membership_change.committees[1].members.pop();
        membership_change.committees[1].fault_bound = 0;
        membership_change.validate().unwrap();
        let configured_old_dealers = membership_change.committees[1].old_dealers.clone();
        let shrink_source_share = proactive_epoch_zero_share(&membership_change, local);
        let shrink_source = shrink_source_share.public();
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            local,
            membership_change,
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        install_proactive_epoch_zero(&server, &shrink_source_share).await;
        install_historical_key_rotation(
            &server,
            &shrink_source,
            &[PartyId(1), PartyId(2), PartyId(3)],
            &[PartyId(1), PartyId(2), PartyId(3)],
        )
        .await;
        let transition =
            server.configured_proactive_refresh_transition(&shrink_source).unwrap().unwrap();
        assert_eq!(transition.purpose, DealPurpose::Reshare);
        assert_eq!(transition.target.epoch, 1);
        assert_eq!(transition.target.members.len(), 3);
        assert_eq!(transition.eligible_dealers, configured_old_dealers);
        assert_eq!(
            transition.session,
            canonical_reshare_session(
                &shrink_source,
                &transition.target,
                transition.history_parent
            )
            .unwrap()
        );
        const ARMED_AT: u64 = 123_000;
        const DUE: u64 = ARMED_AT + 1_000;
        server.arm_proactive_refresh_for_activation(&shrink_source, ARMED_AT).await.unwrap();
        let schedule = server.proactive_refresh_schedule.lock().await.clone().unwrap();
        assert_eq!(schedule.target_epoch, Some(1));
        assert_eq!(schedule.due_unix_ms, Some(DUE));
        // Configured governance may explicitly begin the exact transition before the fallback
        // deadline; the pacemaker still starts it if nobody does.
        server.ensure_refresh_due_for_live_ingress(&transition, DUE - 1).await.unwrap();
        server.progress_protocols(DUE, std::time::Duration::from_millis(10)).await.unwrap();
        assert!(
            server
                .avss
                .lock()
                .await
                .get(&transition.session)
                .is_some_and(|run| run.dealer_outbound.is_some()),
            "the deadline must start the exact configured shrink transition"
        );
    }

    fn historical_qual_request(
        transition: &AvssTransition,
        sender: PartyId,
        context: [u8; 32],
    ) -> PeerRequest {
        let message = QualMessage {
            context,
            body: QualMessageBody::Vote(crate::qual::QualVote {
                round: 0,
                phase: VotePhase::Prevote,
                value: None,
            }),
        };
        let identity = Identity::from_test_secrets(
            sender,
            transition.target.epoch,
            &historical_replay_seed(sender),
            historical_replay_x25519_secret(sender, transition.target.epoch),
        )
        .unwrap();
        let envelope = identity
            .sign_envelope(
                &transition.target,
                transition.session,
                None,
                qual_sequence(&message).unwrap(),
                postcard::to_allocvec(&message).unwrap(),
            )
            .unwrap();
        PeerRequest::Qual {
            operation: QualOperation::Deliver,
            body: postcard::to_allocvec(&QualDeliverRequest {
                transition: transition.clone(),
                wire: QualWire {
                    version: QUAL_WIRE_VERSION,
                    envelope,
                    proof_of_lock_witnesses: Vec::new(),
                },
            })
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn activation_certificate_keeps_first_valid_witness_representation() {
        let scenario = activation_witness_scenario();
        scenario.validate().unwrap();
        let local = PartyId(1);
        let state = tempfile::tempdir().unwrap();
        let server = PartyServer::new(
            local,
            scenario.clone(),
            state.path(),
            &historical_replay_seed(local),
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        let committee = scenario.genesis_committee().unwrap();
        let (key_id, session) = canonical_dkg_identity(&scenario).unwrap();
        let polynomial = SecretPolynomial::random(committee.threshold, &mut OsRng).unwrap();
        let verification_shares = committee
            .members
            .iter()
            .map(|member| {
                let index = committee.frost_index(member.id).unwrap();
                let share = polynomial.evaluate(Scalar::from(u64::from(index)));
                (member.id, PointBytes((ED25519_BASEPOINT_POINT * share).compress().to_bytes()))
            })
            .collect();
        let public = EpochPublic {
            key_id,
            committee: committee.clone(),
            verification_shares,
            group_key: PointBytes(
                (ED25519_BASEPOINT_POINT * polynomial.constant()).compress().to_bytes(),
            ),
        };
        public.validate().unwrap();
        let transition = AvssTransition {
            purpose: DealPurpose::Dkg,
            session,
            key_id,
            fault_bound: 1,
            history_parent: EpochHistoryParent::genesis(
                scenario.quic_network_id().unwrap(),
                key_id,
            )
            .unwrap(),
            old: None,
            target: committee,
            eligible_dealers: Vec::new(),
        };

        let all = historical_activation_request(&transition, public.clone(), 0xB1, None);
        let first = all.acknowledgements[..3].to_vec();
        let alternate = all.acknowledgements[1..].to_vec();
        server.persist_activation_certificate(&transition, &all.value, &first).await.unwrap();
        let certificate_path = server
            .protocol_store
            .activation_certificate_path(all.value.epoch, all.value.activation_digest);
        let first_bytes = tokio::fs::read(&certificate_path).await.unwrap();
        server.persist_activation_certificate(&transition, &all.value, &alternate).await.unwrap();
        assert_eq!(tokio::fs::read(&certificate_path).await.unwrap(), first_bytes);

        let mut conflicting = historical_activation_request(&transition, public, 0xB2, None);
        conflicting.acknowledgements.truncate(3);
        assert!(
            server
                .persist_activation_certificate(
                    &transition,
                    &conflicting.value,
                    &conflicting.acknowledgements,
                )
                .await
                .is_err()
        );
        assert_eq!(tokio::fs::read(certificate_path).await.unwrap(), first_bytes);
    }

    #[tokio::test]
    async fn closed_grow_replays_are_terminally_idempotent_after_shrink_and_restart() {
        let scenario = historical_replay_scenario();
        scenario.validate().unwrap();
        let state = tempfile::tempdir().unwrap();
        let local = PartyId(1);
        let peer = PartyId(2);
        let local_seed = historical_replay_seed(local);
        let server = boxed_party_server_new(
            local,
            scenario.clone(),
            state.path(),
            &local_seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();

        let epoch_zero_committee = scenario.genesis_committee().unwrap();
        let (key_id, dkg_session) = canonical_dkg_identity(&scenario).unwrap();
        let dkg = AvssTransition {
            purpose: DealPurpose::Dkg,
            session: dkg_session,
            key_id,
            fault_bound: 0,
            history_parent: EpochHistoryParent::genesis(
                scenario.quic_network_id().unwrap(),
                key_id,
            )
            .unwrap(),
            old: None,
            target: epoch_zero_committee.clone(),
            eligible_dealers: Vec::new(),
        };
        let dkg_polynomial = SecretPolynomial::random(1, &mut OsRng).unwrap();
        let epoch_zero = aggregate_dkg(
            key_id,
            epoch_zero_committee,
            local,
            vec![make_dkg_output(local, &dkg_polynomial, &dkg.target, local).unwrap()],
        )
        .unwrap();
        let epoch_zero_public = epoch_zero.public();
        let dkg_certificate =
            historical_activation_request(&dkg, epoch_zero_public.clone(), 0xA0, None);
        let grow_history_parent = dkg_certificate.value.history_link.successor_parent().unwrap();

        let (grow_rotation_context, grow_rotation_certificate, epoch_one_committee) =
            install_historical_key_rotation(&server, &epoch_zero_public, &[local, peer], &[local])
                .await;
        let grow = AvssTransition {
            purpose: DealPurpose::Reshare,
            session: canonical_reshare_session(
                &epoch_zero_public,
                &epoch_one_committee,
                grow_history_parent,
            )
            .unwrap(),
            key_id,
            fault_bound: 0,
            history_parent: grow_history_parent,
            old: Some(epoch_zero_public),
            target: epoch_one_committee.clone(),
            eligible_dealers: vec![local],
        };
        let grow_polynomial = make_proactive_reshare_polynomial(
            &epoch_zero,
            local,
            epoch_one_committee.threshold,
            &mut OsRng,
        )
        .unwrap();
        let epoch_one = epoch_one_committee
            .members
            .iter()
            .map(|recipient| {
                let output =
                    make_dkg_output(local, &grow_polynomial, &epoch_one_committee, recipient.id)
                        .unwrap();
                (
                    recipient.id,
                    aggregate_proactive_reshare(
                        &epoch_zero,
                        epoch_one_committee.clone(),
                        recipient.id,
                        &[local],
                        vec![output],
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let epoch_one_public = epoch_one[&local].public();
        let grow_certificate = historical_activation_request(
            &grow,
            epoch_one_public.clone(),
            0xA1,
            Some(grow_rotation_certificate.semantic_digest(&grow_rotation_context).unwrap()),
        );
        let shrink_history_parent = grow_certificate.value.history_link.successor_parent().unwrap();

        let (shrink_rotation_context, shrink_rotation_certificate, epoch_two_committee) =
            install_historical_key_rotation(&server, &epoch_one_public, &[local], &[local, peer])
                .await;
        let shrink = AvssTransition {
            purpose: DealPurpose::Reshare,
            session: canonical_reshare_session(
                &epoch_one_public,
                &epoch_two_committee,
                shrink_history_parent,
            )
            .unwrap(),
            key_id,
            fault_bound: 0,
            history_parent: shrink_history_parent,
            old: Some(epoch_one_public.clone()),
            target: epoch_two_committee.clone(),
            eligible_dealers: vec![local, peer],
        };
        let shrink_polynomials = [local, peer]
            .into_iter()
            .map(|dealer| {
                (
                    dealer,
                    make_proactive_reshare_polynomial(
                        &epoch_one[&dealer],
                        dealer,
                        epoch_two_committee.threshold,
                        &mut OsRng,
                    )
                    .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let shrink_outputs = shrink_polynomials
            .iter()
            .map(|(dealer, polynomial)| {
                make_dkg_output(*dealer, polynomial, &epoch_two_committee, local).unwrap()
            })
            .collect();
        let epoch_two = aggregate_proactive_reshare(
            &epoch_one[&local],
            epoch_two_committee,
            local,
            &[local, peer],
            shrink_outputs,
        )
        .unwrap();

        let shrink_certificate = historical_activation_request(
            &shrink,
            epoch_two.public(),
            0xA2,
            Some(shrink_rotation_certificate.semantic_digest(&shrink_rotation_context).unwrap()),
        );
        // Persist the durable genesis and grow AVSS session state so the successor activations can
        // durably supersede them; without the live predecessor sessions the epoch-history CAS in
        // `persist_activation_certificate` has nothing to close.
        for predecessor in [&dkg, &grow] {
            let run = new_avss_run(&server, predecessor.clone()).unwrap();
            server.persist_avss_run(&run).await.unwrap();
        }
        for certificate in [&dkg_certificate, &grow_certificate, &shrink_certificate] {
            server
                .persist_activation_certificate(
                    &certificate.transition,
                    &certificate.value,
                    &certificate.acknowledgements,
                )
                .await
                .unwrap();
        }
        server.store.save(&epoch_zero, &mut OsRng).await.unwrap();
        server.store.save(&epoch_one[&local], &mut OsRng).await.unwrap();
        server.store.save(&epoch_two, &mut OsRng).await.unwrap();
        // A certified active epoch persists its proactive-refresh clock as part of activation;
        // restore fails closed without it. Arm the active epoch-2 schedule to mirror that write.
        server.arm_proactive_refresh_for_activation(&epoch_two.public(), 0).await.unwrap();
        let epoch_zero_retirement = ShareRetirement::for_certified_successor(
            0,
            grow.old.as_ref().unwrap().committee.digest(),
            grow_certificate.value.epoch,
            grow_certificate.value.activation_digest,
        )
        .unwrap();
        let epoch_one_retirement = ShareRetirement::for_certified_successor(
            1,
            grow.target.digest(),
            shrink_certificate.value.epoch,
            shrink_certificate.value.activation_digest,
        )
        .unwrap();
        server.store.retire_share(epoch_zero_retirement).await.unwrap();
        server.store.retire_share(epoch_one_retirement).await.unwrap();
        let grow_transition_key = ActivationTransitionKey {
            epoch: grow.target.epoch,
            transition_digest: avss_transition_digest(&grow).unwrap(),
        };
        let grow_index_path =
            server.protocol_store.activation_transition_index_path(grow_transition_key);
        let original_grow_index = tokio::fs::read(&grow_index_path).await.unwrap();
        let mut corrupt_grow_index = original_grow_index.clone();
        *corrupt_grow_index.last_mut().unwrap() ^= 1;
        tokio::fs::write(&grow_index_path, &corrupt_grow_index).await.unwrap();
        drop(server);

        assert!(
            boxed_party_server_new(
                local,
                scenario.clone(),
                state.path(),
                &local_seed,
                &historical_replay_x25519_secret(local, 0),
            )
            .await
            .is_err(),
            "startup must not repair a present corrupt activation index"
        );
        assert_eq!(tokio::fs::read(&grow_index_path).await.unwrap(), corrupt_grow_index);
        tokio::fs::remove_file(&grow_index_path).await.unwrap();

        let restored = boxed_party_server_new(
            local,
            scenario.clone(),
            state.path(),
            &local_seed,
            &historical_replay_x25519_secret(local, 0),
        )
        .await
        .unwrap();
        assert!(tokio::fs::try_exists(&grow_index_path).await.unwrap());
        assert_eq!(
            restored
                .protocol_store
                .load_activation_certificate_for_transition(grow_transition_key)
                .await
                .unwrap()
                .unwrap()
                .key
                .activation_digest,
            grow_certificate.value.activation_digest
        );
        assert_eq!(*restored.active_epoch.read().await, Some(2));
        assert_eq!(restored.epochs.read().await.keys().copied().collect::<Vec<_>>(), vec![2]);
        assert!(restored.protocol_session_status(grow.session).await.is_none());
        assert_eq!(
            restored
                .store
                .load_retirement(0, grow.old.as_ref().unwrap().committee.digest())
                .await
                .unwrap(),
            Some(epoch_zero_retirement)
        );
        assert_eq!(
            restored.store.load_retirement(1, grow.target.digest()).await.unwrap(),
            Some(epoch_one_retirement)
        );

        // Poison unrelated retained history after startup. Exact grow replay below must not
        // enumerate or authenticate either directory, while the explicit audit remains strict.
        let shrink_certificate_path = restored.protocol_store.activation_certificate_path(
            shrink_certificate.value.epoch,
            shrink_certificate.value.activation_digest,
        );
        let mut corrupt_shrink_certificate =
            tokio::fs::read(&shrink_certificate_path).await.unwrap();
        *corrupt_shrink_certificate.last_mut().unwrap() ^= 1;
        tokio::fs::write(&shrink_certificate_path, corrupt_shrink_certificate).await.unwrap();
        let activation_junk = shrink_certificate_path.parent().unwrap().join("unexpected-entry");
        tokio::fs::write(&activation_junk, b"junk").await.unwrap();
        let index_junk = grow_index_path.parent().unwrap().join("unexpected-entry");
        tokio::fs::write(&index_junk, b"junk").await.unwrap();

        let qual = historical_qual_request(&grow, peer, qual_config(&grow).unwrap().digest());
        let acknowledgement = grow_certificate
            .acknowledgements
            .iter()
            .find(|acknowledgement| acknowledgement.from == peer)
            .unwrap()
            .clone();
        let ack = PeerRequest::Epoch {
            operation: EpochOperation::Acknowledge,
            body: postcard::to_allocvec(&ActivationAckDeliverRequest {
                transition: grow.clone(),
                acknowledgement,
            })
            .unwrap(),
        };
        let activate = PeerRequest::Epoch {
            operation: EpochOperation::Activate,
            body: postcard::to_allocvec(&grow_certificate).unwrap(),
        };
        let retire = PeerRequest::Epoch {
            operation: EpochOperation::Retire,
            body: postcard::to_allocvec(&grow_certificate).unwrap(),
        };
        for request in [&qual, &ack, &activate, &retire] {
            for _ in 0..2 {
                assert_eq!(
                    restored.handle_quic_peer_request(peer, request.clone()).await,
                    PeerResponse::Success { body: Vec::new() }
                );
            }
        }

        // A valid delivery without the exact close marker remains retryable even though a later
        // activation record exists; durable certification alone must never invent closure.
        let open_qual =
            historical_qual_request(&shrink, local, qual_config(&shrink).unwrap().digest());
        assert!(matches!(
            restored.handle_local_peer_request(open_qual).await,
            PeerResponse::Rejected { code: RejectionCode::Unavailable, retryable: true, .. }
        ));

        let mut wrong_context = qual_config(&grow).unwrap().digest();
        wrong_context[0] ^= 1;
        assert!(matches!(
            restored
                .handle_quic_peer_request(
                    peer,
                    historical_qual_request(&grow, peer, wrong_context),
                )
                .await,
            PeerResponse::Rejected { retryable: false, .. }
        ));

        let mut wrong_value = grow_certificate.value.clone();
        wrong_value.avss_transcript_digest[0] ^= 1;
        let wrong_statement = activation_statement(&wrong_value, grow.session);
        let wrong_acknowledgement = Identity::from_test_secrets(
            peer,
            grow.target.epoch,
            &historical_replay_seed(peer),
            historical_replay_x25519_secret(peer, grow.target.epoch),
        )
        .unwrap()
        .sign_envelope(
            &grow.target,
            grow.session,
            None,
            activation_sequence(wrong_value.epoch),
            postcard::to_allocvec(&wrong_statement).unwrap(),
        )
        .unwrap();
        let wrong_ack = PeerRequest::Epoch {
            operation: EpochOperation::Acknowledge,
            body: postcard::to_allocvec(&ActivationAckDeliverRequest {
                transition: grow.clone(),
                acknowledgement: wrong_acknowledgement,
            })
            .unwrap(),
        };
        let mut wrong_certificate = grow_certificate.clone();
        wrong_certificate.value = wrong_value;
        for request in [
            wrong_ack,
            PeerRequest::Epoch {
                operation: EpochOperation::Activate,
                body: postcard::to_allocvec(&wrong_certificate).unwrap(),
            },
            PeerRequest::Epoch {
                operation: EpochOperation::Retire,
                body: postcard::to_allocvec(&wrong_certificate).unwrap(),
            },
        ] {
            assert!(matches!(
                restored.handle_quic_peer_request(peer, request).await,
                PeerResponse::Rejected { retryable: false, .. }
            ));
        }

        assert_eq!(*restored.active_epoch.read().await, Some(2));
        assert_eq!(restored.epochs.read().await.keys().copied().collect::<Vec<_>>(), vec![2]);
        assert!(restored.protocol_session_status(grow.session).await.is_none());
        assert_eq!(
            restored
                .store
                .load_retirement(0, grow.old.as_ref().unwrap().committee.digest())
                .await
                .unwrap(),
            Some(epoch_zero_retirement)
        );
        assert_eq!(
            restored.store.load_retirement(1, grow.target.digest()).await.unwrap(),
            Some(epoch_one_retirement)
        );
    }
}
