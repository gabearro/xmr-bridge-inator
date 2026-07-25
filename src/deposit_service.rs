//! Persistent host adapter for the cross-epoch deposit ledger and Monero wallet journal.
//!
//! The portable allocation reducer lives in [`crate::deposit_ledger`]. This module owns the pieces
//! which must be committed atomically around it: its canonical bytes, the autonomous scanner and
//! consolidation worker state, and the authenticated QUIC outbox. Keeping
//! those effects in one encrypted [`crate::storage::WalletSnapshotStore`] record prevents a crash
//! from releasing an address or peer acknowledgement whose durable wallet state was lost.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    committee::{Committee, PartyId, SessionId},
    compact_epoch_registry::{CompactEpochRegistry, CompactRegistryError, VerifiedIssuerWindow},
    compact_registry_archive::{
        CompactRegistryArchiveError, CompactRegistryObjectReader, CompactRegistryObjectRef,
        lookup_verified_issuer_window, prepare_compact_registry_genesis,
    },
    compact_registry_store::{
        CompactRegistryStore, CompactRegistryStoreCheckpoint, CompactRegistryStoreError,
    },
    config::Scenario,
    consolidation_consensus::{
        AttemptSafetyPhase, CONSOLIDATION_ABANDONMENT_APPLICATION,
        CONSOLIDATION_INTENT_APPLICATION, ConsolidationConsensusError, ConsolidationIntent,
        ConsolidationIntentCertificate, ShareUnexposedCertificate, decode_consolidation_intent,
        sign_unselected_share_unexposed_attestation, verify_share_unexposed_attestation,
    },
    consolidation_roast::{
        ConsolidationRoast, ConsolidationRoastError, RoastAttemptPrefixSeal,
        RoastContributionPhase, RoastViewPlan, deterministic_roast_family_digest,
    },
    deposit_archive::{
        ArchivedDepositCheckpoint, CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
        CERTIFIED_LEDGER_ENTRY_ARTIFACT, DepositArchiveError, DepositArchiveEvent,
        DepositArchiveHead, DepositArchiveOperation, DepositArchiveSegment, DepositArchiveStore,
        DepositArtifactChunkRequest, MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES, assemble_artifact_chunks,
    },
    deposit_consensus::{
        CommitCertificate, ConsensusBinding, ConsensusContext, ConsensusError,
        ConsensusMessageBody, ConsensusStep, ConsensusValue, ConsensusValueDigest,
        DepositConsensus, PrepareCertificate, ViewChangeCertificate, decode_consensus_message,
    },
    deposit_consolidation::{
        AttemptBinding, AttemptStatus, ConsolidationCoordinator, ConsolidationError,
        ConsolidationId, ConsolidationPersistEffect, ConsolidationPhase, ConsolidationRecord,
        MAX_CONSOLIDATIONS, OpaqueIntentBinding, SignedTransactionBinding,
        TransactionAuthorization, ValidatedNonceAuthorization, consolidation_input_set_binding,
        consolidation_signed_bytes_binding, nonce_tombstone_for_attempt,
    },
    deposit_consolidation_wire::{
        ByzantineCandidateRelay, ByzantineCertifiedIntent, ByzantineConsensusBody,
        ByzantineConsensusRelay, ByzantineConsensusValueAttachment,
        ByzantineConsolidationWireMessage, ByzantineDeliveryKind, ByzantineKeyImageBindingRelay,
        ByzantinePreprocessRelay, ByzantineRelayAck, ByzantineShareRelay,
        ConsolidationAttemptWireBinding, ConsolidationConsensusSlot, ConsolidationWireError,
        PortableKeyImageBindingAttestation, PortableKeyImageBindingCertificate,
        PortableSignedTransactionAttestation, SignedPreprocessContribution,
        SignedShareContribution, referenced_consolidation_consensus_values,
    },
    deposit_index::{
        DepositIndexBuilder, DepositIndexError, DepositIndexObjectId, DepositIndexReader,
        DepositIndexUpdate, LocalSafetyQuery, LocalSafetyValue, PortableAllocationQuery,
        PortableConsolidationStatus, PortableConsolidationTerminalRecord,
        PortableDepositOutputRecord, PortableStateQuery, PortableStateRecord,
        SignedIndexCheckpointSlot, VerifiedDepositIndexPreflight, VerifiedDepositIndexTransition,
        VerifiedDepositObservationIndexTransition, VerifiedPortableScannerSnapshot,
        lookup_portable_state, subaddress_spend_key, verify_portable_scanner_snapshot,
    },
    deposit_index_checkpoint::{
        DepositIndexCheckpointCandidate, DepositIndexCheckpointCertificate,
        DepositIndexCheckpointError, DepositIndexCheckpointOperation,
        DepositIndexCheckpointStatement, PortableDepositIndexHead, VerifiedDepositIndexCheckpoint,
        deposit_index_checkpoint_consensus_context,
        deposit_index_checkpoint_consensus_context_from_digest, sign_checkpoint_transition,
        sign_deposit_observation_checkpoint_transition,
    },
    deposit_index_store::{
        DepositIndexStore, DepositIndexStoreCheckpoint, DepositIndexStoreError,
        VerifiedPortableIndexImport,
    },
    deposit_ledger::{
        CertifiedDepositObservation, CertifiedLedgerEntry, CompactLedgerCursor,
        ConsolidationAbandonmentStatement, ConsolidationCompletionStatement,
        DepositObservationStatement, LateConsolidationSettlementStatement, LedgerError,
        LedgerPayload, LedgerRequestId, LedgerStatement, MAX_ALLOCATION_CLOCK_SKEW_SECONDS,
        MIN_ALLOCATION_CERTIFICATION_LEAD_SECONDS, RequestBinding, VerifiedTerminalLedgerAdmission,
        verify_attestation, verify_deposit_observation_attestation,
    },
    deposit_sync_wire::{
        DepositIndexCheckpointAttestWire, DepositIndexCheckpointCertificateWire,
        DepositIndexCheckpointLedgerBinding, DepositIndexCheckpointObservationBinding,
        DepositObservationIndexCheckpointAttestWire,
        DepositObservationIndexCheckpointCertificateWire, DepositSyncAdvertisement,
        DepositSyncContext, DepositSyncObject, DepositSyncObjectPage, DepositSyncObjectPageRequest,
        DepositSyncObjectRef, DepositSyncWireError, MAX_DEPOSIT_SYNC_PAGE_OBJECTS,
        MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES,
    },
    deposit_wallet::{
        CanonicalDepositAddress, ChainPoint, DepositAddressDeriver, DepositSubaddressIndex,
        DepositWalletError, DepositWalletId, SignedSweepTransaction, SweepId, SweepStatus,
        VerifiedRecognitionAnchor, WalletOutputId,
    },
    deposit_worker::{
        DepositChainSource, DepositConsolidationBackend, DepositOutputBinding,
        DepositOutputIndexBackend, DepositRollback, DepositWorkerConfig, DepositWorkerError,
        DepositWorkerState, PreparedFrostlassSweep, PreparedSweepIntent, SweepPlan,
        SweepSigningSessionTombstone, VerifiedCanonicalSweepInclusion,
        VerifiedLocalDepositObservation, WorkerEventBatch, canonical_sweep_transaction_key_images,
        canonicalize_certified_sweep_key_images, root_consolidation_destination_binding,
    },
    identity::{Identity, IdentityError, SignedEnvelope},
    key_rotation::{KeyRotationError, VerifiedRegistryHandoffTarget},
    keys::EpochPublic,
    quic_transport::{DepositOperation, PeerRequest, RequestId},
    roast_attempt_archive::{
        PortableRoastTransactionCompletionProof, RoastAttemptArchiveError, RoastAttemptArchiveHead,
        RoastAttemptArchiveRecord, RoastAttemptArchiveStage, RoastAttemptArchiveStore,
    },
    signing::{CanonicalSignerSet, ProofVerifiedKeyImagePreview},
    storage::{
        ProtocolStore, StoreError, WalletArtifactRef, WalletArtifactStore, WalletId,
        WalletSnapshotStore,
    },
};

use zeroize::Zeroizing;

const DEPOSIT_SERVICE_SNAPSHOT_VERSION: u16 = 16;
const DEPOSIT_LOCAL_STATE_VERSION: u16 = 12;
/// A proposer schedules address release far enough ahead for an n-f checkpoint to form, but
/// strictly inside the receiver admission window. With the current 30-second minimum and
/// 300-second maximum, a receiver may be at most 30 seconds ahead of the proposer (and up to
/// 240 seconds behind) when it first admits the proposal.
const ALLOCATION_ISSUANCE_LEAD_SECONDS: u64 = 2 * MIN_ALLOCATION_CERTIFICATION_LEAD_SECONDS;
const MAX_DEPOSIT_OUTBOX_ENTRIES: usize = 16_384;
const MAX_DEPOSIT_OUTBOX_ENTRIES_PER_RECIPIENT: usize = 4_096;
const MAX_PUBLIC_CONSOLIDATIONS_PER_REQUEST: usize = 1_024;
// A portable completion retains canonical Monero transaction bytes and its n-f certificate. Keep
// this below the authenticated QUIC 8 MiB frame while large enough that every ledger-valid
// completion can be gossiped and replayed.
const MAX_DEPOSIT_MESSAGE_BYTES: usize = 6 * 1024 * 1024;
const MAX_CONSOLIDATION_MESSAGE_BYTES: usize =
    crate::deposit_consolidation_wire::MAX_CONSOLIDATION_WIRE_BYTES;
const MAX_REDUCER_BYTES: usize = 48 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = crate::storage::MAX_WALLET_SNAPSHOT_BYTES;
const DEPOSIT_PROTOCOL_VERSION: u16 = 13;
pub(crate) const DEPOSIT_WIRE_VERSION: u16 = 2;
const MAX_PENDING_LEDGER_SLOTS: usize = 8;
const MAX_PENDING_DEPOSIT_OBSERVATIONS: usize = 4_096;
const DEPOSIT_CONSENSUS_LANE_VERSION: u16 = 1;
const DEPOSIT_CONSENSUS_VALUE_VERSION: u16 = 4;
const DEPOSIT_CHECKPOINT_CONSENSUS_LANE_VERSION: u16 = 1;
const CONSOLIDATION_COMPLETION_EVIDENCE_VERSION: u16 = 1;
const CONSOLIDATION_LATE_SETTLEMENT_EVIDENCE_VERSION: u16 = 3;
const CONSOLIDATION_ABANDONMENT_OBSERVATION_VERSION: u16 = 2;
const CONSOLIDATION_ABANDONMENT_EVIDENCE_VERSION: u16 = 2;
const CONSOLIDATION_ABANDONMENT_WIRE_VERSION: u16 = 2;
const MAX_CONSOLIDATION_ABANDONMENT_POOLS: usize = 32;
pub const MAX_CONSOLIDATION_ABANDONMENT_MESSAGE_BYTES: usize = 512 * 1024;
const BYZANTINE_CONSENSUS_LANE_VERSION: u16 = 1;
const BYZANTINE_BOOTSTRAP_CONTINUATION_VERSION: u16 = 1;
const MAX_ADMITTED_BYZANTINE_VALUES: usize = 32;
const MAX_PENDING_CLIENT_REQUESTS: usize = 1_024;
const MAX_PENDING_CLIENT_REQUESTS_PER_SOURCE: usize = 256;
const MAX_ADMITTED_CONSENSUS_VALUES: usize = 128;
const HANDOFF_OBSERVATION_FENCE_VERSION: u16 = 1;

/// Authenticated client request. `request` is the caller's stable idempotency key and `binding`
/// commits to business data without placing it in the public allocation ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositAddressRequest {
    pub request: LedgerRequestId,
    pub binding: RequestBinding,
}

/// Derive the internal certified-ledger id from the complete tenant/request binding. Consensus
/// participants can therefore reject a same-id/different-binding race without trusting which
/// peer's client gossip arrived first.
#[must_use]
pub fn deposit_request_id_for_binding(binding: RequestBinding) -> LedgerRequestId {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-request-id-from-binding/v1");
    hasher.update(&binding.0);
    LedgerRequestId(*hasher.finalize().as_bytes())
}

fn validate_deposit_address_request(
    request: DepositAddressRequest,
) -> Result<(), DepositServiceError> {
    if request.request.0 == [0_u8; 32]
        || request.request != deposit_request_id_for_binding(request.binding)
    {
        return Err(DepositServiceError::InvalidRequest);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositAddressStatus {
    Syncing,
    Pending,
    Active,
    Expired,
    Permanent,
}

/// Chain-readiness gate for client-visible permanence/expiry decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositScannerSyncStatus {
    Ready { scanner_tip: ChainPoint, confirmed_horizon: u64 },
    Syncing { scanner_tip: ChainPoint, confirmed_horizon: Option<u64> },
    Unavailable { scanner_tip: ChainPoint },
}

impl DepositScannerSyncStatus {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Client-visible allocation state. Address bytes and a certificate are released only together.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositAddressResponse {
    pub request: LedgerRequestId,
    pub status: DepositAddressStatus,
    pub address: Option<CanonicalDepositAddress>,
    pub certificate: Option<CertifiedLedgerEntry>,
    pub created_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub leader: PartyId,
}

/// Post-CAS capabilities for one freshly released consolidation signing attempt.
///
/// Neither authorization can be constructed from wire data or an in-memory reducer mutation: the
/// service returns them only after the exact composite worker/coordinator snapshot was persisted
/// and read back. `start_messages` were fully encoded and size-checked before reservation.
#[derive(Debug)]
pub struct PersistedSweepRelease {
    pub authorization: TransactionAuthorization,
    pub attempt: AttemptBinding,
    pub start_messages: BTreeMap<PartyId, Vec<u8>>,
    /// Locally reconstructed transaction handed directly to the FROSTLASS signer. The type is
    /// intentionally non-Clone and redacts private prepared material from `Debug`.
    pub prepared: PreparedFrostlassSweep,
    /// Fused worker/coordinator capability. The host must still consume it at its persistent
    /// `(session, intent_digest)` tombstone boundary before creating a nonce.
    pub nonce_authorization: ValidatedNonceAuthorization,
}

/// Post-persistence work emitted by the coordinator-free consolidation runtime.
#[derive(Debug)]
pub enum ByzantineConsolidationAction {
    /// Exact daemon-validated bootstrap value is durable, while no BA message or nonce has been
    /// exposed. The host may hold here for deterministic failover testing, then present the
    /// continuation to `continue_byzantine_bootstrap`.
    BootstrapPrepared {
        sweep: SweepId,
        slot: [u8; 32],
        outer_view: u64,
        bootstrap_ba_view: u64,
        proposer: PartyId,
        binding: ConsolidationAttemptWireBinding,
        prepared_intent_digest: [u8; 32],
        continuation: ByzantineBootstrapContinuation,
    },
    Release {
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        release: PersistedSweepRelease,
    },
    CompleteContributionSet {
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        preprocesses: Option<Vec<SignedPreprocessContribution>>,
        shares: Option<Vec<SignedShareContribution>>,
    },
    AuthorizeKeyImages {
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        certificate: PortableKeyImageBindingCertificate,
    },
    BroadcastCandidate {
        family: [u8; 32],
        view: u64,
        sweep: SweepId,
        binding: ConsolidationAttemptWireBinding,
        attestation: PortableSignedTransactionAttestation,
    },
    RetireView {
        family: [u8; 32],
        view: u64,
        binding: ConsolidationAttemptWireBinding,
        signing_session: SessionId,
    },
}

/// Snapshot-bound continuation for the pre-BA bootstrap gate. Its fields are intentionally
/// private: callers can replay the exact token, but cannot substitute another prepared value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByzantineBootstrapContinuation {
    version: u16,
    slot: [u8; 32],
    prepared_intent_digest: [u8; 32],
    lane_digest: [u8; 32],
}

impl ByzantineBootstrapContinuation {
    #[must_use]
    pub const fn slot(&self) -> [u8; 32] {
        self.slot
    }

    #[must_use]
    pub const fn prepared_intent_digest(&self) -> [u8; 32] {
        self.prepared_intent_digest
    }
}

/// Durable effects of one autonomous scanner tick which must also be applied to volatile signing
/// machines before they process another round message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DepositWorkerTickOutcome {
    /// Sessions whose authorized inputs disappeared. The worker and public coordinator are already
    /// durably quarantined when this is returned; the host must now discard any matching in-memory
    /// FROSTLASS machine. These sessions are never resumable if the old branch later returns.
    pub invalidated_consolidation_sessions: Vec<SessionId>,
}

/// Public, non-authorizing storage closure for a durable consolidation session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsolidationSessionClosure {
    pub session: SessionId,
    pub purpose: Vec<u8>,
}

/// Demo-acceptance evidence that one exact output is already part of the party's authenticated
/// portable index. The checkpoint statement was signed by `n-f` parties and the output record is
/// addressed by its immutable Monero transaction/index identity. This contains no private wallet
/// material and grants no protocol authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableDepositObservationEvidence {
    pub output: PortableDepositOutputRecord,
    pub portable_index_digest: [u8; 32],
    pub checkpoint_statement_digest: [u8; 32],
    pub checkpoint_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicConsolidationPhase {
    Reserved,
    Signing,
    Certified,
    Broadcast,
    Confirmed,
    Quarantined,
    Aborted,
    Abandoned,
}

/// Read-only public consolidation view. It contains commitments and canonical input IDs only,
/// never private view/spend material, key offsets, or the outgoing-view seed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicConsolidationStatus {
    pub authorization: ConsolidationId,
    pub sweep: SweepId,
    pub plan: SweepPlan,
    pub signed: Option<SignedTransactionBinding>,
    pub certificate_digest: Option<[u8; 32]>,
    pub phase: PublicConsolidationPhase,
    pub destination_binding: [u8; 32],
    pub confirmation: Option<ChainPoint>,
    /// Inner Byzantine-agreement view which certified the randomized bootstrap proposal.
    pub bootstrap_ba_view: u64,
    /// Deterministic leader of the certified inner BA view.
    pub bootstrap_ba_proposer: PartyId,
    /// Digest of the exact daemon-validated prepared attachment selected by BA.
    pub bootstrap_prepared_intent_digest: [u8; 32],
    /// Witness-subset-independent digest of the genesis intent decision.
    pub bootstrap_certificate_digest: [u8; 32],
    /// Canonical n-f witness roster carried by the genesis intent certificate.
    pub bootstrap_certificate_signers: Vec<PartyId>,
    /// Highest certified ROAST view observed for this immutable authorization family.
    pub roast_view: u64,
    /// Deterministic relay seed for the current view. This party has no signing authority beyond
    /// being one member of `roast_signers`.
    pub roast_relay_seed: PartyId,
    /// Exact deterministic `n-f` signer subset for `roast_view`.
    pub roast_signers: Vec<PartyId>,
    /// Number of certified fresh-session views retained for this family.
    pub roast_view_count: u16,
    /// Number of byte-exact signed transaction variants known for this family.
    pub roast_candidate_count: u16,
    /// Candidates backed by at least `f+1` byte-identical portable attestations.
    pub roast_endorsed_candidate_count: u16,
    /// Digest of the verified n-f intent commit certificate for `roast_view`.
    pub roast_intent_certificate_digest: [u8; 32],
    /// Canonical n-f witness roster carried by that certificate.
    pub roast_intent_certificate_signers: Vec<PartyId>,
    /// Full immutable attempt binding certified for `roast_view`.
    pub roast_attempt_binding_digest: [u8; 32],
    /// Number of distinct portable candidate witnesses behind the selected endorsed candidate.
    pub roast_endorsed_witness_count: u16,
    /// Digest binding the selected candidate, view and exact attributable witnesses.
    pub roast_endorsed_evidence_digest: [u8; 32],
    /// Canonical n-f signer roster from the final global ledger completion certificate.
    pub completion_certificate_signers: Vec<PartyId>,
    /// Digest of the proof-verified, n-f-authorized key-image family binding.
    pub key_image_binding_digest: [u8; 32],
    /// Exact unsigned transaction digest committed by that binding.
    pub key_image_unsigned_transaction_digest: [u8; 32],
    /// Digest of the exact participant-sorted proof-bearing preprocess set.
    pub key_image_preprocess_set_digest: [u8; 32],
    /// Canonical distinct origins whose portable proofs authorize the binding.
    pub key_image_authorizers: Vec<PartyId>,
    /// Required and observed authorization quorum; zero before the pre-share certificate exists.
    pub key_image_authorization_quorum: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositAllocateWire {
    version: u16,
    registry: [u8; 32],
    pub statement: LedgerStatement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositAttestationWire {
    version: u16,
    registry: [u8; 32],
    pub statement: LedgerStatement,
    pub attestation: SignedEnvelope,
}

impl DepositAttestationWire {
    fn new(
        registry: &CompactEpochRegistry,
        statement: LedgerStatement,
        attestation: SignedEnvelope,
    ) -> Self {
        Self { version: DEPOSIT_WIRE_VERSION, registry: registry.digest(), statement, attestation }
    }
}

/// One exact certified ledger entry. Issuer authority is resolved from the authenticated compact
/// registry archive; no lifetime registry copy is accepted from a peer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositCertificateWire {
    version: u16,
    pub entry: CertifiedLedgerEntry,
}

impl DepositCertificateWire {
    fn new(entry: CertifiedLedgerEntry) -> Self {
        Self { version: DEPOSIT_WIRE_VERSION, entry }
    }
}

/// One active-issuer confirmed-output proposal. It is not authority until exact n-f attestations
/// form a [`CertifiedDepositObservation`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositObservationWire {
    version: u16,
    registry: [u8; 32],
    pub statement: DepositObservationStatement,
}

impl DepositObservationWire {
    fn new(registry: &CompactEpochRegistry, statement: DepositObservationStatement) -> Self {
        Self { version: DEPOSIT_WIRE_VERSION, registry: registry.digest(), statement }
    }
}

/// One independently verified member witness for an exact observation statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositObservationAttestationWire {
    version: u16,
    registry: [u8; 32],
    pub statement: DepositObservationStatement,
    pub attestation: SignedEnvelope,
}

impl DepositObservationAttestationWire {
    fn new(
        registry: &CompactEpochRegistry,
        statement: DepositObservationStatement,
        attestation: SignedEnvelope,
    ) -> Self {
        Self { version: DEPOSIT_WIRE_VERSION, registry: registry.digest(), statement, attestation }
    }
}

/// Exact n-f observation certificate disseminated before its separately ordered index checkpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositObservationCertificateWire {
    version: u16,
    pub observation: CertifiedDepositObservation,
}

impl DepositObservationCertificateWire {
    fn new(observation: CertifiedDepositObservation) -> Self {
        Self { version: DEPOSIT_WIRE_VERSION, observation }
    }
}

/// Authenticated member gossip for an internal, tenant-bound allocation request. The request is
/// intentionally not trusted merely because it arrived over QUIC; it enters only a bounded pool
/// and still needs a Byzantine consensus commit before any ledger attestation is possible.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositClientRequestStatement {
    version: u16,
    registry: [u8; 32],
    activation: [u8; 32],
    request: DepositAddressRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositClientRequestWire {
    version: u16,
    registry: [u8; 32],
    activation: [u8; 32],
    request: DepositAddressRequest,
    origin: SignedEnvelope,
}

impl DepositClientRequestWire {
    fn new(
        registry: &CompactEpochRegistry,
        request: DepositAddressRequest,
        identity: &Identity,
    ) -> Result<Self, DepositServiceError> {
        let active = registry.active();
        let statement = DepositClientRequestStatement {
            version: DEPOSIT_WIRE_VERSION,
            registry: registry.digest(),
            activation: active.activation_binding(),
            request,
        };
        let payload = postcard::to_allocvec(&statement)?;
        let origin = identity.sign_envelope(
            active.committee(),
            deposit_client_request_session(&statement),
            None,
            1,
            payload,
        )?;
        let wire = Self {
            version: DEPOSIT_WIRE_VERSION,
            registry: statement.registry,
            activation: statement.activation,
            request,
            origin,
        };
        wire.validate(registry)?;
        Ok(wire)
    }

    fn validate(&self, registry: &CompactEpochRegistry) -> Result<(), DepositServiceError> {
        if self.version != DEPOSIT_WIRE_VERSION
            || self.registry == [0_u8; 32]
            || self.activation == [0_u8; 32]
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        validate_deposit_address_request(self.request)
            .map_err(|_| DepositServiceError::InvalidPeerMessage)?;
        let active = registry.active();
        if self.registry != registry.digest()
            || self.activation != active.activation_binding()
            || self.origin.to.is_some()
            || self.origin.sequence != 1
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let statement = DepositClientRequestStatement {
            version: self.version,
            registry: self.registry,
            activation: self.activation,
            request: self.request,
        };
        if self.origin.session != deposit_client_request_session(&statement)
            || self.origin.payload != postcard::to_allocvec(&statement)?
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        Identity::verify_envelope(active.committee(), self.origin.from, &self.origin)?;
        Ok(())
    }

    const fn origin(&self) -> PartyId {
        self.origin.from
    }
}

fn deposit_client_request_session(statement: &DepositClientRequestStatement) -> SessionId {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-client-request-session/v1");
    hasher.update(&statement.version.to_le_bytes());
    hasher.update(&statement.registry);
    hasher.update(&statement.activation);
    hasher.update(&statement.request.request.0);
    hasher.update(&statement.request.binding.0);
    SessionId(*hasher.finalize().as_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositConsensusPurpose {
    /// One globally ordered BA lane. Allocation, handoff, and any independently verifiable
    /// consolidation completion are competing application values in this same sequence-scoped
    /// reducer; operation- or family-scoped purposes would fragment honest replicas by arrival
    /// order even though the consensus context/session is identical.
    NextLedgerSlot { sequence: u64 },
    /// One value-independent BA lane chooses the complete certified operation which may consume
    /// the next global portable-index checkpoint sequence. The permanent checkpoint signing slot
    /// is forbidden until this lane commits.
    NextIndexCheckpoint { sequence: u64 },
}

impl DepositConsensusPurpose {
    const fn sequence(self) -> u64 {
        match self {
            Self::NextLedgerSlot { sequence } | Self::NextIndexCheckpoint { sequence } => sequence,
        }
    }
}

/// Self-contained public authority for admitting one signed consolidation into the global ledger
/// BA.  Candidate gossip is only a liveness optimization: a lagging member can verify this value
/// from the active registry, the exact ROAST slot, the all-selected key-image certificate, and a
/// canonical `f + 1` set of transaction endorsements carried by the proposal itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ConsolidationCompletionEvidence {
    version: u16,
    family: [u8; 32],
    attempt_prefix: RoastAttemptPrefixSeal,
    slot: ConsolidationConsensusSlot,
    binding: ConsolidationAttemptWireBinding,
    key_images: PortableKeyImageBindingCertificate,
    endorsements: Vec<PortableSignedTransactionAttestation>,
}

impl ConsolidationCompletionEvidence {
    fn new(
        roast: &ConsolidationRoast,
        view: u64,
        key_images: PortableKeyImageBindingCertificate,
        endorsements: Vec<PortableSignedTransactionAttestation>,
    ) -> Result<Self, DepositServiceError> {
        let evidence = Self {
            version: CONSOLIDATION_COMPLETION_EVIDENCE_VERSION,
            family: roast.family_digest(),
            attempt_prefix: roast.attempt_prefix_seal()?,
            slot: roast.expected_slot(view)?,
            binding: roast.wire_binding(view)?,
            key_images,
            endorsements,
        };
        // The full statement-specific graph is checked by `verify`; this constructor still keeps
        // the representation canonical and refuses an empty/oversized public witness.
        if evidence.endorsements.is_empty()
            || evidence.endorsements.len() > evidence.slot.committee().members.len()
        {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        Ok(evidence)
    }

    fn digest(&self) -> Result<[u8; 32], DepositServiceError> {
        let bytes = postcard::to_allocvec(self)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/deposit-consolidation-completion-evidence/v1",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn verify(
        &self,
        protocol: &DepositProtocolState,
        completion: &ConsolidationCompletionStatement,
        expected_network: Option<[u8; 32]>,
    ) -> Result<(), DepositServiceError> {
        let active = protocol.registry.active();
        if active.epoch() != completion.attempt().epoch() {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        let committee = active.committee();
        let fault_bound = active.fault_bound();
        let required_endorsements = usize::from(fault_bound)
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidConsensusValue)?;
        let registry = active.registry_id().digest();
        let expected_family = deterministic_roast_family_digest(
            self.slot.binding(),
            committee,
            fault_bound,
            completion.authorization(),
            self.slot.family_anchor(),
        );
        if self.version != CONSOLIDATION_COMPLETION_EVIDENCE_VERSION
            || self.family == [0; 32]
            || self.family != expected_family
            || self.attempt_prefix.family() != self.family
            || self.attempt_prefix.family_anchor() != self.slot.family_anchor()
            || self.attempt_prefix.closed_through_view() < self.slot.roast_view()
            || self.attempt_prefix.closed_through_attempt() < completion.attempt().attempt()
            || self.attempt_prefix.closed_through_view().checked_add(1)
                != Some(self.attempt_prefix.closed_through_attempt())
            || self.attempt_prefix.accumulator() == [0; 32]
            || self.slot.roast_view().checked_add(1) != Some(completion.attempt().attempt())
            || self.slot.committee() != committee
            || self.slot.fault_bound() != fault_bound
            || self.slot.binding().wallet != protocol.ledger.wallet_id().0
            || self.slot.binding().registry != registry
            || self.slot.binding().activation != active.activation_binding()
            || self.slot.binding().domain != consolidation_intent_consensus_domain()
            || expected_network.is_some_and(|network| self.slot.binding().network != network)
            || self.binding.attempt() != completion.attempt()
            || self.binding.authorization_digest() != completion.authorization().digest()
            || self.binding.consolidation_id() != completion.id()
            || completion.authorization().root_group_key() != active.group_key()
            || self.endorsements.len() != required_endorsements
        {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        self.slot.consensus_context()?;
        self.binding.validate_authorization(completion.authorization())?;
        self.binding.validate_active(
            committee,
            registry,
            active.activation_binding(),
            active.group_key(),
        )?;
        let key_images = self.key_images.verify(
            committee,
            fault_bound,
            self.slot.binding().network,
            &self.binding,
        )?;
        if key_images.sweep() != completion.plan().id
            || key_images.inputs() != completion.inputs()
            || key_images.family_digest() != self.family
            || key_images.signing_context().into_bytes() != completion.attempt().signing_context()
        {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        let mut previous = None;
        for endorsement in &self.endorsements {
            endorsement.verify(committee, self.slot.binding().network, &self.binding)?;
            if previous.is_some_and(|origin| origin >= endorsement.origin())
                || endorsement.signed().binding() != completion.signed_binding()
                || endorsement.signed().transaction() != completion.signed_transaction()
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            previous = Some(endorsement.origin());
        }
        Ok(())
    }
}

/// Self-contained historical authorization carried by a successor committee when canonical chain
/// inclusion defeats an earlier abandonment. The historical f+1 transaction endorsements and
/// all-selected key-image certificate remain attributable to the old committee; the enclosing
/// sequence-lane BA and final ledger attestations are issued only by the current committee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ConsolidationLateSettlementEvidence {
    version: u16,
    abandonment_statement: LedgerStatement,
    completion_proof: PortableRoastTransactionCompletionProof,
}

impl ConsolidationLateSettlementEvidence {
    fn new(
        abandonment_statement: LedgerStatement,
        completion_proof: PortableRoastTransactionCompletionProof,
    ) -> Self {
        Self {
            version: CONSOLIDATION_LATE_SETTLEMENT_EVIDENCE_VERSION,
            abandonment_statement,
            completion_proof,
        }
    }

    fn digest(&self) -> Result<[u8; 32], DepositServiceError> {
        let bytes = postcard::to_allocvec(self)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/consolidation-late-settlement-evidence/v3",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn verify(
        &self,
        protocol: &DepositProtocolState,
        settlement: &LateConsolidationSettlementStatement,
        expected_network: [u8; 32],
    ) -> Result<(), DepositServiceError> {
        let completion = settlement.historical_completion();
        let LedgerPayload::ConsolidationAbandonment(abandonment) =
            &self.abandonment_statement.payload
        else {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        };
        let verified = self.completion_proof.verify_expected(
            abandonment.attempt_prefix(),
            protocol.ledger.wallet_id(),
            expected_network,
            abandonment.family(),
            completion.transaction_id(),
        )?;
        let archived_record = self.completion_proof.record();
        let mapping = self.completion_proof.mapping();
        if self.version != CONSOLIDATION_LATE_SETTLEMENT_EVIDENCE_VERSION
            || self.abandonment_statement.digest() != settlement.abandonment_statement()
            || self.abandonment_statement.wallet != protocol.ledger.wallet_id()
            || abandonment.id() != completion.id()
            || archived_record.intent().authorization() != completion.authorization()
            || archived_record.intent().attempt() != completion.attempt()
            || mapping.signed_binding() != completion.signed_binding()
            || mapping.signed_transaction() != completion.signed_transaction()
            || mapping.plan() != completion.plan()
            || mapping.key_image_certificate()
                != archived_record
                    .key_image_certificate()
                    .ok_or(DepositServiceError::InvalidLateConsolidationSettlement)?
            || verified.member().view() != archived_record.view()
            || verified.member().attempt() != completion.attempt().attempt()
            || completion.plan().id != completion.authorization().sweep_id()
        {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        }
        Ok(())
    }
}

/// Exact objective chain observation signed before an honest party may vote to abandon an
/// unsigned nonce lineage. It intentionally excludes the eventual global ledger sequence so the
/// same n-f certificate survives unrelated allocation races while remaining bound to every
/// historical signing and finality coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ConsolidationAbandonmentObservation {
    version: u16,
    network: [u8; 32],
    registry: [u8; 32],
    activation: [u8; 32],
    family: [u8; 32],
    /// Ordered commitment to every certified absolute view/attempt in this family. This makes the
    /// n-f observation certificate close the entire nonce lineage, not merely the latest retained
    /// hot view.
    attempt_prefix: RoastAttemptPrefixSeal,
    slot: ConsolidationConsensusSlot,
    /// Exact certified intent whose selected signers must prove their share was never exposed
    /// before this family can be abandoned.
    intent_certificate: ConsolidationIntentCertificate,
    /// Deterministic successor context used solely for the durable share-exposure fence.
    abandonment_context: ConsensusContext,
    binding: ConsolidationAttemptWireBinding,
    key_images: PortableKeyImageBindingCertificate,
    authorization: TransactionAuthorization,
    attempt: AttemptBinding,
    sweep_sequence: u64,
    inputs: Vec<WalletOutputId>,
    missing_inputs: Vec<WalletOutputId>,
    ancestor: ChainPoint,
    observation_tip: ChainPoint,
    finality_depth: u32,
}

impl ConsolidationAbandonmentObservation {
    fn digest(&self) -> Result<[u8; 32], DepositServiceError> {
        let bytes = postcard::to_allocvec(self)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/consolidation-abandonment-observation/v2",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn session(&self) -> Result<SessionId, DepositServiceError> {
        Ok(SessionId(self.digest()?))
    }

    fn validate_public(
        &self,
        protocol: &DepositProtocolState,
        expected_network: [u8; 32],
    ) -> Result<(), DepositServiceError> {
        let active = protocol.registry.active();
        if active.epoch() != self.attempt.epoch() {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        let committee = active.committee();
        let fault_bound = active.fault_bound();
        let registry = active.registry_id().digest();
        let required = committee
            .n()
            .checked_sub(fault_bound)
            .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
        self.authorization.validate()?;
        self.attempt.validate()?;
        let intent_context = self.slot.consensus_context()?;
        let intent = ConsolidationIntent::new(
            &intent_context,
            self.authorization.clone(),
            self.attempt.clone(),
        )?;
        self.intent_certificate.verify_expected(&intent_context, &intent)?;
        crate::consolidation_consensus::validate_abandonment_transition(
            &self.abandonment_context,
            &self.intent_certificate,
        )?;
        if self.abandonment_context
            != consolidation_abandonment_fence_context(
                &intent_context,
                &self.intent_certificate,
                self.family,
                self.attempt_prefix,
                self.ancestor,
                self.observation_tip,
            )?
        {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        self.binding.validate_authorization(&self.authorization)?;
        self.binding.validate_active(
            committee,
            registry,
            active.activation_binding(),
            active.group_key(),
        )?;
        let key_images =
            self.key_images.verify(committee, fault_bound, expected_network, &self.binding)?;
        let expected_family = deterministic_roast_family_digest(
            self.slot.binding(),
            committee,
            fault_bound,
            &self.authorization,
            self.slot.family_anchor(),
        );
        let finality_height = self
            .ancestor
            .height
            .checked_add(u64::from(self.finality_depth))
            .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
        if self.version != CONSOLIDATION_ABANDONMENT_OBSERVATION_VERSION
            || self.network == [0; 32]
            || self.network != expected_network
            || self.registry != registry
            || self.activation != active.activation_binding()
            || self.family == [0; 32]
            || self.family != expected_family
            || self.attempt_prefix.family() != self.family
            || self.attempt_prefix.family_anchor() != self.slot.family_anchor()
            || self.attempt_prefix.closed_through_view() != self.slot.roast_view()
            || self.attempt_prefix.closed_through_attempt() != self.attempt.attempt()
            || self.attempt_prefix.closed_through_view().checked_add(1)
                != Some(self.attempt_prefix.closed_through_attempt())
            || self.attempt_prefix.accumulator() == [0; 32]
            || self.slot.committee() != committee
            || self.slot.fault_bound() != fault_bound
            || self.slot.binding().wallet != protocol.ledger.wallet_id().0
            || self.slot.binding().network != self.network
            || self.slot.binding().registry != self.registry
            || self.slot.binding().activation != self.activation
            || self.slot.binding().domain != consolidation_intent_consensus_domain()
            || self.slot.roast_view().checked_add(1) != Some(self.attempt.attempt())
            || self.binding.attempt() != &self.attempt
            || self.binding.authorization_digest() != self.authorization.digest()
            || self.binding.consolidation_id() != self.authorization.id()
            || self.authorization.wallet_id() != protocol.ledger.wallet_id()
            || self.authorization.root_group_key() != active.group_key()
            || self.authorization.input_set() != consolidation_input_set_binding(&self.inputs)
            || self.authorization.input_count()
                != u32::try_from(self.inputs.len()).ok().unwrap_or(0)
            || self.attempt.signers().len() < usize::from(required)
            || self.attempt.signers().len() > committee.members.len()
            || self.inputs.is_empty()
            || self.inputs.windows(2).any(|window| window[0] >= window[1])
            || self.missing_inputs.is_empty()
            || self.missing_inputs.windows(2).any(|window| window[0] >= window[1])
            || self.missing_inputs.iter().any(|input| self.inputs.binary_search(input).is_err())
            || self.finality_depth == 0
            || self.observation_tip.height != finality_height
            || self.observation_tip.height <= self.ancestor.height
            || ChainPoint::new(self.ancestor.height, self.ancestor.hash).is_err()
            || ChainPoint::new(self.observation_tip.height, self.observation_tip.hash).is_err()
            || key_images.sweep() != self.authorization.sweep_id()
            || key_images.inputs() != self.inputs.as_slice()
            || key_images.family_digest() != self.family
            || key_images.signing_context().into_bytes() != self.attempt.signing_context()
        {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        Ok(())
    }

    fn matches_statement(&self, statement: &ConsolidationAbandonmentStatement) -> bool {
        self.family == statement.family()
            && self.attempt_prefix == statement.attempt_prefix()
            && &self.slot == statement.slot()
            && &self.binding == statement.binding()
            && &self.key_images == statement.key_images()
            && &self.authorization == statement.authorization()
            && &self.attempt == statement.attempt()
            && self.sweep_sequence == statement.sweep_sequence()
            && self.inputs.as_slice() == statement.inputs()
            && self.missing_inputs.as_slice() == statement.missing_inputs()
            && self.ancestor == statement.ancestor()
            && self.observation_tip == statement.observation_tip()
            && self.finality_depth == statement.finality_depth()
    }
}

fn consolidation_abandonment_fence_context(
    intent_context: &ConsensusContext,
    intent_certificate: &ConsolidationIntentCertificate,
    family: [u8; 32],
    prefix: RoastAttemptPrefixSeal,
    ancestor: ChainPoint,
    observation_tip: ChainPoint,
) -> Result<ConsensusContext, DepositServiceError> {
    let mut material = Vec::with_capacity(32 * 7 + 40);
    material.extend_from_slice(&intent_context.digest());
    material.extend_from_slice(&intent_certificate.decision_digest());
    material.extend_from_slice(&family);
    material.extend_from_slice(&prefix.family_anchor());
    material.extend_from_slice(&prefix.closed_through_view().to_le_bytes());
    material.extend_from_slice(&prefix.closed_through_attempt().to_le_bytes());
    material.extend_from_slice(&prefix.accumulator());
    material.extend_from_slice(&ancestor.height.to_le_bytes());
    material.extend_from_slice(&ancestor.hash);
    material.extend_from_slice(&observation_tip.height.to_le_bytes());
    material.extend_from_slice(&observation_tip.hash);
    let mut binding = intent_context.binding().clone();
    binding.application = CONSOLIDATION_ABANDONMENT_APPLICATION.to_vec();
    Ok(ConsensusContext::new(
        binding,
        SessionId::derive(b"consolidation-abandonment-fence/v1", &material),
        intent_context.committee().clone(),
        intent_context.fault_bound(),
        intent_context
            .height()
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?,
        intent_context
            .sequence()
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?,
        intent_certificate.decision_digest(),
    )?)
}

/// Canonical n-f historical-committee certificate required before abandonment enters global BA.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ConsolidationAbandonmentEvidence {
    version: u16,
    observation: ConsolidationAbandonmentObservation,
    share_unexposed: ShareUnexposedCertificate,
    attestations: Vec<SignedEnvelope>,
}

impl ConsolidationAbandonmentEvidence {
    fn digest(&self) -> Result<[u8; 32], DepositServiceError> {
        let bytes = postcard::to_allocvec(self)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/consolidation-abandonment-evidence/v2",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn verify(
        &self,
        protocol: &DepositProtocolState,
        abandonment: &ConsolidationAbandonmentStatement,
        expected_network: [u8; 32],
    ) -> Result<(), DepositServiceError> {
        self.observation.validate_public(protocol, expected_network)?;
        if self.version != CONSOLIDATION_ABANDONMENT_EVIDENCE_VERSION
            || !self.observation.matches_statement(abandonment)
        {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        self.share_unexposed
            .verify(&self.observation.abandonment_context, &self.observation.intent_certificate)?;
        let active = protocol.registry.active();
        if active.epoch() != self.observation.attempt.epoch() {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        let required = usize::from(
            active
                .committee()
                .n()
                .checked_sub(active.fault_bound())
                .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?,
        );
        if self.attestations.len() != required {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        let payload = postcard::to_allocvec(&self.observation)?;
        let session = self.observation.session()?;
        let mut previous = None;
        for envelope in &self.attestations {
            if previous.is_some_and(|party| party >= envelope.from)
                || envelope.to.is_some()
                || envelope.session != session
                || envelope.sequence != 1
                || envelope.payload != payload
            {
                return Err(DepositServiceError::InvalidConsolidationAbandonment);
            }
            Identity::verify_envelope(active.committee(), envelope.from, envelope)?;
            previous = Some(envelope.from);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableConsolidationAbandonmentPool {
    observation: ConsolidationAbandonmentObservation,
    share_unexposed: BTreeMap<PartyId, SignedEnvelope>,
    attestations: BTreeMap<PartyId, SignedEnvelope>,
}

/// One authenticated observation signature carried over QUIC. The inner envelope is a portable
/// broadcast; authenticated point-to-point routing must match its origin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAbandonmentObservationWire {
    version: u16,
    observation: ConsolidationAbandonmentObservation,
    share_unexposed: SignedEnvelope,
    attestation: SignedEnvelope,
}

impl ConsolidationAbandonmentObservationWire {
    fn new(
        observation: ConsolidationAbandonmentObservation,
        share_unexposed: SignedEnvelope,
        identity: &Identity,
        committee: &Committee,
    ) -> Result<Self, DepositServiceError> {
        let payload = postcard::to_allocvec(&observation)?;
        let attestation =
            identity.sign_envelope(committee, observation.session()?, None, 1, payload)?;
        Ok(Self {
            version: CONSOLIDATION_ABANDONMENT_WIRE_VERSION,
            observation,
            share_unexposed,
            attestation,
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self, DepositServiceError> {
        if bytes.len() > MAX_CONSOLIDATION_ABANDONMENT_MESSAGE_BYTES {
            return Err(DepositServiceError::InvalidMessageSize);
        }
        let (wire, trailing) = postcard::take_from_bytes::<Self>(bytes)?;
        if !trailing.is_empty() || postcard::to_allocvec(&wire)?.as_slice() != bytes {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        Ok(wire)
    }

    fn validate(
        &self,
        protocol: &DepositProtocolState,
        authenticated_sender: PartyId,
        expected_network: [u8; 32],
    ) -> Result<(), DepositServiceError> {
        self.observation.validate_public(protocol, expected_network)?;
        let active = protocol.registry.active();
        let payload = postcard::to_allocvec(&self.observation)?;
        if self.version != CONSOLIDATION_ABANDONMENT_WIRE_VERSION
            || self.attestation.from != authenticated_sender
            || self.attestation.to.is_some()
            || self.attestation.session != self.observation.session()?
            || self.attestation.sequence != 1
            || self.attestation.payload != payload
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        if self.share_unexposed.from != authenticated_sender {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        verify_share_unexposed_attestation(
            &self.observation.abandonment_context,
            &self.observation.intent_certificate,
            &self.share_unexposed,
        )?;
        Identity::verify_envelope(active.committee(), authenticated_sender, &self.attestation)?;
        Ok(())
    }
}

/// Portable consensus traffic. The complete context is carried so a lagging party can verify and
/// install a terminal certificate without first seeing the proposal. Service admission still
/// reconstructs the expected context from local certified history before reducing this payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositConsensusWire {
    version: u16,
    context: ConsensusContext,
    purpose: DepositConsensusPurpose,
    payload: DepositConsensusPayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositConsensusPayload {
    Envelope(SignedEnvelope),
    ViewCertificate(ViewChangeCertificate),
    CommitCertificate(CommitCertificate),
}

impl DepositConsensusWire {
    fn envelope(
        context: ConsensusContext,
        purpose: DepositConsensusPurpose,
        envelope: SignedEnvelope,
    ) -> Self {
        Self {
            version: DEPOSIT_WIRE_VERSION,
            context,
            purpose,
            payload: DepositConsensusPayload::Envelope(envelope),
        }
    }

    fn view_certificate(
        context: ConsensusContext,
        purpose: DepositConsensusPurpose,
        certificate: ViewChangeCertificate,
    ) -> Self {
        Self {
            version: DEPOSIT_WIRE_VERSION,
            context,
            purpose,
            payload: DepositConsensusPayload::ViewCertificate(certificate),
        }
    }

    fn commit_certificate(
        context: ConsensusContext,
        purpose: DepositConsensusPurpose,
        certificate: CommitCertificate,
    ) -> Self {
        Self {
            version: DEPOSIT_WIRE_VERSION,
            context,
            purpose,
            payload: DepositConsensusPayload::CommitCertificate(certificate),
        }
    }

    fn validate_for_operation(
        &self,
        operation: DepositOperation,
    ) -> Result<(), DepositServiceError> {
        if self.version != DEPOSIT_WIRE_VERSION
            || self.purpose.sequence() == 0
            || self.purpose.sequence() != self.context.sequence()
            || self.purpose.sequence() != self.context.height()
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        self.context.validate()?;
        match (&self.payload, operation) {
            (DepositConsensusPayload::Envelope(envelope), DepositOperation::ConsensusProposal) => {
                let message = decode_consensus_message(&self.context, envelope)?;
                if !matches!(message.body, ConsensusMessageBody::Proposal(_)) {
                    return Err(DepositServiceError::InvalidPeerMessage);
                }
            }
            (DepositConsensusPayload::Envelope(envelope), DepositOperation::ConsensusMessage) => {
                let message = decode_consensus_message(&self.context, envelope)?;
                if matches!(message.body, ConsensusMessageBody::Proposal(_)) {
                    return Err(DepositServiceError::InvalidPeerMessage);
                }
            }
            (
                DepositConsensusPayload::ViewCertificate(certificate),
                DepositOperation::ConsensusCertificate,
            ) => certificate.verify(&self.context)?,
            (
                DepositConsensusPayload::CommitCertificate(certificate),
                DepositOperation::ConsensusCertificate,
            ) => certificate.verify(&self.context)?,
            _ => return Err(DepositServiceError::InvalidPeerMessage),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingClientRequest {
    request: DepositAddressRequest,
    sources: BTreeSet<PartyId>,
}

fn pending_client_request_quota(committee: &Committee) -> Result<usize, DepositServiceError> {
    let members = usize::from(committee.n());
    let partition = MAX_PENDING_CLIENT_REQUESTS
        .checked_div(members)
        .filter(|quota| *quota != 0)
        .ok_or(DepositServiceError::InvalidProtocolState)?;
    Ok(partition.min(MAX_PENDING_CLIENT_REQUESTS_PER_SOURCE))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositConsensusValue {
    version: u16,
    statement: LedgerStatement,
    terminal_evidence: Option<ConsolidationTerminalEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AdmittedDepositConsensusValue {
    admitted_at: u64,
    statement: LedgerStatement,
    terminal_evidence: Option<ConsolidationTerminalEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ConsolidationTerminalEvidence {
    Completion(ConsolidationCompletionEvidence),
    Abandonment(ConsolidationAbandonmentEvidence),
    LateSettlement(ConsolidationLateSettlementEvidence),
}

impl DepositConsensusValue {
    fn new(statement: LedgerStatement) -> Result<ConsensusValue, DepositServiceError> {
        if matches!(
            statement.payload,
            LedgerPayload::ConsolidationCompletion(_)
                | LedgerPayload::ConsolidationAbandonment(_)
                | LedgerPayload::LateConsolidationSettlement(_)
        ) {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        Self::with_evidence(statement, None)
    }

    fn completion(
        statement: LedgerStatement,
        completion_evidence: ConsolidationCompletionEvidence,
    ) -> Result<ConsensusValue, DepositServiceError> {
        if !matches!(statement.payload, LedgerPayload::ConsolidationCompletion(_)) {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        Self::with_evidence(
            statement,
            Some(ConsolidationTerminalEvidence::Completion(completion_evidence)),
        )
    }

    fn abandonment(
        statement: LedgerStatement,
        abandonment_evidence: ConsolidationAbandonmentEvidence,
    ) -> Result<ConsensusValue, DepositServiceError> {
        if !matches!(statement.payload, LedgerPayload::ConsolidationAbandonment(_)) {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        Self::with_evidence(
            statement,
            Some(ConsolidationTerminalEvidence::Abandonment(abandonment_evidence)),
        )
    }

    fn late_settlement(
        statement: LedgerStatement,
        evidence: ConsolidationLateSettlementEvidence,
    ) -> Result<ConsensusValue, DepositServiceError> {
        if !matches!(statement.payload, LedgerPayload::LateConsolidationSettlement(_)) {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        Self::with_evidence(
            statement,
            Some(ConsolidationTerminalEvidence::LateSettlement(evidence)),
        )
    }

    fn with_evidence(
        statement: LedgerStatement,
        terminal_evidence: Option<ConsolidationTerminalEvidence>,
    ) -> Result<ConsensusValue, DepositServiceError> {
        let value = Self { version: DEPOSIT_CONSENSUS_VALUE_VERSION, statement, terminal_evidence };
        Ok(ConsensusValue::new(postcard::to_allocvec(&value)?)?)
    }

    fn decode(value: &ConsensusValue) -> Result<Self, DepositServiceError> {
        value.validate()?;
        let (decoded, trailing) = postcard::take_from_bytes::<Self>(value.as_bytes())?;
        if !trailing.is_empty() || decoded.version != DEPOSIT_CONSENSUS_VALUE_VERSION {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        if postcard::to_allocvec(&decoded)? != value.as_bytes() {
            return Err(DepositServiceError::InvalidConsensusValue);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableDepositConsensusLane {
    version: u16,
    purpose: DepositConsensusPurpose,
    reducer: DepositConsensus,
    admitted_values: BTreeMap<ConsensusValueDigest, AdmittedDepositConsensusValue>,
    deadline_view: u64,
    deadline_unix_ms: u64,
    timeout_requested: bool,
}

impl DurableDepositConsensusLane {
    fn new(
        purpose: DepositConsensusPurpose,
        reducer: DepositConsensus,
        now_seconds: u64,
        deadline_unix_ms: u64,
    ) -> Result<Self, DepositServiceError> {
        if now_seconds == 0 || deadline_unix_ms == 0 {
            return Err(DepositServiceError::InvalidTime);
        }
        Ok(Self {
            version: DEPOSIT_CONSENSUS_LANE_VERSION,
            purpose,
            deadline_view: reducer.view(),
            reducer,
            admitted_values: BTreeMap::new(),
            deadline_unix_ms,
            timeout_requested: false,
        })
    }

    fn enter_view(&mut self, view: u64, deadline_unix_ms: u64) {
        self.deadline_view = view;
        self.deadline_unix_ms = deadline_unix_ms;
        self.timeout_requested = false;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AdmittedDepositCheckpointConsensusValue {
    admitted_at: u64,
    candidate: DepositIndexCheckpointCandidate,
}

/// Durable value-independent BA lane which precedes the irreversible checkpoint signing slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableDepositCheckpointConsensusLane {
    version: u16,
    purpose: DepositConsensusPurpose,
    reducer: DepositConsensus,
    admitted_values: BTreeMap<ConsensusValueDigest, AdmittedDepositCheckpointConsensusValue>,
    deadline_view: u64,
    deadline_unix_ms: u64,
    timeout_requested: bool,
}

impl DurableDepositCheckpointConsensusLane {
    fn new(
        purpose: DepositConsensusPurpose,
        reducer: DepositConsensus,
        now_seconds: u64,
        deadline_unix_ms: u64,
    ) -> Result<Self, DepositServiceError> {
        if now_seconds == 0
            || deadline_unix_ms == 0
            || !matches!(purpose, DepositConsensusPurpose::NextIndexCheckpoint { .. })
        {
            return Err(DepositServiceError::InvalidTime);
        }
        Ok(Self {
            version: DEPOSIT_CHECKPOINT_CONSENSUS_LANE_VERSION,
            purpose,
            deadline_view: reducer.view(),
            reducer,
            admitted_values: BTreeMap::new(),
            deadline_unix_ms,
            timeout_requested: false,
        })
    }

    fn enter_view(&mut self, view: u64, deadline_unix_ms: u64) {
        self.deadline_view = view;
        self.deadline_unix_ms = deadline_unix_ms;
        self.timeout_requested = false;
    }
}

/// Exact prepared attachment which passed both local worker reconstruction and an asynchronous
/// daemon ring revalidation before it became eligible for any BA reducer call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ValidatedByzantineConsensusValue {
    value: ConsensusValue,
    binding: ConsolidationAttemptWireBinding,
    prepared_intent: Vec<u8>,
    prepared_intent_digest: [u8; 32],
    slot_digest: [u8; 32],
    validated_worker_revision: u64,
}

/// One value-independent, persistent consolidation BA lane. There is deliberately at most one
/// lane per wallet, which bounds live nonce machines and fences honest votes across randomized
/// proposer values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableByzantineConsensusLane {
    version: u16,
    slot: ConsolidationConsensusSlot,
    reducer: DepositConsensus,
    admitted_values: BTreeMap<ConsensusValueDigest, ValidatedByzantineConsensusValue>,
    local_candidate: ConsensusValueDigest,
    deadline_view: u64,
    deadline_unix_ms: u64,
    base_timeout_ms: u64,
    timeout_requested: bool,
}

impl DurableByzantineConsensusLane {
    fn new(
        slot: ConsolidationConsensusSlot,
        reducer: DepositConsensus,
        local: ValidatedByzantineConsensusValue,
        now_ms: u64,
        base_timeout_ms: u64,
    ) -> Result<Self, DepositServiceError> {
        if now_ms == 0 || base_timeout_ms == 0 {
            return Err(DepositServiceError::InvalidTime);
        }
        let local_candidate = local.value.digest();
        let mut admitted_values = BTreeMap::new();
        admitted_values.insert(local_candidate, local);
        let deadline_unix_ms = byzantine_view_deadline(now_ms, base_timeout_ms, 0)?;
        let lane = Self {
            version: BYZANTINE_CONSENSUS_LANE_VERSION,
            slot,
            reducer,
            admitted_values,
            local_candidate,
            deadline_view: 0,
            deadline_unix_ms,
            base_timeout_ms,
            timeout_requested: false,
        };
        lane.validate()?;
        Ok(lane)
    }

    fn validate(&self) -> Result<(), DepositServiceError> {
        let context = self.slot.consensus_context()?;
        if self.version != BYZANTINE_CONSENSUS_LANE_VERSION
            || self.reducer.context() != &context
            || self.reducer.local_party().0 == 0
            || self.deadline_view != self.reducer.view()
            || self.deadline_unix_ms == 0
            || self.base_timeout_ms == 0
            || self.admitted_values.is_empty()
            || self.admitted_values.len() > MAX_ADMITTED_BYZANTINE_VALUES
            || !self.admitted_values.contains_key(&self.local_candidate)
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        for (digest, admitted) in &self.admitted_values {
            let prepared = PreparedSweepIntent::decode(&admitted.prepared_intent)?;
            let intent = decode_consolidation_intent(&context, &admitted.value)?;
            if admitted.value.digest() != *digest
                || admitted.prepared_intent_digest != prepared.digest()?
                || admitted.slot_digest != self.slot.digest()
                || admitted.binding.attempt() != intent.attempt()
                || admitted.binding.validate_authorization(intent.authorization()).is_err()
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            ByzantineConsensusValueAttachment::new(
                &context,
                &self.slot,
                &admitted.value,
                admitted.binding.clone(),
                admitted.prepared_intent.clone(),
            )?;
            // Deterministic signer/session validation is part of the pre-vote application
            // predicate, not a post-certificate check.
            let plan = RoastViewPlan::derive(
                &self.slot,
                self.slot.committee(),
                self.slot.fault_bound(),
                intent.authorization(),
            )?;
            if admitted.binding.attempt().attempt() != plan.attempt()
                || admitted.binding.attempt().session() != plan.signing_session()
                || admitted.binding.attempt().signers() != plan.signers()
                || admitted.binding.leader() != plan.relay_seed()
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
        }
        self.reducer.validate_application_values(|value| {
            self.admitted_values
                .get(&value.digest())
                .is_some_and(|admitted| &admitted.value == value)
        })?;
        if self
            .reducer
            .commit()
            .is_some_and(|commit| !self.admitted_values.contains_key(&commit.value().digest()))
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        Ok(())
    }

    fn digest(&self) -> Result<[u8; 32], DepositServiceError> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/deposit-service/byzantine-consensus-lane/v1",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn continuation(&self) -> Result<ByzantineBootstrapContinuation, DepositServiceError> {
        let local = self
            .admitted_values
            .get(&self.local_candidate)
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        Ok(ByzantineBootstrapContinuation {
            version: BYZANTINE_BOOTSTRAP_CONTINUATION_VERSION,
            slot: self.slot.digest(),
            prepared_intent_digest: local.prepared_intent_digest,
            lane_digest: self.digest()?,
        })
    }

    fn verify_continuation(
        &self,
        continuation: ByzantineBootstrapContinuation,
    ) -> Result<(), DepositServiceError> {
        if continuation.version != BYZANTINE_BOOTSTRAP_CONTINUATION_VERSION
            || continuation != self.continuation()?
            || self.reducer.started()
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        Ok(())
    }

    fn enter_view(&mut self, view: u64, now_ms: u64) -> Result<(), DepositServiceError> {
        self.deadline_view = view;
        self.deadline_unix_ms = byzantine_view_deadline(now_ms, self.base_timeout_ms, view)?;
        self.timeout_requested = false;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingLedgerSlot {
    statement: LedgerStatement,
    attestations: BTreeMap<PartyId, SignedEnvelope>,
}

/// One bounded post-ledger checkpoint round.
///
/// Ledger witnesses authorize the business statement, while these independent witnesses authorize
/// the exact resulting portable index root. Keeping both decisions in the durable reducer prevents
/// a restart from substituting a different local reconstruction after the ledger quorum formed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingIndexCheckpointSlot {
    ledger: CertifiedLedgerEntry,
    ledger_artifact: WalletArtifactRef,
    statement: DepositIndexCheckpointStatement,
    reserved_at: u64,
    witnesses: BTreeMap<PartyId, SignedEnvelope>,
}

/// One exact confirmed-output fact retained until it reaches the independent portable checkpoint
/// lane. The issuer-specific statement may be refreshed after a certified handoff, while the
/// party-local anti-equivocation slot remains bound to its issuer-independent `fact_digest`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingDepositObservationSlot {
    statement: crate::deposit_ledger::DepositObservationStatement,
    attestations: BTreeMap<PartyId, SignedEnvelope>,
}

/// The sole observation operation currently occupying the global archive/checkpoint ordinal.
///
/// The exact certified observation artifact is staged before any checkpoint witness is released.
/// It remains harmless and unreachable until the checkpoint certificate, archive event, portable
/// index transition, and reducer successor win one outer wallet-snapshot CAS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingDepositObservationCheckpointSlot {
    observation: CertifiedDepositObservation,
    observation_artifact: WalletArtifactRef,
    statement: DepositIndexCheckpointStatement,
    reserved_at: u64,
    witnesses: BTreeMap<PartyId, SignedEnvelope>,
}

/// In-memory, content-authenticated view of one bounded QUIC sync download.
///
/// The read set is tracked so adoption can reject detached objects instead of persisting attacker-
/// supplied content which was never consumed from an advertised authenticated root.
struct DepositSyncCandidateReader {
    registry: BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    index: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    archive: BTreeMap<WalletArtifactRef, Vec<u8>>,
    consumed: RefCell<BTreeSet<DepositSyncObjectRef>>,
}

struct VerifiedDepositSyncCandidate {
    reader: DepositSyncCandidateReader,
    operation: Option<VerifiedDepositSyncOperation>,
    operation_artifact: Option<WalletArtifactRef>,
    checkpoint: Option<VerifiedDepositIndexCheckpoint>,
    scanner_snapshot: Option<VerifiedPortableScannerSnapshot>,
    terminal_statement: Option<LedgerStatement>,
}

enum VerifiedDepositSyncOperation {
    Ledger(CertifiedLedgerEntry),
    DepositObservation(CertifiedDepositObservation),
}

impl DepositSyncCandidateReader {
    fn new(
        wallet: DepositWalletId,
        objects: Vec<DepositSyncObject>,
    ) -> Result<Self, DepositSyncWireError> {
        let mut registry = BTreeMap::new();
        let mut index = BTreeMap::new();
        let mut archive = BTreeMap::new();
        for object in objects {
            let reference = object.reference();
            if reference.wallet() != wallet {
                return Err(DepositSyncWireError::InvalidObjectReference);
            }
            let bytes = object.bytes().to_vec();
            let duplicate = match reference {
                DepositSyncObjectRef::Registry(reference) => registry.insert(reference, bytes),
                DepositSyncObjectRef::Index(reference) => index.insert(reference, bytes),
                DepositSyncObjectRef::CertificateArchive(reference) => {
                    archive.insert(reference, bytes)
                }
            };
            if duplicate.is_some() {
                return Err(DepositSyncWireError::InvalidObjectManifest);
            }
        }
        Ok(Self { registry, index, archive, consumed: RefCell::new(BTreeSet::new()) })
    }

    fn load_archive(&self, reference: WalletArtifactRef) -> Result<Vec<u8>, DepositSyncWireError> {
        let bytes =
            self.archive.get(&reference).ok_or(DepositSyncWireError::ObjectUnavailable)?.clone();
        self.consumed.borrow_mut().insert(DepositSyncObjectRef::CertificateArchive(reference));
        Ok(bytes)
    }

    fn all_objects_consumed(&self) -> bool {
        self.consumed.borrow().len()
            == self
                .registry
                .len()
                .saturating_add(self.index.len())
                .saturating_add(self.archive.len())
    }

    fn objects(&self) -> impl Iterator<Item = (DepositSyncObjectRef, &[u8])> {
        self.registry
            .iter()
            .map(|(reference, bytes)| {
                (DepositSyncObjectRef::Registry(*reference), bytes.as_slice())
            })
            .chain(self.index.iter().map(|(reference, bytes)| {
                (DepositSyncObjectRef::Index(*reference), bytes.as_slice())
            }))
            .chain(self.archive.iter().map(|(reference, bytes)| {
                (DepositSyncObjectRef::CertificateArchive(*reference), bytes.as_slice())
            }))
    }
}

impl CompactRegistryObjectReader for DepositSyncCandidateReader {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        let value = self.registry.get(&reference).cloned();
        if value.is_some() {
            self.consumed.borrow_mut().insert(DepositSyncObjectRef::Registry(reference));
        }
        Ok(value)
    }
}

impl DepositIndexReader for DepositSyncCandidateReader {
    fn load_index_object(
        &self,
        reference: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        let value = self.index.get(&reference).cloned();
        if value.is_some() {
            self.consumed.borrow_mut().insert(DepositSyncObjectRef::Index(reference));
        }
        Ok(value)
    }
}

/// Durable proof that the retiring issuer certified one immutable scanner frontier.
///
/// The referenced ledger statement is in the authenticated portable index. Keeping its semantic
/// identity here lets restart validation prove that the local observation filter is anchored to
/// the exact current ledger head instead of an unauthenticated scanner tip.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CertifiedHandoffObservationFence {
    version: u16,
    statement: LedgerStatement,
    cutoff: ChainPoint,
}

impl CertifiedHandoffObservationFence {
    fn from_statement(statement: &LedgerStatement) -> Result<Self, DepositServiceError> {
        let LedgerPayload::HandoffFence(fence) = &statement.payload else {
            return Err(DepositServiceError::InvalidConsensusValue);
        };
        let certified = Self {
            version: HANDOFF_OBSERVATION_FENCE_VERSION,
            statement: statement.clone(),
            cutoff: fence.cutoff(),
        };
        certified.validate_shape()?;
        Ok(certified)
    }

    fn validate_shape(&self) -> Result<(), DepositServiceError> {
        let LedgerPayload::HandoffFence(fence) = &self.statement.payload else {
            return Err(DepositServiceError::InvalidProtocolState);
        };
        if self.version != HANDOFF_OBSERVATION_FENCE_VERSION
            || self.statement.sequence == 0
            || self.statement.digest() == [0; 32]
            || self.cutoff != fence.cutoff()
            || ChainPoint::new(self.cutoff.height, self.cutoff.hash).is_err()
        {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        Ok(())
    }
}

/// Party-local signer locks around the portable certified history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositProtocolState {
    version: u16,
    local_party: PartyId,
    registry: CompactEpochRegistry,
    ledger: CompactLedgerCursor,
    /// Independent archive/checkpoint ordinal. Observation-only checkpoints advance this without
    /// consuming a ledger sequence.
    checkpoint_sequence: u64,
    pending: BTreeMap<u64, PendingLedgerSlot>,
    /// Bounded, replay-safe observation queue keyed by absolute Monero output identity.
    pending_observations: BTreeMap<WalletOutputId, PendingDepositObservationSlot>,
    /// Bounded, unauthoritative client request gossip. Only a consensus commit can move one of
    /// these requests into `pending` or `signed_slots`.
    client_requests: BTreeMap<LedgerRequestId, PendingClientRequest>,
    /// Exact activation-certified successor selected by the host. Once present, new allocations
    /// are closed and the next idle global consensus height deterministically seals this target.
    pending_handoff: Option<EpochPublic>,
    /// Full verified source public metadata needed to reconstruct the non-serializable target
    /// capability after restart.
    pending_handoff_source: Option<EpochPublic>,
    pending_handoff_fault_bound: Option<u16>,
    /// Witness-independent durable activation-history root for `pending_handoff`.
    pending_handoff_root: Option<[u8; 32]>,
    /// Quorum-certified finite chain frontier. Until this ledger decision exists, no new
    /// observation checkpoint may enter the retiring issuer's portable prefix.
    pending_handoff_fence: Option<CertifiedHandoffObservationFence>,
    /// At most one live allocation height. This serializes the next ledger slot and bounds
    /// retained portable vote/certificate evidence.
    consensus_lane: Option<DurableDepositConsensusLane>,
    /// One BA decision over all valid ledger/observation operations competing for the next
    /// portable checkpoint. This lane must commit before either checkpoint signing lane exists.
    checkpoint_consensus_lane: Option<DurableDepositCheckpointConsensusLane>,
    /// At most one n-f checkpoint witness round may follow the live ledger height.
    index_checkpoint: Option<PendingIndexCheckpointSlot>,
    /// Observation form of the same globally serialized checkpoint lane. This is mutually
    /// exclusive with `index_checkpoint`.
    observation_checkpoint: Option<PendingDepositObservationCheckpointSlot>,
}

impl DepositProtocolState {
    fn genesis(
        local_party: PartyId,
        registry: CompactEpochRegistry,
        ledger: CompactLedgerCursor,
    ) -> Result<Self, DepositServiceError> {
        registry.validate()?;
        if ledger.wallet_id() != registry.wallet() || ledger.registry_id() != registry.id() {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        Ok(Self {
            version: DEPOSIT_PROTOCOL_VERSION,
            local_party,
            registry,
            ledger,
            checkpoint_sequence: 0,
            pending: BTreeMap::new(),
            pending_observations: BTreeMap::new(),
            client_requests: BTreeMap::new(),
            pending_handoff: None,
            pending_handoff_source: None,
            pending_handoff_fault_bound: None,
            pending_handoff_root: None,
            pending_handoff_fence: None,
            consensus_lane: None,
            checkpoint_consensus_lane: None,
            index_checkpoint: None,
            observation_checkpoint: None,
        })
    }

    fn require_live(&self) -> Result<(), DepositServiceError> {
        Ok(())
    }

    /// Encode only party-local mutable state. The authenticated registry and portable certified
    /// ledger live in immutable archive objects referenced by the outer wallet snapshot.
    fn encode_local(
        &self,
        deriver: &DepositAddressDeriver,
    ) -> Result<Vec<u8>, DepositServiceError> {
        self.validate_archive_replay(deriver)?;
        DepositLocalState::from_protocol(self).encode()
    }

    fn current_consensus_leader(&self) -> Result<PartyId, DepositServiceError> {
        if let Some(lane) = &self.consensus_lane {
            return Ok(lane.reducer.leader());
        }
        let committee = self.registry.active().committee();
        let n = u64::from(committee.n());
        let sequence = self.ledger.next_sequence();
        let index =
            (sequence.checked_sub(1).ok_or(DepositServiceError::InvalidProtocolState)? % n) + 1;
        committee
            .party_for_frost_index(
                u16::try_from(index).map_err(|_| DepositServiceError::InvalidProtocolState)?,
            )
            .map_err(DepositServiceError::from)
    }

    fn retain_client_request(
        &mut self,
        source: PartyId,
        request: DepositAddressRequest,
    ) -> Result<bool, DepositServiceError> {
        validate_deposit_address_request(request)?;
        let committee = self.registry.active().committee();
        committee.member(source)?;
        let source_quota = pending_client_request_quota(committee)?;
        let source_count = self
            .client_requests
            .values()
            .filter(|pending| pending.sources.contains(&source))
            .count();
        if let Some(existing) = self.client_requests.get_mut(&request.request) {
            if existing.request != request {
                return Err(DepositServiceError::RequestEquivocation);
            }
            if !existing.sources.contains(&source) && source_count >= source_quota {
                return Err(DepositServiceError::ConsensusRequestPoolFull);
            }
            return Ok(existing.sources.insert(source));
        }
        if self.client_requests.len() >= MAX_PENDING_CLIENT_REQUESTS || source_count >= source_quota
        {
            return Err(DepositServiceError::ConsensusRequestPoolFull);
        }
        self.client_requests.insert(
            request.request,
            PendingClientRequest { request, sources: BTreeSet::from([source]) },
        );
        Ok(true)
    }

    fn next_client_request(&self) -> Result<Option<DepositAddressRequest>, DepositServiceError> {
        let committee = self.registry.active().committee();
        let n = u64::from(committee.n());
        let first = (self.ledger.next_sequence() - 1) % n;
        for offset in 0..n {
            let frost_index = u16::try_from(((first + offset) % n) + 1)
                .map_err(|_| DepositServiceError::InvalidProtocolState)?;
            let origin = committee.party_for_frost_index(frost_index)?;
            if let Some(pending) =
                self.client_requests.values().find(|pending| pending.sources.contains(&origin))
            {
                return Ok(Some(pending.request));
            }
        }
        Ok(None)
    }

    fn reserve(
        &mut self,
        statement: LedgerStatement,
        now: u64,
        deriver: &DepositAddressDeriver,
        recognition: Option<&VerifiedRecognitionAnchor>,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        terminal_admission: Option<&VerifiedTerminalLedgerAdmission>,
        preflight: &VerifiedDepositIndexPreflight,
    ) -> Result<(), DepositServiceError> {
        // An exact replay is an idempotent retry, including after the proposal's wall-clock
        // validity window. The original acceptance and signer lock are already durable. Check it
        // before applying admission-time clock rules, but never permit a different statement to
        // occupy the same sequence.
        if let Some(existing) = self.pending.get(&statement.sequence) {
            return if existing.statement == statement {
                Ok(())
            } else {
                Err(DepositServiceError::SlotConflict(statement.sequence))
            };
        }
        validate_allocation_clock(&statement, now)?;
        if matches!(
            statement.payload,
            LedgerPayload::ConsolidationCompletion(_)
                | LedgerPayload::ConsolidationAbandonment(_)
                | LedgerPayload::LateConsolidationSettlement(_)
        ) {
            self.ledger.validate_next_terminal_statement(
                &self.registry,
                historical_issuer,
                &statement,
                now,
                terminal_admission.ok_or(DepositServiceError::InvalidPortableTerminalEvidence)?,
                preflight,
                |address| deriver.verify_address(address).is_ok(),
            )?;
        } else {
            if terminal_admission.is_some() {
                return Err(DepositServiceError::InvalidPortableTerminalEvidence);
            }
            self.ledger.validate_next_statement(
                &self.registry,
                historical_issuer,
                &statement,
                now,
                recognition,
                preflight,
                |address| deriver.verify_address(address).is_ok(),
            )?;
        }
        if self.pending.len() >= MAX_PENDING_LEDGER_SLOTS {
            return Err(DepositServiceError::TooManyPendingSlots);
        }
        self.pending.insert(
            statement.sequence,
            PendingLedgerSlot { statement, attestations: BTreeMap::new() },
        );
        Ok(())
    }

    fn stage_local_attestation(
        &mut self,
        sequence: u64,
        identity: &Identity,
    ) -> Result<SignedEnvelope, DepositServiceError> {
        if identity.party() != self.local_party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let slot = self.pending.get(&sequence).ok_or(DepositServiceError::UnknownSlot(sequence))?;
        self.registry.active().committee().member(self.local_party)?;
        if let Some(existing) = slot.attestations.get(&self.local_party) {
            return slot
                .attestations
                .get(&self.local_party)
                .cloned()
                .ok_or(DepositServiceError::InvalidProtocolState)
                .and_then(|envelope| {
                    if &envelope == existing {
                        Ok(envelope)
                    } else {
                        Err(DepositServiceError::InvalidProtocolState)
                    }
                });
        }
        // Handoff attestations deliberately sign the compact registry-transition payload rather
        // than the ordinary LedgerAttestation wrapper. `attestation_payload` selects the exact
        // wire object for every statement kind so the resulting witnesses can be converted into
        // a RegistryHandoffCertificate without signature reinterpretation.
        let payload = slot.statement.attestation_payload()?;
        let envelope = identity.sign_envelope(
            self.registry.active().committee(),
            slot.statement.slot_session(),
            None,
            sequence,
            payload,
        )?;
        self.pending
            .get_mut(&sequence)
            .ok_or(DepositServiceError::UnknownSlot(sequence))?
            .attestations
            .insert(self.local_party, envelope.clone());
        Ok(envelope)
    }

    fn accept_attestation(
        &mut self,
        statement: &LedgerStatement,
        envelope: SignedEnvelope,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<Option<CertifiedLedgerEntry>, DepositServiceError> {
        let sender = verify_attestation(statement, &self.registry, &envelope)?;
        let slot = self
            .pending
            .get_mut(&statement.sequence)
            .ok_or(DepositServiceError::UnknownSlot(statement.sequence))?;
        if slot.statement != *statement {
            return Err(DepositServiceError::SlotConflict(statement.sequence));
        }
        if let Some(existing) = slot.attestations.get(&sender) {
            if existing != &envelope {
                return Err(DepositServiceError::AttestationEquivocation(sender));
            }
        } else {
            slot.attestations.insert(sender, envelope);
        }
        let required = usize::from(
            self.registry.active().committee().n() - self.registry.active().fault_bound(),
        );
        if slot.attestations.len() < required {
            return Ok(None);
        }
        let entry = CertifiedLedgerEntry {
            statement: statement.clone(),
            attestations: slot.attestations.values().cloned().collect(),
        };
        entry.verify_active(&self.registry, historical_issuer)?;
        Ok(Some(entry))
    }

    fn retain_certified_pending(
        &mut self,
        entry: &CertifiedLedgerEntry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<(), DepositServiceError> {
        entry.verify_active(&self.registry, historical_issuer)?;
        let sequence = entry.statement.sequence;
        if sequence != self.ledger.next_sequence() || entry.statement.previous != self.ledger.head()
        {
            return Err(DepositServiceError::SlotConflict(sequence));
        }
        if let Some(existing) = self.pending.get(&sequence)
            && existing.statement != entry.statement
        {
            return Err(DepositServiceError::SlotConflict(sequence));
        }
        if self.pending.len() >= MAX_PENDING_LEDGER_SLOTS && !self.pending.contains_key(&sequence) {
            return Err(DepositServiceError::TooManyPendingSlots);
        }
        let slot = self.pending.entry(sequence).or_insert_with(|| PendingLedgerSlot {
            statement: entry.statement.clone(),
            attestations: BTreeMap::new(),
        });
        for witness in &entry.attestations {
            if let Some(existing) = slot.attestations.get(&witness.from)
                && existing != witness
            {
                return Err(DepositServiceError::AttestationEquivocation(witness.from));
            }
            slot.attestations.insert(witness.from, witness.clone());
        }
        Ok(())
    }

    fn next_certified_ledger_entry(&self) -> Option<CertifiedLedgerEntry> {
        let required = usize::from(
            self.registry.active().committee().n() - self.registry.active().fault_bound(),
        );
        self.pending
            .values()
            .filter(|slot| slot.attestations.len() >= required)
            .min_by_key(|slot| slot.statement.sequence)
            .map(|slot| CertifiedLedgerEntry {
                statement: slot.statement.clone(),
                attestations: slot.attestations.values().take(required).cloned().collect(),
            })
    }

    /// Whether one observation belongs to the retiring issuer's finite certified prefix.
    ///
    /// Before a fence is certified, pending-handoff observations are deliberately ineligible.
    /// This lets the ledger BA certify exactly one immutable frontier before any further scanner
    /// work can compete with cutover.
    fn observation_is_source_handoff_prefix(
        &self,
        statement: &DepositObservationStatement,
    ) -> bool {
        let Some(_) = self.pending_handoff.as_ref() else {
            return true;
        };
        let Some(fence) = self.pending_handoff_fence.as_ref() else {
            return self
                .observation_checkpoint
                .as_ref()
                .is_some_and(|checkpoint| checkpoint.observation.statement == *statement)
                || self.checkpoint_consensus_lane.as_ref().is_some_and(|lane| {
                    lane.admitted_values.values().any(|admitted| {
                        matches!(
                            &admitted.candidate,
                            DepositIndexCheckpointCandidate::DepositObservation(observation)
                                if observation.statement == *statement
                        )
                    })
                });
        };
        let observed = statement.observed_block();
        observed.height < fence.cutoff.height
            || (observed.height == fence.cutoff.height && observed.hash == fence.cutoff.hash)
    }

    fn has_source_handoff_prefix_observations(&self) -> bool {
        self.pending_observations
            .values()
            .any(|slot| self.observation_is_source_handoff_prefix(&slot.statement))
    }

    /// Rebind every still-uncheckpointed chain fact to the newly active issuer. The local signed
    /// fact tombstone intentionally excludes issuer fields, while all old-issuer attestations are
    /// discarded and must never combine with successor witnesses.
    fn reissue_pending_observations_for_active(
        &mut self,
    ) -> Result<Vec<DepositObservationStatement>, DepositServiceError> {
        if self.observation_checkpoint.is_some() {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let mut obsolete = Vec::with_capacity(self.pending_observations.len());
        for slot in self.pending_observations.values_mut() {
            let old = slot.statement.clone();
            let successor = old.reissue_for_active(&self.registry)?;
            if successor != old {
                obsolete.push(old);
                slot.statement = successor;
                slot.attestations.clear();
            }
        }
        Ok(obsolete)
    }

    fn begin_index_checkpoint(
        &mut self,
        ledger: CertifiedLedgerEntry,
        ledger_artifact: WalletArtifactRef,
        statement: DepositIndexCheckpointStatement,
        reserved_at: u64,
    ) -> Result<(), DepositServiceError> {
        self.committed_checkpoint_selection(&DepositIndexCheckpointCandidate::Ledger(
            ledger.clone(),
        ))?;
        let expected_checkpoint_sequence = self
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        if self.observation_checkpoint.is_some()
            || ledger.statement.sequence != self.ledger.next_sequence()
            || ledger_artifact.wallet_id() != WalletId(ledger.statement.wallet.0)
            || statement.operation()
                != (DepositIndexCheckpointOperation::Ledger {
                    statement: ledger.statement.digest(),
                })
            || ledger.statement.digest() != statement.ledger_decision()
            || ledger.statement.previous != self.ledger.head()
            || statement.ledger_sequence() != ledger.statement.sequence
            || statement.sequence() != expected_checkpoint_sequence
            || statement.previous_head().digest() != self.ledger.portable_index_digest()
            || statement.context().registry_digest() != self.registry.digest()
            || validate_now(reserved_at).is_err()
            || matches!(
                &ledger.statement.payload,
                LedgerPayload::Allocation(allocation) if reserved_at >= allocation.created_at
            )
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        if let Some(existing) = &self.index_checkpoint
            && (existing.ledger.statement != ledger.statement
                || existing.ledger_artifact != ledger_artifact
                || existing.statement != statement
                || existing.reserved_at != reserved_at)
        {
            return Err(DepositServiceError::SlotConflict(ledger.statement.sequence));
        }
        if self.index_checkpoint.is_none() {
            self.index_checkpoint = Some(PendingIndexCheckpointSlot {
                ledger,
                ledger_artifact,
                statement,
                reserved_at,
                witnesses: BTreeMap::new(),
            });
        }
        Ok(())
    }

    fn accept_index_checkpoint_witness(
        &mut self,
        witness: SignedEnvelope,
    ) -> Result<(), DepositServiceError> {
        let checkpoint = self
            .index_checkpoint
            .as_mut()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let committee = self.registry.active().committee();
        Identity::verify_envelope(committee, witness.from, &witness)?;
        if witness.to.is_some()
            || witness.session != checkpoint.statement.slot_session()
            || witness.sequence != checkpoint.statement.sequence()
            || witness.payload != checkpoint.statement.to_bytes()?
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        if let Some(existing) = checkpoint.witnesses.get(&witness.from) {
            if existing != &witness {
                return Err(DepositServiceError::AttestationEquivocation(witness.from));
            }
            return Ok(());
        }
        checkpoint.witnesses.insert(witness.from, witness);
        Ok(())
    }

    fn completed_index_checkpoint(
        &self,
        network: [u8; 32],
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
    ) -> Result<Option<DepositIndexCheckpointCertificate>, DepositServiceError> {
        let checkpoint = self
            .index_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let required = usize::from(
            self.registry.active().committee().n() - self.registry.active().fault_bound(),
        );
        eprintln!(
            "TRACE_CKPT completed_index_checkpoint witnesses={} required={} seq={} parties={:?}",
            checkpoint.witnesses.len(),
            required,
            checkpoint.statement.sequence(),
            checkpoint.witnesses.keys().collect::<Vec<_>>(),
        );
        if checkpoint.witnesses.len() < required {
            return Ok(None);
        }
        let witnesses = checkpoint.witnesses.values().take(required).cloned().collect::<Vec<_>>();
        let selection = self.committed_checkpoint_selection(
            &DepositIndexCheckpointCandidate::Ledger(checkpoint.ledger.clone()),
        )?;
        Ok(Some(DepositIndexCheckpointCertificate::from_witnesses(
            network,
            &self.registry,
            historical_issuer,
            previous,
            &checkpoint.ledger,
            checkpoint.statement.clone(),
            selection,
            witnesses,
        )?))
    }

    /// Peer-originated admission. Enforces the `MAX_PENDING_DEPOSIT_OBSERVATIONS` Byzantine memory
    /// bound so an authenticated-but-hostile committee member cannot grow the reducer's pending
    /// pool with structurally valid observations this party never scanned. Worker-scanned local
    /// detections use [`Self::retain_locally_verified_deposit_observation`], which bypasses the cap.
    fn retain_deposit_observation(
        &mut self,
        statement: DepositObservationStatement,
    ) -> Result<bool, DepositServiceError> {
        self.admit_deposit_observation(statement, true)
    }

    /// Admit `statement` into the bounded pending-observation pool.
    ///
    /// `enforce_peer_cap` gates the `MAX_PENDING_DEPOSIT_OBSERVATIONS` peer memory bound. It is
    /// `true` for every peer-originated path (gossiped statements and certified observations) and
    /// `false` for worker-scanned local detections: those are the authority-of-record, are already
    /// bounded by the confirmed scan cursor, and must never be rejected. If the local path were
    /// capped, a full pool of post-cutoff suffix observations under an active handoff fence would
    /// wedge durable `WorkerEventBatch` replay before its at-least-once ACK, permanently deadlocking
    /// every driver that calls `replay_pending_worker_events` first (see `apply_worker_event_batch`).
    /// Dedup of an already-present output still returns `Ok(false)` regardless of the cap, and all
    /// cryptographic reauthentication is performed by callers on the statement before this method.
    fn admit_deposit_observation(
        &mut self,
        statement: DepositObservationStatement,
        enforce_peer_cap: bool,
    ) -> Result<bool, DepositServiceError> {
        statement.validate_active(&self.registry)?;
        if statement.wallet_id() != self.ledger.wallet_id() {
            return Err(DepositServiceError::WrongWallet);
        }
        if let Some(existing) = self.pending_observations.get(&statement.output()) {
            return if existing.statement == statement {
                Ok(false)
            } else {
                Err(DepositServiceError::ObservationEquivocation)
            };
        }
        if enforce_peer_cap && self.pending_observations.len() >= MAX_PENDING_DEPOSIT_OBSERVATIONS {
            return Err(DepositServiceError::TooManyPendingObservations);
        }
        self.pending_observations.insert(
            statement.output(),
            PendingDepositObservationSlot { statement, attestations: BTreeMap::new() },
        );
        Ok(true)
    }

    fn retain_locally_verified_deposit_observation(
        &mut self,
        statement: DepositObservationStatement,
        verified: &VerifiedLocalDepositObservation,
    ) -> Result<bool, DepositServiceError> {
        if verified.wallet_id() != statement.wallet_id()
            || verified.allocation_statement() != statement.allocation_statement()
            || verified.observation_statement() != statement.digest()
            || verified.output() != statement.output()
            || verified.verification_horizon().height < statement.confirmation_horizon().height
            || (verified.verification_horizon().height == statement.confirmation_horizon().height
                && verified.verification_horizon() != statement.confirmation_horizon())
        {
            return Err(DepositServiceError::InvalidDepositObservation);
        }
        // Worker-scanned local detections are the authority-of-record and are bounded by the
        // confirmed scan cursor, not by the peer memory cap. Bypassing the cap here is what keeps
        // `apply_worker_event_batch` able to admit every durable detection and reach its ACK even
        // when the peer-facing pool is already full of post-cutoff suffix observations.
        self.admit_deposit_observation(statement, false)
    }

    fn accept_deposit_observation_attestation(
        &mut self,
        statement: &DepositObservationStatement,
        attestation: SignedEnvelope,
    ) -> Result<Option<CertifiedDepositObservation>, DepositServiceError> {
        let sender =
            verify_deposit_observation_attestation(statement, &self.registry, &attestation)?;
        let slot = self
            .pending_observations
            .get_mut(&statement.output())
            .ok_or(DepositServiceError::UnknownDepositObservation)?;
        if slot.statement != *statement {
            return Err(DepositServiceError::ObservationEquivocation);
        }
        if let Some(existing) = slot.attestations.get(&sender) {
            if existing != &attestation {
                return Err(DepositServiceError::AttestationEquivocation(sender));
            }
        } else {
            slot.attestations.insert(sender, attestation);
        }
        self.completed_deposit_observation(statement.output())
    }

    fn completed_deposit_observation(
        &self,
        output: WalletOutputId,
    ) -> Result<Option<CertifiedDepositObservation>, DepositServiceError> {
        let slot = self
            .pending_observations
            .get(&output)
            .ok_or(DepositServiceError::UnknownDepositObservation)?;
        let required = usize::from(
            self.registry.active().committee().n() - self.registry.active().fault_bound(),
        );
        if slot.attestations.len() < required {
            return Ok(None);
        }
        let observation = CertifiedDepositObservation {
            statement: slot.statement.clone(),
            attestations: slot.attestations.values().take(required).cloned().collect(),
        };
        let verified = observation.verify_active(&self.registry)?;
        if verified.signers().len() != required {
            return Err(DepositServiceError::InvalidDepositObservation);
        }
        Ok(Some(observation))
    }

    fn retain_certified_deposit_observation(
        &mut self,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositServiceError> {
        let verified = observation.verify_active(&self.registry)?;
        if verified.signers().len() != usize::from(verified.required()) {
            return Err(DepositServiceError::InvalidDepositObservation);
        }
        self.retain_deposit_observation(observation.statement.clone())?;
        let slot = self
            .pending_observations
            .get_mut(&observation.statement.output())
            .ok_or(DepositServiceError::UnknownDepositObservation)?;
        for witness in &observation.attestations {
            let sender = verify_deposit_observation_attestation(
                &observation.statement,
                &self.registry,
                witness,
            )?;
            if let Some(existing) = slot.attestations.get(&sender)
                && existing != witness
            {
                return Err(DepositServiceError::AttestationEquivocation(sender));
            }
            slot.attestations.insert(sender, witness.clone());
        }
        Ok(())
    }

    fn next_certified_deposit_observation(
        &self,
    ) -> Result<Option<CertifiedDepositObservation>, DepositServiceError> {
        let required = usize::from(
            self.registry.active().committee().n() - self.registry.active().fault_bound(),
        );
        let Some(output) = self
            .pending_observations
            .values()
            .filter(|slot| {
                slot.attestations.len() >= required
                    && self.observation_is_source_handoff_prefix(&slot.statement)
            })
            .min_by_key(|slot| (slot.statement.observed_block().height, slot.statement.output()))
            .map(|slot| slot.statement.output())
        else {
            return Ok(None);
        };
        self.completed_deposit_observation(output)
    }

    fn begin_deposit_observation_checkpoint(
        &mut self,
        observation: CertifiedDepositObservation,
        observation_artifact: WalletArtifactRef,
        statement: DepositIndexCheckpointStatement,
        reserved_at: u64,
    ) -> Result<(), DepositServiceError> {
        self.committed_checkpoint_selection(&DepositIndexCheckpointCandidate::DepositObservation(
            observation.clone(),
        ))?;
        let verified = observation.verify_active(&self.registry)?;
        let expected_sequence = self
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        if self.index_checkpoint.is_some()
            || verified.signers().len() != usize::from(verified.required())
            || observation_artifact.wallet_id() != WalletId(self.ledger.wallet_id().0)
            || observation_artifact.kind() != CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
            || statement.sequence() != expected_sequence
            || statement.operation()
                != (DepositIndexCheckpointOperation::DepositObservation {
                    statement: observation.statement.digest(),
                })
            || statement.ledger_sequence()
                != self
                    .ledger
                    .next_sequence()
                    .checked_sub(1)
                    .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            || statement.ledger_decision() != self.ledger.head()
            || statement.previous_head().digest() != self.ledger.portable_index_digest()
            || statement.context().registry_digest() != self.registry.digest()
            || validate_now(reserved_at).is_err()
            || self
                .pending_observations
                .get(&observation.statement.output())
                .is_none_or(|pending| pending.statement != observation.statement)
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        if let Some(existing) = &self.observation_checkpoint
            && (existing.observation != observation
                || existing.observation_artifact != observation_artifact
                || existing.statement != statement
                || existing.reserved_at != reserved_at)
        {
            return Err(DepositServiceError::ObservationEquivocation);
        }
        if self.observation_checkpoint.is_none() {
            self.observation_checkpoint = Some(PendingDepositObservationCheckpointSlot {
                observation,
                observation_artifact,
                statement,
                reserved_at,
                witnesses: BTreeMap::new(),
            });
        }
        Ok(())
    }

    fn accept_deposit_observation_checkpoint_witness(
        &mut self,
        witness: SignedEnvelope,
    ) -> Result<(), DepositServiceError> {
        let checkpoint = self
            .observation_checkpoint
            .as_mut()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let committee = self.registry.active().committee();
        Identity::verify_envelope(committee, witness.from, &witness)?;
        if witness.to.is_some()
            || witness.session != checkpoint.statement.slot_session()
            || witness.sequence != checkpoint.statement.sequence()
            || witness.payload != checkpoint.statement.to_bytes()?
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        if let Some(existing) = checkpoint.witnesses.get(&witness.from) {
            if existing != &witness {
                return Err(DepositServiceError::AttestationEquivocation(witness.from));
            }
            return Ok(());
        }
        checkpoint.witnesses.insert(witness.from, witness);
        Ok(())
    }

    fn completed_deposit_observation_checkpoint(
        &self,
        network: [u8; 32],
        previous: Option<&VerifiedDepositIndexCheckpoint>,
    ) -> Result<Option<DepositIndexCheckpointCertificate>, DepositServiceError> {
        let checkpoint = self
            .observation_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let required = usize::from(
            self.registry.active().committee().n() - self.registry.active().fault_bound(),
        );
        if checkpoint.witnesses.len() < required {
            return Ok(None);
        }
        let witnesses = checkpoint.witnesses.values().take(required).cloned().collect::<Vec<_>>();
        let selection = self.committed_checkpoint_selection(
            &DepositIndexCheckpointCandidate::DepositObservation(checkpoint.observation.clone()),
        )?;
        Ok(Some(DepositIndexCheckpointCertificate::from_deposit_observation_witnesses(
            network,
            &self.registry,
            previous,
            &checkpoint.observation,
            checkpoint.statement.clone(),
            selection,
            witnesses,
        )?))
    }

    fn committed_checkpoint_selection(
        &self,
        expected: &DepositIndexCheckpointCandidate,
    ) -> Result<CommitCertificate, DepositServiceError> {
        let lane = self
            .checkpoint_consensus_lane
            .as_ref()
            .ok_or(DepositServiceError::ConsensusUnavailable)?;
        let commit = lane.reducer.commit().ok_or(DepositServiceError::ConsensusUnavailable)?;
        let candidate = DepositIndexCheckpointCandidate::from_consensus_value(commit.value())?;
        if &candidate != expected
            || lane.purpose
                != (DepositConsensusPurpose::NextIndexCheckpoint {
                    sequence: self
                        .checkpoint_sequence
                        .checked_add(1)
                        .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?,
                })
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        Ok(commit.clone())
    }

    fn adopt_deposit_observation_checkpoint(
        &mut self,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositServiceError> {
        self.committed_checkpoint_selection(&DepositIndexCheckpointCandidate::DepositObservation(
            observation.clone(),
        ))?;
        let checkpoint = self
            .observation_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        if checkpoint.observation != *observation
            || checkpoint.statement.sequence()
                != self
                    .checkpoint_sequence
                    .checked_add(1)
                    .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        self.checkpoint_sequence = checkpoint.statement.sequence();
        self.pending_observations.remove(&observation.statement.output());
        self.observation_checkpoint = None;
        self.checkpoint_consensus_lane = None;
        Ok(())
    }

    fn adopt_certificate(
        &mut self,
        entry: CertifiedLedgerEntry,
        deriver: &DepositAddressDeriver,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        preflight: &VerifiedDepositIndexPreflight,
        transition: &VerifiedDepositIndexTransition,
    ) -> Result<(), DepositServiceError> {
        self.committed_checkpoint_selection(&DepositIndexCheckpointCandidate::Ledger(
            entry.clone(),
        ))?;
        let sequence = entry.statement.sequence;
        let statement = entry.statement.clone();
        let mut candidate = self.clone();
        let checkpoint_sequence = candidate
            .index_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .statement
            .sequence();
        candidate.ledger.advance_certificate(
            &candidate.registry,
            historical_issuer,
            entry,
            preflight,
            transition,
            |address| deriver.verify_address(address).is_ok(),
        )?;
        candidate.pending.remove(&sequence);
        candidate.checkpoint_sequence = checkpoint_sequence;
        candidate.index_checkpoint = None;
        candidate.checkpoint_consensus_lane = None;
        if matches!(&statement.payload, LedgerPayload::HandoffFence(_)) {
            let fence = CertifiedHandoffObservationFence::from_statement(&statement)?;
            if candidate.pending_handoff_fence.as_ref().is_some_and(|existing| existing != &fence) {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            candidate.pending_handoff_fence = Some(fence);
        }
        if let Some(lane) = candidate.consensus_lane.take() {
            if lane.purpose.sequence() != sequence {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            if let Some(committed) = lane.reducer.commit() {
                let decided = DepositConsensusValue::decode(committed.value())?;
                if decided.statement != statement {
                    return Err(DepositServiceError::InvalidProtocolState);
                }
            }
        }
        if let LedgerPayload::Allocation(allocation) = &statement.payload {
            candidate.client_requests.remove(&allocation.request);
        }
        *self = candidate;
        Ok(())
    }

    fn pending_response(
        &self,
        request: DepositAddressRequest,
        status: DepositAddressStatus,
    ) -> Result<DepositAddressResponse, DepositServiceError> {
        let leader = self.current_consensus_leader()?;
        Ok(DepositAddressResponse {
            request: request.request,
            status,
            address: None,
            certificate: None,
            created_at: None,
            expires_at: None,
            leader,
        })
    }

    fn syncing_response(
        &self,
        request: DepositAddressRequest,
    ) -> Result<DepositAddressResponse, DepositServiceError> {
        self.pending_response(request, DepositAddressStatus::Syncing)
    }

    fn validate(&self, deriver: &DepositAddressDeriver) -> Result<(), DepositServiceError> {
        self.validate_inner(deriver)
    }

    /// The ledger was just rebuilt by applying every authenticated archive event. Rechecking its
    /// local cross-index invariants must not materialize a second vector of all certificates.
    fn validate_archive_replay(
        &self,
        deriver: &DepositAddressDeriver,
    ) -> Result<(), DepositServiceError> {
        self.validate_inner(deriver)
    }

    fn validate_inner(&self, deriver: &DepositAddressDeriver) -> Result<(), DepositServiceError> {
        // `MAX_PENDING_DEPOSIT_OBSERVATIONS` is an admission-time peer memory bound, not a structural
        // reducer invariant: worker-scanned local detections are the authority-of-record and may
        // legitimately drive the pool past the cap (e.g. an active handoff fence retains a growing
        // post-cutoff suffix that is ineligible for checkpoint draining). Bounding the durable pool
        // here would resurrect the same capacity deadlock the admission split removes. The pool's
        // memory is instead backstopped by `MAX_REDUCER_BYTES`, enforced by `DepositLocalState`
        // encode/decode, so this check must not cap `pending_observations`.
        if self.version != DEPOSIT_PROTOCOL_VERSION
            || self.registry.wallet() != deriver.wallet_id()
            || self.ledger.wallet_id() != deriver.wallet_id()
            || self.ledger.registry_id() != self.registry.id()
            || self.pending.len() > MAX_PENDING_LEDGER_SLOTS
            || self.client_requests.len() > MAX_PENDING_CLIENT_REQUESTS
            || (self.index_checkpoint.is_some() && self.observation_checkpoint.is_some())
        {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        self.registry.validate()?;
        let active = self.registry.active();
        if let Some(checkpoint) = &self.index_checkpoint {
            self.committed_checkpoint_selection(&DepositIndexCheckpointCandidate::Ledger(
                checkpoint.ledger.clone(),
            ))?;
            let checkpoint_sequence = checkpoint.statement.sequence();
            let ledger_sequence = checkpoint.ledger.statement.sequence;
            let payload = checkpoint.statement.to_bytes()?;
            if self.checkpoint_sequence.checked_add(1) != Some(checkpoint_sequence)
                || ledger_sequence != self.ledger.next_sequence()
                || checkpoint.ledger_artifact.wallet_id() != WalletId(self.ledger.wallet_id().0)
                || checkpoint.statement.operation()
                    != (DepositIndexCheckpointOperation::Ledger {
                        statement: checkpoint.ledger.statement.digest(),
                    })
                || checkpoint.statement.ledger_sequence() != ledger_sequence
                || checkpoint.ledger.statement.digest() != checkpoint.statement.ledger_decision()
                || checkpoint.ledger.statement.previous != self.ledger.head()
                || checkpoint.statement.previous_head().digest()
                    != self.ledger.portable_index_digest()
                || checkpoint.statement.context().registry_digest() != self.registry.digest()
                || validate_now(checkpoint.reserved_at).is_err()
                || matches!(
                    &checkpoint.ledger.statement.payload,
                    LedgerPayload::Allocation(allocation)
                        if checkpoint.reserved_at >= allocation.created_at
                )
                || checkpoint.witnesses.len() > usize::from(active.committee().n())
                || self
                    .pending
                    .get(&ledger_sequence)
                    .is_none_or(|pending| pending.statement != checkpoint.ledger.statement)
            {
                return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
            }
            for (party, witness) in &checkpoint.witnesses {
                if *party != witness.from
                    || Identity::verify_envelope(active.committee(), *party, witness).is_err()
                    || witness.to.is_some()
                    || witness.session != checkpoint.statement.slot_session()
                    || witness.sequence != checkpoint_sequence
                    || witness.payload != payload
                {
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
            }
        }
        for (output, slot) in &self.pending_observations {
            if *output != slot.statement.output()
                || slot.statement.wallet_id() != self.ledger.wallet_id()
                || slot.statement.validate_active(&self.registry).is_err()
                || slot.attestations.len() > usize::from(active.committee().n())
            {
                return Err(DepositServiceError::InvalidDepositObservation);
            }
            let mut senders = BTreeSet::new();
            for (sender, envelope) in &slot.attestations {
                if verify_deposit_observation_attestation(
                    &slot.statement,
                    &self.registry,
                    envelope,
                )? != *sender
                    || !senders.insert(*sender)
                {
                    return Err(DepositServiceError::InvalidDepositObservation);
                }
            }
        }
        if let Some(checkpoint) = &self.observation_checkpoint {
            self.committed_checkpoint_selection(
                &DepositIndexCheckpointCandidate::DepositObservation(
                    checkpoint.observation.clone(),
                ),
            )?;
            let checkpoint_sequence = checkpoint.statement.sequence();
            let payload = checkpoint.statement.to_bytes()?;
            let verified_observation = checkpoint.observation.verify_active(&self.registry)?;
            let expected_observation =
                self.completed_deposit_observation(checkpoint.observation.statement.output())?;
            if self.checkpoint_sequence.checked_add(1) != Some(checkpoint_sequence)
                || verified_observation.signers().len()
                    != usize::from(verified_observation.required())
                || expected_observation.as_ref() != Some(&checkpoint.observation)
                || checkpoint.observation_artifact.wallet_id()
                    != WalletId(self.ledger.wallet_id().0)
                || checkpoint.observation_artifact.kind() != CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
                || checkpoint.statement.operation()
                    != (DepositIndexCheckpointOperation::DepositObservation {
                        statement: checkpoint.observation.statement.digest(),
                    })
                || checkpoint.statement.ledger_sequence()
                    != self
                        .ledger
                        .next_sequence()
                        .checked_sub(1)
                        .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
                || checkpoint.statement.ledger_decision() != self.ledger.head()
                || checkpoint.statement.previous_head().digest()
                    != self.ledger.portable_index_digest()
                || checkpoint.statement.context().registry_digest() != self.registry.digest()
                || validate_now(checkpoint.reserved_at).is_err()
                || checkpoint.witnesses.len() > usize::from(active.committee().n())
            {
                return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
            }
            for (party, witness) in &checkpoint.witnesses {
                if *party != witness.from
                    || Identity::verify_envelope(active.committee(), *party, witness).is_err()
                    || witness.to.is_some()
                    || witness.session != checkpoint.statement.slot_session()
                    || witness.sequence != checkpoint_sequence
                    || witness.payload != payload
                {
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
            }
        }
        if let Some(target) = &self.pending_handoff {
            validate_handoff_target(self, deriver, target)?;
        }
        if self.pending_handoff.is_some() != self.pending_handoff_source.is_some()
            || self.pending_handoff.is_some() != self.pending_handoff_fault_bound.is_some()
            || (self.pending_handoff.is_none() && self.pending_handoff_root.is_some())
            || (self.pending_handoff.is_none() && self.pending_handoff_fence.is_some())
            || (self.pending_handoff_fence.is_some() && self.pending_handoff_root.is_none())
            || self.pending_handoff_root == Some([0; 32])
        {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        if let Some(fence) = &self.pending_handoff_fence {
            fence.validate_shape()?;
            let target =
                self.pending_handoff.as_ref().ok_or(DepositServiceError::InvalidProtocolState)?;
            let LedgerPayload::HandoffFence(statement) = &fence.statement.payload else {
                return Err(DepositServiceError::InvalidProtocolState);
            };
            if fence.statement.wallet != self.ledger.wallet_id()
                || fence.statement.issuer_epoch != self.registry.active_epoch()
                || fence.statement.issuer_committee != active.committee().digest()
                || fence.statement.issuer_activation != active.activation()
                || fence.statement.sequence.checked_add(1) != Some(self.ledger.next_sequence())
                || fence.statement.digest() != self.ledger.head()
                || statement.target_epoch() != target.committee.epoch
                || statement.target_committee() != target.committee.digest()
                || statement.target_activation() != target.activation_digest()?
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
        }
        let source_quota = pending_client_request_quota(active.committee())?;
        for (request, pending) in &self.client_requests {
            if *request != pending.request.request
                || validate_deposit_address_request(pending.request).is_err()
                || pending.sources.is_empty()
                || pending.sources.len() > usize::from(active.committee().n())
                || pending.sources.iter().any(|source| active.committee().member(*source).is_err())
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
        }
        if active.committee().members.iter().any(|member| {
            self.client_requests
                .values()
                .filter(|pending| pending.sources.contains(&member.id))
                .count()
                > source_quota
        }) {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        if let Some(lane) = &self.consensus_lane {
            validate_deposit_consensus_lane(self, deriver, lane, None)?;
        }
        if let Some(lane) = &self.checkpoint_consensus_lane {
            validate_deposit_checkpoint_consensus_lane(self, lane, None)?;
        }
        if (self.index_checkpoint.is_some() || self.observation_checkpoint.is_some())
            && self
                .checkpoint_consensus_lane
                .as_ref()
                .and_then(|lane| lane.reducer.commit())
                .is_none()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        for (sequence, slot) in &self.pending {
            if *sequence != slot.statement.sequence
                || slot.statement.sequence != self.ledger.next_sequence()
                || slot.statement.previous != self.ledger.head()
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            if let LedgerPayload::Allocation(allocation) = &slot.statement.payload {
                if allocation.address.index() != self.ledger.next_index()
                    || deriver.verify_address(&allocation.address).is_err()
                {
                    return Err(DepositServiceError::InvalidProtocolState);
                }
            }
            let mut senders = BTreeSet::new();
            for (sender, envelope) in &slot.attestations {
                if verify_attestation(&slot.statement, &self.registry, envelope)? != *sender
                    || !senders.insert(*sender)
                {
                    return Err(DepositServiceError::InvalidProtocolState);
                }
            }
        }
        Ok(())
    }
}

/// Snapshot-local protocol state. In particular this never embeds `CompactEpochRegistry`,
/// `CompactLedgerCursor`, or any quorum certificate. Those are reconstructed from the two archive
/// heads before these local signer locks and observations are accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositLocalState {
    version: u16,
    local_party: PartyId,
    checkpoint_sequence: u64,
    pending: BTreeMap<u64, PendingLedgerSlot>,
    pending_observations: BTreeMap<WalletOutputId, PendingDepositObservationSlot>,
    client_requests: BTreeMap<LedgerRequestId, PendingClientRequest>,
    pending_handoff: Option<EpochPublic>,
    pending_handoff_source: Option<EpochPublic>,
    pending_handoff_fault_bound: Option<u16>,
    pending_handoff_root: Option<[u8; 32]>,
    pending_handoff_fence: Option<CertifiedHandoffObservationFence>,
    consensus_lane: Option<DurableDepositConsensusLane>,
    checkpoint_consensus_lane: Option<DurableDepositCheckpointConsensusLane>,
    index_checkpoint: Option<PendingIndexCheckpointSlot>,
    observation_checkpoint: Option<PendingDepositObservationCheckpointSlot>,
}

impl DepositLocalState {
    fn from_protocol(protocol: &DepositProtocolState) -> Self {
        Self {
            version: DEPOSIT_LOCAL_STATE_VERSION,
            local_party: protocol.local_party,
            checkpoint_sequence: protocol.checkpoint_sequence,
            pending: protocol.pending.clone(),
            pending_observations: protocol.pending_observations.clone(),
            client_requests: protocol.client_requests.clone(),
            pending_handoff: protocol.pending_handoff.clone(),
            pending_handoff_source: protocol.pending_handoff_source.clone(),
            pending_handoff_fault_bound: protocol.pending_handoff_fault_bound,
            pending_handoff_root: protocol.pending_handoff_root,
            pending_handoff_fence: protocol.pending_handoff_fence.clone(),
            consensus_lane: protocol.consensus_lane.clone(),
            checkpoint_consensus_lane: protocol.checkpoint_consensus_lane.clone(),
            index_checkpoint: protocol.index_checkpoint.clone(),
            observation_checkpoint: protocol.observation_checkpoint.clone(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, DepositServiceError> {
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositServiceError::Serialization)?;
        if bytes.len() > MAX_REDUCER_BYTES {
            return Err(DepositServiceError::ReducerTooLarge);
        }
        Ok(bytes)
    }

    fn decode(
        bytes: &[u8],
        registry: CompactEpochRegistry,
        ledger: CompactLedgerCursor,
        deriver: &DepositAddressDeriver,
        local_party: PartyId,
        consensus_network: [u8; 32],
    ) -> Result<DepositProtocolState, DepositServiceError> {
        if bytes.len() > MAX_REDUCER_BYTES {
            return Err(DepositServiceError::ReducerTooLarge);
        }
        let (version, _) = postcard::take_from_bytes::<u16>(bytes)
            .map_err(|_| DepositServiceError::Serialization)?;
        let local = match version {
            DEPOSIT_LOCAL_STATE_VERSION => {
                let (local, trailing) = postcard::take_from_bytes::<Self>(bytes)
                    .map_err(|_| DepositServiceError::Serialization)?;
                if !trailing.is_empty() {
                    return Err(DepositServiceError::TrailingBytes);
                }
                if local.encode()? != bytes {
                    return Err(DepositServiceError::NonCanonicalSnapshot);
                }
                local
            }
            _ => return Err(DepositServiceError::UnsupportedVersion(version)),
        };
        if local.local_party != local_party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let protocol = DepositProtocolState {
            version: DEPOSIT_PROTOCOL_VERSION,
            local_party: local.local_party,
            registry,
            ledger,
            checkpoint_sequence: local.checkpoint_sequence,
            pending: local.pending,
            pending_observations: local.pending_observations,
            client_requests: local.client_requests,
            pending_handoff: local.pending_handoff,
            pending_handoff_source: local.pending_handoff_source,
            pending_handoff_fault_bound: local.pending_handoff_fault_bound,
            pending_handoff_root: local.pending_handoff_root,
            pending_handoff_fence: local.pending_handoff_fence,
            consensus_lane: local.consensus_lane,
            checkpoint_consensus_lane: local.checkpoint_consensus_lane,
            index_checkpoint: local.index_checkpoint,
            observation_checkpoint: local.observation_checkpoint,
        };
        protocol.validate_archive_replay(deriver)?;
        if let Some(lane) = &protocol.consensus_lane {
            validate_deposit_consensus_lane(&protocol, deriver, lane, Some(consensus_network))?;
        }
        if let Some(lane) = &protocol.checkpoint_consensus_lane {
            validate_deposit_checkpoint_consensus_lane(&protocol, lane, Some(consensus_network))?;
        }
        Ok(protocol)
    }
}

const DEPOSIT_CONSENSUS_APPLICATION: &[u8] = b"deposit-ledger/v1";

fn deposit_consensus_domain() -> [u8; 32] {
    *blake3::Hasher::new_derive_key("threshold-monero/deposit-ledger-consensus-domain/v1")
        .finalize()
        .as_bytes()
}

fn deposit_consensus_session(
    binding: &ConsensusBinding,
    committee: &Committee,
    fault_bound: u16,
    sequence: u64,
    previous: [u8; 32],
) -> Result<SessionId, DepositServiceError> {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/deposit-ledger-consensus-session/v1");
    hasher.update(&binding.domain);
    hasher.update(&(binding.application.len() as u64).to_le_bytes());
    hasher.update(&binding.application);
    hasher.update(&binding.wallet);
    hasher.update(&binding.network);
    hasher.update(&binding.registry);
    hasher.update(&binding.activation);
    hasher.update(&committee.digest());
    hasher.update(&fault_bound.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&previous);
    let session = SessionId(*hasher.finalize().as_bytes());
    if session.0 == [0_u8; 32] {
        return Err(DepositServiceError::InvalidProtocolState);
    }
    Ok(session)
}

fn deposit_consensus_context(
    protocol: &DepositProtocolState,
    wallet: DepositWalletId,
    network: [u8; 32],
) -> Result<ConsensusContext, DepositServiceError> {
    let active = protocol.registry.active();
    let sequence = protocol.ledger.next_sequence();
    let previous = protocol.ledger.head();
    let binding = ConsensusBinding {
        domain: deposit_consensus_domain(),
        application: DEPOSIT_CONSENSUS_APPLICATION.to_vec(),
        wallet: wallet.0,
        network,
        registry: protocol.registry.digest(),
        activation: active.activation_binding(),
    };
    let session = deposit_consensus_session(
        &binding,
        active.committee(),
        active.fault_bound(),
        sequence,
        previous,
    )?;
    Ok(ConsensusContext::new(
        binding,
        session,
        active.committee().clone(),
        active.fault_bound(),
        sequence,
        sequence,
        previous,
    )?)
}

fn validate_deposit_consensus_lane(
    protocol: &DepositProtocolState,
    deriver: &DepositAddressDeriver,
    lane: &DurableDepositConsensusLane,
    trusted_network: Option<[u8; 32]>,
) -> Result<(), DepositServiceError> {
    if lane.version != DEPOSIT_CONSENSUS_LANE_VERSION
        || lane.reducer.local_party() != protocol.local_party
        || lane.purpose.sequence() != protocol.ledger.next_sequence()
        || lane.deadline_view != lane.reducer.view()
        || lane.deadline_unix_ms == 0
        || lane.admitted_values.is_empty()
        || lane.admitted_values.len() > MAX_ADMITTED_CONSENSUS_VALUES
    {
        return Err(DepositServiceError::InvalidProtocolState);
    }
    let expected = deposit_consensus_context(
        protocol,
        deriver.wallet_id(),
        trusted_network.unwrap_or(lane.reducer.context().binding().network),
    )?;
    if lane.reducer.context() != &expected {
        return Err(DepositServiceError::InvalidProtocolState);
    }
    for (digest, admitted) in &lane.admitted_values {
        let value = DepositConsensusValue::with_evidence(
            admitted.statement.clone(),
            admitted.terminal_evidence.clone(),
        )?;
        if admitted.admitted_at == 0
            || admitted.statement.sequence != lane.purpose.sequence()
            || value.digest() != *digest
            || validate_deposit_consensus_value(
                protocol,
                deriver,
                None,
                &value,
                admitted.admitted_at,
                false,
                lane.purpose,
                trusted_network,
            )
            .is_err()
        {
            return Err(DepositServiceError::InvalidProtocolState);
        }
    }
    lane.reducer.validate_application_values(|value| {
        lane.admitted_values.get(&value.digest()).is_some_and(|admitted| {
            DepositConsensusValue::decode(value).is_ok_and(|decoded| {
                decoded.statement == admitted.statement
                    && decoded.terminal_evidence == admitted.terminal_evidence
            }) && validate_deposit_consensus_value(
                protocol,
                deriver,
                None,
                value,
                admitted.admitted_at,
                false,
                lane.purpose,
                trusted_network,
            )
            .is_ok()
        })
    })?;
    match lane.reducer.commit() {
        Some(commit) => {
            let decoded = DepositConsensusValue::decode(commit.value())?;
            let admitted = lane
                .admitted_values
                .get(&commit.value().digest())
                .ok_or(DepositServiceError::InvalidProtocolState)?;
            if admitted.statement != decoded.statement
                || admitted.terminal_evidence != decoded.terminal_evidence
                || protocol
                    .pending
                    .get(&decoded.statement.sequence)
                    .is_none_or(|slot| slot.statement != decoded.statement)
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
        }
        None if !protocol.pending.is_empty() => {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        None => {}
    }
    Ok(())
}

fn validate_checkpoint_candidate_for_protocol(
    protocol: &DepositProtocolState,
    candidate: &DepositIndexCheckpointCandidate,
) -> Result<(), DepositServiceError> {
    let active = protocol.registry.active();
    let required = usize::from(active.committee().n() - active.fault_bound());
    match candidate {
        DepositIndexCheckpointCandidate::Ledger(entry) => {
            if entry.attestations.len() != required
                || entry.statement.sequence != protocol.ledger.next_sequence()
                || entry.statement.previous != protocol.ledger.head()
                || protocol
                    .pending
                    .get(&entry.statement.sequence)
                    .is_none_or(|slot| slot.statement != entry.statement)
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            let mut previous = None;
            for witness in &entry.attestations {
                if previous.is_some_and(|party| party >= witness.from)
                    || verify_attestation(&entry.statement, &protocol.registry, witness)?
                        != witness.from
                    || protocol
                        .pending
                        .get(&entry.statement.sequence)
                        .and_then(|slot| slot.attestations.get(&witness.from))
                        != Some(witness)
                {
                    return Err(DepositServiceError::InvalidConsensusValue);
                }
                previous = Some(witness.from);
            }
        }
        DepositIndexCheckpointCandidate::DepositObservation(observation) => {
            let verified = observation.verify_active(&protocol.registry)?;
            if verified.signers().len() != required
                || !protocol.observation_is_source_handoff_prefix(&observation.statement)
                || protocol
                    .pending_observations
                    .get(&observation.statement.output())
                    .is_none_or(|slot| slot.statement != observation.statement)
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            let pending = &protocol.pending_observations[&observation.statement.output()];
            if observation
                .attestations
                .iter()
                .any(|witness| pending.attestations.get(&witness.from) != Some(witness))
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
        }
    }
    Ok(())
}

fn validate_deposit_checkpoint_consensus_lane(
    protocol: &DepositProtocolState,
    lane: &DurableDepositCheckpointConsensusLane,
    trusted_network: Option<[u8; 32]>,
) -> Result<(), DepositServiceError> {
    let checkpoint_sequence = protocol
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
    let purpose = DepositConsensusPurpose::NextIndexCheckpoint { sequence: checkpoint_sequence };
    if lane.version != DEPOSIT_CHECKPOINT_CONSENSUS_LANE_VERSION
        || lane.purpose != purpose
        || lane.reducer.local_party() != protocol.local_party
        || lane.deadline_view != lane.reducer.view()
        || lane.deadline_unix_ms == 0
        || lane.admitted_values.is_empty()
        || lane.admitted_values.len() > MAX_ADMITTED_CONSENSUS_VALUES
    {
        return Err(DepositServiceError::InvalidProtocolState);
    }
    let network = trusted_network.unwrap_or(lane.reducer.context().binding().network);
    let expected = deposit_index_checkpoint_consensus_context_from_digest(
        network,
        &protocol.registry,
        checkpoint_sequence,
        protocol.ledger.portable_index_digest(),
    )?;
    if lane.reducer.context() != &expected {
        return Err(DepositServiceError::InvalidProtocolState);
    }
    for (digest, admitted) in &lane.admitted_values {
        let value = admitted.candidate.to_consensus_value()?;
        if admitted.admitted_at == 0
            || value.digest() != *digest
            || validate_checkpoint_candidate_for_protocol(protocol, &admitted.candidate).is_err()
        {
            return Err(DepositServiceError::InvalidProtocolState);
        }
    }
    lane.reducer.validate_application_values(|value| {
        lane.admitted_values.get(&value.digest()).is_some_and(|admitted| {
            DepositIndexCheckpointCandidate::from_consensus_value(value)
                .is_ok_and(|candidate| candidate == admitted.candidate)
                && validate_checkpoint_candidate_for_protocol(protocol, &admitted.candidate).is_ok()
        })
    })?;
    Ok(())
}

fn validate_deposit_consensus_statement(
    protocol: &DepositProtocolState,
    deriver: &DepositAddressDeriver,
    statement: &LedgerStatement,
    admitted_at: u64,
    purpose: DepositConsensusPurpose,
) -> Result<(), DepositServiceError> {
    validate_now(admitted_at)?;
    match (&statement.payload, purpose) {
        (
            LedgerPayload::Allocation(allocation),
            DepositConsensusPurpose::NextLedgerSlot { sequence },
        ) if sequence == statement.sequence => {
            validate_deposit_address_request(DepositAddressRequest {
                request: allocation.request,
                binding: allocation.binding,
            })
            .map_err(|_| DepositServiceError::InvalidConsensusValue)?;
            if let Some(pending) = protocol.client_requests.get(&allocation.request)
                && pending.request.binding != allocation.binding
            {
                return Err(DepositServiceError::RequestEquivocation);
            }
        }
        (
            LedgerPayload::HandoffFence(fence),
            DepositConsensusPurpose::NextLedgerSlot { sequence },
        ) if sequence == statement.sequence => {
            if protocol.pending_handoff_fence.is_some() {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            let target = protocol
                .pending_handoff
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            validate_handoff_target(protocol, deriver, target)?;
            let source = protocol
                .pending_handoff_source
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            let verified_target = VerifiedRegistryHandoffTarget::from_verified_activation(
                Some(source),
                target.clone(),
                protocol
                    .pending_handoff_fault_bound
                    .ok_or(DepositServiceError::ConsensusUnavailable)?,
                protocol.pending_handoff_root.ok_or(DepositServiceError::ConsensusUnavailable)?,
                deriver,
            )?;
            let expected = LedgerStatement::handoff_fence(
                &protocol.registry,
                protocol.ledger.next_sequence(),
                protocol.ledger.head(),
                &verified_target,
                fence.cutoff(),
            )?;
            if &expected != statement {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
        }
        (LedgerPayload::Handoff(handoff), DepositConsensusPurpose::NextLedgerSlot { sequence })
            if sequence == statement.sequence =>
        {
            if protocol.pending_handoff_fence.is_none()
                || protocol.has_source_handoff_prefix_observations()
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            let target = protocol
                .pending_handoff
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            validate_handoff_target(protocol, deriver, target)?;
            let source = protocol
                .pending_handoff_source
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            let verified_target = VerifiedRegistryHandoffTarget::from_verified_activation(
                Some(source),
                target.clone(),
                protocol
                    .pending_handoff_fault_bound
                    .ok_or(DepositServiceError::ConsensusUnavailable)?,
                protocol.pending_handoff_root.ok_or(DepositServiceError::ConsensusUnavailable)?,
                deriver,
            )?;
            let expected = LedgerStatement::handoff(
                &protocol.registry,
                protocol.ledger.next_sequence(),
                protocol.ledger.head(),
                protocol.ledger.portable_index_digest(),
                &verified_target,
                protocol.ledger.next_index(),
            )?;
            if &expected != statement {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
        }
        (
            LedgerPayload::ConsolidationCompletion(completion),
            DepositConsensusPurpose::NextLedgerSlot { sequence },
        ) if sequence == statement.sequence && completion.id().0 != [0; 32] => {}
        (
            LedgerPayload::ConsolidationAbandonment(abandonment),
            DepositConsensusPurpose::NextLedgerSlot { sequence },
        ) if sequence == statement.sequence && abandonment.id().0 != [0; 32] => {}
        (
            LedgerPayload::LateConsolidationSettlement(settlement),
            DepositConsensusPurpose::NextLedgerSlot { sequence },
        ) if sequence == statement.sequence && settlement.id().0 != [0; 32] => {}
        _ => return Err(DepositServiceError::InvalidConsensusValue),
    }
    let active = protocol.registry.active();
    if statement.wallet != protocol.ledger.wallet_id()
        || statement.sequence != protocol.ledger.next_sequence()
        || statement.previous != protocol.ledger.head()
        || statement.issuer_epoch != active.epoch()
        || statement.issuer_committee != active.committee().digest()
        || statement.issuer_activation != active.activation()
    {
        return Err(DepositServiceError::InvalidConsensusValue);
    }
    Ok(())
}

fn validate_handoff_target(
    protocol: &DepositProtocolState,
    deriver: &DepositAddressDeriver,
    target: &EpochPublic,
) -> Result<(), DepositServiceError> {
    target.validate()?;
    if target.committee.epoch
        != protocol.registry.active_epoch().checked_add(1).ok_or(DepositServiceError::WrongEpoch)?
        || target.group_key_bytes() != deriver.root_spend_key()
    {
        return Err(DepositServiceError::WrongEpoch);
    }
    Ok(())
}

fn validate_trusted_handoff_target(
    scenario: &Scenario,
    protocol: &DepositProtocolState,
    deriver: &DepositAddressDeriver,
    target: &EpochPublic,
) -> Result<TrustedHandoffTarget, DepositServiceError> {
    validate_handoff_target(protocol, deriver, target)?;
    let active = protocol.registry.active();
    validate_trusted_committee_transition(
        scenario,
        active.committee(),
        active.fault_bound(),
        &target.committee,
    )
}

/// Locally trusted policy for one exact epoch transition.
///
/// Configured scenario epochs remain byte-for-byte pinned. Once that finite chain is exhausted,
/// the only transition the deposit registry accepts is a proactive refresh of the active
/// committee: the signing access structure remains fixed while every selected identity supplies
/// a fresh receiver key. Stable scenario identities may replace a silent member. The caller still
/// has to supply the
/// old-quorum terminal handoff certificate before installing the returned fault bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrustedHandoffTarget {
    fault_bound: u16,
}

fn validate_trusted_committee_transition(
    scenario: &Scenario,
    source: &Committee,
    source_fault_bound: u16,
    target: &Committee,
) -> Result<TrustedHandoffTarget, DepositServiceError> {
    target.validate()?;
    if source.epoch.checked_add(1) != Some(target.epoch) {
        return Err(DepositServiceError::WrongEpoch);
    }

    if let Some(policy) = scenario.configured_key_rotation_target_policy(source)? {
        let eligible = policy.eligible();
        let eligible_members = eligible.by_id();
        let target_members = target.by_id();
        if target.epoch != eligible.epoch
            || target.threshold != eligible.threshold
            || target.n() != policy.desired_n()
            || target_members.iter().any(|(party, member)| {
                eligible_members
                    .get(party)
                    .is_none_or(|eligible| eligible.signing_key != member.signing_key)
            })
            || target_members.iter().any(|(_, member)| {
                source
                    .members
                    .iter()
                    .chain(eligible.members.iter())
                    .any(|prior| prior.encryption_key == member.encryption_key)
            })
        {
            return Err(DepositServiceError::WrongEpoch);
        }
        return Ok(TrustedHandoffTarget { fault_bound: policy.target_fault_bound() });
    }

    // Scenario validation makes its configured epochs contiguous from zero. Consequently an
    // unconfigured immediate successor is necessarily beyond, rather than inside, that pinned
    // chain. Keep this explicit so a malformed in-memory scenario cannot turn a gap into a
    // dynamic trust root.
    let configured_len =
        u64::try_from(scenario.committees.len()).map_err(|_| DepositServiceError::WrongEpoch)?;
    if target.epoch < configured_len
        || target.threshold != source.threshold
        || target.n() != source.n()
    {
        return Err(DepositServiceError::WrongEpoch);
    }

    let target_members = target.by_id();
    if target_members.iter().any(|(party, member)| {
        scenario.party(*party).map_or(true, |eligible| eligible.signing_key.0 != member.signing_key)
    }) {
        return Err(DepositServiceError::WrongEpoch);
    }
    if target.members.iter().any(|target_member| {
        source
            .members
            .iter()
            .any(|source_member| source_member.encryption_key == target_member.encryption_key)
    }) {
        return Err(DepositServiceError::WrongEpoch);
    }
    target.validate_async_security_with_faults(source_fault_bound)?;
    Ok(TrustedHandoffTarget { fault_bound: source_fault_bound })
}

fn handoff_consensus_purpose(
    sequence: u64,
    _target: &EpochPublic,
) -> Result<DepositConsensusPurpose, DepositServiceError> {
    Ok(DepositConsensusPurpose::NextLedgerSlot { sequence })
}

fn completion_consensus_purpose(
    statement: &LedgerStatement,
    evidence: &ConsolidationCompletionEvidence,
) -> Result<DepositConsensusPurpose, DepositServiceError> {
    let LedgerPayload::ConsolidationCompletion(_) = &statement.payload else {
        return Err(DepositServiceError::InvalidConsensusValue);
    };
    if evidence.family == [0; 32] {
        return Err(DepositServiceError::InvalidConsensusValue);
    }
    Ok(DepositConsensusPurpose::NextLedgerSlot { sequence: statement.sequence })
}

fn validate_consensus_purpose(
    protocol: &DepositProtocolState,
    deriver: &DepositAddressDeriver,
    purpose: DepositConsensusPurpose,
    lane_exists: bool,
) -> Result<(), DepositServiceError> {
    if purpose.sequence() != protocol.ledger.next_sequence() {
        return Err(DepositServiceError::ConsensusUnavailable);
    }
    match purpose {
        DepositConsensusPurpose::NextLedgerSlot { .. } => {
            if !lane_exists && let Some(target) = protocol.pending_handoff.as_ref() {
                validate_handoff_target(protocol, deriver, target)?;
            }
        }
        DepositConsensusPurpose::NextIndexCheckpoint { .. } => {
            return Err(DepositServiceError::ConsensusUnavailable);
        }
    }
    Ok(())
}

#[derive(Default)]
struct DepositConsensusHostEffects {
    messages: Vec<(u64, PartyId, DepositOperation, Vec<u8>)>,
    prune: Option<DepositConsensusOutboxScope>,
    terminal: Option<(LedgerStatement, ConsolidationTerminalEvidence)>,
    committed: Option<AdmittedDepositConsensusValue>,
}

#[derive(Clone)]
struct ValidatedDepositConsensusValue {
    digest: ConsensusValueDigest,
    admitted: AdmittedDepositConsensusValue,
    registration: Option<DepositSubaddressIndex>,
}

fn validate_deposit_consensus_value(
    protocol: &DepositProtocolState,
    deriver: &DepositAddressDeriver,
    worker: Option<&DepositWorkerState>,
    value: &ConsensusValue,
    admitted_at: u64,
    require_client_request: bool,
    purpose: DepositConsensusPurpose,
    expected_network: Option<[u8; 32]>,
) -> Result<ValidatedDepositConsensusValue, DepositServiceError> {
    let decoded = DepositConsensusValue::decode(value)?;
    validate_deposit_consensus_statement(
        protocol,
        deriver,
        &decoded.statement,
        admitted_at,
        purpose,
    )?;
    let registration = match &decoded.statement.payload {
        LedgerPayload::Allocation(allocation) => {
            if decoded.terminal_evidence.is_some() {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            // The recognition anchor is authenticated against the live scanner at genuine
            // admission (every caller that admits an untrusted or freshly proposed value passes
            // `Some(worker)`). Worker-free calls only re-validate the party's own already-admitted
            // durable lane for local self-consistency (e.g. `encode_local`, which has no access to
            // the worker that lives in `DepositRuntime`). Requiring a worker there made every
            // allocation lane impossible to encode, wedging ledger consensus; defer the anchor
            // check to the worker-bearing admission path, mirroring the late-settlement arm below.
            if let Some(worker) = worker {
                worker.scan_state().verify_recognition_anchor(allocation.recognition_anchor)?;
            }
            if require_client_request
                && protocol.client_requests.get(&allocation.request).is_none_or(|pending| {
                    pending.request.request != allocation.request
                        || pending.request.binding != allocation.binding
                })
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            Some(allocation.address.index())
        }
        LedgerPayload::HandoffFence(fence) => {
            if decoded.terminal_evidence.is_some()
                || protocol.observation_checkpoint.is_some()
                || protocol.checkpoint_consensus_lane.is_some()
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            let worker = worker.ok_or(DepositServiceError::MissingScannerAnchor)?;
            // The fence is a checkpoint at or behind the beginning of the retained reorg
            // window, never the mutable confirmed tip. Every voter must authenticate its exact
            // height and hash before admitting the value. A normal rollback cannot cross this
            // point; a daemon branch which does cross it trips the worker's AnchorMismatch path
            // and therefore fails closed instead of silently repartitioning observations.
            worker
                .scan_state()
                .verify_recognition_anchor(fence.cutoff())
                .map_err(|_| DepositServiceError::InvalidConsensusValue)?;
            None
        }
        LedgerPayload::Handoff(_) => {
            if decoded.terminal_evidence.is_some()
                || protocol.observation_checkpoint.is_some()
                || protocol.checkpoint_consensus_lane.is_some()
                || protocol.has_source_handoff_prefix_observations()
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            None
        }
        LedgerPayload::ConsolidationCompletion(completion) => {
            let Some(ConsolidationTerminalEvidence::Completion(evidence)) =
                decoded.terminal_evidence.as_ref()
            else {
                return Err(DepositServiceError::InvalidConsensusValue);
            };
            if completion_consensus_purpose(&decoded.statement, evidence)? != purpose {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            evidence.verify(protocol, completion, expected_network)?;
            None
        }
        LedgerPayload::ConsolidationAbandonment(abandonment) => {
            let Some(ConsolidationTerminalEvidence::Abandonment(evidence)) =
                decoded.terminal_evidence.as_ref()
            else {
                return Err(DepositServiceError::InvalidConsensusValue);
            };
            let network = expected_network.ok_or(DepositServiceError::InvalidConsensusValue)?;
            if (DepositConsensusPurpose::NextLedgerSlot { sequence: decoded.statement.sequence })
                != purpose
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            evidence.verify(protocol, abandonment, network)?;
            None
        }
        LedgerPayload::LateConsolidationSettlement(settlement) => {
            let Some(ConsolidationTerminalEvidence::LateSettlement(evidence)) =
                decoded.terminal_evidence.as_ref()
            else {
                return Err(DepositServiceError::InvalidConsensusValue);
            };
            let network = expected_network.ok_or(DepositServiceError::InvalidConsensusValue)?;
            if (DepositConsensusPurpose::NextLedgerSlot { sequence: decoded.statement.sequence })
                != purpose
            {
                return Err(DepositServiceError::InvalidConsensusValue);
            }
            evidence.verify(protocol, settlement, network)?;
            if let Some(worker) = worker {
                validate_late_settlement_observation_locally(worker, settlement)?;
            }
            None
        }
    };
    Ok(ValidatedDepositConsensusValue {
        digest: value.digest(),
        admitted: AdmittedDepositConsensusValue {
            admitted_at,
            statement: decoded.statement,
            terminal_evidence: decoded.terminal_evidence,
        },
        registration,
    })
}

fn verified_terminal_admission(
    protocol: &DepositProtocolState,
    statement: &LedgerStatement,
    network: [u8; 32],
) -> Result<Option<VerifiedTerminalLedgerAdmission>, DepositServiceError> {
    let Some(lane) = protocol.consensus_lane.as_ref() else {
        return if matches!(
            statement.payload,
            LedgerPayload::ConsolidationCompletion(_)
                | LedgerPayload::ConsolidationAbandonment(_)
                | LedgerPayload::LateConsolidationSettlement(_)
        ) {
            Err(DepositServiceError::InvalidPortableTerminalEvidence)
        } else {
            Ok(None)
        };
    };
    let commit = lane.reducer.commit().ok_or(DepositServiceError::ConsensusUnavailable)?;
    let admitted = lane
        .admitted_values
        .get(&commit.value().digest())
        .ok_or(DepositServiceError::InvalidConsensusValue)?;
    if admitted.statement != *statement {
        return Err(DepositServiceError::InvalidConsensusValue);
    }
    let evidence_digest = match (&statement.payload, admitted.terminal_evidence.as_ref()) {
        (
            LedgerPayload::ConsolidationCompletion(completion),
            Some(ConsolidationTerminalEvidence::Completion(evidence)),
        ) => {
            evidence.verify(protocol, completion, Some(network))?;
            evidence.digest()?
        }
        (
            LedgerPayload::ConsolidationAbandonment(abandonment),
            Some(ConsolidationTerminalEvidence::Abandonment(evidence)),
        ) => {
            evidence.verify(protocol, abandonment, network)?;
            evidence.digest()?
        }
        (
            LedgerPayload::LateConsolidationSettlement(settlement),
            Some(ConsolidationTerminalEvidence::LateSettlement(evidence)),
        ) => {
            evidence.verify(protocol, settlement, network)?;
            evidence.digest()?
        }
        (
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_),
            None,
        ) => return Ok(None),
        _ => return Err(DepositServiceError::InvalidPortableTerminalEvidence),
    };
    Ok(Some(VerifiedTerminalLedgerAdmission::from_verified_consensus(
        &protocol.registry,
        statement,
        evidence_digest,
    )?))
}

/// Reproduce a proposed late-settlement observation from this party's own retained scanner state.
///
/// The portable current-committee BA certificate is meaningful only because every honest voter
/// performs this check before admitting the value. Restored lane state may omit `worker` because
/// the admission and local scanner snapshot were already sealed by the same authenticated CAS.
fn validate_late_settlement_observation_locally(
    worker: &DepositWorkerState,
    settlement: &LateConsolidationSettlementStatement,
) -> Result<(), DepositServiceError> {
    let completion = settlement.historical_completion();
    let matching = worker.reconcile_sweep_family_settlements()?.into_iter().any(|evidence| {
        evidence.sweep == completion.plan().id
            && evidence.transaction_id() == completion.transaction_id()
            && evidence.signed_transaction == *completion.signed_transaction()
            && evidence.block == settlement.inclusion()
    });
    let scan = worker.scan_state();
    if !matching
        || worker.config().confirmation_depth != settlement.finality_depth()
        || scan.chain_point(settlement.inclusion().height) != Some(settlement.inclusion())
        || scan.chain_point(settlement.observation_tip().height)
            != Some(settlement.observation_tip())
        || scan.tip().height < settlement.observation_tip().height
    {
        return Err(DepositServiceError::InvalidLateConsolidationSettlement);
    }
    Ok(())
}

fn merge_consensus_steps(
    mut left: ConsensusStep,
    right: ConsensusStep,
) -> Result<ConsensusStep, DepositServiceError> {
    left.broadcast.extend(right.broadcast);
    merge_optional_consensus_effect(
        &mut left.relay_view_certificate,
        right.relay_view_certificate,
    )?;
    merge_optional_consensus_effect(
        &mut left.relay_commit_certificate,
        right.relay_commit_certificate,
    )?;
    merge_optional_consensus_effect(&mut left.commit, right.commit)?;
    left.evidence.extend(right.evidence);
    if let Some(view) = right.entered_view {
        if left.entered_view.is_some_and(|existing| existing != view) {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        left.entered_view = Some(view);
    }
    left.duplicate &= right.duplicate;
    left.changed |= right.changed;
    Ok(left)
}

fn merge_optional_consensus_effect<T: Eq>(
    target: &mut Option<T>,
    incoming: Option<T>,
) -> Result<(), DepositServiceError> {
    if let Some(incoming) = incoming {
        if target.as_ref().is_some_and(|existing| existing != &incoming) {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        *target = Some(incoming);
    }
    Ok(())
}

fn consensus_envelope_relevant_to_view(
    context: &ConsensusContext,
    envelope: &SignedEnvelope,
    current_view: u64,
) -> Result<bool, DepositServiceError> {
    let message = decode_consensus_message(context, envelope)?;
    Ok(match message.body {
        ConsensusMessageBody::Proposal(proposal) => proposal.view == current_view,
        ConsensusMessageBody::Prevote(vote) | ConsensusMessageBody::Precommit(vote) => {
            vote.view == current_view
        }
        ConsensusMessageBody::ViewChange(change) => {
            change.target_view == current_view.saturating_add(1)
        }
    })
}

fn consensus_value_created_at(value: &ConsensusValue) -> Result<Option<u64>, DepositServiceError> {
    let decoded = DepositConsensusValue::decode(value)?;
    match decoded.statement.payload {
        LedgerPayload::Allocation(allocation) => Ok(Some(allocation.created_at)),
        LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_) => Ok(None),
        LedgerPayload::ConsolidationCompletion(_)
        | LedgerPayload::ConsolidationAbandonment(_)
        | LedgerPayload::LateConsolidationSettlement(_) => {
            Err(DepositServiceError::InvalidConsensusValue)
        }
    }
}

fn insert_deposit_consensus_reference(
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    value: &ConsensusValue,
) -> Result<(), DepositServiceError> {
    value.validate()?;
    if let Some(existing) = values.insert(value.digest(), value.clone())
        && existing != *value
    {
        return Err(DepositServiceError::InvalidConsensusValue);
    }
    if values.len() > MAX_ADMITTED_CONSENSUS_VALUES {
        return Err(DepositServiceError::ConsensusRequestPoolFull);
    }
    Ok(())
}

fn collect_deposit_prepare_reference(
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    certificate: Option<&PrepareCertificate>,
) -> Result<(), DepositServiceError> {
    if let Some(certificate) = certificate {
        insert_deposit_consensus_reference(values, certificate.value())?;
    }
    Ok(())
}

fn collect_deposit_view_certificate_references(
    context: &ConsensusContext,
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    certificate: &ViewChangeCertificate,
) -> Result<(), DepositServiceError> {
    certificate.verify(context)?;
    for witness in certificate.witnesses() {
        let message = decode_consensus_message(context, witness)?;
        let ConsensusMessageBody::ViewChange(change) = message.body else {
            return Err(DepositServiceError::InvalidConsensusValue);
        };
        collect_deposit_prepare_reference(values, change.highest_prepared.as_ref())?;
    }
    Ok(())
}

fn collect_deposit_message_references(
    context: &ConsensusContext,
    values: &mut BTreeMap<ConsensusValueDigest, ConsensusValue>,
    body: &ConsensusMessageBody,
) -> Result<(), DepositServiceError> {
    match body {
        ConsensusMessageBody::Proposal(proposal) => {
            insert_deposit_consensus_reference(values, &proposal.value)?;
            collect_deposit_prepare_reference(values, proposal.proof_of_lock.as_ref())?;
            if let Some(certificate) = &proposal.view_change {
                collect_deposit_view_certificate_references(context, values, certificate)?;
            }
        }
        ConsensusMessageBody::ViewChange(change) => {
            collect_deposit_prepare_reference(values, change.highest_prepared.as_ref())?;
        }
        ConsensusMessageBody::Prevote(_) | ConsensusMessageBody::Precommit(_) => {}
    }
    Ok(())
}

/// Collect every full application value reachable through an ingress object before the reducer
/// sees it. This includes prepared values nested in proposals and view-change witnesses, so an
/// outer valid quorum object cannot smuggle a value past the service's asynchronous authority
/// checks.
fn referenced_deposit_consensus_values(
    wire: &DepositConsensusWire,
) -> Result<Vec<ConsensusValue>, DepositServiceError> {
    let mut values = BTreeMap::new();
    match &wire.payload {
        DepositConsensusPayload::Envelope(envelope) => {
            let message = decode_consensus_message(&wire.context, envelope)?;
            collect_deposit_message_references(&wire.context, &mut values, &message.body)?;
        }
        DepositConsensusPayload::ViewCertificate(certificate) => {
            collect_deposit_view_certificate_references(&wire.context, &mut values, certificate)?;
        }
        DepositConsensusPayload::CommitCertificate(certificate) => {
            certificate.verify(&wire.context)?;
            insert_deposit_consensus_reference(&mut values, certificate.value())?;
        }
    }
    Ok(values.into_values().collect())
}

fn byzantine_view_deadline(
    now_ms: u64,
    base_timeout_ms: u64,
    view: u64,
) -> Result<u64, DepositServiceError> {
    if now_ms == 0 || base_timeout_ms == 0 {
        return Err(DepositServiceError::InvalidTime);
    }
    // Monotonic bounded exponential backoff avoids synchronized hot-looping while ensuring a
    // Byzantine leader cannot increase retained timer state without bound.
    let shift = u32::try_from(view.min(6)).map_err(|_| DepositServiceError::InvalidTime)?;
    let timeout =
        base_timeout_ms.checked_mul(1_u64 << shift).ok_or(DepositServiceError::InvalidTime)?;
    now_ms.checked_add(timeout).ok_or(DepositServiceError::InvalidTime)
}

fn validate_allocation_clock(
    statement: &LedgerStatement,
    now: u64,
) -> Result<(), DepositServiceError> {
    let LedgerPayload::Allocation(allocation) = &statement.payload else {
        return Ok(());
    };
    validate_allocation_created_at(allocation.created_at, now)
}

fn validate_allocation_created_at(created_at: u64, now: u64) -> Result<(), DepositServiceError> {
    if created_at > now.saturating_add(MAX_ALLOCATION_CLOCK_SKEW_SECONDS) {
        return Err(DepositServiceError::ClockSkew);
    }
    if now
        .checked_add(MIN_ALLOCATION_CERTIFICATION_LEAD_SECONDS)
        .is_none_or(|minimum| created_at < minimum)
    {
        return Err(DepositServiceError::AllocationExpired);
    }
    Ok(())
}

#[cfg(test)]
mod allocation_clock_tests {
    use super::*;

    #[test]
    fn proposer_lead_accepts_the_documented_receiver_clock_bounds() {
        const PROPOSER_NOW: u64 = 1_700_000_000;
        let created_at = PROPOSER_NOW + ALLOCATION_ISSUANCE_LEAD_SECONDS;
        let maximum_receiver_ahead =
            ALLOCATION_ISSUANCE_LEAD_SECONDS - MIN_ALLOCATION_CERTIFICATION_LEAD_SECONDS;
        let maximum_receiver_behind =
            MAX_ALLOCATION_CLOCK_SKEW_SECONDS - ALLOCATION_ISSUANCE_LEAD_SECONDS;

        assert_eq!(ALLOCATION_ISSUANCE_LEAD_SECONDS, 60);
        assert!(validate_allocation_created_at(created_at, PROPOSER_NOW).is_ok());
        assert!(
            validate_allocation_created_at(created_at, PROPOSER_NOW + maximum_receiver_ahead,)
                .is_ok()
        );
        assert!(
            validate_allocation_created_at(created_at, PROPOSER_NOW - maximum_receiver_behind,)
                .is_ok()
        );
        assert!(matches!(
            validate_allocation_created_at(created_at, PROPOSER_NOW + maximum_receiver_ahead + 1,),
            Err(DepositServiceError::AllocationExpired)
        ));
        assert!(matches!(
            validate_allocation_created_at(created_at, PROPOSER_NOW - maximum_receiver_behind - 1,),
            Err(DepositServiceError::ClockSkew)
        ));
    }
}

/// Serialized, encrypted repository for one party's complete deposit-wallet state.
///
/// The mutex ensures that two HTTP/QUIC/worker tasks cannot both try to write the same successor
/// revision. Reducer mutation is still performed under the owning service's state mutex; this
/// repository only establishes the storage ordering boundary.
#[derive(Debug)]
pub(crate) struct DepositSnapshotRepository {
    store: WalletSnapshotStore,
    mutation: Mutex<()>,
}

impl DepositSnapshotRepository {
    pub(crate) fn new(
        directory: impl Into<std::path::PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositServiceError> {
        Ok(Self {
            store: WalletSnapshotStore::new(directory, party, identity_seed)?,
            mutation: Mutex::new(()),
        })
    }

    pub(crate) async fn persist(
        &self,
        snapshot: &DepositServiceSnapshot,
    ) -> Result<(), DepositServiceError> {
        self.persist_and_read_back(snapshot).await.map(|_| ())
    }

    /// Persist one exact successor and return the canonical authenticated readback while holding
    /// the repository mutation lock across both operations.
    pub(crate) async fn persist_and_read_back(
        &self,
        snapshot: &DepositServiceSnapshot,
    ) -> Result<DepositServiceSnapshot, DepositServiceError> {
        let _guard = self.mutation.lock().await;
        let bytes = snapshot.to_bytes()?;
        let metadata = self
            .store
            .save_snapshot(
                WalletId(snapshot.wallet.0),
                snapshot.revision,
                &bytes,
                &mut rand_core::OsRng,
            )
            .await?;
        if metadata.revision != snapshot.revision {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        let stored = self.store.load_snapshot(WalletId(snapshot.wallet.0)).await?;
        if stored.metadata.revision != snapshot.revision || stored.state.as_bytes() != bytes {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        let restored = DepositServiceSnapshot::from_bytes(stored.state.as_bytes())?;
        if &restored != snapshot {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        Ok(restored)
    }

    pub(crate) async fn load(
        &self,
        wallet: DepositWalletId,
    ) -> Result<DepositServiceSnapshot, DepositServiceError> {
        let _guard = self.mutation.lock().await;
        let stored = self.store.load_snapshot(WalletId(wallet.0)).await?;
        let snapshot = DepositServiceSnapshot::from_bytes(stored.state.as_bytes())?;
        if snapshot.wallet != wallet || snapshot.revision != stored.metadata.revision {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        Ok(snapshot)
    }

    pub(crate) fn snapshot_path(&self, wallet: DepositWalletId) -> std::path::PathBuf {
        self.store.wallet_snapshot_path(WalletId(wallet.0))
    }
}

/// Stable identifier of one deposit-ledger message retained until a peer durably accepts it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DepositPeerMessageId {
    wallet: DepositWalletId,
    sequence: u64,
    recipient: PartyId,
    operation: DepositOperation,
    digest: [u8; 32],
}

impl DepositPeerMessageId {
    /// Derive an identifier over the exact operation, recipient, and canonical body.
    #[must_use]
    pub fn derive(
        wallet: DepositWalletId,
        sequence: u64,
        recipient: PartyId,
        operation: DepositOperation,
        body: &[u8],
    ) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-peer-message/v1");
        hasher.update(&wallet.0);
        hasher.update(&sequence.to_le_bytes());
        hasher.update(&recipient.0.to_le_bytes());
        hasher.update(&[operation_tag(operation)]);
        hasher.update(&(body.len() as u64).to_le_bytes());
        hasher.update(body);
        Self { wallet, sequence, recipient, operation, digest: *hasher.finalize().as_bytes() }
    }

    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn recipient(self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn operation(self) -> DepositOperation {
        self.operation
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Derive the transport request ID used for every retransmission of this exact effect.
    #[must_use]
    pub fn request_id(self, network_id: [u8; 32]) -> RequestId {
        let mut material = Vec::with_capacity(107);
        material.extend_from_slice(&self.wallet.0);
        material.extend_from_slice(&self.sequence.to_le_bytes());
        material.extend_from_slice(&self.recipient.0.to_le_bytes());
        material.push(operation_tag(self.operation));
        material.extend_from_slice(&self.digest);
        RequestId::derive(network_id, b"deposit-ledger-message/v1", &material)
    }
}

/// One exact message exposed to the persistent QUIC relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDepositPeerMessage {
    pub id: DepositPeerMessageId,
    pub body: Vec<u8>,
}

impl PendingDepositPeerMessage {
    #[must_use]
    pub const fn recipient(&self) -> PartyId {
        self.id.recipient
    }

    #[must_use]
    pub fn to_quic_request(&self) -> PeerRequest {
        PeerRequest::Deposit { operation: self.id.operation, body: self.body.clone() }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableDepositMessage {
    id: DepositPeerMessageId,
    body_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DepositConsensusOutboxScope {
    sequence: u64,
    context: [u8; 32],
}

/// Canonical plaintext sealed by `WalletSnapshotStore`.
///
/// `reducer` contains only the canonical party-local state. The authenticated registry and
/// certified ledger are reconstructed from archive heads first, then
/// [`DepositLocalState::decode`] validates these local locks against that immutable history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct DepositServiceSnapshot {
    version: u16,
    wallet: DepositWalletId,
    birth_anchor: ChainPoint,
    revision: u64,
    archive_head: Option<DepositArchiveHead>,
    /// Constant-size semantic registry head plus the exact bounded recovery journal, if this
    /// snapshot installed a prepared genesis/handoff transition.
    compact_registry_checkpoint: CompactRegistryStoreCheckpoint,
    /// Authenticated portable and party-local deposit-index roots. An unsettled checkpoint names
    /// the exact crash-recovery journals whose immutable objects were installed before this
    /// wallet-snapshot CAS.
    deposit_index_checkpoint: DepositIndexStoreCheckpoint,
    /// Exact operation certificate at the archive tip. Its artifact kind is determined by the
    /// checkpoint operation (ledger or confirmed-output observation), and the referenced bytes
    /// are re-read and verified at startup.
    checkpoint_operation_certificate: Option<WalletArtifactRef>,
    /// n-f decision over the witness-independent portable head. Sequence zero is the only state
    /// permitted to omit both checkpoint authorities.
    index_checkpoint_certificate: Option<DepositIndexCheckpointCertificate>,
    /// Encrypted content-addressed proof archive for every ROAST view evicted from the bounded hot
    /// reducer. This head is installed in the same snapshot CAS as the corresponding eviction.
    roast_attempt_archive_head: RoastAttemptArchiveHead,
    reducer: Vec<u8>,
    /// Canonical public consolidation coordinator bytes. They share the wallet snapshot CAS with
    /// private worker intent bytes, protocol claims, and peer effects.
    consolidation: Vec<u8>,
    /// Canonical coordinator-free Byzantine reducers, keyed by immutable authorization ID. Exact
    /// contribution/candidate bodies and relay ACK tombstones share this same snapshot CAS.
    consolidation_roasts: BTreeMap<ConsolidationId, Vec<u8>>,
    /// Bounded pre-BA n-f certificates for objective unsigned input-reorg observations, keyed by
    /// the canonical observation digest.
    consolidation_abandonments: BTreeMap<[u8; 32], DurableConsolidationAbandonmentPool>,
    /// The sole value-independent prepared-intent BA lane. Keeping this in the same encrypted CAS
    /// as worker evidence and QUIC effects prevents cross-slot voting after restart.
    byzantine_consensus_lane: Option<DurableByzantineConsensusLane>,
    worker: Option<DepositWorkerState>,
    outbox: BTreeMap<DepositPeerMessageId, DurableDepositMessage>,
    /// Canonical message bodies are retained once even when the same certificate is pending for
    /// every committee member. `outbox` contains only recipient-specific effect identifiers.
    outbox_bodies: BTreeMap<[u8; 32], Vec<u8>>,
}

impl DepositServiceSnapshot {
    pub(crate) fn new_archived(
        wallet: DepositWalletId,
        network: [u8; 32],
        reducer: Vec<u8>,
        birth_anchor: ChainPoint,
        archive_head: DepositArchiveHead,
        compact_registry_checkpoint: CompactRegistryStoreCheckpoint,
        deposit_index_checkpoint: DepositIndexStoreCheckpoint,
    ) -> Result<Self, DepositServiceError> {
        let consolidation = ConsolidationCoordinator::new(wallet)?.encode()?;
        let roast_attempt_archive_head = RoastAttemptArchiveHead::empty(wallet, network)?;
        if deposit_index_checkpoint.wallet() != wallet
            || compact_registry_checkpoint.wallet() != wallet
        {
            return Err(DepositServiceError::WrongWallet);
        }
        compact_registry_checkpoint.to_bytes()?;
        deposit_index_checkpoint.to_bytes()?;
        let snapshot = Self {
            version: DEPOSIT_SERVICE_SNAPSHOT_VERSION,
            wallet,
            birth_anchor,
            revision: 0,
            archive_head: Some(archive_head),
            compact_registry_checkpoint,
            deposit_index_checkpoint,
            checkpoint_operation_certificate: None,
            index_checkpoint_certificate: None,
            roast_attempt_archive_head,
            reducer,
            consolidation,
            consolidation_roasts: BTreeMap::new(),
            consolidation_abandonments: BTreeMap::new(),
            byzantine_consensus_lane: None,
            worker: None,
            outbox: BTreeMap::new(),
            outbox_bodies: BTreeMap::new(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn archive_head(&self) -> Result<DepositArchiveHead, DepositServiceError> {
        self.archive_head.ok_or(DepositServiceError::MissingArchiveHead)
    }

    fn compact_registry_checkpoint(&self) -> &CompactRegistryStoreCheckpoint {
        &self.compact_registry_checkpoint
    }

    fn roast_attempt_archive_head(&self) -> RoastAttemptArchiveHead {
        self.roast_attempt_archive_head
    }

    fn deposit_index_checkpoint(&self) -> &DepositIndexStoreCheckpoint {
        &self.deposit_index_checkpoint
    }

    fn checkpoint_operation_certificate(&self) -> Option<WalletArtifactRef> {
        self.checkpoint_operation_certificate
    }

    fn index_checkpoint_certificate(&self) -> Option<&DepositIndexCheckpointCertificate> {
        self.index_checkpoint_certificate.as_ref()
    }

    fn install_deposit_index_checkpoint(
        &mut self,
        expected: &DepositIndexStoreCheckpoint,
        successor: DepositIndexStoreCheckpoint,
    ) -> Result<bool, DepositServiceError> {
        if &self.deposit_index_checkpoint != expected
            || expected.wallet() != self.wallet
            || successor.wallet() != self.wallet
            || successor.party() != expected.party()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        successor.to_bytes()?;
        let changed = successor != *expected;
        if changed {
            self.deposit_index_checkpoint = successor;
            self.revision = self.next_revision()?;
        }
        Ok(changed)
    }

    /// Install one reducer mutation and one prepared index checkpoint as a single outer CAS.
    ///
    /// Component setters must not each consume a wallet revision: WalletSnapshotStore accepts
    /// exactly one successor revision for the complete state-machine transition.
    fn replace_reducer_and_install_deposit_index_checkpoint(
        &mut self,
        reducer: Vec<u8>,
        expected: &DepositIndexStoreCheckpoint,
        successor: DepositIndexStoreCheckpoint,
    ) -> Result<bool, DepositServiceError> {
        if reducer.is_empty() || reducer.len() > MAX_REDUCER_BYTES {
            return Err(DepositServiceError::ReducerTooLarge);
        }
        if &self.deposit_index_checkpoint != expected
            || expected.wallet() != self.wallet
            || successor.wallet() != self.wallet
            || successor.party() != expected.party()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        successor.to_bytes()?;
        let changed = self.reducer != reducer || successor != *expected;
        if changed {
            let mut candidate = self.clone();
            candidate.reducer = reducer;
            candidate.deposit_index_checkpoint = successor;
            candidate.revision = self.next_revision()?;
            candidate.validate()?;
            *self = candidate;
        }
        Ok(changed)
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_certified_index_transition<I>(
        &mut self,
        reducer: Vec<u8>,
        worker: DepositWorkerState,
        consolidation: &ConsolidationCoordinator,
        expected_index: &DepositIndexStoreCheckpoint,
        successor_index: DepositIndexStoreCheckpoint,
        archive_head: DepositArchiveHead,
        ledger_certificate: WalletArtifactRef,
        ledger_statement: &LedgerStatement,
        checkpoint_certificate: DepositIndexCheckpointCertificate,
        compact_transition: Option<(
            &CompactRegistryStoreCheckpoint,
            CompactRegistryStoreCheckpoint,
        )>,
        messages: I,
    ) -> Result<(), DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        if reducer.is_empty()
            || reducer.len() > MAX_REDUCER_BYTES
            || &self.deposit_index_checkpoint != expected_index
            || successor_index.wallet() != self.wallet
            || successor_index.party() != expected_index.party()
            || archive_head.wallet_id() != self.wallet
            || ledger_certificate.wallet_id() != WalletId(self.wallet.0)
            || ledger_certificate.kind() != CERTIFIED_LEDGER_ENTRY_ARTIFACT
            || ledger_statement.wallet != self.wallet
            || archive_head.len() != checkpoint_certificate.statement().sequence()
            || checkpoint_certificate.statement().operation()
                != (DepositIndexCheckpointOperation::Ledger {
                    statement: ledger_statement.digest(),
                })
            || checkpoint_certificate.statement().ledger_sequence() != ledger_statement.sequence
            || checkpoint_certificate.statement().ledger_decision() != ledger_statement.digest()
            || checkpoint_certificate.statement().resulting_head()
                != &PortableDepositIndexHead::from_head(successor_index.portable_head())?
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.reducer = reducer;
        candidate.worker = Some(worker);
        candidate.consolidation = consolidation.encode()?;
        candidate.deposit_index_checkpoint = successor_index;
        candidate.archive_head = Some(archive_head);
        candidate.checkpoint_operation_certificate = Some(ledger_certificate);
        candidate.index_checkpoint_certificate = Some(checkpoint_certificate.clone());
        if let Some((expected, successor)) = compact_transition {
            if &candidate.compact_registry_checkpoint != expected
                || successor.wallet() != candidate.wallet
            {
                return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
            }
            successor.to_bytes()?;
            candidate.compact_registry_checkpoint = successor;
        }
        candidate.prune_certified_outbox_in_place(
            ledger_statement,
            Some(checkpoint_certificate.statement().sequence()),
        );
        candidate.revision = original.revision;
        candidate.enqueue_many(messages)?;
        candidate.revision = original.next_revision()?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_certified_observation_transition<I>(
        &mut self,
        reducer: Vec<u8>,
        worker: DepositWorkerState,
        consolidation: &ConsolidationCoordinator,
        expected_index: &DepositIndexStoreCheckpoint,
        successor_index: DepositIndexStoreCheckpoint,
        archive_head: DepositArchiveHead,
        observation_artifact: WalletArtifactRef,
        observation: &CertifiedDepositObservation,
        checkpoint_certificate: DepositIndexCheckpointCertificate,
        messages: I,
    ) -> Result<(), DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        let resulting = PortableDepositIndexHead::from_head(successor_index.portable_head())?;
        if reducer.is_empty()
            || reducer.len() > MAX_REDUCER_BYTES
            || &self.deposit_index_checkpoint != expected_index
            || successor_index.wallet() != self.wallet
            || successor_index.party() != expected_index.party()
            || archive_head.wallet_id() != self.wallet
            || archive_head.len() != checkpoint_certificate.statement().sequence()
            || observation_artifact.wallet_id() != WalletId(self.wallet.0)
            || observation_artifact.kind() != CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
            || observation.statement.wallet_id() != self.wallet
            || checkpoint_certificate.statement().operation()
                != (DepositIndexCheckpointOperation::DepositObservation {
                    statement: observation.statement.digest(),
                })
            || checkpoint_certificate.statement().ledger_sequence() != resulting.through_sequence()
            || checkpoint_certificate.statement().ledger_decision() != resulting.ledger_head()
            || checkpoint_certificate.statement().resulting_head() != &resulting
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.reducer = reducer;
        candidate.worker = Some(worker);
        candidate.consolidation = consolidation.encode()?;
        candidate.deposit_index_checkpoint = successor_index;
        candidate.archive_head = Some(archive_head);
        candidate.checkpoint_operation_certificate = Some(observation_artifact);
        candidate.index_checkpoint_certificate = Some(checkpoint_certificate);
        candidate.prune_deposit_observation_outbox_in_place(&observation.statement)?;
        candidate.revision = original.revision;
        candidate.enqueue_many(messages)?;
        candidate.revision = original.next_revision()?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn settle_prepared_state_checkpoints(
        &mut self,
        expected_index: &DepositIndexStoreCheckpoint,
        settled_index: DepositIndexStoreCheckpoint,
        compact_transition: Option<(
            &CompactRegistryStoreCheckpoint,
            CompactRegistryStoreCheckpoint,
        )>,
    ) -> Result<(), DepositServiceError> {
        if &self.deposit_index_checkpoint != expected_index
            || settled_index.wallet() != self.wallet
            || settled_index.party() != expected_index.party()
            || settled_index.has_recovery_journal()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let mut candidate = self.clone();
        candidate.deposit_index_checkpoint = settled_index;
        if let Some((expected, settled)) = compact_transition {
            if &candidate.compact_registry_checkpoint != expected
                || settled.wallet() != candidate.wallet
                || settled.has_recovery_journal()
            {
                return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
            }
            candidate.compact_registry_checkpoint = settled;
        }
        candidate.revision = self.next_revision()?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn install_compact_registry_checkpoint(
        &mut self,
        expected: &CompactRegistryStoreCheckpoint,
        successor: CompactRegistryStoreCheckpoint,
    ) -> Result<bool, DepositServiceError> {
        if &self.compact_registry_checkpoint != expected
            || expected.wallet() != self.wallet
            || successor.wallet() != self.wallet
        {
            return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
        }
        successor.to_bytes()?;
        let changed = successor != *expected;
        if changed {
            self.compact_registry_checkpoint = successor;
            self.revision = self.next_revision()?;
        }
        Ok(changed)
    }

    /// Replace an exact fresh local genesis with one fully verified portable sync snapshot.
    ///
    /// All component authorities consume one outer revision. Immutable objects are materialized
    /// and independently opened before this method is called; this function never turns a raw
    /// downloaded head into authority.
    #[allow(clippy::too_many_arguments)]
    fn install_verified_sync_state(
        &mut self,
        expected_index: &DepositIndexStoreCheckpoint,
        index: DepositIndexStoreCheckpoint,
        expected_registry: &CompactRegistryStoreCheckpoint,
        registry: CompactRegistryStoreCheckpoint,
        archive: DepositArchiveHead,
        protocol: &DepositProtocolState,
        deriver: &DepositAddressDeriver,
        worker: DepositWorkerState,
        consolidation: &ConsolidationCoordinator,
        operation_artifact: Option<WalletArtifactRef>,
        checkpoint_certificate: Option<DepositIndexCheckpointCertificate>,
    ) -> Result<(), DepositServiceError> {
        let current_portable =
            PortableDepositIndexHead::from_head(self.deposit_index_checkpoint.portable_head())?;
        if current_portable.through_sequence() != 0
            || &self.deposit_index_checkpoint != expected_index
            || &self.compact_registry_checkpoint != expected_registry
            || expected_index.has_recovery_journal()
            || expected_registry.has_recovery_journal()
            || index.has_recovery_journal()
            || registry.has_recovery_journal()
            || index.wallet() != self.wallet
            || index.party() != expected_index.party()
            || registry.wallet() != self.wallet
            || archive.wallet_id() != self.wallet
            || !self.outbox.is_empty()
            || !self.outbox_bodies.is_empty()
            || !self.consolidation_roasts.is_empty()
            || !self.consolidation_abandonments.is_empty()
            || self.byzantine_consensus_lane.is_some()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let imported = PortableDepositIndexHead::from_head(index.portable_head())?;
        match (imported.through_sequence(), operation_artifact, checkpoint_certificate.as_ref()) {
            (0, None, None) => {}
            (0, _, _) | (_, None, _) | (_, _, None) => {
                return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
            }
            (sequence, Some(operation), Some(checkpoint))
                if operation.wallet_id() == WalletId(self.wallet.0)
                    && checkpoint.statement().ledger_sequence() == sequence
                    && checkpoint.statement().resulting_head() == &imported
                    && match checkpoint.statement().operation() {
                        DepositIndexCheckpointOperation::Ledger { .. } => {
                            operation.kind() == CERTIFIED_LEDGER_ENTRY_ARTIFACT
                        }
                        DepositIndexCheckpointOperation::DepositObservation { .. } => {
                            operation.kind() == CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
                        }
                    } => {}
            _ => return Err(DepositServiceError::InvalidDepositIndexCheckpoint),
        }
        let mut candidate = self.clone();
        candidate.reducer = protocol.encode_local(deriver)?;
        candidate.worker = Some(worker);
        candidate.consolidation = consolidation.encode()?;
        candidate.deposit_index_checkpoint = index;
        candidate.compact_registry_checkpoint = registry;
        candidate.archive_head = Some(archive);
        candidate.checkpoint_operation_certificate = operation_artifact;
        candidate.index_checkpoint_certificate = checkpoint_certificate;
        candidate.consolidation_roasts.clear();
        candidate.consolidation_abandonments.clear();
        candidate.byzantine_consensus_lane = None;
        candidate.outbox.clear();
        candidate.outbox_bodies.clear();
        candidate.revision = self.next_revision()?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn install_roast_attempt_archive_head(
        &mut self,
        current: RoastAttemptArchiveHead,
        successor: RoastAttemptArchiveHead,
    ) -> Result<bool, DepositServiceError> {
        if self.roast_attempt_archive_head != current
            || successor.wallet_id() != self.wallet
            || successor.network_id() != current.network_id()
            || successor.generation() < current.generation()
            || successor.attempt_count() < current.attempt_count()
            || successor.transaction_count() < current.transaction_count()
        {
            return Err(DepositServiceError::InvalidRoastAttemptArchive);
        }
        successor.validate()?;
        let changed = successor != current;
        self.roast_attempt_archive_head = successor;
        Ok(changed)
    }

    fn install_archive_head(
        &mut self,
        archive_head: DepositArchiveHead,
    ) -> Result<bool, DepositServiceError> {
        if archive_head.wallet_id() != self.wallet {
            return Err(DepositServiceError::WrongWallet);
        }
        let changed = self.archive_head != Some(archive_head);
        self.archive_head = Some(archive_head);
        Ok(changed)
    }

    pub(crate) fn reducer_bytes(&self) -> &[u8] {
        &self.reducer
    }

    pub(crate) fn worker(&self) -> Option<&DepositWorkerState> {
        self.worker.as_ref()
    }

    pub(crate) fn consolidation(&self) -> Result<ConsolidationCoordinator, DepositServiceError> {
        let consolidation = ConsolidationCoordinator::decode(&self.consolidation)?;
        if consolidation.wallet_id() != self.wallet {
            return Err(DepositServiceError::WrongWallet);
        }
        self.validate_roasts()?;
        Ok(consolidation)
    }

    fn validate_roasts(&self) -> Result<(), DepositServiceError> {
        if self.consolidation_roasts.len() > MAX_CONSOLIDATIONS {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        if self.consolidation_abandonments.len() > MAX_CONSOLIDATION_ABANDONMENT_POOLS {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        for (digest, pool) in &self.consolidation_abandonments {
            let payload = postcard::to_allocvec(&pool.observation)?;
            let session = pool.observation.session()?;
            if pool.observation.digest()? != *digest
                || pool.observation.slot.binding().wallet != self.wallet.0
                || pool.share_unexposed.is_empty()
                || pool.share_unexposed.len() > pool.observation.slot.committee().members.len()
                || pool.attestations.is_empty()
                || pool.attestations.len() > pool.observation.slot.committee().members.len()
                || !pool.share_unexposed.keys().eq(pool.attestations.keys())
            {
                return Err(DepositServiceError::InvalidConsolidationAbandonment);
            }
            for (party, witness) in &pool.share_unexposed {
                if witness.from != *party {
                    return Err(DepositServiceError::InvalidConsolidationAbandonment);
                }
                verify_share_unexposed_attestation(
                    &pool.observation.abandonment_context,
                    &pool.observation.intent_certificate,
                    witness,
                )?;
            }
            for (party, envelope) in &pool.attestations {
                if envelope.from != *party
                    || envelope.to.is_some()
                    || envelope.session != session
                    || envelope.sequence != 1
                    || envelope.payload != payload
                {
                    return Err(DepositServiceError::InvalidConsolidationAbandonment);
                }
                Identity::verify_envelope(pool.observation.slot.committee(), *party, envelope)?;
            }
        }
        let mut families = BTreeSet::new();
        for (authorization, bytes) in &self.consolidation_roasts {
            let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
            if roast.authorization_id() != *authorization
                || roast.wallet_id() != self.wallet
                || !families.insert(roast.family_digest())
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
        }
        if let Some(lane) = &self.byzantine_consensus_lane {
            lane.validate()?;
            let worker = self.worker.as_ref().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if lane.slot.binding().wallet != self.wallet.0
                || lane.reducer.local_party().0 == 0
                || lane.admitted_values.values().any(|admitted| {
                    admitted.validated_worker_revision > worker.revision()
                        || PreparedSweepIntent::decode(&admitted.prepared_intent).is_err()
                })
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            let same_family_roasts = self
                .consolidation_roasts
                .values()
                .filter_map(|bytes| ConsolidationRoast::decode_authenticated_snapshot(bytes).ok())
                .filter(|roast| {
                    roast.expected_slot(lane.slot.roast_view()).ok().as_ref() == Some(&lane.slot)
                })
                .count();
            if same_family_roasts > 1
                || (lane.slot.roast_view() == 0 && same_family_roasts != 0)
                || (lane.slot.roast_view() > 0 && same_family_roasts != 1)
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
        }
        Ok(())
    }

    fn roast_by_family(
        &self,
        family: [u8; 32],
    ) -> Result<(ConsolidationId, ConsolidationRoast), DepositServiceError> {
        let mut found = None;
        for (authorization, bytes) in &self.consolidation_roasts {
            let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
            if roast.family_digest() == family {
                if found.is_some() {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
                found = Some((*authorization, roast));
            }
        }
        found.ok_or(DepositServiceError::ByzantineConsolidationUnavailable)
    }

    /// Atomically replace one exact ROAST reducer and append all corresponding full wire bodies.
    fn replace_roast_and_enqueue<I>(
        &mut self,
        roast: &ConsolidationRoast,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        if roast.wallet_id() != self.wallet || roast.authorization_id().0 == [0; 32] {
            return Err(DepositServiceError::WrongWallet);
        }
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.consolidation_roasts.insert(roast.authorization_id(), roast.encode()?);
        candidate.prune_superseded_roast_attempt_outbox_in_place(roast)?;
        candidate.prune_compacted_roast_outbox_in_place(roast)?;
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        candidate.revision = original.revision;
        let changed = candidate.consolidation_roasts != original.consolidation_roasts
            || candidate.outbox != original.outbox
            || candidate.outbox_bodies != original.outbox_bodies;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    fn replace_roast_worker_and_enqueue<I>(
        &mut self,
        roast: &ConsolidationRoast,
        worker: DepositWorkerState,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        if roast.wallet_id() != self.wallet || worker.wallet_id() != self.wallet {
            return Err(DepositServiceError::WrongWallet);
        }
        worker.encode()?;
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.consolidation_roasts.insert(roast.authorization_id(), roast.encode()?);
        candidate.prune_superseded_roast_attempt_outbox_in_place(roast)?;
        candidate.prune_compacted_roast_outbox_in_place(roast)?;
        candidate.worker = Some(worker);
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        candidate.revision = original.revision;
        let changed = candidate.consolidation_roasts != original.consolidation_roasts
            || candidate.worker != original.worker
            || candidate.outbox != original.outbox
            || candidate.outbox_bodies != original.outbox_bodies;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    fn replace_byzantine_lane_and_enqueue<I>(
        &mut self,
        lane: Option<DurableByzantineConsensusLane>,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        if let Some(lane) = &lane {
            lane.validate()?;
            if lane.slot.binding().wallet != self.wallet.0 {
                return Err(DepositServiceError::WrongWallet);
            }
        }
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.byzantine_consensus_lane = lane;
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        candidate.revision = original.revision;
        let changed = candidate.byzantine_consensus_lane != original.byzantine_consensus_lane
            || candidate.outbox != original.outbox
            || candidate.outbox_bodies != original.outbox_bodies;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    fn merge_abandonment_observation_and_enqueue<I>(
        &mut self,
        observation: ConsolidationAbandonmentObservation,
        share_unexposed: impl IntoIterator<Item = SignedEnvelope>,
        attestations: impl IntoIterator<Item = SignedEnvelope>,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        let digest = observation.digest()?;
        let original = self.clone();
        let mut candidate = self.clone();
        if !candidate.consolidation_abandonments.contains_key(&digest)
            && candidate.consolidation_abandonments.len() >= MAX_CONSOLIDATION_ABANDONMENT_POOLS
        {
            return Err(DepositServiceError::ConsolidationAbandonmentPoolFull);
        }
        let pool = candidate.consolidation_abandonments.entry(digest).or_insert_with(|| {
            DurableConsolidationAbandonmentPool {
                observation: observation.clone(),
                share_unexposed: BTreeMap::new(),
                attestations: BTreeMap::new(),
            }
        });
        if pool.observation != observation {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        for witness in share_unexposed {
            if let Some(existing) = pool.share_unexposed.get(&witness.from) {
                if existing != &witness {
                    return Err(DepositServiceError::InvalidConsolidationAbandonment);
                }
            } else {
                pool.share_unexposed.insert(witness.from, witness);
            }
        }
        for envelope in attestations {
            if let Some(existing) = pool.attestations.get(&envelope.from) {
                if existing != &envelope {
                    return Err(DepositServiceError::InvalidConsolidationAbandonment);
                }
            } else {
                pool.attestations.insert(envelope.from, envelope);
            }
        }
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        candidate.revision = original.revision;
        let changed = candidate.consolidation_abandonments != original.consolidation_abandonments
            || candidate.outbox != original.outbox
            || candidate.outbox_bodies != original.outbox_bodies;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    fn cancel_byzantine_lane_for_endorsed_roast(
        &mut self,
        roast: &ConsolidationRoast,
    ) -> Result<bool, DepositServiceError> {
        if !roast.has_endorsed_candidate() {
            return Ok(false);
        }
        let Some(lane) = self.byzantine_consensus_lane.as_ref() else {
            return Ok(false);
        };
        if lane.slot.roast_view() == 0 || roast.expected_slot(lane.slot.roast_view())? != lane.slot
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let slot = lane.slot.clone();
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.byzantine_consensus_lane = None;
        candidate.prune_byzantine_consensus_slot_outbox_in_place(&slot)?;
        let changed = candidate != original;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(changed)
    }

    /// Atomically turn one committed BA lane into its durable ROAST/nonce-release family. There
    /// is no snapshot revision in which the lane disappeared but the nonce tombstones did not
    /// exist, or vice versa.
    fn install_byzantine_roast_release_and_enqueue<I>(
        &mut self,
        reducer: Vec<u8>,
        worker: DepositWorkerState,
        consolidation: &ConsolidationCoordinator,
        roast: &ConsolidationRoast,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        if reducer.len() > MAX_REDUCER_BYTES
            || worker.wallet_id() != self.wallet
            || consolidation.wallet_id() != self.wallet
            || roast.wallet_id() != self.wallet
        {
            return Err(DepositServiceError::WrongWallet);
        }
        worker.encode()?;
        roast.encode()?;
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.version = DEPOSIT_SERVICE_SNAPSHOT_VERSION;
        candidate.reducer = reducer;
        candidate.worker = Some(worker);
        candidate.consolidation = consolidation.encode()?;
        candidate.byzantine_consensus_lane = None;
        candidate.consolidation_roasts.insert(roast.authorization_id(), roast.encode()?);
        candidate.prune_superseded_roast_attempt_outbox_in_place(roast)?;
        candidate.prune_compacted_roast_outbox_in_place(roast)?;
        candidate.prune_byzantine_consensus_slot_outbox_in_place(
            &original
                .byzantine_consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?
                .slot,
        )?;
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        candidate.revision = original.revision;
        let changed = candidate != original;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    /// A durable intent certificate subsumes every partial consensus message for the exact slot.
    /// Remove those predecessor effects in the same CAS which installs the ROAST family so a
    /// receiver that finalized first cannot permanently block the certified intent behind a
    /// now-irrelevant proposal/vote retry.
    fn prune_byzantine_consensus_slot_outbox_in_place(
        &mut self,
        slot: &ConsolidationConsensusSlot,
    ) -> Result<usize, DepositServiceError> {
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                if id.operation != DepositOperation::Consolidation {
                    return None;
                }
                let body = self.outbox_bodies.get(&message.body_digest)?;
                match ByzantineConsolidationWireMessage::decode(body) {
                    Ok(ByzantineConsolidationWireMessage::Consensus(relay))
                        if relay.slot() == slot =>
                    {
                        Some(Ok(*id))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Err(DepositServiceError::from(error))),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    /// Retire recipient-specific copies of incomplete predecessor-attempt rounds as soon as a
    /// successor attempt is certified.
    ///
    /// The ROAST reducer remains the content-addressed owner of each exact signed inner body and
    /// does not synthesize an ACK when these outer copies are removed. This preserves attributable
    /// evidence and nonce/share-exposure safety while preventing one withheld recipient ACK from
    /// multiplying a large preprocess across every later view. Completed transaction candidates
    /// remain relayable because any valid predecessor candidate may already be the on-chain winner.
    fn prune_superseded_roast_attempt_outbox_in_place(
        &mut self,
        roast: &ConsolidationRoast,
    ) -> Result<usize, DepositServiceError> {
        let current_view = roast
            .next_view()
            .checked_sub(1)
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                if id.operation != DepositOperation::Consolidation {
                    return None;
                }
                let body = match self.outbox_bodies.get(&message.body_digest) {
                    Some(body) => body,
                    None => return Some(Err(DepositServiceError::InvalidOutbox)),
                };
                let wire = match ByzantineConsolidationWireMessage::decode(body) {
                    Ok(wire) => wire,
                    Err(error) => return Some(Err(error.into())),
                };
                let obsolete = match &wire {
                    ByzantineConsolidationWireMessage::Preprocess(_)
                    | ByzantineConsolidationWireMessage::KeyImageBinding(_)
                    | ByzantineConsolidationWireMessage::Share(_) => {
                        wire.family() == roast.family_digest() && wire.view() < current_view
                    }
                    ByzantineConsolidationWireMessage::Consensus(_)
                    | ByzantineConsolidationWireMessage::CertifiedIntent(_)
                    | ByzantineConsolidationWireMessage::Candidate(_)
                    | ByzantineConsolidationWireMessage::Ack(_) => false,
                };
                obsolete.then_some(Ok(*id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    /// Once a view leaves the exact replay window, no message body can advance it. Retire every
    /// locally-created retry for that compacted prefix in the same CAS which stores the new ROAST
    /// high-water. A delayed candidate which actually reached the chain remains recoverable through
    /// the worker's independent family/key-image settlement evidence.
    fn prune_compacted_roast_outbox_in_place(
        &mut self,
        roast: &ConsolidationRoast,
    ) -> Result<usize, DepositServiceError> {
        if roast.compacted_through().is_none() {
            return Ok(0);
        }
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                if id.operation != DepositOperation::Consolidation {
                    return None;
                }
                let body = match self.outbox_bodies.get(&message.body_digest) {
                    Some(body) => body,
                    None => return Some(Err(DepositServiceError::InvalidOutbox)),
                };
                let wire = match ByzantineConsolidationWireMessage::decode(body) {
                    Ok(wire) => wire,
                    Err(error) => return Some(Err(error.into())),
                };
                let same_family = match &wire {
                    ByzantineConsolidationWireMessage::Consensus(relay) => {
                        roast.owns_slot_family(relay.slot())
                    }
                    ByzantineConsolidationWireMessage::CertifiedIntent(_)
                    | ByzantineConsolidationWireMessage::Preprocess(_)
                    | ByzantineConsolidationWireMessage::KeyImageBinding(_)
                    | ByzantineConsolidationWireMessage::Share(_)
                    | ByzantineConsolidationWireMessage::Candidate(_) => {
                        wire.family() == roast.family_digest()
                    }
                    ByzantineConsolidationWireMessage::Ack(_) => false,
                };
                (same_family && roast.is_fully_compacted_view(wire.view())).then_some(Ok(*id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    /// Install a terminal completion seal and retire every pending family delivery in one enclosing
    /// snapshot CAS. The retained reducer contains only certified intent cores and exact digest
    /// tombstones, so late byte-identical retries remain ACKable without keeping round bodies hot.
    fn seal_roast_completion_and_prune_outbox_in_place(
        &mut self,
        family: [u8; 32],
        completed_view: u64,
        prefix: RoastAttemptPrefixSeal,
        statement: [u8; 32],
        evidence: [u8; 32],
    ) -> Result<bool, DepositServiceError> {
        let (authorization, mut roast) = self.roast_by_family(family)?;
        let changed = roast.seal_completion(completed_view, prefix, statement, evidence)?;
        if changed {
            self.consolidation_roasts.insert(authorization, roast.encode()?);
        }
        let pruned = self.prune_roast_family_outbox_in_place(&roast)?;
        Ok(changed || pruned != 0)
    }

    /// Seal an unsigned input-reorg lineage selected by the global ledger BA and retire every
    /// family delivery atomically. The reducer keeps only non-signable exact replay tombstones.
    fn seal_roast_abandonment_and_prune_outbox_in_place(
        &mut self,
        family: [u8; 32],
        abandoned_view: u64,
        prefix: RoastAttemptPrefixSeal,
        statement: [u8; 32],
        evidence: [u8; 32],
    ) -> Result<bool, DepositServiceError> {
        let (authorization, mut roast) = self.roast_by_family(family)?;
        let changed = roast.seal_abandonment(abandoned_view, prefix, statement, evidence)?;
        if changed {
            self.consolidation_roasts.insert(authorization, roast.encode()?);
        }
        let pruned = self.prune_roast_family_outbox_in_place(&roast)?;
        Ok(changed || pruned != 0)
    }

    fn prune_roast_family_outbox_in_place(
        &mut self,
        roast: &ConsolidationRoast,
    ) -> Result<usize, DepositServiceError> {
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                if id.operation != DepositOperation::Consolidation {
                    return None;
                }
                let body = match self.outbox_bodies.get(&message.body_digest) {
                    Some(body) => body,
                    None => return Some(Err(DepositServiceError::InvalidOutbox)),
                };
                let wire = match ByzantineConsolidationWireMessage::decode(body) {
                    Ok(wire) => wire,
                    Err(error) => return Some(Err(error.into())),
                };
                let same_family = match &wire {
                    ByzantineConsolidationWireMessage::Consensus(relay) => {
                        roast.owns_slot_family(relay.slot())
                    }
                    ByzantineConsolidationWireMessage::CertifiedIntent(_)
                    | ByzantineConsolidationWireMessage::Preprocess(_)
                    | ByzantineConsolidationWireMessage::KeyImageBinding(_)
                    | ByzantineConsolidationWireMessage::Share(_)
                    | ByzantineConsolidationWireMessage::Candidate(_) => {
                        wire.family() == roast.family_digest()
                    }
                    ByzantineConsolidationWireMessage::Ack(_) => false,
                };
                same_family.then_some(Ok(*id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    fn prune_abandonment_observation_in_place(
        &mut self,
        observation: [u8; 32],
    ) -> Result<usize, DepositServiceError> {
        let family = self
            .consolidation_abandonments
            .get(&observation)
            .map(|pool| pool.observation.family)
            .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
        self.consolidation_abandonments.retain(|_, pool| pool.observation.family != family);
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                if id.operation != DepositOperation::ConsolidationAbandonment {
                    return None;
                }
                let body = match self.outbox_bodies.get(&message.body_digest) {
                    Some(body) => body,
                    None => return Some(Err(DepositServiceError::InvalidOutbox)),
                };
                match ConsolidationAbandonmentObservationWire::decode(body) {
                    Ok(wire) if wire.observation.family == family => Some(Ok(*id)),
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    pub(crate) fn replace_reducer(&mut self, reducer: Vec<u8>) -> Result<(), DepositServiceError> {
        if reducer.len() > MAX_REDUCER_BYTES {
            return Err(DepositServiceError::ReducerTooLarge);
        }
        if self.reducer == reducer {
            return Ok(());
        }
        let revision = self.next_revision()?;
        self.reducer = reducer;
        self.revision = revision;
        Ok(())
    }

    pub(crate) fn replace_worker(
        &mut self,
        worker: DepositWorkerState,
    ) -> Result<(), DepositServiceError> {
        worker.encode()?;
        if worker.wallet_id() != self.wallet {
            return Err(DepositServiceError::WrongWallet);
        }
        if self.worker.as_ref() == Some(&worker) {
            return Ok(());
        }
        let revision = self.next_revision()?;
        self.worker = Some(worker);
        self.revision = revision;
        Ok(())
    }

    /// Commit portable ledger bytes, worker tombstones, coordinator state, and certificate gossip
    /// as one authenticated snapshot revision.
    pub(crate) fn replace_all_and_enqueue<I>(
        &mut self,
        reducer: Vec<u8>,
        worker: DepositWorkerState,
        consolidation: &ConsolidationCoordinator,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        if reducer.len() > MAX_REDUCER_BYTES {
            return Err(DepositServiceError::ReducerTooLarge);
        }
        worker.encode()?;
        let consolidation_bytes = consolidation.encode()?;
        if worker.wallet_id() != self.wallet || consolidation.wallet_id() != self.wallet {
            return Err(DepositServiceError::WrongWallet);
        }

        let original = self.clone();
        let mut candidate = self.clone();
        candidate.reducer = reducer;
        candidate.worker = Some(worker);
        candidate.consolidation = consolidation_bytes;
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        let changed = candidate.reducer != original.reducer
            || candidate.worker != original.worker
            || candidate.consolidation != original.consolidation
            || candidate.outbox != original.outbox
            || candidate.outbox_bodies != original.outbox_bodies;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    /// Commit reducer changes and their peer effects as one authenticated storage revision.
    pub(crate) fn replace_reducer_and_enqueue<I>(
        &mut self,
        reducer: Vec<u8>,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        self.replace_reducer_prune_consensus_and_enqueue(reducer, None, messages)
    }

    fn replace_reducer_prune_consensus_and_enqueue<I>(
        &mut self,
        reducer: Vec<u8>,
        prune: Option<DepositConsensusOutboxScope>,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        let original = self.clone();
        let mut candidate = self.clone();
        candidate.replace_reducer(reducer)?;
        if let Some(scope) = prune {
            candidate.prune_consensus_outbox_in_place(scope)?;
        }
        // `enqueue_many` is independently useful and therefore normally consumes a revision.
        // Reset only this private candidate so both mutations share one outer transaction.
        candidate.revision = original.revision;
        let identifiers = candidate.enqueue_many(messages)?;
        let changed = candidate.reducer != original.reducer
            || candidate.worker != original.worker
            || candidate.outbox != original.outbox
            || candidate.outbox_bodies != original.outbox_bodies;
        candidate.revision = if changed { original.next_revision()? } else { original.revision };
        candidate.validate()?;
        *self = candidate;
        Ok(identifiers)
    }

    fn prune_consensus_outbox_in_place(
        &mut self,
        scope: DepositConsensusOutboxScope,
    ) -> Result<usize, DepositServiceError> {
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                if id.sequence != scope.sequence {
                    return None;
                }
                match id.operation {
                    DepositOperation::ConsensusProposal
                    | DepositOperation::ConsensusMessage
                    | DepositOperation::ConsensusCertificate => {
                        let body = self.outbox_bodies.get(&message.body_digest)?;
                        let (wire, trailing) =
                            postcard::take_from_bytes::<DepositConsensusWire>(body).ok()?;
                        (trailing.is_empty()
                            && postcard::to_allocvec(&wire).ok().as_deref()
                                == Some(body.as_slice())
                            && wire.context.digest() == scope.context)
                            .then_some(*id)
                    }
                    DepositOperation::Allocate
                    | DepositOperation::Attest
                    | DepositOperation::Certificate
                    | DepositOperation::DepositObservation
                    | DepositOperation::DepositObservationAttest
                    | DepositOperation::DepositObservationCertificate
                    | DepositOperation::IndexCheckpointAttest
                    | DepositOperation::IndexCheckpointCertificate
                    | DepositOperation::DepositObservationIndexCheckpointAttest
                    | DepositOperation::DepositObservationIndexCheckpointCertificate
                    | DepositOperation::Handoff
                    | DepositOperation::SyncHead
                    | DepositOperation::SyncObjects
                    | DepositOperation::ConsolidationCompletion
                    | DepositOperation::Consolidation
                    | DepositOperation::ConsolidationAbandonment
                    // Origin proof remains available to lagging honest parties across every
                    // view. Certification is the only point at which request gossip is obsolete.
                    | DepositOperation::ClientRequest => None,
                }
            })
            .collect::<Vec<_>>();
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    fn prune_certified_outbox_in_place(
        &mut self,
        statement: &LedgerStatement,
        checkpoint_sequence: Option<u64>,
    ) -> usize {
        let ledger_sequence = statement.sequence;
        let certified_request = match &statement.payload {
            LedgerPayload::Allocation(allocation) => Some((allocation.request, allocation.binding)),
            LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => None,
        };
        let stale = self
            .outbox
            .iter()
            .filter(|(id, message)| {
                match id.operation {
                    // Checkpoint messages use the globally monotonic checkpoint ordinal, not the
                    // ledger sequence. Observation-only checkpoints can make those two counters
                    // diverge, so compare checkpoint effects only with an explicitly completed
                    // checkpoint. Preserve the current certificate for catch-up gossip.
                    DepositOperation::IndexCheckpointAttest => {
                        checkpoint_sequence.is_some_and(|sequence| id.sequence <= sequence)
                    }
                    DepositOperation::IndexCheckpointCertificate => {
                        checkpoint_sequence.is_some_and(|sequence| id.sequence < sequence)
                    }
                    _ if id.sequence <= ledger_sequence => match id.operation {
                        DepositOperation::Certificate => id.sequence < ledger_sequence,
                        DepositOperation::ClientRequest => {
                            certified_request.is_some_and(|(request, binding)| {
                                self.outbox_bodies
                                    .get(&message.body_digest)
                                    .and_then(|body| {
                                        postcard::from_bytes::<DepositClientRequestWire>(body).ok()
                                    })
                                    .is_some_and(|wire| {
                                        wire.request.request == request
                                            && wire.request.binding == binding
                                    })
                            })
                        }
                        DepositOperation::ConsensusProposal
                        | DepositOperation::ConsensusMessage
                        | DepositOperation::ConsensusCertificate
                        | DepositOperation::Allocate
                        | DepositOperation::Attest
                        | DepositOperation::Handoff
                        | DepositOperation::ConsolidationCompletion => true,
                        // Sync is request/response only. Consolidation signing has its own portable
                        // closure/pruning rules; a ledger height must never discard either one.
                        DepositOperation::SyncHead
                        | DepositOperation::SyncObjects
                        | DepositOperation::DepositObservation
                        | DepositOperation::DepositObservationAttest
                        | DepositOperation::DepositObservationCertificate
                        | DepositOperation::DepositObservationIndexCheckpointAttest
                        | DepositOperation::DepositObservationIndexCheckpointCertificate
                        | DepositOperation::Consolidation
                        | DepositOperation::ConsolidationAbandonment => false,
                        DepositOperation::IndexCheckpointAttest
                        | DepositOperation::IndexCheckpointCertificate => false,
                    },
                    _ => false,
                }
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        stale.len()
    }

    fn prune_deposit_observation_outbox_in_place(
        &mut self,
        statement: &DepositObservationStatement,
    ) -> Result<usize, DepositServiceError> {
        let digest = statement.digest();
        let output = statement.output();
        let stale = self
            .outbox
            .iter()
            .filter_map(|(id, message)| {
                let body = match self.outbox_bodies.get(&message.body_digest) {
                    Some(body) => body,
                    None => return Some(Err(DepositServiceError::InvalidOutbox)),
                };
                let matches = match id.operation {
                    DepositOperation::DepositObservation => {
                        postcard::from_bytes::<DepositObservationWire>(body).is_ok_and(|wire| {
                            wire.statement.output() == output && wire.statement.digest() == digest
                        })
                    }
                    DepositOperation::DepositObservationAttest => postcard::from_bytes::<
                        DepositObservationAttestationWire,
                    >(body)
                    .is_ok_and(|wire| {
                        wire.statement.output() == output && wire.statement.digest() == digest
                    }),
                    DepositOperation::DepositObservationCertificate => postcard::from_bytes::<
                        DepositObservationCertificateWire,
                    >(body)
                    .is_ok_and(|wire| {
                        wire.observation.statement.output() == output
                            && wire.observation.statement.digest() == digest
                    }),
                    DepositOperation::DepositObservationIndexCheckpointAttest => {
                        DepositObservationIndexCheckpointAttestWire::from_bytes(body)
                            .is_ok_and(|wire| wire.binding().statement_digest() == digest)
                    }
                    DepositOperation::DepositObservationIndexCheckpointCertificate => {
                        DepositObservationIndexCheckpointCertificateWire::from_bytes(body)
                            .is_ok_and(|wire| wire.binding().statement_digest() == digest)
                    }
                    DepositOperation::Allocate
                    | DepositOperation::Attest
                    | DepositOperation::Certificate
                    | DepositOperation::Handoff
                    | DepositOperation::IndexCheckpointAttest
                    | DepositOperation::IndexCheckpointCertificate
                    | DepositOperation::SyncHead
                    | DepositOperation::SyncObjects
                    | DepositOperation::ConsolidationCompletion
                    | DepositOperation::Consolidation
                    | DepositOperation::ClientRequest
                    | DepositOperation::ConsolidationAbandonment
                    | DepositOperation::ConsensusProposal
                    | DepositOperation::ConsensusMessage
                    | DepositOperation::ConsensusCertificate => false,
                };
                matches.then_some(Ok(*id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for id in &stale {
            self.outbox.remove(id);
        }
        self.prune_unreferenced_outbox_bodies();
        Ok(stale.len())
    }

    /// Atomically append a batch of peer effects and consume one snapshot revision.
    pub(crate) fn enqueue_many<I>(
        &mut self,
        messages: I,
    ) -> Result<Vec<DepositPeerMessageId>, DepositServiceError>
    where
        I: IntoIterator<Item = (u64, PartyId, DepositOperation, Vec<u8>)>,
    {
        let messages = messages.into_iter().collect::<Vec<_>>();
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        let mut staged = Vec::with_capacity(messages.len());
        for (sequence, recipient, operation, body) in messages {
            if sequence == 0 {
                return Err(DepositServiceError::InvalidSequence);
            }
            if body.is_empty() || body.len() > max_deposit_message_bytes(operation) {
                return Err(DepositServiceError::InvalidMessageSize);
            }
            if operation == DepositOperation::Consolidation {
                let wire = ByzantineConsolidationWireMessage::decode(&body)?;
                if wire.expected_recipient() != recipient {
                    return Err(DepositServiceError::InvalidOutbox);
                }
            }
            if operation == DepositOperation::ConsolidationAbandonment {
                let wire = ConsolidationAbandonmentObservationWire::decode(&body)?;
                wire.observation.slot.committee().member(recipient)?;
            }
            let id =
                DepositPeerMessageId::derive(self.wallet, sequence, recipient, operation, &body);
            if let Some(existing) = self.outbox.get(&id) {
                let existing_body = self
                    .outbox_bodies
                    .get(&existing.body_digest)
                    .ok_or(DepositServiceError::InvalidOutbox)?;
                if existing_body != &body {
                    return Err(DepositServiceError::OutboxEquivocation);
                }
            }
            staged.push((id, body));
        }
        let mut staged_bodies = BTreeMap::new();
        for (_, body) in &staged {
            let body_digest = deposit_message_body_digest(body);
            if self.outbox_bodies.get(&body_digest).is_some_and(|existing| existing != body)
                || staged_bodies.insert(body_digest, body).is_some_and(|existing| existing != body)
            {
                return Err(DepositServiceError::OutboxEquivocation);
            }
        }
        let newly_added = staged
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !self.outbox.contains_key(id))
            .collect::<BTreeSet<_>>()
            .len();
        if self.outbox.len().saturating_add(newly_added) > MAX_DEPOSIT_OUTBOX_ENTRIES {
            return Err(DepositServiceError::OutboxFull);
        }
        let recipients = staged.iter().map(|(id, _)| id.recipient).collect::<BTreeSet<_>>();
        for recipient in recipients {
            let existing = self.outbox.keys().filter(|id| id.recipient == recipient).count();
            let added = staged
                .iter()
                .filter(|(id, _)| id.recipient == recipient && !self.outbox.contains_key(id))
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
                .len();
            if existing.saturating_add(added) > MAX_DEPOSIT_OUTBOX_ENTRIES_PER_RECIPIENT {
                return Err(DepositServiceError::OutboxFull);
            }
        }
        let changed = staged.iter().any(|(id, _)| !self.outbox.contains_key(id));
        let revision = changed.then(|| self.next_revision()).transpose()?;
        let mut identifiers = Vec::with_capacity(staged.len());
        for (id, body) in staged {
            identifiers.push(id);
            if let std::collections::btree_map::Entry::Vacant(entry) = self.outbox.entry(id) {
                let body_digest = deposit_message_body_digest(&body);
                if let Some(existing) = self.outbox_bodies.get(&body_digest) {
                    if existing != &body {
                        return Err(DepositServiceError::OutboxEquivocation);
                    }
                } else {
                    self.outbox_bodies.insert(body_digest, body);
                }
                entry.insert(DurableDepositMessage { id, body_digest });
            }
        }
        if let Some(revision) = revision {
            self.revision = revision;
        }
        Ok(identifiers)
    }

    pub(crate) fn pending(&self, limit: usize) -> Vec<PendingDepositPeerMessage> {
        let limit = limit.min(MAX_DEPOSIT_OUTBOX_ENTRIES);
        if limit == 0 {
            return Vec::new();
        }
        let mut pending = self
            .outbox
            .values()
            .filter_map(|message| {
                self.outbox_bodies
                    .get(&message.body_digest)
                    .map(|body| PendingDepositPeerMessage { id: message.id, body: body.clone() })
            })
            .collect::<Vec<_>>();
        pending.sort_by_key(|message| {
            (
                message.id.sequence,
                causal_operation_order(message.id.operation),
                message.id.recipient,
                message.id.digest,
            )
        });
        // Always expose the causal-earliest item for every recipient before using the remaining
        // batch capacity. A low-id silent peer may retain thousands of durable effects; a global
        // prefix would otherwise hide all work for healthy higher-id recipients indefinitely.
        let mut first_by_recipient = BTreeMap::new();
        for message in &pending {
            first_by_recipient.entry(message.recipient()).or_insert_with(|| message.clone());
        }
        let mut fair = first_by_recipient.into_values().take(limit).collect::<Vec<_>>();
        if fair.len() == limit {
            return fair;
        }
        let selected = fair.iter().map(|message| message.id).collect::<BTreeSet<_>>();
        fair.extend(
            pending
                .into_iter()
                .filter(|message| !selected.contains(&message.id))
                .take(limit - fair.len()),
        );
        fair
    }

    pub(crate) fn acknowledge(
        &mut self,
        acknowledgements: &[DepositPeerMessageId],
    ) -> Result<usize, DepositServiceError> {
        for acknowledgement in acknowledgements {
            if acknowledgement.wallet != self.wallet {
                return Err(DepositServiceError::WrongWallet);
            }
        }
        let removed = acknowledgements
            .iter()
            .filter(|acknowledgement| self.outbox.contains_key(acknowledgement))
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        if removed != 0 {
            let revision = self.next_revision()?;
            for acknowledgement in acknowledgements {
                self.outbox.remove(acknowledgement);
            }
            self.prune_unreferenced_outbox_bodies();
            self.revision = revision;
        }
        Ok(removed)
    }

    fn prune_unreferenced_outbox_bodies(&mut self) {
        let referenced =
            self.outbox.values().map(|message| message.body_digest).collect::<BTreeSet<_>>();
        self.outbox_bodies.retain(|digest, _| referenced.contains(digest));
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, DepositServiceError> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositServiceError::Serialization)?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(DepositServiceError::SnapshotTooLarge);
        }
        Ok(bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, DepositServiceError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(DepositServiceError::SnapshotTooLarge);
        }
        let (version, _) = postcard::take_from_bytes::<u16>(bytes)
            .map_err(|_| DepositServiceError::Serialization)?;
        if version != DEPOSIT_SERVICE_SNAPSHOT_VERSION {
            return Err(DepositServiceError::UnsupportedVersion(version));
        }
        let (snapshot, remaining) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositServiceError::Serialization)?;
        if !remaining.is_empty() {
            return Err(DepositServiceError::TrailingBytes);
        }
        snapshot.validate()?;
        if snapshot.to_bytes()? != bytes {
            return Err(DepositServiceError::NonCanonicalSnapshot);
        }
        Ok(snapshot)
    }

    fn next_revision(&self) -> Result<u64, DepositServiceError> {
        self.revision.checked_add(1).ok_or(DepositServiceError::RevisionExhausted)
    }

    fn validate(&self) -> Result<(), DepositServiceError> {
        if self.version != DEPOSIT_SERVICE_SNAPSHOT_VERSION {
            return Err(DepositServiceError::UnsupportedVersion(self.version));
        }
        let archive_head = self.archive_head()?;
        self.compact_registry_checkpoint.to_bytes()?;
        self.deposit_index_checkpoint.to_bytes()?;
        let portable_head =
            PortableDepositIndexHead::from_head(self.deposit_index_checkpoint.portable_head())?;
        if let Some(certificate) = &self.index_checkpoint_certificate {
            certificate.to_bytes()?;
        }
        self.roast_attempt_archive_head.validate()?;
        archive_head.validate()?;
        if archive_head.wallet_id() != self.wallet
            || self.compact_registry_checkpoint.wallet() != self.wallet
            || self.compact_registry_checkpoint.head().is_none()
            || self.deposit_index_checkpoint.wallet() != self.wallet
            || self.roast_attempt_archive_head.wallet_id() != self.wallet
            || self.roast_attempt_archive_head.network_id() == [0; 32]
        {
            return Err(DepositServiceError::WrongWallet);
        }
        match (
            portable_head.through_sequence(),
            self.checkpoint_operation_certificate,
            self.index_checkpoint_certificate.as_ref(),
        ) {
            (0, None, None) if archive_head.is_empty() => {}
            (0, _, _) | (_, None, _) | (_, _, None) => {
                return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
            }
            (ledger_sequence, Some(operation), Some(checkpoint)) => {
                let expected_kind = match checkpoint.statement().operation() {
                    DepositIndexCheckpointOperation::Ledger { .. } => {
                        CERTIFIED_LEDGER_ENTRY_ARTIFACT
                    }
                    DepositIndexCheckpointOperation::DepositObservation { .. } => {
                        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
                    }
                };
                if operation.wallet_id() != WalletId(self.wallet.0)
                    || operation.kind() != expected_kind
                    || checkpoint.statement().sequence() != archive_head.len()
                    || checkpoint.statement().ledger_sequence() != ledger_sequence
                    || checkpoint.statement().resulting_head() != &portable_head
                {
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
            }
        }
        if self.wallet.0 == [0_u8; 32]
            || self.birth_anchor.hash == [0_u8; 32]
            || self.reducer.is_empty()
        {
            return Err(DepositServiceError::WrongWallet);
        }
        if self.reducer.len() > MAX_REDUCER_BYTES {
            return Err(DepositServiceError::ReducerTooLarge);
        }
        let consolidation = ConsolidationCoordinator::decode(&self.consolidation)?;
        if consolidation.wallet_id() != self.wallet {
            return Err(DepositServiceError::WrongWallet);
        }
        self.validate_roasts()?;
        if let Some(worker) = &self.worker {
            if worker.wallet_id() != self.wallet
                || worker.scan_state().birth_anchor() != self.birth_anchor
            {
                return Err(DepositServiceError::WrongWallet);
            }
            worker.encode()?;
        }
        if self.outbox.len() > MAX_DEPOSIT_OUTBOX_ENTRIES {
            return Err(DepositServiceError::OutboxFull);
        }
        for (id, message) in &self.outbox {
            let body = self
                .outbox_bodies
                .get(&message.body_digest)
                .ok_or(DepositServiceError::InvalidOutbox)?;
            if id != &message.id
                || id.wallet != self.wallet
                || id.sequence == 0
                || body.is_empty()
                || body.len() > max_deposit_message_bytes(id.operation)
                || deposit_message_body_digest(body) != message.body_digest
                || DepositPeerMessageId::derive(
                    self.wallet,
                    id.sequence,
                    id.recipient,
                    id.operation,
                    body,
                ) != *id
            {
                return Err(DepositServiceError::InvalidOutbox);
            }
            if id.operation == DepositOperation::Consolidation {
                let wire = ByzantineConsolidationWireMessage::decode(body)?;
                if matches!(wire, ByzantineConsolidationWireMessage::Ack(_))
                    || wire.expected_recipient() != id.recipient
                    || id.sequence
                        != match &wire {
                            ByzantineConsolidationWireMessage::Consensus(message) => {
                                message.slot().ledger_sequence()
                            }
                            ByzantineConsolidationWireMessage::CertifiedIntent(message) => {
                                message.slot().ledger_sequence()
                            }
                            ByzantineConsolidationWireMessage::Preprocess(_)
                            | ByzantineConsolidationWireMessage::KeyImageBinding(_)
                            | ByzantineConsolidationWireMessage::Share(_)
                            | ByzantineConsolidationWireMessage::Candidate(_) => {
                                let (_, roast) = self.roast_by_family(wire.family())?;
                                if !matches!(&wire, ByzantineConsolidationWireMessage::Candidate(_))
                                    && wire
                                        .view()
                                        .checked_add(1)
                                        .is_some_and(|successor| successor < roast.next_view())
                                {
                                    return Err(DepositServiceError::InvalidOutbox);
                                }
                                roast.expected_slot(wire.view())?.ledger_sequence()
                            }
                            ByzantineConsolidationWireMessage::Ack(_) => unreachable!(),
                        }
                {
                    return Err(DepositServiceError::InvalidOutbox);
                }
            }
            if id.operation == DepositOperation::ConsolidationAbandonment {
                let wire = ConsolidationAbandonmentObservationWire::decode(body)?;
                wire.observation.slot.committee().member(id.recipient)?;
            }
        }
        let referenced =
            self.outbox.values().map(|message| message.body_digest).collect::<BTreeSet<_>>();
        if referenced.len() != self.outbox_bodies.len()
            || self.outbox_bodies.keys().any(|digest| !referenced.contains(digest))
        {
            return Err(DepositServiceError::InvalidOutbox);
        }
        Ok(())
    }
}

struct DepositRuntime {
    deriver: DepositAddressDeriver,
    snapshot: DepositServiceSnapshot,
    protocol: DepositProtocolState,
    consolidation: ConsolidationCoordinator,
}

/// Per-tick authenticated index adapter. Local output bindings cross their own wallet-snapshot CAS
/// before the worker is allowed to return a cursor advance. The service then uses the adapter's
/// read-back snapshot as the base for the worker-state CAS.
struct SnapshotDepositOutputIndexBackend {
    wallet: DepositWalletId,
    repository: Arc<DepositSnapshotRepository>,
    index: Arc<Mutex<Option<DepositIndexStore>>>,
    snapshot: Mutex<DepositServiceSnapshot>,
}

impl SnapshotDepositOutputIndexBackend {
    fn new(
        wallet: DepositWalletId,
        repository: Arc<DepositSnapshotRepository>,
        index: Arc<Mutex<Option<DepositIndexStore>>>,
        snapshot: DepositServiceSnapshot,
    ) -> Self {
        Self { wallet, repository, index, snapshot: Mutex::new(snapshot) }
    }

    async fn durable_snapshot(&self) -> DepositServiceSnapshot {
        self.snapshot.lock().await.clone()
    }

    fn chain_error(error: impl std::fmt::Display) -> crate::deposit_worker::ChainSourceError {
        crate::deposit_worker::ChainSourceError::Invalid(format!(
            "authenticated deposit index: {error}"
        ))
    }
}

impl DepositOutputIndexBackend for SnapshotDepositOutputIndexBackend {
    fn portable_snapshot(
        &self,
        wallet: DepositWalletId,
    ) -> crate::deposit_worker::ChainFuture<'_, [u8; 32]> {
        Box::pin(async move {
            if wallet != self.wallet {
                return Err(Self::chain_error("wrong wallet"));
            }
            let guard = self.index.lock().await;
            let store = guard.as_ref().ok_or_else(|| Self::chain_error("store unavailable"))?;
            Ok(store.portable_head().digest())
        })
    }

    fn preload_subaddress_spend_keys<'a>(
        &'a self,
        wallet: DepositWalletId,
        portable_snapshot: [u8; 32],
        spend_keys: &'a [[u8; 32]],
    ) -> crate::deposit_worker::ChainFuture<'a, Vec<Option<DepositSubaddressIndex>>> {
        Box::pin(async move {
            if wallet != self.wallet {
                return Err(Self::chain_error("wrong wallet"));
            }
            let mut guard = self.index.lock().await;
            let store = guard.as_mut().ok_or_else(|| Self::chain_error("store unavailable"))?;
            if store.portable_head().digest() != portable_snapshot {
                return Err(Self::chain_error("portable snapshot changed"));
            }
            let mut result = Vec::with_capacity(spend_keys.len());
            for spend_key in spend_keys {
                let query = PortableAllocationQuery::SubaddressSpendKey(*spend_key);
                let record = store.lookup_portable(&query).await.map_err(Self::chain_error)?;
                result.push(record.map(|record| record.allocation().address.index()));
            }
            if store.portable_head().digest() != portable_snapshot {
                return Err(Self::chain_error("portable snapshot changed"));
            }
            Ok(result)
        })
    }

    fn bind_outputs<'a>(
        &'a self,
        wallet: DepositWalletId,
        portable_snapshot: [u8; 32],
        bindings: &'a [DepositOutputBinding],
    ) -> crate::deposit_worker::ChainFuture<'a, ()> {
        Box::pin(async move {
            if wallet != self.wallet {
                return Err(Self::chain_error("wrong wallet"));
            }
            if bindings.is_empty() {
                return Ok(());
            }
            let mut index_guard = self.index.lock().await;
            let store =
                index_guard.as_mut().ok_or_else(|| Self::chain_error("store unavailable"))?;
            if store.portable_head().digest() != portable_snapshot {
                return Err(Self::chain_error("portable snapshot changed"));
            }
            let expected_checkpoint = store.checkpoint().clone();
            let local_safety_head = store.local_safety_head().clone();
            for binding in bindings {
                store
                    .preload_local_safety_query(LocalSafetyQuery::Output(binding.output))
                    .await
                    .map_err(Self::chain_error)?;
                store
                    .preload_local_safety_query(LocalSafetyQuery::OneTimeOutputKey(
                        binding.output_key,
                    ))
                    .await
                    .map_err(Self::chain_error)?;
                if let Some(index) = binding.subaddress {
                    store
                        .preload_local_safety_query(LocalSafetyQuery::FirstUsed(index))
                        .await
                        .map_err(Self::chain_error)?;
                }
            }
            let mut builder =
                DepositIndexBuilder::new(&*store, local_safety_head).map_err(Self::chain_error)?;
            for binding in bindings {
                if binding.observed_at == 0 {
                    return Err(Self::chain_error("zero output observation timestamp"));
                }
                builder
                    .bind_output(
                        binding.output,
                        binding.output_key,
                        binding.subaddress,
                        binding.amount_atomic_units,
                    )
                    .map_err(Self::chain_error)?;
                if let Some(index) = binding.subaddress {
                    builder
                        .mark_first_used(index, binding.observed_at)
                        .map_err(Self::chain_error)?;
                }
            }
            let Some(update) = builder.finish().map_err(Self::chain_error)? else {
                return Ok(());
            };
            let prepared = store.prepare_snapshot(vec![update]).await.map_err(Self::chain_error)?;
            let mut snapshot_guard = self.snapshot.lock().await;
            if snapshot_guard.deposit_index_checkpoint() != &expected_checkpoint {
                store.abort_prepared(&prepared).await.map_err(Self::chain_error)?;
                return Err(Self::chain_error("wallet snapshot checkpoint changed"));
            }
            let mut candidate = snapshot_guard.clone();
            candidate
                .install_deposit_index_checkpoint(
                    &expected_checkpoint,
                    prepared.checkpoint().clone(),
                )
                .map_err(Self::chain_error)?;
            let durable = match self.repository.persist_and_read_back(&candidate).await {
                Ok(durable) => durable,
                Err(save_error) => {
                    // A save/readback error is ambiguous: the wallet snapshot may already have
                    // installed the prepared checkpoint before the read failed. Never destroy
                    // its recovery journal until an authenticated reload proves that the old
                    // checkpoint is still authoritative.
                    let authenticated = match self.repository.load(self.wallet).await {
                        Ok(snapshot) => snapshot,
                        Err(load_error) => {
                            return Err(Self::chain_error(format!(
                                "ambiguous wallet snapshot commit ({save_error}); authenticated \
                                 reload failed ({load_error})"
                            )));
                        }
                    };
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint() {
                        *snapshot_guard = authenticated.clone();
                        authenticated
                    } else if authenticated.deposit_index_checkpoint() == &expected_checkpoint {
                        *snapshot_guard = authenticated;
                        store.abort_prepared(&prepared).await.map_err(Self::chain_error)?;
                        return Err(Self::chain_error(save_error));
                    } else {
                        *snapshot_guard = authenticated;
                        return Err(Self::chain_error(
                            "ambiguous wallet snapshot commit resolved to an unrelated checkpoint",
                        ));
                    }
                }
            };
            if durable.deposit_index_checkpoint() != prepared.checkpoint() {
                return Err(Self::chain_error("unsettled checkpoint readback mismatch"));
            }
            // Preserve the authenticated unsettled checkpoint in memory before asking the index
            // store to clear its recovery journal. If that commit fails, the service must carry
            // the exact durable recovery anchor forward rather than accidentally reverting to
            // the pre-journal checkpoint on the worker's subsequent error path.
            *snapshot_guard = durable.clone();
            store
                .commit_prepared(&prepared, durable.deposit_index_checkpoint())
                .await
                .map_err(Self::chain_error)?;
            let mut settled_candidate = durable;
            settled_candidate
                .install_deposit_index_checkpoint(
                    prepared.checkpoint(),
                    prepared.settled_checkpoint().clone(),
                )
                .map_err(Self::chain_error)?;
            let settled = self
                .repository
                .persist_and_read_back(&settled_candidate)
                .await
                .map_err(Self::chain_error)?;
            if settled.deposit_index_checkpoint() != store.checkpoint() {
                return Err(Self::chain_error("settled checkpoint readback mismatch"));
            }
            *snapshot_guard = settled;
            Ok(())
        })
    }
}

fn consolidation_intent_consensus_domain() -> [u8; 32] {
    *blake3::Hasher::new_derive_key(
        "threshold-monero/deposit-consolidation-intent-consensus-domain/v1",
    )
    .finalize()
    .as_bytes()
}

fn validate_byzantine_identity(
    identity: &Identity,
    committee: &Committee,
    expected_party: PartyId,
) -> Result<(), DepositServiceError> {
    if identity.party() != expected_party
        || committee.member(expected_party)?.signing_key != identity.signing_public_key()
    {
        return Err(DepositServiceError::WrongLocalParty);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct RetainedByzantineAuthority {
    committee: Committee,
    fault_bound: u16,
}

impl RetainedByzantineAuthority {
    const fn committee(&self) -> &Committee {
        &self.committee
    }

    const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }
}

fn validate_runtime_wallet_group(
    runtime: &DepositRuntime,
) -> Result<[u8; 32], DepositServiceError> {
    let active_group = runtime.protocol.registry.active().group_key();
    let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    if active_group != runtime.deriver.root_spend_key()
        || active_group != worker.scan_state().root_spend_key()
    {
        return Err(DepositServiceError::WrongRegistry);
    }
    Ok(active_group)
}

fn validate_retained_byzantine_roast(
    runtime: &DepositRuntime,
    roast: &ConsolidationRoast,
    expected_network: [u8; 32],
) -> Result<[u8; 32], DepositServiceError> {
    let active_group = validate_runtime_wallet_group(runtime)?;
    if roast.quic_network_id() != expected_network
        || roast.authorization().root_group_key() != active_group
        || roast.wallet_id() != runtime.snapshot.wallet
    {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    Ok(active_group)
}

fn validate_restored_byzantine_authority(
    protocol: &DepositProtocolState,
    snapshot: &DepositServiceSnapshot,
    deriver: &DepositAddressDeriver,
    expected_network: [u8; 32],
) -> Result<(), DepositServiceError> {
    let active = protocol.registry.active();
    let worker = snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    let group = active.group_key();
    if group != deriver.root_spend_key() || group != worker.scan_state().root_spend_key() {
        return Err(DepositServiceError::WrongRegistry);
    }
    if let Some(lane) = &snapshot.byzantine_consensus_lane {
        let slot = &lane.slot;
        if active.epoch() != slot.committee().epoch
            || active.committee() != slot.committee()
            || active.fault_bound() != slot.fault_bound()
            || active.activation_binding() != slot.binding().activation
            || active.registry_id().digest() != slot.binding().registry
            || slot.binding().wallet != snapshot.wallet.0
            || slot.binding().network != expected_network
            || slot.binding().domain != consolidation_intent_consensus_domain()
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        slot.consensus_context()?;
    }
    for bytes in snapshot.consolidation_roasts.values() {
        let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
        if roast.quic_network_id() != expected_network
            || roast.authorization().root_group_key() != group
            || roast.wallet_id() != snapshot.wallet
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
    }
    Ok(())
}

fn validate_active_byzantine_slot(
    runtime: &DepositRuntime,
    slot: &ConsolidationConsensusSlot,
    expected_network: [u8; 32],
) -> Result<RetainedByzantineAuthority, DepositServiceError> {
    let active = runtime.protocol.registry.active();
    validate_runtime_wallet_group(runtime)?;
    if active.epoch() != slot.committee().epoch
        || active.committee() != slot.committee()
        || active.fault_bound() != slot.fault_bound()
        || active.activation_binding() != slot.binding().activation
        || active.registry_id().digest() != slot.binding().registry
        || slot.binding().wallet != runtime.snapshot.wallet.0
        || slot.binding().network != expected_network
        || slot.binding().domain != consolidation_intent_consensus_domain()
    {
        return Err(DepositServiceError::WrongRegistry);
    }
    slot.consensus_context()?;
    Ok(RetainedByzantineAuthority {
        committee: slot.committee().clone(),
        fault_bound: slot.fault_bound(),
    })
}

fn validate_certified_intent_family_chain(
    runtime: &DepositRuntime,
    certified: &ByzantineCertifiedIntent,
    intent: &ConsolidationIntent,
    expected_family: [u8; 32],
) -> Result<(), DepositServiceError> {
    if certified.family() != expected_family {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    let view = certified.slot().roast_view();
    if view == 0 {
        return Ok(());
    }
    let (_, roast) = runtime.snapshot.roast_by_family(expected_family)?;
    let record = runtime
        .consolidation
        .record(roast.authorization_id())
        .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
    if roast.expected_slot(view)? != *certified.slot()
        || roast.authorization() != intent.authorization()
        || roast.committee() != certified.slot().committee()
        || roast.fault_bound() != certified.slot().fault_bound()
        || !matches!(
            record.phase,
            ConsolidationPhase::IntentReserved
                | ConsolidationPhase::SigningReleased { .. }
                | ConsolidationPhase::AwaitingFreshAttempt { .. }
                | ConsolidationPhase::AttemptsExhausted { .. }
        )
    {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    Ok(())
}

fn retained_certified_intent_matches(
    runtime: &DepositRuntime,
    certified: &ByzantineCertifiedIntent,
    expected_family: [u8; 32],
) -> Result<bool, DepositServiceError> {
    let Ok((_, roast)) = runtime.snapshot.roast_by_family(expected_family) else {
        return Ok(false);
    };
    if roast.family_digest() != certified.family() {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    let view = certified.slot().roast_view();
    if view >= roast.next_view() {
        return Ok(false);
    }
    let (context, intent, certificate) = roast
        .certified_intent(view)
        .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
    let wire_intent = certified.certificate().verify_in_context(context)?;
    if roast.expected_slot(view)? != *certified.slot()
        || &wire_intent != intent
        || certified.certificate() != certificate
        || certified.binding() != &roast.wire_binding(view)?
    {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    let retained_prepared = worker
        .scan_state()
        .sweep(roast.sweep_id())
        .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?
        .signing_intent
        .prepared_sweep_intent_bytes();
    if retained_prepared != certified.prepared_intent_bytes() {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    Ok(true)
}

fn byzantine_bootstrap_action(
    lane: &DurableByzantineConsensusLane,
) -> Result<ByzantineConsolidationAction, DepositServiceError> {
    lane.validate()?;
    if lane.reducer.started() {
        return Err(DepositServiceError::InvalidByzantineConsolidationState);
    }
    let local = lane
        .admitted_values
        .get(&lane.local_candidate)
        .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
    let sweep = PreparedSweepIntent::decode(&local.prepared_intent)?.plan().id;
    Ok(ByzantineConsolidationAction::BootstrapPrepared {
        sweep,
        slot: lane.slot.digest(),
        outer_view: lane.slot.roast_view(),
        bootstrap_ba_view: lane.reducer.view(),
        proposer: lane.reducer.leader(),
        binding: local.binding.clone(),
        prepared_intent_digest: local.prepared_intent_digest,
        continuation: lane.continuation()?,
    })
}

fn byzantine_value_attachment(
    lane: &DurableByzantineConsensusLane,
    value: &ConsensusValue,
) -> Result<ByzantineConsensusValueAttachment, DepositServiceError> {
    let admitted = lane
        .admitted_values
        .get(&value.digest())
        .filter(|admitted| admitted.value == *value)
        .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
    Ok(ByzantineConsensusValueAttachment::new(
        lane.reducer.context(),
        &lane.slot,
        value,
        admitted.binding.clone(),
        admitted.prepared_intent.clone(),
    )?)
}

fn byzantine_consensus_step_messages(
    relay: PartyId,
    lane: &DurableByzantineConsensusLane,
    step: &ConsensusStep,
) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
    lane.validate()?;
    lane.slot.committee().member(relay)?;
    let context = lane.reducer.context().clone();
    let peers = lane
        .slot
        .committee()
        .members
        .iter()
        .map(|member| member.id)
        .filter(|party| *party != relay)
        .collect::<Vec<_>>();
    let mut output = Vec::new();
    for envelope in &step.broadcast {
        let body = ByzantineConsensusBody::Message(envelope.clone());
        let attachments = referenced_consolidation_consensus_values(&context, &body)?
            .iter()
            .map(|value| byzantine_value_attachment(lane, value))
            .collect::<Result<Vec<_>, _>>()?;
        for recipient in peers.iter().copied().filter(|party| *party != envelope.from) {
            let relay_message = ByzantineConsensusRelay::new_message(
                relay,
                recipient,
                lane.slot.clone(),
                context.clone(),
                envelope.clone(),
                attachments.clone(),
            )?;
            let encoded = ByzantineConsolidationWireMessage::Consensus(relay_message).encode()?;
            output.push((
                lane.slot.ledger_sequence(),
                recipient,
                DepositOperation::Consolidation,
                encoded,
            ));
        }
    }
    if let Some(certificate) = &step.relay_view_certificate {
        let body = ByzantineConsensusBody::ViewCertificate(certificate.clone());
        let attachments = referenced_consolidation_consensus_values(&context, &body)?
            .iter()
            .map(|value| byzantine_value_attachment(lane, value))
            .collect::<Result<Vec<_>, _>>()?;
        for recipient in peers {
            let relay_message = ByzantineConsensusRelay::new_view_certificate(
                relay,
                recipient,
                lane.slot.clone(),
                context.clone(),
                certificate.clone(),
                attachments.clone(),
            )?;
            let encoded = ByzantineConsolidationWireMessage::Consensus(relay_message).encode()?;
            output.push((
                lane.slot.ledger_sequence(),
                recipient,
                DepositOperation::Consolidation,
                encoded,
            ));
        }
    }
    Ok(output)
}

fn has_live_byzantine_family(runtime: &DepositRuntime) -> Result<bool, DepositServiceError> {
    Ok(live_byzantine_roast(runtime)?.is_some())
}

fn live_byzantine_roast(
    runtime: &DepositRuntime,
) -> Result<Option<ConsolidationRoast>, DepositServiceError> {
    let mut live = None;
    for bytes in runtime.snapshot.consolidation_roasts.values() {
        let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
        let record = runtime
            .consolidation
            .record(roast.authorization_id())
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        if matches!(
            record.phase,
            ConsolidationPhase::IntentReserved
                | ConsolidationPhase::SigningReleased { .. }
                | ConsolidationPhase::AwaitingFreshAttempt { .. }
                | ConsolidationPhase::AttemptsExhausted { .. }
        ) {
            if live.replace(roast).is_some() {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
        }
    }
    Ok(live)
}

fn pending_byzantine_roast_actions(
    runtime: &DepositRuntime,
    local_party: PartyId,
) -> Result<Vec<ByzantineConsolidationAction>, DepositServiceError> {
    let mut actions = Vec::new();
    if let Some(roast) = live_byzantine_roast(runtime)? {
        let view = roast
            .next_view()
            .checked_sub(1)
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let binding = roast.wire_binding(view)?;
        if let Some(preprocesses) = roast.complete_preprocesses(view)? {
            actions.push(ByzantineConsolidationAction::CompleteContributionSet {
                family: roast.family_digest(),
                view,
                binding: binding.clone(),
                preprocesses: Some(preprocesses),
                shares: None,
            });
        }
        if roast.local_party() == local_party
            && roast.local_safety_phase(view) == Some(AttemptSafetyPhase::NonceReleased)
            && let Some(certificate) = roast.key_image_binding_certificate(view)?
        {
            actions.push(ByzantineConsolidationAction::AuthorizeKeyImages {
                family: roast.family_digest(),
                view,
                binding: binding.clone(),
                certificate: certificate.clone(),
            });
        }
        if let Some(shares) = roast.complete_shares(view)? {
            actions.push(ByzantineConsolidationAction::CompleteContributionSet {
                family: roast.family_digest(),
                view,
                binding,
                preprocesses: None,
                shares: Some(shares),
            });
        }
    }
    Ok(actions)
}

/// One terminal and every full ledger statement reached through its authenticated portable-index
/// aliases. The compact ledger cursor deliberately retains none of this history.
#[derive(Clone, Debug)]
struct AuthenticatedPortableTerminal {
    terminal: PortableConsolidationTerminalRecord,
    current_statement: LedgerStatement,
    abandonment_statement: Option<LedgerStatement>,
}

impl AuthenticatedPortableTerminal {
    fn validate(&self) -> Result<(), DepositServiceError> {
        if self.terminal.wallet_id() != self.current_statement.wallet {
            return Err(DepositServiceError::InvalidPortableTerminalEvidence);
        }
        match (self.terminal.status(), &self.current_statement.payload) {
            (
                PortableConsolidationStatus::Completed {
                    statement_sequence,
                    statement_digest,
                    attempt,
                    session,
                    transaction,
                },
                LedgerPayload::ConsolidationCompletion(completion),
            ) => {
                if self.abandonment_statement.is_some()
                    || self.current_statement.sequence != *statement_sequence
                    || self.current_statement.digest() != *statement_digest
                    || self.terminal.consolidation_id() != completion.id()
                    || self.terminal.sweep_id() != completion.plan().id
                    || self.terminal.sweep_sequence() != completion.plan().sequence
                    || self.terminal.inputs() != completion.inputs()
                    || *attempt != completion.attempt().attempt()
                    || *session != completion.attempt().session()
                    || *transaction != completion.transaction_id()
                {
                    return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                }
            }
            (
                PortableConsolidationStatus::Abandoned { evidence },
                LedgerPayload::ConsolidationAbandonment(abandonment),
            ) => {
                if self
                    .abandonment_statement
                    .as_ref()
                    .is_none_or(|statement| statement != &self.current_statement)
                    || self.current_statement.sequence != evidence.statement_sequence()
                    || self.current_statement.digest() != evidence.statement_digest()
                    || self.terminal.consolidation_id() != abandonment.id()
                    || self.terminal.sweep_id() != abandonment.authorization().sweep_id()
                    || self.terminal.sweep_sequence() != abandonment.sweep_sequence()
                    || self.terminal.inputs() != abandonment.inputs()
                    || evidence.roast_family() != abandonment.family()
                    || evidence.attempt_prefix() != abandonment.attempt_prefix()
                    || evidence.terminal_attempt() != abandonment.attempt().attempt()
                    || evidence.terminal_session() != abandonment.attempt().session()
                {
                    return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                }
            }
            (
                PortableConsolidationStatus::LateSettled {
                    settlement_sequence,
                    settlement_digest,
                    historical_attempt,
                    historical_session,
                    transaction,
                    abandonment,
                },
                LedgerPayload::LateConsolidationSettlement(settlement),
            ) => {
                let completion = settlement.historical_completion();
                let Some(abandonment_statement) = &self.abandonment_statement else {
                    return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                };
                let LedgerPayload::ConsolidationAbandonment(abandonment_payload) =
                    &abandonment_statement.payload
                else {
                    return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                };
                if self.current_statement.sequence != *settlement_sequence
                    || self.current_statement.digest() != *settlement_digest
                    || abandonment_statement.sequence != abandonment.statement_sequence()
                    || abandonment_statement.digest() != abandonment.statement_digest()
                    || settlement.abandonment_statement() != abandonment.statement_digest()
                    || self.terminal.consolidation_id() != settlement.id()
                    || self.terminal.consolidation_id() != abandonment_payload.id()
                    || self.terminal.sweep_id() != completion.plan().id
                    || self.terminal.sweep_id() != abandonment_payload.authorization().sweep_id()
                    || self.terminal.sweep_sequence() != completion.plan().sequence
                    || self.terminal.sweep_sequence() != abandonment_payload.sweep_sequence()
                    || self.terminal.inputs() != completion.inputs()
                    || self.terminal.inputs() != abandonment_payload.inputs()
                    || *historical_attempt != completion.attempt().attempt()
                    || *historical_session != completion.attempt().session()
                    || *transaction != completion.transaction_id()
                    || abandonment.roast_family() != abandonment_payload.family()
                    || abandonment.attempt_prefix() != abandonment_payload.attempt_prefix()
                    || abandonment.terminal_attempt() != abandonment_payload.attempt().attempt()
                    || abandonment.terminal_session() != abandonment_payload.attempt().session()
                {
                    return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                }
            }
            _ => return Err(DepositServiceError::InvalidPortableTerminalEvidence),
        }
        Ok(())
    }

    fn completion(&self) -> Option<&ConsolidationCompletionStatement> {
        match &self.current_statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => Some(completion),
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                Some(settlement.historical_completion())
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationAbandonment(_) => None,
        }
    }

    fn abandonment_statement(&self) -> Option<&LedgerStatement> {
        self.abandonment_statement.as_ref()
    }
}

/// Persistent deposit-address state machine for one party.
///
/// The service starts dormant because the root public spend key does not exist until epoch zero is
/// activated. [`Self::ensure_genesis`] creates or restores the stable wallet exactly once. Every
/// later epoch enters through the atomic certified handoff/index checkpoint transition; the
/// service never constructs a fresh per-epoch allocation state or replays a registry extension.
pub struct DepositService {
    party: PartyId,
    scenario: Scenario,
    repository: Arc<DepositSnapshotRepository>,
    archive: DepositArchiveStore,
    roast_archive: RoastAttemptArchiveStore,
    deposit_index_directory: PathBuf,
    deposit_index_identity_seed: Zeroizing<[u8; 32]>,
    protocol_store: Arc<ProtocolStore>,
    deposit_index: Arc<Mutex<Option<DepositIndexStore>>>,
    compact_registry: Arc<Mutex<Option<CompactRegistryStore>>>,
    private_view_scalar: Zeroizing<[u8; 32]>,
    configured_birth_anchor: Option<ChainPoint>,
    worker_config: DepositWorkerConfig,
    source: Arc<dyn DepositChainSource>,
    consolidation_backend: Option<Arc<dyn DepositConsolidationBackend>>,
    runtime: Mutex<Option<DepositRuntime>>,
    runtime_ready: AtomicBool,
}

impl std::fmt::Debug for DepositService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DepositService")
            .field("party", &self.party)
            .field("configured", &true)
            .finish_non_exhaustive()
    }
}

impl DepositService {
    /// Advance durable ROAST consensus/view timers and return only capabilities which survived an
    /// authenticated snapshot readback.
    pub async fn progress_byzantine_consolidations(
        &self,
        identity: &Identity,
        now_ms: u64,
        base_timeout_ms: u64,
    ) -> Result<Vec<ByzantineConsolidationAction>, DepositServiceError> {
        validate_consensus_now(now_ms)?;
        if identity.party() != self.party || base_timeout_ms == 0 {
            return Err(DepositServiceError::WrongLocalParty);
        }

        let preparation = {
            let mut guard = self.runtime.lock().await;
            let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
            runtime.protocol.require_live()?;
            let expected_network = self.scenario.quic_network_id()?;
            validate_runtime_wallet_group(runtime)?;
            if let Some(slot) = runtime
                .snapshot
                .byzantine_consensus_lane
                .as_ref()
                .map(|lane| lane.slot.clone())
                .filter(|slot| slot.roast_view() > 0)
            {
                let mut matching = None;
                for bytes in runtime.snapshot.consolidation_roasts.values() {
                    let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
                    if roast.expected_slot(slot.roast_view()).ok().as_ref() == Some(&slot) {
                        if matching.replace(roast).is_some() {
                            return Err(DepositServiceError::InvalidByzantineConsolidationState);
                        }
                    }
                }
                if let Some(roast) = matching.filter(ConsolidationRoast::has_endorsed_candidate) {
                    validate_retained_byzantine_roast(runtime, &roast, expected_network)?;
                    let mut snapshot = runtime.snapshot.clone();
                    if !snapshot.cancel_byzantine_lane_for_endorsed_roast(&roast)? {
                        return Err(DepositServiceError::InvalidByzantineConsolidationState);
                    }
                    runtime.snapshot = self.repository.persist_and_read_back(&snapshot).await?;
                    return Ok(self
                        .adopt_endorsed_byzantine_candidate(runtime, &roast)
                        .await?
                        .unwrap_or_default());
                }
            }
            if let Some(lane) = &runtime.snapshot.byzantine_consensus_lane {
                validate_active_byzantine_slot(runtime, &lane.slot, expected_network)?;
                validate_byzantine_identity(identity, lane.slot.committee(), self.party)?;
                lane.validate()?;
                if !lane.reducer.started() {
                    return Ok(vec![byzantine_bootstrap_action(lane)?]);
                }
                if lane.reducer.commit().is_some() {
                    // A commit is intentionally a durable intermediate state. Final nonce release
                    // is handled below by a separate CAS/readback path.
                    return self.finalize_committed_byzantine_lane(runtime, identity, now_ms).await;
                }
                if now_ms >= lane.deadline_unix_ms && !lane.timeout_requested {
                    let mut lane = lane.clone();
                    let step = lane.reducer.request_view_change(identity)?;
                    lane.timeout_requested = true;
                    if let Some(view) = step.entered_view {
                        lane.enter_view(view, now_ms)?;
                    }
                    let messages = byzantine_consensus_step_messages(self.party, &lane, &step)?;
                    let mut snapshot = runtime.snapshot.clone();
                    snapshot.replace_byzantine_lane_and_enqueue(Some(lane), messages)?;
                    let durable = self.repository.persist_and_read_back(&snapshot).await?;
                    runtime.snapshot = durable;
                }
                return Ok(Vec::new());
            }

            if let Some(roast) = live_byzantine_roast(runtime)? {
                validate_retained_byzantine_roast(runtime, &roast, expected_network)?;
                if let Some(actions) =
                    self.adopt_endorsed_byzantine_candidate(runtime, &roast).await?
                {
                    return Ok(actions);
                }
                return self
                    .start_successor_byzantine_lane(
                        runtime,
                        identity,
                        &roast,
                        now_ms,
                        base_timeout_ms,
                    )
                    .await;
            }
            // A handoff is a strict epoch fence. Existing old-epoch lanes/families above may
            // finish, but no new prepared family may cross a pending registry cutover.
            if runtime.protocol.pending_handoff.is_some() {
                return Ok(Vec::new());
            }
            validate_byzantine_identity(
                identity,
                runtime.protocol.registry.active().committee(),
                self.party,
            )?;
            let backend = self
                .consolidation_backend
                .as_ref()
                .cloned()
                .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?;
            let active = runtime.protocol.registry.active();
            let worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let destination =
                root_consolidation_destination_binding(&runtime.deriver, worker.config());
            let Some(plan) = worker.plan_sweep(active.committee().epoch, destination)? else {
                return Ok(Vec::new());
            };
            let ledger_sequence = runtime.protocol.ledger.next_sequence();
            let ledger_previous = runtime.protocol.ledger.head();
            let ledger_height = if ledger_previous == [0; 32] { 0 } else { ledger_sequence };
            (
                backend,
                worker,
                plan,
                active.committee().clone(),
                active.fault_bound(),
                runtime.protocol.registry.digest(),
                active.activation_binding(),
                runtime.deriver.root_spend_key(),
                runtime.snapshot.revision,
                ledger_height,
                ledger_sequence,
                ledger_previous,
            )
        };

        let (
            backend,
            worker_before_rpc,
            plan,
            committee,
            fault_bound,
            registry_digest,
            activation_digest,
            root_group_key,
            snapshot_revision,
            ledger_height,
            ledger_sequence,
            ledger_previous,
        ) = preparation;
        let deriver = DepositAddressDeriver::new(
            self.scenario.network,
            root_group_key,
            &self.private_view_scalar,
        )?;
        let prepared = backend.prepare_sweep(&worker_before_rpc, &deriver, &plan).await?;
        if prepared.plan() != &plan {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        backend.validate_prepared_sweep(&worker_before_rpc, &prepared).await?;

        let consensus_binding = ConsensusBinding {
            domain: consolidation_intent_consensus_domain(),
            application: CONSOLIDATION_INTENT_APPLICATION.to_vec(),
            wallet: plan.wallet.0,
            network: self.scenario.quic_network_id()?,
            registry: registry_digest,
            activation: activation_digest,
        };
        let slot = ConsolidationConsensusSlot::new(
            consensus_binding,
            &committee,
            fault_bound,
            0,
            ledger_height,
            ledger_sequence,
            ledger_previous,
        )?;
        let context = slot.consensus_context()?;
        let authorization = build_consolidation_authorization(&worker_before_rpc, &prepared)?;
        let roast_plan = RoastViewPlan::derive(&slot, &committee, fault_bound, &authorization)?;
        let signers = CanonicalSignerSet::new(
            &committee,
            roast_plan.relay_seed(),
            roast_plan.signers().iter().copied(),
        )
        .map_err(|_| DepositServiceError::InvalidByzantineConsolidationState)?;
        let (rebuilt_authorization, attempt) = build_consolidation_bindings(
            &worker_before_rpc,
            &prepared,
            &committee,
            &signers,
            registry_digest,
            activation_digest,
            roast_plan.signing_session(),
            roast_plan.attempt(),
        )?;
        if rebuilt_authorization != authorization {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let intent = ConsolidationIntent::new(&context, authorization, attempt.clone())?;
        let value = intent.to_consensus_value()?;
        let binding = ConsolidationAttemptWireBinding::new(
            intent.authorization(),
            &attempt,
            roast_plan.relay_seed(),
        )?;
        ByzantineConsensusValueAttachment::new(
            &context,
            &slot,
            &value,
            binding.clone(),
            prepared.prepared_intent().encode()?,
        )?;
        let admitted = ValidatedByzantineConsensusValue {
            value,
            binding,
            prepared_intent: prepared.prepared_intent().encode()?,
            prepared_intent_digest: prepared.prepared_intent().digest()?,
            slot_digest: slot.digest(),
            validated_worker_revision: worker_before_rpc.revision(),
        };
        let reducer = DepositConsensus::new(context, self.party)?;
        let lane =
            DurableByzantineConsensusLane::new(slot, reducer, admitted, now_ms, base_timeout_ms)?;

        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        validate_runtime_wallet_group(runtime)?;
        if runtime.snapshot.revision != snapshot_revision
            || runtime.snapshot.byzantine_consensus_lane.is_some()
            || runtime.protocol.pending_handoff.is_some()
            || runtime.protocol.registry.digest() != registry_digest
            || runtime.protocol.registry.active().activation_binding() != activation_digest
        {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let current_worker =
            runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if current_worker.revision() != worker_before_rpc.revision()
            || current_worker.plan_sweep(committee.epoch, plan.destination_binding)? != Some(plan)
        {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_byzantine_lane_and_enqueue(Some(lane), Vec::new())?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        let action = byzantine_bootstrap_action(
            durable
                .byzantine_consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?,
        )?;
        runtime.snapshot = durable;
        Ok(vec![action])
    }

    /// Consume the exact durable pre-BA gate token and start only that backend-validated value.
    /// The implementation verifies the lane digest under the service mutex before any consensus
    /// envelope can enter the outbox.
    pub async fn continue_byzantine_bootstrap(
        &self,
        identity: &Identity,
        continuation: ByzantineBootstrapContinuation,
        now_ms: u64,
    ) -> Result<Vec<ByzantineConsolidationAction>, DepositServiceError> {
        validate_consensus_now(now_ms)?;
        let (lane_before, worker_before, prepared, backend, root_group_key) = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            runtime.protocol.require_live()?;
            let lane = runtime
                .snapshot
                .byzantine_consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::ByzantineConsensusUnavailable)?;
            validate_active_byzantine_slot(runtime, &lane.slot, self.scenario.quic_network_id()?)?;
            validate_byzantine_identity(identity, lane.slot.committee(), self.party)?;
            lane.verify_continuation(continuation)?;
            let worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let local = lane
                .admitted_values
                .get(&lane.local_candidate)
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
            let prepared_intent = PreparedSweepIntent::decode(&local.prepared_intent)?;
            let prepared =
                worker.verify_prepared_sweep_intent(&runtime.deriver, &prepared_intent)?;
            (
                lane.clone(),
                worker,
                prepared,
                self.consolidation_backend
                    .as_ref()
                    .cloned()
                    .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?,
                runtime.deriver.root_spend_key(),
            )
        };
        // Re-query every absolute ring member at continuation time. A long-lived acceptance hold
        // can span a daemon reorg; the old persisted validation is never blindly reused.
        backend.validate_prepared_sweep(&worker_before, &prepared).await?;

        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let current_lane = runtime
            .snapshot
            .byzantine_consensus_lane
            .as_ref()
            .ok_or(DepositServiceError::ByzantineConsensusUnavailable)?;
        validate_active_byzantine_slot(
            runtime,
            &current_lane.slot,
            self.scenario.quic_network_id()?,
        )?;
        if current_lane != &lane_before
            || runtime.deriver.root_spend_key() != root_group_key
            || runtime
                .snapshot
                .worker()
                .ok_or(DepositServiceError::MissingScannerAnchor)?
                .revision()
                != worker_before.revision()
        {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        current_lane.verify_continuation(continuation)?;
        let mut lane = current_lane.clone();
        lane.admitted_values
            .get_mut(&lane.local_candidate)
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?
            .validated_worker_revision = worker_before.revision();
        let candidate = lane
            .admitted_values
            .get(&lane.local_candidate)
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?
            .value
            .clone();
        let step = lane.reducer.start(identity, candidate)?;
        if let Some(view) = step.entered_view {
            lane.enter_view(view, now_ms)?;
        }
        let messages = byzantine_consensus_step_messages(self.party, &lane, &step)?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_byzantine_lane_and_enqueue(Some(lane), messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(Vec::new())
    }

    async fn start_successor_byzantine_lane(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        roast: &ConsolidationRoast,
        now_ms: u64,
        base_timeout_ms: u64,
    ) -> Result<Vec<ByzantineConsolidationAction>, DepositServiceError> {
        validate_retained_byzantine_roast(runtime, roast, self.scenario.quic_network_id()?)?;
        if now_ms < roast.outer_deadline_unix_ms() || roast.has_endorsed_candidate() {
            return pending_byzantine_roast_actions(runtime, self.party);
        }
        let view = roast.next_view();
        let slot = roast.expected_slot(view)?;
        let context = slot.consensus_context()?;
        validate_byzantine_identity(identity, roast.committee(), self.party)?;
        let worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let prepared = worker.reconstruct_reserved_sweep(&runtime.deriver, roast.sweep_id())?;
        self.consolidation_backend
            .as_ref()
            .cloned()
            .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?
            .validate_prepared_sweep(&worker, &prepared)
            .await?;
        let plan = roast.expected_plan(view)?;
        let signers = CanonicalSignerSet::new(
            roast.committee(),
            plan.relay_seed(),
            plan.signers().iter().copied(),
        )
        .map_err(|_| DepositServiceError::InvalidByzantineConsolidationState)?;
        let (authorization, attempt) = build_consolidation_bindings(
            &worker,
            &prepared,
            roast.committee(),
            &signers,
            slot.binding().registry,
            slot.binding().activation,
            plan.signing_session(),
            plan.attempt(),
        )?;
        if &authorization != roast.authorization() {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let intent = ConsolidationIntent::new(&context, authorization, attempt.clone())?;
        let value = intent.to_consensus_value()?;
        let binding = ConsolidationAttemptWireBinding::new(
            intent.authorization(),
            &attempt,
            plan.relay_seed(),
        )?;
        ByzantineConsensusValueAttachment::new(
            &context,
            &slot,
            &value,
            binding.clone(),
            prepared.prepared_intent().encode()?,
        )?;
        let admitted = ValidatedByzantineConsensusValue {
            value: value.clone(),
            binding,
            prepared_intent: prepared.prepared_intent().encode()?,
            prepared_intent_digest: prepared.prepared_intent().digest()?,
            slot_digest: slot.digest(),
            validated_worker_revision: worker.revision(),
        };
        let mut lane = DurableByzantineConsensusLane::new(
            slot,
            DepositConsensus::new(context, self.party)?,
            admitted,
            now_ms,
            base_timeout_ms,
        )?;
        let step = lane.reducer.start(identity, value)?;
        if let Some(inner_view) = step.entered_view {
            lane.enter_view(inner_view, now_ms)?;
        }
        let messages = byzantine_consensus_step_messages(self.party, &lane, &step)?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_byzantine_lane_and_enqueue(Some(lane), messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(Vec::new())
    }

    async fn adopt_endorsed_byzantine_candidate(
        &self,
        runtime: &mut DepositRuntime,
        roast: &ConsolidationRoast,
    ) -> Result<Option<Vec<ByzantineConsolidationAction>>, DepositServiceError> {
        let Some((view, attestation)) = roast.endorsed_candidate_attestations()?.into_iter().next()
        else {
            return Ok(None);
        };
        if self.authenticated_portable_terminal_by_sweep(roast.sweep_id()).await?.is_some() {
            return Ok(Some(Vec::new()));
        }
        let binding = roast.wire_binding(view)?;
        attestation.verify(roast.committee(), roast.quic_network_id(), &binding)?;
        let (_, intent, _) = roast
            .certified_intent(view)
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        if intent.attempt() != binding.attempt() {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let existing = runtime
            .consolidation
            .record(roast.authorization_id())
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        if existing.signed == Some(attestation.signed().binding()) {
            return Ok(Some(vec![ByzantineConsolidationAction::BroadcastCandidate {
                family: roast.family_digest(),
                view,
                sweep: roast.sweep_id(),
                binding,
                attestation,
            }]));
        }

        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let mut consolidation = runtime.snapshot.consolidation()?;
        let worker_effect = worker.adopt_portable_sweep_family_candidate(
            roast.sweep_id(),
            SweepSigningSessionTombstone {
                attempt: intent.attempt().attempt(),
                session: intent.attempt().session(),
                intent_digest: intent.attempt().worker_intent_digest(),
            },
            attestation.signed().transaction(),
        )?;
        let consolidation_effect = consolidation.record_portable_signed_attempt(
            roast.authorization_id(),
            intent.attempt(),
            attestation.signed().binding(),
        )?;
        let invalidated_session =
            consolidation_effect.as_ref().and_then(ConsolidationPersistEffect::invalidated_session);
        let consolidation_commitment =
            consolidation_effect.as_ref().map(ConsolidationPersistEffect::state_commitment);
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_all_and_enqueue(
            runtime.protocol.encode_local(&runtime.deriver)?,
            worker,
            &consolidation,
            Vec::new(),
        )?;
        validate_consolidation_alignment(self, &runtime.protocol, &snapshot, &consolidation)
            .await?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        let durable_worker = durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if durable_worker.revision() != worker_effect.revision() {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        let durable_consolidation = durable.consolidation()?;
        if let (Some(effect), Some(commitment)) = (consolidation_effect, consolidation_commitment) {
            let _ = durable_consolidation.persisted_receipt_after_cas(
                effect,
                durable_consolidation.revision(),
                commitment,
            )?;
        }
        runtime.snapshot = durable;
        runtime.consolidation = durable_consolidation;
        let mut actions = Vec::new();
        if let Some(invalidated_session) = invalidated_session {
            let retired_view = roast
                .view_for_signing_session(invalidated_session)
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
            actions.push(ByzantineConsolidationAction::RetireView {
                family: roast.family_digest(),
                view: retired_view,
                binding: roast.wire_binding(retired_view)?,
                signing_session: invalidated_session,
            });
        }
        actions.push(ByzantineConsolidationAction::BroadcastCandidate {
            family: roast.family_digest(),
            view,
            sweep: roast.sweep_id(),
            binding,
            attestation,
        });
        Ok(Some(actions))
    }

    /// Convert a durably committed intent lane into one exact signing family. This method is
    /// invoked while the service mutex is held, so the daemon revalidation and the single
    /// composite snapshot CAS cannot race a scanner or registry transition.
    async fn finalize_committed_byzantine_lane(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        now_ms: u64,
    ) -> Result<Vec<ByzantineConsolidationAction>, DepositServiceError> {
        validate_consensus_now(now_ms)?;
        let lane = runtime
            .snapshot
            .byzantine_consensus_lane
            .clone()
            .ok_or(DepositServiceError::ByzantineConsensusUnavailable)?;
        validate_active_byzantine_slot(runtime, &lane.slot, self.scenario.quic_network_id()?)?;
        lane.validate()?;
        validate_byzantine_identity(identity, lane.slot.committee(), self.party)?;
        let context = lane.slot.consensus_context()?;
        let commit = lane
            .reducer
            .commit()
            .cloned()
            .ok_or(DepositServiceError::ByzantineConsensusUnavailable)?;
        commit.verify(&context)?;
        let admitted = lane
            .admitted_values
            .get(&commit.value().digest())
            .filter(|candidate| candidate.value == *commit.value())
            .cloned()
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let intent = decode_consolidation_intent(&context, commit.value())?;
        let intent_certificate = ConsolidationIntentCertificate::new(context.clone(), commit)?;
        intent_certificate.verify_expected(&context, &intent)?;
        let worker_before =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let prepared_intent = PreparedSweepIntent::decode(&admitted.prepared_intent)?;
        let prepared =
            worker_before.verify_prepared_sweep_intent(&runtime.deriver, &prepared_intent)?;
        if prepared.prepared_intent().digest()? != admitted.prepared_intent_digest {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        self.consolidation_backend
            .as_ref()
            .cloned()
            .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?
            .validate_prepared_sweep(&worker_before, &prepared)
            .await?;

        let expected_family = deterministic_roast_family_digest(
            context.binding(),
            lane.slot.committee(),
            lane.slot.fault_bound(),
            intent.authorization(),
            lane.slot.family_anchor(),
        );
        let current_roast_archive_head = runtime.snapshot.roast_attempt_archive_head();
        let mut staged_roast_archive_head = current_roast_archive_head;
        let mut staged_roast_archive = None;
        let mut roast = if lane.slot.roast_view() == 0 {
            if !runtime.snapshot.consolidation_roasts.is_empty() {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            ConsolidationRoast::new(
                self.party,
                self.scenario.quic_network_id()?,
                lane.slot.clone(),
                context.clone(),
                intent.clone(),
                intent_certificate.clone(),
                now_ms,
                lane.base_timeout_ms,
            )?
        } else {
            let (_, mut existing) = runtime.snapshot.roast_by_family(expected_family)?;
            if existing.authorization() != intent.authorization()
                || existing.expected_slot(lane.slot.roast_view())? != lane.slot
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            // Archive every full predecessor before append_certified_view can move the oldest hot
            // body into the digest-only replay window. This head remains unreachable until the
            // enclosing snapshot CAS below succeeds.
            let stage = self.stage_hot_roast_attempts(staged_roast_archive_head, &existing).await?;
            staged_roast_archive_head = Self::compose_roast_archive_stage(
                &mut staged_roast_archive,
                staged_roast_archive_head,
                stage,
            )?;
            let appended = existing.append_certified_view(
                context.clone(),
                intent.clone(),
                intent_certificate.clone(),
                now_ms,
            )?;
            if appended != lane.slot.roast_view() {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            existing
        };
        // Include the newly certified view as well. Re-staging predecessors is content-addressed
        // and idempotent; only this final descendant head is installed by the snapshot CAS.
        let stage = self.stage_hot_roast_attempts(staged_roast_archive_head, &roast).await?;
        staged_roast_archive_head = Self::compose_roast_archive_stage(
            &mut staged_roast_archive,
            staged_roast_archive_head,
            stage,
        )?;
        let family = roast.family_digest();
        if family != expected_family {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let plan = roast
            .plan(lane.slot.roast_view())
            .cloned()
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let signers = CanonicalSignerSet::new(
            lane.slot.committee(),
            plan.relay_seed(),
            plan.signers().iter().copied(),
        )
        .map_err(|_| DepositServiceError::InvalidByzantineConsolidationState)?;
        let rebuilt = build_consolidation_bindings(
            &worker_before,
            &prepared,
            lane.slot.committee(),
            &signers,
            lane.slot.binding().registry,
            lane.slot.binding().activation,
            plan.signing_session(),
            plan.attempt(),
        )?;
        if rebuilt != (intent.authorization().clone(), intent.attempt().clone())
            || admitted.binding.attempt() != intent.attempt()
            || admitted.binding.leader() != plan.relay_seed()
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }

        let mut worker = worker_before;
        let mut consolidation = runtime.snapshot.consolidation()?;
        let worker_release = if lane.slot.roast_view() == 0 {
            worker.reserve_prepared_sweep(
                &prepared,
                lane.slot.committee(),
                &signers,
                runtime.deriver.root_spend_key(),
                plan.signing_session(),
            )?;
            if consolidation.reserve_intent(intent.authorization().clone())?.is_none() {
                return Err(DepositServiceError::StaleConsolidationCandidate);
            }
            worker.release_sweep_for_signing(prepared.plan().id)?
        } else {
            let previous = consolidation
                .record(intent.authorization().id())
                .and_then(|record| record.attempts.get(&record.attempt_high_water()))
                .map(|tombstone| tombstone.binding.clone())
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
            if previous.attempt().checked_add(1) != Some(intent.attempt().attempt()) {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            consolidation.catch_up_burned_attempt(intent.authorization().id(), previous)?;
            worker.recover_released_sweep_signing(
                &runtime.deriver,
                prepared.plan().id,
                lane.slot.committee(),
                &signers,
                runtime.deriver.root_spend_key(),
                plan.signing_session(),
            )?
        };
        let consolidation_effect =
            consolidation.release_signing(intent.authorization().id(), intent.attempt().clone())?;
        let consolidation_commitment = consolidation_effect.state_commitment();
        let selected = plan.signers().binary_search(&self.party).is_ok();
        if selected {
            roast.mark_local_nonce_released(lane.slot.roast_view())?;
        }

        let mut messages = Vec::new();
        for recipient in lane
            .slot
            .committee()
            .members
            .iter()
            .map(|member| member.id)
            .filter(|party| *party != self.party)
        {
            let certified = ByzantineCertifiedIntent::new(
                self.party,
                recipient,
                lane.slot.clone(),
                family,
                admitted.binding.clone(),
                intent_certificate.clone(),
                admitted.prepared_intent.clone(),
            )?;
            messages.push((
                lane.slot.ledger_sequence(),
                recipient,
                DepositOperation::Consolidation,
                ByzantineConsolidationWireMessage::CertifiedIntent(certified).encode()?,
            ));
        }
        let mut candidate = runtime.snapshot.clone();
        candidate.install_byzantine_roast_release_and_enqueue(
            runtime.protocol.encode_local(&runtime.deriver)?,
            worker,
            &consolidation,
            &roast,
            messages,
        )?;
        candidate.install_roast_attempt_archive_head(
            current_roast_archive_head,
            staged_roast_archive_head,
        )?;
        validate_consolidation_alignment(self, &runtime.protocol, &candidate, &consolidation)
            .await?;
        let durable = self.repository.persist_and_read_back(&candidate).await?;
        if staged_roast_archive
            .as_ref()
            .is_none_or(|stage| stage.head != durable.roast_attempt_archive_head())
        {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        let durable_consolidation = durable.consolidation()?;
        let action = if selected {
            let durable_worker =
                durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            let worker_authorization = durable_worker
                .signing_authorization_after_persist(worker_release, durable_worker.revision())?;
            let receipt = durable_consolidation.persisted_receipt_after_cas(
                consolidation_effect,
                durable_consolidation.revision(),
                consolidation_commitment,
            )?;
            let coordinator_authorization =
                durable_consolidation.nonce_action_after_persist(receipt)?;
            let nonce_authorization =
                coordinator_authorization.bind_worker_authorization(worker_authorization)?;
            Some(ByzantineConsolidationAction::Release {
                family,
                view: lane.slot.roast_view(),
                binding: admitted.binding,
                release: PersistedSweepRelease {
                    authorization: intent.authorization().clone(),
                    attempt: intent.attempt().clone(),
                    start_messages: BTreeMap::new(),
                    prepared,
                    nonce_authorization,
                },
            })
        } else {
            None
        };
        runtime.snapshot = durable;
        runtime.consolidation = durable_consolidation;
        Ok(action.into_iter().collect())
    }

    async fn accept_byzantine_consensus_relay(
        &self,
        identity: &Identity,
        authenticated_sender: PartyId,
        relay: &ByzantineConsensusRelay,
        now_ms: u64,
    ) -> Result<(), DepositServiceError> {
        validate_consensus_now(now_ms)?;
        let (worker_before, prepared_values, backend) = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            runtime.protocol.require_live()?;
            let lane = runtime
                .snapshot
                .byzantine_consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::ByzantineConsensusUnavailable)?;
            if relay.slot() != &lane.slot || relay.context() != lane.reducer.context() {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            let activation = validate_active_byzantine_slot(
                runtime,
                relay.slot(),
                self.scenario.quic_network_id()?,
            )?;
            validate_byzantine_identity(identity, activation.committee(), self.party)?;
            ByzantineConsolidationWireMessage::Consensus(relay.clone())
                .validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    activation.committee(),
                )?;
            relay.verify_expected(&lane.slot, lane.reducer.context())?;
            let worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let prepared = relay.verify_referenced_values_with_worker(
                &lane.slot,
                lane.reducer.context(),
                &worker,
                &runtime.deriver,
                activation.committee(),
                relay.slot().binding().registry,
                relay.slot().binding().activation,
                None,
            )?;
            (
                worker,
                prepared,
                self.consolidation_backend
                    .as_ref()
                    .cloned()
                    .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?,
            )
        };
        // Every direct and nested proposal/lock/view-change value crosses the daemon predicate
        // before any of them enters the durable application-valid map or BA reducer.
        for prepared in &prepared_values {
            backend.validate_prepared_sweep(&worker_before, prepared).await?;
        }

        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let activation = validate_active_byzantine_slot(
            runtime,
            relay.slot(),
            self.scenario.quic_network_id()?,
        )?;
        validate_byzantine_identity(identity, activation.committee(), self.party)?;
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if worker.revision() != worker_before.revision() {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let current = runtime
            .snapshot
            .byzantine_consensus_lane
            .as_ref()
            .ok_or(DepositServiceError::ByzantineConsensusUnavailable)?;
        if relay.slot() != &current.slot || relay.context() != current.reducer.context() {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let mut lane = current.clone();
        for value in relay.referenced_values()? {
            let attachment = relay
                .attachment(value.digest())
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
            let prepared_intent = PreparedSweepIntent::decode(attachment.prepared_intent_bytes())?;
            let admitted = ValidatedByzantineConsensusValue {
                value: value.clone(),
                binding: attachment.binding().clone(),
                prepared_intent: attachment.prepared_intent_bytes().to_vec(),
                prepared_intent_digest: prepared_intent.digest()?,
                slot_digest: lane.slot.digest(),
                validated_worker_revision: worker.revision(),
            };
            if let Some(existing) = lane.admitted_values.insert(value.digest(), admitted.clone())
                && existing != admitted
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
        }
        let step = match relay.body() {
            ByzantineConsensusBody::Message(envelope) => {
                lane.reducer.handle_with_value_validator(identity, envelope.clone(), |value| {
                    lane.admitted_values
                        .get(&value.digest())
                        .is_some_and(|admitted| admitted.value == *value)
                })?
            }
            ByzantineConsensusBody::ViewCertificate(certificate) => lane
                .reducer
                .handle_view_certificate_with_validator(identity, certificate.clone(), |value| {
                    lane.admitted_values
                        .get(&value.digest())
                        .is_some_and(|admitted| admitted.value == *value)
                })?,
        };
        if let Some(view) = step.entered_view {
            lane.enter_view(view, now_ms)?;
        }
        let messages = byzantine_consensus_step_messages(self.party, &lane, &step)?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_byzantine_lane_and_enqueue(Some(lane), messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(())
    }

    async fn accept_byzantine_certified_intent(
        &self,
        identity: &Identity,
        authenticated_sender: PartyId,
        certified: &ByzantineCertifiedIntent,
        now_ms: u64,
    ) -> Result<(), DepositServiceError> {
        validate_consensus_now(now_ms)?;
        let (worker_before, prepared, backend, expected_family) = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            runtime.protocol.require_live()?;
            let activation = validate_active_byzantine_slot(
                runtime,
                certified.slot(),
                self.scenario.quic_network_id()?,
            )?;
            validate_byzantine_identity(identity, activation.committee(), self.party)?;
            ByzantineConsolidationWireMessage::CertifiedIntent(certified.clone())
                .validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    activation.committee(),
                )?;
            let context = certified.slot().consensus_context()?;
            let intent = certified.certificate().verify_in_context(&context)?;
            let family = deterministic_roast_family_digest(
                context.binding(),
                activation.committee(),
                activation.fault_bound(),
                intent.authorization(),
                certified.slot().family_anchor(),
            );
            if retained_certified_intent_matches(runtime, certified, family)? {
                return Ok(());
            }
            validate_certified_intent_family_chain(runtime, certified, &intent, family)?;
            let worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let prepared = certified.verify_with_worker(
                certified.slot(),
                family,
                certified.binding(),
                &context,
                &worker,
                &runtime.deriver,
                activation.committee(),
                certified.slot().binding().registry,
                certified.slot().binding().activation,
            )?;
            (
                worker,
                prepared,
                self.consolidation_backend
                    .as_ref()
                    .cloned()
                    .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?,
                family,
            )
        };
        backend.validate_prepared_sweep(&worker_before, &prepared).await?;

        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let activation = validate_active_byzantine_slot(
            runtime,
            certified.slot(),
            self.scenario.quic_network_id()?,
        )?;
        validate_byzantine_identity(identity, activation.committee(), self.party)?;
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if worker.revision() != worker_before.revision() {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let context = certified.slot().consensus_context()?;
        let intent = certified.certificate().verify_in_context(&context)?;
        let current_family = deterministic_roast_family_digest(
            context.binding(),
            activation.committee(),
            activation.fault_bound(),
            intent.authorization(),
            certified.slot().family_anchor(),
        );
        if current_family != expected_family {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let already_retained =
            retained_certified_intent_matches(runtime, certified, current_family)?;
        if already_retained {
            return Ok(());
        }
        validate_certified_intent_family_chain(runtime, certified, &intent, current_family)?;
        let value = certified.certificate().certificate().value().clone();
        let prepared_intent = PreparedSweepIntent::decode(certified.prepared_intent_bytes())?;
        let admitted = ValidatedByzantineConsensusValue {
            value: value.clone(),
            binding: certified.binding().clone(),
            prepared_intent: certified.prepared_intent_bytes().to_vec(),
            prepared_intent_digest: prepared_intent.digest()?,
            slot_digest: certified.slot().digest(),
            validated_worker_revision: worker.revision(),
        };
        let mut lane = match runtime.snapshot.byzantine_consensus_lane.as_ref() {
            Some(existing) if existing.slot == *certified.slot() => existing.clone(),
            Some(_) => return Err(DepositServiceError::InvalidByzantineConsolidationState),
            None => {
                if has_live_byzantine_family(runtime)? && certified.slot().roast_view() == 0 {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
                let base_timeout_ms = self
                    .scenario
                    .protocol_timeout_seconds
                    .checked_mul(1_000)
                    .filter(|timeout| *timeout != 0)
                    .ok_or(DepositServiceError::InvalidTime)?;
                DurableByzantineConsensusLane::new(
                    certified.slot().clone(),
                    DepositConsensus::new(context.clone(), self.party)?,
                    admitted.clone(),
                    now_ms,
                    base_timeout_ms,
                )?
            }
        };
        if let Some(existing) = lane.admitted_values.insert(value.digest(), admitted.clone())
            && existing != admitted
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let step = lane.reducer.handle_commit_certificate_with_validator(
            certified.certificate().certificate().clone(),
            |candidate| {
                lane.admitted_values
                    .get(&candidate.digest())
                    .is_some_and(|admitted| admitted.value == *candidate)
            },
        )?;
        let messages = byzantine_consensus_step_messages(self.party, &lane, &step)?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_byzantine_lane_and_enqueue(Some(lane), messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(())
    }

    async fn validate_byzantine_roast_route(
        &self,
        authenticated_sender: PartyId,
        identity: &Identity,
        message: &ByzantineConsolidationWireMessage,
        family: [u8; 32],
    ) -> Result<(), DepositServiceError> {
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (_, roast) = runtime.snapshot.roast_by_family(family)?;
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let binding = roast.wire_binding(message.view())?;
        let authority = validate_terminal_attempt_against_roast(
            &binding,
            &roast,
            worker,
            self.scenario.quic_network_id()?,
            runtime.protocol.registry.active().group_key(),
        )?;
        if authority.fault_bound() != roast.fault_bound() || message.view() >= roast.next_view() {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        validate_byzantine_identity(identity, authority.committee(), self.party)?;
        message.validate_authenticated_route_in_committee(
            authenticated_sender,
            self.party,
            authority.committee(),
        )?;
        Ok(())
    }

    /// Admit one authenticated coordinator-free wire body. A successful ACK is returned only
    /// after the original full body and its reducer effect have been persisted and read back.
    ///
    /// A host which no longer retains the historical epoch identity must first call
    /// [`Self::acknowledge_sealed_byzantine_consolidation`].
    pub async fn accept_byzantine_consolidation(
        &self,
        identity: &Identity,
        authenticated_sender: PartyId,
        message: ByzantineConsolidationWireMessage,
        now_ms: u64,
    ) -> Result<ByzantineRelayAck, DepositServiceError> {
        let delivery = message.delivery_id()?;
        match &message {
            ByzantineConsolidationWireMessage::Consensus(relay) => {
                self.accept_byzantine_consensus_relay(
                    identity,
                    authenticated_sender,
                    relay,
                    now_ms,
                )
                .await?;
            }
            ByzantineConsolidationWireMessage::CertifiedIntent(certified) => {
                self.accept_byzantine_certified_intent(
                    identity,
                    authenticated_sender,
                    certified,
                    now_ms,
                )
                .await?;
            }
            ByzantineConsolidationWireMessage::Preprocess(relay) => {
                self.validate_byzantine_roast_route(
                    authenticated_sender,
                    identity,
                    &message,
                    relay.family(),
                )
                .await?;
                self.record_byzantine_preprocess(
                    relay.family(),
                    relay.view(),
                    relay.contribution().clone(),
                )
                .await?;
            }
            ByzantineConsolidationWireMessage::Share(relay) => {
                self.validate_byzantine_roast_route(
                    authenticated_sender,
                    identity,
                    &message,
                    relay.family(),
                )
                .await?;
                self.record_byzantine_share(
                    relay.family(),
                    relay.view(),
                    relay.contribution().clone(),
                )
                .await?;
            }
            ByzantineConsolidationWireMessage::Candidate(relay) => {
                self.validate_byzantine_roast_route(
                    authenticated_sender,
                    identity,
                    &message,
                    relay.family(),
                )
                .await?;
                self.record_byzantine_candidate(
                    relay.family(),
                    relay.view(),
                    relay.attestation().clone(),
                )
                .await?;
            }
            ByzantineConsolidationWireMessage::KeyImageBinding(relay) => {
                self.validate_byzantine_roast_route(
                    authenticated_sender,
                    identity,
                    &message,
                    relay.family(),
                )
                .await?;
                self.record_byzantine_key_image_binding(
                    relay.family(),
                    relay.view(),
                    relay.attestation().clone(),
                )
                .await?;
            }
            ByzantineConsolidationWireMessage::Ack(_) => {
                return Err(DepositServiceError::InvalidPeerMessage);
            }
        }
        Ok(ByzantineRelayAck::new(self.party, delivery)?)
    }

    /// Classify an exact retry from an immutable, ledger-certified historical family without
    /// consulting a retired local epoch identity or mutating the snapshot. Partial BA traffic is
    /// subsumed by the retained commit certificate; contribution traffic must be an exact
    /// archived replay. `None` means the family is still live (or unknown) and normal ingress,
    /// including its current epoch identity and mutable admission checks, remains required.
    pub async fn acknowledge_sealed_byzantine_consolidation(
        &self,
        authenticated_sender: PartyId,
        message: &ByzantineConsolidationWireMessage,
    ) -> Result<Option<ByzantineRelayAck>, DepositServiceError> {
        if matches!(message, ByzantineConsolidationWireMessage::Ack(_)) {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let delivery = message.delivery_id()?;
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;

        let roast = match message {
            ByzantineConsolidationWireMessage::Consensus(relay) => {
                let mut found = None;
                for bytes in runtime.snapshot.consolidation_roasts.values() {
                    let candidate = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
                    if candidate.expected_slot(relay.view()).ok().as_ref() == Some(relay.slot()) {
                        if found.replace(candidate).is_some() {
                            return Err(DepositServiceError::InvalidByzantineConsolidationState);
                        }
                    }
                }
                let Some(roast) = found else {
                    return Ok(None);
                };
                message.validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    roast.committee(),
                )?;
                relay.verify_expected(relay.slot(), &relay.slot().consensus_context()?)?;
                roast
            }
            ByzantineConsolidationWireMessage::CertifiedIntent(certified) => {
                let Ok((_, roast)) = runtime.snapshot.roast_by_family(certified.family()) else {
                    return Ok(None);
                };
                if roast.expected_slot(certified.view()).ok().as_ref() != Some(certified.slot()) {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
                message.validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    roast.committee(),
                )?;
                roast
            }
            ByzantineConsolidationWireMessage::Preprocess(relay) => {
                let Ok((_, roast)) = runtime.snapshot.roast_by_family(relay.family()) else {
                    return Ok(None);
                };
                message.validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    roast.committee(),
                )?;
                roast
            }
            ByzantineConsolidationWireMessage::KeyImageBinding(relay) => {
                let Ok((_, roast)) = runtime.snapshot.roast_by_family(relay.family()) else {
                    return Ok(None);
                };
                message.validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    roast.committee(),
                )?;
                roast
            }
            ByzantineConsolidationWireMessage::Share(relay) => {
                let Ok((_, roast)) = runtime.snapshot.roast_by_family(relay.family()) else {
                    return Ok(None);
                };
                message.validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    roast.committee(),
                )?;
                roast
            }
            ByzantineConsolidationWireMessage::Candidate(relay) => {
                let Ok((_, roast)) = runtime.snapshot.roast_by_family(relay.family()) else {
                    return Ok(None);
                };
                message.validate_authenticated_route_in_committee(
                    authenticated_sender,
                    self.party,
                    roast.committee(),
                )?;
                roast
            }
            ByzantineConsolidationWireMessage::Ack(_) => unreachable!(),
        };

        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let binding = roast.wire_binding(message.view())?;
        validate_terminal_attempt_against_roast(
            &binding,
            &roast,
            worker,
            self.scenario.quic_network_id()?,
            runtime.protocol.registry.active().group_key(),
        )?;
        let record = runtime
            .consolidation
            .record(roast.authorization_id())
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let portable = self.authenticated_portable_terminal_by_sweep(roast.sweep_id()).await?;
        if !record_has_certified_portable_completion(portable.as_ref(), record) {
            return Ok(None);
        }

        match message {
            ByzantineConsolidationWireMessage::Consensus(_) => {}
            ByzantineConsolidationWireMessage::CertifiedIntent(certified) => {
                if !retained_certified_intent_matches(runtime, certified, roast.family_digest())? {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
            }
            ByzantineConsolidationWireMessage::Preprocess(relay) => {
                let mut probe = roast.clone();
                if probe.observe_preprocess(relay.view(), relay.contribution())? {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
            }
            ByzantineConsolidationWireMessage::KeyImageBinding(relay) => {
                let mut probe = roast.clone();
                if probe.observe_key_image_binding(relay.view(), relay.attestation())? {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
            }
            ByzantineConsolidationWireMessage::Share(relay) => {
                let mut probe = roast.clone();
                if probe.observe_share(relay.view(), relay.contribution())? {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
            }
            ByzantineConsolidationWireMessage::Candidate(relay) => {
                let mut probe = roast.clone();
                if probe.observe_candidate(relay.view(), relay.attestation())? {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
            }
            ByzantineConsolidationWireMessage::Ack(_) => unreachable!(),
        }
        Ok(Some(ByzantineRelayAck::new(self.party, delivery)?))
    }

    /// Atomically checkpoint an authenticated exact relay ACK and retire the matching full-body
    /// generic outbox entry.
    pub async fn acknowledge_byzantine_consolidation(
        &self,
        authenticated_sender: PartyId,
        acknowledgement: ByzantineRelayAck,
    ) -> Result<bool, DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let expected = acknowledgement.acknowledged();
        if acknowledgement.route().from != authenticated_sender
            || acknowledgement.route().to != self.party
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let matching = runtime
            .snapshot
            .outbox
            .iter()
            .filter_map(|(id, durable)| {
                if id.operation != DepositOperation::Consolidation {
                    return None;
                }
                let body = runtime.snapshot.outbox_bodies.get(&durable.body_digest)?;
                let wire = ByzantineConsolidationWireMessage::decode(body).ok()?;
                (wire.delivery_id().ok()? == expected).then_some((*id, wire))
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Ok(false);
        }
        if matching.len() != 1 {
            return Err(DepositServiceError::InvalidOutbox);
        }
        let (matching_id, matching_wire) = &matching[0];
        let roast = match matching_wire {
            ByzantineConsolidationWireMessage::Consensus(message) => {
                let mut matched = None;
                for bytes in runtime.snapshot.consolidation_roasts.values() {
                    let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
                    if roast.expected_slot(message.view()).ok().as_ref() == Some(message.slot())
                        && matched.replace(roast).is_some()
                    {
                        return Err(DepositServiceError::InvalidByzantineConsolidationState);
                    }
                }
                matched.ok_or(DepositServiceError::InvalidByzantineConsolidationState)?
            }
            ByzantineConsolidationWireMessage::CertifiedIntent(message) => {
                let (_, roast) = runtime.snapshot.roast_by_family(message.family())?;
                if roast.expected_slot(message.view())? != *message.slot() {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
                roast
            }
            ByzantineConsolidationWireMessage::Preprocess(_)
            | ByzantineConsolidationWireMessage::KeyImageBinding(_)
            | ByzantineConsolidationWireMessage::Share(_)
            | ByzantineConsolidationWireMessage::Candidate(_) => {
                let (_, roast) = runtime.snapshot.roast_by_family(expected.family())?;
                roast
            }
            ByzantineConsolidationWireMessage::Ack(_) => {
                return Err(DepositServiceError::InvalidOutbox);
            }
        };
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let binding = roast.wire_binding(expected.view())?;
        let authority = validate_terminal_attempt_against_roast(
            &binding,
            &roast,
            worker,
            self.scenario.quic_network_id()?,
            runtime.protocol.registry.active().group_key(),
        )?;
        acknowledgement.verify_expected(authority.committee(), expected)?;

        let mut snapshot = runtime.snapshot.clone();
        let phase = match expected.kind() {
            ByzantineDeliveryKind::Preprocess => Some(RoastContributionPhase::Preprocess),
            ByzantineDeliveryKind::KeyImageBinding => Some(RoastContributionPhase::KeyImageBinding),
            ByzantineDeliveryKind::Share => Some(RoastContributionPhase::Share),
            ByzantineDeliveryKind::Candidate => Some(RoastContributionPhase::Candidate),
            ByzantineDeliveryKind::ConsensusMessage
            | ByzantineDeliveryKind::ViewCertificate
            | ByzantineDeliveryKind::CertifiedIntent => None,
        };
        if let Some(phase) = phase {
            let (authorization, mut roast) = snapshot.roast_by_family(expected.family())?;
            let relay = roast
                .pending_relays(expected.view(), phase, expected.origin())?
                .into_iter()
                .find(|relay| relay.recipient() == authenticated_sender)
                .ok_or(DepositServiceError::InvalidOutbox)?;
            let exact_inner = match matching_wire {
                ByzantineConsolidationWireMessage::Preprocess(message) => {
                    postcard::to_allocvec(message.contribution())?
                }
                ByzantineConsolidationWireMessage::KeyImageBinding(message) => {
                    postcard::to_allocvec(message.attestation())?
                }
                ByzantineConsolidationWireMessage::Share(message) => {
                    postcard::to_allocvec(message.contribution())?
                }
                ByzantineConsolidationWireMessage::Candidate(message) => {
                    postcard::to_allocvec(message.attestation())?
                }
                ByzantineConsolidationWireMessage::Consensus(_)
                | ByzantineConsolidationWireMessage::CertifiedIntent(_)
                | ByzantineConsolidationWireMessage::Ack(_) => {
                    return Err(DepositServiceError::InvalidOutbox);
                }
            };
            if roast.relay_body(&relay)? != exact_inner {
                return Err(DepositServiceError::InvalidOutbox);
            }
            roast.acknowledge_relay(authenticated_sender, relay)?;
            snapshot.consolidation_roasts.insert(authorization, roast.encode()?);
        }
        let original_revision = runtime.snapshot.revision;
        snapshot.revision = original_revision;
        if snapshot.acknowledge(&[*matching_id])? != 1 {
            return Err(DepositServiceError::InvalidOutbox);
        }
        snapshot.revision = original_revision;
        snapshot.revision = runtime.snapshot.next_revision()?;
        snapshot.validate()?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(true)
    }

    pub async fn record_byzantine_preprocess(
        &self,
        family: [u8; 32],
        view: u64,
        contribution: SignedPreprocessContribution,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (_, mut roast) = runtime.snapshot.roast_by_family(family)?;
        if roast.local_party() != self.party
            || roast.quic_network_id() != self.scenario.quic_network_id()?
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        roast.observe_preprocess(view, &contribution)?;
        let binding = roast.wire_binding(view)?;
        let ledger_sequence = roast.expected_slot(view)?.ledger_sequence();
        let network = roast.quic_network_id();
        let messages = roast
            .pending_relays(view, RoastContributionPhase::Preprocess, contribution.sender())?
            .into_iter()
            .map(|relay| {
                let wire =
                    ByzantineConsolidationWireMessage::Preprocess(ByzantinePreprocessRelay::new(
                        self.party,
                        relay.recipient(),
                        family,
                        view,
                        binding.clone(),
                        contribution.clone(),
                        roast.committee(),
                        network,
                    )?);
                Ok((
                    ledger_sequence,
                    relay.recipient(),
                    DepositOperation::Consolidation,
                    wire.encode()?,
                ))
            })
            .collect::<Result<Vec<_>, DepositServiceError>>()?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_roast_and_enqueue(&roast, messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(())
    }

    pub async fn record_byzantine_key_image_binding(
        &self,
        family: [u8; 32],
        view: u64,
        attestation: PortableKeyImageBindingAttestation,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (_, mut roast) = runtime.snapshot.roast_by_family(family)?;
        if roast.local_party() != self.party
            || roast.quic_network_id() != self.scenario.quic_network_id()?
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        roast.observe_key_image_binding(view, &attestation)?;
        let binding = roast.wire_binding(view)?;
        let ledger_sequence = roast.expected_slot(view)?.ledger_sequence();
        let network = roast.quic_network_id();
        let messages = roast
            .pending_relays(view, RoastContributionPhase::KeyImageBinding, attestation.origin())?
            .into_iter()
            .map(|relay| {
                let wire = ByzantineConsolidationWireMessage::KeyImageBinding(
                    ByzantineKeyImageBindingRelay::new(
                        self.party,
                        relay.recipient(),
                        family,
                        view,
                        binding.clone(),
                        attestation.clone(),
                        roast.committee(),
                        network,
                    )?,
                );
                Ok((
                    ledger_sequence,
                    relay.recipient(),
                    DepositOperation::Consolidation,
                    wire.encode()?,
                ))
            })
            .collect::<Result<Vec<_>, DepositServiceError>>()?;
        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let mut expected_pin = None;
        if let Some(certificate) = roast.key_image_binding_certificate(view)? {
            let value = certificate.verify(
                roast.committee(),
                roast.fault_bound(),
                roast.quic_network_id(),
                &binding,
            )?;
            let worker_binding = worker
                .preview_sweep_family_key_images(roast.sweep_id(), value.key_images().to_vec())?;
            value.verify_worker_binding(&worker_binding)?;
            match worker.sweep_family_key_images(roast.sweep_id()) {
                Some(existing) if existing == &worker_binding => {}
                Some(_) => {
                    return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
                }
                None => {
                    worker.pin_sweep_family_key_image_binding(worker_binding.clone())?;
                }
            }
            expected_pin = Some(worker_binding);
        }
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_roast_worker_and_enqueue(&roast, worker, messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        if let Some(expected) = expected_pin
            && durable.worker().and_then(|worker| worker.sweep_family_key_images(roast.sweep_id()))
                != Some(&expected)
        {
            return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
        }
        runtime.snapshot = durable;
        Ok(())
    }

    /// Construct the local portable key-image attestation only from the API-unforgeable
    /// proof-verified signing preview and the exact durable worker family, then persist/relay it.
    pub async fn record_local_byzantine_key_image_preview(
        &self,
        family: [u8; 32],
        view: u64,
        binding: &ConsolidationAttemptWireBinding,
        identity: &Identity,
        preview: &ProofVerifiedKeyImagePreview,
    ) -> Result<PortableKeyImageBindingAttestation, DepositServiceError> {
        let attestation = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            runtime.protocol.require_live()?;
            let (_, roast) = runtime.snapshot.roast_by_family(family)?;
            if &roast.wire_binding(view)? != binding
                || roast.local_safety_phase(view) != Some(AttemptSafetyPhase::NonceReleased)
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
            validate_byzantine_identity(identity, roast.committee(), self.party)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            let worker_binding = worker.preview_sweep_family_key_images(
                roast.sweep_id(),
                preview.key_images().iter().map(|image| image.to_bytes()).collect(),
            )?;
            PortableKeyImageBindingAttestation::sign(
                identity,
                roast.committee(),
                roast.quic_network_id(),
                binding.clone(),
                preview,
                &worker_binding,
            )?
        };
        self.record_byzantine_key_image_binding(family, view, attestation.clone()).await?;
        Ok(attestation)
    }

    /// Verify the exact reducer certificate against the host's still-bound local preview and pin
    /// the worker family through authenticated snapshot readback before a CLSAG share may leave.
    pub async fn authorize_byzantine_key_images(
        &self,
        family: [u8; 32],
        view: u64,
        binding: &ConsolidationAttemptWireBinding,
        preview: &ProofVerifiedKeyImagePreview,
        certificate: &PortableKeyImageBindingCertificate,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (_, roast) = runtime.snapshot.roast_by_family(family)?;
        if &roast.wire_binding(view)? != binding
            || roast.local_safety_phase(view) != Some(AttemptSafetyPhase::NonceReleased)
            || roast.key_image_binding_certificate(view)? != Some(certificate)
        {
            return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
        }
        let value = certificate.verify(
            roast.committee(),
            roast.fault_bound(),
            roast.quic_network_id(),
            binding,
        )?;
        if !certificate.authorizers().contains(&self.party) {
            return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
        }
        let current_worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let worker_binding = current_worker.preview_sweep_family_key_images(
            roast.sweep_id(),
            preview.key_images().iter().map(|image| image.to_bytes()).collect(),
        )?;
        value.verify_proof_verified_preview(binding, preview, &worker_binding)?;
        if let Some(existing) = current_worker.sweep_family_key_images(roast.sweep_id()) {
            if existing != &worker_binding {
                return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
            }
            return Ok(());
        }
        let mut worker = current_worker;
        let pin = worker.pin_sweep_family_key_image_binding(worker_binding.clone())?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_worker(worker)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        let durable_worker = durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if pin.persistence.revision() != durable_worker.revision()
            || durable_worker.sweep_family_key_images(roast.sweep_id()) != Some(&worker_binding)
        {
            return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
        }
        runtime.snapshot = durable;
        Ok(())
    }

    pub async fn record_byzantine_share(
        &self,
        family: [u8; 32],
        view: u64,
        contribution: SignedShareContribution,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (_, mut roast) = runtime.snapshot.roast_by_family(family)?;
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let pinned = worker
            .sweep_family_key_images(roast.sweep_id())
            .ok_or(DepositServiceError::MissingByzantineKeyImageAuthorization)?;
        let certificate = roast
            .key_image_binding_certificate(view)?
            .ok_or(DepositServiceError::MissingByzantineKeyImageAuthorization)?;
        certificate
            .value()
            .ok_or(DepositServiceError::MissingByzantineKeyImageAuthorization)?
            .verify_worker_binding(pinned)?;
        let share_payload = postcard::to_allocvec(&contribution)?;
        let pending_exposure = if contribution.sender() == self.party {
            Some(roast.prepare_local_share_exposure(view, share_payload.clone())?)
        } else {
            None
        };
        if contribution.sender() == self.party
            && roast.local_safety_phase(view) != Some(AttemptSafetyPhase::ShareExposed)
        {
            return Err(DepositServiceError::MissingByzantineKeyImageAuthorization);
        }
        roast.observe_share(view, &contribution)?;
        let binding = roast.wire_binding(view)?;
        let ledger_sequence = roast.expected_slot(view)?.ledger_sequence();
        let network = roast.quic_network_id();
        let messages = roast
            .pending_relays(view, RoastContributionPhase::Share, contribution.sender())?
            .into_iter()
            .map(|relay| {
                let wire = ByzantineConsolidationWireMessage::Share(ByzantineShareRelay::new(
                    self.party,
                    relay.recipient(),
                    family,
                    view,
                    binding.clone(),
                    contribution.clone(),
                    roast.committee(),
                    network,
                )?);
                Ok((
                    ledger_sequence,
                    relay.recipient(),
                    DepositOperation::Consolidation,
                    wire.encode()?,
                ))
            })
            .collect::<Result<Vec<_>, DepositServiceError>>()?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_roast_and_enqueue(&roast, messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        if let Some(pending) = pending_exposure {
            let (_, durable_roast) = durable.roast_by_family(family)?;
            let safety = durable_roast
                .local_safety_bytes(view)?
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
            let (context, intent, intent_certificate) = durable_roast
                .certified_intent(view)
                .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
            let exposed = pending.release_after_persisted_state(
                &safety,
                context,
                intent,
                intent_certificate,
            )?;
            if exposed.payload() != share_payload {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }
        }
        runtime.snapshot = durable;
        Ok(())
    }

    pub async fn record_byzantine_candidate(
        &self,
        family: [u8; 32],
        view: u64,
        attestation: PortableSignedTransactionAttestation,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (_, mut roast) = runtime.snapshot.roast_by_family(family)?;
        let mut replay_probe = roast.clone();
        if !replay_probe.observe_candidate(view, &attestation)? {
            return Ok(());
        }
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let prepared = worker.reconstruct_reserved_sweep(&runtime.deriver, roast.sweep_id())?;
        let binding = roast.wire_binding(view)?;
        attestation.verify(roast.committee(), roast.quic_network_id(), &binding)?;
        worker.validate_sweep_family_candidate(
            roast.sweep_id(),
            attestation.signed().transaction(),
        )?;
        roast.observe_candidate(view, &attestation)?;
        let ledger_sequence = roast.expected_slot(view)?.ledger_sequence();
        let network = roast.quic_network_id();
        let messages = roast
            .pending_relays(view, RoastContributionPhase::Candidate, attestation.origin())?
            .into_iter()
            .map(|relay| {
                let candidate = ByzantineCandidateRelay::new(
                    self.party,
                    relay.recipient(),
                    family,
                    view,
                    binding.clone(),
                    attestation.clone(),
                    roast.committee(),
                    network,
                )?;
                candidate.verify_with_worker(
                    roast.committee(),
                    network,
                    family,
                    view,
                    &binding,
                    &prepared,
                    worker,
                )?;
                let wire = ByzantineConsolidationWireMessage::Candidate(candidate);
                Ok((
                    ledger_sequence,
                    relay.recipient(),
                    DepositOperation::Consolidation,
                    wire.encode()?,
                ))
            })
            .collect::<Result<Vec<_>, DepositServiceError>>()?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_roast_and_enqueue(&roast, messages)?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(())
    }

    /// Configure a deposit service. No wallet state is created until epoch-zero activation.
    pub fn new(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<PathBuf>,
        identity_seed: &[u8; 32],
        private_view_scalar: Zeroizing<[u8; 32]>,
        worker_config: DepositWorkerConfig,
        source: Arc<dyn DepositChainSource>,
    ) -> Result<Arc<Self>, DepositServiceError> {
        let configured_birth_anchor = scenario
            .deposit_birth_anchor
            .map(|anchor| ChainPoint::new(anchor.height, anchor.hash.0))
            .transpose()?;
        if scenario.network != crate::NetworkKind::Regtest && configured_birth_anchor.is_none() {
            return Err(DepositServiceError::MissingConfiguredBirthAnchor);
        }
        Self::new_inner(
            party,
            scenario,
            state_directory,
            identity_seed,
            private_view_scalar,
            configured_birth_anchor,
            worker_config,
            source,
            None,
        )
    }

    /// Configure a deposit service with autonomous consolidation preparation and publication.
    ///
    /// The backend is invoked only after the service has copied a stable candidate out of its
    /// runtime mutex. Daemon RPC latency therefore cannot stop allocation, history, or QUIC
    /// certificate progress.
    pub fn new_with_consolidation_backend(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<PathBuf>,
        identity_seed: &[u8; 32],
        private_view_scalar: Zeroizing<[u8; 32]>,
        worker_config: DepositWorkerConfig,
        source: Arc<dyn DepositChainSource>,
        consolidation_backend: Arc<dyn DepositConsolidationBackend>,
    ) -> Result<Arc<Self>, DepositServiceError> {
        let configured_birth_anchor = scenario
            .deposit_birth_anchor
            .map(|anchor| ChainPoint::new(anchor.height, anchor.hash.0))
            .transpose()?;
        if scenario.network != crate::NetworkKind::Regtest && configured_birth_anchor.is_none() {
            return Err(DepositServiceError::MissingConfiguredBirthAnchor);
        }
        Self::new_inner(
            party,
            scenario,
            state_directory,
            identity_seed,
            private_view_scalar,
            configured_birth_anchor,
            worker_config,
            source,
            Some(consolidation_backend),
        )
    }

    /// Configure an exact deployment-wide wallet birth checkpoint and require it to match the
    /// checkpoint already bound into the scenario trust domain. This constructor is useful to
    /// make that equality explicit at an integration boundary; [`Self::new`] uses the same
    /// scenario-bound point directly.
    pub fn new_with_birth_anchor(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<PathBuf>,
        identity_seed: &[u8; 32],
        private_view_scalar: Zeroizing<[u8; 32]>,
        birth_anchor: ChainPoint,
        worker_config: DepositWorkerConfig,
        source: Arc<dyn DepositChainSource>,
    ) -> Result<Arc<Self>, DepositServiceError> {
        let scenario_anchor = scenario
            .deposit_birth_anchor
            .map(|anchor| ChainPoint::new(anchor.height, anchor.hash.0))
            .transpose()?;
        if scenario_anchor != Some(birth_anchor) {
            return Err(DepositServiceError::BirthAnchorNotScenarioBound);
        }
        Self::new_inner(
            party,
            scenario,
            state_directory,
            identity_seed,
            private_view_scalar,
            Some(birth_anchor),
            worker_config,
            source,
            None,
        )
    }

    /// Configure a scenario-bound birth anchor and autonomous consolidation backend together.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_birth_anchor_and_consolidation_backend(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<PathBuf>,
        identity_seed: &[u8; 32],
        private_view_scalar: Zeroizing<[u8; 32]>,
        birth_anchor: ChainPoint,
        worker_config: DepositWorkerConfig,
        source: Arc<dyn DepositChainSource>,
        consolidation_backend: Arc<dyn DepositConsolidationBackend>,
    ) -> Result<Arc<Self>, DepositServiceError> {
        let scenario_anchor = scenario
            .deposit_birth_anchor
            .map(|anchor| ChainPoint::new(anchor.height, anchor.hash.0))
            .transpose()?;
        if scenario_anchor != Some(birth_anchor) {
            return Err(DepositServiceError::BirthAnchorNotScenarioBound);
        }
        Self::new_inner(
            party,
            scenario,
            state_directory,
            identity_seed,
            private_view_scalar,
            Some(birth_anchor),
            worker_config,
            source,
            Some(consolidation_backend),
        )
    }

    fn new_inner(
        party: PartyId,
        scenario: Scenario,
        state_directory: impl Into<PathBuf>,
        identity_seed: &[u8; 32],
        private_view_scalar: Zeroizing<[u8; 32]>,
        configured_birth_anchor: Option<ChainPoint>,
        worker_config: DepositWorkerConfig,
        source: Arc<dyn DepositChainSource>,
        consolidation_backend: Option<Arc<dyn DepositConsolidationBackend>>,
    ) -> Result<Arc<Self>, DepositServiceError> {
        scenario.validate()?;
        worker_config.validate()?;
        if let Some(anchor) = configured_birth_anchor {
            ChainPoint::new(anchor.height, anchor.hash)?;
        }
        let state_directory = state_directory.into();
        let protocol_store = Arc::new(ProtocolStore::new(&state_directory, party, identity_seed)?);
        Ok(Arc::new(Self {
            party,
            scenario,
            repository: Arc::new(DepositSnapshotRepository::new(
                state_directory.clone(),
                party,
                identity_seed,
            )?),
            archive: DepositArchiveStore::new(state_directory.clone(), party, identity_seed)?,
            roast_archive: RoastAttemptArchiveStore::new(
                state_directory.clone(),
                party,
                identity_seed,
            )?,
            deposit_index_directory: state_directory,
            deposit_index_identity_seed: Zeroizing::new(*identity_seed),
            protocol_store,
            deposit_index: Arc::new(Mutex::new(None)),
            compact_registry: Arc::new(Mutex::new(None)),
            private_view_scalar,
            configured_birth_anchor,
            worker_config,
            source,
            consolidation_backend,
            runtime: Mutex::new(None),
            runtime_ready: AtomicBool::new(false),
        }))
    }

    async fn resolve_birth_anchor(&self) -> Result<ChainPoint, DepositServiceError> {
        let anchor = match self.configured_birth_anchor {
            Some(anchor) => anchor,
            None if self.scenario.network == crate::NetworkKind::Regtest => {
                return Ok(ChainPoint::new(0, self.source.block_hash(0).await?)?);
            }
            None => return Err(DepositServiceError::MissingConfiguredBirthAnchor),
        };
        if self.source.block_hash(anchor.height).await? != anchor.hash {
            return Err(DepositServiceError::BirthAnchorMismatch);
        }
        Ok(anchor)
    }

    /// Restore from the two independently authenticated compact heads. Startup never replays the
    /// certificate or epoch prefix: the portable index supplies the exact last statement needed
    /// to bind a bounded ledger cursor.
    async fn restore_archived_protocol(
        &self,
        snapshot: &DepositServiceSnapshot,
        deriver: &DepositAddressDeriver,
    ) -> Result<DepositProtocolState, DepositServiceError> {
        let archive_head = snapshot.archive_head()?;
        let registry = {
            let guard = self.compact_registry.lock().await;
            let store =
                guard.as_ref().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
            store
                .head()
                .ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?
                .registry()
                .clone()
        };
        if registry.wallet() != snapshot.wallet {
            return Err(DepositServiceError::WrongWallet);
        }
        let (portable, last_statement) = {
            let mut guard = self.deposit_index.lock().await;
            let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            let portable = PortableDepositIndexHead::from_head(store.portable_head())?;
            let last_statement = if portable.through_sequence() == 0 {
                None
            } else {
                match store
                    .lookup_portable_state(PortableStateQuery::Sequence(
                        portable.through_sequence(),
                    ))
                    .await?
                {
                    Some(PortableStateRecord::Statement(statement)) => Some(statement),
                    None | Some(_) => {
                        return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                    }
                }
            };
            (portable, last_statement)
        };
        let expected_checkpoint_sequence = snapshot
            .index_checkpoint_certificate()
            .map_or(0, |checkpoint| checkpoint.statement().sequence());
        if archive_head.len() != expected_checkpoint_sequence {
            return Err(DepositServiceError::InvalidArchiveHead);
        }
        let ledger = CompactLedgerCursor::from_authenticated_portable_head(
            &registry,
            &portable,
            last_statement.as_ref(),
        )?;
        let protocol = DepositLocalState::decode(
            snapshot.reducer_bytes(),
            registry,
            ledger,
            deriver,
            self.party,
            self.scenario.quic_network_id()?,
        )?;
        if protocol.checkpoint_sequence != archive_head.len() {
            return Err(DepositServiceError::InvalidArchiveHead);
        }
        if let Some(target) = &protocol.pending_handoff {
            validate_trusted_handoff_target(&self.scenario, &protocol, deriver, target)?;
        }
        Ok(protocol)
    }

    /// Restore and cross-check the sole supported snapshot schema.
    async fn restore_current_snapshot(
        &self,
        mut snapshot: DepositServiceSnapshot,
        deriver: &DepositAddressDeriver,
    ) -> Result<(DepositServiceSnapshot, DepositProtocolState), DepositServiceError> {
        snapshot.validate()?;
        self.initialize_deposit_index(&mut snapshot).await?;
        self.initialize_compact_registry(&mut snapshot).await?;
        let roast_head = snapshot.roast_attempt_archive_head();
        if roast_head.network_id() != self.scenario.quic_network_id()? {
            return Err(DepositServiceError::InvalidRoastAttemptArchive);
        }
        self.roast_archive.recover_stage_journal(&self.protocol_store, roast_head).await?;
        self.roast_archive.verify_head(roast_head).await?;
        let protocol = self.restore_archived_protocol(&snapshot, deriver).await?;
        validate_restored_byzantine_authority(
            &protocol,
            &snapshot,
            deriver,
            self.scenario.quic_network_id()?,
        )?;
        self.authenticate_restored_consensus_dependencies(&protocol).await?;
        let consolidation = snapshot.consolidation()?;
        validate_consolidation_alignment(self, &protocol, &snapshot, &consolidation).await?;
        Ok((snapshot, protocol))
    }

    async fn initialize_deposit_index(
        &self,
        snapshot: &mut DepositServiceSnapshot,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.deposit_index.lock().await;
        if let Some(store) = guard.as_ref() {
            if store.checkpoint() != snapshot.deposit_index_checkpoint() {
                return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
            }
            return Ok(());
        }
        let store = DepositIndexStore::open_with_stores(
            Arc::clone(&self.protocol_store),
            WalletArtifactStore::new(
                self.deposit_index_directory.clone(),
                self.party,
                &self.deposit_index_identity_seed,
            )?,
            snapshot.deposit_index_checkpoint().clone(),
        )
        .await?;
        let settled = store.checkpoint().clone();
        if &settled != snapshot.deposit_index_checkpoint() {
            let mut candidate = snapshot.clone();
            candidate
                .install_deposit_index_checkpoint(snapshot.deposit_index_checkpoint(), settled)?;
            *snapshot = self.repository.persist_and_read_back(&candidate).await?;
        }
        *guard = Some(store);
        Ok(())
    }

    async fn initialize_compact_registry(
        &self,
        snapshot: &mut DepositServiceSnapshot,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.compact_registry.lock().await;
        if let Some(store) = guard.as_ref() {
            if store.checkpoint() != snapshot.compact_registry_checkpoint() {
                return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
            }
            return Ok(());
        }
        let store = CompactRegistryStore::open_with_stores(
            Arc::clone(&self.protocol_store),
            WalletArtifactStore::new(
                self.deposit_index_directory.clone(),
                self.party,
                &self.deposit_index_identity_seed,
            )?,
            snapshot.compact_registry_checkpoint().clone(),
        )
        .await?;
        let settled = store.checkpoint().clone();
        if &settled != snapshot.compact_registry_checkpoint() {
            let mut candidate = snapshot.clone();
            candidate.install_compact_registry_checkpoint(
                snapshot.compact_registry_checkpoint(),
                settled,
            )?;
            *snapshot = self.repository.persist_and_read_back(&candidate).await?;
        }
        *guard = Some(store);
        Ok(())
    }

    /// Load one terminal through the authenticated portable index. Worker state deliberately
    /// carries no duplicate certified-terminal cache.
    async fn authenticated_portable_terminal(
        &self,
        query: PortableStateQuery,
    ) -> Result<Option<AuthenticatedPortableTerminal>, DepositServiceError> {
        let mut guard = self.deposit_index.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let terminal = match store.lookup_portable_state(query).await? {
            Some(PortableStateRecord::Terminal(terminal)) => terminal,
            None => return Ok(None),
            Some(_) => return Err(DepositServiceError::InvalidPortableTerminalEvidence),
        };
        let (current_sequence, current_digest, abandonment_reference) = match terminal.status() {
            PortableConsolidationStatus::Completed {
                statement_sequence, statement_digest, ..
            } => (*statement_sequence, *statement_digest, None),
            PortableConsolidationStatus::Abandoned { evidence } => (
                evidence.statement_sequence(),
                evidence.statement_digest(),
                Some((evidence.statement_sequence(), evidence.statement_digest())),
            ),
            PortableConsolidationStatus::LateSettled {
                settlement_sequence,
                settlement_digest,
                abandonment,
                ..
            } => (
                *settlement_sequence,
                *settlement_digest,
                Some((abandonment.statement_sequence(), abandonment.statement_digest())),
            ),
        };
        let current_statement = match store
            .lookup_portable_state(PortableStateQuery::Sequence(current_sequence))
            .await?
        {
            Some(PortableStateRecord::Statement(statement))
                if statement.digest() == current_digest =>
            {
                statement
            }
            None | Some(_) => {
                return Err(DepositServiceError::InvalidPortableTerminalEvidence);
            }
        };
        let abandonment_statement = match abandonment_reference {
            None => None,
            Some((sequence, digest))
                if sequence == current_sequence && digest == current_digest =>
            {
                Some(current_statement.clone())
            }
            Some((sequence, digest)) => {
                match store.lookup_portable_state(PortableStateQuery::Sequence(sequence)).await? {
                    Some(PortableStateRecord::Statement(statement))
                        if statement.digest() == digest =>
                    {
                        Some(statement)
                    }
                    None | Some(_) => {
                        return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                    }
                }
            }
        };
        let evidence =
            AuthenticatedPortableTerminal { terminal, current_statement, abandonment_statement };
        evidence.validate()?;
        Ok(Some(evidence))
    }

    async fn authenticated_portable_terminal_by_sweep(
        &self,
        sweep: SweepId,
    ) -> Result<Option<AuthenticatedPortableTerminal>, DepositServiceError> {
        self.authenticated_portable_terminal(PortableStateQuery::Sweep(sweep)).await
    }

    /// Resolve the portable family which permanently claimed an exact output.
    async fn portable_claiming_sweep(
        &self,
        output: WalletOutputId,
    ) -> Result<Option<SweepId>, DepositServiceError> {
        let mut guard = self.deposit_index.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        match store.lookup_portable_state(PortableStateQuery::ClaimedOutput(output)).await? {
            Some(PortableStateRecord::OutputClaim(claim)) => Ok(Some(claim.sweep_id())),
            None => Ok(None),
            Some(_) => Err(DepositServiceError::InvalidPortableTerminalEvidence),
        }
    }

    async fn load_deposit_archive_artifact(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<Vec<u8>, DepositServiceError> {
        let chunk_limit = u32::try_from(MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES)
            .map_err(|_| DepositServiceError::InvalidArchiveHead)?;
        let mut chunks = Vec::new();
        let mut offset = 0_u64;
        loop {
            let request = DepositArtifactChunkRequest::new(reference, offset, chunk_limit)?;
            let chunk = self.archive.artifact_chunk(request).await?;
            offset = offset
                .checked_add(
                    u64::try_from(chunk.bytes.len())
                        .map_err(|_| DepositServiceError::InvalidArchiveHead)?,
                )
                .ok_or(DepositServiceError::InvalidArchiveHead)?;
            let complete = chunk.complete;
            chunks.push(chunk);
            if complete {
                break;
            }
        }
        Ok(assemble_artifact_chunks(reference, &chunks)?)
    }

    async fn load_certified_ledger_artifact(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<CertifiedLedgerEntry, DepositServiceError> {
        Ok(CertifiedLedgerEntry::from_bytes(&self.load_deposit_archive_artifact(reference).await?)?)
    }

    async fn load_certified_deposit_observation_artifact(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<CertifiedDepositObservation, DepositServiceError> {
        Ok(CertifiedDepositObservation::from_bytes(
            &self.load_deposit_archive_artifact(reference).await?,
        )?)
    }

    async fn load_index_checkpoint_artifact(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<DepositIndexCheckpointCertificate, DepositServiceError> {
        Ok(DepositIndexCheckpointCertificate::from_bytes(
            &self.load_deposit_archive_artifact(reference).await?,
        )?)
    }

    async fn historical_issuer_for_statement(
        &self,
        statement: &LedgerStatement,
    ) -> Result<Option<VerifiedIssuerWindow>, DepositServiceError> {
        let LedgerPayload::LateConsolidationSettlement(settlement) = &statement.payload else {
            return Ok(None);
        };
        let epoch = settlement.historical_completion().attempt().epoch();
        let mut guard = self.compact_registry.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
        Ok(Some(store.lookup_issuer_window(epoch).await?))
    }

    /// Authenticate every external dependency which cannot be proved from the consensus value
    /// alone before that value enters a reducer. The portable-index preflight closes all alias,
    /// terminal, output-claim, signing-session, and sequence conflicts. A late settlement also
    /// binds its proposer-carried abandonment statement and historical issuer to this party's
    /// independently authenticated stores.
    async fn authenticate_consensus_value_dependencies(
        &self,
        protocol: &DepositProtocolState,
        value: &ConsensusValue,
    ) -> Result<(), DepositServiceError> {
        let decoded = DepositConsensusValue::decode(value)?;
        self.verified_index_preflight(&decoded.statement).await?;

        let LedgerPayload::LateConsolidationSettlement(settlement) = &decoded.statement.payload
        else {
            return Ok(());
        };
        let Some(ConsolidationTerminalEvidence::LateSettlement(evidence)) =
            decoded.terminal_evidence.as_ref()
        else {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        };
        let completion = settlement.historical_completion();
        let indexed = self
            .authenticated_portable_terminal_by_sweep(completion.plan().id)
            .await?
            .ok_or(DepositServiceError::InvalidLateConsolidationSettlement)?;
        let PortableConsolidationStatus::Abandoned { evidence: indexed_abandonment } =
            indexed.terminal.status()
        else {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        };
        if indexed.terminal.consolidation_id() != settlement.id()
            || indexed.terminal.sweep_id() != completion.plan().id
            || indexed.terminal.inputs() != completion.inputs()
            || indexed.abandonment_statement() != Some(&evidence.abandonment_statement)
            || indexed_abandonment.statement_digest() != evidence.abandonment_statement.digest()
            || settlement.abandonment_statement() != evidence.abandonment_statement.digest()
        {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        }

        let historical_issuer = {
            let mut guard = self.compact_registry.lock().await;
            let store =
                guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
            store.lookup_issuer_window(completion.attempt().epoch()).await?
        };
        if historical_issuer.issuer().group_key() != completion.authorization().root_group_key() {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        }
        let reconstructed = LedgerStatement::late_consolidation_settlement(
            &protocol.registry,
            &historical_issuer,
            decoded.statement.sequence,
            decoded.statement.previous,
            evidence.abandonment_statement.digest(),
            completion.clone(),
            settlement.inclusion(),
            settlement.observation_tip(),
            settlement.finality_depth(),
        )?;
        if reconstructed != decoded.statement {
            return Err(DepositServiceError::InvalidLateConsolidationSettlement);
        }
        Ok(())
    }

    async fn authenticate_restored_consensus_dependencies(
        &self,
        protocol: &DepositProtocolState,
    ) -> Result<(), DepositServiceError> {
        let Some(lane) = protocol.consensus_lane.as_ref() else {
            return Ok(());
        };
        for admitted in lane.admitted_values.values() {
            let value = DepositConsensusValue::with_evidence(
                admitted.statement.clone(),
                admitted.terminal_evidence.clone(),
            )?;
            self.authenticate_consensus_value_dependencies(protocol, &value).await?;
        }
        Ok(())
    }

    /// Resolve a witness-bearing ledger certificate from its authenticated party-local locator.
    /// Portable state remains witness independent; this is used only by diagnostics which expose
    /// the exact current-committee certificate signers.
    async fn authenticated_certified_entry(
        &self,
        statement: &LedgerStatement,
    ) -> Result<CertifiedLedgerEntry, DepositServiceError> {
        let locator = {
            let mut guard = self.deposit_index.lock().await;
            let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            match store
                .lookup_local_safety(LocalSafetyQuery::CertifiedEntryLocator(statement.sequence))
                .await?
                .map(|record| record.value().clone())
            {
                Some(LocalSafetyValue::CertifiedEntryLocator(locator)) => locator,
                None | Some(_) => {
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
            }
        };
        if locator.wallet_id() != statement.wallet
            || locator.ledger_sequence() != statement.sequence
            || locator.ledger_statement() != statement.digest()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let entry = self.load_certified_ledger_artifact(locator.ledger_artifact()).await?;
        if entry.statement != *statement {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let (issuer, historical) = {
            let historical_epoch = match &entry.statement.payload {
                LedgerPayload::LateConsolidationSettlement(settlement) => {
                    Some(settlement.historical_completion().attempt().epoch())
                }
                LedgerPayload::Allocation(_)
                | LedgerPayload::HandoffFence(_)
                | LedgerPayload::Handoff(_)
                | LedgerPayload::ConsolidationCompletion(_)
                | LedgerPayload::ConsolidationAbandonment(_) => None,
            };
            let mut guard = self.compact_registry.lock().await;
            let store =
                guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
            let issuer = store.lookup_issuer_window(entry.statement.issuer_epoch).await?;
            let historical = match historical_epoch {
                Some(epoch) => Some(store.lookup_issuer_window(epoch).await?),
                None => None,
            };
            (issuer, historical)
        };
        entry.verify(&issuer, historical.as_ref())?;
        Ok(entry)
    }

    /// Authenticate only the snapshot-authoritative latest checkpoint. No prefix replay is
    /// accepted: the exact archive-tip event, typed operation artifact, n-f checkpoint artifact,
    /// issuer window, and current portable root must all agree.
    async fn authenticated_latest_index_checkpoint(
        &self,
        snapshot: &DepositServiceSnapshot,
    ) -> Result<Option<VerifiedDepositIndexCheckpoint>, DepositServiceError> {
        let portable = PortableDepositIndexHead::from_head(
            snapshot.deposit_index_checkpoint().portable_head(),
        )?;
        if portable.through_sequence() == 0 {
            if !snapshot.archive_head()?.is_empty()
                || snapshot.checkpoint_operation_certificate().is_some()
                || snapshot.index_checkpoint_certificate().is_some()
            {
                return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
            }
            return Ok(None);
        }
        let operation_reference = snapshot
            .checkpoint_operation_certificate()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let snapshot_certificate = snapshot
            .index_checkpoint_certificate()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let archive_head = snapshot.archive_head()?;
        if archive_head.len() != snapshot_certificate.statement().sequence() {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let event_reference =
            archive_head.event_reference().ok_or(DepositServiceError::InvalidArchiveHead)?;
        let event = DepositArchiveEvent::from_bytes(
            &self.load_deposit_archive_artifact(event_reference).await?,
        )?;
        if event.wallet_id() != snapshot.wallet
            || event.ordinal().checked_add(1) != Some(archive_head.len())
            || event.operation_reference() != operation_reference
            || event.operation()
                != match snapshot_certificate.statement().operation() {
                    DepositIndexCheckpointOperation::Ledger { .. } => {
                        DepositArchiveOperation::Ledger
                    }
                    DepositIndexCheckpointOperation::DepositObservation { .. } => {
                        DepositArchiveOperation::DepositObservation
                    }
                }
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let certificate = self.load_index_checkpoint_artifact(event.checkpoint_reference()).await?;
        if &certificate != snapshot_certificate
            || certificate.statement().resulting_head() != &portable
            || certificate.statement().ledger_sequence() != portable.through_sequence()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        match certificate.statement().operation() {
            DepositIndexCheckpointOperation::Ledger { statement } => {
                let ledger = self.load_certified_ledger_artifact(operation_reference).await?;
                if statement != ledger.statement.digest()
                    || ledger.statement.sequence != portable.through_sequence()
                    || ledger.statement.digest() != portable.ledger_head()
                    || certificate.statement().ledger_decision() != ledger.statement.digest()
                {
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
                let (issuer, historical) = {
                    let historical_epoch = match &ledger.statement.payload {
                        LedgerPayload::LateConsolidationSettlement(settlement) => {
                            Some(settlement.historical_completion().attempt().epoch())
                        }
                        LedgerPayload::Allocation(_)
                        | LedgerPayload::HandoffFence(_)
                        | LedgerPayload::Handoff(_)
                        | LedgerPayload::ConsolidationCompletion(_)
                        | LedgerPayload::ConsolidationAbandonment(_) => None,
                    };
                    let mut guard = self.compact_registry.lock().await;
                    let store = guard
                        .as_mut()
                        .ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
                    let issuer = store.lookup_issuer_window(ledger.statement.issuer_epoch).await?;
                    let historical = match historical_epoch {
                        Some(epoch) => Some(store.lookup_issuer_window(epoch).await?),
                        None => None,
                    };
                    (issuer, historical)
                };
                Ok(Some(certificate.verify_anchored(
                    self.scenario.quic_network_id()?,
                    &issuer,
                    historical.as_ref(),
                    &ledger,
                    &portable,
                )?))
            }
            DepositIndexCheckpointOperation::DepositObservation { statement } => {
                let observation =
                    self.load_certified_deposit_observation_artifact(operation_reference).await?;
                if statement != observation.statement.digest()
                    || certificate.statement().ledger_decision() != portable.ledger_head()
                {
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
                let issuer = {
                    let mut guard = self.compact_registry.lock().await;
                    let store = guard
                        .as_mut()
                        .ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
                    store.lookup_issuer_window(observation.statement.issuer_epoch()).await?
                };
                Ok(Some(certificate.verify_archived_deposit_observation_anchored(
                    self.scenario.quic_network_id()?,
                    &issuer,
                    &observation,
                    &portable,
                )?))
            }
        }
    }

    /// Resolve one certified allocation entirely through authenticated direct index paths.
    ///
    /// Portable state supplies the witness-independent statement; the local safety tree supplies
    /// an exact witness-bearing artifact locator and permanent first-use tombstone. The artifact
    /// is re-read, canonical-decoded, and verified under its directly authenticated issuer window
    /// before client-visible address bytes are released.
    async fn certified_address_response(
        &self,
        request: DepositAddressRequest,
        now: u64,
        leader: PartyId,
    ) -> Result<Option<DepositAddressResponse>, DepositServiceError> {
        let archive_head = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if !worker.allocation_view_ready() {
                return Ok(None);
            }
            runtime.snapshot.archive_head()?
        };
        let (record, permanently_used, locator) = {
            let mut guard = self.deposit_index.lock().await;
            let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            let Some(record) =
                store.lookup_portable(&PortableAllocationQuery::Request(request.request)).await?
            else {
                return Ok(None);
            };
            let allocation = record.allocation();
            if allocation.binding != request.binding {
                return Err(DepositServiceError::RequestEquivocation);
            }
            let permanently_used = match store
                .lookup_portable_state(PortableStateQuery::FirstUsed(allocation.address.index()))
                .await?
            {
                Some(PortableStateRecord::FirstUse(first_use))
                    if first_use.allocation_sequence() == record.statement().sequence
                        && first_use.allocation_statement() == record.statement_digest()
                        && first_use.index() == allocation.address.index() =>
                {
                    true
                }
                None => false,
                Some(_) => return Err(DepositServiceError::InvalidDepositIndexCheckpoint),
            };
            let locator = match store
                .lookup_local_safety(LocalSafetyQuery::CertifiedEntryLocator(
                    record.statement().sequence,
                ))
                .await?
                .map(|record| record.value().clone())
            {
                Some(LocalSafetyValue::CertifiedEntryLocator(locator)) => Some(locator),
                None => None,
                Some(_) => return Err(DepositServiceError::InvalidDepositIndexCheckpoint),
            };
            (record, permanently_used, locator)
        };
        let allocation = record.allocation();
        let locator = locator.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        if locator.wallet_id() != record.wallet_id()
            || locator.ledger_sequence() != record.statement().sequence
            || locator.ledger_statement() != record.statement_digest()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }

        let mut archived = None;
        self.archive
            .visit_checkpoints(archive_head, |checkpoint| {
                if let ArchivedDepositCheckpoint::Ledger(entry) = checkpoint
                    && entry.event_artifact == locator.event_artifact()
                {
                    if archived.is_some() {
                        return Err(DepositArchiveError::BrokenArchiveChain);
                    }
                    archived = Some(entry);
                }
                Ok(())
            })
            .await?;
        let archived = archived.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        if archived.checkpoint_sequence != locator.checkpoint_sequence()
            || archived.entry_artifact != locator.ledger_artifact()
            || archived.checkpoint_artifact != locator.checkpoint_artifact()
            || archived.entry.statement != *record.statement()
            || archived.checkpoint.statement().decision_digest() != locator.checkpoint_decision()
            || archived.checkpoint.certificate_digest()? != locator.checkpoint_certificate_digest()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let (issuer, historical) = {
            let historical_epoch = match &archived.entry.statement.payload {
                LedgerPayload::LateConsolidationSettlement(settlement) => {
                    Some(settlement.historical_completion().attempt().epoch())
                }
                LedgerPayload::Allocation(_)
                | LedgerPayload::HandoffFence(_)
                | LedgerPayload::Handoff(_)
                | LedgerPayload::ConsolidationCompletion(_)
                | LedgerPayload::ConsolidationAbandonment(_) => None,
            };
            let mut guard = self.compact_registry.lock().await;
            let store =
                guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
            let issuer = store.lookup_issuer_window(archived.entry.statement.issuer_epoch).await?;
            let historical = match historical_epoch {
                Some(epoch) => Some(store.lookup_issuer_window(epoch).await?),
                None => None,
            };
            (issuer, historical)
        };
        let verified_checkpoint = archived.checkpoint.verify_anchored(
            self.scenario.quic_network_id()?,
            &issuer,
            historical.as_ref(),
            &archived.entry,
            archived.checkpoint.statement().resulting_head(),
        )?;
        let verified_entry = archived.entry.verify(&issuer, historical.as_ref())?;
        let verified_locator =
            archived.verified_ledger_locator(&verified_entry, &verified_checkpoint)?;
        if verified_locator.checkpoint_sequence() != locator.checkpoint_sequence()
            || verified_locator.checkpoint_decision() != locator.checkpoint_decision()
            || verified_locator.checkpoint_certificate_digest()
                != locator.checkpoint_certificate_digest()
            || verified_locator.ledger_sequence() != locator.ledger_sequence()
            || verified_locator.ledger_statement() != locator.ledger_statement()
            || verified_locator.event_artifact() != locator.event_artifact()
            || verified_locator.ledger_artifact() != locator.ledger_artifact()
            || verified_locator.checkpoint_artifact() != locator.checkpoint_artifact()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let issuance =
            archived.entry.verify_allocation_issuance_schedule(&issuer, &verified_checkpoint)?;

        let (status, visible) = if now < allocation.created_at {
            // Do not return the certificate either: it contains the address.
            (DepositAddressStatus::Pending, None)
        } else if permanently_used {
            // A portable first-use certificate makes the address permanent. The 30-day deadline
            // applies only to unused allocations, so authenticate the original release window
            // even when this retrieval happens after that window.
            let release_time = now.min(allocation.expires_at.saturating_sub(1));
            (DepositAddressStatus::Permanent, Some(issuance.clone().release_at(release_time)?))
        } else if now >= allocation.expires_at {
            (DepositAddressStatus::Expired, None)
        } else {
            (DepositAddressStatus::Active, Some(issuance.release_at(now)?))
        };
        let certificate = visible.as_ref().map(|_| archived.entry);
        Ok(Some(DepositAddressResponse {
            request: request.request,
            status,
            address: visible.map(|allocation| allocation.address().clone()),
            certificate,
            created_at: Some(allocation.created_at),
            expires_at: Some(allocation.expires_at),
            leader,
        }))
    }

    async fn preload_portable_statement_paths(
        store: &mut DepositIndexStore,
        statement: &LedgerStatement,
    ) -> Result<(), DepositServiceError> {
        store.reset_bounded_cache()?;
        store
            .preload_portable_state_query(PortableStateQuery::Sequence(statement.sequence))
            .await?;
        match &statement.payload {
            LedgerPayload::Allocation(allocation) => {
                for query in [
                    PortableAllocationQuery::Request(allocation.request),
                    PortableAllocationQuery::Address(allocation.address.clone()),
                    PortableAllocationQuery::Index(allocation.address.index()),
                    PortableAllocationQuery::SubaddressSpendKey(subaddress_spend_key(
                        &allocation.address,
                    )?),
                ] {
                    store.preload_portable_query(&query).await?;
                }
            }
            LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_) => {}
            LedgerPayload::ConsolidationCompletion(completion) => {
                for query in [
                    PortableStateQuery::Consolidation(completion.id()),
                    PortableStateQuery::Sweep(completion.authorization().sweep_id()),
                    PortableStateQuery::SigningSession(completion.attempt().session()),
                    PortableStateQuery::NextSweepSequence,
                ] {
                    store.preload_portable_state_query(query).await?;
                }
                for output in completion.inputs() {
                    store
                        .preload_portable_state_query(PortableStateQuery::ClaimedOutput(*output))
                        .await?;
                }
            }
            LedgerPayload::ConsolidationAbandonment(abandonment) => {
                for query in [
                    PortableStateQuery::Consolidation(abandonment.id()),
                    PortableStateQuery::Sweep(abandonment.authorization().sweep_id()),
                    PortableStateQuery::SigningSession(abandonment.attempt().session()),
                    PortableStateQuery::NextSweepSequence,
                ] {
                    store.preload_portable_state_query(query).await?;
                }
                for output in abandonment.inputs() {
                    store
                        .preload_portable_state_query(PortableStateQuery::ClaimedOutput(*output))
                        .await?;
                }
            }
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                let completion = settlement.historical_completion();
                for query in [
                    PortableStateQuery::Consolidation(settlement.id()),
                    PortableStateQuery::Sweep(completion.authorization().sweep_id()),
                    PortableStateQuery::SigningSession(completion.attempt().session()),
                    PortableStateQuery::NextSweepSequence,
                ] {
                    store.preload_portable_state_query(query).await?;
                }
                for output in completion.inputs() {
                    store
                        .preload_portable_state_query(PortableStateQuery::ClaimedOutput(*output))
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn verified_index_preflight(
        &self,
        statement: &LedgerStatement,
    ) -> Result<VerifiedDepositIndexPreflight, DepositServiceError> {
        let mut guard = self.deposit_index.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        Self::preload_portable_statement_paths(store, statement).await?;
        let head = store.portable_head().clone();
        let mut builder = DepositIndexBuilder::new(store, head)?;
        Ok(builder.preflight_ledger_statement(statement)?)
    }

    async fn expected_index_checkpoint_material(
        &self,
        now: u64,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        entry: &CertifiedLedgerEntry,
    ) -> Result<
        (VerifiedDepositIndexPreflight, DepositIndexUpdate, DepositIndexCheckpointStatement),
        DepositServiceError,
    > {
        entry.verify_active(registry, historical_issuer)?;
        let mut guard = self.deposit_index.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        Self::preload_portable_statement_paths(store, &entry.statement).await?;
        let head = store.portable_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, head)?;
        let preflight = builder.preflight_ledger_statement(&entry.statement)?;
        let update = builder.finish()?.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let statement = DepositIndexCheckpointStatement::for_transition(
            now,
            self.scenario.quic_network_id()?,
            registry,
            historical_issuer,
            previous,
            entry,
            &preflight,
            &update,
            &*store,
        )?;
        Ok((preflight, update, statement))
    }

    async fn preload_deposit_observation_paths(
        store: &mut DepositIndexStore,
        statement: &DepositObservationStatement,
    ) -> Result<(), DepositServiceError> {
        for query in [
            PortableStateQuery::Sequence(statement.allocation_sequence()),
            PortableStateQuery::ObservedOutput(statement.output()),
            PortableStateQuery::ObservedOneTimeOutputKey(statement.output_key()),
            PortableStateQuery::FirstUsed(statement.index()),
        ] {
            store.preload_portable_state_query(query).await?;
        }
        Ok(())
    }

    async fn expected_deposit_observation_checkpoint_material(
        &self,
        now: u64,
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
    ) -> Result<
        (
            DepositIndexUpdate,
            VerifiedDepositObservationIndexTransition,
            DepositIndexCheckpointStatement,
        ),
        DepositServiceError,
    > {
        observation.verify_active(registry)?;
        let mut guard = self.deposit_index.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        Self::preload_deposit_observation_paths(store, &observation.statement).await?;
        let head = store.portable_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, head)?;
        if !builder.apply_verified_active_deposit_observation(observation, registry)? {
            return Err(DepositServiceError::ObservationAlreadyCertified);
        }
        let update = builder.finish()?.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let transition =
            update.verify_deposit_observation_transition(&*store, &observation.statement)?;
        let statement = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            now,
            self.scenario.quic_network_id()?,
            registry,
            previous,
            observation,
            &transition,
        )?;
        Ok((update, transition, statement))
    }

    async fn authenticate_checkpoint_consensus_candidate(
        &self,
        runtime: &DepositRuntime,
        candidate: &DepositIndexCheckpointCandidate,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        match candidate {
            DepositIndexCheckpointCandidate::Ledger(entry) => {
                let historical = self.historical_issuer_for_statement(&entry.statement).await?;
                entry.verify_active(&runtime.protocol.registry, historical.as_ref())?;
                self.expected_index_checkpoint_material(
                    now,
                    &runtime.protocol.registry,
                    historical.as_ref(),
                    previous.as_ref(),
                    entry,
                )
                .await?;
            }
            DepositIndexCheckpointCandidate::DepositObservation(observation) => {
                if !runtime.protocol.observation_is_source_handoff_prefix(&observation.statement) {
                    return Err(DepositServiceError::ConsensusUnavailable);
                }
                observation.verify_active(&runtime.protocol.registry)?;
                self.expected_deposit_observation_checkpoint_material(
                    now,
                    &runtime.protocol.registry,
                    previous.as_ref(),
                    observation,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Commit the checkpoint anti-equivocation slot and the empty durable witness lane before the
    /// identity is permitted to sign. The portable root remains unchanged until n-f checkpoint
    /// witnesses certify it.
    async fn commit_index_checkpoint_signing_lock(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
        slot: SignedIndexCheckpointSlot,
    ) -> Result<(), DepositServiceError> {
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_checkpoint = store.checkpoint().clone();
        if runtime.snapshot.deposit_index_checkpoint() != &expected_checkpoint {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        store.reset_bounded_cache()?;
        store
            .preload_local_safety_query(LocalSafetyQuery::SignedIndexCheckpointSlot(
                slot.checkpoint_sequence(),
            ))
            .await?;
        let local_head = store.local_safety_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, local_head)?;
        builder.record_signed_index_checkpoint_slot(slot)?;
        let Some(update) = builder.finish()? else {
            drop(index_guard);
            return self.commit_protocol(runtime, protocol).await;
        };
        let prepared = store.prepare_snapshot(vec![update]).await?;
        let mut candidate = runtime.snapshot.clone();
        candidate.replace_reducer_and_install_deposit_index_checkpoint(
            protocol.encode_local(&runtime.deriver)?,
            &expected_checkpoint,
            prepared.checkpoint().clone(),
        )?;
        let durable = match self.repository.persist_and_read_back(&candidate).await {
            Ok(durable) => durable,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint() =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == &expected_checkpoint =>
                {
                    store.abort_prepared(&prepared).await?;
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        runtime.snapshot = durable.clone();
        runtime.protocol = protocol;
        if let Err(error) =
            store.commit_prepared(&prepared, durable.deposit_index_checkpoint()).await
        {
            *index_guard = None;
            return Err(error.into());
        }
        let mut settled_candidate = durable;
        settled_candidate.install_deposit_index_checkpoint(
            prepared.checkpoint(),
            prepared.settled_checkpoint().clone(),
        )?;
        let settled = match self.repository.persist_and_read_back(&settled_candidate).await {
            Ok(settled) => settled,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(save_error);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if settled.deposit_index_checkpoint() != store.checkpoint() {
            runtime.snapshot = settled;
            *index_guard = None;
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        runtime.snapshot = settled;
        Ok(())
    }

    async fn sign_durable_index_checkpoint(
        &self,
        now: u64,
        identity: &Identity,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        entry: &CertifiedLedgerEntry,
        expected_statement: &DepositIndexCheckpointStatement,
    ) -> Result<SignedEnvelope, DepositServiceError> {
        let mut guard = self.deposit_index.lock().await;
        let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let authorization =
            store.authenticate_signed_index_checkpoint_slot(expected_statement.sequence()).await?;
        Self::preload_portable_statement_paths(store, &entry.statement).await?;
        let head = store.portable_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, head)?;
        let preflight = builder.preflight_ledger_statement(&entry.statement)?;
        let update = builder.finish()?.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let (statement, witness) = sign_checkpoint_transition(
            now,
            identity,
            &authorization,
            self.scenario.quic_network_id()?,
            registry,
            historical_issuer,
            previous,
            entry,
            &preflight,
            &update,
            &*store,
        )?;
        if &statement != expected_statement {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        Ok(witness)
    }

    /// Burn the local allocation/slot aliases before any attestation bytes are constructed.
    ///
    /// The pending reducer and local-safety root share one wallet-snapshot revision. A crash may
    /// therefore leave either the old state or the complete signer lock, never an emitted
    /// signature whose anti-equivocation record was lost.
    async fn commit_reserved_ledger_lock(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
        statement: &LedgerStatement,
    ) -> Result<(), DepositServiceError> {
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_checkpoint = store.checkpoint().clone();
        if runtime.snapshot.deposit_index_checkpoint() != &expected_checkpoint {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        store.reset_bounded_cache()?;
        for query in [
            LocalSafetyQuery::SignedLedgerSlot(statement.sequence),
            LocalSafetyQuery::CertifiedEntryLocator(statement.sequence),
        ] {
            store.preload_local_safety_query(query).await?;
        }
        if let LedgerPayload::Allocation(allocation) = &statement.payload {
            for query in [
                LocalSafetyQuery::ProposedIndex(allocation.address.index()),
                LocalSafetyQuery::ReservedRequest(allocation.request),
            ] {
                store.preload_local_safety_query(query).await?;
            }
        }
        let local_head = store.local_safety_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, local_head)?;
        if let LedgerPayload::Allocation(allocation) = &statement.payload {
            builder.reserve_allocation_proposal(
                allocation.request,
                allocation.binding,
                allocation.address.index(),
            )?;
        }
        builder.record_signed_ledger_slot(statement.sequence, statement.digest())?;
        let Some(update) = builder.finish()? else {
            drop(index_guard);
            return self.commit_protocol(runtime, protocol).await;
        };
        let prepared = store.prepare_snapshot(vec![update]).await?;
        let mut candidate = runtime.snapshot.clone();
        candidate.replace_reducer_and_install_deposit_index_checkpoint(
            protocol.encode_local(&runtime.deriver)?,
            &expected_checkpoint,
            prepared.checkpoint().clone(),
        )?;
        let durable = match self.repository.persist_and_read_back(&candidate).await {
            Ok(durable) => durable,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint() =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == &expected_checkpoint =>
                {
                    store.abort_prepared(&prepared).await?;
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        runtime.snapshot = durable.clone();
        runtime.protocol = protocol;
        if let Err(error) =
            store.commit_prepared(&prepared, durable.deposit_index_checkpoint()).await
        {
            *index_guard = None;
            return Err(error.into());
        }
        let mut settled_candidate = durable;
        settled_candidate.install_deposit_index_checkpoint(
            prepared.checkpoint(),
            prepared.settled_checkpoint().clone(),
        )?;
        let settled = match self.repository.persist_and_read_back(&settled_candidate).await {
            Ok(settled) => settled,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(save_error);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if settled.deposit_index_checkpoint() != store.checkpoint() {
            runtime.snapshot = settled;
            *index_guard = None;
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        runtime.snapshot = settled;
        Ok(())
    }

    /// Burn the paired output/key observation aliases in the same outer snapshot revision as the
    /// pending observation statement. The store may release an attestation only after this
    /// prepared transition is committed, settled, and authenticated by exact readback.
    async fn commit_deposit_observation_signing_lock(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
        statement: &DepositObservationStatement,
    ) -> Result<(), DepositServiceError> {
        let pending = protocol
            .pending_observations
            .get(&statement.output())
            .ok_or(DepositServiceError::UnknownDepositObservation)?;
        if pending.statement != *statement {
            return Err(DepositServiceError::ObservationEquivocation);
        }
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_checkpoint = store.checkpoint().clone();
        if runtime.snapshot.deposit_index_checkpoint() != &expected_checkpoint {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        store.reset_bounded_cache()?;
        for query in [
            LocalSafetyQuery::Output(statement.output()),
            LocalSafetyQuery::OneTimeOutputKey(statement.output_key()),
            LocalSafetyQuery::SignedDepositObservationOutput(statement.output()),
            LocalSafetyQuery::SignedDepositObservationKey(statement.output_key()),
        ] {
            store.preload_local_safety_query(query).await?;
        }
        let local_head = store.local_safety_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, local_head)?;
        builder.record_signed_deposit_observation(statement)?;
        let Some(update) = builder.finish()? else {
            drop(index_guard);
            return self.commit_protocol(runtime, protocol).await;
        };
        let prepared = store.prepare_snapshot(vec![update]).await?;
        let mut candidate = runtime.snapshot.clone();
        candidate.replace_reducer_and_install_deposit_index_checkpoint(
            protocol.encode_local(&runtime.deriver)?,
            &expected_checkpoint,
            prepared.checkpoint().clone(),
        )?;
        let durable = match self.repository.persist_and_read_back(&candidate).await {
            Ok(durable) => durable,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint() =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == &expected_checkpoint =>
                {
                    store.abort_prepared(&prepared).await?;
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        runtime.snapshot = durable.clone();
        runtime.protocol = protocol;
        if let Err(error) =
            store.commit_prepared(&prepared, durable.deposit_index_checkpoint()).await
        {
            *index_guard = None;
            return Err(error.into());
        }
        let mut settled_candidate = durable;
        settled_candidate.install_deposit_index_checkpoint(
            prepared.checkpoint(),
            prepared.settled_checkpoint().clone(),
        )?;
        let settled = match self.repository.persist_and_read_back(&settled_candidate).await {
            Ok(settled) => settled,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(save_error);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if settled.deposit_index_checkpoint() != store.checkpoint()
            || settled.deposit_index_checkpoint().has_recovery_journal()
        {
            runtime.snapshot = settled;
            *index_guard = None;
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        runtime.snapshot = settled;
        Ok(())
    }

    async fn verify_local_deposit_observation(
        &self,
        runtime: &DepositRuntime,
        statement: &DepositObservationStatement,
    ) -> Result<VerifiedLocalDepositObservation, DepositServiceError> {
        statement.validate_active(&runtime.protocol.registry)?;
        let allocation = {
            let mut index_guard = self.deposit_index.lock().await;
            let store =
                index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            store
                .lookup_portable(&PortableAllocationQuery::Index(statement.index()))
                .await?
                .ok_or(DepositServiceError::UnknownDepositAddress)?
        };
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        Ok(worker.verify_local_deposit_observation(&allocation, statement)?)
    }

    async fn deposit_observation_is_portable(
        &self,
        statement: &DepositObservationStatement,
    ) -> Result<bool, DepositServiceError> {
        let existing = {
            let mut index_guard = self.deposit_index.lock().await;
            let store =
                index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            store
                .lookup_portable_state(PortableStateQuery::ObservedOutput(statement.output()))
                .await?
        };
        match existing {
            None => Ok(false),
            Some(PortableStateRecord::DepositOutput(output))
                if output.wallet_id() == statement.wallet_id()
                    && output.allocation_sequence() == statement.allocation_sequence()
                    && output.allocation_statement() == statement.allocation_statement()
                    && output.index() == statement.index()
                    && output.output_key() == statement.output_key()
                    && output.index_on_blockchain() == statement.index_on_blockchain()
                    && output.amount_atomic_units() == statement.amount_atomic_units()
                    && output.observed_block() == statement.observed_block()
                    && output.block_timestamp() == statement.block_timestamp()
                    && output.observation_digest() == statement.digest() =>
            {
                Ok(true)
            }
            Some(_) => Err(DepositServiceError::ObservationEquivocation),
        }
    }

    async fn sign_durable_deposit_observation(
        &self,
        runtime: &DepositRuntime,
        identity: &Identity,
        statement: &DepositObservationStatement,
    ) -> Result<SignedEnvelope, DepositServiceError> {
        self.verify_local_deposit_observation(runtime, statement).await?;
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        if runtime.snapshot.deposit_index_checkpoint() != store.checkpoint() {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        Ok(store
            .sign_deposit_observation_attestation(identity, &runtime.protocol.registry, statement)
            .await?)
    }

    async fn sign_durable_deposit_observation_checkpoint(
        &self,
        now: u64,
        identity: &Identity,
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        expected_statement: &DepositIndexCheckpointStatement,
    ) -> Result<SignedEnvelope, DepositServiceError> {
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let authorization =
            store.authenticate_signed_index_checkpoint_slot(expected_statement.sequence()).await?;
        Self::preload_deposit_observation_paths(store, &observation.statement).await?;
        let head = store.portable_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, head)?;
        if !builder.apply_verified_active_deposit_observation(observation, registry)? {
            return Err(DepositServiceError::ObservationAlreadyCertified);
        }
        let update = builder.finish()?.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let transition =
            update.verify_deposit_observation_transition(&*store, &observation.statement)?;
        let (statement, witness) = sign_deposit_observation_checkpoint_transition(
            now,
            identity,
            &authorization,
            self.scenario.quic_network_id()?,
            registry,
            previous,
            observation,
            &transition,
        )?;
        if &statement != expected_statement {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        Ok(witness)
    }

    async fn stage_hot_roast_attempts(
        &self,
        current: RoastAttemptArchiveHead,
        roast: &ConsolidationRoast,
    ) -> Result<RoastAttemptArchiveStage, DepositServiceError> {
        let records = roast
            .hot_attempt_archive_materials()?
            .into_iter()
            .map(|material| {
                RoastAttemptArchiveRecord::new(
                    material.slot,
                    material.context,
                    material.intent,
                    material.intent_certificate,
                    material.wire_binding,
                    material.key_image_certificate,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.roast_archive.stage_attempts(current, &records, &mut rand_core::OsRng).await?)
    }

    fn compose_roast_archive_stage(
        aggregate: &mut Option<RoastAttemptArchiveStage>,
        current: RoastAttemptArchiveHead,
        next: RoastAttemptArchiveStage,
    ) -> Result<RoastAttemptArchiveHead, DepositServiceError> {
        let next_head = next.ensure_cas(current)?;
        *aggregate = Some(match aggregate.take() {
            Some(previous) => previous.compose(next)?,
            None => next,
        });
        Ok(next_head)
    }

    #[must_use]
    pub const fn party_id(&self) -> PartyId {
        self.party
    }

    /// Whether a fully restored deposit runtime is immediately available to local callers.
    ///
    /// This is deliberately a synchronous status probe: initialization publishes the flag only
    /// after the authenticated runtime has been completely restored. Reading it never waits for
    /// the runtime mutex, reads authenticated storage, or contacts a chain source.
    #[must_use]
    pub fn local_runtime_ready(&self) -> bool {
        self.runtime_ready.load(Ordering::Acquire)
    }

    pub(crate) async fn verify_registry_handoff_target(
        &self,
        source: Option<&EpochPublic>,
        public: &EpochPublic,
        fault_bound: u16,
        certified_activation_root: [u8; 32],
    ) -> Result<VerifiedRegistryHandoffTarget, DepositServiceError> {
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        Ok(VerifiedRegistryHandoffTarget::from_verified_activation(
            source,
            public.clone(),
            fault_bound,
            certified_activation_root,
            &runtime.deriver,
        )?)
    }

    /// Return the globally active deposit-ledger epoch restored by this party.
    pub async fn active_epoch(&self) -> Result<u64, DepositServiceError> {
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        Ok(runtime.protocol.registry.active_epoch())
    }

    pub async fn active_registry(&self) -> Result<CompactEpochRegistry, DepositServiceError> {
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.registry.validate()?;
        Ok(runtime.protocol.registry.clone())
    }

    /// Stable deployment/wallet binding for every QUIC compact-state sync message.
    pub async fn deposit_sync_context(&self) -> Result<DepositSyncContext, DepositServiceError> {
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        Ok(DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?)
    }

    /// Advertise only the exact settled authorities retained by one authenticated snapshot.
    pub async fn deposit_sync_advertisement(
        &self,
        context: DepositSyncContext,
    ) -> Result<DepositSyncAdvertisement, DepositServiceError> {
        let snapshot = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let expected = DepositSyncContext::new(
                self.scenario.quic_network_id()?,
                runtime.deriver.wallet_id(),
            )?;
            if context != expected {
                return Err(DepositSyncWireError::InvalidContext.into());
            }
            runtime.snapshot.clone()
        };
        self.authenticated_latest_index_checkpoint(&snapshot).await?;
        Ok(DepositSyncAdvertisement::from_checkpoints(
            context,
            snapshot.compact_registry_checkpoint(),
            snapshot.archive_head()?,
            snapshot.deposit_index_checkpoint(),
            snapshot.index_checkpoint_certificate().cloned(),
        )?)
    }

    /// Serve a deterministic page only after authenticating its complete root-connected manifest.
    pub async fn serve_deposit_sync_objects(
        &self,
        authenticated_party: PartyId,
        advertisement: &DepositSyncAdvertisement,
        request: &DepositSyncObjectPageRequest,
    ) -> Result<DepositSyncObjectPage, DepositServiceError> {
        let local = self.deposit_sync_advertisement(advertisement.context()).await?;
        if &local != advertisement {
            return Err(DepositSyncWireError::WrongAdvertisement.into());
        }
        {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            runtime.protocol.registry.active().committee().member(authenticated_party)?;
        }
        request.validate_for(advertisement)?;
        let artifacts = WalletArtifactStore::new(
            self.deposit_index_directory.clone(),
            self.party,
            &self.deposit_index_identity_seed,
        )?;
        let mut plaintext = BTreeMap::new();
        for reference in request.references().iter().copied() {
            let artifact = artifacts.load_artifact(reference.storage_reference()?).await?;
            if plaintext.insert(reference, artifact.contents.into_bytes()).is_some() {
                return Err(DepositSyncWireError::InvalidObjectManifest.into());
            }
        }
        let verified = request.verify_reachable_manifest(advertisement, |reference| {
            Ok(plaintext.get(&reference).cloned())
        })?;
        Ok(DepositSyncObjectPage::build(request, advertisement, &verified)?)
    }

    /// Return the first finite root request only for an authenticated strict successor.
    pub async fn deposit_sync_plan(
        &self,
        advertisement: &DepositSyncAdvertisement,
        active_target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<DepositSyncObjectPageRequest>, DepositServiceError> {
        let context = self.deposit_sync_context().await?;
        if advertisement.context() != context {
            return Err(DepositSyncWireError::InvalidContext.into());
        }
        advertisement.registry_archive().registry().verify_active_target(active_target)?;
        let current = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            PortableDepositIndexHead::from_head(
                runtime.snapshot.deposit_index_checkpoint().portable_head(),
            )?
        };
        if advertisement.portable_index().through_sequence() < current.through_sequence() {
            return Ok(None);
        }
        if advertisement.portable_index().through_sequence() == current.through_sequence() {
            if advertisement.portable_index() != &current {
                return Err(DepositSyncWireError::InvalidAdvertisement.into());
            }
            return Ok(None);
        }
        Ok(Some(DepositSyncObjectPageRequest::new(
            advertisement,
            vec![DepositSyncObjectRef::Registry(
                advertisement.registry_archive().index_root_reference(),
            )],
            u16::try_from(MAX_DEPOSIT_SYNC_PAGE_OBJECTS)
                .map_err(|_| DepositSyncWireError::InvalidObjectRequest)?,
            u32::try_from(MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES)
                .map_err(|_| DepositSyncWireError::InvalidObjectRequest)?,
        )?))
    }

    fn verify_deposit_sync_candidate(
        &self,
        advertisement: &DepositSyncAdvertisement,
        objects: Vec<DepositSyncObject>,
        active_target: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedDepositSyncCandidate, DepositServiceError> {
        let expected_context = DepositSyncContext::new(
            self.scenario.quic_network_id()?,
            advertisement.context().wallet(),
        )?;
        if advertisement.context() != expected_context {
            return Err(DepositSyncWireError::InvalidContext.into());
        }

        // This capability comes only from the host's locally verified durable activation history.
        // It is checked before any downloaded object is written to local storage.
        advertisement.registry_archive().registry().verify_active_target(active_target)?;
        let reader = DepositSyncCandidateReader::new(advertisement.context().wallet(), objects)?;
        advertisement.registry_archive().verify_bounded(&reader)?;

        let through = advertisement.portable_index().through_sequence();
        if through == 0 {
            let canonical_first = DepositSubaddressIndex::new(0, 1)?;
            let canonical_index = crate::deposit_index::DepositIndexHead::empty_portable(
                advertisement.context().wallet(),
                canonical_first,
            )?;
            let canonical_portable = PortableDepositIndexHead::from_head(&canonical_index)?;
            let canonical_registry = prepare_compact_registry_genesis(
                active_target,
                canonical_first,
                canonical_portable.digest(),
            )?;
            let active = advertisement.registry_archive().registry().active();
            if active_target.committee().epoch != 0
                || advertisement.checkpoint_certificate().is_some()
                || !advertisement.certificate_archive().is_empty()
                || advertisement.portable_index() != &canonical_portable
                || canonical_registry.proposed_head() != advertisement.registry_archive()
                || canonical_registry.staged_objects().len() != reader.registry.len()
                || canonical_registry.staged_objects().iter().any(|object| {
                    reader.registry.get(&object.reference()).map(Vec::as_slice)
                        != Some(object.contents())
                })
                || active.start_sequence() != 1
                || active.first_index() != canonical_first
                || active.portable_index_checkpoint() != advertisement.portable_index().digest()
                || !reader.index.is_empty()
                || !reader.archive.is_empty()
                || !reader.all_objects_consumed()
            {
                return Err(DepositSyncWireError::InvalidAdvertisement.into());
            }
            return Ok(VerifiedDepositSyncCandidate {
                reader,
                operation: None,
                operation_artifact: None,
                checkpoint: None,
                scanner_snapshot: None,
                terminal_statement: None,
            });
        }

        let advertised_certificate = advertisement
            .checkpoint_certificate()
            .ok_or(DepositSyncWireError::InvalidCheckpointCertificate)?;
        let archive = advertisement.certificate_archive();
        let event_reference =
            archive.event_reference().ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        let segment_reference =
            archive.segment_reference().ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        let event_bytes = reader.load_archive(event_reference)?;
        event_reference.verify_contents(&event_bytes)?;
        let event = DepositArchiveEvent::from_bytes(&event_bytes)?;
        let expected_ordinal =
            archive.len().checked_sub(1).ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        if event.wallet_id() != advertisement.context().wallet()
            || event.ordinal() != expected_ordinal
        {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact.into());
        }
        let segment_bytes = reader.load_archive(segment_reference)?;
        segment_reference.verify_contents(&segment_bytes)?;
        let segment = DepositArchiveSegment::from_bytes(&segment_bytes)?;
        if segment.wallet_id() != advertisement.context().wallet()
            || segment.end_ordinal()? != archive.len()
            || segment.event_references().last().copied() != Some(event_reference)
        {
            return Err(DepositSyncWireError::InvalidCertifiedArtifact.into());
        }

        let checkpoint_artifact = event.checkpoint_reference();
        let checkpoint_bytes = reader.load_archive(checkpoint_artifact)?;
        checkpoint_artifact.verify_contents(&checkpoint_bytes)?;
        let certificate = DepositIndexCheckpointCertificate::from_bytes(&checkpoint_bytes)?;
        if &certificate != advertised_certificate
            || certificate.statement().sequence() != archive.len()
            || certificate.statement().ledger_sequence() != through
            || certificate.statement().ledger_decision()
                != advertisement.portable_index().ledger_head()
            || certificate.statement().resulting_head() != advertisement.portable_index()
            || certificate.statement().context().wallet_id() != advertisement.context().wallet()
            || certificate.statement().context().network() != advertisement.context().network()
            || match (event.operation(), certificate.statement().operation()) {
                (
                    DepositArchiveOperation::Ledger,
                    DepositIndexCheckpointOperation::Ledger { .. },
                )
                | (
                    DepositArchiveOperation::DepositObservation,
                    DepositIndexCheckpointOperation::DepositObservation { .. },
                ) => false,
                _ => true,
            }
        {
            return Err(DepositSyncWireError::InvalidCheckpointCertificate.into());
        }

        let portable_head = advertisement.portable_index().to_index_head()?;
        let terminal_statement = match lookup_portable_state(
            &reader,
            &portable_head,
            PortableStateQuery::Sequence(through),
        )? {
            Some(PortableStateRecord::Statement(statement))
                if statement.wallet == advertisement.context().wallet()
                    && statement.sequence == through
                    && statement.digest() == advertisement.portable_index().ledger_head() =>
            {
                statement
            }
            _ => return Err(DepositSyncWireError::InvalidObjectManifest.into()),
        };

        let operation_artifact = event.operation_reference();
        let operation_bytes = reader.load_archive(operation_artifact)?;
        operation_artifact.verify_contents(&operation_bytes)?;
        let (operation, checkpoint) = match event.operation() {
            DepositArchiveOperation::Ledger => {
                let ledger = CertifiedLedgerEntry::from_bytes(&operation_bytes)?;
                if ledger.statement != terminal_statement
                    || ledger.statement.wallet != advertisement.context().wallet()
                    || ledger.statement.sequence != through
                    || ledger.statement.digest() != advertisement.portable_index().ledger_head()
                    || certificate.statement().operation()
                        != (DepositIndexCheckpointOperation::Ledger {
                            statement: ledger.statement.digest(),
                        })
                {
                    return Err(DepositSyncWireError::InvalidCertifiedArtifact.into());
                }
                let issuer = lookup_verified_issuer_window(
                    advertisement.registry_archive(),
                    ledger.statement.issuer_epoch,
                    &reader,
                )?;
                let historical = match &ledger.statement.payload {
                    LedgerPayload::LateConsolidationSettlement(settlement) => {
                        Some(lookup_verified_issuer_window(
                            advertisement.registry_archive(),
                            settlement.historical_completion().attempt().epoch(),
                            &reader,
                        )?)
                    }
                    LedgerPayload::Allocation(_)
                    | LedgerPayload::HandoffFence(_)
                    | LedgerPayload::Handoff(_)
                    | LedgerPayload::ConsolidationCompletion(_)
                    | LedgerPayload::ConsolidationAbandonment(_) => None,
                };
                let checkpoint = certificate.verify_anchored(
                    self.scenario.quic_network_id()?,
                    &issuer,
                    historical.as_ref(),
                    &ledger,
                    advertisement.portable_index(),
                )?;
                (VerifiedDepositSyncOperation::Ledger(ledger), checkpoint)
            }
            DepositArchiveOperation::DepositObservation => {
                let observation = CertifiedDepositObservation::from_bytes(&operation_bytes)?;
                if observation.statement.wallet_id() != advertisement.context().wallet()
                    || certificate.statement().operation()
                        != (DepositIndexCheckpointOperation::DepositObservation {
                            statement: observation.statement.digest(),
                        })
                {
                    return Err(DepositSyncWireError::InvalidCertifiedArtifact.into());
                }
                match lookup_portable_state(
                    &reader,
                    &portable_head,
                    PortableStateQuery::Sequence(observation.statement.allocation_sequence()),
                )? {
                    Some(PortableStateRecord::Statement(statement))
                        if statement.digest() == observation.statement.allocation_statement()
                            && matches!(statement.payload, LedgerPayload::Allocation(_)) => {}
                    _ => return Err(DepositSyncWireError::InvalidObjectManifest.into()),
                }
                match lookup_portable_state(
                    &reader,
                    &portable_head,
                    PortableStateQuery::ObservedOutput(observation.statement.output()),
                )? {
                    Some(PortableStateRecord::DepositOutput(output))
                        if output.wallet_id() == advertisement.context().wallet()
                            && output.allocation_sequence()
                                == observation.statement.allocation_sequence()
                            && output.allocation_statement()
                                == observation.statement.allocation_statement()
                            && output.output_key() == observation.statement.output_key()
                            && output.observation_digest() == observation.statement.digest() => {}
                    _ => return Err(DepositSyncWireError::InvalidObjectManifest.into()),
                }
                let issuer = lookup_verified_issuer_window(
                    advertisement.registry_archive(),
                    observation.statement.issuer_epoch(),
                    &reader,
                )?;
                let checkpoint = certificate.verify_archived_deposit_observation_anchored(
                    self.scenario.quic_network_id()?,
                    &issuer,
                    &observation,
                    advertisement.portable_index(),
                )?;
                (VerifiedDepositSyncOperation::DepositObservation(observation), checkpoint)
            }
        };
        if checkpoint.resulting_head() != advertisement.portable_index() {
            return Err(DepositSyncWireError::InvalidObjectManifest.into());
        }
        let scanner_snapshot =
            verify_portable_scanner_snapshot(&reader, &portable_head, &checkpoint)?;
        if !reader.all_objects_consumed() {
            return Err(DepositSyncWireError::InvalidObjectManifest.into());
        }
        Ok(VerifiedDepositSyncCandidate {
            reader,
            operation: Some(operation),
            operation_artifact: Some(operation_artifact),
            checkpoint: Some(checkpoint),
            scanner_snapshot: Some(scanner_snapshot),
            terminal_statement: Some(terminal_statement),
        })
    }

    /// Install one completely downloaded fresh-join candidate as a single wallet-snapshot CAS.
    ///
    /// Verification, semantic whole-tree traversal, and active-target authentication all happen
    /// before any downloaded plaintext is written. The only accepted base is this party's exact
    /// current-format empty index/local-safety state; this is intentionally not a generic rollback
    /// or history replacement API.
    pub async fn adopt_deposit_sync_candidate(
        &self,
        advertisement: DepositSyncAdvertisement,
        objects: Vec<DepositSyncObject>,
        active_target: &VerifiedRegistryHandoffTarget,
    ) -> Result<bool, DepositServiceError> {
        let verified =
            self.verify_deposit_sync_candidate(&advertisement, objects, active_target)?;
        let VerifiedDepositSyncCandidate {
            reader,
            operation,
            operation_artifact,
            checkpoint,
            scanner_snapshot,
            terminal_statement,
        } = verified;

        let mut runtime_guard = self.runtime.lock().await;
        let runtime = runtime_guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        let current = PortableDepositIndexHead::from_head(
            runtime.snapshot.deposit_index_checkpoint().portable_head(),
        )?;
        if advertisement.portable_index() == &current {
            return Ok(false);
        }
        if current.through_sequence() != 0
            || advertisement.portable_index().through_sequence() == 0
            || runtime.protocol.index_checkpoint.is_some()
            || runtime.protocol.observation_checkpoint.is_some()
            || runtime.protocol.consensus_lane.is_some()
            || !runtime.protocol.pending.is_empty()
            || !runtime.protocol.client_requests.is_empty()
            || runtime.protocol.pending_handoff.is_some()
            || runtime.consolidation.records().next().is_some()
        {
            return Err(DepositSyncWireError::InvalidAdvertisement.into());
        }
        advertisement.registry_archive().registry().active().committee().member(self.party)?;

        let expected_index = runtime.snapshot.deposit_index_checkpoint().clone();
        let expected_registry = runtime.snapshot.compact_registry_checkpoint().clone();
        let operation = operation.ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        let operation_artifact =
            operation_artifact.ok_or(DepositSyncWireError::InvalidCertifiedArtifact)?;
        match &operation {
            VerifiedDepositSyncOperation::Ledger(ledger) => {
                if operation_artifact.kind() != CERTIFIED_LEDGER_ENTRY_ARTIFACT {
                    return Err(DepositSyncWireError::InvalidCertifiedArtifact.into());
                }
                operation_artifact.verify_contents(&ledger.to_bytes()?)?;
            }
            VerifiedDepositSyncOperation::DepositObservation(observation) => {
                if operation_artifact.kind() != CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT {
                    return Err(DepositSyncWireError::InvalidCertifiedArtifact.into());
                }
                operation_artifact.verify_contents(&observation.to_bytes()?)?;
            }
        }
        let checkpoint = checkpoint.ok_or(DepositSyncWireError::InvalidCheckpointCertificate)?;
        let scanner_snapshot =
            scanner_snapshot.ok_or(DepositSyncWireError::InvalidCheckpointCertificate)?;
        let import = VerifiedPortableIndexImport::from_certified_checkpoint(&checkpoint)?;
        let imported_index = expected_index.import_verified_portable(&import)?;
        if PortableDepositIndexHead::from_head(imported_index.portable_head())?
            != *advertisement.portable_index()
        {
            return Err(DepositSyncWireError::InvalidObjectManifest.into());
        }
        let imported_registry = CompactRegistryStoreCheckpoint::settled(
            advertisement.context().wallet(),
            advertisement.registry_archive().clone(),
        )?;
        if imported_registry.digest() != advertisement.registry_checkpoint_digest() {
            return Err(DepositSyncWireError::InvalidAdvertisement.into());
        }

        // Materialize only exact content-addressed objects consumed by the verified root
        // traversals. Unreachable peer-supplied objects were rejected by the verifier above.
        let artifacts = WalletArtifactStore::new(
            self.deposit_index_directory.clone(),
            self.party,
            &self.deposit_index_identity_seed,
        )?;
        for (reference, bytes) in reader.objects() {
            let storage = reference.storage_reference()?;
            let installed = artifacts
                .create_artifact(storage.wallet_id(), storage.kind(), bytes, &mut rand_core::OsRng)
                .await?;
            if installed != storage {
                return Err(DepositSyncWireError::ObjectAuthentication.into());
            }
        }

        // Open both prospective stores before their heads become authoritative. Opening performs
        // exact artifact readback and bounded semantic head verification.
        let mut imported_index_store = DepositIndexStore::open_with_stores(
            Arc::clone(&self.protocol_store),
            WalletArtifactStore::new(
                self.deposit_index_directory.clone(),
                self.party,
                &self.deposit_index_identity_seed,
            )?,
            imported_index.clone(),
        )
        .await?;
        if PortableDepositIndexHead::from_head(imported_index_store.portable_head())?
            != *advertisement.portable_index()
        {
            return Err(DepositSyncWireError::InvalidObjectManifest.into());
        }
        let imported_registry_store = CompactRegistryStore::open_with_stores(
            Arc::clone(&self.protocol_store),
            WalletArtifactStore::new(
                self.deposit_index_directory.clone(),
                self.party,
                &self.deposit_index_identity_seed,
            )?,
            imported_registry.clone(),
        )
        .await?;
        if imported_registry_store.head() != Some(advertisement.registry_archive()) {
            return Err(DepositSyncWireError::InvalidObjectManifest.into());
        }

        let registry = advertisement.registry_archive().registry().clone();
        let mut retained_observations = BTreeMap::new();
        for (output_id, mut slot) in runtime.protocol.pending_observations.clone() {
            let imported_output = imported_index_store
                .lookup_portable_state(PortableStateQuery::ObservedOutput(output_id))
                .await?;
            match imported_output {
                Some(PortableStateRecord::DepositOutput(output))
                    if output.wallet_id() == slot.statement.wallet_id()
                        && output.allocation_sequence() == slot.statement.allocation_sequence()
                        && output.allocation_statement()
                            == slot.statement.allocation_statement()
                        && output.index() == slot.statement.index()
                        && output.output() == slot.statement.output()
                        && output.output_key() == slot.statement.output_key()
                        && output.index_on_blockchain() == slot.statement.index_on_blockchain()
                        && output.amount_atomic_units() == slot.statement.amount_atomic_units()
                        && output.observed_block() == slot.statement.observed_block()
                        && output.block_timestamp() == slot.statement.block_timestamp() =>
                {
                    // The imported mixed tip already made this exact semantic fact portable.
                    // Its canonical observation digest may belong to an earlier issuer retry.
                    continue;
                }
                Some(_) => {
                    return Err(DepositServiceError::ObservationEquivocation);
                }
                None => {}
            }

            let imported_allocation = imported_index_store
                .lookup_portable_state(PortableStateQuery::Sequence(
                    slot.statement.allocation_sequence(),
                ))
                .await?;
            match imported_allocation {
                Some(PortableStateRecord::Statement(statement))
                    if statement.digest() == slot.statement.allocation_statement()
                        && matches!(statement.payload, LedgerPayload::Allocation(_)) => {}
                _ => {
                    return Err(DepositServiceError::InvalidDepositObservation);
                }
            }
            if slot.statement.validate_active(&registry).is_err() {
                slot.statement = slot.statement.reissue_for_active(&registry)?;
                slot.attestations.clear();
            } else {
                for (party, witness) in &slot.attestations {
                    if verify_deposit_observation_attestation(&slot.statement, &registry, witness)?
                        != *party
                    {
                        return Err(DepositServiceError::InvalidDepositObservation);
                    }
                }
            }
            retained_observations.insert(output_id, slot);
        }
        let cursor = CompactLedgerCursor::from_authenticated_portable_head(
            &registry,
            advertisement.portable_index(),
            terminal_statement.as_ref(),
        )?;
        let mut protocol = DepositProtocolState::genesis(self.party, registry, cursor)?;
        protocol.checkpoint_sequence = advertisement.certificate_archive().len();
        protocol.pending_observations = retained_observations;
        protocol.validate(&runtime.deriver)?;
        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let worker_effect = worker
            .adopt_verified_portable_scanner_snapshot(&scanner_snapshot)?
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_worker_revision = worker_effect.revision();
        let consolidation = ConsolidationCoordinator::new(advertisement.context().wallet())?;

        let mut sync_base = runtime.snapshot.clone();
        for slot in runtime.protocol.pending_observations.values() {
            sync_base.prune_deposit_observation_outbox_in_place(&slot.statement)?;
        }
        if !sync_base.outbox.is_empty() || !sync_base.outbox_bodies.is_empty() {
            return Err(DepositSyncWireError::InvalidAdvertisement.into());
        }
        let mut candidate = sync_base;
        candidate.install_verified_sync_state(
            &expected_index,
            imported_index,
            &expected_registry,
            imported_registry,
            advertisement.certificate_archive(),
            &protocol,
            &runtime.deriver,
            worker,
            &consolidation,
            Some(operation_artifact),
            Some(
                advertisement
                    .checkpoint_certificate()
                    .ok_or(DepositSyncWireError::InvalidCheckpointCertificate)?
                    .clone(),
            ),
        )?;
        let pending_outputs = protocol.pending_observations.keys().copied().collect::<Vec<_>>();
        let mut observation_messages = Vec::new();
        for output in pending_outputs {
            if let Some(observation) = protocol.completed_deposit_observation(output)? {
                observation_messages
                    .extend(self.deposit_observation_certificate_messages(&protocol, observation)?);
                continue;
            }
            let slot = protocol
                .pending_observations
                .get(&output)
                .ok_or(DepositServiceError::UnknownDepositObservation)?;
            if let Some(attestation) = slot.attestations.get(&self.party) {
                observation_messages.extend(
                    self.deposit_observation_statement_and_attestation_messages(
                        &protocol,
                        slot.statement.clone(),
                        attestation.clone(),
                    )?,
                );
            } else {
                observation_messages.extend(
                    self.deposit_observation_statement_messages(&protocol, slot.statement.clone())?,
                );
            }
        }
        candidate.revision = runtime.snapshot.revision;
        candidate.enqueue_many(observation_messages)?;
        candidate.revision = runtime.snapshot.next_revision()?;
        candidate.validate()?;

        let mut index_guard = self.deposit_index.lock().await;
        let mut registry_guard = self.compact_registry.lock().await;
        if index_guard.as_ref().map(DepositIndexStore::checkpoint) != Some(&expected_index)
            || registry_guard.as_ref().map(CompactRegistryStore::checkpoint)
                != Some(&expected_registry)
        {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        let durable = match self.repository.persist_and_read_back(&candidate).await {
            Ok(durable) => durable,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated) if authenticated == candidate => authenticated,
                Ok(authenticated) if authenticated == runtime.snapshot => return Err(save_error),
                Ok(_) => {
                    *index_guard = None;
                    *registry_guard = None;
                    return Err(DepositServiceError::StorageRevisionMismatch);
                }
                Err(load_error) => {
                    *index_guard = None;
                    *registry_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        *index_guard = Some(imported_index_store);
        *registry_guard = Some(imported_registry_store);
        if durable.worker().is_none_or(|worker| worker.revision() != expected_worker_revision) {
            *index_guard = None;
            *registry_guard = None;
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        runtime.snapshot = durable;
        runtime.protocol = protocol;
        runtime.consolidation = consolidation;
        Ok(true)
    }

    /// Issuance remains closed while scanner or compact-state recovery is incomplete.
    pub async fn deposit_sync_ready(&self) -> Result<bool, DepositServiceError> {
        let sync = self.scanner_sync_status().await?;
        let snapshot = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if !sync_status_matches_runtime(sync, runtime)?
                || runtime.snapshot.deposit_index_checkpoint().has_recovery_journal()
                || runtime.snapshot.compact_registry_checkpoint().has_recovery_journal()
                || !worker.allocation_view_ready()
                || worker.portable_index_head()
                    != Some(runtime.snapshot.deposit_index_checkpoint().portable_head().digest())
            {
                return Ok(false);
            }
            runtime.snapshot.clone()
        };
        self.authenticated_latest_index_checkpoint(&snapshot).await?;
        Ok(true)
    }

    /// Return restart-stable evidence only after `output` is present under the exact settled
    /// portable head authenticated by the latest `n-f` checkpoint certificate.
    ///
    /// This accessor exists for the private-Regtest crash campaign. It is deliberately read-only:
    /// it cannot make a local scan portable, create an attestation, or advance either reducer.
    pub async fn durable_deposit_observation_evidence(
        &self,
        output: WalletOutputId,
    ) -> Result<Option<DurableDepositObservationEvidence>, DepositServiceError> {
        if output.transaction == [0; 32] {
            return Ok(None);
        }
        let snapshot = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            if runtime.snapshot.deposit_index_checkpoint().has_recovery_journal() {
                return Ok(None);
            }
            runtime.snapshot.clone()
        };
        let Some(_) = self.authenticated_latest_index_checkpoint(&snapshot).await? else {
            return Ok(None);
        };
        let certificate = snapshot
            .index_checkpoint_certificate()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let checkpoint = snapshot.deposit_index_checkpoint().clone();
        let record = {
            let mut guard = self.deposit_index.lock().await;
            let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            if store.checkpoint() != &checkpoint {
                return Ok(None);
            }
            match store.lookup_portable_state(PortableStateQuery::ObservedOutput(output)).await? {
                Some(PortableStateRecord::DepositOutput(record)) if record.output() == output => {
                    record
                }
                None => return Ok(None),
                Some(_) => return Err(DepositServiceError::InvalidDepositIndexCheckpoint),
            }
        };
        let unchanged = {
            let guard = self.runtime.lock().await;
            guard.as_ref().is_some_and(|runtime| {
                runtime.snapshot.revision == snapshot.revision
                    && runtime.snapshot.deposit_index_checkpoint() == &checkpoint
                    && runtime.snapshot.index_checkpoint_certificate() == Some(certificate)
            })
        };
        if !unchanged {
            return Ok(None);
        }
        Ok(Some(DurableDepositObservationEvidence {
            output: record,
            portable_index_digest: checkpoint.portable_head().digest(),
            checkpoint_statement_digest: certificate.statement().decision_digest(),
            checkpoint_sequence: certificate.statement().sequence(),
        }))
    }

    /// Compare the durable scanner with the configured daemon's current confirmed horizon without
    /// holding the service runtime mutex across either RPC.
    pub async fn scanner_sync_status(
        &self,
    ) -> Result<DepositScannerSyncStatus, DepositServiceError> {
        let (snapshot_revision, worker_revision, scanner_tip, config, initially_blocked) = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            (
                runtime.snapshot.revision,
                worker.revision(),
                worker.scan_state().tip(),
                worker.config(),
                worker.replay_pending_events()?.is_some(),
            )
        };

        if initially_blocked {
            return Ok(DepositScannerSyncStatus::Syncing { scanner_tip, confirmed_horizon: None });
        }
        let timeout_duration = Duration::from_millis(config.request_timeout_millis);
        let daemon_height =
            match tokio::time::timeout(timeout_duration, self.source.latest_height()).await {
                Ok(Ok(height)) => height,
                Ok(Err(_)) | Err(_) => {
                    return Ok(DepositScannerSyncStatus::Unavailable { scanner_tip });
                }
            };
        if daemon_height < scanner_tip.height {
            return Ok(DepositScannerSyncStatus::Unavailable { scanner_tip });
        }
        let confirmed_horizon = daemon_height
            .checked_add(1)
            .and_then(|length| length.checked_sub(u64::from(config.confirmation_depth)));
        let Some(confirmed_horizon) = confirmed_horizon else {
            return Ok(DepositScannerSyncStatus::Syncing { scanner_tip, confirmed_horizon: None });
        };
        let scanner_hash = match tokio::time::timeout(
            timeout_duration,
            self.source.block_hash(scanner_tip.height),
        )
        .await
        {
            Ok(Ok(hash)) => hash,
            Ok(Err(_)) | Err(_) => {
                return Ok(DepositScannerSyncStatus::Unavailable { scanner_tip });
            }
        };

        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let unchanged = runtime.snapshot.revision == snapshot_revision
            && worker.revision() == worker_revision
            && worker.scan_state().tip() == scanner_tip
            && worker.config() == config;
        let blocked = worker.replay_pending_events()?.is_some();
        if !unchanged
            || blocked
            || scanner_hash != scanner_tip.hash
            || scanner_tip.height < confirmed_horizon
        {
            return Ok(DepositScannerSyncStatus::Syncing {
                scanner_tip: worker.scan_state().tip(),
                confirmed_horizon: Some(confirmed_horizon),
            });
        }
        Ok(DepositScannerSyncStatus::Ready { scanner_tip, confirmed_horizon })
    }

    /// Enumerate every durable session tombstone purpose. The values are public commitments and
    /// carry no nonce authority. A host calls this under its consolidation transition gate on
    /// startup (and after reorg) to idempotently ensure ProtocolStore closure before accepting any
    /// signing message; it must also discard matching volatile FROSTLASS machines.
    pub async fn consolidation_session_closures(
        &self,
    ) -> Result<Vec<ConsolidationSessionClosure>, DepositServiceError> {
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        let mut closures = Vec::new();
        for (_, record) in runtime.consolidation.records() {
            for tombstone in record.attempts.values() {
                let closure =
                    nonce_tombstone_for_attempt(&record.authorization, &tombstone.binding)?;
                closures.push(ConsolidationSessionClosure {
                    session: closure.session(),
                    purpose: closure.purpose().to_vec(),
                });
            }
        }
        closures.sort_unstable_by_key(|closure| closure.session);
        if closures.windows(2).any(|pair| pair[0].session == pair[1].session) {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        Ok(closures)
    }

    pub async fn public_consolidation_status(
        &self,
        sweep: SweepId,
    ) -> Result<Option<PublicConsolidationStatus>, DepositServiceError> {
        let portable = self.authenticated_portable_terminal_by_sweep(sweep).await?;
        let (certificate_digest, completion_certificate_signers) = if let Some(portable) =
            portable.as_ref().filter(|portable| portable.completion().is_some())
        {
            let entry = self.authenticated_certified_entry(&portable.current_statement).await?;
            (
                Some(portable.current_statement.digest()),
                entry.attestations.iter().map(|attestation| attestation.from).collect(),
            )
        } else {
            (None, Vec::new())
        };
        let guard = self.runtime.lock().await;
        let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
        let Some(record) = runtime.consolidation.record_by_sweep(sweep) else {
            return Ok(None);
        };
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let local = worker
            .scan_state()
            .sweep(sweep)
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        let plan = PreparedSweepIntent::decode(local.signing_intent.prepared_sweep_intent_bytes())?
            .plan()
            .clone();
        let phase = match record.phase {
            ConsolidationPhase::IntentReserved => PublicConsolidationPhase::Reserved,
            ConsolidationPhase::SigningReleased { .. }
            | ConsolidationPhase::AwaitingFreshAttempt { .. }
            | ConsolidationPhase::AttemptsExhausted { .. } => PublicConsolidationPhase::Signing,
            ConsolidationPhase::Signed => {
                if certificate_digest.is_some() {
                    PublicConsolidationPhase::Certified
                } else {
                    PublicConsolidationPhase::Signing
                }
            }
            ConsolidationPhase::Broadcast => PublicConsolidationPhase::Broadcast,
            ConsolidationPhase::Confirmed => PublicConsolidationPhase::Confirmed,
            ConsolidationPhase::QuarantinedByInputReorg { .. } => {
                PublicConsolidationPhase::Quarantined
            }
            ConsolidationPhase::AbortedBeforeNonce => PublicConsolidationPhase::Aborted,
            ConsolidationPhase::AbandonedByInputReorg { .. } => PublicConsolidationPhase::Abandoned,
        };
        let roast = runtime
            .snapshot
            .consolidation_roasts
            .get(&record.authorization.id())
            .ok_or(DepositServiceError::ByzantineConsolidationUnavailable)
            .and_then(|bytes| {
                ConsolidationRoast::decode_authenticated_snapshot(bytes)
                    .map_err(DepositServiceError::from)
            })?;
        if roast.local_party() != self.party
            || roast.quic_network_id() != self.scenario.quic_network_id()?
            || roast.authorization_id() != record.authorization.id()
        {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        let roast_evidence = roast.public_evidence()?;
        if record.signed.is_some_and(|signed| {
            signed.attempt_binding_digest() != roast_evidence.attempt_binding_digest
        }) {
            return Err(DepositServiceError::InvalidByzantineConsolidationState);
        }
        Ok(Some(PublicConsolidationStatus {
            authorization: record.authorization.id(),
            sweep,
            destination_binding: plan.destination_binding,
            plan,
            signed: record.signed,
            certificate_digest,
            phase,
            confirmation: record.confirmation,
            bootstrap_ba_view: roast_evidence.bootstrap_ba_view,
            bootstrap_ba_proposer: roast_evidence.bootstrap_ba_proposer,
            bootstrap_prepared_intent_digest: roast_evidence.bootstrap_prepared_intent_digest,
            bootstrap_certificate_digest: roast_evidence.bootstrap_certificate_digest,
            bootstrap_certificate_signers: roast_evidence.bootstrap_certificate_signers,
            roast_view: roast_evidence.view,
            roast_relay_seed: roast_evidence.relay_seed,
            roast_signers: roast_evidence.signers,
            roast_view_count: roast_evidence.view_count,
            roast_candidate_count: roast_evidence.candidate_count,
            roast_endorsed_candidate_count: roast_evidence.endorsed_candidate_count,
            roast_intent_certificate_digest: roast_evidence.intent_certificate_digest,
            roast_intent_certificate_signers: roast_evidence.intent_certificate_signers,
            roast_attempt_binding_digest: roast_evidence.attempt_binding_digest,
            roast_endorsed_witness_count: roast_evidence.endorsed_witness_count,
            roast_endorsed_evidence_digest: roast_evidence.endorsed_evidence_digest,
            completion_certificate_signers,
            key_image_binding_digest: roast_evidence.key_image_binding_digest,
            key_image_unsigned_transaction_digest: roast_evidence
                .key_image_unsigned_transaction_digest,
            key_image_preprocess_set_digest: roast_evidence.key_image_preprocess_set_digest,
            key_image_authorizers: roast_evidence.key_image_authorizers,
            key_image_authorization_quorum: roast_evidence.key_image_authorization_quorum,
        }))
    }

    /// Resolve the consolidation claiming one exact deposited output, allowing a deposit client
    /// to poll without knowing the internal SweepId.
    pub async fn public_consolidation_status_for_output(
        &self,
        output: WalletOutputId,
    ) -> Result<Option<PublicConsolidationStatus>, DepositServiceError> {
        let local = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            worker
                .scan_state()
                .sweeps()
                .find(|sweep| sweep.inputs.binary_search(&output).is_ok())
                .map(|sweep| sweep.id)
        };
        let portable = self.portable_claiming_sweep(output).await?;
        if local.is_some() && portable.is_some() && local != portable {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        };
        let sweep = portable.or(local);
        match sweep {
            Some(sweep) => self.public_consolidation_status(sweep).await,
            None => Ok(None),
        }
    }

    /// Resolve bounded consolidation history for one certified deposit request. External tenant
    /// identifiers remain a server concern; this method accepts only the internal certified ID.
    pub async fn public_consolidation_statuses_for_request(
        &self,
        request: LedgerRequestId,
    ) -> Result<Vec<PublicConsolidationStatus>, DepositServiceError> {
        let subaddress = {
            let mut guard = self.deposit_index.lock().await;
            let store = guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
            let Some(record) =
                store.lookup_portable(&PortableAllocationQuery::Request(request)).await?
            else {
                return Ok(Vec::new());
            };
            record.allocation().address.index()
        };
        let sweeps = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            let mut sweeps = worker
                .scan_state()
                .sweeps()
                .filter(|sweep| {
                    sweep.inputs.iter().any(|input| {
                        worker
                            .scan_state()
                            .output(*input)
                            .is_some_and(|output| output.subaddress() == subaddress)
                    })
                })
                .map(|sweep| sweep.id)
                .collect::<Vec<_>>();
            sweeps.sort_unstable();
            sweeps.dedup();
            if sweeps.len() > MAX_PUBLIC_CONSOLIDATIONS_PER_REQUEST {
                return Err(DepositServiceError::TooManyConsolidationsForRequest);
            }
            sweeps
        };
        let mut statuses = Vec::with_capacity(sweeps.len());
        for sweep in sweeps {
            if let Some(status) = self.public_consolidation_status(sweep).await? {
                statuses.push(status);
            }
        }
        Ok(statuses)
    }

    /// Return byte-exact portable sweeps which this party may publish or safely rebroadcast.
    /// Quarantined sweeps remain excluded until a future canonical-input revalidation transition.
    pub async fn certified_sweeps_awaiting_publish(
        &self,
    ) -> Result<Vec<SweepId>, DepositServiceError> {
        let candidates = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            runtime
                .consolidation
                .records()
                .filter_map(|(_, record)| {
                    matches!(
                        record.phase,
                        ConsolidationPhase::Signed
                            | ConsolidationPhase::Broadcast
                            | ConsolidationPhase::Confirmed
                    )
                    .then_some(record.authorization.sweep_id())
                })
                .collect::<Vec<_>>()
        };
        let mut sweeps = Vec::new();
        for sweep in candidates {
            if self
                .authenticated_portable_terminal_by_sweep(sweep)
                .await?
                .is_some_and(|portable| portable.completion().is_some())
            {
                sweeps.push(sweep);
            }
        }
        sweeps.sort_unstable();
        sweeps.dedup();
        Ok(sweeps)
    }

    /// Recover the crash boundary after exact signed bytes became durable but before the leader
    /// reserved their portable completion statement.
    pub async fn signed_sweeps_awaiting_completion(
        &self,
    ) -> Result<Vec<SweepId>, DepositServiceError> {
        let candidates = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            runtime
                .consolidation
                .records()
                .filter_map(|(_, record)| {
                    (matches!(
                        record.phase,
                        ConsolidationPhase::Signed | ConsolidationPhase::Confirmed
                    ) && worker.scan_state().sweep(record.authorization.sweep_id()).is_some())
                    .then_some(record.authorization.sweep_id())
                })
                .collect::<Vec<_>>()
        };
        let mut sweeps = Vec::new();
        for sweep in candidates {
            if self.authenticated_portable_terminal_by_sweep(sweep).await?.is_none() {
                sweeps.push(sweep);
            }
        }
        sweeps.sort_unstable();
        sweeps.dedup();
        Ok(sweeps)
    }

    /// Persist the irreversible local share fence before making its signed witness or observation
    /// visible to the network.
    async fn prepare_local_abandonment_wire(
        &self,
        runtime: &mut DepositRuntime,
        observation: ConsolidationAbandonmentObservation,
        identity: &Identity,
    ) -> Result<ConsolidationAbandonmentObservationWire, DepositServiceError> {
        let view = observation.slot.roast_view();
        let share_unexposed = if observation.attempt.signers().binary_search(&self.party).is_ok() {
            let (_, mut roast) = runtime.snapshot.roast_by_family(observation.family)?;
            let pending = roast.prepare_local_share_unexposed(
                view,
                &observation.abandonment_context,
                identity,
            )?;
            let mut fenced_snapshot = runtime.snapshot.clone();
            fenced_snapshot.replace_roast_and_enqueue(&roast, Vec::new())?;
            let durable = self.repository.persist_and_read_back(&fenced_snapshot).await?;
            let (_, durable_roast) = durable.roast_by_family(observation.family)?;
            let persisted_safety = durable_roast
                .local_safety_bytes(view)?
                .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
            let (intent_context, intent, intent_certificate) = durable_roast
                .certified_intent(view)
                .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
            let fenced = pending.release_after_persisted_state(
                &persisted_safety,
                intent_context,
                intent,
                intent_certificate,
            )?;
            runtime.snapshot = durable;
            fenced.into_parts().0
        } else {
            sign_unselected_share_unexposed_attestation(
                &observation.abandonment_context,
                &observation.intent_certificate,
                identity,
            )?
        };
        let active = runtime.protocol.registry.active();
        if active.epoch() != observation.attempt.epoch() {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        ConsolidationAbandonmentObservationWire::new(
            observation,
            share_unexposed,
            identity,
            active.committee(),
        )
    }

    /// Sign every locally final, objectively reproducible unsigned input-reorg observation and
    /// persist its broadcast before returning. Repeated calls are exact no-ops after the local
    /// witness is durable.
    pub async fn progress_consolidation_abandonment_observations(
        &self,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        if identity.party() != self.party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        let network = self.scenario.quic_network_id()?;
        let observations = locally_observable_abandonments(
            &runtime.protocol,
            &runtime.snapshot,
            &runtime.consolidation,
            network,
        )?;
        for observation in observations {
            let digest = observation.digest()?;
            if runtime
                .snapshot
                .consolidation_abandonments
                .get(&digest)
                .is_some_and(|pool| pool.attestations.contains_key(&self.party))
            {
                continue;
            }
            let wire =
                self.prepare_local_abandonment_wire(runtime, observation.clone(), identity).await?;
            let active = runtime.protocol.registry.active();
            if active.epoch() != observation.attempt.epoch() {
                return Err(DepositServiceError::InvalidConsolidationAbandonment);
            }
            wire.validate(&runtime.protocol, self.party, network)?;
            let body = postcard::to_allocvec(&wire)?;
            if body.len() > MAX_CONSOLIDATION_ABANDONMENT_MESSAGE_BYTES {
                return Err(DepositServiceError::InvalidMessageSize);
            }
            let messages = committee_recipients(active.committee(), self.party)
                .into_iter()
                .map(|party| {
                    (
                        observation.attempt.attempt(),
                        party,
                        DepositOperation::ConsolidationAbandonment,
                        body.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let mut snapshot = runtime.snapshot.clone();
            snapshot.merge_abandonment_observation_and_enqueue(
                observation,
                [wire.share_unexposed.clone()],
                [wire.attestation.clone()],
                messages,
            )?;
            runtime.snapshot = self.repository.persist_and_read_back(&snapshot).await?;
        }
        Ok(())
    }

    /// Admit one authenticated historical-committee observation. Success means the peer witness,
    /// any locally-created countersignature, and every resulting QUIC effect survived encrypted
    /// readback, so the transport may safely ACK an exact retry.
    pub async fn accept_consolidation_abandonment_observation(
        &self,
        identity: &Identity,
        authenticated_sender: PartyId,
        body: &[u8],
    ) -> Result<(), DepositServiceError> {
        if identity.party() != self.party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let wire = ConsolidationAbandonmentObservationWire::decode(body)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        let network = self.scenario.quic_network_id()?;
        wire.validate(&runtime.protocol, authenticated_sender, network)?;
        validate_abandonment_observation_locally(
            &runtime.protocol,
            &runtime.snapshot,
            &runtime.consolidation,
            &wire.observation,
            network,
        )?;
        let digest = wire.observation.digest()?;
        let mut share_unexposed = vec![wire.share_unexposed.clone()];
        let mut attestations = vec![wire.attestation.clone()];
        let mut messages = Vec::new();
        if !runtime
            .snapshot
            .consolidation_abandonments
            .get(&digest)
            .is_some_and(|pool| pool.attestations.contains_key(&self.party))
        {
            let local = self
                .prepare_local_abandonment_wire(runtime, wire.observation.clone(), identity)
                .await?;
            let active = runtime.protocol.registry.active();
            if active.epoch() != wire.observation.attempt.epoch() {
                return Err(DepositServiceError::InvalidConsolidationAbandonment);
            }
            let local_body = postcard::to_allocvec(&local)?;
            share_unexposed.push(local.share_unexposed.clone());
            attestations.push(local.attestation.clone());
            messages.extend(committee_recipients(active.committee(), self.party).into_iter().map(
                |party| {
                    (
                        wire.observation.attempt.attempt(),
                        party,
                        DepositOperation::ConsolidationAbandonment,
                        local_body.clone(),
                    )
                },
            ));
        }
        let mut snapshot = runtime.snapshot.clone();
        snapshot.merge_abandonment_observation_and_enqueue(
            wire.observation,
            share_unexposed,
            attestations,
            messages,
        )?;
        if snapshot == runtime.snapshot {
            return Ok(());
        }
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.snapshot = durable;
        Ok(())
    }

    /// Propose the exact portable completion through the sequence-scoped Byzantine ledger lane.
    /// Every member may start this reducer; proposer rotation, not a fixed wallet leader, drives
    /// liveness after an endorsed ROAST candidate exists.
    pub async fn propose_consolidation_completion(
        &self,
        sweep: SweepId,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        if identity.party() != self.party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let local = worker
            .scan_state()
            .sweep(sweep)
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        let signed_transaction = local
            .signed_transaction
            .clone()
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        let plan = PreparedSweepIntent::decode(local.signing_intent.prepared_sweep_intent_bytes())?
            .plan()
            .clone();
        let record = runtime
            .consolidation
            .record_by_sweep(sweep)
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        if !matches!(
            record.phase,
            ConsolidationPhase::Signed
                | ConsolidationPhase::Confirmed
                | ConsolidationPhase::QuarantinedByInputReorg { .. }
        ) {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        let signed = record.signed.ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        let attempt = record
            .attempts
            .get(&signed.attempt())
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?
            .binding
            .clone();
        let statement = LedgerStatement::consolidation_completion(
            &runtime.protocol.registry,
            runtime.protocol.ledger.next_sequence(),
            runtime.protocol.ledger.head(),
            plan,
            record.authorization.clone(),
            attempt,
            signed,
            signed_transaction,
        )?;
        let completion = match &statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => completion,
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => unreachable!(),
        };
        if !local_completion_matches(worker, &runtime.consolidation, completion)? {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }

        let roast_bytes = runtime
            .snapshot
            .consolidation_roasts
            .get(&completion.id())
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let roast = ConsolidationRoast::decode_authenticated_snapshot(roast_bytes)?;
        let (view, key_images, endorsements) = roast
            .endorsed_candidate_completion_evidence()?
            .into_iter()
            .find(|(_, _, endorsements)| {
                endorsements.first().is_some_and(|endorsement| {
                    endorsement.signed().binding() == completion.signed_binding()
                        && endorsement.signed().transaction() == completion.signed_transaction()
                })
            })
            .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
        let evidence =
            ConsolidationCompletionEvidence::new(&roast, view, key_images, endorsements)?;
        evidence.verify(&runtime.protocol, completion, Some(self.scenario.quic_network_id()?))?;
        let purpose = completion_consensus_purpose(&statement, &evidence)?;
        if let Some(lane) = &runtime.protocol.consensus_lane {
            // A sequence-scoped lane may already be deciding an allocation, handoff, another
            // family, or this exact candidate. All are valid competing values; do not create a
            // second reducer. The server retries this proposal first on the next free height.
            if lane.purpose.sequence() != purpose.sequence() {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            return Ok(());
        }
        if !runtime.protocol.pending.is_empty() {
            return Ok(());
        }
        let value = DepositConsensusValue::completion(statement, evidence)?;
        let now_unix_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| DepositServiceError::InvalidTime)?
                .as_millis(),
        )
        .map_err(|_| DepositServiceError::InvalidTime)?;
        let now = validate_consensus_now(now_unix_ms)?;
        let mut candidate = runtime.protocol.clone();
        let admission = validate_deposit_consensus_value(
            &candidate,
            &runtime.deriver,
            None,
            &value,
            now,
            false,
            purpose,
            Some(self.scenario.quic_network_id()?),
        )?;
        let context = deposit_consensus_context(
            &candidate,
            runtime.deriver.wallet_id(),
            self.scenario.quic_network_id()?,
        )?;
        let mut reducer = DepositConsensus::new(context, self.party)?;
        let step = reducer.start(identity, value)?;
        let mut lane = DurableDepositConsensusLane::new(
            purpose,
            reducer,
            now,
            self.consensus_deadline(now_unix_ms)?,
        )?;
        install_consensus_admission(&mut lane, admission)?;
        candidate.consensus_lane = Some(lane);
        let effects = self.consensus_step_effects(
            &mut candidate,
            &runtime.deriver,
            identity,
            now_unix_ms,
            step,
        )?;
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await
    }

    /// Publish or republish a byte-exact sweep only after the sole portable n-f completion
    /// certificate agrees with the worker tombstone and any local coordinator record.
    ///
    /// No runtime mutex is held across the daemon RPC. A crash after successful submission but
    /// before the final CAS simply causes safe byte-identical republication.
    pub async fn publish_certified_consolidation(
        &self,
        sweep: SweepId,
    ) -> Result<(), DepositServiceError> {
        let backend = self
            .consolidation_backend
            .as_ref()
            .cloned()
            .ok_or(DepositServiceError::ConsolidationBackendUnavailable)?;
        let (certificate_digest, signed, local_id) = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            let portable = portable_signed_sweep(self, runtime, sweep).await?;
            let local = runtime
                .snapshot
                .worker()
                .and_then(|worker| worker.scan_state().sweep(sweep))
                .ok_or(DepositServiceError::ConsolidationInputsRequireRevalidation)?;
            if matches!(local.status, SweepStatus::QuarantinedByReorg { .. }) {
                return Err(DepositServiceError::ConsolidationInputsRequireRevalidation);
            }
            if !matches!(
                local.status,
                SweepStatus::Signed { .. }
                    | SweepStatus::Broadcast { .. }
                    | SweepStatus::Confirmed { .. }
            ) {
                return Err(DepositServiceError::ConsolidationCompletionMismatch);
            }
            portable
        };
        let transaction = signed.transaction()?;
        backend.publish_sweep(&transaction).await?;

        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        let (current_digest, current_signed, current_local_id) =
            portable_signed_sweep(self, runtime, sweep).await?;
        if current_digest != certificate_digest
            || current_signed != signed
            || current_local_id != local_id
        {
            return Err(DepositServiceError::StaleConsolidationCandidate);
        }
        let Some(local) =
            runtime.snapshot.worker().and_then(|worker| worker.scan_state().sweep(sweep))
        else {
            return Err(DepositServiceError::ConsolidationInputsRequireRevalidation);
        };
        if matches!(local.status, SweepStatus::Broadcast { .. } | SweepStatus::Confirmed { .. }) {
            return Ok(());
        }
        if !matches!(local.status, SweepStatus::Signed { .. }) {
            return if matches!(local.status, SweepStatus::QuarantinedByReorg { .. }) {
                Err(DepositServiceError::ConsolidationInputsRequireRevalidation)
            } else {
                Err(DepositServiceError::ConsolidationCompletionMismatch)
            };
        }
        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let worker_effect = worker.mark_sweep_broadcast(sweep, signed.transaction_id())?;
        let mut consolidation = runtime.snapshot.consolidation()?;
        let id = local_id.ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        let consolidation_effect = consolidation
            .mark_broadcast(id, signed.transaction_id())?
            .ok_or(DepositServiceError::StaleConsolidationCandidate)?;
        let mut candidate = runtime.snapshot.clone();
        candidate.replace_all_and_enqueue(
            runtime.protocol.encode_local(&runtime.deriver)?,
            worker,
            &consolidation,
            Vec::new(),
        )?;
        validate_consolidation_alignment(self, &runtime.protocol, &candidate, &consolidation)
            .await?;
        let durable = self.repository.persist_and_read_back(&candidate).await?;
        let durable_consolidation = durable.consolidation()?;
        let durable_worker = durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if durable_worker.revision() != worker_effect.revision() {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        // Broadcast does not mint any follow-on capability, but decoding and comparing the exact
        // coordinator readback still proves both halves shared this CAS.
        if durable_consolidation.revision() != consolidation_effect.revision()
            || consolidation_effect.state_commitment() == [0_u8; 32]
        {
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        runtime.snapshot = durable;
        runtime.consolidation = durable_consolidation;
        Ok(())
    }

    /// Create or restore the stable wallet and anchor its scanner before accepting allocations.
    pub async fn ensure_genesis(
        &self,
        public: &EpochPublic,
        certified_activation_root: [u8; 32],
    ) -> Result<DepositWalletId, DepositServiceError> {
        public.validate()?;
        let genesis_committee = self.scenario.genesis_committee()?;
        if public.committee.epoch != 0 || public.committee.digest() != genesis_committee.digest() {
            return Err(DepositServiceError::WrongEpoch);
        }
        let activation = public.activation_digest()?;
        let deriver = DepositAddressDeriver::new(
            self.scenario.network,
            public.group_key_bytes(),
            &self.private_view_scalar,
        )?;
        let wallet = deriver.wallet_id();
        let birth_anchor = self.resolve_birth_anchor().await?;
        let first_index = DepositSubaddressIndex::new(0, 1)?;
        let fault_bound = self.scenario.committee_spec(0)?.fault_bound;
        let verified_genesis = VerifiedRegistryHandoffTarget::from_verified_activation(
            None,
            public.clone(),
            fault_bound,
            certified_activation_root,
            &deriver,
        )?;
        let mut guard = self.runtime.lock().await;
        if let Some(runtime) = guard.as_ref() {
            if runtime.deriver.wallet_id() != wallet {
                return Err(DepositServiceError::WrongWallet);
            }
            validate_fresh_registry_genesis(
                &runtime.protocol.registry,
                wallet,
                public,
                fault_bound,
                activation,
                certified_activation_root,
                first_index,
            )?;
            return Ok(wallet);
        }

        let path = self.repository.snapshot_path(wallet);
        let (mut snapshot, protocol) = if tokio::fs::try_exists(&path).await? {
            let snapshot = self.repository.load(wallet).await?;
            let (snapshot, protocol) = self.restore_current_snapshot(snapshot, &deriver).await?;
            validate_fresh_registry_genesis(
                &protocol.registry,
                wallet,
                public,
                fault_bound,
                activation,
                certified_activation_root,
                first_index,
            )?;
            if let Some(worker) = snapshot.worker() {
                let encoded = worker.encode()?;
                let restored = DepositWorkerState::decode(&encoded, &deriver)?;
                if snapshot.birth_anchor != birth_anchor
                    || worker.scan_state().birth_anchor() != birth_anchor
                {
                    return Err(DepositServiceError::BirthAnchorMismatch);
                }
                if &restored != worker {
                    return Err(DepositServiceError::InvalidProtocolState);
                }
            } else {
                return Err(DepositServiceError::MissingScannerAnchor);
            }
            (snapshot, protocol)
        } else {
            let deposit_index_checkpoint =
                DepositIndexStoreCheckpoint::empty(wallet, self.party, first_index)?;
            let portable_head =
                PortableDepositIndexHead::from_head(deposit_index_checkpoint.portable_head())?;
            let empty_registry_checkpoint = CompactRegistryStoreCheckpoint::empty(wallet)?;
            let mut registry_store = CompactRegistryStore::open_with_stores(
                Arc::clone(&self.protocol_store),
                WalletArtifactStore::new(
                    self.deposit_index_directory.clone(),
                    self.party,
                    &self.deposit_index_identity_seed,
                )?,
                empty_registry_checkpoint,
            )
            .await?;
            let prepared_registry = registry_store
                .prepare_genesis(&verified_genesis, first_index, portable_head.digest())
                .await?;
            let registry = prepared_registry.proposed_head().registry().clone();
            validate_fresh_registry_genesis(
                &registry,
                wallet,
                public,
                fault_bound,
                activation,
                certified_activation_root,
                first_index,
            )?;
            let ledger = CompactLedgerCursor::genesis(&registry, &portable_head)?;
            let protocol = DepositProtocolState::genesis(self.party, registry, ledger)?;
            let mut worker = DepositWorkerState::new(&deriver, birth_anchor, self.worker_config)?;
            worker.initialize_portable_index_head(portable_head.digest())?;
            let archive_head = DepositArchiveHead::empty(wallet)?;
            let mut snapshot = DepositServiceSnapshot::new_archived(
                wallet,
                self.scenario.quic_network_id()?,
                protocol.encode_local(&deriver)?,
                birth_anchor,
                archive_head,
                prepared_registry.checkpoint().clone(),
                deposit_index_checkpoint,
            )?;
            snapshot.worker = Some(worker);
            // Worker initialization is part of revision zero, before any address can be issued.
            snapshot.validate()?;
            let durable = match self.repository.persist_and_read_back(&snapshot).await {
                Ok(durable) => durable,
                Err(save_error) => match self.repository.load(wallet).await {
                    Ok(durable)
                        if durable.compact_registry_checkpoint()
                            == prepared_registry.checkpoint() =>
                    {
                        durable
                    }
                    Ok(_) => {
                        registry_store.abort_prepared(&prepared_registry).await?;
                        return Err(save_error);
                    }
                    Err(load_error) => {
                        return Err(DepositServiceError::AmbiguousStorageCommit {
                            save: save_error.to_string(),
                            load: load_error.to_string(),
                        });
                    }
                },
            };
            if durable.compact_registry_checkpoint() != prepared_registry.checkpoint() {
                return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
            }
            registry_store
                .commit_prepared(&prepared_registry, durable.compact_registry_checkpoint())
                .await?;
            let mut settled_candidate = durable;
            settled_candidate.install_compact_registry_checkpoint(
                prepared_registry.checkpoint(),
                prepared_registry.settled_checkpoint().clone(),
            )?;
            snapshot = self.repository.persist_and_read_back(&settled_candidate).await?;
            if snapshot.compact_registry_checkpoint() != registry_store.checkpoint() {
                return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
            }
            *self.compact_registry.lock().await = Some(registry_store);
            (snapshot, protocol)
        };
        self.initialize_deposit_index(&mut snapshot).await?;
        let consolidation = snapshot.consolidation()?;
        validate_consolidation_alignment(self, &protocol, &snapshot, &consolidation).await?;
        *guard = Some(DepositRuntime { deriver, snapshot, protocol, consolidation });
        self.runtime_ready.store(true, Ordering::Release);
        Ok(wallet)
    }

    /// Return the current certified client state without creating a new allocation.
    pub async fn address_status(
        &self,
        request: DepositAddressRequest,
        now: u64,
    ) -> Result<DepositAddressResponse, DepositServiceError> {
        validate_now(now)?;
        validate_deposit_address_request(request)?;
        let sync = self.scanner_sync_status().await?;
        let (leader, pending) = {
            let guard = self.runtime.lock().await;
            let runtime = guard.as_ref().ok_or(DepositServiceError::NotInitialized)?;
            if !sync_status_matches_runtime(sync, runtime)? {
                return runtime.protocol.syncing_response(request);
            }
            runtime.protocol.require_live()?;
            let pending = runtime.protocol.pending.values().find_map(|slot| {
                let LedgerPayload::Allocation(allocation) = &slot.statement.payload else {
                    return None;
                };
                (allocation.request == request.request).then_some(allocation.binding)
            });
            if pending.is_some_and(|binding| binding != request.binding) {
                return Err(DepositServiceError::RequestEquivocation);
            }
            (runtime.protocol.current_consensus_leader()?, pending.is_some())
        };
        if let Some(response) = self.certified_address_response(request, now, leader).await? {
            return Ok(response);
        }
        let _ = pending;
        Ok(DepositAddressResponse {
            request: request.request,
            status: DepositAddressStatus::Pending,
            address: None,
            certificate: None,
            created_at: None,
            expires_at: None,
            leader,
        })
    }

    /// Admit one locally authenticated client request, durably gossip its origin-signed form, and
    /// start the next allocation consensus height when no earlier ledger slot is live.
    pub async fn submit_allocation_request(
        &self,
        request: DepositAddressRequest,
        now_unix_ms: u64,
        identity: &Identity,
    ) -> Result<DepositAddressResponse, DepositServiceError> {
        let now = validate_consensus_now(now_unix_ms)?;
        let current = self.address_status(request, now).await?;
        if current.status != DepositAddressStatus::Pending {
            return Ok(current);
        }
        let sync = self.scanner_sync_status().await?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        if !sync_status_matches_runtime(sync, runtime)? {
            return runtime.protocol.syncing_response(request);
        }
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        require_no_pending_handoff(&runtime.protocol)?;

        let wire = DepositClientRequestWire::new(&runtime.protocol.registry, request, identity)?;
        let mut candidate = runtime.protocol.clone();
        let changed = candidate.retain_client_request(wire.origin(), request)?;
        let mut effects = DepositConsensusHostEffects::default();
        if changed {
            effects.messages.extend(self.client_request_messages(
                &candidate,
                candidate.ledger.next_sequence(),
                &wire,
            )?);
        }
        self.start_deposit_lane_if_ready(
            &mut candidate,
            &runtime.deriver,
            runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?,
            now_unix_ms,
            identity,
            &mut effects,
        )?;
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await?;
        runtime.protocol.pending_response(request, DepositAddressStatus::Pending)
    }

    /// Accept an origin-signed client request from an authenticated active member. Relays preserve
    /// the original signer; they cannot manufacture another admission source.
    pub async fn handle_client_request(
        &self,
        authenticated_party: PartyId,
        wire: DepositClientRequestWire,
        now_unix_ms: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        validate_consensus_now(now_unix_ms)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        wire.validate(&runtime.protocol.registry)?;
        require_no_pending_handoff(&runtime.protocol)?;

        let mut candidate = runtime.protocol.clone();
        let changed = candidate.retain_client_request(wire.origin(), wire.request)?;
        let mut effects = DepositConsensusHostEffects::default();
        if changed {
            effects.messages.extend(self.client_request_messages(
                &candidate,
                candidate.ledger.next_sequence(),
                &wire,
            )?);
        }
        self.start_deposit_lane_if_ready(
            &mut candidate,
            &runtime.deriver,
            runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?,
            now_unix_ms,
            identity,
            &mut effects,
        )?;
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await
    }

    /// Reduce one portable proposal/vote/view/commit object from authenticated QUIC.
    pub async fn handle_consensus(
        &self,
        authenticated_party: PartyId,
        operation: DepositOperation,
        wire: DepositConsensusWire,
        now_unix_ms: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        let now = validate_consensus_now(now_unix_ms)?;
        wire.validate_for_operation(operation)?;
        if matches!(wire.purpose, DepositConsensusPurpose::NextIndexCheckpoint { .. }) {
            return self
                .handle_checkpoint_consensus(authenticated_party, wire, now_unix_ms, now, identity)
                .await;
        }
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        let expected = deposit_consensus_context(
            &runtime.protocol,
            runtime.deriver.wallet_id(),
            self.scenario.quic_network_id()?,
        )?;
        if wire.context != expected
            || wire.purpose.sequence() != expected.sequence()
            || wire.purpose.sequence() != expected.height()
        {
            return Err(DepositServiceError::ConsensusUnavailable);
        }

        let previously_admitted = runtime
            .protocol
            .consensus_lane
            .as_ref()
            .map(|lane| lane.admitted_values.clone())
            .unwrap_or_default();
        let mut freshly_authenticated = BTreeSet::new();
        for value in referenced_deposit_consensus_values(&wire)? {
            if let Some(admitted) = previously_admitted.get(&value.digest()) {
                let decoded = DepositConsensusValue::decode(&value)?;
                if decoded.statement != admitted.statement
                    || decoded.terminal_evidence != admitted.terminal_evidence
                {
                    return Err(DepositServiceError::InvalidConsensusValue);
                }
                continue;
            }
            self.authenticate_consensus_value_dependencies(&runtime.protocol, &value).await?;
            freshly_authenticated.insert(value.digest());
        }

        let mut candidate = runtime.protocol.clone();
        validate_consensus_purpose(
            &candidate,
            &runtime.deriver,
            wire.purpose,
            candidate.consensus_lane.is_some(),
        )?;
        let mut initial = ConsensusStep::default();
        if candidate.consensus_lane.is_none() {
            match &wire.payload {
                DepositConsensusPayload::CommitCertificate(_) => {
                    let reducer = DepositConsensus::new(expected.clone(), self.party)?;
                    candidate.consensus_lane = Some(DurableDepositConsensusLane::new(
                        wire.purpose,
                        reducer,
                        now,
                        self.consensus_deadline(now_unix_ms)?,
                    )?);
                }
                DepositConsensusPayload::Envelope(envelope)
                    if matches!(
                        decode_consensus_message(&expected, envelope)?.body,
                        ConsensusMessageBody::Proposal(_)
                    ) =>
                {
                    let message = decode_consensus_message(&expected, envelope)?;
                    let ConsensusMessageBody::Proposal(proposal) = message.body else {
                        unreachable!()
                    };
                    let admission = validate_deposit_consensus_value(
                        &candidate,
                        &runtime.deriver,
                        Some(
                            runtime
                                .snapshot
                                .worker()
                                .ok_or(DepositServiceError::MissingScannerAnchor)?,
                        ),
                        &proposal.value,
                        now,
                        true,
                        wire.purpose,
                        Some(expected.binding().network),
                    )?;
                    if matches!(
                        admission.admitted.statement.payload,
                        LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_)
                    ) {
                        require_consolidation_quiescent(self, runtime).await?;
                    }
                    let mut reducer = DepositConsensus::new(expected.clone(), self.party)?;
                    initial = reducer.start(identity, proposal.value)?;
                    let mut lane = DurableDepositConsensusLane::new(
                        wire.purpose,
                        reducer,
                        now,
                        self.consensus_deadline(now_unix_ms)?,
                    )?;
                    install_consensus_admission(&mut lane, admission)?;
                    candidate.consensus_lane = Some(lane);
                }
                DepositConsensusPayload::Envelope(_)
                | DepositConsensusPayload::ViewCertificate(_) => {
                    let mut effects = DepositConsensusHostEffects::default();
                    self.start_deposit_lane_if_ready(
                        &mut candidate,
                        &runtime.deriver,
                        runtime
                            .snapshot
                            .worker()
                            .ok_or(DepositServiceError::MissingScannerAnchor)?,
                        now_unix_ms,
                        identity,
                        &mut effects,
                    )?;
                    if candidate.consensus_lane.is_none() {
                        return Err(DepositServiceError::ConsensusUnavailable);
                    }
                    initial.broadcast = effects
                        .messages
                        .iter()
                        .filter_map(|(_, _, operation, body)| {
                            matches!(
                                operation,
                                DepositOperation::ConsensusProposal
                                    | DepositOperation::ConsensusMessage
                            )
                            .then(|| postcard::from_bytes::<DepositConsensusWire>(body).ok())
                            .flatten()
                            .and_then(|wire| match wire.payload {
                                DepositConsensusPayload::Envelope(envelope) => Some(envelope),
                                DepositConsensusPayload::ViewCertificate(_)
                                | DepositConsensusPayload::CommitCertificate(_) => None,
                            })
                        })
                        .collect();
                }
            }
        }

        let mut lane =
            candidate.consensus_lane.take().ok_or(DepositServiceError::ConsensusUnavailable)?;
        if lane.reducer.context() != &expected || lane.purpose != wire.purpose {
            return Err(DepositServiceError::ConsensusUnavailable);
        }
        let existing = lane.admitted_values.clone();
        let validation_protocol = candidate.clone();
        let validation_worker =
            runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let certificate_backed = matches!(
            wire.payload,
            DepositConsensusPayload::ViewCertificate(_)
                | DepositConsensusPayload::CommitCertificate(_)
        );
        let handoff_quiescent = match require_consolidation_quiescent(self, runtime).await {
            Ok(()) => true,
            Err(DepositServiceError::ConsolidationNotPortable) => false,
            Err(error) => return Err(error),
        };
        let mut newly_admitted = BTreeMap::new();
        let mut validator = |value: &ConsensusValue| {
            if let Some(admitted) = existing.get(&value.digest()) {
                return DepositConsensusValue::decode(value).is_ok_and(|decoded| {
                    decoded.statement == admitted.statement
                        && decoded.terminal_evidence == admitted.terminal_evidence
                });
            }
            let admitted_at = if certificate_backed {
                consensus_value_created_at(value).ok().flatten().unwrap_or(now)
            } else {
                now
            };
            match validate_deposit_consensus_value(
                &validation_protocol,
                &runtime.deriver,
                Some(validation_worker),
                value,
                admitted_at,
                !certificate_backed,
                wire.purpose,
                Some(expected.binding().network),
            ) {
                Ok(admission)
                    if freshly_authenticated.contains(&admission.digest)
                        && (!matches!(
                            admission.admitted.statement.payload,
                            LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_)
                        ) || handoff_quiescent) =>
                {
                    newly_admitted.insert(admission.digest, admission);
                    true
                }
                Ok(_) => false,
                Err(_) => false,
            }
        };
        let commit_backed = matches!(&wire.payload, DepositConsensusPayload::CommitCertificate(_));
        let reduced = match wire.payload {
            DepositConsensusPayload::Envelope(envelope) => {
                lane.reducer.handle_with_value_validator(identity, envelope, &mut validator)?
            }
            DepositConsensusPayload::ViewCertificate(certificate) => lane
                .reducer
                .handle_view_certificate_with_validator(identity, certificate, &mut validator)?,
            DepositConsensusPayload::CommitCertificate(certificate) => lane
                .reducer
                .handle_commit_certificate_with_validator(certificate, &mut validator)?,
        };
        drop(validator);
        for admission in newly_admitted.into_values() {
            install_consensus_admission(&mut lane, admission)?;
        }
        candidate.consensus_lane = Some(lane);
        let step = merge_consensus_steps(initial, reduced)?;
        let mut effects = self.consensus_step_effects(
            &mut candidate,
            &runtime.deriver,
            identity,
            now_unix_ms,
            step,
        )?;
        if commit_backed && effects.prune.is_none() {
            effects.prune = Some(DepositConsensusOutboxScope {
                sequence: expected.sequence(),
                context: expected.digest(),
            });
        }
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await
    }

    async fn handle_checkpoint_consensus(
        &self,
        authenticated_party: PartyId,
        wire: DepositConsensusWire,
        now_unix_ms: u64,
        now: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        let checkpoint_sequence = runtime
            .protocol
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_purpose =
            DepositConsensusPurpose::NextIndexCheckpoint { sequence: checkpoint_sequence };
        let previous_head = PortableDepositIndexHead::from_head(
            runtime.snapshot.deposit_index_checkpoint().portable_head(),
        )?;
        let expected = deposit_index_checkpoint_consensus_context(
            self.scenario.quic_network_id()?,
            &runtime.protocol.registry,
            checkpoint_sequence,
            &previous_head,
        )?;
        if wire.purpose != expected_purpose || wire.context != expected {
            return Err(DepositServiceError::ConsensusUnavailable);
        }

        let previously_admitted = runtime
            .protocol
            .checkpoint_consensus_lane
            .as_ref()
            .map(|lane| lane.admitted_values.clone())
            .unwrap_or_default();
        let mut freshly_authenticated = BTreeMap::new();
        for value in referenced_deposit_consensus_values(&wire)? {
            if let Some(admitted) = previously_admitted.get(&value.digest()) {
                if DepositIndexCheckpointCandidate::from_consensus_value(&value)?
                    != admitted.candidate
                {
                    return Err(DepositServiceError::InvalidConsensusValue);
                }
                continue;
            }
            let operation = DepositIndexCheckpointCandidate::from_consensus_value(&value)?;
            self.authenticate_checkpoint_consensus_candidate(runtime, &operation, now).await?;
            freshly_authenticated.insert(value.digest(), operation);
        }

        let mut candidate = runtime.protocol.clone();
        for operation in freshly_authenticated.values() {
            match operation {
                DepositIndexCheckpointCandidate::Ledger(entry) => {
                    let historical = self.historical_issuer_for_statement(&entry.statement).await?;
                    candidate.retain_certified_pending(entry, historical.as_ref())?;
                }
                DepositIndexCheckpointCandidate::DepositObservation(observation) => {
                    candidate.retain_certified_deposit_observation(observation)?;
                }
            }
        }
        let mut initial = ConsensusStep::default();
        if candidate.checkpoint_consensus_lane.is_none() {
            match &wire.payload {
                DepositConsensusPayload::CommitCertificate(_) => {
                    candidate.checkpoint_consensus_lane =
                        Some(DurableDepositCheckpointConsensusLane::new(
                            expected_purpose,
                            DepositConsensus::new(expected.clone(), self.party)?,
                            now,
                            self.consensus_deadline(now_unix_ms)?,
                        )?);
                }
                DepositConsensusPayload::Envelope(envelope)
                    if matches!(
                        decode_consensus_message(&expected, envelope)?.body,
                        ConsensusMessageBody::Proposal(_)
                    ) =>
                {
                    let message = decode_consensus_message(&expected, envelope)?;
                    let ConsensusMessageBody::Proposal(proposal) = message.body else {
                        unreachable!()
                    };
                    let operation =
                        DepositIndexCheckpointCandidate::from_consensus_value(&proposal.value)?;
                    if freshly_authenticated.get(&proposal.value.digest()) != Some(&operation) {
                        return Err(DepositServiceError::InvalidConsensusValue);
                    }
                    let mut reducer = DepositConsensus::new(expected.clone(), self.party)?;
                    initial = reducer.start(identity, proposal.value)?;
                    candidate.checkpoint_consensus_lane =
                        Some(DurableDepositCheckpointConsensusLane::new(
                            expected_purpose,
                            reducer,
                            now,
                            self.consensus_deadline(now_unix_ms)?,
                        )?);
                }
                DepositConsensusPayload::Envelope(_)
                | DepositConsensusPayload::ViewCertificate(_) => {
                    return Err(DepositServiceError::ConsensusUnavailable);
                }
            }
        }

        let mut lane = candidate
            .checkpoint_consensus_lane
            .take()
            .ok_or(DepositServiceError::ConsensusUnavailable)?;
        if lane.purpose != expected_purpose || lane.reducer.context() != &expected {
            return Err(DepositServiceError::ConsensusUnavailable);
        }
        for operation in freshly_authenticated.values().cloned() {
            install_checkpoint_consensus_admission(&mut lane, now, operation)?;
        }
        let existing = lane.admitted_values.clone();
        let mut validator = |value: &ConsensusValue| {
            existing.get(&value.digest()).is_some_and(|admitted| {
                DepositIndexCheckpointCandidate::from_consensus_value(value)
                    .is_ok_and(|operation| operation == admitted.candidate)
            })
        };
        let commit_backed = matches!(&wire.payload, DepositConsensusPayload::CommitCertificate(_));
        let reduced = match wire.payload {
            DepositConsensusPayload::Envelope(envelope) => {
                lane.reducer.handle_with_value_validator(identity, envelope, &mut validator)?
            }
            DepositConsensusPayload::ViewCertificate(certificate) => lane
                .reducer
                .handle_view_certificate_with_validator(identity, certificate, &mut validator)?,
            DepositConsensusPayload::CommitCertificate(certificate) => lane
                .reducer
                .handle_commit_certificate_with_validator(certificate, &mut validator)?,
        };
        candidate.checkpoint_consensus_lane = Some(lane);
        let step = merge_consensus_steps(initial, reduced)?;
        let mut effects =
            self.checkpoint_consensus_step_effects(&mut candidate, now_unix_ms, step)?;
        if commit_backed && effects.prune.is_none() {
            effects.prune = Some(DepositConsensusOutboxScope {
                sequence: checkpoint_sequence,
                context: expected.digest(),
            });
        }
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await?;
        self.resume_decided_checkpoint_round(runtime, identity, now).await
    }

    /// Start the next globally ordered deposit operation and drive one durable timeout per view.
    pub async fn progress_allocation_consensus(
        &self,
        now_unix_ms: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        let now = validate_consensus_now(now_unix_ms)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        self.replay_pending_worker_events(runtime).await?;
        // A live ledger lane owns its pacemaker even while scanner observations continue to
        // arrive. Service its durable deadline before doing any observation/checkpoint work so a
        // silent ledger leader cannot indefinitely strand a handoff fence behind an adversarial
        // stream of otherwise valid deposits.
        if let Some(mut lane) = runtime.protocol.consensus_lane.clone()
            && lane.reducer.commit().is_none()
            && now_unix_ms >= lane.deadline_unix_ms
            && !lane.timeout_requested
        {
            let mut candidate = runtime.protocol.clone();
            let step = lane.reducer.request_view_change(identity)?;
            lane.timeout_requested = true;
            candidate.consensus_lane = Some(lane);
            let effects = self.consensus_step_effects(
                &mut candidate,
                &runtime.deriver,
                identity,
                now_unix_ms,
                step,
            )?;
            return self.commit_consensus_protocol(runtime, candidate, effects, identity).await;
        }
        if let Some(lane) = runtime.protocol.index_checkpoint.clone() {
            return self
                .start_or_resume_index_checkpoint_round(runtime, identity, lane.ledger, now)
                .await;
        }
        if let Some(lane) = runtime.protocol.checkpoint_consensus_lane.as_ref() {
            if lane.reducer.commit().is_some() {
                return self.resume_decided_checkpoint_round(runtime, identity, now).await;
            }
            if now_unix_ms >= lane.deadline_unix_ms && !lane.timeout_requested {
                let mut candidate = runtime.protocol.clone();
                let mut lane = candidate
                    .checkpoint_consensus_lane
                    .take()
                    .ok_or(DepositServiceError::ConsensusUnavailable)?;
                let step = lane.reducer.request_view_change(identity)?;
                lane.timeout_requested = true;
                candidate.checkpoint_consensus_lane = Some(lane);
                let effects =
                    self.checkpoint_consensus_step_effects(&mut candidate, now_unix_ms, step)?;
                self.commit_consensus_protocol(runtime, candidate, effects, identity).await?;
            }
            return Ok(());
        }
        if let Some(certificate) = runtime.protocol.next_certified_ledger_entry() {
            return self
                .start_or_resume_index_checkpoint_round(runtime, identity, certificate, now)
                .await;
        }
        if self.progress_deposit_observations_locked(runtime, identity, now).await? {
            // Observation certificate/checkpoint work shares the ordered checkpoint namespace
            // with ledger operations and therefore gets one durable action before another ledger
            // proposal is started.
            return Ok(());
        }
        let mut candidate = runtime.protocol.clone();
        let mut effects = DepositConsensusHostEffects::default();
        self.start_late_settlement_lane_if_ready(
            runtime,
            &mut candidate,
            now_unix_ms,
            identity,
            &mut effects,
        )
        .await?;
        self.start_abandonment_lane_if_ready(
            runtime,
            &mut candidate,
            now_unix_ms,
            identity,
            &mut effects,
        )
        .await?;
        let may_start = candidate.consensus_lane.is_some()
            || candidate.pending_handoff.is_none()
            || match require_consolidation_quiescent(self, runtime).await {
                Ok(()) => true,
                Err(DepositServiceError::ConsolidationNotPortable) => false,
                Err(error) => return Err(error),
            };
        if may_start {
            self.start_deposit_lane_if_ready(
                &mut candidate,
                &runtime.deriver,
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?,
                now_unix_ms,
                identity,
                &mut effects,
            )?;
        }
        if let Some(mut lane) = candidate.consensus_lane.take() {
            if lane.reducer.commit().is_none()
                && now_unix_ms >= lane.deadline_unix_ms
                && !lane.timeout_requested
            {
                let step = lane.reducer.request_view_change(identity)?;
                lane.timeout_requested = true;
                candidate.consensus_lane = Some(lane);
                let timeout_effects = self.consensus_step_effects(
                    &mut candidate,
                    &runtime.deriver,
                    identity,
                    now_unix_ms,
                    step,
                )?;
                effects.messages.extend(timeout_effects.messages);
                effects.prune = timeout_effects.prune;
            } else {
                candidate.consensus_lane = Some(lane);
            }
        }
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await
    }

    fn validate_consensus_identity(
        &self,
        protocol: &DepositProtocolState,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        if identity.party() != self.party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let member = protocol.registry.active().committee().member(self.party)?;
        if member.signing_key != identity.signing_public_key() {
            return Err(DepositServiceError::WrongLocalParty);
        }
        Ok(())
    }

    fn consensus_deadline(&self, now_unix_ms: u64) -> Result<u64, DepositServiceError> {
        let timeout = self
            .scenario
            .protocol_timeout_seconds
            .checked_mul(1_000)
            .filter(|timeout| *timeout != 0)
            .ok_or(DepositServiceError::InvalidTime)?;
        now_unix_ms.checked_add(timeout).ok_or(DepositServiceError::InvalidTime)
    }

    fn client_request_messages(
        &self,
        protocol: &DepositProtocolState,
        sequence: u64,
        wire: &DepositClientRequestWire,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let body = postcard::to_allocvec(wire)?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| (sequence, party, DepositOperation::ClientRequest, body.clone()))
            .collect())
    }

    fn start_deposit_lane_if_ready(
        &self,
        protocol: &mut DepositProtocolState,
        deriver: &DepositAddressDeriver,
        worker: &DepositWorkerState,
        now_unix_ms: u64,
        identity: &Identity,
        effects: &mut DepositConsensusHostEffects,
    ) -> Result<(), DepositServiceError> {
        if protocol.consensus_lane.is_some()
            || !protocol.pending.is_empty()
            || protocol.checkpoint_consensus_lane.is_some()
            || protocol.observation_checkpoint.is_some()
            || protocol.next_certified_deposit_observation()?.is_some()
        {
            return Ok(());
        }
        let now = validate_consensus_now(now_unix_ms)?;
        let (purpose, statement, require_client_request) = if let Some(target) =
            protocol.pending_handoff.as_ref()
        {
            validate_trusted_handoff_target(&self.scenario, protocol, deriver, target)?;
            if protocol.ledger.is_sealed() {
                return Ok(());
            }
            // Merely fencing a target is not signing authority. The host sets this root only
            // through `progress_certified_handoff`, after its activation certificate is
            // durably persisted and re-authenticated.
            let Some(certified_root) = protocol.pending_handoff_root else {
                return Ok(());
            };
            let source = protocol
                .pending_handoff_source
                .as_ref()
                .ok_or(DepositServiceError::WrongRegistry)?;
            let verified_target = VerifiedRegistryHandoffTarget::from_verified_activation(
                Some(source),
                target.clone(),
                protocol.pending_handoff_fault_bound.ok_or(DepositServiceError::WrongRegistry)?,
                certified_root,
                deriver,
            )?;
            let purpose = handoff_consensus_purpose(protocol.ledger.next_sequence(), target)?;
            let statement = if protocol.pending_handoff_fence.is_none() {
                // The moving checkpoint is the newest chain point which this scanner already
                // treats as non-rollbackable. Using the tip here would let a shallow reorg change
                // membership of the source prefix after the BA decision.
                let cutoff = worker.reorg_checkpoint();
                worker.scan_state().verify_recognition_anchor(cutoff)?;
                LedgerStatement::handoff_fence(
                    &protocol.registry,
                    protocol.ledger.next_sequence(),
                    protocol.ledger.head(),
                    &verified_target,
                    cutoff,
                )?
            } else {
                if protocol.has_source_handoff_prefix_observations() {
                    return Ok(());
                }
                LedgerStatement::handoff(
                    &protocol.registry,
                    protocol.ledger.next_sequence(),
                    protocol.ledger.head(),
                    protocol.ledger.portable_index_digest(),
                    &verified_target,
                    protocol.ledger.next_index(),
                )?
            };
            (purpose, statement, false)
        } else {
            let Some(request) = protocol.next_client_request()? else {
                return Ok(());
            };
            let recognition_anchor = worker.reorg_checkpoint();
            worker.scan_state().verify_recognition_anchor(recognition_anchor)?;
            let created_at = now
                .checked_add(ALLOCATION_ISSUANCE_LEAD_SECONDS)
                .ok_or(DepositServiceError::InvalidTime)?;
            let statement = LedgerStatement::allocation(
                &protocol.registry,
                protocol.ledger.next_sequence(),
                protocol.ledger.head(),
                request.request,
                request.binding,
                deriver.derive(protocol.ledger.next_index()),
                recognition_anchor,
                created_at,
            )?;
            (
                DepositConsensusPurpose::NextLedgerSlot {
                    sequence: protocol.ledger.next_sequence(),
                },
                statement,
                true,
            )
        };
        let value = DepositConsensusValue::new(statement)?;
        let admission = validate_deposit_consensus_value(
            protocol,
            deriver,
            Some(worker),
            &value,
            now,
            require_client_request,
            purpose,
            Some(self.scenario.quic_network_id()?),
        )?;
        let context = deposit_consensus_context(
            protocol,
            deriver.wallet_id(),
            self.scenario.quic_network_id()?,
        )?;
        if purpose.sequence() != context.sequence() {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        let mut reducer = DepositConsensus::new(context, self.party)?;
        let step = reducer.start(identity, value)?;
        let mut lane = DurableDepositConsensusLane::new(
            purpose,
            reducer,
            now,
            self.consensus_deadline(now_unix_ms)?,
        )?;
        install_consensus_admission(&mut lane, admission)?;
        protocol.consensus_lane = Some(lane);
        let step_effects =
            self.consensus_step_effects(protocol, deriver, identity, now_unix_ms, step)?;
        effects.messages.extend(step_effects.messages);
        effects.prune = step_effects.prune;
        Ok(())
    }

    /// Give canonical inclusion precedence over abandonment at every free ledger height.
    ///
    /// Only a locally reconstructed full transaction with an authenticated archived attempt and
    /// exact MMR membership can enter this lane. Every receiver repeats the portable proof checks
    /// and its own scanner observation before voting.
    async fn start_late_settlement_lane_if_ready(
        &self,
        runtime: &DepositRuntime,
        protocol: &mut DepositProtocolState,
        now_unix_ms: u64,
        identity: &Identity,
        effects: &mut DepositConsensusHostEffects,
    ) -> Result<(), DepositServiceError> {
        if protocol.consensus_lane.is_some() || !protocol.pending.is_empty() {
            return Ok(());
        }
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let mut settlements = worker.reconcile_sweep_family_settlements()?;
        settlements
            .sort_unstable_by_key(|settlement| (settlement.sweep, settlement.transaction_id()));
        let network = self.scenario.quic_network_id()?;
        let archive_head = runtime.snapshot.roast_attempt_archive_head();

        for observed in settlements {
            if runtime.consolidation.record_by_sweep(observed.sweep).is_none() {
                continue;
            }
            let Some(portable_evidence) =
                self.authenticated_portable_terminal_by_sweep(observed.sweep).await?
            else {
                continue;
            };
            let portable_terminal = &portable_evidence.terminal;
            let PortableConsolidationStatus::Abandoned { evidence: indexed_abandonment } =
                portable_terminal.status()
            else {
                // A completed or already late-settled terminal is permanently authoritative.
                continue;
            };
            let Some(certified_abandonment) = portable_evidence.abandonment_statement() else {
                continue;
            };
            let LedgerPayload::ConsolidationAbandonment(abandonment) =
                &certified_abandonment.payload
            else {
                return Err(DepositServiceError::InvalidPortableTerminalEvidence);
            };
            if abandonment.authorization().sweep_id() != observed.sweep
                || portable_terminal.consolidation_id() != abandonment.id()
                || portable_terminal.inputs() != abandonment.inputs()
                || indexed_abandonment.statement_digest() != certified_abandonment.digest()
                || indexed_abandonment.attempt_prefix() != abandonment.attempt_prefix()
                || protocol.registry.active_epoch() <= abandonment.attempt().epoch()
            {
                continue;
            }
            let completion_proof = match self
                .roast_archive
                .export_portable_transaction_completion(
                    archive_head,
                    runtime.deriver.wallet_id(),
                    abandonment.attempt_prefix(),
                    observed.transaction_id(),
                )
                .await
            {
                Ok(proof) => proof,
                Err(RoastAttemptArchiveError::TransactionNotFound { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            let archived_record = completion_proof.record();
            let mapping = completion_proof.mapping();
            let plan = mapping.plan().clone();
            if plan.id != observed.sweep {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            if mapping.signed_transaction() != &observed.signed_transaction {
                return Err(DepositServiceError::InvalidLateConsolidationSettlement);
            }
            let historical_completion = ConsolidationCompletionStatement::from_archived_components(
                plan,
                archived_record.intent().authorization().clone(),
                archived_record.intent().attempt().clone(),
                mapping.signed_binding(),
                mapping.signed_transaction().clone(),
            );
            let finality_depth = worker.config().confirmation_depth;
            let finality_height = observed
                .block
                .height
                .checked_add(u64::from(finality_depth))
                .ok_or(DepositServiceError::InvalidTime)?;
            let Some(observation_tip) = worker.scan_state().chain_point(finality_height) else {
                continue;
            };
            let historical_issuer = {
                let mut guard = self.compact_registry.lock().await;
                let store =
                    guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
                store.lookup_issuer_window(historical_completion.attempt().epoch()).await?
            };
            let statement = LedgerStatement::late_consolidation_settlement(
                &protocol.registry,
                &historical_issuer,
                protocol.ledger.next_sequence(),
                protocol.ledger.head(),
                certified_abandonment.digest(),
                historical_completion,
                observed.block,
                observation_tip,
                finality_depth,
            )?;
            let LedgerPayload::LateConsolidationSettlement(settlement) = &statement.payload else {
                return Err(DepositServiceError::InvalidProtocolState);
            };
            let evidence = ConsolidationLateSettlementEvidence::new(
                certified_abandonment.clone(),
                completion_proof,
            );
            evidence.verify(protocol, settlement, network)?;
            validate_late_settlement_observation_locally(worker, settlement)?;

            let purpose = DepositConsensusPurpose::NextLedgerSlot { sequence: statement.sequence };
            let value = DepositConsensusValue::late_settlement(statement, evidence)?;
            let now = validate_consensus_now(now_unix_ms)?;
            let admission = validate_deposit_consensus_value(
                protocol,
                &runtime.deriver,
                Some(worker),
                &value,
                now,
                false,
                purpose,
                Some(network),
            )?;
            let context =
                deposit_consensus_context(protocol, runtime.deriver.wallet_id(), network)?;
            let mut reducer = DepositConsensus::new(context, self.party)?;
            let step = reducer.start(identity, value)?;
            let mut lane = DurableDepositConsensusLane::new(
                purpose,
                reducer,
                now,
                self.consensus_deadline(now_unix_ms)?,
            )?;
            install_consensus_admission(&mut lane, admission)?;
            protocol.consensus_lane = Some(lane);
            let started = self.consensus_step_effects(
                protocol,
                &runtime.deriver,
                identity,
                now_unix_ms,
                step,
            )?;
            effects.messages.extend(started.messages);
            effects.prune = started.prune;
            effects.terminal = started.terminal;
            return Ok(());
        }
        Ok(())
    }

    async fn start_abandonment_lane_if_ready(
        &self,
        runtime: &DepositRuntime,
        protocol: &mut DepositProtocolState,
        now_unix_ms: u64,
        identity: &Identity,
        effects: &mut DepositConsensusHostEffects,
    ) -> Result<(), DepositServiceError> {
        if protocol.consensus_lane.is_some() || !protocol.pending.is_empty() {
            return Ok(());
        }
        let network = self.scenario.quic_network_id()?;
        let mut ready = Vec::new();
        for (digest, pool) in &runtime.snapshot.consolidation_abandonments {
            let active = protocol.registry.active();
            if active.epoch() != pool.observation.attempt.epoch() {
                return Err(DepositServiceError::InvalidConsolidationAbandonment);
            }
            let required = usize::from(
                active
                    .committee()
                    .n()
                    .checked_sub(active.fault_bound())
                    .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?,
            );
            let already_terminal = self
                .authenticated_portable_terminal_by_sweep(pool.observation.authorization.sweep_id())
                .await?
                .is_some();
            if pool.attestations.len() < required
                || already_terminal
                || runtime
                    .snapshot
                    .worker()
                    .ok_or(DepositServiceError::MissingScannerAnchor)?
                    .reconcile_sweep_family_settlements()?
                    .iter()
                    .any(|settlement| settlement.sweep == pool.observation.authorization.sweep_id())
            {
                continue;
            }
            let share_unexposed = match ShareUnexposedCertificate::from_available_witnesses(
                &pool.observation.abandonment_context,
                &pool.observation.intent_certificate,
                pool.share_unexposed.values().cloned().collect(),
            ) {
                Ok(certificate) => certificate,
                Err(
                    ConsolidationConsensusError::InsufficientShareWitnesses
                    | ConsolidationConsensusError::UnsafeIntersection,
                ) => continue,
                Err(error) => return Err(error.into()),
            };
            let evidence = ConsolidationAbandonmentEvidence {
                version: CONSOLIDATION_ABANDONMENT_EVIDENCE_VERSION,
                observation: pool.observation.clone(),
                share_unexposed,
                attestations: pool.attestations.values().take(required).cloned().collect(),
            };
            ready.push((*digest, evidence));
        }
        ready.sort_unstable_by_key(|(digest, _)| *digest);
        let Some((_, evidence)) = ready.into_iter().next() else {
            return Ok(());
        };
        let observation = &evidence.observation;
        let statement = LedgerStatement::consolidation_abandonment(
            &protocol.registry,
            protocol.ledger.next_sequence(),
            protocol.ledger.head(),
            observation.family,
            observation.attempt_prefix,
            observation.slot.clone(),
            observation.binding.clone(),
            observation.key_images.clone(),
            observation.authorization.clone(),
            observation.attempt.clone(),
            observation.sweep_sequence,
            observation.inputs.clone(),
            observation.missing_inputs.clone(),
            observation.ancestor,
            observation.observation_tip,
            observation.finality_depth,
        )?;
        let LedgerPayload::ConsolidationAbandonment(abandonment) = &statement.payload else {
            return Err(DepositServiceError::InvalidConsensusValue);
        };
        evidence.verify(protocol, abandonment, network)?;
        let purpose = DepositConsensusPurpose::NextLedgerSlot { sequence: statement.sequence };
        let value = DepositConsensusValue::abandonment(statement, evidence)?;
        let now = validate_consensus_now(now_unix_ms)?;
        let admission = validate_deposit_consensus_value(
            protocol,
            &runtime.deriver,
            None,
            &value,
            now,
            false,
            purpose,
            Some(network),
        )?;
        let context = deposit_consensus_context(protocol, runtime.deriver.wallet_id(), network)?;
        let mut reducer = DepositConsensus::new(context, self.party)?;
        let step = reducer.start(identity, value)?;
        let mut lane = DurableDepositConsensusLane::new(
            purpose,
            reducer,
            now,
            self.consensus_deadline(now_unix_ms)?,
        )?;
        install_consensus_admission(&mut lane, admission)?;
        protocol.consensus_lane = Some(lane);
        let started =
            self.consensus_step_effects(protocol, &runtime.deriver, identity, now_unix_ms, step)?;
        effects.messages.extend(started.messages);
        effects.prune = started.prune;
        effects.terminal = started.terminal;
        Ok(())
    }

    fn consensus_step_effects(
        &self,
        protocol: &mut DepositProtocolState,
        _deriver: &DepositAddressDeriver,
        _identity: &Identity,
        now_unix_ms: u64,
        mut step: ConsensusStep,
    ) -> Result<DepositConsensusHostEffects, DepositServiceError> {
        let (purpose, context, current_view) = {
            let lane = protocol
                .consensus_lane
                .as_mut()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            if let Some(view) = step.entered_view {
                lane.enter_view(view, self.consensus_deadline(now_unix_ms)?);
            }
            (lane.purpose, lane.reducer.context().clone(), lane.reducer.view())
        };
        step.broadcast.retain(|envelope| {
            consensus_envelope_relevant_to_view(&context, envelope, current_view).unwrap_or(false)
        });
        let mut effects = DepositConsensusHostEffects {
            messages: self.consensus_step_messages(protocol, &step)?,
            prune: (step.entered_view.is_some() || step.commit.is_some()).then_some(
                DepositConsensusOutboxScope {
                    sequence: purpose.sequence(),
                    context: context.digest(),
                },
            ),
            terminal: None,
            committed: None,
        };
        if let Some(commit) = step.commit {
            let lane = protocol
                .consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            if lane.reducer.commit() != Some(&commit) {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            let admitted = lane
                .admitted_values
                .get(&commit.value().digest())
                .ok_or(DepositServiceError::InvalidConsensusValue)?
                .clone();
            if let Some(slot) = protocol.pending.get(&admitted.statement.sequence)
                && slot.statement != admitted.statement
            {
                return Err(DepositServiceError::SlotConflict(admitted.statement.sequence));
            }
            match (&admitted.statement.payload, &admitted.terminal_evidence) {
                (
                    LedgerPayload::ConsolidationCompletion(completion),
                    Some(ConsolidationTerminalEvidence::Completion(evidence)),
                ) => {
                    evidence.verify(protocol, completion, Some(context.binding().network))?;
                    effects.terminal = Some((
                        admitted.statement.clone(),
                        ConsolidationTerminalEvidence::Completion(evidence.clone()),
                    ));
                }
                (
                    LedgerPayload::ConsolidationAbandonment(abandonment),
                    Some(ConsolidationTerminalEvidence::Abandonment(evidence)),
                ) => {
                    evidence.verify(protocol, abandonment, context.binding().network)?;
                    effects.terminal = Some((
                        admitted.statement.clone(),
                        ConsolidationTerminalEvidence::Abandonment(evidence.clone()),
                    ));
                }
                (
                    LedgerPayload::LateConsolidationSettlement(settlement),
                    Some(ConsolidationTerminalEvidence::LateSettlement(evidence)),
                ) => {
                    evidence.verify(protocol, settlement, context.binding().network)?;
                    effects.terminal = Some((
                        admitted.statement.clone(),
                        ConsolidationTerminalEvidence::LateSettlement(evidence.clone()),
                    ));
                }
                (
                    LedgerPayload::Allocation(_)
                    | LedgerPayload::HandoffFence(_)
                    | LedgerPayload::Handoff(_),
                    None,
                ) => {}
                _ => return Err(DepositServiceError::InvalidConsensusValue),
            }
            // The async host layer must first commit/read back the local index safety slot. Only
            // then may it construct this party's ledger signature and add its peer effect.
            effects.committed = Some(admitted);
        }
        Ok(effects)
    }

    fn consensus_step_messages(
        &self,
        protocol: &DepositProtocolState,
        step: &ConsensusStep,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let lane =
            protocol.consensus_lane.as_ref().ok_or(DepositServiceError::ConsensusUnavailable)?;
        let context = lane.reducer.context().clone();
        let purpose = lane.purpose;
        let recipients = committee_recipients(context.committee(), self.party);
        let mut messages = Vec::new();
        for envelope in &step.broadcast {
            let decoded = decode_consensus_message(&context, envelope)?;
            let operation = if matches!(decoded.body, ConsensusMessageBody::Proposal(_)) {
                DepositOperation::ConsensusProposal
            } else {
                DepositOperation::ConsensusMessage
            };
            let body = postcard::to_allocvec(&DepositConsensusWire::envelope(
                context.clone(),
                purpose,
                envelope.clone(),
            ))?;
            messages.extend(
                recipients
                    .iter()
                    .copied()
                    .map(|party| (purpose.sequence(), party, operation, body.clone())),
            );
        }
        if let Some(certificate) = &step.relay_view_certificate {
            let body = postcard::to_allocvec(&DepositConsensusWire::view_certificate(
                context.clone(),
                purpose,
                certificate.clone(),
            ))?;
            messages.extend(recipients.iter().copied().map(|party| {
                (purpose.sequence(), party, DepositOperation::ConsensusCertificate, body.clone())
            }));
        }
        if let Some(certificate) = &step.relay_commit_certificate {
            let body = postcard::to_allocvec(&DepositConsensusWire::commit_certificate(
                context,
                purpose,
                certificate.clone(),
            ))?;
            messages.extend(recipients.iter().copied().map(|party| {
                (purpose.sequence(), party, DepositOperation::ConsensusCertificate, body.clone())
            }));
        }
        Ok(messages)
    }

    async fn commit_consensus_protocol(
        &self,
        runtime: &mut DepositRuntime,
        mut protocol: DepositProtocolState,
        mut effects: DepositConsensusHostEffects,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        if let Some(admitted) = effects.committed.take() {
            let historical = self.historical_issuer_for_statement(&admitted.statement).await?;
            let preflight = self.verified_index_preflight(&admitted.statement).await?;
            let terminal_admission = verified_terminal_admission(
                &protocol,
                &admitted.statement,
                self.scenario.quic_network_id()?,
            )?;
            let recognition = match &admitted.statement.payload {
                LedgerPayload::Allocation(allocation) => Some(
                    runtime
                        .snapshot
                        .worker()
                        .ok_or(DepositServiceError::MissingScannerAnchor)?
                        .scan_state()
                        .verify_recognition_anchor(allocation.recognition_anchor)?,
                ),
                LedgerPayload::HandoffFence(_)
                | LedgerPayload::Handoff(_)
                | LedgerPayload::ConsolidationCompletion(_)
                | LedgerPayload::ConsolidationAbandonment(_)
                | LedgerPayload::LateConsolidationSettlement(_) => None,
            };
            protocol.reserve(
                admitted.statement.clone(),
                admitted.admitted_at,
                &runtime.deriver,
                recognition.as_ref(),
                historical.as_ref(),
                terminal_admission.as_ref(),
                &preflight,
            )?;
            // This CAS burns the exact ledger slot before `stage_local_attestation` is allowed to
            // construct signature bytes.
            self.commit_reserved_ledger_lock(runtime, protocol, &admitted.statement).await?;
            protocol = runtime.protocol.clone();
            let attestation =
                protocol.stage_local_attestation(admitted.statement.sequence, identity)?;
            effects.messages.extend(self.attestation_messages(
                &protocol,
                admitted.statement,
                attestation,
            )?);
        }
        let encoded = protocol.encode_local(&runtime.deriver)?;
        let archive_head = runtime.snapshot.archive_head()?;
        if let Some((statement, ConsolidationTerminalEvidence::Completion(evidence))) =
            &effects.terminal
        {
            if protocol
                .pending
                .get(&statement.sequence)
                .is_none_or(|slot| slot.statement != *statement)
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            let LedgerPayload::ConsolidationCompletion(completion) = &statement.payload else {
                return Err(DepositServiceError::InvalidProtocolState);
            };
            evidence.verify(&protocol, completion, Some(self.scenario.quic_network_id()?))?;
            let local_roast = runtime
                .snapshot
                .consolidation_roasts
                .get(&completion.id())
                .map(|bytes| ConsolidationRoast::decode_authenticated_snapshot(bytes))
                .transpose()?;
            if let Some(roast) = &local_roast {
                let view = evidence.slot.roast_view();
                let (_, intent, _) = roast
                    .certified_intent(view)
                    .ok_or(DepositServiceError::InvalidByzantineConsolidationState)?;
                if roast.family_digest() != evidence.family
                    || roast.expected_slot(view)? != evidence.slot
                    || roast.wire_binding(view)? != evidence.binding
                    || intent.attempt() != completion.attempt()
                    || roast.authorization() != completion.authorization()
                    || roast.sweep_id() != completion.plan().id
                {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
            }
            let current_roast_archive_head = runtime.snapshot.roast_attempt_archive_head();
            let mut staged_roast_archive_head = current_roast_archive_head;
            let mut staged_roast_archive = None;
            if let Some(roast) = &local_roast {
                let stage = self.stage_hot_roast_attempts(staged_roast_archive_head, roast).await?;
                staged_roast_archive_head = Self::compose_roast_archive_stage(
                    &mut staged_roast_archive,
                    staged_roast_archive_head,
                    stage,
                )?;
                let mapping = self
                    .roast_archive
                    .stage_transaction_mapping(
                        staged_roast_archive_head,
                        evidence.family,
                        evidence.slot.roast_view(),
                        completion.plan().clone(),
                        evidence.key_images.clone(),
                        evidence.endorsements.clone(),
                        &mut rand_core::OsRng,
                    )
                    .await?;
                staged_roast_archive_head = Self::compose_roast_archive_stage(
                    &mut staged_roast_archive,
                    staged_roast_archive_head,
                    mapping,
                )?;
            }

            // Adopt the BA-selected candidate before creating a ledger attestation. A party with
            // the private family independently reconstructs and validates the exact attempt. A
            // lagger which never received PreparedSweepIntent installs only a public terminal
            // input/session/key-image tombstone; that record cannot authorize a nonce or become a
            // locally signable SweepRecord. Both paths share this snapshot CAS with the pending
            // statement and all BA/attestation effects.
            let mut worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let mut consolidation = runtime.snapshot.consolidation()?;
            let certified_key_images = canonicalize_certified_sweep_key_images(
                evidence
                    .key_images
                    .value()
                    .ok_or(DepositServiceError::InvalidConsensusValue)?
                    .key_images(),
            )?;
            let _verified_public = worker.verify_public_sweep_completion(
                statement.digest(),
                completion.authorization(),
                completion.plan(),
                completion.attempt(),
                completion.signed_binding(),
                completion.signed_transaction(),
                certified_key_images,
            )?;
            let has_private_family = worker.scan_state().sweep(completion.plan().id).is_some();
            let consolidation_effect = if has_private_family {
                let verified = worker.verify_certified_sweep_signing_attempt(
                    completion.plan().id,
                    completion.attempt(),
                    evidence.slot.committee(),
                )?;
                worker.adopt_verified_portable_sweep_family_candidate(
                    &verified,
                    completion.signed_transaction(),
                )?;
                consolidation.record_verified_portable_signed_attempt(
                    completion.id(),
                    verified,
                    completion.signed_binding(),
                )?
            } else {
                consolidation.record_certified_public_terminal_completion(
                    completion.authorization().clone(),
                    completion.attempt().clone(),
                    completion.signed_binding(),
                )?
            };
            let expected_worker_revision = worker.revision();
            let consolidation_commitment =
                consolidation_effect.as_ref().map(ConsolidationPersistEffect::state_commitment);
            let mut snapshot = runtime.snapshot.clone();
            snapshot.replace_all_and_enqueue(encoded, worker, &consolidation, effects.messages)?;
            if local_roast.is_some() {
                snapshot.seal_roast_completion_and_prune_outbox_in_place(
                    evidence.family,
                    evidence.slot.roast_view(),
                    evidence.attempt_prefix,
                    statement.digest(),
                    evidence.digest()?,
                )?;
            }
            snapshot.install_roast_attempt_archive_head(
                current_roast_archive_head,
                staged_roast_archive_head,
            )?;
            if let Some(scope) = effects.prune {
                snapshot.prune_consensus_outbox_in_place(scope)?;
            }
            let heads_changed = snapshot.install_archive_head(archive_head)?;
            if heads_changed && snapshot.revision == runtime.snapshot.revision {
                snapshot.revision = runtime.snapshot.next_revision()?;
            }
            validate_consolidation_alignment(self, &protocol, &snapshot, &consolidation).await?;
            let durable = self.repository.persist_and_read_back(&snapshot).await?;
            if staged_roast_archive
                .as_ref()
                .is_some_and(|stage| stage.head != durable.roast_attempt_archive_head())
            {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
            let durable_worker =
                durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if durable_worker.revision() != expected_worker_revision {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
            let durable_consolidation = durable.consolidation()?;
            if let (Some(effect), Some(commitment)) =
                (consolidation_effect, consolidation_commitment)
            {
                let _ = durable_consolidation.persisted_receipt_after_cas(
                    effect,
                    durable_consolidation.revision(),
                    commitment,
                )?;
            }
            runtime.protocol = protocol;
            runtime.snapshot = durable;
            runtime.consolidation = durable_consolidation;
            return Ok(());
        }
        if let Some((statement, ConsolidationTerminalEvidence::LateSettlement(evidence))) =
            &effects.terminal
        {
            if protocol
                .pending
                .get(&statement.sequence)
                .is_none_or(|slot| slot.statement != *statement)
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            let LedgerPayload::LateConsolidationSettlement(settlement) = &statement.payload else {
                return Err(DepositServiceError::InvalidProtocolState);
            };
            let network = self.scenario.quic_network_id()?;
            evidence.verify(&protocol, settlement, network)?;
            let lane = protocol
                .consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            let commit = lane.reducer.commit().ok_or(DepositServiceError::ConsensusUnavailable)?;
            let decided = DepositConsensusValue::decode(commit.value())?;
            if decided.statement != *statement
                || decided.terminal_evidence
                    != Some(ConsolidationTerminalEvidence::LateSettlement(evidence.clone()))
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            let inclusion_certificate = commit.digest();
            let completion = settlement.historical_completion();
            let portable_record = evidence.completion_proof.record();
            let portable_mapping = evidence.completion_proof.mapping();
            let LedgerPayload::ConsolidationAbandonment(abandonment) =
                &evidence.abandonment_statement.payload
            else {
                return Err(DepositServiceError::InvalidLateConsolidationSettlement);
            };
            let current_roast_archive_head = runtime.snapshot.roast_attempt_archive_head();
            let mapping = self
                .roast_archive
                .stage_transaction_mapping(
                    current_roast_archive_head,
                    portable_record.family(),
                    portable_record.view(),
                    portable_mapping.plan().clone(),
                    portable_mapping.key_image_certificate().clone(),
                    portable_mapping.endorsements().to_vec(),
                    &mut rand_core::OsRng,
                )
                .await?;
            let staged_roast_archive_head = mapping.ensure_cas(current_roast_archive_head)?;
            let archived = self
                .roast_archive
                .verify_prefix_transaction(
                    staged_roast_archive_head,
                    runtime.deriver.wallet_id(),
                    abandonment.attempt_prefix(),
                    completion.transaction_id(),
                )
                .await?;
            if archived.attempt_record() != portable_record
                || archived.membership_proof() != evidence.completion_proof.membership()
            {
                return Err(DepositServiceError::InvalidLateConsolidationSettlement);
            }
            let prior_evidence = self
                .authenticated_portable_terminal_by_sweep(completion.plan().id)
                .await?
                .ok_or(DepositServiceError::InvalidLateConsolidationSettlement)?;
            let prior = &prior_evidence.terminal;
            let worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            validate_late_settlement_observation_locally(&worker, settlement)?;
            let inclusion = VerifiedCanonicalSweepInclusion::from_current_committee_certificate(
                inclusion_certificate,
                portable_record.family(),
                completion.transaction_id(),
                consolidation_signed_bytes_binding(completion.signed_transaction().as_bytes()),
                abandonment.attempt_prefix(),
                settlement.inclusion(),
                settlement.observation_tip(),
                settlement.finality_depth(),
            )?;
            let (_verified_public, verified_archived) = worker
                .verify_archived_prefix_sweep_completion(
                    inclusion_certificate,
                    completion.plan(),
                    archived,
                    inclusion,
                    prior,
                )?;
            let mut consolidation = runtime.snapshot.consolidation()?;
            let consolidation_effect = consolidation
                .record_verified_archived_chain_authoritative_settlement(
                    completion.id(),
                    verified_archived,
                )?;
            let expected_worker_revision = worker.revision();
            let consolidation_commitment =
                consolidation_effect.as_ref().map(ConsolidationPersistEffect::state_commitment);
            let mut snapshot = runtime.snapshot.clone();
            snapshot.replace_all_and_enqueue(encoded, worker, &consolidation, effects.messages)?;
            snapshot.install_roast_attempt_archive_head(
                current_roast_archive_head,
                staged_roast_archive_head,
            )?;
            if let Some(scope) = effects.prune {
                snapshot.prune_consensus_outbox_in_place(scope)?;
            }
            let heads_changed = snapshot.install_archive_head(archive_head)?;
            if heads_changed && snapshot.revision == runtime.snapshot.revision {
                snapshot.revision = runtime.snapshot.next_revision()?;
            }
            validate_consolidation_alignment(self, &protocol, &snapshot, &consolidation).await?;
            let durable = self.repository.persist_and_read_back(&snapshot).await?;
            if mapping.head != durable.roast_attempt_archive_head() {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
            let durable_worker =
                durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if durable_worker.revision() != expected_worker_revision {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
            let durable_consolidation = durable.consolidation()?;
            if let (Some(effect), Some(commitment)) =
                (consolidation_effect, consolidation_commitment)
            {
                let _ = durable_consolidation.persisted_receipt_after_cas(
                    effect,
                    durable_consolidation.revision(),
                    commitment,
                )?;
            }
            runtime.protocol = protocol;
            runtime.snapshot = durable;
            runtime.consolidation = durable_consolidation;
            return Ok(());
        }
        if let Some((statement, ConsolidationTerminalEvidence::Abandonment(evidence))) =
            &effects.terminal
        {
            if protocol
                .pending
                .get(&statement.sequence)
                .is_none_or(|slot| slot.statement != *statement)
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
            let LedgerPayload::ConsolidationAbandonment(abandonment) = &statement.payload else {
                return Err(DepositServiceError::InvalidProtocolState);
            };
            let network = self.scenario.quic_network_id()?;
            evidence.verify(&protocol, abandonment, network)?;
            let current_roast_archive_head = runtime.snapshot.roast_attempt_archive_head();
            let mut staged_roast_archive_head = current_roast_archive_head;
            let mut staged_roast_archive = None;
            if let Some(bytes) = runtime.snapshot.consolidation_roasts.get(&abandonment.id()) {
                let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
                if roast.family_digest() != abandonment.family()
                    || roast.attempt_prefix_seal()? != abandonment.attempt_prefix()
                {
                    return Err(DepositServiceError::InvalidByzantineConsolidationState);
                }
                let stage =
                    self.stage_hot_roast_attempts(staged_roast_archive_head, &roast).await?;
                staged_roast_archive_head = Self::compose_roast_archive_stage(
                    &mut staged_roast_archive,
                    staged_roast_archive_head,
                    stage,
                )?;
                let archive_plan = runtime
                    .snapshot
                    .worker()
                    .and_then(|worker| {
                        worker.scan_state().sweep(abandonment.authorization().sweep_id())
                    })
                    .ok_or(DepositServiceError::InvalidConsolidationAbandonment)
                    .and_then(|sweep| {
                        PreparedSweepIntent::decode(
                            sweep.signing_intent.prepared_sweep_intent_bytes(),
                        )
                        .map_err(DepositServiceError::from)
                    })?
                    .plan()
                    .clone();
                for (view, key_images, endorsements) in
                    roast.endorsed_candidate_completion_evidence()?
                {
                    let mapping = self
                        .roast_archive
                        .stage_transaction_mapping(
                            staged_roast_archive_head,
                            abandonment.family(),
                            view,
                            archive_plan.clone(),
                            key_images,
                            endorsements,
                            &mut rand_core::OsRng,
                        )
                        .await?;
                    staged_roast_archive_head = Self::compose_roast_archive_stage(
                        &mut staged_roast_archive,
                        staged_roast_archive_head,
                        mapping,
                    )?;
                }
            }
            let key_images = abandonment
                .key_images()
                .value()
                .ok_or(DepositServiceError::InvalidConsensusValue)?
                .key_images()
                .to_vec();
            let mut worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let has_private_family =
                worker.scan_state().sweep(abandonment.authorization().sweep_id()).is_some();
            if has_private_family {
                worker.record_certified_sweep_abandonment(
                    abandonment.authorization().sweep_id(),
                    abandonment.attempt(),
                    abandonment.slot().committee(),
                    abandonment.ancestor(),
                )?;
            }
            let _public_abandonment = worker.verify_public_sweep_abandonment(
                statement.digest(),
                abandonment.authorization(),
                abandonment.attempt_prefix(),
                abandonment.attempt(),
                abandonment.sweep_sequence(),
                abandonment.inputs().to_vec(),
                key_images,
                abandonment.missing_inputs().to_vec(),
                abandonment.ancestor(),
                abandonment.observation_tip(),
                abandonment.finality_depth(),
            )?;
            let mut consolidation = runtime.snapshot.consolidation()?;
            let consolidation_effect = consolidation.record_certified_public_abandonment(
                abandonment.authorization().clone(),
                abandonment.attempt().clone(),
                abandonment.ancestor(),
            )?;
            let expected_worker_revision = worker.revision();
            let consolidation_commitment =
                consolidation_effect.as_ref().map(ConsolidationPersistEffect::state_commitment);
            let mut snapshot = runtime.snapshot.clone();
            snapshot.replace_all_and_enqueue(encoded, worker, &consolidation, effects.messages)?;
            if snapshot.consolidation_roasts.contains_key(&abandonment.id()) {
                snapshot.seal_roast_abandonment_and_prune_outbox_in_place(
                    abandonment.family(),
                    abandonment.slot().roast_view(),
                    abandonment.attempt_prefix(),
                    statement.digest(),
                    evidence.digest()?,
                )?;
            }
            snapshot.install_roast_attempt_archive_head(
                current_roast_archive_head,
                staged_roast_archive_head,
            )?;
            snapshot.prune_abandonment_observation_in_place(evidence.observation.digest()?)?;
            if let Some(scope) = effects.prune {
                snapshot.prune_consensus_outbox_in_place(scope)?;
            }
            let heads_changed = snapshot.install_archive_head(archive_head)?;
            if heads_changed && snapshot.revision == runtime.snapshot.revision {
                snapshot.revision = runtime.snapshot.next_revision()?;
            }
            validate_consolidation_alignment(self, &protocol, &snapshot, &consolidation).await?;
            let durable = self.repository.persist_and_read_back(&snapshot).await?;
            if staged_roast_archive
                .as_ref()
                .is_some_and(|stage| stage.head != durable.roast_attempt_archive_head())
            {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
            let durable_worker =
                durable.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if durable_worker.revision() != expected_worker_revision {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
            let durable_consolidation = durable.consolidation()?;
            if let (Some(effect), Some(commitment)) =
                (consolidation_effect, consolidation_commitment)
            {
                let _ = durable_consolidation.persisted_receipt_after_cas(
                    effect,
                    durable_consolidation.revision(),
                    commitment,
                )?;
            }
            runtime.protocol = protocol;
            runtime.snapshot = durable;
            runtime.consolidation = durable_consolidation;
            return Ok(());
        }
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_reducer_prune_consensus_and_enqueue(
            encoded,
            effects.prune,
            effects.messages,
        )?;
        let heads_changed = snapshot.install_archive_head(archive_head)?;
        if heads_changed && snapshot.revision == runtime.snapshot.revision {
            snapshot.revision = runtime.snapshot.next_revision()?;
        }
        validate_consolidation_alignment(self, &protocol, &snapshot, &runtime.consolidation)
            .await?;
        if snapshot.revision != runtime.snapshot.revision {
            self.repository.persist(&snapshot).await?;
        }
        runtime.protocol = protocol;
        runtime.snapshot = snapshot;
        Ok(())
    }

    /// Durably pin an exact successor without authorizing any handoff signature.
    ///
    /// Pinning happens before the quiescence check so new ingress closes while an existing
    /// consolidation finishes. The supplied root is only a proposed identity at this phase; it
    /// is deliberately not retained as signing authority. [`Self::progress_certified_handoff`]
    /// must be called after the host durably persists and re-authenticates the activation proof.
    pub async fn begin_handoff(
        &self,
        source: &EpochPublic,
        target: &EpochPublic,
        proposed_activation_root: [u8; 32],
        now_unix_ms: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        target.validate()?;
        if proposed_activation_root == [0; 32] {
            return Err(DepositServiceError::WrongRegistry);
        }
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let trust = validate_trusted_handoff_target(
            &self.scenario,
            &runtime.protocol,
            &runtime.deriver,
            target,
        )?;
        let active = runtime.protocol.registry.active();
        if source.committee != *active.committee()
            || source.key_id != active.key_id()
            || source.group_key_bytes() != active.group_key()
            || source.activation_digest()? != active.activation()
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        let target_fault_bound = trust.fault_bound;
        if runtime.protocol.pending_handoff.as_ref().is_some_and(|pending| pending != target) {
            return Err(DepositServiceError::WrongRegistry);
        }
        if runtime.protocol.pending_handoff_source.as_ref().is_some_and(|pending| pending != source)
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        if runtime
            .protocol
            .pending_handoff_root
            .is_some_and(|root| root != proposed_activation_root)
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        if runtime
            .protocol
            .pending_handoff_fault_bound
            .is_some_and(|fault_bound| fault_bound != target_fault_bound)
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        validate_consensus_now(now_unix_ms)?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;

        // The exact target is the transition checkpoint, not the later handoff proposal. Persist
        // it first so every new allocation and consolidation Start closes immediately, even when
        // an already released consolidation still needs its old-epoch share. A retry resumes from
        // this same target after that exact obligation becomes portable.
        if runtime.protocol.pending_handoff.is_none() {
            let mut candidate = runtime.protocol.clone();
            candidate.pending_handoff = Some(target.clone());
            candidate.pending_handoff_source = Some(source.clone());
            candidate.pending_handoff_fault_bound = Some(target_fault_bound);
            candidate.pending_handoff_root = None;
            candidate.pending_handoff_fence = None;
            self.commit_protocol(runtime, candidate).await?;
        }
        require_consolidation_quiescent(self, runtime).await
    }

    /// Authenticate the host-persisted activation proof and only then start/resume the terminal
    /// old-quorum handoff consensus lane.
    pub async fn progress_certified_handoff(
        &self,
        source: &EpochPublic,
        target: &EpochPublic,
        certified_activation_root: [u8; 32],
        now_unix_ms: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        source.validate()?;
        target.validate()?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let trust = validate_trusted_handoff_target(
            &self.scenario,
            &runtime.protocol,
            &runtime.deriver,
            target,
        )?;
        let active = runtime.protocol.registry.active();
        if source.committee.digest() != active.committee().digest()
            || source.key_id != active.key_id()
            || source.group_key_bytes() != active.group_key()
            || source.activation_digest()? != active.activation()
            || runtime.protocol.pending_handoff.as_ref() != Some(target)
            || runtime.protocol.pending_handoff_source.as_ref() != Some(source)
            || runtime.protocol.pending_handoff_fault_bound != Some(trust.fault_bound)
            || runtime
                .protocol
                .pending_handoff_root
                .is_some_and(|root| root != certified_activation_root)
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        validate_consensus_now(now_unix_ms)?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        VerifiedRegistryHandoffTarget::from_verified_activation(
            Some(source),
            target.clone(),
            trust.fault_bound,
            certified_activation_root,
            &runtime.deriver,
        )?;
        require_consolidation_quiescent(self, runtime).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.pending_handoff_root = Some(certified_activation_root);
        let mut effects = DepositConsensusHostEffects::default();
        self.start_deposit_lane_if_ready(
            &mut candidate,
            &runtime.deriver,
            runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?,
            now_unix_ms,
            identity,
            &mut effects,
        )?;
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await
    }

    /// Confirm that the atomic handoff/index checkpoint CAS already installed the exact certified
    /// successor. This method never replays ledger history and never performs a second registry
    /// mutation: before the coupled CAS it returns a retryable gap; afterwards it is idempotent.
    pub async fn apply_certified_handoff(
        &self,
        source: &EpochPublic,
        target: &EpochPublic,
        certified_activation_root: [u8; 32],
    ) -> Result<(), DepositServiceError> {
        source.validate()?;
        target.validate()?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        let (source_epoch, target_epoch) = {
            let mut compact_guard = self.compact_registry.lock().await;
            let compact_store = compact_guard
                .as_mut()
                .ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
            (
                compact_store.lookup_epoch(source.committee.epoch).await?,
                if runtime.protocol.registry.active_epoch() == target.committee.epoch {
                    Some(compact_store.lookup_epoch(target.committee.epoch).await?)
                } else {
                    None
                },
            )
        };
        let source_link = source_epoch.link();
        if source_link.committee().digest() != source.committee.digest()
            || source_link.key_id() != source.key_id
            || source_link.group_key() != source.group_key_bytes()
            || source_link.activation() != source.activation_digest()?
        {
            return Err(DepositServiceError::WrongRegistry);
        }
        let trust = validate_trusted_committee_transition(
            &self.scenario,
            source_link.committee(),
            source_link.fault_bound(),
            &target.committee,
        )?;
        let verified_target = VerifiedRegistryHandoffTarget::from_verified_activation(
            Some(source),
            target.clone(),
            trust.fault_bound,
            certified_activation_root,
            &runtime.deriver,
        )?;
        let active_epoch = runtime.protocol.registry.active_epoch();
        if active_epoch == target.committee.epoch {
            let active = runtime.protocol.registry.active();
            let target_link =
                target_epoch.as_ref().ok_or(DepositServiceError::WrongRegistry)?.link();
            if active.committee().digest() == target.committee.digest()
                && active.key_id() == verified_target.key_id()
                && active.group_key() == verified_target.group_key()
                && active.fault_bound() == verified_target.fault_bound()
                && active.activation_binding() == verified_target.activation()
                && target_link.committee().digest() == target.committee.digest()
                && target_link.key_id() == verified_target.key_id()
                && target_link.group_key() == verified_target.group_key()
                && target_link.fault_bound() == verified_target.fault_bound()
                && target_link.activation() == verified_target.activation()
                && target_link.certified_activation_root()
                    == verified_target.certified_activation_root()
            {
                return Ok(());
            }
            return Err(DepositServiceError::WrongRegistry);
        }
        if active_epoch == source.committee.epoch {
            let active = runtime.protocol.registry.active();
            if active.committee().digest() != source.committee.digest()
                || active.key_id() != source.key_id
                || active.group_key() != source.group_key_bytes()
                || active.activation_binding() != source.activation_digest()?
                || runtime.protocol.pending_handoff.as_ref() != Some(target)
                || runtime.protocol.pending_handoff_source.as_ref() != Some(source)
                || runtime.protocol.pending_handoff_fault_bound != Some(trust.fault_bound)
                || runtime.protocol.pending_handoff_root != Some(certified_activation_root)
                || runtime.protocol.pending_handoff_fence.is_none()
            {
                return Err(DepositServiceError::WrongRegistry);
            }
            return Err(DepositServiceError::CertifiedHandoffUnavailable(target.committee.epoch));
        }
        Err(DepositServiceError::WrongRegistry)
    }

    /// Apply a leader proposal received over authenticated QUIC and durably stage this party's
    /// one permitted attestation for the slot.
    pub async fn handle_allocate(
        &self,
        authenticated_party: PartyId,
        wire: DepositAllocateWire,
        now: u64,
        identity: &Identity,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        validate_allocate_wire(runtime, authenticated_party, &wire)?;
        if !statement_is_consensus_committed(&runtime.protocol, &wire.statement)? {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let sequence = wire.statement.sequence;
        if sequence < runtime.protocol.ledger.next_sequence() {
            let existing = {
                let mut index = self.deposit_index.lock().await;
                let store =
                    index.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
                store.lookup_portable_state(PortableStateQuery::Sequence(sequence)).await?
            };
            let digest = match existing {
                Some(PortableStateRecord::Statement(record)) => record.digest(),
                None | Some(_) => return Err(DepositServiceError::InvalidDepositIndexCheckpoint),
            };
            if digest != wire.statement.digest() {
                return Err(DepositServiceError::SlotConflict(sequence));
            }
            return Ok(());
        }
        match &wire.statement.payload {
            LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_) => {
                require_consolidation_quiescent(self, runtime).await?;
            }
            LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_)
            | LedgerPayload::Allocation(_) => {}
        }
        let completion_authorized = match &wire.statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => {
                let worker =
                    runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
                local_completion_matches(worker, &runtime.consolidation, completion)?
                    || public_terminal_completion_matches(&wire.statement, &runtime.consolidation)
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => false,
        };
        if matches!(&wire.statement.payload, LedgerPayload::ConsolidationCompletion(_))
            && !completion_authorized
        {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        let historical_issuer = match &wire.statement.payload {
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                let epoch = settlement.historical_completion().attempt().epoch();
                let mut registry = self.compact_registry.lock().await;
                let store = registry
                    .as_mut()
                    .ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
                Some(store.lookup_issuer_window(epoch).await?)
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_) => None,
        };
        let preflight = self.verified_index_preflight(&wire.statement).await?;
        let terminal_admission = verified_terminal_admission(
            &runtime.protocol,
            &wire.statement,
            self.scenario.quic_network_id()?,
        )?;
        let recognition = match &wire.statement.payload {
            LedgerPayload::Allocation(allocation) => Some(
                runtime
                    .snapshot
                    .worker()
                    .ok_or(DepositServiceError::MissingScannerAnchor)?
                    .scan_state()
                    .verify_recognition_anchor(allocation.recognition_anchor)?,
            ),
            LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => None,
        };
        let mut candidate = runtime.protocol.clone();
        candidate.reserve(
            wire.statement.clone(),
            now,
            &runtime.deriver,
            recognition.as_ref(),
            historical_issuer.as_ref(),
            terminal_admission.as_ref(),
            &preflight,
        )?;
        self.commit_reserved_ledger_lock(runtime, candidate, &wire.statement).await?;
        let mut candidate = runtime.protocol.clone();
        let attestation = candidate.stage_local_attestation(sequence, identity)?;
        let messages = self.attestation_messages(&candidate, wire.statement, attestation)?;
        self.commit_protocol_with_messages(runtime, candidate, messages).await
    }

    async fn start_or_resume_index_checkpoint_round(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        entry: CertifiedLedgerEntry,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        self.offer_checkpoint_consensus_candidate(
            runtime,
            identity,
            DepositIndexCheckpointCandidate::Ledger(entry),
            now,
        )
        .await?;
        self.resume_decided_checkpoint_round(runtime, identity, now).await
    }

    async fn start_or_resume_deposit_observation_checkpoint_round(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        observation: CertifiedDepositObservation,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        self.offer_checkpoint_consensus_candidate(
            runtime,
            identity,
            DepositIndexCheckpointCandidate::DepositObservation(observation),
            now,
        )
        .await?;
        self.resume_decided_checkpoint_round(runtime, identity, now).await
    }

    async fn offer_checkpoint_consensus_candidate(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        operation: DepositIndexCheckpointCandidate,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        if runtime.protocol.index_checkpoint.is_some()
            || runtime.protocol.observation_checkpoint.is_some()
        {
            runtime.protocol.committed_checkpoint_selection(&operation)?;
            return Ok(());
        }
        self.authenticate_checkpoint_consensus_candidate(runtime, &operation, now).await?;
        let checkpoint_sequence = runtime
            .protocol
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let purpose =
            DepositConsensusPurpose::NextIndexCheckpoint { sequence: checkpoint_sequence };
        let previous_head = PortableDepositIndexHead::from_head(
            runtime.snapshot.deposit_index_checkpoint().portable_head(),
        )?;
        let context = deposit_index_checkpoint_consensus_context(
            self.scenario.quic_network_id()?,
            &runtime.protocol.registry,
            checkpoint_sequence,
            &previous_head,
        )?;
        let value = operation.to_consensus_value()?;
        let mut candidate = runtime.protocol.clone();
        match &operation {
            DepositIndexCheckpointCandidate::Ledger(entry) => {
                let historical = self.historical_issuer_for_statement(&entry.statement).await?;
                candidate.retain_certified_pending(entry, historical.as_ref())?;
            }
            DepositIndexCheckpointCandidate::DepositObservation(observation) => {
                candidate.retain_certified_deposit_observation(observation)?;
            }
        }
        let mut step = ConsensusStep::default();
        if candidate.checkpoint_consensus_lane.is_none() {
            let mut reducer = DepositConsensus::new(context.clone(), self.party)?;
            step = reducer.start(identity, value)?;
            candidate.checkpoint_consensus_lane = Some(DurableDepositCheckpointConsensusLane::new(
                purpose,
                reducer,
                now,
                self.consensus_deadline(now.saturating_mul(1_000))?,
            )?);
        }
        let lane = candidate
            .checkpoint_consensus_lane
            .as_mut()
            .ok_or(DepositServiceError::ConsensusUnavailable)?;
        if lane.purpose != purpose || lane.reducer.context() != &context {
            return Err(DepositServiceError::ConsensusUnavailable);
        }
        install_checkpoint_consensus_admission(lane, now, operation)?;
        let effects = self.checkpoint_consensus_step_effects(
            &mut candidate,
            now.saturating_mul(1_000),
            step,
        )?;
        self.commit_consensus_protocol(runtime, candidate, effects, identity).await
    }

    async fn resume_decided_checkpoint_round(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        let Some(commit) = runtime
            .protocol
            .checkpoint_consensus_lane
            .as_ref()
            .and_then(|lane| lane.reducer.commit())
            .cloned()
        else {
            return Ok(());
        };
        match DepositIndexCheckpointCandidate::from_consensus_value(commit.value())? {
            DepositIndexCheckpointCandidate::Ledger(entry) => {
                self.start_or_resume_decided_index_checkpoint_round(runtime, identity, entry, now)
                    .await
            }
            DepositIndexCheckpointCandidate::DepositObservation(observation) => {
                self.start_or_resume_decided_deposit_observation_checkpoint_round(
                    runtime,
                    identity,
                    observation,
                    now,
                )
                .await
            }
        }
    }

    fn checkpoint_consensus_step_effects(
        &self,
        protocol: &mut DepositProtocolState,
        now_unix_ms: u64,
        mut step: ConsensusStep,
    ) -> Result<DepositConsensusHostEffects, DepositServiceError> {
        let (purpose, context, current_view) = {
            let lane = protocol
                .checkpoint_consensus_lane
                .as_mut()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            if let Some(view) = step.entered_view {
                lane.enter_view(view, self.consensus_deadline(now_unix_ms)?);
            }
            (lane.purpose, lane.reducer.context().clone(), lane.reducer.view())
        };
        step.broadcast.retain(|envelope| {
            consensus_envelope_relevant_to_view(&context, envelope, current_view).unwrap_or(false)
        });
        if let Some(commit) = &step.commit {
            let lane = protocol
                .checkpoint_consensus_lane
                .as_ref()
                .ok_or(DepositServiceError::ConsensusUnavailable)?;
            if lane.reducer.commit() != Some(commit)
                || lane.admitted_values.get(&commit.value().digest()).is_none()
            {
                return Err(DepositServiceError::InvalidProtocolState);
            }
        }
        Ok(DepositConsensusHostEffects {
            messages: self.checkpoint_consensus_step_messages(protocol, &step)?,
            prune: (step.entered_view.is_some() || step.commit.is_some()).then_some(
                DepositConsensusOutboxScope {
                    sequence: purpose.sequence(),
                    context: context.digest(),
                },
            ),
            terminal: None,
            committed: None,
        })
    }

    fn checkpoint_consensus_step_messages(
        &self,
        protocol: &DepositProtocolState,
        step: &ConsensusStep,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let lane = protocol
            .checkpoint_consensus_lane
            .as_ref()
            .ok_or(DepositServiceError::ConsensusUnavailable)?;
        let context = lane.reducer.context().clone();
        let purpose = lane.purpose;
        let recipients = committee_recipients(context.committee(), self.party);
        let mut messages = Vec::new();
        for envelope in &step.broadcast {
            let decoded = decode_consensus_message(&context, envelope)?;
            let operation = if matches!(decoded.body, ConsensusMessageBody::Proposal(_)) {
                DepositOperation::ConsensusProposal
            } else {
                DepositOperation::ConsensusMessage
            };
            let body = postcard::to_allocvec(&DepositConsensusWire::envelope(
                context.clone(),
                purpose,
                envelope.clone(),
            ))?;
            messages.extend(
                recipients
                    .iter()
                    .copied()
                    .map(|party| (purpose.sequence(), party, operation, body.clone())),
            );
        }
        if let Some(certificate) = &step.relay_view_certificate {
            let body = postcard::to_allocvec(&DepositConsensusWire::view_certificate(
                context.clone(),
                purpose,
                certificate.clone(),
            ))?;
            messages.extend(recipients.iter().copied().map(|party| {
                (purpose.sequence(), party, DepositOperation::ConsensusCertificate, body.clone())
            }));
        }
        if let Some(certificate) = &step.relay_commit_certificate {
            let body = postcard::to_allocvec(&DepositConsensusWire::commit_certificate(
                context,
                purpose,
                certificate.clone(),
            ))?;
            messages.extend(recipients.iter().copied().map(|party| {
                (purpose.sequence(), party, DepositOperation::ConsensusCertificate, body.clone())
            }));
        }
        Ok(messages)
    }

    fn adopt_certified_checkpoint_selection(
        &self,
        protocol: &mut DepositProtocolState,
        context: ConsensusContext,
        selection: CommitCertificate,
        operation: DepositIndexCheckpointCandidate,
        admitted_at: u64,
    ) -> Result<(), DepositServiceError> {
        let purpose = DepositConsensusPurpose::NextIndexCheckpoint {
            sequence: protocol
                .checkpoint_sequence
                .checked_add(1)
                .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?,
        };
        let mut lane = match protocol.checkpoint_consensus_lane.take() {
            Some(lane) => lane,
            None => DurableDepositCheckpointConsensusLane::new(
                purpose,
                DepositConsensus::new(context.clone(), self.party)?,
                admitted_at,
                self.consensus_deadline(admitted_at.saturating_mul(1_000))?,
            )?,
        };
        if lane.purpose != purpose || lane.reducer.context() != &context {
            return Err(DepositServiceError::ConsensusUnavailable);
        }
        install_checkpoint_consensus_admission(&mut lane, admitted_at, operation.clone())?;
        let expected = operation.to_consensus_value()?;
        lane.reducer
            .handle_commit_certificate_with_validator(selection, |value| value == &expected)?;
        protocol.checkpoint_consensus_lane = Some(lane);
        Ok(())
    }

    async fn start_or_resume_decided_index_checkpoint_round(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        entry: CertifiedLedgerEntry,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        if identity.party() != self.party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let historical = self.historical_issuer_for_statement(&entry.statement).await?;
        let verified_entry =
            entry.verify_active(&runtime.protocol.registry, historical.as_ref())?;
        if runtime.protocol.index_checkpoint.is_none() {
            if matches!(
                &entry.statement.payload,
                LedgerPayload::Allocation(allocation) if now >= allocation.created_at
            ) {
                return Err(DepositServiceError::AllocationExpired);
            }
            let staged = self
                .archive
                .stage_certified_ledger_entry(&entry, &verified_entry, &mut rand_core::OsRng)
                .await?;
            let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
            let (_, _, statement) = self
                .expected_index_checkpoint_material(
                    now,
                    &runtime.protocol.registry,
                    historical.as_ref(),
                    previous.as_ref(),
                    &entry,
                )
                .await?;
            let mut candidate = runtime.protocol.clone();
            candidate.begin_index_checkpoint(
                entry.clone(),
                staged.reference(),
                statement.clone(),
                now,
            )?;
            self.commit_index_checkpoint_signing_lock(
                runtime,
                candidate,
                statement.signing_slot(now)?,
            )
            .await?;
        }
        let lane = runtime
            .protocol
            .index_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .clone();
        if lane.ledger.statement != entry.statement {
            return Err(DepositServiceError::SlotConflict(entry.statement.sequence));
        }
        self.archive
            .authenticate_certified_entry_artifact(lane.ledger_artifact, &verified_entry)
            .await?;
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        let witness = match lane.witnesses.get(&self.party) {
            Some(witness) => witness.clone(),
            None => {
                self.sign_durable_index_checkpoint(
                    now,
                    identity,
                    &runtime.protocol.registry,
                    historical.as_ref(),
                    previous.as_ref(),
                    &lane.ledger,
                    &lane.statement,
                )
                .await?
            }
        };
        let mut candidate = runtime.protocol.clone();
        candidate.accept_index_checkpoint_witness(witness.clone())?;
        let context =
            DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?;
        let binding = DepositIndexCheckpointLedgerBinding::new(
            context,
            lane.statement.sequence(),
            lane.ledger_artifact,
            &lane.ledger,
        )?;
        let mut messages = self.certificate_messages(&candidate, lane.ledger.clone())?;
        messages.extend(self.index_checkpoint_attestation_messages(
            &candidate,
            binding,
            lane.statement,
            witness,
        )?);
        let completed = candidate.completed_index_checkpoint(
            self.scenario.quic_network_id()?,
            historical.as_ref(),
            previous.as_ref(),
        )?;
        match completed {
            Some(certificate) => {
                let r = self
                    .finalize_index_checkpoint_certificate(runtime, candidate, certificate, now)
                    .await;
                if let Err(e) = &r {
                    eprintln!("TRACE_FINALIZE (decided-round) error={e:?}");
                }
                r
            }
            None => self.commit_protocol_with_messages(runtime, candidate, messages).await,
        }
    }

    /// Drive at most one deterministic observation action. A live checkpoint is always resumed
    /// before a newly certified observation, and a certified observation is always checkpointed
    /// before this party signs another pending fact.
    async fn progress_deposit_observations_locked(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        now: u64,
    ) -> Result<bool, DepositServiceError> {
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        if let Some(lane) = runtime.protocol.observation_checkpoint.clone() {
            self.start_or_resume_deposit_observation_checkpoint_round(
                runtime,
                identity,
                lane.observation,
                now,
            )
            .await?;
            return Ok(true);
        }
        if let Some(observation) = runtime.protocol.next_certified_deposit_observation()? {
            self.start_or_resume_deposit_observation_checkpoint_round(
                runtime,
                identity,
                observation,
                now,
            )
            .await?;
            return Ok(true);
        }
        let statement = runtime
            .protocol
            .pending_observations
            .values()
            .filter(|slot| {
                !slot.attestations.contains_key(&self.party)
                    && runtime.protocol.observation_is_source_handoff_prefix(&slot.statement)
            })
            .min_by_key(|slot| (slot.statement.observed_block().height, slot.statement.output()))
            .map(|slot| slot.statement.clone());
        let Some(statement) = statement else {
            return Ok(false);
        };
        // This check intentionally precedes every state change in the peer-originated path. One
        // authenticated Byzantine member therefore cannot consume the global bounded reducer by
        // sending structurally valid observations which this party never scanned.
        self.verify_local_deposit_observation(runtime, &statement).await?;
        let protocol = runtime.protocol.clone();
        self.commit_deposit_observation_signing_lock(runtime, protocol, &statement).await?;
        let attestation =
            self.sign_durable_deposit_observation(runtime, identity, &statement).await?;
        let mut candidate = runtime.protocol.clone();
        let completed =
            candidate.accept_deposit_observation_attestation(&statement, attestation.clone())?;
        let mut messages = self.deposit_observation_statement_and_attestation_messages(
            &candidate,
            statement,
            attestation,
        )?;
        if let Some(observation) = completed.clone() {
            messages.extend(
                self.deposit_observation_certificate_messages(&candidate, observation.clone())?,
            );
        }
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        if let Some(observation) = completed {
            self.start_or_resume_deposit_observation_checkpoint_round(
                runtime,
                identity,
                observation,
                now,
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn start_or_resume_decided_deposit_observation_checkpoint_round(
        &self,
        runtime: &mut DepositRuntime,
        identity: &Identity,
        observation: CertifiedDepositObservation,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        let verified_observation = observation.verify_active(&runtime.protocol.registry)?;
        if runtime.protocol.observation_checkpoint.is_none() {
            // The checkpoint namespace is globally ordered. Retain the n-f observation and retry
            // after the currently durable ledger checkpoint completes rather than manufacturing
            // an independent sequence.
            if runtime.protocol.index_checkpoint.is_some() {
                return Ok(());
            }
            let staged = self
                .archive
                .stage_certified_deposit_observation(
                    &observation,
                    &verified_observation,
                    &mut rand_core::OsRng,
                )
                .await?;
            let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
            let (_, _, statement) = self
                .expected_deposit_observation_checkpoint_material(
                    now,
                    &runtime.protocol.registry,
                    previous.as_ref(),
                    &observation,
                )
                .await?;
            let mut candidate = runtime.protocol.clone();
            candidate.begin_deposit_observation_checkpoint(
                observation.clone(),
                staged.reference(),
                statement.clone(),
                now,
            )?;
            self.commit_index_checkpoint_signing_lock(
                runtime,
                candidate,
                statement.signing_slot(now)?,
            )
            .await?;
        }
        let lane = runtime
            .protocol
            .observation_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .clone();
        if lane.observation.statement != observation.statement {
            return Err(DepositServiceError::ObservationEquivocation);
        }
        self.archive
            .authenticate_certified_deposit_observation_artifact(
                lane.observation_artifact,
                &verified_observation,
            )
            .await?;
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        let witness = match lane.witnesses.get(&self.party) {
            Some(witness) => witness.clone(),
            None => {
                self.sign_durable_deposit_observation_checkpoint(
                    now,
                    identity,
                    &runtime.protocol.registry,
                    previous.as_ref(),
                    &lane.observation,
                    &lane.statement,
                )
                .await?
            }
        };
        let mut candidate = runtime.protocol.clone();
        candidate.accept_deposit_observation_checkpoint_witness(witness.clone())?;
        let context =
            DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?;
        let binding = DepositIndexCheckpointObservationBinding::new(
            context,
            lane.statement.sequence(),
            lane.observation_artifact,
            &lane.observation,
        )?;
        let mut messages =
            self.deposit_observation_certificate_messages(&candidate, lane.observation.clone())?;
        messages.extend(self.deposit_observation_checkpoint_attestation_messages(
            &candidate,
            binding,
            lane.statement,
            witness,
        )?);
        match candidate.completed_deposit_observation_checkpoint(
            self.scenario.quic_network_id()?,
            previous.as_ref(),
        )? {
            Some(certificate) => {
                self.finalize_deposit_observation_checkpoint_certificate(
                    runtime,
                    candidate,
                    certificate,
                    now,
                )
                .await
            }
            None => self.commit_protocol_with_messages(runtime, candidate, messages).await,
        }
    }

    /// Admit a proposal only after this party resolves its exact certified allocation and
    /// independently matches every chain fact against its retained confirmed scanner.
    pub async fn handle_deposit_observation(
        &self,
        authenticated_party: PartyId,
        wire: DepositObservationWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        if wire.version != DEPOSIT_WIRE_VERSION
            || wire.registry != runtime.protocol.registry.digest()
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        wire.statement.validate_active(&runtime.protocol.registry)?;
        if self.deposit_observation_is_portable(&wire.statement).await? {
            return Ok(());
        }
        self.replay_pending_worker_events(runtime).await?;
        let verified = self.verify_local_deposit_observation(runtime, &wire.statement).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.retain_locally_verified_deposit_observation(wire.statement.clone(), &verified)?;
        let messages = self.deposit_observation_statement_messages(&candidate, wire.statement)?;
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        self.progress_deposit_observations_locked(runtime, identity, now).await?;
        Ok(())
    }

    /// Retain an individual witness only after the same exact local scanner admission used by a
    /// proposal. The TLS sender must be the envelope signer.
    pub async fn handle_deposit_observation_attestation(
        &self,
        authenticated_party: PartyId,
        wire: DepositObservationAttestationWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        if wire.version != DEPOSIT_WIRE_VERSION
            || wire.registry != runtime.protocol.registry.digest()
            || wire.attestation.from != authenticated_party
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        if verify_deposit_observation_attestation(
            &wire.statement,
            &runtime.protocol.registry,
            &wire.attestation,
        )? != authenticated_party
        {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        if self.deposit_observation_is_portable(&wire.statement).await? {
            return Ok(());
        }
        self.replay_pending_worker_events(runtime).await?;
        let verified = self.verify_local_deposit_observation(runtime, &wire.statement).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.retain_locally_verified_deposit_observation(wire.statement.clone(), &verified)?;
        let completed = candidate
            .accept_deposit_observation_attestation(&wire.statement, wire.attestation.clone())?;
        let mut messages = self.deposit_observation_attestation_messages(
            &candidate,
            wire.statement,
            wire.attestation,
        )?;
        if let Some(observation) = completed.clone() {
            messages.extend(
                self.deposit_observation_certificate_messages(&candidate, observation.clone())?,
            );
        }
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        if let Some(observation) = completed {
            self.start_or_resume_deposit_observation_checkpoint_round(
                runtime,
                identity,
                observation,
                now,
            )
            .await?;
        } else {
            self.progress_deposit_observations_locked(runtime, identity, now).await?;
        }
        Ok(())
    }

    /// Quorum evidence is sufficient admission for a receiver which has not yet scanned the
    /// output locally. Applying it still requires the independent n-f checkpoint lane.
    pub async fn handle_deposit_observation_certificate(
        &self,
        authenticated_party: PartyId,
        wire: DepositObservationCertificateWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        if wire.version != DEPOSIT_WIRE_VERSION {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let verified = wire.observation.verify_active(&runtime.protocol.registry)?;
        if verified.signers().len() != usize::from(verified.required()) {
            return Err(DepositServiceError::InvalidDepositObservation);
        }
        if self.deposit_observation_is_portable(&wire.observation.statement).await? {
            return Ok(());
        }
        self.replay_pending_worker_events(runtime).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.retain_certified_deposit_observation(&wire.observation)?;
        let messages =
            self.deposit_observation_certificate_messages(&candidate, wire.observation.clone())?;
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        self.start_or_resume_deposit_observation_checkpoint_round(
            runtime,
            identity,
            wire.observation,
            now,
        )
        .await
    }

    pub async fn handle_deposit_observation_index_checkpoint_attest(
        &self,
        authenticated_party: PartyId,
        wire: DepositObservationIndexCheckpointAttestWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        self.validate_consensus_identity(&runtime.protocol, identity)?;
        let context =
            DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?;
        if wire.context() != context || wire.witness().from != authenticated_party {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let lane = runtime
            .protocol
            .observation_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .clone();
        if wire.binding().checkpoint_sequence() != lane.statement.sequence()
            || wire.binding().allocation_sequence()
                != lane.observation.statement.allocation_sequence()
            || wire.binding().statement_digest() != lane.observation.statement.digest()
            || wire.binding().certificate() != lane.observation_artifact
            || wire.binding().verify_observation(&lane.observation).is_err()
            || wire.statement() != &lane.statement
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        if !lane.witnesses.contains_key(&self.party) {
            self.start_or_resume_deposit_observation_checkpoint_round(
                runtime,
                identity,
                lane.observation.clone(),
                now,
            )
            .await?;
            if runtime.protocol.observation_checkpoint.is_none() {
                return Ok(());
            }
        }
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.accept_deposit_observation_checkpoint_witness(wire.witness().clone())?;
        match candidate.completed_deposit_observation_checkpoint(
            self.scenario.quic_network_id()?,
            previous.as_ref(),
        )? {
            Some(certificate) => {
                self.finalize_deposit_observation_checkpoint_certificate(
                    runtime,
                    candidate,
                    certificate,
                    now,
                )
                .await
            }
            None => self.commit_protocol(runtime, candidate).await,
        }
    }

    pub async fn handle_deposit_observation_index_checkpoint_certificate(
        &self,
        authenticated_party: PartyId,
        wire: DepositObservationIndexCheckpointCertificateWire,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        let context =
            DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?;
        if wire.context() != context {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        if runtime.snapshot.index_checkpoint_certificate() == Some(wire.certificate())
            && runtime.snapshot.checkpoint_operation_certificate()
                == Some(wire.binding().certificate())
        {
            return Ok(());
        }
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        let DepositIndexCheckpointCandidate::DepositObservation(observation) =
            wire.certificate().selected_candidate()?
        else {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        };
        if !runtime.protocol.observation_is_source_handoff_prefix(&observation.statement) {
            return Err(DepositServiceError::ConsensusUnavailable);
        }
        if wire.binding().checkpoint_sequence() != wire.certificate().statement().sequence()
            || wire.binding().allocation_sequence() != observation.statement.allocation_sequence()
            || wire.binding().statement_digest() != observation.statement.digest()
            || wire.binding().verify_observation(&observation).is_err()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        wire.certificate().verify_active_deposit_observation(
            self.scenario.quic_network_id()?,
            &runtime.protocol.registry,
            previous.as_ref(),
            &observation,
        )?;
        let (_, transition, expected_statement) = self
            .expected_deposit_observation_checkpoint_material(
                now,
                &runtime.protocol.registry,
                previous.as_ref(),
                &observation,
            )
            .await?;
        if &expected_statement != wire.certificate().statement() {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let verified = observation.verify_active(&runtime.protocol.registry)?;
        let staged = self
            .archive
            .stage_certified_deposit_observation(&observation, &verified, &mut rand_core::OsRng)
            .await?;
        let mut protocol = runtime.protocol.clone();
        protocol.retain_certified_deposit_observation(&observation)?;
        let selection_context = deposit_index_checkpoint_consensus_context(
            self.scenario.quic_network_id()?,
            &protocol.registry,
            expected_statement.sequence(),
            expected_statement.previous_head(),
        )?;
        self.adopt_certified_checkpoint_selection(
            &mut protocol,
            selection_context,
            wire.certificate().selection().clone(),
            DepositIndexCheckpointCandidate::DepositObservation(observation.clone()),
            now,
        )?;
        protocol.index_checkpoint = None;
        protocol.observation_checkpoint = None;
        protocol.begin_deposit_observation_checkpoint(
            observation,
            staged.reference(),
            expected_statement,
            now,
        )?;
        for witness in wire.certificate().witnesses() {
            protocol.accept_deposit_observation_checkpoint_witness(witness.clone())?;
        }
        let _ = transition;
        self.finalize_deposit_observation_checkpoint_certificate(
            runtime,
            protocol,
            wire.certificate().clone(),
            now,
        )
        .await
    }

    /// Apply one authenticated peer witness. Reaching n-f seals only the ledger decision; a
    /// separate durable checkpoint-witness round must finish before the portable root advances.
    pub async fn handle_attestation(
        &self,
        authenticated_party: PartyId,
        wire: DepositAttestationWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        validate_attestation_wire(runtime, authenticated_party, &wire)?;
        self.replay_pending_worker_events(runtime).await?;
        if wire.statement.sequence < runtime.protocol.ledger.next_sequence() {
            let existing = {
                let mut index = self.deposit_index.lock().await;
                let store =
                    index.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
                store
                    .lookup_portable_state(PortableStateQuery::Sequence(wire.statement.sequence))
                    .await?
            };
            let exact = match existing {
                Some(PortableStateRecord::Statement(record)) => {
                    record.digest() == wire.statement.digest()
                }
                _ => false,
            };
            return if exact {
                Ok(())
            } else {
                Err(DepositServiceError::SlotConflict(wire.statement.sequence))
            };
        }
        let historical = self.historical_issuer_for_statement(&wire.statement).await?;
        let mut candidate = runtime.protocol.clone();
        let certificate =
            candidate.accept_attestation(&wire.statement, wire.attestation, historical.as_ref())?;
        let Some(certificate) = certificate else {
            return self.commit_protocol_with_messages(runtime, candidate, Vec::new()).await;
        };
        let messages = self.certificate_messages(&candidate, certificate.clone())?;
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        self.start_or_resume_index_checkpoint_round(runtime, identity, certificate, now).await
    }

    /// Retain a directly verified ledger certificate, then participate in its independent
    /// portable-index checkpoint round.
    pub async fn handle_certificate(
        &self,
        authenticated_party: PartyId,
        wire: DepositCertificateWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        if wire.version != DEPOSIT_WIRE_VERSION {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        if wire.entry.statement.sequence < runtime.protocol.ledger.next_sequence() {
            let existing = {
                let mut index = self.deposit_index.lock().await;
                let store =
                    index.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
                store
                    .lookup_portable_state(PortableStateQuery::Sequence(
                        wire.entry.statement.sequence,
                    ))
                    .await?
            };
            let exact = match existing {
                Some(PortableStateRecord::Statement(record)) => {
                    record.digest() == wire.entry.statement.digest()
                }
                _ => false,
            };
            return if exact {
                Ok(())
            } else {
                Err(DepositServiceError::SlotConflict(wire.entry.statement.sequence))
            };
        }
        self.replay_pending_worker_events(runtime).await?;
        let historical = self.historical_issuer_for_statement(&wire.entry.statement).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.retain_certified_pending(&wire.entry, historical.as_ref())?;
        let messages = self.certificate_messages(&candidate, wire.entry.clone())?;
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        self.start_or_resume_index_checkpoint_round(runtime, identity, wire.entry, now).await
    }

    pub async fn handle_index_checkpoint_attest(
        &self,
        authenticated_party: PartyId,
        wire: DepositIndexCheckpointAttestWire,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        let context =
            DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?;
        if wire.context() != context || wire.witness().from != authenticated_party {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        let lane = runtime
            .protocol
            .index_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .clone();
        if wire.binding().checkpoint_sequence() != lane.statement.sequence()
            || wire.binding().ledger_sequence() != lane.ledger.statement.sequence
            || wire.binding().decision() != lane.ledger.statement.digest()
            || wire.statement() != &lane.statement
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        if !lane.witnesses.contains_key(&self.party) {
            self.start_or_resume_index_checkpoint_round(
                runtime,
                identity,
                lane.ledger.clone(),
                now,
            )
            .await?;
        }
        let historical = self.historical_issuer_for_statement(&lane.ledger.statement).await?;
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        let mut candidate = runtime.protocol.clone();
        candidate.accept_index_checkpoint_witness(wire.witness().clone())?;
        match candidate.completed_index_checkpoint(
            self.scenario.quic_network_id()?,
            historical.as_ref(),
            previous.as_ref(),
        )? {
            Some(certificate) => {
                let r = self
                    .finalize_index_checkpoint_certificate(runtime, candidate, certificate, now)
                    .await;
                if let Err(e) = &r {
                    eprintln!("TRACE_FINALIZE (attest-handler) error={e:?}");
                }
                r
            }
            None => self.commit_protocol(runtime, candidate).await,
        }
    }

    pub async fn handle_index_checkpoint_certificate(
        &self,
        authenticated_party: PartyId,
        wire: DepositIndexCheckpointCertificateWire,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        let context =
            DepositSyncContext::new(self.scenario.quic_network_id()?, runtime.deriver.wallet_id())?;
        if wire.context() != context {
            return Err(DepositServiceError::InvalidPeerMessage);
        }
        if runtime.snapshot.index_checkpoint_certificate() == Some(wire.certificate())
            && runtime.snapshot.checkpoint_operation_certificate()
                == Some(wire.binding().certificate())
        {
            return Ok(());
        }
        runtime.protocol.registry.active().committee().member(authenticated_party)?;
        let DepositIndexCheckpointCandidate::Ledger(entry) =
            wire.certificate().selected_candidate()?
        else {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        };
        if wire.binding().checkpoint_sequence() != wire.certificate().statement().sequence()
            || wire.binding().ledger_sequence() != entry.statement.sequence
            || wire.binding().decision() != entry.statement.digest()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let historical = self.historical_issuer_for_statement(&entry.statement).await?;
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        wire.certificate().verify_active(
            self.scenario.quic_network_id()?,
            &runtime.protocol.registry,
            historical.as_ref(),
            previous.as_ref(),
            &entry,
        )?;
        let reservation_time = match &entry.statement.payload {
            LedgerPayload::Allocation(allocation) => allocation
                .created_at
                .checked_sub(1)
                .filter(|time| *time != 0)
                .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?,
            LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => now,
        };
        let (_, _, expected_statement) = self
            .expected_index_checkpoint_material(
                reservation_time,
                &runtime.protocol.registry,
                historical.as_ref(),
                previous.as_ref(),
                &entry,
            )
            .await?;
        if &expected_statement != wire.certificate().statement() {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let verified_entry =
            entry.verify_active(&runtime.protocol.registry, historical.as_ref())?;
        let staged = self
            .archive
            .stage_certified_ledger_entry(&entry, &verified_entry, &mut rand_core::OsRng)
            .await?;
        let mut protocol = runtime.protocol.clone();
        protocol.retain_certified_pending(&entry, historical.as_ref())?;
        let selection_context = deposit_index_checkpoint_consensus_context(
            self.scenario.quic_network_id()?,
            &protocol.registry,
            expected_statement.sequence(),
            expected_statement.previous_head(),
        )?;
        self.adopt_certified_checkpoint_selection(
            &mut protocol,
            selection_context,
            wire.certificate().selection().clone(),
            DepositIndexCheckpointCandidate::Ledger(entry.clone()),
            reservation_time,
        )?;
        protocol.index_checkpoint = None;
        protocol.observation_checkpoint = None;
        protocol.begin_index_checkpoint(
            entry,
            staged.reference(),
            expected_statement,
            reservation_time,
        )?;
        for witness in wire.certificate().witnesses() {
            protocol.accept_index_checkpoint_witness(witness.clone())?;
        }
        self.finalize_index_checkpoint_certificate(
            runtime,
            protocol,
            wire.certificate().clone(),
            now,
        )
        .await
    }

    /// Reconstruct every mandatory peer effect from durable signer locks and certificates. The
    /// host calls this once after restoring the epoch identity and may call it repeatedly; message
    /// identifiers are content-addressed and certificate gossip tombstones prevent restart storms
    /// after successful ACKs.
    pub async fn recover_peer_messages(
        &self,
        identity: &Identity,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        if identity.party() != self.party {
            return Err(DepositServiceError::WrongLocalParty);
        }
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        self.replay_pending_worker_events(runtime).await?;
        // A prepared ledger checkpoint already owns the single global checkpoint sequence.
        if let Some(lane) = runtime.protocol.index_checkpoint.clone() {
            return self
                .start_or_resume_index_checkpoint_round(runtime, identity, lane.ledger, now)
                .await;
        }
        if let Some(lane) = runtime.protocol.checkpoint_consensus_lane.as_ref() {
            return if lane.reducer.commit().is_some() {
                self.resume_decided_checkpoint_round(runtime, identity, now).await
            } else {
                // Every unacknowledged BA effect is already in the durable outbox. The pacemaker
                // drives a fresh view if those exact relays cannot complete after restart.
                Ok(())
            };
        }
        if let Some(certificate) = runtime.protocol.next_certified_ledger_entry() {
            return self
                .start_or_resume_index_checkpoint_round(runtime, identity, certificate, now)
                .await;
        }
        if self.progress_deposit_observations_locked(runtime, identity, now).await? {
            return Ok(());
        }
        let mut candidate = runtime.protocol.clone();
        let mut messages = Vec::new();
        let is_active_member = candidate
            .registry
            .active()
            .committee()
            .members
            .iter()
            .any(|member| member.id == self.party);
        if is_active_member {
            let pending =
                candidate.pending.values().map(|slot| slot.statement.clone()).collect::<Vec<_>>();
            for statement in pending {
                if !statement_is_consensus_committed(&candidate, &statement)? {
                    return Err(DepositServiceError::InvalidProtocolState);
                }
                let attestation =
                    candidate.stage_local_attestation(statement.sequence, identity)?;
                messages.extend(self.attestation_messages(&candidate, statement, attestation)?);
            }
            let observations = candidate
                .pending_observations
                .values()
                .filter(|slot| candidate.observation_is_source_handoff_prefix(&slot.statement))
                .map(|slot| (slot.statement.clone(), slot.attestations.get(&self.party).cloned()))
                .collect::<Vec<_>>();
            for (statement, local_attestation) in observations {
                if let Some(attestation) = local_attestation {
                    messages.extend(self.deposit_observation_statement_and_attestation_messages(
                        &candidate,
                        statement,
                        attestation,
                    )?);
                } else {
                    messages.extend(
                        self.deposit_observation_statement_messages(&candidate, statement)?,
                    );
                }
            }
        }
        let certified = candidate.pending.values().find_map(|slot| {
            let required = usize::from(
                candidate.registry.active().committee().n()
                    - candidate.registry.active().fault_bound(),
            );
            (slot.attestations.len() >= required).then(|| CertifiedLedgerEntry {
                statement: slot.statement.clone(),
                attestations: slot.attestations.values().take(required).cloned().collect(),
            })
        });
        self.commit_protocol_with_messages(runtime, candidate, messages).await?;
        if let Some(certificate) = certified {
            return self
                .start_or_resume_index_checkpoint_round(runtime, identity, certificate, now)
                .await;
        }
        Ok(())
    }

    pub async fn pending_peer_messages(&self, limit: usize) -> Vec<PendingDepositPeerMessage> {
        let guard = self.runtime.lock().await;
        guard.as_ref().map_or_else(Vec::new, |runtime| runtime.snapshot.pending(limit))
    }

    /// Remove transport effects only after the remote party reported durable acceptance and this
    /// ACK checkpoint itself reaches encrypted storage.
    pub async fn acknowledge_peer_messages(
        &self,
        acknowledgements: &[DepositPeerMessageId],
    ) -> Result<(), DepositServiceError> {
        if acknowledgements.is_empty() {
            return Ok(());
        }
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        let mut snapshot = runtime.snapshot.clone();
        if snapshot.acknowledge(acknowledgements)? == 0 {
            return Ok(());
        }
        self.repository.persist(&snapshot).await?;
        runtime.snapshot = snapshot;
        Ok(())
    }

    /// Advance the confirmed scanner and idempotently apply detections before clearing its event
    /// batch. The same event is replayed after any crash between these two snapshots.
    pub async fn tick_worker(&self) -> Result<DepositWorkerTickOutcome, DepositServiceError> {
        let mut guard = self.runtime.lock().await;
        let runtime = guard.as_mut().ok_or(DepositServiceError::NotInitialized)?;
        runtime.protocol.require_live()?;
        // A restored at-least-once batch is a causal predecessor of every future daemon read.
        // Applying/ACKing it first prevents `PendingEvents` from becoming a permanent restart
        // deadlock and prevents a replacement branch from racing its orphan rollback.
        let mut invalidated_sessions = self.replay_pending_worker_events(runtime).await?;
        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let output_index = SnapshotDepositOutputIndexBackend::new(
            runtime.deriver.wallet_id(),
            Arc::clone(&self.repository),
            Arc::clone(&self.deposit_index),
            runtime.snapshot.clone(),
        );
        let tick_result = if worker.allocation_backfill().is_some() {
            worker
                .tick_allocation_backfill(self.source.as_ref(), &runtime.deriver, &output_index)
                .await
        } else {
            worker.tick(self.source.as_ref(), &runtime.deriver, &output_index).await
        };
        // `bind_outputs` may have crossed an index-only snapshot CAS before a later daemon or
        // scanner error. Always advance the in-memory base to its authenticated readback.
        runtime.snapshot = output_index.durable_snapshot().await;
        let tick = tick_result?;
        let Some(effect) = tick.persistence else {
            invalidated_sessions.extend(self.reconcile_consolidation_confirmations(runtime).await?);
            invalidated_sessions.sort_unstable();
            invalidated_sessions.dedup();
            return Ok(DepositWorkerTickOutcome {
                invalidated_consolidation_sessions: invalidated_sessions,
            });
        };
        let pending = worker.replay_pending_events()?;
        let mut consolidation = runtime.snapshot.consolidation()?;
        if let Some(rollback) = pending.as_ref().and_then(|batch| batch.rollback.as_ref()) {
            invalidated_sessions
                .extend(apply_consolidation_rollback(&mut consolidation, rollback)?);
        }
        // The scanner sweep transition and its public nonce lifecycle are one crash boundary.
        // Persisting either side alone would make the restored cross-component invariant reject
        // the snapshot and could leave a volatile nonce machine live on an orphaned input.
        self.commit_composite_with_messages(
            runtime,
            runtime.protocol.clone(),
            worker,
            consolidation,
            Vec::new(),
            None,
            None,
        )
        .await?;
        let persisted =
            runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        if persisted.revision() != effect.revision() {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        invalidated_sessions.extend(self.replay_pending_worker_events(runtime).await?);
        invalidated_sessions.extend(self.reconcile_consolidation_confirmations(runtime).await?);
        invalidated_sessions.sort_unstable();
        invalidated_sessions.dedup();
        Ok(DepositWorkerTickOutcome { invalidated_consolidation_sessions: invalidated_sessions })
    }

    /// Consume only scanner-retained root-output evidence when moving a sweep to confirmed.
    ///
    /// A same-family transaction from an older/newer ROAST view may beat the locally selected
    /// candidate on chain. Its exact full bytes, retained inclusion, and f+1 candidate
    /// endorsements are checked before the worker reconstructs the certified attempt. Worker,
    /// coordinator, stale successor lane, and transport cleanup then share one snapshot CAS.
    /// The returned sessions name volatile FROST machines which the server must retire only after
    /// that CAS is durable.
    async fn reconcile_consolidation_confirmations(
        &self,
        runtime: &mut DepositRuntime,
    ) -> Result<Vec<SessionId>, DepositServiceError> {
        let mut invalidated_sessions = Vec::new();
        loop {
            let evidence = runtime
                .snapshot
                .worker()
                .ok_or(DepositServiceError::MissingScannerAnchor)?
                .reconcile_sweep_family_settlements()?
                .into_iter()
                .next();
            let Some(evidence) = evidence else {
                break;
            };

            let mut consolidation = runtime.snapshot.consolidation()?;
            let (consolidation_id, authorization, ordinary_broadcast) = {
                let record = consolidation
                    .record_by_sweep(evidence.sweep)
                    .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
                let worker_record = runtime
                    .snapshot
                    .worker()
                    .and_then(|worker| worker.scan_state().sweep(evidence.sweep))
                    .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
                let ordinary_broadcast = record.phase == ConsolidationPhase::Broadcast
                    && matches!(
                        worker_record.status,
                        SweepStatus::Broadcast { transaction }
                            if transaction == evidence.transaction_id()
                    )
                    && worker_record.signed_transaction.as_ref()
                        == Some(&evidence.signed_transaction)
                    && record.signed.is_some_and(|binding| {
                        signed_binding_matches_bytes(binding, &evidence.signed_transaction)
                    });
                (record.authorization.id(), record.authorization.clone(), ordinary_broadcast)
            };

            // The worker also stages full family evidence for its already-selected broadcast
            // candidate. That ordinary case needs no ROAST reconstruction and remains valid after
            // a portable completion has pruned the hot family state.
            if ordinary_broadcast {
                let mut worker = runtime
                    .snapshot
                    .worker()
                    .cloned()
                    .ok_or(DepositServiceError::MissingScannerAnchor)?;
                let worker_effect = worker.mark_sweep_confirmed(
                    evidence.sweep,
                    evidence.transaction_id(),
                    evidence.block,
                )?;
                let consolidation_effect = consolidation
                    .mark_confirmed(consolidation_id, evidence.transaction_id(), evidence.block)?
                    .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
                self.commit_composite_with_messages(
                    runtime,
                    runtime.protocol.clone(),
                    worker,
                    consolidation,
                    Vec::new(),
                    None,
                    None,
                )
                .await?;
                let durable_worker =
                    runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
                if durable_worker.revision() != worker_effect.revision()
                    || runtime.consolidation.revision() != consolidation_effect.revision()
                {
                    return Err(DepositServiceError::StorageRevisionMismatch);
                }
                continue;
            }
            let roast = runtime
                .snapshot
                .consolidation_roasts
                .get(&consolidation_id)
                .map(|bytes| ConsolidationRoast::decode_authenticated_snapshot(bytes))
                .transpose()?;
            if let Some(roast) = &roast
                && (roast.authorization() != &authorization || roast.sweep_id() != evidence.sweep)
            {
                return Err(DepositServiceError::InvalidByzantineConsolidationState);
            }

            // Endorsements are ordered by absolute view and transaction ID. If the same exact
            // transaction was endorsed in multiple views, the oldest authenticated attempt is a
            // deterministic sufficient provenance witness.
            let mut certified = None;
            if let Some(roast) = &roast {
                for (view, endorsed) in roast.endorsed_candidates() {
                    if endorsed.transaction() != evidence.transaction_id() {
                        continue;
                    }
                    let binding = roast.wire_binding(view)?;
                    let signed = signed_binding_for(
                        &authorization,
                        binding.attempt(),
                        &evidence.signed_transaction,
                    )?;
                    if signed == endorsed {
                        certified = Some((binding.attempt().clone(), signed));
                        break;
                    }
                }
            }

            // A completion BA may already have sealed the hot ROAST bodies before the scanner
            // observes the transaction. The pending/final ledger statement is then the stronger
            // self-contained terminal certificate and names the same exact attempt and bytes.
            if certified.is_none() {
                certified = runtime.protocol.pending.values().map(|slot| &slot.statement).find_map(
                    |statement| {
                        let LedgerPayload::ConsolidationCompletion(completion) = &statement.payload
                        else {
                            return None;
                        };
                        (completion.authorization() == &authorization
                            && completion.signed_transaction() == &evidence.signed_transaction
                            && public_terminal_completion_matches(
                                statement,
                                &runtime.consolidation,
                            ))
                        .then(|| (completion.attempt().clone(), completion.signed_binding()))
                    },
                );
                if certified.is_none() {
                    let portable =
                        self.authenticated_portable_terminal_by_sweep(evidence.sweep).await?;
                    certified = portable.as_ref().and_then(|portable| {
                        let completion = portable.completion()?;
                        (completion.authorization() == &authorization
                            && completion.signed_transaction() == &evidence.signed_transaction
                            && public_completion_matches(completion, &runtime.consolidation))
                        .then(|| (completion.attempt().clone(), completion.signed_binding()))
                    });
                }
            }
            let (exact_attempt, signed_binding) =
                certified.ok_or(DepositServiceError::InvalidPortableTerminalEvidence)?;
            let committee = if let Some(roast) = &roast {
                if roast.committee().epoch != exact_attempt.epoch() {
                    return Err(DepositServiceError::InvalidPortableTerminalEvidence);
                }
                roast.committee().clone()
            } else {
                let mut guard = self.compact_registry.lock().await;
                let store =
                    guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
                store
                    .lookup_issuer_window(exact_attempt.epoch())
                    .await?
                    .issuer()
                    .committee()
                    .clone()
            };

            let mut worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let verified = worker.verify_certified_sweep_signing_attempt(
                evidence.sweep,
                &exact_attempt,
                &committee,
            )?;
            let worker_effect = worker.mark_verified_sweep_family_confirmed(
                &verified,
                &evidence.signed_transaction,
                evidence.block,
            )?;
            let consolidation_effect = consolidation
                .record_verified_chain_authoritative_settlement(
                    consolidation_id,
                    verified,
                    signed_binding,
                    evidence.transaction_id(),
                    evidence.block,
                )?;
            if let Some(session) = consolidation_effect
                .as_ref()
                .and_then(ConsolidationPersistEffect::invalidated_session)
            {
                invalidated_sessions.push(session);
            }
            let expected_consolidation_revision = consolidation.revision();

            self.commit_chain_authoritative_settlement(
                runtime,
                worker,
                consolidation,
                roast.as_ref(),
            )
            .await?;
            let durable_worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if durable_worker.revision() != worker_effect.revision()
                || runtime.consolidation.revision() != expected_consolidation_revision
            {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
        }

        loop {
            let evidence = runtime
                .snapshot
                .worker()
                .ok_or(DepositServiceError::MissingScannerAnchor)?
                .reconcile_broadcast_confirmations()?
                .into_iter()
                .next();
            let Some(evidence) = evidence else {
                invalidated_sessions.sort_unstable();
                invalidated_sessions.dedup();
                return Ok(invalidated_sessions);
            };

            let mut worker = runtime
                .snapshot
                .worker()
                .cloned()
                .ok_or(DepositServiceError::MissingScannerAnchor)?;
            let worker_effect = worker.mark_sweep_confirmed(
                evidence.sweep,
                evidence.transaction,
                evidence.block,
            )?;
            let mut consolidation = runtime.snapshot.consolidation()?;
            let consolidation_id = consolidation
                .record_by_sweep(evidence.sweep)
                .map(|record| record.authorization.id())
                .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
            let consolidation_effect = consolidation
                .mark_confirmed(consolidation_id, evidence.transaction, evidence.block)?
                .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;

            self.commit_composite_with_messages(
                runtime,
                runtime.protocol.clone(),
                worker,
                consolidation,
                Vec::new(),
                None,
                None,
            )
            .await?;
            let durable_worker =
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
            if durable_worker.revision() != worker_effect.revision()
                || runtime.consolidation.revision() != consolidation_effect.revision()
            {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
        }
    }

    async fn replay_pending_worker_events(
        &self,
        runtime: &mut DepositRuntime,
    ) -> Result<Vec<SessionId>, DepositServiceError> {
        let batch = runtime
            .snapshot
            .worker()
            .ok_or(DepositServiceError::MissingScannerAnchor)?
            .replay_pending_events()?;
        let Some(batch) = batch else {
            return Ok(Vec::new());
        };
        let sessions = if let Some(rollback) = &batch.rollback {
            consolidation_sessions_for_rollback(
                runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?,
                rollback,
            )?
        } else {
            Vec::new()
        };
        self.apply_worker_event_batch(runtime, batch).await?;
        Ok(sessions)
    }

    async fn apply_worker_event_batch(
        &self,
        runtime: &mut DepositRuntime,
        batch: WorkerEventBatch,
    ) -> Result<(), DepositServiceError> {
        // Persist every exact observation statement while the worker's at-least-once batch still
        // exists. A crash after this CAS replays the same batch into the exact same reducer slots;
        // a crash before it leaves the worker batch untouched. No positive worker ACK is allowed
        // to become durable without these statements.
        let observations = self.worker_observation_statements(runtime, &batch).await?;
        let mut protocol = runtime.protocol.clone();
        let mut protocol_changed = false;
        let mut retracted_observations = Vec::new();
        for (statement, verified) in &observations {
            protocol_changed |= protocol
                .retain_locally_verified_deposit_observation(statement.clone(), verified)?;
        }
        if let Some(rollback) = &batch.rollback {
            let active_output = protocol
                .observation_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.observation.statement.output());
            let required = usize::from(
                protocol.registry.active().committee().n()
                    - protocol.registry.active().fault_bound(),
            );
            for orphaned in &rollback.orphaned_deposits {
                let certified = protocol
                    .pending_observations
                    .get(&orphaned.output)
                    .is_some_and(|slot| slot.attestations.len() >= required);
                if active_output != Some(orphaned.output) && !certified {
                    if let Some(retracted) = protocol.pending_observations.remove(&orphaned.output)
                    {
                        retracted_observations.push(retracted.statement);
                        protocol_changed = true;
                    }
                }
            }
        }
        if protocol_changed {
            if retracted_observations.is_empty() {
                self.commit_protocol(runtime, protocol).await?;
            } else {
                self.commit_protocol_prune_observations(runtime, protocol, &retracted_observations)
                    .await?;
            }
        }
        for (statement, _) in &observations {
            if runtime
                .protocol
                .pending_observations
                .get(&statement.output())
                .is_none_or(|pending| pending.statement != *statement)
            {
                return Err(DepositServiceError::StorageRevisionMismatch);
            }
        }

        // Output identity bindings and permanent first-use timestamps crossed an authenticated
        // local-index CAS before the worker was allowed to advance its scan cursor. Reorg events
        // never retract those burning-bug records; they only update the worker's bounded
        // canonical-chain view and may retire an uncertified pending proposal.
        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        worker.acknowledge_events(batch.id)?;
        self.commit_worker(runtime, worker).await
    }

    async fn worker_observation_statements(
        &self,
        runtime: &DepositRuntime,
        batch: &WorkerEventBatch,
    ) -> Result<
        Vec<(DepositObservationStatement, VerifiedLocalDepositObservation)>,
        DepositServiceError,
    > {
        if batch.detections.is_empty() {
            return Ok(Vec::new());
        }
        let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let mut statements = Vec::with_capacity(batch.detections.len());
        for detection in &batch.detections {
            let allocation = store
                .lookup_portable(&PortableAllocationQuery::Index(detection.subaddress))
                .await?
                .ok_or(DepositServiceError::UnknownDepositAddress)?;
            let output = worker
                .scan_state()
                .output(detection.output)
                .ok_or(DepositServiceError::InvalidDepositObservation)?;
            let statement = DepositObservationStatement::new(
                &runtime.protocol.registry,
                allocation.statement(),
                detection.output,
                output.output_key(),
                detection.index_on_blockchain,
                detection.amount_atomic_units,
                detection.observed_block,
                detection.block_timestamp,
                worker.scan_state().tip(),
                worker.config().confirmation_depth,
            )?;
            let verified = worker.verify_local_deposit_observation(&allocation, &statement)?;
            statements.push((statement, verified));
        }
        statements.sort_unstable_by_key(|(statement, _)| {
            (statement.observed_block().height, statement.output())
        });
        if statements.windows(2).any(|pair| pair[0].0.output() == pair[1].0.output()) {
            return Err(DepositServiceError::InvalidDepositObservation);
        }
        Ok(statements)
    }

    async fn commit_protocol(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
    ) -> Result<(), DepositServiceError> {
        let encoded = protocol.encode_local(&runtime.deriver)?;
        let archive_head = runtime.snapshot.archive_head()?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_reducer(encoded)?;
        let heads_changed = snapshot.install_archive_head(archive_head)?;
        if heads_changed && snapshot.revision == runtime.snapshot.revision {
            snapshot.revision = runtime.snapshot.next_revision()?;
        }
        validate_consolidation_alignment(self, &protocol, &snapshot, &runtime.consolidation)
            .await?;
        self.repository.persist(&snapshot).await?;
        runtime.protocol = protocol;
        runtime.snapshot = snapshot;
        Ok(())
    }

    async fn commit_protocol_prune_observations(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
        obsolete: &[DepositObservationStatement],
    ) -> Result<(), DepositServiceError> {
        let encoded = protocol.encode_local(&runtime.deriver)?;
        let archive_head = runtime.snapshot.archive_head()?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_reducer(encoded)?;
        for statement in obsolete {
            snapshot.prune_deposit_observation_outbox_in_place(statement)?;
        }
        let heads_changed = snapshot.install_archive_head(archive_head)?;
        if heads_changed && snapshot.revision == runtime.snapshot.revision {
            snapshot.revision = runtime.snapshot.next_revision()?;
        }
        validate_consolidation_alignment(self, &protocol, &snapshot, &runtime.consolidation)
            .await?;
        let durable = self.repository.persist_and_read_back(&snapshot).await?;
        runtime.protocol = protocol;
        runtime.snapshot = durable;
        Ok(())
    }

    async fn commit_protocol_with_messages(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
        messages: Vec<(u64, PartyId, DepositOperation, Vec<u8>)>,
    ) -> Result<(), DepositServiceError> {
        let encoded = protocol.encode_local(&runtime.deriver)?;
        let archive_head = runtime.snapshot.archive_head()?;
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_reducer_and_enqueue(encoded, messages)?;
        let heads_changed = snapshot.install_archive_head(archive_head)?;
        if heads_changed && snapshot.revision == runtime.snapshot.revision {
            snapshot.revision = runtime.snapshot.next_revision()?;
        }
        validate_consolidation_alignment(self, &protocol, &snapshot, &runtime.consolidation)
            .await?;
        if snapshot.revision != runtime.snapshot.revision {
            self.repository.persist(&snapshot).await?;
        }
        runtime.protocol = protocol;
        runtime.snapshot = snapshot;
        Ok(())
    }

    async fn commit_worker(
        &self,
        runtime: &mut DepositRuntime,
        worker: DepositWorkerState,
    ) -> Result<(), DepositServiceError> {
        let mut snapshot = runtime.snapshot.clone();
        snapshot.replace_worker(worker)?;
        validate_consolidation_alignment(
            self,
            &runtime.protocol,
            &snapshot,
            &runtime.consolidation,
        )
        .await?;
        self.repository.persist(&snapshot).await?;
        runtime.snapshot = snapshot;
        Ok(())
    }

    async fn commit_composite_with_messages(
        &self,
        runtime: &mut DepositRuntime,
        protocol: DepositProtocolState,
        worker: DepositWorkerState,
        consolidation: ConsolidationCoordinator,
        messages: Vec<(u64, PartyId, DepositOperation, Vec<u8>)>,
        archive_head: Option<DepositArchiveHead>,
        certified_statement: Option<&LedgerStatement>,
    ) -> Result<(), DepositServiceError> {
        let encoded = protocol.encode_local(&runtime.deriver)?;
        let archive_head = archive_head.unwrap_or(runtime.snapshot.archive_head()?);
        let mut candidate = runtime.snapshot.clone();
        candidate.replace_all_and_enqueue(encoded, worker, &consolidation, messages)?;
        let heads_changed = candidate.install_archive_head(archive_head)?;
        if heads_changed && candidate.revision == runtime.snapshot.revision {
            candidate.revision = runtime.snapshot.next_revision()?;
        }
        if let Some(statement) = certified_statement
            && candidate.prune_certified_outbox_in_place(statement, None) != 0
            && candidate.revision == runtime.snapshot.revision
        {
            candidate.revision = runtime.snapshot.next_revision()?;
        }
        validate_consolidation_alignment(self, &protocol, &candidate, &consolidation).await?;
        let durable = self.repository.persist_and_read_back(&candidate).await?;
        let durable_consolidation = durable.consolidation()?;
        validate_consolidation_alignment(self, &protocol, &durable, &durable_consolidation).await?;
        runtime.protocol = protocol;
        runtime.snapshot = durable;
        runtime.consolidation = durable_consolidation;
        Ok(())
    }

    /// Persist a canonical same-family winner and retire any already-obsolete successor BA lane
    /// as one encrypted snapshot CAS. The ROAST itself remains as portable endorsement evidence
    /// until the completion ledger certificate seals the family.
    async fn commit_chain_authoritative_settlement(
        &self,
        runtime: &mut DepositRuntime,
        worker: DepositWorkerState,
        consolidation: ConsolidationCoordinator,
        roast: Option<&ConsolidationRoast>,
    ) -> Result<(), DepositServiceError> {
        let protocol = runtime.protocol.clone();
        let encoded = protocol.encode_local(&runtime.deriver)?;
        let archive_head = runtime.snapshot.archive_head()?;
        let mut candidate = runtime.snapshot.clone();
        candidate.replace_all_and_enqueue(encoded, worker, &consolidation, Vec::new())?;
        if let Some(roast) = roast
            && !roast.is_completion_sealed()
        {
            candidate.cancel_byzantine_lane_for_endorsed_roast(roast)?;
        }
        let heads_changed = candidate.install_archive_head(archive_head)?;
        if heads_changed && candidate.revision == runtime.snapshot.revision {
            candidate.revision = runtime.snapshot.next_revision()?;
        }
        validate_consolidation_alignment(self, &protocol, &candidate, &consolidation).await?;
        let durable = self.repository.persist_and_read_back(&candidate).await?;
        let durable_consolidation = durable.consolidation()?;
        validate_consolidation_alignment(self, &protocol, &durable, &durable_consolidation).await?;
        runtime.snapshot = durable;
        runtime.consolidation = durable_consolidation;
        Ok(())
    }

    /// Install an n-f checkpoint decision and every state derived from its ledger certificate in
    /// one wallet-snapshot CAS. Immutable archive/index objects may be materialized beforehand,
    /// but none become live authority until this exact candidate wins the CAS.
    async fn finalize_index_checkpoint_certificate(
        &self,
        runtime: &mut DepositRuntime,
        mut protocol: DepositProtocolState,
        checkpoint_certificate: DepositIndexCheckpointCertificate,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let lane = protocol
            .index_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .clone();
        let historical = self.historical_issuer_for_statement(&lane.ledger.statement).await?;
        let verified_entry = lane.ledger.verify_active(&protocol.registry, historical.as_ref())?;
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        let verified_checkpoint = checkpoint_certificate.verify_active(
            self.scenario.quic_network_id()?,
            &protocol.registry,
            historical.as_ref(),
            previous.as_ref(),
            &lane.ledger,
        )?;
        if verified_checkpoint.resulting_head()
            != checkpoint_certificate.statement().resulting_head()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }

        eprintln!("TRACE_FIN step=verify_checkpoint ok");
        let staged_ledger = self
            .archive
            .authenticate_certified_entry_artifact(lane.ledger_artifact, &verified_entry)
            .await?;
        eprintln!("TRACE_FIN step=authenticate_entry ok");
        let archive_append = self
            .archive
            .append_ledger_checkpoint(
                runtime.snapshot.archive_head()?,
                staged_ledger,
                &checkpoint_certificate,
                &verified_checkpoint,
                &mut rand_core::OsRng,
            )
            .await?;
        if archive_append.entry_artifact != lane.ledger_artifact
            || archive_append.head.len() != checkpoint_certificate.statement().sequence()
        {
            return Err(DepositServiceError::InvalidArchiveHead);
        }

        eprintln!("TRACE_FIN step=append_ledger_checkpoint ok");
        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_index = store.checkpoint().clone();
        if runtime.snapshot.deposit_index_checkpoint() != &expected_index {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }

        store.reset_bounded_cache()?;
        for query in [
            LocalSafetyQuery::SignedLedgerSlot(lane.ledger.statement.sequence),
            LocalSafetyQuery::CertifiedEntryLocator(lane.ledger.statement.sequence),
        ] {
            store.preload_local_safety_query(query).await?;
        }
        eprintln!("TRACE_FIN step=preload_local_safety ok");
        let local_head = store.local_safety_head().clone();
        let mut local_builder = DepositIndexBuilder::new(&*store, local_head)?;
        local_builder.record_certified_entry_locator(archive_append.verified_ledger_locator())?;
        let local_update = local_builder.finish()?;
        eprintln!("TRACE_FIN step=local_builder ok");

        let prior_terminal = match &lane.ledger.statement.payload {
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                match store
                    .lookup_portable_state(PortableStateQuery::Consolidation(settlement.id()))
                    .await?
                {
                    Some(PortableStateRecord::Terminal(terminal)) => Some(terminal),
                    _ => return Err(DepositServiceError::InvalidLateConsolidationSettlement),
                }
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_) => None,
        };
        eprintln!("TRACE_FIN step=prior_terminal ok");
        Self::preload_portable_statement_paths(store, &lane.ledger.statement).await?;
        eprintln!("TRACE_FIN step=preload_portable_paths ok");
        let portable_head = store.portable_head().clone();
        let mut portable_builder = DepositIndexBuilder::new(&*store, portable_head)?;
        let preflight = portable_builder.preflight_ledger_statement(&lane.ledger.statement)?;
        eprintln!("TRACE_FIN step=preflight ok");
        let candidate_terminal = match &lane.ledger.statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => {
                portable_builder.candidate_portable_terminal(completion.id())?
            }
            LedgerPayload::ConsolidationAbandonment(abandonment) => {
                portable_builder.candidate_portable_terminal(abandonment.id())?
            }
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                portable_builder.candidate_portable_terminal(settlement.id())?
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_) => None,
        };
        let portable_update =
            portable_builder.finish()?.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let transition = portable_update.verify_ledger_transition_for_preflight(
            &*store,
            &lane.ledger.statement,
            &preflight,
        )?;
        checkpoint_certificate.statement().verify_transition(
            self.scenario.quic_network_id()?,
            &protocol.registry,
            historical.as_ref(),
            previous.as_ref(),
            &lane.ledger,
            &preflight,
            &portable_update,
            &*store,
        )?;
        if PortableDepositIndexHead::from_head(transition.resulting_head())?
            != *verified_checkpoint.resulting_head()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let scanner_transition = portable_update.verify_portable_scanner_transition(&*store)?;
        let mut updates = vec![portable_update];
        if let Some(local_update) = local_update {
            updates.push(local_update);
        }

        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        worker.adopt_verified_portable_scanner_transition(&scanner_transition)?;
        let mut consolidation = runtime.snapshot.consolidation()?;
        match &lane.ledger.statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => {
                let terminal = candidate_terminal
                    .as_ref()
                    .ok_or(DepositServiceError::InvalidPortableTerminalEvidence)?;
                let key_images =
                    canonical_sweep_transaction_key_images(completion.signed_transaction())?;
                let verified = worker.verify_public_sweep_completion(
                    lane.ledger.statement.digest(),
                    completion.authorization(),
                    completion.plan(),
                    completion.attempt(),
                    completion.signed_binding(),
                    completion.signed_transaction(),
                    key_images,
                )?;
                worker.adopt_verified_public_sweep_completion(verified, terminal)?;
                consolidation.record_certified_public_terminal_completion(
                    completion.authorization().clone(),
                    completion.attempt().clone(),
                    completion.signed_binding(),
                )?;
            }
            LedgerPayload::ConsolidationAbandonment(abandonment) => {
                let terminal = candidate_terminal
                    .as_ref()
                    .ok_or(DepositServiceError::InvalidPortableTerminalEvidence)?;
                let key_images = abandonment
                    .key_images()
                    .value()
                    .ok_or(DepositServiceError::InvalidConsensusValue)?
                    .key_images()
                    .to_vec();
                let verified = worker.verify_public_sweep_abandonment(
                    lane.ledger.statement.digest(),
                    abandonment.authorization(),
                    abandonment.attempt_prefix(),
                    abandonment.attempt(),
                    abandonment.sweep_sequence(),
                    abandonment.inputs().to_vec(),
                    key_images,
                    abandonment.missing_inputs().to_vec(),
                    abandonment.ancestor(),
                    abandonment.observation_tip(),
                    abandonment.finality_depth(),
                )?;
                worker.adopt_verified_public_sweep_abandonment(verified, terminal)?;
                consolidation.record_certified_public_abandonment(
                    abandonment.authorization().clone(),
                    abandonment.attempt().clone(),
                    abandonment.ancestor(),
                )?;
            }
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                let prior = prior_terminal
                    .as_ref()
                    .ok_or(DepositServiceError::InvalidLateConsolidationSettlement)?;
                let terminal = candidate_terminal
                    .as_ref()
                    .ok_or(DepositServiceError::InvalidPortableTerminalEvidence)?;
                let completion = settlement.historical_completion();
                let PortableConsolidationStatus::Abandoned { evidence } = prior.status() else {
                    return Err(DepositServiceError::InvalidLateConsolidationSettlement);
                };
                let archived = self
                    .roast_archive
                    .verify_prefix_transaction(
                        runtime.snapshot.roast_attempt_archive_head(),
                        runtime.deriver.wallet_id(),
                        evidence.attempt_prefix(),
                        completion.transaction_id(),
                    )
                    .await?;
                let inclusion =
                    VerifiedCanonicalSweepInclusion::from_current_committee_certificate(
                        lane.ledger.statement.digest(),
                        evidence.roast_family(),
                        completion.transaction_id(),
                        consolidation_signed_bytes_binding(
                            completion.signed_transaction().as_bytes(),
                        ),
                        evidence.attempt_prefix(),
                        settlement.inclusion(),
                        settlement.observation_tip(),
                        settlement.finality_depth(),
                    )?;
                let (verified, verified_archived) = worker
                    .verify_archived_prefix_sweep_completion(
                        lane.ledger.statement.digest(),
                        completion.plan(),
                        archived,
                        inclusion,
                        prior,
                    )?;
                worker.adopt_verified_public_sweep_completion(verified, terminal)?;
                consolidation.record_verified_archived_chain_authoritative_settlement(
                    completion.id(),
                    verified_archived,
                )?;
            }
            LedgerPayload::Allocation(_) | LedgerPayload::HandoffFence(_) => {}
            LedgerPayload::Handoff(_) => {}
        }

        let old_protocol = protocol.clone();
        let mut compact_guard = self.compact_registry.lock().await;
        let compact_store =
            compact_guard.as_mut().ok_or(DepositServiceError::InvalidCompactRegistryCheckpoint)?;
        let expected_compact = compact_store.checkpoint().clone();
        if runtime.snapshot.compact_registry_checkpoint() != &expected_compact {
            return Err(DepositServiceError::InvalidCompactRegistryCheckpoint);
        }
        let prepared_compact =
            if matches!(&lane.ledger.statement.payload, LedgerPayload::Handoff(_)) {
                let source = protocol
                    .pending_handoff_source
                    .as_ref()
                    .ok_or(DepositServiceError::WrongRegistry)?;
                let target =
                    protocol.pending_handoff.as_ref().ok_or(DepositServiceError::WrongRegistry)?;
                let verified_target = VerifiedRegistryHandoffTarget::from_verified_activation(
                    Some(source),
                    target.clone(),
                    protocol
                        .pending_handoff_fault_bound
                        .ok_or(DepositServiceError::WrongRegistry)?,
                    protocol.pending_handoff_root.ok_or(DepositServiceError::WrongRegistry)?,
                    &runtime.deriver,
                )?;
                let handoff_certificate =
                    lane.ledger.registry_handoff_certificate(&protocol.registry)?;
                Some(
                    compact_store
                        .prepare_append(
                            &verified_target,
                            handoff_certificate,
                            checkpoint_certificate.statement().previous_head(),
                        )
                        .await?,
                )
            } else {
                None
            };
        let mut obsolete_observations = Vec::new();
        let adopt_result = (|| -> Result<(), DepositServiceError> {
            protocol.adopt_certificate(
                lane.ledger.clone(),
                &runtime.deriver,
                historical.as_ref(),
                &preflight,
                &transition,
            )?;
            if let Some(prepared_registry) = &prepared_compact {
                let old = protocol.registry.clone();
                let new = prepared_registry.proposed_head().registry().clone();
                protocol.ledger.apply_registry_extension(
                    &old,
                    &new,
                    &lane.ledger,
                    &preflight,
                    &transition,
                )?;
                protocol.registry = new;
                obsolete_observations = protocol.reissue_pending_observations_for_active()?;
                protocol.pending_handoff = None;
                protocol.pending_handoff_source = None;
                protocol.pending_handoff_fault_bound = None;
                protocol.pending_handoff_root = None;
                protocol.pending_handoff_fence = None;
            }
            Ok(())
        })();
        if let Err(error) = adopt_result {
            if let Some(prepared_registry) = &prepared_compact {
                compact_store.abort_prepared(prepared_registry).await?;
            }
            return Err(error);
        }
        let prepared = match store.prepare_snapshot(updates).await {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Some(prepared_registry) = &prepared_compact {
                    compact_store.abort_prepared(prepared_registry).await?;
                }
                return Err(error.into());
            }
        };
        let candidate_result = (|| -> Result<DepositServiceSnapshot, DepositServiceError> {
            let context = DepositSyncContext::new(
                self.scenario.quic_network_id()?,
                runtime.deriver.wallet_id(),
            )?;
            let binding = DepositIndexCheckpointLedgerBinding::new(
                context,
                checkpoint_certificate.statement().sequence(),
                archive_append.entry_artifact,
                &lane.ledger,
            )?;
            let mut messages = self.index_checkpoint_certificate_messages(
                &old_protocol,
                binding,
                checkpoint_certificate.clone(),
            )?;
            if prepared_compact.is_some() {
                messages.extend(self.index_checkpoint_certificate_messages(
                    &protocol,
                    binding,
                    checkpoint_certificate.clone(),
                )?);
            }
            let mut candidate = runtime.snapshot.clone();
            let compact_transition = prepared_compact.as_ref().map(|prepared_registry| {
                (&expected_compact, prepared_registry.checkpoint().clone())
            });
            candidate.finalize_certified_index_transition(
                protocol.encode_local(&runtime.deriver)?,
                worker,
                &consolidation,
                &expected_index,
                prepared.checkpoint().clone(),
                archive_append.head,
                archive_append.entry_artifact,
                &lane.ledger.statement,
                checkpoint_certificate,
                compact_transition,
                messages,
            )?;
            for statement in &obsolete_observations {
                candidate.prune_deposit_observation_outbox_in_place(statement)?;
            }
            candidate.validate()?;
            Ok(candidate)
        })();
        let candidate = match candidate_result {
            Ok(candidate) => candidate,
            Err(error) => {
                let index_abort = store.abort_prepared(&prepared).await;
                let compact_abort: Result<(), DepositServiceError> = match &prepared_compact {
                    Some(prepared_registry) => {
                        compact_store.abort_prepared(prepared_registry).await.map_err(Into::into)
                    }
                    None => Ok(()),
                };
                if let Err(abort_error) = index_abort {
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(abort_error.into());
                }
                if let Err(abort_error) = compact_abort {
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(abort_error);
                }
                return Err(error);
            }
        };
        let target_compact = prepared_compact
            .as_ref()
            .map_or(&expected_compact, |prepared_registry| prepared_registry.checkpoint());
        let durable = match self.repository.persist_and_read_back(&candidate).await {
            Ok(durable) => durable,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint()
                        && authenticated.compact_registry_checkpoint() == target_compact
                        && authenticated.archive_head()? == archive_append.head
                        && authenticated.checkpoint_operation_certificate()
                            == Some(archive_append.entry_artifact) =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == &expected_index
                        && authenticated.compact_registry_checkpoint() == &expected_compact
                        && authenticated.archive_head()? == runtime.snapshot.archive_head()? =>
                {
                    let index_abort = store.abort_prepared(&prepared).await;
                    let compact_abort: Result<(), DepositServiceError> = match &prepared_compact {
                        Some(prepared_registry) => compact_store
                            .abort_prepared(prepared_registry)
                            .await
                            .map_err(Into::into),
                        None => Ok(()),
                    };
                    if let Err(error) = index_abort {
                        *index_guard = None;
                        *compact_guard = None;
                        return Err(error.into());
                    }
                    if let Err(error) = compact_abort {
                        *index_guard = None;
                        *compact_guard = None;
                        return Err(error);
                    }
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(DepositServiceError::StorageRevisionMismatch);
                }
                Err(load_error) => {
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if durable.deposit_index_checkpoint() != prepared.checkpoint()
            || durable.compact_registry_checkpoint() != target_compact
            || durable.archive_head()? != archive_append.head
            || durable.checkpoint_operation_certificate() != Some(archive_append.entry_artifact)
        {
            runtime.snapshot = durable;
            *index_guard = None;
            *compact_guard = None;
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        runtime.snapshot = durable.clone();
        runtime.protocol = protocol;
        runtime.consolidation = consolidation;
        if let Err(error) =
            store.commit_prepared(&prepared, durable.deposit_index_checkpoint()).await
        {
            *index_guard = None;
            *compact_guard = None;
            return Err(error.into());
        }
        if let Some(prepared_registry) = &prepared_compact
            && let Err(error) = compact_store
                .commit_prepared(prepared_registry, durable.compact_registry_checkpoint())
                .await
        {
            *index_guard = None;
            *compact_guard = None;
            return Err(error.into());
        }
        let mut settled_candidate = durable;
        if let Err(error) = settled_candidate.settle_prepared_state_checkpoints(
            prepared.checkpoint(),
            prepared.settled_checkpoint().clone(),
            prepared_compact.as_ref().map(|prepared_registry| {
                (prepared_registry.checkpoint(), prepared_registry.settled_checkpoint().clone())
            }),
        ) {
            *index_guard = None;
            *compact_guard = None;
            return Err(error);
        }
        let settled = match self.repository.persist_and_read_back(&settled_candidate).await {
            Ok(settled) => settled,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint()
                        == prepared.settled_checkpoint()
                        && authenticated.compact_registry_checkpoint()
                            == prepared_compact
                                .as_ref()
                                .map_or(&expected_compact, |prepared_registry| {
                                    prepared_registry.settled_checkpoint()
                                }) =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint()
                        && authenticated.compact_registry_checkpoint() == target_compact =>
                {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(DepositServiceError::StorageRevisionMismatch);
                }
                Err(load_error) => {
                    *index_guard = None;
                    *compact_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if settled.deposit_index_checkpoint() != store.checkpoint()
            || settled.compact_registry_checkpoint() != compact_store.checkpoint()
        {
            runtime.snapshot = settled;
            *index_guard = None;
            *compact_guard = None;
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        runtime.snapshot = settled;
        Ok(())
    }

    /// Install an observation-only n-f checkpoint, its portable first-use/output state, worker
    /// cursor adoption, and archive authority in one outer snapshot CAS. The allocation ledger
    /// sequence/head and next subaddress index remain unchanged.
    async fn finalize_deposit_observation_checkpoint_certificate(
        &self,
        runtime: &mut DepositRuntime,
        mut protocol: DepositProtocolState,
        checkpoint_certificate: DepositIndexCheckpointCertificate,
        now: u64,
    ) -> Result<(), DepositServiceError> {
        validate_now(now)?;
        let lane = protocol
            .observation_checkpoint
            .as_ref()
            .ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?
            .clone();
        let verified_observation = lane.observation.verify_active(&protocol.registry)?;
        let previous = self.authenticated_latest_index_checkpoint(&runtime.snapshot).await?;
        let verified_checkpoint = checkpoint_certificate.verify_active_deposit_observation(
            self.scenario.quic_network_id()?,
            &protocol.registry,
            previous.as_ref(),
            &lane.observation,
        )?;
        if verified_checkpoint.resulting_head()
            != checkpoint_certificate.statement().resulting_head()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }

        let staged_observation = self
            .archive
            .authenticate_certified_deposit_observation_artifact(
                lane.observation_artifact,
                &verified_observation,
            )
            .await?;
        let archive_append = self
            .archive
            .append_deposit_observation_checkpoint(
                runtime.snapshot.archive_head()?,
                staged_observation,
                &checkpoint_certificate,
                &verified_checkpoint,
                &mut rand_core::OsRng,
            )
            .await?;
        if archive_append.observation_artifact != lane.observation_artifact
            || archive_append.head.len() != checkpoint_certificate.statement().sequence()
        {
            return Err(DepositServiceError::InvalidArchiveHead);
        }

        let mut index_guard = self.deposit_index.lock().await;
        let store =
            index_guard.as_mut().ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let expected_index = store.checkpoint().clone();
        if runtime.snapshot.deposit_index_checkpoint() != &expected_index {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        Self::preload_deposit_observation_paths(store, &lane.observation.statement).await?;
        let portable_head = store.portable_head().clone();
        let mut builder = DepositIndexBuilder::new(&*store, portable_head)?;
        if !builder
            .apply_verified_active_deposit_observation(&lane.observation, &protocol.registry)?
        {
            return Err(DepositServiceError::ObservationAlreadyCertified);
        }
        let portable_update =
            builder.finish()?.ok_or(DepositServiceError::InvalidDepositIndexCheckpoint)?;
        let transition = portable_update
            .verify_deposit_observation_transition(&*store, &lane.observation.statement)?;
        checkpoint_certificate.statement().verify_deposit_observation_transition(
            self.scenario.quic_network_id()?,
            &protocol.registry,
            previous.as_ref(),
            &lane.observation,
            &transition,
        )?;
        if PortableDepositIndexHead::from_head(transition.resulting_head())?
            != *verified_checkpoint.resulting_head()
        {
            return Err(DepositServiceError::InvalidDepositIndexCheckpoint);
        }
        let scanner_transition = portable_update.verify_portable_scanner_transition(&*store)?;
        let mut worker =
            runtime.snapshot.worker().cloned().ok_or(DepositServiceError::MissingScannerAnchor)?;
        worker.adopt_verified_portable_scanner_transition(&scanner_transition)?;
        protocol.ledger.adopt_verified_deposit_observation_transition(&transition)?;
        protocol.adopt_deposit_observation_checkpoint(&lane.observation)?;
        let consolidation = runtime.snapshot.consolidation()?;
        let prepared = store.prepare_snapshot(vec![portable_update]).await?;

        let candidate_result = (|| -> Result<DepositServiceSnapshot, DepositServiceError> {
            let context = DepositSyncContext::new(
                self.scenario.quic_network_id()?,
                runtime.deriver.wallet_id(),
            )?;
            let binding = DepositIndexCheckpointObservationBinding::new(
                context,
                checkpoint_certificate.statement().sequence(),
                archive_append.observation_artifact,
                &lane.observation,
            )?;
            let mut messages =
                self.deposit_observation_certificate_messages(&protocol, lane.observation.clone())?;
            messages.extend(self.deposit_observation_checkpoint_certificate_messages(
                &protocol,
                binding,
                checkpoint_certificate.clone(),
            )?);
            let mut candidate = runtime.snapshot.clone();
            candidate.finalize_certified_observation_transition(
                protocol.encode_local(&runtime.deriver)?,
                worker,
                &consolidation,
                &expected_index,
                prepared.checkpoint().clone(),
                archive_append.head,
                archive_append.observation_artifact,
                &lane.observation,
                checkpoint_certificate.clone(),
                messages,
            )?;
            Ok(candidate)
        })();
        let candidate = match candidate_result {
            Ok(candidate) => candidate,
            Err(error) => {
                if let Err(abort_error) = store.abort_prepared(&prepared).await {
                    *index_guard = None;
                    return Err(abort_error.into());
                }
                return Err(error);
            }
        };
        let durable = match self.repository.persist_and_read_back(&candidate).await {
            Ok(durable) => durable,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint()
                        && authenticated.archive_head()? == archive_append.head
                        && authenticated.checkpoint_operation_certificate()
                            == Some(archive_append.observation_artifact)
                        && authenticated.index_checkpoint_certificate()
                            == Some(&checkpoint_certificate) =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == &expected_index
                        && authenticated.archive_head()? == runtime.snapshot.archive_head()? =>
                {
                    if let Err(error) = store.abort_prepared(&prepared).await {
                        *index_guard = None;
                        return Err(error.into());
                    }
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(DepositServiceError::StorageRevisionMismatch);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if durable.deposit_index_checkpoint() != prepared.checkpoint()
            || durable.archive_head()? != archive_append.head
            || durable.checkpoint_operation_certificate()
                != Some(archive_append.observation_artifact)
            || durable.index_checkpoint_certificate() != Some(&checkpoint_certificate)
        {
            runtime.snapshot = durable;
            *index_guard = None;
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        runtime.snapshot = durable.clone();
        runtime.protocol = protocol;
        runtime.consolidation = consolidation;
        if let Err(error) =
            store.commit_prepared(&prepared, durable.deposit_index_checkpoint()).await
        {
            *index_guard = None;
            return Err(error.into());
        }
        let mut settled_candidate = durable;
        if let Err(error) = settled_candidate.settle_prepared_state_checkpoints(
            prepared.checkpoint(),
            prepared.settled_checkpoint().clone(),
            None,
        ) {
            *index_guard = None;
            return Err(error);
        }
        let settled = match self.repository.persist_and_read_back(&settled_candidate).await {
            Ok(settled) => settled,
            Err(save_error) => match self.repository.load(runtime.snapshot.wallet).await {
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint()
                        == prepared.settled_checkpoint()
                        && authenticated.archive_head()? == archive_append.head =>
                {
                    authenticated
                }
                Ok(authenticated)
                    if authenticated.deposit_index_checkpoint() == prepared.checkpoint()
                        && authenticated.archive_head()? == archive_append.head =>
                {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(save_error);
                }
                Ok(authenticated) => {
                    runtime.snapshot = authenticated;
                    *index_guard = None;
                    return Err(DepositServiceError::StorageRevisionMismatch);
                }
                Err(load_error) => {
                    *index_guard = None;
                    return Err(DepositServiceError::AmbiguousStorageCommit {
                        save: save_error.to_string(),
                        load: load_error.to_string(),
                    });
                }
            },
        };
        if settled.deposit_index_checkpoint() != store.checkpoint()
            || settled.archive_head()? != archive_append.head
        {
            runtime.snapshot = settled;
            *index_guard = None;
            return Err(DepositServiceError::StorageRevisionMismatch);
        }
        runtime.snapshot = settled;
        Ok(())
    }

    fn attestation_messages(
        &self,
        protocol: &DepositProtocolState,
        statement: LedgerStatement,
        attestation: SignedEnvelope,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let body = postcard::to_allocvec(&DepositAttestationWire::new(
            &protocol.registry,
            statement.clone(),
            attestation,
        ))?;
        let active = protocol.registry.active();
        let completion_signers = match &statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => {
                Some(completion.attempt().signers())
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => None,
        };
        Ok(attestation_recipients(
            active.committee(),
            active.fault_bound(),
            self.party,
            completion_signers,
        )?
        .into_iter()
        .map(|party| (statement.sequence, party, DepositOperation::Attest, body.clone()))
        .collect())
    }

    fn certificate_messages(
        &self,
        protocol: &DepositProtocolState,
        certificate: CertifiedLedgerEntry,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = certificate.statement.sequence;
        let body = postcard::to_allocvec(&DepositCertificateWire::new(certificate))?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| (sequence, party, DepositOperation::Certificate, body.clone()))
            .collect())
    }

    fn deposit_observation_statement_messages(
        &self,
        protocol: &DepositProtocolState,
        statement: DepositObservationStatement,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = statement.allocation_sequence();
        let body =
            postcard::to_allocvec(&DepositObservationWire::new(&protocol.registry, statement))?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| (sequence, party, DepositOperation::DepositObservation, body.clone()))
            .collect())
    }

    fn deposit_observation_statement_and_attestation_messages(
        &self,
        protocol: &DepositProtocolState,
        statement: DepositObservationStatement,
        attestation: SignedEnvelope,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = statement.allocation_sequence();
        let proposal = postcard::to_allocvec(&DepositObservationWire::new(
            &protocol.registry,
            statement.clone(),
        ))?;
        let attest = postcard::to_allocvec(&DepositObservationAttestationWire::new(
            &protocol.registry,
            statement,
            attestation,
        ))?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .flat_map(|party| {
                [
                    (sequence, party, DepositOperation::DepositObservation, proposal.clone()),
                    (sequence, party, DepositOperation::DepositObservationAttest, attest.clone()),
                ]
            })
            .collect())
    }

    fn deposit_observation_attestation_messages(
        &self,
        protocol: &DepositProtocolState,
        statement: DepositObservationStatement,
        attestation: SignedEnvelope,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = statement.allocation_sequence();
        let body = postcard::to_allocvec(&DepositObservationAttestationWire::new(
            &protocol.registry,
            statement,
            attestation,
        ))?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| {
                (sequence, party, DepositOperation::DepositObservationAttest, body.clone())
            })
            .collect())
    }

    fn deposit_observation_certificate_messages(
        &self,
        protocol: &DepositProtocolState,
        observation: CertifiedDepositObservation,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = observation.statement.allocation_sequence();
        let body = postcard::to_allocvec(&DepositObservationCertificateWire::new(observation))?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| {
                (sequence, party, DepositOperation::DepositObservationCertificate, body.clone())
            })
            .collect())
    }

    fn index_checkpoint_attestation_messages(
        &self,
        protocol: &DepositProtocolState,
        binding: DepositIndexCheckpointLedgerBinding,
        statement: DepositIndexCheckpointStatement,
        witness: SignedEnvelope,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = statement.sequence();
        let body =
            DepositIndexCheckpointAttestWire::new(binding, statement, witness)?.to_bytes()?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| (sequence, party, DepositOperation::IndexCheckpointAttest, body.clone()))
            .collect())
    }

    fn index_checkpoint_certificate_messages(
        &self,
        protocol: &DepositProtocolState,
        binding: DepositIndexCheckpointLedgerBinding,
        certificate: DepositIndexCheckpointCertificate,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = certificate.statement().sequence();
        let body = DepositIndexCheckpointCertificateWire::new(binding, certificate)?.to_bytes()?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| {
                (sequence, party, DepositOperation::IndexCheckpointCertificate, body.clone())
            })
            .collect())
    }

    fn deposit_observation_checkpoint_attestation_messages(
        &self,
        protocol: &DepositProtocolState,
        binding: DepositIndexCheckpointObservationBinding,
        statement: DepositIndexCheckpointStatement,
        witness: SignedEnvelope,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = statement.sequence();
        let body = DepositObservationIndexCheckpointAttestWire::new(binding, statement, witness)?
            .to_bytes()?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| {
                (
                    sequence,
                    party,
                    DepositOperation::DepositObservationIndexCheckpointAttest,
                    body.clone(),
                )
            })
            .collect())
    }

    fn deposit_observation_checkpoint_certificate_messages(
        &self,
        protocol: &DepositProtocolState,
        binding: DepositIndexCheckpointObservationBinding,
        certificate: DepositIndexCheckpointCertificate,
    ) -> Result<Vec<(u64, PartyId, DepositOperation, Vec<u8>)>, DepositServiceError> {
        let sequence = certificate.statement().sequence();
        let body = DepositObservationIndexCheckpointCertificateWire::new(binding, certificate)?
            .to_bytes()?;
        Ok(committee_recipients(protocol.registry.active().committee(), self.party)
            .into_iter()
            .map(|party| {
                (
                    sequence,
                    party,
                    DepositOperation::DepositObservationIndexCheckpointCertificate,
                    body.clone(),
                )
            })
            .collect())
    }
}

fn require_consolidation_signer_quorum(
    committee: &Committee,
    fault_bound: u16,
    signers: &[PartyId],
) -> Result<(), DepositServiceError> {
    let required =
        committee.n().checked_sub(fault_bound).ok_or(DepositServiceError::InvalidProtocolState)?;
    if signers.len() < usize::from(required)
        || signers.iter().any(|party| committee.member(*party).is_err())
    {
        return Err(DepositServiceError::InvalidProtocolState);
    }
    Ok(())
}

fn attestation_recipients(
    committee: &Committee,
    fault_bound: u16,
    local_party: PartyId,
    completion_signers: Option<&[PartyId]>,
) -> Result<Vec<PartyId>, DepositServiceError> {
    if let Some(signers) = completion_signers {
        require_consolidation_signer_quorum(committee, fault_bound, signers)?;
    }
    // Ledger finality is a committee decision, not a second threshold-signing round. Every active
    // member receives the BA winner and may contribute to the independent `n - f` ledger
    // certificate even when it was not selected for the winning FROST attempt.
    Ok(committee_recipients(committee, local_party))
}

fn committee_recipients(committee: &Committee, local_party: PartyId) -> Vec<PartyId> {
    committee.members.iter().map(|member| member.id).filter(|party| *party != local_party).collect()
}

fn build_consolidation_bindings(
    worker: &DepositWorkerState,
    prepared: &PreparedFrostlassSweep,
    committee: &Committee,
    signers: &CanonicalSignerSet,
    registry_digest: [u8; 32],
    activation_digest: [u8; 32],
    session: SessionId,
    attempt_number: u64,
) -> Result<(TransactionAuthorization, AttemptBinding), DepositServiceError> {
    let authorization = build_consolidation_authorization(worker, prepared)?;
    let root_group_key = worker.scan_state().root_spend_key();
    let (worker_intent, signing_context) =
        worker.prepared_signing_binding(prepared, committee, signers, root_group_key, session)?;
    let attempt = AttemptBinding::new(
        attempt_number,
        committee.epoch,
        registry_digest,
        committee.digest(),
        activation_digest,
        root_group_key,
        committee.threshold,
        signers.parties().to_vec(),
        worker_intent,
        session,
        signing_context,
    )?;
    Ok((authorization, attempt))
}

fn build_consolidation_authorization(
    worker: &DepositWorkerState,
    prepared: &PreparedFrostlassSweep,
) -> Result<TransactionAuthorization, DepositServiceError> {
    let intent_bytes = prepared.prepared_intent().encode()?;
    let plan = prepared.plan();
    TransactionAuthorization::new(
        plan.wallet,
        plan.id,
        OpaqueIntentBinding::from_prepared_sweep_bytes(&intent_bytes),
        consolidation_input_set_binding(&plan.inputs),
        plan.destination_binding,
        worker.scan_state().root_spend_key(),
        u32::try_from(plan.inputs.len()).map_err(|_| DepositServiceError::InvalidProtocolState)?,
        plan.total_input_atomic_units,
        prepared.fee_atomic_units(),
        worker.config().maximum_fee_atomic_units,
    )
    .map_err(Into::into)
}

/// Match a completion proposal against this party's already durable local signing state.
///
/// Public ledger validity is necessary but deliberately insufficient for creating an attestation:
/// the private prepared plan, coordinator authorization/attempt, signed binding, and exact Monero
/// bytes must all agree first.
fn local_completion_matches(
    worker: &DepositWorkerState,
    consolidation: &ConsolidationCoordinator,
    completion: &ConsolidationCompletionStatement,
) -> Result<bool, DepositServiceError> {
    let Some(worker_record) = worker.scan_state().sweep(completion.plan().id) else {
        return Ok(false);
    };
    let Some(coordinator_record) = consolidation.record(completion.id()) else {
        return Ok(false);
    };
    let prepared =
        PreparedSweepIntent::decode(worker_record.signing_intent.prepared_sweep_intent_bytes())?;
    let attempt = completion.attempt();
    let Some(tombstone) = coordinator_record.attempts.get(&attempt.attempt()) else {
        return Ok(false);
    };
    let worker_has_exact_signed_bytes = matches!(
        worker_record.status,
        SweepStatus::Signed { transaction }
            | SweepStatus::Confirmed { transaction, .. }
            | SweepStatus::QuarantinedByReorg {
                transaction: Some(transaction),
                ..
            } if transaction == completion.transaction_id()
    );
    let coordinator_has_exact_signed_bytes = matches!(
        coordinator_record.phase,
        ConsolidationPhase::Signed
            | ConsolidationPhase::Confirmed
            | ConsolidationPhase::QuarantinedByInputReorg { .. }
    );
    Ok(prepared.plan() == completion.plan()
        && worker_record.inputs == completion.inputs()
        && worker_has_exact_signed_bytes
        && worker_record.signed_transaction.as_ref() == Some(completion.signed_transaction())
        && coordinator_record.authorization == *completion.authorization()
        && coordinator_has_exact_signed_bytes
        && coordinator_record.signed == Some(completion.signed_binding())
        && tombstone.binding == *attempt
        && tombstone.status == AttemptStatus::Completed)
}

fn public_terminal_completion_matches(
    statement: &LedgerStatement,
    consolidation: &ConsolidationCoordinator,
) -> bool {
    let completion = match &statement.payload {
        LedgerPayload::ConsolidationCompletion(completion) => completion,
        LedgerPayload::LateConsolidationSettlement(settlement) => {
            settlement.historical_completion()
        }
        LedgerPayload::Allocation(_)
        | LedgerPayload::HandoffFence(_)
        | LedgerPayload::Handoff(_)
        | LedgerPayload::ConsolidationAbandonment(_) => return false,
    };
    public_completion_matches(completion, consolidation)
}

fn public_completion_matches(
    completion: &ConsolidationCompletionStatement,
    consolidation: &ConsolidationCoordinator,
) -> bool {
    let Some(record) = consolidation.record(completion.id()) else {
        return false;
    };
    record.authorization == *completion.authorization()
        && record.signed == Some(completion.signed_binding())
        && matches!(
            record.phase,
            ConsolidationPhase::Signed
                | ConsolidationPhase::Broadcast
                | ConsolidationPhase::Confirmed
                | ConsolidationPhase::QuarantinedByInputReorg { .. }
        )
        && record.attempts.get(&completion.attempt().attempt()).is_some_and(|tombstone| {
            tombstone.binding == *completion.attempt()
                && tombstone.status == AttemptStatus::Completed
        })
}

fn record_has_public_terminal_completion(
    protocol: &DepositProtocolState,
    consolidation: &ConsolidationCoordinator,
    record: &ConsolidationRecord,
    portable: Option<&AuthenticatedPortableTerminal>,
) -> bool {
    let matches_record = |statement: &LedgerStatement| {
        public_terminal_completion_matches(statement, consolidation)
            && match &statement.payload {
                LedgerPayload::ConsolidationCompletion(completion) => {
                    completion.id() == record.authorization.id()
                }
                LedgerPayload::LateConsolidationSettlement(settlement) => {
                    settlement.id() == record.authorization.id()
                }
                LedgerPayload::Allocation(_)
                | LedgerPayload::HandoffFence(_)
                | LedgerPayload::Handoff(_)
                | LedgerPayload::ConsolidationAbandonment(_) => false,
            }
    };
    protocol.pending.values().any(|slot| matches_record(&slot.statement))
        || portable.is_some_and(|portable| matches_record(&portable.current_statement))
}

fn record_has_certified_portable_completion(
    portable: Option<&AuthenticatedPortableTerminal>,
    record: &ConsolidationRecord,
) -> bool {
    portable.and_then(AuthenticatedPortableTerminal::completion).is_some_and(|completion| {
        completion.authorization() == &record.authorization
            && record.signed == Some(completion.signed_binding())
            && record.attempts.get(&completion.attempt().attempt()).is_some_and(|tombstone| {
                tombstone.binding == *completion.attempt()
                    && tombstone.status == AttemptStatus::Completed
            })
    })
}

async fn portable_signed_sweep(
    service: &DepositService,
    runtime: &DepositRuntime,
    sweep: SweepId,
) -> Result<([u8; 32], SignedSweepTransaction, Option<ConsolidationId>), DepositServiceError> {
    let portable = service
        .authenticated_portable_terminal_by_sweep(sweep)
        .await?
        .ok_or(DepositServiceError::ConsolidationNotCertified)?;
    let completion = portable.completion().ok_or(DepositServiceError::ConsolidationNotCertified)?;
    let local = runtime.consolidation.record(completion.id());
    if let Some(record) = local {
        let attempt = record.attempts.get(&completion.attempt().attempt());
        if record.authorization != *completion.authorization()
            || record.signed != Some(completion.signed_binding())
            || !attempt.is_some_and(|attempt| {
                attempt.binding == *completion.attempt()
                    && attempt.status == AttemptStatus::Completed
            })
        {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
    }
    Ok((
        portable.current_statement.digest(),
        completion.signed_transaction().clone(),
        local.map(|record| record.authorization.id()),
    ))
}

fn signed_binding_matches_bytes(
    binding: SignedTransactionBinding,
    signed: &SignedSweepTransaction,
) -> bool {
    let bytes = signed.as_bytes();
    binding.transaction() == signed.transaction_id()
        && binding.exact_bytes_digest() == consolidation_signed_bytes_binding(bytes)
        && usize::try_from(binding.exact_bytes_len()).ok() == Some(bytes.len())
}

fn signed_binding_for(
    authorization: &TransactionAuthorization,
    attempt: &AttemptBinding,
    signed: &SignedSweepTransaction,
) -> Result<SignedTransactionBinding, DepositServiceError> {
    let bytes = signed.as_bytes();
    let exact_bytes_len =
        u32::try_from(bytes.len()).map_err(|_| DepositServiceError::InvalidMessageSize)?;
    Ok(SignedTransactionBinding {
        authorization: authorization.digest(),
        attempt: attempt.attempt(),
        attempt_binding: attempt.digest(),
        session: attempt.session(),
        signing_context: attempt.signing_context(),
        opaque_intent: authorization.opaque_intent(),
        transaction: signed.transaction_id(),
        exact_bytes: consolidation_signed_bytes_binding(bytes),
        exact_bytes_len,
    })
}

/// A chain winner may become durable before its completion BA finishes. During that narrow
/// interval, retain the f+1 ROAST endorsement as the portable authorization which closes the
/// worker/coordinator alignment check. Once the ledger certificate is installed the ordinary
/// portable-completion predicate supersedes this one.
fn record_has_endorsed_chain_settlement(
    snapshot: &DepositServiceSnapshot,
    record: &ConsolidationRecord,
) -> Result<bool, DepositServiceError> {
    if record.phase != ConsolidationPhase::Confirmed || record.confirmation.is_none() {
        return Ok(false);
    }
    let Some(signed) = record.signed else {
        return Ok(false);
    };
    let Some(tombstone) = record.attempts.get(&signed.attempt()) else {
        return Ok(false);
    };
    if tombstone.status != AttemptStatus::Completed {
        return Ok(false);
    }
    let Some(bytes) = snapshot.consolidation_roasts.get(&record.authorization.id()) else {
        return Ok(false);
    };
    let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
    if roast.authorization() != &record.authorization {
        return Ok(false);
    }
    for (view, endorsed) in roast.endorsed_candidates() {
        if endorsed != signed {
            continue;
        }
        let binding = roast.wire_binding(view)?;
        return Ok(binding.attempt() == &tombstone.binding);
    }
    Ok(false)
}

/// Cross-check portable history, permanent worker claims, and the optional party-local signing
/// lifecycle on every restore and before installing a composite candidate.
async fn validate_consolidation_alignment(
    service: &DepositService,
    protocol: &DepositProtocolState,
    snapshot: &DepositServiceSnapshot,
    consolidation: &ConsolidationCoordinator,
) -> Result<(), DepositServiceError> {
    let worker = snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    let mut portable = BTreeMap::new();
    for (_, record) in consolidation.records() {
        let indexed = service
            .authenticated_portable_terminal_by_sweep(record.authorization.sweep_id())
            .await?;
        if indexed
            .as_ref()
            .is_some_and(|indexed| indexed.terminal.consolidation_id() != record.authorization.id())
        {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        portable.insert(record.authorization.id(), indexed);
    }

    for slot in protocol.pending.values() {
        if let LedgerPayload::ConsolidationCompletion(completion) = &slot.statement.payload
            && !local_completion_matches(worker, consolidation, completion)?
            && !public_terminal_completion_matches(&slot.statement, consolidation)
        {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
    }

    for (_, record) in consolidation.records() {
        let sweep = record.authorization.sweep_id();
        let indexed = portable.get(&record.authorization.id()).and_then(Option::as_ref);
        let portable_completion = record_has_certified_portable_completion(indexed, record);
        if indexed.is_some_and(|indexed| indexed.completion().is_some()) && !portable_completion {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        let public_terminal =
            record_has_public_terminal_completion(protocol, consolidation, record, indexed);
        let chain_endorsed = record_has_endorsed_chain_settlement(snapshot, record)?;
        if matches!(record.phase, ConsolidationPhase::Broadcast | ConsolidationPhase::Confirmed)
            && !portable_completion
            && !chain_endorsed
        {
            return Err(DepositServiceError::ConsolidationNotCertified);
        }
        if matches!(
            record.phase,
            ConsolidationPhase::SigningReleased { .. }
                | ConsolidationPhase::AwaitingFreshAttempt { .. }
                | ConsolidationPhase::AttemptsExhausted { .. }
                | ConsolidationPhase::Signed
                | ConsolidationPhase::Broadcast
                | ConsolidationPhase::Confirmed
                | ConsolidationPhase::QuarantinedByInputReorg { .. }
        ) && worker.scan_state().sweep(sweep).is_none()
            && !public_terminal
        {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
    }

    for sweep in worker.scan_state().sweeps() {
        let coordinator_record = consolidation.record_by_sweep(sweep.id);
        if coordinator_record.is_none() {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        let Some(record) = coordinator_record else {
            continue;
        };
        let prepared =
            PreparedSweepIntent::decode(sweep.signing_intent.prepared_sweep_intent_bytes())?;
        let plan = prepared.plan();
        let expected_authorization = TransactionAuthorization::new(
            plan.wallet,
            plan.id,
            OpaqueIntentBinding::from_prepared_sweep_bytes(
                sweep.signing_intent.prepared_sweep_intent_bytes(),
            ),
            consolidation_input_set_binding(&plan.inputs),
            plan.destination_binding,
            worker.scan_state().root_spend_key(),
            u32::try_from(plan.inputs.len())
                .map_err(|_| DepositServiceError::ConsolidationCompletionMismatch)?,
            plan.total_input_atomic_units,
            sweep.signing_intent.fee_atomic_units(),
            worker.config().maximum_fee_atomic_units,
        )?;
        let attempt_matches = record.attempts.values().any(|tombstone| {
            tombstone.binding.session().0 == sweep.signing_intent.session()
                && tombstone.binding.worker_intent_digest() == sweep.signing_intent.intent_digest()
                && tombstone.binding.signing_context() == sweep.signing_intent.signing_context()
                && tombstone.binding.root_group_key() == sweep.signing_intent.group_key()
        });
        let signed_matches = match (&sweep.signed_transaction, record.signed) {
            (Some(signed), Some(binding)) => signed_binding_matches_bytes(binding, signed),
            (None, None) => true,
            _ => false,
        };
        if record.authorization != expected_authorization || !attempt_matches || !signed_matches {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        let phase_matches = match sweep.status {
            SweepStatus::Reserved => record.phase == ConsolidationPhase::IntentReserved,
            SweepStatus::SigningReleased => matches!(
                record.phase,
                ConsolidationPhase::SigningReleased { .. }
                    | ConsolidationPhase::AwaitingFreshAttempt { .. }
                    | ConsolidationPhase::AttemptsExhausted { .. }
            ),
            SweepStatus::Signed { .. } => record.phase == ConsolidationPhase::Signed,
            SweepStatus::Broadcast { .. } => record.phase == ConsolidationPhase::Broadcast,
            SweepStatus::Confirmed { .. } => record.phase == ConsolidationPhase::Confirmed,
            SweepStatus::QuarantinedByReorg { .. } => {
                matches!(record.phase, ConsolidationPhase::QuarantinedByInputReorg { .. })
            }
            SweepStatus::AbandonedByReorg { .. } => {
                matches!(record.phase, ConsolidationPhase::AbandonedByInputReorg { .. })
            }
        };
        if !phase_matches {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
    }
    Ok(())
}

fn consolidation_sessions_for_rollback(
    worker: &DepositWorkerState,
    rollback: &DepositRollback,
) -> Result<Vec<SessionId>, DepositServiceError> {
    let mut sessions = Vec::with_capacity(rollback.quarantined_sweeps.len());
    for sweep in &rollback.quarantined_sweeps {
        let record = worker
            .scan_state()
            .sweep(*sweep)
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        if !matches!(record.status, SweepStatus::QuarantinedByReorg { .. }) {
            return Err(DepositServiceError::ConsolidationCompletionMismatch);
        }
        sessions.push(SessionId(record.signing_intent.session()));
    }
    sessions.sort_unstable();
    sessions.dedup();
    Ok(sessions)
}

/// Mirror an already-staged scanner rollback into the public nonce lifecycle. The caller persists
/// this coordinator together with the post-rollback worker before acknowledging the event batch.
fn apply_consolidation_rollback(
    consolidation: &mut ConsolidationCoordinator,
    rollback: &DepositRollback,
) -> Result<Vec<SessionId>, DepositServiceError> {
    let mut invalidated_sessions = Vec::new();
    for sweep in rollback.invalidated_sweeps.iter().chain(&rollback.quarantined_sweeps) {
        let id = consolidation
            .record_by_sweep(*sweep)
            .map(|record| record.authorization.id())
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        match consolidation.handle_input_reorg(id, rollback.ancestor) {
            Ok(effect) => {
                if let Some(session) = effect.invalidated_session() {
                    invalidated_sessions.push(session);
                }
            }
            Err(ConsolidationError::NoMutation) => {}
            Err(error) => return Err(error.into()),
        }
    }
    for sweep in &rollback.reverted_confirmations {
        let id = consolidation
            .record_by_sweep(*sweep)
            .map(|record| record.authorization.id())
            .ok_or(DepositServiceError::ConsolidationCompletionMismatch)?;
        consolidation.rollback_confirmation(id, rollback.ancestor)?;
    }
    invalidated_sessions.sort_unstable();
    invalidated_sessions.dedup();
    Ok(invalidated_sessions)
}

fn require_no_pending_handoff(protocol: &DepositProtocolState) -> Result<(), DepositServiceError> {
    let pending = protocol.pending.values().any(|slot| {
        matches!(
            &slot.statement.payload,
            LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_)
        )
    });
    let checkpoint = protocol.index_checkpoint.as_ref().is_some_and(|slot| {
        matches!(
            &slot.ledger.statement.payload,
            LedgerPayload::HandoffFence(_) | LedgerPayload::Handoff(_)
        )
    });
    if protocol.pending_handoff.is_some() || pending || checkpoint {
        return Err(DepositServiceError::HandoffPending);
    }
    Ok(())
}

fn statement_is_consensus_committed(
    protocol: &DepositProtocolState,
    statement: &LedgerStatement,
) -> Result<bool, DepositServiceError> {
    let Some(lane) = &protocol.consensus_lane else {
        return Ok(false);
    };
    let Some(commit) = lane.reducer.commit() else {
        return Ok(false);
    };
    let decided = DepositConsensusValue::decode(commit.value())?;
    Ok(lane.purpose.sequence() == statement.sequence && decided.statement == *statement)
}

fn sync_status_matches_runtime(
    status: DepositScannerSyncStatus,
    runtime: &DepositRuntime,
) -> Result<bool, DepositServiceError> {
    let DepositScannerSyncStatus::Ready { scanner_tip, confirmed_horizon } = status else {
        return Ok(false);
    };
    let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    Ok(worker.replay_pending_events()?.is_none()
        && worker.scan_state().tip() == scanner_tip
        && scanner_tip.height >= confirmed_horizon)
}

fn validate_terminal_attempt_against_roast(
    binding: &ConsolidationAttemptWireBinding,
    roast: &ConsolidationRoast,
    worker: &DepositWorkerState,
    expected_network: [u8; 32],
    expected_group_key: [u8; 32],
) -> Result<RetainedByzantineAuthority, DepositServiceError> {
    let view = binding
        .attempt()
        .attempt()
        .checked_sub(1)
        .ok_or(DepositServiceError::InvalidPortableTerminalEvidence)?;
    let slot = roast.expected_slot(view)?;
    if roast.wire_binding(view)? != *binding
        || slot.committee() != roast.committee()
        || slot.fault_bound() != roast.fault_bound()
        || binding.attempt().epoch() != roast.committee().epoch
        || roast.quic_network_id() != expected_network
        || slot.binding().network != expected_network
        || roast.authorization().root_group_key() != expected_group_key
        || worker.scan_state().root_spend_key() != expected_group_key
    {
        return Err(DepositServiceError::InvalidPortableTerminalEvidence);
    }
    binding.validate_authorization(roast.authorization())?;
    binding.validate_active(
        roast.committee(),
        slot.binding().registry,
        slot.binding().activation,
        worker.scan_state().root_spend_key(),
    )?;
    Ok(RetainedByzantineAuthority {
        committee: roast.committee().clone(),
        fault_bound: roast.fault_bound(),
    })
}

async fn require_consolidation_quiescent(
    service: &DepositService,
    runtime: &DepositRuntime,
) -> Result<(), DepositServiceError> {
    let worker = runtime.snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    let mut portable = BTreeMap::new();
    for (_, record) in runtime.consolidation.records() {
        let indexed = service
            .authenticated_portable_terminal_by_sweep(record.authorization.sweep_id())
            .await?;
        if indexed
            .as_ref()
            .is_some_and(|indexed| indexed.terminal.consolidation_id() != record.authorization.id())
        {
            return Err(DepositServiceError::ConsolidationNotPortable);
        }
        portable.insert(record.authorization.id(), indexed);
    }
    // A bootstrap BA lane exists before a coordinator record or ROAST family does.  Treating that
    // gap as quiescent lets an epoch handoff retire the only identity capable of completing (or
    // acknowledging) the already durable old-epoch proposal.
    if runtime.snapshot.byzantine_consensus_lane.is_some()
        || worker.replay_pending_events()?.is_some()
    {
        return Err(DepositServiceError::ConsolidationNotPortable);
    }
    for bytes in runtime.snapshot.consolidation_roasts.values() {
        let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
        let record = runtime
            .consolidation
            .record(roast.authorization_id())
            .ok_or(DepositServiceError::ConsolidationNotPortable)?;
        let indexed = portable.get(&record.authorization.id()).and_then(Option::as_ref);
        if !record_has_certified_portable_completion(indexed, record) {
            return Err(DepositServiceError::ConsolidationNotPortable);
        }
    }
    // No unsealed consolidation relay may straddle the identity cutover.  Messages belonging to
    // a portable completion are safe: the successor runtime can authenticate their historical
    // route and answer from retained certificate/ROAST evidence without restoring a private key.
    for message in runtime
        .snapshot
        .outbox
        .values()
        .filter(|message| message.id.operation == DepositOperation::Consolidation)
    {
        let body = runtime
            .snapshot
            .outbox_bodies
            .get(&message.body_digest)
            .ok_or(DepositServiceError::InvalidOutbox)?;
        let wire = ByzantineConsolidationWireMessage::decode(body)?;
        let roast = match &wire {
            // Consensus traffic is deliberately scoped by the value-independent slot digest,
            // before a winning value-derived ROAST family exists.  Resolve it by the exact slot
            // retained in the family chain; treating `wire.family()` as the post-decision family
            // would strand a lost-ACK consensus relay at every handoff.
            ByzantineConsolidationWireMessage::Consensus(relay) => {
                let mut matched = None;
                for bytes in runtime.snapshot.consolidation_roasts.values() {
                    let candidate = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
                    if candidate.expected_slot(relay.slot().roast_view()).ok().as_ref()
                        == Some(relay.slot())
                    {
                        if matched.replace(candidate).is_some() {
                            return Err(DepositServiceError::InvalidByzantineConsolidationState);
                        }
                    }
                }
                matched.ok_or(DepositServiceError::ConsolidationNotPortable)?
            }
            ByzantineConsolidationWireMessage::CertifiedIntent(_)
            | ByzantineConsolidationWireMessage::Preprocess(_)
            | ByzantineConsolidationWireMessage::KeyImageBinding(_)
            | ByzantineConsolidationWireMessage::Share(_)
            | ByzantineConsolidationWireMessage::Candidate(_) => runtime
                .snapshot
                .roast_by_family(wire.family())
                .map(|(_, roast)| roast)
                .map_err(|_| DepositServiceError::ConsolidationNotPortable)?,
            ByzantineConsolidationWireMessage::Ack(_) => {
                return Err(DepositServiceError::InvalidOutbox);
            }
        };
        let record = runtime
            .consolidation
            .record(roast.authorization_id())
            .ok_or(DepositServiceError::ConsolidationNotPortable)?;
        let indexed = portable.get(&record.authorization.id()).and_then(Option::as_ref);
        if !record_has_certified_portable_completion(indexed, record) {
            return Err(DepositServiceError::ConsolidationNotPortable);
        }
    }
    for (_, record) in runtime.consolidation.records() {
        let indexed = portable.get(&record.authorization.id()).and_then(Option::as_ref);
        let is_portable = record_has_ledger_certified_completion(indexed, record);
        let safe = match record.phase {
            ConsolidationPhase::AbortedBeforeNonce => true,
            ConsolidationPhase::Signed
            | ConsolidationPhase::Broadcast
            | ConsolidationPhase::Confirmed
            | ConsolidationPhase::QuarantinedByInputReorg { .. } => is_portable,
            ConsolidationPhase::IntentReserved
            | ConsolidationPhase::SigningReleased { .. }
            | ConsolidationPhase::AwaitingFreshAttempt { .. }
            | ConsolidationPhase::AttemptsExhausted { .. } => false,
            ConsolidationPhase::AbandonedByInputReorg { .. } => true,
        };
        if !safe {
            return Err(DepositServiceError::ConsolidationNotPortable);
        }
    }
    for sweep in worker.scan_state().sweeps() {
        let portable = runtime.consolidation.record_by_sweep(sweep.id).is_some_and(|record| {
            let indexed = portable.get(&record.authorization.id()).and_then(Option::as_ref);
            record_has_ledger_certified_completion(indexed, record)
        });
        if !portable {
            return Err(DepositServiceError::ConsolidationNotPortable);
        }
    }
    Ok(())
}

fn record_has_ledger_certified_completion(
    portable: Option<&AuthenticatedPortableTerminal>,
    record: &ConsolidationRecord,
) -> bool {
    portable
        .and_then(AuthenticatedPortableTerminal::completion)
        .is_some_and(|completion| completion.authorization() == &record.authorization)
}

fn validate_fresh_registry_genesis(
    registry: &CompactEpochRegistry,
    wallet: DepositWalletId,
    genesis_public: &EpochPublic,
    fault_bound: u16,
    activation: [u8; 32],
    certified_activation_root: [u8; 32],
    first_index: DepositSubaddressIndex,
) -> Result<(), DepositServiceError> {
    registry.validate()?;
    genesis_public.validate()?;
    if registry.wallet() != wallet || genesis_public.committee.epoch != 0 {
        return Err(DepositServiceError::WrongRegistry);
    }
    if registry.active_epoch() == 0 {
        let active = registry.active();
        if active.committee().digest() != genesis_public.committee.digest()
            || active.fault_bound() != fault_bound
            || active.activation() != activation
            || active.certified_activation_root() != certified_activation_root
            || active.key_id() != genesis_public.key_id
            || active.group_key() != genesis_public.group_key_bytes()
            || active.start_sequence() != 1
            || active.first_index() != first_index
            || active.predecessor_ledger_head()
                != crate::compact_epoch_registry::compact_registry_genesis_ledger_head(wallet)
        {
            return Err(DepositServiceError::WrongRegistry);
        }
    }
    Ok(())
}

fn validate_allocate_wire(
    runtime: &DepositRuntime,
    authenticated_party: PartyId,
    wire: &DepositAllocateWire,
) -> Result<(), DepositServiceError> {
    if wire.version != DEPOSIT_WIRE_VERSION || wire.registry != runtime.protocol.registry.digest() {
        return Err(DepositServiceError::InvalidPeerMessage);
    }
    runtime.protocol.registry.active().committee().member(authenticated_party)?;
    Ok(())
}

fn validate_attestation_wire(
    runtime: &DepositRuntime,
    authenticated_party: PartyId,
    wire: &DepositAttestationWire,
) -> Result<(), DepositServiceError> {
    if wire.version != DEPOSIT_WIRE_VERSION
        || wire.registry != runtime.protocol.registry.digest()
        || wire.attestation.from != authenticated_party
    {
        return Err(DepositServiceError::InvalidPeerMessage);
    }
    verify_attestation(&wire.statement, &runtime.protocol.registry, &wire.attestation)?;
    Ok(())
}

fn validate_now(now: u64) -> Result<(), DepositServiceError> {
    if now == 0 || now > 253_402_300_799 {
        return Err(DepositServiceError::InvalidTime);
    }
    Ok(())
}

fn validate_consensus_now(now_unix_ms: u64) -> Result<u64, DepositServiceError> {
    if now_unix_ms == 0 {
        return Err(DepositServiceError::InvalidTime);
    }
    let now = now_unix_ms / 1_000;
    validate_now(now)?;
    Ok(now)
}

fn install_consensus_admission(
    lane: &mut DurableDepositConsensusLane,
    admission: ValidatedDepositConsensusValue,
) -> Result<(), DepositServiceError> {
    if let Some(existing) = lane.admitted_values.get(&admission.digest) {
        if existing != &admission.admitted {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        return Ok(());
    }
    if lane.admitted_values.len() >= MAX_ADMITTED_CONSENSUS_VALUES {
        return Err(DepositServiceError::ConsensusRequestPoolFull);
    }
    lane.admitted_values.insert(admission.digest, admission.admitted);
    // Proposal/address/request lifetime conflicts are burned in the authenticated local safety
    // index before any ledger signature is exposed. The bounded consensus lane retains only the
    // live value; it must not duplicate a deployment-lifetime address set.
    let _ = admission.registration;
    Ok(())
}

fn install_checkpoint_consensus_admission(
    lane: &mut DurableDepositCheckpointConsensusLane,
    admitted_at: u64,
    candidate: DepositIndexCheckpointCandidate,
) -> Result<(), DepositServiceError> {
    validate_now(admitted_at)?;
    let value = candidate.to_consensus_value()?;
    let digest = value.digest();
    let admission = AdmittedDepositCheckpointConsensusValue { admitted_at, candidate };
    if let Some(existing) = lane.admitted_values.get(&digest) {
        // Admission time is local scheduling metadata, not Byzantine-agreed candidate identity.
        // Keep the first durable timestamp when the exact same certified operation is learned
        // again (including while importing its final checkpoint certificate after restart).
        if existing.candidate != admission.candidate {
            return Err(DepositServiceError::InvalidProtocolState);
        }
        return Ok(());
    }
    if lane.admitted_values.len() >= MAX_ADMITTED_CONSENSUS_VALUES {
        return Err(DepositServiceError::ConsensusRequestPoolFull);
    }
    lane.admitted_values.insert(digest, admission);
    Ok(())
}

fn validate_abandonment_observation_locally(
    protocol: &DepositProtocolState,
    snapshot: &DepositServiceSnapshot,
    consolidation: &ConsolidationCoordinator,
    observation: &ConsolidationAbandonmentObservation,
    expected_network: [u8; 32],
) -> Result<(), DepositServiceError> {
    observation.validate_public(protocol, expected_network)?;
    let (_, roast) = snapshot.roast_by_family(observation.family)?;
    let worker = snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    let sweep = observation.authorization.sweep_id();
    let worker_record = worker
        .scan_state()
        .sweep(sweep)
        .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
    let coordinator_record = consolidation
        .record(observation.authorization.id())
        .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
    let coordinator_attempt = coordinator_record
        .attempts
        .get(&observation.attempt.attempt())
        .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
    let plan =
        PreparedSweepIntent::decode(worker_record.signing_intent.prepared_sweep_intent_bytes())?
            .plan()
            .clone();
    let finality_depth = worker.config().confirmation_depth;
    let expected_tip_height = observation
        .ancestor
        .height
        .checked_add(u64::from(finality_depth))
        .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
    let scan = worker.scan_state();
    let missing_inputs = worker_record
        .inputs
        .iter()
        .filter(|input| scan.output(**input).is_none())
        .copied()
        .collect::<Vec<_>>();
    if roast.is_terminal_sealed()
        || roast.authorization() != &observation.authorization
        || roast.attempt_prefix_seal()? != observation.attempt_prefix
        || roast.expected_slot(observation.slot.roast_view())? != observation.slot
        || roast
            .certified_intent(observation.slot.roast_view())
            .is_none_or(|(_, _, certificate)| certificate != &observation.intent_certificate)
        || roast.wire_binding(observation.slot.roast_view())? != observation.binding
        || roast.key_image_certificate(observation.slot.roast_view())
            != Some(&observation.key_images)
        || worker_record.id != sweep
        || worker_record.inputs != observation.inputs
        || worker_record.signing_attempt_high_water != observation.attempt.attempt()
        || !matches!(
            worker_record.status,
            SweepStatus::QuarantinedByReorg { ancestor, transaction: None }
                if ancestor == observation.ancestor
        )
        || coordinator_record.authorization != observation.authorization
        || coordinator_record.attempt_high_water() != observation.attempt.attempt()
        || coordinator_record.signed.is_some()
        || coordinator_attempt.binding != observation.attempt
        || !matches!(
            coordinator_record.phase,
            ConsolidationPhase::QuarantinedByInputReorg { ancestor }
                if ancestor == observation.ancestor
        )
        || plan.id != sweep
        || plan.sequence != observation.sweep_sequence
        || plan.inputs != observation.inputs
        || finality_depth != observation.finality_depth
        || expected_tip_height != observation.observation_tip.height
        || scan.tip().height < expected_tip_height
        || scan.chain_point(observation.ancestor.height) != Some(observation.ancestor)
        || scan.chain_point(expected_tip_height) != Some(observation.observation_tip)
        || missing_inputs != observation.missing_inputs
        || missing_inputs.is_empty()
    {
        return Err(DepositServiceError::InvalidConsolidationAbandonment);
    }
    Ok(())
}

fn locally_observable_abandonments(
    protocol: &DepositProtocolState,
    snapshot: &DepositServiceSnapshot,
    consolidation: &ConsolidationCoordinator,
    expected_network: [u8; 32],
) -> Result<Vec<ConsolidationAbandonmentObservation>, DepositServiceError> {
    let worker = snapshot.worker().ok_or(DepositServiceError::MissingScannerAnchor)?;
    let mut observations = Vec::new();
    for bytes in snapshot.consolidation_roasts.values() {
        let roast = ConsolidationRoast::decode_authenticated_snapshot(bytes)?;
        if roast.is_terminal_sealed() {
            continue;
        }
        let Some(record) = consolidation.record(roast.authorization_id()) else {
            continue;
        };
        let ConsolidationPhase::QuarantinedByInputReorg { ancestor } = record.phase else {
            continue;
        };
        if record.signed.is_some() || record.attempt_high_water() == 0 {
            continue;
        }
        let attempt_number = record.attempt_high_water();
        let view = attempt_number
            .checked_sub(1)
            .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
        let Some(attempt) =
            record.attempts.get(&attempt_number).map(|attempt| attempt.binding.clone())
        else {
            continue;
        };
        let Some(worker_record) = worker.scan_state().sweep(roast.sweep_id()) else {
            continue;
        };
        // Canonical inclusion is authoritative. Once the scanner has retained and fully validated
        // any same-family transaction, the family must settle to those exact bytes instead of
        // collecting an abandonment certificate for its now-stale input observation.
        if worker
            .reconcile_sweep_family_settlements()?
            .iter()
            .any(|settlement| settlement.sweep == roast.sweep_id())
        {
            continue;
        }
        if !matches!(
            worker_record.status,
            SweepStatus::QuarantinedByReorg { ancestor: worker_ancestor, transaction: None }
                if worker_ancestor == ancestor
        ) {
            continue;
        }
        let finality_depth = worker.config().confirmation_depth;
        let Some(tip_height) = ancestor.height.checked_add(u64::from(finality_depth)) else {
            continue;
        };
        let Some(observation_tip) = worker.scan_state().chain_point(tip_height) else {
            continue;
        };
        if worker.scan_state().tip().height < tip_height {
            continue;
        }
        let missing_inputs = worker_record
            .inputs
            .iter()
            .filter(|input| worker.scan_state().output(**input).is_none())
            .copied()
            .collect::<Vec<_>>();
        if missing_inputs.is_empty() {
            continue;
        }
        let plan = PreparedSweepIntent::decode(
            worker_record.signing_intent.prepared_sweep_intent_bytes(),
        )?
        .plan()
        .clone();
        let key_images = roast
            .key_image_certificate(view)
            .cloned()
            .ok_or(DepositServiceError::MissingByzantineKeyImageAuthorization)?;
        let (intent_context, certified_intent, intent_certificate) =
            roast
                .certified_intent(view)
                .ok_or(DepositServiceError::InvalidConsolidationAbandonment)?;
        if certified_intent.authorization() != &record.authorization
            || certified_intent.attempt() != &attempt
        {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        let attempt_prefix = roast.attempt_prefix_seal()?;
        let abandonment_context = consolidation_abandonment_fence_context(
            intent_context,
            intent_certificate,
            roast.family_digest(),
            attempt_prefix,
            ancestor,
            observation_tip,
        )?;
        let active = protocol.registry.active();
        if active.epoch() != attempt.epoch()
            || active.committee() != roast.committee()
            || active.fault_bound() != roast.fault_bound()
            || roast.quic_network_id() != expected_network
            || active.group_key() != record.authorization.root_group_key()
            || active.group_key() != worker.scan_state().root_spend_key()
        {
            return Err(DepositServiceError::InvalidConsolidationAbandonment);
        }
        let observation = ConsolidationAbandonmentObservation {
            version: CONSOLIDATION_ABANDONMENT_OBSERVATION_VERSION,
            network: expected_network,
            registry: active.registry_id().digest(),
            activation: active.activation_binding(),
            family: roast.family_digest(),
            attempt_prefix,
            slot: roast.expected_slot(view)?,
            intent_certificate: intent_certificate.clone(),
            abandonment_context,
            binding: roast.wire_binding(view)?,
            key_images,
            authorization: record.authorization.clone(),
            attempt,
            sweep_sequence: plan.sequence,
            inputs: worker_record.inputs.clone(),
            missing_inputs,
            ancestor,
            observation_tip,
            finality_depth,
        };
        validate_abandonment_observation_locally(
            protocol,
            snapshot,
            consolidation,
            &observation,
            expected_network,
        )?;
        observations.push(observation);
    }
    observations.sort_unstable_by_key(|observation| observation.authorization.id());
    Ok(observations)
}

fn operation_tag(operation: DepositOperation) -> u8 {
    match operation {
        DepositOperation::Allocate => 0,
        DepositOperation::Attest => 1,
        DepositOperation::Certificate => 2,
        DepositOperation::Handoff => 3,
        DepositOperation::DepositObservation => 4,
        DepositOperation::DepositObservationAttest => 5,
        DepositOperation::DepositObservationCertificate => 6,
        DepositOperation::IndexCheckpointAttest => 7,
        DepositOperation::IndexCheckpointCertificate => 8,
        DepositOperation::DepositObservationIndexCheckpointAttest => 9,
        DepositOperation::DepositObservationIndexCheckpointCertificate => 10,
        DepositOperation::SyncHead => 11,
        DepositOperation::SyncObjects => 12,
        DepositOperation::ConsolidationCompletion => 13,
        DepositOperation::Consolidation => 14,
        DepositOperation::ClientRequest => 15,
        DepositOperation::ConsolidationAbandonment => 16,
        DepositOperation::ConsensusProposal => 17,
        DepositOperation::ConsensusMessage => 18,
        DepositOperation::ConsensusCertificate => 19,
    }
}

fn deposit_message_body_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-outbox-body/v1");
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

const fn causal_operation_order(operation: DepositOperation) -> u8 {
    operation.causal_priority()
}

const fn max_deposit_message_bytes(operation: DepositOperation) -> usize {
    match operation {
        DepositOperation::ConsolidationCompletion | DepositOperation::Consolidation => {
            MAX_CONSOLIDATION_MESSAGE_BYTES
        }
        DepositOperation::ConsolidationAbandonment => MAX_CONSOLIDATION_ABANDONMENT_MESSAGE_BYTES,
        DepositOperation::Allocate
        | DepositOperation::Attest
        | DepositOperation::Certificate
        | DepositOperation::DepositObservation
        | DepositOperation::DepositObservationAttest
        | DepositOperation::DepositObservationCertificate
        | DepositOperation::IndexCheckpointAttest
        | DepositOperation::IndexCheckpointCertificate
        | DepositOperation::DepositObservationIndexCheckpointAttest
        | DepositOperation::DepositObservationIndexCheckpointCertificate
        | DepositOperation::Handoff
        | DepositOperation::SyncHead
        | DepositOperation::SyncObjects
        | DepositOperation::ClientRequest
        | DepositOperation::ConsensusProposal
        | DepositOperation::ConsensusMessage
        | DepositOperation::ConsensusCertificate => MAX_DEPOSIT_MESSAGE_BYTES,
    }
}

#[derive(Debug, Error)]
pub enum DepositServiceError {
    #[error("coordinator-free Byzantine consolidation state is not initialized")]
    ByzantineConsolidationUnavailable,
    #[error("durable coordinator-free consolidation state is inconsistent")]
    InvalidByzantineConsolidationState,
    #[error("n-f key-image authorization is not durable for this consolidation family")]
    MissingByzantineKeyImageAuthorization,
    #[error("proof-verified xG/xH equality is unavailable for the key-image authorization")]
    MissingByzantineKeyImageDleqProof,
    #[error("the durable Byzantine consolidation consensus lane is unavailable")]
    ByzantineConsensusUnavailable,
    #[error("coordinator-free consolidation reducer is invalid: {0}")]
    ConsolidationRoast(#[from] ConsolidationRoastError),
    #[error("consolidation intent consensus state is invalid: {0}")]
    ConsolidationConsensus(#[from] ConsolidationConsensusError),
    #[error("deposit wallet is not initialized from an activated root key")]
    NotInitialized,
    #[error("deposit wallet scanner has no durable chain anchor")]
    MissingScannerAnchor,
    #[error("testnet/mainnet deposit scanning requires an explicit deployment-wide birth anchor")]
    MissingConfiguredBirthAnchor,
    #[error("configured deposit birth anchor does not match the pinned daemon chain")]
    BirthAnchorMismatch,
    #[error("explicit deposit birth anchor is not bound by the scenario trust-domain digest")]
    BirthAnchorNotScenarioBound,
    #[error("deposit operation targets an unexpected key epoch")]
    WrongEpoch,
    #[error("old-quorum handoff certificate for epoch {0} is not yet available")]
    CertifiedHandoffUnavailable(u64),
    #[error("deposit operation uses an unauthenticated or stale epoch registry")]
    WrongRegistry,
    #[error("party {0} is the current deposit allocation leader")]
    NotLeader(PartyId),
    #[error("deposit client request is malformed")]
    InvalidRequest,
    #[error("deposit peer message is malformed or its TLS identity is not authorized")]
    InvalidPeerMessage,
    #[error("deposit operation timestamp is invalid")]
    InvalidTime,
    #[error("unsupported deposit service snapshot version {0}")]
    UnsupportedVersion(u16),
    #[error("deposit service snapshot belongs to another wallet")]
    WrongWallet,
    #[error("deposit service snapshot is missing its authenticated archive heads")]
    MissingArchiveHead,
    #[error("deposit service snapshot archive head is malformed")]
    InvalidArchiveHead,
    #[error("deposit reducer snapshot exceeds its bound")]
    ReducerTooLarge,
    #[error("deposit protocol state is inconsistent")]
    InvalidProtocolState,
    #[error("deposit allocation consensus value is malformed or invalid for this ledger slot")]
    InvalidConsensusValue,
    #[error("deposit allocation consensus request pool is exhausted")]
    ConsensusRequestPoolFull,
    #[error("deposit allocation consensus context is unavailable at the local ledger tip")]
    ConsensusUnavailable,
    #[error("deposit protocol state belongs to another local party")]
    WrongLocalParty,
    #[error("deposit ledger slot {0} is unknown")]
    UnknownSlot(u64),
    #[error("deposit ledger slot {0} conflicts with a durable signer lock")]
    SlotConflict(u64),
    #[error("too many pending deposit ledger slots")]
    TooManyPendingSlots,
    #[error("deposit allocation request id was reused with another binding")]
    RequestEquivocation,
    #[error("deposit allocation request was already durably reserved in another ledger branch")]
    RequestAlreadyReserved,
    #[error("deposit allocation timestamp exceeds permitted clock skew")]
    ClockSkew,
    #[error("deposit allocation is already expired")]
    AllocationExpired,
    #[error("deposit attester {0} equivocated")]
    AttestationEquivocation(PartyId),
    #[error("deposit observation conflicts with a previous observation")]
    ObservationEquivocation,
    #[error("too many pending deposit observations")]
    TooManyPendingObservations,
    #[error("deposit observation is not retained in the durable reducer")]
    UnknownDepositObservation,
    #[error("deposit observation or its certificate is malformed")]
    InvalidDepositObservation,
    #[error("deposit observation is already present in the portable checkpointed index")]
    ObservationAlreadyCertified,
    #[error("deposit observation names an address absent from the certified ledger")]
    UnknownDepositAddress,
    #[error("deposit service snapshot exceeds its bound")]
    SnapshotTooLarge,
    #[error("deposit service snapshot has trailing bytes")]
    TrailingBytes,
    #[error("deposit service snapshot is not canonical")]
    NonCanonicalSnapshot,
    #[error("deposit service snapshot serialization failed")]
    Serialization,
    #[error(
        "deposit snapshot persistence was ambiguous: save failed ({save}); authenticated reload failed ({load})"
    )]
    AmbiguousStorageCommit { save: String, load: String },
    #[error("deposit service revision is exhausted")]
    RevisionExhausted,
    #[error("deposit peer message is empty or oversized")]
    InvalidMessageSize,
    #[error("deposit peer message sequence must be non-zero")]
    InvalidSequence,
    #[error("deposit peer outbox capacity is exhausted")]
    OutboxFull,
    #[error("deposit request has more consolidation records than the public status bound")]
    TooManyConsolidationsForRequest,
    #[error("deposit peer outbox entry is inconsistent")]
    InvalidOutbox,
    #[error("deposit peer outbox identifier equivocated")]
    OutboxEquivocation,
    #[error("the durable consolidation Complete-exposure binding is malformed")]
    InvalidConsolidationCompleteExposure,
    #[error("one consolidation session has conflicting durable Complete-exposure bindings")]
    ConsolidationCompleteExposureEquivocation,
    #[error("the durable consolidation Complete-exposure capacity is exhausted")]
    TooManyConsolidationCompleteExposures,
    #[error("deposit wallet journal is invalid: {0}")]
    Wallet(#[from] DepositWalletError),
    #[error("deposit scanner/consolidation worker is invalid: {0}")]
    Worker(#[from] DepositWorkerError),
    #[error("authenticated deposit index storage is invalid: {0}")]
    DepositIndexStore(#[from] DepositIndexStoreError),
    #[error("authenticated deposit index transition is invalid: {0}")]
    DepositIndex(#[from] DepositIndexError),
    #[error("authenticated deposit index checkpoint is invalid: {0}")]
    DepositIndexCheckpoint(#[from] DepositIndexCheckpointError),
    #[error("deposit synchronization/checkpoint wire is invalid: {0}")]
    DepositSyncWire(#[from] DepositSyncWireError),
    #[error("deposit snapshot's authenticated index checkpoint is inconsistent")]
    InvalidDepositIndexCheckpoint,
    #[error("authenticated compact registry storage is invalid: {0}")]
    CompactRegistryStore(#[from] CompactRegistryStoreError),
    #[error("authenticated compact registry is invalid: {0}")]
    CompactRegistry(#[from] CompactRegistryError),
    #[error("authenticated compact registry archive is invalid: {0}")]
    CompactRegistryArchive(#[from] CompactRegistryArchiveError),
    #[error("deposit snapshot's compact registry checkpoint is inconsistent")]
    InvalidCompactRegistryCheckpoint,
    #[error("deposit consolidation coordinator is invalid: {0}")]
    Consolidation(#[from] ConsolidationError),
    #[error("deposit consolidation QUIC message is invalid: {0}")]
    ConsolidationWire(#[from] ConsolidationWireError),
    #[error("deposit allocation consensus is invalid: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("deposit consolidation backend is not configured")]
    ConsolidationBackendUnavailable,
    #[error("deposit consolidation candidate changed while a daemon RPC was in flight")]
    StaleConsolidationCandidate,
    #[error("consolidation recovery history is not a complete continuation of local tombstones")]
    ConsolidationRecoveryHistoryIncomplete,
    #[error("consolidation attempt cannot resume and requires a fresh higher attempt")]
    ConsolidationRecoveryRequired,
    #[error("consolidation recovery is missing a durable status from an exact signer")]
    ConsolidationRecoveryStatusIncomplete,
    #[error("consolidation recovery status conflicts with the leader's permanent attempt history")]
    ConsolidationRecoveryStatusConflict,
    #[error(
        "consolidation recovery is fenced because a signature share was durably exposed; an exact abandonment certificate is required"
    )]
    ConsolidationRecoveryExposureFenced,
    #[error("deposit consolidation cannot progress while epoch handoff is pending")]
    HandoffPending,
    #[error("epoch handoff requires every nonce-bearing consolidation to be portable")]
    ConsolidationNotPortable,
    #[error("a portable consolidation completion does not match local durable signed state")]
    ConsolidationCompletionMismatch,
    #[error("a consolidation round message conflicts with a durable message for that phase")]
    ConsolidationWireEquivocation,
    #[error("portable consolidation terminal evidence is malformed or unauthenticated")]
    InvalidPortableTerminalEvidence,
    #[error("portable consolidation terminal evidence capacity is exhausted")]
    TooMuchPortableTerminalEvidence,
    #[error("consolidation abandonment evidence is malformed or not locally reproducible")]
    InvalidConsolidationAbandonment,
    #[error("late consolidation settlement evidence is malformed or not locally authorized")]
    InvalidLateConsolidationSettlement,
    #[error("the authenticated ROAST attempt archive head or transition is malformed")]
    InvalidRoastAttemptArchive,
    #[error("consolidation abandonment observation pool is exhausted")]
    ConsolidationAbandonmentPoolFull,
    #[error("the durable consolidation attempt is closed to further signing round messages")]
    ConsolidationRoundClosed,
    #[error("portable consolidation certification is required before publication")]
    ConsolidationNotCertified,
    #[error("consolidation inputs must be revalidated on the canonical chain before publication")]
    ConsolidationInputsRequireRevalidation,
    #[error("portable deposit ledger validation failed: {0}")]
    Ledger(#[from] LedgerError),
    #[error("deposit identity operation failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("deposit committee validation failed: {0}")]
    Committee(#[from] crate::committee::CommitteeError),
    #[error("deposit scenario configuration failed: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("deposit epoch key validation failed: {0}")]
    Key(#[from] crate::keys::KeyError),
    #[error("verified registry handoff target is invalid: {0}")]
    KeyRotation(#[from] KeyRotationError),
    #[error("deposit chain source failed: {0}")]
    ChainSource(#[from] crate::deposit_worker::ChainSourceError),
    #[error("deposit service I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("deposit wire serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("deposit wallet snapshot storage failed: {0}")]
    Storage(#[from] StoreError),
    #[error("deposit archive storage or replay failed: {0}")]
    Archive(#[from] DepositArchiveError),
    #[error("ROAST attempt archive storage or proof verification failed: {0}")]
    RoastAttemptArchive(#[from] RoastAttemptArchiveError),
    #[error("deposit snapshot's internal revision differs from authenticated storage metadata")]
    StorageRevisionMismatch,
}

#[cfg(test)]
mod observation_protocol_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::Member,
        config::NetworkKind,
        deposit_consensus::{ConsensusMessage, Proposal, ViewChange, Vote, sign_consensus_message},
        deposit_index::DepositIndexHead,
        deposit_ledger::sign_deposit_observation_attestation,
        keys::PointBytes,
    };

    fn test_identity(party: PartyId, epoch: u64, salt: u8) -> Identity {
        let mut signing = [salt; 32];
        signing[0..2].copy_from_slice(&party.0.to_le_bytes());
        let mut encryption = [salt.wrapping_add(1); 32];
        encryption[0..8].copy_from_slice(&epoch.to_le_bytes());
        encryption[8..10].copy_from_slice(&party.0.to_le_bytes());
        Identity::from_test_secrets(party, epoch, &signing, encryption).unwrap()
    }

    fn test_committee(epoch: u64, salt: u8) -> (Committee, BTreeMap<PartyId, Identity>) {
        let identities = (1_u16..=4)
            .map(|number| {
                let party = PartyId(number);
                (party, test_identity(party, epoch, salt.wrapping_add(number as u8)))
            })
            .collect::<BTreeMap<_, _>>();
        let members = identities
            .values()
            .map(|identity| Member {
                id: identity.party(),
                signing_key: identity.signing_public_key(),
                encryption_key: identity.encryption_public_key(),
            })
            .collect();
        (Committee { epoch, threshold: 2, members }, identities)
    }

    fn test_deriver_with_root(root_scalar: u64) -> DepositAddressDeriver {
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(root_scalar)).compress().to_bytes();
        DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap()
    }

    fn test_deriver() -> DepositAddressDeriver {
        test_deriver_with_root(42)
    }

    fn test_registry(
        deriver: &DepositAddressDeriver,
        salt: u8,
    ) -> (CompactEpochRegistry, BTreeMap<PartyId, Identity>, DepositIndexHead) {
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let portable = DepositIndexHead::empty_portable(deriver.wallet_id(), first_index).unwrap();
        let (committee, identities) = test_committee(0, salt);
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            [salt.wrapping_add(1); 32],
            [salt.wrapping_add(2); 32],
            deriver.wallet_id(),
            [salt.wrapping_add(3); 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, first_index, portable.digest()).unwrap();
        (pending.proposed_head().registry().clone(), identities, portable)
    }

    fn protocol_fixture()
    -> (DepositProtocolState, DepositAddressDeriver, BTreeMap<PartyId, Identity>, LedgerStatement)
    {
        let deriver = test_deriver();
        let (registry, identities, portable) = test_registry(&deriver, 0x20);
        let logical = PortableDepositIndexHead::from_head(&portable).unwrap();
        let ledger = CompactLedgerCursor::genesis(&registry, &logical).unwrap();
        let allocation = LedgerStatement::allocation(
            &registry,
            ledger.next_sequence(),
            ledger.head(),
            LedgerRequestId([0x31; 32]),
            RequestBinding([0x32; 32]),
            deriver.derive(ledger.next_index()),
            ChainPoint::new(10, [0x33; 32]).unwrap(),
            1_700_000_000,
        )
        .unwrap();
        let protocol = DepositProtocolState::genesis(PartyId(1), registry, ledger).unwrap();
        (protocol, deriver, identities, allocation)
    }

    fn consensus_fixture() -> (ConsensusContext, BTreeMap<PartyId, Identity>) {
        let (protocol, deriver, identities, _) = protocol_fixture();
        let context =
            deposit_consensus_context(&protocol, deriver.wallet_id(), [0x55; 32]).unwrap();
        (context, identities)
    }

    fn opaque_consensus_value(tag: u8) -> ConsensusValue {
        ConsensusValue::new(vec![tag; 16]).unwrap()
    }

    fn prepare_certificate(
        context: &ConsensusContext,
        identities: &BTreeMap<PartyId, Identity>,
        view: u64,
        value: &ConsensusValue,
    ) -> PrepareCertificate {
        let witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    context,
                    identity,
                    ConsensusMessageBody::Prevote(Vote { view, value: value.digest() }),
                )
                .unwrap()
            })
            .collect();
        PrepareCertificate::from_witnesses(context, view, value.clone(), witnesses).unwrap()
    }

    fn view_certificate(
        context: &ConsensusContext,
        identities: &BTreeMap<PartyId, Identity>,
        target_view: u64,
        prepared: &PrepareCertificate,
    ) -> ViewChangeCertificate {
        let witnesses = identities
            .values()
            .take(3)
            .enumerate()
            .map(|(index, identity)| {
                sign_consensus_message(
                    context,
                    identity,
                    ConsensusMessageBody::ViewChange(ViewChange {
                        from_view: target_view - 1,
                        target_view,
                        highest_prepared: (index == 0).then(|| prepared.clone()),
                    }),
                )
                .unwrap()
            })
            .collect();
        ViewChangeCertificate::from_witnesses(context, target_view, witnesses).unwrap()
    }

    fn referenced_digests(wire: &DepositConsensusWire) -> BTreeSet<ConsensusValueDigest> {
        referenced_deposit_consensus_values(wire)
            .unwrap()
            .into_iter()
            .map(|value| value.digest())
            .collect()
    }

    #[test]
    fn referenced_values_expose_a_direct_proposal_value() {
        let (context, identities) = consensus_fixture();
        let value = opaque_consensus_value(0x81);
        let leader = context.leader(0);
        let envelope = sign_consensus_message(
            &context,
            identities.get(&leader).unwrap(),
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: value.clone(),
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        let wire = DepositConsensusWire::envelope(
            context.clone(),
            DepositConsensusPurpose::NextLedgerSlot { sequence: context.sequence() },
            envelope,
        );

        assert_eq!(referenced_digests(&wire), BTreeSet::from([value.digest()]));
    }

    #[test]
    fn referenced_values_expose_proof_and_nested_view_certificate_values() {
        let (context, identities) = consensus_fixture();
        let direct = opaque_consensus_value(0x82);
        let proof_value = opaque_consensus_value(0x83);
        let nested_value = opaque_consensus_value(0x84);
        let proof = prepare_certificate(&context, &identities, 0, &proof_value);
        let nested_prepare = prepare_certificate(&context, &identities, 0, &nested_value);
        let view_change = view_certificate(&context, &identities, 1, &nested_prepare);
        let leader = context.leader(1);

        // Obtain the canonical proposal slot, then sign a shallow-valid but semantically
        // conflicting body. The extractor runs before the reducer by design, so it must surface
        // every value even when the reducer will subsequently reject the proof relationship.
        let template = sign_consensus_message(
            &context,
            identities.get(&leader).unwrap(),
            ConsensusMessageBody::Proposal(Proposal {
                view: 1,
                value: nested_value.clone(),
                proof_of_lock: Some(nested_prepare),
                view_change: Some(view_change.clone()),
            }),
        )
        .unwrap();
        let message = ConsensusMessage::new(
            &context,
            ConsensusMessageBody::Proposal(Proposal {
                view: 1,
                value: direct.clone(),
                proof_of_lock: Some(proof),
                view_change: Some(view_change),
            }),
        );
        let envelope = identities
            .get(&leader)
            .unwrap()
            .sign_envelope(
                context.committee(),
                context.session(),
                None,
                template.sequence,
                postcard::to_allocvec(&message).unwrap(),
            )
            .unwrap();
        decode_consensus_message(&context, &envelope).unwrap();
        let wire = DepositConsensusWire::envelope(
            context.clone(),
            DepositConsensusPurpose::NextLedgerSlot { sequence: context.sequence() },
            envelope,
        );

        assert_eq!(
            referenced_digests(&wire),
            BTreeSet::from([direct.digest(), proof_value.digest(), nested_value.digest()])
        );
    }

    #[test]
    fn referenced_values_expose_a_standalone_view_certificate_value() {
        let (context, identities) = consensus_fixture();
        let value = opaque_consensus_value(0x85);
        let prepared = prepare_certificate(&context, &identities, 0, &value);
        let certificate = view_certificate(&context, &identities, 1, &prepared);
        let wire = DepositConsensusWire::view_certificate(
            context.clone(),
            DepositConsensusPurpose::NextLedgerSlot { sequence: context.sequence() },
            certificate,
        );

        assert_eq!(referenced_digests(&wire), BTreeSet::from([value.digest()]));
    }

    #[test]
    fn referenced_values_expose_a_commit_certificate_value() {
        let (context, identities) = consensus_fixture();
        let value = opaque_consensus_value(0x86);
        let witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::Precommit(Vote { view: 0, value: value.digest() }),
                )
                .unwrap()
            })
            .collect();
        let certificate =
            CommitCertificate::from_witnesses(&context, 0, value.clone(), witnesses).unwrap();
        let wire = DepositConsensusWire::commit_certificate(
            context.clone(),
            DepositConsensusPurpose::NextLedgerSlot { sequence: context.sequence() },
            certificate,
        );

        assert_eq!(referenced_digests(&wire), BTreeSet::from([value.digest()]));
    }

    #[test]
    fn committed_checkpoint_selection_restores_without_reopening_the_slot() {
        let (mut protocol, deriver, identities, statement) = protocol_fixture();
        let payload = statement.attestation_payload().unwrap();
        let attestations = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        protocol.registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence,
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect();
        let entry = CertifiedLedgerEntry { statement, attestations };
        entry.verify_active(&protocol.registry, None).unwrap();
        protocol.retain_certified_pending(&entry, None).unwrap();
        let previous = PortableDepositIndexHead::from_head(
            &DepositIndexHead::empty_portable(deriver.wallet_id(), protocol.ledger.next_index())
                .unwrap(),
        )
        .unwrap();
        let context = deposit_index_checkpoint_consensus_context(
            [0x55; 32],
            &protocol.registry,
            1,
            &previous,
        )
        .unwrap();
        let operation = DepositIndexCheckpointCandidate::Ledger(entry);
        let value = operation.to_consensus_value().unwrap();
        let witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::Precommit(Vote { view: 0, value: value.digest() }),
                )
                .unwrap()
            })
            .collect();
        let commit =
            CommitCertificate::from_witnesses(&context, 0, value.clone(), witnesses).unwrap();
        let mut reducer = DepositConsensus::new(context, PartyId(1)).unwrap();
        reducer
            .handle_commit_certificate_with_validator(commit.clone(), |candidate| {
                candidate == &value
            })
            .unwrap();
        let mut lane = DurableDepositCheckpointConsensusLane::new(
            DepositConsensusPurpose::NextIndexCheckpoint { sequence: 1 },
            reducer,
            1_699_999_999,
            1_700_000_999_000,
        )
        .unwrap();
        install_checkpoint_consensus_admission(&mut lane, 1_699_999_999, operation.clone())
            .unwrap();
        install_checkpoint_consensus_admission(&mut lane, 1_700_000_123, operation).unwrap();
        assert_eq!(lane.admitted_values.get(&value.digest()).unwrap().admitted_at, 1_699_999_999,);
        protocol.checkpoint_consensus_lane = Some(lane);
        protocol.validate(&deriver).unwrap();

        let registry = protocol.registry.clone();
        let ledger = protocol.ledger.clone();
        let encoded = protocol.encode_local(&deriver).unwrap();
        let restored =
            DepositLocalState::decode(&encoded, registry, ledger, &deriver, PartyId(1), [0x55; 32])
                .unwrap();
        let restored_lane = restored.checkpoint_consensus_lane.unwrap();
        assert_eq!(restored_lane.reducer.commit(), Some(&commit));
        assert_eq!(
            DepositIndexCheckpointCandidate::from_consensus_value(
                restored_lane.reducer.commit().unwrap().value()
            )
            .unwrap()
            .operation(),
            DepositIndexCheckpointOperation::Ledger {
                statement: restored_lane
                    .admitted_values
                    .values()
                    .next()
                    .and_then(|admitted| match &admitted.candidate {
                        DepositIndexCheckpointCandidate::Ledger(entry) => {
                            Some(entry.statement.digest())
                        }
                        DepositIndexCheckpointCandidate::DepositObservation(_) => None,
                    })
                    .unwrap(),
            }
        );
    }

    /// Regression guard for the checkpoint-commit livelock (Byzantine liveness).
    ///
    /// A certified ledger entry `L` and a certified observation `O` compete for the same portable
    /// checkpoint sequence `s`. The checkpoint BA lane commits `O` while `L` stays certified. The
    /// fixed behavior is that the *committed BA lane* — not the `next_certified_ledger_entry`
    /// fallback — decides which operation the durable checkpoint round signs:
    ///
    /// * the observation checkpoint stages and completes even though a certified ledger entry
    ///   exists (the losing `L` must not veto `O`'s staging), advancing `checkpoint_sequence`;
    /// * a restart resumes the committed `O`, never the certified-but-losing `L`;
    /// * once `O` is adopted, `L` becomes the winning candidate for the next sequence `s + 1`.
    ///
    /// This fails if the observation staging guard is reverted to key on
    /// `next_certified_ledger_entry`, or if progress/recovery consult
    /// `next_certified_ledger_entry` before the committed checkpoint lane, because both regressions
    /// resurrect the permanent redispatch of the losing lane.
    #[test]
    fn committed_observation_checkpoint_wins_over_losing_certified_ledger_and_ledger_follows_at_next_sequence()
     {
        struct EmptyReader;
        impl DepositIndexReader for EmptyReader {
            fn load_index_object(
                &self,
                _id: DepositIndexObjectId,
            ) -> Result<Option<Vec<u8>>, DepositIndexError> {
                Ok(None)
            }
        }

        #[derive(Default)]
        struct MemReader {
            objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
        }
        impl MemReader {
            fn apply(&mut self, update: &DepositIndexUpdate) {
                for id in update.obsolete_objects() {
                    self.objects.remove(&id);
                }
                self.objects
                    .extend(update.staged_objects().map(|(id, bytes)| (id, bytes.to_vec())));
            }
        }
        impl DepositIndexReader for MemReader {
            fn load_index_object(
                &self,
                id: DepositIndexObjectId,
            ) -> Result<Option<Vec<u8>>, DepositIndexError> {
                Ok(self.objects.get(&id).cloned())
            }
        }

        let network = [0x55; 32];
        let (mut protocol, deriver, identities, allocation) = protocol_fixture();
        let registry = protocol.registry.clone();
        let committee = registry.active().committee().clone();

        let certify_ledger = |statement: LedgerStatement| -> CertifiedLedgerEntry {
            let payload = statement.attestation_payload().unwrap();
            let attestations = identities
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
                .collect();
            let entry = CertifiedLedgerEntry { statement, attestations };
            entry.verify_active(&registry, None).unwrap();
            entry
        };

        // ----- Advance the portable index + compact ledger by one certified allocation so an
        // observation of the committed allocation is a legitimate checkpoint candidate. -----
        let head0 =
            DepositIndexHead::empty_portable(deriver.wallet_id(), protocol.ledger.next_index())
                .unwrap();
        let ledger_one = certify_ledger(allocation.clone());
        let reader = EmptyReader;
        let preflight = DepositIndexBuilder::new(&reader, head0.clone())
            .unwrap()
            .preflight_ledger_statement(&ledger_one.statement)
            .unwrap();
        let mut builder = DepositIndexBuilder::new(&reader, head0.clone()).unwrap();
        assert!(builder.apply_verified_active_entry(&ledger_one, &registry, None).unwrap());
        let allocation_update = builder.finish().unwrap().unwrap();
        let allocation_checkpoint_statement = DepositIndexCheckpointStatement::for_transition(
            1_699_999_000,
            network,
            &registry,
            None,
            None,
            &ledger_one,
            &preflight,
            &allocation_update,
            &reader,
        )
        .unwrap();
        let allocation_selection =
            crate::deposit_index_checkpoint::certify_checkpoint_candidate_for_test(
                network,
                &registry,
                allocation_checkpoint_statement.sequence(),
                allocation_checkpoint_statement.previous_head(),
                DepositIndexCheckpointCandidate::Ledger(ledger_one.clone()),
                &identities,
            );
        let allocation_witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        &committee,
                        allocation_checkpoint_statement.slot_session(),
                        None,
                        allocation_checkpoint_statement.sequence(),
                        allocation_checkpoint_statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let allocation_certificate = DepositIndexCheckpointCertificate::from_witnesses(
            network,
            &registry,
            None,
            None,
            &ledger_one,
            allocation_checkpoint_statement,
            allocation_selection,
            allocation_witnesses,
        )
        .unwrap();
        let previous = allocation_certificate
            .verify_active(network, &registry, None, None, &ledger_one)
            .unwrap();
        protocol.ledger = previous.compact_cursor(&registry, Some(&allocation)).unwrap();
        protocol.checkpoint_sequence = previous.sequence();
        assert_eq!(protocol.checkpoint_sequence, 1);
        assert_eq!(protocol.ledger.next_sequence(), 2);
        assert_eq!(protocol.ledger.head(), allocation.digest());

        // ----- Candidate O: certified observation of the now-committed allocation. -----
        let observation_statement = observation_statement(&registry, &allocation, 1);
        let observation = CertifiedDepositObservation {
            statement: observation_statement.clone(),
            attestations: identities
                .values()
                .take(3)
                .map(|identity| {
                    sign_deposit_observation_attestation(
                        identity,
                        &registry,
                        &observation_statement,
                    )
                    .unwrap()
                })
                .collect(),
        };
        observation.verify_active(&registry).unwrap();
        protocol.retain_certified_deposit_observation(&observation).unwrap();

        // ----- Candidate L: certified next ledger slot (sequence s at the ledger level). It stays
        // certified while O wins the checkpoint BA lane. -----
        let losing_ledger_statement = LedgerStatement::allocation(
            &registry,
            protocol.ledger.next_sequence(),
            protocol.ledger.head(),
            LedgerRequestId([0x51; 32]),
            RequestBinding([0x52; 32]),
            deriver.derive(protocol.ledger.next_index()),
            ChainPoint::new(10, [0x34; 32]).unwrap(),
            1_700_000_000,
        )
        .unwrap();
        let losing_ledger = certify_ledger(losing_ledger_statement);
        protocol.retain_certified_pending(&losing_ledger, None).unwrap();
        // The losing ledger candidate really is a certified competitor for this checkpoint slot: a
        // regression that consulted this fallback first would redispatch the wrong lane.
        assert_eq!(
            protocol.next_certified_ledger_entry().map(|entry| entry.statement.digest()),
            Some(losing_ledger.statement.digest())
        );

        // ----- Observation-only checkpoint transition/material for O at sequence s = 2. -----
        let mut mem = MemReader::default();
        mem.apply(&allocation_update);
        let mut observation_builder =
            DepositIndexBuilder::new(&mem, allocation_update.next_head().clone()).unwrap();
        assert!(
            observation_builder
                .apply_verified_active_deposit_observation(&observation, &registry)
                .unwrap()
        );
        let observation_update = observation_builder.finish().unwrap().unwrap();
        let observation_transition = observation_update
            .verify_deposit_observation_transition(&mem, &observation.statement)
            .unwrap();
        let observation_checkpoint_statement =
            DepositIndexCheckpointStatement::for_deposit_observation_transition(
                1_699_999_500,
                network,
                &registry,
                Some(&previous),
                &observation,
                &observation_transition,
            )
            .unwrap();
        assert_eq!(observation_checkpoint_statement.sequence(), 2);

        // ----- Drive the checkpoint BA lane to commit O at sequence s = 2. -----
        let observation_candidate =
            DepositIndexCheckpointCandidate::DepositObservation(observation.clone());
        let ledger_candidate = DepositIndexCheckpointCandidate::Ledger(losing_ledger.clone());
        let observation_value = observation_candidate.to_consensus_value().unwrap();
        let context = deposit_index_checkpoint_consensus_context(
            network,
            &registry,
            2,
            observation_checkpoint_statement.previous_head(),
        )
        .unwrap();
        let commit_witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    &context,
                    identity,
                    ConsensusMessageBody::Precommit(Vote {
                        view: 0,
                        value: observation_value.digest(),
                    }),
                )
                .unwrap()
            })
            .collect();
        let commit = CommitCertificate::from_witnesses(
            &context,
            0,
            observation_value.clone(),
            commit_witnesses,
        )
        .unwrap();
        let mut reducer = DepositConsensus::new(context, PartyId(1)).unwrap();
        reducer
            .handle_commit_certificate_with_validator(commit.clone(), |candidate| {
                candidate == &observation_value
            })
            .unwrap();
        let mut lane = DurableDepositCheckpointConsensusLane::new(
            DepositConsensusPurpose::NextIndexCheckpoint { sequence: 2 },
            reducer,
            1_699_999_800,
            1_700_000_999_000,
        )
        .unwrap();
        install_checkpoint_consensus_admission(
            &mut lane,
            1_699_999_700,
            observation_candidate.clone(),
        )
        .unwrap();
        protocol.checkpoint_consensus_lane = Some(lane);

        // The committed lane, not the fallback, selects O; the certified-but-losing L is blocked
        // from opening its own checkpoint at this sequence.
        assert!(protocol.committed_checkpoint_selection(&observation_candidate).is_ok());
        assert!(matches!(
            protocol.committed_checkpoint_selection(&ledger_candidate),
            Err(DepositServiceError::InvalidDepositIndexCheckpoint)
        ));

        // ----- The observation checkpoint STAGES (despite the certified ledger entry existing)
        // and COMPLETES an n-f witness round. -----
        let observation_artifact = WalletArtifactRef::for_contents(
            WalletId(protocol.ledger.wallet_id().0),
            CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
            &postcard::to_allocvec(&observation).unwrap(),
        )
        .unwrap();
        protocol
            .begin_deposit_observation_checkpoint(
                observation.clone(),
                observation_artifact,
                observation_checkpoint_statement.clone(),
                1_699_999_600,
            )
            .unwrap();
        for identity in identities.values().take(3) {
            let witness = identity
                .sign_envelope(
                    &committee,
                    observation_checkpoint_statement.slot_session(),
                    None,
                    observation_checkpoint_statement.sequence(),
                    observation_checkpoint_statement.to_bytes().unwrap(),
                )
                .unwrap();
            protocol.accept_deposit_observation_checkpoint_witness(witness).unwrap();
        }
        assert!(
            protocol
                .completed_deposit_observation_checkpoint(network, Some(&previous))
                .unwrap()
                .is_some()
        );
        protocol.validate(&deriver).unwrap();

        // ----- Restart: recovery resumes the committed O, not the certified-but-losing L. -----
        let encoded = protocol.encode_local(&deriver).unwrap();
        let mut restored = DepositLocalState::decode(
            &encoded,
            registry.clone(),
            protocol.ledger.clone(),
            &deriver,
            PartyId(1),
            network,
        )
        .unwrap();
        let restored_commit = restored
            .checkpoint_consensus_lane
            .as_ref()
            .and_then(|lane| lane.reducer.commit())
            .expect("committed checkpoint lane survives restart");
        assert_eq!(
            DepositIndexCheckpointCandidate::from_consensus_value(restored_commit.value()).unwrap(),
            observation_candidate,
            "restart must resume the committed observation, never the losing certified ledger"
        );
        assert!(restored.observation_checkpoint.is_some());
        assert!(restored.index_checkpoint.is_none());

        // ----- Adopt O: `checkpoint_sequence` advances (not a silent no-op) and the lane clears. -----
        restored.adopt_deposit_observation_checkpoint(&observation).unwrap();
        assert_eq!(restored.checkpoint_sequence, 2);
        assert!(restored.observation_checkpoint.is_none());
        assert!(restored.checkpoint_consensus_lane.is_none());
        assert!(!restored.pending_observations.contains_key(&observation.statement.output()));

        // ----- L now wins the following checkpoint sequence s + 1 = 3. -----
        let ledger_value = ledger_candidate.to_consensus_value().unwrap();
        let next_context = deposit_index_checkpoint_consensus_context(
            network,
            &registry,
            3,
            observation_checkpoint_statement.resulting_head(),
        )
        .unwrap();
        let next_commit_witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                sign_consensus_message(
                    &next_context,
                    identity,
                    ConsensusMessageBody::Precommit(Vote { view: 0, value: ledger_value.digest() }),
                )
                .unwrap()
            })
            .collect();
        let next_commit = CommitCertificate::from_witnesses(
            &next_context,
            0,
            ledger_value.clone(),
            next_commit_witnesses,
        )
        .unwrap();
        let mut next_reducer = DepositConsensus::new(next_context, PartyId(1)).unwrap();
        next_reducer
            .handle_commit_certificate_with_validator(next_commit, |candidate| {
                candidate == &ledger_value
            })
            .unwrap();
        let mut next_lane = DurableDepositCheckpointConsensusLane::new(
            DepositConsensusPurpose::NextIndexCheckpoint { sequence: 3 },
            next_reducer,
            1_699_999_900,
            1_700_000_999_000,
        )
        .unwrap();
        install_checkpoint_consensus_admission(
            &mut next_lane,
            1_699_999_950,
            ledger_candidate.clone(),
        )
        .unwrap();
        restored.checkpoint_consensus_lane = Some(next_lane);
        assert!(restored.committed_checkpoint_selection(&ledger_candidate).is_ok());
        assert!(matches!(
            restored.committed_checkpoint_selection(&observation_candidate),
            Err(DepositServiceError::InvalidDepositIndexCheckpoint)
        ));
    }

    #[test]
    fn deposit_consensus_value_v4_rejects_old_versions_and_trailing_bytes() {
        let (_, _, _, allocation) = protocol_fixture();
        let current = DepositConsensusValue::new(allocation.clone()).unwrap();
        let decoded = DepositConsensusValue::decode(&current).unwrap();
        assert_eq!(decoded.version, DEPOSIT_CONSENSUS_VALUE_VERSION);

        let stale = DepositConsensusValue {
            version: DEPOSIT_CONSENSUS_VALUE_VERSION - 1,
            statement: allocation,
            terminal_evidence: None,
        };
        let stale = ConsensusValue::new(postcard::to_allocvec(&stale).unwrap()).unwrap();
        assert!(matches!(
            DepositConsensusValue::decode(&stale),
            Err(DepositServiceError::InvalidConsensusValue)
        ));

        let mut trailing = postcard::to_allocvec(&decoded).unwrap();
        trailing.push(0);
        let trailing = ConsensusValue::new(trailing).unwrap();
        assert!(matches!(
            DepositConsensusValue::decode(&trailing),
            Err(DepositServiceError::InvalidConsensusValue)
        ));
    }

    fn observation_statement(
        registry: &CompactEpochRegistry,
        allocation: &LedgerStatement,
        nonce: u64,
    ) -> DepositObservationStatement {
        observation_statement_at(registry, allocation, nonce, 20)
    }

    fn observation_statement_at(
        registry: &CompactEpochRegistry,
        allocation: &LedgerStatement,
        nonce: u64,
        observed_height: u64,
    ) -> DepositObservationStatement {
        let mut transaction = [0x41; 32];
        transaction[..8].copy_from_slice(&nonce.to_le_bytes());
        let mut output_key = [0x42; 32];
        output_key[..8].copy_from_slice(&nonce.to_le_bytes());
        let mut observed_hash = [0x43; 32];
        observed_hash[..8].copy_from_slice(&observed_height.to_le_bytes());
        DepositObservationStatement::new(
            registry,
            allocation,
            WalletOutputId { transaction, index_in_transaction: nonce },
            output_key,
            nonce.checked_add(100).unwrap(),
            10_000,
            ChainPoint::new(observed_height, observed_hash).unwrap(),
            1_700_000_020,
            ChainPoint::new(observed_height.checked_add(9).unwrap(), [0x44; 32]).unwrap(),
            10,
        )
        .unwrap()
    }

    fn byzantine_authority_fixture() -> (DepositRuntime, ConsolidationConsensusSlot, [u8; 32]) {
        let (protocol, deriver, _, _) = protocol_fixture();
        let wallet = deriver.wallet_id();
        let network = [0x55; 32];
        let anchor = ChainPoint::new(0, [0x91; 32]).unwrap();
        let worker =
            DepositWorkerState::new(&deriver, anchor, DepositWorkerConfig::default()).unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let deposit_index_checkpoint =
            DepositIndexStoreCheckpoint::empty(wallet, PartyId(1), first_index).unwrap();
        let active = protocol.registry.active();
        let target = VerifiedRegistryHandoffTarget::for_test(
            active.committee().clone(),
            active.fault_bound(),
            active.activation(),
            active.certified_activation_root(),
            wallet,
            active.key_id(),
            active.group_key(),
        )
        .unwrap();
        let pending_registry = prepare_compact_registry_genesis(
            &target,
            first_index,
            deposit_index_checkpoint.portable_head().digest(),
        )
        .unwrap();
        assert_eq!(pending_registry.proposed_head().registry(), &protocol.registry);
        let compact_registry_checkpoint = CompactRegistryStoreCheckpoint::settled(
            wallet,
            pending_registry.proposed_head().clone(),
        )
        .unwrap();
        let mut snapshot = DepositServiceSnapshot::new_archived(
            wallet,
            network,
            vec![1],
            anchor,
            DepositArchiveHead::empty(wallet).unwrap(),
            compact_registry_checkpoint,
            deposit_index_checkpoint,
        )
        .unwrap();
        snapshot.worker = Some(worker);
        let previous = protocol.ledger.head();
        let sequence = protocol.ledger.next_sequence();
        let height = if previous == [0; 32] { 0 } else { sequence };
        let slot = ConsolidationConsensusSlot::new(
            ConsensusBinding {
                domain: consolidation_intent_consensus_domain(),
                application: CONSOLIDATION_INTENT_APPLICATION.to_vec(),
                wallet: wallet.0,
                network,
                registry: active.registry_id().digest(),
                activation: active.activation_binding(),
            },
            active.committee(),
            active.fault_bound(),
            0,
            height,
            sequence,
            previous,
        )
        .unwrap();
        let consolidation = ConsolidationCoordinator::new(wallet).unwrap();
        (DepositRuntime { deriver, snapshot, protocol, consolidation }, slot, network)
    }

    #[test]
    fn byzantine_authority_rejects_wrong_network_and_wallet_group_bindings() {
        let (mut runtime, slot, network) = byzantine_authority_fixture();
        assert!(validate_active_byzantine_slot(&runtime, &slot, network).is_ok());
        assert!(
            validate_restored_byzantine_authority(
                &runtime.protocol,
                &runtime.snapshot,
                &runtime.deriver,
                network,
            )
            .is_ok()
        );

        assert!(matches!(
            validate_active_byzantine_slot(&runtime, &slot, [0x56; 32]),
            Err(DepositServiceError::WrongRegistry)
        ));

        runtime.deriver = test_deriver_with_root(43);
        assert!(matches!(
            validate_active_byzantine_slot(&runtime, &slot, network),
            Err(DepositServiceError::WrongRegistry)
        ));
        assert!(matches!(
            validate_restored_byzantine_authority(
                &runtime.protocol,
                &runtime.snapshot,
                &runtime.deriver,
                network,
            ),
            Err(DepositServiceError::WrongRegistry)
        ));

        runtime.deriver = test_deriver();
        runtime.snapshot.worker = Some(
            DepositWorkerState::new(
                &test_deriver_with_root(44),
                ChainPoint::new(0, [0x91; 32]).unwrap(),
                DepositWorkerConfig::default(),
            )
            .unwrap(),
        );
        assert!(matches!(
            validate_active_byzantine_slot(&runtime, &slot, network),
            Err(DepositServiceError::WrongRegistry)
        ));
        assert!(matches!(
            validate_restored_byzantine_authority(
                &runtime.protocol,
                &runtime.snapshot,
                &runtime.deriver,
                network,
            ),
            Err(DepositServiceError::WrongRegistry)
        ));
    }

    #[test]
    fn observation_reducer_selects_the_canonical_first_n_minus_f_witnesses() {
        let (mut protocol, _, identities, allocation) = protocol_fixture();
        let statement = observation_statement(&protocol.registry, &allocation, 1);
        assert!(protocol.retain_deposit_observation(statement.clone()).unwrap());
        let mut completed = None;
        for party in [PartyId(4), PartyId(1), PartyId(3)] {
            let witness = sign_deposit_observation_attestation(
                identities.get(&party).unwrap(),
                &protocol.registry,
                &statement,
            )
            .unwrap();
            completed =
                protocol.accept_deposit_observation_attestation(&statement, witness).unwrap();
        }
        let certificate = completed.unwrap();
        assert_eq!(
            certificate.attestations.iter().map(|witness| witness.from).collect::<Vec<_>>(),
            vec![PartyId(1), PartyId(3), PartyId(4)]
        );
        certificate.verify_active(&protocol.registry).unwrap();
    }

    #[test]
    fn observation_reducer_restart_reprogresses_to_the_same_certificate() {
        let (mut protocol, deriver, identities, allocation) = protocol_fixture();
        let statement = observation_statement(&protocol.registry, &allocation, 2);
        protocol.retain_deposit_observation(statement.clone()).unwrap();
        for party in [PartyId(4), PartyId(1)] {
            let witness = sign_deposit_observation_attestation(
                identities.get(&party).unwrap(),
                &protocol.registry,
                &statement,
            )
            .unwrap();
            assert!(
                protocol
                    .accept_deposit_observation_attestation(&statement, witness)
                    .unwrap()
                    .is_none()
            );
        }
        let encoded = DepositLocalState::from_protocol(&protocol).encode().unwrap();
        let mut restarted = DepositLocalState::decode(
            &encoded,
            protocol.registry.clone(),
            protocol.ledger.clone(),
            &deriver,
            protocol.local_party,
            [0x55; 32],
        )
        .unwrap();
        assert_eq!(restarted, protocol);

        let witness = sign_deposit_observation_attestation(
            identities.get(&PartyId(3)).unwrap(),
            &restarted.registry,
            &statement,
        )
        .unwrap();
        let certificate =
            restarted.accept_deposit_observation_attestation(&statement, witness).unwrap().unwrap();
        assert_eq!(
            certificate.attestations.iter().map(|witness| witness.from).collect::<Vec<_>>(),
            vec![PartyId(1), PartyId(3), PartyId(4)]
        );
        let reencoded = DepositLocalState::from_protocol(&restarted).encode().unwrap();
        let replayed = DepositLocalState::decode(
            &reencoded,
            restarted.registry.clone(),
            restarted.ledger.clone(),
            &deriver,
            restarted.local_party,
            [0x55; 32],
        )
        .unwrap();
        assert_eq!(
            replayed.completed_deposit_observation(statement.output()).unwrap(),
            Some(certificate)
        );
    }

    #[test]
    fn invalid_local_admission_capabilities_cannot_fill_the_pending_pool() {
        let (mut protocol, _, _, allocation) = protocol_fixture();
        let before = protocol.clone();
        for nonce in 1..=u64::try_from(MAX_PENDING_DEPOSIT_OBSERVATIONS + 32).unwrap() {
            let statement = observation_statement(&protocol.registry, &allocation, nonce);
            let invalid = VerifiedLocalDepositObservation::for_test(
                statement.wallet_id(),
                statement.allocation_statement(),
                [0xff; 32],
                statement.output(),
                statement.confirmation_horizon(),
            );
            assert!(matches!(
                protocol.retain_locally_verified_deposit_observation(statement, &invalid),
                Err(DepositServiceError::InvalidDepositObservation)
            ));
        }
        assert_eq!(protocol, before);
        assert!(protocol.pending_observations.is_empty());
    }

    #[test]
    fn local_observation_admission_accepts_a_later_verified_scanner_horizon() {
        let (mut protocol, _, _, allocation) = protocol_fixture();
        let statement = observation_statement(&protocol.registry, &allocation, 7);
        let wrong_same_height = VerifiedLocalDepositObservation::for_test(
            statement.wallet_id(),
            statement.allocation_statement(),
            statement.digest(),
            statement.output(),
            ChainPoint::new(statement.confirmation_horizon().height, [0x91; 32]).unwrap(),
        );
        assert!(matches!(
            protocol.retain_locally_verified_deposit_observation(
                statement.clone(),
                &wrong_same_height,
            ),
            Err(DepositServiceError::InvalidDepositObservation)
        ));
        assert!(protocol.pending_observations.is_empty());

        let later_horizon = ChainPoint::new(
            statement.confirmation_horizon().height.checked_add(1).unwrap(),
            [0x92; 32],
        )
        .unwrap();
        let verified = VerifiedLocalDepositObservation::for_test(
            statement.wallet_id(),
            statement.allocation_statement(),
            statement.digest(),
            statement.output(),
            later_horizon,
        );
        assert!(
            protocol
                .retain_locally_verified_deposit_observation(statement.clone(), &verified)
                .unwrap()
        );
        assert_eq!(
            protocol.pending_observations.get(&statement.output()).unwrap().statement,
            statement
        );
    }

    #[test]
    fn certified_handoff_fence_partitions_continuous_observations_across_restart() {
        let (mut protocol, _, _, allocation) = protocol_fixture();
        let (target_committee, _) = test_committee(1, 0x91);
        let target = EpochPublic {
            key_id: protocol.registry.active().key_id(),
            committee: target_committee.clone(),
            verification_shares: BTreeMap::new(),
            group_key: PointBytes(protocol.registry.active().group_key()),
        };
        let verified_target = VerifiedRegistryHandoffTarget::for_test(
            target_committee,
            1,
            [0xa1; 32],
            [0xa2; 32],
            protocol.registry.wallet(),
            protocol.registry.active().key_id(),
            protocol.registry.active().group_key(),
        )
        .unwrap();
        let mut cutoff_hash = [0x43; 32];
        cutoff_hash[..8].copy_from_slice(&22_u64.to_le_bytes());
        let cutoff = ChainPoint::new(22, cutoff_hash).unwrap();
        let fence_statement = LedgerStatement::handoff_fence(
            &protocol.registry,
            protocol.ledger.next_sequence(),
            protocol.ledger.head(),
            &verified_target,
            cutoff,
        )
        .unwrap();
        protocol.pending_handoff = Some(target);
        protocol.pending_handoff_fence =
            Some(CertifiedHandoffObservationFence::from_statement(&fence_statement).unwrap());

        for (nonce, height) in (1_u64..=6).zip(20_u64..=25) {
            protocol
                .retain_deposit_observation(observation_statement_at(
                    &protocol.registry,
                    &allocation,
                    nonce,
                    height,
                ))
                .unwrap();
        }
        let source_prefix = protocol
            .pending_observations
            .values()
            .filter(|slot| protocol.observation_is_source_handoff_prefix(&slot.statement))
            .map(|slot| slot.statement.output())
            .collect::<BTreeSet<_>>();
        let successor_suffix = protocol
            .pending_observations
            .values()
            .filter(|slot| !protocol.observation_is_source_handoff_prefix(&slot.statement))
            .map(|slot| slot.statement.output())
            .collect::<BTreeSet<_>>();
        assert_eq!(source_prefix.len(), 3);
        assert_eq!(successor_suffix.len(), 3);
        assert!(source_prefix.is_disjoint(&successor_suffix));

        // The sole supported local schema persists the exact statement-bound cutoff. A restart
        // cannot move the frontier to include payments which arrived later.
        let local = DepositLocalState::from_protocol(&protocol);
        let encoded = local.encode().unwrap();
        let (restarted, trailing) =
            postcard::take_from_bytes::<DepositLocalState>(&encoded).unwrap();
        assert!(trailing.is_empty());
        assert_eq!(restarted, local);
        assert_eq!(restarted.pending_handoff_fence.as_ref().unwrap().cutoff, cutoff);

        // A Byzantine client keeps paying the permanent address. The source drains exactly the
        // certified finite prefix; every later output stays queued and therefore cannot starve
        // the terminal handoff.
        for output in &source_prefix {
            protocol.pending_observations.remove(output);
        }
        for (nonce, height) in (7_u64..=12).zip(26_u64..=31) {
            protocol
                .retain_deposit_observation(observation_statement_at(
                    &protocol.registry,
                    &allocation,
                    nonce,
                    height,
                ))
                .unwrap();
        }
        assert!(!protocol.has_source_handoff_prefix_observations());
        assert_eq!(protocol.pending_observations.len(), 9);
        assert!(
            protocol
                .pending_observations
                .values()
                .all(|slot| !protocol.observation_is_source_handoff_prefix(&slot.statement))
        );

        // Activation removes the source filter. The successor sees the exact suffix, including
        // payments which arrived after the fence, with no prefix output reintroduced.
        protocol.pending_handoff = None;
        protocol.pending_handoff_fence = None;
        let successor_outputs = protocol
            .pending_observations
            .values()
            .filter(|slot| protocol.observation_is_source_handoff_prefix(&slot.statement))
            .map(|slot| slot.statement.output())
            .collect::<BTreeSet<_>>();
        assert_eq!(successor_outputs.len(), 9);
        assert!(successor_outputs.is_disjoint(&source_prefix));
        assert!(successor_suffix.is_subset(&successor_outputs));
    }

    /// Regression for a capacity deadlock: a full peer-facing pool must never wedge worker-batch
    /// replay. `apply_worker_event_batch` replays a durable `WorkerEventBatch` all-or-nothing via
    /// `retain_locally_verified_deposit_observation` and only ACKs (`worker.acknowledge_events`)
    /// after the loop, while every driver (`tick_worker`, `recover_peer_messages`,
    /// `progress_allocation_consensus`, and the apply-message handlers) runs `replay_pending_worker_events`
    /// first, before anything can drain the pool. Under an active handoff fence the retained
    /// post-cutoff suffix is ineligible for checkpoint draining yet still counts toward the cap, so
    /// if the local authority path were bounded by `MAX_PENDING_DEPOSIT_OBSERVATIONS` the reducer
    /// would deadlock permanently — replay would error `TooManyPendingObservations` before the ACK on
    /// every path, forever.
    ///
    /// Phase A reproduces that scenario at the exact call the replay loop makes and asserts the
    /// local detection is admitted while a peer-originated admission at the cap still fails closed
    /// (the Byzantine memory bound is provably retained). Phase B proves the ACK gate: the over-cap
    /// pool still `encode_local`s and decodes, so `commit_protocol` — which `apply_worker_event_batch`
    /// clears before `worker.acknowledge_events` — succeeds and the batch is acknowledged rather than
    /// replayed forever.
    #[test]
    fn full_pending_pool_does_not_deadlock_worker_batch_replay_during_handoff() {
        // Phase A: install the same active handoff fence as
        // `certified_handoff_fence_partitions_continuous_observations_across_restart`.
        let (mut protocol, _, _, allocation) = protocol_fixture();
        let (target_committee, _) = test_committee(1, 0x91);
        let target = EpochPublic {
            key_id: protocol.registry.active().key_id(),
            committee: target_committee.clone(),
            verification_shares: BTreeMap::new(),
            group_key: PointBytes(protocol.registry.active().group_key()),
        };
        let verified_target = VerifiedRegistryHandoffTarget::for_test(
            target_committee,
            1,
            [0xa1; 32],
            [0xa2; 32],
            protocol.registry.wallet(),
            protocol.registry.active().key_id(),
            protocol.registry.active().group_key(),
        )
        .unwrap();
        let mut cutoff_hash = [0x43; 32];
        cutoff_hash[..8].copy_from_slice(&22_u64.to_le_bytes());
        let cutoff = ChainPoint::new(22, cutoff_hash).unwrap();
        let fence_statement = LedgerStatement::handoff_fence(
            &protocol.registry,
            protocol.ledger.next_sequence(),
            protocol.ledger.head(),
            &verified_target,
            cutoff,
        )
        .unwrap();
        protocol.pending_handoff = Some(target);
        protocol.pending_handoff_fence =
            Some(CertifiedHandoffObservationFence::from_statement(&fence_statement).unwrap());

        // Fill the pool to the peer cap with post-cutoff suffix observations (observed height 30 is
        // strictly past the fence cutoff at height 22). Every one is ineligible for checkpoint
        // draining, so the pool cannot self-relieve.
        for nonce in 1..=u64::try_from(MAX_PENDING_DEPOSIT_OBSERVATIONS).unwrap() {
            assert!(
                protocol
                    .retain_deposit_observation(observation_statement_at(
                        &protocol.registry,
                        &allocation,
                        nonce,
                        30,
                    ))
                    .unwrap()
            );
        }
        assert_eq!(protocol.pending_observations.len(), MAX_PENDING_DEPOSIT_OBSERVATIONS);
        assert!(
            protocol
                .pending_observations
                .values()
                .all(|slot| !protocol.observation_is_source_handoff_prefix(&slot.statement)),
            "every retained observation must be a post-cutoff suffix, ineligible for checkpoints",
        );

        // The Byzantine memory bound is retained: a peer-originated admission at the cap fails closed.
        let peer_overflow = observation_statement_at(&protocol.registry, &allocation, 9_000, 30);
        assert!(matches!(
            protocol.retain_deposit_observation(peer_overflow),
            Err(DepositServiceError::TooManyPendingObservations)
        ));
        // Dedup of an already-present output still returns Ok(false) even with a full pool.
        let existing = observation_statement_at(&protocol.registry, &allocation, 1, 30);
        assert!(!protocol.retain_deposit_observation(existing).unwrap());
        assert_eq!(protocol.pending_observations.len(), MAX_PENDING_DEPOSIT_OBSERVATIONS);

        // The worker-batch replay body: one brand-new locally verified detection. This is exactly
        // the call `apply_worker_event_batch` makes per detection before it may ACK. Before the fix
        // this returned `TooManyPendingObservations`; the local authority path must now bypass the
        // cap and admit it.
        let detection = observation_statement_at(&protocol.registry, &allocation, 9_001, 31);
        let verified = VerifiedLocalDepositObservation::for_test(
            detection.wallet_id(),
            detection.allocation_statement(),
            detection.digest(),
            detection.output(),
            detection.confirmation_horizon(),
        );
        assert!(
            protocol
                .retain_locally_verified_deposit_observation(detection.clone(), &verified)
                .unwrap(),
            "a worker-scanned local detection must bypass the peer cap so batch replay reaches its ACK",
        );
        assert_eq!(protocol.pending_observations.len(), MAX_PENDING_DEPOSIT_OBSERVATIONS + 1,);
        assert_eq!(
            protocol.pending_observations.get(&detection.output()).unwrap().statement,
            detection
        );

        // Phase B: the ACK gate. `apply_worker_event_batch` only reaches `worker.acknowledge_events`
        // after `commit_protocol` persists the reducer, and `commit_protocol` re-validates via
        // `encode_local`. An over-cap pool of local detections must therefore still encode and decode
        // canonically, otherwise the batch could never become durable and replay would wedge forever.
        // A validate-clean protocol (no handoff fence) is used so the round-trip exercises the
        // relaxed `validate_inner` capacity invariant directly.
        let (mut clean, deriver, _, clean_allocation) = protocol_fixture();
        for nonce in 1..=u64::try_from(MAX_PENDING_DEPOSIT_OBSERVATIONS + 1).unwrap() {
            let statement = observation_statement(&clean.registry, &clean_allocation, nonce);
            let verified = VerifiedLocalDepositObservation::for_test(
                statement.wallet_id(),
                statement.allocation_statement(),
                statement.digest(),
                statement.output(),
                statement.confirmation_horizon(),
            );
            assert!(
                clean.retain_locally_verified_deposit_observation(statement, &verified).unwrap()
            );
        }
        assert_eq!(clean.pending_observations.len(), MAX_PENDING_DEPOSIT_OBSERVATIONS + 1);
        let encoded = clean.encode_local(&deriver).unwrap();
        let replayed = DepositLocalState::decode(
            &encoded,
            clean.registry.clone(),
            clean.ledger.clone(),
            &deriver,
            clean.local_party,
            [0x55; 32],
        )
        .unwrap();
        assert_eq!(
            replayed.pending_observations.len(),
            MAX_PENDING_DEPOSIT_OBSERVATIONS + 1,
            "the over-cap local pool must survive the encode/validate/decode ACK gate",
        );
    }

    #[test]
    fn successor_reissue_clears_old_witnesses_and_preserves_the_chain_fact() {
        let (mut protocol, deriver, successor_identities, _) = protocol_fixture();
        let (old_registry, old_identities, old_portable) = test_registry(&deriver, 0x60);
        let old_ledger = CompactLedgerCursor::genesis(
            &old_registry,
            &PortableDepositIndexHead::from_head(&old_portable).unwrap(),
        )
        .unwrap();
        let old_allocation = LedgerStatement::allocation(
            &old_registry,
            old_ledger.next_sequence(),
            old_ledger.head(),
            LedgerRequestId([0x71; 32]),
            RequestBinding([0x72; 32]),
            deriver.derive(old_ledger.next_index()),
            ChainPoint::new(10, [0x73; 32]).unwrap(),
            1_700_000_000,
        )
        .unwrap();
        let old = observation_statement(&old_registry, &old_allocation, 9);
        let witness = sign_deposit_observation_attestation(
            old_identities.get(&PartyId(4)).unwrap(),
            &old_registry,
            &old,
        )
        .unwrap();
        protocol.pending_observations.insert(
            old.output(),
            PendingDepositObservationSlot {
                statement: old.clone(),
                attestations: BTreeMap::from([(PartyId(4), witness)]),
            },
        );

        let obsolete = protocol.reissue_pending_observations_for_active().unwrap();
        assert_eq!(obsolete, vec![old.clone()]);
        let successor = protocol.pending_observations.get(&old.output()).unwrap();
        successor.statement.validate_active(&protocol.registry).unwrap();
        assert_eq!(successor.statement.fact_digest(), old.fact_digest());
        assert_ne!(successor.statement.digest(), old.digest());
        assert!(successor.attestations.is_empty());

        let successor_statement = successor.statement.clone();
        for party in [PartyId(1), PartyId(2)] {
            let witness = sign_deposit_observation_attestation(
                successor_identities.get(&party).unwrap(),
                &protocol.registry,
                &successor_statement,
            )
            .unwrap();
            assert!(
                protocol
                    .accept_deposit_observation_attestation(&successor_statement, witness,)
                    .unwrap()
                    .is_none()
            );
        }
        let final_witness = sign_deposit_observation_attestation(
            successor_identities.get(&PartyId(3)).unwrap(),
            &protocol.registry,
            &successor_statement,
        )
        .unwrap();
        assert!(
            protocol
                .accept_deposit_observation_attestation(&successor_statement, final_witness,)
                .unwrap()
                .is_some()
        );
    }
}
