//! Byzantine support certificates for selecting a stable deposit-sync prefix.
//!
//! A moving archive tip is not a consensus value: healthy replicas can answer at pairwise
//! different tips forever while allocations continue. This module instead lets current-epoch
//! members endorse an exact candidate checkpoint after finding its semantic tuple beneath one
//! independently authenticated, immutable local archive anchor. `f + 1` distinct endorsements
//! guarantee that at least one signer is honest; full graph verification remains mandatory before
//! importing the selected state.

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    committee::{CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    compact_epoch_registry::{CompactRegistryError, RegistryId},
    deposit_archive::{
        DepositArchiveError, DepositArchiveEvent, DepositArchiveOperation,
        DepositArchivePrefixTarget, MAX_DEPOSIT_ARCHIVE_EVENT_BYTES, VerifiedDepositArchivePrefix,
    },
    deposit_index_checkpoint::{
        DepositIndexCheckpointCertificate, DepositIndexCheckpointError,
        DepositIndexCheckpointOperation, PortableDepositIndexHead, VerifiedDepositIndexCheckpoint,
    },
    deposit_sync_wire::{
        DepositSyncContext, DepositSyncHeadRequest, DepositSyncHeadResponse,
        DepositSyncObjectAnchor, DepositSyncWireError,
    },
    deposit_wallet::DepositSubaddressIndex,
    identity::{Identity, IdentityError, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::WalletArtifactRef,
};

pub const DEPOSIT_SYNC_SUPPORT_VERSION: u16 = 1;
pub const DEPOSIT_SYNC_SUPPORT_DOMAIN: [u8; 16] = *b"tm-sync-support1";
pub const MAX_DEPOSIT_SYNC_SUPPORT_STATEMENT_BYTES: usize = 16 * 1024;
pub const MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES: usize =
    crate::deposit_archive::MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES
        + MAX_DEPOSIT_ARCHIVE_EVENT_BYTES
        + MAX_DEPOSIT_SYNC_SUPPORT_STATEMENT_BYTES
        + 4096;
pub const MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES: usize =
    MAX_DEPOSIT_SYNC_SUPPORT_STATEMENT_BYTES + 1024;
pub const MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES: usize = MAX_COMMITTEE_MEMBERS
    * MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES
    + MAX_DEPOSIT_SYNC_SUPPORT_STATEMENT_BYTES
    + 4096;
pub const MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_START_BYTES: usize =
    MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES + 1024;
pub const MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_CONTINUE_BYTES: usize = 1024;
pub const MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_PROGRESS_BYTES: usize =
    MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES + 1024;

const SUPPORT_ENDORSEMENT_SESSION_DOMAIN: &[u8] =
    b"threshold-monero/deposit-sync-support/endorsement/v1";
const SUPPORT_STATEMENT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync-support/statement/v1";
const SUPPORT_CERTIFICATE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-sync-support/certificate/v1";
const SUPPORT_ATTEMPT_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-sync-prefix-support/attempt/v1";
const PREFIX_SUPPORT_START_DOMAIN: [u8; 16] = *b"tm-prefix-start1";
const PREFIX_SUPPORT_CONTINUE_DOMAIN: [u8; 16] = *b"tm-prefix-cont01";
const PREFIX_SUPPORT_PROGRESS_DOMAIN: [u8; 16] = *b"tm-prefix-prog01";

/// Exact source candidate which current-epoch members may recognize as a stable prefix.
///
/// Several fields intentionally repeat data committed by `anchor` and `resulting_head`. Those
/// explicit equalities make cross-context, cross-handoff, and partial-tuple replay checks local and
/// unambiguous at every trust boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncSupportStatement {
    version: u16,
    domain: [u8; 16],
    context: DepositSyncContext,
    head_request: [u8; 32],
    requester: PartyId,
    source: PartyId,
    source_lease: [u8; 32],
    anchor: DepositSyncObjectAnchor,
    registry_id: RegistryId,
    active_epoch: u64,
    active_committee: [u8; 32],
    active_fault_bound: u16,
    active_activation: [u8; 32],
    active_certified_activation_root: [u8; 32],
    active_key_id: [u8; 32],
    active_group_key: [u8; 32],
    checkpoint_sequence: u64,
    terminal_event: WalletArtifactRef,
    checkpoint_context: [u8; 32],
    checkpoint_issuer_epoch: u64,
    checkpoint_issuer_committee: [u8; 32],
    checkpoint_issuer_activation: [u8; 32],
    checkpoint_operation: DepositIndexCheckpointOperation,
    checkpoint_update: [u8; 32],
    checkpoint_decision: [u8; 32],
    resulting_head: PortableDepositIndexHead,
    ledger_sequence: u64,
    ledger_head: [u8; 32],
    next_index: DepositSubaddressIndex,
}

impl DepositSyncSupportStatement {
    /// Bind one already validated source response to the exact current deposit registry.
    pub fn from_head_response(
        request: DepositSyncHeadRequest,
        response: &DepositSyncHeadResponse,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Self, DepositSyncSupportError> {
        // This exercises the response's complete private validator and rejects a response which
        // was issued for another source, requester, context, advertisement, or lease.
        response.to_bytes(request)?;
        let advertisement = response.advertisement();
        let checkpoint = advertisement
            .checkpoint_certificate()
            .ok_or(DepositSyncSupportError::InvalidStatement)?;
        let checkpoint_statement = checkpoint.statement();
        let registry = advertisement.registry_archive().registry();
        let issuer = registry.active();
        if advertisement.context() != request.context()
            || issuer.committee().digest() != active.committee().digest()
            || issuer.committee() != active.committee()
            || issuer.fault_bound() != active.fault_bound()
            || issuer.activation() != active.activation()
            || issuer.certified_activation_root() != active.certified_activation_root()
            || issuer.key_id() != active.key_id()
            || issuer.group_key() != active.group_key()
        {
            return Err(DepositSyncSupportError::WrongActiveRegistry);
        }
        let anchor = advertisement.object_anchor();
        let terminal_event =
            anchor.certificate_event_root().ok_or(DepositSyncSupportError::InvalidStatement)?;
        let checkpoint_context = checkpoint_statement.context();
        let statement = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: DEPOSIT_SYNC_SUPPORT_DOMAIN,
            context: request.context(),
            head_request: request.digest(),
            requester: request.requester(),
            source: request.source(),
            source_lease: response.lease().digest(),
            anchor,
            registry_id: advertisement.registry_id(),
            active_epoch: active.committee().epoch,
            active_committee: active.committee().digest(),
            active_fault_bound: active.fault_bound(),
            active_activation: active.activation(),
            active_certified_activation_root: active.certified_activation_root(),
            active_key_id: active.key_id(),
            active_group_key: active.group_key(),
            checkpoint_sequence: checkpoint_statement.sequence(),
            terminal_event,
            checkpoint_context: checkpoint_context.digest(),
            checkpoint_issuer_epoch: checkpoint_context.epoch(),
            checkpoint_issuer_committee: checkpoint_context.committee_digest(),
            checkpoint_issuer_activation: checkpoint_context.activation_digest(),
            checkpoint_operation: checkpoint_statement.operation(),
            checkpoint_update: checkpoint_statement.update_digest(),
            checkpoint_decision: checkpoint_statement.decision_digest(),
            resulting_head: checkpoint_statement.resulting_head().clone(),
            ledger_sequence: checkpoint_statement.ledger_sequence(),
            ledger_head: checkpoint_statement.ledger_decision(),
            next_index: checkpoint_statement.resulting_head().next_index(),
        };
        statement.validate_against(active)?;
        Ok(statement)
    }

    fn validate_static(&self) -> Result<(), DepositSyncSupportError> {
        let canonical_context =
            DepositSyncContext::new(self.context.network(), self.context.wallet())?;
        let canonical_head_request =
            DepositSyncHeadRequest::new(self.context, self.source, self.requester)?;
        self.anchor.validate_context(self.context)?;
        self.registry_id.validate()?;
        self.resulting_head.maximum_reachable_objects()?;
        let checkpoint_operation_digest = match self.checkpoint_operation {
            DepositIndexCheckpointOperation::Ledger { statement }
            | DepositIndexCheckpointOperation::DepositObservation { statement } => statement,
        };
        let maximum_objects = self.resulting_head.maximum_reachable_objects()?;
        if self.version != DEPOSIT_SYNC_SUPPORT_VERSION
            || self.domain != DEPOSIT_SYNC_SUPPORT_DOMAIN
            || canonical_context != self.context
            || self.head_request != canonical_head_request.digest()
            || self.requester.0 == 0
            || self.source.0 == 0
            || self.source_lease == [0; 32]
            || self.registry_id.wallet() != self.context.wallet()
            || self.registry_id.active_epoch() != self.active_epoch
            || self.anchor.wallet() != self.context.wallet()
            || self.anchor.registry_id_digest() != self.registry_id.digest()
            || self.anchor.registry_active_epoch() != self.active_epoch
            || self.active_committee == [0; 32]
            || self.active_activation == [0; 32]
            || self.active_certified_activation_root == [0; 32]
            || self.active_key_id == [0; 32]
            || self.active_group_key == [0; 32]
            || self.checkpoint_sequence == 0
            || self.anchor.checkpoint_sequence() != self.checkpoint_sequence
            || self.anchor.certificate_event_root() != Some(self.terminal_event)
            || self.anchor.certificate_segment_root().is_none()
            || self.checkpoint_context == [0; 32]
            || self.checkpoint_issuer_committee == [0; 32]
            || self.checkpoint_issuer_activation == [0; 32]
            || checkpoint_operation_digest == [0; 32]
            || self.checkpoint_update == [0; 32]
            || self.checkpoint_decision == [0; 32]
            || self.resulting_head.wallet_id() != self.context.wallet()
            || self.resulting_head.through_sequence() == 0
            || self.resulting_head.ledger_head() == [0; 32]
            || self.resulting_head.through_sequence() != self.ledger_sequence
            || self.resulting_head.ledger_head() != self.ledger_head
            || self.resulting_head.next_index() != self.next_index
            || self.anchor.ledger_sequence() != self.ledger_sequence
            || self.anchor.portable_index_digest() != self.resulting_head.digest()
            || self.anchor.portable_root() != self.resulting_head.root()
            || self.anchor.portable_entries() != self.resulting_head.entry_count()
            || self.anchor.portable_maximum_objects() != maximum_objects
        {
            return Err(DepositSyncSupportError::InvalidStatement);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositSyncSupportError> {
        self.validate_static()?;
        active.committee().validate_async_security_with_faults(active.fault_bound())?;
        active.committee().member(self.requester)?;
        // Ordinary support is current-committee sampling. A removed predecessor may export an
        // exact handoff-bound graph only through the separate certified-handoff export path.
        active.committee().member(self.source)?;
        if active.wallet() != self.context.wallet()
            || active.committee().epoch != self.active_epoch
            || active.committee().digest() != self.active_committee
            || active.fault_bound() != self.active_fault_bound
            || active.activation() != self.active_activation
            || active.certified_activation_root() != self.active_certified_activation_root
            || active.key_id() != self.active_key_id
            || active.group_key() != self.active_group_key
        {
            return Err(DepositSyncSupportError::WrongActiveRegistry);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.validate_static()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_SYNC_SUPPORT_STATEMENT_BYTES,
            "deposit sync support statement",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncSupportError> {
        let statement: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_SUPPORT_STATEMENT_BYTES,
            "deposit sync support statement",
        )?;
        statement.validate_static()?;
        Ok(statement)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.to_bytes().expect("validated support statement serializes");
        length_prefixed_hash(SUPPORT_STATEMENT_DIGEST_DOMAIN, &bytes)
    }

    pub fn prefix_target(&self) -> Result<DepositArchivePrefixTarget, DepositSyncSupportError> {
        Ok(DepositArchivePrefixTarget::new(
            self.context.wallet(),
            self.checkpoint_sequence,
            self.terminal_event,
            self.checkpoint_decision,
            self.resulting_head.clone(),
        )?)
    }

    #[must_use]
    pub const fn context(&self) -> DepositSyncContext {
        self.context
    }

    #[must_use]
    pub const fn requester(&self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn source(&self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn source_lease_digest(&self) -> [u8; 32] {
        self.source_lease
    }

    #[must_use]
    pub const fn anchor(&self) -> DepositSyncObjectAnchor {
        self.anchor
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.registry_id
    }

    #[must_use]
    pub const fn active_epoch(&self) -> u64 {
        self.active_epoch
    }

    #[must_use]
    pub const fn active_committee_digest(&self) -> [u8; 32] {
        self.active_committee
    }

    #[must_use]
    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn terminal_event(&self) -> WalletArtifactRef {
        self.terminal_event
    }

    #[must_use]
    pub const fn checkpoint_decision(&self) -> [u8; 32] {
        self.checkpoint_decision
    }

    #[must_use]
    pub const fn resulting_head(&self) -> &PortableDepositIndexHead {
        &self.resulting_head
    }

    #[must_use]
    pub const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn ledger_head(&self) -> [u8; 32] {
        self.ledger_head
    }

    #[must_use]
    pub const fn next_index(&self) -> DepositSubaddressIndex {
        self.next_index
    }
}

/// Candidate statement plus the exact terminal archive event and checkpoint certificate.
///
/// The event proves that the source's advertised terminal reference names these exact checkpoint
/// bytes. Endorsers recognize the witness-independent checkpoint tuple under their own local
/// anchor, whose event/certificate witness subset may differ.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncSupportRequest {
    version: u16,
    domain: [u8; 16],
    statement: DepositSyncSupportStatement,
    terminal_event: DepositArchiveEvent,
    terminal_checkpoint: DepositIndexCheckpointCertificate,
}

impl DepositSyncSupportRequest {
    pub fn new(
        statement: DepositSyncSupportStatement,
        terminal_event: DepositArchiveEvent,
        terminal_checkpoint: DepositIndexCheckpointCertificate,
    ) -> Result<Self, DepositSyncSupportError> {
        let request = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: DEPOSIT_SYNC_SUPPORT_DOMAIN,
            statement,
            terminal_event,
            terminal_checkpoint,
        };
        request.validate()?;
        Ok(request)
    }

    /// Match these exact source certificate bytes to a caller-authenticated verification result.
    ///
    /// Semantic prefix recognition alone is insufficient: a Byzantine source could copy a valid
    /// statement while corrupting its witness set. The non-serializable capability proves that
    /// the complete candidate certificate passed active or archived-issuer verification first.
    pub fn verify_terminal_capability(
        &self,
        verified: &VerifiedDepositIndexCheckpoint,
    ) -> Result<(), DepositSyncSupportError> {
        self.validate()?;
        let certificate_digest = self.terminal_checkpoint.certificate_digest()?;
        let statement = self.terminal_checkpoint.statement();
        if verified.context() != statement.context()
            || verified.sequence() != statement.sequence()
            || verified.decision_digest() != statement.decision_digest()
            || verified.certificate_digest() != certificate_digest
            || verified.operation() != statement.operation()
            || verified.ledger_sequence() != statement.ledger_sequence()
            || verified.ledger_decision() != statement.ledger_decision()
            || verified.update_digest() != statement.update_digest()
            || verified.resulting_head() != statement.resulting_head()
            || verified.signers().len() != self.terminal_checkpoint.witnesses().len()
            || verified
                .signers()
                .iter()
                .copied()
                .zip(self.terminal_checkpoint.witnesses().iter().map(|witness| witness.from))
                .any(|(verified_signer, certificate_signer)| verified_signer != certificate_signer)
        {
            return Err(DepositSyncSupportError::InvalidRequest);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), DepositSyncSupportError> {
        self.statement.validate_static()?;
        let event_bytes = self.terminal_event.to_bytes()?;
        self.statement
            .terminal_event
            .verify_contents(&event_bytes)
            .map_err(|_| DepositSyncSupportError::InvalidRequest)?;
        let checkpoint_bytes = self.terminal_checkpoint.to_bytes()?;
        self.terminal_event
            .checkpoint_reference()
            .verify_contents(&checkpoint_bytes)
            .map_err(|_| DepositSyncSupportError::InvalidRequest)?;
        let checkpoint = self.terminal_checkpoint.statement();
        let event_operation_matches = matches!(
            (self.terminal_event.operation(), checkpoint.operation()),
            (DepositArchiveOperation::Ledger, DepositIndexCheckpointOperation::Ledger { .. })
                | (
                    DepositArchiveOperation::DepositObservation,
                    DepositIndexCheckpointOperation::DepositObservation { .. }
                )
        );
        if self.version != DEPOSIT_SYNC_SUPPORT_VERSION
            || self.domain != DEPOSIT_SYNC_SUPPORT_DOMAIN
            || self.terminal_event.wallet_id() != self.statement.context.wallet()
            || self.terminal_event.ordinal().checked_add(1)
                != Some(self.statement.checkpoint_sequence)
            || !event_operation_matches
            || checkpoint.context().wallet_id() != self.statement.context.wallet()
            || checkpoint.context().network() != self.statement.context.network()
            || checkpoint.sequence() != self.statement.checkpoint_sequence
            || checkpoint.context().digest() != self.statement.checkpoint_context
            || checkpoint.context().epoch() != self.statement.checkpoint_issuer_epoch
            || checkpoint.context().committee_digest() != self.statement.checkpoint_issuer_committee
            || checkpoint.context().activation_digest()
                != self.statement.checkpoint_issuer_activation
            || checkpoint.operation() != self.statement.checkpoint_operation
            || checkpoint.update_digest() != self.statement.checkpoint_update
            || checkpoint.decision_digest() != self.statement.checkpoint_decision
            || checkpoint.resulting_head() != &self.statement.resulting_head
            || checkpoint.ledger_sequence() != self.statement.ledger_sequence
            || checkpoint.ledger_decision() != self.statement.ledger_head
        {
            return Err(DepositSyncSupportError::InvalidRequest);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.validate()?;
        encode_bounded(self, MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES, "deposit sync support request")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncSupportError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES,
            "deposit sync support request",
        )?;
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositSyncSupportStatement {
        &self.statement
    }

    #[must_use]
    pub const fn terminal_event(&self) -> DepositArchiveEvent {
        self.terminal_event
    }

    #[must_use]
    pub const fn terminal_checkpoint(&self) -> &DepositIndexCheckpointCertificate {
        &self.terminal_checkpoint
    }
}

/// Stable key for one exact full prefix-support request.
///
/// This binds the terminal event and exact checkpoint witness bytes in addition to the semantic
/// statement. A requester therefore cannot reuse a durable cursor or cached endorsement after
/// changing any part of the fully authenticated start request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DepositSyncPrefixSupportAttempt([u8; 32]);

impl DepositSyncPrefixSupportAttempt {
    pub fn for_request(
        request: &DepositSyncSupportRequest,
    ) -> Result<Self, DepositSyncSupportError> {
        let attempt = length_prefixed_hash(SUPPORT_ATTEMPT_DIGEST_DOMAIN, &request.to_bytes()?);
        if attempt == [0; 32] {
            return Err(DepositSyncSupportError::InvalidAttempt);
        }
        Ok(Self(attempt))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, DepositSyncSupportError> {
        if bytes == [0; 32] {
            return Err(DepositSyncSupportError::InvalidAttempt);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Full first request for one endorser-side fixed-anchor scan.
///
/// Only this message carries the potentially multi-mebibyte terminal checkpoint. `replaces`
/// makes source rotation explicit and atomic: a different attempt can replace the requester's
/// single durable slot only when it names the exact attempt currently occupying that slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncPrefixSupportStart {
    version: u16,
    domain: [u8; 16],
    request: DepositSyncSupportRequest,
    replaces: Option<DepositSyncPrefixSupportAttempt>,
}

impl DepositSyncPrefixSupportStart {
    pub fn new(
        request: DepositSyncSupportRequest,
        replaces: Option<DepositSyncPrefixSupportAttempt>,
    ) -> Result<Self, DepositSyncSupportError> {
        request.validate()?;
        let start = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: PREFIX_SUPPORT_START_DOMAIN,
            request,
            replaces,
        };
        start.validate()?;
        Ok(start)
    }

    fn validate(&self) -> Result<(), DepositSyncSupportError> {
        self.request.validate()?;
        if self.version != DEPOSIT_SYNC_SUPPORT_VERSION
            || self.domain != PREFIX_SUPPORT_START_DOMAIN
            || self.replaces.is_some_and(|attempt| attempt.to_bytes() == [0; 32])
        {
            return Err(DepositSyncSupportError::InvalidAttempt);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.validate()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_START_BYTES,
            "deposit sync prefix-support start",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncSupportError> {
        let start: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_START_BYTES,
            "deposit sync prefix-support start",
        )?;
        start.validate()?;
        Ok(start)
    }

    #[must_use]
    pub const fn request(&self) -> &DepositSyncSupportRequest {
        &self.request
    }

    pub fn attempt(&self) -> Result<DepositSyncPrefixSupportAttempt, DepositSyncSupportError> {
        DepositSyncPrefixSupportAttempt::for_request(&self.request)
    }

    #[must_use]
    pub const fn replaces(&self) -> Option<DepositSyncPrefixSupportAttempt> {
        self.replaces
    }
}

/// Small continuation for one exact persisted cursor revision.
///
/// The revision is part of the authenticated QUIC request ID. Every successful scan step returns
/// a strictly newer revision, preventing the runtime's idempotent response cache from replaying a
/// stale `Pending` result forever.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncPrefixSupportContinue {
    version: u16,
    domain: [u8; 16],
    attempt: DepositSyncPrefixSupportAttempt,
    revision: u64,
}

impl DepositSyncPrefixSupportContinue {
    pub fn new(
        attempt: DepositSyncPrefixSupportAttempt,
        revision: u64,
    ) -> Result<Self, DepositSyncSupportError> {
        let continuation = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: PREFIX_SUPPORT_CONTINUE_DOMAIN,
            attempt,
            revision,
        };
        continuation.validate()?;
        Ok(continuation)
    }

    fn validate(self) -> Result<(), DepositSyncSupportError> {
        if self.version != DEPOSIT_SYNC_SUPPORT_VERSION
            || self.domain != PREFIX_SUPPORT_CONTINUE_DOMAIN
            || self.attempt.to_bytes() == [0; 32]
            || self.revision == 0
        {
            return Err(DepositSyncSupportError::InvalidAttempt);
        }
        Ok(())
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.validate()?;
        encode_bounded(
            &self,
            MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_CONTINUE_BYTES,
            "deposit sync prefix-support continuation",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncSupportError> {
        let continuation: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_CONTINUE_BYTES,
            "deposit sync prefix-support continuation",
        )?;
        continuation.validate()?;
        Ok(continuation)
    }

    #[must_use]
    pub const fn attempt(self) -> DepositSyncPrefixSupportAttempt {
        self.attempt
    }

    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncPrefixSupportProgressState {
    Pending { next_revision: u64 },
    Endorsed { endorsement: DepositSyncSupportEndorsement },
}

/// Bounded result of one start/continue scan step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncPrefixSupportProgress {
    version: u16,
    domain: [u8; 16],
    attempt: DepositSyncPrefixSupportAttempt,
    state: DepositSyncPrefixSupportProgressState,
}

impl DepositSyncPrefixSupportProgress {
    pub fn pending(
        attempt: DepositSyncPrefixSupportAttempt,
        next_revision: u64,
    ) -> Result<Self, DepositSyncSupportError> {
        let progress = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: PREFIX_SUPPORT_PROGRESS_DOMAIN,
            attempt,
            state: DepositSyncPrefixSupportProgressState::Pending { next_revision },
        };
        progress.validate_shape()?;
        Ok(progress)
    }

    pub fn endorsed(
        attempt: DepositSyncPrefixSupportAttempt,
        endorsement: DepositSyncSupportEndorsement,
    ) -> Result<Self, DepositSyncSupportError> {
        let progress = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: PREFIX_SUPPORT_PROGRESS_DOMAIN,
            attempt,
            state: DepositSyncPrefixSupportProgressState::Endorsed { endorsement },
        };
        progress.validate_shape()?;
        Ok(progress)
    }

    fn validate_shape(&self) -> Result<(), DepositSyncSupportError> {
        if self.version != DEPOSIT_SYNC_SUPPORT_VERSION
            || self.domain != PREFIX_SUPPORT_PROGRESS_DOMAIN
            || self.attempt.to_bytes() == [0; 32]
            || matches!(
                &self.state,
                DepositSyncPrefixSupportProgressState::Pending { next_revision: 0 }
            )
        {
            return Err(DepositSyncSupportError::InvalidProgress);
        }
        Ok(())
    }

    fn verify_for_attempt(
        &self,
        expected_attempt: DepositSyncPrefixSupportAttempt,
        expected_next_revision: u64,
        statement: &DepositSyncSupportStatement,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<&DepositSyncSupportEndorsement>, DepositSyncSupportError> {
        self.validate_response_binding(expected_attempt, expected_next_revision)?;
        match &self.state {
            DepositSyncPrefixSupportProgressState::Pending { .. } => Ok(None),
            DepositSyncPrefixSupportProgressState::Endorsed { endorsement } => {
                endorsement.verify(statement, active)?;
                Ok(Some(endorsement))
            }
        }
    }

    fn validate_response_binding(
        &self,
        expected_attempt: DepositSyncPrefixSupportAttempt,
        expected_next_revision: u64,
    ) -> Result<(), DepositSyncSupportError> {
        self.validate_shape()?;
        if self.attempt != expected_attempt {
            return Err(DepositSyncSupportError::InvalidProgress);
        }
        match &self.state {
            DepositSyncPrefixSupportProgressState::Pending { next_revision }
                if *next_revision == expected_next_revision =>
            {
                Ok(())
            }
            DepositSyncPrefixSupportProgressState::Pending { .. } => {
                Err(DepositSyncSupportError::InvalidProgress)
            }
            DepositSyncPrefixSupportProgressState::Endorsed { .. } => Ok(()),
        }
    }

    /// Verify the exact result of the full start request.
    ///
    /// A restart may evict the transport response cache after the endorser has already advanced
    /// this exact attempt through later continuations. The pending revision is an opaque,
    /// endorser-local continuation cursor rather than protocol authority, so an exact Start replay
    /// may return any nonzero latest durable revision. Continue responses remain strictly
    /// successor-bound by [`Self::verify_for_continue`].
    pub fn verify_for_start(
        &self,
        start: &DepositSyncPrefixSupportStart,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<&DepositSyncSupportEndorsement>, DepositSyncSupportError> {
        self.validate_shape()?;
        if self.attempt != start.attempt()? {
            return Err(DepositSyncSupportError::InvalidProgress);
        }
        match &self.state {
            DepositSyncPrefixSupportProgressState::Pending { .. } => Ok(None),
            DepositSyncPrefixSupportProgressState::Endorsed { endorsement } => {
                endorsement.verify(start.request().statement(), active)?;
                Ok(Some(endorsement))
            }
        }
    }

    /// Verify the exact result of one persisted continuation revision.
    pub fn verify_for_continue(
        &self,
        continuation: DepositSyncPrefixSupportContinue,
        request: &DepositSyncSupportRequest,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<&DepositSyncSupportEndorsement>, DepositSyncSupportError> {
        let expected_attempt = DepositSyncPrefixSupportAttempt::for_request(request)?;
        if continuation.attempt() != expected_attempt {
            return Err(DepositSyncSupportError::InvalidProgress);
        }
        let expected_next_revision = continuation
            .revision()
            .checked_add(1)
            .ok_or(DepositSyncSupportError::InvalidProgress)?;
        self.verify_for_attempt(
            expected_attempt,
            expected_next_revision,
            request.statement(),
            active,
        )
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.validate_shape()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_PROGRESS_BYTES,
            "deposit sync prefix-support progress",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncSupportError> {
        let progress: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_PREFIX_SUPPORT_PROGRESS_BYTES,
            "deposit sync prefix-support progress",
        )?;
        progress.validate_shape()?;
        Ok(progress)
    }

    #[must_use]
    pub const fn attempt(&self) -> DepositSyncPrefixSupportAttempt {
        self.attempt
    }

    #[must_use]
    pub const fn next_revision(&self) -> Option<u64> {
        match &self.state {
            DepositSyncPrefixSupportProgressState::Pending { next_revision } => {
                Some(*next_revision)
            }
            DepositSyncPrefixSupportProgressState::Endorsed { .. } => None,
        }
    }

    #[must_use]
    pub const fn endorsement(&self) -> Option<&DepositSyncSupportEndorsement> {
        match &self.state {
            DepositSyncPrefixSupportProgressState::Pending { .. } => None,
            DepositSyncPrefixSupportProgressState::Endorsed { endorsement } => Some(endorsement),
        }
    }
}

/// One current-epoch Ed25519 endorsement of the complete support statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncSupportEndorsement {
    envelope: SignedEnvelope,
}

impl DepositSyncSupportEndorsement {
    pub fn endorse(
        request: &DepositSyncSupportRequest,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        prefix: &VerifiedDepositArchivePrefix,
        active: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Self, DepositSyncSupportError> {
        request.verify_terminal_capability(verified_terminal)?;
        request.statement.validate_against(active)?;
        if prefix.target() != &request.statement.prefix_target()?
            || prefix.anchor().wallet_id() != request.statement.context.wallet()
            || prefix.anchor().len() < request.statement.checkpoint_sequence
        {
            return Err(DepositSyncSupportError::WrongPrefix);
        }
        active.committee().member(identity.party())?;
        let envelope = identity.sign_envelope(
            active.committee(),
            support_session(&request.statement),
            Some(request.statement.requester),
            request.statement.checkpoint_sequence,
            request.statement.to_bytes()?,
        )?;
        let endorsement = Self { envelope };
        endorsement.verify(&request.statement, active)?;
        Ok(endorsement)
    }

    fn validate_shape(
        &self,
        statement: &DepositSyncSupportStatement,
    ) -> Result<(), DepositSyncSupportError> {
        if self.envelope.session != support_session(statement)
            || self.envelope.to != Some(statement.requester)
            || self.envelope.sequence != statement.checkpoint_sequence
            || self.envelope.payload != statement.to_bytes()?
        {
            return Err(DepositSyncSupportError::InvalidEndorsement);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        statement: &DepositSyncSupportStatement,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<PartyId, DepositSyncSupportError> {
        statement.validate_against(active)?;
        self.validate_shape(statement)?;
        Identity::verify_envelope(active.committee(), statement.requester, &self.envelope)?;
        Ok(self.envelope.from)
    }

    pub fn to_bytes(
        &self,
        statement: &DepositSyncSupportStatement,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.verify(statement, active)?;
        encode_bounded(
            self,
            MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES,
            "deposit sync support endorsement",
        )
    }

    pub fn from_bytes(
        statement: &DepositSyncSupportStatement,
        active: &VerifiedRegistryHandoffTarget,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncSupportError> {
        let endorsement: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES,
            "deposit sync support endorsement",
        )?;
        endorsement.verify(statement, active)?;
        Ok(endorsement)
    }

    #[must_use]
    pub const fn signer(&self) -> PartyId {
        self.envelope.from
    }
}

/// Exactly `f + 1` distinct current-member endorsements, sorted by party ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncSupportCertificate {
    version: u16,
    domain: [u8; 16],
    statement: DepositSyncSupportStatement,
    #[serde(deserialize_with = "deserialize_endorsements")]
    endorsements: Vec<DepositSyncSupportEndorsement>,
}

impl DepositSyncSupportCertificate {
    pub fn new(
        statement: DepositSyncSupportStatement,
        mut endorsements: Vec<DepositSyncSupportEndorsement>,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Self, DepositSyncSupportError> {
        statement.validate_against(active)?;
        endorsements.sort_by_key(DepositSyncSupportEndorsement::signer);
        let certificate = Self {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: DEPOSIT_SYNC_SUPPORT_DOMAIN,
            statement,
            endorsements,
        };
        certificate.verify_internal(active)?;
        Ok(certificate)
    }

    fn validate_shape(&self) -> Result<(), DepositSyncSupportError> {
        self.statement.validate_static()?;
        let required = usize::from(
            self.statement
                .active_fault_bound
                .checked_add(1)
                .ok_or(DepositSyncSupportError::InvalidCertificate)?,
        );
        if self.version != DEPOSIT_SYNC_SUPPORT_VERSION
            || self.domain != DEPOSIT_SYNC_SUPPORT_DOMAIN
            || required == 0
            || required > MAX_COMMITTEE_MEMBERS
            || self.endorsements.len() != required
        {
            return Err(DepositSyncSupportError::InvalidCertificate);
        }
        let mut previous = None;
        for endorsement in &self.endorsements {
            endorsement.validate_shape(&self.statement)?;
            if previous.is_some_and(|party| party >= endorsement.signer()) {
                return Err(DepositSyncSupportError::InvalidCertificate);
            }
            previous = Some(endorsement.signer());
        }
        Ok(())
    }

    fn verify_internal(
        &self,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositSyncSupportError> {
        self.validate_shape()?;
        self.statement.validate_against(active)?;
        for endorsement in &self.endorsements {
            endorsement.verify(&self.statement, active)?;
        }
        Ok(())
    }

    pub fn verify(
        &self,
        expected: &DepositSyncSupportStatement,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedDepositSyncSupportCertificate, DepositSyncSupportError> {
        self.verify_internal(active)?;
        if &self.statement != expected {
            return Err(DepositSyncSupportError::WrongStatement);
        }
        let certificate_bytes = encode_bounded(
            self,
            MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES,
            "deposit sync support certificate",
        )?;
        Ok(VerifiedDepositSyncSupportCertificate {
            statement: self.statement.clone(),
            certificate_digest: length_prefixed_hash(
                SUPPORT_CERTIFICATE_DIGEST_DOMAIN,
                &certificate_bytes,
            ),
            certificate_bytes,
            statement_digest: self.statement.digest(),
            checkpoint_sequence: self.statement.checkpoint_sequence,
            checkpoint_decision: self.statement.checkpoint_decision,
            resulting_head: self.statement.resulting_head.clone(),
            signers: self.endorsements.iter().map(DepositSyncSupportEndorsement::signer).collect(),
        })
    }

    pub fn to_bytes(
        &self,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<Vec<u8>, DepositSyncSupportError> {
        self.verify_internal(active)?;
        encode_bounded(
            self,
            MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES,
            "deposit sync support certificate",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositSyncSupportError> {
        let certificate: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES,
            "deposit sync support certificate",
        )?;
        certificate.validate_shape()?;
        Ok(certificate)
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositSyncSupportStatement {
        &self.statement
    }

    #[must_use]
    pub fn endorsements(&self) -> &[DepositSyncSupportEndorsement] {
        &self.endorsements
    }
}

/// Non-serializable admission proof returned only after current-registry signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositSyncSupportCertificate {
    statement: DepositSyncSupportStatement,
    certificate_digest: [u8; 32],
    certificate_bytes: Vec<u8>,
    statement_digest: [u8; 32],
    checkpoint_sequence: u64,
    checkpoint_decision: [u8; 32],
    resulting_head: PortableDepositIndexHead,
    signers: Vec<PartyId>,
}

impl VerifiedDepositSyncSupportCertificate {
    /// Complete statement whose exact canonical certificate passed current-registry verification.
    #[must_use]
    pub const fn statement(&self) -> &DepositSyncSupportStatement {
        &self.statement
    }

    /// Stable digest of [`Self::certificate_bytes`] for compact journal/index binding.
    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    /// Exact canonical certificate bytes which a durable stage journals before adoption.
    ///
    /// Restart must decode these with [`DepositSyncSupportCertificate::from_bytes`] and call
    /// [`DepositSyncSupportCertificate::verify`] against the reconstructed statement and current
    /// authenticated registry target before treating them as authority.
    #[must_use]
    pub fn certificate_bytes(&self) -> &[u8] {
        &self.certificate_bytes
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn checkpoint_decision(&self) -> [u8; 32] {
        self.checkpoint_decision
    }

    #[must_use]
    pub const fn resulting_head(&self) -> &PortableDepositIndexHead {
        &self.resulting_head
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }
}

fn support_session(statement: &DepositSyncSupportStatement) -> SessionId {
    SessionId::derive(SUPPORT_ENDORSEMENT_SESSION_DOMAIN, &statement.digest())
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, DepositSyncSupportError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| DepositSyncSupportError::Serialization)?;
    if bytes.len() > maximum {
        return Err(DepositSyncSupportError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn decode_canonical_bounded<T>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, DepositSyncSupportError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > maximum {
        return Err(DepositSyncSupportError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| DepositSyncSupportError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositSyncSupportError::TrailingBytes(kind));
    }
    if postcard::to_allocvec(&value).map_err(|_| DepositSyncSupportError::Serialization)? != bytes {
        return Err(DepositSyncSupportError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

fn length_prefixed_hash(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn deserialize_endorsements<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositSyncSupportEndorsement>, D::Error>
where
    D: Deserializer<'de>,
{
    struct EndorsementVisitor;

    impl<'de> Visitor<'de> for EndorsementVisitor {
        type Value = Vec<DepositSyncSupportEndorsement>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX_COMMITTEE_MEMBERS} support endorsements")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAX_COMMITTEE_MEMBERS) {
                return Err(A::Error::custom("too many support endorsements"));
            }
            let mut endorsements =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_COMMITTEE_MEMBERS));
            while let Some(endorsement) = sequence.next_element()? {
                if endorsements.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::custom("too many support endorsements"));
                }
                endorsements.push(endorsement);
            }
            Ok(endorsements)
        }
    }

    deserializer.deserialize_seq(EndorsementVisitor)
}

#[derive(Debug, Error)]
pub enum DepositSyncSupportError {
    #[error("deposit-sync wire validation failed: {0}")]
    Wire(#[from] DepositSyncWireError),
    #[error("deposit archive validation failed: {0}")]
    Archive(#[from] DepositArchiveError),
    #[error("deposit checkpoint validation failed: {0}")]
    Checkpoint(#[from] DepositIndexCheckpointError),
    #[error("compact registry validation failed: {0}")]
    CompactRegistry(#[from] CompactRegistryError),
    #[error("committee validation failed: {0}")]
    Committee(#[from] CommitteeError),
    #[error("identity validation failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("support statement is malformed or internally inconsistent")]
    InvalidStatement,
    #[error("support statement is not bound to the current deposit registry")]
    WrongActiveRegistry,
    #[error("support request does not carry its exact terminal event and checkpoint")]
    InvalidRequest,
    #[error("prefix-support attempt or continuation is malformed")]
    InvalidAttempt,
    #[error("prefix-support progress is malformed or belongs to another attempt")]
    InvalidProgress,
    #[error("the locally authenticated archive does not contain the requested semantic prefix")]
    WrongPrefix,
    #[error("support endorsement is malformed, replayed, or invalidly signed")]
    InvalidEndorsement,
    #[error("support certificate does not contain exactly f+1 distinct current members")]
    InvalidCertificate,
    #[error("support certificate is for another statement")]
    WrongStatement,
    #[error("{0} has trailing bytes")]
    TrailingBytes(&'static str),
    #[error("{0} is not canonically encoded")]
    NonCanonicalEncoding(&'static str),
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("support serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuation_is_canonical_attempt_bound_and_revision_advancing() {
        assert!(matches!(
            DepositSyncPrefixSupportAttempt::from_bytes([0; 32]),
            Err(DepositSyncSupportError::InvalidAttempt)
        ));
        let attempt = DepositSyncPrefixSupportAttempt::from_bytes([0x41; 32]).unwrap();
        let other = DepositSyncPrefixSupportAttempt::from_bytes([0x42; 32]).unwrap();
        assert!(matches!(
            DepositSyncPrefixSupportContinue::new(attempt, 0),
            Err(DepositSyncSupportError::InvalidAttempt)
        ));

        let first = DepositSyncPrefixSupportContinue::new(attempt, 1).unwrap();
        let second = DepositSyncPrefixSupportContinue::new(attempt, 2).unwrap();
        assert_ne!(first.to_bytes().unwrap(), second.to_bytes().unwrap());
        assert_eq!(
            DepositSyncPrefixSupportContinue::from_bytes(&first.to_bytes().unwrap()).unwrap(),
            first
        );
        let mut trailing = first.to_bytes().unwrap();
        trailing.push(0);
        assert!(matches!(
            DepositSyncPrefixSupportContinue::from_bytes(&trailing),
            Err(DepositSyncSupportError::TrailingBytes(_))
        ));

        let pending = DepositSyncPrefixSupportProgress::pending(attempt, 2).unwrap();
        assert_eq!(pending.attempt(), attempt);
        assert_eq!(pending.next_revision(), Some(2));
        assert!(pending.endorsement().is_none());
        assert!(pending.validate_response_binding(attempt, 2).is_ok());
        assert!(matches!(
            pending.validate_response_binding(attempt, 1),
            Err(DepositSyncSupportError::InvalidProgress)
        ));
        assert!(matches!(
            pending.validate_response_binding(other, 2),
            Err(DepositSyncSupportError::InvalidProgress)
        ));
        assert_eq!(
            DepositSyncPrefixSupportProgress::from_bytes(&pending.to_bytes().unwrap()).unwrap(),
            pending
        );
        assert!(matches!(
            DepositSyncPrefixSupportProgress::pending(attempt, 0),
            Err(DepositSyncSupportError::InvalidProgress)
        ));
        assert_ne!(
            DepositSyncPrefixSupportProgress::pending(other, 2).unwrap().to_bytes().unwrap(),
            pending.to_bytes().unwrap()
        );
    }
}
