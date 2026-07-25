//! Immutable authenticated archive for exact portable deposit-index checkpoints.
//!
//! A ledger or observation certificate is materialized before checkpoint voting, but that
//! artifact alone is never an authoritative archive append. Only after an independent n-f index
//! checkpoint exists does the finalizer install its exact certificate and a linked event naming
//! both artifacts. The caller installs the returned head with the portable index, reducer,
//! scanner, compact registry, and outbox in one outer wallet-snapshot CAS.

use std::path::PathBuf;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::PartyId,
    deposit_index_checkpoint::{
        DepositIndexCheckpointCertificate, DepositIndexCheckpointError,
        DepositIndexCheckpointOperation, DepositIndexCheckpointParent,
        VerifiedDepositIndexCheckpoint,
    },
    deposit_ledger::{
        CertifiedDepositObservation, CertifiedLedgerEntry, LedgerError,
        VerifiedDepositObservationCertificate, VerifiedEntry,
    },
    deposit_wallet::DepositWalletId,
    storage::{
        MAX_WALLET_ARTIFACT_BYTES, StoreError, WalletArtifactKind, WalletArtifactRef,
        WalletArtifactStore, WalletId,
    },
};

const ARCHIVE_HEAD_VERSION: u16 = 2;
const ARCHIVE_EVENT_VERSION: u16 = 2;
const ARTIFACT_CHUNK_VERSION: u16 = 1;
const ARCHIVE_SEGMENT_VERSION: u16 = 2;

/// A portable certificate is already bounded to 4 MiB by `CertifiedLedgerEntry::to_bytes`.
pub const MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
/// An observation certificate has the same committee-witness bound as a ledger certificate.
pub const MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
/// Independent n-f checkpoint witnesses plus the bounded statement.
pub const MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
/// Linked events contain only fixed-size content addresses and chain metadata.
pub const MAX_DEPOSIT_ARCHIVE_EVENT_BYTES: usize = 4 * 1024;
/// One authenticated QUIC response chunk. The complete object may be larger and is verified only
/// after exact ordered assembly against its content address.
pub const MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES: usize = 1024 * 1024;
/// Maximum event references copied into one immutable replay segment. Total archive length remains
/// a `u64` and is not capped by this per-object resource bound.
pub const MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS: usize = 128;
/// Maximum canonical bytes in one immutable replay segment.
pub const MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES: usize = 64 * 1024;

/// Exact certificate bytes retained outside recurring wallet snapshots.
pub const CERTIFIED_LEDGER_ENTRY_ARTIFACT: WalletArtifactKind = WalletArtifactKind(1);
/// One linked `(ordinal, previous, payload)` archive event.
pub const DEPOSIT_ARCHIVE_EVENT_ARTIFACT: WalletArtifactKind = WalletArtifactKind(2);
/// Exact witness-bearing n-f portable-index checkpoint certificate.
pub const DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT: WalletArtifactKind = WalletArtifactKind(3);
/// Bounded linked page of event references used for forward streaming replay.
pub const DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT: WalletArtifactKind = WalletArtifactKind(4);
/// Exact n-f confirmed-output observation certificate.
pub const CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT: WalletArtifactKind = WalletArtifactKind(5);

/// Compact authenticated position in a wallet's complete certified-ledger archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArchiveHead {
    version: u16,
    wallet: DepositWalletId,
    length: u64,
    event: Option<WalletArtifactRef>,
    segment: Option<WalletArtifactRef>,
}

impl DepositArchiveHead {
    pub fn empty(wallet: DepositWalletId) -> Result<Self, DepositArchiveError> {
        let head =
            Self { version: ARCHIVE_HEAD_VERSION, wallet, length: 0, event: None, segment: None };
        head.validate()?;
        Ok(head)
    }

    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn len(self) -> u64 {
        self.length
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.length == 0
    }

    #[must_use]
    pub const fn event_reference(self) -> Option<WalletArtifactRef> {
        self.event
    }

    #[must_use]
    pub const fn segment_reference(self) -> Option<WalletArtifactRef> {
        self.segment
    }

    pub(crate) fn validate(self) -> Result<(), DepositArchiveError> {
        if self.version != ARCHIVE_HEAD_VERSION
            || self.wallet.0 == [0_u8; 32]
            || (self.length == 0) != self.event.is_none()
            || self.event.is_none() != self.segment.is_none()
        {
            return Err(DepositArchiveError::InvalidArchiveHead);
        }
        if let Some(reference) = self.event {
            validate_reference(
                reference,
                self.wallet,
                DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
                MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
            )?;
        }
        if let Some(reference) = self.segment {
            validate_reference(
                reference,
                self.wallet,
                DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
                MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositArchivePayload {
    LedgerCheckpoint { ledger: WalletArtifactRef, checkpoint: WalletArtifactRef },
    DepositObservationCheckpoint { observation: WalletArtifactRef, checkpoint: WalletArtifactRef },
}

impl DepositArchivePayload {
    #[must_use]
    const fn checkpoint_reference(self) -> WalletArtifactRef {
        match self {
            Self::LedgerCheckpoint { checkpoint, .. }
            | Self::DepositObservationCheckpoint { checkpoint, .. } => checkpoint,
        }
    }
}

/// Exact portable operation paired with one independently certified checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositArchiveOperation {
    Ledger,
    DepositObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArchiveEvent {
    version: u16,
    wallet: DepositWalletId,
    ordinal: u64,
    previous: Option<WalletArtifactRef>,
    payload: DepositArchivePayload,
}

impl DepositArchiveEvent {
    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn ordinal(self) -> u64 {
        self.ordinal
    }

    #[must_use]
    pub const fn previous(self) -> Option<WalletArtifactRef> {
        self.previous
    }

    #[must_use]
    pub const fn operation_reference(self) -> WalletArtifactRef {
        match self.payload {
            DepositArchivePayload::LedgerCheckpoint { ledger, .. } => ledger,
            DepositArchivePayload::DepositObservationCheckpoint { observation, .. } => observation,
        }
    }

    #[must_use]
    pub const fn checkpoint_reference(self) -> WalletArtifactRef {
        match self.payload {
            DepositArchivePayload::LedgerCheckpoint { checkpoint, .. }
            | DepositArchivePayload::DepositObservationCheckpoint { checkpoint, .. } => checkpoint,
        }
    }

    #[must_use]
    pub const fn operation(self) -> DepositArchiveOperation {
        match self.payload {
            DepositArchivePayload::LedgerCheckpoint { .. } => DepositArchiveOperation::Ledger,
            DepositArchivePayload::DepositObservationCheckpoint { .. } => {
                DepositArchiveOperation::DepositObservation
            }
        }
    }

    /// Canonical bounded bytes used by archive transfer peers.
    pub fn to_bytes(self) -> Result<Vec<u8>, DepositArchiveError> {
        validate_event(&self, self.wallet, self.ordinal)?;
        encode_bounded(&self, MAX_DEPOSIT_ARCHIVE_EVENT_BYTES, "deposit archive event")
    }

    /// Decode one exact linked event before following its payload and predecessor references.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositArchiveError> {
        let event: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
            "deposit archive event",
        )?;
        validate_event(&event, event.wallet, event.ordinal)?;
        Ok(event)
    }
}

/// One bounded forward-replay page. Partial pages are replaced content-addressedly in the compact
/// head; once full, they become immutable predecessors of the next page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArchiveSegment {
    version: u16,
    wallet: DepositWalletId,
    start_ordinal: u64,
    previous: Option<WalletArtifactRef>,
    events: Vec<WalletArtifactRef>,
}

impl DepositArchiveSegment {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn start_ordinal(&self) -> u64 {
        self.start_ordinal
    }

    pub fn end_ordinal(&self) -> Result<u64, DepositArchiveError> {
        self.start_ordinal
            .checked_add(
                u64::try_from(self.events.len())
                    .map_err(|_| DepositArchiveError::ArchiveOrdinalExhausted)?,
            )
            .ok_or(DepositArchiveError::ArchiveOrdinalExhausted)
    }

    #[must_use]
    pub const fn previous(&self) -> Option<WalletArtifactRef> {
        self.previous
    }

    #[must_use]
    pub fn event_references(&self) -> &[WalletArtifactRef] {
        &self.events
    }

    fn validate(&self) -> Result<(), DepositArchiveError> {
        let segment_width = u64::try_from(MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS)
            .map_err(|_| DepositArchiveError::InvalidArchiveSegment)?;
        if self.version != ARCHIVE_SEGMENT_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.events.is_empty()
            || self.events.len() > MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS
            || self.start_ordinal % segment_width != 0
            || (self.start_ordinal == 0) != self.previous.is_none()
        {
            return Err(DepositArchiveError::InvalidArchiveSegment);
        }
        self.end_ordinal()?;
        if let Some(previous) = self.previous {
            validate_reference(
                previous,
                self.wallet,
                DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
                MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
            )?;
        }
        for event in &self.events {
            validate_reference(
                *event,
                self.wallet,
                DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
                MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
            )?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositArchiveError> {
        self.validate()?;
        encode_bounded(self, MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES, "deposit archive segment")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositArchiveError> {
        let segment: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
            "deposit archive segment",
        )?;
        segment.validate()?;
        Ok(segment)
    }
}

/// Result of committing one exact ledger/checkpoint pair to the immutable archive graph.
///
/// The caller must install `head` in the same outer wallet-snapshot CAS as the checkpoint's
/// resulting portable index. Until that CAS succeeds, every newly created object is an
/// unreachable, harmless orphan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositArchiveAppend {
    pub head: DepositArchiveHead,
    pub entry_artifact: WalletArtifactRef,
    pub checkpoint_artifact: WalletArtifactRef,
    pub event_artifact: WalletArtifactRef,
    /// False only when `head` already ended in this exact ledger/checkpoint pair.
    pub appended: bool,
    verified_locator: VerifiedDepositArchiveLedgerLocator,
}

impl DepositArchiveAppend {
    /// Exact, non-serializable archive/checkpoint proof consumed by the portable index locator.
    #[must_use]
    pub const fn verified_ledger_locator(&self) -> VerifiedDepositArchiveLedgerLocator {
        self.verified_locator
    }
}

/// Result of committing one exact confirmed-output observation/checkpoint pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositObservationArchiveAppend {
    pub head: DepositArchiveHead,
    pub observation_artifact: WalletArtifactRef,
    pub checkpoint_artifact: WalletArtifactRef,
    pub event_artifact: WalletArtifactRef,
    /// False only when `head` already ended in this exact observation/checkpoint pair.
    pub appended: bool,
    verified_observation: VerifiedCertifiedDepositObservationArtifact,
}

impl DepositObservationArchiveAppend {
    #[must_use]
    pub const fn verified_observation_artifact(
        &self,
    ) -> VerifiedCertifiedDepositObservationArtifact {
        self.verified_observation
    }
}

/// Private-constructor proof that an exact encrypted artifact was created or loaded, content
/// authenticated, canonically decoded, and matched to the API-unforgeable verification result for
/// those exact [`CertifiedLedgerEntry`] bytes.
///
/// This token is intentionally non-serializable. Durable locator restore must mint a fresh token
/// by calling [`DepositArchiveStore::authenticate_certified_entry_artifact`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCertifiedLedgerEntryArtifact {
    wallet: DepositWalletId,
    sequence: u64,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    reference: WalletArtifactRef,
}

impl VerifiedCertifiedLedgerEntryArtifact {
    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn statement_digest(self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn certificate_digest(self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub const fn reference(self) -> WalletArtifactRef {
        self.reference
    }
}

/// Private-constructor proof that one exact, cryptographically verified observation certificate
/// survived encrypted readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCertifiedDepositObservationArtifact {
    wallet: DepositWalletId,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    reference: WalletArtifactRef,
}

impl VerifiedCertifiedDepositObservationArtifact {
    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn statement_digest(self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn certificate_digest(self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub const fn reference(self) -> WalletArtifactRef {
        self.reference
    }
}

/// Non-serializable proof binding one ledger allocation to the exact archive event and exact
/// n-f checkpoint certificate which made it authoritative.
///
/// The private constructor prevents callers from substituting the latest certificate or
/// manufacturing locator fields from mutable service state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDepositArchiveLedgerLocator {
    wallet: DepositWalletId,
    checkpoint_sequence: u64,
    checkpoint_decision: [u8; 32],
    checkpoint_certificate_digest: [u8; 32],
    ledger_sequence: u64,
    ledger_statement: [u8; 32],
    event_artifact: WalletArtifactRef,
    ledger_artifact: WalletArtifactRef,
    checkpoint_artifact: WalletArtifactRef,
}

impl VerifiedDepositArchiveLedgerLocator {
    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn checkpoint_decision(self) -> [u8; 32] {
        self.checkpoint_decision
    }

    #[must_use]
    pub const fn checkpoint_certificate_digest(self) -> [u8; 32] {
        self.checkpoint_certificate_digest
    }

    #[must_use]
    pub const fn ledger_sequence(self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn ledger_statement(self) -> [u8; 32] {
        self.ledger_statement
    }

    #[must_use]
    pub const fn event_artifact(self) -> WalletArtifactRef {
        self.event_artifact
    }

    #[must_use]
    pub const fn ledger_artifact(self) -> WalletArtifactRef {
        self.ledger_artifact
    }

    #[must_use]
    pub const fn checkpoint_artifact(self) -> WalletArtifactRef {
        self.checkpoint_artifact
    }
}

/// One replayed exact ledger certificate and the checkpoint which made it authoritative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedCertifiedLedgerEntry {
    pub ordinal: u64,
    pub checkpoint_sequence: u64,
    pub event_artifact: WalletArtifactRef,
    pub entry_artifact: WalletArtifactRef,
    pub checkpoint_artifact: WalletArtifactRef,
    pub entry: CertifiedLedgerEntry,
    pub checkpoint: DepositIndexCheckpointCertificate,
    _archive_authenticated: (),
}

impl ArchivedCertifiedLedgerEntry {
    /// Bind this authenticated replay item to a separately verified exact checkpoint certificate.
    pub fn verified_ledger_locator(
        &self,
        verified_entry: &VerifiedEntry,
        verified_checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<VerifiedDepositArchiveLedgerLocator, DepositArchiveError> {
        let verified_entry_artifact =
            verified_certified_entry_artifact(self.entry_artifact, &self.entry, verified_entry)?;
        verified_ledger_locator(
            self.event_artifact,
            self.entry_artifact,
            self.checkpoint_artifact,
            &self.entry,
            verified_entry_artifact,
            &self.checkpoint,
            verified_checkpoint,
        )
    }
}

/// One replayed exact confirmed-output observation and its authoritative checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedCertifiedDepositObservation {
    pub ordinal: u64,
    pub checkpoint_sequence: u64,
    pub event_artifact: WalletArtifactRef,
    pub observation_artifact: WalletArtifactRef,
    pub checkpoint_artifact: WalletArtifactRef,
    pub observation: CertifiedDepositObservation,
    pub checkpoint: DepositIndexCheckpointCertificate,
    _archive_authenticated: (),
}

impl ArchivedCertifiedDepositObservation {
    /// Bind this authenticated replay item to a separately verified exact observation certificate.
    pub fn verified_observation_artifact(
        &self,
        verified_observation: &VerifiedDepositObservationCertificate,
    ) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositArchiveError> {
        verified_certified_observation_artifact(
            self.observation_artifact,
            &self.observation,
            verified_observation,
        )
    }

    /// Bind the exact archived checkpoint bytes to their full witness-verification result.
    pub fn verify_exact_checkpoint(
        &self,
        verified_checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<(), DepositArchiveError> {
        verify_checkpoint_capability(
            &self.checkpoint,
            verified_checkpoint,
            self.observation.statement.wallet_id(),
        )
    }
}

/// Fresh-sync/history traversal item in independent checkpoint order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchivedDepositCheckpoint {
    Ledger(ArchivedCertifiedLedgerEntry),
    DepositObservation(ArchivedCertifiedDepositObservation),
}

impl ArchivedDepositCheckpoint {
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        match self {
            Self::Ledger(entry) => entry.ordinal,
            Self::DepositObservation(observation) => observation.ordinal,
        }
    }

    #[must_use]
    pub const fn checkpoint_sequence(&self) -> u64 {
        match self {
            Self::Ledger(entry) => entry.checkpoint_sequence,
            Self::DepositObservation(observation) => observation.checkpoint_sequence,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> DepositArchiveOperation {
        match self {
            Self::Ledger(_) => DepositArchiveOperation::Ledger,
            Self::DepositObservation(_) => DepositArchiveOperation::DepositObservation,
        }
    }
}

/// Bounded request for plaintext bytes of a content-addressed archive object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArtifactChunkRequest {
    version: u16,
    pub reference: WalletArtifactRef,
    pub offset: u64,
    pub maximum_bytes: u32,
}

impl DepositArtifactChunkRequest {
    pub fn new(
        reference: WalletArtifactRef,
        offset: u64,
        maximum_bytes: u32,
    ) -> Result<Self, DepositArchiveError> {
        let request = Self { version: ARTIFACT_CHUNK_VERSION, reference, offset, maximum_bytes };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(self) -> Result<(), DepositArchiveError> {
        let maximum = usize::try_from(self.maximum_bytes)
            .map_err(|_| DepositArchiveError::InvalidArtifactChunk)?;
        if self.version != ARTIFACT_CHUNK_VERSION
            || maximum == 0
            || maximum > MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES
            || self.offset >= self.reference.plaintext_len()
        {
            return Err(DepositArchiveError::InvalidArtifactChunk);
        }
        Ok(())
    }
}

/// One ordered plaintext chunk. The authenticated QUIC peer identity supplies origin
/// authentication; the complete assembled object is content-authenticated by `reference`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArtifactChunk {
    version: u16,
    pub reference: WalletArtifactRef,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub complete: bool,
}

impl DepositArtifactChunk {
    pub(crate) fn from_parts(
        reference: WalletArtifactRef,
        offset: u64,
        bytes: Vec<u8>,
        complete: bool,
    ) -> Result<Self, DepositArchiveError> {
        let chunk = Self { version: ARTIFACT_CHUNK_VERSION, reference, offset, bytes, complete };
        chunk.validate()?;
        Ok(chunk)
    }

    pub(crate) fn validate(&self) -> Result<(), DepositArchiveError> {
        let byte_len = u64::try_from(self.bytes.len())
            .map_err(|_| DepositArchiveError::InvalidArtifactChunk)?;
        let end =
            self.offset.checked_add(byte_len).ok_or(DepositArchiveError::InvalidArtifactChunk)?;
        if self.version != ARTIFACT_CHUNK_VERSION
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES
            || self.offset >= self.reference.plaintext_len()
            || end > self.reference.plaintext_len()
            || self.complete != (end == self.reference.plaintext_len())
        {
            return Err(DepositArchiveError::InvalidArtifactChunk);
        }
        Ok(())
    }
}

/// Per-party encrypted backing store for deposit archive objects.
#[derive(Debug)]
pub struct DepositArchiveStore {
    artifacts: WalletArtifactStore,
}

impl DepositArchiveStore {
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositArchiveError> {
        Ok(Self { artifacts: WalletArtifactStore::new(directory, party, identity_seed)? })
    }

    #[must_use]
    pub fn artifact_path(&self, reference: WalletArtifactRef) -> PathBuf {
        self.artifacts.artifact_path(reference)
    }

    /// Materialize and authenticate an exact ledger certificate before checkpoint voting.
    ///
    /// This method has no archive head argument and cannot create an event or advance authority.
    /// The returned capability is pre-round material only. Only
    /// [`Self::append_ledger_checkpoint`] can bind it to a checkpoint/event and make it reachable
    /// from an archive head.
    pub async fn stage_certified_ledger_entry<R: RngCore + CryptoRng>(
        &self,
        entry: &CertifiedLedgerEntry,
        verified_entry: &VerifiedEntry,
        rng: &mut R,
    ) -> Result<VerifiedCertifiedLedgerEntryArtifact, DepositArchiveError> {
        verified_entry.verify_exact_certificate(entry)?;
        let bytes = entry.to_bytes()?;
        if entry.statement.sequence == 0 || entry.statement.wallet.0 == [0; 32] {
            return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
        }
        let reference = self
            .artifacts
            .create_artifact(
                WalletId(entry.statement.wallet.0),
                CERTIFIED_LEDGER_ENTRY_ARTIFACT,
                &bytes,
                rng,
            )
            .await?;
        self.authenticate_certified_entry_artifact(reference, verified_entry).await
    }

    /// Observation analogue of [`Self::stage_certified_ledger_entry`].
    pub async fn stage_certified_deposit_observation<R: RngCore + CryptoRng>(
        &self,
        observation: &CertifiedDepositObservation,
        verified_observation: &VerifiedDepositObservationCertificate,
        rng: &mut R,
    ) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositArchiveError> {
        verified_observation.verify_exact_certificate(observation)?;
        let bytes = observation.to_bytes()?;
        let wallet = observation.statement.wallet_id();
        let digest = observation.statement.digest();
        if wallet.0 == [0; 32] || digest == [0; 32] {
            return Err(DepositArchiveError::CertifiedObservationArtifactMismatch);
        }
        let reference = self
            .artifacts
            .create_artifact(
                WalletId(wallet.0),
                CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
                &bytes,
                rng,
            )
            .await?;
        self.authenticate_certified_deposit_observation_artifact(reference, verified_observation)
            .await
    }

    /// Append one ledger operation only after its exact n-f index checkpoint is available.
    pub async fn append_ledger_checkpoint<R: RngCore + CryptoRng>(
        &self,
        head: DepositArchiveHead,
        verified_entry: VerifiedCertifiedLedgerEntryArtifact,
        checkpoint: &DepositIndexCheckpointCertificate,
        verified_checkpoint: &VerifiedDepositIndexCheckpoint,
        rng: &mut R,
    ) -> Result<DepositArchiveAppend, DepositArchiveError> {
        head.validate()?;
        if verified_entry.wallet != head.wallet {
            return Err(DepositArchiveError::WrongWallet);
        }
        let authenticated = self.reauthenticate_certified_entry_artifact(verified_entry).await?;
        if authenticated != verified_entry {
            return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
        }
        let entry = self.load_certified_entry(verified_entry.reference, head.wallet).await?;
        verify_checkpoint_capability(checkpoint, verified_checkpoint, head.wallet)?;
        let statement = checkpoint.statement();
        if statement.operation()
            != (DepositIndexCheckpointOperation::Ledger {
                statement: verified_entry.statement_digest,
            })
            || statement.ledger_sequence() != verified_entry.sequence
            || statement.ledger_decision() != verified_entry.statement_digest
            || entry.statement.previous != statement.previous_head().ledger_head()
        {
            return Err(DepositArchiveError::CheckpointOperationMismatch);
        }
        let checkpoint_artifact =
            self.stage_checkpoint_certificate(head.wallet, checkpoint, rng).await?;
        let payload = DepositArchivePayload::LedgerCheckpoint {
            ledger: verified_entry.reference,
            checkpoint: checkpoint_artifact,
        };
        let (next, event_artifact, appended) = self
            .append_checkpoint_event(head, payload, checkpoint, checkpoint_artifact, rng)
            .await?;
        let verified_locator = verified_ledger_locator(
            event_artifact,
            verified_entry.reference,
            checkpoint_artifact,
            &entry,
            verified_entry,
            checkpoint,
            verified_checkpoint,
        )?;
        Ok(DepositArchiveAppend {
            head: next,
            entry_artifact: verified_entry.reference,
            checkpoint_artifact,
            event_artifact,
            appended,
            verified_locator,
        })
    }

    /// Append one observation-only operation after its independent n-f checkpoint exists.
    pub async fn append_deposit_observation_checkpoint<R: RngCore + CryptoRng>(
        &self,
        head: DepositArchiveHead,
        verified_observation: VerifiedCertifiedDepositObservationArtifact,
        checkpoint: &DepositIndexCheckpointCertificate,
        verified_checkpoint: &VerifiedDepositIndexCheckpoint,
        rng: &mut R,
    ) -> Result<DepositObservationArchiveAppend, DepositArchiveError> {
        head.validate()?;
        if verified_observation.wallet != head.wallet {
            return Err(DepositArchiveError::WrongWallet);
        }
        let authenticated =
            self.reauthenticate_certified_observation_artifact(verified_observation).await?;
        if authenticated != verified_observation {
            return Err(DepositArchiveError::CertifiedObservationArtifactMismatch);
        }
        let observation =
            self.load_certified_observation(verified_observation.reference, head.wallet).await?;
        verify_checkpoint_capability(checkpoint, verified_checkpoint, head.wallet)?;
        let statement = checkpoint.statement();
        if statement.operation()
            != (DepositIndexCheckpointOperation::DepositObservation {
                statement: verified_observation.statement_digest,
            })
            || observation.statement.digest() != verified_observation.statement_digest
        {
            return Err(DepositArchiveError::CheckpointOperationMismatch);
        }
        let checkpoint_artifact =
            self.stage_checkpoint_certificate(head.wallet, checkpoint, rng).await?;
        let payload = DepositArchivePayload::DepositObservationCheckpoint {
            observation: verified_observation.reference,
            checkpoint: checkpoint_artifact,
        };
        let (next, event_artifact, appended) = self
            .append_checkpoint_event(head, payload, checkpoint, checkpoint_artifact, rng)
            .await?;
        Ok(DepositObservationArchiveAppend {
            head: next,
            observation_artifact: verified_observation.reference,
            checkpoint_artifact,
            event_artifact,
            appended,
            verified_observation,
        })
    }

    /// Re-read a retained exact certificate after restart and bind it to a freshly reissued,
    /// API-unforgeable certificate-verification result.
    pub async fn authenticate_certified_entry_artifact(
        &self,
        reference: WalletArtifactRef,
        verified_entry: &VerifiedEntry,
    ) -> Result<VerifiedCertifiedLedgerEntryArtifact, DepositArchiveError> {
        let wallet = DepositWalletId(reference.wallet_id().0);
        validate_reference(
            reference,
            wallet,
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        verify_certified_entry_artifact_readback(
            reference,
            verified_entry,
            artifact.contents.as_bytes(),
        )
    }

    /// Reissue an observation-artifact capability only after exact encrypted readback.
    pub async fn authenticate_certified_deposit_observation_artifact(
        &self,
        reference: WalletArtifactRef,
        verified_observation: &VerifiedDepositObservationCertificate,
    ) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositArchiveError> {
        let wallet = DepositWalletId(reference.wallet_id().0);
        validate_reference(
            reference,
            wallet,
            CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
            MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        verify_certified_observation_artifact_readback(
            reference,
            verified_observation,
            artifact.contents.as_bytes(),
        )
    }

    async fn reauthenticate_certified_entry_artifact(
        &self,
        verified: VerifiedCertifiedLedgerEntryArtifact,
    ) -> Result<VerifiedCertifiedLedgerEntryArtifact, DepositArchiveError> {
        let entry = self.load_certified_entry(verified.reference, verified.wallet).await?;
        let rebuilt = VerifiedCertifiedLedgerEntryArtifact {
            wallet: entry.statement.wallet,
            sequence: entry.statement.sequence,
            statement_digest: entry.statement.digest(),
            certificate_digest: entry.certificate_digest()?,
            reference: verified.reference,
        };
        if rebuilt != verified {
            return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
        }
        Ok(rebuilt)
    }

    async fn reauthenticate_certified_observation_artifact(
        &self,
        verified: VerifiedCertifiedDepositObservationArtifact,
    ) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositArchiveError> {
        let observation =
            self.load_certified_observation(verified.reference, verified.wallet).await?;
        let rebuilt = VerifiedCertifiedDepositObservationArtifact {
            wallet: observation.statement.wallet_id(),
            statement_digest: observation.statement.digest(),
            certificate_digest: observation.certificate_digest()?,
            reference: verified.reference,
        };
        if rebuilt != verified {
            return Err(DepositArchiveError::CertifiedObservationArtifactMismatch);
        }
        Ok(rebuilt)
    }

    /// Reconstruct the exact non-serializable ledger locator at a committed archive tip.
    ///
    /// Observation tips are intentionally rejected. A caller restoring an older ledger locator
    /// uses [`Self::visit_checkpoints`] and
    /// [`ArchivedCertifiedLedgerEntry::verified_ledger_locator`] instead.
    pub async fn authenticate_head_ledger_locator(
        &self,
        head: DepositArchiveHead,
        verified_entry: &VerifiedEntry,
        verified_checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<VerifiedDepositArchiveLedgerLocator, DepositArchiveError> {
        head.validate()?;
        let event_reference =
            head.event.ok_or(DepositArchiveError::CertifiedEntryArtifactMismatch)?;
        let event = self
            .load_event(
                event_reference,
                head.wallet,
                head.length
                    .checked_sub(1)
                    .ok_or(DepositArchiveError::CertifiedEntryArtifactMismatch)?,
            )
            .await?;
        let DepositArchivePayload::LedgerCheckpoint { ledger, checkpoint } = event.payload else {
            return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
        };
        let entry = self.load_certified_entry(ledger, head.wallet).await?;
        let checkpoint_certificate = self.load_checkpoint(checkpoint, head.wallet).await?;
        verified_ledger_locator(
            event_reference,
            ledger,
            checkpoint,
            &entry,
            verified_certified_entry_artifact(ledger, &entry, verified_entry)?,
            &checkpoint_certificate,
            verified_checkpoint,
        )
    }

    /// Authenticate every object reachable from one compact head and expose exact operation and
    /// checkpoint certificates in independent checkpoint order.
    pub async fn visit_checkpoints<F>(
        &self,
        head: DepositArchiveHead,
        mut visitor: F,
    ) -> Result<(), DepositArchiveError>
    where
        F: FnMut(ArchivedDepositCheckpoint) -> Result<(), DepositArchiveError>,
    {
        head.validate()?;
        let mut reversed_segments = Vec::new();
        let mut segment_reference = head.segment;
        let mut expected_end = head.length;
        let mut newest_segment = true;
        while let Some(reference) = segment_reference {
            let segment = self.load_segment(reference, head.wallet).await?;
            if segment.end_ordinal()? != expected_end
                || (newest_segment && segment.events.last().copied() != head.event)
            {
                return Err(DepositArchiveError::BrokenArchiveChain);
            }
            expected_end = segment.start_ordinal;
            segment_reference = segment.previous;
            reversed_segments.push(reference);
            newest_segment = false;
        }
        if expected_end != 0 || reversed_segments.is_empty() != head.is_empty() {
            return Err(DepositArchiveError::BrokenArchiveChain);
        }
        reversed_segments.reverse();

        let mut previous_event = None;
        let mut previous_checkpoint: Option<DepositIndexCheckpointCertificate> = None;
        let mut visited = 0_u64;
        for segment_reference in reversed_segments {
            let segment = self.load_segment(segment_reference, head.wallet).await?;
            for (offset, event_artifact) in segment.events.iter().copied().enumerate() {
                let offset = u64::try_from(offset)
                    .map_err(|_| DepositArchiveError::ArchiveOrdinalExhausted)?;
                let ordinal = segment
                    .start_ordinal
                    .checked_add(offset)
                    .ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
                if ordinal != visited {
                    return Err(DepositArchiveError::BrokenArchiveChain);
                }
                let event = self.load_event(event_artifact, head.wallet, ordinal).await?;
                if event.previous != previous_event {
                    return Err(DepositArchiveError::BrokenArchiveChain);
                }
                let checkpoint_sequence =
                    ordinal.checked_add(1).ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
                let checkpoint_artifact = event.checkpoint_reference();
                let checkpoint = self.load_checkpoint(checkpoint_artifact, head.wallet).await?;
                if checkpoint.statement().sequence() != checkpoint_sequence
                    || checkpoint.statement().context().wallet_id() != head.wallet
                {
                    return Err(DepositArchiveError::ArchiveCheckpointSequenceMismatch {
                        expected: checkpoint_sequence,
                        actual: checkpoint.statement().sequence(),
                    });
                }
                match (&previous_checkpoint, checkpoint.statement().parent()) {
                    (Some(previous), DepositIndexCheckpointParent::Certified { decision })
                        if decision == previous.statement().decision_digest()
                            && checkpoint.statement().previous_head()
                                == previous.statement().resulting_head() => {}
                    (None, DepositIndexCheckpointParent::Genesis) if checkpoint_sequence == 1 => {}
                    _ => return Err(DepositArchiveError::ArchiveCheckpointParentMismatch),
                }
                let archived = match event.payload {
                    DepositArchivePayload::LedgerCheckpoint { ledger, checkpoint: expected }
                        if expected == checkpoint_artifact =>
                    {
                        let entry = self.load_certified_entry(ledger, head.wallet).await?;
                        if checkpoint.statement().operation()
                            != (DepositIndexCheckpointOperation::Ledger {
                                statement: entry.statement.digest(),
                            })
                            || checkpoint.statement().ledger_sequence() != entry.statement.sequence
                            || checkpoint.statement().ledger_decision() != entry.statement.digest()
                            || entry.statement.previous
                                != checkpoint.statement().previous_head().ledger_head()
                        {
                            return Err(DepositArchiveError::CheckpointOperationMismatch);
                        }
                        ArchivedDepositCheckpoint::Ledger(ArchivedCertifiedLedgerEntry {
                            ordinal,
                            checkpoint_sequence,
                            event_artifact,
                            entry_artifact: ledger,
                            checkpoint_artifact,
                            entry,
                            checkpoint: checkpoint.clone(),
                            _archive_authenticated: (),
                        })
                    }
                    DepositArchivePayload::DepositObservationCheckpoint {
                        observation,
                        checkpoint: expected,
                    } if expected == checkpoint_artifact => {
                        let observation =
                            self.load_certified_observation(observation, head.wallet).await?;
                        if checkpoint.statement().operation()
                            != (DepositIndexCheckpointOperation::DepositObservation {
                                statement: observation.statement.digest(),
                            })
                        {
                            return Err(DepositArchiveError::CheckpointOperationMismatch);
                        }
                        ArchivedDepositCheckpoint::DepositObservation(
                            ArchivedCertifiedDepositObservation {
                                ordinal,
                                checkpoint_sequence,
                                event_artifact,
                                observation_artifact: event.operation_reference(),
                                checkpoint_artifact,
                                observation,
                                checkpoint: checkpoint.clone(),
                                _archive_authenticated: (),
                            },
                        )
                    }
                    _ => return Err(DepositArchiveError::BrokenArchiveChain),
                };
                previous_event = Some(event_artifact);
                previous_checkpoint = Some(checkpoint);
                visited = checkpoint_sequence;
                visitor(archived)?;
            }
        }
        if visited != head.length || previous_event != head.event {
            return Err(DepositArchiveError::BrokenArchiveChain);
        }
        Ok(())
    }

    /// Convenience traversal for callers interested only in globally ordered ledger operations.
    ///
    /// Observation checkpoints remain fully authenticated in the prefix and are skipped only
    /// after their exact event/checkpoint pair has passed validation.
    pub async fn visit_certified_entries<F>(
        &self,
        head: DepositArchiveHead,
        mut visitor: F,
    ) -> Result<(), DepositArchiveError>
    where
        F: FnMut(ArchivedCertifiedLedgerEntry) -> Result<(), DepositArchiveError>,
    {
        self.visit_checkpoints(head, |archived| {
            if let ArchivedDepositCheckpoint::Ledger(entry) = archived {
                visitor(entry)?;
            }
            Ok(())
        })
        .await
    }

    async fn stage_checkpoint_certificate<R: RngCore + CryptoRng>(
        &self,
        wallet: DepositWalletId,
        checkpoint: &DepositIndexCheckpointCertificate,
        rng: &mut R,
    ) -> Result<WalletArtifactRef, DepositArchiveError> {
        if checkpoint.statement().context().wallet_id() != wallet {
            return Err(DepositArchiveError::WrongWallet);
        }
        let bytes = checkpoint.to_bytes()?;
        let reference = self
            .artifacts
            .create_artifact(
                WalletId(wallet.0),
                DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
                &bytes,
                rng,
            )
            .await?;
        let readback = self.load_checkpoint(reference, wallet).await?;
        if readback != *checkpoint {
            return Err(DepositArchiveError::CheckpointArtifactMismatch);
        }
        Ok(reference)
    }

    async fn append_checkpoint_event<R: RngCore + CryptoRng>(
        &self,
        head: DepositArchiveHead,
        payload: DepositArchivePayload,
        checkpoint: &DepositIndexCheckpointCertificate,
        checkpoint_artifact: WalletArtifactRef,
        rng: &mut R,
    ) -> Result<(DepositArchiveHead, WalletArtifactRef, bool), DepositArchiveError> {
        head.validate()?;
        validate_reference(
            checkpoint_artifact,
            head.wallet,
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
        )?;
        if checkpoint.statement().context().wallet_id() != head.wallet
            || payload.checkpoint_reference() != checkpoint_artifact
        {
            return Err(DepositArchiveError::CheckpointArtifactMismatch);
        }

        let current_segment = if let Some(reference) = head.segment {
            let segment = self.load_segment(reference, head.wallet).await?;
            if segment.end_ordinal()? != head.length || segment.events.last().copied() != head.event
            {
                return Err(DepositArchiveError::BrokenArchiveChain);
            }
            Some(segment)
        } else {
            None
        };

        let checkpoint_sequence = checkpoint.statement().sequence();
        if checkpoint_sequence == head.length {
            let ordinal = checkpoint_sequence.checked_sub(1).ok_or(
                DepositArchiveError::ArchiveCheckpointSequenceMismatch {
                    expected: 1,
                    actual: checkpoint_sequence,
                },
            )?;
            let event_artifact =
                head.event.ok_or(DepositArchiveError::ArchiveCheckpointConflict)?;
            let event = self.load_event(event_artifact, head.wallet, ordinal).await?;
            if event.payload != payload {
                return Err(DepositArchiveError::ArchiveCheckpointConflict);
            }
            return Ok((head, event_artifact, false));
        }
        let expected_sequence =
            head.length.checked_add(1).ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
        if checkpoint_sequence != expected_sequence {
            return Err(DepositArchiveError::ArchiveCheckpointSequenceMismatch {
                expected: expected_sequence,
                actual: checkpoint_sequence,
            });
        }

        match (head.event, checkpoint.statement().parent()) {
            (None, DepositIndexCheckpointParent::Genesis) => {
                if head.length != 0 {
                    return Err(DepositArchiveError::BrokenArchiveChain);
                }
            }
            (Some(previous_event), DepositIndexCheckpointParent::Certified { decision }) => {
                let previous = self
                    .load_event(
                        previous_event,
                        head.wallet,
                        head.length
                            .checked_sub(1)
                            .ok_or(DepositArchiveError::BrokenArchiveChain)?,
                    )
                    .await?;
                let previous_checkpoint =
                    self.load_checkpoint(previous.checkpoint_reference(), head.wallet).await?;
                if previous_checkpoint.statement().sequence() != head.length
                    || previous_checkpoint.statement().decision_digest() != decision
                    || checkpoint.statement().previous_head()
                        != previous_checkpoint.statement().resulting_head()
                {
                    return Err(DepositArchiveError::ArchiveCheckpointParentMismatch);
                }
            }
            _ => return Err(DepositArchiveError::ArchiveCheckpointParentMismatch),
        }

        let ordinal = head.length;
        let event = DepositArchiveEvent {
            version: ARCHIVE_EVENT_VERSION,
            wallet: head.wallet,
            ordinal,
            previous: head.event,
            payload,
        };
        let event_bytes = event.to_bytes()?;
        let event_artifact = self
            .artifacts
            .create_artifact(
                WalletId(head.wallet.0),
                DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
                &event_bytes,
                rng,
            )
            .await?;
        if self.load_event(event_artifact, head.wallet, ordinal).await? != event {
            return Err(DepositArchiveError::ArtifactReferenceMismatch);
        }

        let segment_width = u64::try_from(MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS)
            .map_err(|_| DepositArchiveError::ArchiveOrdinalExhausted)?;
        let segment = if ordinal % segment_width == 0 {
            DepositArchiveSegment {
                version: ARCHIVE_SEGMENT_VERSION,
                wallet: head.wallet,
                start_ordinal: ordinal,
                previous: head.segment,
                events: vec![event_artifact],
            }
        } else {
            let previous = current_segment.ok_or(DepositArchiveError::BrokenArchiveChain)?;
            let expected_start = ordinal - (ordinal % segment_width);
            if previous.start_ordinal != expected_start
                || previous.events.len() >= MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS
            {
                return Err(DepositArchiveError::BrokenArchiveChain);
            }
            let mut events = previous.events;
            events.push(event_artifact);
            DepositArchiveSegment {
                version: ARCHIVE_SEGMENT_VERSION,
                wallet: head.wallet,
                start_ordinal: previous.start_ordinal,
                previous: previous.previous,
                events,
            }
        };
        let segment_bytes = segment.to_bytes()?;
        let segment_artifact = self
            .artifacts
            .create_artifact(
                WalletId(head.wallet.0),
                DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
                &segment_bytes,
                rng,
            )
            .await?;
        if self.load_segment(segment_artifact, head.wallet).await? != segment {
            return Err(DepositArchiveError::ArtifactReferenceMismatch);
        }
        let next = DepositArchiveHead {
            version: ARCHIVE_HEAD_VERSION,
            wallet: head.wallet,
            length: checkpoint_sequence,
            event: Some(event_artifact),
            segment: Some(segment_artifact),
        };
        next.validate()?;
        Ok((next, event_artifact, true))
    }

    async fn load_certified_entry(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
    ) -> Result<CertifiedLedgerEntry, DepositArchiveError> {
        validate_reference(
            reference,
            wallet,
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        let entry = CertifiedLedgerEntry::from_bytes(artifact.contents.as_bytes())?;
        if entry.statement.wallet != wallet {
            return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
        }
        Ok(entry)
    }

    async fn load_certified_observation(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
    ) -> Result<CertifiedDepositObservation, DepositArchiveError> {
        validate_reference(
            reference,
            wallet,
            CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
            MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        let observation = CertifiedDepositObservation::from_bytes(artifact.contents.as_bytes())?;
        if observation.statement.wallet_id() != wallet {
            return Err(DepositArchiveError::CertifiedObservationArtifactMismatch);
        }
        Ok(observation)
    }

    async fn load_checkpoint(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
    ) -> Result<DepositIndexCheckpointCertificate, DepositArchiveError> {
        validate_reference(
            reference,
            wallet,
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        let checkpoint =
            DepositIndexCheckpointCertificate::from_bytes(artifact.contents.as_bytes())?;
        if checkpoint.statement().context().wallet_id() != wallet {
            return Err(DepositArchiveError::CheckpointArtifactMismatch);
        }
        Ok(checkpoint)
    }

    /// Read one bounded plaintext object chunk for authenticated QUIC transfer.
    pub async fn artifact_chunk(
        &self,
        request: DepositArtifactChunkRequest,
    ) -> Result<DepositArtifactChunk, DepositArchiveError> {
        request.validate()?;
        let artifact = self.artifacts.load_artifact(request.reference).await?;
        let start = usize::try_from(request.offset)
            .map_err(|_| DepositArchiveError::InvalidArtifactChunk)?;
        let maximum = usize::try_from(request.maximum_bytes)
            .map_err(|_| DepositArchiveError::InvalidArtifactChunk)?;
        let end = start.saturating_add(maximum).min(artifact.contents.len());
        DepositArtifactChunk::from_parts(
            request.reference,
            request.offset,
            artifact.contents.as_bytes()[start..end].to_vec(),
            end == artifact.contents.len(),
        )
    }

    /// Verify and locally encrypt an object assembled from peer chunks. The expected reference is
    /// never trusted as a filename until the exact plaintext hash/context has been checked.
    pub async fn persist_transferred_artifact<R: RngCore + CryptoRng>(
        &self,
        reference: WalletArtifactRef,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), DepositArchiveError> {
        reference.verify_contents(bytes)?;
        let stored = self
            .artifacts
            .create_artifact(reference.wallet_id(), reference.kind(), bytes, rng)
            .await?;
        if stored != reference {
            return Err(DepositArchiveError::ArtifactReferenceMismatch);
        }
        Ok(())
    }

    async fn load_event(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
        ordinal: u64,
    ) -> Result<DepositArchiveEvent, DepositArchiveError> {
        validate_reference(
            reference,
            wallet,
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        let event: DepositArchiveEvent = decode_canonical_bounded(
            artifact.contents.as_bytes(),
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
            "deposit archive event",
        )?;
        validate_event(&event, wallet, ordinal)?;
        Ok(event)
    }

    async fn load_segment(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
    ) -> Result<DepositArchiveSegment, DepositArchiveError> {
        validate_reference(
            reference,
            wallet,
            DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
        )?;
        let artifact = self.artifacts.load_artifact(reference).await?;
        let segment = DepositArchiveSegment::from_bytes(artifact.contents.as_bytes())?;
        if segment.wallet != wallet {
            return Err(DepositArchiveError::InvalidArchiveSegment);
        }
        Ok(segment)
    }
}

/// Assemble an exact sequence of bounded chunks and authenticate the completed object.
pub fn assemble_artifact_chunks(
    reference: WalletArtifactRef,
    chunks: &[DepositArtifactChunk],
) -> Result<Vec<u8>, DepositArchiveError> {
    let capacity = usize::try_from(reference.plaintext_len())
        .map_err(|_| DepositArchiveError::InvalidArtifactChunk)?;
    if capacity > MAX_WALLET_ARTIFACT_BYTES || chunks.is_empty() {
        return Err(DepositArchiveError::InvalidArtifactChunk);
    }
    let mut bytes = Vec::with_capacity(capacity);
    let mut next_offset = 0_u64;
    for (position, chunk) in chunks.iter().enumerate() {
        chunk.validate()?;
        if chunk.reference != reference
            || chunk.offset != next_offset
            || (chunk.complete && position + 1 != chunks.len())
        {
            return Err(DepositArchiveError::InvalidArtifactChunk);
        }
        bytes.extend_from_slice(&chunk.bytes);
        next_offset =
            u64::try_from(bytes.len()).map_err(|_| DepositArchiveError::InvalidArtifactChunk)?;
    }
    if !chunks.last().is_some_and(|chunk| chunk.complete) {
        return Err(DepositArchiveError::InvalidArtifactChunk);
    }
    reference.verify_contents(&bytes)?;
    Ok(bytes)
}

fn validate_event(
    event: &DepositArchiveEvent,
    wallet: DepositWalletId,
    ordinal: u64,
) -> Result<(), DepositArchiveError> {
    if event.version != ARCHIVE_EVENT_VERSION || event.wallet != wallet || event.ordinal != ordinal
    {
        return Err(DepositArchiveError::BrokenArchiveChain);
    }
    if (ordinal == 0) != event.previous.is_none() {
        return Err(DepositArchiveError::BrokenArchiveChain);
    }
    if let Some(previous) = event.previous {
        validate_reference(
            previous,
            wallet,
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
    }
    match event.payload {
        DepositArchivePayload::LedgerCheckpoint { ledger, checkpoint } => {
            validate_reference(
                ledger,
                wallet,
                CERTIFIED_LEDGER_ENTRY_ARTIFACT,
                MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
            )?;
            validate_reference(
                checkpoint,
                wallet,
                DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
                MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
            )
        }
        DepositArchivePayload::DepositObservationCheckpoint { observation, checkpoint } => {
            validate_reference(
                observation,
                wallet,
                CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
                MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES,
            )?;
            validate_reference(
                checkpoint,
                wallet,
                DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
                MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
            )
        }
    }
}

fn validate_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
    kind: WalletArtifactKind,
    maximum: usize,
) -> Result<(), DepositArchiveError> {
    let length = usize::try_from(reference.plaintext_len())
        .map_err(|_| DepositArchiveError::ArtifactReferenceMismatch)?;
    if reference.wallet_id() != WalletId(wallet.0)
        || reference.kind() != kind
        || length == 0
        || length > maximum
    {
        return Err(DepositArchiveError::ArtifactReferenceMismatch);
    }
    Ok(())
}

pub(crate) fn verify_certified_entry_artifact_readback(
    reference: WalletArtifactRef,
    verified_entry: &VerifiedEntry,
    bytes: &[u8],
) -> Result<VerifiedCertifiedLedgerEntryArtifact, DepositArchiveError> {
    reference.verify_contents(bytes)?;
    let decoded = CertifiedLedgerEntry::from_bytes(bytes)?;
    verified_certified_entry_artifact(reference, &decoded, verified_entry)
}

pub(crate) fn verify_certified_observation_artifact_readback(
    reference: WalletArtifactRef,
    verified_observation: &VerifiedDepositObservationCertificate,
    bytes: &[u8],
) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositArchiveError> {
    reference.verify_contents(bytes)?;
    let decoded = CertifiedDepositObservation::from_bytes(bytes)?;
    verified_certified_observation_artifact(reference, &decoded, verified_observation)
}

fn verified_certified_entry_artifact(
    reference: WalletArtifactRef,
    entry: &CertifiedLedgerEntry,
    verified_entry: &VerifiedEntry,
) -> Result<VerifiedCertifiedLedgerEntryArtifact, DepositArchiveError> {
    let wallet = entry.statement.wallet;
    validate_reference(
        reference,
        wallet,
        CERTIFIED_LEDGER_ENTRY_ARTIFACT,
        MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
    )?;
    verified_entry.verify_exact_certificate(entry)?;
    if verified_entry.wallet_id() != wallet
        || verified_entry.sequence() != entry.statement.sequence
        || verified_entry.statement_digest() != entry.statement.digest()
        || verified_entry.certificate_digest() != entry.certificate_digest()?
    {
        return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
    }
    Ok(VerifiedCertifiedLedgerEntryArtifact {
        wallet,
        sequence: entry.statement.sequence,
        statement_digest: entry.statement.digest(),
        certificate_digest: verified_entry.certificate_digest(),
        reference,
    })
}

fn verified_certified_observation_artifact(
    reference: WalletArtifactRef,
    observation: &CertifiedDepositObservation,
    verified_observation: &VerifiedDepositObservationCertificate,
) -> Result<VerifiedCertifiedDepositObservationArtifact, DepositArchiveError> {
    let wallet = observation.statement.wallet_id();
    validate_reference(
        reference,
        wallet,
        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT,
        MAX_CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT_BYTES,
    )?;
    verified_observation.verify_exact_certificate(observation)?;
    if verified_observation.wallet_id() != wallet
        || verified_observation.statement_digest() != observation.statement.digest()
        || verified_observation.certificate_digest() != observation.certificate_digest()?
    {
        return Err(DepositArchiveError::CertifiedObservationArtifactMismatch);
    }
    Ok(VerifiedCertifiedDepositObservationArtifact {
        wallet,
        statement_digest: observation.statement.digest(),
        certificate_digest: verified_observation.certificate_digest(),
        reference,
    })
}

fn verify_checkpoint_capability(
    checkpoint: &DepositIndexCheckpointCertificate,
    verified: &VerifiedDepositIndexCheckpoint,
    wallet: DepositWalletId,
) -> Result<(), DepositArchiveError> {
    let statement = checkpoint.statement();
    let signers: Vec<_> = checkpoint.witnesses().iter().map(|witness| witness.from).collect();
    if statement.context().wallet_id() != wallet
        || statement.context() != verified.context()
        || statement.sequence() != verified.sequence()
        || statement.decision_digest() != verified.decision_digest()
        || statement.operation() != verified.operation()
        || statement.ledger_sequence() != verified.ledger_sequence()
        || statement.ledger_decision() != verified.ledger_decision()
        || statement.update_digest() != verified.update_digest()
        || statement.resulting_head() != verified.resulting_head()
        || checkpoint.certificate_digest()? != verified.certificate_digest()
        || signers != verified.signers()
    {
        return Err(DepositArchiveError::CheckpointCapabilityMismatch);
    }
    Ok(())
}

fn verified_ledger_locator(
    event_artifact: WalletArtifactRef,
    ledger_artifact: WalletArtifactRef,
    checkpoint_artifact: WalletArtifactRef,
    entry: &CertifiedLedgerEntry,
    verified_entry: VerifiedCertifiedLedgerEntryArtifact,
    checkpoint: &DepositIndexCheckpointCertificate,
    verified_checkpoint: &VerifiedDepositIndexCheckpoint,
) -> Result<VerifiedDepositArchiveLedgerLocator, DepositArchiveError> {
    let wallet = entry.statement.wallet;
    if verified_entry.reference != ledger_artifact
        || verified_entry.wallet != wallet
        || verified_entry.sequence != entry.statement.sequence
        || verified_entry.statement_digest != entry.statement.digest()
        || verified_entry.certificate_digest != entry.certificate_digest()?
    {
        return Err(DepositArchiveError::CertifiedEntryArtifactMismatch);
    }
    verify_checkpoint_capability(checkpoint, verified_checkpoint, wallet)?;
    let statement = checkpoint.statement();
    let ledger_statement = entry.statement.digest();
    if statement.operation()
        != (DepositIndexCheckpointOperation::Ledger { statement: ledger_statement })
        || statement.ledger_sequence() != entry.statement.sequence
        || statement.ledger_decision() != ledger_statement
        || entry.statement.previous != statement.previous_head().ledger_head()
    {
        return Err(DepositArchiveError::CheckpointOperationMismatch);
    }
    validate_reference(
        event_artifact,
        wallet,
        DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
        MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
    )?;
    validate_reference(
        ledger_artifact,
        wallet,
        CERTIFIED_LEDGER_ENTRY_ARTIFACT,
        MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
    )?;
    validate_reference(
        checkpoint_artifact,
        wallet,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
        MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
    )?;
    Ok(VerifiedDepositArchiveLedgerLocator {
        wallet,
        checkpoint_sequence: statement.sequence(),
        checkpoint_decision: statement.decision_digest(),
        checkpoint_certificate_digest: checkpoint.certificate_digest()?,
        ledger_sequence: entry.statement.sequence,
        ledger_statement,
        event_artifact,
        ledger_artifact,
        checkpoint_artifact,
    })
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, DepositArchiveError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| DepositArchiveError::Serialization)?;
    if bytes.len() > maximum {
        return Err(DepositArchiveError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn decode_canonical_bounded<T>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, DepositArchiveError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > maximum {
        return Err(DepositArchiveError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    let (value, trailing) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| DepositArchiveError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositArchiveError::TrailingBytes { kind, trailing: trailing.len() });
    }
    if postcard::to_allocvec(&value).map_err(|_| DepositArchiveError::Serialization)? != bytes {
        return Err(DepositArchiveError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

#[derive(Debug, Error)]
pub enum DepositArchiveError {
    #[error("deposit archive storage failed: {0}")]
    Store(#[from] StoreError),
    #[error("deposit ledger validation failed: {0}")]
    Ledger(#[from] LedgerError),
    #[error("deposit-index checkpoint validation failed: {0}")]
    Checkpoint(#[from] DepositIndexCheckpointError),
    #[error("archive serialization failed")]
    Serialization,
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{0} encoding is not canonical")]
    NonCanonicalEncoding(&'static str),
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("deposit archive head is invalid")]
    InvalidArchiveHead,
    #[error("deposit archive chain is broken")]
    BrokenArchiveChain,
    #[error("deposit archive exhausted its u64 ordinal space")]
    ArchiveOrdinalExhausted,
    #[error("deposit archive segment is invalid")]
    InvalidArchiveSegment,
    #[error("archive certificate belongs to another wallet")]
    WrongWallet,
    #[error("archive artifact reference has the wrong wallet, kind, or length")]
    ArtifactReferenceMismatch,
    #[error("certified-entry artifact does not canonically decode to the expected statement")]
    CertifiedEntryArtifactMismatch,
    #[error("certified-observation artifact does not canonically decode to the expected statement")]
    CertifiedObservationArtifactMismatch,
    #[error("checkpoint artifact does not canonically decode to the exact expected certificate")]
    CheckpointArtifactMismatch,
    #[error("checkpoint certificate does not match the supplied cryptographic capability")]
    CheckpointCapabilityMismatch,
    #[error("checkpoint operation does not match its exact archived operation certificate")]
    CheckpointOperationMismatch,
    #[error("archive checkpoint sequence mismatch: expected {expected}, got {actual}")]
    ArchiveCheckpointSequenceMismatch { expected: u64, actual: u64 },
    #[error("archive already contains a different checkpoint at this sequence")]
    ArchiveCheckpointConflict,
    #[error("checkpoint parent does not match the exact preceding archived decision")]
    ArchiveCheckpointParentMismatch,
    #[error("artifact transfer chunk is invalid, out of order, or incomplete")]
    InvalidArtifactChunk,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_epoch_registry::CompactEpochRegistry,
        compact_registry_archive::prepare_compact_registry_genesis,
        config::NetworkKind,
        deposit_index::{
            DepositIndexBuilder, DepositIndexError, DepositIndexHead, DepositIndexObjectId,
            DepositIndexReader, DepositIndexUpdate, VerifiedDepositIndexPreflight,
            VerifiedDepositObservationIndexTransition,
        },
        deposit_index_checkpoint::{
            DepositIndexCheckpointCandidate, DepositIndexCheckpointStatement,
            certify_checkpoint_candidate_for_test,
        },
        deposit_ledger::{
            DepositObservationStatement, LedgerRequestId, LedgerStatement, RequestBinding,
            VerifiedDepositObservationCertificate, VerifiedEntry, genesis_head,
            sign_deposit_observation_attestation,
        },
        deposit_wallet::{
            ChainPoint, DepositAddressDeriver, DepositSubaddressIndex, WalletOutputId,
        },
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    const SIGNING_NOW: u64 = 999;

    #[derive(Clone, Default)]
    struct MemoryIndexReader {
        objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    }

    impl MemoryIndexReader {
        fn apply(&mut self, update: &DepositIndexUpdate) {
            for id in update.obsolete_objects() {
                self.objects.remove(&id);
            }
            self.objects.extend(update.staged_objects().map(|(id, bytes)| (id, bytes.to_vec())));
        }
    }

    impl DepositIndexReader for MemoryIndexReader {
        fn load_index_object(
            &self,
            id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(self.objects.get(&id).cloned())
        }
    }

    fn deriver() -> DepositAddressDeriver {
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap()
    }

    fn identities() -> (Committee, BTreeMap<PartyId, Identity>) {
        let identities = (1_u16..=4)
            .map(|value| {
                let party = PartyId(value);
                let seed = u8::try_from(value).unwrap();
                let identity =
                    Identity::from_test_secrets(party, 0, &[seed; 32], [seed | 0x80; 32]).unwrap();
                (party, identity)
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
        (Committee { epoch: 0, threshold: 2, members }, identities)
    }

    struct Fixture {
        network: [u8; 32],
        registry: CompactEpochRegistry,
        ledger: CertifiedLedgerEntry,
        verified_ledger: VerifiedEntry,
        preflight: VerifiedDepositIndexPreflight,
        update: DepositIndexUpdate,
        identities: BTreeMap<PartyId, Identity>,
        reader: MemoryIndexReader,
    }

    fn make_fixture(request_byte: u8) -> Fixture {
        let deriver = deriver();
        let (committee, identities) = identities();
        let wallet = deriver.wallet_id();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let head = DepositIndexHead::empty_portable(wallet, first_index).unwrap();
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee.clone(),
            1,
            [0x22; 32],
            [0x23; 32],
            wallet,
            [0x24; 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let registry = prepare_compact_registry_genesis(&target, first_index, head.digest())
            .unwrap()
            .proposed_head()
            .registry()
            .clone();
        let statement = LedgerStatement::allocation(
            &registry,
            1,
            genesis_head(wallet),
            LedgerRequestId([request_byte; 32]),
            RequestBinding([request_byte.wrapping_add(1); 32]),
            deriver.derive(first_index),
            ChainPoint::new(0, [0x6b; 32]).unwrap(),
            1_000,
        )
        .unwrap();
        let payload = statement.attestation_payload().unwrap();
        let attestations = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence,
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect();
        let ledger = CertifiedLedgerEntry { statement, attestations };
        let verified_ledger = ledger.verify_active(&registry, None).unwrap();
        let reader = MemoryIndexReader::default();
        let mut preflight_builder = DepositIndexBuilder::new(&reader, head.clone()).unwrap();
        let preflight = preflight_builder.preflight_ledger_statement(&ledger.statement).unwrap();
        let mut builder = DepositIndexBuilder::new(&reader, head).unwrap();
        assert!(builder.apply_verified_active_entry(&ledger, &registry, None).unwrap());
        let update = builder.finish().unwrap().unwrap();
        update
            .verify_ledger_transition_for_preflight(&reader, &ledger.statement, &preflight)
            .unwrap();
        Fixture {
            network: [0x55; 32],
            registry,
            ledger,
            verified_ledger,
            preflight,
            update,
            identities,
            reader,
        }
    }

    fn ledger_checkpoint_with_signers(
        fixture: &Fixture,
        signers: &[PartyId],
    ) -> DepositIndexCheckpointCertificate {
        let statement = DepositIndexCheckpointStatement::for_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        let selection = certify_checkpoint_candidate_for_test(
            fixture.network,
            &fixture.registry,
            statement.sequence(),
            statement.previous_head(),
            DepositIndexCheckpointCandidate::Ledger(fixture.ledger.clone()),
            &fixture.identities,
        );
        let witnesses = signers
            .iter()
            .map(|party| {
                fixture
                    .identities
                    .get(party)
                    .unwrap()
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence(),
                        statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        DepositIndexCheckpointCertificate::from_witnesses(
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            statement,
            selection,
            witnesses,
        )
        .unwrap()
    }

    fn ledger_certificate_with_signers(
        fixture: &Fixture,
        signers: &[PartyId],
    ) -> CertifiedLedgerEntry {
        let statement = fixture.ledger.statement.clone();
        let payload = statement.attestation_payload().unwrap();
        let attestations = signers
            .iter()
            .map(|party| {
                fixture
                    .identities
                    .get(party)
                    .unwrap()
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence,
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect();
        CertifiedLedgerEntry { statement, attestations }
    }

    fn ledger_checkpoint(fixture: &Fixture) -> DepositIndexCheckpointCertificate {
        ledger_checkpoint_with_signers(fixture, &[PartyId(1), PartyId(2), PartyId(3)])
    }

    fn checkpoint_with_corrupted_witness(
        checkpoint: &DepositIndexCheckpointCertificate,
    ) -> DepositIndexCheckpointCertificate {
        #[derive(serde::Serialize)]
        struct CheckpointWire<'a> {
            version: u16,
            statement: &'a DepositIndexCheckpointStatement,
            selection: &'a crate::deposit_consensus::CommitCertificate,
            witnesses: &'a [crate::identity::SignedEnvelope],
        }

        let mut witnesses = checkpoint.witnesses().to_vec();
        witnesses[0].signature[0] ^= 1;
        let bytes = postcard::to_allocvec(&CheckpointWire {
            // Must mirror DepositIndexCheckpointCertificate::CERTIFICATE_VERSION so the
            // re-decoded certificate passes its canonical round-trip check.
            version: 2,
            statement: checkpoint.statement(),
            selection: checkpoint.selection(),
            witnesses: &witnesses,
        })
        .unwrap();
        DepositIndexCheckpointCertificate::from_bytes(&bytes).unwrap()
    }

    fn verify_ledger_checkpoint(
        fixture: &Fixture,
        certificate: &DepositIndexCheckpointCertificate,
    ) -> VerifiedDepositIndexCheckpoint {
        certificate
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap()
    }

    fn certified_observation(
        fixture: &Fixture,
        output_byte: u8,
    ) -> (CertifiedDepositObservation, VerifiedDepositObservationCertificate) {
        let output_key_byte = output_byte.wrapping_add(0x10);
        let statement = DepositObservationStatement::new(
            &fixture.registry,
            &fixture.ledger.statement,
            WalletOutputId {
                transaction: [output_byte; 32],
                index_in_transaction: u64::from(output_byte),
            },
            [output_key_byte; 32],
            u64::from(output_byte),
            1_000 + u64::from(output_byte),
            ChainPoint::new(20, [output_byte; 32]).unwrap(),
            900 + u64::from(output_byte),
            ChainPoint::new(29, [output_key_byte; 32]).unwrap(),
            10,
        )
        .unwrap();
        let attestations = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                sign_deposit_observation_attestation(identity, &fixture.registry, &statement)
                    .unwrap()
            })
            .collect();
        let observation = CertifiedDepositObservation { statement, attestations };
        let verified = observation.verify_active(&fixture.registry).unwrap();
        (observation, verified)
    }

    fn observation_transition(
        fixture: &Fixture,
        observation: &CertifiedDepositObservation,
    ) -> VerifiedDepositObservationIndexTransition {
        let mut reader = fixture.reader.clone();
        reader.apply(&fixture.update);
        let mut builder =
            DepositIndexBuilder::new(&reader, fixture.update.next_head().clone()).unwrap();
        assert!(
            builder
                .apply_verified_active_deposit_observation(observation, &fixture.registry)
                .unwrap()
        );
        builder
            .finish()
            .unwrap()
            .unwrap()
            .verify_deposit_observation_transition(&reader, &observation.statement)
            .unwrap()
    }

    fn observation_checkpoint(
        fixture: &Fixture,
        previous: &VerifiedDepositIndexCheckpoint,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> DepositIndexCheckpointCertificate {
        let statement = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            Some(previous),
            observation,
            transition,
        )
        .unwrap();
        let selection = certify_checkpoint_candidate_for_test(
            fixture.network,
            &fixture.registry,
            statement.sequence(),
            statement.previous_head(),
            DepositIndexCheckpointCandidate::DepositObservation(observation.clone()),
            &fixture.identities,
        );
        let witnesses = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence(),
                        statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        DepositIndexCheckpointCertificate::from_deposit_observation_witnesses(
            fixture.network,
            &fixture.registry,
            Some(previous),
            observation,
            statement,
            selection,
            witnesses,
        )
        .unwrap()
    }

    struct CertifiedHistory {
        ledger_checkpoint: DepositIndexCheckpointCertificate,
        verified_ledger: VerifiedDepositIndexCheckpoint,
        observation: CertifiedDepositObservation,
        verified_observation_certificate: VerifiedDepositObservationCertificate,
        observation_checkpoint: DepositIndexCheckpointCertificate,
        verified_observation_checkpoint: VerifiedDepositIndexCheckpoint,
    }

    fn certified_history(fixture: &Fixture) -> CertifiedHistory {
        let ledger_checkpoint = ledger_checkpoint(fixture);
        let verified_ledger = verify_ledger_checkpoint(fixture, &ledger_checkpoint);
        let (observation, verified_observation_certificate) = certified_observation(fixture, 0x41);
        let transition = observation_transition(fixture, &observation);
        let observation_checkpoint =
            observation_checkpoint(fixture, &verified_ledger, &observation, &transition);
        let verified_observation_checkpoint = observation_checkpoint
            .verify_active_deposit_observation(
                fixture.network,
                &fixture.registry,
                Some(&verified_ledger),
                &observation,
            )
            .unwrap();
        CertifiedHistory {
            ledger_checkpoint,
            verified_ledger,
            observation,
            verified_observation_certificate,
            observation_checkpoint,
            verified_observation_checkpoint,
        }
    }

    async fn collect_checkpoints(
        archive: &DepositArchiveStore,
        head: DepositArchiveHead,
    ) -> Result<Vec<ArchivedDepositCheckpoint>, DepositArchiveError> {
        let mut checkpoints = Vec::new();
        archive
            .visit_checkpoints(head, |checkpoint| {
                checkpoints.push(checkpoint);
                Ok(())
            })
            .await?;
        Ok(checkpoints)
    }

    async fn corrupt_artifact(archive: &DepositArchiveStore, reference: WalletArtifactRef) {
        let path = archive.artifact_path(reference);
        let mut sealed = tokio::fs::read(&path).await.unwrap();
        *sealed.last_mut().unwrap() ^= 1;
        tokio::fs::write(path, sealed).await.unwrap();
    }

    #[tokio::test]
    async fn staging_is_non_authoritative_and_restart_reauthenticates_exact_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x31);
        let original_head = DepositArchiveHead::empty(fixture.registry.wallet()).unwrap();
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x31; 32]).unwrap();

        let staged = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();
        assert_eq!(staged.wallet_id(), fixture.registry.wallet());
        assert_eq!(staged.sequence(), fixture.ledger.statement.sequence);
        assert_eq!(staged.statement_digest(), fixture.ledger.statement.digest());
        assert_eq!(staged.certificate_digest(), fixture.verified_ledger.certificate_digest());
        assert!(collect_checkpoints(&archive, original_head).await.unwrap().is_empty());
        assert!(original_head.is_empty());

        let alternate_certificate =
            ledger_certificate_with_signers(&fixture, &[PartyId(2), PartyId(3), PartyId(4)]);
        let alternate_verified =
            alternate_certificate.verify_active(&fixture.registry, None).unwrap();
        assert_eq!(
            alternate_verified.statement_digest(),
            fixture.verified_ledger.statement_digest()
        );
        assert_ne!(
            alternate_verified.certificate_digest(),
            fixture.verified_ledger.certificate_digest()
        );
        assert!(matches!(
            archive
                .stage_certified_ledger_entry(&fixture.ledger, &alternate_verified, &mut OsRng,)
                .await,
            Err(DepositArchiveError::Ledger(LedgerError::VerificationCapabilityMismatch))
        ));
        assert!(matches!(
            archive
                .stage_certified_ledger_entry(
                    &alternate_certificate,
                    &fixture.verified_ledger,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::Ledger(LedgerError::VerificationCapabilityMismatch))
        ));

        let conflicting_fixture = make_fixture(0x30);
        assert!(matches!(
            archive
                .stage_certified_ledger_entry(
                    &fixture.ledger,
                    &conflicting_fixture.verified_ledger,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::Ledger(LedgerError::VerificationCapabilityMismatch))
        ));
        let mut corrupted_witness = fixture.ledger.clone();
        corrupted_witness.attestations[0].signature[0] ^= 1;
        assert!(matches!(
            archive
                .stage_certified_ledger_entry(
                    &corrupted_witness,
                    &fixture.verified_ledger,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::Ledger(LedgerError::VerificationCapabilityMismatch))
        ));

        drop(archive);
        let restarted =
            DepositArchiveStore::new(directory.path(), PartyId(1), &[0x31; 32]).unwrap();
        assert_eq!(
            restarted
                .authenticate_certified_entry_artifact(
                    staged.reference(),
                    &fixture.verified_ledger,
                )
                .await
                .unwrap(),
            staged
        );
        assert!(matches!(
            restarted
                .authenticate_certified_entry_artifact(
                    staged.reference(),
                    &conflicting_fixture.verified_ledger,
                )
                .await,
            Err(DepositArchiveError::Ledger(LedgerError::VerificationCapabilityMismatch))
        ));
        assert!(collect_checkpoints(&restarted, original_head).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn append_is_partial_commit_safe_and_committed_retry_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x32);
        let checkpoint = ledger_checkpoint(&fixture);
        let verified_checkpoint = verify_ledger_checkpoint(&fixture, &checkpoint);
        let original_head = DepositArchiveHead::empty(fixture.registry.wallet()).unwrap();
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x32; 32]).unwrap();
        let staged = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();

        // Model a crash after writing immutable objects but before the outer wallet snapshot CAS.
        let orphaned = archive
            .append_ledger_checkpoint(
                original_head,
                staged,
                &checkpoint,
                &verified_checkpoint,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert!(orphaned.appended);
        assert!(collect_checkpoints(&archive, original_head).await.unwrap().is_empty());

        drop(archive);
        let restarted =
            DepositArchiveStore::new(directory.path(), PartyId(1), &[0x32; 32]).unwrap();
        let restored = restarted
            .authenticate_certified_entry_artifact(staged.reference(), &fixture.verified_ledger)
            .await
            .unwrap();
        let retried = restarted
            .append_ledger_checkpoint(
                original_head,
                restored,
                &checkpoint,
                &verified_checkpoint,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(retried, orphaned);

        let committed_retry = restarted
            .append_ledger_checkpoint(
                retried.head,
                restored,
                &checkpoint,
                &verified_checkpoint,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert!(!committed_retry.appended);
        assert_eq!(committed_retry.head, retried.head);
        assert_eq!(committed_retry.entry_artifact, retried.entry_artifact);
        assert_eq!(committed_retry.checkpoint_artifact, retried.checkpoint_artifact);
        assert_eq!(committed_retry.event_artifact, retried.event_artifact);
        assert_eq!(committed_retry.verified_ledger_locator(), retried.verified_ledger_locator());
        let expected_locator = retried.verified_ledger_locator();
        drop(restarted);
        let committed_restart =
            DepositArchiveStore::new(directory.path(), PartyId(1), &[0x32; 32]).unwrap();
        assert_eq!(
            committed_restart
                .authenticate_head_ledger_locator(
                    retried.head,
                    &fixture.verified_ledger,
                    &verified_checkpoint,
                )
                .await
                .unwrap(),
            expected_locator
        );
    }

    #[tokio::test]
    async fn traversal_fails_closed_for_tampered_ledger_checkpoint_or_event() {
        #[derive(Clone, Copy)]
        enum Target {
            Ledger,
            Checkpoint,
            Event,
        }

        let fixture = make_fixture(0x33);
        let checkpoint = ledger_checkpoint(&fixture);
        let verified_checkpoint = verify_ledger_checkpoint(&fixture, &checkpoint);
        for (target, seed) in
            [(Target::Ledger, 0x41), (Target::Checkpoint, 0x42), (Target::Event, 0x43)]
        {
            let directory = tempfile::tempdir().unwrap();
            let archive =
                DepositArchiveStore::new(directory.path(), PartyId(1), &[seed; 32]).unwrap();
            let staged = archive
                .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
                .await
                .unwrap();
            let append = archive
                .append_ledger_checkpoint(
                    DepositArchiveHead::empty(fixture.registry.wallet()).unwrap(),
                    staged,
                    &checkpoint,
                    &verified_checkpoint,
                    &mut OsRng,
                )
                .await
                .unwrap();
            let reference = match target {
                Target::Ledger => append.entry_artifact,
                Target::Checkpoint => append.checkpoint_artifact,
                Target::Event => append.event_artifact,
            };
            corrupt_artifact(&archive, reference).await;
            assert!(collect_checkpoints(&archive, append.head).await.is_err());
        }
    }

    #[tokio::test]
    async fn checkpoint_order_conflict_and_independent_ledger_sequence_are_enforced() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x34);
        let history = certified_history(&fixture);
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x51; 32]).unwrap();
        let empty = DepositArchiveHead::empty(fixture.registry.wallet()).unwrap();

        let staged_observation = archive
            .stage_certified_deposit_observation(
                &history.observation,
                &history.verified_observation_certificate,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert!(matches!(
            archive
                .append_deposit_observation_checkpoint(
                    empty,
                    staged_observation,
                    &history.observation_checkpoint,
                    &history.verified_observation_checkpoint,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::ArchiveCheckpointSequenceMismatch { expected: 1, actual: 2 })
        ));

        let staged_ledger = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();
        let ledger_append = archive
            .append_ledger_checkpoint(
                empty,
                staged_ledger,
                &history.ledger_checkpoint,
                &history.verified_ledger,
                &mut OsRng,
            )
            .await
            .unwrap();

        let conflicting_fixture = make_fixture(0x35);
        let conflicting_checkpoint = ledger_checkpoint(&conflicting_fixture);
        let conflicting_verified =
            verify_ledger_checkpoint(&conflicting_fixture, &conflicting_checkpoint);
        let conflicting_staged = archive
            .stage_certified_ledger_entry(
                &conflicting_fixture.ledger,
                &conflicting_fixture.verified_ledger,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert!(matches!(
            archive
                .append_ledger_checkpoint(
                    ledger_append.head,
                    conflicting_staged,
                    &conflicting_checkpoint,
                    &conflicting_verified,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::ArchiveCheckpointConflict)
        ));

        let conflicting_history = certified_history(&conflicting_fixture);
        let conflicting_observation = archive
            .stage_certified_deposit_observation(
                &conflicting_history.observation,
                &conflicting_history.verified_observation_certificate,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert!(matches!(
            archive
                .append_deposit_observation_checkpoint(
                    ledger_append.head,
                    conflicting_observation,
                    &conflicting_history.observation_checkpoint,
                    &conflicting_history.verified_observation_checkpoint,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::ArchiveCheckpointParentMismatch)
        ));

        let observation_append = archive
            .append_deposit_observation_checkpoint(
                ledger_append.head,
                staged_observation,
                &history.observation_checkpoint,
                &history.verified_observation_checkpoint,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(observation_append.head.len(), 2);
        assert_eq!(history.verified_observation_checkpoint.sequence(), 2);
        assert_eq!(history.verified_observation_checkpoint.ledger_sequence(), 1);
        assert_eq!(fixture.ledger.statement.sequence, 1);
    }

    #[tokio::test]
    async fn fresh_traversal_exposes_exact_ledger_and_observation_pairs() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x36);
        let history = certified_history(&fixture);
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x52; 32]).unwrap();
        let staged_ledger = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();
        let ledger_append = archive
            .append_ledger_checkpoint(
                DepositArchiveHead::empty(fixture.registry.wallet()).unwrap(),
                staged_ledger,
                &history.ledger_checkpoint,
                &history.verified_ledger,
                &mut OsRng,
            )
            .await
            .unwrap();
        let staged_observation = archive
            .stage_certified_deposit_observation(
                &history.observation,
                &history.verified_observation_certificate,
                &mut OsRng,
            )
            .await
            .unwrap();
        let observation_append = archive
            .append_deposit_observation_checkpoint(
                ledger_append.head,
                staged_observation,
                &history.observation_checkpoint,
                &history.verified_observation_checkpoint,
                &mut OsRng,
            )
            .await
            .unwrap();
        drop(archive);

        let restarted =
            DepositArchiveStore::new(directory.path(), PartyId(1), &[0x52; 32]).unwrap();
        let checkpoints = collect_checkpoints(&restarted, observation_append.head).await.unwrap();
        assert_eq!(checkpoints.len(), 2);
        match &checkpoints[0] {
            ArchivedDepositCheckpoint::Ledger(archived) => {
                assert_eq!(archived.ordinal, 0);
                assert_eq!(archived.checkpoint_sequence, 1);
                assert_eq!(archived.entry, fixture.ledger);
                assert_eq!(archived.checkpoint, history.ledger_checkpoint);
                assert_eq!(archived.entry_artifact, ledger_append.entry_artifact);
                assert_eq!(archived.checkpoint_artifact, ledger_append.checkpoint_artifact);
                assert_eq!(archived.event_artifact, ledger_append.event_artifact);
            }
            ArchivedDepositCheckpoint::DepositObservation(_) => {
                panic!("checkpoint one must be the exact ledger pair")
            }
        }
        match &checkpoints[1] {
            ArchivedDepositCheckpoint::DepositObservation(archived) => {
                assert_eq!(archived.ordinal, 1);
                assert_eq!(archived.checkpoint_sequence, 2);
                assert_eq!(archived.observation, history.observation);
                assert_eq!(archived.checkpoint, history.observation_checkpoint);
                assert_eq!(archived.observation_artifact, observation_append.observation_artifact);
                assert_eq!(archived.checkpoint_artifact, observation_append.checkpoint_artifact);
                assert_eq!(archived.event_artifact, observation_append.event_artifact);
                assert_eq!(
                    archived
                        .verified_observation_artifact(&history.verified_observation_certificate)
                        .unwrap(),
                    staged_observation
                );
                assert_eq!(observation_append.verified_observation_artifact(), staged_observation);
                archived.verify_exact_checkpoint(&history.verified_observation_checkpoint).unwrap();
            }
            ArchivedDepositCheckpoint::Ledger(_) => {
                panic!("checkpoint two must be the exact observation pair")
            }
        }
    }

    #[tokio::test]
    async fn locator_capability_is_bound_to_exact_checkpoint_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x37);
        let checkpoint = ledger_checkpoint(&fixture);
        let verified_checkpoint = verify_ledger_checkpoint(&fixture, &checkpoint);
        let corrupted_checkpoint = checkpoint_with_corrupted_witness(&checkpoint);
        let alternate_checkpoint =
            ledger_checkpoint_with_signers(&fixture, &[PartyId(2), PartyId(3), PartyId(4)]);
        let alternate_verified = verify_ledger_checkpoint(&fixture, &alternate_checkpoint);
        assert_eq!(alternate_verified.decision_digest(), verified_checkpoint.decision_digest());
        assert_ne!(
            alternate_verified.certificate_digest(),
            verified_checkpoint.certificate_digest()
        );

        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x53; 32]).unwrap();
        let staged = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();
        let corrupted_checkpoint_artifact = WalletArtifactRef::for_contents(
            WalletId(fixture.registry.wallet().0),
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            &corrupted_checkpoint.to_bytes().unwrap(),
        )
        .unwrap();
        let corrupted_event = DepositArchiveEvent {
            version: ARCHIVE_EVENT_VERSION,
            wallet: fixture.registry.wallet(),
            ordinal: 0,
            previous: None,
            payload: DepositArchivePayload::LedgerCheckpoint {
                ledger: staged.reference(),
                checkpoint: corrupted_checkpoint_artifact,
            },
        };
        let corrupted_event_artifact = WalletArtifactRef::for_contents(
            WalletId(fixture.registry.wallet().0),
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            &corrupted_event.to_bytes().unwrap(),
        )
        .unwrap();
        let empty = DepositArchiveHead::empty(fixture.registry.wallet()).unwrap();
        assert!(matches!(
            archive
                .append_ledger_checkpoint(
                    empty,
                    staged,
                    &corrupted_checkpoint,
                    &verified_checkpoint,
                    &mut OsRng,
                )
                .await,
            Err(DepositArchiveError::CheckpointCapabilityMismatch)
        ));
        assert!(
            !tokio::fs::try_exists(archive.artifact_path(corrupted_checkpoint_artifact))
                .await
                .unwrap()
        );
        assert!(
            !tokio::fs::try_exists(archive.artifact_path(corrupted_event_artifact)).await.unwrap()
        );
        assert!(collect_checkpoints(&archive, empty).await.unwrap().is_empty());
        let append = archive
            .append_ledger_checkpoint(empty, staged, &checkpoint, &verified_checkpoint, &mut OsRng)
            .await
            .unwrap();
        let locator = append.verified_ledger_locator();
        assert_eq!(locator.wallet_id(), fixture.registry.wallet());
        assert_eq!(locator.checkpoint_sequence(), verified_checkpoint.sequence());
        assert_eq!(locator.checkpoint_decision(), verified_checkpoint.decision_digest());
        assert_eq!(
            locator.checkpoint_certificate_digest(),
            verified_checkpoint.certificate_digest()
        );
        assert_eq!(locator.ledger_sequence(), fixture.ledger.statement.sequence);
        assert_eq!(locator.ledger_statement(), fixture.ledger.statement.digest());
        assert_eq!(locator.event_artifact(), append.event_artifact);
        assert_eq!(locator.ledger_artifact(), append.entry_artifact);
        assert_eq!(locator.checkpoint_artifact(), append.checkpoint_artifact);

        let mut archived = collect_checkpoints(&archive, append.head).await.unwrap();
        let ArchivedDepositCheckpoint::Ledger(archived) = archived.remove(0) else {
            panic!("ledger append must traverse as a ledger checkpoint");
        };
        assert_eq!(
            archived
                .verified_ledger_locator(&fixture.verified_ledger, &verified_checkpoint)
                .unwrap(),
            locator
        );
        assert!(matches!(
            archived.verified_ledger_locator(&fixture.verified_ledger, &alternate_verified),
            Err(DepositArchiveError::CheckpointCapabilityMismatch)
        ));
    }
}
