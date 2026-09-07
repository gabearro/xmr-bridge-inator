//! Immutable authenticated archive for exact portable deposit-index checkpoints.
//!
//! A ledger or observation certificate is materialized before checkpoint voting, but that
//! artifact alone is never an authoritative archive append. Only after an independent n-f index
//! checkpoint exists does the finalizer install its exact certificate and a linked event naming
//! both artifacts. The caller installs the returned head with the portable index, reducer,
//! scanner, compact registry, and outbox in one outer wallet-snapshot CAS.

use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::Arc,
};

use rand_core::{CryptoRng, RngCore};
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::{
    committee::PartyId,
    deposit_index_checkpoint::{
        DepositIndexCheckpointCertificate, DepositIndexCheckpointError,
        DepositIndexCheckpointOperation, DepositIndexCheckpointParent, PortableDepositIndexHead,
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
const CERTIFIED_LEDGER_ROUTE_VERSION: u16 = 1;
const CERTIFIED_LEDGER_ROUTE_DIRECTORY: &str = "deposit-certified-ledger-routes-v1";
const CERTIFIED_LEDGER_ROUTE_DATABASE_FILE: &str = "routes.redb";
const CERTIFIED_LEDGER_ROUTE_DATABASE_CACHE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CERTIFIED_LEDGER_ROUTE_BYTES: usize = 2 * 1024;

const CERTIFIED_LEDGER_ROUTE_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("certified-ledger-routes-v1");

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
/// One support-prefix step authenticates only a small, deterministic slice of history.
///
/// Checkpoint certificates may each be as large as 4 MiB, so the event bound is deliberately
/// lower than the archive segment bound. A caller persists the returned cursor and cooperatively
/// continues without ever restarting from a moving archive tip.
pub const MAX_DEPOSIT_ARCHIVE_PREFIX_EVENTS_PER_STEP: usize = 4;
/// A support-prefix step can cross several short segments, but never an attacker-selected count.
pub const MAX_DEPOSIT_ARCHIVE_PREFIX_SEGMENTS_PER_STEP: usize = 4;
/// Maximum plaintext authenticated by one support-prefix step.
pub const MAX_DEPOSIT_ARCHIVE_PREFIX_BYTES_PER_STEP: usize =
    MAX_DEPOSIT_ARCHIVE_PREFIX_EVENTS_PER_STEP
        * (MAX_DEPOSIT_ARCHIVE_EVENT_BYTES
            + MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES)
        + MAX_DEPOSIT_ARCHIVE_PREFIX_SEGMENTS_PER_STEP * MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES;
/// Fixed upper bound for a restart-persisted support-prefix cursor.
pub const MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES: usize = 4 * 1024;

const ARCHIVE_PREFIX_CURSOR_VERSION: u16 = 1;

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

    #[cfg(test)]
    pub(crate) fn from_test_parts(
        wallet: DepositWalletId,
        length: u64,
        event: Option<WalletArtifactRef>,
        segment: Option<WalletArtifactRef>,
    ) -> Result<Self, DepositArchiveError> {
        let head = Self { version: ARCHIVE_HEAD_VERSION, wallet, length, event, segment };
        head.validate()?;
        Ok(head)
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

/// Witness-independent terminal checkpoint which a source can recognize in one anchored archive.
///
/// `terminal_event` binds the requester's exact advertised variant. Honest replicas may retain a
/// different witness-set-specific event artifact for the same checkpoint decision, so prefix
/// recognition compares the complete semantic checkpoint tuple rather than requiring identical
/// event bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArchivePrefixTarget {
    wallet: DepositWalletId,
    checkpoint_sequence: u64,
    terminal_event: WalletArtifactRef,
    checkpoint_decision: [u8; 32],
    resulting_head: PortableDepositIndexHead,
}

impl DepositArchivePrefixTarget {
    pub fn new(
        wallet: DepositWalletId,
        checkpoint_sequence: u64,
        terminal_event: WalletArtifactRef,
        checkpoint_decision: [u8; 32],
        resulting_head: PortableDepositIndexHead,
    ) -> Result<Self, DepositArchiveError> {
        let target = Self {
            wallet,
            checkpoint_sequence,
            terminal_event,
            checkpoint_decision,
            resulting_head,
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), DepositArchiveError> {
        validate_reference(
            self.terminal_event,
            self.wallet,
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
        if self.wallet.0 == [0_u8; 32]
            || self.checkpoint_sequence == 0
            || self.checkpoint_decision == [0_u8; 32]
            || self.resulting_head.wallet_id() != self.wallet
            || self.resulting_head.through_sequence() == 0
            || self.resulting_head.ledger_head() == [0_u8; 32]
        {
            return Err(DepositArchiveError::InvalidPrefixTarget);
        }
        self.resulting_head
            .maximum_reachable_objects()
            .map_err(|_| DepositArchiveError::InvalidPrefixTarget)?;
        Ok(())
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositArchivePrefixParent {
    decision: [u8; 32],
    resulting_head: PortableDepositIndexHead,
}

/// Restart-stable cursor for one fixed archive-head prefix lookup.
///
/// The full anchor and target are repeated in the cursor. A caller cannot resume against a newer
/// head or substitute another checkpoint after a crash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositArchivePrefixCursor {
    version: u16,
    anchor: DepositArchiveHead,
    target: DepositArchivePrefixTarget,
    segment: WalletArtifactRef,
    segment_end: u64,
    next_ordinal: u64,
    next_event: WalletArtifactRef,
    expected_parent: Option<DepositArchivePrefixParent>,
}

impl DepositArchivePrefixCursor {
    pub fn start(
        anchor: DepositArchiveHead,
        target: DepositArchivePrefixTarget,
    ) -> Result<Self, DepositArchiveError> {
        anchor.validate()?;
        target.validate()?;
        if anchor.wallet_id() != target.wallet()
            || target.checkpoint_sequence() > anchor.len()
            || anchor.is_empty()
        {
            return Err(DepositArchiveError::InvalidPrefixCursor);
        }
        let cursor = Self {
            version: ARCHIVE_PREFIX_CURSOR_VERSION,
            anchor,
            target,
            segment: anchor.segment_reference().ok_or(DepositArchiveError::InvalidPrefixCursor)?,
            segment_end: anchor.len(),
            next_ordinal: anchor
                .len()
                .checked_sub(1)
                .ok_or(DepositArchiveError::InvalidPrefixCursor)?,
            next_event: anchor.event_reference().ok_or(DepositArchiveError::InvalidPrefixCursor)?,
            expected_parent: None,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    fn validate(&self) -> Result<(), DepositArchiveError> {
        self.anchor.validate()?;
        self.target.validate()?;
        validate_reference(
            self.segment,
            self.anchor.wallet_id(),
            DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
        )?;
        validate_reference(
            self.next_event,
            self.anchor.wallet_id(),
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
        let target_ordinal = self
            .target
            .checkpoint_sequence()
            .checked_sub(1)
            .ok_or(DepositArchiveError::InvalidPrefixCursor)?;
        let initial_ordinal =
            self.anchor.len().checked_sub(1).ok_or(DepositArchiveError::InvalidPrefixCursor)?;
        let initial = self.next_ordinal == initial_ordinal;
        if let Some(parent) = self.expected_parent.as_ref() {
            parent
                .resulting_head
                .maximum_reachable_objects()
                .map_err(|_| DepositArchiveError::InvalidPrefixCursor)?;
        }
        if self.version != ARCHIVE_PREFIX_CURSOR_VERSION
            || self.anchor.wallet_id() != self.target.wallet()
            || self.target.checkpoint_sequence() > self.anchor.len()
            || self.next_ordinal < target_ordinal
            || self.next_ordinal > initial_ordinal
            || self.segment_end == 0
            || self.segment_end > self.anchor.len()
            || self.next_ordinal >= self.segment_end
            || initial != self.expected_parent.is_none()
            || (initial
                && (self.segment
                    != self.anchor.segment_reference().expect("validated nonempty head")
                    || self.segment_end != self.anchor.len()
                    || self.next_event
                        != self.anchor.event_reference().expect("validated nonempty head")))
            || self.expected_parent.as_ref().is_some_and(|parent| {
                parent.decision == [0_u8; 32]
                    || parent.resulting_head.wallet_id() != self.anchor.wallet_id()
            })
        {
            return Err(DepositArchiveError::InvalidPrefixCursor);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositArchiveError> {
        self.validate()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES,
            "deposit archive prefix cursor",
        )
    }

    /// Decode canonical cursor contents recovered from an authenticated local stage record.
    ///
    /// A cursor is resumable progress, not a self-authenticating wire proof: accepting
    /// caller-controlled bytes would let the caller forge `expected_parent` and skip the chain
    /// between `anchor` and `next_event`. Production callers must place these bytes inside the
    /// same encrypted/MACed durable state which binds the support request and fixed anchor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositArchiveError> {
        let cursor: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES,
            "deposit archive prefix cursor",
        )?;
        cursor.validate()?;
        Ok(cursor)
    }

    #[must_use]
    pub const fn anchor(&self) -> DepositArchiveHead {
        self.anchor
    }

    #[must_use]
    pub const fn target(&self) -> &DepositArchivePrefixTarget {
        &self.target
    }
}

/// Non-serializable proof that an exact semantic checkpoint belongs to one fixed archive anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositArchivePrefix {
    anchor: DepositArchiveHead,
    target: DepositArchivePrefixTarget,
    local_terminal_event: WalletArtifactRef,
}

impl VerifiedDepositArchivePrefix {
    #[must_use]
    pub const fn anchor(&self) -> DepositArchiveHead {
        self.anchor
    }

    #[must_use]
    pub const fn target(&self) -> &DepositArchivePrefixTarget {
        &self.target
    }

    #[must_use]
    pub const fn local_terminal_event(&self) -> WalletArtifactRef {
        self.local_terminal_event
    }
}

/// Result of one bounded anchored-prefix step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepositArchivePrefixStep {
    Pending(DepositArchivePrefixCursor),
    Included(VerifiedDepositArchivePrefix),
    NotIncluded,
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

/// Persisted, non-authoritative routing hint for one exact certified ledger statement.
///
/// The route cache is derived from already verified live appends or the selected permanent
/// import's complete archive audit. Its bytes are never accepted as archive membership or
/// certificate authority: every lookup re-reads the named event, ledger certificate, and
/// checkpoint certificate and the service independently verifies the exact portable statement and
/// both certificates under the authenticated issuer window before using the result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CertifiedLedgerRoute {
    version: u16,
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

impl CertifiedLedgerRoute {
    fn from_verified(
        locator: VerifiedDepositArchiveLedgerLocator,
    ) -> Result<Self, DepositArchiveError> {
        let route = Self {
            version: CERTIFIED_LEDGER_ROUTE_VERSION,
            wallet: locator.wallet,
            checkpoint_sequence: locator.checkpoint_sequence,
            checkpoint_decision: locator.checkpoint_decision,
            checkpoint_certificate_digest: locator.checkpoint_certificate_digest,
            ledger_sequence: locator.ledger_sequence,
            ledger_statement: locator.ledger_statement,
            event_artifact: locator.event_artifact,
            ledger_artifact: locator.ledger_artifact,
            checkpoint_artifact: locator.checkpoint_artifact,
        };
        route.validate()?;
        Ok(route)
    }

    fn from_authenticated_parts(
        event_artifact: WalletArtifactRef,
        ledger_artifact: WalletArtifactRef,
        checkpoint_artifact: WalletArtifactRef,
        entry: &CertifiedLedgerEntry,
        checkpoint: &DepositIndexCheckpointCertificate,
    ) -> Result<Self, DepositArchiveError> {
        let statement = checkpoint.statement();
        let route = Self {
            version: CERTIFIED_LEDGER_ROUTE_VERSION,
            wallet: entry.statement.wallet,
            checkpoint_sequence: statement.sequence(),
            checkpoint_decision: statement.decision_digest(),
            checkpoint_certificate_digest: checkpoint.certificate_digest()?,
            ledger_sequence: entry.statement.sequence,
            ledger_statement: entry.statement.digest(),
            event_artifact,
            ledger_artifact,
            checkpoint_artifact,
        };
        route.validate()?;
        Ok(route)
    }

    fn validate(self) -> Result<(), DepositArchiveError> {
        if self.version != CERTIFIED_LEDGER_ROUTE_VERSION
            || self.wallet.0 == [0; 32]
            || self.checkpoint_sequence == 0
            || self.checkpoint_decision == [0; 32]
            || self.checkpoint_certificate_digest == [0; 32]
            || self.ledger_sequence == 0
            || self.ledger_statement == [0; 32]
            || self.checkpoint_sequence < self.ledger_sequence
        {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        validate_reference(
            self.event_artifact,
            self.wallet,
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )
        .map_err(|_| DepositArchiveError::CertifiedLedgerRouteMismatch)?;
        validate_reference(
            self.ledger_artifact,
            self.wallet,
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        )
        .map_err(|_| DepositArchiveError::CertifiedLedgerRouteMismatch)?;
        validate_reference(
            self.checkpoint_artifact,
            self.wallet,
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
        )
        .map_err(|_| DepositArchiveError::CertifiedLedgerRouteMismatch)?;
        Ok(())
    }

    fn key(self) -> [u8; 64] {
        let mut key = [0_u8; 64];
        key[..32].copy_from_slice(&self.wallet.0);
        key[32..].copy_from_slice(&self.ledger_statement);
        key
    }
}

/// Three directly routed artifacts which still require service-level statement and issuer
/// verification. This deliberately does not carry the archive-authenticated marker used by
/// [`ArchivedCertifiedLedgerEntry`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RoutedCertifiedLedgerEntry {
    pub ordinal: u64,
    pub checkpoint_sequence: u64,
    pub event_artifact: WalletArtifactRef,
    pub entry_artifact: WalletArtifactRef,
    pub checkpoint_artifact: WalletArtifactRef,
    pub entry: CertifiedLedgerEntry,
    pub checkpoint: DepositIndexCheckpointCertificate,
}

/// Completeness witness returned by a full permanent-archive audit and route rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CertifiedLedgerRouteRebuildSummary {
    unique_ledger_routes: u64,
    maximum_ledger_sequence: u64,
    terminal_ledger_statement: [u8; 32],
}

impl CertifiedLedgerRouteRebuildSummary {
    #[must_use]
    pub const fn unique_ledger_routes(self) -> u64 {
        self.unique_ledger_routes
    }

    #[must_use]
    pub const fn maximum_ledger_sequence(self) -> u64 {
        self.maximum_ledger_sequence
    }

    #[must_use]
    pub const fn terminal_ledger_statement(self) -> [u8; 32] {
        self.terminal_ledger_statement
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CertifiedLedgerRouteRebuildAccumulator {
    unique_ledger_routes: u64,
    maximum_ledger_sequence: u64,
    next_older_ledger_sequence: Option<u64>,
    terminal_ledger_statement: [u8; 32],
}

impl CertifiedLedgerRouteRebuildAccumulator {
    fn record(&mut self, route: CertifiedLedgerRoute) -> Result<(), DepositArchiveError> {
        route.validate()?;
        match self.next_older_ledger_sequence {
            None => {
                self.maximum_ledger_sequence = route.ledger_sequence;
                self.terminal_ledger_statement = route.ledger_statement;
            }
            Some(expected) if route.ledger_sequence == expected => {}
            Some(_) => return Err(DepositArchiveError::CertifiedLedgerRouteMismatch),
        }
        self.unique_ledger_routes = self
            .unique_ledger_routes
            .checked_add(1)
            .ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
        self.next_older_ledger_sequence = route.ledger_sequence.checked_sub(1);
        Ok(())
    }

    fn finish(self) -> Result<CertifiedLedgerRouteRebuildSummary, DepositArchiveError> {
        if (self.unique_ledger_routes == 0)
            != (self.maximum_ledger_sequence == 0
                && self.terminal_ledger_statement == [0; 32]
                && self.next_older_ledger_sequence.is_none())
            || (self.unique_ledger_routes != 0
                && (self.unique_ledger_routes != self.maximum_ledger_sequence
                    || self.next_older_ledger_sequence != Some(0)))
        {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        Ok(CertifiedLedgerRouteRebuildSummary {
            unique_ledger_routes: self.unique_ledger_routes,
            maximum_ledger_sequence: self.maximum_ledger_sequence,
            terminal_ledger_statement: self.terminal_ledger_statement,
        })
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
    certified_ledger_routes: Arc<Database>,
    #[cfg(test)]
    artifact_loads: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    segment_loads: std::sync::atomic::AtomicU64,
}

impl DepositArchiveStore {
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositArchiveError> {
        let artifacts = WalletArtifactStore::new(directory, party, identity_seed)?;
        let certified_ledger_routes =
            open_certified_ledger_route_database(artifacts.artifact_root())?;
        Ok(Self {
            artifacts,
            certified_ledger_routes: Arc::new(certified_ledger_routes),
            #[cfg(test)]
            artifact_loads: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            segment_loads: std::sync::atomic::AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn artifact_path(&self, reference: WalletArtifactRef) -> PathBuf {
        self.artifacts.artifact_path(reference)
    }

    #[cfg(test)]
    fn reset_test_load_counts(&self) {
        self.artifact_loads.store(0, std::sync::atomic::Ordering::Relaxed);
        self.segment_loads.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    fn test_load_counts(&self) -> (u64, u64) {
        (
            self.artifact_loads.load(std::sync::atomic::Ordering::Relaxed),
            self.segment_loads.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Atomically upsert one bounded batch of already verified live routes.
    ///
    /// The Redb commit uses immediate durability and is read back exactly before this returns.
    /// Route bytes remain non-authoritative even though live append supplied verification
    /// capabilities; every request repeats content and certificate verification.
    async fn persist_certified_ledger_routes(
        &self,
        locators: &[VerifiedDepositArchiveLedgerLocator],
    ) -> Result<(), DepositArchiveError> {
        if locators.is_empty() {
            return Ok(());
        }
        if locators.len() > MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        let routes = locators
            .iter()
            .copied()
            .map(CertifiedLedgerRoute::from_verified)
            .collect::<Result<Vec<_>, _>>()?;
        let database = Arc::clone(&self.certified_ledger_routes);
        tokio::task::spawn_blocking(move || {
            persist_certified_ledger_routes_blocking(&database, &routes)
        })
        .await
        .map_err(|error| DepositArchiveError::CertifiedLedgerRouteStore(error.to_string()))?
    }

    async fn persist_authenticated_route_batch(
        &self,
        routes: &[CertifiedLedgerRoute],
    ) -> Result<(), DepositArchiveError> {
        if routes.is_empty() {
            return Ok(());
        }
        if routes.len() > MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        for route in routes {
            route.validate()?;
        }
        let routes = routes.to_vec();
        let database = Arc::clone(&self.certified_ledger_routes);
        tokio::task::spawn_blocking(move || {
            persist_certified_ledger_routes_blocking(&database, &routes)
        })
        .await
        .map_err(|error| DepositArchiveError::CertifiedLedgerRouteStore(error.to_string()))?
    }

    async fn certified_ledger_route(
        &self,
        wallet: DepositWalletId,
        statement: [u8; 32],
    ) -> Result<CertifiedLedgerRoute, DepositArchiveError> {
        if wallet.0 == [0; 32] || statement == [0; 32] {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        let key = certified_ledger_route_key(wallet, statement);
        let database = Arc::clone(&self.certified_ledger_routes);
        tokio::task::spawn_blocking(move || load_certified_ledger_route_blocking(&database, key))
            .await
            .map_err(|error| DepositArchiveError::CertifiedLedgerRouteStore(error.to_string()))?
    }

    /// Authenticate one bounded slice of a semantic-prefix lookup beneath an immutable anchor.
    ///
    /// The caller must obtain `cursor.anchor` from an already authenticated local snapshot and
    /// persist the returned cursor between calls. This method follows only content-addressed
    /// predecessor links carried by that anchor; an independently advancing live head can neither
    /// restart nor redirect the lookup.
    pub async fn verify_anchored_prefix_step(
        &self,
        mut cursor: DepositArchivePrefixCursor,
    ) -> Result<DepositArchivePrefixStep, DepositArchiveError> {
        cursor.validate()?;
        let wallet = cursor.anchor.wallet_id();
        let target_ordinal = cursor
            .target
            .checkpoint_sequence()
            .checked_sub(1)
            .ok_or(DepositArchiveError::InvalidPrefixCursor)?;
        let mut events = 0_usize;
        let mut segments = 0_usize;
        let mut authenticated_bytes = 0_usize;

        while events < MAX_DEPOSIT_ARCHIVE_PREFIX_EVENTS_PER_STEP
            && segments < MAX_DEPOSIT_ARCHIVE_PREFIX_SEGMENTS_PER_STEP
        {
            let segment_reference = cursor.segment;
            let segment = self.load_segment(segment_reference, wallet).await?;
            segments = segments.checked_add(1).ok_or(DepositArchiveError::InvalidPrefixCursor)?;
            authenticated_bytes = authenticated_bytes
                .checked_add(
                    usize::try_from(segment_reference.plaintext_len())
                        .map_err(|_| DepositArchiveError::InvalidPrefixCursor)?,
                )
                .ok_or(DepositArchiveError::InvalidPrefixCursor)?;
            if authenticated_bytes > MAX_DEPOSIT_ARCHIVE_PREFIX_BYTES_PER_STEP {
                return Err(DepositArchiveError::InvalidPrefixCursor);
            }
            let segment_end = segment.end_ordinal()?;
            if segment_end != cursor.segment_end
                || cursor.next_ordinal < segment.start_ordinal
                || cursor.next_ordinal >= segment_end
            {
                return Err(DepositArchiveError::BrokenArchiveChain);
            }

            while events < MAX_DEPOSIT_ARCHIVE_PREFIX_EVENTS_PER_STEP
                && cursor.next_ordinal >= segment.start_ordinal
            {
                let offset = usize::try_from(
                    cursor
                        .next_ordinal
                        .checked_sub(segment.start_ordinal)
                        .ok_or(DepositArchiveError::BrokenArchiveChain)?,
                )
                .map_err(|_| DepositArchiveError::BrokenArchiveChain)?;
                let local_event_reference = segment
                    .events
                    .get(offset)
                    .copied()
                    .ok_or(DepositArchiveError::BrokenArchiveChain)?;
                if local_event_reference != cursor.next_event {
                    return Err(DepositArchiveError::BrokenArchiveChain);
                }

                let event =
                    self.load_event(local_event_reference, wallet, cursor.next_ordinal).await?;
                let checkpoint_reference = event.payload.checkpoint_reference();
                let checkpoint = self.load_checkpoint(checkpoint_reference, wallet).await?;
                authenticated_bytes = authenticated_bytes
                    .checked_add(
                        usize::try_from(local_event_reference.plaintext_len())
                            .map_err(|_| DepositArchiveError::InvalidPrefixCursor)?,
                    )
                    .and_then(|bytes| {
                        usize::try_from(checkpoint_reference.plaintext_len())
                            .ok()
                            .and_then(|checkpoint_bytes| bytes.checked_add(checkpoint_bytes))
                    })
                    .ok_or(DepositArchiveError::InvalidPrefixCursor)?;
                if authenticated_bytes > MAX_DEPOSIT_ARCHIVE_PREFIX_BYTES_PER_STEP {
                    return Err(DepositArchiveError::InvalidPrefixCursor);
                }
                events = events.checked_add(1).ok_or(DepositArchiveError::InvalidPrefixCursor)?;

                let statement = checkpoint.statement();
                let expected_sequence = cursor
                    .next_ordinal
                    .checked_add(1)
                    .ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
                if statement.sequence() != expected_sequence {
                    return Err(DepositArchiveError::ArchiveCheckpointSequenceMismatch {
                        expected: expected_sequence,
                        actual: statement.sequence(),
                    });
                }
                if let Some(parent) = cursor.expected_parent.as_ref() {
                    if statement.decision_digest() != parent.decision
                        || statement.resulting_head() != &parent.resulting_head
                    {
                        return Err(DepositArchiveError::ArchiveCheckpointParentMismatch);
                    }
                }

                if cursor.next_ordinal == target_ordinal {
                    if target_ordinal == 0
                        && !matches!(statement.parent(), DepositIndexCheckpointParent::Genesis)
                    {
                        return Err(DepositArchiveError::ArchiveCheckpointParentMismatch);
                    }
                    if statement.decision_digest() != cursor.target.checkpoint_decision()
                        || statement.resulting_head() != cursor.target.resulting_head()
                    {
                        return Ok(DepositArchivePrefixStep::NotIncluded);
                    }
                    return Ok(DepositArchivePrefixStep::Included(VerifiedDepositArchivePrefix {
                        anchor: cursor.anchor,
                        target: cursor.target,
                        local_terminal_event: local_event_reference,
                    }));
                }

                let DepositIndexCheckpointParent::Certified { decision } = statement.parent()
                else {
                    return Err(DepositArchiveError::ArchiveCheckpointParentMismatch);
                };
                let next_event = event.previous.ok_or(DepositArchiveError::BrokenArchiveChain)?;
                let next_ordinal = cursor
                    .next_ordinal
                    .checked_sub(1)
                    .ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
                cursor.expected_parent = Some(DepositArchivePrefixParent {
                    decision,
                    resulting_head: statement.previous_head().clone(),
                });
                cursor.next_ordinal = next_ordinal;
                cursor.next_event = next_event;

                if next_ordinal < segment.start_ordinal {
                    let previous_segment =
                        segment.previous.ok_or(DepositArchiveError::BrokenArchiveChain)?;
                    cursor.segment = previous_segment;
                    cursor.segment_end = segment.start_ordinal;
                    break;
                }
            }
        }

        if authenticated_bytes > MAX_DEPOSIT_ARCHIVE_PREFIX_BYTES_PER_STEP {
            return Err(DepositArchiveError::InvalidPrefixCursor);
        }
        cursor.validate()?;
        Ok(DepositArchivePrefixStep::Pending(cursor))
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
        self.persist_certified_ledger_routes(&[verified_locator]).await?;
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
        #[cfg(test)]
        self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        #[cfg(test)]
        self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// Re-open one exact ledger/checkpoint event through the non-authoritative derived route cache.
    ///
    /// This performs exactly three artifact reads and validates every route field and cross-link.
    /// The returned value deliberately carries no archive-membership authority. The caller must
    /// exact-match a statement from the authenticated portable index, verify both certificates
    /// under its authenticated issuer window, and fence the runtime snapshot after those reads.
    pub(crate) async fn load_routed_certified_entry(
        &self,
        head: DepositArchiveHead,
        wallet: DepositWalletId,
        ledger_statement: [u8; 32],
    ) -> Result<RoutedCertifiedLedgerEntry, DepositArchiveError> {
        head.validate()?;
        if wallet != head.wallet_id() {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        let route = self.certified_ledger_route(wallet, ledger_statement).await?;
        route.validate()?;
        let checkpoint_sequence = route.checkpoint_sequence;
        if route.wallet != wallet
            || route.ledger_statement != ledger_statement
            || checkpoint_sequence > head.len()
        {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        let ordinal = checkpoint_sequence
            .checked_sub(1)
            .ok_or(DepositArchiveError::CertifiedLedgerRouteMismatch)?;
        let event_artifact = route.event_artifact;
        let event = self.load_event(event_artifact, wallet, ordinal).await?;
        let (entry_artifact, checkpoint_artifact) = match event.payload {
            DepositArchivePayload::LedgerCheckpoint { ledger, checkpoint }
                if ledger == route.ledger_artifact && checkpoint == route.checkpoint_artifact =>
            {
                (ledger, checkpoint)
            }
            DepositArchivePayload::LedgerCheckpoint { .. }
            | DepositArchivePayload::DepositObservationCheckpoint { .. } => {
                return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
            }
        };

        let entry = self.load_certified_entry(entry_artifact, wallet).await?;
        let checkpoint = self.load_checkpoint(checkpoint_artifact, wallet).await?;
        let statement = checkpoint.statement();
        let loaded_ledger_statement = entry.statement.digest();
        if entry.statement.sequence != route.ledger_sequence
            || loaded_ledger_statement != route.ledger_statement
            || statement.sequence() != checkpoint_sequence
            || statement.decision_digest() != route.checkpoint_decision
            || checkpoint.certificate_digest()? != route.checkpoint_certificate_digest
            || statement.operation()
                != (DepositIndexCheckpointOperation::Ledger { statement: loaded_ledger_statement })
            || statement.ledger_sequence() != entry.statement.sequence
            || statement.ledger_decision() != loaded_ledger_statement
            || entry.statement.previous != statement.previous_head().ledger_head()
        {
            return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
        }
        Ok(RoutedCertifiedLedgerEntry {
            ordinal,
            checkpoint_sequence,
            event_artifact,
            entry_artifact,
            checkpoint_artifact,
            entry,
            checkpoint,
        })
    }

    /// Authenticate every object reachable from one compact head in newest-to-oldest order.
    ///
    /// Segments point toward older history, so reverse order is the only constant-memory linear
    /// traversal. The visitor must not infer authority from ordering alone; every yielded item has
    /// already crossed the exact event and checkpoint links to its newer neighbor.
    pub async fn visit_checkpoints<F>(
        &self,
        head: DepositArchiveHead,
        visitor: F,
    ) -> Result<(), DepositArchiveError>
    where
        F: FnMut(ArchivedDepositCheckpoint) -> Result<(), DepositArchiveError>,
    {
        self.visit_checkpoints_inner(head, false, visitor).await?;
        Ok(())
    }

    /// Fully authenticate the selected permanent archive and rebuild every ledger route.
    ///
    /// Imports call this only after their marker-bearing snapshot is authoritative and all owned
    /// artifacts have been materialized and released. Each segment's bounded route batch is
    /// committed with immediate durability and exact readback before traversal continues.
    pub(crate) async fn rebuild_certified_ledger_routes(
        &self,
        head: DepositArchiveHead,
    ) -> Result<CertifiedLedgerRouteRebuildSummary, DepositArchiveError> {
        self.visit_checkpoints_inner(head, true, |_| Ok(())).await
    }

    async fn visit_checkpoints_inner<F>(
        &self,
        head: DepositArchiveHead,
        rebuild_routes: bool,
        mut visitor: F,
    ) -> Result<CertifiedLedgerRouteRebuildSummary, DepositArchiveError>
    where
        F: FnMut(ArchivedDepositCheckpoint) -> Result<(), DepositArchiveError>,
    {
        head.validate()?;
        let mut segment_reference = head.segment;
        let mut expected_end = head.length;
        let mut newer_event: Option<DepositArchiveEvent> = None;
        let mut newer_checkpoint: Option<DepositIndexCheckpointCertificate> = None;
        let mut route_summary = CertifiedLedgerRouteRebuildAccumulator::default();
        while let Some(reference) = segment_reference {
            let segment = self.load_segment(reference, head.wallet).await?;
            if segment.end_ordinal()? != expected_end
                || (newer_event.is_none() && segment.events.last().copied() != head.event)
            {
                return Err(DepositArchiveError::BrokenArchiveChain);
            }
            let mut route_batch = Vec::new();
            for (offset, event_artifact) in segment.events.iter().copied().enumerate().rev() {
                let offset = u64::try_from(offset)
                    .map_err(|_| DepositArchiveError::ArchiveOrdinalExhausted)?;
                let ordinal = segment
                    .start_ordinal
                    .checked_add(offset)
                    .ok_or(DepositArchiveError::ArchiveOrdinalExhausted)?;
                let event = self.load_event(event_artifact, head.wallet, ordinal).await?;
                if match &newer_event {
                    Some(newer) => newer.previous != Some(event_artifact),
                    None => Some(event_artifact) != head.event,
                } {
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
                if let Some(newer) = &newer_checkpoint {
                    match newer.statement().parent() {
                        DepositIndexCheckpointParent::Certified { decision }
                            if decision == checkpoint.statement().decision_digest()
                                && newer.statement().previous_head()
                                    == checkpoint.statement().resulting_head() => {}
                        DepositIndexCheckpointParent::Certified { .. }
                        | DepositIndexCheckpointParent::Genesis => {
                            return Err(DepositArchiveError::ArchiveCheckpointParentMismatch);
                        }
                    }
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
                        let route = CertifiedLedgerRoute::from_authenticated_parts(
                            event_artifact,
                            ledger,
                            checkpoint_artifact,
                            &entry,
                            &checkpoint,
                        )?;
                        route_summary.record(route)?;
                        if rebuild_routes {
                            route_batch.push(route);
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
                visitor(archived)?;
                newer_event = Some(event);
                newer_checkpoint = Some(checkpoint);
            }
            if rebuild_routes {
                self.persist_authenticated_route_batch(&route_batch).await?;
            }
            expected_end = segment.start_ordinal;
            segment_reference = segment.previous;
        }
        if expected_end != 0 || head.segment.is_none() != head.is_empty() {
            return Err(DepositArchiveError::BrokenArchiveChain);
        }
        match (newer_event, newer_checkpoint) {
            (None, None) if head.is_empty() => {}
            (Some(oldest_event), Some(oldest_checkpoint))
                if !head.is_empty()
                    && oldest_event.ordinal == 0
                    && oldest_event.previous.is_none()
                    && matches!(
                        oldest_checkpoint.statement().parent(),
                        DepositIndexCheckpointParent::Genesis
                    ) => {}
            (None, None) | (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {
                return Err(DepositArchiveError::BrokenArchiveChain);
            }
        }
        route_summary.finish()
    }

    /// Convenience reverse traversal for callers interested only in ledger operations.
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
        #[cfg(test)]
        self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        #[cfg(test)]
        self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        #[cfg(test)]
        self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        #[cfg(test)]
        self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        #[cfg(test)]
        {
            self.artifact_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.segment_loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let artifact = self.artifacts.load_artifact(reference).await?;
        let segment = DepositArchiveSegment::from_bytes(artifact.contents.as_bytes())?;
        if segment.wallet != wallet {
            return Err(DepositArchiveError::InvalidArchiveSegment);
        }
        Ok(segment)
    }
}

fn certified_ledger_route_key(wallet: DepositWalletId, statement: [u8; 32]) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(&wallet.0);
    key[32..].copy_from_slice(&statement);
    key
}

fn open_certified_ledger_route_database(
    artifact_root: &Path,
) -> Result<Database, DepositArchiveError> {
    let directory = artifact_root.join(CERTIFIED_LEDGER_ROUTE_DIRECTORY);
    std::fs::create_dir_all(&directory).map_err(certified_ledger_route_store_error)?;
    let directory_metadata =
        std::fs::symlink_metadata(&directory).map_err(certified_ledger_route_store_error)?;
    if !directory_metadata.file_type().is_dir() || directory_metadata.file_type().is_symlink() {
        return Err(DepositArchiveError::CertifiedLedgerRouteStore(
            "route database directory is not a regular directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .map_err(certified_ledger_route_store_error)?;

    let path = directory.join(CERTIFIED_LEDGER_ROUTE_DATABASE_FILE);
    if let Ok(metadata) = std::fs::symlink_metadata(&path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err(DepositArchiveError::CertifiedLedgerRouteStore(
            "route database path is not a regular file".to_owned(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(&path).map_err(certified_ledger_route_store_error)?;
    let opened = file.metadata().map_err(certified_ledger_route_store_error)?;
    let current = std::fs::symlink_metadata(&path).map_err(certified_ledger_route_store_error)?;
    if !opened.is_file() || !current.is_file() {
        return Err(DepositArchiveError::CertifiedLedgerRouteStore(
            "route database file identity is invalid".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(DepositArchiveError::CertifiedLedgerRouteStore(
                "route database file changed while opening".to_owned(),
            ));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(certified_ledger_route_store_error)?;
    }

    let mut builder = Database::builder();
    builder.set_cache_size(CERTIFIED_LEDGER_ROUTE_DATABASE_CACHE_BYTES);
    let database = builder.create_file(file).map_err(certified_ledger_route_store_error)?;
    let mut transaction = database.begin_write().map_err(certified_ledger_route_store_error)?;
    configure_certified_ledger_route_write(&mut transaction)?;
    drop(
        transaction
            .open_table(CERTIFIED_LEDGER_ROUTE_TABLE)
            .map_err(certified_ledger_route_store_error)?,
    );
    transaction.commit().map_err(certified_ledger_route_store_error)?;
    #[cfg(unix)]
    std::fs::File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(certified_ledger_route_store_error)?;
    Ok(database)
}

fn persist_certified_ledger_routes_blocking(
    database: &Database,
    routes: &[CertifiedLedgerRoute],
) -> Result<(), DepositArchiveError> {
    if routes.is_empty() || routes.len() > MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS {
        return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
    }
    let encoded = routes
        .iter()
        .copied()
        .map(|route| {
            route.validate()?;
            let bytes =
                encode_bounded(&route, MAX_CERTIFIED_LEDGER_ROUTE_BYTES, "certified ledger route")?;
            Ok((route.key(), route, bytes))
        })
        .collect::<Result<Vec<_>, DepositArchiveError>>()?;

    let mut transaction = database.begin_write().map_err(certified_ledger_route_store_error)?;
    configure_certified_ledger_route_write(&mut transaction)?;
    {
        let mut table = transaction
            .open_table(CERTIFIED_LEDGER_ROUTE_TABLE)
            .map_err(certified_ledger_route_store_error)?;
        for (key, _, bytes) in &encoded {
            table
                .insert(key.as_slice(), bytes.as_slice())
                .map_err(certified_ledger_route_store_error)?;
        }
    }
    transaction.commit().map_err(certified_ledger_route_store_error)?;

    let transaction = database.begin_read().map_err(certified_ledger_route_store_error)?;
    let table = transaction
        .open_table(CERTIFIED_LEDGER_ROUTE_TABLE)
        .map_err(certified_ledger_route_store_error)?;
    for (key, expected, bytes) in encoded {
        let durable = table
            .get(key.as_slice())
            .map_err(certified_ledger_route_store_error)?
            .ok_or_else(|| {
                DepositArchiveError::CertifiedLedgerRouteStore(
                    "route commit has no exact readback".to_owned(),
                )
            })?;
        if durable.value() != bytes.as_slice()
            || decode_canonical_bounded::<CertifiedLedgerRoute>(
                durable.value(),
                MAX_CERTIFIED_LEDGER_ROUTE_BYTES,
                "certified ledger route",
            )? != expected
        {
            return Err(DepositArchiveError::CertifiedLedgerRouteStore(
                "route commit readback differs".to_owned(),
            ));
        }
    }
    Ok(())
}

fn load_certified_ledger_route_blocking(
    database: &Database,
    key: [u8; 64],
) -> Result<CertifiedLedgerRoute, DepositArchiveError> {
    let transaction = database.begin_read().map_err(certified_ledger_route_store_error)?;
    let table = transaction
        .open_table(CERTIFIED_LEDGER_ROUTE_TABLE)
        .map_err(certified_ledger_route_store_error)?;
    let value = table
        .get(key.as_slice())
        .map_err(certified_ledger_route_store_error)?
        .ok_or(DepositArchiveError::CertifiedLedgerRouteMissing)?;
    let route = decode_canonical_bounded::<CertifiedLedgerRoute>(
        value.value(),
        MAX_CERTIFIED_LEDGER_ROUTE_BYTES,
        "certified ledger route",
    )
    .map_err(|_| DepositArchiveError::CertifiedLedgerRouteMismatch)?;
    route.validate()?;
    if route.key() != key {
        return Err(DepositArchiveError::CertifiedLedgerRouteMismatch);
    }
    Ok(route)
}

fn configure_certified_ledger_route_write(
    transaction: &mut redb::WriteTransaction,
) -> Result<(), DepositArchiveError> {
    transaction
        .set_durability(redb::Durability::Immediate)
        .map_err(certified_ledger_route_store_error)?;
    transaction.set_two_phase_commit(true);
    transaction.set_quick_repair(true);
    Ok(())
}

fn certified_ledger_route_store_error(error: impl std::fmt::Display) -> DepositArchiveError {
    DepositArchiveError::CertifiedLedgerRouteStore(error.to_string())
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
    #[error("deposit archive prefix target is invalid")]
    InvalidPrefixTarget,
    #[error("deposit archive prefix cursor is invalid")]
    InvalidPrefixCursor,
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
    #[error("derived certified-ledger route is absent")]
    CertifiedLedgerRouteMissing,
    #[error("derived certified-ledger route is malformed or does not match its artifacts")]
    CertifiedLedgerRouteMismatch,
    #[error("derived certified-ledger route storage failed: {0}")]
    CertifiedLedgerRouteStore(String),
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
        compact_registry_store::CompactRegistryStoreCheckpoint,
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
        deposit_index_store::{DepositIndexStoreCheckpoint, VerifiedPortableIndexAdvance},
        deposit_ledger::{
            DepositObservationStatement, LedgerRequestId, LedgerStatement, RequestBinding,
            VerifiedDepositObservationCertificate, VerifiedEntry, genesis_head,
            sign_deposit_observation_attestation,
        },
        deposit_sync_support::{
            DEPOSIT_SYNC_SUPPORT_DOMAIN, DEPOSIT_SYNC_SUPPORT_VERSION,
            DepositSyncSupportCertificate, DepositSyncSupportEndorsement, DepositSyncSupportError,
            DepositSyncSupportRequest, DepositSyncSupportStatement,
        },
        deposit_sync_wire::{
            DepositSyncAdvertisement, DepositSyncContext, DepositSyncHeadRequest,
            DepositSyncHeadResponse,
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

    fn certified_ledger_route(
        authority: VerifiedDepositArchiveLedgerLocator,
        event_artifact: WalletArtifactRef,
        ledger_artifact: WalletArtifactRef,
        checkpoint_artifact: WalletArtifactRef,
    ) -> CertifiedLedgerRoute {
        let route = CertifiedLedgerRoute {
            version: CERTIFIED_LEDGER_ROUTE_VERSION,
            wallet: authority.wallet_id(),
            checkpoint_sequence: authority.checkpoint_sequence(),
            checkpoint_decision: authority.checkpoint_decision(),
            checkpoint_certificate_digest: authority.checkpoint_certificate_digest(),
            ledger_sequence: authority.ledger_sequence(),
            ledger_statement: authority.ledger_statement(),
            event_artifact,
            ledger_artifact,
            checkpoint_artifact,
        };
        route.validate().unwrap();
        route
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

    fn certified_observation_at(
        fixture: &Fixture,
        nonce: u64,
    ) -> (CertifiedDepositObservation, VerifiedDepositObservationCertificate) {
        let mut transaction = [0x81; 32];
        transaction[..8].copy_from_slice(&nonce.to_le_bytes());
        let mut output_key = [0x91; 32];
        output_key[..8].copy_from_slice(&nonce.to_le_bytes());
        let mut observed_hash = [0xa1; 32];
        observed_hash[..8].copy_from_slice(&nonce.to_le_bytes());
        let mut horizon_hash = [0xb1; 32];
        horizon_hash[..8].copy_from_slice(&nonce.to_le_bytes());
        let statement = DepositObservationStatement::new(
            &fixture.registry,
            &fixture.ledger.statement,
            WalletOutputId { transaction, index_in_transaction: nonce },
            output_key,
            nonce,
            10_000 + nonce,
            ChainPoint::new(20, observed_hash).unwrap(),
            900 + nonce,
            ChainPoint::new(29, horizon_hash).unwrap(),
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

    async fn build_linear_archive(
        archive: &DepositArchiveStore,
        fixture: &Fixture,
        event_count: usize,
    ) -> (DepositArchiveHead, Vec<WalletArtifactRef>) {
        assert!(event_count > 0);
        let ledger_checkpoint = ledger_checkpoint(fixture);
        let mut previous_verified = verify_ledger_checkpoint(fixture, &ledger_checkpoint);
        let staged = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();
        let ledger_append = archive
            .append_ledger_checkpoint(
                DepositArchiveHead::empty(fixture.registry.wallet()).unwrap(),
                staged,
                &ledger_checkpoint,
                &previous_verified,
                &mut OsRng,
            )
            .await
            .unwrap();
        let mut head = ledger_append.head;
        let mut events = vec![ledger_append.event_artifact];
        let mut reader = fixture.reader.clone();
        reader.apply(&fixture.update);
        let mut index_head = fixture.update.next_head().clone();

        for nonce in 1..u64::try_from(event_count).unwrap() {
            let (observation, verified_observation) = certified_observation_at(fixture, nonce);
            let mut builder = DepositIndexBuilder::new(&reader, index_head).unwrap();
            assert!(
                builder
                    .apply_verified_active_deposit_observation(&observation, &fixture.registry,)
                    .unwrap()
            );
            let update = builder.finish().unwrap().unwrap();
            let transition = update
                .verify_deposit_observation_transition(&reader, &observation.statement)
                .unwrap();
            let checkpoint =
                observation_checkpoint(fixture, &previous_verified, &observation, &transition);
            let verified_checkpoint = checkpoint
                .verify_active_deposit_observation(
                    fixture.network,
                    &fixture.registry,
                    Some(&previous_verified),
                    &observation,
                )
                .unwrap();
            let staged = archive
                .stage_certified_deposit_observation(
                    &observation,
                    &verified_observation,
                    &mut OsRng,
                )
                .await
                .unwrap();
            let append = archive
                .append_deposit_observation_checkpoint(
                    head,
                    staged,
                    &checkpoint,
                    &verified_checkpoint,
                    &mut OsRng,
                )
                .await
                .unwrap();
            head = append.head;
            events.push(append.event_artifact);
            index_head = update.next_head().clone();
            reader.apply(&update);
            previous_verified = verified_checkpoint;
        }
        (head, events)
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
    async fn reverse_archive_traversal_loads_each_full_segment_once_and_rejects_corruption() {
        const SEGMENTS: usize = 3;
        const EVENTS: usize = SEGMENTS * MAX_DEPOSIT_ARCHIVE_SEGMENT_EVENTS;

        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x2f);
        let identity_seed = [0x2f; 32];
        let archive =
            DepositArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let (head, events) = build_linear_archive(&archive, &fixture, EVENTS).await;
        assert_eq!(head.len(), u64::try_from(EVENTS).unwrap());
        assert_eq!(events.len(), EVENTS);

        archive.reset_test_load_counts();
        let mut ordinals = Vec::with_capacity(EVENTS);
        archive
            .visit_checkpoints(head, |checkpoint| {
                ordinals.push(match checkpoint {
                    ArchivedDepositCheckpoint::Ledger(entry) => entry.ordinal,
                    ArchivedDepositCheckpoint::DepositObservation(observation) => {
                        observation.ordinal
                    }
                });
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(ordinals, (0..u64::try_from(EVENTS).unwrap()).rev().collect::<Vec<_>>());
        let (artifact_loads, segment_loads) = archive.test_load_counts();
        assert_eq!(segment_loads, u64::try_from(SEGMENTS).unwrap());
        assert_eq!(
            artifact_loads,
            u64::try_from(SEGMENTS + (3 * EVENTS)).unwrap(),
            "one segment plus event/checkpoint/operation load per archive item"
        );

        let route_key = certified_ledger_route_key(
            fixture.registry.wallet(),
            fixture.ledger.statement.digest(),
        );
        let mut transaction = archive.certified_ledger_routes.begin_write().unwrap();
        configure_certified_ledger_route_write(&mut transaction).unwrap();
        {
            let mut table = transaction.open_table(CERTIFIED_LEDGER_ROUTE_TABLE).unwrap();
            assert!(table.remove(route_key.as_slice()).unwrap().is_some());
        }
        transaction.commit().unwrap();
        assert!(matches!(
            archive
                .load_routed_certified_entry(
                    head,
                    fixture.registry.wallet(),
                    fixture.ledger.statement.digest(),
                )
                .await,
            Err(DepositArchiveError::CertifiedLedgerRouteMissing)
        ));
        let summary = archive.rebuild_certified_ledger_routes(head).await.unwrap();
        assert_eq!(summary.unique_ledger_routes(), 1);
        assert_eq!(summary.maximum_ledger_sequence(), 1);
        assert_eq!(summary.terminal_ledger_statement(), fixture.ledger.statement.digest());
        drop(archive);

        let archive =
            DepositArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        archive.reset_test_load_counts();
        let routed = archive
            .load_routed_certified_entry(
                head,
                fixture.registry.wallet(),
                fixture.ledger.statement.digest(),
            )
            .await
            .unwrap();
        assert_eq!(routed.entry, fixture.ledger);
        assert_eq!(archive.test_load_counts(), (3, 0));

        for reference in [events[0], events[EVENTS / 2], events[EVENTS - 1]] {
            let path = archive.artifact_path(reference);
            let original = tokio::fs::read(&path).await.unwrap();
            let mut corrupted = original.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            tokio::fs::write(&path, corrupted).await.unwrap();
            assert!(
                archive.visit_checkpoints(head, |_| Ok(())).await.is_err(),
                "oldest, middle, and newest corruption must all fail closed"
            );
            tokio::fs::write(path, original).await.unwrap();
        }
    }

    fn prefix_target_from_checkpoint(
        wallet: DepositWalletId,
        event: WalletArtifactRef,
        checkpoint: &DepositIndexCheckpointCertificate,
    ) -> DepositArchivePrefixTarget {
        DepositArchivePrefixTarget::new(
            wallet,
            checkpoint.statement().sequence(),
            event,
            checkpoint.statement().decision_digest(),
            checkpoint.statement().resulting_head().clone(),
        )
        .unwrap()
    }

    async fn finish_prefix_lookup(
        archive: &DepositArchiveStore,
        mut cursor: DepositArchivePrefixCursor,
    ) -> DepositArchivePrefixStep {
        loop {
            let encoded = cursor.to_bytes().unwrap();
            assert!(encoded.len() <= MAX_DEPOSIT_ARCHIVE_PREFIX_CURSOR_BYTES);
            assert_eq!(DepositArchivePrefixCursor::from_bytes(&encoded).unwrap(), cursor);
            match archive.verify_anchored_prefix_step(cursor).await.unwrap() {
                DepositArchivePrefixStep::Pending(next) => cursor = next,
                terminal => return terminal,
            }
        }
    }

    #[tokio::test]
    async fn anchored_prefix_lookup_is_bounded_canonical_and_independent_of_moving_tip() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x79);
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x79; 32]).unwrap();
        let (fixed_head, events) = build_linear_archive(&archive, &fixture, 10).await;
        let checkpoints = collect_checkpoints(&archive, fixed_head).await.unwrap();
        let target_checkpoint = match checkpoints.iter().find(|item| item.ordinal() == 2).unwrap() {
            ArchivedDepositCheckpoint::DepositObservation(item) => &item.checkpoint,
            ArchivedDepositCheckpoint::Ledger(_) => unreachable!("ordinal two is an observation"),
        };
        let target =
            prefix_target_from_checkpoint(fixture.registry.wallet(), events[2], target_checkpoint);
        let cursor = DepositArchivePrefixCursor::start(fixed_head, target.clone()).unwrap();

        // Add a strict successor graph after the cursor has fixed its anchor. The lookup must
        // neither restart from nor follow this independently moving tip.
        let (moving_head, _) = build_linear_archive(&archive, &fixture, 13).await;
        assert!(moving_head.len() > fixed_head.len());

        archive.reset_test_load_counts();
        let DepositArchivePrefixStep::Included(verified) =
            finish_prefix_lookup(&archive, cursor).await
        else {
            panic!("fixed semantic checkpoint must be included");
        };
        assert_eq!(verified.anchor(), fixed_head);
        assert_eq!(verified.target(), &target);
        assert_eq!(verified.local_terminal_event(), events[2]);
        let (artifact_loads, segment_loads) = archive.test_load_counts();
        assert!(segment_loads <= 2, "each bounded step reloads at most its fixed segment");
        assert!(artifact_loads <= 18, "two steps load only segment/event/checkpoint objects");
    }

    #[tokio::test]
    async fn anchored_prefix_lookup_rejects_wrong_semantic_prefix_without_following_an_alias() {
        let directory = tempfile::tempdir().unwrap();
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x7a; 32]).unwrap();
        let fixture = make_fixture(0x7a);
        let conflicting = make_fixture(0x7b);
        let (head, _) = build_linear_archive(&archive, &fixture, 6).await;
        let (conflicting_head, conflicting_events) =
            build_linear_archive(&archive, &conflicting, 4).await;
        assert_eq!(head.wallet_id(), conflicting_head.wallet_id());
        let conflicting_checkpoints =
            collect_checkpoints(&archive, conflicting_head).await.unwrap();
        let checkpoint =
            match conflicting_checkpoints.iter().find(|item| item.ordinal() == 2).unwrap() {
                ArchivedDepositCheckpoint::DepositObservation(item) => &item.checkpoint,
                ArchivedDepositCheckpoint::Ledger(_) => {
                    unreachable!("ordinal two is an observation")
                }
            };
        let wrong = prefix_target_from_checkpoint(
            fixture.registry.wallet(),
            conflicting_events[2],
            checkpoint,
        );
        let cursor = DepositArchivePrefixCursor::start(head, wrong).unwrap();
        assert_eq!(
            finish_prefix_lookup(&archive, cursor).await,
            DepositArchivePrefixStep::NotIncluded
        );
    }

    #[tokio::test]
    async fn support_certificate_requires_f_plus_one_and_rejects_replay_or_noncanonical_order() {
        #[derive(Serialize)]
        struct RawCertificate<'a> {
            version: u16,
            domain: [u8; 16],
            statement: &'a DepositSyncSupportStatement,
            endorsements: &'a [DepositSyncSupportEndorsement],
        }

        let directory = tempfile::tempdir().unwrap();
        let fixture = make_fixture(0x7c);
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x7c; 32]).unwrap();
        let checkpoint = ledger_checkpoint(&fixture);
        let verified_checkpoint = verify_ledger_checkpoint(&fixture, &checkpoint);
        let staged = archive
            .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
            .await
            .unwrap();
        let appended = archive
            .append_ledger_checkpoint(
                DepositArchiveHead::empty(fixture.registry.wallet()).unwrap(),
                staged,
                &checkpoint,
                &verified_checkpoint,
                &mut OsRng,
            )
            .await
            .unwrap();

        let active = fixture.registry.active();
        let target = VerifiedRegistryHandoffTarget::for_test(
            active.committee().clone(),
            active.fault_bound(),
            active.activation(),
            active.certified_activation_root(),
            fixture.registry.wallet(),
            active.key_id(),
            active.group_key(),
        )
        .unwrap();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let empty_head =
            DepositIndexHead::empty_portable(fixture.registry.wallet(), first_index).unwrap();
        let registry_head =
            prepare_compact_registry_genesis(&target, first_index, empty_head.digest())
                .unwrap()
                .proposed_head()
                .clone();
        let registry_checkpoint =
            CompactRegistryStoreCheckpoint::settled(fixture.registry.wallet(), registry_head)
                .unwrap();
        let empty_index =
            DepositIndexStoreCheckpoint::empty(fixture.registry.wallet(), PartyId(1), first_index)
                .unwrap();
        let advance =
            VerifiedPortableIndexAdvance::from_certified_checkpoint(&verified_checkpoint).unwrap();
        let index_checkpoint = empty_index.adopt_verified_portable(&advance).unwrap();
        let context = DepositSyncContext::new(fixture.network, fixture.registry.wallet()).unwrap();
        let advertisement = DepositSyncAdvertisement::from_checkpoints(
            context,
            &registry_checkpoint,
            appended.head,
            &index_checkpoint,
            Some(checkpoint.clone()),
        )
        .unwrap();
        let head_request = DepositSyncHeadRequest::new(context, PartyId(1), PartyId(4)).unwrap();
        let head_response =
            DepositSyncHeadResponse::issue(head_request, advertisement, &[0x91; 32]).unwrap();
        let statement =
            DepositSyncSupportStatement::from_head_response(head_request, &head_response, &target)
                .unwrap();
        let terminal_event = archive
            .load_event(appended.event_artifact, fixture.registry.wallet(), 0)
            .await
            .unwrap();
        let support_request =
            DepositSyncSupportRequest::new(statement.clone(), terminal_event, checkpoint).unwrap();
        let statement_bytes = statement.to_bytes().unwrap();
        assert_eq!(DepositSyncSupportStatement::from_bytes(&statement_bytes).unwrap(), statement);
        let request_bytes = support_request.to_bytes().unwrap();
        assert_eq!(DepositSyncSupportRequest::from_bytes(&request_bytes).unwrap(), support_request);
        let mut noncanonical_request = request_bytes;
        noncanonical_request.push(0);
        assert!(matches!(
            DepositSyncSupportRequest::from_bytes(&noncanonical_request),
            Err(DepositSyncSupportError::TrailingBytes(_))
        ));
        let prefix_cursor =
            DepositArchivePrefixCursor::start(appended.head, statement.prefix_target().unwrap())
                .unwrap();
        let DepositArchivePrefixStep::Included(prefix) =
            archive.verify_anchored_prefix_step(prefix_cursor).await.unwrap()
        else {
            panic!("the source terminal checkpoint is the local fixed prefix");
        };
        let alternate_checkpoint =
            ledger_checkpoint_with_signers(&fixture, &[PartyId(2), PartyId(3), PartyId(4)]);
        let alternate_verified = verify_ledger_checkpoint(&fixture, &alternate_checkpoint);
        assert!(matches!(
            DepositSyncSupportEndorsement::endorse(
                &support_request,
                &alternate_verified,
                &prefix,
                &target,
                &fixture.identities[&PartyId(1)],
            ),
            Err(DepositSyncSupportError::InvalidRequest)
        ));
        let endorsement_one = DepositSyncSupportEndorsement::endorse(
            &support_request,
            &verified_checkpoint,
            &prefix,
            &target,
            &fixture.identities[&PartyId(1)],
        )
        .unwrap();
        let endorsement_two = DepositSyncSupportEndorsement::endorse(
            &support_request,
            &verified_checkpoint,
            &prefix,
            &target,
            &fixture.identities[&PartyId(2)],
        )
        .unwrap();

        assert!(matches!(
            DepositSyncSupportCertificate::new(
                statement.clone(),
                vec![endorsement_one.clone()],
                &target,
            ),
            Err(DepositSyncSupportError::InvalidCertificate)
        ));
        assert!(matches!(
            DepositSyncSupportCertificate::new(
                statement.clone(),
                vec![endorsement_one.clone(), endorsement_one.clone()],
                &target,
            ),
            Err(DepositSyncSupportError::InvalidCertificate)
        ));
        let certificate = DepositSyncSupportCertificate::new(
            statement.clone(),
            vec![endorsement_two.clone(), endorsement_one.clone()],
            &target,
        )
        .unwrap();
        let verified = certificate.verify(&statement, &target).unwrap();
        assert_eq!(verified.signers(), &[PartyId(1), PartyId(2)]);
        let bytes = certificate.to_bytes(&target).unwrap();
        assert_eq!(verified.statement(), &statement);
        assert_eq!(verified.certificate_bytes(), bytes.as_slice());
        assert_ne!(verified.certificate_digest(), [0; 32]);
        let restarted_verified = DepositSyncSupportCertificate::from_bytes(&bytes)
            .unwrap()
            .verify(&statement, &target)
            .unwrap();
        assert_eq!(restarted_verified, verified);
        assert_eq!(restarted_verified.certificate_digest(), verified.certificate_digest());

        let mut mutated = verified.certificate_bytes().to_vec();
        *mutated.last_mut().unwrap() ^= 1;
        let mutated = DepositSyncSupportCertificate::from_bytes(&mutated).unwrap();
        assert!(mutated.verify(&statement, &target).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            DepositSyncSupportCertificate::from_bytes(&trailing),
            Err(DepositSyncSupportError::TrailingBytes(_))
        ));

        let reversed = [endorsement_two, endorsement_one];
        let reversed = postcard::to_allocvec(&RawCertificate {
            version: DEPOSIT_SYNC_SUPPORT_VERSION,
            domain: DEPOSIT_SYNC_SUPPORT_DOMAIN,
            statement: &statement,
            endorsements: &reversed,
        })
        .unwrap();
        assert!(matches!(
            DepositSyncSupportCertificate::from_bytes(&reversed),
            Err(DepositSyncSupportError::InvalidCertificate)
        ));

        let wrong_context = DepositSyncHeadRequest::new(
            DepositSyncContext::new([0x56; 32], fixture.registry.wallet()).unwrap(),
            PartyId(1),
            PartyId(4),
        )
        .unwrap();
        assert!(
            DepositSyncSupportStatement::from_head_response(
                wrong_context,
                &head_response,
                &target,
            )
            .is_err()
        );
        let wrong_target = VerifiedRegistryHandoffTarget::for_test(
            active.committee().clone(),
            active.fault_bound(),
            [0x92; 32],
            active.certified_activation_root(),
            fixture.registry.wallet(),
            active.key_id(),
            active.group_key(),
        )
        .unwrap();
        assert!(matches!(
            certificate.verify(&statement, &wrong_target),
            Err(DepositSyncSupportError::WrongActiveRegistry)
        ));

        let mut removed_source_committee = active.committee().clone();
        removed_source_committee.members[0].id = PartyId(5);
        let removed_source_target = VerifiedRegistryHandoffTarget::for_test(
            removed_source_committee,
            active.fault_bound(),
            active.activation(),
            active.certified_activation_root(),
            fixture.registry.wallet(),
            active.key_id(),
            active.group_key(),
        )
        .unwrap();
        assert!(matches!(
            statement.validate_against(&removed_source_target),
            Err(DepositSyncSupportError::Committee(_))
        ));
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
                panic!("newest checkpoint must be the exact observation pair")
            }
        }
        match &checkpoints[1] {
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
                panic!("oldest checkpoint must be the exact ledger pair")
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

    #[tokio::test]
    async fn certified_route_survives_restart_and_loads_exactly_three_artifacts() {
        let directory = tempfile::tempdir().unwrap();
        let identity_seed = [0x61; 32];
        let archive =
            DepositArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let fixture = make_fixture(0x62);
        let (head, _) = build_linear_archive(&archive, &fixture, 16).await;
        let archived = collect_checkpoints(&archive, head)
            .await
            .unwrap()
            .into_iter()
            .find_map(|checkpoint| match checkpoint {
                ArchivedDepositCheckpoint::Ledger(entry) => Some(entry),
                ArchivedDepositCheckpoint::DepositObservation(_) => None,
            })
            .unwrap();
        drop(archive);
        let archive =
            DepositArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();

        archive.reset_test_load_counts();
        let located = archive
            .load_routed_certified_entry(
                head,
                fixture.registry.wallet(),
                fixture.ledger.statement.digest(),
            )
            .await
            .unwrap();
        assert_eq!(located.ordinal, archived.ordinal);
        assert_eq!(located.checkpoint_sequence, archived.checkpoint_sequence);
        assert_eq!(located.event_artifact, archived.event_artifact);
        assert_eq!(located.entry_artifact, archived.entry_artifact);
        assert_eq!(located.checkpoint_artifact, archived.checkpoint_artifact);
        assert_eq!(located.entry, archived.entry);
        assert_eq!(located.checkpoint, archived.checkpoint);
        assert_eq!(
            archive.test_load_counts(),
            (3, 0),
            "a route must read only its event, ledger certificate, and checkpoint"
        );
    }

    #[tokio::test]
    async fn certified_route_rebuild_is_complete_and_rejects_mixed_records() {
        let directory = tempfile::tempdir().unwrap();
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x63; 32]).unwrap();
        let left = make_fixture(0x64);
        let right = make_fixture(0x65);
        let mut appends = Vec::new();
        for fixture in [&left, &right] {
            let checkpoint = ledger_checkpoint(fixture);
            let verified_checkpoint = verify_ledger_checkpoint(fixture, &checkpoint);
            let staged = archive
                .stage_certified_ledger_entry(&fixture.ledger, &fixture.verified_ledger, &mut OsRng)
                .await
                .unwrap();
            appends.push(
                archive
                    .append_ledger_checkpoint(
                        DepositArchiveHead::empty(fixture.registry.wallet()).unwrap(),
                        staged,
                        &checkpoint,
                        &verified_checkpoint,
                        &mut OsRng,
                    )
                    .await
                    .unwrap(),
            );
        }
        let left = appends[0];
        let right = appends[1];
        let left_authority = left.verified_ledger_locator();
        let right_authority = right.verified_ledger_locator();

        let summary = archive.rebuild_certified_ledger_routes(left.head).await.unwrap();
        assert_eq!(summary.unique_ledger_routes(), 1);
        assert_eq!(summary.maximum_ledger_sequence(), 1);
        assert_eq!(summary.terminal_ledger_statement(), left_authority.ledger_statement());

        let mixed_artifact = certified_ledger_route(
            left_authority,
            left_authority.event_artifact(),
            right_authority.ledger_artifact(),
            left_authority.checkpoint_artifact(),
        );
        archive.persist_authenticated_route_batch(&[mixed_artifact]).await.unwrap();
        assert!(matches!(
            archive
                .load_routed_certified_entry(
                    left.head,
                    left_authority.wallet_id(),
                    left_authority.ledger_statement(),
                )
                .await,
            Err(DepositArchiveError::CertifiedLedgerRouteMismatch)
        ));

        let mixed_authority = certified_ledger_route(
            right_authority,
            left_authority.event_artifact(),
            left_authority.ledger_artifact(),
            left_authority.checkpoint_artifact(),
        );
        archive.persist_authenticated_route_batch(&[mixed_authority]).await.unwrap();
        assert!(matches!(
            archive
                .load_routed_certified_entry(
                    left.head,
                    right_authority.wallet_id(),
                    right_authority.ledger_statement(),
                )
                .await,
            Err(DepositArchiveError::CertifiedLedgerRouteMismatch)
        ));
    }

    #[tokio::test]
    async fn certified_route_missing_and_malformed_records_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let archive = DepositArchiveStore::new(directory.path(), PartyId(1), &[0x66; 32]).unwrap();
        let wallet = deriver().wallet_id();
        let head = DepositArchiveHead::empty(wallet).unwrap();
        let statement = [0x67; 32];
        assert!(matches!(
            archive.load_routed_certified_entry(head, wallet, statement).await,
            Err(DepositArchiveError::CertifiedLedgerRouteMissing)
        ));

        let key = certified_ledger_route_key(wallet, statement);
        let mut transaction = archive.certified_ledger_routes.begin_write().unwrap();
        configure_certified_ledger_route_write(&mut transaction).unwrap();
        {
            let mut table = transaction.open_table(CERTIFIED_LEDGER_ROUTE_TABLE).unwrap();
            table.insert(key.as_slice(), [0xff_u8].as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        assert!(matches!(
            archive.load_routed_certified_entry(head, wallet, statement).await,
            Err(DepositArchiveError::CertifiedLedgerRouteMismatch)
        ));
    }
}
