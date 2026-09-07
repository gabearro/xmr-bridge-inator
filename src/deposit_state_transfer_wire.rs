//! Clean-v7, bounded QUIC payloads for post-handoff deposit-state transfer.
//!
//! Ordinary deposit sync serves a moving current head.  A post-handoff export instead serves one
//! immutable, old-quorum-certified graph after the source committee has retired.  These payloads
//! deliberately use a distinct lease and object-capability domain: possession of a current-sync
//! lease can never authorize a historical export read, and an export capability can never be
//! replayed against the current-sync reducer.
//!
//! Decoding an [`DepositStateExportHeadResponse`] only establishes bounded canonical structure.
//! The target must verify the embedded seal certificate against the predecessor registry and
//! handoff, then call [`DepositStateExportHeadResponse::validate_verified_seal`] before importing
//! any object.  The source-local MAC key is never serialized.

use std::{cell::RefCell, collections::BTreeSet, fmt};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{
    committee::PartyId,
    compact_epoch_registry::{
        COMPACT_REGISTRY_INDEX_DEPTH, CompactEpochRegistry, RegistryHandoffCertificate,
    },
    compact_registry_archive::{
        COMPACT_REGISTRY_INDEX_OBJECT_READS, CompactRegistryArchiveError,
        CompactRegistryObjectReader, CompactRegistryObjectRef, CompactRegistryTraversalTarget,
        MAX_COMPACT_REGISTRY_HEAD_BYTES, MAX_COMPACT_REGISTRY_INDEX_NODE_BYTES,
        MAX_COMPACT_REGISTRY_LINK_BYTES, MAX_COMPACT_REGISTRY_WITNESS_BYTES,
        lookup_compact_registry_epoch, verify_compact_registry_object,
    },
    deposit_archive::{
        CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT, CERTIFIED_LEDGER_ENTRY_ARTIFACT,
        DEPOSIT_ARCHIVE_EVENT_ARTIFACT, DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT, DepositArchiveEvent,
        DepositArchiveOperation, DepositArchiveSegment, MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        MAX_DEPOSIT_ARCHIVE_EVENT_BYTES, MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
    },
    deposit_index::{DepositIndexObjectId, MAX_HAMT_DEPTH, PortableIndexTraversalTarget},
    deposit_ledger::{CertifiedLedgerEntry, LedgerPayload},
    deposit_state_export::{
        DepositPostHandoffExportSealCertificate, DepositPostHandoffExportSealStatement,
        DepositStateExportError, MAX_POST_HANDOFF_EXPORT_SEAL_BYTES,
        VerifiedDepositPostHandoffExportCandidate, VerifiedDepositPostHandoffExportSeal,
        VerifiedPreImportDepositStateExportSeal,
    },
    deposit_state_import::{
        DepositStateImportError, DepositStateImportedAck, DepositStateImportedCertificate,
        DepositStateImportedStatement, MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES,
        MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES, VerifiedStateImportTransitionBinding,
    },
    deposit_sync_wire::{
        DepositSyncAdvertisement, DepositSyncArchiveLeafKind, DepositSyncContext,
        DepositSyncObject, DepositSyncObjectAnchor, DepositSyncObjectRef,
        DepositSyncTraversalTarget, DepositSyncWireError, MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES,
        MAX_DEPOSIT_SYNC_PAGE_OBJECTS, MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES,
        MAX_DEPOSIT_SYNC_REQUEST_OBJECTS, MAX_DEPOSIT_SYNC_WIRE_BYTES,
    },
    deposit_wallet::DepositWalletId,
    identity::{Identity, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{WalletArtifactRef, WalletId},
};

/// Fresh state-transfer wire version.  There is no legacy decoder.
pub const DEPOSIT_STATE_TRANSFER_WIRE_VERSION: u16 = 7;
const MAX_POST_HANDOFF_EXPORT_ADVERTISEMENT_BYTES: usize =
    MAX_COMPACT_REGISTRY_HEAD_BYTES + 256 * 1024;
// Verifying one immediate successor reads the source and target sparse-index paths. They always
// share the root, so this is the exact worst-case union when adjacent epochs diverge immediately.
const MAX_POST_HANDOFF_EXPORT_REGISTRY_INDEX_EVIDENCE_OBJECTS: usize =
    2 * COMPACT_REGISTRY_INDEX_OBJECT_READS - 1;
// The two paths terminate in two links, the target handoff witness, and (outside genesis) the
// source handoff witness. Exact reachability checks below reject unused objects below this bound.
const MAX_POST_HANDOFF_EXPORT_REGISTRY_EVIDENCE_OBJECTS: usize =
    MAX_POST_HANDOFF_EXPORT_REGISTRY_INDEX_EVIDENCE_OBJECTS + 4;
// Canonical vector length prefixes, content-address metadata for every bounded registry object,
// the three archive references, and the fixed evidence fields.
const MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_FRAMING_BYTES: usize = 64 * 1024;
/// Maximum canonical candidate-evidence body inside one seal request.
pub const MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES: usize =
    MAX_POST_HANDOFF_EXPORT_ADVERTISEMENT_BYTES
        + MAX_POST_HANDOFF_EXPORT_REGISTRY_INDEX_EVIDENCE_OBJECTS
            * MAX_COMPACT_REGISTRY_INDEX_NODE_BYTES
        + 2 * MAX_COMPACT_REGISTRY_LINK_BYTES
        + 2 * MAX_COMPACT_REGISTRY_WITNESS_BYTES
        + MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES
        + MAX_DEPOSIT_ARCHIVE_EVENT_BYTES
        + MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES
        + MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_FRAMING_BYTES;
// The duplicated seal statement, source self-vote envelope, and canonical request field framing.
const MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_FRAMING_BYTES: usize = 64 * 1024;
/// A source seal request carries one canonical, source-self-voted candidate proof. The cap is the
/// exact composition of its independently bounded candidate, seal, and request framing; it is not
/// an unrelated transport-sized allocation.
pub const MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES: usize =
    MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES
        + MAX_POST_HANDOFF_EXPORT_SEAL_BYTES
        + MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_FRAMING_BYTES;
const _: () = assert!(MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES <= MAX_DEPOSIT_SYNC_WIRE_BYTES);
/// Maximum typed seal-request acknowledgement.
pub const MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_ACK_BYTES: usize = 1024;
/// Maximum one-member seal vote.
pub const MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES: usize = 64 * 1024;
/// Maximum typed seal-vote acknowledgement.
pub const MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_ACK_BYTES: usize = 1024;
/// Maximum delivery of an exact old-quorum seal certificate.
pub const MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES: usize = 128 * 1024;
/// Maximum typed seal-certificate acknowledgement.
pub const MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_ACK_BYTES: usize = 1024;
/// Maximum certified-export head request.
pub const MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES: usize = 1024;
/// Maximum certified-export head response.
pub const MAX_DEPOSIT_STATE_EXPORT_HEAD_RESPONSE_BYTES: usize = 512 * 1024;
/// Maximum certified-export object request.
pub const MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES: usize = 256 * 1024;
/// Maximum certified-export object response.
pub const MAX_DEPOSIT_STATE_EXPORT_OBJECTS_RESPONSE_BYTES: usize = MAX_DEPOSIT_SYNC_WIRE_BYTES;
/// Maximum exact certified-export lease release.
pub const MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES: usize = 4 * 1024;
/// Maximum typed certified-export release acknowledgement.
pub const MAX_DEPOSIT_STATE_EXPORT_RELEASE_ACK_BYTES: usize = 1024;
/// Maximum one target-quorum import acknowledgement delivery.
pub const MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES: usize =
    MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES + 1024;
/// Maximum typed acknowledgement-delivery receipt.
pub const MAX_DEPOSIT_STATE_IMPORTED_ACK_RECEIPT_BYTES: usize = 1024;
/// Maximum target-quorum import certificate delivery.
pub const MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES: usize =
    MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES + 1024;
/// Maximum typed import-certificate receipt.
pub const MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_RECEIPT_BYTES: usize = 1024;

const CONTEXT_DOMAIN: [u8; 16] = *b"tm-xfer-ctx-v007";
const CANDIDATE_EVIDENCE_DOMAIN: [u8; 16] = *b"tm-xfer-evid-v07";
const SEAL_REQUEST_DOMAIN: [u8; 16] = *b"tm-xfer-sreq-v07";
const SEAL_REQUEST_ACK_DOMAIN: [u8; 16] = *b"tm-xfer-sack-v07";
const SEAL_VOTE_DOMAIN: [u8; 16] = *b"tm-xfer-vote-v07";
const SEAL_VOTE_ACK_DOMAIN: [u8; 16] = *b"tm-xfer-vack-v07";
const SEAL_CERTIFICATE_DOMAIN: [u8; 16] = *b"tm-xfer-cert-v07";
const SEAL_CERTIFICATE_ACK_DOMAIN: [u8; 16] = *b"tm-xfer-cack-v07";
const EXPORT_HEAD_REQUEST_DOMAIN: [u8; 16] = *b"tm-xfer-head-v07";
const EXPORT_HEAD_RESPONSE_DOMAIN: [u8; 16] = *b"tm-xfer-hres-v07";
const EXPORT_LEASE_DOMAIN: [u8; 16] = *b"tm-xfer-lease-v7";
const EXPORT_OBJECT_CAPABILITY_DOMAIN: [u8; 16] = *b"tm-xfer-ocap-v07";
const EXPORT_OBJECT_REQUEST_DOMAIN: [u8; 16] = *b"tm-xfer-oreq-v07";
const EXPORT_OBJECT_RESPONSE_DOMAIN: [u8; 16] = *b"tm-xfer-ores-v07";
const EXPORT_RELEASE_REQUEST_DOMAIN: [u8; 16] = *b"tm-xfer-rreq-v07";
const EXPORT_RELEASE_ACK_DOMAIN: [u8; 16] = *b"tm-xfer-rack-v07";
const IMPORT_ACK_DELIVERY_DOMAIN: [u8; 16] = *b"tm-xfer-iack-v07";
const IMPORT_ACK_RECEIPT_DOMAIN: [u8; 16] = *b"tm-xfer-iakr-v07";
const IMPORT_CERTIFICATE_DELIVERY_DOMAIN: [u8; 16] = *b"tm-xfer-icrt-v07";
const IMPORT_CERTIFICATE_RECEIPT_DOMAIN: [u8; 16] = *b"tm-xfer-icrr-v07";

const CONTEXT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-state-transfer/context/v7";
const CANDIDATE_EVIDENCE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-candidate-evidence/v7";
const SEAL_REQUEST_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-seal-request/v7";
const SEAL_VOTE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-state-transfer/export-seal-vote/v7";
const SEAL_CERTIFICATE_DELIVERY_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-seal-certificate-delivery/v7";
const EXPORT_HEAD_REQUEST_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-head-request/v7";
const EXPORT_HEAD_RESPONSE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-head-response/v7";
const EXPORT_LEASE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-state-transfer/export-lease/v7";
const EXPORT_LEASE_MAC_DOMAIN: &[u8] =
    b"threshold-monero/deposit-state-transfer/export-lease-mac/v7";
const EXPORT_OBJECT_CAPABILITY_MAC_DOMAIN: &[u8] =
    b"threshold-monero/deposit-state-transfer/export-object-capability-mac/v7";
const EXPORT_OBJECT_REQUEST_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-object-request/v7";
const EXPORT_OBJECT_RESPONSE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-object-response/v7";
const EXPORT_RELEASE_REQUEST_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/export-release-request/v7";
const IMPORT_ACK_DELIVERY_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/import-ack-delivery/v7";
const IMPORT_CERTIFICATE_DELIVERY_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/import-certificate-delivery/v7";
const EXACT_BYTES_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-transfer/exact-canonical-bytes/v7";

/// Deployment and wallet binding repeated by every state-transfer message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateTransferContext {
    version: u16,
    domain: [u8; 16],
    network: [u8; 32],
    wallet: DepositWalletId,
}

impl DepositStateTransferContext {
    pub fn new(
        network: [u8; 32],
        wallet: DepositWalletId,
    ) -> Result<Self, DepositStateTransferWireError> {
        let context = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: CONTEXT_DOMAIN,
            network,
            wallet,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(self) -> Result<(), DepositStateTransferWireError> {
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != CONTEXT_DOMAIN
            || self.network == [0; 32]
            || self.wallet.0 == [0; 32]
        {
            return Err(DepositStateTransferWireError::InvalidContext);
        }
        Ok(())
    }

    fn validate_sync_context(
        self,
        context: DepositSyncContext,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate()?;
        if self.network != context.network() || self.wallet != context.wallet() {
            return Err(DepositStateTransferWireError::WrongAdvertisement);
        }
        Ok(())
    }

    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("fixed transfer context serializes");
        length_prefixed_hash(CONTEXT_DIGEST_DOMAIN, &bytes)
    }
}

/// One exact content-addressed compact-registry object in a seal candidate proof.
///
/// The object bytes are capped before allocation during deserialization. The complete evidence
/// validator additionally requires the exact union of the fixed-depth source and target paths and
/// rejects every detached or duplicate object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportRegistryEvidenceObject {
    reference: CompactRegistryObjectRef,
    #[serde(deserialize_with = "deserialize_candidate_registry_object_bytes")]
    bytes: Vec<u8>,
}

impl DepositPostHandoffExportRegistryEvidenceObject {
    pub fn new(
        reference: CompactRegistryObjectRef,
        bytes: Vec<u8>,
    ) -> Result<Self, DepositStateTransferWireError> {
        let object = Self { reference, bytes };
        object.validate()?;
        Ok(object)
    }

    pub fn from_sync_object(
        object: &DepositSyncObject,
    ) -> Result<Self, DepositStateTransferWireError> {
        let DepositSyncObjectRef::Registry(reference) = object.reference() else {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        };
        Self::new(reference, object.bytes().to_vec())
    }

    fn validate(&self) -> Result<(), DepositStateTransferWireError> {
        if self.bytes.is_empty()
            || self.bytes.len()
                != usize::try_from(self.reference.plaintext_len())
                    .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?
            || self.bytes.len() > MAX_COMPACT_REGISTRY_WITNESS_BYTES
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }
        self.reference
            .verify_contents(&self.bytes)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        verify_compact_registry_object(self.reference, &self.bytes)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        Ok(())
    }

    #[must_use]
    pub const fn reference(&self) -> CompactRegistryObjectRef {
        self.reference
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Canonical source-specific evidence from which a predecessor can reconstruct the exact verified
/// candidate before casting its first seal vote.
///
/// The checkpoint certificate is not copied: the canonical advertisement already carries those
/// exact bytes. The remaining terminal archive objects and the exact union of the source/target
/// registry paths are content addressed by the signed statement. No certified ExportHead appears
/// in this proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportCandidateEvidence {
    version: u16,
    domain: [u8; 16],
    statement: [u8; 32],
    #[serde(deserialize_with = "deserialize_candidate_advertisement_bytes")]
    advertisement: Vec<u8>,
    #[serde(deserialize_with = "deserialize_candidate_registry_objects")]
    registry_objects: Vec<DepositPostHandoffExportRegistryEvidenceObject>,
    archive_segment_reference: WalletArtifactRef,
    #[serde(deserialize_with = "deserialize_candidate_archive_segment_bytes")]
    archive_segment: Vec<u8>,
    archive_event_reference: WalletArtifactRef,
    #[serde(deserialize_with = "deserialize_candidate_archive_event_bytes")]
    archive_event: Vec<u8>,
    terminal_ledger_reference: WalletArtifactRef,
    #[serde(deserialize_with = "deserialize_candidate_ledger_bytes")]
    terminal_ledger: Vec<u8>,
}

impl DepositPostHandoffExportCandidateEvidence {
    pub fn new(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        advertisement: &DepositSyncAdvertisement,
        registry_objects: Vec<DepositSyncObject>,
        archive_segment: &DepositSyncObject,
        archive_event: &DepositSyncObject,
        terminal_ledger: &DepositSyncObject,
    ) -> Result<Self, DepositStateTransferWireError> {
        let mut registry_objects = registry_objects
            .iter()
            .map(DepositPostHandoffExportRegistryEvidenceObject::from_sync_object)
            .collect::<Result<Vec<_>, _>>()?;
        registry_objects.sort_by_key(DepositPostHandoffExportRegistryEvidenceObject::reference);
        let archive_segment_reference = archive_segment
            .reference()
            .storage_reference()
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let archive_event_reference = archive_event
            .reference()
            .storage_reference()
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let terminal_ledger_reference = terminal_ledger
            .reference()
            .storage_reference()
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let evidence = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: CANDIDATE_EVIDENCE_DOMAIN,
            statement: candidate.statement().digest(),
            advertisement: advertisement.to_bytes()?,
            registry_objects,
            archive_segment_reference,
            archive_segment: archive_segment.bytes().to_vec(),
            archive_event_reference,
            archive_event: archive_event.bytes().to_vec(),
            terminal_ledger_reference,
            terminal_ledger: terminal_ledger.bytes().to_vec(),
        };
        evidence.validate_for_candidate(candidate)?;
        Ok(evidence)
    }

    pub fn validate_for_candidate(
        &self,
        candidate: &VerifiedDepositPostHandoffExportCandidate,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_for_statement(candidate.statement())
    }

    fn validate_for_statement(
        &self,
        statement: &DepositPostHandoffExportSealStatement,
    ) -> Result<(), DepositStateTransferWireError> {
        validate_seal_statement_shape(statement)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != CANDIDATE_EVIDENCE_DOMAIN
            || self.statement != statement.digest()
            || self.registry_objects.is_empty()
            || self.registry_objects.len() > MAX_POST_HANDOFF_EXPORT_REGISTRY_EVIDENCE_OBJECTS
            || self.registry_objects.windows(2).any(|pair| pair[0].reference >= pair[1].reference)
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }

        let advertisement = self.advertisement()?;
        statement
            .final_export()
            .validate_advertisement(&advertisement)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        for object in &self.registry_objects {
            object.validate()?;
            if object.reference.wallet() != statement.source().wallet() {
                return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
            }
        }
        let reader = CandidateRegistryEvidenceReader::new(&self.registry_objects);
        let archive = statement.final_export().target_registry_archive();
        let epoch = lookup_compact_registry_epoch(archive, statement.target_epoch(), &reader)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        if epoch.link_reference() != archive.active_link_reference()
            || epoch.witness_reference() != archive.active_witness_reference()
            || epoch.witness().is_none()
            || !reader.consumed_exact_object_set()
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }

        let final_export = statement.final_export();
        let archive_head = final_export.archive();
        validate_candidate_archive_object(
            self.archive_segment_reference,
            &self.archive_segment,
            statement.source().wallet(),
            DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
        )?;
        validate_candidate_archive_object(
            self.archive_event_reference,
            &self.archive_event,
            statement.source().wallet(),
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
        validate_candidate_archive_object(
            self.terminal_ledger_reference,
            &self.terminal_ledger,
            statement.source().wallet(),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        )?;
        if archive_head.segment_reference() != Some(self.archive_segment_reference)
            || archive_head.event_reference() != Some(self.archive_event_reference)
            || self.terminal_ledger_reference != statement.terminal_operation_artifact()
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }

        let segment = DepositArchiveSegment::from_bytes(&self.archive_segment)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let event = DepositArchiveEvent::from_bytes(&self.archive_event)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        if segment.wallet_id() != statement.source().wallet()
            || segment.end_ordinal().ok() != Some(archive_head.len())
            || segment.event_references().last().copied() != Some(self.archive_event_reference)
            || event.wallet_id() != statement.source().wallet()
            || event.ordinal().checked_add(1) != Some(archive_head.len())
            || event.operation() != DepositArchiveOperation::Ledger
            || event.operation_reference() != self.terminal_ledger_reference
            || event.checkpoint_reference() != statement.terminal_checkpoint_artifact()
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }

        let ledger = CertifiedLedgerEntry::from_bytes(&self.terminal_ledger)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        if ledger.statement.wallet != statement.source().wallet()
            || ledger.statement.sequence
                != final_export.resulting_portable_head().through_sequence()
            || ledger.statement.digest() != statement.handoff_statement_digest()
            || !matches!(ledger.statement.payload, LedgerPayload::Handoff(_))
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }
        let checkpoint = advertisement
            .checkpoint_certificate()
            .ok_or(DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let checkpoint_bytes = checkpoint
            .to_bytes()
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        validate_candidate_archive_object(
            statement.terminal_checkpoint_artifact(),
            &checkpoint_bytes,
            statement.source().wallet(),
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            crate::deposit_archive::MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
        )?;
        Ok(())
    }

    /// Cryptographically reconstruct the non-serializable candidate capability without treating
    /// the serialized seal statement as authority.
    fn verify_and_reconstruct_candidate(
        &self,
        network: [u8; 32],
        source_party: PartyId,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedDepositPostHandoffExportCandidate, DepositStateTransferWireError> {
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != CANDIDATE_EVIDENCE_DOMAIN
            || self.statement == [0; 32]
            || self.registry_objects.is_empty()
            || self.registry_objects.len() > MAX_POST_HANDOFF_EXPORT_REGISTRY_EVIDENCE_OBJECTS
            || self.registry_objects.windows(2).any(|pair| pair[0].reference >= pair[1].reference)
        {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }
        source.validate().map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        for object in &self.registry_objects {
            object.validate()?;
            if object.reference.wallet() != source.wallet() {
                return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
            }
        }
        validate_candidate_archive_object(
            self.archive_segment_reference,
            &self.archive_segment,
            source.wallet(),
            DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES,
        )?;
        validate_candidate_archive_object(
            self.archive_event_reference,
            &self.archive_event,
            source.wallet(),
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
        validate_candidate_archive_object(
            self.terminal_ledger_reference,
            &self.terminal_ledger,
            source.wallet(),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        )?;

        let advertisement = self.advertisement()?;
        let archive_segment = DepositArchiveSegment::from_bytes(&self.archive_segment)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let archive_event = DepositArchiveEvent::from_bytes(&self.archive_event)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let terminal_ledger = CertifiedLedgerEntry::from_bytes(&self.terminal_ledger)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let checkpoint = advertisement
            .checkpoint_certificate()
            .ok_or(DepositStateTransferWireError::InvalidCandidateEvidence)?;
        let reader = CandidateRegistryEvidenceReader::new(&self.registry_objects);
        let candidate = VerifiedDepositPostHandoffExportCandidate::from_verified_remote_evidence(
            network,
            source_party,
            source,
            handoff,
            target,
            &advertisement,
            &reader,
            self.archive_segment_reference,
            &archive_segment,
            self.archive_event_reference,
            archive_event,
            self.terminal_ledger_reference,
            &terminal_ledger,
            checkpoint,
        )
        .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)?;
        if !reader.consumed_exact_object_set() {
            return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
        }
        if candidate.statement().digest() != self.statement {
            return Err(DepositStateTransferWireError::WrongCandidateEvidence);
        }
        Ok(candidate)
    }

    pub fn to_bytes(
        &self,
        candidate: &VerifiedDepositPostHandoffExportCandidate,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for_candidate(candidate)?;
        encode_bounded(
            self,
            MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES,
            "post-handoff export candidate evidence",
        )
    }

    pub fn from_bytes(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let evidence: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES,
            "post-handoff export candidate evidence",
        )?;
        evidence.validate_for_candidate(candidate)?;
        Ok(evidence)
    }

    /// Reauthenticate persisted evidence against live transition authority, never against a
    /// candidate reconstructed from a different replica's witness archive.
    pub(crate) fn from_bytes_verified(
        bytes: &[u8],
        network: [u8; 32],
        source_party: PartyId,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(Self, VerifiedDepositPostHandoffExportCandidate), DepositStateTransferWireError>
    {
        let evidence: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_CANDIDATE_EVIDENCE_BYTES,
            "post-handoff export candidate evidence",
        )?;
        let candidate = evidence.verify_and_reconstruct_candidate(
            network,
            source_party,
            source,
            handoff,
            target,
        )?;
        Ok((evidence, candidate))
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(self).expect("validated export candidate evidence serializes");
        length_prefixed_hash(CANDIDATE_EVIDENCE_DIGEST_DOMAIN, &bytes)
    }

    pub fn advertisement(&self) -> Result<DepositSyncAdvertisement, DepositStateTransferWireError> {
        DepositSyncAdvertisement::from_bytes(&self.advertisement)
            .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)
    }

    #[must_use]
    pub fn registry_objects(&self) -> &[DepositPostHandoffExportRegistryEvidenceObject] {
        &self.registry_objects
    }

    #[must_use]
    pub const fn archive_segment_reference(&self) -> WalletArtifactRef {
        self.archive_segment_reference
    }

    #[must_use]
    pub fn archive_segment_bytes(&self) -> &[u8] {
        &self.archive_segment
    }

    #[must_use]
    pub const fn archive_event_reference(&self) -> WalletArtifactRef {
        self.archive_event_reference
    }

    #[must_use]
    pub fn archive_event_bytes(&self) -> &[u8] {
        &self.archive_event
    }

    #[must_use]
    pub const fn terminal_ledger_reference(&self) -> WalletArtifactRef {
        self.terminal_ledger_reference
    }

    #[must_use]
    pub fn terminal_ledger_bytes(&self) -> &[u8] {
        &self.terminal_ledger
    }
}

struct CandidateRegistryEvidenceReader<'a> {
    objects: &'a [DepositPostHandoffExportRegistryEvidenceObject],
    loaded: RefCell<BTreeSet<CompactRegistryObjectRef>>,
}

impl<'a> CandidateRegistryEvidenceReader<'a> {
    fn new(objects: &'a [DepositPostHandoffExportRegistryEvidenceObject]) -> Self {
        Self { objects, loaded: RefCell::new(BTreeSet::new()) }
    }

    fn consumed_exact_object_set(&self) -> bool {
        self.loaded.borrow().len() == self.objects.len()
    }
}

impl CompactRegistryObjectReader for CandidateRegistryEvidenceReader<'_> {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        let object = self
            .objects
            .binary_search_by_key(&reference, |object| object.reference)
            .ok()
            .map(|index| self.objects[index].bytes.clone());
        if object.is_some() {
            self.loaded.borrow_mut().insert(reference);
        }
        Ok(object)
    }
}

fn validate_candidate_archive_object(
    reference: WalletArtifactRef,
    bytes: &[u8],
    wallet: DepositWalletId,
    kind: crate::storage::WalletArtifactKind,
    maximum: usize,
) -> Result<(), DepositStateTransferWireError> {
    if reference.wallet_id() != WalletId(wallet.0)
        || reference.kind() != kind
        || bytes.is_empty()
        || bytes.len() > maximum
        || usize::try_from(reference.plaintext_len()).ok() != Some(bytes.len())
    {
        return Err(DepositStateTransferWireError::InvalidCandidateEvidence);
    }
    reference
        .verify_contents(bytes)
        .map_err(|_| DepositStateTransferWireError::InvalidCandidateEvidence)
}

/// A serving source asks one predecessor member for its vote on one exact export candidate.
///
/// Construction consumes a non-serializable verified candidate, not a raw statement. Every remote
/// request carries the source's already journaled self-vote and the exact bounded evidence body
/// which that vote commits through the statement's content-addressed projections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealRequest {
    version: u16,
    domain: [u8; 16],
    requester: PartyId,
    voter: PartyId,
    statement: DepositPostHandoffExportSealStatement,
    evidence_digest: [u8; 32],
    evidence: DepositPostHandoffExportCandidateEvidence,
    source_self_vote: SignedEnvelope,
}

impl DepositPostHandoffExportSealRequest {
    pub fn new(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        voter: PartyId,
        evidence: DepositPostHandoffExportCandidateEvidence,
        source_self_vote: SignedEnvelope,
    ) -> Result<Self, DepositStateTransferWireError> {
        evidence.validate_for_candidate(candidate)?;
        let statement = candidate.statement().clone();
        let request = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_REQUEST_DOMAIN,
            requester: statement.source_party(),
            voter,
            statement,
            evidence_digest: evidence.digest(),
            evidence,
            source_self_vote,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), DepositStateTransferWireError> {
        validate_seal_statement_shape(&self.statement)?;
        self.evidence.validate_for_statement(&self.statement)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != SEAL_REQUEST_DOMAIN
            || self.requester.0 == 0
            || self.voter.0 == 0
            || self.requester != self.statement.source_party()
            || self.evidence_digest == [0; 32]
            || self.evidence_digest != self.evidence.digest()
            || !source_self_vote_has_exact_shape(&self.statement, &self.source_self_vote)
        {
            return Err(DepositStateTransferWireError::InvalidSealRequest);
        }
        Ok(())
    }

    pub fn validate_verified_candidate(
        &self,
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        source: &CompactEpochRegistry,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate()?;
        source.validate().map_err(|_| DepositStateTransferWireError::InvalidSealRequest)?;
        if candidate.statement() != &self.statement
            || candidate.statement().source() != source.id()
            || source.active().committee().member(self.requester).is_err()
            || source.active().committee().member(self.voter).is_err()
        {
            return Err(DepositStateTransferWireError::WrongCandidateEvidence);
        }
        self.evidence.validate_for_candidate(candidate)?;
        Identity::verify_envelope(
            source.active().committee(),
            self.requester,
            &self.source_self_vote,
        )
        .map_err(|_| DepositStateTransferWireError::InvalidSourceSelfVote)
    }

    /// Reconstruct and authenticate the exact remote-signing candidate from this request.
    ///
    /// `network`, `source`, `handoff`, and `target` are live caller authority. The serialized
    /// statement is compared only after the evidence has independently minted the candidate.
    pub fn verify_and_reconstruct_candidate(
        &self,
        network: [u8; 32],
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedDepositPostHandoffExportCandidate, DepositStateTransferWireError> {
        self.validate()?;
        source.validate().map_err(|_| DepositStateTransferWireError::InvalidSealRequest)?;
        if source.active().committee().member(self.requester).is_err()
            || source.active().committee().member(self.voter).is_err()
        {
            return Err(DepositStateTransferWireError::WrongCandidateEvidence);
        }
        let candidate = self.evidence.verify_and_reconstruct_candidate(
            network,
            self.requester,
            source,
            handoff,
            target,
        )?;
        if candidate.statement() != &self.statement {
            return Err(DepositStateTransferWireError::WrongCandidateEvidence);
        }
        Identity::verify_envelope(
            source.active().committee(),
            self.requester,
            &self.source_self_vote,
        )
        .map_err(|_| DepositStateTransferWireError::InvalidSourceSelfVote)?;
        Ok(candidate)
    }

    #[must_use]
    pub const fn requester(&self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn voter(&self) -> PartyId {
        self.voter
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        &self.statement
    }

    #[must_use]
    pub const fn evidence(&self) -> &DepositPostHandoffExportCandidateEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn source_self_vote(&self) -> &SignedEnvelope {
        &self.source_self_vote
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("validated seal request serializes");
        length_prefixed_hash(SEAL_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate()?;
        encode_bounded(
            self,
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES,
            "post-handoff export seal request",
        )
    }

    pub fn from_bytes(
        authenticated_requester: PartyId,
        local_voter: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES,
            "post-handoff export seal request",
        )?;
        request.validate()?;
        if request.requester != authenticated_requester || request.voter != local_voter {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        Ok(request)
    }
}

fn source_self_vote_has_exact_shape(
    statement: &DepositPostHandoffExportSealStatement,
    vote: &SignedEnvelope,
) -> bool {
    vote.from == statement.source_party()
        && vote.to.is_none()
        && vote.session == statement.session()
        && vote.sequence == statement.final_export().terminal_checkpoint().sequence()
        && vote.payload == statement.signing_payload()
}

/// Exact receipt for a durably accepted seal solicitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealRequestAck {
    version: u16,
    domain: [u8; 16],
    request: [u8; 32],
    statement: [u8; 32],
    requester: PartyId,
    voter: PartyId,
}

impl DepositPostHandoffExportSealRequestAck {
    pub fn issue(
        request: &DepositPostHandoffExportSealRequest,
    ) -> Result<Self, DepositStateTransferWireError> {
        request.validate()?;
        Ok(Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_REQUEST_ACK_DOMAIN,
            request: request.digest(),
            statement: request.statement.digest(),
            requester: request.requester,
            voter: request.voter,
        })
    }

    fn validate_for(
        self,
        request: &DepositPostHandoffExportSealRequest,
    ) -> Result<(), DepositStateTransferWireError> {
        request.validate()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != SEAL_REQUEST_ACK_DOMAIN
            || self.request != request.digest()
            || self.statement != request.statement.digest()
            || self.requester != request.requester
            || self.voter != request.voter
        {
            return Err(DepositStateTransferWireError::InvalidSealRequestAck);
        }
        Ok(())
    }

    pub fn to_bytes(
        self,
        request: &DepositPostHandoffExportSealRequest,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(request)?;
        encode_bounded(
            &self,
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_ACK_BYTES,
            "post-handoff export seal request acknowledgement",
        )
    }

    pub fn from_bytes(
        request: &DepositPostHandoffExportSealRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let acknowledgement: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_ACK_BYTES,
            "post-handoff export seal request acknowledgement",
        )?;
        acknowledgement.validate_for(request)?;
        Ok(acknowledgement)
    }
}

/// One predecessor member's exact vote for a prior seal request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealVote {
    version: u16,
    domain: [u8; 16],
    request: [u8; 32],
    statement: [u8; 32],
    requester: PartyId,
    voter: PartyId,
    target_epoch: u64,
    envelope: SignedEnvelope,
}

impl DepositPostHandoffExportSealVote {
    pub fn new(
        request: &DepositPostHandoffExportSealRequest,
        envelope: SignedEnvelope,
    ) -> Result<Self, DepositStateTransferWireError> {
        request.validate()?;
        let vote = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_VOTE_DOMAIN,
            request: request.digest(),
            statement: request.statement.digest(),
            requester: request.requester,
            voter: request.voter,
            target_epoch: request.statement.target_epoch(),
            envelope,
        };
        vote.validate_for(request)?;
        Ok(vote)
    }

    fn validate_for(
        &self,
        request: &DepositPostHandoffExportSealRequest,
    ) -> Result<(), DepositStateTransferWireError> {
        request.validate()?;
        let statement = &request.statement;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != SEAL_VOTE_DOMAIN
            || self.request != request.digest()
            || self.statement != statement.digest()
            || self.requester != request.requester
            || self.voter != request.voter
            || self.target_epoch != statement.target_epoch()
            || self.envelope.from != self.voter
            || self.envelope.to.is_some()
            || self.envelope.session != statement.session()
            || self.envelope.sequence != statement.final_export().terminal_checkpoint().sequence()
            || self.envelope.payload != statement.signing_payload()
        {
            return Err(DepositStateTransferWireError::InvalidSealVote);
        }
        Ok(())
    }

    #[must_use]
    pub const fn voter(&self) -> PartyId {
        self.voter
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub const fn envelope(&self) -> &SignedEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("validated seal vote serializes");
        length_prefixed_hash(SEAL_VOTE_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(
        &self,
        request: &DepositPostHandoffExportSealRequest,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(request)?;
        encode_bounded(
            self,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
            "post-handoff export seal vote",
        )
    }

    pub fn from_bytes(
        request: &DepositPostHandoffExportSealRequest,
        authenticated_voter: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let vote: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
            "post-handoff export seal vote",
        )?;
        vote.validate_for(request)?;
        if vote.voter != authenticated_voter {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        Ok(vote)
    }

    /// Decode only the bounded canonical routing projection needed to locate the durable source
    /// journal. The caller must still authenticate the QUIC peer and call [`Self::from_bytes`]
    /// against the recovered exact request before recording the vote.
    pub fn routing_from_bytes(
        bytes: &[u8],
    ) -> Result<(PartyId, PartyId, u64, [u8; 32]), DepositStateTransferWireError> {
        let vote: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
            "post-handoff export seal vote",
        )?;
        if vote.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || vote.domain != SEAL_VOTE_DOMAIN
            || vote.request == [0; 32]
            || vote.statement == [0; 32]
            || vote.requester.0 == 0
            || vote.voter.0 == 0
            || vote.target_epoch == 0
            || vote.envelope.from != vote.voter
            || vote.envelope.to.is_some()
        {
            return Err(DepositStateTransferWireError::InvalidSealVote);
        }
        Ok((vote.requester, vote.voter, vote.target_epoch, vote.request))
    }
}

/// Exact receipt for a durably recorded seal vote.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealVoteAck {
    version: u16,
    domain: [u8; 16],
    vote: [u8; 32],
    request: [u8; 32],
    requester: PartyId,
    voter: PartyId,
}

impl DepositPostHandoffExportSealVoteAck {
    pub fn issue(
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
    ) -> Result<Self, DepositStateTransferWireError> {
        vote.validate_for(request)?;
        Ok(Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_VOTE_ACK_DOMAIN,
            vote: vote.digest(),
            request: request.digest(),
            requester: request.requester,
            voter: vote.voter,
        })
    }

    fn validate_for(
        self,
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
    ) -> Result<(), DepositStateTransferWireError> {
        vote.validate_for(request)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != SEAL_VOTE_ACK_DOMAIN
            || self.vote != vote.digest()
            || self.request != request.digest()
            || self.requester != request.requester
            || self.voter != vote.voter
        {
            return Err(DepositStateTransferWireError::InvalidSealVoteAck);
        }
        Ok(())
    }

    pub fn to_bytes(
        self,
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(request, vote)?;
        encode_bounded(
            &self,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_ACK_BYTES,
            "post-handoff export seal vote acknowledgement",
        )
    }

    pub fn from_bytes(
        request: &DepositPostHandoffExportSealRequest,
        vote: &DepositPostHandoffExportSealVote,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let acknowledgement: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_ACK_BYTES,
            "post-handoff export seal vote acknowledgement",
        )?;
        acknowledgement.validate_for(request, vote)?;
        Ok(acknowledgement)
    }
}

/// Delivery of one already verified exact old-quorum seal to a predecessor or target replica.
///
/// The wire shape deliberately permits either committee. The receiving service must authenticate
/// `recipient` as a member of the exact predecessor committee or the exact handoff target
/// committee before installing the delivery. Target delivery seeds the durable pre-`ExportHead`
/// import intent; predecessor delivery keeps the immutable export live.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealCertificateDelivery {
    version: u16,
    domain: [u8; 16],
    source: PartyId,
    recipient: PartyId,
    semantic_transition: [u8; 32],
    statement: [u8; 32],
    certificate_digest: [u8; 32],
    certificate: DepositPostHandoffExportSealCertificate,
}

impl DepositPostHandoffExportSealCertificateDelivery {
    pub fn from_verified(
        seal: &VerifiedDepositPostHandoffExportSeal,
        recipient: PartyId,
    ) -> Result<Self, DepositStateTransferWireError> {
        let statement = seal.statement();
        let delivery = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_CERTIFICATE_DOMAIN,
            source: statement.source_party(),
            recipient,
            semantic_transition: statement.semantic_transition_digest(),
            statement: seal.statement_digest(),
            certificate_digest: seal.certificate_digest(),
            certificate: seal.certificate().clone(),
        };
        delivery.validate_shape()?;
        delivery.validate_verified_seal(seal)?;
        Ok(delivery)
    }

    fn validate_shape(&self) -> Result<(), DepositStateTransferWireError> {
        let certificate_bytes = self.certificate.to_bytes()?;
        let statement = self.certificate.statement();
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != SEAL_CERTIFICATE_DOMAIN
            || self.source.0 == 0
            || self.recipient.0 == 0
            || self.source != statement.source_party()
            || self.semantic_transition != statement.semantic_transition_digest()
            || self.statement != statement.digest()
            || self.certificate_digest != self.certificate.digest()?
            || certificate_bytes.is_empty()
        {
            return Err(DepositStateTransferWireError::InvalidSealCertificateDelivery);
        }
        Ok(())
    }

    pub fn validate_verified_seal(
        &self,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_shape()?;
        self.validate_verified_seal_parts(
            seal.certificate(),
            seal.statement_digest(),
            seal.certificate_digest(),
            seal.statement().semantic_transition_digest(),
        )
    }

    /// Validate this delivery against a cold target's bounded pre-import read authority.
    ///
    /// This is an exact certificate comparison only. It neither converts the token into a full
    /// seal nor authorizes import, registry CAS, readiness, or a `StateImported` acknowledgement.
    pub(crate) fn validate_pre_import_verified_seal(
        &self,
        seal: &VerifiedPreImportDepositStateExportSeal,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_shape()?;
        self.validate_verified_seal_parts(
            seal.certificate(),
            seal.statement_digest(),
            seal.certificate_digest(),
            seal.statement().semantic_transition_digest(),
        )
    }

    fn validate_verified_seal_parts(
        &self,
        certificate: &DepositPostHandoffExportSealCertificate,
        statement_digest: [u8; 32],
        certificate_digest: [u8; 32],
        semantic_transition: [u8; 32],
    ) -> Result<(), DepositStateTransferWireError> {
        if &self.certificate != certificate
            || self.statement != statement_digest
            || self.certificate_digest != certificate_digest
            || self.semantic_transition != semantic_transition
        {
            return Err(DepositStateTransferWireError::WrongVerifiedSeal);
        }
        Ok(())
    }

    #[must_use]
    pub const fn source(&self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn recipient(&self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn certificate(&self) -> &DepositPostHandoffExportSealCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(self).expect("validated seal certificate delivery serializes");
        length_prefixed_hash(SEAL_CERTIFICATE_DELIVERY_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_shape()?;
        encode_bounded(
            self,
            MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES,
            "post-handoff export seal certificate delivery",
        )
    }

    pub fn from_bytes(
        authenticated_source: PartyId,
        local_recipient: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let delivery: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES,
            "post-handoff export seal certificate delivery",
        )?;
        delivery.validate_shape()?;
        if delivery.source != authenticated_source || delivery.recipient != local_recipient {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        Ok(delivery)
    }
}

/// Exact receipt for a durably recorded seal certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealCertificateAck {
    version: u16,
    domain: [u8; 16],
    delivery: [u8; 32],
    semantic_transition: [u8; 32],
    statement: [u8; 32],
    certificate: [u8; 32],
    source: PartyId,
    recipient: PartyId,
}

impl DepositPostHandoffExportSealCertificateAck {
    pub fn issue(
        delivery: &DepositPostHandoffExportSealCertificateDelivery,
    ) -> Result<Self, DepositStateTransferWireError> {
        delivery.validate_shape()?;
        Ok(Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_CERTIFICATE_ACK_DOMAIN,
            delivery: delivery.digest(),
            semantic_transition: delivery.semantic_transition,
            statement: delivery.statement,
            certificate: delivery.certificate_digest,
            source: delivery.source,
            recipient: delivery.recipient,
        })
    }

    fn validate_for(
        self,
        delivery: &DepositPostHandoffExportSealCertificateDelivery,
    ) -> Result<(), DepositStateTransferWireError> {
        delivery.validate_shape()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != SEAL_CERTIFICATE_ACK_DOMAIN
            || self.delivery != delivery.digest()
            || self.semantic_transition != delivery.semantic_transition
            || self.statement != delivery.statement
            || self.certificate != delivery.certificate_digest
            || self.source != delivery.source
            || self.recipient != delivery.recipient
        {
            return Err(DepositStateTransferWireError::InvalidSealCertificateAck);
        }
        Ok(())
    }

    pub fn to_bytes(
        self,
        delivery: &DepositPostHandoffExportSealCertificateDelivery,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(delivery)?;
        encode_bounded(
            &self,
            MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_ACK_BYTES,
            "post-handoff export seal certificate acknowledgement",
        )
    }

    pub fn from_bytes(
        delivery: &DepositPostHandoffExportSealCertificateDelivery,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let acknowledgement: Self = decode_canonical_bounded(
            bytes,
            MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_ACK_BYTES,
            "post-handoff export seal certificate acknowledgement",
        )?;
        acknowledgement.validate_for(delivery)?;
        Ok(acknowledgement)
    }
}

/// Request one exact certified historical export from one predecessor source.
///
/// `nonce` is generated once by the requester and persisted with the request.  Retrying the exact
/// request therefore replays the same durable source lease, while a new request cannot alias an
/// earlier requester slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportHeadRequest {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    semantic_transition: [u8; 32],
    source: PartyId,
    requester: PartyId,
    nonce: [u8; 32],
}

impl DepositStateExportHeadRequest {
    pub fn new(
        context: DepositStateTransferContext,
        semantic_transition: [u8; 32],
        source: PartyId,
        requester: PartyId,
        nonce: [u8; 32],
    ) -> Result<Self, DepositStateTransferWireError> {
        let request = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_HEAD_REQUEST_DOMAIN,
            context,
            semantic_transition,
            source,
            requester,
            nonce,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), DepositStateTransferWireError> {
        self.context.validate()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_HEAD_REQUEST_DOMAIN
            || self.semantic_transition == [0; 32]
            || self.source.0 == 0
            || self.requester.0 == 0
            || self.nonce == [0; 32]
        {
            return Err(DepositStateTransferWireError::InvalidExportHeadRequest);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub const fn semantic_transition_digest(self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("validated export head request serializes");
        length_prefixed_hash(EXPORT_HEAD_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate()?;
        encode_bounded(
            &self,
            MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES,
            "deposit state export head request",
        )
    }

    pub fn from_bytes(
        authenticated_source: PartyId,
        authenticated_requester: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES,
            "deposit state export head request",
        )?;
        request.validate()?;
        if request.source != authenticated_source || request.requester != authenticated_requester {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        Ok(request)
    }
}

/// Opaque source-issued authority for one exact old-quorum-certified export graph.
///
/// The serialized lease contains every security-relevant binding, but its tag can only be checked
/// by the named source.  Requesters persist and echo it as an opaque capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportLease {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    head_request: [u8; 32],
    request_nonce: [u8; 32],
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate: [u8; 32],
    advertisement: [u8; 32],
    anchor: DepositSyncObjectAnchor,
    portable_root: Option<DepositIndexObjectId>,
    portable_head: [u8; 32],
    source: PartyId,
    requester: PartyId,
    tag: [u8; 32],
}

impl DepositStateExportLease {
    fn issue(
        mac_key: &[u8; 32],
        request: DepositStateExportHeadRequest,
        advertisement: &DepositSyncAdvertisement,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<Self, DepositStateTransferWireError> {
        reject_zero_mac_key(mac_key)?;
        request.validate()?;
        advertisement.to_bytes()?;
        request.context.validate_sync_context(advertisement.context())?;
        let statement = seal.statement();
        let transition = VerifiedStateImportTransitionBinding::from_verified_export_seal(seal)?;
        statement.final_export().validate_advertisement(advertisement)?;
        if statement.network() != request.context.network
            || statement.source().wallet() != request.context.wallet
            || statement.source_party() != request.source
            || statement.semantic_transition_digest() != request.semantic_transition
            || transition.network() != request.context.network
            || transition.wallet() != request.context.wallet
            || transition.source_party() != request.source
        {
            return Err(DepositStateTransferWireError::WrongVerifiedSeal);
        }
        let anchor = advertisement.object_anchor();
        let mut lease = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_LEASE_DOMAIN,
            context: request.context,
            head_request: request.digest(),
            request_nonce: request.nonce,
            semantic_transition: request.semantic_transition,
            transition_binding: transition.transition_binding(),
            seal_statement: seal.statement_digest(),
            seal_certificate: seal.certificate_digest(),
            advertisement: advertisement.digest(),
            anchor,
            portable_root: anchor.portable_root(),
            portable_head: anchor.portable_index_digest(),
            source: request.source,
            requester: request.requester,
            tag: [0; 32],
        };
        lease.validate_for(request, advertisement)?;
        lease.validate_verified_seal(seal)?;
        lease.tag = export_lease_mac(mac_key, &lease)?;
        Ok(lease)
    }

    fn validate_structure(self) -> Result<(), DepositStateTransferWireError> {
        self.context.validate()?;
        let sync_context = DepositSyncContext::new(self.context.network, self.context.wallet)?;
        self.anchor.validate_context(sync_context)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_LEASE_DOMAIN
            || self.head_request == [0; 32]
            || self.request_nonce == [0; 32]
            || self.semantic_transition == [0; 32]
            || self.transition_binding == [0; 32]
            || self.seal_statement == [0; 32]
            || self.seal_certificate == [0; 32]
            || self.advertisement == [0; 32]
            || self.advertisement != self.anchor.advertisement_digest()
            || self.portable_root != self.anchor.portable_root()
            || self.portable_head == [0; 32]
            || self.portable_head != self.anchor.portable_index_digest()
            || self.source.0 == 0
            || self.requester.0 == 0
        {
            return Err(DepositStateTransferWireError::InvalidExportLease);
        }
        Ok(())
    }

    fn validate_for(
        self,
        request: DepositStateExportHeadRequest,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_structure()?;
        request.validate()?;
        advertisement.to_bytes()?;
        request.context.validate_sync_context(advertisement.context())?;
        if self.context != request.context
            || self.head_request != request.digest()
            || self.request_nonce != request.nonce
            || self.semantic_transition != request.semantic_transition
            || self.advertisement != advertisement.digest()
            || self.anchor != advertisement.object_anchor()
            || self.portable_root != advertisement.portable_index().root()
            || self.portable_head != advertisement.portable_index().digest()
            || self.source != request.source
            || self.requester != request.requester
        {
            return Err(DepositStateTransferWireError::InvalidExportLease);
        }
        Ok(())
    }

    fn validate_verified_seal(
        self,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<(), DepositStateTransferWireError> {
        let transition = VerifiedStateImportTransitionBinding::from_verified_export_seal(seal)?;
        self.validate_verified_seal_parts(
            seal.statement(),
            seal.statement_digest(),
            seal.certificate_digest(),
            transition,
        )
    }

    /// Validate this opaque read lease against the cold target's exact old-quorum authority.
    ///
    /// Success authorizes only bounded pre-import export reads. It does not authorize graph
    /// adoption, registry CAS, target readiness, or a `StateImported` acknowledgement.
    pub(crate) fn validate_pre_import_verified_seal(
        self,
        seal: &VerifiedPreImportDepositStateExportSeal,
    ) -> Result<(), DepositStateTransferWireError> {
        let transition =
            VerifiedStateImportTransitionBinding::from_verified_pre_import_export_seal(seal)?;
        self.validate_verified_seal_parts(
            seal.statement(),
            seal.statement_digest(),
            seal.certificate_digest(),
            transition,
        )
    }

    fn validate_verified_seal_parts(
        self,
        statement: &DepositPostHandoffExportSealStatement,
        statement_digest: [u8; 32],
        certificate_digest: [u8; 32],
        transition: VerifiedStateImportTransitionBinding,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_structure()?;
        if self.context.network != statement.network()
            || self.context.wallet != statement.source().wallet()
            || self.semantic_transition != statement.semantic_transition_digest()
            || self.transition_binding != transition.transition_binding()
            || self.seal_statement != statement_digest
            || self.seal_certificate != certificate_digest
            || self.advertisement != statement.final_export().advertisement_digest()
            || self.portable_root != statement.final_export().resulting_portable_head().root()
            || self.portable_head != statement.final_export().resulting_portable_head().digest()
            || self.source != statement.source_party()
            || self.source != transition.source_party()
        {
            return Err(DepositStateTransferWireError::WrongVerifiedSeal);
        }
        Ok(())
    }

    /// Authenticate this lease for the exact transport-authenticated parties.
    pub fn authenticate_for(
        self,
        mac_key: &[u8; 32],
        source: PartyId,
        requester: PartyId,
    ) -> Result<(), DepositStateTransferWireError> {
        reject_zero_mac_key(mac_key)?;
        self.validate_structure()?;
        if self.source != source || self.requester != requester {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        let expected = export_lease_mac(mac_key, &self)?;
        if !bool::from(self.tag.ct_eq(&expected)) {
            return Err(DepositStateTransferWireError::InvalidExportLease);
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub const fn head_request_digest(self) -> [u8; 32] {
        self.head_request
    }

    #[must_use]
    pub const fn request_nonce(self) -> [u8; 32] {
        self.request_nonce
    }

    #[must_use]
    pub const fn semantic_transition_digest(self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn transition_binding(self) -> [u8; 32] {
        self.transition_binding
    }

    #[must_use]
    pub const fn seal_statement_digest(self) -> [u8; 32] {
        self.seal_statement
    }

    #[must_use]
    pub const fn seal_certificate_digest(self) -> [u8; 32] {
        self.seal_certificate
    }

    #[must_use]
    pub const fn advertisement_digest(self) -> [u8; 32] {
        self.advertisement
    }

    #[must_use]
    pub const fn anchor(self) -> DepositSyncObjectAnchor {
        self.anchor
    }

    #[must_use]
    pub const fn portable_root(self) -> Option<DepositIndexObjectId> {
        self.portable_root
    }

    #[must_use]
    pub const fn portable_head_digest(self) -> [u8; 32] {
        self.portable_head
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(&self).expect("validated export lease serializes");
        length_prefixed_hash(EXPORT_LEASE_DIGEST_DOMAIN, &bytes)
    }

    pub fn root_targets(
        self,
    ) -> Result<Vec<DepositSyncTraversalTarget>, DepositStateTransferWireError> {
        self.validate_structure()?;
        export_root_targets(self.anchor)
    }

    #[must_use]
    pub fn is_root_target(self, target: DepositSyncTraversalTarget) -> bool {
        self.root_targets().is_ok_and(|roots| roots.contains(&target))
    }
}

/// Full exact seal, advertisement, and independently pinned historical-serving lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportHeadResponse {
    version: u16,
    domain: [u8; 16],
    request: [u8; 32],
    semantic_transition: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate_digest: [u8; 32],
    advertisement_digest: [u8; 32],
    source: PartyId,
    requester: PartyId,
    certificate: DepositPostHandoffExportSealCertificate,
    advertisement: DepositSyncAdvertisement,
    lease: DepositStateExportLease,
}

impl DepositStateExportHeadResponse {
    pub fn issue(
        request: DepositStateExportHeadRequest,
        advertisement: DepositSyncAdvertisement,
        seal: &VerifiedDepositPostHandoffExportSeal,
        mac_key: &[u8; 32],
    ) -> Result<Self, DepositStateTransferWireError> {
        request.validate()?;
        let lease = DepositStateExportLease::issue(mac_key, request, &advertisement, seal)?;
        let response = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_HEAD_RESPONSE_DOMAIN,
            request: request.digest(),
            semantic_transition: seal.statement().semantic_transition_digest(),
            seal_statement: seal.statement_digest(),
            seal_certificate_digest: seal.certificate_digest(),
            advertisement_digest: advertisement.digest(),
            source: request.source,
            requester: request.requester,
            certificate: seal.certificate().clone(),
            advertisement,
            lease,
        };
        response.validate_for(request)?;
        response.validate_verified_seal(request, seal)?;
        Ok(response)
    }

    fn validate_for(
        &self,
        request: DepositStateExportHeadRequest,
    ) -> Result<(), DepositStateTransferWireError> {
        request.validate()?;
        let certificate_bytes = self.certificate.to_bytes()?;
        self.advertisement.to_bytes()?;
        let statement = self.certificate.statement();
        statement.final_export().validate_advertisement(&self.advertisement)?;
        self.lease.validate_for(request, &self.advertisement)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_HEAD_RESPONSE_DOMAIN
            || self.request != request.digest()
            || self.semantic_transition != request.semantic_transition
            || self.semantic_transition != statement.semantic_transition_digest()
            || self.seal_statement != statement.digest()
            || self.seal_certificate_digest != self.certificate.digest()?
            || self.advertisement_digest != self.advertisement.digest()
            || self.advertisement_digest != statement.final_export().advertisement_digest()
            || self.source != request.source
            || self.source != statement.source_party()
            || self.requester != request.requester
            || self.lease.semantic_transition != self.semantic_transition
            || self.lease.seal_statement != self.seal_statement
            || self.lease.seal_certificate != self.seal_certificate_digest
            || self.lease.advertisement != self.advertisement_digest
            || certificate_bytes.is_empty()
        {
            return Err(DepositStateTransferWireError::InvalidExportHeadResponse);
        }
        Ok(())
    }

    /// Upgrade a structurally decoded response with the caller's cryptographically verified seal.
    pub fn validate_verified_seal(
        &self,
        request: DepositStateExportHeadRequest,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_for(request)?;
        self.lease.validate_verified_seal(seal)?;
        self.validate_verified_seal_parts(
            seal.certificate(),
            seal.statement_digest(),
            seal.certificate_digest(),
            seal.statement().semantic_transition_digest(),
        )
    }

    /// Validate a decoded head against the cold target's bounded pre-import read authority.
    ///
    /// This performs the same exact certificate, advertisement, lease, and transition checks as
    /// [`Self::validate_verified_seal`], but cannot authorize import or any durable target-state
    /// transition.
    pub(crate) fn validate_pre_import_verified_seal(
        &self,
        request: DepositStateExportHeadRequest,
        seal: &VerifiedPreImportDepositStateExportSeal,
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate_for(request)?;
        self.lease.validate_pre_import_verified_seal(seal)?;
        self.validate_verified_seal_parts(
            seal.certificate(),
            seal.statement_digest(),
            seal.certificate_digest(),
            seal.statement().semantic_transition_digest(),
        )
    }

    fn validate_verified_seal_parts(
        &self,
        certificate: &DepositPostHandoffExportSealCertificate,
        statement_digest: [u8; 32],
        certificate_digest: [u8; 32],
        semantic_transition: [u8; 32],
    ) -> Result<(), DepositStateTransferWireError> {
        if &self.certificate != certificate
            || self.seal_statement != statement_digest
            || self.seal_certificate_digest != certificate_digest
            || self.semantic_transition != semantic_transition
        {
            return Err(DepositStateTransferWireError::WrongVerifiedSeal);
        }
        Ok(())
    }

    #[must_use]
    pub const fn certificate(&self) -> &DepositPostHandoffExportSealCertificate {
        &self.certificate
    }

    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request
    }

    #[must_use]
    pub const fn advertisement(&self) -> &DepositSyncAdvertisement {
        &self.advertisement
    }

    #[must_use]
    pub const fn lease(&self) -> DepositStateExportLease {
        self.lease
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn seal_statement_digest(&self) -> [u8; 32] {
        self.seal_statement
    }

    #[must_use]
    pub const fn seal_certificate_digest(&self) -> [u8; 32] {
        self.seal_certificate_digest
    }

    #[must_use]
    pub const fn advertisement_digest(&self) -> [u8; 32] {
        self.advertisement_digest
    }

    #[must_use]
    pub const fn source(&self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(&self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("validated export head response serializes");
        length_prefixed_hash(EXPORT_HEAD_RESPONSE_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(
        &self,
        request: DepositStateExportHeadRequest,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(request)?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_EXPORT_HEAD_RESPONSE_BYTES,
            "deposit state export head response",
        )
    }

    /// Decode bounded canonical structure.  This does not verify old-committee signatures.
    pub fn from_bytes(
        request: DepositStateExportHeadRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let response: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_HEAD_RESPONSE_BYTES,
            "deposit state export head response",
        )?;
        response.validate_for(request)?;
        Ok(response)
    }
}

/// Source-local authority for one exact parent-child edge under a certified-export lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportObjectCapability {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate: [u8; 32],
    advertisement: [u8; 32],
    lease: [u8; 32],
    source: PartyId,
    requester: PartyId,
    parent: DepositSyncTraversalTarget,
    child: DepositSyncTraversalTarget,
    tag: [u8; 32],
}

impl DepositStateExportObjectCapability {
    pub fn issue(
        mac_key: &[u8; 32],
        lease: DepositStateExportLease,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    ) -> Result<Self, DepositStateTransferWireError> {
        reject_zero_mac_key(mac_key)?;
        lease.authenticate_for(mac_key, lease.source, lease.requester)?;
        let mut capability = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_OBJECT_CAPABILITY_DOMAIN,
            context: lease.context,
            semantic_transition: lease.semantic_transition,
            transition_binding: lease.transition_binding,
            seal_statement: lease.seal_statement,
            seal_certificate: lease.seal_certificate,
            advertisement: lease.advertisement,
            lease: lease.digest(),
            source: lease.source,
            requester: lease.requester,
            parent,
            child,
            tag: [0; 32],
        };
        capability.validate_binding(lease, parent, child)?;
        capability.tag = export_object_capability_mac(mac_key, &capability)?;
        Ok(capability)
    }

    fn validate_binding(
        self,
        lease: DepositStateExportLease,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    ) -> Result<(), DepositStateTransferWireError> {
        lease.validate_structure()?;
        validate_export_target(lease, parent)?;
        validate_export_target(lease, child)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_OBJECT_CAPABILITY_DOMAIN
            || self.context != lease.context
            || self.semantic_transition != lease.semantic_transition
            || self.transition_binding != lease.transition_binding
            || self.seal_statement != lease.seal_statement
            || self.seal_certificate != lease.seal_certificate
            || self.advertisement != lease.advertisement
            || self.lease != lease.digest()
            || self.source != lease.source
            || self.requester != lease.requester
            || self.parent != parent
            || self.child != child
            || self.parent == self.child
        {
            return Err(DepositStateTransferWireError::InvalidExportObjectCapability);
        }
        Ok(())
    }

    pub fn authenticate_for(
        self,
        mac_key: &[u8; 32],
        lease: DepositStateExportLease,
        parent: DepositSyncTraversalTarget,
        child: DepositSyncTraversalTarget,
    ) -> Result<(), DepositStateTransferWireError> {
        reject_zero_mac_key(mac_key)?;
        self.validate_binding(lease, parent, child)?;
        let expected = export_object_capability_mac(mac_key, &self)?;
        if !bool::from(self.tag.ct_eq(&expected)) {
            return Err(DepositStateTransferWireError::InvalidExportObjectCapability);
        }
        Ok(())
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn parent(self) -> DepositSyncTraversalTarget {
        self.parent
    }

    #[must_use]
    pub const fn child(self) -> DepositSyncTraversalTarget {
        self.child
    }
}

/// One exact certified-export object request entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportObjectRequestEntry {
    target: DepositSyncTraversalTarget,
    capability: Option<DepositStateExportObjectCapability>,
}

impl DepositStateExportObjectRequestEntry {
    pub fn advertised_root(
        lease: DepositStateExportLease,
        target: DepositSyncTraversalTarget,
    ) -> Result<Self, DepositStateTransferWireError> {
        lease.validate_structure()?;
        validate_export_target(lease, target)?;
        if !lease.is_root_target(target) {
            return Err(DepositStateTransferWireError::InvalidExportObjectRequest);
        }
        Ok(Self { target, capability: None })
    }

    #[must_use]
    pub const fn authorized(capability: DepositStateExportObjectCapability) -> Self {
        Self { target: capability.child, capability: Some(capability) }
    }

    #[must_use]
    pub const fn target(self) -> DepositSyncTraversalTarget {
        self.target
    }

    #[must_use]
    pub const fn reference(self) -> DepositSyncObjectRef {
        self.target.reference()
    }

    #[must_use]
    pub const fn capability(self) -> Option<DepositStateExportObjectCapability> {
        self.capability
    }
}

/// One cursorless, hard-bounded certified-export object page request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportObjectsRequest {
    version: u16,
    domain: [u8; 16],
    lease: DepositStateExportLease,
    #[serde(deserialize_with = "deserialize_export_object_request_entries")]
    entries: Vec<DepositStateExportObjectRequestEntry>,
}

impl DepositStateExportObjectsRequest {
    pub fn new(
        lease: DepositStateExportLease,
        entries: Vec<DepositStateExportObjectRequestEntry>,
    ) -> Result<Self, DepositStateTransferWireError> {
        let request = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_OBJECT_REQUEST_DOMAIN,
            lease,
            entries,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate shape without trusting the opaque source-local MAC tags.
    pub fn validate(&self) -> Result<(), DepositStateTransferWireError> {
        self.lease.validate_structure()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_OBJECT_REQUEST_DOMAIN
            || self.entries.is_empty()
            || self.entries.len() > MAX_DEPOSIT_SYNC_REQUEST_OBJECTS
        {
            return Err(DepositStateTransferWireError::InvalidExportObjectRequest);
        }
        let mut targets = BTreeSet::new();
        let mut plaintext_bytes = 0_usize;
        for entry in &self.entries {
            validate_export_target(self.lease, entry.target)?;
            if !targets.insert(entry.target) {
                return Err(DepositStateTransferWireError::InvalidExportObjectRequest);
            }
            plaintext_bytes = plaintext_bytes
                .checked_add(
                    usize::try_from(entry.reference().plaintext_len())
                        .map_err(|_| DepositStateTransferWireError::InvalidExportObjectRequest)?,
                )
                .ok_or(DepositStateTransferWireError::InvalidExportObjectRequest)?;
            if self.lease.is_root_target(entry.target) {
                if entry.capability.is_some() {
                    return Err(DepositStateTransferWireError::InvalidExportObjectRequest);
                }
            } else {
                let capability = entry
                    .capability
                    .ok_or(DepositStateTransferWireError::InvalidExportObjectCapability)?;
                capability.validate_binding(self.lease, capability.parent, entry.target)?;
            }
        }
        if plaintext_bytes > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES {
            return Err(DepositStateTransferWireError::InvalidExportObjectRequest);
        }
        Ok(())
    }

    /// Authenticate the lease and every non-root capability at the serving source.
    pub fn authenticate_capabilities(
        &self,
        source: PartyId,
        requester: PartyId,
        mac_key: &[u8; 32],
    ) -> Result<(), DepositStateTransferWireError> {
        self.validate()?;
        self.lease.authenticate_for(mac_key, source, requester)?;
        for entry in &self.entries {
            if let Some(capability) = entry.capability {
                capability.authenticate_for(
                    mac_key,
                    self.lease,
                    capability.parent,
                    entry.target,
                )?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn context(&self) -> DepositStateTransferContext {
        self.lease.context
    }

    #[must_use]
    pub const fn lease(&self) -> DepositStateExportLease {
        self.lease
    }

    #[must_use]
    pub const fn source(&self) -> PartyId {
        self.lease.source
    }

    #[must_use]
    pub const fn requester(&self) -> PartyId {
        self.lease.requester
    }

    #[must_use]
    pub fn entries(&self) -> &[DepositStateExportObjectRequestEntry] {
        &self.entries
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(self).expect("validated export object request serializes");
        length_prefixed_hash(EXPORT_OBJECT_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES,
            "deposit state export object request",
        )
    }

    pub fn from_bytes(
        source: PartyId,
        requester: PartyId,
        mac_key: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES,
            "deposit state export object request",
        )?;
        request.authenticate_capabilities(source, requester, mac_key)?;
        Ok(request)
    }

    /// Decode only bounded canonical routing data.  The handler must immediately call
    /// [`Self::from_bytes`] with the selected source's stable MAC key.
    pub fn context_from_bytes(
        bytes: &[u8],
    ) -> Result<DepositStateTransferContext, DepositStateTransferWireError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES,
            "deposit state export object request",
        )?;
        request.validate()?;
        Ok(request.context())
    }
}

/// Exact request-bound object page plus source-local child capabilities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportObjectsResponse {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    semantic_transition: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate: [u8; 32],
    advertisement: [u8; 32],
    lease: [u8; 32],
    source: PartyId,
    requester: PartyId,
    request: [u8; 32],
    #[serde(deserialize_with = "deserialize_export_objects")]
    objects: Vec<DepositSyncObject>,
    #[serde(deserialize_with = "deserialize_export_object_capabilities")]
    capabilities: Vec<DepositStateExportObjectCapability>,
}

impl DepositStateExportObjectsResponse {
    pub fn build(
        request: &DepositStateExportObjectsRequest,
        objects: Vec<DepositSyncObject>,
        capabilities: Vec<DepositStateExportObjectCapability>,
    ) -> Result<Self, DepositStateTransferWireError> {
        let lease = request.lease;
        let response = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_OBJECT_RESPONSE_DOMAIN,
            context: lease.context,
            semantic_transition: lease.semantic_transition,
            seal_statement: lease.seal_statement,
            seal_certificate: lease.seal_certificate,
            advertisement: lease.advertisement,
            lease: lease.digest(),
            source: lease.source,
            requester: lease.requester,
            request: request.digest(),
            objects,
            capabilities,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    pub fn validate_for(
        &self,
        request: &DepositStateExportObjectsRequest,
    ) -> Result<(), DepositStateTransferWireError> {
        request.validate()?;
        let lease = request.lease;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_OBJECT_RESPONSE_DOMAIN
            || self.context != lease.context
            || self.semantic_transition != lease.semantic_transition
            || self.seal_statement != lease.seal_statement
            || self.seal_certificate != lease.seal_certificate
            || self.advertisement != lease.advertisement
            || self.lease != lease.digest()
            || self.source != lease.source
            || self.requester != lease.requester
            || self.request != request.digest()
            || self.objects.len() != request.entries.len()
            || self.objects.len() > MAX_DEPOSIT_SYNC_PAGE_OBJECTS
            || self.capabilities.len() > MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES
        {
            return Err(DepositStateTransferWireError::InvalidExportObjectResponse);
        }

        let mut expected_edges = BTreeSet::new();
        let mut plaintext_bytes = 0_usize;
        for (object, entry) in self.objects.iter().zip(&request.entries) {
            if object.reference() != entry.reference() {
                return Err(DepositStateTransferWireError::InvalidExportObjectResponse);
            }
            let rebuilt = DepositSyncObject::new(object.reference(), object.bytes().to_vec())?;
            if &rebuilt != object {
                return Err(DepositStateTransferWireError::InvalidExportObjectResponse);
            }
            for child in object.authenticated_semantic_children(entry.target)? {
                validate_export_target(lease, child)?;
                expected_edges.insert((entry.target, child));
            }
            plaintext_bytes = plaintext_bytes
                .checked_add(object.bytes().len())
                .ok_or(DepositStateTransferWireError::InvalidExportObjectResponse)?;
        }
        if plaintext_bytes > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES {
            return Err(DepositStateTransferWireError::InvalidExportObjectResponse);
        }

        let mut edges = BTreeSet::new();
        for capability in &self.capabilities {
            capability.validate_binding(lease, capability.parent, capability.child)?;
            if !edges.insert((capability.parent, capability.child)) {
                return Err(DepositStateTransferWireError::InvalidExportObjectResponse);
            }
        }
        if edges != expected_edges {
            return Err(DepositStateTransferWireError::InvalidExportObjectResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn objects(&self) -> &[DepositSyncObject] {
        &self.objects
    }

    #[must_use]
    pub fn capabilities(&self) -> &[DepositStateExportObjectCapability] {
        &self.capabilities
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(self).expect("validated export object response serializes");
        length_prefixed_hash(EXPORT_OBJECT_RESPONSE_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(
        &self,
        request: &DepositStateExportObjectsRequest,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(request)?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_RESPONSE_BYTES,
            "deposit state export object response",
        )
    }

    pub fn from_bytes(
        request: &DepositStateExportObjectsRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let response: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_RESPONSE_BYTES,
            "deposit state export object response",
        )?;
        response.validate_for(request)?;
        Ok(response)
    }
}

/// Storage-routing projection for an exact certified-export release.
///
/// This projection is bounded and canonical but not MAC-authenticated.  It exists so the server
/// can select the cold source store before service initialization; the selected store must still
/// decode the same bytes with [`DepositStateExportReleaseRequest::from_bytes`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositStateExportReleaseRouting {
    context: DepositStateTransferContext,
    source: PartyId,
    requester: PartyId,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate: [u8; 32],
    advertisement: [u8; 32],
    portable_root: Option<DepositIndexObjectId>,
    portable_head: [u8; 32],
    lease: [u8; 32],
}

impl DepositStateExportReleaseRouting {
    fn from_lease(lease: DepositStateExportLease) -> Self {
        Self {
            context: lease.context,
            source: lease.source,
            requester: lease.requester,
            semantic_transition: lease.semantic_transition,
            transition_binding: lease.transition_binding,
            seal_statement: lease.seal_statement,
            seal_certificate: lease.seal_certificate,
            advertisement: lease.advertisement,
            portable_root: lease.portable_root,
            portable_head: lease.portable_head,
            lease: lease.digest(),
        }
    }

    #[must_use]
    pub const fn context(self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub const fn requester(self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub const fn semantic_transition_digest(self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn transition_binding(self) -> [u8; 32] {
        self.transition_binding
    }

    #[must_use]
    pub const fn seal_statement_digest(self) -> [u8; 32] {
        self.seal_statement
    }

    #[must_use]
    pub const fn seal_certificate_digest(self) -> [u8; 32] {
        self.seal_certificate
    }

    #[must_use]
    pub const fn advertisement_digest(self) -> [u8; 32] {
        self.advertisement
    }

    #[must_use]
    pub const fn portable_root(self) -> Option<DepositIndexObjectId> {
        self.portable_root
    }

    #[must_use]
    pub const fn portable_head_digest(self) -> [u8; 32] {
        self.portable_head
    }

    #[must_use]
    pub const fn lease_digest(self) -> [u8; 32] {
        self.lease
    }
}

/// Full exact lease release.  Replaying it after a committed release is successful and harmless.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportReleaseRequest {
    version: u16,
    domain: [u8; 16],
    lease: DepositStateExportLease,
}

impl DepositStateExportReleaseRequest {
    pub fn new(lease: DepositStateExportLease) -> Result<Self, DepositStateTransferWireError> {
        let request = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_RELEASE_REQUEST_DOMAIN,
            lease,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), DepositStateTransferWireError> {
        self.lease.validate_structure()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_RELEASE_REQUEST_DOMAIN
        {
            return Err(DepositStateTransferWireError::InvalidExportReleaseRequest);
        }
        Ok(())
    }

    #[must_use]
    pub const fn lease(self) -> DepositStateExportLease {
        self.lease
    }

    #[must_use]
    pub fn routing(self) -> DepositStateExportReleaseRouting {
        DepositStateExportReleaseRouting::from_lease(self.lease)
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(&self).expect("validated export release request serializes");
        length_prefixed_hash(EXPORT_RELEASE_REQUEST_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate()?;
        encode_bounded(
            &self,
            MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES,
            "deposit state export release request",
        )
    }

    pub fn from_bytes(
        source: PartyId,
        requester: PartyId,
        mac_key: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES,
            "deposit state export release request",
        )?;
        request.validate()?;
        request.lease.authenticate_for(mac_key, source, requester)?;
        Ok(request)
    }

    pub fn routing_from_bytes(
        bytes: &[u8],
    ) -> Result<DepositStateExportReleaseRouting, DepositStateTransferWireError> {
        let request: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES,
            "deposit state export release request",
        )?;
        request.validate()?;
        Ok(request.routing())
    }
}

/// Exact/idempotent source-store release disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositStateExportReleaseDisposition {
    Released,
    AlreadyReleased,
}

/// Request-bound release acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportReleaseAck {
    version: u16,
    domain: [u8; 16],
    request: [u8; 32],
    lease: [u8; 32],
    context: DepositStateTransferContext,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    source: PartyId,
    requester: PartyId,
    disposition: DepositStateExportReleaseDisposition,
}

impl DepositStateExportReleaseAck {
    pub fn issue(
        request: DepositStateExportReleaseRequest,
        disposition: DepositStateExportReleaseDisposition,
    ) -> Result<Self, DepositStateTransferWireError> {
        request.validate()?;
        let lease = request.lease;
        Ok(Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: EXPORT_RELEASE_ACK_DOMAIN,
            request: request.digest(),
            lease: lease.digest(),
            context: lease.context,
            semantic_transition: lease.semantic_transition,
            transition_binding: lease.transition_binding,
            source: lease.source,
            requester: lease.requester,
            disposition,
        })
    }

    fn validate_for(
        self,
        request: DepositStateExportReleaseRequest,
    ) -> Result<(), DepositStateTransferWireError> {
        request.validate()?;
        let lease = request.lease;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != EXPORT_RELEASE_ACK_DOMAIN
            || self.request != request.digest()
            || self.lease != lease.digest()
            || self.context != lease.context
            || self.semantic_transition != lease.semantic_transition
            || self.transition_binding != lease.transition_binding
            || self.source != lease.source
            || self.requester != lease.requester
        {
            return Err(DepositStateTransferWireError::InvalidExportReleaseAck);
        }
        Ok(())
    }

    #[must_use]
    pub const fn disposition(self) -> DepositStateExportReleaseDisposition {
        self.disposition
    }

    pub fn to_bytes(
        self,
        request: DepositStateExportReleaseRequest,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(request)?;
        encode_bounded(
            &self,
            MAX_DEPOSIT_STATE_EXPORT_RELEASE_ACK_BYTES,
            "deposit state export release acknowledgement",
        )
    }

    pub fn from_bytes(
        request: DepositStateExportReleaseRequest,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let acknowledgement: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_EXPORT_RELEASE_ACK_BYTES,
            "deposit state export release acknowledgement",
        )?;
        acknowledgement.validate_for(request)?;
        Ok(acknowledgement)
    }
}

/// One exact target-member acknowledgement bound to its already-journaled semantic statement.
///
/// The full statement is intentionally not retransmitted on this route: the transport cap is the
/// canonical acknowledgement plus fixed framing.  The recipient looks up the exact statement by
/// `transition_binding` and must call [`Self::verify_for_statement`] before recording the ACK.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateImportedAckDelivery {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    sender: PartyId,
    recipient: PartyId,
    target_epoch: u64,
    transition_binding: [u8; 32],
    statement_digest: [u8; 32],
    acknowledgement_digest: [u8; 32],
    #[serde(deserialize_with = "deserialize_import_ack_bytes")]
    acknowledgement: Vec<u8>,
}

impl DepositStateImportedAckDelivery {
    pub fn new(
        statement: &DepositStateImportedStatement,
        acknowledgement: &DepositStateImportedAck,
        recipient: PartyId,
    ) -> Result<Self, DepositStateTransferWireError> {
        let sender = acknowledgement.verify(statement)?;
        let acknowledgement_bytes = acknowledgement.to_bytes(statement)?;
        let context = DepositStateTransferContext::new(statement.network(), statement.wallet())?;
        let delivery = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: IMPORT_ACK_DELIVERY_DOMAIN,
            context,
            sender,
            recipient,
            target_epoch: statement.target_epoch(),
            transition_binding: statement.transition_binding(),
            statement_digest: statement.digest(),
            acknowledgement_digest: exact_bytes_digest(&acknowledgement_bytes),
            acknowledgement: acknowledgement_bytes,
        };
        delivery.validate_shape()?;
        delivery.verify_for_statement(statement)?;
        Ok(delivery)
    }

    fn validate_shape(&self) -> Result<(), DepositStateTransferWireError> {
        self.context.validate()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != IMPORT_ACK_DELIVERY_DOMAIN
            || self.sender.0 == 0
            || self.recipient.0 == 0
            || self.target_epoch == 0
            || self.transition_binding == [0; 32]
            || self.statement_digest == [0; 32]
            || self.acknowledgement.is_empty()
            || self.acknowledgement.len() > MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES
            || self.acknowledgement_digest != exact_bytes_digest(&self.acknowledgement)
        {
            return Err(DepositStateTransferWireError::InvalidImportedAckDelivery);
        }
        Ok(())
    }

    /// Rehydrate and authenticate the ACK against the exact locally journaled statement.
    pub fn verify_for_statement(
        &self,
        statement: &DepositStateImportedStatement,
    ) -> Result<DepositStateImportedAck, DepositStateTransferWireError> {
        self.validate_shape()?;
        if self.target_epoch != statement.target_epoch()
            || self.transition_binding != statement.transition_binding()
            || self.statement_digest != statement.digest()
            || self.context.network != statement.network()
            || self.context.wallet != statement.wallet()
        {
            return Err(DepositStateTransferWireError::InvalidImportedAckDelivery);
        }
        let acknowledgement =
            DepositStateImportedAck::from_bytes(statement, &self.acknowledgement)?;
        if acknowledgement.verify(statement)? != self.sender {
            return Err(DepositStateTransferWireError::InvalidImportedAckDelivery);
        }
        Ok(acknowledgement)
    }

    #[must_use]
    pub const fn sender(&self) -> PartyId {
        self.sender
    }

    #[must_use]
    pub const fn context(&self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub const fn recipient(&self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub const fn transition_binding(&self) -> [u8; 32] {
        self.transition_binding
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub fn acknowledgement_bytes(&self) -> &[u8] {
        &self.acknowledgement
    }

    #[must_use]
    pub const fn acknowledgement_digest(&self) -> [u8; 32] {
        self.acknowledgement_digest
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self)
            .expect("validated state-imported acknowledgement delivery serializes");
        length_prefixed_hash(IMPORT_ACK_DELIVERY_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_shape()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES,
            "deposit state imported acknowledgement delivery",
        )
    }

    pub fn from_bytes(
        authenticated_sender: PartyId,
        local_recipient: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let delivery: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES,
            "deposit state imported acknowledgement delivery",
        )?;
        delivery.validate_shape()?;
        if delivery.sender != authenticated_sender || delivery.recipient != local_recipient {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        Ok(delivery)
    }
}

/// Idempotent disposition after an acknowledgement is durably journaled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositStateImportedAckDisposition {
    Recorded,
    AlreadyRecorded,
}

/// Exact receipt for one durable target acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateImportedAckReceipt {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    delivery: [u8; 32],
    transition_binding: [u8; 32],
    statement: [u8; 32],
    acknowledgement: [u8; 32],
    sender: PartyId,
    recipient: PartyId,
    disposition: DepositStateImportedAckDisposition,
}

impl DepositStateImportedAckReceipt {
    pub fn issue(
        delivery: &DepositStateImportedAckDelivery,
        statement: &DepositStateImportedStatement,
        disposition: DepositStateImportedAckDisposition,
    ) -> Result<Self, DepositStateTransferWireError> {
        delivery.verify_for_statement(statement)?;
        Ok(Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: IMPORT_ACK_RECEIPT_DOMAIN,
            context: delivery.context,
            delivery: delivery.digest(),
            transition_binding: delivery.transition_binding,
            statement: delivery.statement_digest,
            acknowledgement: delivery.acknowledgement_digest,
            sender: delivery.sender,
            recipient: delivery.recipient,
            disposition,
        })
    }

    fn validate_for(
        self,
        delivery: &DepositStateImportedAckDelivery,
        statement: &DepositStateImportedStatement,
    ) -> Result<(), DepositStateTransferWireError> {
        delivery.verify_for_statement(statement)?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != IMPORT_ACK_RECEIPT_DOMAIN
            || self.context != delivery.context
            || self.delivery != delivery.digest()
            || self.transition_binding != delivery.transition_binding
            || self.statement != delivery.statement_digest
            || self.acknowledgement != delivery.acknowledgement_digest
            || self.sender != delivery.sender
            || self.recipient != delivery.recipient
        {
            return Err(DepositStateTransferWireError::InvalidImportedAckReceipt);
        }
        Ok(())
    }

    #[must_use]
    pub const fn disposition(self) -> DepositStateImportedAckDisposition {
        self.disposition
    }

    pub fn to_bytes(
        self,
        delivery: &DepositStateImportedAckDelivery,
        statement: &DepositStateImportedStatement,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(delivery, statement)?;
        encode_bounded(
            &self,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_RECEIPT_BYTES,
            "deposit state imported acknowledgement receipt",
        )
    }

    pub fn from_bytes(
        delivery: &DepositStateImportedAckDelivery,
        statement: &DepositStateImportedStatement,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let receipt: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_RECEIPT_BYTES,
            "deposit state imported acknowledgement receipt",
        )?;
        receipt.validate_for(delivery, statement)?;
        Ok(receipt)
    }
}

/// Delivery of the exact target `n-f` import certificate which gates readiness and predecessor
/// export-root reclamation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateImportedCertificateDelivery {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    sender: PartyId,
    recipient: PartyId,
    transition_binding: [u8; 32],
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    certificate: DepositStateImportedCertificate,
}

impl DepositStateImportedCertificateDelivery {
    pub fn new(
        certificate: DepositStateImportedCertificate,
        sender: PartyId,
        recipient: PartyId,
    ) -> Result<Self, DepositStateTransferWireError> {
        let certificate_bytes = certificate.to_bytes()?;
        let statement = certificate.statement();
        let context = DepositStateTransferContext::new(statement.network(), statement.wallet())?;
        let delivery = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: IMPORT_CERTIFICATE_DELIVERY_DOMAIN,
            context,
            sender,
            recipient,
            transition_binding: statement.transition_binding(),
            statement_digest: statement.digest(),
            certificate_digest: exact_bytes_digest(&certificate_bytes),
            certificate,
        };
        delivery.validate()?;
        Ok(delivery)
    }

    fn validate(&self) -> Result<(), DepositStateTransferWireError> {
        let certificate_bytes = self.certificate.to_bytes()?;
        let statement = self.certificate.statement();
        self.context.validate()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != IMPORT_CERTIFICATE_DELIVERY_DOMAIN
            || self.context.network != statement.network()
            || self.context.wallet != statement.wallet()
            || self.sender.0 == 0
            || self.recipient.0 == 0
            || statement.target_committee().member(self.sender).is_err()
            || self.transition_binding != statement.transition_binding()
            || self.statement_digest != statement.digest()
            || self.certificate_digest != exact_bytes_digest(&certificate_bytes)
        {
            return Err(DepositStateTransferWireError::InvalidImportedCertificateDelivery);
        }
        Ok(())
    }

    #[must_use]
    pub const fn sender(&self) -> PartyId {
        self.sender
    }

    #[must_use]
    pub const fn context(&self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub const fn recipient(&self) -> PartyId {
        self.recipient
    }

    #[must_use]
    pub const fn transition_binding(&self) -> [u8; 32] {
        self.transition_binding
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub const fn certificate(&self) -> &DepositStateImportedCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self)
            .expect("validated state-imported certificate delivery serializes");
        length_prefixed_hash(IMPORT_CERTIFICATE_DELIVERY_DIGEST_DOMAIN, &bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES,
            "deposit state imported certificate delivery",
        )
    }

    pub fn from_bytes(
        authenticated_sender: PartyId,
        local_recipient: PartyId,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let delivery: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES,
            "deposit state imported certificate delivery",
        )?;
        delivery.validate()?;
        if delivery.sender != authenticated_sender || delivery.recipient != local_recipient {
            return Err(DepositStateTransferWireError::WrongAuthenticatedParty);
        }
        Ok(delivery)
    }
}

/// Exact import-certificate execution disposition.
///
/// The service may report `Installed` only after the cold successor mutation/readiness gate and
/// transition-wide export-root reclaim commit.  The wire type itself grants neither authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositStateImportedCertificateDisposition {
    Installed,
    AlreadyInstalled,
    /// This execution has finished without installing the certificate: the exact local import
    /// still lacks its certified reopen. This is not an availability acknowledgement. The sender
    /// may resolve this transport attempt, but must retain and retry the certificate delivery.
    /// Appended to preserve existing encodings; older decoders reject this variant closed.
    Deferred,
}

/// Exact receipt for a completed import-certificate execution, not necessarily an install.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateImportedCertificateReceipt {
    version: u16,
    domain: [u8; 16],
    context: DepositStateTransferContext,
    delivery: [u8; 32],
    transition_binding: [u8; 32],
    statement: [u8; 32],
    certificate: [u8; 32],
    sender: PartyId,
    recipient: PartyId,
    disposition: DepositStateImportedCertificateDisposition,
}

impl DepositStateImportedCertificateReceipt {
    pub fn issue(
        delivery: &DepositStateImportedCertificateDelivery,
        disposition: DepositStateImportedCertificateDisposition,
    ) -> Result<Self, DepositStateTransferWireError> {
        delivery.validate()?;
        Ok(Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: IMPORT_CERTIFICATE_RECEIPT_DOMAIN,
            context: delivery.context,
            delivery: delivery.digest(),
            transition_binding: delivery.transition_binding,
            statement: delivery.statement_digest,
            certificate: delivery.certificate_digest,
            sender: delivery.sender,
            recipient: delivery.recipient,
            disposition,
        })
    }

    fn validate_for(
        self,
        delivery: &DepositStateImportedCertificateDelivery,
    ) -> Result<(), DepositStateTransferWireError> {
        delivery.validate()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.domain != IMPORT_CERTIFICATE_RECEIPT_DOMAIN
            || self.context != delivery.context
            || self.delivery != delivery.digest()
            || self.transition_binding != delivery.transition_binding
            || self.statement != delivery.statement_digest
            || self.certificate != delivery.certificate_digest
            || self.sender != delivery.sender
            || self.recipient != delivery.recipient
        {
            return Err(DepositStateTransferWireError::InvalidImportedCertificateReceipt);
        }
        Ok(())
    }

    #[must_use]
    pub const fn disposition(self) -> DepositStateImportedCertificateDisposition {
        self.disposition
    }

    pub fn to_bytes(
        self,
        delivery: &DepositStateImportedCertificateDelivery,
    ) -> Result<Vec<u8>, DepositStateTransferWireError> {
        self.validate_for(delivery)?;
        encode_bounded(
            &self,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_RECEIPT_BYTES,
            "deposit state imported certificate receipt",
        )
    }

    pub fn from_bytes(
        delivery: &DepositStateImportedCertificateDelivery,
        bytes: &[u8],
    ) -> Result<Self, DepositStateTransferWireError> {
        let receipt: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_RECEIPT_BYTES,
            "deposit state imported certificate receipt",
        )?;
        receipt.validate_for(delivery)?;
        Ok(receipt)
    }
}

fn validate_seal_statement_shape(
    statement: &DepositPostHandoffExportSealStatement,
) -> Result<(), DepositStateTransferWireError> {
    // The certificate constructor invokes the export module's full intrinsic statement validator.
    // An empty witness set is used only as a validation carrier; no code treats it as verified.
    let carrier = DepositPostHandoffExportSealCertificate::new(statement.clone(), Vec::new())?;
    let bytes = carrier.to_bytes()?;
    if bytes.is_empty() {
        return Err(DepositStateTransferWireError::InvalidSealRequest);
    }
    Ok(())
}

fn export_root_targets(
    anchor: DepositSyncObjectAnchor,
) -> Result<Vec<DepositSyncTraversalTarget>, DepositStateTransferWireError> {
    let mut roots = Vec::with_capacity(3);
    roots.push(DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Index {
        reference: anchor.registry_root(),
        depth: 0,
        semantic_hash: anchor.registry_semantic_root(),
    }));
    if let Some(id) = anchor.portable_root() {
        roots.push(DepositSyncTraversalTarget::PortableIndex(PortableIndexTraversalTarget::Node {
            id,
            depth: 0,
            expected_entries: Some(anchor.portable_entries()),
        }));
    }
    if let Some(reference) = anchor.certificate_segment_root() {
        roots.push(DepositSyncTraversalTarget::ArchiveSegment {
            reference,
            expected_end_ordinal: anchor.checkpoint_sequence(),
            expected_last_event: anchor.certificate_event_root(),
        });
    }
    if roots.is_empty() {
        return Err(DepositStateTransferWireError::InvalidExportLease);
    }
    Ok(roots)
}

fn validate_export_target(
    lease: DepositStateExportLease,
    target: DepositSyncTraversalTarget,
) -> Result<(), DepositStateTransferWireError> {
    lease.validate_structure()?;
    let anchor = lease.anchor;
    let reference = target.reference();
    reference.storage_reference()?;
    if reference.wallet() != lease.context.wallet {
        return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
    }
    match target {
        DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Index {
            depth,
            semantic_hash,
            ..
        }) => {
            if depth > COMPACT_REGISTRY_INDEX_DEPTH || semantic_hash == [0; 32] {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
        DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::Link {
            epoch,
            chain_root,
            ..
        }) => {
            if epoch > anchor.registry_active_epoch() || chain_root == [0; 32] {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
        DepositSyncTraversalTarget::Registry(CompactRegistryTraversalTarget::HandoffWitness {
            target_epoch,
            ..
        }) => {
            if target_epoch == 0 || target_epoch > anchor.registry_active_epoch() {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
        DepositSyncTraversalTarget::PortableIndex(PortableIndexTraversalTarget::Node {
            depth,
            expected_entries,
            ..
        }) => {
            if depth > MAX_HAMT_DEPTH || expected_entries == Some(0) {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
        DepositSyncTraversalTarget::PortableIndex(PortableIndexTraversalTarget::Value {
            ..
        }) => {}
        DepositSyncTraversalTarget::ArchiveSegment {
            reference,
            expected_end_ordinal,
            expected_last_event,
        } => {
            if reference.kind() != DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT
                || expected_end_ordinal == 0
                || expected_end_ordinal > anchor.checkpoint_sequence()
                || expected_last_event.is_some_and(|event| {
                    event.kind() != DEPOSIT_ARCHIVE_EVENT_ARTIFACT
                        || event.wallet_id() != WalletId(anchor.wallet().0)
                })
            {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
        DepositSyncTraversalTarget::ArchiveEvent { reference, expected_ordinal } => {
            if reference.kind() != DEPOSIT_ARCHIVE_EVENT_ARTIFACT
                || expected_ordinal >= anchor.checkpoint_sequence()
            {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
        DepositSyncTraversalTarget::ArchiveLeaf { reference, checkpoint_sequence, kind } => {
            let expected_kind = match kind {
                DepositSyncArchiveLeafKind::CertifiedLedger => CERTIFIED_LEDGER_ENTRY_ARTIFACT,
                DepositSyncArchiveLeafKind::CertifiedObservation => {
                    CERTIFIED_DEPOSIT_OBSERVATION_ARTIFACT
                }
                DepositSyncArchiveLeafKind::LedgerCheckpoint
                | DepositSyncArchiveLeafKind::ObservationCheckpoint => {
                    DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT
                }
            };
            if reference.kind() != expected_kind
                || checkpoint_sequence == 0
                || checkpoint_sequence > anchor.checkpoint_sequence()
            {
                return Err(DepositStateTransferWireError::InvalidExportTraversalTarget);
            }
        }
    }
    Ok(())
}

fn export_lease_mac(
    mac_key: &[u8; 32],
    lease: &DepositStateExportLease,
) -> Result<[u8; 32], DepositStateTransferWireError> {
    reject_zero_mac_key(mac_key)?;
    let mut material = *lease;
    material.tag = [0; 32];
    let bytes = postcard::to_allocvec(&material)
        .map_err(|_| DepositStateTransferWireError::Serialization)?;
    Ok(keyed_length_prefixed_hash(mac_key, EXPORT_LEASE_MAC_DOMAIN, &bytes))
}

fn export_object_capability_mac(
    mac_key: &[u8; 32],
    capability: &DepositStateExportObjectCapability,
) -> Result<[u8; 32], DepositStateTransferWireError> {
    reject_zero_mac_key(mac_key)?;
    let mut material = *capability;
    material.tag = [0; 32];
    let bytes = postcard::to_allocvec(&material)
        .map_err(|_| DepositStateTransferWireError::Serialization)?;
    Ok(keyed_length_prefixed_hash(mac_key, EXPORT_OBJECT_CAPABILITY_MAC_DOMAIN, &bytes))
}

fn reject_zero_mac_key(mac_key: &[u8; 32]) -> Result<(), DepositStateTransferWireError> {
    if *mac_key == [0; 32] {
        return Err(DepositStateTransferWireError::ZeroMacKey);
    }
    Ok(())
}

fn keyed_length_prefixed_hash(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn length_prefixed_hash(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn exact_bytes_digest(bytes: &[u8]) -> [u8; 32] {
    length_prefixed_hash(EXACT_BYTES_DIGEST_DOMAIN, bytes)
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, DepositStateTransferWireError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|_| DepositStateTransferWireError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositStateTransferWireError::ObjectTooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

fn decode_canonical_bounded<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, DepositStateTransferWireError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositStateTransferWireError::ObjectTooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    let (value, trailing) = postcard::take_from_bytes(bytes)
        .map_err(|_| DepositStateTransferWireError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositStateTransferWireError::TrailingBytes {
            kind,
            trailing: trailing.len(),
        });
    }
    if postcard::to_allocvec(&value).map_err(|_| DepositStateTransferWireError::Serialization)?
        != bytes
    {
        return Err(DepositStateTransferWireError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

fn deserialize_bounded_vec<'de, D, T, const MAXIMUM: usize>(
    deserializer: D,
    kind: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MAXIMUM: usize> {
        kind: &'static str,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T, const MAXIMUM: usize> Visitor<'de> for BoundedVecVisitor<T, MAXIMUM>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAXIMUM} {}", self.kind)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAXIMUM) {
                return Err(A::Error::custom(format_args!(
                    "too many {}; maximum is {MAXIMUM}",
                    self.kind
                )));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAXIMUM));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAXIMUM {
                    return Err(A::Error::custom(format_args!(
                        "too many {}; maximum is {MAXIMUM}",
                        self.kind
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer
        .deserialize_seq(BoundedVecVisitor::<T, MAXIMUM> { kind, marker: std::marker::PhantomData })
}

fn deserialize_export_object_request_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositStateExportObjectRequestEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_DEPOSIT_SYNC_REQUEST_OBJECTS>(
        deserializer,
        "certified-export object request entries",
    )
}

fn deserialize_candidate_advertisement_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_POST_HANDOFF_EXPORT_ADVERTISEMENT_BYTES>(
        deserializer,
        "post-handoff export candidate advertisement bytes",
    )
}

fn deserialize_candidate_registry_object_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_COMPACT_REGISTRY_WITNESS_BYTES>(
        deserializer,
        "post-handoff export candidate registry object bytes",
    )
}

fn deserialize_candidate_registry_objects<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositPostHandoffExportRegistryEvidenceObject>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_POST_HANDOFF_EXPORT_REGISTRY_EVIDENCE_OBJECTS>(
        deserializer,
        "post-handoff export candidate registry objects",
    )
}

fn deserialize_candidate_archive_segment_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_DEPOSIT_ARCHIVE_SEGMENT_BYTES>(
        deserializer,
        "post-handoff export candidate archive segment bytes",
    )
}

fn deserialize_candidate_archive_event_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_DEPOSIT_ARCHIVE_EVENT_BYTES>(
        deserializer,
        "post-handoff export candidate archive event bytes",
    )
}

fn deserialize_candidate_ledger_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES>(
        deserializer,
        "post-handoff export candidate terminal ledger bytes",
    )
}

fn deserialize_export_objects<'de, D>(deserializer: D) -> Result<Vec<DepositSyncObject>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_DEPOSIT_SYNC_PAGE_OBJECTS>(
        deserializer,
        "certified-export objects",
    )
}

fn deserialize_export_object_capabilities<'de, D>(
    deserializer: D,
) -> Result<Vec<DepositStateExportObjectCapability>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES>(
        deserializer,
        "certified-export object capabilities",
    )
}

fn deserialize_import_ack_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec::<_, _, MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES>(
        deserializer,
        "state-imported acknowledgement bytes",
    )
}

#[derive(Debug, Error)]
pub enum DepositStateTransferWireError {
    #[error("post-handoff export error: {0}")]
    StateExport(#[from] DepositStateExportError),
    #[error("deposit-state import error: {0}")]
    StateImport(#[from] DepositStateImportError),
    #[error("deposit-sync object error: {0}")]
    Sync(#[from] DepositSyncWireError),
    #[error("state-transfer context is malformed")]
    InvalidContext,
    #[error("transport-authenticated party does not match the typed payload")]
    WrongAuthenticatedParty,
    #[error("post-handoff export candidate evidence is malformed, detached, or incomplete")]
    InvalidCandidateEvidence,
    #[error("post-handoff export candidate evidence does not match the verified candidate")]
    WrongCandidateEvidence,
    #[error("post-handoff export request lacks the exact verified serving-source self-vote")]
    InvalidSourceSelfVote,
    #[error("post-handoff export seal request is malformed")]
    InvalidSealRequest,
    #[error("post-handoff export seal request acknowledgement is malformed")]
    InvalidSealRequestAck,
    #[error("post-handoff export seal vote is malformed")]
    InvalidSealVote,
    #[error("post-handoff export seal vote acknowledgement is malformed")]
    InvalidSealVoteAck,
    #[error("post-handoff export seal certificate delivery is malformed")]
    InvalidSealCertificateDelivery,
    #[error("post-handoff export seal certificate acknowledgement is malformed")]
    InvalidSealCertificateAck,
    #[error("verified export seal does not match the exact wire payload")]
    WrongVerifiedSeal,
    #[error("certified-export head request is malformed")]
    InvalidExportHeadRequest,
    #[error("certified-export head response is malformed")]
    InvalidExportHeadResponse,
    #[error("certified-export lease is malformed or unauthenticated")]
    InvalidExportLease,
    #[error("certified-export traversal target is malformed")]
    InvalidExportTraversalTarget,
    #[error("certified-export object capability is malformed or unauthenticated")]
    InvalidExportObjectCapability,
    #[error("certified-export object request is malformed")]
    InvalidExportObjectRequest,
    #[error("certified-export object response is malformed")]
    InvalidExportObjectResponse,
    #[error("certified-export release request is malformed")]
    InvalidExportReleaseRequest,
    #[error("certified-export release acknowledgement is malformed")]
    InvalidExportReleaseAck,
    #[error("state-imported acknowledgement delivery is malformed")]
    InvalidImportedAckDelivery,
    #[error("state-imported acknowledgement receipt is malformed")]
    InvalidImportedAckReceipt,
    #[error("state-imported certificate delivery is malformed")]
    InvalidImportedCertificateDelivery,
    #[error("state-imported certificate receipt is malformed")]
    InvalidImportedCertificateReceipt,
    #[error("state-transfer MAC key must not be all zero")]
    ZeroMacKey,
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("state-transfer serialization failed")]
    Serialization,
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{0} encoding is not canonical")]
    NonCanonicalEncoding(&'static str),
    #[error("certified-export advertisement does not match the transfer context")]
    WrongAdvertisement,
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_registry_archive::{
            COMPACT_REGISTRY_APPEND_OBJECTS, CompactRegistryArchiveHead, CompactRegistryIndexStep,
            CompactRegistryObjectKind, PendingCompactRegistryMutation, compact_registry_index_step,
            prepare_compact_registry_append, prepare_compact_registry_genesis,
        },
        compact_registry_store::CompactRegistryStoreCheckpoint,
        config::NetworkKind,
        deposit_archive::{
            DepositArchiveAppend, DepositArchiveHead, DepositArchiveStore,
            DepositArtifactChunkRequest, MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES,
        },
        deposit_index::{
            DepositIndexBuilder, DepositIndexError, DepositIndexHead, DepositIndexObjectId,
            DepositIndexReader, DepositIndexUpdate,
        },
        deposit_index_checkpoint::{
            DepositIndexCheckpointCandidate, DepositIndexCheckpointCertificate,
            DepositIndexCheckpointStatement, PortableDepositIndexHead,
            VerifiedDepositIndexCheckpoint, certify_checkpoint_candidate_for_test,
        },
        deposit_index_store::{DepositIndexStoreCheckpoint, VerifiedPortableIndexAdvance},
        deposit_ledger::{
            CertifiedLedgerEntry, LedgerRequestId, LedgerStatement, RequestBinding, VerifiedEntry,
            genesis_head as ledger_genesis_head,
        },
        deposit_state_export::{
            DepositHandoffStateBinding, DepositStateExportBinding,
            VerifiedDepositPostHandoffExportCandidate,
        },
        deposit_sync_wire::{DepositSyncHeadRequest, DepositSyncObjectRef},
        deposit_wallet::{ChainPoint, DepositAddressDeriver, DepositSubaddressIndex},
        identity::Identity,
        keys::{EpochPublic, PointBytes},
    };

    const SOURCE: PartyId = PartyId(1);
    const REQUESTER: PartyId = PartyId(2);

    fn context() -> DepositStateTransferContext {
        DepositStateTransferContext::new([0x41; 32], DepositWalletId([0x42; 32])).unwrap()
    }

    #[derive(Clone, Default)]
    struct RegistryObjects(BTreeMap<CompactRegistryObjectRef, Vec<u8>>);

    impl RegistryObjects {
        fn install(&mut self, pending: &PendingCompactRegistryMutation) {
            self.0.extend(
                pending
                    .staged_objects()
                    .iter()
                    .map(|object| (object.reference(), object.contents().to_vec())),
            );
        }
    }

    impl CompactRegistryObjectReader for RegistryObjects {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            Ok(self.0.get(&reference).cloned())
        }
    }

    fn collect_registry_epoch_evidence_path(
        head: &CompactRegistryArchiveHead,
        epoch: u64,
        reader: &RegistryObjects,
        objects: &mut BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    ) {
        let mut reference = head.index_root_reference();
        let mut semantic_hash = head.registry().id().index_root();
        for depth in 0..=COMPACT_REGISTRY_INDEX_DEPTH {
            let bytes = reader.load(reference).unwrap().expect("registry path object");
            let step = compact_registry_index_step(
                head.wallet(),
                epoch,
                depth,
                semantic_hash,
                reference,
                &bytes,
            )
            .unwrap();
            objects.entry(reference).or_insert(bytes);
            match step {
                CompactRegistryIndexStep::Branch { next: Some(next), next_semantic_hash } => {
                    reference = next;
                    semantic_hash = next_semantic_hash;
                }
                CompactRegistryIndexStep::Branch { next: None, .. } => {
                    panic!("fixture epoch must have a complete registry path");
                }
                CompactRegistryIndexStep::Leaf { link, witness, .. } => {
                    for reference in [Some(link), witness].into_iter().flatten() {
                        let bytes = reader.load(reference).unwrap().expect("registry leaf object");
                        verify_compact_registry_object(reference, &bytes).unwrap();
                        objects.entry(reference).or_insert(bytes);
                    }
                    return;
                }
            }
        }
        panic!("fixture registry path did not terminate in a leaf");
    }

    fn collect_registry_evidence_objects(
        head: &CompactRegistryArchiveHead,
        source_epoch: u64,
        target_epoch: u64,
        reader: &RegistryObjects,
    ) -> Vec<DepositSyncObject> {
        let mut objects = BTreeMap::new();
        collect_registry_epoch_evidence_path(head, source_epoch, reader, &mut objects);
        collect_registry_epoch_evidence_path(head, target_epoch, reader, &mut objects);
        objects
            .into_iter()
            .map(|(reference, bytes)| {
                DepositSyncObject::new(DepositSyncObjectRef::Registry(reference), bytes).unwrap()
            })
            .collect()
    }

    #[derive(Clone, Default)]
    struct MemoryIndex(BTreeMap<DepositIndexObjectId, Vec<u8>>);

    impl MemoryIndex {
        fn apply(&mut self, update: &DepositIndexUpdate) {
            for id in update.obsolete_objects() {
                self.0.remove(&id);
            }
            self.0.extend(update.staged_objects().map(|(id, bytes)| (id, bytes.to_vec())));
        }
    }

    impl DepositIndexReader for MemoryIndex {
        fn load_index_object(
            &self,
            id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(self.0.get(&id).cloned())
        }
    }

    pub(crate) struct ExportEvidenceFixture {
        pub(crate) network: [u8; 32],
        pub(crate) source: CompactEpochRegistry,
        pub(crate) handoff: RegistryHandoffCertificate,
        pub(crate) target: VerifiedRegistryHandoffTarget,
        pub(crate) candidate: VerifiedDepositPostHandoffExportCandidate,
        pub(crate) evidence: DepositPostHandoffExportCandidateEvidence,
        detached_registry_object: DepositPostHandoffExportRegistryEvidenceObject,
        pub(crate) source_identity: Identity,
        pub(crate) source_self_vote: SignedEnvelope,
    }

    struct PreparedExportEvidenceAuthority {
        network: [u8; 32],
        wallet: DepositWalletId,
        first_index: DepositSubaddressIndex,
        source_identities: BTreeMap<PartyId, Identity>,
        source_committee: Committee,
        source_head: CompactRegistryArchiveHead,
        source: CompactEpochRegistry,
        source_objects: RegistryObjects,
        target: VerifiedRegistryHandoffTarget,
        allocation: Box<CertifiedLedgerEntry>,
        verified_allocation: VerifiedEntry,
        allocation_checkpoint: Box<DepositIndexCheckpointCertificate>,
        verified_allocation_checkpoint: Box<VerifiedDepositIndexCheckpoint>,
        source_portable: PortableDepositIndexHead,
        ledger: Box<CertifiedLedgerEntry>,
        verified_ledger: VerifiedEntry,
        handoff: RegistryHandoffCertificate,
        checkpoint: Box<DepositIndexCheckpointCertificate>,
        verified_checkpoint: Box<VerifiedDepositIndexCheckpoint>,
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    pub(crate) fn test_identities(epoch: u64) -> BTreeMap<PartyId, Identity> {
        (1_u16..=4)
            .map(|value| {
                let party = PartyId(value);
                let mut signing_seed = [u8::try_from(value).unwrap(); 32];
                signing_seed[0] ^= u8::try_from(epoch).unwrap();
                let identity = Identity::from_test_secrets(
                    party,
                    epoch,
                    &signing_seed,
                    test_x25519_secret(party, epoch),
                )
                .unwrap();
                (party, identity)
            })
            .collect()
    }

    fn test_committee(epoch: u64, identities: &BTreeMap<PartyId, Identity>) -> Committee {
        Committee {
            epoch,
            threshold: 2,
            members: identities
                .values()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        }
        .canonicalized()
        .unwrap()
    }

    fn source_public(source: &CompactEpochRegistry) -> EpochPublic {
        let committee = source.active().committee().clone();
        assert_eq!(committee.threshold, 2, "fixture uses a linear sharing polynomial");
        let group_key = PointBytes(source.active().group_key());
        let group = group_key.parse().unwrap();
        let slope = ED25519_BASEPOINT_POINT * Scalar::from(7_u64);
        let verification_shares = (1..=committee.n())
            .map(|index| {
                let party = committee.party_for_frost_index(index).unwrap();
                let share = group + slope * Scalar::from(u64::from(index));
                (party, PointBytes::from(share))
            })
            .collect::<BTreeMap<_, _>>();
        let public = EpochPublic {
            key_id: source.active().key_id(),
            committee,
            verification_shares,
            group_key,
        };
        public.validate().unwrap();
        public
    }

    pub(crate) fn seal_certificate_for(
        fixture: &ExportEvidenceFixture,
        witness_parties: &[PartyId],
    ) -> DepositPostHandoffExportSealCertificate {
        let statement = fixture.candidate.statement();
        let required = fixture
            .source
            .active()
            .committee()
            .n()
            .checked_sub(fixture.source.active().fault_bound())
            .unwrap();
        assert_eq!(witness_parties.len(), usize::from(required));
        assert!(witness_parties.contains(&statement.source_party()));
        let identities = test_identities(fixture.source.active_epoch());
        let witnesses = witness_parties
            .iter()
            .map(|party| {
                identities[party]
                    .sign_envelope(
                        fixture.source.active().committee(),
                        statement.session(),
                        None,
                        statement.final_export().terminal_checkpoint().sequence(),
                        statement.signing_payload(),
                    )
                    .unwrap()
            })
            .collect();
        DepositPostHandoffExportSealCertificate::new(statement.clone(), witnesses).unwrap()
    }

    fn sign_ledger(
        statement: LedgerStatement,
        identities: &BTreeMap<PartyId, Identity>,
        committee: &Committee,
    ) -> CertifiedLedgerEntry {
        let payload = statement.attestation_payload().unwrap();
        let attestations = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        committee,
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

    #[allow(clippy::too_many_arguments)]
    fn apply_and_checkpoint(
        now: u64,
        network: [u8; 32],
        source: &CompactEpochRegistry,
        ledger: &CertifiedLedgerEntry,
        previous_checkpoint: Option<&VerifiedDepositIndexCheckpoint>,
        expected_head: DepositIndexHead,
        reader: &MemoryIndex,
        identities: &BTreeMap<PartyId, Identity>,
    ) -> (DepositIndexUpdate, DepositIndexCheckpointCertificate, VerifiedDepositIndexCheckpoint)
    {
        let mut preflight_builder =
            DepositIndexBuilder::new(reader, expected_head.clone()).unwrap();
        let preflight = preflight_builder.preflight_ledger_statement(&ledger.statement).unwrap();
        let mut builder = DepositIndexBuilder::new(reader, expected_head).unwrap();
        assert!(builder.apply_verified_active_entry(ledger, source, None).unwrap());
        let update = builder.finish().unwrap().unwrap();
        let statement = DepositIndexCheckpointStatement::for_transition(
            now,
            network,
            source,
            None,
            previous_checkpoint,
            ledger,
            &preflight,
            &update,
            reader,
        )
        .unwrap();
        let selection = certify_checkpoint_candidate_for_test(
            network,
            source,
            statement.sequence(),
            statement.previous_head(),
            DepositIndexCheckpointCandidate::Ledger(ledger.clone()),
            identities,
        );
        let witnesses = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        source.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence(),
                        statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let certificate = DepositIndexCheckpointCertificate::from_witnesses(
            network,
            source,
            None,
            previous_checkpoint,
            ledger,
            statement,
            selection,
            witnesses,
        )
        .unwrap();
        let verified =
            certificate.verify_active(network, source, None, previous_checkpoint, ledger).unwrap();
        (update, certificate, verified)
    }

    async fn load_archive_object(
        archive: &DepositArchiveStore,
        reference: WalletArtifactRef,
    ) -> Vec<u8> {
        let maximum = usize::try_from(reference.plaintext_len()).unwrap();
        assert!(maximum <= MAX_DEPOSIT_ARTIFACT_CHUNK_BYTES);
        let request =
            DepositArtifactChunkRequest::new(reference, 0, u32::try_from(maximum).unwrap())
                .unwrap();
        let chunk = archive.artifact_chunk(request).await.unwrap();
        assert!(chunk.complete);
        chunk.bytes
    }

    fn prepare_export_evidence_authority() -> Box<PreparedExportEvidenceAuthority> {
        let network = [0x61; 32];
        let root_spend = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root_spend,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let wallet = deriver.wallet_id();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let key_id = [0x63; 32];
        let group_key = deriver.root_spend_key();
        let source_identities = test_identities(0);
        let source_committee = test_committee(0, &source_identities);
        let source_target = VerifiedRegistryHandoffTarget::for_test(
            source_committee.clone(),
            1,
            [0x65; 32],
            [0x66; 32],
            wallet,
            key_id,
            group_key,
        )
        .unwrap();
        let initial_head = DepositIndexHead::empty_portable(wallet, first_index).unwrap();
        let source_pending =
            prepare_compact_registry_genesis(&source_target, first_index, initial_head.digest())
                .unwrap();
        let source_head = source_pending.proposed_head().clone();
        let source = source_head.registry().clone();
        let mut source_objects = RegistryObjects::default();
        source_objects.install(&source_pending);

        let target_identities = test_identities(1);
        let target = VerifiedRegistryHandoffTarget::for_test(
            test_committee(1, &target_identities),
            1,
            [0x67; 32],
            [0x68; 32],
            wallet,
            key_id,
            group_key,
        )
        .unwrap();

        let allocation = Box::new(sign_ledger(
            LedgerStatement::allocation(
                &source,
                1,
                ledger_genesis_head(wallet),
                LedgerRequestId([0x69; 32]),
                RequestBinding([0x6a; 32]),
                deriver.derive(first_index),
                ChainPoint::new(1, [0x6b; 32]).unwrap(),
                1_000,
            )
            .unwrap(),
            &source_identities,
            &source_committee,
        ));
        let verified_allocation = allocation.verify_active(&source, None).unwrap();
        let mut index_reader = MemoryIndex::default();
        let (allocation_update, allocation_checkpoint, verified_allocation_checkpoint) =
            apply_and_checkpoint(
                999,
                network,
                &source,
                &allocation,
                None,
                initial_head,
                &index_reader,
                &source_identities,
            );
        let allocation_checkpoint = Box::new(allocation_checkpoint);
        let verified_allocation_checkpoint = Box::new(verified_allocation_checkpoint);
        index_reader.apply(&allocation_update);
        let source_portable =
            PortableDepositIndexHead::from_head(allocation_update.next_head()).unwrap();
        let source_state = DepositHandoffStateBinding::new(
            Some(verified_allocation_checkpoint.decision_digest()),
            source_portable.clone(),
        )
        .unwrap();
        let ledger = Box::new(sign_ledger(
            LedgerStatement::handoff(
                &source,
                2,
                allocation.statement.digest(),
                source_state,
                &target,
                source_portable.next_index(),
            )
            .unwrap(),
            &source_identities,
            &source_committee,
        ));
        let verified_ledger = ledger.verify_active(&source, None).unwrap();
        let handoff = ledger.registry_handoff_certificate(&source).unwrap();
        let (terminal_update, checkpoint, verified_checkpoint) = apply_and_checkpoint(
            1,
            network,
            &source,
            &ledger,
            Some(verified_allocation_checkpoint.as_ref()),
            allocation_update.next_head().clone(),
            &index_reader,
            &source_identities,
        );
        index_reader.apply(&terminal_update);

        Box::new(PreparedExportEvidenceAuthority {
            network,
            wallet,
            first_index,
            source_identities,
            source_committee,
            source_head,
            source,
            source_objects,
            target,
            allocation,
            verified_allocation,
            allocation_checkpoint,
            verified_allocation_checkpoint,
            source_portable,
            ledger,
            verified_ledger,
            handoff,
            checkpoint: Box::new(checkpoint),
            verified_checkpoint: Box::new(verified_checkpoint),
        })
    }

    fn complete_export_evidence_fixture(
        prepared: &PreparedExportEvidenceAuthority,
        append: DepositArchiveAppend,
        segment_bytes: Vec<u8>,
        event_bytes: Vec<u8>,
        ledger_bytes: Vec<u8>,
    ) -> Box<ExportEvidenceFixture> {
        let target_pending = prepare_compact_registry_append(
            &prepared.source_head,
            &prepared.target,
            prepared.handoff.clone(),
            &prepared.source_portable,
            &prepared.source_objects,
        )
        .unwrap();
        assert_eq!(target_pending.staged_objects().len(), COMPACT_REGISTRY_APPEND_OBJECTS);
        let target_head = target_pending.proposed_head().clone();
        let registry_checkpoint =
            CompactRegistryStoreCheckpoint::settled(prepared.wallet, target_head).unwrap();
        let portable_advance =
            VerifiedPortableIndexAdvance::from_certified_checkpoint(&prepared.verified_checkpoint)
                .unwrap();
        let index_checkpoint =
            DepositIndexStoreCheckpoint::empty(prepared.wallet, SOURCE, prepared.first_index)
                .unwrap()
                .adopt_verified_portable(&portable_advance)
                .unwrap();
        let advertisement = DepositSyncAdvertisement::from_checkpoints(
            DepositSyncContext::new(prepared.network, prepared.wallet).unwrap(),
            &registry_checkpoint,
            append.head,
            &index_checkpoint,
            Some((*prepared.checkpoint).clone()),
        )
        .unwrap();

        // A compact-registry append stages only the successor path. Its sibling subtree still
        // points at predecessor objects, and authenticating the successor necessarily reloads
        // the predecessor link before accepting the handoff witness. Model the installed graph,
        // not just this mutation's newly staged objects.
        let mut registry_reader = prepared.source_objects.clone();
        registry_reader.0.extend(
            target_pending
                .staged_objects()
                .iter()
                .map(|object| (object.reference(), object.contents().to_vec())),
        );
        let registry_objects = collect_registry_evidence_objects(
            target_pending.proposed_head(),
            prepared.source.active_epoch(),
            prepared.target.committee().epoch,
            &registry_reader,
        );
        assert!(registry_objects.len() <= MAX_POST_HANDOFF_EXPORT_REGISTRY_EVIDENCE_OBJECTS);
        assert!(
            registry_objects.len() < registry_reader.0.len(),
            "obsolete predecessor path nodes are not candidate evidence"
        );
        let evidence_references = registry_objects
            .iter()
            .filter_map(|object| match object.reference() {
                DepositSyncObjectRef::Registry(reference) => Some(reference),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let detached_registry_object = registry_reader
            .0
            .iter()
            .find(|(reference, _)| !evidence_references.contains(reference))
            .map(|(reference, bytes)| {
                DepositPostHandoffExportRegistryEvidenceObject::new(*reference, bytes.clone())
                    .unwrap()
            })
            .expect("append leaves an obsolete predecessor path node");
        assert!(registry_objects.iter().any(|object| {
            matches!(
                object.reference(),
                DepositSyncObjectRef::Registry(reference)
                    if reference.kind() == CompactRegistryObjectKind::HandoffWitness
            )
        }));
        let segment_reference = append.head.segment_reference().unwrap();
        let segment = DepositArchiveSegment::from_bytes(&segment_bytes).unwrap();
        let event = DepositArchiveEvent::from_bytes(&event_bytes).unwrap();
        let candidate = VerifiedDepositPostHandoffExportCandidate::from_verified_append(
            prepared.network,
            SOURCE,
            &prepared.source,
            &prepared.handoff,
            &prepared.target,
            DepositStateExportBinding::from_advertisement(&advertisement).unwrap(),
            &advertisement,
            &registry_reader,
            &append,
            &prepared.verified_checkpoint,
        )
        .unwrap();
        let remote_candidate =
            VerifiedDepositPostHandoffExportCandidate::from_verified_remote_evidence(
                prepared.network,
                SOURCE,
                &prepared.source,
                &prepared.handoff,
                &prepared.target,
                &advertisement,
                &registry_reader,
                segment_reference,
                &segment,
                append.event_artifact,
                event,
                append.entry_artifact,
                &prepared.ledger,
                advertisement.checkpoint_certificate().unwrap(),
            )
            .unwrap();
        assert_eq!(remote_candidate.statement(), candidate.statement());
        let segment_object = DepositSyncObject::new(
            DepositSyncObjectRef::CertificateArchive(segment_reference),
            segment_bytes,
        )
        .unwrap();
        let event_object = DepositSyncObject::new(
            DepositSyncObjectRef::CertificateArchive(append.event_artifact),
            event_bytes,
        )
        .unwrap();
        let ledger_object = DepositSyncObject::new(
            DepositSyncObjectRef::CertificateArchive(append.entry_artifact),
            ledger_bytes,
        )
        .unwrap();
        let evidence = DepositPostHandoffExportCandidateEvidence::new(
            &candidate,
            &advertisement,
            registry_objects,
            &segment_object,
            &event_object,
            &ledger_object,
        )
        .unwrap();
        let statement = candidate.statement();
        let source_self_vote = prepared.source_identities[&SOURCE]
            .sign_envelope(
                &prepared.source_committee,
                statement.session(),
                None,
                statement.final_export().terminal_checkpoint().sequence(),
                statement.signing_payload(),
            )
            .unwrap();
        Box::new(ExportEvidenceFixture {
            network: prepared.network,
            source: prepared.source.clone(),
            handoff: prepared.handoff.clone(),
            target: prepared.target.clone(),
            candidate,
            evidence,
            detached_registry_object,
            source_identity: Identity::from_test_secrets(
                SOURCE,
                0,
                &[1; 32],
                test_x25519_secret(SOURCE, 0),
            )
            .unwrap(),
            source_self_vote,
        })
    }

    pub(crate) fn export_evidence_fixture()
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Box<ExportEvidenceFixture>>>> {
        export_evidence_fixture_with_alternate_witnesses(false)
    }

    pub(crate) fn export_evidence_fixture_with_alternate_witnesses(
        alternate: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Box<ExportEvidenceFixture>>>> {
        // This fixture deliberately composes several archive/index state machines. Keeping either
        // that async state or its large result inline in every caller makes the debug-build test
        // future larger than Rust's default 2 MiB test-thread stack. Box both so the focused
        // protocol tests exercise the same production calls without requiring a larger stack.
        Box::pin(async move {
            // `DepositIndexBuilder::finish` performs several authenticated path proofs. Run the
            // synchronous authority construction on a fresh default-size blocking-worker stack so
            // it does not inherit the async test poller's already-live frames. This does not raise
            // any stack limit or change protocol behavior; it only isolates the CPU-bound fixture
            // phase from the archive-I/O phase below.
            let mut prepared =
                tokio::task::spawn_blocking(prepare_export_evidence_authority).await.unwrap();
            if alternate {
                let statement = prepared.checkpoint.statement().clone();
                let witnesses = [PartyId(1), PartyId(2), PartyId(4)]
                    .into_iter()
                    .map(|party| {
                        prepared.source_identities[&party]
                            .sign_envelope(
                                &prepared.source_committee,
                                statement.slot_session(),
                                None,
                                statement.sequence(),
                                statement.to_bytes().unwrap(),
                            )
                            .unwrap()
                    })
                    .collect();
                prepared.checkpoint = Box::new(
                    DepositIndexCheckpointCertificate::from_witnesses(
                        prepared.network,
                        &prepared.source,
                        None,
                        Some(&prepared.verified_allocation_checkpoint),
                        &prepared.ledger,
                        statement,
                        prepared.checkpoint.selection().clone(),
                        witnesses,
                    )
                    .unwrap(),
                );
                prepared.verified_checkpoint = Box::new(
                    prepared
                        .checkpoint
                        .verify_active(
                            prepared.network,
                            &prepared.source,
                            None,
                            Some(&prepared.verified_allocation_checkpoint),
                            &prepared.ledger,
                        )
                        .unwrap(),
                );
            }
            let archive_directory = tempfile::tempdir().unwrap();
            let archive =
                DepositArchiveStore::new(archive_directory.path(), SOURCE, &[0x6c; 32]).unwrap();
            let staged_allocation = archive
                .stage_certified_ledger_entry(
                    &prepared.allocation,
                    &prepared.verified_allocation,
                    &mut OsRng,
                )
                .await
                .unwrap();
            let allocation_append = archive
                .append_ledger_checkpoint(
                    DepositArchiveHead::empty(prepared.wallet).unwrap(),
                    staged_allocation,
                    &prepared.allocation_checkpoint,
                    &prepared.verified_allocation_checkpoint,
                    &mut OsRng,
                )
                .await
                .unwrap();
            let staged = archive
                .stage_certified_ledger_entry(
                    &prepared.ledger,
                    &prepared.verified_ledger,
                    &mut OsRng,
                )
                .await
                .unwrap();
            let append = archive
                .append_ledger_checkpoint(
                    allocation_append.head,
                    staged,
                    &prepared.checkpoint,
                    &prepared.verified_checkpoint,
                    &mut OsRng,
                )
                .await
                .unwrap();

            let segment_reference = append.head.segment_reference().unwrap();
            let segment_bytes = load_archive_object(&archive, segment_reference).await;
            let event_bytes = load_archive_object(&archive, append.event_artifact).await;
            let ledger_bytes = load_archive_object(&archive, append.entry_artifact).await;
            complete_export_evidence_fixture(
                &prepared,
                append,
                segment_bytes,
                event_bytes,
                ledger_bytes,
            )
        })
    }

    #[test]
    fn all_v7_route_domains_are_exact_and_distinct() {
        let domains = [
            CONTEXT_DOMAIN,
            CANDIDATE_EVIDENCE_DOMAIN,
            SEAL_REQUEST_DOMAIN,
            SEAL_REQUEST_ACK_DOMAIN,
            SEAL_VOTE_DOMAIN,
            SEAL_VOTE_ACK_DOMAIN,
            SEAL_CERTIFICATE_DOMAIN,
            SEAL_CERTIFICATE_ACK_DOMAIN,
            EXPORT_HEAD_REQUEST_DOMAIN,
            EXPORT_HEAD_RESPONSE_DOMAIN,
            EXPORT_LEASE_DOMAIN,
            EXPORT_OBJECT_CAPABILITY_DOMAIN,
            EXPORT_OBJECT_REQUEST_DOMAIN,
            EXPORT_OBJECT_RESPONSE_DOMAIN,
            EXPORT_RELEASE_REQUEST_DOMAIN,
            EXPORT_RELEASE_ACK_DOMAIN,
            IMPORT_ACK_DELIVERY_DOMAIN,
            IMPORT_ACK_RECEIPT_DOMAIN,
            IMPORT_CERTIFICATE_DELIVERY_DOMAIN,
            IMPORT_CERTIFICATE_RECEIPT_DOMAIN,
        ];
        assert!(domains.iter().all(|domain| domain.len() == 16));
        assert_eq!(domains.iter().copied().collect::<BTreeSet<_>>().len(), domains.len());
        assert_eq!(DEPOSIT_STATE_TRANSFER_WIRE_VERSION, 7);
    }

    #[tokio::test]
    async fn candidate_evidence_reconstructs_exact_capability_and_rejects_tampering() {
        let fixture = export_evidence_fixture().await;
        let request = DepositPostHandoffExportSealRequest::new(
            &fixture.candidate,
            REQUESTER,
            fixture.evidence.clone(),
            fixture.source_self_vote.clone(),
        )
        .unwrap();
        let request_bytes = request.to_bytes().unwrap();
        assert!(request_bytes.len() <= MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES);
        let request =
            DepositPostHandoffExportSealRequest::from_bytes(SOURCE, REQUESTER, &request_bytes)
                .unwrap();
        let reconstructed = request
            .verify_and_reconstruct_candidate(
                fixture.network,
                &fixture.source,
                &fixture.handoff,
                &fixture.target,
            )
            .unwrap();
        assert_eq!(reconstructed.statement(), fixture.candidate.statement());

        let evidence_bytes = fixture.evidence.to_bytes(&fixture.candidate).unwrap();
        let (recovered, candidate) =
            DepositPostHandoffExportCandidateEvidence::from_bytes_verified(
                &evidence_bytes,
                fixture.network,
                SOURCE,
                &fixture.source,
                &fixture.handoff,
                &fixture.target,
            )
            .unwrap();
        assert_eq!(recovered, fixture.evidence);
        assert_eq!(candidate.statement(), fixture.candidate.statement());
        assert!(
            DepositPostHandoffExportCandidateEvidence::from_bytes_verified(
                &evidence_bytes,
                [0x99; 32],
                SOURCE,
                &fixture.source,
                &fixture.handoff,
                &fixture.target,
            )
            .is_err()
        );

        let mut missing = fixture.evidence.clone();
        missing.registry_objects.pop();
        assert!(matches!(
            missing.validate_for_candidate(&fixture.candidate),
            Err(DepositStateTransferWireError::InvalidCandidateEvidence)
        ));

        let mut detached = fixture.evidence.clone();
        detached.registry_objects.push(fixture.detached_registry_object.clone());
        detached
            .registry_objects
            .sort_by_key(DepositPostHandoffExportRegistryEvidenceObject::reference);
        assert!(matches!(
            detached.validate_for_candidate(&fixture.candidate),
            Err(DepositStateTransferWireError::InvalidCandidateEvidence)
        ));

        let mut tampered = fixture.evidence.clone();
        tampered.archive_event[0] ^= 1;
        assert!(
            DepositPostHandoffExportCandidateEvidence::from_bytes_verified(
                &postcard::to_allocvec(&tampered).unwrap(),
                fixture.network,
                SOURCE,
                &fixture.source,
                &fixture.handoff,
                &fixture.target,
            )
            .is_err()
        );
        assert!(matches!(
            tampered.validate_for_candidate(&fixture.candidate),
            Err(DepositStateTransferWireError::InvalidCandidateEvidence)
        ));
    }

    #[tokio::test]
    async fn candidate_request_rejects_invalid_source_self_vote_signature() {
        let fixture = export_evidence_fixture().await;
        let mut invalid_source_vote = fixture.source_self_vote.clone();
        invalid_source_vote.signature[0] ^= 1;
        let request = DepositPostHandoffExportSealRequest::new(
            &fixture.candidate,
            REQUESTER,
            fixture.evidence,
            invalid_source_vote,
        )
        .unwrap();
        assert!(matches!(
            request.verify_and_reconstruct_candidate(
                fixture.network,
                &fixture.source,
                &fixture.handoff,
                &fixture.target,
            ),
            Err(DepositStateTransferWireError::InvalidSourceSelfVote)
        ));
    }

    #[tokio::test]
    async fn pre_import_wire_validation_matches_full_seal_and_rejects_wrong_certificate() {
        let fixture = export_evidence_fixture().await;
        let source_public = source_public(&fixture.source);
        let certificate_a = seal_certificate_for(&fixture, &[SOURCE, PartyId(2), PartyId(3)]);
        let certificate_b = seal_certificate_for(&fixture, &[SOURCE, PartyId(2), PartyId(4)]);
        let full_a = certificate_a.verify(&fixture.source, &fixture.handoff).unwrap();
        let full_b = certificate_b.verify(&fixture.source, &fixture.handoff).unwrap();
        let pre_import_a = certificate_a
            .verify_pre_import(
                fixture.network,
                &source_public,
                fixture.source.active().fault_bound(),
                fixture.source.active().certified_activation_root(),
                &fixture.target,
            )
            .unwrap();
        let pre_import_b = certificate_b
            .verify_pre_import(
                fixture.network,
                &source_public,
                fixture.source.active().fault_bound(),
                fixture.source.active().certified_activation_root(),
                &fixture.target,
            )
            .unwrap();

        assert_eq!(
            VerifiedStateImportTransitionBinding::from_verified_export_seal(&full_a).unwrap(),
            VerifiedStateImportTransitionBinding::from_verified_pre_import_export_seal(
                &pre_import_a,
            )
            .unwrap()
        );
        assert_ne!(pre_import_a.certificate_digest(), pre_import_b.certificate_digest());

        let delivery =
            DepositPostHandoffExportSealCertificateDelivery::from_verified(&full_a, REQUESTER)
                .unwrap();
        delivery.validate_verified_seal(&full_a).unwrap();
        delivery.validate_pre_import_verified_seal(&pre_import_a).unwrap();
        assert!(matches!(
            delivery.validate_pre_import_verified_seal(&pre_import_b),
            Err(DepositStateTransferWireError::WrongVerifiedSeal)
        ));

        let statement = full_a.statement();
        let request = DepositStateExportHeadRequest::new(
            DepositStateTransferContext::new(statement.network(), statement.source().wallet())
                .unwrap(),
            statement.semantic_transition_digest(),
            statement.source_party(),
            REQUESTER,
            [0x71; 32],
        )
        .unwrap();
        let advertisement = fixture.evidence.advertisement().unwrap();
        let response_a = DepositStateExportHeadResponse::issue(
            request,
            advertisement.clone(),
            &full_a,
            &[0x72; 32],
        )
        .unwrap();
        let response_b =
            DepositStateExportHeadResponse::issue(request, advertisement, &full_b, &[0x73; 32])
                .unwrap();

        response_a.validate_verified_seal(request, &full_a).unwrap();
        response_a.validate_pre_import_verified_seal(request, &pre_import_a).unwrap();
        response_a.lease().validate_pre_import_verified_seal(&pre_import_a).unwrap();

        assert!(matches!(
            response_a.lease().validate_pre_import_verified_seal(&pre_import_b),
            Err(DepositStateTransferWireError::WrongVerifiedSeal)
        ));
        assert!(matches!(
            response_a.validate_pre_import_verified_seal(request, &pre_import_b),
            Err(DepositStateTransferWireError::WrongVerifiedSeal)
        ));
        assert!(matches!(
            response_b.validate_pre_import_verified_seal(request, &pre_import_a),
            Err(DepositStateTransferWireError::WrongVerifiedSeal)
        ));

        let mut corrupted_certificate = response_a;
        corrupted_certificate.certificate = certificate_b;
        assert!(matches!(
            corrupted_certificate.validate_pre_import_verified_seal(request, &pre_import_a),
            Err(DepositStateTransferWireError::InvalidExportHeadResponse)
        ));
    }

    #[test]
    fn export_head_request_is_canonical_party_bound_and_nonce_distinct() {
        let first = DepositStateExportHeadRequest::new(
            context(),
            [0x43; 32],
            SOURCE,
            REQUESTER,
            [0x44; 32],
        )
        .unwrap();
        let second = DepositStateExportHeadRequest::new(
            context(),
            [0x43; 32],
            SOURCE,
            REQUESTER,
            [0x45; 32],
        )
        .unwrap();
        assert_ne!(first.digest(), second.digest());

        let bytes = first.to_bytes().unwrap();
        assert_eq!(
            DepositStateExportHeadRequest::from_bytes(SOURCE, REQUESTER, &bytes).unwrap(),
            first
        );
        assert!(DepositStateExportHeadRequest::from_bytes(REQUESTER, SOURCE, &bytes).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DepositStateExportHeadRequest::from_bytes(SOURCE, REQUESTER, &trailing).is_err());
        assert!(
            DepositStateExportHeadRequest::new(context(), [0x43; 32], SOURCE, REQUESTER, [0; 32],)
                .is_err()
        );
    }

    #[test]
    fn ordinary_sync_head_and_certified_export_head_do_not_alias() {
        let transfer = DepositStateExportHeadRequest::new(
            context(),
            [0x43; 32],
            SOURCE,
            REQUESTER,
            [0x44; 32],
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        assert!(DepositSyncHeadRequest::from_bytes(SOURCE, REQUESTER, &transfer).is_err());

        let sync_context =
            DepositSyncContext::new(context().network(), context().wallet()).unwrap();
        let ordinary = DepositSyncHeadRequest::new(sync_context, SOURCE, REQUESTER)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(DepositStateExportHeadRequest::from_bytes(SOURCE, REQUESTER, &ordinary).is_err());
    }

    #[test]
    fn seal_vote_routing_projection_is_canonical_and_epoch_bound() {
        let vote = DepositPostHandoffExportSealVote {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            domain: SEAL_VOTE_DOMAIN,
            request: [0x51; 32],
            statement: [0x52; 32],
            requester: SOURCE,
            voter: REQUESTER,
            target_epoch: 7,
            envelope: SignedEnvelope {
                version: 1,
                committee: [0x53; 32],
                epoch: 6,
                session: crate::committee::SessionId([0x54; 32]),
                from: REQUESTER,
                to: None,
                sequence: 11,
                payload: vec![0x55; 32],
                signature: [0x56; 64],
            },
        };
        let bytes = encode_bounded(
            &vote,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
            "post-handoff export seal vote",
        )
        .unwrap();
        assert_eq!(
            DepositPostHandoffExportSealVote::routing_from_bytes(&bytes).unwrap(),
            (SOURCE, REQUESTER, 7, [0x51; 32])
        );

        let mut zero_epoch = vote;
        zero_epoch.target_epoch = 0;
        let bytes = encode_bounded(
            &zero_epoch,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES,
            "post-handoff export seal vote",
        )
        .unwrap();
        assert!(DepositPostHandoffExportSealVote::routing_from_bytes(&bytes).is_err());
    }

    #[test]
    fn every_route_has_a_hard_top_level_decode_bound() {
        macro_rules! rejects_oversize {
            ($kind:ty, $maximum:expr) => {{
                let bytes = vec![0_u8; $maximum + 1];
                assert!(decode_canonical_bounded::<$kind>(&bytes, $maximum, "test route").is_err());
            }};
        }

        rejects_oversize!(
            DepositPostHandoffExportSealRequest,
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_BYTES
        );
        rejects_oversize!(
            DepositPostHandoffExportSealRequestAck,
            MAX_POST_HANDOFF_EXPORT_SEAL_REQUEST_ACK_BYTES
        );
        rejects_oversize!(
            DepositPostHandoffExportSealVote,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_BYTES
        );
        rejects_oversize!(
            DepositPostHandoffExportSealVoteAck,
            MAX_POST_HANDOFF_EXPORT_SEAL_VOTE_ACK_BYTES
        );
        rejects_oversize!(
            DepositPostHandoffExportSealCertificateDelivery,
            MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DELIVERY_BYTES
        );
        rejects_oversize!(
            DepositPostHandoffExportSealCertificateAck,
            MAX_POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_ACK_BYTES
        );
        rejects_oversize!(
            DepositStateExportHeadRequest,
            MAX_DEPOSIT_STATE_EXPORT_HEAD_REQUEST_BYTES
        );
        rejects_oversize!(
            DepositStateExportHeadResponse,
            MAX_DEPOSIT_STATE_EXPORT_HEAD_RESPONSE_BYTES
        );
        rejects_oversize!(
            DepositStateExportObjectsRequest,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_REQUEST_BYTES
        );
        rejects_oversize!(
            DepositStateExportObjectsResponse,
            MAX_DEPOSIT_STATE_EXPORT_OBJECTS_RESPONSE_BYTES
        );
        rejects_oversize!(
            DepositStateExportReleaseRequest,
            MAX_DEPOSIT_STATE_EXPORT_RELEASE_REQUEST_BYTES
        );
        rejects_oversize!(DepositStateExportReleaseAck, MAX_DEPOSIT_STATE_EXPORT_RELEASE_ACK_BYTES);
        rejects_oversize!(
            DepositStateImportedAckDelivery,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_DELIVERY_BYTES
        );
        rejects_oversize!(
            DepositStateImportedAckReceipt,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_RECEIPT_BYTES
        );
        rejects_oversize!(
            DepositStateImportedCertificateDelivery,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_DELIVERY_BYTES
        );
        rejects_oversize!(
            DepositStateImportedCertificateReceipt,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_RECEIPT_BYTES
        );
    }

    #[test]
    fn zero_mac_key_is_never_an_export_authority() {
        assert!(matches!(
            reject_zero_mac_key(&[0; 32]),
            Err(DepositStateTransferWireError::ZeroMacKey)
        ));
        assert!(reject_zero_mac_key(&[1; 32]).is_ok());
    }
}
