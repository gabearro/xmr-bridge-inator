//! Durable, non-authoritative staging for compact deposit-state synchronization.
//!
//! A peer advertisement is only an availability anchor. Downloaded objects remain in a distinct
//! wallet-artifact kind and can never be opened by the live registry, index, or certificate
//! archive stores. The complete candidate is re-authenticated by `DepositService` before its
//! existing wallet-snapshot CAS grants any authority.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::OpenOptions,
    io,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand_core::OsRng;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId},
    compact_registry_archive::{
        COMPACT_REGISTRY_APPEND_OBJECTS, COMPACT_REGISTRY_GENESIS_OBJECTS,
        CompactRegistryArchiveError, CompactRegistryArchiveHead, CompactRegistryObjectReader,
        CompactRegistryObjectRef,
    },
    deposit_index::{DepositIndexError, DepositIndexObjectId, DepositIndexReader},
    deposit_index_checkpoint::PortableDepositIndexHead,
    deposit_state_export::{
        DepositPostHandoffExportSealCertificate, DepositPostHandoffExportSealStatement,
        DepositStateExportError, VerifiedDepositPostHandoffExportSeal,
        VerifiedPreImportDepositStateExportSeal,
    },
    deposit_state_import::VerifiedStateImportedCertificate,
    deposit_state_transfer_wire::{
        DEPOSIT_STATE_TRANSFER_WIRE_VERSION, DepositStateExportHeadRequest,
        DepositStateExportHeadResponse, DepositStateExportLease,
        DepositStateExportObjectRequestEntry, DepositStateExportObjectsRequest,
        DepositStateExportObjectsResponse, DepositStateExportReleaseAck,
        DepositStateExportReleaseRequest, DepositStateTransferContext,
        DepositStateTransferWireError,
    },
    deposit_sync_support::{
        DepositSyncSupportCertificate, DepositSyncSupportError, DepositSyncSupportStatement,
        MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES, VerifiedDepositSyncSupportCertificate,
    },
    deposit_sync_wire::{
        DEPOSIT_SYNC_WIRE_VERSION, DepositSyncAdvertisement, DepositSyncAnchorLease,
        DepositSyncContext, DepositSyncHeadRequest, DepositSyncHeadResponse, DepositSyncObject,
        DepositSyncObjectRef, DepositSyncObjectRequestEntry, DepositSyncReleaseAck,
        DepositSyncReleaseRequest, DepositSyncTraversalTarget, DepositSyncWireError,
        MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES, MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES,
        MAX_DEPOSIT_SYNC_REQUEST_OBJECTS,
    },
    deposit_wallet::DepositSubaddressIndex,
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{
        DepositSyncSpoolHeadKey, DepositSyncSpoolHeadMetadata, MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
        MAX_WALLET_ARTIFACT_BYTES, ProtocolStore, StoreError, WalletArtifactKind,
        WalletArtifactOwner, WalletArtifactRef, WalletArtifactStore, WalletId,
    },
};

const DEPOSIT_SYNC_SPOOL_HEAD_VERSION: u16 = 9;
const DEPOSIT_SYNC_SPOOL_PAGE_VERSION: u16 = 7;
const DEPOSIT_SYNC_SPOOL_OBJECT_VERSION: u16 = 7;
const DEPOSIT_SYNC_SPOOL_FRONTIER_VERSION: u16 = 7;
const DEPOSIT_SYNC_SPOOL_INDEX_VERSION: u16 = 8;
const DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION: u16 = 7;
const DEPOSIT_SYNC_SPOOL_SEALED_VALUE_VERSION: u16 = 7;
const STAGE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync-stage/anchor/v2";
const SPOOL_NAMESPACE_DIRECTORY: &str = "deposit-sync-spool-v7";
const SPOOL_CATALOG_DIRECTORY: &str = "authenticated-catalog-v7";
const SPOOL_DELETING_NAMESPACE_PREFIX: &str = ".deleting-v7-";
const SPOOL_MEMBERSHIP_DATABASE_FILE: &str = "objects-v7.redb";
const SPOOL_KEY_DERIVATION_SALT: &[u8] = b"threshold-monero/deposit-sync-spool/hkdf/v7";
const SPOOL_LOOKUP_KEY_INFO: &[u8] = b"membership-lookup-key";
const SPOOL_VALUE_KEY_INFO: &[u8] = b"membership-value-aead-key";
const SPOOL_MEMBERSHIP_LOOKUP_DOMAIN: &[u8] =
    b"threshold-monero/deposit-sync-spool/membership-lookup/v7";
const SPOOL_REPLAY_LOOKUP_DOMAIN: &[u8] = b"threshold-monero/deposit-sync-spool/replay-lookup/v7";
const SPOOL_RESPONSE_EVIDENCE_LOOKUP_DOMAIN: &[u8] =
    b"threshold-monero/deposit-sync-spool/response-evidence-lookup/v1";
const SPOOL_RESPONSE_EVIDENCE_ACCUMULATOR_DOMAIN: &str =
    "threshold-monero/deposit-sync-spool/response-evidence-accumulator/v1";
const SPOOL_CHECKPOINT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync-spool/checkpoint/v7";
const SPOOL_OBJECTS_DIGEST_DOMAIN: &str = "threshold-monero/deposit-sync-spool/page-objects/v7";
const CERTIFIED_EXPORT_TARGET_BINDING_DOMAIN: &str =
    "threshold-monero/deposit-sync-spool/certified-export-target/v1";
const CERTIFIED_EXPORT_HEAD_NONCE_DOMAIN: &str =
    "threshold-monero/deposit-sync-spool/certified-export-head-nonce/v1";
const SPOOL_VERIFIED_SUMMARY_DOMAIN: &str =
    "threshold-monero/deposit-sync-spool/verified-summary/v1";
// Must match the canonical QUIC traversal encoding. The stage decodes only the terminal shape so
// it can refuse an arbitrary non-exhausted opaque downloader cursor.
const DEPOSIT_SYNC_DOWNLOAD_FRONTIER_VERSION: u16 = 3;
const SPOOL_MEMBERSHIP_VALUE_LABEL: &[u8] = b"membership";
const SPOOL_REPLAY_VALUE_LABEL: &[u8] = b"request-replay";
const SPOOL_RESPONSE_EVIDENCE_VALUE_LABEL: &[u8] = b"response-evidence";
const SPOOL_INDEX_VALUE_LABEL: &[u8] = b"index-head";
const SPOOL_INDEX_HEAD_KEY: &[u8] = b"head";
const MAX_DEPOSIT_SYNC_SPOOL_MEMBERSHIP_RECORD_BYTES: usize =
    MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES + 64 * 1024;
const MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES: usize = 4 * 1024;
const MAX_DEPOSIT_SYNC_SPOOL_SEALED_VALUE_BYTES: usize =
    MAX_DEPOSIT_SYNC_SPOOL_MEMBERSHIP_RECORD_BYTES + 64 * 1024;
const DEPOSIT_SYNC_SPOOL_DATABASE_CACHE_BYTES: usize = 4 * 1024 * 1024;

const SPOOL_MEMBERSHIP_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-sync-spool-membership-v7");
const SPOOL_REPLAY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-sync-spool-replay-v7");
const SPOOL_RESPONSE_EVIDENCE_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-sync-spool-response-evidence-v1");
const SPOOL_INDEX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-sync-spool-index-v7");
/// Immutable metadata page for the bounded disk-backed sync spool.
///
/// It is deliberately disjoint from both staged object envelopes and every live artifact kind.
pub const DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT: WalletArtifactKind = WalletArtifactKind(0xd502);
/// Candidate-bound object envelope used by the multi-anchor spool.
pub const DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT: WalletArtifactKind = WalletArtifactKind(0xd503);
/// Candidate-bound recovery envelope for a maximum-sized capability frontier.
pub const DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT: WalletArtifactKind = WalletArtifactKind(0xd504);
/// Exact validated SyncHead response retained for restart-safe historical lease resumption.
pub const DEPOSIT_SYNC_SPOOL_HEAD_RESPONSE_ARTIFACT: WalletArtifactKind =
    WalletArtifactKind(0xd505);
/// Out-of-line exact SyncHead response retained for one fixed-size authenticated support claim.
pub const DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT: WalletArtifactKind =
    WalletArtifactKind(0xd506);
/// Out-of-line canonical prefix-support certificate. It remains non-authoritative until decoded
/// and reverified against a locally authenticated registry target in the current process.
pub const DEPOSIT_SYNC_SPOOL_PREFIX_CERTIFICATE_ARTIFACT: WalletArtifactKind =
    WalletArtifactKind(0xd507);

/// At most one exact anchor may consume the admission slot of an authenticated committee source.
/// Committees are already hard bounded by this same engineering limit.
pub const MAX_DEPOSIT_SYNC_STAGE_CANDIDATES: usize = MAX_COMMITTEE_MEMBERS;
const STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES: u64 = 4 * 1024;
const SPOOL_INDEX_RECORD_PHYSICAL_OVERHEAD_BYTES: u64 = 8 * 1024;
/// A page is exactly one wire-request-sized unit, so a Byzantine source cannot force an
/// unbounded pending intent or page decode.
pub const MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS: usize = MAX_DEPOSIT_SYNC_REQUEST_OBJECTS;
/// The mutable head contains counters, one cursor/delivery intent, and at most one page intent.
/// Opaque planner/verifier state is bounded independently of lifetime object and page counts.
///
/// A maximum-width traversal can carry 128 frames with 16 KiB of authenticated reducer state per
/// frame. Two MiB admits that exact worst case without turning the mutable head into an
/// unbounded attacker-controlled allocation.
pub const MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES: usize = 2 * 1024 * 1024;
const MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES: usize = MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES + 1024;
/// Maximum canonical semantic summary retained after full verification.
pub const MAX_DEPOSIT_SYNC_VERIFIED_SUMMARY_BYTES: usize = 16 * 1024;
/// A page contains only bounded content addresses, never object plaintext.
pub const MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES: usize = 256 * 1024;
/// Per-page plaintext bound. Lifetime byte totals are checked `u64` counters, while the
/// candidate-derived `maximum_objects` binding supplies the lifetime reachable-object quota.
pub const MAX_DEPOSIT_SYNC_SPOOL_PAGE_PLAINTEXT_BYTES: u64 =
    MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES as u64;
const MAX_DEPOSIT_SYNC_SPOOL_PAGE_PHYSICAL_BYTES: u64 = MAX_DEPOSIT_SYNC_SPOOL_PAGE_PLAINTEXT_BYTES
    + MAX_DEPOSIT_SYNC_SPOOL_PAGE_PLAINTEXT_BYTES
    + (MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS as u64) * STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES
    + (MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS as u64) * SPOOL_INDEX_RECORD_PHYSICAL_OVERHEAD_BYTES
    + MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES as u64
    + STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES
    + MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES as u64
    + STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DepositSyncAnchorId([u8; 32]);

impl DepositSyncAnchorId {
    #[must_use]
    pub fn for_advertisement(advertisement: &DepositSyncAdvertisement) -> Self {
        Self::for_admission(advertisement, DepositSyncSpoolAdmissionKind::Ordinary)
    }

    fn for_admission(
        advertisement: &DepositSyncAdvertisement,
        admission: DepositSyncSpoolAdmissionKind,
    ) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(STAGE_DIGEST_DOMAIN);
        let context = advertisement.context();
        hasher.update(&context.network());
        hasher.update(&context.wallet().0);
        hasher.update(&advertisement.digest());
        match admission {
            DepositSyncSpoolAdmissionKind::Ordinary => {
                hasher.update(&[0]);
            }
            DepositSyncSpoolAdmissionKind::CertifiedExport {
                request_digest,
                semantic_transition,
                seal_certificate,
            } => {
                hasher.update(&[1]);
                hasher.update(&request_digest);
                hasher.update(&semantic_transition);
                hasher.update(&seal_certificate);
            }
        }
        Self(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolAdmissionKind {
    Ordinary,
    CertifiedExport {
        request_digest: [u8; 32],
        semantic_transition: [u8; 32],
        seal_certificate: [u8; 32],
    },
}

/// Exact authority binding carried by the mutable spool head and every immutable page.
///
/// `candidate_root` is the exact advertisement digest, not merely a semantic checkpoint height.
/// Together with the network/wallet key and derived anchor this prevents a valid page from one
/// candidate, fork, wallet, or network from being substituted into another spool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolBinding {
    key: DepositSyncSpoolHeadKey,
    anchor: DepositSyncAnchorId,
    admission: DepositSyncSpoolAdmissionKind,
    candidate_root: [u8; 32],
    maximum_objects: u64,
}

/// Durable bounded stage of one exact candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositSyncSpoolPhase {
    Downloading,
    Frozen,
    Verifying,
    Verified,
    Materializing,
    ReadyToCas,
    Deleting,
}

/// Authenticated bounded reducer position.
///
/// The state bytes are interpreted only by the phase owner in the QUIC/service integration.
/// Storage authenticates their exact bytes and monotonic revision without depending on planner
/// internals.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncSpoolCheckpoint {
    phase: DepositSyncSpoolPhase,
    revision: u64,
    cursor: Vec<u8>,
}

impl DepositSyncSpoolCheckpoint {
    #[must_use]
    pub fn downloading() -> Self {
        Self { phase: DepositSyncSpoolPhase::Downloading, revision: 0, cursor: Vec::new() }
    }

    pub fn successor(
        &self,
        phase: DepositSyncSpoolPhase,
        cursor: Vec<u8>,
    ) -> Result<Self, DepositSyncStageError> {
        let successor = Self {
            phase,
            revision: self
                .revision
                .checked_add(1)
                .ok_or(DepositSyncStageError::InvalidSpoolTransition)?,
            cursor,
        };
        successor.validate()?;
        if !valid_spool_phase_successor(self.phase, successor.phase) {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(successor)
    }

    #[must_use]
    pub const fn phase(&self) -> DepositSyncSpoolPhase {
        self.phase
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn cursor(&self) -> &[u8] {
        &self.cursor
    }

    fn validate(&self) -> Result<(), DepositSyncStageError> {
        if self.cursor.len() > MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], DepositSyncStageError> {
        self.validate()?;
        let encoded = encode_canonical(
            self,
            MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES,
            "deposit sync spool checkpoint",
        )?;
        let mut hasher = blake3::Hasher::new_derive_key(SPOOL_CHECKPOINT_DIGEST_DOMAIN);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }
}

const DEPOSIT_SYNC_VERIFIED_SUMMARY_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncVerifiedSummaryEnvelope {
    version: u16,
    binding: DepositSyncSpoolBinding,
    object_count: u64,
    payload_digest: [u8; 32],
    payload: Vec<u8>,
}

impl DepositSyncVerifiedSummaryEnvelope {
    fn new(
        binding: DepositSyncSpoolBinding,
        object_count: u64,
        payload: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        if payload.is_empty() || payload.len() > MAX_DEPOSIT_SYNC_VERIFIED_SUMMARY_BYTES {
            return Err(DepositSyncStageError::TooLarge {
                kind: "deposit sync verified summary",
                actual: payload.len(),
                maximum: MAX_DEPOSIT_SYNC_VERIFIED_SUMMARY_BYTES,
            });
        }
        let mut hasher = blake3::Hasher::new_derive_key(SPOOL_VERIFIED_SUMMARY_DOMAIN);
        hasher.update(&(payload.len() as u64).to_le_bytes());
        hasher.update(payload);
        let envelope = Self {
            version: DEPOSIT_SYNC_VERIFIED_SUMMARY_VERSION,
            binding,
            object_count,
            payload_digest: *hasher.finalize().as_bytes(),
            payload: payload.to_vec(),
        };
        envelope.validate(binding, object_count)?;
        Ok(envelope)
    }

    fn validate(
        &self,
        binding: DepositSyncSpoolBinding,
        object_count: u64,
    ) -> Result<(), DepositSyncStageError> {
        if self.version != DEPOSIT_SYNC_VERIFIED_SUMMARY_VERSION
            || self.binding != binding
            || self.object_count != object_count
            || self.object_count == 0
            || self.object_count > binding.maximum_objects
            || self.payload.is_empty()
            || self.payload.len() > MAX_DEPOSIT_SYNC_VERIFIED_SUMMARY_BYTES
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let mut hasher = blake3::Hasher::new_derive_key(SPOOL_VERIFIED_SUMMARY_DOMAIN);
        hasher.update(&(self.payload.len() as u64).to_le_bytes());
        hasher.update(&self.payload);
        if *hasher.finalize().as_bytes() != self.payload_digest {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        Ok(())
    }

    fn to_checkpoint_cursor(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        encode_canonical(
            self,
            MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit sync verified-summary envelope",
        )
    }

    fn from_checkpoint_cursor(
        binding: DepositSyncSpoolBinding,
        object_count: u64,
        cursor: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let envelope: Self = decode_canonical(
            cursor,
            MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit sync verified-summary envelope",
        )?;
        envelope.validate(binding, object_count)?;
        Ok(envelope)
    }
}

/// Exact request-to-checkpoint transition committed with one immutable page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncSpoolPageTransition {
    request_digest: [u8; 32],
    response_digest: [u8; 32],
    objects_digest: [u8; 32],
    expected_revision: u64,
    expected_checkpoint_digest: [u8; 32],
    next_revision: u64,
    next_checkpoint_digest: [u8; 32],
}

impl DepositSyncSpoolPageTransition {
    pub fn new(
        request_digest: [u8; 32],
        response_digest: [u8; 32],
        objects_digest: [u8; 32],
        expected: &DepositSyncSpoolCheckpoint,
        next: &DepositSyncSpoolCheckpoint,
    ) -> Result<Self, DepositSyncStageError> {
        expected.validate()?;
        next.validate()?;
        let transition = Self {
            request_digest,
            response_digest,
            objects_digest,
            expected_revision: expected.revision,
            expected_checkpoint_digest: expected.digest()?,
            next_revision: next.revision,
            next_checkpoint_digest: next.digest()?,
        };
        transition.validate()?;
        Ok(transition)
    }

    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    #[must_use]
    pub const fn response_digest(&self) -> [u8; 32] {
        self.response_digest
    }

    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    #[must_use]
    pub const fn next_revision(&self) -> u64 {
        self.next_revision
    }

    fn validate(&self) -> Result<(), DepositSyncStageError> {
        if self.request_digest == [0; 32]
            || self.response_digest == [0; 32]
            || self.objects_digest == [0; 32]
            || self.expected_checkpoint_digest == [0; 32]
            || self.next_checkpoint_digest == [0; 32]
            || self.expected_revision.checked_add(1) != Some(self.next_revision)
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(())
    }

    fn validate_checkpoints(
        &self,
        expected: &DepositSyncSpoolCheckpoint,
        next: &DepositSyncSpoolCheckpoint,
    ) -> Result<(), DepositSyncStageError> {
        self.validate()?;
        if expected.phase != DepositSyncSpoolPhase::Downloading
            || next.phase != DepositSyncSpoolPhase::Downloading
            || expected.revision != self.expected_revision
            || next.revision != self.next_revision
            || expected.digest()? != self.expected_checkpoint_digest
            || next.digest()? != self.next_checkpoint_digest
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(())
    }
}

const fn valid_spool_phase_successor(
    current: DepositSyncSpoolPhase,
    next: DepositSyncSpoolPhase,
) -> bool {
    matches!(
        (current, next),
        (DepositSyncSpoolPhase::Downloading, DepositSyncSpoolPhase::Downloading)
            | (DepositSyncSpoolPhase::Downloading, DepositSyncSpoolPhase::Frozen)
            | (DepositSyncSpoolPhase::Frozen, DepositSyncSpoolPhase::Frozen)
            | (DepositSyncSpoolPhase::Frozen, DepositSyncSpoolPhase::Verifying)
            | (DepositSyncSpoolPhase::Verifying, DepositSyncSpoolPhase::Verifying)
            | (DepositSyncSpoolPhase::Verifying, DepositSyncSpoolPhase::Verified)
            | (DepositSyncSpoolPhase::Verified, DepositSyncSpoolPhase::Verifying)
            | (DepositSyncSpoolPhase::Verified, DepositSyncSpoolPhase::Verified)
            | (DepositSyncSpoolPhase::Verified, DepositSyncSpoolPhase::Materializing)
            | (DepositSyncSpoolPhase::Materializing, DepositSyncSpoolPhase::Verifying)
            | (DepositSyncSpoolPhase::Materializing, DepositSyncSpoolPhase::Materializing)
            | (DepositSyncSpoolPhase::Materializing, DepositSyncSpoolPhase::ReadyToCas)
            | (DepositSyncSpoolPhase::Materializing, DepositSyncSpoolPhase::Verified)
            | (DepositSyncSpoolPhase::ReadyToCas, DepositSyncSpoolPhase::Verifying)
            | (DepositSyncSpoolPhase::ReadyToCas, DepositSyncSpoolPhase::ReadyToCas)
            | (DepositSyncSpoolPhase::ReadyToCas, DepositSyncSpoolPhase::Verified)
            | (_, DepositSyncSpoolPhase::Deleting)
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolObjectEnvelope {
    version: u16,
    binding: DepositSyncSpoolBinding,
    reference: DepositSyncObjectRef,
    bytes: Vec<u8>,
}

impl DepositSyncSpoolObjectEnvelope {
    fn from_object(
        binding: DepositSyncSpoolBinding,
        object: &DepositSyncObject,
    ) -> Result<Self, DepositSyncStageError> {
        drop(DepositSyncObject::new(object.reference(), object.bytes().to_vec())?);
        Ok(Self {
            version: DEPOSIT_SYNC_SPOOL_OBJECT_VERSION,
            binding,
            reference: object.reference(),
            bytes: object.bytes().to_vec(),
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        if self.version != DEPOSIT_SYNC_SPOOL_OBJECT_VERSION {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        drop(DepositSyncObject::new(self.reference, self.bytes.clone())?);
        encode_canonical(self, MAX_WALLET_ARTIFACT_BYTES, "deposit sync spool object")
    }

    fn from_bytes(
        binding: DepositSyncSpoolBinding,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let envelope: Self =
            decode_canonical(bytes, MAX_WALLET_ARTIFACT_BYTES, "deposit sync spool object")?;
        if envelope.version != DEPOSIT_SYNC_SPOOL_OBJECT_VERSION || envelope.binding != binding {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        drop(DepositSyncObject::new(envelope.reference, envelope.bytes.clone())?);
        Ok(envelope)
    }

    fn into_object(self) -> Result<DepositSyncObject, DepositSyncStageError> {
        Ok(DepositSyncObject::new(self.reference, self.bytes)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolFrontierEnvelope {
    version: u16,
    binding: DepositSyncSpoolBinding,
    checkpoint: DepositSyncSpoolCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncDurableDownloadFrontier {
    version: u16,
    lease: DepositSyncAnchorLease,
    pending: Vec<DepositSyncObjectRequestEntry>,
    complete: bool,
}

impl DepositSyncDurableDownloadFrontier {
    fn completed_embedded(bytes: &[u8]) -> Result<Self, DepositSyncStageError> {
        let frontier: Self = decode_canonical(
            bytes,
            MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit sync completed download frontier",
        )
        .map_err(|_| DepositSyncStageError::IncompleteObjectGraph)?;
        if frontier.version != DEPOSIT_SYNC_DOWNLOAD_FRONTIER_VERSION
            || !frontier.complete
            || !frontier.pending.is_empty()
        {
            return Err(DepositSyncStageError::IncompleteObjectGraph);
        }
        Ok(frontier)
    }

    fn completed(
        lease: DepositSyncAnchorLease,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let frontier = Self::completed_embedded(bytes)?;
        if frontier.lease != lease {
            return Err(DepositSyncStageError::IncompleteObjectGraph);
        }
        Ok(frontier)
    }
}

/// One restart-stable certified-export traversal frame.
///
/// Export capabilities deliberately use a different wire domain from ordinary compact sync.
/// Keeping their typed entries in a disjoint cursor prevents a valid ordinary capability from
/// being reinterpreted as historical-export authority after a restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositStateExportTraversalFrame {
    entry: DepositStateExportObjectRequestEntry,
    children: Option<Vec<DepositStateExportObjectRequestEntry>>,
    next_child: u16,
}

/// Durable depth-first traversal of one exact old-quorum-certified export lease.
///
/// This is non-authoritative staging state. Every request and response remains bound to the
/// source-issued export lease, while final wallet authority still requires the service's complete
/// graph verification and wallet-snapshot CAS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportDownloadFrontier {
    version: u16,
    lease: DepositStateExportLease,
    root_index: u8,
    stack: Vec<DepositStateExportTraversalFrame>,
    complete: bool,
}

impl DepositStateExportDownloadFrontier {
    pub fn fresh(lease: DepositStateExportLease) -> Result<Self, DepositSyncStageError> {
        let root =
            *lease.root_targets()?.first().ok_or(DepositSyncStageError::IncompleteObjectGraph)?;
        let frontier = Self {
            version: DEPOSIT_STATE_TRANSFER_WIRE_VERSION,
            lease,
            root_index: 0,
            stack: vec![DepositStateExportTraversalFrame {
                entry: DepositStateExportObjectRequestEntry::advertised_root(lease, root)?,
                children: None,
                next_child: 0,
            }],
            complete: false,
        };
        frontier.validate()?;
        Ok(frontier)
    }

    pub fn from_checkpoint(
        lease: DepositStateExportLease,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        if bytes.is_empty() {
            return Self::fresh(lease);
        }
        let frontier: Self = decode_canonical(
            bytes,
            MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit certified-export download frontier",
        )?;
        if frontier.lease != lease {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        frontier.validate()?;
        Ok(frontier)
    }

    fn completed(
        lease: DepositStateExportLease,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let frontier = Self::from_checkpoint(lease, bytes)
            .map_err(|_| DepositSyncStageError::IncompleteObjectGraph)?;
        let roots =
            lease.root_targets().map_err(|_| DepositSyncStageError::IncompleteObjectGraph)?;
        if !frontier.complete
            || !frontier.stack.is_empty()
            || usize::from(frontier.root_index) != roots.len()
        {
            return Err(DepositSyncStageError::IncompleteObjectGraph);
        }
        Ok(frontier)
    }

    fn completed_embedded(bytes: &[u8]) -> Result<Self, DepositSyncStageError> {
        let frontier: Self = decode_canonical(
            bytes,
            MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit certified-export completed frontier",
        )
        .map_err(|_| DepositSyncStageError::IncompleteObjectGraph)?;
        let lease = frontier.lease;
        Self::completed(lease, bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        self.validate()?;
        encode_canonical(
            self,
            MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
            "deposit certified-export download frontier",
        )
    }

    #[must_use]
    pub const fn lease(&self) -> DepositStateExportLease {
        self.lease
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn request(
        &self,
    ) -> Result<Option<DepositStateExportObjectsRequest>, DepositSyncStageError> {
        self.validate()?;
        if self.complete {
            return Ok(None);
        }
        let frame = self.stack.last().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        if frame.children.is_some() || frame.next_child != 0 {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        Ok(Some(DepositStateExportObjectsRequest::new(self.lease, vec![frame.entry])?))
    }

    pub fn apply_response(
        &mut self,
        request: &DepositStateExportObjectsRequest,
        response: &DepositStateExportObjectsResponse,
    ) -> Result<(), DepositSyncStageError> {
        self.validate()?;
        response.validate_for(request)?;
        if request.lease() != self.lease || self.request()?.as_ref() != Some(request) {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        let frame = self.stack.last().cloned().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        let [object] = response.objects() else {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        };
        if object.reference() != frame.entry.reference() {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        let mut children = object.authenticated_semantic_children(frame.entry.target())?;
        if matches!(children.first(), Some(DepositSyncTraversalTarget::ArchiveSegment { .. })) {
            children.rotate_left(1);
        }
        let child_entries = children
            .into_iter()
            .map(|child| {
                let mut matching = response.capabilities().iter().copied().filter(|capability| {
                    capability.parent() == frame.entry.target() && capability.child() == child
                });
                let capability =
                    matching.next().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
                if matching.next().is_some() {
                    return Err(DepositSyncStageError::InvalidSpoolCursor);
                }
                Ok(DepositStateExportObjectRequestEntry::authorized(capability))
            })
            .collect::<Result<Vec<_>, DepositSyncStageError>>()?;
        if child_entries.len() > MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        let current = self.stack.last_mut().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        current.children = Some(child_entries);
        self.advance()?;
        self.validate()
    }

    fn advance(&mut self) -> Result<(), DepositSyncStageError> {
        loop {
            if let Some(current) = self.stack.last_mut() {
                let children =
                    current.children.as_ref().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
                if let Some(entry) = children.get(usize::from(current.next_child)).copied() {
                    current.next_child = current
                        .next_child
                        .checked_add(1)
                        .ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
                    self.stack.push(DepositStateExportTraversalFrame {
                        entry,
                        children: None,
                        next_child: 0,
                    });
                    return Ok(());
                }
                self.stack.pop();
                continue;
            }

            let roots = self.lease.root_targets()?;
            self.root_index =
                self.root_index.checked_add(1).ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
            if let Some(root) = roots.get(usize::from(self.root_index)).copied() {
                self.stack.push(DepositStateExportTraversalFrame {
                    entry: DepositStateExportObjectRequestEntry::advertised_root(self.lease, root)?,
                    children: None,
                    next_child: 0,
                });
            } else {
                self.complete = true;
            }
            return Ok(());
        }
    }

    fn validate(&self) -> Result<(), DepositSyncStageError> {
        let roots = self.lease.root_targets()?;
        if self.version != DEPOSIT_STATE_TRANSFER_WIRE_VERSION
            || self.complete != self.stack.is_empty()
            || usize::from(self.root_index) > roots.len()
            || self.complete != (usize::from(self.root_index) == roots.len())
        {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        if let Some(first) = self.stack.first() {
            let expected = DepositStateExportObjectRequestEntry::advertised_root(
                self.lease,
                roots[usize::from(self.root_index)],
            )?;
            if first.entry != expected {
                return Err(DepositSyncStageError::InvalidSpoolCursor);
            }
        }
        for (index, frame) in self.stack.iter().enumerate() {
            DepositStateExportObjectsRequest::new(self.lease, vec![frame.entry])?;
            if index + 1 == self.stack.len() {
                if frame.children.is_some() || frame.next_child != 0 {
                    return Err(DepositSyncStageError::InvalidSpoolCursor);
                }
                continue;
            }
            let children =
                frame.children.as_ref().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
            if children.is_empty()
                || children.len() > MAX_DEPOSIT_SYNC_PAGE_CAPABILITIES
                || usize::from(frame.next_child) == 0
                || usize::from(frame.next_child) > children.len()
                || children[usize::from(frame.next_child) - 1] != self.stack[index + 1].entry
            {
                return Err(DepositSyncStageError::InvalidSpoolCursor);
            }
            for child in children {
                DepositStateExportObjectsRequest::new(self.lease, vec![*child])?;
                let capability =
                    child.capability().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
                if capability.parent() != frame.entry.target()
                    || capability.child() != child.target()
                {
                    return Err(DepositSyncStageError::InvalidSpoolCursor);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn completed_download_frontier_for_test(
    lease: DepositSyncAnchorLease,
) -> Result<Vec<u8>, DepositSyncStageError> {
    encode_canonical(
        &DepositSyncDurableDownloadFrontier {
            version: DEPOSIT_SYNC_DOWNLOAD_FRONTIER_VERSION,
            lease,
            pending: Vec::new(),
            complete: true,
        },
        MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES,
        "deposit sync completed download frontier",
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolHeadResponseEnvelope {
    Ordinary {
        version: u16,
        binding: DepositSyncSpoolBinding,
        source: PartyId,
        response: Vec<u8>,
    },
    CertifiedExport {
        version: u16,
        binding: DepositSyncSpoolBinding,
        source: PartyId,
        requester: PartyId,
        request: Vec<u8>,
        response: Vec<u8>,
    },
}

/// Process-local authority shared by the full import seal and the deliberately weaker cold-target
/// pre-import token. Implementations may only validate and persist bounded export-read state.
trait CertifiedExportReadSeal {
    fn statement(&self) -> &DepositPostHandoffExportSealStatement;
    fn statement_digest(&self) -> [u8; 32];
    fn certificate_digest(&self) -> [u8; 32];
    fn canonical_certificate_bytes(&self) -> &[u8];
    fn validate_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateExportError>;
    fn validate_head(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
    ) -> Result<(), DepositStateTransferWireError>;
}

impl CertifiedExportReadSeal for VerifiedDepositPostHandoffExportSeal {
    fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        VerifiedDepositPostHandoffExportSeal::statement(self)
    }

    fn statement_digest(&self) -> [u8; 32] {
        VerifiedDepositPostHandoffExportSeal::statement_digest(self)
    }

    fn certificate_digest(&self) -> [u8; 32] {
        VerifiedDepositPostHandoffExportSeal::certificate_digest(self)
    }

    fn canonical_certificate_bytes(&self) -> &[u8] {
        VerifiedDepositPostHandoffExportSeal::canonical_certificate_bytes(self)
    }

    fn validate_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateExportError> {
        VerifiedDepositPostHandoffExportSeal::validate_target(self, target)
    }

    fn validate_head(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
    ) -> Result<(), DepositStateTransferWireError> {
        response.validate_verified_seal(request, self)
    }
}

impl CertifiedExportReadSeal for VerifiedPreImportDepositStateExportSeal {
    fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        VerifiedPreImportDepositStateExportSeal::statement(self)
    }

    fn statement_digest(&self) -> [u8; 32] {
        VerifiedPreImportDepositStateExportSeal::statement_digest(self)
    }

    fn certificate_digest(&self) -> [u8; 32] {
        VerifiedPreImportDepositStateExportSeal::certificate_digest(self)
    }

    fn canonical_certificate_bytes(&self) -> &[u8] {
        VerifiedPreImportDepositStateExportSeal::canonical_certificate_bytes(self)
    }

    fn validate_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateExportError> {
        VerifiedPreImportDepositStateExportSeal::validate_target(self, target)
    }

    fn validate_head(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
    ) -> Result<(), DepositStateTransferWireError> {
        response.validate_pre_import_verified_seal(request, self)
    }
}

impl DepositSyncSpoolHeadResponseEnvelope {
    fn from_response(
        binding: DepositSyncSpoolBinding,
        response: &DepositSyncHeadResponse,
        requester: PartyId,
    ) -> Result<Self, DepositSyncStageError> {
        let request = DepositSyncHeadRequest::new(
            response.advertisement().context(),
            response.lease().source(),
            requester,
        )?;
        let bytes = response.to_bytes(request)?;
        Ok(Self::Ordinary {
            version: DEPOSIT_SYNC_SPOOL_HEAD_VERSION,
            binding,
            source: response.lease().source(),
            response: bytes,
        })
    }

    fn from_certified_export<S: CertifiedExportReadSeal + ?Sized>(
        binding: DepositSyncSpoolBinding,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
        seal: &S,
    ) -> Result<Self, DepositSyncStageError> {
        seal.validate_head(request, response)?;
        if certified_export_spool_binding(request, response)? != binding
            || request.context().network() != binding.key.network_id
            || request.context().wallet() != binding.key.wallet_id
            || request.source() != response.source()
            || request.requester() != response.requester()
        {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        Ok(Self::CertifiedExport {
            version: DEPOSIT_SYNC_SPOOL_HEAD_VERSION,
            binding,
            source: request.source(),
            requester: request.requester(),
            request: request.to_bytes()?,
            response: response.to_bytes(request)?,
        })
    }

    const fn source(&self) -> PartyId {
        match self {
            Self::Ordinary { source, .. } | Self::CertifiedExport { source, .. } => *source,
        }
    }

    const fn binding(&self) -> DepositSyncSpoolBinding {
        match self {
            Self::Ordinary { binding, .. } | Self::CertifiedExport { binding, .. } => *binding,
        }
    }

    const fn version(&self) -> u16 {
        match self {
            Self::Ordinary { version, .. } | Self::CertifiedExport { version, .. } => *version,
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        if self.version() != DEPOSIT_SYNC_SPOOL_HEAD_VERSION {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        match self {
            Self::Ordinary { binding, source, response, .. } => {
                if source.0 == 0 || *binding != self.binding() || response.is_empty() {
                    return Err(DepositSyncStageError::InvalidEnvelope);
                }
            }
            Self::CertifiedExport { binding, source, requester, request, response, .. } => {
                if source.0 == 0
                    || requester.0 == 0
                    || *binding != self.binding()
                    || request.is_empty()
                    || response.is_empty()
                {
                    return Err(DepositSyncStageError::InvalidEnvelope);
                }
            }
        }
        encode_canonical(self, MAX_WALLET_ARTIFACT_BYTES, "deposit sync spool head response")
    }

    fn from_bytes(
        binding: DepositSyncSpoolBinding,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let envelope: Self =
            decode_canonical(bytes, MAX_WALLET_ARTIFACT_BYTES, "deposit sync spool head response")?;
        if envelope.version() != DEPOSIT_SYNC_SPOOL_HEAD_VERSION
            || envelope.binding() != binding
            || envelope.source().0 == 0
        {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        envelope.to_bytes()?;
        Ok(envelope)
    }

    fn decode_response(
        self,
        requester: PartyId,
    ) -> Result<DepositSyncHeadResponse, DepositSyncStageError> {
        let Self::Ordinary { version, binding, source, response } = self else {
            return Err(DepositSyncStageError::WrongHeadAdmission);
        };
        if version != DEPOSIT_SYNC_SPOOL_HEAD_VERSION {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        let context = crate::deposit_sync_wire::DepositSyncContext::new(
            binding.key.network_id,
            binding.key.wallet_id,
        )?;
        let request = DepositSyncHeadRequest::new(context, source, requester)?;
        let response = DepositSyncHeadResponse::from_bytes(request, &response)?;
        if spool_binding(response.advertisement())? != binding {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        Ok(response)
    }

    fn decode_certified_export(
        self,
    ) -> Result<
        (DepositStateExportHeadRequest, DepositStateExportHeadResponse),
        DepositSyncStageError,
    > {
        let Self::CertifiedExport { version, binding, source, requester, request, response } = self
        else {
            return Err(DepositSyncStageError::WrongHeadAdmission);
        };
        if version != DEPOSIT_SYNC_SPOOL_HEAD_VERSION {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        let request = DepositStateExportHeadRequest::from_bytes(source, requester, &request)?;
        let response = DepositStateExportHeadResponse::from_bytes(request, &response)?;
        if certified_export_spool_binding(request, &response)? != binding
            || response.source() != source
            || response.requester() != requester
        {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        Ok((request, response))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncPrefixCertificateEnvelope {
    version: u16,
    binding: DepositSyncSpoolBinding,
    source: PartyId,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    certificate: Vec<u8>,
}

impl DepositSyncPrefixCertificateEnvelope {
    fn from_verified(
        binding: DepositSyncSpoolBinding,
        verified: &VerifiedDepositSyncSupportCertificate,
    ) -> Result<Self, DepositSyncStageError> {
        let envelope = Self {
            version: DEPOSIT_SYNC_SPOOL_CATALOG_VERSION,
            binding,
            source: verified.statement().source(),
            statement_digest: verified.statement_digest(),
            certificate_digest: verified.certificate_digest(),
            certificate: verified.certificate_bytes().to_vec(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<(), DepositSyncStageError> {
        if self.version != DEPOSIT_SYNC_SPOOL_CATALOG_VERSION
            || self.source.0 == 0
            || self.statement_digest == [0; 32]
            || self.certificate_digest == [0; 32]
            || self.certificate.is_empty()
            || self.certificate.len() > MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES
        {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        self.validate()?;
        encode_canonical(
            self,
            MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES + 1024,
            "deposit sync prefix certificate",
        )
    }

    fn from_bytes(
        binding: DepositSyncSpoolBinding,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let envelope: Self = decode_canonical(
            bytes,
            MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES + 1024,
            "deposit sync prefix certificate",
        )?;
        envelope.validate()?;
        if envelope.binding != binding {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        Ok(envelope)
    }
}

impl DepositSyncSpoolFrontierEnvelope {
    fn new(
        binding: DepositSyncSpoolBinding,
        checkpoint: DepositSyncSpoolCheckpoint,
    ) -> Result<Self, DepositSyncStageError> {
        checkpoint.validate()?;
        if checkpoint.phase != DepositSyncSpoolPhase::Downloading {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(Self { version: DEPOSIT_SYNC_SPOOL_FRONTIER_VERSION, binding, checkpoint })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        if self.version != DEPOSIT_SYNC_SPOOL_FRONTIER_VERSION {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        self.checkpoint.validate()?;
        encode_canonical(
            self,
            MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES + 256,
            "deposit sync spool frontier",
        )
    }

    fn from_bytes(
        binding: DepositSyncSpoolBinding,
        bytes: &[u8],
    ) -> Result<Self, DepositSyncStageError> {
        let envelope: Self = decode_canonical(
            bytes,
            MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES + 256,
            "deposit sync spool frontier",
        )?;
        if envelope.version != DEPOSIT_SYNC_SPOOL_FRONTIER_VERSION
            || envelope.binding != binding
            || envelope.checkpoint.phase != DepositSyncSpoolPhase::Downloading
        {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        envelope.checkpoint.validate()?;
        Ok(envelope)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolPageLink {
    artifact: WalletArtifactRef,
    ordinal: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolEntry {
    reference: DepositSyncObjectRef,
    envelope: WalletArtifactRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolPage {
    version: u16,
    binding: DepositSyncSpoolBinding,
    owner: WalletArtifactOwner,
    ordinal: u64,
    previous: Option<DepositSyncSpoolPageLink>,
    transition: DepositSyncSpoolPageTransition,
    next_checkpoint: WalletArtifactRef,
    entries: Vec<DepositSyncSpoolEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolPendingPage {
    page: DepositSyncSpoolPageLink,
    previous: Option<DepositSyncSpoolPageLink>,
    transition: DepositSyncSpoolPageTransition,
    next_checkpoint: WalletArtifactRef,
    entries: Vec<DepositSyncSpoolEntry>,
    added_plaintext_bytes: u64,
    added_physical_bytes: u64,
    next_membership_revision: u64,
}

/// Journal-before-write intent for the immutable, source-bound SyncHead response.
///
/// The owner and exact binding live in the authenticated spool head. Persisting this reference and
/// source before creating the owned artifact makes every crash cut either resumable or removable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolPendingHeadResponse {
    reference: WalletArtifactRef,
    source: PartyId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolPendingDelete {
    page: DepositSyncSpoolPageLink,
    previous: Option<DepositSyncSpoolPageLink>,
    transition: DepositSyncSpoolPageTransition,
    frontier: WalletArtifactRef,
    entries: Vec<DepositSyncSpoolEntry>,
    removed_plaintext_bytes: u64,
    removed_physical_bytes: u64,
    next_membership_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolDeletion {
    position: Option<DepositSyncSpoolPageLink>,
    remaining_pages: u64,
    remaining_objects: u64,
    pending: Option<DepositSyncSpoolPendingDelete>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolScan {
    snapshot_head: Option<DepositSyncSpoolPageLink>,
    snapshot_pages: u64,
    snapshot_objects: u64,
    position: Option<DepositSyncSpoolPageLink>,
    remaining_pages: u64,
    remaining_objects: u64,
}

/// Journal-before-release cursor for materialized permanent-artifact reservations.
///
/// The marker binds the immutable ReadyToCas projection. `position` advances only after every
/// artifact in one bounded immutable page has been authenticated and its reservation has been
/// released. A crash may therefore replay at most one page, and the storage primitive makes that
/// replay idempotent while still rejecting a reservation owned by another journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolOwnershipRelease {
    marker: DepositSyncImportMarker,
    position: Option<DepositSyncSpoolPageLink>,
    remaining_pages: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolHead {
    version: u16,
    binding: DepositSyncSpoolBinding,
    owner: WalletArtifactOwner,
    head_response: Option<WalletArtifactRef>,
    pending_head_response: Option<DepositSyncSpoolPendingHeadResponse>,
    /// Revision at which the current source-bound download traversal began.
    ///
    /// A reset advances the checkpoint and this floor together. Replay evidence from a lower
    /// revision therefore remains immutable equivocation evidence while an exact response may be
    /// consumed again by a later traversal generation.
    download_generation_start_revision: u64,
    /// Number of sealed response-evidence rows which are not backed by immutable object pages.
    ///
    /// A response containing only previously staged objects still needs permanent equivocation
    /// evidence. This authenticated counter is advanced with the downloader checkpoint through a
    /// Redb prepare/head-CAS/finalize journal.
    response_evidence_count: u64,
    /// Commutative accumulator over every sealed response-evidence row.
    ///
    /// Full reconciliation recomputes this projection, so deleting or replacing an older row
    /// cannot turn permanent equivocation evidence back into an unseen request.
    response_evidence_accumulator: [u8; 32],
    committed: Option<DepositSyncSpoolPageLink>,
    membership_revision: u64,
    page_count: u64,
    object_count: u64,
    plaintext_bytes: u64,
    physical_bytes: u64,
    checkpoint: DepositSyncSpoolCheckpoint,
    last_transition: Option<DepositSyncSpoolPageTransition>,
    pending: Option<DepositSyncSpoolPendingPage>,
    scan: Option<DepositSyncSpoolScan>,
    ownership_release: Option<DepositSyncSpoolOwnershipRelease>,
    deletion: Option<DepositSyncSpoolDeletion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolMembershipRecord {
    version: u16,
    binding: DepositSyncSpoolBinding,
    reference: DepositSyncObjectRef,
    envelope: WalletArtifactRef,
    first_page: DepositSyncSpoolPageLink,
    entry_index: u16,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolReplayRecord {
    version: u16,
    binding: DepositSyncSpoolBinding,
    transition: DepositSyncSpoolPageTransition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolResponseEvidenceState {
    Stable {
        records: u64,
        accumulator: [u8; 32],
    },
    Prepared {
        prior_records: u64,
        next_records: u64,
        prior_accumulator: [u8; 32],
        next_accumulator: [u8; 32],
        transition: DepositSyncSpoolPageTransition,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolIndexState {
    Stable {
        membership_revision: u64,
        latest: Option<DepositSyncSpoolPageLink>,
        pages: u64,
        objects: u64,
    },
    Prepared {
        prior_revision: u64,
        next_revision: u64,
        prior_latest: Option<DepositSyncSpoolPageLink>,
        next_latest: DepositSyncSpoolPageLink,
        prior_pages: u64,
        next_pages: u64,
        prior_objects: u64,
        next_objects: u64,
    },
    PreparedDelete {
        prior_revision: u64,
        next_revision: u64,
        prior_latest: DepositSyncSpoolPageLink,
        next_latest: Option<DepositSyncSpoolPageLink>,
        prior_pages: u64,
        next_pages: u64,
        prior_objects: u64,
        next_objects: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolIndexHead {
    version: u16,
    binding: DepositSyncSpoolBinding,
    response_evidence: DepositSyncSpoolResponseEvidenceState,
    state: DepositSyncSpoolIndexState,
}

/// Exact process-local identity of one successfully reconciled durable spool state.
///
/// The protocol metadata authenticates the mutable spool head. The sealed index digest binds the
/// authenticated Redb index bytes and decoded state, while the process generation changes before
/// every supported database write. Together they prevent row-only writes and prepared/rollback ABA
/// transitions from hitting an older proof.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DepositSyncSpoolReconciliationIdentity {
    head: DepositSyncSpoolHeadMetadata,
    index: Option<DepositSyncSpoolIndexHead>,
    sealed_index_digest: Option<[u8; 32]>,
    membership_write_generation: u64,
}

enum DepositSyncSpoolReconciliationState {
    Active(Option<DepositSyncSpoolReconciliationIdentity>),
    Retired,
}

/// Tiny process-local cache shared by the live database handle for one exact binding.
///
/// It is deliberately non-durable: every process restart performs a complete reconciliation
/// before populating it. Closing the last handle or deleting the namespace retires the instance.
struct DepositSyncSpoolReconciliationCache {
    binding: DepositSyncSpoolBinding,
    state: Mutex<DepositSyncSpoolReconciliationState>,
    membership_write_generation: AtomicU64,
    membership_write_generation_valid: AtomicBool,
    #[cfg(test)]
    response_evidence_scans: AtomicU64,
}

impl DepositSyncSpoolReconciliationCache {
    fn new(binding: DepositSyncSpoolBinding) -> Self {
        Self {
            binding,
            state: Mutex::new(DepositSyncSpoolReconciliationState::Active(None)),
            membership_write_generation: AtomicU64::new(0),
            membership_write_generation_valid: AtomicBool::new(true),
            #[cfg(test)]
            response_evidence_scans: AtomicU64::new(0),
        }
    }

    async fn retire(&self) {
        self.membership_write_generation_valid.store(false, Ordering::Release);
        *self.state.lock().await = DepositSyncSpoolReconciliationState::Retired;
    }

    fn invalidate_membership_write_generation(&self) {
        self.membership_write_generation_valid.store(false, Ordering::Release);
        if let Ok(mut state) = self.state.try_lock()
            && let DepositSyncSpoolReconciliationState::Active(cached) = &mut *state
        {
            *cached = None;
        }
    }

    #[cfg(test)]
    fn response_evidence_scans(&self) -> u64 {
        self.response_evidence_scans.load(Ordering::Relaxed)
    }
}

/// The only supported process-local writer for one spool membership database.
///
/// Starting any write advances the manager-shared generation exactly once before Redb is touched.
/// A failed or aborted write therefore leaves the old proof cold, which is conservative. The
/// generation is deliberately non-durable: a new process starts with an empty reconciliation cache
/// and performs a full authenticated row scan before trusting its new local generation.
///
/// Safety invariant: the manager exposes at most one live mutable spool store for an exact binding,
/// and every production write begins while that store's mutation lock is held. Frozen candidates
/// share only the read path. Closing the last store handle retires this generation and forces the
/// next weak-handle reopen to start cold.
struct DepositSyncSpoolMembershipDatabase {
    database: Database,
    reconciliation: Arc<DepositSyncSpoolReconciliationCache>,
}

impl DepositSyncSpoolMembershipDatabase {
    fn begin_read(&self) -> Result<redb::ReadTransaction, redb::TransactionError> {
        self.database.begin_read()
    }

    fn begin_write(&self) -> Result<DepositSyncSpoolMembershipWrite, DepositSyncStageError> {
        if !self.reconciliation.membership_write_generation_valid.load(Ordering::Acquire) {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let prior_generation =
            self.reconciliation.membership_write_generation.load(Ordering::Acquire);
        let next_generation = prior_generation.checked_add(1).ok_or_else(|| {
            self.reconciliation.invalidate_membership_write_generation();
            DepositSyncStageError::MembershipIndexDivergence
        })?;
        if self
            .reconciliation
            .membership_write_generation
            .compare_exchange(
                prior_generation,
                next_generation,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.reconciliation.invalidate_membership_write_generation();
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let transaction = self.database.begin_write().map_spool_database()?;
        Ok(DepositSyncSpoolMembershipWrite { transaction })
    }
}

struct DepositSyncSpoolMembershipWrite {
    transaction: redb::WriteTransaction,
}

impl DepositSyncSpoolMembershipWrite {
    fn commit(self) -> Result<(), DepositSyncStageError> {
        self.transaction.commit().map_spool_database()
    }
}

impl Deref for DepositSyncSpoolMembershipWrite {
    type Target = redb::WriteTransaction;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl DerefMut for DepositSyncSpoolMembershipWrite {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transaction
    }
}

struct DepositSyncSpoolProcessCache {
    binding: DepositSyncSpoolBinding,
    handle: Weak<DepositSyncSpoolStore>,
    reconciliation: Arc<DepositSyncSpoolReconciliationCache>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolSealedValue {
    version: u16,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

struct DepositSyncRuntimePage {
    link: DepositSyncSpoolPageLink,
    entries: Vec<DepositSyncSpoolEntry>,
    previous: Option<DepositSyncSpoolPageLink>,
    next_index: usize,
    delivered_index: Option<usize>,
}

/// Bounded counters authenticated by the spool head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DepositSyncSpoolStats {
    pub phase: DepositSyncSpoolPhase,
    pub checkpoint_revision: u64,
    pub checkpoint_digest: [u8; 32],
    pub pages: u64,
    pub objects: u64,
    pub plaintext_bytes: u64,
    pub physical_bytes: u64,
    pub has_pending_page: bool,
    pub has_iteration: bool,
    pub is_deleting: bool,
}

const DEPOSIT_SYNC_IMPORT_MARKER_VERSION: u16 = 2;
const DEPOSIT_SYNC_IMPORT_MARKER_DOMAIN: &str = "threshold-monero/deposit-sync/import-marker/v2";
const DEPOSIT_SYNC_IMPORT_CURSOR_VERSION: u16 = 2;
const DEPOSIT_SYNC_IMPORT_CURSOR_BYTES: usize = 1024;

/// Constant-size wallet-snapshot marker for a fully materialized candidate.
///
/// The marker is safe to embed in the authoritative wallet snapshot CAS. It binds the exact spool,
/// its cleanup owner, and the immutable ReadyToCas head without carrying any downloaded objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositSyncImportMarker {
    version: u16,
    binding: DepositSyncSpoolBinding,
    owner: WalletArtifactOwner,
    prepared_head_digest: [u8; 32],
    object_count: u64,
}

impl DepositSyncImportMarker {
    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.binding.key.network_id
    }

    #[must_use]
    pub const fn wallet(&self) -> crate::deposit_wallet::DepositWalletId {
        self.binding.key.wallet_id
    }

    #[must_use]
    pub const fn anchor(&self) -> DepositSyncAnchorId {
        self.binding.anchor
    }

    #[must_use]
    pub const fn candidate_root(&self) -> [u8; 32] {
        self.binding.candidate_root
    }

    #[must_use]
    pub const fn owner(&self) -> WalletArtifactOwner {
        self.owner
    }

    #[must_use]
    pub const fn prepared_head_digest(&self) -> [u8; 32] {
        self.prepared_head_digest
    }

    #[must_use]
    pub const fn object_count(&self) -> u64 {
        self.object_count
    }

    #[must_use]
    pub const fn maximum_objects(&self) -> u64 {
        self.binding.maximum_objects
    }

    pub fn validate_for(
        &self,
        wallet: crate::deposit_wallet::DepositWalletId,
    ) -> Result<(), DepositSyncStageError> {
        if self.version != DEPOSIT_SYNC_IMPORT_MARKER_VERSION
            || self.binding.key.wallet_id != wallet
            || self.binding.key.network_id == [0; 32]
            || self.binding.anchor.0 == [0; 32]
            || self.binding.candidate_root == [0; 32]
            || self.binding.maximum_objects == 0
            || self.object_count == 0
            || self.object_count > self.binding.maximum_objects
            || self.prepared_head_digest == [0; 32]
        {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        self.binding.key.validate()?;
        self.owner.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], DepositSyncStageError> {
        self.validate_for(self.binding.key.wallet_id)?;
        let bytes =
            encode_canonical(self, DEPOSIT_SYNC_IMPORT_CURSOR_BYTES, "deposit sync import marker")?;
        let mut hasher = blake3::Hasher::new_derive_key(DEPOSIT_SYNC_IMPORT_MARKER_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncPreparedReferenceCursor {
    version: u16,
    marker: [u8; 32],
    position: DepositSyncSpoolPageLink,
    remaining_pages: u64,
}

/// One bounded deterministic page of permanent artifact references owned by an import journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositSyncPreparedReferencePage {
    pub references: Vec<WalletArtifactRef>,
    pub next_cursor: Option<Vec<u8>>,
}

/// Result of replaying the one durable pending-page intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositSyncSpoolRecovery {
    /// No page intent needed recovery.
    Clean,
    /// Every planned object was durable; the page and compact head are now committed.
    Committed,
    /// At least one planned object was absent; owned partial writes were removed and the previous
    /// committed head remains authoritative.
    RolledBack,
}

const DEPOSIT_SYNC_SPOOL_CATALOG_VERSION: u16 = 7;
const DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_VERSION: u16 = 5;
const DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_DOMAIN: &str =
    "threshold-monero/deposit-sync-spool/admission-policy/v5";
const DEPOSIT_SYNC_SUPPORT_ID_DOMAIN: &str = "threshold-monero/deposit-sync/support-identity/v3";
const DEPOSIT_SYNC_ARCHIVE_OBJECT_SLACK: u64 = 4;
const DEPOSIT_SYNC_PREFIX_TRANSIENT_COOLDOWN_ROUNDS: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct DepositSyncSupportId([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolActiveState {
    Admitting,
    Switching {
        previous: DepositSyncSpoolBinding,
    },
    Failing {
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
    },
    Rejecting {
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
        post_abort: Option<DepositSyncCheckpointIdentity>,
        rejection: DepositSyncVariantRejection,
    },
    /// The marker-bearing wallet snapshot is authoritative and the exact spool head has durably
    /// journaled reservation release. Recovery must finish that journal before any abort, rebase,
    /// source rotation, or candidate deletion may proceed.
    ReleasingOwnership {
        marker: DepositSyncImportMarker,
    },
    /// Permanent artifact reservations were relinquished after the marker-bearing snapshot became
    /// authoritative. The snapshot marker has not yet been durably cleared.
    OwnershipReleased {
        marker: DepositSyncImportMarker,
    },
    /// The caller durably cleared the authoritative snapshot marker. Cleanup can now finish
    /// without consulting the snapshot again.
    Committed {
        marker: DepositSyncImportMarker,
    },
    Active,
    Deleting {
        prepared: bool,
    },
}

/// Exact checkpoint accepted after a restart-idempotent prepared-import abort.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncCheckpointIdentity {
    revision: u64,
    digest: [u8; 32],
}

/// Terminal verifier classification attributable to one exact source variant.
///
/// Local stale-CAS and I/O failures deliberately have no representation here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositSyncVariantRejection {
    CryptographicInvalid,
    SemanticInvalid,
}

/// Fixed-size witness-independent facts needed for admission and state-dominated cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncCandidateFacts {
    support: DepositSyncSupportId,
    active_epoch: u64,
    checkpoint_sequence: u64,
    portable_sequence: u64,
    portable_digest: [u8; 32],
    ledger_head: [u8; 32],
    next_index: DepositSubaddressIndex,
}

/// Persisted derivation of the locally authenticated committee admission and resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolAdmissionPolicy {
    version: u16,
    support: DepositSyncSupportId,
    active_epoch: u64,
    committee_digest: [u8; 32],
    committee_size: u16,
    sampling_sources: u16,
    fault_bound: u16,
    required_supporters: u16,
    maximum_objects: u64,
    policy_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncClaimArtifact {
    reference: WalletArtifactRef,
    owner: WalletArtifactOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolClaimState {
    /// The fixed-size lease and artifact owner are journaled before the response is created.
    Installing,
    Ready,
    Deleting,
}

/// One fixed-size claim slot for one mutually authenticated committee source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolClaim {
    binding: DepositSyncSpoolBinding,
    policy: DepositSyncSpoolAdmissionPolicy,
    facts: DepositSyncCandidateFacts,
    lease: DepositSyncAnchorLease,
    response: DepositSyncClaimArtifact,
    state: DepositSyncSpoolClaimState,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct DepositSyncFailedVariant {
    source: PartyId,
    anchor: DepositSyncAnchorId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncCertifiedClaim {
    binding: DepositSyncSpoolBinding,
    lease: DepositSyncAnchorLease,
    response: DepositSyncClaimArtifact,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
enum DepositSyncPendingReleaseKey {
    Ordinary(PartyId),
    CertifiedExport { source: PartyId, request_digest: [u8; 32] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncPendingRelease {
    Ordinary { request: DepositSyncReleaseRequest, acknowledged: bool },
    CertifiedExport { request: DepositStateExportReleaseRequest, acknowledged: bool },
}

impl DepositSyncPendingRelease {
    const fn acknowledged(self) -> bool {
        match self {
            Self::Ordinary { acknowledged, .. } | Self::CertifiedExport { acknowledged, .. } => {
                acknowledged
            }
        }
    }

    fn mark_acknowledged(&mut self) {
        match self {
            Self::Ordinary { acknowledged, .. } | Self::CertifiedExport { acknowledged, .. } => {
                *acknowledged = true
            }
        }
    }
}

/// Durable pre-request authority for one source-specific old-quorum-certified export.
///
/// The verified capability itself is deliberately not deserializable. Its exact canonical
/// certificate bytes and locally verified target binding are retained so a restart can retry the
/// same deterministic ExportHead request without treating persisted bytes as fresh authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositStateExportSpoolIntent {
    context: DepositStateTransferContext,
    source: PartyId,
    requester: PartyId,
    semantic_transition: [u8; 32],
    target_binding: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate_digest: [u8; 32],
    request: DepositStateExportHeadRequest,
    request_digest: [u8; 32],
    seal_certificate: Vec<u8>,
}

/// Bounded restart evidence for the one selected cold certified-export lane.
///
/// This value is deliberately only data. In particular, it is not a
/// [`VerifiedPreImportDepositStateExportSeal`] and cannot open a spool. The caller must decode the
/// retained canonical certificate, reconstruct its predecessor and target authority from
/// authenticated epoch history, and freshly verify it before presenting that process-local token
/// to [`DepositSyncSpoolManager::reopen_active_pre_import_certified_export`].
///
/// `response` is present only after the exact selected head artifact is durable. While selection
/// is still in the journal-before-artifact `Installing` cut, the exact request plus canonical seal
/// and fixed bindings are sufficient to reauthenticate the job and retry that one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreImportCertifiedExportRecoveryEvidence {
    context: DepositStateTransferContext,
    source: PartyId,
    requester: PartyId,
    semantic_transition: [u8; 32],
    target_binding: [u8; 32],
    seal_statement: [u8; 32],
    seal_certificate_digest: [u8; 32],
    seal_certificate: Vec<u8>,
    request: DepositStateExportHeadRequest,
    response: Option<DepositStateExportHeadResponse>,
}

/// ABA-safe authenticated catalog fence for the selected journal-before-head crash cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InstallingCertifiedExportCheckpoint {
    context: DepositStateTransferContext,
    source: PartyId,
    request_digest: [u8; 32],
    catalog_revision: u64,
    catalog_snapshot_hash: [u8; 32],
}

impl InstallingCertifiedExportCheckpoint {
    #[must_use]
    pub(crate) const fn context(self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub(crate) const fn source(self) -> PartyId {
        self.source
    }

    #[must_use]
    pub(crate) const fn request_digest(self) -> [u8; 32] {
        self.request_digest
    }
}

impl PreImportCertifiedExportRecoveryEvidence {
    fn from_selected(
        active: DepositStateExportSpoolActive,
        intent: &DepositStateExportSpoolIntent,
        response: Option<DepositStateExportHeadResponse>,
    ) -> Result<Self, DepositSyncStageError> {
        validate_certified_export_intent(intent)?;
        if !matches!(
            active.state,
            DepositStateExportSpoolActiveState::Installing
                | DepositStateExportSpoolActiveState::Active
        ) || !certified_export_intent_matches_active(intent, active)
            || (active.state == DepositStateExportSpoolActiveState::Active) != response.is_some()
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        if let Some(response) = response.as_ref() {
            validate_certified_export_head(active, intent.request, response)?;
        }
        Ok(Self {
            context: intent.context,
            source: intent.source,
            requester: intent.requester,
            semantic_transition: intent.semantic_transition,
            target_binding: intent.target_binding,
            seal_statement: intent.seal_statement,
            seal_certificate_digest: intent.seal_certificate_digest,
            seal_certificate: intent.seal_certificate.clone(),
            request: intent.request,
            response,
        })
    }

    #[must_use]
    pub(crate) const fn context(&self) -> DepositStateTransferContext {
        self.context
    }

    #[must_use]
    pub(crate) const fn source(&self) -> PartyId {
        self.source
    }

    #[must_use]
    pub(crate) const fn requester(&self) -> PartyId {
        self.requester
    }

    #[must_use]
    pub(crate) const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub(crate) const fn seal_statement_digest(&self) -> [u8; 32] {
        self.seal_statement
    }

    #[must_use]
    pub(crate) const fn seal_certificate_digest(&self) -> [u8; 32] {
        self.seal_certificate_digest
    }

    #[must_use]
    pub(crate) fn canonical_seal_certificate_bytes(&self) -> &[u8] {
        &self.seal_certificate
    }

    #[must_use]
    pub(crate) const fn head_request(&self) -> DepositStateExportHeadRequest {
        self.request
    }

    #[must_use]
    pub(crate) const fn head_response(&self) -> Option<&DepositStateExportHeadResponse> {
        self.response.as_ref()
    }

    /// Compare only the fixed target binding retained when the certificate was originally
    /// authenticated. A match is not target authority; callers must still authenticate `target`
    /// from epoch history before verifying the canonical certificate.
    #[must_use]
    pub(crate) fn binds_target(&self, target: &VerifiedRegistryHandoffTarget) -> bool {
        self.context.wallet() == target.wallet()
            && self.target_binding == certified_export_target_binding(target)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositStateExportSpoolActiveState {
    Installing,
    Active,
    ReleasingOwnership { marker: DepositSyncImportMarker },
    OwnershipReleased { marker: DepositSyncImportMarker },
    Committed { marker: DepositSyncImportMarker },
    Deleting { prepared: bool },
}

/// One exact certified-export admission, disjoint from ordinary f+1/prefix admission.
///
/// The canonical request and response bytes live in the spool's owned head artifact. This catalog
/// record carries only fixed-size recovery bindings and the import-marker lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositStateExportSpoolActive {
    binding: DepositSyncSpoolBinding,
    context: DepositStateTransferContext,
    source: PartyId,
    requester: PartyId,
    semantic_transition: [u8; 32],
    request_digest: [u8; 32],
    response_digest: [u8; 32],
    lease_digest: [u8; 32],
    state: DepositStateExportSpoolActiveState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncPrefixEvidence {
    source: PartyId,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    certificate: DepositSyncClaimArtifact,
    endorsers: Vec<PartyId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncSpoolAuthority {
    /// Exact f+1 source responses. Every signer is also a lease-backed failover source.
    ExactClaims,
    /// One serving lease plus f+1 current-member semantic prefix endorsements. Endorsers are
    /// authority signers only and must never be treated as serving leases.
    Prefix(DepositSyncPrefixEvidence),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DepositSyncPrefixAttemptState {
    Installing,
    Collecting,
    Promoting(DepositSyncPrefixEvidence),
    Deleting(Option<DepositSyncPrefixEvidence>),
}

/// Non-authoritative ownership of one source lease while f+1 prefix endorsements are collected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncPrefixSupportAttempt {
    binding: DepositSyncSpoolBinding,
    policy: DepositSyncSpoolAdmissionPolicy,
    facts: DepositSyncCandidateFacts,
    claim: DepositSyncSpoolClaim,
    statement_digest: [u8; 32],
    state: DepositSyncPrefixAttemptState,
}

/// Bounded per-source failure memory for deterministic prefix-source rotation.
///
/// Transient failures impose a persisted one-round cooldown and increase the source's strike
/// count; terminal cryptographic or semantic rejection excludes it for the current authority.
/// Both classes are cleared when committee authority changes or local state dominates the failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncPrefixSourceFailure {
    source: PartyId,
    anchor: DepositSyncAnchorId,
    active_epoch: u64,
    committee_digest: [u8; 32],
    facts: DepositSyncCandidateFacts,
    strikes: u32,
    last_failure_round: u64,
    retry_after_round: u64,
    permanent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DepositSyncPrefixFailureClass {
    Transient,
    Permanent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolActive {
    support: DepositSyncSupportId,
    binding: DepositSyncSpoolBinding,
    policy: DepositSyncSpoolAdmissionPolicy,
    facts: DepositSyncCandidateFacts,
    authority: DepositSyncSpoolAuthority,
    certified_claims: BTreeMap<PartyId, DepositSyncCertifiedClaim>,
    failed_variants: BTreeSet<DepositSyncFailedVariant>,
    rejected_variants: BTreeSet<DepositSyncFailedVariant>,
    source_failure_round: u64,
    pinned_source: Option<PartyId>,
    state: DepositSyncSpoolActiveState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositSyncSpoolCatalog {
    version: u16,
    key: DepositSyncSpoolHeadKey,
    sampling_round: u64,
    claims: BTreeMap<PartyId, DepositSyncSpoolClaim>,
    pending_releases: BTreeMap<DepositSyncPendingReleaseKey, DepositSyncPendingRelease>,
    prefix_source_failures: BTreeMap<PartyId, DepositSyncPrefixSourceFailure>,
    prefix_attempt: Option<DepositSyncPrefixSupportAttempt>,
    active: Option<DepositSyncSpoolActive>,
    certified_export_intents: BTreeMap<PartyId, DepositStateExportSpoolIntent>,
    certified_export: Option<DepositStateExportSpoolActive>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DepositSyncPrefixAuthorization {
    source: PartyId,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
}

/// Restart-safe work item returned only after the exact source response and target binding have
/// been reconstructed from the authenticated attempt journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositSyncPrefixSupportWork {
    response: DepositSyncHeadResponse,
    statement: DepositSyncSupportStatement,
}

impl DepositSyncPrefixSupportWork {
    #[must_use]
    pub const fn response(&self) -> &DepositSyncHeadResponse {
        &self.response
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositSyncSupportStatement {
        &self.statement
    }
}

impl DepositSyncSupportId {
    fn from_advertisement(
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Self, DepositSyncStageError> {
        let active = advertisement.registry_archive().registry().active();
        active.validate().map_err(|_| DepositSyncStageError::InvalidSnapshot)?;
        let (checkpoint_marker, checkpoint_decision) = match advertisement.checkpoint_certificate()
        {
            Some(certificate) => (1_u8, certificate.statement().decision_digest()),
            None if advertisement.certificate_archive().len() == 0 => (0_u8, [0; 32]),
            None => return Err(DepositSyncStageError::InvalidSnapshot),
        };
        let mut hasher = blake3::Hasher::new_derive_key(DEPOSIT_SYNC_SUPPORT_ID_DOMAIN);
        hasher.update(&DEPOSIT_SYNC_WIRE_VERSION.to_le_bytes());
        hasher.update(&advertisement.context().digest());
        hasher.update(&advertisement.registry_id().digest());
        hasher.update(&advertisement.certificate_archive().len().to_le_bytes());
        hasher.update(&[checkpoint_marker]);
        hasher.update(&checkpoint_decision);
        hasher.update(&advertisement.portable_index().digest());
        let support = *hasher.finalize().as_bytes();
        if support == [0; 32] {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        Ok(Self(support))
    }
}

impl DepositSyncCandidateFacts {
    fn from_advertisement(
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Self, DepositSyncStageError> {
        let portable = advertisement.portable_index();
        Ok(Self {
            support: DepositSyncSupportId::from_advertisement(advertisement)?,
            active_epoch: advertisement.registry_archive().registry().active_epoch(),
            checkpoint_sequence: advertisement.certificate_archive().len(),
            portable_sequence: portable.through_sequence(),
            portable_digest: portable.digest(),
            ledger_head: portable.ledger_head(),
            next_index: portable.next_index(),
        })
    }
}

impl DepositSyncSpoolAdmissionPolicy {
    fn authenticated(
        advertisement: &DepositSyncAdvertisement,
        target: &VerifiedRegistryHandoffTarget,
        requester: PartyId,
    ) -> Result<Self, DepositSyncStageError> {
        advertisement
            .registry_archive()
            .registry()
            .verify_active_target(target)
            .map_err(|_| DepositSyncStageError::WrongContext)?;
        let committee_size = target.committee().n();
        target.committee().member(requester).map_err(|_| DepositSyncStageError::WrongContext)?;
        let fault_bound = target.fault_bound();
        // An honest requester needs responses from n-f-1 remote members. Requiring every remote
        // peer lets the f Byzantine members stop stable-prefix selection by staying silent.
        let sampling_sources = committee_size
            .checked_sub(fault_bound)
            .and_then(|members| members.checked_sub(1))
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        let required_supporters =
            fault_bound.checked_add(1).ok_or(DepositSyncStageError::InvalidSnapshot)?;
        let maximum_objects = maximum_reachable_objects(advertisement)?;
        if required_supporters == 0 || required_supporters > committee_size {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let mut policy = Self {
            version: DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_VERSION,
            support: DepositSyncSupportId::from_advertisement(advertisement)?,
            active_epoch: target.committee().epoch,
            committee_digest: target.committee().digest(),
            committee_size,
            sampling_sources,
            fault_bound,
            required_supporters,
            maximum_objects,
            policy_digest: [0; 32],
        };
        policy.policy_digest = policy.computed_digest();
        Ok(policy)
    }

    fn computed_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.support.0);
        hasher.update(&self.active_epoch.to_le_bytes());
        hasher.update(&self.committee_digest);
        hasher.update(&self.committee_size.to_le_bytes());
        hasher.update(&self.sampling_sources.to_le_bytes());
        hasher.update(&self.fault_bound.to_le_bytes());
        hasher.update(&self.required_supporters.to_le_bytes());
        hasher.update(&self.maximum_objects.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Process-local admission result derived from persisted evidence for one exact advertisement.
///
/// A caller receives no writable spool until the authenticated active committee has supplied
/// `f+1` distinct matching advertisements. This guarantees at least one honest availability
/// source without requiring every non-requester honest party to be online at the same instant.
#[derive(Debug)]
pub enum DepositSyncSpoolAdmission {
    Pending {
        supporters: u16,
        required: u16,
    },
    /// The authenticated `n-f-1` remote-source sampling threshold completed without any semantic
    /// family reaching `f+1`. All unmatched slots are durably queued for release before repolling.
    SamplingRoundComplete {
        round: u64,
    },
    /// Exact moving tips filled the sampling round without one f+1 family. One deterministic
    /// serving claim was atomically retained as a non-authoritative prefix attempt before every
    /// other source lease was queued for release.
    PrefixSupportRequired {
        round: u64,
        work: DepositSyncPrefixSupportWork,
    },
    /// The semantic family is admitted, but a different exact source-bound variant is progressing.
    Standby {
        spool: Arc<DepositSyncSpoolStore>,
        preferred_source: Option<PartyId>,
    },
    Admitted {
        spool: Arc<DepositSyncSpoolStore>,
        /// Exact authenticated source whose retained lease serves the active spool.
        source: PartyId,
        /// Authenticated semantic supporters whose fixed claims formed the f+1 certificate.
        supporters: Vec<PartyId>,
    },
    /// Stable-prefix admission: `source` alone owns the serving lease. `endorsers` are the
    /// canonical sorted f+1 authority signers and need not include or serve `source`.
    AdmittedPrefix {
        spool: Arc<DepositSyncSpoolStore>,
        source: PartyId,
        /// Exact semantic statement promoted by this admission.
        statement_digest: [u8; 32],
        /// Exact canonical `f+1` support certificate promoted by this admission.
        certificate_digest: [u8; 32],
        endorsers: Vec<PartyId>,
    },
}

/// Process-lifetime credentials for opening exact candidate-bound spools.
///
/// This manager carries no mutable candidate state. Each advertisement opens a disjoint
/// network/wallet/anchor namespace whose authenticated head and encrypted membership database
/// must agree before the handle is returned.
pub struct DepositSyncSpoolManager {
    directory: PathBuf,
    party: PartyId,
    network_id: [u8; 32],
    identity_seed: Zeroizing<[u8; 32]>,
    catalog_protocol: ProtocolStore,
    artifacts: WalletArtifactStore,
    catalog_mutation: Mutex<()>,
    spool_cache: Mutex<BTreeMap<DepositSyncAnchorId, DepositSyncSpoolProcessCache>>,
    prefix_authorizations: Mutex<BTreeMap<DepositSyncAnchorId, DepositSyncPrefixAuthorization>>,
}

impl std::fmt::Debug for DepositSyncSpoolManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DepositSyncSpoolManager")
            .field("directory", &self.directory)
            .field("party", &self.party)
            .field("network_id", &hex::encode(self.network_id))
            .finish_non_exhaustive()
    }
}

impl DepositSyncSpoolManager {
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        network_id: [u8; 32],
    ) -> Result<Self, DepositSyncStageError> {
        if network_id == [0; 32] {
            return Err(DepositSyncStageError::WrongContext);
        }
        let directory = directory.into();
        let catalog_directory =
            directory.join(SPOOL_NAMESPACE_DIRECTORY).join(SPOOL_CATALOG_DIRECTORY);
        let artifacts = WalletArtifactStore::new(&directory, party, identity_seed)?;
        Ok(Self {
            directory,
            party,
            network_id,
            identity_seed: Zeroizing::new(*identity_seed),
            catalog_protocol: ProtocolStore::new(catalog_directory, party, identity_seed)?,
            artifacts,
            catalog_mutation: Mutex::new(()),
            spool_cache: Mutex::new(BTreeMap::new()),
            prefix_authorizations: Mutex::new(BTreeMap::new()),
        })
    }

    /// Persist one verified source-specific export capability before acknowledging its delivery.
    ///
    /// The nonce is deterministic over the exact certificate, target, source, and requester, so a
    /// restart always retries the same request. Distinct predecessor sources occupy independent
    /// bounded slots; a withholding source therefore cannot prevent an honest source from being
    /// requested.
    pub async fn record_certified_export_intent(
        &self,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateExportHeadRequest, DepositSyncStageError> {
        self.record_certified_export_intent_inner(seal, target).await
    }

    /// Persist the same exact head intent from cold-target, old-quorum-authenticated read
    /// authority. This token can prepare and replay only bounded export fetches; it cannot open a
    /// full spool handle or authorize freeze, verification, materialization, or import.
    pub(crate) async fn record_pre_import_certified_export_intent(
        &self,
        seal: &VerifiedPreImportDepositStateExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateExportHeadRequest, DepositSyncStageError> {
        self.record_certified_export_intent_inner(seal, target).await
    }

    async fn record_certified_export_intent_inner<S: CertifiedExportReadSeal + ?Sized>(
        &self,
        seal: &S,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositStateExportHeadRequest, DepositSyncStageError> {
        seal.validate_target(target)?;
        target
            .committee()
            .validate_async_security_with_faults(target.fault_bound())
            .map_err(|_| DepositSyncStageError::InvalidSnapshot)?;
        target.committee().member(self.party).map_err(|_| DepositSyncStageError::WrongContext)?;
        let statement = seal.statement();
        let source = statement.source_party();
        if statement.network() != self.network_id
            || statement.source().wallet() != target.wallet()
            || source.0 == 0
            || source == self.party
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let context = DepositStateTransferContext::new(self.network_id, target.wallet())?;
        let target_binding = certified_export_target_binding(target);
        let nonce = certified_export_head_nonce(seal, target_binding, source, self.party);
        let request = DepositStateExportHeadRequest::new(
            context,
            statement.semantic_transition_digest(),
            source,
            self.party,
            nonce,
        )?;
        let intent = DepositStateExportSpoolIntent {
            context,
            source,
            requester: self.party,
            semantic_transition: statement.semantic_transition_digest(),
            target_binding,
            seal_statement: seal.statement_digest(),
            seal_certificate_digest: seal.certificate_digest(),
            request,
            request_digest: request.digest(),
            seal_certificate: seal.canonical_certificate_bytes().to_vec(),
        };
        validate_certified_export_intent(&intent)?;

        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if catalog.active.is_some()
            || catalog.prefix_attempt.is_some()
            || !catalog.claims.is_empty()
        {
            return Err(DepositSyncStageError::OrdinaryAdmissionInProgress);
        }
        if catalog.certified_export_intents.values().any(|existing| {
            existing.context != context
                || existing.target_binding != target_binding
                || existing.semantic_transition != intent.semantic_transition
        }) {
            return Err(DepositSyncStageError::CertifiedExportIntentConflict);
        }
        match catalog.certified_export_intents.get(&source) {
            Some(existing) if existing == &intent => return Ok(existing.request),
            Some(_) => return Err(DepositSyncStageError::CertifiedExportIntentConflict),
            None => {}
        }
        if let Some(active) = catalog.certified_export {
            if !matches!(
                active.state,
                DepositStateExportSpoolActiveState::Installing
                    | DepositStateExportSpoolActiveState::Active
            ) {
                return Err(DepositSyncStageError::CertifiedExportAdmissionInProgress);
            }
            if active.context != context
                || active.semantic_transition != intent.semantic_transition
                || !catalog.certified_export_intents.get(&active.source).is_some_and(|selected| {
                    certified_export_intent_matches_active(selected, active)
                })
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        if catalog.certified_export_intents.len() >= MAX_COMMITTEE_MEMBERS {
            return Err(DepositSyncStageError::CandidateQuota);
        }
        catalog.certified_export_intents.insert(source, intent);
        let _ = self.persist_catalog(metadata, &catalog).await?;
        Ok(request)
    }

    /// Retire obsolete downloads after the caller reopens the exact locally installed target
    /// import journal. Selected leases use the durable deletion/release path; a prepared import
    /// still requires its own ownership disposition and cannot be discarded here.
    pub(crate) async fn retire_completed_certified_export_intents(
        &self,
        installed: &VerifiedStateImportedCertificate,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<usize, DepositSyncStageError> {
        if installed.network() != self.network_id
            || installed.wallet() != target.wallet()
            || installed.target_epoch() != target.committee().epoch
            || installed.target_committee_digest() != target.committee().digest()
            || installed.target_activation() != target.activation()
            || installed.target_certified_activation_root() != target.certified_activation_root()
            || target.committee().member(self.party).is_err()
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: self.network_id, wallet_id: installed.wallet() };
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let previous = catalog.certified_export_intents.len();
        let target_binding = certified_export_target_binding(target);
        if let Some(active) = catalog.certified_export {
            let selected = catalog
                .certified_export_intents
                .get(&active.source)
                .filter(|intent| certified_export_intent_matches_active(intent, active))
                .ok_or(DepositSyncStageError::InvalidSnapshot)?;
            if selected.semantic_transition != installed.semantic_transition_digest()
                || selected.target_binding != target_binding
            {
                return Ok(0);
            }
            match active.state {
                DepositStateExportSpoolActiveState::Installing => {
                    // No durable response means no exact lease to release. As in source failover,
                    // delete first so an interrupted catalog CAS leaves Installing retryable.
                    self.delete_candidate_namespace(active.binding, false).await?;
                    catalog.certified_export = None;
                }
                DepositStateExportSpoolActiveState::Active => {
                    let spool = self.open_cached_binding(active.binding).await?;
                    if matches!(
                        spool.checkpoint().await?.phase(),
                        DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
                    ) {
                        return Err(DepositSyncStageError::PreparedImportDispositionRequired);
                    }
                    catalog.certified_export.as_mut().expect("active checked").state =
                        DepositStateExportSpoolActiveState::Deleting { prepared: false };
                }
                _ => return Err(DepositSyncStageError::PreparedImportDispositionRequired),
            }
        }
        catalog.certified_export_intents.retain(|_, intent| {
            intent.semantic_transition != installed.semantic_transition_digest()
                || intent.target_binding != target_binding
        });
        let retired = previous - catalog.certified_export_intents.len();
        if retired != 0 {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        Ok(retired)
    }

    /// Return deterministic pending ExportHead requests in predecessor-party order.
    ///
    /// Once one valid response selects an `Installing` lane, only that exact retained request is
    /// retried. After its head is durably readable, dormant same-transition competitors remain
    /// retained for exact-fenced source failover, while this method stays quiescent until the
    /// active source is failed or the import completes.
    pub async fn pending_certified_export_heads(
        &self,
        context: DepositStateTransferContext,
    ) -> Result<Vec<DepositStateExportHeadRequest>, DepositSyncStageError> {
        if context.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) = catalog.certified_export {
            if active.state != DepositStateExportSpoolActiveState::Installing {
                return Ok(Vec::new());
            }
            let selected = catalog
                .certified_export_intents
                .get(&active.source)
                .filter(|intent| certified_export_intent_matches_active(intent, active))
                .ok_or(DepositSyncStageError::InvalidSnapshot)?;
            return Ok(vec![selected.request]);
        }
        Ok(catalog
            .certified_export_intents
            .values()
            .filter_map(|intent| (intent.context == context).then_some(intent.request))
            .collect())
    }

    /// Recover bounded data for the exact selected cold certified-export lane.
    ///
    /// Persisted bytes never become authority through this method. A caller can use them to locate
    /// the archived predecessor/target transition and freshly verify the canonical seal, then call
    /// [`Self::reopen_active_pre_import_certified_export`] with the resulting process-local token.
    /// The `Installing` crash cut returns the exact selected request without a response; `Active`
    /// returns the exact durable request/response pair after artifact readback.
    pub(crate) async fn active_pre_import_certified_export_recovery_evidence(
        &self,
        context: DepositStateTransferContext,
    ) -> Result<Option<PreImportCertifiedExportRecoveryEvidence>, DepositSyncStageError> {
        if context.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let Some(active) = catalog.certified_export else {
            return Ok(None);
        };
        if active.context != context
            || !matches!(
                active.state,
                DepositStateExportSpoolActiveState::Installing
                    | DepositStateExportSpoolActiveState::Active
            )
        {
            return Ok(None);
        }
        let intent = catalog
            .certified_export_intents
            .get(&active.source)
            .filter(|intent| certified_export_intent_matches_active(intent, active))
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        let response = if active.state == DepositStateExportSpoolActiveState::Active {
            let spool = self.open_cached_binding(active.binding).await?;
            let _ = spool.initialize().await?;
            let (request, response) = spool.export_head_response().await?;
            if request != intent.request {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
            Some(response)
        } else {
            None
        };
        Ok(Some(PreImportCertifiedExportRecoveryEvidence::from_selected(active, intent, response)?))
    }

    /// Return an authenticated ABA fence only for a selected response whose head artifact has not
    /// become durable yet.
    pub(crate) async fn installing_certified_export_checkpoint(
        &self,
        context: DepositStateTransferContext,
    ) -> Result<Option<InstallingCertifiedExportCheckpoint>, DepositSyncStageError> {
        if context.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let Some(active) = catalog.certified_export else {
            return Ok(None);
        };
        if active.context != context
            || active.state != DepositStateExportSpoolActiveState::Installing
        {
            return Ok(None);
        }
        let intent = catalog
            .certified_export_intents
            .get(&active.source)
            .filter(|intent| certified_export_intent_matches_active(intent, active))
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        let metadata = metadata.ok_or(DepositSyncStageError::MissingReadback)?;
        Ok(Some(InstallingCertifiedExportCheckpoint {
            context,
            source: active.source,
            request_digest: intent.request_digest,
            catalog_revision: metadata.revision,
            catalog_snapshot_hash: metadata.snapshot_hash,
        }))
    }

    /// Reauthenticate and reopen only the exact already-active certified export.
    ///
    /// This never selects a source or creates an intent. The fully verified seal must match the
    /// selected durable intent and exact retained head before the import-capable spool handle is
    /// returned.
    pub async fn reopen_active_certified_export(
        &self,
        context: DepositStateTransferContext,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<Arc<DepositSyncSpoolStore>>, DepositSyncStageError> {
        self.reopen_active_certified_export_inner(context, seal, target).await
    }

    /// Reauthenticate the exact already-active certified export for bounded cold-target reads.
    ///
    /// The restricted token can recover only the fetch-only wrapper. Re-presenting the full seal
    /// remains mandatory before any freeze or import operation becomes reachable.
    pub(crate) async fn reopen_active_pre_import_certified_export(
        &self,
        context: DepositStateTransferContext,
        seal: &VerifiedPreImportDepositStateExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<PreImportDepositStateExportSpool>, DepositSyncStageError> {
        Ok(self
            .reopen_active_certified_export_inner(context, seal, target)
            .await?
            .map(|spool| PreImportDepositStateExportSpool { spool }))
    }

    async fn reopen_active_certified_export_inner<S: CertifiedExportReadSeal + ?Sized>(
        &self,
        context: DepositStateTransferContext,
        seal: &S,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<Arc<DepositSyncSpoolStore>>, DepositSyncStageError> {
        seal.validate_target(target)?;
        let statement = seal.statement();
        if context.network() != self.network_id
            || context.wallet() != target.wallet()
            || statement.network() != context.network()
            || statement.source().wallet() != context.wallet()
            || target.committee().member(self.party).is_err()
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let Some(active) = catalog.certified_export else {
            return Ok(None);
        };
        if active.state != DepositStateExportSpoolActiveState::Active
            || active.context != context
            || active.source != statement.source_party()
            || active.semantic_transition != statement.semantic_transition_digest()
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let intent = catalog
            .certified_export_intents
            .get(&active.source)
            .filter(|intent| certified_export_intent_matches_active(intent, active))
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        if intent.target_binding != certified_export_target_binding(target)
            || intent.seal_statement != seal.statement_digest()
            || intent.seal_certificate_digest != seal.certificate_digest()
            || intent.seal_certificate.as_slice() != seal.canonical_certificate_bytes()
        {
            return Err(DepositSyncStageError::CertifiedExportIntentConflict);
        }
        let spool = self.open_cached_binding(active.binding).await?;
        let _ = spool.initialize().await?;
        let (request, response) = spool.export_head_response().await?;
        validate_certified_export_head(active, request, &response)?;
        seal.validate_head(request, &response)?;
        response
            .advertisement()
            .registry_archive()
            .registry()
            .verify_active_target(target)
            .map_err(|_| DepositSyncStageError::WrongContext)?;
        Ok(Some(spool))
    }

    /// Return durable per-source releases.
    ///
    /// A listed source must not be probed again until its exact ACK is committed. Other
    /// nonpending authenticated sources remain eligible, so one offline peer cannot stop a round.
    pub async fn pending_releases(
        &self,
        context: DepositSyncContext,
    ) -> Result<Vec<DepositSyncReleaseRequest>, DepositSyncStageError> {
        if context.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        Ok(catalog
            .pending_releases
            .values()
            .filter_map(|pending| match pending {
                DepositSyncPendingRelease::Ordinary { request, .. } => Some(*request),
                DepositSyncPendingRelease::CertifiedExport { .. } => None,
            })
            .collect())
    }

    /// Return exact certified-export releases which remain pending a typed source ACK.
    pub async fn pending_export_releases(
        &self,
        context: DepositStateTransferContext,
    ) -> Result<Vec<DepositStateExportReleaseRequest>, DepositSyncStageError> {
        if context.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        Ok(catalog
            .pending_releases
            .values()
            .filter_map(|pending| match pending {
                DepositSyncPendingRelease::CertifiedExport { request, .. } => Some(*request),
                DepositSyncPendingRelease::Ordinary { .. } => None,
            })
            .collect())
    }

    /// Reconcile candidate admission against a locally authenticated current committee.
    ///
    /// Committee replacement never acknowledges a requester lease. Every release intent remains
    /// durable until the exact source returns its typed ACK; source-side handoff export retention
    /// is a separate global pin and cannot be inferred from target membership alone.
    pub async fn reconcile_pending_releases(
        &self,
        context: DepositSyncContext,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositSyncStageError> {
        if context.network() != self.network_id || context.wallet() != target.wallet() {
            return Err(DepositSyncStageError::WrongContext);
        }
        target
            .committee()
            .validate_async_security_with_faults(target.fault_bound())
            .map_err(|_| DepositSyncStageError::InvalidSnapshot)?;
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        drop(_catalog_mutation);
        // Re-establish process-local non-serializable prefix authority on restart. Collecting
        // attempts remain non-authoritative and simply return `None`.
        let _ = self.resume_prefix_admission(context, target).await?;
        Ok(())
    }

    /// Remove one release intent only after a typed, source-authenticated ACK names its digest.
    pub async fn acknowledge_release(
        &self,
        acknowledgement: DepositSyncReleaseAck,
    ) -> Result<(), DepositSyncStageError> {
        let context = acknowledgement.context();
        let source = acknowledgement.source();
        validate_source(source)?;
        if context.network() != self.network_id
            || acknowledgement.requester() != self.party
            || acknowledgement.request_digest() == [0; 32]
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let release_key = DepositSyncPendingReleaseKey::Ordinary(source);
        let pending = catalog
            .pending_releases
            .get(&release_key)
            .ok_or(DepositSyncStageError::UnknownRelease)?;
        let DepositSyncPendingRelease::Ordinary { request, acknowledged } = pending else {
            return Err(DepositSyncStageError::ReleaseConflict);
        };
        if request.digest() != acknowledgement.request_digest() {
            return Err(DepositSyncStageError::ReleaseConflict);
        }
        if !*acknowledged {
            catalog
                .pending_releases
                .get_mut(&release_key)
                .ok_or(DepositSyncStageError::UnknownRelease)?
                .mark_acknowledged();
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        }
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await
    }

    /// Remove one certified-export release only after validating its exact typed source ACK.
    pub async fn acknowledge_export_release(
        &self,
        request: DepositStateExportReleaseRequest,
        acknowledgement: DepositStateExportReleaseAck,
    ) -> Result<(), DepositSyncStageError> {
        // Re-encoding performs the wire type's complete exact-request validation.
        let _ = acknowledgement.to_bytes(request)?;
        let lease = request.lease();
        let context = lease.context();
        let source = lease.source();
        if context.network() != self.network_id
            || lease.requester() != self.party
            || source == self.party
            || source.0 == 0
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let release_key = DepositSyncPendingReleaseKey::CertifiedExport {
            source,
            request_digest: request.digest(),
        };
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let pending = catalog
            .pending_releases
            .get(&release_key)
            .ok_or(DepositSyncStageError::UnknownRelease)?;
        let DepositSyncPendingRelease::CertifiedExport { request: durable, acknowledged } = pending
        else {
            return Err(DepositSyncStageError::ReleaseConflict);
        };
        if *durable != request {
            return Err(DepositSyncStageError::ReleaseConflict);
        }
        if !*acknowledged {
            catalog
                .pending_releases
                .get_mut(&release_key)
                .ok_or(DepositSyncStageError::UnknownRelease)?
                .mark_acknowledged();
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        }
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await
    }

    /// Retain the lease for a validated but locally dominated/unadmitted Head response.
    pub async fn enqueue_unadmitted_release(
        &self,
        response: &DepositSyncHeadResponse,
    ) -> Result<(), DepositSyncStageError> {
        let advertisement = response.advertisement();
        if advertisement.context().network() != self.network_id
            || response.lease().requester() != self.party
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let binding = spool_binding(advertisement)?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if self.enqueue_release(&mut catalog, response.lease())? {
            let _ = self.persist_catalog(metadata, &catalog).await?;
        }
        Ok(())
    }

    /// Durably own one exact serving lease before any asynchronous prefix-endorsement scans.
    ///
    /// This state is deliberately non-authoritative: it exposes only the work needed to collect
    /// endorsements and never a writable spool. A crash can reconstruct the exact response, or
    /// queue its exact release without leaking the source pin.
    pub async fn begin_prefix_support_attempt(
        &self,
        response: &DepositSyncHeadResponse,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositSyncPrefixSupportWork, DepositSyncStageError> {
        let advertisement = response.advertisement();
        let source = response.lease().source();
        if advertisement.context().network() != self.network_id
            || response.lease().requester() != self.party
            || response.lease().advertisement_digest() != advertisement.digest()
            || source == self.party
        {
            return Err(DepositSyncStageError::InvalidSource);
        }
        validate_source(source)?;
        let policy =
            DepositSyncSpoolAdmissionPolicy::authenticated(advertisement, target, self.party)?;
        target.committee().member(source).map_err(|_| DepositSyncStageError::InvalidSource)?;
        let binding = spool_binding(advertisement)?;
        let facts = DepositSyncCandidateFacts::from_advertisement(advertisement)?;
        if binding.maximum_objects != policy.maximum_objects || facts.support != policy.support {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let request = DepositSyncHeadRequest::new(advertisement.context(), source, self.party)?;
        let statement = DepositSyncSupportStatement::from_head_response(request, response, target)?;
        let statement_digest = statement.digest();

        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if catalog.certified_export.is_some() || !catalog.certified_export_intents.is_empty() {
            return Err(DepositSyncStageError::CertifiedExportAdmissionInProgress);
        }
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        if let Some(attempt) = catalog.prefix_attempt.as_ref() {
            if attempt.binding == binding
                && attempt.claim.lease == response.lease()
                && attempt.statement_digest == statement_digest
                && matches!(
                    attempt.state,
                    DepositSyncPrefixAttemptState::Collecting
                        | DepositSyncPrefixAttemptState::Promoting(_)
                )
            {
                return self.load_prefix_attempt_work(attempt, target).await;
            }
            return Err(DepositSyncStageError::PrefixAttemptBusy);
        }
        if let Some(active) = catalog.active.as_ref() {
            let already_owned = active
                .certified_claims
                .get(&source)
                .is_some_and(|claim| claim.lease == response.lease());
            if !already_owned {
                self.enqueue_release(&mut catalog, response.lease())?;
                let _ = self.persist_catalog(metadata, &catalog).await?;
            }
            return Err(DepositSyncStageError::SourceLeaseBusy(source));
        }
        if catalog.pending_releases.contains_key(&DepositSyncPendingReleaseKey::Ordinary(source)) {
            return Err(DepositSyncStageError::PendingReleaseRequired(source));
        }
        if !prefix_source_is_eligible(&catalog, source) {
            let lease = catalog.claims.get(&source).map_or(response.lease(), |claim| claim.lease);
            self.enqueue_release(&mut catalog, lease)?;
            if let Some(claim) = catalog.claims.get_mut(&source) {
                claim.state = DepositSyncSpoolClaimState::Deleting;
            }
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
            return Err(DepositSyncStageError::PrefixSourceQuarantined(source));
        }

        if let Some(existing) = catalog.claims.get(&source).copied() {
            let durable = self.verify_claim_response(source, &existing).await?;
            if existing.state != DepositSyncSpoolClaimState::Ready
                || existing.binding != binding
                || existing.policy != policy
                || existing.facts != facts
                || existing.lease != response.lease()
                || durable != *response
            {
                self.enqueue_release(&mut catalog, existing.lease)?;
                catalog
                    .claims
                    .get_mut(&source)
                    .ok_or(DepositSyncStageError::InvalidSnapshot)?
                    .state = DepositSyncSpoolClaimState::Deleting;
                let _ = self.persist_catalog(metadata, &catalog).await?;
                return Err(DepositSyncStageError::PendingReleaseRequired(source));
            }
            let claim =
                catalog.claims.remove(&source).ok_or(DepositSyncStageError::InvalidSnapshot)?;
            catalog.prefix_attempt = Some(DepositSyncPrefixSupportAttempt {
                binding,
                policy,
                facts,
                claim,
                statement_digest,
                state: DepositSyncPrefixAttemptState::Collecting,
            });
            let _ = self.persist_catalog(metadata, &catalog).await?;
            return Ok(DepositSyncPrefixSupportWork { response: durable, statement });
        }

        let envelope =
            DepositSyncSpoolHeadResponseEnvelope::from_response(binding, response, self.party)?;
        let bytes = envelope.to_bytes()?;
        let reference = WalletArtifactRef::for_contents(
            WalletId(binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT,
            &bytes,
        )?;
        let response_artifact =
            DepositSyncClaimArtifact { reference, owner: WalletArtifactOwner::random(&mut OsRng) };
        let claim = DepositSyncSpoolClaim {
            binding,
            policy,
            facts,
            lease: response.lease(),
            response: response_artifact,
            state: DepositSyncSpoolClaimState::Installing,
        };
        catalog.prefix_attempt = Some(DepositSyncPrefixSupportAttempt {
            binding,
            policy,
            facts,
            claim,
            statement_digest,
            state: DepositSyncPrefixAttemptState::Installing,
        });
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                response_artifact.owner,
                WalletId(binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT,
                &bytes,
                &mut OsRng,
            )
            .await?;
        if installed != reference {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let attempt =
            catalog.prefix_attempt.as_mut().ok_or(DepositSyncStageError::InvalidSnapshot)?;
        attempt.claim.state = DepositSyncSpoolClaimState::Ready;
        attempt.state = DepositSyncPrefixAttemptState::Collecting;
        let _ = self.persist_catalog(metadata, &catalog).await?;
        Ok(DepositSyncPrefixSupportWork { response: response.clone(), statement })
    }

    /// Reconstruct exact endorsement work after restart without granting spool authority.
    ///
    /// A promoted prefix remains discoverable while its active spool is live. This closes the
    /// crash cut after stage promotion but before the requester journal records its exact
    /// admission tombstone.
    pub async fn prefix_support_work(
        &self,
        context: DepositSyncContext,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<DepositSyncPrefixSupportWork>, DepositSyncStageError> {
        if context.network() != self.network_id || context.wallet() != target.wallet() {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        if let Some(attempt) = catalog.prefix_attempt.as_ref() {
            return Ok(Some(self.load_prefix_attempt_work(attempt, target).await?));
        }
        let Some(active) = catalog.active.as_ref() else {
            return Ok(None);
        };
        let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority else {
            return Ok(None);
        };
        if !matches!(
            active.state,
            DepositSyncSpoolActiveState::Active | DepositSyncSpoolActiveState::Admitting
        ) {
            return Ok(None);
        }
        let certified = active
            .certified_claims
            .get(&evidence.source)
            .copied()
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        let attempt = DepositSyncPrefixSupportAttempt {
            binding: active.binding,
            policy: active.policy,
            facts: active.facts,
            claim: DepositSyncSpoolClaim {
                binding: certified.binding,
                policy: active.policy,
                facts: active.facts,
                lease: certified.lease,
                response: certified.response,
                state: DepositSyncSpoolClaimState::Ready,
            },
            statement_digest: evidence.statement_digest,
            state: DepositSyncPrefixAttemptState::Promoting(evidence.clone()),
        };
        let work = self.load_prefix_attempt_work(&attempt, target).await?;
        self.verify_prefix_evidence(active.binding, evidence, &work, target).await?;
        Ok(Some(work))
    }

    /// Reverify persisted prefix authority against trusted local history after restart.
    ///
    /// A collecting attempt remains non-authoritative and returns `None`. A fully promoted active
    /// candidate returns a typed admission only after its exact stored response and raw canonical
    /// certificate have both been revalidated in this process.
    pub async fn resume_prefix_admission(
        &self,
        context: DepositSyncContext,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<DepositSyncSpoolAdmission>, DepositSyncStageError> {
        if context.network() != self.network_id || context.wallet() != target.wallet() {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        if let Some(attempt) = catalog.prefix_attempt.as_ref() {
            let work = self.load_prefix_attempt_work(attempt, target).await?;
            let DepositSyncPrefixAttemptState::Promoting(evidence) = &attempt.state else {
                return Ok(None);
            };
            match self.verify_prefix_evidence(attempt.binding, evidence, &work, target).await {
                Ok(()) => {}
                Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    // The crash occurred after journal-before-create. The exact response/lease is
                    // still owned. Roll back only the absent certificate intent so the runtime's
                    // durable endorsements can deterministically recreate and retry promotion.
                    catalog
                        .prefix_attempt
                        .as_mut()
                        .ok_or(DepositSyncStageError::UnknownAnchor)?
                        .state = DepositSyncPrefixAttemptState::Collecting;
                    let _ = self.persist_catalog(metadata, &catalog).await?;
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
            let attempt =
                catalog.prefix_attempt.take().ok_or(DepositSyncStageError::UnknownAnchor)?;
            let evidence = match attempt.state {
                DepositSyncPrefixAttemptState::Promoting(evidence) => evidence,
                _ => return Err(DepositSyncStageError::InvalidSnapshot),
            };
            let source = evidence.source;
            let claim = attempt.claim;
            let certified_claims = BTreeMap::from([(
                source,
                DepositSyncCertifiedClaim {
                    binding: claim.binding,
                    lease: claim.lease,
                    response: claim.response,
                },
            )]);
            catalog.prefix_source_failures.remove(&source);
            catalog.active = Some(DepositSyncSpoolActive {
                support: attempt.facts.support,
                binding: attempt.binding,
                policy: attempt.policy,
                facts: attempt.facts,
                authority: DepositSyncSpoolAuthority::Prefix(evidence.clone()),
                certified_claims,
                failed_variants: BTreeSet::new(),
                rejected_variants: BTreeSet::new(),
                source_failure_round: 0,
                pinned_source: Some(source),
                state: DepositSyncSpoolActiveState::Admitting,
            });
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            let spool = self.open_cached_binding(attempt.binding).await?;
            let _ = spool.initialize().await?;
            spool.install_head_response(&work.response, self.party).await?;
            catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                DepositSyncSpoolActiveState::Active;
            let _ = self.persist_catalog(metadata, &catalog).await?;
            self.record_prefix_authorization(attempt.binding.anchor, &evidence).await;
            return Ok(Some(DepositSyncSpoolAdmission::AdmittedPrefix {
                spool,
                source,
                statement_digest: evidence.statement_digest,
                certificate_digest: evidence.certificate_digest,
                endorsers: evidence.endorsers,
            }));
        }
        let Some(active) = catalog.active.as_ref() else {
            return Ok(None);
        };
        let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority else {
            return Ok(None);
        };
        if !matches!(
            active.state,
            DepositSyncSpoolActiveState::Active | DepositSyncSpoolActiveState::Admitting
        ) {
            return Ok(None);
        }
        let source = evidence.source;
        let certified = active
            .certified_claims
            .get(&source)
            .copied()
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        let attempt = DepositSyncPrefixSupportAttempt {
            binding: active.binding,
            policy: active.policy,
            facts: active.facts,
            claim: DepositSyncSpoolClaim {
                binding: certified.binding,
                policy: active.policy,
                facts: active.facts,
                lease: certified.lease,
                response: certified.response,
                state: DepositSyncSpoolClaimState::Ready,
            },
            statement_digest: evidence.statement_digest,
            state: DepositSyncPrefixAttemptState::Promoting(evidence.clone()),
        };
        let work = self.load_prefix_attempt_work(&attempt, target).await?;
        self.verify_prefix_evidence(active.binding, evidence, &work, target).await?;
        let binding = active.binding;
        let statement_digest = evidence.statement_digest;
        let certificate_digest = evidence.certificate_digest;
        let endorsers = evidence.endorsers.clone();
        self.record_prefix_authorization(binding.anchor, evidence).await;
        let spool = self.open_cached_binding(binding).await?;
        let _ = spool.initialize().await?;
        let durable = spool.head_response(self.party).await?;
        if durable != work.response {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        Ok(Some(DepositSyncSpoolAdmission::AdmittedPrefix {
            spool,
            source,
            statement_digest,
            certificate_digest,
            endorsers,
        }))
    }

    /// Freshly reauthenticate and reopen one durable exact-claims candidate after restart.
    ///
    /// The serialized catalog is only bounded recovery data. This method grants process-local
    /// spool authority only after loading every certified response artifact, authenticating its
    /// advertisement against `target`, checking current source membership and the exact `f+1`
    /// policy, and matching the selected full spool head. All non-deleting reducer phases are
    /// eligible because a fully downloaded candidate must remain adoptable without a live peer.
    pub async fn resume_exact_claims_admission(
        &self,
        context: DepositSyncContext,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Option<DepositSyncSpoolAdmission>, DepositSyncStageError> {
        if context.network() != self.network_id || context.wallet() != target.wallet() {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        let should_activate = catalog.active.as_ref().is_some_and(|active| {
            active.authority == DepositSyncSpoolAuthority::ExactClaims
                && active.state == DepositSyncSpoolActiveState::Admitting
                && active.pinned_source.is_none()
        });
        if should_activate {
            let _ = self.activate_next_stored_claim(&mut metadata, &mut catalog).await?;
        }

        let Some(active) = catalog.active.as_ref().cloned() else {
            return Ok(None);
        };
        if active.authority != DepositSyncSpoolAuthority::ExactClaims
            || active.state != DepositSyncSpoolActiveState::Active
        {
            return Ok(None);
        }
        let Some(source) = active.pinned_source else {
            return Ok(None);
        };
        if source_unavailable(&active, source)
            || !active.certified_claims.contains_key(&source)
            || catalog
                .pending_releases
                .contains_key(&DepositSyncPendingReleaseKey::Ordinary(source))
        {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }

        let mut selected_response = None;
        let mut supporters = Vec::with_capacity(active.certified_claims.len());
        let mut authenticated_policy = None;
        for (supporter, certified) in &active.certified_claims {
            target
                .committee()
                .member(*supporter)
                .map_err(|_| DepositSyncStageError::InvalidAdmissionEvidence)?;
            let claim = DepositSyncSpoolClaim {
                binding: certified.binding,
                policy: active.policy,
                facts: active.facts,
                lease: certified.lease,
                response: certified.response,
                state: DepositSyncSpoolClaimState::Ready,
            };
            let response = self.verify_claim_response(*supporter, &claim).await?;
            let advertisement = response.advertisement();
            let policy =
                DepositSyncSpoolAdmissionPolicy::authenticated(advertisement, target, self.party)
                    .map_err(|_| DepositSyncStageError::InvalidAdmissionEvidence)?;
            let facts = DepositSyncCandidateFacts::from_advertisement(advertisement)
                .map_err(|_| DepositSyncStageError::InvalidAdmissionEvidence)?;
            if authenticated_policy.is_some_and(|expected| expected != policy) {
                return Err(DepositSyncStageError::InvalidAdmissionEvidence);
            }
            authenticated_policy.get_or_insert(policy);
            if advertisement.context() != context
                || policy != active.policy
                || facts != active.facts
                || facts.support != active.support
                || certified.binding != spool_binding(advertisement)?
            {
                return Err(DepositSyncStageError::InvalidAdmissionEvidence);
            }
            if *supporter == source {
                if certified.binding != active.binding {
                    return Err(DepositSyncStageError::InvalidAdmissionEvidence);
                }
                selected_response = Some(response);
            }
            supporters.push(*supporter);
        }
        let authenticated_policy =
            authenticated_policy.ok_or(DepositSyncStageError::InvalidAdmissionEvidence)?;
        if supporters.len() < usize::from(authenticated_policy.required_supporters) {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        let selected_response =
            selected_response.ok_or(DepositSyncStageError::InvalidAdmissionEvidence)?;

        if !spool_namespace(&self.directory, active.binding).exists() {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let spool = self.open_cached_binding(active.binding).await?;
        let durable_response = spool.head_response(self.party).await?;
        if durable_response != selected_response {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        match spool.checkpoint().await?.phase() {
            DepositSyncSpoolPhase::Downloading
            | DepositSyncSpoolPhase::Frozen
            | DepositSyncSpoolPhase::Verifying
            | DepositSyncSpoolPhase::Verified
            | DepositSyncSpoolPhase::Materializing
            | DepositSyncSpoolPhase::ReadyToCas => {}
            DepositSyncSpoolPhase::Deleting => return Ok(None),
        }
        Ok(Some(DepositSyncSpoolAdmission::Admitted { spool, source, supporters }))
    }

    /// Abandon one exact non-authoritative prefix attempt and durably queue only its serving
    /// source lease for typed release.
    pub async fn discard_prefix_support_attempt(
        &self,
        context: DepositSyncContext,
        expected_statement_digest: [u8; 32],
    ) -> Result<(), DepositSyncStageError> {
        self.dispose_prefix_support_attempt(
            context,
            expected_statement_digest,
            DepositSyncPrefixFailureClass::Transient,
        )
        .await
    }

    /// Permanently reject a provably invalid non-authoritative prefix attempt.
    ///
    /// Only cryptographic or semantic contradictions belong here. Transport unavailability and
    /// timeouts must use [`Self::discard_prefix_support_attempt`] so an honest source becomes
    /// eligible again after its bounded cooldown.
    pub async fn reject_prefix_support_attempt(
        &self,
        context: DepositSyncContext,
        expected_statement_digest: [u8; 32],
        _rejection: DepositSyncVariantRejection,
    ) -> Result<(), DepositSyncStageError> {
        self.dispose_prefix_support_attempt(
            context,
            expected_statement_digest,
            DepositSyncPrefixFailureClass::Permanent,
        )
        .await
    }

    async fn dispose_prefix_support_attempt(
        &self,
        context: DepositSyncContext,
        expected_statement_digest: [u8; 32],
        failure_class: DepositSyncPrefixFailureClass,
    ) -> Result<(), DepositSyncStageError> {
        if context.network() != self.network_id || expected_statement_digest == [0; 32] {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let (source, binding, policy, facts) = {
            let attempt =
                catalog.prefix_attempt.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
            if attempt.statement_digest != expected_statement_digest {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
            let evidence = match &attempt.state {
                DepositSyncPrefixAttemptState::Promoting(evidence) => Some(evidence.clone()),
                DepositSyncPrefixAttemptState::Deleting(evidence) => evidence.clone(),
                DepositSyncPrefixAttemptState::Installing
                | DepositSyncPrefixAttemptState::Collecting => None,
            };
            let source = attempt.claim.lease.source();
            let binding = attempt.binding;
            let policy = attempt.policy;
            let facts = attempt.facts;
            attempt.claim.state = DepositSyncSpoolClaimState::Deleting;
            attempt.state = DepositSyncPrefixAttemptState::Deleting(evidence);
            (source, binding, policy, facts)
        };
        record_prefix_source_failure(&mut catalog, source, binding, policy, facts, failure_class)?;
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await
    }

    /// Atomically promote an owned prefix attempt after exact f+1 certificate verification.
    pub async fn open_or_create_with_prefix_support(
        &self,
        response: &DepositSyncHeadResponse,
        certificate: &VerifiedDepositSyncSupportCertificate,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositSyncSpoolAdmission, DepositSyncStageError> {
        let binding = spool_binding(response.advertisement())?;
        if let Some(admission) =
            self.resume_prefix_admission(response.advertisement().context(), target).await?
        {
            let DepositSyncSpoolAdmission::AdmittedPrefix { spool, source, .. } = &admission else {
                return Err(DepositSyncStageError::InvalidAdmissionEvidence);
            };
            let authorization =
                self.prefix_authorizations.lock().await.get(&binding.anchor).copied();
            if spool.binding != binding
                || *source != response.lease().source()
                || certificate.statement().source_lease_digest() != response.lease().digest()
                || authorization
                    != Some(DepositSyncPrefixAuthorization {
                        source: *source,
                        statement_digest: certificate.statement_digest(),
                        certificate_digest: certificate.certificate_digest(),
                    })
            {
                return Err(DepositSyncStageError::InvalidAdmissionEvidence);
            }
            return Ok(admission);
        }
        let work = self.begin_prefix_support_attempt(response, target).await?;
        if certificate.statement() != work.statement() {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        let source = response.lease().source();
        let envelope = DepositSyncPrefixCertificateEnvelope::from_verified(binding, certificate)?;
        let certificate_bytes = envelope.to_bytes()?;
        let certificate_reference = WalletArtifactRef::for_contents(
            WalletId(binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_PREFIX_CERTIFICATE_ARTIFACT,
            &certificate_bytes,
        )?;
        let proposed_evidence = DepositSyncPrefixEvidence {
            source,
            statement_digest: certificate.statement_digest(),
            certificate_digest: certificate.certificate_digest(),
            certificate: DepositSyncClaimArtifact {
                reference: certificate_reference,
                owner: WalletArtifactOwner::random(&mut OsRng),
            },
            endorsers: certificate.signers().to_vec(),
        };

        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        let attempt =
            catalog.prefix_attempt.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
        if attempt.binding != binding
            || attempt.claim.lease != response.lease()
            || attempt.statement_digest != certificate.statement_digest()
        {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        let attempt_state = attempt.state.clone();
        let evidence = match attempt_state {
            DepositSyncPrefixAttemptState::Collecting => {
                catalog
                    .prefix_attempt
                    .as_mut()
                    .ok_or(DepositSyncStageError::UnknownAnchor)?
                    .state = DepositSyncPrefixAttemptState::Promoting(proposed_evidence.clone());
                metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                proposed_evidence
            }
            DepositSyncPrefixAttemptState::Promoting(existing)
                if existing.source == proposed_evidence.source
                    && existing.statement_digest == proposed_evidence.statement_digest
                    && existing.certificate_digest == proposed_evidence.certificate_digest
                    && existing.certificate.reference
                        == proposed_evidence.certificate.reference
                    && existing.endorsers == proposed_evidence.endorsers =>
            {
                existing
            }
            _ => return Err(DepositSyncStageError::InvalidAdmissionEvidence),
        };
        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                evidence.certificate.owner,
                WalletId(binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_PREFIX_CERTIFICATE_ARTIFACT,
                &certificate_bytes,
                &mut OsRng,
            )
            .await?;
        if installed != evidence.certificate.reference {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let work = self
            .load_prefix_attempt_work(
                catalog.prefix_attempt.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?,
                target,
            )
            .await?;
        self.verify_prefix_evidence(binding, &evidence, &work, target).await?;
        let attempt = catalog.prefix_attempt.take().ok_or(DepositSyncStageError::UnknownAnchor)?;
        let claim = attempt.claim;
        if claim.state != DepositSyncSpoolClaimState::Ready {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let certified_claims = BTreeMap::from([(
            source,
            DepositSyncCertifiedClaim {
                binding: claim.binding,
                lease: claim.lease,
                response: claim.response,
            },
        )]);
        catalog.active = Some(DepositSyncSpoolActive {
            support: attempt.facts.support,
            binding,
            policy: attempt.policy,
            facts: attempt.facts,
            authority: DepositSyncSpoolAuthority::Prefix(evidence.clone()),
            certified_claims,
            failed_variants: BTreeSet::new(),
            rejected_variants: BTreeSet::new(),
            source_failure_round: 0,
            pinned_source: Some(source),
            state: DepositSyncSpoolActiveState::Admitting,
        });
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        let spool = self.open_cached_binding(binding).await?;
        let _ = spool.initialize().await?;
        spool.install_head_response(response, self.party).await?;
        let active = catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
        active.state = DepositSyncSpoolActiveState::Active;
        let _ = self.persist_catalog(metadata, &catalog).await?;
        self.record_prefix_authorization(binding.anchor, &evidence).await;
        Ok(DepositSyncSpoolAdmission::AdmittedPrefix {
            spool,
            source,
            statement_digest: evidence.statement_digest,
            certificate_digest: evidence.certificate_digest,
            endorsers: evidence.endorsers,
        })
    }

    /// Open one exact old-quorum-certified export without applying ordinary f+1 tip admission.
    ///
    /// The verified seal and locally authenticated target are process-local authority. Only their
    /// fixed bindings and the exact canonical request/response bytes are journaled. A crash after
    /// the catalog intent but before the head artifact is harmless: an exact retry resumes the
    /// same `Installing` record, while a conflicting response is rejected.
    pub async fn open_or_create_certified_export(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
        seal: &VerifiedDepositPostHandoffExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Arc<DepositSyncSpoolStore>, DepositSyncStageError> {
        self.open_or_create_certified_export_inner(request, response, seal, target).await
    }

    /// Admit an exact old-quorum-certified head for a cold target without returning full import
    /// authority. Re-presenting the fully verified seal to
    /// [`Self::open_or_create_certified_export`] is mandatory before the caller can freeze or
    /// import the downloaded graph.
    pub(crate) async fn open_or_create_pre_import_certified_export(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
        seal: &VerifiedPreImportDepositStateExportSeal,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<PreImportDepositStateExportSpool, DepositSyncStageError> {
        let spool =
            self.open_or_create_certified_export_inner(request, response, seal, target).await?;
        Ok(PreImportDepositStateExportSpool { spool })
    }

    async fn open_or_create_certified_export_inner<S: CertifiedExportReadSeal + ?Sized>(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
        seal: &S,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Arc<DepositSyncSpoolStore>, DepositSyncStageError> {
        seal.validate_head(request, response)?;
        seal.validate_target(target)?;
        let advertisement = response.advertisement();
        advertisement
            .registry_archive()
            .registry()
            .verify_active_target(target)
            .map_err(|_| DepositSyncStageError::WrongContext)?;
        if request.context().network() != self.network_id
            || request.context().wallet() != target.wallet()
            || request.requester() != self.party
            || response.requester() != self.party
            || request.source() == self.party
            || request.source() != response.source()
            || response.lease().source() != request.source()
            || response.lease().requester() != self.party
            || target.committee().member(self.party).is_err()
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let binding = certified_export_spool_binding(request, response)?;
        let proposed = DepositStateExportSpoolActive {
            binding,
            context: request.context(),
            source: request.source(),
            requester: self.party,
            semantic_transition: request.semantic_transition_digest(),
            request_digest: request.digest(),
            response_digest: response.digest(),
            lease_digest: response.lease().digest(),
            state: DepositStateExportSpoolActiveState::Installing,
        };
        let target_binding = certified_export_target_binding(target);
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if catalog.active.is_some()
            || catalog.prefix_attempt.is_some()
            || !catalog.claims.is_empty()
        {
            return Err(DepositSyncStageError::OrdinaryAdmissionInProgress);
        }
        match catalog.certified_export {
            Some(existing)
                if certified_export_same_admission(existing, proposed)
                    && matches!(
                        existing.state,
                        DepositStateExportSpoolActiveState::Installing
                            | DepositStateExportSpoolActiveState::Active
                    ) => {}
            Some(_) => return Err(DepositSyncStageError::CertifiedExportAdmissionInProgress),
            None => {
                let intent = catalog
                    .certified_export_intents
                    .get(&request.source())
                    .ok_or(DepositSyncStageError::CertifiedExportIntentRequired)?;
                if intent.context != request.context()
                    || intent.source != request.source()
                    || intent.requester != request.requester()
                    || intent.semantic_transition != request.semantic_transition_digest()
                    || intent.target_binding != target_binding
                    || intent.seal_statement != seal.statement_digest()
                    || intent.seal_certificate_digest != seal.certificate_digest()
                    || intent.request != request
                    || intent.request_digest != request.digest()
                    || intent.seal_certificate.as_slice() != seal.canonical_certificate_bytes()
                {
                    return Err(DepositSyncStageError::CertifiedExportIntentConflict);
                }
                // The first exact valid response wins. Retain the selected and competing intents
                // until the exact head artifact is durably readable: a crash in this Installing
                // window can then retry only the selected request without reopening selection.
                catalog.certified_export = Some(proposed);
                metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            }
        }

        let spool = self.open_cached_binding(binding).await?;
        let _ = spool.initialize().await?;
        spool.install_certified_export_head_response(request, response, seal).await?;
        let (durable_request, durable_response) = spool.export_head_response().await?;
        if durable_request != request || durable_response != *response {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let active = catalog.certified_export.ok_or(DepositSyncStageError::UnknownAnchor)?;
        if !certified_export_same_admission(active, proposed) {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        if active.state == DepositStateExportSpoolActiveState::Installing {
            catalog.certified_export.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                DepositStateExportSpoolActiveState::Active;
            let _ = self.persist_catalog(metadata, &catalog).await?;
        }
        Ok(spool)
    }

    /// Record one fixed-size semantic support claim and open only the single active exact variant.
    pub async fn open_or_create(
        &self,
        response: &DepositSyncHeadResponse,
        source: PartyId,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositSyncSpoolAdmission, DepositSyncStageError> {
        let advertisement = response.advertisement();
        if advertisement.context().network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        validate_source(source)?;
        if source == self.party
            || response.lease().source() != source
            || response.lease().requester() != self.party
            || response.lease().advertisement_digest() != advertisement.digest()
        {
            return Err(DepositSyncStageError::InvalidSource);
        }
        let policy =
            DepositSyncSpoolAdmissionPolicy::authenticated(advertisement, target, self.party)?;
        if target.committee().member(source).is_err() {
            return Err(DepositSyncStageError::InvalidSource);
        }
        let binding = spool_binding(advertisement)?;
        if binding.maximum_objects != policy.maximum_objects {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let facts = DepositSyncCandidateFacts::from_advertisement(advertisement)?;
        if facts.support != policy.support {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        if let Some(admission) =
            self.resume_prefix_admission(advertisement.context(), target).await?
        {
            let DepositSyncSpoolAdmission::AdmittedPrefix { spool, source: active_source, .. } =
                &admission
            else {
                return Err(DepositSyncStageError::InvalidAdmissionEvidence);
            };
            let active_response = spool.head_response(self.party).await?;
            if active_response.lease() != response.lease() {
                if *active_source == source {
                    return Err(DepositSyncStageError::SourceLeaseBusy(source));
                }
                self.enqueue_unadmitted_release(response).await?;
            }
            return Ok(admission);
        }
        let key = binding.key;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if catalog.certified_export.is_some() || !catalog.certified_export_intents.is_empty() {
            return Err(DepositSyncStageError::CertifiedExportAdmissionInProgress);
        }
        if self.reconcile_catalog_for_target(&mut catalog, target).await? {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        if let Some(attempt) = catalog.prefix_attempt.as_ref() {
            let already_owned =
                attempt.claim.lease == response.lease() && attempt.claim.binding == binding;
            if !already_owned {
                self.enqueue_release(&mut catalog, response.lease())?;
                let _ = self.persist_catalog(metadata, &catalog).await?;
            }
            return Err(DepositSyncStageError::AdmissionEvidenceRequired);
        }
        if let Some(active) = catalog.active.as_ref()
            && matches!(&active.authority, DepositSyncSpoolAuthority::Prefix(_))
        {
            let already_owned = active
                .certified_claims
                .get(&source)
                .is_some_and(|claim| claim.lease == response.lease());
            if !already_owned {
                self.enqueue_release(&mut catalog, response.lease())?;
                let _ = self.persist_catalog(metadata, &catalog).await?;
            }
            return Err(DepositSyncStageError::AdmissionEvidenceRequired);
        }
        if catalog.pending_releases.contains_key(&DepositSyncPendingReleaseKey::Ordinary(source)) {
            return Err(DepositSyncStageError::PendingReleaseRequired(source));
        }
        let committed_or_releasing = catalog.active.as_ref().and_then(|active| {
            matches!(
                active.state,
                DepositSyncSpoolActiveState::ReleasingOwnership { .. }
                    | DepositSyncSpoolActiveState::OwnershipReleased { .. }
                    | DepositSyncSpoolActiveState::Committed { .. }
            )
            .then_some((active.binding, active.pinned_source))
        });
        if let Some((active_binding, pinned_source)) = committed_or_releasing {
            self.enqueue_release(&mut catalog, response.lease())?;
            let _ = self.persist_catalog(metadata, &catalog).await?;
            return self.standby_admission(active_binding, pinned_source).await;
        }
        if catalog.active.as_ref().is_some_and(|active| {
            active.state == DepositSyncSpoolActiveState::Admitting
                && active.pinned_source.is_none()
                && !active.failed_variants.is_empty()
        }) {
            let _ = self.activate_next_stored_claim(&mut metadata, &mut catalog).await?;
        }
        if catalog.active.as_ref().is_some_and(|active| {
            active.state == DepositSyncSpoolActiveState::Admitting
                && active.pinned_source.is_some()
                && (active.binding != binding || active.pinned_source != Some(source))
        }) {
            catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                DepositSyncSpoolActiveState::Deleting { prepared: false };
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        if let Some(active) = catalog.active.as_ref()
            && active.support != facts.support
            && let Some(pinned_source) = active.pinned_source
        {
            let active_binding = active.binding;
            self.enqueue_release(&mut catalog, response.lease())?;
            let _ = self.persist_catalog(metadata, &catalog).await?;
            return self.standby_admission(active_binding, Some(pinned_source)).await;
        }

        // Claims describe current availability and are replaceable only by the same authenticated
        // source. Persist the exact historical-serving lease out of line before it can contribute
        // to the immutable admission certificate.
        metadata = Some(
            self.install_claim_response(
                metadata,
                &mut catalog,
                source,
                response,
                binding,
                policy,
                facts,
            )
            .await?,
        );

        let matching_supporters = catalog
            .claims
            .iter()
            .filter_map(|(party, claim)| {
                (claim.state == DepositSyncSpoolClaimState::Ready
                    && claim.facts.support == facts.support
                    && claim.policy == policy)
                    .then_some(*party)
            })
            .collect::<BTreeSet<_>>();
        let supporter_count = u16::try_from(matching_supporters.len())
            .map_err(|_| DepositSyncStageError::CandidateQuota)?;
        let matching_claims = matching_supporters
            .iter()
            .map(|source| {
                let claim =
                    catalog.claims.get(source).ok_or(DepositSyncStageError::InvalidSnapshot)?;
                Ok((
                    *source,
                    DepositSyncCertifiedClaim {
                        binding: claim.binding,
                        lease: claim.lease,
                        response: claim.response,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, DepositSyncStageError>>()?;

        if catalog.active.is_some() {
            let active_support = catalog.active.as_ref().expect("active checked").support;
            if active_support != facts.support {
                let active = catalog.active.as_ref().expect("active checked");
                let active_binding = active.binding;
                let preferred_source = active.pinned_source.or_else(|| {
                    active
                        .certified_claims
                        .iter()
                        .find(|(source, _)| !source_unavailable(active, **source))
                        .map(|(source, _)| *source)
                });
                if supporter_count < policy.required_supporters
                    || active.pinned_source.is_some()
                    || !candidate_facts_are_stale(active.facts, facts)
                {
                    let _ = self.persist_catalog(metadata, &catalog).await?;
                    return self.standby_admission(active_binding, preferred_source).await;
                }
                catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                    DepositSyncSpoolActiveState::Deleting { prepared: false };
                metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
                catalog.active = Some(DepositSyncSpoolActive {
                    support: facts.support,
                    binding,
                    policy,
                    facts,
                    authority: DepositSyncSpoolAuthority::ExactClaims,
                    certified_claims: matching_claims.clone(),
                    failed_variants: BTreeSet::new(),
                    rejected_variants: BTreeSet::new(),
                    source_failure_round: 0,
                    pinned_source: Some(source),
                    state: DepositSyncSpoolActiveState::Admitting,
                });
                metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
            } else {
                let certified_changed = {
                    let active = catalog.active.as_mut().expect("active checked");
                    if active.policy != policy || active.facts != facts {
                        return Err(DepositSyncStageError::InvalidSnapshot);
                    }
                    let prior = active.certified_claims.len();
                    for (supporter, claim) in &matching_claims {
                        active.certified_claims.entry(*supporter).or_insert(*claim);
                    }
                    active.certified_claims.len() != prior
                };
                if certified_changed {
                    metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                }
                let active = catalog.active.as_mut().expect("active checked");
                if source_unavailable(active, source) {
                    let active_binding = active.binding;
                    let preferred_source = active.pinned_source.or_else(|| {
                        active
                            .certified_claims
                            .iter()
                            .find(|(candidate, _)| !source_unavailable(active, **candidate))
                            .map(|(candidate, _)| *candidate)
                    });
                    let _ = self.persist_catalog(metadata, &catalog).await?;
                    return self.standby_admission(active_binding, preferred_source).await;
                }
                if active.binding != binding {
                    if let Some(pinned_source) = active.pinned_source {
                        let active_binding = active.binding;
                        let _ = self.persist_catalog(metadata, &catalog).await?;
                        return self.standby_admission(active_binding, Some(pinned_source)).await;
                    }
                    let previous = active.binding;
                    active.binding = binding;
                    active.pinned_source = Some(source);
                    active.state = DepositSyncSpoolActiveState::Switching { previous };
                    metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                    self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
                } else if let Some(pinned_source) = active.pinned_source {
                    if pinned_source != source {
                        let active_binding = active.binding;
                        let _ = self.persist_catalog(metadata, &catalog).await?;
                        return self.standby_admission(active_binding, Some(pinned_source)).await;
                    }
                } else {
                    active.pinned_source = Some(source);
                    let _ = self.persist_catalog(metadata, &catalog).await?;
                }
            }
        } else {
            if supporter_count < policy.required_supporters {
                if sampling_authority_is_complete_without_quorum(&catalog, policy)? {
                    catalog.sampling_round = catalog
                        .sampling_round
                        .checked_add(1)
                        .ok_or(DepositSyncStageError::InvalidSnapshot)?;
                    let selected = select_prefix_claim(&catalog);
                    let prefix = if let Some((selected_source, selected_claim)) = selected {
                        let selected_response =
                            self.verify_claim_response(selected_source, &selected_claim).await?;
                        if selected_response.advertisement().checkpoint_certificate().is_some() {
                            let request = DepositSyncHeadRequest::new(
                                selected_response.advertisement().context(),
                                selected_source,
                                self.party,
                            )?;
                            let statement = DepositSyncSupportStatement::from_head_response(
                                request,
                                &selected_response,
                                target,
                            )?;
                            Some((selected_source, selected_response, statement))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    if let Some((selected_source, selected_response, statement)) = prefix {
                        let selected_claim = catalog
                            .claims
                            .remove(&selected_source)
                            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
                        catalog.prefix_attempt = Some(DepositSyncPrefixSupportAttempt {
                            binding: selected_claim.binding,
                            policy: selected_claim.policy,
                            facts: selected_claim.facts,
                            claim: selected_claim,
                            statement_digest: statement.digest(),
                            state: DepositSyncPrefixAttemptState::Collecting,
                        });
                        let releases =
                            catalog.claims.values().map(|claim| claim.lease).collect::<Vec<_>>();
                        for lease in releases {
                            self.enqueue_release(&mut catalog, lease)?;
                        }
                        for claim in catalog.claims.values_mut() {
                            claim.state = DepositSyncSpoolClaimState::Deleting;
                        }
                        let round = catalog.sampling_round;
                        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
                        return Ok(DepositSyncSpoolAdmission::PrefixSupportRequired {
                            round,
                            work: DepositSyncPrefixSupportWork {
                                response: selected_response,
                                statement,
                            },
                        });
                    }
                    let releases =
                        catalog.claims.values().map(|claim| claim.lease).collect::<Vec<_>>();
                    for lease in releases {
                        self.enqueue_release(&mut catalog, lease)?;
                    }
                    for claim in catalog.claims.values_mut() {
                        claim.state = DepositSyncSpoolClaimState::Deleting;
                    }
                    let round = catalog.sampling_round;
                    metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                    self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
                    return Ok(DepositSyncSpoolAdmission::SamplingRoundComplete { round });
                }
                let _ = self.persist_catalog(metadata, &catalog).await?;
                return Ok(DepositSyncSpoolAdmission::Pending {
                    supporters: supporter_count,
                    required: policy.required_supporters,
                });
            }
            catalog.active = Some(DepositSyncSpoolActive {
                support: facts.support,
                binding,
                policy,
                facts,
                authority: DepositSyncSpoolAuthority::ExactClaims,
                certified_claims: matching_claims,
                failed_variants: BTreeSet::new(),
                rejected_variants: BTreeSet::new(),
                source_failure_round: 0,
                pinned_source: Some(source),
                state: DepositSyncSpoolActiveState::Admitting,
            });
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }

        let spool = self.open_cached_binding(binding).await?;
        let _ = spool.initialize().await?;
        {
            let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
            if active.binding != binding
                || active.support != facts.support
                || active.pinned_source != Some(source)
                || !matches!(
                    active.state,
                    DepositSyncSpoolActiveState::Admitting | DepositSyncSpoolActiveState::Active
                )
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        spool.install_head_response(response, self.party).await?;
        if catalog
            .active
            .as_ref()
            .is_some_and(|active| active.state == DepositSyncSpoolActiveState::Admitting)
        {
            catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                DepositSyncSpoolActiveState::Active;
            let _ = self.persist_catalog(metadata, &catalog).await?;
        }
        let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
        if active.authority != DepositSyncSpoolAuthority::ExactClaims {
            return Err(DepositSyncStageError::AdmissionEvidenceRequired);
        }
        let supporters = active.certified_claims.keys().copied().collect();
        Ok(DepositSyncSpoolAdmission::Admitted { spool, source, supporters })
    }

    /// Inspect an exact candidate without creating its namespace or mutable head.
    pub async fn candidate_state(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Option<DepositSyncSpoolPhase>, DepositSyncStageError> {
        if advertisement.context().network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let binding = spool_binding(advertisement)?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) = catalog.active.as_ref() {
            if active.binding != binding {
                return Ok(None);
            }
            match active.state {
                DepositSyncSpoolActiveState::Admitting
                | DepositSyncSpoolActiveState::Switching { .. }
                | DepositSyncSpoolActiveState::Failing { .. }
                | DepositSyncSpoolActiveState::Rejecting { .. } => {
                    return Ok(None);
                }
                DepositSyncSpoolActiveState::Deleting { .. } => {
                    return Ok(Some(DepositSyncSpoolPhase::Deleting));
                }
                DepositSyncSpoolActiveState::ReleasingOwnership { .. }
                | DepositSyncSpoolActiveState::OwnershipReleased { .. } => {
                    return Ok(Some(DepositSyncSpoolPhase::ReadyToCas));
                }
                DepositSyncSpoolActiveState::Committed { .. } => {
                    return Ok(Some(DepositSyncSpoolPhase::Deleting));
                }
                DepositSyncSpoolActiveState::Active => {}
            }
        } else if let Some(active) = catalog.certified_export.as_ref() {
            if active.binding != binding {
                return Ok(None);
            }
            match active.state {
                DepositStateExportSpoolActiveState::Installing => return Ok(None),
                DepositStateExportSpoolActiveState::Deleting { .. } => {
                    return Ok(Some(DepositSyncSpoolPhase::Deleting));
                }
                DepositStateExportSpoolActiveState::ReleasingOwnership { .. }
                | DepositStateExportSpoolActiveState::OwnershipReleased { .. } => {
                    return Ok(Some(DepositSyncSpoolPhase::ReadyToCas));
                }
                DepositStateExportSpoolActiveState::Committed { .. } => {
                    return Ok(Some(DepositSyncSpoolPhase::Deleting));
                }
                DepositStateExportSpoolActiveState::Active => {}
            }
        } else {
            return Ok(None);
        }
        let namespace = spool_namespace(&self.directory, binding);
        if !namespace.exists() {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let protocol = ProtocolStore::new(&namespace, self.party, &self.identity_seed)?;
        let Some(blob) = protocol.load_deposit_sync_spool_head(binding.key).await? else {
            return Ok(None);
        };
        let head: DepositSyncSpoolHead = decode_canonical(
            blob.state.as_bytes(),
            MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
            "deposit sync spool head",
        )?;
        if head.version != DEPOSIT_SYNC_SPOOL_HEAD_VERSION || head.binding != binding {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        Ok(Some(head.checkpoint.phase()))
    }

    /// Reopen the exact ReadyToCas spool named by an authoritative wallet-snapshot marker.
    pub async fn open_prepared_import(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<Arc<DepositSyncSpoolStore>, DepositSyncStageError> {
        marker.validate_for(marker.wallet())?;
        if marker.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(marker.binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) =
            catalog.certified_export.as_ref().filter(|active| active.binding == marker.binding)
        {
            let valid_state = matches!(active.state, DepositStateExportSpoolActiveState::Active)
                || matches!(
                    active.state,
                    DepositStateExportSpoolActiveState::ReleasingOwnership { marker: durable }
                        | DepositStateExportSpoolActiveState::OwnershipReleased { marker: durable }
                        if durable == *marker
                );
            if !valid_state {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            let spool = self.open_cached_binding(marker.binding).await?;
            let _ = spool.initialize().await?;
            if spool.import_marker().await? != *marker {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            return Ok(spool);
        }
        let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
        let valid_state = matches!(
            active.state,
            DepositSyncSpoolActiveState::Active | DepositSyncSpoolActiveState::Admitting
        ) || matches!(
            active.state,
            DepositSyncSpoolActiveState::ReleasingOwnership { marker: durable }
                | DepositSyncSpoolActiveState::OwnershipReleased { marker: durable }
                if durable == *marker
        );
        if active.binding != marker.binding || !valid_state {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        if let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority
            && !self.prefix_is_authorized(active.binding.anchor, evidence).await
        {
            return Err(DepositSyncStageError::AdmissionEvidenceRequired);
        }
        let spool = self.open_cached_binding(marker.binding).await?;
        let _ = spool.initialize().await?;
        if spool.import_marker().await? != *marker {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        Ok(spool)
    }

    /// Abort a stale pre-CAS marker and leave the verified candidate available for retry.
    pub async fn abort_prepared_import(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<(), DepositSyncStageError> {
        let spool = self.open_prepared_import(marker).await?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(marker.binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) =
            catalog.certified_export.as_ref().filter(|active| active.binding == marker.binding)
        {
            if active.state != DepositStateExportSpoolActiveState::Active {
                return Err(DepositSyncStageError::PreparedImportDispositionRequired);
            }
            return spool.abort_prepared_import(Some(marker)).await;
        }
        let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
        if active.binding != marker.binding
            || !matches!(
                active.state,
                DepositSyncSpoolActiveState::Active | DepositSyncSpoolActiveState::Admitting
            )
        {
            return Err(DepositSyncStageError::PreparedImportDispositionRequired);
        }
        spool.abort_prepared_import(Some(marker)).await
    }

    /// Relinquish permanent-artifact ownership and durably retain the marker before clearing it
    /// from the authoritative wallet snapshot.
    ///
    /// The caller must first commit the marker-bearing named-root snapshot and durably register
    /// every page from [`DepositSyncSpoolStore::prepared_reference_page`] with retention. This
    /// transition is intentionally irreversible: once reservations are released, abort is unsafe.
    pub async fn release_prepared_import_ownership(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<(), DepositSyncStageError> {
        marker.validate_for(marker.wallet())?;
        if marker.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let spool = {
            let _catalog_mutation = self.catalog_mutation.lock().await;
            let (mut metadata, mut catalog) = self.load_catalog(marker.binding.key).await?;
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
            if let Some(active) =
                catalog.certified_export.as_ref().filter(|active| active.binding == marker.binding)
            {
                match active.state {
                    DepositStateExportSpoolActiveState::OwnershipReleased { marker: durable }
                        if durable == *marker =>
                    {
                        return Ok(());
                    }
                    DepositStateExportSpoolActiveState::Deleting { prepared: true } => {
                        return Ok(());
                    }
                    DepositStateExportSpoolActiveState::Active
                    | DepositStateExportSpoolActiveState::ReleasingOwnership { .. } => {}
                    _ => return Err(DepositSyncStageError::InvalidImportMarker),
                }
                if let DepositStateExportSpoolActiveState::ReleasingOwnership { marker: durable } =
                    active.state
                    && durable != *marker
                {
                    return Err(DepositSyncStageError::InvalidImportMarker);
                }
                let spool = self.open_cached_binding(marker.binding).await?;
                let _ = spool.initialize().await?;
                if spool.import_marker().await? != *marker {
                    return Err(DepositSyncStageError::InvalidImportMarker);
                }
                spool.begin_prepared_import_release(marker).await?;
                let active = catalog
                    .certified_export
                    .as_mut()
                    .ok_or(DepositSyncStageError::UnknownAnchor)?;
                if !matches!(
                    active.state,
                    DepositStateExportSpoolActiveState::ReleasingOwnership { .. }
                ) {
                    active.state =
                        DepositStateExportSpoolActiveState::ReleasingOwnership { marker: *marker };
                    let _ = self.persist_catalog(metadata, &catalog).await?;
                }
                spool
            } else {
                let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
                if active.binding != marker.binding {
                    return Err(DepositSyncStageError::InvalidImportMarker);
                }
                if let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority
                    && !self.prefix_is_authorized(active.binding.anchor, evidence).await
                {
                    return Err(DepositSyncStageError::AdmissionEvidenceRequired);
                }
                match active.state {
                    DepositSyncSpoolActiveState::OwnershipReleased { marker: durable }
                        if durable == *marker =>
                    {
                        return Ok(());
                    }
                    DepositSyncSpoolActiveState::Deleting { prepared: true } => return Ok(()),
                    DepositSyncSpoolActiveState::Active
                    | DepositSyncSpoolActiveState::Admitting
                    | DepositSyncSpoolActiveState::ReleasingOwnership { marker: _ } => {}
                    _ => return Err(DepositSyncStageError::InvalidImportMarker),
                }
                if let DepositSyncSpoolActiveState::ReleasingOwnership { marker: durable } =
                    active.state
                    && durable != *marker
                {
                    return Err(DepositSyncStageError::InvalidImportMarker);
                }
                let spool = self.open_cached_binding(marker.binding).await?;
                let _ = spool.initialize().await?;
                if spool.import_marker().await? != *marker {
                    return Err(DepositSyncStageError::InvalidImportMarker);
                }
                // This authenticated head write is the point of no return. Direct spool
                // abort/rebase rejects the journal even before catalog promotion is visible.
                spool.begin_prepared_import_release(marker).await?;
                let active = catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
                if !matches!(active.state, DepositSyncSpoolActiveState::ReleasingOwnership { .. }) {
                    active.state =
                        DepositSyncSpoolActiveState::ReleasingOwnership { marker: *marker };
                    let _ = self.persist_catalog(metadata, &catalog).await?;
                }
                spool
            }
        };
        spool.resume_prepared_import_release(marker).await?;

        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(marker.binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) =
            catalog.certified_export.as_mut().filter(|active| active.binding == marker.binding)
        {
            if matches!(
                active.state,
                DepositStateExportSpoolActiveState::Deleting { prepared: true }
            ) || active.state
                == (DepositStateExportSpoolActiveState::OwnershipReleased { marker: *marker })
            {
                return Ok(());
            }
            if active.state
                != (DepositStateExportSpoolActiveState::ReleasingOwnership { marker: *marker })
                || !spool.prepared_import_release_is_complete(marker).await?
            {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            active.state =
                DepositStateExportSpoolActiveState::OwnershipReleased { marker: *marker };
            let _ = self.persist_catalog(metadata, &catalog).await?;
            return Ok(());
        }
        let Some(active) = catalog.active.as_mut() else {
            if !spool_namespace(&self.directory, marker.binding).exists() {
                return Ok(());
            }
            return Err(DepositSyncStageError::UnknownAnchor);
        };
        if active.binding == marker.binding
            && matches!(active.state, DepositSyncSpoolActiveState::Deleting { prepared: true })
        {
            return Ok(());
        }
        if active.binding == marker.binding
            && active.state == (DepositSyncSpoolActiveState::OwnershipReleased { marker: *marker })
        {
            return Ok(());
        }
        if active.binding != marker.binding
            || active.state != (DepositSyncSpoolActiveState::ReleasingOwnership { marker: *marker })
            || !spool.prepared_import_release_is_complete(marker).await?
        {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        active.state = DepositSyncSpoolActiveState::OwnershipReleased { marker: *marker };
        let _ = self.persist_catalog(metadata, &catalog).await?;
        Ok(())
    }

    /// Return the exact marker whose ownership was already released, allowing startup and
    /// in-process ambiguous-CAS recovery to finish without relying on marker bytes in the snapshot.
    pub async fn ownership_released_import(
        &self,
        context: DepositSyncContext,
    ) -> Result<Option<DepositSyncImportMarker>, DepositSyncStageError> {
        if context.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let ordinary = catalog.active.as_ref().and_then(|active| match active.state {
            DepositSyncSpoolActiveState::OwnershipReleased { marker } => Some(marker),
            _ => None,
        });
        let certified_export =
            catalog.certified_export.as_ref().and_then(|active| match active.state {
                DepositStateExportSpoolActiveState::OwnershipReleased { marker } => Some(marker),
                _ => None,
            });
        match (ordinary, certified_export) {
            (Some(_), Some(_)) => Err(DepositSyncStageError::InvalidSnapshot),
            (Some(marker), None) | (None, Some(marker)) => Ok(Some(marker)),
            (None, None) => Ok(None),
        }
    }

    /// Journal that the authoritative snapshot marker was cleared, then finish cleanup from that
    /// durable intent. This requires the preceding ownership-release state.
    pub async fn complete_prepared_import(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<(), DepositSyncStageError> {
        marker.validate_for(marker.wallet())?;
        if marker.network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(marker.binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) =
            catalog.certified_export.as_ref().filter(|active| active.binding == marker.binding)
        {
            if matches!(
                active.state,
                DepositStateExportSpoolActiveState::Deleting { prepared: true }
            ) {
                return Ok(());
            }
            if active.state
                != (DepositStateExportSpoolActiveState::OwnershipReleased { marker: *marker })
            {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            let spool = self.open_cached_binding(marker.binding).await?;
            let _ = spool.initialize().await?;
            if spool.import_marker().await? != *marker {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            commit_certified_export_import(&mut catalog, marker)?;
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            return self.recover_catalog_deletions(&mut metadata, &mut catalog).await;
        }
        let Some(active) = catalog.active.as_mut() else {
            if !spool_namespace(&self.directory, marker.binding).exists() {
                return Ok(());
            }
            return Err(DepositSyncStageError::UnknownAnchor);
        };
        if active.binding == marker.binding
            && matches!(active.state, DepositSyncSpoolActiveState::Deleting { prepared: true })
        {
            return Ok(());
        }
        if active.binding != marker.binding
            || active.state != (DepositSyncSpoolActiveState::OwnershipReleased { marker: *marker })
        {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        let spool = self.open_cached_binding(marker.binding).await?;
        let _ = spool.initialize().await?;
        if spool.import_marker().await? != *marker {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        active.state = DepositSyncSpoolActiveState::Committed { marker: *marker };
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await
    }

    /// Permanently discard one exact candidate with restart-safe page-at-a-time deletion.
    pub async fn discard(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositSyncStageError> {
        let binding = spool_binding(advertisement)?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if catalog.active.as_ref().is_some_and(|active| active.binding == binding)
            && spool_namespace(&self.directory, binding).exists()
        {
            let phase = self.open_cached_binding(binding).await?.checkpoint().await?.phase();
            if matches!(
                phase,
                DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
            ) {
                return Err(DepositSyncStageError::PreparedImportDispositionRequired);
            }
        }
        let mut changed = false;
        if let Some(attempt) =
            catalog.prefix_attempt.as_mut().filter(|attempt| attempt.binding == binding)
        {
            let evidence = match &attempt.state {
                DepositSyncPrefixAttemptState::Promoting(evidence) => Some(evidence.clone()),
                DepositSyncPrefixAttemptState::Deleting(evidence) => evidence.clone(),
                DepositSyncPrefixAttemptState::Installing
                | DepositSyncPrefixAttemptState::Collecting => None,
            };
            attempt.claim.state = DepositSyncSpoolClaimState::Deleting;
            attempt.state = DepositSyncPrefixAttemptState::Deleting(evidence);
            changed = true;
        }
        for claim in catalog.claims.values_mut() {
            if claim.binding == binding {
                claim.state = DepositSyncSpoolClaimState::Deleting;
                changed = true;
            }
        }
        if catalog.active.as_ref().is_some_and(|active| active.binding == binding) {
            catalog.active.as_mut().expect("active checked").state =
                DepositSyncSpoolActiveState::Deleting { prepared: false };
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        } else if changed {
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        }
        Ok(())
    }

    /// Abandon the selected journal-before-head cut behind its authenticated catalog position.
    ///
    /// No release is invented when the exact response lease was never durable. Competing source
    /// intents remain available immediately after the fenced namespace deletion and catalog CAS.
    pub(crate) async fn fail_installing_certified_export_source(
        &self,
        checkpoint: InstallingCertifiedExportCheckpoint,
    ) -> Result<(), DepositSyncStageError> {
        let context = checkpoint.context;
        if context.network() != self.network_id
            || checkpoint.source.0 == 0
            || checkpoint.source == self.party
            || checkpoint.request_digest == [0; 32]
            || checkpoint.catalog_snapshot_hash == [0; 32]
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let durable_metadata = metadata.ok_or(DepositSyncStageError::MissingReadback)?;
        let active = catalog.certified_export.ok_or(DepositSyncStageError::UnknownAnchor)?;
        let selected = catalog
            .certified_export_intents
            .get(&checkpoint.source)
            .filter(|intent| certified_export_intent_matches_active(intent, active))
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        if durable_metadata.revision != checkpoint.catalog_revision
            || durable_metadata.snapshot_hash != checkpoint.catalog_snapshot_hash
            || active.context != context
            || active.source != checkpoint.source
            || active.request_digest != checkpoint.request_digest
            || selected.request_digest != checkpoint.request_digest
            || active.state != DepositStateExportSpoolActiveState::Installing
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }

        // A durable response would have been promoted to `Active` by recovery above and must take
        // the lease-aware failure path. With no readable response there is no exact release
        // request to manufacture. Delete the empty/partial candidate namespace first; a crash
        // leaves the still-durable Installing record retryable. Only then clear the selected lane
        // by catalog CAS/readback, retaining every competing source intent.
        self.delete_candidate_namespace(active.binding, false).await?;
        catalog.certified_export_intents.remove(&checkpoint.source);
        catalog.certified_export = None;
        let _ = self.persist_catalog(Some(durable_metadata), &catalog).await?;
        Ok(())
    }

    /// Release and delete one failed certified-export source behind an exact checkpoint fence.
    ///
    /// Once cleanup commits, a fresh certified intent from another predecessor can be admitted;
    /// the failed source's exact lease release remains independently retryable until its ACK.
    pub async fn fail_certified_export_source(
        &self,
        context: DepositStateTransferContext,
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), DepositSyncStageError> {
        if context.network() != self.network_id
            || source.0 == 0
            || source == self.party
            || expected_digest == [0; 32]
        {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key =
            DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
        key.validate()?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let active = catalog.certified_export.ok_or(DepositSyncStageError::UnknownAnchor)?;
        if active.context != context
            || active.source != source
            || active.state != DepositStateExportSpoolActiveState::Active
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let spool = self.open_cached_binding(active.binding).await?;
        let checkpoint = spool.checkpoint().await?;
        if matches!(
            checkpoint.phase(),
            DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
        ) || checkpoint.revision() != expected_revision
            || checkpoint.digest()? != expected_digest
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let selected = catalog
            .certified_export_intents
            .remove(&source)
            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
        if !certified_export_intent_matches_active(&selected, active) {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        catalog.certified_export.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
            DepositStateExportSpoolActiveState::Deleting { prepared: false };
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await
    }

    /// Fail the currently pinned source with an exact optimistic checkpoint guard.
    ///
    /// The source-bound frontier is reset before the durable pin is released. A different
    /// supporter can then select its own exact variant; no caller can reset a newer frontier.
    pub async fn fail_download_source(
        &self,
        advertisement: &DepositSyncAdvertisement,
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), DepositSyncStageError> {
        self.fail_download_source_with_prefix_class(
            advertisement,
            source,
            expected_revision,
            expected_digest,
            DepositSyncPrefixFailureClass::Transient,
        )
        .await
    }

    async fn fail_download_source_with_prefix_class(
        &self,
        advertisement: &DepositSyncAdvertisement,
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
        prefix_class: DepositSyncPrefixFailureClass,
    ) -> Result<(), DepositSyncStageError> {
        validate_source(source)?;
        let binding = spool_binding(advertisement)?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if let Some(active) = catalog.active.as_ref()
            && let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority
        {
            if active.binding != binding
                || active.state != DepositSyncSpoolActiveState::Active
                || active.pinned_source != Some(source)
                || evidence.source != source
                || !self.prefix_is_authorized(binding.anchor, evidence).await
            {
                return Err(DepositSyncStageError::AdmissionEvidenceRequired);
            }
            let policy = active.policy;
            let facts = active.facts;
            let spool = self.open_cached_binding(binding).await?;
            let checkpoint = spool.checkpoint().await?;
            if checkpoint.phase() == DepositSyncSpoolPhase::Deleting
                || matches!(
                    checkpoint.phase(),
                    DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
                )
                || checkpoint.revision() != expected_revision
                || checkpoint.digest()? != expected_digest
            {
                return Err(DepositSyncStageError::InvalidSpoolTransition);
            }
            record_prefix_source_failure(
                &mut catalog,
                source,
                binding,
                policy,
                facts,
                prefix_class,
            )?;
            catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                DepositSyncSpoolActiveState::Deleting { prepared: false };
            metadata = Some(self.persist_catalog(metadata, &catalog).await?);
            return self.recover_catalog_deletions(&mut metadata, &mut catalog).await;
        }
        let failure_round = {
            let active = catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
            if active.binding != binding
                || active.state != DepositSyncSpoolActiveState::Active
                || active.pinned_source != Some(source)
                || !active.certified_claims.contains_key(&source)
                || active.authority != DepositSyncSpoolAuthority::ExactClaims
            {
                return Err(DepositSyncStageError::InvalidSpoolTransition);
            }
            let round = active.source_failure_round;
            active.state =
                DepositSyncSpoolActiveState::Failing { source, expected_revision, expected_digest };
            round
        };
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        if catalog.active.as_ref().is_some_and(|active| {
            active.source_failure_round == failure_round
                && active.state == DepositSyncSpoolActiveState::Admitting
                && active.pinned_source.is_none()
        }) {
            let _ = self.activate_next_stored_claim(&mut metadata, &mut catalog).await?;
        }
        Ok(())
    }

    /// Permanently reject one exact terminal-invalid source variant and activate a frozen alternate.
    ///
    /// Callers may use this only after cryptographic or semantic verification fails. Transient I/O
    /// and local snapshot-CAS races must retain the candidate and retry through their own paths.
    pub async fn reject_exact_variant(
        &self,
        advertisement: &DepositSyncAdvertisement,
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
        rejection: DepositSyncVariantRejection,
    ) -> Result<(), DepositSyncStageError> {
        validate_source(source)?;
        let binding = spool_binding(advertisement)?;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        {
            let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
            if active.binding != binding
                || active.state != DepositSyncSpoolActiveState::Active
                || active.pinned_source != Some(source)
                || !active.certified_claims.contains_key(&source)
                || active.authority != DepositSyncSpoolAuthority::ExactClaims
            {
                return Err(DepositSyncStageError::InvalidSpoolTransition);
            }
        }
        let spool = self.open_cached_binding(binding).await?;
        let checkpoint = spool.checkpoint().await?;
        if checkpoint.phase() == DepositSyncSpoolPhase::Deleting
            || checkpoint.revision() != expected_revision
            || checkpoint.digest()? != expected_digest
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let post_abort = if matches!(
            checkpoint.phase(),
            DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
        ) {
            let successor = checkpoint
                .successor(DepositSyncSpoolPhase::Verified, checkpoint.cursor().to_vec())?;
            Some(DepositSyncCheckpointIdentity {
                revision: successor.revision(),
                digest: successor.digest()?,
            })
        } else {
            None
        };
        catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
            DepositSyncSpoolActiveState::Rejecting {
                source,
                expected_revision,
                expected_digest,
                post_abort,
                rejection,
            };
        metadata = Some(self.persist_catalog(metadata, &catalog).await?);
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let _ = self.activate_next_stored_claim(&mut metadata, &mut catalog).await?;
        Ok(())
    }

    /// Permanently reject a prefix-certified candidate.
    ///
    /// Unlike exact-family rejection, prefix endorsers are not serving failover leases. The whole
    /// candidate is deleted and only its one lease-backed `source` is queued for release.
    pub async fn reject_prefix_variant(
        &self,
        advertisement: &DepositSyncAdvertisement,
        source: PartyId,
        expected_revision: u64,
        expected_digest: [u8; 32],
        _rejection: DepositSyncVariantRejection,
    ) -> Result<(), DepositSyncStageError> {
        validate_source(source)?;
        let binding = spool_binding(advertisement)?;
        {
            let _catalog_mutation = self.catalog_mutation.lock().await;
            let (mut metadata, mut catalog) = self.load_catalog(binding.key).await?;
            self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
            let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
            let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority else {
                return Err(DepositSyncStageError::InvalidAdmissionEvidence);
            };
            if active.binding != binding
                || active.state != DepositSyncSpoolActiveState::Active
                || active.pinned_source != Some(source)
                || evidence.source != source
            {
                return Err(DepositSyncStageError::InvalidSpoolTransition);
            }
        }
        self.fail_download_source_with_prefix_class(
            advertisement,
            source,
            expected_revision,
            expected_digest,
            DepositSyncPrefixFailureClass::Permanent,
        )
        .await
    }

    /// Remove every catalogued candidate which can no longer succeed against local authority.
    pub async fn discard_stale_against(
        &self,
        local: &DepositSyncAdvertisement,
    ) -> Result<usize, DepositSyncStageError> {
        if local.context().network() != self.network_id {
            return Err(DepositSyncStageError::WrongContext);
        }
        let key = spool_binding(local)?.key;
        let _catalog_mutation = self.catalog_mutation.lock().await;
        let (mut metadata, mut catalog) = self.load_catalog(key).await?;
        self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
        let local_facts = DepositSyncCandidateFacts::from_advertisement(local)?;
        let mut stale_supports = catalog
            .claims
            .values()
            .filter_map(|claim| {
                candidate_facts_are_stale(claim.facts, local_facts).then_some(claim.facts.support)
            })
            .collect::<BTreeSet<_>>();
        if let Some(attempt) = catalog.prefix_attempt.as_ref()
            && candidate_facts_are_stale(attempt.facts, local_facts)
        {
            stale_supports.insert(attempt.facts.support);
        }
        if let Some(active) = catalog.active.as_ref()
            && candidate_facts_are_stale(active.facts, local_facts)
        {
            stale_supports.insert(active.support);
        }
        if let Some(active) =
            catalog.active.as_ref().filter(|active| stale_supports.contains(&active.support))
            && spool_namespace(&self.directory, active.binding).exists()
        {
            let phase = self.open_cached_binding(active.binding).await?.checkpoint().await?.phase();
            if matches!(
                phase,
                DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
            ) {
                return Err(DepositSyncStageError::PreparedImportDispositionRequired);
            }
        }
        let prior_prefix_failures = catalog.prefix_source_failures.len();
        catalog
            .prefix_source_failures
            .retain(|_, failure| !candidate_facts_are_stale(failure.facts, local_facts));
        let prefix_failures_changed = catalog.prefix_source_failures.len() != prior_prefix_failures;
        let removed = stale_supports.len();
        if removed != 0 {
            if let Some(attempt) = catalog
                .prefix_attempt
                .as_mut()
                .filter(|attempt| stale_supports.contains(&attempt.facts.support))
            {
                let evidence = match &attempt.state {
                    DepositSyncPrefixAttemptState::Promoting(evidence) => Some(evidence.clone()),
                    DepositSyncPrefixAttemptState::Deleting(evidence) => evidence.clone(),
                    DepositSyncPrefixAttemptState::Installing
                    | DepositSyncPrefixAttemptState::Collecting => None,
                };
                attempt.claim.state = DepositSyncSpoolClaimState::Deleting;
                attempt.state = DepositSyncPrefixAttemptState::Deleting(evidence);
            }
            for claim in catalog.claims.values_mut() {
                if stale_supports.contains(&claim.facts.support) {
                    claim.state = DepositSyncSpoolClaimState::Deleting;
                }
            }
            if catalog
                .active
                .as_ref()
                .is_some_and(|active| stale_supports.contains(&active.support))
            {
                catalog.active.as_mut().expect("active checked").state =
                    DepositSyncSpoolActiveState::Deleting { prepared: false };
                metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
            } else {
                metadata = Some(self.persist_catalog(metadata, &catalog).await?);
                self.recover_catalog_deletions(&mut metadata, &mut catalog).await?;
            }
        } else if prefix_failures_changed {
            let _ = self.persist_catalog(metadata, &catalog).await?;
        }
        Ok(removed)
    }

    async fn install_claim_response(
        &self,
        mut metadata: Option<DepositSyncSpoolHeadMetadata>,
        catalog: &mut DepositSyncSpoolCatalog,
        source: PartyId,
        response: &DepositSyncHeadResponse,
        binding: DepositSyncSpoolBinding,
        policy: DepositSyncSpoolAdmissionPolicy,
        facts: DepositSyncCandidateFacts,
    ) -> Result<DepositSyncSpoolHeadMetadata, DepositSyncStageError> {
        let envelope =
            DepositSyncSpoolHeadResponseEnvelope::from_response(binding, response, self.party)?;
        if envelope.source() != source {
            return Err(DepositSyncStageError::InvalidSource);
        }
        let bytes = envelope.to_bytes()?;
        let reference = WalletArtifactRef::for_contents(
            WalletId(binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT,
            &bytes,
        )?;
        if let Some(existing) = catalog.claims.get(&source)
            && existing.state == DepositSyncSpoolClaimState::Ready
            && existing.binding == binding
            && existing.policy == policy
            && existing.facts == facts
            && existing.lease == response.lease()
            && existing.response.reference == reference
        {
            self.verify_claim_response(source, existing).await?;
            return metadata.ok_or(DepositSyncStageError::MissingReadback);
        }

        if let Some(existing) = catalog.claims.get(&source).copied() {
            self.verify_claim_response(source, &existing).await?;
            if self.claim_artifact_is_certified(catalog, existing.response) {
                return Err(DepositSyncStageError::SourceLeaseBusy(source));
            }
            self.enqueue_release(catalog, existing.lease)?;
            catalog.claims.get_mut(&source).ok_or(DepositSyncStageError::InvalidSnapshot)?.state =
                DepositSyncSpoolClaimState::Deleting;
            metadata = Some(self.persist_catalog(metadata, catalog).await?);
            self.recover_catalog_deletions(&mut metadata, catalog).await?;
            return Err(DepositSyncStageError::PendingReleaseRequired(source));
        }

        let response_artifact =
            DepositSyncClaimArtifact { reference, owner: WalletArtifactOwner::random(&mut OsRng) };
        catalog.claims.insert(
            source,
            DepositSyncSpoolClaim {
                binding,
                policy,
                facts,
                lease: response.lease(),
                response: response_artifact,
                state: DepositSyncSpoolClaimState::Installing,
            },
        );
        metadata = Some(self.persist_catalog(metadata, catalog).await?);

        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                response_artifact.owner,
                WalletId(binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT,
                &bytes,
                &mut OsRng,
            )
            .await?;
        if installed != reference {
            return Err(DepositSyncStageError::MissingReadback);
        }
        {
            let claim =
                catalog.claims.get(&source).ok_or(DepositSyncStageError::InvalidSnapshot)?;
            self.verify_claim_response(source, claim).await?;
        }
        catalog.claims.get_mut(&source).ok_or(DepositSyncStageError::InvalidSnapshot)?.state =
            DepositSyncSpoolClaimState::Ready;
        self.persist_catalog(metadata, catalog).await
    }

    async fn load_prefix_attempt_work(
        &self,
        attempt: &DepositSyncPrefixSupportAttempt,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<DepositSyncPrefixSupportWork, DepositSyncStageError> {
        if !matches!(
            attempt.state,
            DepositSyncPrefixAttemptState::Collecting | DepositSyncPrefixAttemptState::Promoting(_)
        ) || attempt.claim.state != DepositSyncSpoolClaimState::Ready
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let response =
            self.verify_claim_response(attempt.claim.lease.source(), &attempt.claim).await?;
        let policy = DepositSyncSpoolAdmissionPolicy::authenticated(
            response.advertisement(),
            target,
            self.party,
        )?;
        let request = DepositSyncHeadRequest::new(
            response.advertisement().context(),
            response.lease().source(),
            self.party,
        )?;
        let statement =
            DepositSyncSupportStatement::from_head_response(request, &response, target)?;
        if policy != attempt.policy
            || spool_binding(response.advertisement())? != attempt.binding
            || DepositSyncCandidateFacts::from_advertisement(response.advertisement())?
                != attempt.facts
            || statement.digest() != attempt.statement_digest
            || statement.source_lease_digest() != attempt.claim.lease.digest()
        {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        Ok(DepositSyncPrefixSupportWork { response, statement })
    }

    async fn verify_prefix_evidence(
        &self,
        binding: DepositSyncSpoolBinding,
        evidence: &DepositSyncPrefixEvidence,
        work: &DepositSyncPrefixSupportWork,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositSyncStageError> {
        validate_prefix_evidence_shape(evidence, target.fault_bound())?;
        let artifact = self
            .artifacts
            .load_artifact_owned(evidence.certificate.reference, evidence.certificate.owner)
            .await?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_PREFIX_CERTIFICATE_ARTIFACT,
            artifact.contents.as_bytes(),
        )?;
        let envelope = DepositSyncPrefixCertificateEnvelope::from_bytes(
            binding,
            artifact.contents.as_bytes(),
        )?;
        if expected != evidence.certificate.reference
            || evidence.source != work.response.lease().source()
            || envelope.source != evidence.source
            || envelope.statement_digest != evidence.statement_digest
            || envelope.certificate_digest != evidence.certificate_digest
            || evidence.statement_digest != work.statement.digest()
        {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        let certificate = DepositSyncSupportCertificate::from_bytes(&envelope.certificate)?;
        let verified = certificate.verify(&work.statement, target)?;
        if verified.statement_digest() != evidence.statement_digest
            || verified.certificate_digest() != evidence.certificate_digest
            || verified.certificate_bytes() != envelope.certificate.as_slice()
            || verified.signers() != evidence.endorsers.as_slice()
            || verified.statement().source() != evidence.source
            || verified.statement().source_lease_digest() != work.response.lease().digest()
        {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        Ok(())
    }

    async fn record_prefix_authorization(
        &self,
        anchor: DepositSyncAnchorId,
        evidence: &DepositSyncPrefixEvidence,
    ) {
        self.prefix_authorizations.lock().await.insert(
            anchor,
            DepositSyncPrefixAuthorization {
                source: evidence.source,
                statement_digest: evidence.statement_digest,
                certificate_digest: evidence.certificate_digest,
            },
        );
    }

    async fn prefix_is_authorized(
        &self,
        anchor: DepositSyncAnchorId,
        evidence: &DepositSyncPrefixEvidence,
    ) -> bool {
        let expected = DepositSyncPrefixAuthorization {
            source: evidence.source,
            statement_digest: evidence.statement_digest,
            certificate_digest: evidence.certificate_digest,
        };
        self.prefix_authorizations.lock().await.get(&anchor).copied() == Some(expected)
    }

    async fn verify_claim_response(
        &self,
        source: PartyId,
        claim: &DepositSyncSpoolClaim,
    ) -> Result<DepositSyncHeadResponse, DepositSyncStageError> {
        let artifact = self
            .artifacts
            .load_artifact_owned(claim.response.reference, claim.response.owner)
            .await?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(claim.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT,
            artifact.contents.as_bytes(),
        )?;
        let envelope = DepositSyncSpoolHeadResponseEnvelope::from_bytes(
            claim.binding,
            artifact.contents.as_bytes(),
        )?;
        if expected != claim.response.reference || envelope.source() != source {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        let response = envelope.decode_response(self.party)?;
        if response.lease().source() != source
            || response.lease().requester() != self.party
            || response.lease() != claim.lease
            || spool_binding(response.advertisement())? != claim.binding
            || DepositSyncCandidateFacts::from_advertisement(response.advertisement())?
                != claim.facts
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        Ok(response)
    }

    fn mark_support_claims_deleting(
        &self,
        catalog: &mut DepositSyncSpoolCatalog,
        support: DepositSyncSupportId,
    ) {
        for claim in catalog.claims.values_mut() {
            if claim.facts.support == support {
                claim.state = DepositSyncSpoolClaimState::Deleting;
            }
        }
    }

    fn claim_artifact_is_certified(
        &self,
        catalog: &DepositSyncSpoolCatalog,
        artifact: DepositSyncClaimArtifact,
    ) -> bool {
        catalog.active.as_ref().is_some_and(|active| {
            active.certified_claims.values().any(|certified| certified.response == artifact)
        })
    }

    fn enqueue_release(
        &self,
        catalog: &mut DepositSyncSpoolCatalog,
        lease: DepositSyncAnchorLease,
    ) -> Result<bool, DepositSyncStageError> {
        if lease.context().network() != catalog.key.network_id
            || lease.context().wallet() != catalog.key.wallet_id
            || lease.requester() != self.party
            || lease.source().0 == 0
            || lease.source() == self.party
            || lease.advertisement_digest() == [0; 32]
            || lease.digest() == [0; 32]
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let request = DepositSyncReleaseRequest::new(lease)?;
        let key = DepositSyncPendingReleaseKey::Ordinary(request.source());
        match catalog.pending_releases.get(&key) {
            Some(DepositSyncPendingRelease::Ordinary { request: existing, .. })
                if *existing == request =>
            {
                Ok(false)
            }
            Some(_) => Err(DepositSyncStageError::ReleaseConflict),
            None => {
                catalog.pending_releases.insert(
                    key,
                    DepositSyncPendingRelease::Ordinary { request, acknowledged: false },
                );
                Ok(true)
            }
        }
    }

    fn enqueue_export_release(
        &self,
        catalog: &mut DepositSyncSpoolCatalog,
        lease: DepositStateExportLease,
    ) -> Result<bool, DepositSyncStageError> {
        if lease.context().network() != catalog.key.network_id
            || lease.context().wallet() != catalog.key.wallet_id
            || lease.requester() != self.party
            || lease.source().0 == 0
            || lease.source() == self.party
            || lease.advertisement_digest() == [0; 32]
            || lease.digest() == [0; 32]
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        let request = DepositStateExportReleaseRequest::new(lease)?;
        let key = DepositSyncPendingReleaseKey::CertifiedExport {
            source: lease.source(),
            request_digest: request.digest(),
        };
        match catalog.pending_releases.get(&key) {
            Some(DepositSyncPendingRelease::CertifiedExport { request: existing, .. })
                if *existing == request =>
            {
                Ok(false)
            }
            Some(_) => Err(DepositSyncStageError::ReleaseConflict),
            None => {
                catalog.pending_releases.insert(
                    key,
                    DepositSyncPendingRelease::CertifiedExport { request, acknowledged: false },
                );
                Ok(true)
            }
        }
    }

    async fn reconcile_catalog_for_target(
        &self,
        catalog: &mut DepositSyncSpoolCatalog,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<bool, DepositSyncStageError> {
        let target_epoch = target.committee().epoch;
        let target_digest = target.committee().digest();
        if let Some(active) = catalog.active.as_ref()
            && (active.policy.active_epoch != target_epoch
                || active.policy.committee_digest != target_digest)
            && spool_namespace(&self.directory, active.binding).exists()
        {
            let phase = self.open_cached_binding(active.binding).await?.checkpoint().await?.phase();
            if matches!(
                phase,
                DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
            ) {
                return Err(DepositSyncStageError::PreparedImportDispositionRequired);
            }
        }

        let mut changed = false;
        let prior_failures = catalog.prefix_source_failures.len();
        catalog.prefix_source_failures.retain(|_, failure| {
            failure.active_epoch == target_epoch
                && failure.committee_digest == target_digest
                && target.committee().member(failure.source).is_ok()
        });
        changed |= catalog.prefix_source_failures.len() != prior_failures;
        if let Some(attempt) = catalog.prefix_attempt.as_mut()
            && (attempt.policy.active_epoch != target_epoch
                || attempt.policy.committee_digest != target_digest
                || target.committee().member(attempt.claim.lease.source()).is_err())
        {
            let evidence = match &attempt.state {
                DepositSyncPrefixAttemptState::Promoting(evidence) => Some(evidence.clone()),
                DepositSyncPrefixAttemptState::Deleting(evidence) => evidence.clone(),
                DepositSyncPrefixAttemptState::Installing
                | DepositSyncPrefixAttemptState::Collecting => None,
            };
            attempt.claim.state = DepositSyncSpoolClaimState::Deleting;
            attempt.state = DepositSyncPrefixAttemptState::Deleting(evidence);
            changed = true;
        }

        let stale_claims = catalog
            .claims
            .iter()
            .filter_map(|(source, claim)| {
                (claim.policy.active_epoch != target_epoch
                    || claim.policy.committee_digest != target_digest
                    || target.committee().member(*source).is_err())
                .then_some((*source, claim.lease))
            })
            .collect::<Vec<_>>();
        for (source, lease) in stale_claims {
            self.enqueue_release(catalog, lease)?;
            catalog.claims.get_mut(&source).ok_or(DepositSyncStageError::InvalidSnapshot)?.state =
                DepositSyncSpoolClaimState::Deleting;
            changed = true;
        }

        let stale_active = catalog.active.as_ref().is_some_and(|active| {
            active.policy.active_epoch != target_epoch
                || active.policy.committee_digest != target_digest
        });
        if stale_active {
            let certified = catalog
                .active
                .as_ref()
                .ok_or(DepositSyncStageError::UnknownAnchor)?
                .certified_claims
                .values()
                .map(|claim| claim.lease)
                .collect::<Vec<_>>();
            for lease in certified {
                self.enqueue_release(catalog, lease)?;
            }
            catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                DepositSyncSpoolActiveState::Deleting { prepared: false };
            changed = true;
        }
        Ok(changed)
    }

    async fn load_catalog(
        &self,
        key: DepositSyncSpoolHeadKey,
    ) -> Result<
        (Option<DepositSyncSpoolHeadMetadata>, DepositSyncSpoolCatalog),
        DepositSyncStageError,
    > {
        let Some(blob) = self.catalog_protocol.load_deposit_sync_spool_head(key).await? else {
            return Ok((
                None,
                DepositSyncSpoolCatalog {
                    version: DEPOSIT_SYNC_SPOOL_CATALOG_VERSION,
                    key,
                    sampling_round: 0,
                    claims: BTreeMap::new(),
                    pending_releases: BTreeMap::new(),
                    prefix_source_failures: BTreeMap::new(),
                    prefix_attempt: None,
                    active: None,
                    certified_export_intents: BTreeMap::new(),
                    certified_export: None,
                },
            ));
        };
        let catalog: DepositSyncSpoolCatalog = decode_canonical(
            blob.state.as_bytes(),
            MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
            "deposit sync spool catalog",
        )?;
        self.validate_catalog(&catalog, key)?;
        Ok((Some(blob.metadata), catalog))
    }

    async fn persist_catalog(
        &self,
        expected: Option<DepositSyncSpoolHeadMetadata>,
        catalog: &DepositSyncSpoolCatalog,
    ) -> Result<DepositSyncSpoolHeadMetadata, DepositSyncStageError> {
        self.validate_catalog(catalog, catalog.key)?;
        let encoded = encode_canonical(
            catalog,
            MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
            "deposit sync spool catalog",
        )?;
        let metadata = self
            .catalog_protocol
            .save_deposit_sync_spool_head(catalog.key, expected, &encoded, &mut OsRng)
            .await?;
        let durable = self
            .catalog_protocol
            .load_deposit_sync_spool_head(catalog.key)
            .await?
            .ok_or(DepositSyncStageError::MissingReadback)?;
        if durable.metadata != metadata || durable.state.as_bytes() != encoded {
            return Err(DepositSyncStageError::MissingReadback);
        }
        Ok(metadata)
    }

    fn validate_catalog(
        &self,
        catalog: &DepositSyncSpoolCatalog,
        key: DepositSyncSpoolHeadKey,
    ) -> Result<(), DepositSyncStageError> {
        if catalog.version != DEPOSIT_SYNC_SPOOL_CATALOG_VERSION
            || catalog.key != key
            || key.network_id != self.network_id
            || catalog.claims.len() > MAX_DEPOSIT_SYNC_STAGE_CANDIDATES
            || catalog.pending_releases.len() > MAX_DEPOSIT_SYNC_STAGE_CANDIDATES.saturating_mul(2)
            || catalog.prefix_source_failures.len() > MAX_DEPOSIT_SYNC_STAGE_CANDIDATES
            || catalog.certified_export_intents.len() > MAX_COMMITTEE_MEMBERS
            || catalog
                .claims
                .len()
                .checked_add(usize::from(catalog.prefix_attempt.is_some()))
                .is_none_or(|claims| claims > MAX_DEPOSIT_SYNC_STAGE_CANDIDATES)
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        for (release_key, pending) in &catalog.pending_releases {
            match (release_key, pending) {
                (
                    DepositSyncPendingReleaseKey::Ordinary(source),
                    DepositSyncPendingRelease::Ordinary { request, .. },
                ) => {
                    let lease = request.lease();
                    if *source != request.source()
                        || *source == self.party
                        || request.requester() != self.party
                        || request.context().network() != key.network_id
                        || request.context().wallet() != key.wallet_id
                        || lease.advertisement_digest() == [0; 32]
                        || request.digest() == [0; 32]
                    {
                        return Err(DepositSyncStageError::InvalidSnapshot);
                    }
                }
                (
                    DepositSyncPendingReleaseKey::CertifiedExport { source, request_digest },
                    DepositSyncPendingRelease::CertifiedExport { request, .. },
                ) => {
                    request.to_bytes()?;
                    let lease = request.lease();
                    if *source != lease.source()
                        || *request_digest != request.digest()
                        || *source == self.party
                        || lease.requester() != self.party
                        || lease.context().network() != key.network_id
                        || lease.context().wallet() != key.wallet_id
                        || lease.advertisement_digest() == [0; 32]
                        || request.digest() == [0; 32]
                    {
                        return Err(DepositSyncStageError::InvalidSnapshot);
                    }
                }
                _ => return Err(DepositSyncStageError::InvalidSnapshot),
            }
        }
        let mut intent_binding = None;
        for (source, intent) in &catalog.certified_export_intents {
            validate_certified_export_intent(intent)?;
            let binding = (intent.context, intent.target_binding, intent.semantic_transition);
            if *source != intent.source
                || intent.requester != self.party
                || intent.context.network() != key.network_id
                || intent.context.wallet() != key.wallet_id
                || intent_binding.is_some_and(|expected| expected != binding)
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
            intent_binding = Some(binding);
        }
        if !catalog.certified_export_intents.is_empty()
            && (catalog.active.is_some()
                || catalog.prefix_attempt.is_some()
                || !catalog.claims.is_empty())
        {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        for (source, failure) in &catalog.prefix_source_failures {
            if *source != failure.source
                || *source == self.party
                || validate_source(*source).is_err()
                || failure.anchor.0 == [0; 32]
                || failure.committee_digest == [0; 32]
                || failure.facts.support.0 == [0; 32]
                || failure.strikes == 0
                || failure.last_failure_round > catalog.sampling_round
                || if failure.permanent {
                    failure.retry_after_round != u64::MAX
                } else {
                    failure
                        .last_failure_round
                        .checked_add(DEPOSIT_SYNC_PREFIX_TRANSIENT_COOLDOWN_ROUNDS)
                        .and_then(|round| round.checked_add(1))
                        != Some(failure.retry_after_round)
                }
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        for (source, claim) in &catalog.claims {
            if validate_source(*source).is_err()
                || *source == self.party
                || claim.binding.key != key
                || claim.binding.admission != DepositSyncSpoolAdmissionKind::Ordinary
                || claim.binding.maximum_objects != claim.policy.maximum_objects
                || claim.facts.support != claim.policy.support
                || claim.policy.computed_digest() != claim.policy.policy_digest
                || claim.policy.version != DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_VERSION
                || claim.policy.required_supporters != claim.policy.fault_bound.saturating_add(1)
                || Some(claim.policy.sampling_sources)
                    != claim
                        .policy
                        .committee_size
                        .checked_sub(claim.policy.fault_bound)
                        .and_then(|members| members.checked_sub(1))
                || claim.policy.required_supporters == 0
                || claim.policy.required_supporters > claim.policy.committee_size
                || claim.policy.maximum_objects == 0
                || claim.lease.source() != *source
                || claim.lease.requester() != self.party
                || claim.lease.context().network() != key.network_id
                || claim.lease.context().wallet() != key.wallet_id
                || claim.lease.advertisement_digest() != claim.binding.candidate_root
                || claim.response.reference.wallet_id() != WalletId(key.wallet_id.0)
                || claim.response.reference.kind() != DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT
                || claim.response.reference.plaintext_len() == 0
                || claim.response.reference.plaintext_len() > MAX_WALLET_ARTIFACT_BYTES as u64
                || claim.response.owner.validate().is_err()
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        if let Some(maximum_claims) =
            catalog.claims.values().map(|claim| claim.policy.committee_size).max()
            && catalog.claims.len() > usize::from(maximum_claims)
        {
            return Err(DepositSyncStageError::CandidateQuota);
        }
        if let Some(attempt) = &catalog.prefix_attempt {
            let source = attempt.claim.lease.source();
            let claim = &attempt.claim;
            if catalog.active.is_some()
                || validate_source(source).is_err()
                || source == self.party
                || catalog.claims.contains_key(&source)
                || attempt.binding.key != key
                || attempt.binding.admission != DepositSyncSpoolAdmissionKind::Ordinary
                || attempt.binding != claim.binding
                || attempt.policy != claim.policy
                || attempt.facts != claim.facts
                || attempt.statement_digest == [0; 32]
                || attempt.policy.computed_digest() != attempt.policy.policy_digest
                || attempt.policy.version != DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_VERSION
                || attempt.policy.required_supporters
                    != attempt.policy.fault_bound.saturating_add(1)
                || Some(attempt.policy.sampling_sources)
                    != attempt
                        .policy
                        .committee_size
                        .checked_sub(attempt.policy.fault_bound)
                        .and_then(|members| members.checked_sub(1))
                || attempt.binding.maximum_objects != attempt.policy.maximum_objects
                || attempt.facts.support != attempt.policy.support
                || claim.lease.requester() != self.party
                || claim.lease.context().network() != key.network_id
                || claim.lease.context().wallet() != key.wallet_id
                || claim.lease.advertisement_digest() != attempt.binding.candidate_root
                || claim.response.reference.wallet_id() != WalletId(key.wallet_id.0)
                || claim.response.reference.kind() != DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT
                || claim.response.reference.plaintext_len() == 0
                || claim.response.reference.plaintext_len() > MAX_WALLET_ARTIFACT_BYTES as u64
                || claim.response.owner.validate().is_err()
                || match &attempt.state {
                    DepositSyncPrefixAttemptState::Installing => {
                        claim.state != DepositSyncSpoolClaimState::Installing
                    }
                    DepositSyncPrefixAttemptState::Collecting => {
                        claim.state != DepositSyncSpoolClaimState::Ready
                    }
                    DepositSyncPrefixAttemptState::Promoting(evidence) => {
                        claim.state != DepositSyncSpoolClaimState::Ready
                            || evidence.source != source
                            || evidence.certificate.reference.wallet_id()
                                != WalletId(key.wallet_id.0)
                            || validate_prefix_evidence_shape(evidence, attempt.policy.fault_bound)
                                .is_err()
                    }
                    DepositSyncPrefixAttemptState::Deleting(evidence) => {
                        claim.state != DepositSyncSpoolClaimState::Deleting
                            || evidence.as_ref().is_some_and(|evidence| {
                                evidence.source != source
                                    || evidence.certificate.reference.wallet_id()
                                        != WalletId(key.wallet_id.0)
                                    || validate_prefix_evidence_shape(
                                        evidence,
                                        attempt.policy.fault_bound,
                                    )
                                    .is_err()
                            })
                    }
                }
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        if let Some(active) = &catalog.active {
            let deleting = matches!(active.state, DepositSyncSpoolActiveState::Deleting { .. });
            let authority_shape_invalid = match &active.authority {
                DepositSyncSpoolAuthority::ExactClaims => {
                    !deleting
                        && active.certified_claims.len()
                            < usize::from(active.policy.required_supporters)
                }
                DepositSyncSpoolAuthority::Prefix(evidence) => {
                    validate_prefix_evidence_shape(evidence, active.policy.fault_bound).is_err()
                        || evidence.certificate.reference.wallet_id() != WalletId(key.wallet_id.0)
                        || (!deleting
                            && (active.certified_claims.len() != 1
                                || active.pinned_source != Some(evidence.source)
                                || !active.certified_claims.contains_key(&evidence.source)
                                || !active.failed_variants.is_empty()
                                || !active.rejected_variants.is_empty()))
                }
            };
            if active.binding.key != key
                || active.binding.admission != DepositSyncSpoolAdmissionKind::Ordinary
                || active.support != active.policy.support
                || active.binding.maximum_objects != active.policy.maximum_objects
                || active.policy.version != DEPOSIT_SYNC_SPOOL_ADMISSION_POLICY_VERSION
                || active.policy.computed_digest() != active.policy.policy_digest
                || active.policy.required_supporters != active.policy.fault_bound.saturating_add(1)
                || Some(active.policy.sampling_sources)
                    != active
                        .policy
                        .committee_size
                        .checked_sub(active.policy.fault_bound)
                        .and_then(|members| members.checked_sub(1))
                || active.policy.maximum_objects == 0
                || active.facts.support != active.support
                || authority_shape_invalid
                || active.certified_claims.len() > usize::from(active.policy.committee_size)
                || active.certified_claims.iter().any(|(source, claim)| {
                    validate_source(*source).is_err()
                        || *source == self.party
                        || claim.binding.key != key
                        || claim.binding.maximum_objects != active.policy.maximum_objects
                        || claim.lease.source() != *source
                        || claim.lease.requester() != self.party
                        || claim.lease.context().network() != key.network_id
                        || claim.lease.context().wallet() != key.wallet_id
                        || claim.lease.advertisement_digest() != claim.binding.candidate_root
                        || claim.response.reference.wallet_id() != WalletId(key.wallet_id.0)
                        || claim.response.reference.kind()
                            != DEPOSIT_SYNC_SPOOL_CLAIM_RESPONSE_ARTIFACT
                        || claim.response.reference.plaintext_len() == 0
                        || claim.response.reference.plaintext_len()
                            > MAX_WALLET_ARTIFACT_BYTES as u64
                        || claim.response.owner.validate().is_err()
                })
                || (!deleting && active.failed_variants.len() > active.certified_claims.len())
                || active.failed_variants.iter().any(|failure| {
                    (!deleting && !active.certified_claims.contains_key(&failure.source))
                        || failure.anchor.0 == [0; 32]
                })
                || (!deleting && active.rejected_variants.len() > active.certified_claims.len())
                || active.rejected_variants.iter().any(|rejection| {
                    (!deleting && !active.certified_claims.contains_key(&rejection.source))
                        || rejection.anchor.0 == [0; 32]
                })
                || (!deleting
                    && active.pinned_source.is_some_and(|source| {
                        !active.certified_claims.contains_key(&source)
                            || source_unavailable(active, source)
                    }))
                || matches!(
                    active.state,
                    DepositSyncSpoolActiveState::Switching { previous }
                        if previous.key != key || previous == active.binding
                )
                || matches!(
                    active.state,
                    DepositSyncSpoolActiveState::Failing {
                        source,
                        expected_digest,
                        ..
                    } if active.pinned_source != Some(source)
                        || !active.certified_claims.contains_key(&source)
                        || expected_digest == [0; 32]
                )
                || matches!(
                    active.state,
                    DepositSyncSpoolActiveState::Rejecting {
                        source,
                        expected_revision,
                        expected_digest,
                        post_abort,
                        ..
                    } if active.pinned_source != Some(source)
                        || !active.certified_claims.contains_key(&source)
                        || expected_digest == [0; 32]
                        || post_abort.is_some_and(|identity| {
                            identity.digest == [0; 32]
                                || expected_revision.checked_add(1) != Some(identity.revision)
                        })
                )
                || matches!(
                    active.state,
                    DepositSyncSpoolActiveState::ReleasingOwnership { marker }
                        | DepositSyncSpoolActiveState::OwnershipReleased { marker }
                        | DepositSyncSpoolActiveState::Committed { marker }
                    if marker.binding != active.binding
                        || marker.validate_for(key.wallet_id).is_err()
                )
                || matches!(
                    active.state,
                    DepositSyncSpoolActiveState::Active
                        | DepositSyncSpoolActiveState::Switching { .. }
                        | DepositSyncSpoolActiveState::Failing { .. }
                        | DepositSyncSpoolActiveState::Rejecting { .. }
                        | DepositSyncSpoolActiveState::ReleasingOwnership { .. }
                        | DepositSyncSpoolActiveState::OwnershipReleased { .. }
                        | DepositSyncSpoolActiveState::Committed { .. }
                    if active.pinned_source.is_none()
                )
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        if let Some(export) = catalog.certified_export {
            let selected_intent_matches = catalog
                .certified_export_intents
                .get(&export.source)
                .is_some_and(|intent| certified_export_intent_matches_active(intent, export));
            let retained_intents_match = catalog.certified_export_intents.values().all(|intent| {
                intent.context == export.context
                    && intent.semantic_transition == export.semantic_transition
                    && intent.requester == export.requester
            });
            let valid_intent_state = match export.state {
                DepositStateExportSpoolActiveState::Installing
                | DepositStateExportSpoolActiveState::Active
                | DepositStateExportSpoolActiveState::ReleasingOwnership { .. }
                | DepositStateExportSpoolActiveState::OwnershipReleased { .. } => {
                    selected_intent_matches && retained_intents_match
                }
                DepositStateExportSpoolActiveState::Committed { .. }
                | DepositStateExportSpoolActiveState::Deleting { prepared: true } => {
                    catalog.certified_export_intents.is_empty()
                }
                DepositStateExportSpoolActiveState::Deleting { prepared: false } => {
                    !catalog.certified_export_intents.contains_key(&export.source)
                        && retained_intents_match
                }
            };
            if !valid_intent_state
                || catalog.active.is_some()
                || catalog.prefix_attempt.is_some()
                || !catalog.claims.is_empty()
                || export.binding.key != key
                || export.context.network() != key.network_id
                || export.context.wallet() != key.wallet_id
                || export.source.0 == 0
                || export.source == self.party
                || export.requester != self.party
                || export.semantic_transition == [0; 32]
                || export.request_digest == [0; 32]
                || export.response_digest == [0; 32]
                || export.lease_digest == [0; 32]
                || !matches!(
                    export.binding.admission,
                    DepositSyncSpoolAdmissionKind::CertifiedExport {
                        request_digest,
                        semantic_transition,
                        seal_certificate,
                    } if request_digest == export.request_digest
                        && semantic_transition == export.semantic_transition
                        && seal_certificate != [0; 32]
                )
                || matches!(
                    export.state,
                    DepositStateExportSpoolActiveState::ReleasingOwnership { marker }
                        | DepositStateExportSpoolActiveState::OwnershipReleased { marker }
                        | DepositStateExportSpoolActiveState::Committed { marker }
                        if marker.binding != export.binding
                            || marker.validate_for(key.wallet_id).is_err()
                )
            {
                return Err(DepositSyncStageError::InvalidSnapshot);
            }
        }
        let aggregate_committee_bound = catalog
            .claims
            .values()
            .map(|claim| claim.policy.committee_size)
            .chain(catalog.active.iter().map(|active| active.policy.committee_size))
            .max()
            .unwrap_or(0);
        let aggregate_refs = catalog
            .claims
            .len()
            .checked_add(catalog.active.as_ref().map_or(0, |active| active.certified_claims.len()));
        if aggregate_refs
            .is_none_or(|refs| refs > usize::from(aggregate_committee_bound).saturating_mul(2))
        {
            return Err(DepositSyncStageError::CandidateQuota);
        }
        Ok(())
    }

    async fn recover_catalog_deletions(
        &self,
        metadata: &mut Option<DepositSyncSpoolHeadMetadata>,
        catalog: &mut DepositSyncSpoolCatalog,
    ) -> Result<(), DepositSyncStageError> {
        loop {
            let acknowledged = catalog
                .pending_releases
                .iter()
                .filter_map(|(key, pending)| {
                    let still_referenced = match pending {
                        DepositSyncPendingRelease::Ordinary { request, .. } => {
                            catalog_has_release_evidence(catalog, request.lease())
                        }
                        DepositSyncPendingRelease::CertifiedExport { request, .. } => {
                            catalog_has_export_release_evidence(catalog, request.lease())
                        }
                    };
                    (pending.acknowledged() && !still_referenced).then_some(*key)
                })
                .collect::<Vec<_>>();
            if !acknowledged.is_empty() {
                for key in acknowledged {
                    catalog.pending_releases.remove(&key);
                }
                *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                continue;
            }
            if let Some(export) = catalog.certified_export {
                match export.state {
                    DepositStateExportSpoolActiveState::Installing => {
                        if !spool_namespace(&self.directory, export.binding).exists() {
                            return Ok(());
                        }
                        let spool = self.open_cached_binding(export.binding).await?;
                        let _ = spool.initialize().await?;
                        let Some((request, response)) =
                            self.try_spool_export_head_response(&spool).await?
                        else {
                            return Ok(());
                        };
                        validate_certified_export_head(export, request, &response)?;
                        catalog
                            .certified_export
                            .as_mut()
                            .ok_or(DepositSyncStageError::UnknownAnchor)?
                            .state = DepositStateExportSpoolActiveState::Active;
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                    DepositStateExportSpoolActiveState::Active => {
                        if !spool_namespace(&self.directory, export.binding).exists() {
                            return Err(DepositSyncStageError::MissingReadback);
                        }
                        let spool = self.open_cached_binding(export.binding).await?;
                        let _ = spool.initialize().await?;
                        let (request, response) = self
                            .try_spool_export_head_response(&spool)
                            .await?
                            .ok_or(DepositSyncStageError::MissingReadback)?;
                        validate_certified_export_head(export, request, &response)?;
                        if let Some(marker) = spool.prepared_import_release_marker().await? {
                            if marker.binding != export.binding {
                                return Err(DepositSyncStageError::InvalidImportMarker);
                            }
                            catalog
                                .certified_export
                                .as_mut()
                                .ok_or(DepositSyncStageError::UnknownAnchor)?
                                .state =
                                DepositStateExportSpoolActiveState::ReleasingOwnership { marker };
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            continue;
                        }
                        return Ok(());
                    }
                    DepositStateExportSpoolActiveState::ReleasingOwnership { marker } => {
                        let spool = self.open_cached_binding(export.binding).await?;
                        let _ = spool.initialize().await?;
                        if spool.import_marker().await? != marker {
                            return Err(DepositSyncStageError::InvalidImportMarker);
                        }
                        spool.resume_prepared_import_release(&marker).await?;
                        if !spool.prepared_import_release_is_complete(&marker).await? {
                            return Err(DepositSyncStageError::InvalidImportMarker);
                        }
                        catalog
                            .certified_export
                            .as_mut()
                            .ok_or(DepositSyncStageError::UnknownAnchor)?
                            .state =
                            DepositStateExportSpoolActiveState::OwnershipReleased { marker };
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        return Ok(());
                    }
                    DepositStateExportSpoolActiveState::OwnershipReleased { .. } => {
                        return Ok(());
                    }
                    DepositStateExportSpoolActiveState::Committed { marker } => {
                        let spool = self.open_cached_binding(export.binding).await?;
                        let _ = spool.initialize().await?;
                        if spool.import_marker().await? != marker {
                            return Err(DepositSyncStageError::InvalidImportMarker);
                        }
                        let (request, response) = spool.export_head_response().await?;
                        validate_certified_export_head(export, request, &response)?;
                        if self.enqueue_export_release(catalog, response.lease())? {
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            continue;
                        }
                        catalog
                            .certified_export
                            .as_mut()
                            .ok_or(DepositSyncStageError::UnknownAnchor)?
                            .state =
                            DepositStateExportSpoolActiveState::Deleting { prepared: true };
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                    DepositStateExportSpoolActiveState::Deleting { prepared } => {
                        let release_is_durable = catalog.pending_releases.values().any(|pending| {
                            matches!(
                                pending,
                                DepositSyncPendingRelease::CertifiedExport { request, .. }
                                    if request.lease().digest() == export.lease_digest
                            )
                        });
                        if !release_is_durable {
                            if !spool_namespace(&self.directory, export.binding).exists() {
                                return Err(DepositSyncStageError::MissingReadback);
                            }
                            let spool = self.open_cached_binding(export.binding).await?;
                            let _ = spool.initialize().await?;
                            let (request, response) = spool.export_head_response().await?;
                            validate_certified_export_head(export, request, &response)?;
                            if self.enqueue_export_release(catalog, response.lease())? {
                                *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                                continue;
                            }
                        }
                        self.delete_candidate_namespace(export.binding, prepared).await?;
                        catalog.certified_export = None;
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                }
            }
            if let Some(attempt) = catalog.prefix_attempt.clone() {
                match attempt.state {
                    DepositSyncPrefixAttemptState::Installing => {
                        match self
                            .verify_claim_response(attempt.claim.lease.source(), &attempt.claim)
                            .await
                        {
                            Ok(_) => {
                                let attempt = catalog
                                    .prefix_attempt
                                    .as_mut()
                                    .ok_or(DepositSyncStageError::InvalidSnapshot)?;
                                attempt.claim.state = DepositSyncSpoolClaimState::Ready;
                                attempt.state = DepositSyncPrefixAttemptState::Collecting;
                            }
                            Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                                if error.kind() == io::ErrorKind::NotFound =>
                            {
                                let attempt = catalog
                                    .prefix_attempt
                                    .as_mut()
                                    .ok_or(DepositSyncStageError::InvalidSnapshot)?;
                                attempt.claim.state = DepositSyncSpoolClaimState::Deleting;
                                attempt.state = DepositSyncPrefixAttemptState::Deleting(None);
                            }
                            Err(error) => return Err(error),
                        }
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                    DepositSyncPrefixAttemptState::Deleting(evidence) => {
                        if self.enqueue_release(catalog, attempt.claim.lease)? {
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            return Ok(());
                        }
                        let _ = self
                            .artifacts
                            .remove_artifact_if_owned(
                                attempt.claim.response.reference,
                                attempt.claim.response.owner,
                            )
                            .await?;
                        if let Some(evidence) = evidence {
                            let _ = self
                                .artifacts
                                .remove_artifact_if_owned(
                                    evidence.certificate.reference,
                                    evidence.certificate.owner,
                                )
                                .await?;
                        }
                        catalog.prefix_attempt = None;
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                    DepositSyncPrefixAttemptState::Collecting
                    | DepositSyncPrefixAttemptState::Promoting(_) => {}
                }
            }
            let deleting_releases = catalog
                .claims
                .values()
                .filter(|claim| claim.state == DepositSyncSpoolClaimState::Deleting)
                .map(|claim| claim.lease)
                .collect::<Vec<_>>();
            let mut releases_changed = false;
            for lease in deleting_releases {
                releases_changed |= self.enqueue_release(catalog, lease)?;
            }
            if releases_changed {
                *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                return Ok(());
            }
            if let Some((source, claim)) = catalog
                .claims
                .iter()
                .find(|(_, claim)| claim.state != DepositSyncSpoolClaimState::Ready)
                .map(|(source, claim)| (*source, *claim))
            {
                match claim.state {
                    DepositSyncSpoolClaimState::Installing => {
                        match self.verify_claim_response(source, &claim).await {
                            Ok(_) => {
                                catalog
                                    .claims
                                    .get_mut(&source)
                                    .ok_or(DepositSyncStageError::InvalidSnapshot)?
                                    .state = DepositSyncSpoolClaimState::Ready;
                            }
                            Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                                if error.kind() == io::ErrorKind::NotFound =>
                            {
                                self.enqueue_release(catalog, claim.lease)?;
                                catalog
                                    .claims
                                    .get_mut(&source)
                                    .ok_or(DepositSyncStageError::InvalidSnapshot)?
                                    .state = DepositSyncSpoolClaimState::Deleting;
                            }
                            Err(error) => return Err(error),
                        }
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                    }
                    DepositSyncSpoolClaimState::Deleting => {
                        if self.claim_artifact_is_certified(catalog, claim.response) {
                            catalog.claims.remove(&source);
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            continue;
                        }
                        if self.enqueue_release(catalog, claim.lease)? {
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            return Ok(());
                        }
                        let _ = self
                            .artifacts
                            .remove_artifact_if_owned(
                                claim.response.reference,
                                claim.response.owner,
                            )
                            .await?;
                        catalog.claims.remove(&source);
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                    }
                    DepositSyncSpoolClaimState::Ready => unreachable!("filtered above"),
                }
                continue;
            }
            let Some(active) = catalog.active.as_ref().cloned() else {
                return Ok(());
            };
            if matches!(
                active.state,
                DepositSyncSpoolActiveState::Active | DepositSyncSpoolActiveState::Admitting
            ) && spool_namespace(&self.directory, active.binding).exists()
            {
                let spool = self.open_cached_binding(active.binding).await?;
                let _ = spool.initialize().await?;
                if let Some(marker) = spool.prepared_import_release_marker().await? {
                    if marker.binding != active.binding {
                        return Err(DepositSyncStageError::InvalidImportMarker);
                    }
                    catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                        DepositSyncSpoolActiveState::ReleasingOwnership { marker };
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                    continue;
                }
            }
            match active.state {
                DepositSyncSpoolActiveState::Active => {
                    let spool = self.open_cached_binding(active.binding).await?;
                    let _ = spool.initialize().await?;
                    match self.try_spool_head_response(&spool).await? {
                        Some(response)
                            if active.pinned_source == Some(response.lease().source()) =>
                        {
                            return Ok(());
                        }
                        Some(_) => return Err(DepositSyncStageError::InvalidSnapshot),
                        None if active.pinned_source.is_none() => {
                            catalog
                                .active
                                .as_mut()
                                .ok_or(DepositSyncStageError::UnknownAnchor)?
                                .state = DepositSyncSpoolActiveState::Admitting;
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            return Ok(());
                        }
                        None => {
                            catalog
                                .active
                                .as_mut()
                                .ok_or(DepositSyncStageError::UnknownAnchor)?
                                .state = DepositSyncSpoolActiveState::Deleting { prepared: false };
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        }
                    }
                }
                DepositSyncSpoolActiveState::Switching { previous } => {
                    self.delete_candidate_namespace(previous, false).await?;
                    catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                        DepositSyncSpoolActiveState::Admitting;
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                }
                DepositSyncSpoolActiveState::Failing {
                    source,
                    expected_revision,
                    expected_digest,
                } => {
                    if active.pinned_source != Some(source)
                        || !active.certified_claims.contains_key(&source)
                    {
                        return Err(DepositSyncStageError::InvalidSnapshot);
                    }
                    let spool = self.open_cached_binding(active.binding).await?;
                    spool.reset_download_checkpoint(expected_revision, expected_digest).await?;
                    let active =
                        catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
                    active.pinned_source = None;
                    active
                        .failed_variants
                        .insert(DepositSyncFailedVariant { source, anchor: active.binding.anchor });
                    active.state = DepositSyncSpoolActiveState::Admitting;
                    if all_certified_sources_failed(active) {
                        active.source_failure_round = active.source_failure_round.saturating_add(1);
                        active.failed_variants.clear();
                    }
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                    return Ok(());
                }
                DepositSyncSpoolActiveState::Rejecting {
                    source,
                    expected_revision,
                    expected_digest,
                    post_abort,
                    rejection: _,
                } => {
                    if active.pinned_source != Some(source)
                        || !active.certified_claims.contains_key(&source)
                    {
                        return Err(DepositSyncStageError::InvalidSnapshot);
                    }
                    if spool_namespace(&self.directory, active.binding).exists() {
                        let spool = self.open_cached_binding(active.binding).await?;
                        let checkpoint = spool.checkpoint().await?;
                        let original = checkpoint.revision() == expected_revision
                            && checkpoint.digest()? == expected_digest;
                        let aborted = post_abort.is_some_and(|identity| {
                            checkpoint.revision() == identity.revision
                                && checkpoint.digest().ok() == Some(identity.digest)
                        });
                        if !original && !aborted {
                            return Err(DepositSyncStageError::InvalidSpoolTransition);
                        }
                        if original {
                            match checkpoint.phase() {
                                DepositSyncSpoolPhase::Materializing => {
                                    spool.abort_prepared_import(None).await?;
                                }
                                DepositSyncSpoolPhase::ReadyToCas => {
                                    let marker = spool.import_marker().await?;
                                    spool.abort_prepared_import(Some(&marker)).await?;
                                }
                                _ if post_abort.is_none() => {}
                                _ => return Err(DepositSyncStageError::InvalidSnapshot),
                            }
                        }
                        if let Some(identity) = post_abort {
                            let checkpoint = spool.checkpoint().await?;
                            if checkpoint.revision() != identity.revision
                                || checkpoint.digest()? != identity.digest
                            {
                                return Err(DepositSyncStageError::InvalidSpoolTransition);
                            }
                        }
                    }
                    self.delete_candidate_namespace(active.binding, false).await?;
                    let active =
                        catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
                    active.pinned_source = None;
                    active.failed_variants.retain(|failure| failure.source != source);
                    active
                        .rejected_variants
                        .insert(DepositSyncFailedVariant { source, anchor: active.binding.anchor });
                    active.state = DepositSyncSpoolActiveState::Admitting;
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                    return Ok(());
                }
                DepositSyncSpoolActiveState::Admitting => {
                    let spool = self.open_cached_binding(active.binding).await?;
                    let _ = spool.initialize().await?;
                    match self.try_spool_head_response(&spool).await? {
                        Some(response)
                            if active.pinned_source == Some(response.lease().source()) =>
                        {
                            catalog
                                .active
                                .as_mut()
                                .ok_or(DepositSyncStageError::UnknownAnchor)?
                                .state = DepositSyncSpoolActiveState::Active;
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        }
                        Some(_) => return Err(DepositSyncStageError::InvalidSnapshot),
                        None if active.pinned_source.is_none() => return Ok(()),
                        None => {
                            let source = active
                                .pinned_source
                                .ok_or(DepositSyncStageError::InvalidSnapshot)?;
                            let certified = active
                                .certified_claims
                                .get(&source)
                                .copied()
                                .filter(|claim| claim.binding == active.binding);
                            if let Some(certified) = certified {
                                let claim = DepositSyncSpoolClaim {
                                    binding: certified.binding,
                                    policy: active.policy,
                                    facts: active.facts,
                                    lease: certified.lease,
                                    response: certified.response,
                                    state: DepositSyncSpoolClaimState::Ready,
                                };
                                let response = self.verify_claim_response(source, &claim).await?;
                                spool.install_head_response(&response, self.party).await?;
                                catalog
                                    .active
                                    .as_mut()
                                    .ok_or(DepositSyncStageError::UnknownAnchor)?
                                    .state = DepositSyncSpoolActiveState::Active;
                                *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            } else {
                                catalog
                                    .active
                                    .as_mut()
                                    .ok_or(DepositSyncStageError::UnknownAnchor)?
                                    .state =
                                    DepositSyncSpoolActiveState::Deleting { prepared: false };
                                *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            }
                        }
                    }
                }
                DepositSyncSpoolActiveState::ReleasingOwnership { marker } => {
                    let spool = self.open_cached_binding(active.binding).await?;
                    let _ = spool.initialize().await?;
                    if spool.import_marker().await? != marker {
                        return Err(DepositSyncStageError::InvalidImportMarker);
                    }
                    spool.resume_prepared_import_release(&marker).await?;
                    if !spool.prepared_import_release_is_complete(&marker).await? {
                        return Err(DepositSyncStageError::InvalidImportMarker);
                    }
                    catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                        DepositSyncSpoolActiveState::OwnershipReleased { marker };
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                    return Ok(());
                }
                DepositSyncSpoolActiveState::OwnershipReleased { .. } => return Ok(()),
                DepositSyncSpoolActiveState::Committed { marker } => {
                    let spool = self.open_cached_binding(active.binding).await?;
                    let _ = spool.initialize().await?;
                    if spool.import_marker().await? != marker {
                        return Err(DepositSyncStageError::InvalidImportMarker);
                    }
                    catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?.state =
                        DepositSyncSpoolActiveState::Deleting { prepared: true };
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                }
                DepositSyncSpoolActiveState::Deleting { prepared } => {
                    if catalog.claims.values().any(|claim| {
                        claim.facts.support == active.support
                            && claim.state != DepositSyncSpoolClaimState::Deleting
                    }) {
                        self.mark_support_claims_deleting(catalog, active.support);
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                    let certified_releases = active
                        .certified_claims
                        .values()
                        .map(|claim| claim.lease)
                        .collect::<Vec<_>>();
                    let mut releases_changed = false;
                    for lease in certified_releases {
                        releases_changed |= self.enqueue_release(catalog, lease)?;
                    }
                    if releases_changed {
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        return Ok(());
                    }
                    if let Some(source) = active.certified_claims.keys().next().copied() {
                        let certified = active
                            .certified_claims
                            .get(&source)
                            .copied()
                            .ok_or(DepositSyncStageError::InvalidSnapshot)?;
                        if self.enqueue_release(catalog, certified.lease)? {
                            *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                            return Ok(());
                        }
                        let _ = self
                            .artifacts
                            .remove_artifact_if_owned(
                                certified.response.reference,
                                certified.response.owner,
                            )
                            .await?;
                        let active =
                            catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
                        active.certified_claims.remove(&source);
                        active.failed_variants.retain(|failure| failure.source != source);
                        active.rejected_variants.retain(|rejection| rejection.source != source);
                        if active.pinned_source == Some(source) {
                            active.pinned_source = None;
                        }
                        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                        continue;
                    }
                    if let DepositSyncSpoolAuthority::Prefix(evidence) = &active.authority {
                        let _ = self
                            .artifacts
                            .remove_artifact_if_owned(
                                evidence.certificate.reference,
                                evidence.certificate.owner,
                            )
                            .await?;
                        self.prefix_authorizations.lock().await.remove(&active.binding.anchor);
                    }
                    self.delete_candidate_namespace(active.binding, prepared).await?;
                    catalog.active = None;
                    *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
                }
            }
        }
    }

    async fn delete_candidate_namespace(
        &self,
        binding: DepositSyncSpoolBinding,
        allow_prepared: bool,
    ) -> Result<(), DepositSyncStageError> {
        let namespace = spool_namespace(&self.directory, binding);
        let deleting = spool_deleting_namespace(&self.directory, binding);
        if deleting.exists() {
            remove_spool_namespace(&deleting)?;
        }
        if namespace.exists() {
            let spool = self.open_cached_binding(binding).await?;
            if spool.protocol.load_deposit_sync_spool_head(binding.key).await?.is_some() {
                spool.delete_contents(allow_prepared).await?;
            } else if spool.membership_count()? != 0 {
                // A namespace created after the durable Admitting intent but before initialize()
                // has no head and an empty membership database, and is safe to remove exactly.
                // Records without an authenticated head indicate corruption, not that crash window.
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
            drop(spool);
            std::fs::rename(&namespace, &deleting).map_spool_database()?;
            sync_parent_directory(&namespace)?;
            remove_spool_namespace(&deleting)?;
        }
        let mut caches = self.spool_cache.lock().await;
        match caches.get(&binding.anchor) {
            Some(cache) if cache.binding == binding => {
                cache.reconciliation.retire().await;
                caches.remove(&binding.anchor);
            }
            Some(_) => return Err(DepositSyncStageError::ReferenceFork),
            None => {}
        }
        Ok(())
    }

    async fn open_cached_binding(
        &self,
        binding: DepositSyncSpoolBinding,
    ) -> Result<Arc<DepositSyncSpoolStore>, DepositSyncStageError> {
        let mut caches = self.spool_cache.lock().await;
        if let Some(cache) = caches.get_mut(&binding.anchor) {
            if cache.binding != binding {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            if let Some(spool) = cache.handle.upgrade() {
                return Ok(spool);
            }
            // Once the last database handle closes, persisted rows may change before this weak
            // handle is reopened. Start with a fresh process generation and an empty proof so the
            // first authenticated read performs a complete reconciliation.
            let reconciliation = Arc::new(DepositSyncSpoolReconciliationCache::new(binding));
            let spool = Arc::new(DepositSyncSpoolStore::open_binding_with_reconciliation(
                &self.directory,
                self.party,
                &self.identity_seed,
                binding,
                Arc::clone(&reconciliation),
            )?);
            cache.reconciliation.retire().await;
            cache.reconciliation = reconciliation;
            cache.handle = Arc::downgrade(&spool);
            return Ok(spool);
        }
        let reconciliation = Arc::new(DepositSyncSpoolReconciliationCache::new(binding));
        let spool = Arc::new(DepositSyncSpoolStore::open_binding_with_reconciliation(
            &self.directory,
            self.party,
            &self.identity_seed,
            binding,
            Arc::clone(&reconciliation),
        )?);
        caches.insert(
            binding.anchor,
            DepositSyncSpoolProcessCache {
                binding,
                handle: Arc::downgrade(&spool),
                reconciliation,
            },
        );
        Ok(spool)
    }

    async fn try_spool_head_response(
        &self,
        spool: &DepositSyncSpoolStore,
    ) -> Result<Option<DepositSyncHeadResponse>, DepositSyncStageError> {
        match spool.head_response(self.party).await {
            Ok(response) => Ok(Some(response)),
            Err(DepositSyncStageError::MissingReadback) => Ok(None),
            Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn try_spool_export_head_response(
        &self,
        spool: &DepositSyncSpoolStore,
    ) -> Result<
        Option<(DepositStateExportHeadRequest, DepositStateExportHeadResponse)>,
        DepositSyncStageError,
    > {
        match spool.export_head_response().await {
            Ok(response) => Ok(Some(response)),
            Err(DepositSyncStageError::MissingReadback) => Ok(None),
            Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn activate_next_stored_claim(
        &self,
        metadata: &mut Option<DepositSyncSpoolHeadMetadata>,
        catalog: &mut DepositSyncSpoolCatalog,
    ) -> Result<bool, DepositSyncStageError> {
        let active = catalog.active.as_ref().ok_or(DepositSyncStageError::UnknownAnchor)?;
        if active.state != DepositSyncSpoolActiveState::Admitting || active.pinned_source.is_some()
        {
            return Ok(false);
        }
        let selected = active
            .certified_claims
            .iter()
            .find(|(source, _)| !source_unavailable(active, **source))
            .map(|(source, claim)| (*source, *claim));
        let Some((source, certified)) = selected else {
            return Ok(false);
        };
        let frozen_claim = DepositSyncSpoolClaim {
            binding: certified.binding,
            policy: active.policy,
            facts: active.facts,
            lease: certified.lease,
            response: certified.response,
            state: DepositSyncSpoolClaimState::Ready,
        };
        let response = self.verify_claim_response(source, &frozen_claim).await?;
        let previous = active.binding;
        {
            let active = catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
            active.binding = certified.binding;
            active.pinned_source = Some(source);
            active.state = if previous == certified.binding {
                DepositSyncSpoolActiveState::Admitting
            } else {
                DepositSyncSpoolActiveState::Switching { previous }
            };
        }
        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
        self.recover_catalog_deletions(metadata, catalog).await?;
        let spool = self.open_cached_binding(certified.binding).await?;
        let _ = spool.initialize().await?;
        spool.install_head_response(&response, self.party).await?;
        let active = catalog.active.as_mut().ok_or(DepositSyncStageError::UnknownAnchor)?;
        if active.binding != certified.binding || active.pinned_source != Some(source) {
            return Err(DepositSyncStageError::InvalidSnapshot);
        }
        active.state = DepositSyncSpoolActiveState::Active;
        *metadata = Some(self.persist_catalog(*metadata, catalog).await?);
        Ok(true)
    }

    async fn standby_admission(
        &self,
        binding: DepositSyncSpoolBinding,
        preferred_source: Option<PartyId>,
    ) -> Result<DepositSyncSpoolAdmission, DepositSyncStageError> {
        let spool = self.open_cached_binding(binding).await?;
        let _ = spool.initialize().await?;
        Ok(DepositSyncSpoolAdmission::Standby { spool, preferred_source })
    }
}

/// Encrypted, restart-safe staging spool for one exact advertised candidate.
///
/// The only mutable record is a bounded authenticated head in `ProtocolStore`. Object plaintext
/// lives in independently encrypted staging envelopes, and immutable metadata pages carry at most
/// [`MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS`] addresses. Iteration persists a one-object delivery
/// intent before returning data, so a restart replays rather than skips the unacknowledged object.
pub struct DepositSyncSpoolStore {
    binding: DepositSyncSpoolBinding,
    protocol: ProtocolStore,
    artifacts: WalletArtifactStore,
    membership: Arc<DepositSyncSpoolMembershipDatabase>,
    membership_path: PathBuf,
    lookup_key: Arc<Zeroizing<[u8; 32]>>,
    value_key: Arc<Zeroizing<[u8; 32]>>,
    mutation: Mutex<()>,
    runtime_page: Mutex<Option<DepositSyncRuntimePage>>,
    reconciliation: Arc<DepositSyncSpoolReconciliationCache>,
}

/// Cold-target view of one exact certified-export spool.
///
/// This wrapper deliberately exposes only bounded fetch, durable progress, completion detection,
/// and read-only object access. It has no path to freeze, verify, materialize, prepare, or commit
/// an import. The caller must re-present a full [`VerifiedDepositPostHandoffExportSeal`] to the
/// manager before obtaining the underlying full spool handle.
#[derive(Clone)]
pub(crate) struct PreImportDepositStateExportSpool {
    spool: Arc<DepositSyncSpoolStore>,
}

/// Read-only, non-authoritative view of one durably complete cold export download.
///
/// The exact head metadata names the compact-registry and portable-index roots, while
/// `object_reader` authenticates content-addressed plaintext from the candidate-bound spool. This
/// is sufficient for a caller to reconstruct and verify the transition needed to obtain a full
/// [`VerifiedDepositPostHandoffExportSeal`]. It is not a completed import, cannot freeze or mutate
/// the spool, and cannot be converted into the full spool handle.
#[derive(Clone)]
pub(crate) struct CompletedPreImportDepositStateExportArtifacts {
    request: DepositStateExportHeadRequest,
    response: DepositStateExportHeadResponse,
    object_reader: FrozenDepositSyncCandidate,
    checkpoint_revision: u64,
    checkpoint_digest: [u8; 32],
}

impl std::fmt::Debug for CompletedPreImportDepositStateExportArtifacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedPreImportDepositStateExportArtifacts")
            .field("source", &self.request.source())
            .field("requester", &self.request.requester())
            .field("advertisement", &hex::encode(self.response.advertisement().digest()))
            .field("checkpoint_revision", &self.checkpoint_revision)
            .finish_non_exhaustive()
    }
}

impl CompletedPreImportDepositStateExportArtifacts {
    #[must_use]
    pub(crate) const fn head_request(&self) -> DepositStateExportHeadRequest {
        self.request
    }

    #[must_use]
    pub(crate) const fn head_response(&self) -> &DepositStateExportHeadResponse {
        &self.response
    }

    #[must_use]
    pub(crate) const fn advertisement(&self) -> &DepositSyncAdvertisement {
        self.response.advertisement()
    }

    #[must_use]
    pub(crate) const fn registry_archive(&self) -> &CompactRegistryArchiveHead {
        self.response.advertisement().registry_archive()
    }

    #[must_use]
    pub(crate) const fn portable_index(&self) -> &PortableDepositIndexHead {
        self.response.advertisement().portable_index()
    }

    #[must_use]
    pub(crate) const fn object_reader(&self) -> &FrozenDepositSyncCandidate {
        &self.object_reader
    }

    #[must_use]
    pub(crate) const fn checkpoint_revision(&self) -> u64 {
        self.checkpoint_revision
    }

    #[must_use]
    pub(crate) const fn checkpoint_digest(&self) -> [u8; 32] {
        self.checkpoint_digest
    }
}

impl std::fmt::Debug for PreImportDepositStateExportSpool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreImportDepositStateExportSpool")
            .field("anchor", &self.spool.binding.anchor)
            .finish_non_exhaustive()
    }
}

impl PreImportDepositStateExportSpool {
    pub(crate) async fn export_head_response(
        &self,
    ) -> Result<
        (DepositStateExportHeadRequest, DepositStateExportHeadResponse),
        DepositSyncStageError,
    > {
        self.spool.export_head_response().await
    }

    pub(crate) async fn export_download_frontier(
        &self,
    ) -> Result<DepositStateExportDownloadFrontier, DepositSyncStageError> {
        self.spool.export_download_frontier().await
    }

    pub(crate) async fn download_checkpoint(
        &self,
    ) -> Result<DepositSyncSpoolCheckpoint, DepositSyncStageError> {
        self.spool.download_checkpoint().await
    }

    pub(crate) async fn checkpoint(
        &self,
    ) -> Result<DepositSyncSpoolCheckpoint, DepositSyncStageError> {
        self.spool.checkpoint().await
    }

    pub(crate) fn contains_object(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<bool, DepositSyncStageError> {
        self.spool.contains_object(reference)
    }

    pub(crate) fn load_object(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<Option<DepositSyncObject>, DepositSyncStageError> {
        self.spool.load_object(reference)
    }

    pub(crate) async fn merge_export_page(
        &self,
        request: &DepositStateExportObjectsRequest,
        response: &DepositStateExportObjectsResponse,
        next_frontier: &DepositStateExportDownloadFrontier,
    ) -> Result<DepositSyncSpoolStats, DepositSyncStageError> {
        self.spool.merge_export_page(request, response, next_frontier).await
    }

    pub(crate) async fn object_graph_is_complete(&self) -> Result<bool, DepositSyncStageError> {
        match self.spool.completed_object_graph_download().await {
            Ok(_) => Ok(true),
            Err(DepositSyncStageError::IncompleteObjectGraph) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Expose only read-only candidate artifacts after the exact export frontier is durably
    /// terminal. This does not freeze the spool or mint either pre-import or full-import
    /// authority.
    pub(crate) async fn completed_artifacts(
        &self,
    ) -> Result<CompletedPreImportDepositStateExportArtifacts, DepositSyncStageError> {
        self.spool.completed_pre_import_artifacts().await
    }
}

/// Non-deserializable O(1) reader for one frozen candidate.
///
/// Values are decrypted one record at a time from the candidate-bound redb namespace. Holding this
/// token never grants authority to mutate the live wallet; the outer wallet CAS remains the only
/// promotion boundary.
#[derive(Clone)]
pub struct FrozenDepositSyncCandidate {
    binding: DepositSyncSpoolBinding,
    membership: Arc<DepositSyncSpoolMembershipDatabase>,
    lookup_key: Arc<Zeroizing<[u8; 32]>>,
    value_key: Arc<Zeroizing<[u8; 32]>>,
    object_count: u64,
    local_read_fault: Arc<AtomicBool>,
}

/// Non-serializable proof that the exact durable source-bound object frontier is exhausted.
///
/// This capability carries no wallet authority. It can only be reconstructed from the
/// authenticated spool head while that head retains the canonical terminal frontier, and is
/// consumed by [`DepositSyncSpoolStore::freeze`].
#[must_use = "a completed download must be consumed by DepositSyncSpoolStore::freeze"]
pub struct CompletedDepositObjectGraphDownload {
    binding: DepositSyncSpoolBinding,
    phase: DepositSyncSpoolPhase,
    checkpoint_revision: u64,
    checkpoint_digest: [u8; 32],
    object_count: u64,
}

impl std::fmt::Debug for CompletedDepositObjectGraphDownload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedDepositObjectGraphDownload")
            .field("anchor", &self.binding.anchor)
            .field("phase", &self.phase)
            .field("checkpoint_revision", &self.checkpoint_revision)
            .field("object_count", &self.object_count)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for FrozenDepositSyncCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrozenDepositSyncCandidate")
            .field("anchor", &self.binding.anchor)
            .field("object_count", &self.object_count)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DepositSyncSpoolStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DepositSyncSpoolStore")
            .field("key", &self.binding.key)
            .field("anchor", &self.binding.anchor)
            .field("membership_path", &self.membership_path)
            .finish_non_exhaustive()
    }
}

impl DepositSyncSpoolStore {
    fn open_exact(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Self, DepositSyncStageError> {
        let binding = spool_binding(advertisement)?;
        Self::open_binding(directory, party, identity_seed, binding)
    }

    fn open_binding(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        binding: DepositSyncSpoolBinding,
    ) -> Result<Self, DepositSyncStageError> {
        Self::open_binding_with_reconciliation(
            directory,
            party,
            identity_seed,
            binding,
            Arc::new(DepositSyncSpoolReconciliationCache::new(binding)),
        )
    }

    fn open_binding_with_reconciliation(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        binding: DepositSyncSpoolBinding,
        reconciliation: Arc<DepositSyncSpoolReconciliationCache>,
    ) -> Result<Self, DepositSyncStageError> {
        if reconciliation.binding != binding {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        let directory = directory.into();
        let namespace = spool_namespace(&directory, binding);
        let membership_path = namespace.join(SPOOL_MEMBERSHIP_DATABASE_FILE);
        let membership =
            open_spool_membership_database(&membership_path, Arc::clone(&reconciliation))?;
        let (lookup_key, value_key) = derive_spool_membership_keys(identity_seed, party, binding)?;
        Ok(Self {
            binding,
            protocol: ProtocolStore::new(&namespace, party, identity_seed)?,
            artifacts: WalletArtifactStore::new(directory, party, identity_seed)?,
            membership: Arc::new(membership),
            membership_path,
            lookup_key: Arc::new(Zeroizing::new(lookup_key)),
            value_key: Arc::new(Zeroizing::new(value_key)),
            mutation: Mutex::new(()),
            runtime_page: Mutex::new(None),
            reconciliation,
        })
    }

    #[cfg(test)]
    pub(crate) async fn frozen_for_verification_test(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        advertisement: &DepositSyncAdvertisement,
        objects: &[DepositSyncObject],
    ) -> Result<(Arc<Self>, FrozenDepositSyncCandidate), DepositSyncStageError> {
        let spool = Arc::new(Self::open_exact(directory, party, identity_seed, advertisement)?);
        let _ = spool.initialize().await?;
        let source = if party == PartyId(1) { PartyId(2) } else { PartyId(1) };
        let request = DepositSyncHeadRequest::new(advertisement.context(), source, party)?;
        let response = DepositSyncHeadResponse::issue(request, advertisement.clone(), &[0xA7; 32])?;
        spool.install_head_response(&response, party).await?;
        let complete_frontier = completed_download_frontier_for_test(response.lease())?;
        let page_count = objects.chunks(MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS).len();
        for (index, page) in objects.chunks(MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS).enumerate() {
            let checkpoint = spool.download_checkpoint().await?;
            let frontier = if index + 1 == page_count {
                complete_frontier.clone()
            } else {
                format!("materialization-test-incomplete-frontier-{index}").into_bytes()
            };
            let next = checkpoint.successor(DepositSyncSpoolPhase::Downloading, frontier)?;
            let ordinal =
                u64::try_from(index).map_err(|_| DepositSyncStageError::SpoolPageQuota)?;
            let mut request_digest = [0x31; 32];
            request_digest[..8].copy_from_slice(&ordinal.to_le_bytes());
            let mut response_digest = [0x32; 32];
            response_digest[..8].copy_from_slice(&ordinal.to_le_bytes());
            spool
                .merge_page(request_digest, response_digest, page, next.revision(), next.cursor())
                .await?;
        }
        let completed = spool.completed_object_graph_download().await?;
        let frozen = spool.freeze(completed).await?;
        Ok((spool, frozen))
    }

    #[cfg(test)]
    pub(crate) async fn verified_for_materialization_test(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        advertisement: &DepositSyncAdvertisement,
        objects: &[DepositSyncObject],
    ) -> Result<Arc<Self>, DepositSyncStageError> {
        let (spool, _frozen) = Self::frozen_for_verification_test(
            directory,
            party,
            identity_seed,
            advertisement,
            objects,
        )
        .await?;
        spool.begin_verification().await?;
        spool.mark_verified(&[0xA5; 32]).await?;
        Ok(spool)
    }

    #[cfg(test)]
    pub(crate) async fn hold_mutation_for_test(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.mutation.lock().await
    }

    /// Create or authenticate the compact head, then resolve any interrupted append or deletion.
    pub async fn initialize(
        &self,
    ) -> Result<(DepositSyncSpoolRecovery, DepositSyncSpoolStats), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let recovery = self.recover_pending_locked().await?;
        let (_, head) = self.load_or_create_spool_head().await?;
        Ok((recovery, spool_stats(&head)?))
    }

    async fn install_head_response(
        &self,
        response: &DepositSyncHeadResponse,
        requester: PartyId,
    ) -> Result<(), DepositSyncStageError> {
        let envelope =
            DepositSyncSpoolHeadResponseEnvelope::from_response(self.binding, response, requester)?;
        self.install_head_response_envelope(envelope).await
    }

    async fn install_certified_export_head_response<S: CertifiedExportReadSeal + ?Sized>(
        &self,
        request: DepositStateExportHeadRequest,
        response: &DepositStateExportHeadResponse,
        seal: &S,
    ) -> Result<(), DepositSyncStageError> {
        let envelope = DepositSyncSpoolHeadResponseEnvelope::from_certified_export(
            self.binding,
            request,
            response,
            seal,
        )?;
        self.install_head_response_envelope(envelope).await
    }

    async fn install_head_response_envelope(
        &self,
        envelope: DepositSyncSpoolHeadResponseEnvelope,
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (mut metadata, mut head) = self.load_existing_spool_head().await?;
        let bytes = envelope.to_bytes()?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_HEAD_RESPONSE_ARTIFACT,
            &bytes,
        )?;
        if let Some(reference) = head.head_response {
            if reference != expected {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            let artifact = self.artifacts.load_artifact_owned(reference, head.owner).await?;
            let durable = DepositSyncSpoolHeadResponseEnvelope::from_bytes(
                self.binding,
                artifact.contents.as_bytes(),
            )?;
            if durable != envelope {
                return Err(DepositSyncStageError::MissingReadback);
            }
            return Ok(());
        }
        if head.pending_head_response.is_some() {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        head.pending_head_response = Some(DepositSyncSpoolPendingHeadResponse {
            reference: expected,
            source: envelope.source(),
        });
        metadata = self.persist_spool_head(Some(metadata), &head).await?;
        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                head.owner,
                WalletId(self.binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_HEAD_RESPONSE_ARTIFACT,
                &bytes,
                &mut OsRng,
            )
            .await?;
        if installed != expected {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let artifact = self.artifacts.load_artifact_owned(expected, head.owner).await?;
        let durable = DepositSyncSpoolHeadResponseEnvelope::from_bytes(
            self.binding,
            artifact.contents.as_bytes(),
        )?;
        if durable != envelope {
            return Err(DepositSyncStageError::MissingReadback);
        }
        head.head_response = Some(expected);
        head.pending_head_response = None;
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    /// Reload the exact validated advertisement and source-issued historical-serving lease.
    pub async fn head_response(
        &self,
        requester: PartyId,
    ) -> Result<DepositSyncHeadResponse, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        let reference = head.head_response.ok_or(DepositSyncStageError::MissingReadback)?;
        let artifact = self.artifacts.load_artifact_owned(reference, head.owner).await?;
        DepositSyncSpoolHeadResponseEnvelope::from_bytes(
            self.binding,
            artifact.contents.as_bytes(),
        )?
        .decode_response(requester)
    }

    /// Reload the exact certified-export request, response, certificate bytes, and opaque lease.
    ///
    /// This is durable evidence only. The caller must reverify the embedded seal against freshly
    /// reconstructed predecessor and target authority before using it to authorize an import.
    pub async fn export_head_response(
        &self,
    ) -> Result<
        (DepositStateExportHeadRequest, DepositStateExportHeadResponse),
        DepositSyncStageError,
    > {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        let reference = head.head_response.ok_or(DepositSyncStageError::MissingReadback)?;
        let artifact = self.artifacts.load_artifact_owned(reference, head.owner).await?;
        DepositSyncSpoolHeadResponseEnvelope::from_bytes(
            self.binding,
            artifact.contents.as_bytes(),
        )?
        .decode_certified_export()
    }

    /// Reconstruct the exact export traversal from its authenticated durable checkpoint.
    pub async fn export_download_frontier(
        &self,
    ) -> Result<DepositStateExportDownloadFrontier, DepositSyncStageError> {
        let (request, response) = self.export_head_response().await?;
        if response.request_digest() != request.digest() {
            return Err(DepositSyncStageError::InvalidEnvelope);
        }
        let checkpoint = self.download_checkpoint().await?;
        DepositStateExportDownloadFrontier::from_checkpoint(response.lease(), checkpoint.cursor())
    }

    /// Return the exact durable downloader revision and its authenticated frontier digest.
    pub async fn download_checkpoint(
        &self,
    ) -> Result<DepositSyncSpoolCheckpoint, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(head.checkpoint)
    }

    /// Optimistically reset one failed source-bound frontier without changing the exact object set.
    async fn reset_download_checkpoint(
        &self,
        expected_revision: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        let successor_revision = expected_revision.checked_add(1);
        if head.checkpoint.phase == DepositSyncSpoolPhase::Downloading
            && successor_revision == Some(head.checkpoint.revision)
            && head.checkpoint.cursor.is_empty()
            && head.last_transition.is_none()
            && head.head_response.is_none()
            && head.download_generation_start_revision == head.checkpoint.revision
        {
            return Ok(());
        }
        if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading
            || head.checkpoint.revision != expected_revision
            || head.checkpoint.digest()? != expected_digest
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let next_checkpoint =
            head.checkpoint.successor(DepositSyncSpoolPhase::Downloading, Vec::new())?;
        if let Some(reference) = head.head_response {
            // `fail_download_source_with_prefix_class` durably records the exact Failing
            // checkpoint in the manager catalog before entering this private reset. A crash after
            // this idempotent unlink but before the head CAS therefore replays this same guarded
            // reset from the outer journal; no unjournaled caller can expose the transient gap.
            let _ = self.artifacts.remove_artifact_if_owned(reference, head.owner).await?;
            head.head_response = None;
        }
        head.checkpoint = next_checkpoint;
        head.download_generation_start_revision = head.checkpoint.revision;
        head.last_transition = None;
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    /// Return the exact durable reducer checkpoint for restart in any non-deleted phase.
    pub async fn checkpoint(&self) -> Result<DepositSyncSpoolCheckpoint, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        Ok(head.checkpoint)
    }

    /// Validate and durably merge one exact certified-export page and its successor frontier.
    pub async fn merge_export_page(
        &self,
        request: &DepositStateExportObjectsRequest,
        response: &DepositStateExportObjectsResponse,
        next_frontier: &DepositStateExportDownloadFrontier,
    ) -> Result<DepositSyncSpoolStats, DepositSyncStageError> {
        response.validate_for(request)?;
        let (head_request, head_response) = self.export_head_response().await?;
        if head_response.request_digest() != head_request.digest()
            || request.lease() != head_response.lease()
            || next_frontier.lease() != head_response.lease()
        {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        let checkpoint = self.download_checkpoint().await?;
        let mut expected = DepositStateExportDownloadFrontier::from_checkpoint(
            request.lease(),
            checkpoint.cursor(),
        )?;
        expected.apply_response(request, response)?;
        if &expected != next_frontier {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        let next =
            checkpoint.successor(DepositSyncSpoolPhase::Downloading, next_frontier.to_bytes()?)?;
        self.merge_page(
            request.digest(),
            response.digest(),
            response.objects(),
            next.revision(),
            next.cursor(),
        )
        .await
    }

    /// Merge one exact bounded wire response.
    ///
    /// Replaying the same request/response pair is idempotent. Reusing a request identity for a
    /// different response is permanent equivocation, and changing the object set beneath an
    /// otherwise identical pair is a local caller/storage fault.
    pub async fn merge_page(
        &self,
        request_digest: [u8; 32],
        response_digest: [u8; 32],
        objects: &[DepositSyncObject],
        next_frontier_revision: u64,
        next_frontier: &[u8],
    ) -> Result<DepositSyncSpoolStats, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (metadata, mut head) = self.load_or_create_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let objects_digest = spool_objects_digest(objects)?;
        if let Some(transition) = head
            .last_transition
            .as_ref()
            .filter(|transition| transition.request_digest == request_digest)
        {
            if transition.response_digest != response_digest {
                return Err(DepositSyncStageError::ResponseEquivocation);
            }
            let replayed_checkpoint = DepositSyncSpoolCheckpoint {
                phase: DepositSyncSpoolPhase::Downloading,
                revision: next_frontier_revision,
                cursor: next_frontier.to_vec(),
            };
            if transition.objects_digest != objects_digest
                || transition.next_revision != next_frontier_revision
                || transition.next_checkpoint_digest != replayed_checkpoint.digest()?
            {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            self.verify_existing_objects(objects)?;
            return spool_stats(&head);
        }
        if let Some(replay) = self.replay_record(request_digest)? {
            let recorded = replay.transition;
            if recorded.response_digest != response_digest {
                return Err(DepositSyncStageError::ResponseEquivocation);
            }
            if recorded.objects_digest != objects_digest {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            if recorded.expected_revision < head.download_generation_start_revision {
                // A source-specific frontier starts again at its exact roots after failover. The
                // immutable replay row still proves what this request returned previously, while
                // the authenticated frontier guarantees at-most-once traversal within the new
                // generation. Reconsume only byte-for-byte identical, already present objects and
                // advance the current checkpoint without appending another page or replay row.
                let next = head
                    .checkpoint
                    .successor(DepositSyncSpoolPhase::Downloading, next_frontier.to_vec())?;
                if next_frontier_revision != next.revision {
                    return Err(DepositSyncStageError::InvalidSpoolTransition);
                }
                self.verify_existing_objects(objects)?;
                let transition = DepositSyncSpoolPageTransition::new(
                    request_digest,
                    response_digest,
                    objects_digest,
                    &head.checkpoint,
                    &next,
                )?;
                head.checkpoint = next;
                head.last_transition = Some(transition);
                self.persist_spool_head(Some(metadata), &head).await?;
                return spool_stats(&head);
            }
            let replayed_checkpoint = DepositSyncSpoolCheckpoint {
                phase: DepositSyncSpoolPhase::Downloading,
                revision: next_frontier_revision,
                cursor: next_frontier.to_vec(),
            };
            if recorded.next_revision != next_frontier_revision
                || recorded.next_checkpoint_digest != replayed_checkpoint.digest()?
            {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            self.verify_existing_objects(objects)?;
            return spool_stats(&head);
        }
        if next_frontier_revision
            != head
                .checkpoint
                .revision
                .checked_add(1)
                .ok_or(DepositSyncStageError::InvalidSpoolTransition)?
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let next = head
            .checkpoint
            .successor(DepositSyncSpoolPhase::Downloading, next_frontier.to_vec())?;
        let transition = DepositSyncSpoolPageTransition::new(
            request_digest,
            response_digest,
            objects_digest,
            &head.checkpoint,
            &next,
        )?;
        if self.objects_are_all_present(objects)? {
            // Source failover may restart a capability traversal from its exact root. Advancing
            // only the bounded authenticated frontier prevents duplicate object pages and
            // artifacts from accumulating. The separate sealed response-evidence journal retains
            // permanent equivocation proof for this exact request without disturbing the
            // page-to-replay-row deletion invariant.
            self.prepare_response_evidence(&head, &transition)?;
            let previous_owner = head.owner;
            head.response_evidence_count = head
                .response_evidence_count
                .checked_add(1)
                .ok_or(DepositSyncStageError::ObjectQuota)?;
            head.response_evidence_accumulator = xor_response_evidence_accumulator(
                head.response_evidence_accumulator,
                response_evidence_commitment(self.binding, &transition)?,
            );
            head.checkpoint = next;
            head.last_transition = Some(transition.clone());
            let next_metadata = self.persist_spool_head(Some(metadata), &head).await?;
            self.finalize_response_evidence(&head, &transition)?;
            self.advance_reconciliation_after_response_evidence_persist(
                metadata,
                next_metadata,
                previous_owner,
                &head,
            )
            .await?;
            return spool_stats(&head);
        }
        self.plan_page_locked(objects, transition, &next).await?;
        self.write_pending_page_locked(objects, &next).await?;
        if self.recover_pending_locked().await? != DepositSyncSpoolRecovery::Committed {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let (_, head) = self.load_or_create_spool_head().await?;
        spool_stats(&head)
    }

    /// Replay the exact pending append after a process boundary.
    pub async fn recover_pending(&self) -> Result<DepositSyncSpoolRecovery, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        self.recover_pending_locked().await
    }

    /// O(1) authenticated membership query used by the capability frontier planner.
    pub fn contains_object(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<bool, DepositSyncStageError> {
        Ok(self.membership_record(reference)?.is_some())
    }

    /// O(1) authenticated object load used by the capability frontier planner.
    pub fn load_object(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<Option<DepositSyncObject>, DepositSyncStageError> {
        self.membership_record(reference)?
            .map(|record| DepositSyncObject::new(record.reference, record.bytes))
            .transpose()
            .map_err(Into::into)
    }

    /// Reconstruct a non-serializable completion capability from the exact durable frontier.
    ///
    /// A crash after committing the final page or after freezing is harmless: both phases retain
    /// the canonical terminal frontier and can re-mint this process-local capability.
    pub async fn completed_object_graph_download(
        &self,
    ) -> Result<CompletedDepositObjectGraphDownload, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        self.completed_object_graph_download_for_head(&head).await
    }

    /// Atomically bind a terminal certified-export frontier to its exact durable head metadata and
    /// a read-only object view. Keeping all reads under the spool mutation lock prevents a
    /// concurrent source reset from splicing a newer head onto the completed object set.
    async fn completed_pre_import_artifacts(
        &self,
    ) -> Result<CompletedPreImportDepositStateExportArtifacts, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        let completed = self.completed_object_graph_download_for_head(&head).await?;
        let response_reference =
            head.head_response.ok_or(DepositSyncStageError::MissingReadback)?;
        let artifact = self.artifacts.load_artifact_owned(response_reference, head.owner).await?;
        let (request, response) = DepositSyncSpoolHeadResponseEnvelope::from_bytes(
            self.binding,
            artifact.contents.as_bytes(),
        )?
        .decode_certified_export()?;
        let reader = self.frozen_reader(completed.object_count);
        for root in response.lease().root_targets()? {
            if reader.load_object(root.reference())?.is_none() {
                return Err(DepositSyncStageError::IncompleteObjectGraph);
            }
        }
        Ok(CompletedPreImportDepositStateExportArtifacts {
            request,
            response,
            object_reader: reader,
            checkpoint_revision: completed.checkpoint_revision,
            checkpoint_digest: completed.checkpoint_digest,
        })
    }

    /// Freeze an exactly completed object graph. No later wire response can be merged.
    pub async fn freeze(
        &self,
        completed: CompletedDepositObjectGraphDownload,
    ) -> Result<FrozenDepositSyncCandidate, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        let durable = self.completed_object_graph_download_for_head(&head).await?;
        if completed.binding != durable.binding
            || completed.phase != durable.phase
            || completed.checkpoint_revision != durable.checkpoint_revision
            || completed.checkpoint_digest != durable.checkpoint_digest
            || completed.object_count != durable.object_count
        {
            return Err(DepositSyncStageError::IncompleteObjectGraph);
        }
        if head.checkpoint.phase == DepositSyncSpoolPhase::Downloading {
            let cursor = head.checkpoint.cursor.clone();
            head.checkpoint = head.checkpoint.successor(DepositSyncSpoolPhase::Frozen, cursor)?;
            self.persist_spool_head(Some(metadata), &head).await?;
        } else if head.checkpoint.phase != DepositSyncSpoolPhase::Frozen {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        Ok(self.frozen_reader(head.object_count))
    }

    async fn completed_object_graph_download_for_head(
        &self,
        head: &DepositSyncSpoolHead,
    ) -> Result<CompletedDepositObjectGraphDownload, DepositSyncStageError> {
        if !matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Downloading | DepositSyncSpoolPhase::Frozen
        ) || head.object_count == 0
            || head.page_count == 0
        {
            return Err(DepositSyncStageError::IncompleteObjectGraph);
        }
        let response_reference =
            head.head_response.ok_or(DepositSyncStageError::MissingReadback)?;
        let artifact = self.artifacts.load_artifact_owned(response_reference, head.owner).await?;
        let envelope = DepositSyncSpoolHeadResponseEnvelope::from_bytes(
            self.binding,
            artifact.contents.as_bytes(),
        )?;
        match envelope {
            ordinary @ DepositSyncSpoolHeadResponseEnvelope::Ordinary { .. } => {
                let response = ordinary.decode_response(self.protocol.party_id())?;
                let _ = DepositSyncDurableDownloadFrontier::completed(
                    response.lease(),
                    head.checkpoint.cursor(),
                )?;
            }
            export @ DepositSyncSpoolHeadResponseEnvelope::CertifiedExport { .. } => {
                let (_, response) = export.decode_certified_export()?;
                let _ = DepositStateExportDownloadFrontier::completed(
                    response.lease(),
                    head.checkpoint.cursor(),
                )?;
            }
        }
        Ok(CompletedDepositObjectGraphDownload {
            binding: self.binding,
            phase: head.checkpoint.phase,
            checkpoint_revision: head.checkpoint.revision,
            checkpoint_digest: head.checkpoint.digest()?,
            object_count: head.object_count,
        })
    }

    /// Reopen the immutable object reader for an exact prepared-import journal.
    ///
    /// This is intentionally separate from download completion: verification has replaced the
    /// frontier cursor by this point, while the authenticated ReadyToCas head and marker bind the
    /// exact already-verified object set. Ownership must still be local and unreleased.
    pub(crate) async fn prepared_import_reader(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<FrozenDepositSyncCandidate, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::ReadyToCas
            || head.ownership_release.is_some()
            || marker.binding != self.binding
            || prepared_import_marker(&head)? != *marker
        {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        Ok(self.frozen_reader(head.object_count))
    }

    pub async fn begin_verification(&self) -> Result<(), DepositSyncStageError> {
        self.advance_phase(
            DepositSyncSpoolPhase::Frozen,
            DepositSyncSpoolPhase::Verifying,
            Some(Vec::new()),
        )
        .await
    }

    /// Persist one bounded verification reducer cursor without changing phase.
    pub async fn checkpoint_verification(
        &self,
        expected_revision: u64,
        cursor: &[u8],
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Verifying {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        if expected_revision.checked_add(1) == Some(head.checkpoint.revision)
            && head.checkpoint.cursor.as_slice() == cursor
        {
            return Ok(());
        }
        if head.checkpoint.revision != expected_revision {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        head.checkpoint =
            head.checkpoint.successor(DepositSyncSpoolPhase::Verifying, cursor.to_vec())?;
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    pub async fn mark_verified(
        &self,
        verified_summary: &[u8],
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        let envelope = DepositSyncVerifiedSummaryEnvelope::new(
            self.binding,
            head.object_count,
            verified_summary,
        )?;
        let cursor = envelope.to_checkpoint_cursor()?;
        if head.checkpoint.phase == DepositSyncSpoolPhase::Verified {
            let durable = DepositSyncVerifiedSummaryEnvelope::from_checkpoint_cursor(
                self.binding,
                head.object_count,
                head.checkpoint.cursor(),
            )?;
            if durable != envelope {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            return Ok(());
        }
        if head.checkpoint.phase != DepositSyncSpoolPhase::Verifying {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        head.checkpoint = head.checkpoint.successor(DepositSyncSpoolPhase::Verified, cursor)?;
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    /// Restart semantic verification against a newer local base without changing the frozen object
    /// set or destructively cleaning already materialized content-addressed artifacts.
    ///
    /// The expected checkpoint identity makes this an authenticated CAS. Retained owner reservations
    /// are safe to reuse because materialization authenticates every frozen object and installs it
    /// under the same deterministic content address. Clearing the scan before the atomic head write
    /// also makes cancellation leave either the complete old phase or a fresh verification phase.
    pub async fn reset_verification_for_local_base(
        &self,
        expected_revision: u64,
        expected_digest: [u8; 32],
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.ownership_release.is_some() {
            return Err(DepositSyncStageError::PreparedImportDispositionRequired);
        }
        if !matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Verifying
                | DepositSyncSpoolPhase::Verified
                | DepositSyncSpoolPhase::Materializing
                | DepositSyncSpoolPhase::ReadyToCas
        ) || head.checkpoint.revision != expected_revision
            || head.checkpoint.digest()? != expected_digest
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        head.checkpoint =
            head.checkpoint.successor(DepositSyncSpoolPhase::Verifying, Vec::new())?;
        head.scan = None;
        self.persist_spool_head(Some(metadata), &head).await?;
        *self.runtime_page.lock().await = None;
        Ok(())
    }

    /// Reload the exact canonical summary retained through all post-verification phases.
    pub async fn verified_summary(&self) -> Result<Vec<u8>, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (_, head) = self.load_existing_spool_head().await?;
        if !matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Verified
                | DepositSyncSpoolPhase::Materializing
                | DepositSyncSpoolPhase::ReadyToCas
        ) {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let envelope = DepositSyncVerifiedSummaryEnvelope::from_checkpoint_cursor(
            self.binding,
            head.object_count,
            head.checkpoint.cursor(),
        )?;
        Ok(envelope.payload)
    }

    /// Start a stable newest-to-oldest materialization scan.
    pub async fn begin_materialization(
        &self,
    ) -> Result<DepositSyncSpoolStats, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        match head.checkpoint.phase {
            DepositSyncSpoolPhase::Verified => {
                let cursor = head.checkpoint.cursor.clone();
                head.checkpoint =
                    head.checkpoint.successor(DepositSyncSpoolPhase::Materializing, cursor)?;
            }
            DepositSyncSpoolPhase::Materializing if head.scan.is_some() => {
                return spool_stats(&head);
            }
            _ => return Err(DepositSyncStageError::InvalidSpoolTransition),
        }
        head.scan = Some(DepositSyncSpoolScan {
            snapshot_head: head.committed,
            snapshot_pages: head.page_count,
            snapshot_objects: head.object_count,
            position: head.committed,
            remaining_pages: head.page_count,
            remaining_objects: head.object_count,
        });
        self.persist_spool_head(Some(metadata), &head).await?;
        *self.runtime_page.lock().await = None;
        spool_stats(&head)
    }

    /// Return one authenticated object from the current bounded page.
    ///
    /// An unacknowledged object is replayed exactly within one process. After restart the complete
    /// current page is replayed from its first object; downstream ingestion must therefore remain
    /// idempotent. The durable cursor advances once per page, not once per object.
    pub async fn next_materialization_object(
        &self,
    ) -> Result<Option<DepositSyncObject>, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        loop {
            let (metadata, mut head) = self.load_existing_spool_head().await?;
            if head.checkpoint.phase != DepositSyncSpoolPhase::Materializing {
                return Err(DepositSyncStageError::InvalidSpoolTransition);
            }
            let scan = head.scan.as_mut().ok_or(DepositSyncStageError::IterationInactive)?;
            if scan.remaining_pages == 0 {
                if scan.position.is_some() || scan.remaining_objects != 0 {
                    return Err(DepositSyncStageError::InvalidSpoolHead);
                }
                return Ok(None);
            }
            let link = scan.position.ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            let reload =
                self.runtime_page.lock().await.as_ref().is_none_or(|runtime| runtime.link != link);
            if reload {
                let page = self.load_spool_page(head.owner, link).await?;
                if page.entries.is_empty() {
                    scan.remaining_pages = scan
                        .remaining_pages
                        .checked_sub(1)
                        .ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
                    scan.position = page.previous;
                    self.persist_spool_head(Some(metadata), &head).await?;
                    continue;
                }
                *self.runtime_page.lock().await = Some(DepositSyncRuntimePage {
                    link,
                    entries: page.entries,
                    previous: page.previous,
                    next_index: 0,
                    delivered_index: None,
                });
            }
            let mut runtime = self.runtime_page.lock().await;
            let runtime = runtime.as_mut().ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
            let index = runtime.delivered_index.unwrap_or(runtime.next_index);
            let entry = runtime
                .entries
                .get(index)
                .copied()
                .ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
            let object = self
                .load_object(entry.reference)?
                .ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
            runtime.delivered_index = Some(index);
            return Ok(Some(object));
        }
    }

    /// Acknowledge the last delivered object.
    ///
    /// Intermediate acknowledgements are process-local. The authenticated head advances only
    /// after the complete bounded page has been acknowledged.
    pub async fn acknowledge_materialized_object(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Materializing {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let scan = head.scan.as_mut().ok_or(DepositSyncStageError::IterationInactive)?;
        let mut runtime = self.runtime_page.lock().await;
        let page = runtime.as_mut().ok_or(DepositSyncStageError::NoPendingDelivery)?;
        if scan.position != Some(page.link) {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        let delivered = page.delivered_index.ok_or(DepositSyncStageError::NoPendingDelivery)?;
        let entry = page.entries.get(delivered).ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        if entry.reference != reference || delivered != page.next_index {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        if delivered + 1 < page.entries.len() {
            page.next_index = delivered + 1;
            page.delivered_index = None;
            return Ok(());
        }
        let page_objects =
            u64::try_from(page.entries.len()).map_err(|_| DepositSyncStageError::Serialization)?;
        scan.remaining_objects = scan
            .remaining_objects
            .checked_sub(page_objects)
            .ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        scan.remaining_pages =
            scan.remaining_pages.checked_sub(1).ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        scan.position = page.previous;
        if (scan.remaining_pages == 0) != scan.position.is_none() {
            return Err(DepositSyncStageError::InvalidSpoolCursor);
        }
        self.persist_spool_head(Some(metadata), &head).await?;
        *runtime = None;
        Ok(())
    }

    /// Clear only a completed scan intent. Staged pages and objects remain untouched.
    pub async fn finish_materialization(&self) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Materializing {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let scan = head.scan.as_ref().ok_or(DepositSyncStageError::IterationInactive)?;
        if scan.remaining_pages != 0 || scan.remaining_objects != 0 || scan.position.is_some() {
            return Err(DepositSyncStageError::IterationIncomplete);
        }
        head.scan = None;
        self.persist_spool_head(Some(metadata), &head).await?;
        *self.runtime_page.lock().await = None;
        Ok(())
    }

    pub async fn mark_ready_to_cas(&self) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase == DepositSyncSpoolPhase::ReadyToCas {
            return Ok(());
        }
        if head.checkpoint.phase != DepositSyncSpoolPhase::Materializing || head.scan.is_some() {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        if head.object_count == 0
            || head.object_count > head.binding.maximum_objects
            || head.committed.is_none()
        {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        let cursor = head.checkpoint.cursor.clone();
        head.checkpoint = head.checkpoint.successor(DepositSyncSpoolPhase::ReadyToCas, cursor)?;
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    /// Install one verified permanent artifact under the spool's durable import owner.
    ///
    /// The object must already belong to the frozen candidate. Replays after a process boundary
    /// are idempotent because both the content address and owner are deterministic.
    pub async fn create_import_artifact_owned(
        &self,
        object: &DepositSyncObject,
    ) -> Result<WalletArtifactRef, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (_, head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Materializing {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let durable = self
            .membership_record(object.reference())?
            .ok_or(DepositSyncStageError::UnknownObject)?;
        if durable.bytes.as_slice() != object.bytes() {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        let expected = object.reference().storage_reference()?;
        let recomputed =
            WalletArtifactRef::for_contents(expected.wallet_id(), expected.kind(), object.bytes())?;
        if expected != recomputed || expected.wallet_id() != WalletId(self.binding.key.wallet_id.0)
        {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                head.owner,
                expected.wallet_id(),
                expected.kind(),
                object.bytes(),
                &mut OsRng,
            )
            .await?;
        if installed != expected {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let artifact = self.artifacts.load_artifact_owned(expected, head.owner).await?;
        if artifact.contents.as_bytes() != object.bytes() {
            return Err(DepositSyncStageError::MissingReadback);
        }
        Ok(expected)
    }

    /// Build the constant-size marker which must be committed by the wallet-snapshot CAS.
    pub async fn import_marker(&self) -> Result<DepositSyncImportMarker, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (_, head) = self.load_existing_spool_head().await?;
        prepared_import_marker(&head)
    }

    /// Deterministically enumerate one bounded page of permanent references for recovery cleanup.
    pub async fn prepared_reference_page(
        &self,
        marker: &DepositSyncImportMarker,
        cursor: Option<&[u8]>,
    ) -> Result<DepositSyncPreparedReferencePage, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (_, head) = self.load_existing_spool_head().await?;
        verify_prepared_import_marker(marker, &head)?;
        let marker_digest = marker.digest()?;
        let (position, remaining_pages) = match cursor {
            Some(bytes) => {
                let cursor: DepositSyncPreparedReferenceCursor = decode_canonical(
                    bytes,
                    DEPOSIT_SYNC_IMPORT_CURSOR_BYTES,
                    "deposit sync prepared-reference cursor",
                )?;
                if cursor.version != DEPOSIT_SYNC_IMPORT_CURSOR_VERSION
                    || cursor.marker != marker_digest
                    || cursor.remaining_pages == 0
                    || cursor.remaining_pages > head.page_count
                    || cursor.position.ordinal.checked_add(1) != Some(cursor.remaining_pages)
                {
                    return Err(DepositSyncStageError::InvalidImportMarker);
                }
                self.validate_spool_page_link(cursor.position)?;
                (Some(cursor.position), cursor.remaining_pages)
            }
            None => (head.committed, head.page_count),
        };
        let Some(position) = position else {
            if remaining_pages != 0 {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            return Ok(DepositSyncPreparedReferencePage {
                references: Vec::new(),
                next_cursor: None,
            });
        };
        let page = self.load_spool_page(head.owner, position).await?;
        let references = page
            .entries
            .iter()
            .map(|entry| entry.reference.storage_reference().map_err(Into::into))
            .collect::<Result<Vec<_>, DepositSyncStageError>>()?;
        let remaining_pages =
            remaining_pages.checked_sub(1).ok_or(DepositSyncStageError::InvalidImportMarker)?;
        let next_cursor = match (page.previous, remaining_pages) {
            (Some(position), remaining_pages @ 1..) => {
                let cursor = DepositSyncPreparedReferenceCursor {
                    version: DEPOSIT_SYNC_IMPORT_CURSOR_VERSION,
                    marker: marker_digest,
                    position,
                    remaining_pages,
                };
                Some(encode_canonical(
                    &cursor,
                    DEPOSIT_SYNC_IMPORT_CURSOR_BYTES,
                    "deposit sync prepared-reference cursor",
                )?)
            }
            (None, 0) => None,
            _ => return Err(DepositSyncStageError::InvalidImportMarker),
        };
        Ok(DepositSyncPreparedReferencePage { references, next_cursor })
    }

    /// Journal reservation release before relinquishing the first materialized artifact.
    async fn begin_prepared_import_release(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if let Some(release) = head.ownership_release {
            validate_ownership_release(release, &head)?;
            if release.marker != *marker {
                return Err(DepositSyncStageError::InvalidImportMarker);
            }
            return Ok(());
        }
        verify_prepared_import_marker(marker, &head)?;
        head.ownership_release = Some(DepositSyncSpoolOwnershipRelease {
            marker: *marker,
            position: head.committed,
            remaining_pages: head.page_count,
        });
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    /// Resume the authenticated page-at-a-time reservation-release journal.
    async fn resume_prepared_import_release(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<(), DepositSyncStageError> {
        while !self.resume_prepared_import_release_page(marker).await? {
            tokio::task::yield_now().await;
        }
        Ok(())
    }

    /// Release at most one immutable spool page, then durably advance the authenticated cursor.
    ///
    /// Releasing the mutation guard between pages keeps unrelated reads responsive. Cancellation
    /// before the cursor write replays only this bounded page; cancellation afterwards starts at
    /// its predecessor.
    async fn resume_prepared_import_release_page(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<bool, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        let release = head.ownership_release.ok_or(DepositSyncStageError::InvalidImportMarker)?;
        validate_ownership_release(release, &head)?;
        if release.marker != *marker {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        let Some(link) = release.position else {
            return Ok(true);
        };
        let page = self.load_spool_page(head.owner, link).await?;
        let mut references = Vec::with_capacity(page.entries.len());
        for entry in &page.entries {
            let reference = entry.reference.storage_reference()?;
            let artifact = self.artifacts.load_artifact_owned(reference, head.owner).await?;
            let expected = WalletArtifactRef::for_contents(
                reference.wallet_id(),
                reference.kind(),
                artifact.contents.as_bytes(),
            )?;
            if expected != reference {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            references.push(reference);
        }
        for reference in references {
            let _ = self.artifacts.release_artifact_ownership(reference, head.owner).await?;
        }
        let remaining_pages = release
            .remaining_pages
            .checked_sub(1)
            .ok_or(DepositSyncStageError::InvalidSpoolCursor)?;
        match (page.previous, remaining_pages) {
            (Some(previous), remaining @ 1..)
                if previous.ordinal.checked_add(1) == Some(remaining) => {}
            (None, 0) => {}
            _ => return Err(DepositSyncStageError::InvalidSpoolCursor),
        }
        head.ownership_release = Some(DepositSyncSpoolOwnershipRelease {
            marker: *marker,
            position: page.previous,
            remaining_pages,
        });
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(remaining_pages == 0)
    }

    async fn prepared_import_release_is_complete(
        &self,
        marker: &DepositSyncImportMarker,
    ) -> Result<bool, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (_, head) = self.load_existing_spool_head().await?;
        let release = head.ownership_release.ok_or(DepositSyncStageError::InvalidImportMarker)?;
        validate_ownership_release(release, &head)?;
        if release.marker != *marker {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        Ok(release.position.is_none() && release.remaining_pages == 0)
    }

    async fn prepared_import_release_marker(
        &self,
    ) -> Result<Option<DepositSyncImportMarker>, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (_, head) = self.load_existing_spool_head().await?;
        let Some(release) = head.ownership_release else {
            return Ok(None);
        };
        validate_ownership_release(release, &head)?;
        Ok(Some(release.marker))
    }

    /// Abort a pre-CAS import without blaming a source, then return to the verified reducer state.
    ///
    /// Materialized artifacts remain reserved by this frozen spool. Removing them before persisting
    /// the phase transition creates a cancellation window in which the durable scan has advanced
    /// past missing artifacts. Keeping them is bounded by the admitted candidate quota and makes a
    /// retry content-addressed and idempotent; candidate deletion remains the sole cleanup owner.
    pub async fn abort_prepared_import(
        &self,
        marker: Option<&DepositSyncImportMarker>,
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.ownership_release.is_some() {
            return Err(DepositSyncStageError::PreparedImportDispositionRequired);
        }
        if !matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
        ) {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        if let Some(marker) = marker {
            verify_prepared_import_marker(marker, &head)?;
        } else if head.checkpoint.phase == DepositSyncSpoolPhase::ReadyToCas {
            return Err(DepositSyncStageError::InvalidImportMarker);
        }
        let cursor = head.checkpoint.cursor.clone();
        head.checkpoint = head.checkpoint.successor(DepositSyncSpoolPhase::Verified, cursor)?;
        head.scan = None;
        self.persist_spool_head(Some(metadata), &head).await?;
        *self.runtime_page.lock().await = None;
        Ok(())
    }

    pub async fn stats(&self) -> Result<DepositSyncSpoolStats, DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (_, head) = self.load_or_create_spool_head().await?;
        spool_stats(&head)
    }

    fn frozen_reader(&self, object_count: u64) -> FrozenDepositSyncCandidate {
        FrozenDepositSyncCandidate {
            binding: self.binding,
            membership: Arc::clone(&self.membership),
            lookup_key: Arc::clone(&self.lookup_key),
            value_key: Arc::clone(&self.value_key),
            object_count,
            local_read_fault: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl FrozenDepositSyncCandidate {
    #[must_use]
    pub const fn object_count(&self) -> u64 {
        self.object_count
    }

    #[must_use]
    pub const fn wallet(&self) -> crate::deposit_wallet::DepositWalletId {
        self.binding.key.wallet_id
    }

    /// Report whether a synchronous verifier reader observed a local database or authentication
    /// failure. Callers must retain the source variant when this is true.
    #[must_use]
    pub fn has_local_read_fault(&self) -> bool {
        self.local_read_fault.load(Ordering::Acquire)
    }

    pub fn load_object(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<Option<DepositSyncObject>, DepositSyncStageError> {
        let lookup = spool_membership_lookup(self.binding, self.lookup_key.as_ref(), reference)?;
        let result: Result<Option<DepositSyncObject>, DepositSyncStageError> = (|| {
            let transaction = self.membership.begin_read().map_spool_database()?;
            let table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
            let Some(value) = table.get(lookup.as_slice()).map_spool_database()? else {
                return Ok(None);
            };
            let record = open_spool_membership_record(
                self.binding,
                self.lookup_key.as_ref(),
                self.value_key.as_ref(),
                lookup,
                value.value(),
            )?;
            if record.reference != reference {
                return Err(DepositSyncStageError::MembershipIndexConflict);
            }
            Ok(Some(DepositSyncObject::new(record.reference, record.bytes)?))
        })();
        if result.is_err() {
            self.local_read_fault.store(true, Ordering::Release);
        }
        result
    }

    pub fn load_bytes(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<Option<Vec<u8>>, DepositSyncStageError> {
        Ok(self.load_object(reference)?.map(|object| object.bytes().to_vec()))
    }

    pub fn load_archive(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<Vec<u8>, DepositSyncStageError> {
        self.load_bytes(DepositSyncObjectRef::CertificateArchive(reference))?
            .ok_or(DepositSyncStageError::UnknownObject)
    }
}

impl CompactRegistryObjectReader for FrozenDepositSyncCandidate {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        self.load_bytes(DepositSyncObjectRef::Registry(reference))
            .map_err(|_| CompactRegistryArchiveError::ObjectAuthentication)
    }
}

impl DepositIndexReader for FrozenDepositSyncCandidate {
    fn load_index_object(
        &self,
        reference: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        self.load_bytes(DepositSyncObjectRef::Index(reference))
            .map_err(|_| DepositIndexError::ObjectAuthentication)
    }
}

impl DepositSyncSpoolStore {
    async fn advance_phase(
        &self,
        expected: DepositSyncSpoolPhase,
        next: DepositSyncSpoolPhase,
        cursor: Option<Vec<u8>>,
    ) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase == next {
            if let Some(cursor) = cursor.as_deref()
                && head.checkpoint.cursor.as_slice() != cursor
            {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            return Ok(());
        }
        if head.checkpoint.phase != expected
            || head.pending.is_some()
            || head.deletion.is_some()
            || head.scan.is_some()
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let cursor = cursor.unwrap_or_else(|| head.checkpoint.cursor.clone());
        head.checkpoint = head.checkpoint.successor(next, cursor)?;
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    fn verify_existing_objects(
        &self,
        objects: &[DepositSyncObject],
    ) -> Result<(), DepositSyncStageError> {
        let mut unique = BTreeSet::new();
        for object in objects {
            if !unique.insert(object.reference()) {
                return Err(DepositSyncStageError::DuplicateSpoolObject);
            }
            let record = self
                .membership_record(object.reference())?
                .ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
            if record.bytes.as_slice() != object.bytes() {
                return Err(DepositSyncStageError::ReferenceFork);
            }
        }
        Ok(())
    }

    fn objects_are_all_present(
        &self,
        objects: &[DepositSyncObject],
    ) -> Result<bool, DepositSyncStageError> {
        let mut unique = BTreeSet::new();
        let mut all_present = true;
        for object in objects {
            if !unique.insert(object.reference()) {
                return Err(DepositSyncStageError::DuplicateSpoolObject);
            }
            match self.membership_record(object.reference())? {
                Some(record) if record.bytes.as_slice() == object.bytes() => {}
                Some(_) => return Err(DepositSyncStageError::ReferenceFork),
                None => all_present = false,
            }
        }
        Ok(all_present)
    }

    async fn load_existing_spool_head(
        &self,
    ) -> Result<(DepositSyncSpoolHeadMetadata, DepositSyncSpoolHead), DepositSyncStageError> {
        let loaded = self
            .protocol
            .load_deposit_sync_spool_head(self.binding.key)
            .await?
            .ok_or(DepositSyncStageError::MissingReadback)?;
        let head = self.decode_spool_head(loaded.state.as_bytes())?;
        self.reconcile_membership_index_cached(loaded.metadata, &head).await?;
        Ok((loaded.metadata, head))
    }

    async fn load_or_create_spool_head(
        &self,
    ) -> Result<(DepositSyncSpoolHeadMetadata, DepositSyncSpoolHead), DepositSyncStageError> {
        if let Some(loaded) = self.protocol.load_deposit_sync_spool_head(self.binding.key).await? {
            let head = self.decode_spool_head(loaded.state.as_bytes())?;
            self.reconcile_membership_index_cached(loaded.metadata, &head).await?;
            return Ok((loaded.metadata, head));
        }
        let head = DepositSyncSpoolHead {
            version: DEPOSIT_SYNC_SPOOL_HEAD_VERSION,
            binding: self.binding,
            owner: WalletArtifactOwner::random(&mut OsRng),
            head_response: None,
            pending_head_response: None,
            download_generation_start_revision: 0,
            response_evidence_count: 0,
            response_evidence_accumulator: [0; 32],
            committed: None,
            membership_revision: 0,
            page_count: 0,
            object_count: 0,
            plaintext_bytes: 0,
            physical_bytes: 0,
            checkpoint: DepositSyncSpoolCheckpoint::downloading(),
            last_transition: None,
            pending: None,
            scan: None,
            ownership_release: None,
            deletion: None,
        };
        let metadata = self.persist_spool_head(None, &head).await?;
        self.initialize_membership_index(&head)?;
        Ok((metadata, head))
    }

    async fn persist_spool_head(
        &self,
        expected: Option<DepositSyncSpoolHeadMetadata>,
        head: &DepositSyncSpoolHead,
    ) -> Result<DepositSyncSpoolHeadMetadata, DepositSyncStageError> {
        self.validate_spool_head(head)?;
        let encoded =
            encode_canonical(head, MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES, "deposit sync spool head")?;
        let metadata = self
            .protocol
            .save_deposit_sync_spool_head(self.binding.key, expected, &encoded, &mut OsRng)
            .await?;
        let durable = self
            .protocol
            .load_deposit_sync_spool_head(self.binding.key)
            .await?
            .ok_or(DepositSyncStageError::MissingReadback)?;
        if durable.metadata != metadata || durable.state.as_bytes() != encoded {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let decoded = self.decode_spool_head(durable.state.as_bytes())?;
        if decoded != *head {
            return Err(DepositSyncStageError::MissingReadback);
        }
        self.advance_reconciliation_after_spool_head_persist(expected, metadata, head).await?;
        Ok(metadata)
    }

    fn decode_spool_head(
        &self,
        bytes: &[u8],
    ) -> Result<DepositSyncSpoolHead, DepositSyncStageError> {
        let head =
            decode_canonical(bytes, MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES, "deposit sync spool head")?;
        self.validate_spool_head(&head)?;
        Ok(head)
    }

    async fn plan_page_locked(
        &self,
        objects: &[DepositSyncObject],
        transition: DepositSyncSpoolPageTransition,
        next_checkpoint: &DepositSyncSpoolCheckpoint,
    ) -> Result<(), DepositSyncStageError> {
        if objects.is_empty() || objects.len() > MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS {
            return Err(DepositSyncStageError::SpoolPageQuota);
        }
        let (metadata, mut head) = self.load_or_create_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        transition.validate_checkpoints(&head.checkpoint, next_checkpoint)?;
        if head.pending.is_some() {
            return Err(DepositSyncStageError::PendingSpoolPage);
        }
        if head.page_count == u64::MAX || head.membership_revision == u64::MAX {
            return Err(DepositSyncStageError::SpoolPageQuota);
        }

        let mut incoming = BTreeSet::new();
        let mut entries = Vec::with_capacity(objects.len());
        let mut added_plaintext_bytes = 0_u64;
        let mut added_physical_bytes = 0_u64;
        for object in objects {
            if object.reference().wallet() != self.binding.key.wallet_id
                || !incoming.insert(object.reference())
            {
                return Err(DepositSyncStageError::DuplicateSpoolObject);
            }
            if let Some(existing) = self.membership_record(object.reference())? {
                if existing.bytes.as_slice() != object.bytes() {
                    return Err(DepositSyncStageError::ReferenceFork);
                }
                continue;
            }
            let envelope = DepositSyncSpoolObjectEnvelope::from_object(self.binding, object)?;
            let envelope_bytes = envelope.to_bytes()?;
            let envelope = WalletArtifactRef::for_contents(
                WalletId(self.binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT,
                &envelope_bytes,
            )?;
            entries.push(DepositSyncSpoolEntry { reference: object.reference(), envelope });
            added_plaintext_bytes = added_plaintext_bytes
                .checked_add(object.reference().plaintext_len())
                .ok_or(DepositSyncStageError::ByteQuota)?;
            added_physical_bytes = added_physical_bytes
                .checked_add(envelope.plaintext_len())
                .and_then(|bytes| bytes.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                .and_then(|bytes| bytes.checked_add(object.reference().plaintext_len()))
                .and_then(|bytes| bytes.checked_add(SPOOL_INDEX_RECORD_PHYSICAL_OVERHEAD_BYTES))
                .ok_or(DepositSyncStageError::ByteQuota)?;
        }
        if added_plaintext_bytes > MAX_DEPOSIT_SYNC_SPOOL_PAGE_PLAINTEXT_BYTES {
            return Err(DepositSyncStageError::ByteQuota);
        }
        let frontier =
            DepositSyncSpoolFrontierEnvelope::new(self.binding, next_checkpoint.clone())?;
        let frontier_bytes = frontier.to_bytes()?;
        let next_checkpoint_artifact = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT,
            &frontier_bytes,
        )?;
        added_physical_bytes = added_physical_bytes
            .checked_add(next_checkpoint_artifact.plaintext_len())
            .and_then(|bytes| bytes.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
            .ok_or(DepositSyncStageError::ByteQuota)?;

        let page = DepositSyncSpoolPage {
            version: DEPOSIT_SYNC_SPOOL_PAGE_VERSION,
            binding: self.binding,
            owner: head.owner,
            ordinal: head.page_count,
            previous: head.committed,
            transition: transition.clone(),
            next_checkpoint: next_checkpoint_artifact,
            entries: entries.clone(),
        };
        self.validate_spool_page(head.owner, &page)?;
        let page_bytes =
            encode_canonical(&page, MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES, "deposit sync spool page")?;
        let page_artifact = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT,
            &page_bytes,
        )?;
        added_physical_bytes = added_physical_bytes
            .checked_add(page_artifact.plaintext_len())
            .and_then(|bytes| bytes.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
            .ok_or(DepositSyncStageError::ByteQuota)?;

        let next_objects = head
            .object_count
            .checked_add(
                u64::try_from(entries.len()).map_err(|_| DepositSyncStageError::Serialization)?,
            )
            .ok_or(DepositSyncStageError::ObjectQuota)?;
        if next_objects > self.binding.maximum_objects {
            return Err(DepositSyncStageError::ObjectQuota);
        }
        let _next_plaintext = head
            .plaintext_bytes
            .checked_add(added_plaintext_bytes)
            .ok_or(DepositSyncStageError::ByteQuota)?;
        let _next_physical = head
            .physical_bytes
            .checked_add(added_physical_bytes)
            .ok_or(DepositSyncStageError::ByteQuota)?;
        if added_physical_bytes > MAX_DEPOSIT_SYNC_SPOOL_PAGE_PHYSICAL_BYTES {
            return Err(DepositSyncStageError::ByteQuota);
        }
        head.pending = Some(DepositSyncSpoolPendingPage {
            page: DepositSyncSpoolPageLink { artifact: page_artifact, ordinal: page.ordinal },
            previous: page.previous,
            transition,
            next_checkpoint: next_checkpoint_artifact,
            entries,
            added_plaintext_bytes,
            added_physical_bytes,
            next_membership_revision: head
                .membership_revision
                .checked_add(1)
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?,
        });
        self.persist_spool_head(Some(metadata), &head).await?;
        Ok(())
    }

    async fn write_pending_page_locked(
        &self,
        objects: &[DepositSyncObject],
        next_checkpoint: &DepositSyncSpoolCheckpoint,
    ) -> Result<(), DepositSyncStageError> {
        let (_, head) = self.load_existing_spool_head().await?;
        let pending = head.pending.as_ref().ok_or(DepositSyncStageError::PendingSpoolPage)?;
        pending.transition.validate_checkpoints(&head.checkpoint, next_checkpoint)?;
        self.write_pending_frontier_artifact(head.owner, pending, next_checkpoint).await?;
        let by_reference =
            objects.iter().map(|object| (object.reference(), object)).collect::<BTreeMap<_, _>>();
        for entry in pending.entries.iter().copied() {
            let object =
                by_reference.get(&entry.reference).ok_or(DepositSyncStageError::ReferenceFork)?;
            let envelope = DepositSyncSpoolObjectEnvelope::from_object(self.binding, object)?;
            let bytes = envelope.to_bytes()?;
            let expected = WalletArtifactRef::for_contents(
                WalletId(self.binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT,
                &bytes,
            )?;
            if entry.reference != object.reference() || entry.envelope != expected {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            let (installed, _) = self
                .artifacts
                .create_artifact_owned(
                    head.owner,
                    WalletId(self.binding.key.wallet_id.0),
                    DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT,
                    &bytes,
                    &mut OsRng,
                )
                .await?;
            if installed != expected {
                return Err(DepositSyncStageError::ReferenceFork);
            }
            drop(self.load_spooled_object(head.owner, entry).await?);
        }
        self.write_pending_page_artifact(head.owner, pending).await
    }

    async fn write_pending_frontier_artifact(
        &self,
        owner: WalletArtifactOwner,
        pending: &DepositSyncSpoolPendingPage,
        next_checkpoint: &DepositSyncSpoolCheckpoint,
    ) -> Result<(), DepositSyncStageError> {
        let envelope =
            DepositSyncSpoolFrontierEnvelope::new(self.binding, next_checkpoint.clone())?;
        let bytes = envelope.to_bytes()?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT,
            &bytes,
        )?;
        if expected != pending.next_checkpoint {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                owner,
                WalletId(self.binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT,
                &bytes,
                &mut OsRng,
            )
            .await?;
        if installed != expected {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        let loaded = self.load_spool_checkpoint(owner, expected).await?;
        if loaded != *next_checkpoint {
            return Err(DepositSyncStageError::MissingReadback);
        }
        Ok(())
    }

    async fn write_pending_page_artifact(
        &self,
        owner: WalletArtifactOwner,
        pending: &DepositSyncSpoolPendingPage,
    ) -> Result<(), DepositSyncStageError> {
        let page = self.page_from_pending(owner, pending)?;
        let bytes =
            encode_canonical(&page, MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES, "deposit sync spool page")?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT,
            &bytes,
        )?;
        if expected != pending.page.artifact {
            return Err(DepositSyncStageError::InvalidSpoolPage);
        }
        let (installed, _) = self
            .artifacts
            .create_artifact_owned(
                owner,
                WalletId(self.binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT,
                &bytes,
                &mut OsRng,
            )
            .await?;
        if installed != expected {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        let durable = self.load_spool_page(owner, pending.page).await?;
        if durable != page {
            return Err(DepositSyncStageError::MissingReadback);
        }
        Ok(())
    }

    async fn recover_pending_locked(
        &self,
    ) -> Result<DepositSyncSpoolRecovery, DepositSyncStageError> {
        let (mut metadata, mut head) = self.load_or_create_spool_head().await?;
        if let Some(pending) = head.pending_head_response {
            if head.head_response.is_some() {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            match self.artifacts.load_artifact_owned(pending.reference, head.owner).await {
                Ok(artifact) => {
                    let envelope = DepositSyncSpoolHeadResponseEnvelope::from_bytes(
                        self.binding,
                        artifact.contents.as_bytes(),
                    )?;
                    let expected = WalletArtifactRef::for_contents(
                        WalletId(self.binding.key.wallet_id.0),
                        DEPOSIT_SYNC_SPOOL_HEAD_RESPONSE_ARTIFACT,
                        artifact.contents.as_bytes(),
                    )?;
                    if expected != pending.reference || envelope.source() != pending.source {
                        return Err(DepositSyncStageError::ReferenceFork);
                    }
                    head.head_response = Some(pending.reference);
                }
                Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    let _ = self
                        .artifacts
                        .remove_artifact_if_owned(pending.reference, head.owner)
                        .await?;
                }
                Err(error) => return Err(error.into()),
            }
            head.pending_head_response = None;
            metadata = self.persist_spool_head(Some(metadata), &head).await?;
        }
        let Some(pending) = head.pending.clone() else {
            return Ok(DepositSyncSpoolRecovery::Clean);
        };
        let mut missing = false;
        let next_checkpoint =
            match self.load_spool_checkpoint(head.owner, pending.next_checkpoint).await {
                Ok(checkpoint) => Some(checkpoint),
                Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    missing = true;
                    None
                }
                Err(error) => return Err(error),
            };
        for entry in &pending.entries {
            match self.load_spooled_object(head.owner, *entry).await {
                Ok(_) => {}
                Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                    if error.kind() == io::ErrorKind::NotFound =>
                {
                    missing = true;
                }
                Err(error) => return Err(error),
            }
        }
        if missing {
            self.rollback_prepared_membership(&head, &pending)?;
            let _ =
                self.artifacts.remove_artifact_if_owned(pending.page.artifact, head.owner).await?;
            let _ = self
                .artifacts
                .remove_artifact_if_owned(pending.next_checkpoint, head.owner)
                .await?;
            for entry in &pending.entries {
                let _ = self.artifacts.remove_artifact_if_owned(entry.envelope, head.owner).await?;
            }
            head.pending = None;
            self.persist_spool_head(Some(metadata), &head).await?;
            return Ok(DepositSyncSpoolRecovery::RolledBack);
        }
        let next_checkpoint =
            next_checkpoint.ok_or(DepositSyncStageError::InvalidSpoolTransition)?;
        pending.transition.validate_checkpoints(&head.checkpoint, &next_checkpoint)?;

        match self.load_spool_page(head.owner, pending.page).await {
            Ok(page) if page == self.page_from_pending(head.owner, &pending)? => {}
            Ok(_) => return Err(DepositSyncStageError::ReferenceFork),
            Err(DepositSyncStageError::Storage(StoreError::Io(error)))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                self.write_pending_page_artifact(head.owner, &pending).await?;
            }
            Err(error) => return Err(error),
        }
        self.prepare_membership_index(&head, &pending).await?;
        if pending.previous != head.committed
            || pending.page.ordinal != head.page_count
            || pending.next_membership_revision
                != head
                    .membership_revision
                    .checked_add(1)
                    .ok_or(DepositSyncStageError::InvalidSpoolHead)?
        {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        head.page_count =
            head.page_count.checked_add(1).ok_or(DepositSyncStageError::SpoolPageQuota)?;
        head.object_count = head
            .object_count
            .checked_add(
                u64::try_from(pending.entries.len())
                    .map_err(|_| DepositSyncStageError::Serialization)?,
            )
            .ok_or(DepositSyncStageError::ObjectQuota)?;
        head.plaintext_bytes = head
            .plaintext_bytes
            .checked_add(pending.added_plaintext_bytes)
            .ok_or(DepositSyncStageError::ByteQuota)?;
        head.physical_bytes = head
            .physical_bytes
            .checked_add(pending.added_physical_bytes)
            .ok_or(DepositSyncStageError::ByteQuota)?;
        head.committed = Some(pending.page);
        head.membership_revision = pending.next_membership_revision;
        head.checkpoint = next_checkpoint;
        head.last_transition = Some(pending.transition);
        head.pending = None;
        let next_metadata = self.persist_spool_head(Some(metadata), &head).await?;
        if let Some(previous_index) = self.finalize_membership_index(&head)? {
            self.advance_reconciliation_after_index_journal_finalize(
                metadata,
                next_metadata,
                previous_index,
                stable_index_head(self.binding, &head),
            )
            .await?;
        }
        Ok(DepositSyncSpoolRecovery::Committed)
    }

    async fn delete_contents(&self, allow_prepared: bool) -> Result<(), DepositSyncStageError> {
        let _mutation = self.mutation.lock().await;
        let _ = self.recover_pending_locked().await?;
        let (metadata, mut head) = self.load_existing_spool_head().await?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Deleting {
            match (allow_prepared, head.ownership_release) {
                (true, Some(release))
                    if release.position.is_none() && release.remaining_pages == 0 =>
                {
                    validate_ownership_release(release, &head)?;
                }
                (false, None) => {}
                _ => return Err(DepositSyncStageError::PreparedImportDispositionRequired),
            }
        }
        if matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Materializing | DepositSyncSpoolPhase::ReadyToCas
        ) && !allow_prepared
        {
            return Err(DepositSyncStageError::PreparedImportDispositionRequired);
        }
        if head.checkpoint.phase != DepositSyncSpoolPhase::Deleting {
            if head.pending.is_some() {
                return Err(DepositSyncStageError::PendingSpoolPage);
            }
            let cursor = head.checkpoint.cursor.clone();
            head.checkpoint = head.checkpoint.successor(DepositSyncSpoolPhase::Deleting, cursor)?;
            head.scan = None;
            // Marker clearance is durably represented by the catalog's Committed state before
            // this call. Clear the completed release cursor in the same authenticated write that
            // starts deletion; no abortable ReadyToCas state can reappear afterwards.
            head.ownership_release = None;
            head.deletion = Some(DepositSyncSpoolDeletion {
                position: head.committed,
                remaining_pages: head.page_count,
                remaining_objects: head.object_count,
                pending: None,
            });
            self.persist_spool_head(Some(metadata), &head).await?;
            *self.runtime_page.lock().await = None;
        }

        loop {
            let (metadata, mut head) = self.load_existing_spool_head().await?;
            let deletion = head.deletion.as_ref().ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            if deletion.remaining_pages == 0 {
                if deletion.position.is_some()
                    || deletion.remaining_objects != 0
                    || deletion.pending.is_some()
                    || head.page_count != 0
                    || head.object_count != 0
                    || head.committed.is_some()
                    || self.membership_count()? != 0
                {
                    return Err(DepositSyncStageError::InvalidSpoolHead);
                }
                if let Some(reference) = head.head_response {
                    let _ = self.artifacts.remove_artifact_if_owned(reference, head.owner).await?;
                    head.head_response = None;
                    self.persist_spool_head(Some(metadata), &head).await?;
                    continue;
                }
                // Keep the authenticated Deleting tombstone until the manager atomically renames
                // the whole exact namespace. A crash before rename can therefore always resume;
                // a crash after rename is recovered from the authenticated catalog intent.
                return Ok(());
            }

            if head.deletion.as_ref().is_some_and(|deletion| deletion.pending.is_none()) {
                let link = deletion.position.ok_or(DepositSyncStageError::InvalidSpoolHead)?;
                let page = self.load_spool_page(head.owner, link).await?;
                let removed_plaintext_bytes =
                    page.entries.iter().try_fold(0_u64, |total, entry| {
                        total
                            .checked_add(entry.reference.plaintext_len())
                            .ok_or(DepositSyncStageError::InvalidSpoolHead)
                    })?;
                let mut removed_physical_bytes =
                    page.entries.iter().try_fold(0_u64, |total, entry| {
                        total
                            .checked_add(entry.envelope.plaintext_len())
                            .and_then(|value| {
                                value.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES)
                            })
                            .and_then(|value| value.checked_add(entry.reference.plaintext_len()))
                            .and_then(|value| {
                                value.checked_add(SPOOL_INDEX_RECORD_PHYSICAL_OVERHEAD_BYTES)
                            })
                            .ok_or(DepositSyncStageError::InvalidSpoolHead)
                    })?;
                removed_physical_bytes = removed_physical_bytes
                    .checked_add(page.next_checkpoint.plaintext_len())
                    .and_then(|value| value.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                    .and_then(|value| value.checked_add(link.artifact.plaintext_len()))
                    .and_then(|value| value.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                    .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
                let pending = DepositSyncSpoolPendingDelete {
                    page: link,
                    previous: page.previous,
                    transition: page.transition,
                    frontier: page.next_checkpoint,
                    entries: page.entries,
                    removed_plaintext_bytes,
                    removed_physical_bytes,
                    next_membership_revision: head
                        .membership_revision
                        .checked_add(1)
                        .ok_or(DepositSyncStageError::InvalidSpoolHead)?,
                };
                head.deletion.as_mut().ok_or(DepositSyncStageError::InvalidSpoolHead)?.pending =
                    Some(pending);
                self.persist_spool_head(Some(metadata), &head).await?;
                continue;
            }

            let pending = head
                .deletion
                .as_ref()
                .and_then(|deletion| deletion.pending.clone())
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            self.prepare_membership_delete(&head, &pending)?;
            for entry in &pending.entries {
                // Pre-CAS abort intentionally retains any materialized permanent reservation so
                // retry stays atomic. Candidate deletion is its sole cleanup owner. Missing
                // reservations (never materialized or already released after committed CAS) are
                // idempotent preserve-content results.
                let permanent = entry.reference.storage_reference()?;
                let _ = self.artifacts.remove_artifact_if_owned(permanent, head.owner).await?;
                let _ = self.artifacts.remove_artifact_if_owned(entry.envelope, head.owner).await?;
            }
            let _ = self.artifacts.remove_artifact_if_owned(pending.frontier, head.owner).await?;
            let _ =
                self.artifacts.remove_artifact_if_owned(pending.page.artifact, head.owner).await?;

            head.page_count =
                head.page_count.checked_sub(1).ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            head.object_count = head
                .object_count
                .checked_sub(pending.entries.len() as u64)
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            head.plaintext_bytes = head
                .plaintext_bytes
                .checked_sub(pending.removed_plaintext_bytes)
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            head.physical_bytes = head
                .physical_bytes
                .checked_sub(pending.removed_physical_bytes)
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            head.committed = pending.previous;
            head.membership_revision = pending.next_membership_revision;
            let deletion = head.deletion.as_mut().ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            deletion.remaining_pages = deletion
                .remaining_pages
                .checked_sub(1)
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            deletion.remaining_objects = deletion
                .remaining_objects
                .checked_sub(pending.entries.len() as u64)
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            deletion.position = pending.previous;
            deletion.pending = None;
            let cursor =
                pending.previous.map_or_else(Vec::new, |link| link.ordinal.to_le_bytes().to_vec());
            head.checkpoint = head.checkpoint.successor(DepositSyncSpoolPhase::Deleting, cursor)?;
            let next_metadata = self.persist_spool_head(Some(metadata), &head).await?;
            if let Some(previous_index) = self.finalize_membership_index(&head)? {
                self.advance_reconciliation_after_index_journal_finalize(
                    metadata,
                    next_metadata,
                    previous_index,
                    stable_index_head(self.binding, &head),
                )
                .await?;
            }
            tokio::task::yield_now().await;
        }
    }

    fn page_from_pending(
        &self,
        owner: WalletArtifactOwner,
        pending: &DepositSyncSpoolPendingPage,
    ) -> Result<DepositSyncSpoolPage, DepositSyncStageError> {
        let page = DepositSyncSpoolPage {
            version: DEPOSIT_SYNC_SPOOL_PAGE_VERSION,
            binding: self.binding,
            owner,
            ordinal: pending.page.ordinal,
            previous: pending.previous,
            transition: pending.transition.clone(),
            next_checkpoint: pending.next_checkpoint,
            entries: pending.entries.clone(),
        };
        self.validate_spool_page(owner, &page)?;
        Ok(page)
    }

    async fn load_spool_page(
        &self,
        owner: WalletArtifactOwner,
        link: DepositSyncSpoolPageLink,
    ) -> Result<DepositSyncSpoolPage, DepositSyncStageError> {
        self.validate_spool_page_link(link)?;
        let artifact = self.artifacts.load_artifact_owned(link.artifact, owner).await?;
        let page: DepositSyncSpoolPage = decode_canonical(
            artifact.contents.as_bytes(),
            MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES,
            "deposit sync spool page",
        )?;
        self.validate_spool_page(owner, &page)?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT,
            artifact.contents.as_bytes(),
        )?;
        if expected != link.artifact || page.ordinal != link.ordinal {
            return Err(DepositSyncStageError::InvalidSpoolPage);
        }
        Ok(page)
    }

    async fn load_spool_checkpoint(
        &self,
        owner: WalletArtifactOwner,
        reference: WalletArtifactRef,
    ) -> Result<DepositSyncSpoolCheckpoint, DepositSyncStageError> {
        if reference.wallet_id() != WalletId(self.binding.key.wallet_id.0)
            || reference.kind() != DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT
            || reference.plaintext_len() == 0
            || reference.plaintext_len() > (MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES + 256) as u64
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let artifact = self.artifacts.load_artifact_owned(reference, owner).await?;
        let envelope = DepositSyncSpoolFrontierEnvelope::from_bytes(
            self.binding,
            artifact.contents.as_bytes(),
        )?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT,
            artifact.contents.as_bytes(),
        )?;
        if expected != reference {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        Ok(envelope.checkpoint)
    }

    async fn load_spooled_object(
        &self,
        owner: WalletArtifactOwner,
        entry: DepositSyncSpoolEntry,
    ) -> Result<DepositSyncObject, DepositSyncStageError> {
        self.validate_spool_entry(entry)?;
        let artifact = self.artifacts.load_artifact_owned(entry.envelope, owner).await?;
        let envelope =
            DepositSyncSpoolObjectEnvelope::from_bytes(self.binding, artifact.contents.as_bytes())?;
        if envelope.reference != entry.reference {
            return Err(DepositSyncStageError::ReferenceFork);
        }
        envelope.into_object()
    }

    fn membership_record(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<Option<DepositSyncSpoolMembershipRecord>, DepositSyncStageError> {
        let lookup = self.membership_lookup(reference)?;
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
        let Some(value) = table.get(lookup.as_slice()).map_spool_database()? else {
            return Ok(None);
        };
        let record = self.open_membership_record(lookup, value.value())?;
        if record.reference != reference {
            return Err(DepositSyncStageError::MembershipIndexConflict);
        }
        Ok(Some(record))
    }

    fn initialize_membership_index(
        &self,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        if head.membership_revision != 0
            || head.committed.is_some()
            || head.page_count != 0
            || head.object_count != 0
            || head.response_evidence_count != 0
            || head.response_evidence_accumulator != [0; 32]
            || head.pending.is_some()
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        {
            let membership = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
            let replay = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
            let response_evidence =
                transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).map_spool_database()?;
            let index = transaction.open_table(SPOOL_INDEX_TABLE).map_spool_database()?;
            if !membership.is_empty().map_spool_database()?
                || !replay.is_empty().map_spool_database()?
                || !response_evidence.is_empty().map_spool_database()?
                || !index.is_empty().map_spool_database()?
            {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        let index = stable_index_head(self.binding, head);
        self.write_index_head_in_transaction(&transaction, &index)?;
        transaction.commit()?;
        Ok(())
    }

    async fn reconcile_membership_index_cached(
        &self,
        metadata: DepositSyncSpoolHeadMetadata,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        if self.reconciliation.binding != self.binding || metadata.key != self.binding.key {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        if matches!(
            *self.reconciliation.state.lock().await,
            DepositSyncSpoolReconciliationState::Retired
        ) {
            return Err(DepositSyncStageError::MissingReadback);
        }
        let observed = match self.membership_reconciliation_identity(metadata) {
            Ok(observed) => observed,
            Err(error) => {
                let mut state = self.reconciliation.state.lock().await;
                if let DepositSyncSpoolReconciliationState::Active(cached) = &mut *state {
                    *cached = None;
                }
                return Err(error);
            }
        };
        {
            let mut state = self.reconciliation.state.lock().await;
            match &mut *state {
                DepositSyncSpoolReconciliationState::Active(Some(cached))
                    if cached == &observed =>
                {
                    return Ok(());
                }
                DepositSyncSpoolReconciliationState::Active(cached) => {
                    *cached = None;
                }
                DepositSyncSpoolReconciliationState::Retired => {
                    return Err(DepositSyncStageError::MissingReadback);
                }
            }
        }
        self.reconcile_membership_index(head).await?;
        let reconciled = self.membership_reconciliation_identity(metadata)?;
        // A reconciled stable index proves the current rows even when the authenticated protocol
        // head carries an append or deletion intent. Prepared Redb journals remain uncacheable.
        // This lets deletion recovery scan permanent evidence once rather than once per page.
        let cacheable = reconciled.index.as_ref() == Some(&stable_index_head(self.binding, head));
        let mut state = self.reconciliation.state.lock().await;
        match &mut *state {
            DepositSyncSpoolReconciliationState::Active(cached) => {
                if cacheable {
                    *cached = Some(reconciled);
                }
            }
            DepositSyncSpoolReconciliationState::Retired => {
                return Err(DepositSyncStageError::MissingReadback);
            }
        }
        Ok(())
    }

    fn reconcile_response_evidence(
        &self,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        let Some(mut index) = self.read_index_head()? else {
            if head.response_evidence_count == 0 && self.response_evidence_count()? == 0 {
                return Ok(());
            }
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        };
        match index.response_evidence.clone() {
            DepositSyncSpoolResponseEvidenceState::Stable { records, accumulator } => {
                if records != head.response_evidence_count
                    || accumulator != head.response_evidence_accumulator
                    || self.response_evidence_projection()? != (records, accumulator)
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                Ok(())
            }
            DepositSyncSpoolResponseEvidenceState::Prepared {
                prior_records,
                next_records,
                prior_accumulator,
                next_accumulator,
                transition,
            } => {
                if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading
                    || prior_records.checked_add(1) != Some(next_records)
                    || self.response_evidence_projection()? != (next_records, next_accumulator)
                    || self.page_replay_record(transition.request_digest)?.is_some()
                    || self
                        .response_evidence_record(transition.request_digest)?
                        .is_none_or(|record| record.transition != transition)
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                let checkpoint_digest = head.checkpoint.digest()?;
                let prepared_before_head = head.response_evidence_count == prior_records
                    && head.response_evidence_accumulator == prior_accumulator
                    && head.checkpoint.revision == transition.expected_revision
                    && checkpoint_digest == transition.expected_checkpoint_digest;
                let prepared_after_head = head.response_evidence_count == next_records
                    && head.response_evidence_accumulator == next_accumulator
                    && head.checkpoint.revision == transition.next_revision
                    && checkpoint_digest == transition.next_checkpoint_digest
                    && head.last_transition.as_ref() == Some(&transition);
                if prepared_before_head == prepared_after_head {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }

                let mut transaction = self.membership.begin_write()?;
                configure_spool_write(&mut transaction);
                if prepared_before_head {
                    let lookup = self.response_evidence_lookup(transition.request_digest)?;
                    let mut evidence = transaction
                        .open_table(SPOOL_RESPONSE_EVIDENCE_TABLE)
                        .map_spool_database()?;
                    if evidence.remove(lookup.as_slice()).map_spool_database()?.is_none()
                        || evidence.len().map_spool_database()? != prior_records
                    {
                        return Err(DepositSyncStageError::MembershipIndexDivergence);
                    }
                }
                index.response_evidence = DepositSyncSpoolResponseEvidenceState::Stable {
                    records: head.response_evidence_count,
                    accumulator: head.response_evidence_accumulator,
                };
                self.write_index_head_in_transaction(&transaction, &index)?;
                transaction.commit()?;
                Ok(())
            }
        }
    }

    async fn reconcile_membership_index(
        &self,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        self.reconcile_response_evidence(head)?;
        let Some(index) = self.read_index_head()? else {
            if head.membership_revision == 0
                && head.committed.is_none()
                && head.page_count == 0
                && head.object_count == 0
                && head.response_evidence_count == 0
                && head.response_evidence_accumulator == [0; 32]
                && self.membership_count()? == 0
                && self.response_evidence_count()? == 0
            {
                return self.initialize_membership_index(head);
            }
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        };
        self.validate_index_head(&index)?;
        match &index.state {
            DepositSyncSpoolIndexState::Stable { membership_revision, latest, pages, objects }
                if *membership_revision == head.membership_revision
                    && *latest == head.committed
                    && *pages == head.page_count
                    && *objects == head.object_count =>
            {
                if self.membership_count()? != *objects || self.replay_count()? != *pages {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                if let Some(latest) = latest {
                    self.verify_page_membership(head.owner, *latest).await?;
                }
                Ok(())
            }
            DepositSyncSpoolIndexState::Stable { .. } => {
                Err(DepositSyncStageError::MembershipIndexDivergence)
            }
            DepositSyncSpoolIndexState::Prepared {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            } => {
                let prepared_matches_pending = head.pending.as_ref().is_some_and(|pending| {
                    *prior_revision == head.membership_revision
                        && *next_revision == pending.next_membership_revision
                        && *prior_latest == head.committed
                        && *next_latest == pending.page
                        && *prior_pages == head.page_count
                        && head.page_count.checked_add(1) == Some(*next_pages)
                        && *prior_objects == head.object_count
                        && head.object_count.checked_add(pending.entries.len() as u64)
                            == Some(*next_objects)
                });
                if prepared_matches_pending {
                    if self.membership_count()? != *next_objects
                        || self.replay_count()? != *next_pages
                    {
                        return Err(DepositSyncStageError::MembershipIndexDivergence);
                    }
                    self.verify_pending_membership(
                        head.pending
                            .as_ref()
                            .ok_or(DepositSyncStageError::MembershipIndexDivergence)?,
                    )?;
                    return Ok(());
                }
                let prepared_matches_committed = head.pending.is_none()
                    && *next_revision == head.membership_revision
                    && Some(*next_latest) == head.committed
                    && *next_pages == head.page_count
                    && *next_objects == head.object_count;
                if !prepared_matches_committed
                    || self.membership_count()? != *next_objects
                    || self.replay_count()? != *next_pages
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                self.verify_page_membership(head.owner, *next_latest).await?;
                self.finalize_membership_index(head).map(|_| ())
            }
            DepositSyncSpoolIndexState::PreparedDelete {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            } => {
                let prepared_matches_pending = head
                    .deletion
                    .as_ref()
                    .and_then(|deletion| deletion.pending.as_ref())
                    .is_some_and(|pending| {
                        *prior_revision == head.membership_revision
                            && *next_revision == pending.next_membership_revision
                            && *prior_latest == pending.page
                            && *next_latest == pending.previous
                            && *prior_pages == head.page_count
                            && head.page_count.checked_sub(1) == Some(*next_pages)
                            && *prior_objects == head.object_count
                            && head.object_count.checked_sub(pending.entries.len() as u64)
                                == Some(*next_objects)
                    });
                if prepared_matches_pending {
                    return (self.membership_count()? == *next_objects
                        && self.replay_count()? == *next_pages)
                        .then_some(())
                        .ok_or(DepositSyncStageError::MembershipIndexDivergence);
                }
                let prepared_matches_committed =
                    head.deletion.as_ref().is_some_and(|deletion| deletion.pending.is_none())
                        && *next_revision == head.membership_revision
                        && *next_latest == head.committed
                        && *next_pages == head.page_count
                        && *next_objects == head.object_count;
                if !prepared_matches_committed
                    || self.membership_count()? != *next_objects
                    || self.replay_count()? != *next_pages
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                self.finalize_membership_index(head).map(|_| ())
            }
        }
    }

    fn prepare_response_evidence(
        &self,
        head: &DepositSyncSpoolHead,
        transition: &DepositSyncSpoolPageTransition,
    ) -> Result<(), DepositSyncStageError> {
        transition.validate()?;
        if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading
            || head.pending.is_some()
            || head.deletion.is_some()
            || transition.expected_revision != head.checkpoint.revision
            || transition.expected_checkpoint_digest != head.checkpoint.digest()?
            || self.page_replay_record(transition.request_digest)?.is_some()
            || self.response_evidence_record(transition.request_digest)?.is_some()
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let mut index =
            self.read_index_head()?.ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        if index != stable_index_head(self.binding, head)
            || self.membership_count()? != head.object_count
            || self.replay_count()? != head.page_count
            || self.response_evidence_count()? != head.response_evidence_count
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let next_records = head
            .response_evidence_count
            .checked_add(1)
            .ok_or(DepositSyncStageError::ObjectQuota)?;
        if next_records > maximum_response_evidence_records(self.binding)? {
            return Err(DepositSyncStageError::ObjectQuota);
        }
        let commitment = response_evidence_commitment(self.binding, transition)?;
        let next_accumulator =
            xor_response_evidence_accumulator(head.response_evidence_accumulator, commitment);
        let lookup = self.response_evidence_lookup(transition.request_digest)?;
        let record = DepositSyncSpoolReplayRecord {
            version: DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION,
            binding: self.binding,
            transition: transition.clone(),
        };
        let encoded = self.seal_index_value(
            SPOOL_RESPONSE_EVIDENCE_VALUE_LABEL,
            &lookup,
            &record,
            MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
        )?;
        index.response_evidence = DepositSyncSpoolResponseEvidenceState::Prepared {
            prior_records: head.response_evidence_count,
            next_records,
            prior_accumulator: head.response_evidence_accumulator,
            next_accumulator,
            transition: transition.clone(),
        };
        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        {
            let mut evidence =
                transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).map_spool_database()?;
            if evidence.get(lookup.as_slice()).map_spool_database()?.is_some() {
                return Err(DepositSyncStageError::ResponseEquivocation);
            }
            evidence.insert(lookup.as_slice(), encoded.as_slice()).map_spool_database()?;
            if evidence.len().map_spool_database()? != next_records {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        self.write_index_head_in_transaction(&transaction, &index)?;
        transaction.commit()?;
        Ok(())
    }

    fn finalize_response_evidence(
        &self,
        head: &DepositSyncSpoolHead,
        transition: &DepositSyncSpoolPageTransition,
    ) -> Result<(), DepositSyncStageError> {
        let mut index =
            self.read_index_head()?.ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        let expected = stable_index_head(self.binding, head);
        if index == expected {
            return (self.response_evidence_count()? == head.response_evidence_count
                && self
                    .response_evidence_record(transition.request_digest)?
                    .is_some_and(|record| record.transition == *transition))
            .then_some(())
            .ok_or(DepositSyncStageError::MembershipIndexDivergence);
        }
        let DepositSyncSpoolResponseEvidenceState::Prepared {
            prior_records,
            next_records,
            prior_accumulator,
            next_accumulator,
            transition: prepared,
        } = index.response_evidence.clone()
        else {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        };
        if prepared != *transition
            || prior_records.checked_add(1) != Some(next_records)
            || next_records != head.response_evidence_count
            || prior_accumulator
                != xor_response_evidence_accumulator(
                    next_accumulator,
                    response_evidence_commitment(self.binding, transition)?,
                )
            || next_accumulator != head.response_evidence_accumulator
            || head.checkpoint.revision != transition.next_revision
            || head.checkpoint.digest()? != transition.next_checkpoint_digest
            || head.last_transition.as_ref() != Some(transition)
            || self.response_evidence_count()? != next_records
            || self
                .response_evidence_record(transition.request_digest)?
                .is_none_or(|record| record.transition != *transition)
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        index.response_evidence = DepositSyncSpoolResponseEvidenceState::Stable {
            records: next_records,
            accumulator: next_accumulator,
        };
        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        self.write_index_head_in_transaction(&transaction, &index)?;
        transaction.commit()?;
        Ok(())
    }

    async fn advance_reconciliation_after_spool_head_persist(
        &self,
        previous: Option<DepositSyncSpoolHeadMetadata>,
        next: DepositSyncSpoolHeadMetadata,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        let Some(previous) = previous else {
            return Ok(());
        };
        if previous.key != self.binding.key
            || next.key != self.binding.key
            || previous.revision.checked_add(1) != Some(next.revision)
            || next.previous_snapshot_hash != previous.snapshot_hash
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let expected_next = stable_index_head(self.binding, head);
        let observed = match self.membership_reconciliation_identity(next) {
            Ok(observed) => observed,
            Err(error) => {
                let mut state = self.reconciliation.state.lock().await;
                if let DepositSyncSpoolReconciliationState::Active(cached) = &mut *state {
                    *cached = None;
                }
                return Err(error);
            }
        };
        let prepared_endpoints = observed.index.as_ref().and_then(prepared_index_stable_endpoints);
        let mut state = self.reconciliation.state.lock().await;
        match &mut *state {
            DepositSyncSpoolReconciliationState::Active(cached) => {
                if let Some(identity) = cached.as_mut() {
                    let exact_unchanged_index = identity.head == previous
                        && identity.index.as_ref() == Some(&expected_next)
                        && identity.index == observed.index
                        && identity.sealed_index_digest.is_some()
                        && identity.sealed_index_digest == observed.sealed_index_digest
                        && identity.membership_write_generation
                            == observed.membership_write_generation;
                    let exact_prepared_successor = identity.head == previous
                        && identity.sealed_index_digest.is_some()
                        && observed.sealed_index_digest.is_some()
                        && identity.membership_write_generation.checked_add(1)
                            == Some(observed.membership_write_generation)
                        && prepared_endpoints.as_ref().is_some_and(|(prior, successor)| {
                            identity.index.as_ref() == Some(prior) && successor == &expected_next
                        });
                    if exact_unchanged_index {
                        identity.head = next;
                    } else if !exact_prepared_successor {
                        *cached = None;
                    }
                }
            }
            DepositSyncSpoolReconciliationState::Retired => {
                return Err(DepositSyncStageError::MissingReadback);
            }
        }
        Ok(())
    }

    async fn advance_reconciliation_after_response_evidence_persist(
        &self,
        previous: DepositSyncSpoolHeadMetadata,
        next: DepositSyncSpoolHeadMetadata,
        previous_owner: WalletArtifactOwner,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        if previous.key != self.binding.key
            || next.key != self.binding.key
            || previous.revision.checked_add(1) != Some(next.revision)
            || next.previous_snapshot_hash != previous.snapshot_hash
            || head.owner != previous_owner
            || head.pending.is_some()
            || head.deletion.is_some()
            || head.response_evidence_count == 0
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let expected_next = stable_index_head(self.binding, head);
        let mut expected_previous = expected_next.clone();
        expected_previous.response_evidence = DepositSyncSpoolResponseEvidenceState::Stable {
            records: head.response_evidence_count - 1,
            accumulator: xor_response_evidence_accumulator(
                head.response_evidence_accumulator,
                response_evidence_commitment(
                    self.binding,
                    head.last_transition
                        .as_ref()
                        .ok_or(DepositSyncStageError::MembershipIndexDivergence)?,
                )?,
            ),
        };
        self.advance_reconciliation_after_index_journal_finalize(
            previous,
            next,
            expected_previous,
            expected_next,
        )
        .await
    }

    async fn advance_reconciliation_after_index_journal_finalize(
        &self,
        previous: DepositSyncSpoolHeadMetadata,
        next: DepositSyncSpoolHeadMetadata,
        expected_previous: DepositSyncSpoolIndexHead,
        expected_next: DepositSyncSpoolIndexHead,
    ) -> Result<(), DepositSyncStageError> {
        if previous.key != self.binding.key
            || next.key != self.binding.key
            || previous.revision.checked_add(1) != Some(next.revision)
            || next.previous_snapshot_hash != previous.snapshot_hash
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        self.validate_index_head(&expected_previous)?;
        self.validate_index_head(&expected_next)?;
        let observed_next = match self.membership_reconciliation_identity(next) {
            Ok(observed) => observed,
            Err(error) => {
                let mut state = self.reconciliation.state.lock().await;
                if let DepositSyncSpoolReconciliationState::Active(cached) = &mut *state {
                    *cached = None;
                }
                return Err(error);
            }
        };
        if observed_next.index.as_ref() != Some(&expected_next)
            || observed_next.sealed_index_digest.is_none()
        {
            let mut state = self.reconciliation.state.lock().await;
            if let DepositSyncSpoolReconciliationState::Active(cached) = &mut *state {
                *cached = None;
            }
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let mut state = self.reconciliation.state.lock().await;
        match &mut *state {
            DepositSyncSpoolReconciliationState::Active(Some(cached))
                if cached.head == previous
                    && cached.index.as_ref() == Some(&expected_previous)
                    && cached.sealed_index_digest.is_some()
                    && cached.membership_write_generation.checked_add(2)
                        == Some(observed_next.membership_write_generation) =>
            {
                *cached = observed_next;
            }
            DepositSyncSpoolReconciliationState::Active(cached) => {
                *cached = None;
            }
            DepositSyncSpoolReconciliationState::Retired => {
                return Err(DepositSyncStageError::MissingReadback);
            }
        }
        Ok(())
    }

    async fn prepare_membership_index(
        &self,
        head: &DepositSyncSpoolHead,
        pending: &DepositSyncSpoolPendingPage,
    ) -> Result<(), DepositSyncStageError> {
        let current =
            self.read_index_head()?.ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        if matches!(
            current.state,
            DepositSyncSpoolIndexState::Prepared {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            } if prior_revision == head.membership_revision
                && next_revision == pending.next_membership_revision
                && prior_latest == head.committed
                && next_latest == pending.page
                && prior_pages == head.page_count
                && head.page_count.checked_add(1) == Some(next_pages)
                && prior_objects == head.object_count
                && head.object_count.checked_add(pending.entries.len() as u64)
                    == Some(next_objects)
        ) {
            self.verify_pending_membership(pending)?;
            return Ok(());
        }
        if current != stable_index_head(self.binding, head)
            || self.membership_count()? != head.object_count
            || self.replay_count()? != head.page_count
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let next_pages =
            head.page_count.checked_add(1).ok_or(DepositSyncStageError::SpoolPageQuota)?;
        let next_objects = head
            .object_count
            .checked_add(
                u64::try_from(pending.entries.len())
                    .map_err(|_| DepositSyncStageError::Serialization)?,
            )
            .ok_or(DepositSyncStageError::ObjectQuota)?;
        let prepared = DepositSyncSpoolIndexHead {
            version: DEPOSIT_SYNC_SPOOL_INDEX_VERSION,
            binding: self.binding,
            response_evidence: DepositSyncSpoolResponseEvidenceState::Stable {
                records: head.response_evidence_count,
                accumulator: head.response_evidence_accumulator,
            },
            state: DepositSyncSpoolIndexState::Prepared {
                prior_revision: head.membership_revision,
                next_revision: pending.next_membership_revision,
                prior_latest: head.committed,
                next_latest: pending.page,
                prior_pages: head.page_count,
                next_pages,
                prior_objects: head.object_count,
                next_objects,
            },
        };
        self.validate_index_head(&prepared)?;
        let mut records = Vec::with_capacity(pending.entries.len());
        for (index, entry) in pending.entries.iter().copied().enumerate() {
            let object = self.load_spooled_object(head.owner, entry).await?;
            let entry_index =
                u16::try_from(index).map_err(|_| DepositSyncStageError::SpoolPageQuota)?;
            let record = DepositSyncSpoolMembershipRecord {
                version: DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION,
                binding: self.binding,
                reference: entry.reference,
                envelope: entry.envelope,
                first_page: pending.page,
                entry_index,
                bytes: object.bytes().to_vec(),
            };
            self.validate_membership_record(&record)?;
            records.push(record);
        }

        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        {
            let mut table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
            for record in records {
                let lookup = self.membership_lookup(record.reference)?;
                if table.get(lookup.as_slice()).map_spool_database()?.is_some() {
                    return Err(DepositSyncStageError::DuplicateSpoolObject);
                }
                let encoded = self.seal_membership_record(lookup, &record)?;
                table.insert(lookup.as_slice(), encoded.as_slice()).map_spool_database()?;
            }
            if table.len().map_spool_database()? != next_objects {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        {
            let lookup = self.replay_lookup(pending.transition.request_digest)?;
            let record = DepositSyncSpoolReplayRecord {
                version: DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION,
                binding: self.binding,
                transition: pending.transition.clone(),
            };
            let encoded = self.seal_index_value(
                SPOOL_REPLAY_VALUE_LABEL,
                &lookup,
                &record,
                MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
            )?;
            let mut replay = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
            if replay.get(lookup.as_slice()).map_spool_database()?.is_some() {
                return Err(DepositSyncStageError::ResponseEquivocation);
            }
            replay.insert(lookup.as_slice(), encoded.as_slice()).map_spool_database()?;
            if replay.len().map_spool_database()? != next_pages {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        self.write_index_head_in_transaction(&transaction, &prepared)?;
        transaction.commit()?;
        Ok(())
    }

    fn prepare_membership_delete(
        &self,
        head: &DepositSyncSpoolHead,
        pending: &DepositSyncSpoolPendingDelete,
    ) -> Result<(), DepositSyncStageError> {
        let current =
            self.read_index_head()?.ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        let next_pages =
            head.page_count.checked_sub(1).ok_or(DepositSyncStageError::InvalidSpoolHead)?;
        let next_objects = head
            .object_count
            .checked_sub(pending.entries.len() as u64)
            .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
        let prepared = DepositSyncSpoolIndexHead {
            version: DEPOSIT_SYNC_SPOOL_INDEX_VERSION,
            binding: self.binding,
            response_evidence: DepositSyncSpoolResponseEvidenceState::Stable {
                records: head.response_evidence_count,
                accumulator: head.response_evidence_accumulator,
            },
            state: DepositSyncSpoolIndexState::PreparedDelete {
                prior_revision: head.membership_revision,
                next_revision: pending.next_membership_revision,
                prior_latest: pending.page,
                next_latest: pending.previous,
                prior_pages: head.page_count,
                next_pages,
                prior_objects: head.object_count,
                next_objects,
            },
        };
        self.validate_index_head(&prepared)?;
        if current == prepared {
            if self.membership_count()? != next_objects || self.replay_count()? != next_pages {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
            return Ok(());
        }
        if current != stable_index_head(self.binding, head)
            || self.membership_count()? != head.object_count
            || self.replay_count()? != head.page_count
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }

        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        {
            let mut table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
            for entry in &pending.entries {
                let lookup = self.membership_lookup(entry.reference)?;
                let encoded = table
                    .get(lookup.as_slice())
                    .map_spool_database()?
                    .ok_or(DepositSyncStageError::MembershipIndexDivergence)?
                    .value()
                    .to_vec();
                let record = self.open_membership_record(lookup, &encoded)?;
                if record.reference != entry.reference
                    || record.envelope != entry.envelope
                    || record.first_page != pending.page
                {
                    return Err(DepositSyncStageError::MembershipIndexConflict);
                }
                table.remove(lookup.as_slice()).map_spool_database()?;
            }
            if table.len().map_spool_database()? != next_objects {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        {
            let lookup = self.replay_lookup(pending.transition.request_digest)?;
            let mut replay = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
            let encoded = replay
                .get(lookup.as_slice())
                .map_spool_database()?
                .ok_or(DepositSyncStageError::MembershipIndexDivergence)?
                .value()
                .to_vec();
            let record: DepositSyncSpoolReplayRecord = self.open_index_value(
                SPOOL_REPLAY_VALUE_LABEL,
                &lookup,
                &encoded,
                MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
            )?;
            if record.transition != pending.transition {
                return Err(DepositSyncStageError::MembershipIndexConflict);
            }
            replay.remove(lookup.as_slice()).map_spool_database()?;
            if replay.len().map_spool_database()? != next_pages {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        self.write_index_head_in_transaction(&transaction, &prepared)?;
        transaction.commit()?;
        Ok(())
    }

    fn rollback_prepared_membership(
        &self,
        head: &DepositSyncSpoolHead,
        pending: &DepositSyncSpoolPendingPage,
    ) -> Result<(), DepositSyncStageError> {
        let current =
            self.read_index_head()?.ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        if current == stable_index_head(self.binding, head) {
            if self.membership_count()? != head.object_count
                || self.replay_count()? != head.page_count
            {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
            return Ok(());
        }
        let DepositSyncSpoolIndexState::Prepared {
            prior_revision,
            next_revision,
            prior_latest,
            next_latest,
            prior_pages,
            prior_objects,
            ..
        } = current.state
        else {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        };
        if prior_revision != head.membership_revision
            || next_revision != pending.next_membership_revision
            || prior_latest != head.committed
            || next_latest != pending.page
            || prior_pages != head.page_count
            || prior_objects != head.object_count
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        {
            let mut table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
            for entry in &pending.entries {
                let lookup = self.membership_lookup(entry.reference)?;
                let encoded = table
                    .get(lookup.as_slice())
                    .map_spool_database()?
                    .ok_or(DepositSyncStageError::MembershipIndexDivergence)?
                    .value()
                    .to_vec();
                let record = self.open_membership_record(lookup, &encoded)?;
                if record.reference != entry.reference || record.first_page != pending.page {
                    return Err(DepositSyncStageError::MembershipIndexConflict);
                }
                table.remove(lookup.as_slice()).map_spool_database()?;
            }
            if table.len().map_spool_database()? != head.object_count {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        {
            let lookup = self.replay_lookup(pending.transition.request_digest)?;
            let mut replay = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
            let removed = replay.remove(lookup.as_slice()).map_spool_database()?.is_some();
            if !removed || replay.len().map_spool_database()? != head.page_count {
                return Err(DepositSyncStageError::MembershipIndexDivergence);
            }
        }
        self.write_index_head_in_transaction(&transaction, &stable_index_head(self.binding, head))?;
        transaction.commit()?;
        Ok(())
    }

    fn finalize_membership_index(
        &self,
        head: &DepositSyncSpoolHead,
    ) -> Result<Option<DepositSyncSpoolIndexHead>, DepositSyncStageError> {
        let stable = stable_index_head(self.binding, head);
        let current =
            self.read_index_head()?.ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        if current == stable {
            return (self.membership_count()? == head.object_count
                && self.replay_count()? == head.page_count)
                .then_some(None)
                .ok_or(DepositSyncStageError::MembershipIndexDivergence);
        }
        let Some((prior, next)) = prepared_index_stable_endpoints(&current) else {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        };
        if !matches!(
            current.response_evidence,
            DepositSyncSpoolResponseEvidenceState::Stable { .. }
        ) || next != stable
            || self.membership_count()? != head.object_count
            || self.replay_count()? != head.page_count
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let mut transaction = self.membership.begin_write()?;
        configure_spool_write(&mut transaction);
        self.write_index_head_in_transaction(&transaction, &stable)?;
        transaction.commit()?;
        Ok(Some(prior))
    }

    fn membership_count(&self) -> Result<u64, DepositSyncStageError> {
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?;
        table.len().map_spool_database()
    }

    fn replay_count(&self) -> Result<u64, DepositSyncStageError> {
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
        table.len().map_spool_database()
    }

    fn response_evidence_count(&self) -> Result<u64, DepositSyncStageError> {
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).map_spool_database()?;
        table.len().map_spool_database()
    }

    fn response_evidence_projection(&self) -> Result<(u64, [u8; 32]), DepositSyncStageError> {
        #[cfg(test)]
        self.reconciliation.response_evidence_scans.fetch_add(1, Ordering::Relaxed);
        let transaction = self.membership.begin_read().map_spool_database()?;
        let evidence =
            transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).map_spool_database()?;
        let replay = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
        let records = evidence.len().map_spool_database()?;
        let mut accumulator = [0_u8; 32];
        for entry in evidence.iter().map_spool_database()? {
            let (key, value) = entry.map_spool_database()?;
            let lookup: [u8; 32] = key
                .value()
                .try_into()
                .map_err(|_| DepositSyncStageError::MembershipIndexConflict)?;
            let record: DepositSyncSpoolReplayRecord = self.open_index_value(
                SPOOL_RESPONSE_EVIDENCE_VALUE_LABEL,
                &lookup,
                value.value(),
                MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
            )?;
            record.transition.validate()?;
            let replay_lookup = self.replay_lookup(record.transition.request_digest)?;
            if record.version != DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION
                || record.binding != self.binding
                || self.response_evidence_lookup(record.transition.request_digest)? != lookup
                || replay.get(replay_lookup.as_slice()).map_spool_database()?.is_some()
            {
                return Err(DepositSyncStageError::MembershipIndexConflict);
            }
            accumulator = xor_response_evidence_accumulator(
                accumulator,
                response_evidence_commitment(self.binding, &record.transition)?,
            );
        }
        Ok((records, accumulator))
    }

    fn replay_lookup(&self, request_digest: [u8; 32]) -> Result<[u8; 32], DepositSyncStageError> {
        if request_digest == [0; 32] {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let mut hasher = blake3::Hasher::new_keyed(self.lookup_key.as_ref());
        hasher.update(SPOOL_REPLAY_LOOKUP_DOMAIN);
        hasher.update(&request_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    fn replay_record(
        &self,
        request_digest: [u8; 32],
    ) -> Result<Option<DepositSyncSpoolReplayRecord>, DepositSyncStageError> {
        if let Some(record) = self.page_replay_record(request_digest)? {
            if self.response_evidence_record(request_digest)?.is_some() {
                return Err(DepositSyncStageError::MembershipIndexConflict);
            }
            return Ok(Some(record));
        }
        self.response_evidence_record(request_digest)
    }

    fn page_replay_record(
        &self,
        request_digest: [u8; 32],
    ) -> Result<Option<DepositSyncSpoolReplayRecord>, DepositSyncStageError> {
        let lookup = self.replay_lookup(request_digest)?;
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?;
        let Some(value) = table.get(lookup.as_slice()).map_spool_database()? else {
            return Ok(None);
        };
        let record: DepositSyncSpoolReplayRecord = self.open_index_value(
            SPOOL_REPLAY_VALUE_LABEL,
            &lookup,
            value.value(),
            MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
        )?;
        if record.version != DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION
            || record.binding != self.binding
            || record.transition.request_digest != request_digest
        {
            return Err(DepositSyncStageError::MembershipIndexConflict);
        }
        record.transition.validate()?;
        Ok(Some(record))
    }

    fn response_evidence_lookup(
        &self,
        request_digest: [u8; 32],
    ) -> Result<[u8; 32], DepositSyncStageError> {
        if request_digest == [0; 32] {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        let mut hasher = blake3::Hasher::new_keyed(self.lookup_key.as_ref());
        hasher.update(SPOOL_RESPONSE_EVIDENCE_LOOKUP_DOMAIN);
        hasher.update(&request_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    fn response_evidence_record(
        &self,
        request_digest: [u8; 32],
    ) -> Result<Option<DepositSyncSpoolReplayRecord>, DepositSyncStageError> {
        let lookup = self.response_evidence_lookup(request_digest)?;
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).map_spool_database()?;
        let Some(value) = table.get(lookup.as_slice()).map_spool_database()? else {
            return Ok(None);
        };
        let record: DepositSyncSpoolReplayRecord = self.open_index_value(
            SPOOL_RESPONSE_EVIDENCE_VALUE_LABEL,
            &lookup,
            value.value(),
            MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
        )?;
        if record.version != DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION
            || record.binding != self.binding
            || record.transition.request_digest != request_digest
        {
            return Err(DepositSyncStageError::MembershipIndexConflict);
        }
        record.transition.validate()?;
        Ok(Some(record))
    }

    fn read_index_head(&self) -> Result<Option<DepositSyncSpoolIndexHead>, DepositSyncStageError> {
        self.read_index_head_with_digest().map(|(head, _)| head)
    }

    fn read_index_head_with_digest(
        &self,
    ) -> Result<(Option<DepositSyncSpoolIndexHead>, Option<[u8; 32]>), DepositSyncStageError> {
        let transaction = self.membership.begin_read().map_spool_database()?;
        let table = transaction.open_table(SPOOL_INDEX_TABLE).map_spool_database()?;
        let Some(value) = table.get(SPOOL_INDEX_HEAD_KEY).map_spool_database()? else {
            return Ok((None, None));
        };
        let encoded = value.value();
        let sealed_index_digest = *blake3::hash(encoded).as_bytes();
        let head = self.open_index_head(encoded)?;
        self.validate_index_head(&head)?;
        Ok((Some(head), Some(sealed_index_digest)))
    }

    fn membership_reconciliation_identity(
        &self,
        metadata: DepositSyncSpoolHeadMetadata,
    ) -> Result<DepositSyncSpoolReconciliationIdentity, DepositSyncStageError> {
        if !self.reconciliation.membership_write_generation_valid.load(Ordering::Acquire) {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let before = self.reconciliation.membership_write_generation.load(Ordering::Acquire);
        let (index, sealed_index_digest) = self.read_index_head_with_digest()?;
        let after = self.reconciliation.membership_write_generation.load(Ordering::Acquire);
        if before != after
            || !self.reconciliation.membership_write_generation_valid.load(Ordering::Acquire)
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        Ok(DepositSyncSpoolReconciliationIdentity {
            head: metadata,
            index,
            sealed_index_digest,
            membership_write_generation: after,
        })
    }

    fn write_index_head_in_transaction(
        &self,
        transaction: &redb::WriteTransaction,
        head: &DepositSyncSpoolIndexHead,
    ) -> Result<(), DepositSyncStageError> {
        self.validate_index_head(head)?;
        let encoded = self.seal_index_head(head)?;
        let mut table = transaction.open_table(SPOOL_INDEX_TABLE).map_spool_database()?;
        table.insert(SPOOL_INDEX_HEAD_KEY, encoded.as_slice()).map_spool_database()?;
        Ok(())
    }

    fn membership_lookup(
        &self,
        reference: DepositSyncObjectRef,
    ) -> Result<[u8; 32], DepositSyncStageError> {
        spool_membership_lookup(self.binding, self.lookup_key.as_ref(), reference)
    }

    fn seal_membership_record(
        &self,
        lookup: [u8; 32],
        record: &DepositSyncSpoolMembershipRecord,
    ) -> Result<Vec<u8>, DepositSyncStageError> {
        self.validate_membership_record(record)?;
        self.seal_index_value(
            SPOOL_MEMBERSHIP_VALUE_LABEL,
            &lookup,
            record,
            MAX_DEPOSIT_SYNC_SPOOL_MEMBERSHIP_RECORD_BYTES,
        )
    }

    fn open_membership_record(
        &self,
        lookup: [u8; 32],
        encoded: &[u8],
    ) -> Result<DepositSyncSpoolMembershipRecord, DepositSyncStageError> {
        let record = open_spool_membership_record(
            self.binding,
            self.lookup_key.as_ref(),
            self.value_key.as_ref(),
            lookup,
            encoded,
        )?;
        self.validate_membership_record(&record)?;
        Ok(record)
    }

    fn seal_index_head(
        &self,
        head: &DepositSyncSpoolIndexHead,
    ) -> Result<Vec<u8>, DepositSyncStageError> {
        self.seal_index_value(
            SPOOL_INDEX_VALUE_LABEL,
            SPOOL_INDEX_HEAD_KEY,
            head,
            MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
        )
    }

    fn open_index_head(
        &self,
        encoded: &[u8],
    ) -> Result<DepositSyncSpoolIndexHead, DepositSyncStageError> {
        self.open_index_value(
            SPOOL_INDEX_VALUE_LABEL,
            SPOOL_INDEX_HEAD_KEY,
            encoded,
            MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
        )
    }

    fn seal_index_value<T: Serialize>(
        &self,
        label: &[u8],
        lookup: &[u8],
        value: &T,
        maximum: usize,
    ) -> Result<Vec<u8>, DepositSyncStageError> {
        let plaintext =
            Zeroizing::new(encode_canonical(value, maximum, "deposit sync spool index plaintext")?);
        let mut nonce = [0_u8; 24];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);
        let aad = spool_index_aad(self.binding, label, lookup);
        let ciphertext =
            XChaCha20Poly1305::new(Key::from_slice(self.value_key.as_ref().as_slice()))
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload { msg: plaintext.as_slice(), aad: &aad },
                )
                .map_err(|_| DepositSyncStageError::MembershipAuthentication)?;
        encode_canonical(
            &DepositSyncSpoolSealedValue {
                version: DEPOSIT_SYNC_SPOOL_SEALED_VALUE_VERSION,
                nonce,
                ciphertext,
            },
            MAX_DEPOSIT_SYNC_SPOOL_SEALED_VALUE_BYTES,
            "sealed deposit sync spool index value",
        )
    }

    fn open_index_value<T: DeserializeOwned + Serialize>(
        &self,
        label: &[u8],
        lookup: &[u8],
        encoded: &[u8],
        maximum: usize,
    ) -> Result<T, DepositSyncStageError> {
        let sealed: DepositSyncSpoolSealedValue = decode_canonical(
            encoded,
            MAX_DEPOSIT_SYNC_SPOOL_SEALED_VALUE_BYTES,
            "sealed deposit sync spool index value",
        )?;
        if sealed.version != DEPOSIT_SYNC_SPOOL_SEALED_VALUE_VERSION {
            return Err(DepositSyncStageError::MembershipAuthentication);
        }
        let aad = spool_index_aad(self.binding, label, lookup);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new(Key::from_slice(self.value_key.as_ref().as_slice()))
                .decrypt(
                    XNonce::from_slice(&sealed.nonce),
                    Payload { msg: &sealed.ciphertext, aad: &aad },
                )
                .map_err(|_| DepositSyncStageError::MembershipAuthentication)?,
        );
        decode_canonical(plaintext.as_slice(), maximum, "deposit sync spool index plaintext")
    }

    fn verify_pending_membership(
        &self,
        pending: &DepositSyncSpoolPendingPage,
    ) -> Result<(), DepositSyncStageError> {
        let replay = self
            .replay_record(pending.transition.request_digest)?
            .ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        if replay.transition != pending.transition {
            return Err(DepositSyncStageError::ResponseEquivocation);
        }
        for (index, entry) in pending.entries.iter().enumerate() {
            let record = self
                .membership_record(entry.reference)?
                .ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
            if record.first_page != pending.page
                || usize::from(record.entry_index) != index
                || record.reference != entry.reference
                || record.envelope != entry.envelope
            {
                return Err(DepositSyncStageError::MembershipIndexConflict);
            }
        }
        Ok(())
    }

    async fn verify_page_membership(
        &self,
        owner: WalletArtifactOwner,
        link: DepositSyncSpoolPageLink,
    ) -> Result<(), DepositSyncStageError> {
        let page = self.load_spool_page(owner, link).await?;
        let checkpoint = self.load_spool_checkpoint(owner, page.next_checkpoint).await?;
        if checkpoint.revision != page.transition.next_revision
            || checkpoint.digest()? != page.transition.next_checkpoint_digest
        {
            return Err(DepositSyncStageError::InvalidSpoolTransition);
        }
        for (index, entry) in page.entries.iter().enumerate() {
            let record = self
                .membership_record(entry.reference)?
                .ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
            if record.first_page != link
                || usize::from(record.entry_index) != index
                || record.reference != entry.reference
                || record.envelope != entry.envelope
            {
                return Err(DepositSyncStageError::MembershipIndexConflict);
            }
        }
        Ok(())
    }

    fn validate_membership_record(
        &self,
        record: &DepositSyncSpoolMembershipRecord,
    ) -> Result<(), DepositSyncStageError> {
        if record.version != DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION
            || record.binding != self.binding
            || usize::from(record.entry_index) >= MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS
            || record.reference.wallet() != self.binding.key.wallet_id
            || record.envelope.wallet_id() != WalletId(self.binding.key.wallet_id.0)
            || record.envelope.kind() != DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT
            || record.envelope.plaintext_len() == 0
            || record.envelope.plaintext_len() > MAX_WALLET_ARTIFACT_BYTES as u64
        {
            return Err(DepositSyncStageError::MembershipIndexConflict);
        }
        self.validate_spool_page_link(record.first_page)?;
        record.reference.storage_reference()?;
        let object = DepositSyncObject::new(record.reference, record.bytes.clone())?;
        let envelope = DepositSyncSpoolObjectEnvelope::from_object(self.binding, &object)?;
        let envelope_bytes = envelope.to_bytes()?;
        let expected = WalletArtifactRef::for_contents(
            WalletId(self.binding.key.wallet_id.0),
            DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT,
            &envelope_bytes,
        )?;
        if expected != record.envelope {
            return Err(DepositSyncStageError::MembershipIndexConflict);
        }
        Ok(())
    }

    fn validate_index_head(
        &self,
        head: &DepositSyncSpoolIndexHead,
    ) -> Result<(), DepositSyncStageError> {
        if head.version != DEPOSIT_SYNC_SPOOL_INDEX_VERSION || head.binding != self.binding {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        let maximum_response_evidence = maximum_response_evidence_records(self.binding)?;
        match &head.response_evidence {
            DepositSyncSpoolResponseEvidenceState::Stable { records, accumulator } => {
                if *records > maximum_response_evidence
                    || (*records == 0) != (*accumulator == [0; 32])
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
            }
            DepositSyncSpoolResponseEvidenceState::Prepared {
                prior_records,
                next_records,
                prior_accumulator,
                next_accumulator,
                transition,
            } => {
                transition.validate()?;
                let commitment = response_evidence_commitment(self.binding, transition)?;
                if prior_records.checked_add(1) != Some(*next_records)
                    || *next_records > maximum_response_evidence
                    || (*prior_records == 0) != (*prior_accumulator == [0; 32])
                    || *next_accumulator
                        != xor_response_evidence_accumulator(*prior_accumulator, commitment)
                    || *next_accumulator == [0; 32]
                    || !matches!(head.state, DepositSyncSpoolIndexState::Stable { .. })
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
            }
        }
        if !matches!(&head.response_evidence, DepositSyncSpoolResponseEvidenceState::Stable { .. })
            && !matches!(head.state, DepositSyncSpoolIndexState::Stable { .. })
        {
            return Err(DepositSyncStageError::MembershipIndexDivergence);
        }
        match head.state {
            DepositSyncSpoolIndexState::Stable { membership_revision, latest, pages, objects } => {
                if membership_revision < pages {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                match latest {
                    Some(link) if link.ordinal.checked_add(1) == Some(pages) => {
                        self.validate_spool_page_link(link)?;
                    }
                    None if pages == 0 && objects == 0 => {}
                    _ => return Err(DepositSyncStageError::MembershipIndexDivergence),
                }
            }
            DepositSyncSpoolIndexState::Prepared {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            } => {
                if prior_revision < prior_pages
                    || prior_revision.checked_add(1) != Some(next_revision)
                    || prior_pages.checked_add(1) != Some(next_pages)
                    || next_latest.ordinal != prior_pages
                    || next_objects < prior_objects
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                self.validate_spool_page_link(next_latest)?;
                match prior_latest {
                    Some(link) if link.ordinal.checked_add(1) == Some(prior_pages) => {
                        self.validate_spool_page_link(link)?;
                    }
                    None if prior_pages == 0 && prior_objects == 0 => {}
                    _ => return Err(DepositSyncStageError::MembershipIndexDivergence),
                }
            }
            DepositSyncSpoolIndexState::PreparedDelete {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            } => {
                if prior_revision.checked_add(1) != Some(next_revision)
                    || prior_pages.checked_sub(1) != Some(next_pages)
                    || prior_latest.ordinal.checked_add(1) != Some(prior_pages)
                    || next_objects > prior_objects
                {
                    return Err(DepositSyncStageError::MembershipIndexDivergence);
                }
                self.validate_spool_page_link(prior_latest)?;
                match next_latest {
                    Some(link)
                        if link.ordinal.checked_add(1) == Some(next_pages)
                            && link.ordinal.checked_add(1) == Some(prior_latest.ordinal) =>
                    {
                        self.validate_spool_page_link(link)?;
                    }
                    None if next_pages == 0 && next_objects == 0 => {}
                    _ => return Err(DepositSyncStageError::MembershipIndexDivergence),
                }
            }
        }
        Ok(())
    }

    fn validate_spool_head(
        &self,
        head: &DepositSyncSpoolHead,
    ) -> Result<(), DepositSyncStageError> {
        let maximum_response_evidence = maximum_response_evidence_records(self.binding)
            .map_err(|_| DepositSyncStageError::InvalidSpoolHead)?;
        if head.version != DEPOSIT_SYNC_SPOOL_HEAD_VERSION
            || head.binding != self.binding
            || head.membership_revision < head.page_count
            || head.page_count > head.object_count
            || head.object_count > self.binding.maximum_objects
            || head.download_generation_start_revision > head.checkpoint.revision
            || head.response_evidence_count > maximum_response_evidence
            || head.response_evidence_count > head.checkpoint.revision
            || (head.response_evidence_count == 0)
                != (head.response_evidence_accumulator == [0; 32])
        {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        head.checkpoint.validate()?;
        if head.checkpoint.phase == DepositSyncSpoolPhase::Frozen {
            if let Ok(frontier) =
                DepositSyncDurableDownloadFrontier::completed_embedded(head.checkpoint.cursor())
            {
                if frontier.lease.context().network() != self.binding.key.network_id
                    || frontier.lease.context().wallet() != self.binding.key.wallet_id
                    || frontier.lease.advertisement_digest() != self.binding.candidate_root
                {
                    return Err(DepositSyncStageError::InvalidSpoolHead);
                }
            } else {
                let frontier = DepositStateExportDownloadFrontier::completed_embedded(
                    head.checkpoint.cursor(),
                )
                .map_err(|_| DepositSyncStageError::InvalidSpoolHead)?;
                if frontier.lease().context().network() != self.binding.key.network_id
                    || frontier.lease().context().wallet() != self.binding.key.wallet_id
                    || frontier.lease().requester() != self.protocol.party_id()
                    || frontier.lease().advertisement_digest() != self.binding.candidate_root
                {
                    return Err(DepositSyncStageError::InvalidSpoolHead);
                }
            }
        }
        if matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Verified
                | DepositSyncSpoolPhase::Materializing
                | DepositSyncSpoolPhase::ReadyToCas
        ) {
            let _ = DepositSyncVerifiedSummaryEnvelope::from_checkpoint_cursor(
                self.binding,
                head.object_count,
                head.checkpoint.cursor(),
            )?;
        }
        if let Some(reference) = head.head_response
            && (reference.wallet_id() != WalletId(self.binding.key.wallet_id.0)
                || reference.kind() != DEPOSIT_SYNC_SPOOL_HEAD_RESPONSE_ARTIFACT
                || reference.plaintext_len() == 0
                || reference.plaintext_len() > MAX_WALLET_ARTIFACT_BYTES as u64)
        {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        if let Some(pending) = head.pending_head_response {
            if head.head_response.is_some()
                || pending.source.0 == 0
                || pending.reference.wallet_id() != WalletId(self.binding.key.wallet_id.0)
                || pending.reference.kind() != DEPOSIT_SYNC_SPOOL_HEAD_RESPONSE_ARTIFACT
                || pending.reference.plaintext_len() == 0
                || pending.reference.plaintext_len() > MAX_WALLET_ARTIFACT_BYTES as u64
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
        }
        if !matches!(
            head.checkpoint.phase,
            DepositSyncSpoolPhase::Downloading | DepositSyncSpoolPhase::Deleting
        ) && head.head_response.is_none()
        {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        if head.checkpoint.phase != DepositSyncSpoolPhase::Deleting
            && head.membership_revision != head.page_count
        {
            return Err(DepositSyncStageError::InvalidSpoolHead);
        }
        if let Some(last) = &head.last_transition {
            last.validate()?;
            if last.expected_revision < head.download_generation_start_revision
                || last.next_revision > head.checkpoint.revision
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
        }
        head.owner.validate()?;
        match head.committed {
            None if head.page_count != 0
                || head.object_count != 0
                || head.plaintext_bytes != 0
                || head.physical_bytes != 0 =>
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            Some(link)
                if head.page_count == 0 || link.ordinal.checked_add(1) != Some(head.page_count) =>
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            Some(link) => self.validate_spool_page_link(link)?,
            None => {}
        }
        if let Some(pending) = &head.pending {
            if head.checkpoint.phase != DepositSyncSpoolPhase::Downloading
                || head.deletion.is_some()
                || head.scan.is_some()
                || pending.previous != head.committed
                || pending.page.ordinal != head.page_count
                || pending.next_membership_revision
                    != head
                        .membership_revision
                        .checked_add(1)
                        .ok_or(DepositSyncStageError::InvalidSpoolHead)?
                || pending.entries.is_empty()
                || pending.entries.len() > MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            pending.transition.validate()?;
            if pending.transition.expected_revision < head.download_generation_start_revision
                || pending.transition.expected_revision != head.checkpoint.revision
                || pending.transition.expected_checkpoint_digest != head.checkpoint.digest()?
                || head.checkpoint.revision.checked_add(1) != Some(pending.transition.next_revision)
                || pending.next_checkpoint.wallet_id() != WalletId(self.binding.key.wallet_id.0)
                || pending.next_checkpoint.kind() != DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT
                || pending.next_checkpoint.plaintext_len() == 0
                || pending.next_checkpoint.plaintext_len()
                    > (MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES + 256) as u64
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            self.validate_spool_page_link(pending.page)?;
            let mut plaintext_bytes = 0_u64;
            let mut physical_bytes = 0_u64;
            let mut unique = BTreeSet::new();
            for entry in &pending.entries {
                self.validate_spool_entry(*entry)?;
                if !unique.insert(entry.reference) {
                    return Err(DepositSyncStageError::InvalidSpoolHead);
                }
                plaintext_bytes = plaintext_bytes
                    .checked_add(entry.reference.plaintext_len())
                    .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
                physical_bytes = physical_bytes
                    .checked_add(entry.envelope.plaintext_len())
                    .and_then(|bytes| bytes.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                    .and_then(|bytes| bytes.checked_add(entry.reference.plaintext_len()))
                    .and_then(|bytes| bytes.checked_add(SPOOL_INDEX_RECORD_PHYSICAL_OVERHEAD_BYTES))
                    .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            }
            physical_bytes = physical_bytes
                .checked_add(pending.next_checkpoint.plaintext_len())
                .and_then(|bytes| bytes.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            let page = self.page_from_pending(head.owner, pending)?;
            let page_bytes = encode_canonical(
                &page,
                MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES,
                "deposit sync spool page",
            )?;
            let page_reference = WalletArtifactRef::for_contents(
                WalletId(self.binding.key.wallet_id.0),
                DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT,
                &page_bytes,
            )?;
            physical_bytes = physical_bytes
                .checked_add(page_reference.plaintext_len())
                .and_then(|bytes| bytes.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
            if page_reference != pending.page.artifact
                || plaintext_bytes != pending.added_plaintext_bytes
                || physical_bytes != pending.added_physical_bytes
                || plaintext_bytes > MAX_DEPOSIT_SYNC_SPOOL_PAGE_PLAINTEXT_BYTES
                || physical_bytes > MAX_DEPOSIT_SYNC_SPOOL_PAGE_PHYSICAL_BYTES
                || head
                    .object_count
                    .checked_add(pending.entries.len() as u64)
                    .is_none_or(|objects| objects > self.binding.maximum_objects)
                || head.plaintext_bytes.checked_add(plaintext_bytes).is_none()
                || head.physical_bytes.checked_add(physical_bytes).is_none()
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
        }
        if let Some(scan) = &head.scan {
            if head.checkpoint.phase != DepositSyncSpoolPhase::Materializing
                || head.pending.is_some()
                || head.deletion.is_some()
                || head.ownership_release.is_some()
                || scan.snapshot_pages > head.page_count
                || scan.snapshot_objects > head.object_count
                || scan.remaining_pages > scan.snapshot_pages
                || scan.remaining_objects > scan.snapshot_objects
            {
                return Err(DepositSyncStageError::InvalidSpoolCursor);
            }
            match scan.snapshot_head {
                Some(link)
                    if scan.snapshot_pages == 0
                        || link.ordinal.checked_add(1) != Some(scan.snapshot_pages) =>
                {
                    return Err(DepositSyncStageError::InvalidSpoolCursor);
                }
                Some(link) => self.validate_spool_page_link(link)?,
                None if scan.snapshot_pages != 0 || scan.snapshot_objects != 0 => {
                    return Err(DepositSyncStageError::InvalidSpoolCursor);
                }
                None => {}
            }
            if let Some(position) = scan.position {
                self.validate_spool_page_link(position)?;
                if position.ordinal >= scan.snapshot_pages {
                    return Err(DepositSyncStageError::InvalidSpoolCursor);
                }
            }
            if (scan.remaining_pages == 0) != scan.position.is_none() {
                return Err(DepositSyncStageError::InvalidSpoolCursor);
            }
        }
        if let Some(release) = head.ownership_release {
            if head.pending.is_some()
                || head.pending_head_response.is_some()
                || head.scan.is_some()
                || head.deletion.is_some()
            {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            validate_ownership_release(release, head)?;
            if let Some(position) = release.position {
                self.validate_spool_page_link(position)?;
            }
        }
        match (&head.deletion, head.checkpoint.phase) {
            (Some(deletion), DepositSyncSpoolPhase::Deleting) => {
                if head.pending.is_some()
                    || head.scan.is_some()
                    || head.ownership_release.is_some()
                    || deletion.remaining_pages != head.page_count
                    || deletion.remaining_objects != head.object_count
                    || deletion.position != head.committed
                {
                    return Err(DepositSyncStageError::InvalidSpoolHead);
                }
                if let Some(pending) = &deletion.pending {
                    let mut plaintext = 0_u64;
                    let mut physical = 0_u64;
                    let mut unique = BTreeSet::new();
                    for entry in &pending.entries {
                        self.validate_spool_entry(*entry)?;
                        if !unique.insert(entry.reference) {
                            return Err(DepositSyncStageError::InvalidSpoolHead);
                        }
                        plaintext = plaintext
                            .checked_add(entry.reference.plaintext_len())
                            .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
                        physical = physical
                            .checked_add(entry.envelope.plaintext_len())
                            .and_then(|value| {
                                value.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES)
                            })
                            .and_then(|value| value.checked_add(entry.reference.plaintext_len()))
                            .and_then(|value| {
                                value.checked_add(SPOOL_INDEX_RECORD_PHYSICAL_OVERHEAD_BYTES)
                            })
                            .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
                    }
                    physical = physical
                        .checked_add(pending.frontier.plaintext_len())
                        .and_then(|value| value.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                        .and_then(|value| value.checked_add(pending.page.artifact.plaintext_len()))
                        .and_then(|value| value.checked_add(STAGED_OBJECT_PHYSICAL_OVERHEAD_BYTES))
                        .ok_or(DepositSyncStageError::InvalidSpoolHead)?;
                    if pending.page
                        != head.committed.ok_or(DepositSyncStageError::InvalidSpoolHead)?
                        || pending.next_membership_revision
                            != head
                                .membership_revision
                                .checked_add(1)
                                .ok_or(DepositSyncStageError::InvalidSpoolHead)?
                        || pending.entries.len() > MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS
                        || pending.frontier.wallet_id() != WalletId(self.binding.key.wallet_id.0)
                        || pending.frontier.kind() != DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT
                        || plaintext != pending.removed_plaintext_bytes
                        || physical != pending.removed_physical_bytes
                    {
                        return Err(DepositSyncStageError::InvalidSpoolHead);
                    }
                    match pending.previous {
                        Some(previous)
                            if previous.ordinal.checked_add(1) == Some(pending.page.ordinal) =>
                        {
                            self.validate_spool_page_link(previous)?;
                        }
                        None if pending.page.ordinal == 0 => {}
                        _ => return Err(DepositSyncStageError::InvalidSpoolHead),
                    }
                }
            }
            (None, DepositSyncSpoolPhase::Deleting) | (Some(_), _) => {
                return Err(DepositSyncStageError::InvalidSpoolHead);
            }
            (None, _) => {}
        }
        Ok(())
    }

    fn validate_spool_page(
        &self,
        owner: WalletArtifactOwner,
        page: &DepositSyncSpoolPage,
    ) -> Result<(), DepositSyncStageError> {
        if page.version != DEPOSIT_SYNC_SPOOL_PAGE_VERSION
            || page.binding != self.binding
            || page.owner != owner
            || page.entries.is_empty()
            || page.entries.len() > MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS
            || page.next_checkpoint.wallet_id() != WalletId(self.binding.key.wallet_id.0)
            || page.next_checkpoint.kind() != DEPOSIT_SYNC_SPOOL_FRONTIER_ARTIFACT
            || page.next_checkpoint.plaintext_len() == 0
            || page.next_checkpoint.plaintext_len()
                > (MAX_DEPOSIT_SYNC_SPOOL_CHECKPOINT_BYTES + 256) as u64
        {
            return Err(DepositSyncStageError::InvalidSpoolPage);
        }
        page.transition.validate()?;
        if page.transition.expected_revision.checked_add(1) != Some(page.transition.next_revision) {
            return Err(DepositSyncStageError::InvalidSpoolPage);
        }
        owner.validate()?;
        match page.previous {
            None if page.ordinal != 0 => return Err(DepositSyncStageError::InvalidSpoolPage),
            Some(previous) if previous.ordinal.checked_add(1) != Some(page.ordinal) => {
                return Err(DepositSyncStageError::InvalidSpoolPage);
            }
            Some(previous) => self.validate_spool_page_link(previous)?,
            None => {}
        }
        let mut unique = BTreeSet::new();
        for entry in &page.entries {
            self.validate_spool_entry(*entry)?;
            if !unique.insert(entry.reference) {
                return Err(DepositSyncStageError::InvalidSpoolPage);
            }
        }
        Ok(())
    }

    fn validate_spool_page_link(
        &self,
        link: DepositSyncSpoolPageLink,
    ) -> Result<(), DepositSyncStageError> {
        if link.artifact.wallet_id() != WalletId(self.binding.key.wallet_id.0)
            || link.artifact.kind() != DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT
            || link.artifact.plaintext_len() == 0
            || link.artifact.plaintext_len() > MAX_DEPOSIT_SYNC_SPOOL_PAGE_BYTES as u64
        {
            return Err(DepositSyncStageError::InvalidSpoolPage);
        }
        Ok(())
    }

    fn validate_spool_entry(
        &self,
        entry: DepositSyncSpoolEntry,
    ) -> Result<(), DepositSyncStageError> {
        if entry.reference.wallet() != self.binding.key.wallet_id
            || entry.reference.storage_reference().is_err()
            || entry.envelope.wallet_id() != WalletId(self.binding.key.wallet_id.0)
            || entry.envelope.kind() != DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT
            || entry.envelope.plaintext_len() == 0
            || entry.envelope.plaintext_len() > MAX_WALLET_ARTIFACT_BYTES as u64
        {
            return Err(DepositSyncStageError::InvalidSpoolPage);
        }
        Ok(())
    }
}

fn stable_index_head(
    binding: DepositSyncSpoolBinding,
    head: &DepositSyncSpoolHead,
) -> DepositSyncSpoolIndexHead {
    DepositSyncSpoolIndexHead {
        version: DEPOSIT_SYNC_SPOOL_INDEX_VERSION,
        binding,
        response_evidence: DepositSyncSpoolResponseEvidenceState::Stable {
            records: head.response_evidence_count,
            accumulator: head.response_evidence_accumulator,
        },
        state: DepositSyncSpoolIndexState::Stable {
            membership_revision: head.membership_revision,
            latest: head.committed,
            pages: head.page_count,
            objects: head.object_count,
        },
    }
}

/// Return the exact stable logical endpoints authenticated by one prepared Redb journal head.
///
/// The caller must additionally bind the sealed prepared generation when it performs recovery.
/// These endpoints are used only to carry an already authenticated process-local predecessor
/// proof across the head CAS and to install the exact sealed successor after journal finalization.
fn prepared_index_stable_endpoints(
    prepared: &DepositSyncSpoolIndexHead,
) -> Option<(DepositSyncSpoolIndexHead, DepositSyncSpoolIndexHead)> {
    match (&prepared.response_evidence, &prepared.state) {
        (
            DepositSyncSpoolResponseEvidenceState::Prepared {
                prior_records,
                next_records,
                prior_accumulator,
                next_accumulator,
                ..
            },
            DepositSyncSpoolIndexState::Stable { .. },
        ) => {
            let mut prior = prepared.clone();
            prior.response_evidence = DepositSyncSpoolResponseEvidenceState::Stable {
                records: *prior_records,
                accumulator: *prior_accumulator,
            };
            let mut next = prepared.clone();
            next.response_evidence = DepositSyncSpoolResponseEvidenceState::Stable {
                records: *next_records,
                accumulator: *next_accumulator,
            };
            Some((prior, next))
        }
        (
            DepositSyncSpoolResponseEvidenceState::Stable { .. },
            DepositSyncSpoolIndexState::Prepared {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            },
        ) => {
            let mut prior = prepared.clone();
            prior.state = DepositSyncSpoolIndexState::Stable {
                membership_revision: *prior_revision,
                latest: *prior_latest,
                pages: *prior_pages,
                objects: *prior_objects,
            };
            let mut next = prepared.clone();
            next.state = DepositSyncSpoolIndexState::Stable {
                membership_revision: *next_revision,
                latest: Some(*next_latest),
                pages: *next_pages,
                objects: *next_objects,
            };
            Some((prior, next))
        }
        (
            DepositSyncSpoolResponseEvidenceState::Stable { .. },
            DepositSyncSpoolIndexState::PreparedDelete {
                prior_revision,
                next_revision,
                prior_latest,
                next_latest,
                prior_pages,
                next_pages,
                prior_objects,
                next_objects,
            },
        ) => {
            let mut prior = prepared.clone();
            prior.state = DepositSyncSpoolIndexState::Stable {
                membership_revision: *prior_revision,
                latest: Some(*prior_latest),
                pages: *prior_pages,
                objects: *prior_objects,
            };
            let mut next = prepared.clone();
            next.state = DepositSyncSpoolIndexState::Stable {
                membership_revision: *next_revision,
                latest: *next_latest,
                pages: *next_pages,
                objects: *next_objects,
            };
            Some((prior, next))
        }
        _ => None,
    }
}

fn maximum_response_evidence_records(
    binding: DepositSyncSpoolBinding,
) -> Result<u64, DepositSyncStageError> {
    binding
        .maximum_objects
        .checked_mul(
            u64::try_from(MAX_COMMITTEE_MEMBERS).map_err(|_| DepositSyncStageError::ObjectQuota)?,
        )
        .ok_or(DepositSyncStageError::ObjectQuota)
}

fn response_evidence_commitment(
    binding: DepositSyncSpoolBinding,
    transition: &DepositSyncSpoolPageTransition,
) -> Result<[u8; 32], DepositSyncStageError> {
    transition.validate()?;
    let encoded = encode_canonical(
        transition,
        MAX_DEPOSIT_SYNC_SPOOL_INDEX_RECORD_BYTES,
        "deposit sync response-evidence transition",
    )?;
    let mut hasher = blake3::Hasher::new_derive_key(SPOOL_RESPONSE_EVIDENCE_ACCUMULATOR_DOMAIN);
    hasher.update(&spool_binding_bytes(binding));
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    let commitment = *hasher.finalize().as_bytes();
    if commitment == [0; 32] {
        return Err(DepositSyncStageError::ReferenceFork);
    }
    Ok(commitment)
}

fn xor_response_evidence_accumulator(mut accumulator: [u8; 32], commitment: [u8; 32]) -> [u8; 32] {
    for (accumulator_byte, commitment_byte) in accumulator.iter_mut().zip(commitment) {
        *accumulator_byte ^= commitment_byte;
    }
    accumulator
}

fn spool_binding(
    advertisement: &DepositSyncAdvertisement,
) -> Result<DepositSyncSpoolBinding, DepositSyncStageError> {
    let context = advertisement.context();
    let key =
        DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
    key.validate()?;
    let admission = DepositSyncSpoolAdmissionKind::Ordinary;
    let binding = DepositSyncSpoolBinding {
        key,
        anchor: DepositSyncAnchorId::for_admission(advertisement, admission),
        admission,
        candidate_root: advertisement.digest(),
        maximum_objects: maximum_reachable_objects(advertisement)?,
    };
    if binding.candidate_root == [0; 32] || binding.maximum_objects == 0 {
        return Err(DepositSyncStageError::WrongContext);
    }
    Ok(binding)
}

fn certified_export_spool_binding(
    request: DepositStateExportHeadRequest,
    response: &DepositStateExportHeadResponse,
) -> Result<DepositSyncSpoolBinding, DepositSyncStageError> {
    let advertisement = response.advertisement();
    if response.request_digest() != request.digest()
        || response.semantic_transition_digest() != request.semantic_transition_digest()
        || response.seal_certificate_digest() == [0; 32]
    {
        return Err(DepositSyncStageError::InvalidAdmissionEvidence);
    }
    let context = advertisement.context();
    let key =
        DepositSyncSpoolHeadKey { network_id: context.network(), wallet_id: context.wallet() };
    key.validate()?;
    let admission = DepositSyncSpoolAdmissionKind::CertifiedExport {
        request_digest: request.digest(),
        semantic_transition: request.semantic_transition_digest(),
        seal_certificate: response.seal_certificate_digest(),
    };
    let binding = DepositSyncSpoolBinding {
        key,
        anchor: DepositSyncAnchorId::for_admission(advertisement, admission),
        admission,
        candidate_root: advertisement.digest(),
        maximum_objects: maximum_reachable_objects(advertisement)?,
    };
    if binding.candidate_root == [0; 32] || binding.maximum_objects == 0 {
        return Err(DepositSyncStageError::WrongContext);
    }
    Ok(binding)
}

fn maximum_reachable_objects(
    advertisement: &DepositSyncAdvertisement,
) -> Result<u64, DepositSyncStageError> {
    let epochs = advertisement
        .registry_archive()
        .registry()
        .active_epoch()
        .checked_add(1)
        .ok_or(DepositSyncStageError::ObjectQuota)?;
    let registry = epochs
        .checked_mul(
            u64::try_from(COMPACT_REGISTRY_APPEND_OBJECTS)
                .map_err(|_| DepositSyncStageError::ObjectQuota)?,
        )
        .and_then(|objects| {
            objects.checked_add(u64::try_from(COMPACT_REGISTRY_GENESIS_OBJECTS).ok()?)
        })
        .ok_or(DepositSyncStageError::ObjectQuota)?;
    let index = portable_reachable_objects(advertisement.portable_index())?;
    let archive = advertisement
        .certificate_archive()
        .len()
        .checked_mul(4)
        .and_then(|objects| objects.checked_add(DEPOSIT_SYNC_ARCHIVE_OBJECT_SLACK))
        .ok_or(DepositSyncStageError::ObjectQuota)?;
    registry
        .checked_add(index)
        .and_then(|objects| objects.checked_add(archive))
        .filter(|objects| *objects != 0)
        .ok_or(DepositSyncStageError::ObjectQuota)
}

fn portable_reachable_objects(
    portable: &PortableDepositIndexHead,
) -> Result<u64, DepositSyncStageError> {
    portable.maximum_reachable_objects().map_err(|_| DepositSyncStageError::ObjectQuota)
}

fn candidate_facts_are_stale(
    candidate: DepositSyncCandidateFacts,
    local: DepositSyncCandidateFacts,
) -> bool {
    match candidate.active_epoch.cmp(&local.active_epoch) {
        std::cmp::Ordering::Less => return true,
        std::cmp::Ordering::Greater => return false,
        std::cmp::Ordering::Equal => {}
    }
    if candidate.checkpoint_sequence <= local.checkpoint_sequence {
        return true;
    }
    candidate.portable_sequence < local.portable_sequence
        || (candidate.portable_sequence == local.portable_sequence
            && (candidate.portable_digest == local.portable_digest
                || candidate.ledger_head != local.ledger_head
                || candidate.next_index != local.next_index))
}

fn source_transiently_failed(active: &DepositSyncSpoolActive, source: PartyId) -> bool {
    active.failed_variants.iter().any(|failure| failure.source == source)
}

fn source_rejected(active: &DepositSyncSpoolActive, source: PartyId) -> bool {
    active.rejected_variants.iter().any(|failure| failure.source == source)
}

fn source_unavailable(active: &DepositSyncSpoolActive, source: PartyId) -> bool {
    source_transiently_failed(active, source) || source_rejected(active, source)
}

fn validate_prefix_evidence_shape(
    evidence: &DepositSyncPrefixEvidence,
    fault_bound: u16,
) -> Result<(), DepositSyncStageError> {
    let required = usize::from(
        fault_bound.checked_add(1).ok_or(DepositSyncStageError::InvalidAdmissionEvidence)?,
    );
    if evidence.source.0 == 0
        || evidence.statement_digest == [0; 32]
        || evidence.certificate_digest == [0; 32]
        || evidence.endorsers.len() != required
        || evidence.endorsers.len() > MAX_COMMITTEE_MEMBERS
        || evidence.certificate.reference.kind() != DEPOSIT_SYNC_SPOOL_PREFIX_CERTIFICATE_ARTIFACT
        || evidence.certificate.reference.plaintext_len() == 0
        || evidence.certificate.reference.plaintext_len()
            > (MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES + 1024) as u64
        || evidence.certificate.owner.validate().is_err()
    {
        return Err(DepositSyncStageError::InvalidAdmissionEvidence);
    }
    let mut previous = None;
    for signer in &evidence.endorsers {
        validate_source(*signer)?;
        if previous.is_some_and(|party| party >= *signer) {
            return Err(DepositSyncStageError::InvalidAdmissionEvidence);
        }
        previous = Some(*signer);
    }
    Ok(())
}

fn all_certified_sources_failed(active: &DepositSyncSpoolActive) -> bool {
    !active.certified_claims.is_empty()
        && active.certified_claims.keys().all(|source| source_unavailable(active, *source))
}

fn sampling_authority_is_complete_without_quorum(
    catalog: &DepositSyncSpoolCatalog,
    policy: DepositSyncSpoolAdmissionPolicy,
) -> Result<bool, DepositSyncStageError> {
    let authority_claims = catalog
        .claims
        .values()
        .filter(|claim| {
            claim.state == DepositSyncSpoolClaimState::Ready
                && claim.policy.active_epoch == policy.active_epoch
                && claim.policy.committee_digest == policy.committee_digest
                && claim.policy.committee_size == policy.committee_size
                && claim.policy.sampling_sources == policy.sampling_sources
                && claim.policy.fault_bound == policy.fault_bound
                && claim.policy.required_supporters == policy.required_supporters
        })
        .collect::<Vec<_>>();
    if authority_claims.len() != usize::from(policy.sampling_sources) {
        return Ok(false);
    }
    let mut families = BTreeMap::<(DepositSyncSupportId, [u8; 32]), usize>::new();
    for claim in authority_claims {
        let count = families.entry((claim.facts.support, claim.policy.policy_digest)).or_default();
        *count = count.checked_add(1).ok_or(DepositSyncStageError::CandidateQuota)?;
    }
    Ok(families.values().all(|count| *count < usize::from(policy.required_supporters)))
}

fn record_prefix_source_failure(
    catalog: &mut DepositSyncSpoolCatalog,
    source: PartyId,
    binding: DepositSyncSpoolBinding,
    policy: DepositSyncSpoolAdmissionPolicy,
    facts: DepositSyncCandidateFacts,
    class: DepositSyncPrefixFailureClass,
) -> Result<(), DepositSyncStageError> {
    let round = catalog.sampling_round;
    let existing = catalog.prefix_source_failures.get(&source).copied();
    if let Some(existing) = existing
        && existing.active_epoch == policy.active_epoch
        && existing.committee_digest == policy.committee_digest
        && existing.anchor == binding.anchor
        && existing.facts == facts
        && existing.last_failure_round == round
    {
        if class == DepositSyncPrefixFailureClass::Permanent && !existing.permanent {
            let failure = catalog
                .prefix_source_failures
                .get_mut(&source)
                .ok_or(DepositSyncStageError::InvalidSnapshot)?;
            failure.permanent = true;
            failure.retry_after_round = u64::MAX;
        }
        return Ok(());
    }
    let strikes = existing
        .filter(|failure| {
            failure.active_epoch == policy.active_epoch
                && failure.committee_digest == policy.committee_digest
        })
        .map_or(0, |failure| failure.strikes)
        .checked_add(1)
        .ok_or(DepositSyncStageError::CandidateQuota)?;
    let permanent = class == DepositSyncPrefixFailureClass::Permanent
        || existing.is_some_and(|failure| {
            failure.active_epoch == policy.active_epoch
                && failure.committee_digest == policy.committee_digest
                && failure.permanent
        });
    let retry_after_round = if permanent {
        u64::MAX
    } else {
        round
            .checked_add(DEPOSIT_SYNC_PREFIX_TRANSIENT_COOLDOWN_ROUNDS)
            .and_then(|round| round.checked_add(1))
            .ok_or(DepositSyncStageError::CandidateQuota)?
    };
    catalog.prefix_source_failures.insert(
        source,
        DepositSyncPrefixSourceFailure {
            source,
            anchor: binding.anchor,
            active_epoch: policy.active_epoch,
            committee_digest: policy.committee_digest,
            facts,
            strikes,
            last_failure_round: round,
            retry_after_round,
            permanent,
        },
    );
    Ok(())
}

fn prefix_source_is_eligible(catalog: &DepositSyncSpoolCatalog, source: PartyId) -> bool {
    catalog.prefix_source_failures.get(&source).is_none_or(|failure| {
        !failure.permanent && catalog.sampling_round >= failure.retry_after_round
    })
}

fn select_prefix_claim(
    catalog: &DepositSyncSpoolCatalog,
) -> Option<(PartyId, DepositSyncSpoolClaim)> {
    catalog
        .claims
        .iter()
        .filter(|(source, claim)| {
            claim.state == DepositSyncSpoolClaimState::Ready
                && prefix_source_is_eligible(catalog, **source)
        })
        .max_by_key(|(source, claim)| {
            (
                Reverse(
                    catalog
                        .prefix_source_failures
                        .get(*source)
                        .map_or(0, |failure| failure.strikes),
                ),
                claim.facts.active_epoch,
                claim.facts.checkpoint_sequence,
                claim.facts.portable_sequence,
                claim.facts.next_index,
                claim.facts.portable_digest,
                claim.facts.ledger_head,
                **source,
            )
        })
        .map(|(source, claim)| (*source, *claim))
}

fn catalog_has_release_evidence(
    catalog: &DepositSyncSpoolCatalog,
    lease: DepositSyncAnchorLease,
) -> bool {
    catalog.claims.values().any(|claim| claim.lease == lease)
        || catalog.prefix_attempt.as_ref().is_some_and(|attempt| attempt.claim.lease == lease)
        || catalog.active.as_ref().is_some_and(|active| {
            active.certified_claims.values().any(|claim| claim.lease == lease)
                || (matches!(active.state, DepositSyncSpoolActiveState::Deleting { .. })
                    && active.binding.candidate_root == lease.advertisement_digest())
        })
}

fn certified_export_target_binding(target: &VerifiedRegistryHandoffTarget) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CERTIFIED_EXPORT_TARGET_BINDING_DOMAIN);
    hasher.update(&target.wallet().0);
    hasher.update(&target.committee().epoch.to_le_bytes());
    hasher.update(&target.committee().digest());
    hasher.update(&target.fault_bound().to_le_bytes());
    hasher.update(&target.key_id());
    hasher.update(&target.group_key());
    hasher.update(&target.activation());
    hasher.update(&target.certified_activation_root());
    *hasher.finalize().as_bytes()
}

fn certified_export_head_nonce<S: CertifiedExportReadSeal + ?Sized>(
    seal: &S,
    target_binding: [u8; 32],
    source: PartyId,
    requester: PartyId,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CERTIFIED_EXPORT_HEAD_NONCE_DOMAIN);
    hasher.update(&target_binding);
    hasher.update(&seal.statement_digest());
    hasher.update(&seal.certificate_digest());
    hasher.update(&source.0.to_le_bytes());
    hasher.update(&requester.0.to_le_bytes());
    let mut nonce = *hasher.finalize().as_bytes();
    if nonce == [0; 32] {
        nonce[0] = 1;
    }
    nonce
}

fn validate_certified_export_intent(
    intent: &DepositStateExportSpoolIntent,
) -> Result<(), DepositSyncStageError> {
    intent.request.to_bytes()?;
    let certificate =
        DepositPostHandoffExportSealCertificate::from_bytes(&intent.seal_certificate)?;
    if intent.context.network() == [0; 32]
        || intent.context.wallet().0 == [0; 32]
        || intent.source.0 == 0
        || intent.requester.0 == 0
        || intent.source == intent.requester
        || intent.semantic_transition == [0; 32]
        || intent.target_binding == [0; 32]
        || intent.seal_statement == [0; 32]
        || intent.seal_certificate_digest == [0; 32]
        || intent.request_digest == [0; 32]
        || intent.request.context() != intent.context
        || intent.request.source() != intent.source
        || intent.request.requester() != intent.requester
        || intent.request.semantic_transition_digest() != intent.semantic_transition
        || intent.request.digest() != intent.request_digest
        || certificate.statement().network() != intent.context.network()
        || certificate.statement().source().wallet() != intent.context.wallet()
        || certificate.statement().source_party() != intent.source
        || certificate.statement().semantic_transition_digest() != intent.semantic_transition
        || certificate.statement().digest() != intent.seal_statement
        || certificate.digest()? != intent.seal_certificate_digest
    {
        return Err(DepositSyncStageError::InvalidSnapshot);
    }
    Ok(())
}

fn certified_export_same_admission(
    mut left: DepositStateExportSpoolActive,
    mut right: DepositStateExportSpoolActive,
) -> bool {
    left.state = DepositStateExportSpoolActiveState::Installing;
    right.state = DepositStateExportSpoolActiveState::Installing;
    left == right
}

fn certified_export_intent_matches_active(
    intent: &DepositStateExportSpoolIntent,
    active: DepositStateExportSpoolActive,
) -> bool {
    matches!(
        active.binding.admission,
        DepositSyncSpoolAdmissionKind::CertifiedExport {
            request_digest,
            semantic_transition,
            seal_certificate,
        } if request_digest == intent.request_digest
            && semantic_transition == intent.semantic_transition
            && seal_certificate == intent.seal_certificate_digest
    ) && intent.context == active.context
        && intent.source == active.source
        && intent.requester == active.requester
        && intent.semantic_transition == active.semantic_transition
        && intent.request_digest == active.request_digest
        && intent.request.context() == active.context
        && intent.request.source() == active.source
        && intent.request.requester() == active.requester
        && intent.request.semantic_transition_digest() == active.semantic_transition
        && intent.request.digest() == active.request_digest
}

fn commit_certified_export_import(
    catalog: &mut DepositSyncSpoolCatalog,
    marker: &DepositSyncImportMarker,
) -> Result<(), DepositSyncStageError> {
    let active = catalog
        .certified_export
        .as_mut()
        .filter(|active| active.binding == marker.binding)
        .ok_or(DepositSyncStageError::InvalidImportMarker)?;
    if active.state != (DepositStateExportSpoolActiveState::OwnershipReleased { marker: *marker }) {
        return Err(DepositSyncStageError::InvalidImportMarker);
    }
    active.state = DepositStateExportSpoolActiveState::Committed { marker: *marker };
    // A committed import is the terminal success boundary for this transition. Alternate source
    // certificates are no longer failover authority and must not keep ordinary synchronization
    // closed after the selected lease is reclaimed.
    catalog.certified_export_intents.clear();
    Ok(())
}

fn validate_certified_export_head(
    active: DepositStateExportSpoolActive,
    request: DepositStateExportHeadRequest,
    response: &DepositStateExportHeadResponse,
) -> Result<(), DepositSyncStageError> {
    if request.context() != active.context
        || request.source() != active.source
        || request.requester() != active.requester
        || request.semantic_transition_digest() != active.semantic_transition
        || request.digest() != active.request_digest
        || response.request_digest() != active.request_digest
        || response.semantic_transition_digest() != active.semantic_transition
        || response.source() != active.source
        || response.requester() != active.requester
        || response.digest() != active.response_digest
        || response.lease().digest() != active.lease_digest
        || response.lease().context() != active.context
        || response.lease().source() != active.source
        || response.lease().requester() != active.requester
        || response.lease().head_request_digest() != active.request_digest
        || certified_export_spool_binding(request, response)? != active.binding
    {
        return Err(DepositSyncStageError::InvalidSnapshot);
    }
    Ok(())
}

fn catalog_has_export_release_evidence(
    catalog: &DepositSyncSpoolCatalog,
    lease: DepositStateExportLease,
) -> bool {
    catalog.certified_export.is_some_and(|active| active.lease_digest == lease.digest())
}

fn validate_source(source: PartyId) -> Result<(), DepositSyncStageError> {
    if source.0 == 0 {
        return Err(DepositSyncStageError::InvalidSource);
    }
    Ok(())
}

fn spool_namespace(base: &Path, binding: DepositSyncSpoolBinding) -> PathBuf {
    base.join(SPOOL_NAMESPACE_DIRECTORY).join(hex::encode(binding.anchor.0))
}

fn spool_deleting_namespace(base: &Path, binding: DepositSyncSpoolBinding) -> PathBuf {
    base.join(SPOOL_NAMESPACE_DIRECTORY)
        .join(format!("{SPOOL_DELETING_NAMESPACE_PREFIX}{}", hex::encode(binding.anchor.0)))
}

fn sync_parent_directory(path: &Path) -> Result<(), DepositSyncStageError> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
        std::fs::File::open(parent).and_then(|directory| directory.sync_all()).map_spool_database()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn remove_spool_namespace(path: &Path) -> Result<(), DepositSyncStageError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(DepositSyncStageError::MembershipIndexDivergence),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(DepositSyncStageError::MembershipDatabase(error.to_string())),
    }
    std::fs::remove_dir_all(path).map_spool_database()?;
    sync_parent_directory(path)
}

fn spool_objects_digest(objects: &[DepositSyncObject]) -> Result<[u8; 32], DepositSyncStageError> {
    if objects.is_empty() || objects.len() > MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS {
        return Err(DepositSyncStageError::SpoolPageQuota);
    }
    let plaintext = objects.iter().try_fold(0_usize, |total, object| {
        total.checked_add(object.bytes().len()).ok_or(DepositSyncStageError::ByteQuota)
    })?;
    if plaintext > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES {
        return Err(DepositSyncStageError::ByteQuota);
    }
    let encoded =
        encode_canonical(&objects, MAX_WALLET_ARTIFACT_BYTES, "deposit sync spool page objects")?;
    let mut hasher = blake3::Hasher::new_derive_key(SPOOL_OBJECTS_DIGEST_DOMAIN);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn spool_membership_lookup(
    binding: DepositSyncSpoolBinding,
    lookup_key: &[u8; 32],
    reference: DepositSyncObjectRef,
) -> Result<[u8; 32], DepositSyncStageError> {
    if reference.wallet() != binding.key.wallet_id {
        return Err(DepositSyncStageError::WrongContext);
    }
    reference.storage_reference()?;
    let encoded = encode_canonical(
        &reference,
        MAX_DEPOSIT_SYNC_SPOOL_MEMBERSHIP_RECORD_BYTES,
        "deposit sync spool membership lookup",
    )?;
    let mut hasher = blake3::Hasher::new_keyed(lookup_key);
    hasher.update(SPOOL_MEMBERSHIP_LOOKUP_DOMAIN);
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn open_spool_membership_record(
    binding: DepositSyncSpoolBinding,
    lookup_key: &[u8; 32],
    value_key: &[u8; 32],
    lookup: [u8; 32],
    encoded: &[u8],
) -> Result<DepositSyncSpoolMembershipRecord, DepositSyncStageError> {
    let sealed: DepositSyncSpoolSealedValue = decode_canonical(
        encoded,
        MAX_DEPOSIT_SYNC_SPOOL_SEALED_VALUE_BYTES,
        "sealed deposit sync spool membership value",
    )?;
    if sealed.version != DEPOSIT_SYNC_SPOOL_SEALED_VALUE_VERSION {
        return Err(DepositSyncStageError::MembershipAuthentication);
    }
    let aad = spool_index_aad(binding, SPOOL_MEMBERSHIP_VALUE_LABEL, &lookup);
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(Key::from_slice(value_key))
            .decrypt(
                XNonce::from_slice(&sealed.nonce),
                Payload { msg: &sealed.ciphertext, aad: &aad },
            )
            .map_err(|_| DepositSyncStageError::MembershipAuthentication)?,
    );
    let record: DepositSyncSpoolMembershipRecord = decode_canonical(
        plaintext.as_slice(),
        MAX_DEPOSIT_SYNC_SPOOL_MEMBERSHIP_RECORD_BYTES,
        "deposit sync spool membership record",
    )?;
    if record.version != DEPOSIT_SYNC_SPOOL_MEMBERSHIP_VERSION
        || record.binding != binding
        || record.reference.wallet() != binding.key.wallet_id
        || record.bytes.len() > MAX_DEPOSIT_SYNC_PAGE_PLAINTEXT_BYTES
        || record.envelope.wallet_id() != WalletId(binding.key.wallet_id.0)
        || record.envelope.kind() != DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT
        || record.first_page.artifact.wallet_id() != WalletId(binding.key.wallet_id.0)
        || record.first_page.artifact.kind() != DEPOSIT_SYNC_SPOOL_PAGE_ARTIFACT
        || usize::from(record.entry_index) >= MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS
        || spool_membership_lookup(binding, lookup_key, record.reference)? != lookup
    {
        return Err(DepositSyncStageError::MembershipIndexConflict);
    }
    let object = DepositSyncObject::new(record.reference, record.bytes.clone())?;
    let envelope = DepositSyncSpoolObjectEnvelope::from_object(binding, &object)?;
    let envelope_bytes = envelope.to_bytes()?;
    let expected = WalletArtifactRef::for_contents(
        WalletId(binding.key.wallet_id.0),
        DEPOSIT_SYNC_SPOOL_OBJECT_ARTIFACT,
        &envelope_bytes,
    )?;
    if expected != record.envelope {
        return Err(DepositSyncStageError::MembershipIndexConflict);
    }
    Ok(record)
}

fn open_spool_membership_database(
    path: &Path,
    reconciliation: Arc<DepositSyncSpoolReconciliationCache>,
) -> Result<DepositSyncSpoolMembershipDatabase, DepositSyncStageError> {
    let parent = path.parent().ok_or(DepositSyncStageError::MembershipIndexDivergence)?;
    std::fs::create_dir_all(parent).map_spool_database()?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_spool_database()?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(DepositSyncStageError::MembershipIndexDivergence);
    }
    #[cfg(unix)]
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .map_spool_database()?;
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
    {
        return Err(DepositSyncStageError::MembershipIndexDivergence);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_spool_database()?;
    let opened = file.metadata().map_spool_database()?;
    let current = std::fs::symlink_metadata(path).map_spool_database()?;
    if !opened.is_file() || !current.is_file() || !same_spool_file_identity(&opened, &current) {
        return Err(DepositSyncStageError::MembershipIndexDivergence);
    }
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_spool_database()?;
    let mut builder = Database::builder();
    builder.set_cache_size(DEPOSIT_SYNC_SPOOL_DATABASE_CACHE_BYTES);
    let database = builder.create_file(file).map_spool_database()?;
    let membership = DepositSyncSpoolMembershipDatabase { database, reconciliation };
    let mut transaction = membership.begin_write()?;
    configure_spool_write(&mut transaction);
    drop(transaction.open_table(SPOOL_MEMBERSHIP_TABLE).map_spool_database()?);
    drop(transaction.open_table(SPOOL_REPLAY_TABLE).map_spool_database()?);
    drop(transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).map_spool_database()?);
    drop(transaction.open_table(SPOOL_INDEX_TABLE).map_spool_database()?);
    transaction.commit()?;
    #[cfg(unix)]
    std::fs::File::open(parent).and_then(|directory| directory.sync_all()).map_spool_database()?;
    Ok(membership)
}

fn derive_spool_membership_keys(
    identity_seed: &[u8; 32],
    party: PartyId,
    binding: DepositSyncSpoolBinding,
) -> Result<([u8; 32], [u8; 32]), DepositSyncStageError> {
    let hkdf = Hkdf::<Sha256>::new(Some(SPOOL_KEY_DERIVATION_SALT), identity_seed);
    let binding = spool_binding_bytes(binding);
    let mut lookup_info = Vec::with_capacity(SPOOL_LOOKUP_KEY_INFO.len() + 2 + binding.len());
    lookup_info.extend_from_slice(SPOOL_LOOKUP_KEY_INFO);
    lookup_info.extend_from_slice(&party.0.to_le_bytes());
    lookup_info.extend_from_slice(&binding);
    let mut value_info = Vec::with_capacity(SPOOL_VALUE_KEY_INFO.len() + 2 + binding.len());
    value_info.extend_from_slice(SPOOL_VALUE_KEY_INFO);
    value_info.extend_from_slice(&party.0.to_le_bytes());
    value_info.extend_from_slice(&binding);
    let mut lookup = [0_u8; 32];
    let mut value = [0_u8; 32];
    hkdf.expand(&lookup_info, &mut lookup)
        .map_err(|_| DepositSyncStageError::MembershipKeyDerivation)?;
    hkdf.expand(&value_info, &mut value)
        .map_err(|_| DepositSyncStageError::MembershipKeyDerivation)?;
    if lookup == value || lookup == [0; 32] || value == [0; 32] {
        return Err(DepositSyncStageError::MembershipKeyDerivation);
    }
    Ok((lookup, value))
}

fn spool_binding_bytes(binding: DepositSyncSpoolBinding) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(233);
    bytes.extend_from_slice(&binding.key.network_id);
    bytes.extend_from_slice(&binding.key.wallet_id.0);
    bytes.extend_from_slice(&binding.anchor.0);
    match binding.admission {
        DepositSyncSpoolAdmissionKind::Ordinary => bytes.push(0),
        DepositSyncSpoolAdmissionKind::CertifiedExport {
            request_digest,
            semantic_transition,
            seal_certificate,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&request_digest);
            bytes.extend_from_slice(&semantic_transition);
            bytes.extend_from_slice(&seal_certificate);
        }
    }
    bytes.extend_from_slice(&binding.candidate_root);
    bytes.extend_from_slice(&binding.maximum_objects.to_le_bytes());
    bytes
}

fn spool_index_aad(binding: DepositSyncSpoolBinding, label: &[u8], lookup: &[u8]) -> Vec<u8> {
    let mut aad = b"threshold-monero/deposit-sync-spool/index-aead/v7".to_vec();
    aad.extend_from_slice(&spool_binding_bytes(binding));
    aad.extend_from_slice(&(label.len() as u64).to_le_bytes());
    aad.extend_from_slice(label);
    aad.extend_from_slice(&(lookup.len() as u64).to_le_bytes());
    aad.extend_from_slice(lookup);
    aad
}

fn configure_spool_write(transaction: &mut redb::WriteTransaction) {
    transaction.set_two_phase_commit(true);
    transaction.set_quick_repair(true);
}

trait SpoolDatabaseResultExt<T> {
    fn map_spool_database(self) -> Result<T, DepositSyncStageError>;
}

impl<T, E: fmt::Display> SpoolDatabaseResultExt<T> for Result<T, E> {
    fn map_spool_database(self) -> Result<T, DepositSyncStageError> {
        self.map_err(|error| DepositSyncStageError::MembershipDatabase(error.to_string()))
    }
}

#[cfg(unix)]
fn same_spool_file_identity(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    first.dev() == second.dev() && first.ino() == second.ino()
}

#[cfg(not(unix))]
fn same_spool_file_identity(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    first.len() == second.len()
}

fn prepared_import_marker(
    head: &DepositSyncSpoolHead,
) -> Result<DepositSyncImportMarker, DepositSyncStageError> {
    if head.checkpoint.phase != DepositSyncSpoolPhase::ReadyToCas
        || head.pending.is_some()
        || head.pending_head_response.is_some()
        || head.scan.is_some()
        || head.deletion.is_some()
        || head.head_response.is_none()
        || head.object_count == 0
        || head.object_count > head.binding.maximum_objects
    {
        return Err(DepositSyncStageError::InvalidImportMarker);
    }
    // Reservation release changes only this bounded recovery cursor. It must not change the
    // authoritative marker committed by the wallet snapshot, so hash the exact ReadyToCas
    // projection that existed before release began.
    let mut prepared = head.clone();
    prepared.ownership_release = None;
    let encoded = encode_canonical(
        &prepared,
        MAX_DEPOSIT_SYNC_SPOOL_HEAD_BYTES,
        "prepared deposit sync spool head",
    )?;
    let mut hasher = blake3::Hasher::new_derive_key(DEPOSIT_SYNC_IMPORT_MARKER_DOMAIN);
    hasher.update(&(encoded.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    let marker = DepositSyncImportMarker {
        version: DEPOSIT_SYNC_IMPORT_MARKER_VERSION,
        binding: head.binding,
        owner: head.owner,
        prepared_head_digest: *hasher.finalize().as_bytes(),
        object_count: head.object_count,
    };
    marker.validate_for(head.binding.key.wallet_id)?;
    Ok(marker)
}

fn verify_prepared_import_marker(
    marker: &DepositSyncImportMarker,
    head: &DepositSyncSpoolHead,
) -> Result<(), DepositSyncStageError> {
    marker.validate_for(head.binding.key.wallet_id)?;
    if marker != &prepared_import_marker(head)? {
        return Err(DepositSyncStageError::InvalidImportMarker);
    }
    Ok(())
}

fn validate_ownership_release(
    release: DepositSyncSpoolOwnershipRelease,
    head: &DepositSyncSpoolHead,
) -> Result<(), DepositSyncStageError> {
    if head.checkpoint.phase != DepositSyncSpoolPhase::ReadyToCas
        || release.marker != prepared_import_marker(head)?
        || release.remaining_pages > head.page_count
    {
        return Err(DepositSyncStageError::InvalidImportMarker);
    }
    match release.position {
        Some(position)
            if release.remaining_pages != 0
                && position.ordinal.checked_add(1) == Some(release.remaining_pages) =>
        {
            if position.ordinal >= head.page_count {
                return Err(DepositSyncStageError::InvalidSpoolCursor);
            }
        }
        None if release.remaining_pages == 0 => {}
        _ => return Err(DepositSyncStageError::InvalidSpoolCursor),
    }
    Ok(())
}

fn spool_stats(
    head: &DepositSyncSpoolHead,
) -> Result<DepositSyncSpoolStats, DepositSyncStageError> {
    Ok(DepositSyncSpoolStats {
        phase: head.checkpoint.phase,
        checkpoint_revision: head.checkpoint.revision,
        checkpoint_digest: head.checkpoint.digest()?,
        pages: head.page_count,
        objects: head.object_count,
        plaintext_bytes: head.plaintext_bytes,
        physical_bytes: head.physical_bytes,
        has_pending_page: head.pending.is_some(),
        has_iteration: head.scan.is_some(),
        is_deleting: head.deletion.is_some(),
    })
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, DepositSyncStageError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| DepositSyncStageError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositSyncStageError::TooLarge { kind, actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, DepositSyncStageError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositSyncStageError::TooLarge { kind, actual: bytes.len(), maximum });
    }
    let (value, trailing) =
        postcard::take_from_bytes(bytes).map_err(|_| DepositSyncStageError::Serialization)?;
    if !trailing.is_empty() || postcard::to_allocvec(&value).ok().as_deref() != Some(bytes) {
        return Err(DepositSyncStageError::NonCanonical);
    }
    Ok(value)
}

#[derive(Debug, Error)]
pub enum DepositSyncStageError {
    #[error("deposit sync staging storage failed: {0}")]
    Storage(#[from] StoreError),
    #[error("deposit sync staging wire object failed: {0}")]
    Wire(#[from] DepositSyncWireError),
    #[error("deposit-state transfer wire object failed: {0}")]
    StateTransfer(#[from] DepositStateTransferWireError),
    #[error("deposit-state export authority failed: {0}")]
    StateExport(#[from] DepositStateExportError),
    #[error("deposit sync staging serialization failed")]
    Serialization,
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    TooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("deposit sync staging encoding is noncanonical")]
    NonCanonical,
    #[error("deposit sync staging context differs")]
    WrongContext,
    #[error("deposit sync staging source is invalid")]
    InvalidSource,
    #[error("deposit sync prefix support attempt already owns the admission slot")]
    PrefixAttemptBusy,
    #[error("deposit sync prefix source {0:?} is not eligible in this sampling round")]
    PrefixSourceQuarantined(PartyId),
    #[error("deposit sync admission requires its typed verified evidence")]
    AdmissionEvidenceRequired,
    #[error("deposit sync admission evidence is invalid")]
    InvalidAdmissionEvidence,
    #[error("ordinary deposit-sync admission already owns this wallet spool")]
    OrdinaryAdmissionInProgress,
    #[error("certified-export admission already owns this wallet spool")]
    CertifiedExportAdmissionInProgress,
    #[error("certified-export response has no exact durable pre-request intent")]
    CertifiedExportIntentRequired,
    #[error("certified-export pre-request intent conflicts with its durable source slot")]
    CertifiedExportIntentConflict,
    #[error("deposit sync source {0:?} must acknowledge its pending release before another head")]
    PendingReleaseRequired(PartyId),
    #[error("deposit sync source {0:?} still has an active certified lease")]
    SourceLeaseBusy(PartyId),
    #[error("deposit sync release is unknown")]
    UnknownRelease,
    #[error("deposit sync release conflicts with the durable source slot")]
    ReleaseConflict,
    #[error("deposit sync staging envelope is invalid")]
    InvalidEnvelope,
    #[error("deposit sync spool contains the other head-admission kind")]
    WrongHeadAdmission,
    #[error("deposit sync staging snapshot is invalid")]
    InvalidSnapshot,
    #[error("deposit sync staging candidate quota is exhausted")]
    CandidateQuota,
    #[error("deposit sync staging object quota is exhausted")]
    ObjectQuota,
    #[error("deposit sync staging byte quota is exhausted")]
    ByteQuota,
    #[error("deposit sync staging anchor is unknown")]
    UnknownAnchor,
    #[error("deposit sync staging object is unknown")]
    UnknownObject,
    #[error("deposit sync staging content reference forked")]
    ReferenceFork,
    #[error("a deposit sync request identity was reused for a different response")]
    ResponseEquivocation,
    #[error("deposit sync staging durable readback disappeared or differed")]
    MissingReadback,
    #[error("deposit sync spool head is invalid")]
    InvalidSpoolHead,
    #[error("deposit sync spool page is invalid")]
    InvalidSpoolPage,
    #[error("deposit sync spool page quota is exhausted")]
    SpoolPageQuota,
    #[error("deposit sync spool already contains this object")]
    DuplicateSpoolObject,
    #[error("deposit sync spool already has an unresolved page intent")]
    PendingSpoolPage,
    #[error("deposit sync spool iteration is not active")]
    IterationInactive,
    #[error("deposit sync spool iteration is not complete")]
    IterationIncomplete,
    #[error("deposit sync spool has no unacknowledged delivery")]
    NoPendingDelivery,
    #[error("deposit sync spool cursor is invalid")]
    InvalidSpoolCursor,
    #[error("deposit sync spool transition is invalid")]
    InvalidSpoolTransition,
    #[error("deposit sync object graph frontier is not durably complete")]
    IncompleteObjectGraph,
    #[error("deposit sync prepared-import marker is invalid")]
    InvalidImportMarker,
    #[error("prepared deposit sync import requires explicit abort or committed disposition")]
    PreparedImportDispositionRequired,
    #[error("deposit sync spool membership database failed: {0}")]
    MembershipDatabase(String),
    #[error("deposit sync spool membership key derivation failed")]
    MembershipKeyDerivation,
    #[error("deposit sync spool membership authentication failed")]
    MembershipAuthentication,
    #[error("deposit sync spool head and membership index diverged")]
    MembershipIndexDivergence,
    #[error("deposit sync spool membership record conflicts")]
    MembershipIndexConflict,
    #[error("deposit sync prefix support validation failed: {0}")]
    PrefixSupport(#[from] DepositSyncSupportError),
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_epoch_registry::CompactEpochRegistry,
        compact_registry_archive::{CompactRegistryObjectRef, prepare_compact_registry_genesis},
        compact_registry_store::CompactRegistryStoreCheckpoint,
        deposit_archive::{DepositArchiveEvent, DepositArchiveHead, DepositArchiveSegment},
        deposit_index_checkpoint::PortableDepositIndexHead,
        deposit_index_store::DepositIndexStoreCheckpoint,
        deposit_ledger::CertifiedLedgerEntry,
        deposit_state_export::{
            DepositPostHandoffExportSealCertificate, VerifiedDepositPostHandoffExportCandidate,
            VerifiedDepositPostHandoffExportSeal,
        },
        deposit_state_transfer_wire::{
            DepositPostHandoffExportCandidateEvidence, DepositStateExportReleaseDisposition,
            tests::{ExportEvidenceFixture, export_evidence_fixture},
        },
        deposit_sync_wire::{DepositSyncContext, DepositSyncObjectRef},
        deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
        keys::{EpochPublic, PointBytes},
    };

    struct Fixture {
        advertisement: DepositSyncAdvertisement,
        objects: Vec<DepositSyncObject>,
        target: VerifiedRegistryHandoffTarget,
    }

    fn fixture(tag: u8) -> Fixture {
        fixture_with_committee(tag, 2, 0)
    }

    fn fixture_with_committee(tag: u8, committee_size: u16, fault_bound: u16) -> Fixture {
        fixture_with_committee_and_index(tag, committee_size, fault_bound, 1)
    }

    fn fixture_with_committee_and_index(
        tag: u8,
        committee_size: u16,
        fault_bound: u16,
        index_minor: u32,
    ) -> Fixture {
        let wallet = DepositWalletId([tag; 32]);
        let context = DepositSyncContext::new([tag.wrapping_add(64); 32], wallet).unwrap();
        let first_index = DepositSubaddressIndex::new(0, index_minor).unwrap();
        let index = DepositIndexStoreCheckpoint::empty(wallet, PartyId(1), first_index).unwrap();
        let portable = PortableDepositIndexHead::from_head(index.portable_head()).unwrap();
        let committee = Committee {
            epoch: 0,
            threshold: fault_bound.checked_add(1).unwrap(),
            members: (1..=committee_size)
                .map(|id| Member {
                    id: PartyId(id),
                    signing_key: [tag.wrapping_add(u8::try_from(id).unwrap()); 32],
                    encryption_key: [tag.wrapping_add(32).wrapping_add(u8::try_from(id).unwrap());
                        32],
                })
                .collect(),
        };
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            fault_bound,
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
        let objects = pending
            .staged_objects()
            .iter()
            .map(|object| {
                DepositSyncObject::new(
                    DepositSyncObjectRef::Registry(object.reference()),
                    object.contents().to_vec(),
                )
                .unwrap()
            })
            .collect();
        Fixture { advertisement, objects, target }
    }

    fn head_response(
        fixture: &Fixture,
        source: PartyId,
        requester: PartyId,
    ) -> DepositSyncHeadResponse {
        let request =
            DepositSyncHeadRequest::new(fixture.advertisement.context(), source, requester)
                .unwrap();
        DepositSyncHeadResponse::issue(request, fixture.advertisement.clone(), &[0xA7; 32]).unwrap()
    }

    struct CertifiedEvidenceRegistryReader<'a>(&'a DepositPostHandoffExportCandidateEvidence);

    impl CompactRegistryObjectReader for CertifiedEvidenceRegistryReader<'_> {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            Ok(self
                .0
                .registry_objects()
                .binary_search_by_key(&reference, |object| object.reference())
                .ok()
                .map(|index| self.0.registry_objects()[index].bytes().to_vec()))
        }
    }

    fn certified_export_identity(party: PartyId) -> Identity {
        let signing_seed = [u8::try_from(party.0).unwrap(); 32];
        let mut x25519_secret = [0x58; 32];
        x25519_secret[1..9].copy_from_slice(&0_u64.to_le_bytes());
        x25519_secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        Identity::from_test_secrets(party, 0, &signing_seed, x25519_secret).unwrap()
    }

    fn certified_export_source_public(source: &CompactEpochRegistry) -> EpochPublic {
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

    fn certified_export_candidate(
        fixture: &ExportEvidenceFixture,
        source: PartyId,
    ) -> VerifiedDepositPostHandoffExportCandidate {
        let advertisement = fixture.evidence.advertisement().unwrap();
        let registry = CertifiedEvidenceRegistryReader(&fixture.evidence);
        let segment =
            DepositArchiveSegment::from_bytes(fixture.evidence.archive_segment_bytes()).unwrap();
        let event =
            DepositArchiveEvent::from_bytes(fixture.evidence.archive_event_bytes()).unwrap();
        let terminal =
            CertifiedLedgerEntry::from_bytes(fixture.evidence.terminal_ledger_bytes()).unwrap();
        VerifiedDepositPostHandoffExportCandidate::from_verified_remote_evidence(
            fixture.network,
            source,
            &fixture.source,
            &fixture.handoff,
            &fixture.target,
            &advertisement,
            &registry,
            fixture.evidence.archive_segment_reference(),
            &segment,
            fixture.evidence.archive_event_reference(),
            event,
            fixture.evidence.terminal_ledger_reference(),
            &terminal,
            advertisement.checkpoint_certificate().unwrap(),
        )
        .unwrap()
    }

    fn certified_export_seal(
        fixture: &ExportEvidenceFixture,
        source: PartyId,
    ) -> VerifiedDepositPostHandoffExportSeal {
        let candidate = certified_export_candidate(fixture, source);
        let statement = candidate.statement();
        let committee = fixture.source.active().committee();
        let witnesses = [PartyId(1), PartyId(2), PartyId(3)]
            .into_iter()
            .map(|party| {
                certified_export_identity(party)
                    .sign_envelope(
                        committee,
                        statement.session(),
                        None,
                        statement.final_export().terminal_checkpoint().sequence(),
                        statement.signing_payload(),
                    )
                    .unwrap()
            })
            .collect();
        DepositPostHandoffExportSealCertificate::new(statement.clone(), witnesses)
            .unwrap()
            .verify(&fixture.source, &fixture.handoff)
            .unwrap()
    }

    fn pre_import_certified_export_seal(
        fixture: &ExportEvidenceFixture,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> VerifiedPreImportDepositStateExportSeal {
        seal.certificate()
            .verify_pre_import(
                fixture.network,
                &certified_export_source_public(&fixture.source),
                fixture.source.active().fault_bound(),
                fixture.source.active().certified_activation_root(),
                &fixture.target,
            )
            .unwrap()
    }

    fn certified_export_manager(
        directory: &Path,
        fixture: &ExportEvidenceFixture,
        seed: &[u8; 32],
    ) -> DepositSyncSpoolManager {
        DepositSyncSpoolManager::new(directory, PartyId(4), seed, fixture.network).unwrap()
    }

    async fn active_reconciliation_identity(
        cache: &DepositSyncSpoolReconciliationCache,
    ) -> Option<DepositSyncSpoolReconciliationIdentity> {
        match &*cache.state.lock().await {
            DepositSyncSpoolReconciliationState::Active(identity) => identity.clone(),
            DepositSyncSpoolReconciliationState::Retired => {
                panic!("reconciliation cache unexpectedly retired")
            }
        }
    }

    #[tokio::test]
    async fn certified_export_intents_survive_restart_in_predecessor_order() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x31; 32];
        let fixture = export_evidence_fixture().await;
        let first_seal = certified_export_seal(&fixture, PartyId(1));
        let second_seal = certified_export_seal(&fixture, PartyId(2));
        assert_eq!(
            first_seal.statement().semantic_transition_digest(),
            second_seal.statement().semantic_transition_digest()
        );
        assert_ne!(first_seal.statement_digest(), second_seal.statement_digest());

        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let second =
            manager.record_certified_export_intent(&second_seal, &fixture.target).await.unwrap();
        let first =
            manager.record_certified_export_intent(&first_seal, &fixture.target).await.unwrap();
        drop(manager);

        let reopened = certified_export_manager(directory.path(), &fixture, &seed);
        let context =
            DepositStateTransferContext::new(fixture.network, fixture.source.wallet()).unwrap();
        assert_eq!(
            reopened.pending_certified_export_heads(context).await.unwrap(),
            vec![first, second],
            "restart must preserve every source slot and enumerate it in PartyId order"
        );
    }

    #[tokio::test]
    async fn ordinary_and_exact_certified_export_requests_have_disjoint_spool_namespaces() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = export_evidence_fixture().await;
        let seal = certified_export_seal(&fixture, PartyId(1));
        let advertisement = fixture.evidence.advertisement().unwrap();
        let context =
            DepositStateTransferContext::new(fixture.network, fixture.source.wallet()).unwrap();
        let request = DepositStateExportHeadRequest::new(
            context,
            seal.statement().semantic_transition_digest(),
            PartyId(1),
            PartyId(4),
            [0x41; 32],
        )
        .unwrap();
        let response = DepositStateExportHeadResponse::issue(
            request,
            advertisement.clone(),
            &seal,
            &[0x42; 32],
        )
        .unwrap();
        let other_request = DepositStateExportHeadRequest::new(
            context,
            seal.statement().semantic_transition_digest(),
            PartyId(1),
            PartyId(4),
            [0x43; 32],
        )
        .unwrap();
        let other_response = DepositStateExportHeadResponse::issue(
            other_request,
            advertisement.clone(),
            &seal,
            &[0x44; 32],
        )
        .unwrap();

        let ordinary = spool_binding(&advertisement).unwrap();
        let certified = certified_export_spool_binding(request, &response).unwrap();
        let other_certified =
            certified_export_spool_binding(other_request, &other_response).unwrap();
        assert_eq!(ordinary.key, certified.key);
        assert_eq!(ordinary.candidate_root, certified.candidate_root);
        assert_ne!(ordinary.admission, certified.admission);
        assert_ne!(ordinary.anchor, certified.anchor);
        assert_ne!(certified.anchor, other_certified.anchor);
        assert_ne!(
            spool_namespace(directory.path(), ordinary),
            spool_namespace(directory.path(), certified)
        );
        assert_ne!(
            spool_namespace(directory.path(), certified),
            spool_namespace(directory.path(), other_certified),
            "the certified namespace must bind the exact ExportHead request"
        );
    }

    #[tokio::test]
    async fn pre_import_head_is_fetch_only_exact_and_upgrades_only_with_the_full_seal() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x49; 32];
        let fixture = export_evidence_fixture().await;
        let first_full = certified_export_seal(&fixture, PartyId(1));
        let second_full = certified_export_seal(&fixture, PartyId(2));
        let first_pre_import = pre_import_certified_export_seal(&fixture, &first_full);
        let second_pre_import = pre_import_certified_export_seal(&fixture, &second_full);
        let advertisement = fixture.evidence.advertisement().unwrap();
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let second_request = manager
            .record_pre_import_certified_export_intent(&second_pre_import, &fixture.target)
            .await
            .unwrap();
        let first_request = manager
            .record_pre_import_certified_export_intent(&first_pre_import, &fixture.target)
            .await
            .unwrap();
        let first_response = DepositStateExportHeadResponse::issue(
            first_request,
            advertisement,
            &first_full,
            &[0x4a; 32],
        )
        .unwrap();
        let pre_import_spool = manager
            .open_or_create_pre_import_certified_export(
                first_request,
                &first_response,
                &first_pre_import,
                &fixture.target,
            )
            .await
            .unwrap();
        assert_eq!(
            pre_import_spool.export_head_response().await.unwrap(),
            (first_request, first_response.clone())
        );
        assert!(!pre_import_spool.object_graph_is_complete().await.unwrap());
        assert!(matches!(
            manager
                .open_or_create_pre_import_certified_export(
                    first_request,
                    &first_response,
                    &second_pre_import,
                    &fixture.target,
                )
                .await,
            Err(DepositSyncStageError::StateTransfer(
                DepositStateTransferWireError::WrongVerifiedSeal
            ))
        ));
        assert!(
            manager
                .pending_certified_export_heads(first_request.context())
                .await
                .unwrap()
                .is_empty(),
            "a pre-import-selected active lane must suppress dormant Head retries"
        );
        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let (_, catalog) =
                manager.load_catalog(pre_import_spool.spool.binding.key).await.unwrap();
            assert_eq!(
                catalog.certified_export_intents.keys().copied().collect::<Vec<_>>(),
                vec![PartyId(1), PartyId(2)],
                "pre-import admission must retain the alternate exact source"
            );
            assert_eq!(
                catalog.certified_export_intents.get(&PartyId(2)).map(|intent| intent.request),
                Some(second_request)
            );
        }
        drop(pre_import_spool);
        drop(manager);

        let reopened = certified_export_manager(directory.path(), &fixture, &seed);
        assert!(
            reopened
                .pending_certified_export_heads(first_request.context())
                .await
                .unwrap()
                .is_empty(),
            "restart must not turn an active source back into pending Head selection"
        );
        let recovery = reopened
            .active_pre_import_certified_export_recovery_evidence(first_request.context())
            .await
            .unwrap()
            .expect("the selected lane must retain bounded unauthoritative recovery evidence");
        assert_eq!(recovery.context(), first_request.context());
        assert_eq!(recovery.source(), first_request.source());
        assert_eq!(recovery.requester(), first_request.requester());
        assert_eq!(
            recovery.semantic_transition_digest(),
            first_pre_import.statement().semantic_transition_digest()
        );
        assert_eq!(recovery.seal_statement_digest(), first_pre_import.statement_digest());
        assert_eq!(recovery.seal_certificate_digest(), first_pre_import.certificate_digest());
        assert_eq!(
            recovery.canonical_seal_certificate_bytes(),
            first_pre_import.canonical_certificate_bytes()
        );
        assert_eq!(recovery.head_request(), first_request);
        assert_eq!(recovery.head_response(), Some(&first_response));
        assert!(recovery.binds_target(&fixture.target));
        let incomplete_pre_import = reopened
            .reopen_active_pre_import_certified_export(
                first_request.context(),
                &first_pre_import,
                &fixture.target,
            )
            .await
            .unwrap()
            .expect("the selected pre-import lane must reopen");
        assert!(matches!(
            incomplete_pre_import.completed_artifacts().await,
            Err(DepositSyncStageError::IncompleteObjectGraph)
        ));
        assert!(
            reopened
                .reopen_active_pre_import_certified_export(
                    first_request.context(),
                    &second_pre_import,
                    &fixture.target,
                )
                .await
                .is_err(),
            "a different source token must not reopen the selected active spool"
        );
        let resumed_pre_import = reopened
            .reopen_active_pre_import_certified_export(
                first_request.context(),
                &first_pre_import,
                &fixture.target,
            )
            .await
            .unwrap();
        assert_eq!(
            resumed_pre_import
                .expect("the exact active pre-import spool must resume")
                .export_head_response()
                .await
                .unwrap(),
            (first_request, first_response.clone())
        );
        let full_spool = reopened
            .reopen_active_certified_export(first_request.context(), &first_full, &fixture.target)
            .await
            .unwrap()
            .expect("the full seal must upgrade the exact active spool");
        assert_eq!(
            full_spool.export_head_response().await.unwrap(),
            (first_request, first_response),
            "only re-presenting the full verified seal returns import-capable spool authority"
        );
    }

    #[tokio::test]
    async fn selected_pre_import_installing_cut_recovers_without_deserializing_authority() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x4b; 32];
        let fixture = export_evidence_fixture().await;
        let full = certified_export_seal(&fixture, PartyId(1));
        let pre_import = pre_import_certified_export_seal(&fixture, &full);
        let competitor_full = certified_export_seal(&fixture, PartyId(2));
        let competitor_pre_import = pre_import_certified_export_seal(&fixture, &competitor_full);
        let advertisement = fixture.evidence.advertisement().unwrap();
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let request = manager
            .record_pre_import_certified_export_intent(&pre_import, &fixture.target)
            .await
            .unwrap();
        let competitor_request = manager
            .record_pre_import_certified_export_intent(&competitor_pre_import, &fixture.target)
            .await
            .unwrap();
        let response =
            DepositStateExportHeadResponse::issue(request, advertisement, &full, &[0x4c; 32])
                .unwrap();
        let binding = certified_export_spool_binding(request, &response).unwrap();
        let proposed = DepositStateExportSpoolActive {
            binding,
            context: request.context(),
            source: request.source(),
            requester: request.requester(),
            semantic_transition: request.semantic_transition_digest(),
            request_digest: request.digest(),
            response_digest: response.digest(),
            lease_digest: response.lease().digest(),
            state: DepositStateExportSpoolActiveState::Installing,
        };
        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let (metadata, mut catalog) = manager.load_catalog(binding.key).await.unwrap();
            catalog.certified_export = Some(proposed);
            let _ = manager.persist_catalog(metadata, &catalog).await.unwrap();
        }
        drop(manager);

        let reopened = certified_export_manager(directory.path(), &fixture, &seed);
        let recovery = reopened
            .active_pre_import_certified_export_recovery_evidence(request.context())
            .await
            .unwrap()
            .expect("the journal-before-head crash cut must retain its exact recovery inputs");
        assert_eq!(recovery.head_request(), request);
        assert_eq!(recovery.head_response(), None);
        assert_eq!(
            recovery.canonical_seal_certificate_bytes(),
            pre_import.canonical_certificate_bytes()
        );
        assert_eq!(
            DepositPostHandoffExportSealCertificate::from_bytes(
                recovery.canonical_seal_certificate_bytes()
            )
            .unwrap()
            .digest()
            .unwrap(),
            recovery.seal_certificate_digest()
        );
        assert!(recovery.binds_target(&fixture.target));
        assert!(
            reopened
                .reopen_active_pre_import_certified_export(
                    request.context(),
                    &pre_import,
                    &fixture.target,
                )
                .await
                .is_err(),
            "the unauthoritative recovery bytes must not make an absent head artifact reopenable"
        );
        let checkpoint = reopened
            .installing_certified_export_checkpoint(request.context())
            .await
            .unwrap()
            .expect("the Installing cut must expose an authenticated ABA fence");
        assert_eq!(checkpoint.source(), request.source());
        assert_eq!(checkpoint.request_digest(), request.digest());
        reopened.fail_installing_certified_export_source(checkpoint).await.unwrap();
        assert_eq!(
            reopened.pending_certified_export_heads(request.context()).await.unwrap(),
            vec![competitor_request],
            "fenced Installing cleanup must expose the retained competing source"
        );
        assert!(
            reopened
                .active_pre_import_certified_export_recovery_evidence(request.context())
                .await
                .unwrap()
                .is_none()
        );
        assert!(reopened.fail_installing_certified_export_source(checkpoint).await.is_err());
    }

    #[tokio::test]
    async fn first_valid_certified_export_response_quiesces_but_retains_competing_intents() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x51; 32];
        let fixture = export_evidence_fixture().await;
        let first_seal = certified_export_seal(&fixture, PartyId(1));
        let second_seal = certified_export_seal(&fixture, PartyId(2));
        let third_seal = certified_export_seal(&fixture, PartyId(3));
        let advertisement = fixture.evidence.advertisement().unwrap();
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let second_request =
            manager.record_certified_export_intent(&second_seal, &fixture.target).await.unwrap();
        let first_request =
            manager.record_certified_export_intent(&first_seal, &fixture.target).await.unwrap();
        let first_response = DepositStateExportHeadResponse::issue(
            first_request,
            advertisement.clone(),
            &first_seal,
            &[0x52; 32],
        )
        .unwrap();
        let spool = manager
            .open_or_create_certified_export(
                first_request,
                &first_response,
                &first_seal,
                &fixture.target,
            )
            .await
            .unwrap();
        let context = first_request.context();
        assert!(
            manager.pending_certified_export_heads(context).await.unwrap().is_empty(),
            "an active certified-export lane must quiesce ExportHead retries"
        );
        assert_eq!(spool.export_head_response().await.unwrap(), (first_request, first_response));
        let third_request =
            manager.record_certified_export_intent(&third_seal, &fixture.target).await.unwrap();
        assert!(
            manager.pending_certified_export_heads(context).await.unwrap().is_empty(),
            "a late same-transition competitor must remain dormant while the selected source is active"
        );
        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let (_, catalog) = manager.load_catalog(spool.binding.key).await.unwrap();
            assert_eq!(
                catalog.certified_export_intents.keys().copied().collect::<Vec<_>>(),
                vec![PartyId(1), PartyId(2), PartyId(3)],
                "promotion and late delivery must retain every exact failover source"
            );
            assert_eq!(
                catalog.certified_export_intents.get(&PartyId(3)).map(|intent| intent.request),
                Some(third_request)
            );
        }

        let second_response = DepositStateExportHeadResponse::issue(
            second_request,
            advertisement,
            &second_seal,
            &[0x53; 32],
        )
        .unwrap();
        assert!(matches!(
            manager
                .open_or_create_certified_export(
                    second_request,
                    &second_response,
                    &second_seal,
                    &fixture.target,
                )
                .await,
            Err(DepositSyncStageError::CertifiedExportAdmissionInProgress)
        ));
    }

    #[tokio::test]
    async fn installing_certified_export_retries_exact_selected_head_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x59; 32];
        let fixture = export_evidence_fixture().await;
        let first_seal = certified_export_seal(&fixture, PartyId(1));
        let second_seal = certified_export_seal(&fixture, PartyId(2));
        let advertisement = fixture.evidence.advertisement().unwrap();
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let second_request =
            manager.record_certified_export_intent(&second_seal, &fixture.target).await.unwrap();
        let first_request =
            manager.record_certified_export_intent(&first_seal, &fixture.target).await.unwrap();
        let first_response = DepositStateExportHeadResponse::issue(
            first_request,
            advertisement,
            &first_seal,
            &[0x5a; 32],
        )
        .unwrap();
        let binding = certified_export_spool_binding(first_request, &first_response).unwrap();
        let installing = DepositStateExportSpoolActive {
            binding,
            context: first_request.context(),
            source: first_request.source(),
            requester: first_request.requester(),
            semantic_transition: first_request.semantic_transition_digest(),
            request_digest: first_request.digest(),
            response_digest: first_response.digest(),
            lease_digest: first_response.lease().digest(),
            state: DepositStateExportSpoolActiveState::Installing,
        };
        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let (metadata, mut catalog) = manager.load_catalog(binding.key).await.unwrap();
            assert_eq!(catalog.certified_export_intents.len(), 2);
            catalog.certified_export = Some(installing);
            manager.persist_catalog(metadata, &catalog).await.unwrap();
        }
        assert!(
            !spool_namespace(directory.path(), binding).exists(),
            "the crash cut must precede creation of the exact spool namespace"
        );
        drop(manager);

        let reopened = certified_export_manager(directory.path(), &fixture, &seed);
        assert_eq!(
            reopened.pending_certified_export_heads(first_request.context()).await.unwrap(),
            vec![first_request],
            "Installing recovery must retry only the already selected exact request"
        );
        assert_ne!(first_request, second_request);
        let _spool = reopened
            .open_or_create_certified_export(
                first_request,
                &first_response,
                &first_seal,
                &fixture.target,
            )
            .await
            .unwrap();
        assert!(
            reopened
                .pending_certified_export_heads(first_request.context())
                .await
                .unwrap()
                .is_empty()
        );
        {
            let _catalog_mutation = reopened.catalog_mutation.lock().await;
            let (_, catalog) = reopened.load_catalog(binding.key).await.unwrap();
            assert_eq!(
                catalog.certified_export.map(|active| active.state),
                Some(DepositStateExportSpoolActiveState::Active)
            );
            assert_eq!(
                catalog.certified_export_intents.keys().copied().collect::<Vec<_>>(),
                vec![PartyId(1), PartyId(2)],
                "promotion to Active must retain exact dormant failover intents"
            );
        }
    }

    #[tokio::test]
    async fn locally_completed_import_retires_downloads_but_preserves_exact_release() {
        use crate::deposit_state_import::{
            DepositStateImportedAck, DepositStateImportedCertificate, VerifiedDepositStateImport,
        };
        use crate::deposit_state_transfer_wire::tests::test_identities;

        let directory = tempfile::tempdir().unwrap();
        let seed = [0x5b; 32];
        let fixture = export_evidence_fixture().await;
        let first_seal = certified_export_seal(&fixture, PartyId(1));
        let second_seal = certified_export_seal(&fixture, PartyId(2));
        let completed = VerifiedDepositStateImport::from_verified_export_seal_for_test(
            fixture.network,
            &fixture.source,
            &fixture.handoff,
            &fixture.target,
            &first_seal,
        )
        .unwrap();
        let acknowledgements = test_identities(fixture.target.committee().epoch)
            .values()
            .take(3)
            .map(|identity| DepositStateImportedAck::sign(&completed, identity).unwrap())
            .collect();
        let installed = DepositStateImportedCertificate::from_completed_import(
            &completed,
            acknowledgements,
            &fixture.target,
        )
        .unwrap()
        .verify_completed_import(&completed, &fixture.target)
        .unwrap();
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let context =
            DepositStateTransferContext::new(fixture.network, fixture.target.wallet()).unwrap();
        for seal in [&first_seal, &second_seal] {
            manager.record_certified_export_intent(seal, &fixture.target).await.unwrap();
        }
        assert_eq!(manager.pending_certified_export_heads(context).await.unwrap().len(), 2);
        assert_eq!(
            manager
                .retire_completed_certified_export_intents(&installed, &fixture.target)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            manager
                .retire_completed_certified_export_intents(&installed, &fixture.target)
                .await
                .unwrap(),
            0
        );
        drop(manager);
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        assert!(manager.pending_certified_export_heads(context).await.unwrap().is_empty());

        // A competing download is obsolete after local import completes through another source.
        // Retire its namespace, but retain the exact source lease until an authenticated ACK.
        let request =
            manager.record_certified_export_intent(&first_seal, &fixture.target).await.unwrap();
        manager.record_certified_export_intent(&second_seal, &fixture.target).await.unwrap();
        let response = DepositStateExportHeadResponse::issue(
            request,
            fixture.evidence.advertisement().unwrap(),
            &first_seal,
            &[0x5c; 32],
        )
        .unwrap();
        let spool = manager
            .open_or_create_certified_export(request, &response, &first_seal, &fixture.target)
            .await
            .unwrap();
        let marker = DepositSyncImportMarker {
            version: DEPOSIT_SYNC_IMPORT_MARKER_VERSION,
            binding: spool.binding,
            owner: WalletArtifactOwner::random(&mut OsRng),
            prepared_head_digest: [0x5d; 32],
            object_count: 1,
        };
        // Model the durable post-ownership-release crash cut. Availability must not bypass
        // the wallet's separate commit/abort disposition or delete this selected namespace.
        {
            let (metadata, mut catalog) = manager.load_catalog(spool.binding.key).await.unwrap();
            catalog.certified_export.as_mut().unwrap().state =
                DepositStateExportSpoolActiveState::OwnershipReleased { marker };
            manager.persist_catalog(metadata, &catalog).await.unwrap();
        }
        assert!(matches!(
            manager.retire_completed_certified_export_intents(&installed, &fixture.target).await,
            Err(DepositSyncStageError::PreparedImportDispositionRequired)
        ));
        assert!(spool_namespace(directory.path(), spool.binding).exists());
        assert!(manager.pending_export_releases(context).await.unwrap().is_empty());
        {
            let (metadata, mut catalog) = manager.load_catalog(spool.binding.key).await.unwrap();
            assert_eq!(catalog.certified_export_intents.len(), 2);
            assert_eq!(
                catalog.certified_export.unwrap().state,
                DepositStateExportSpoolActiveState::OwnershipReleased { marker }
            );
            // Restore the ordinary download fixture to exercise its independent cleanup path.
            catalog.certified_export.as_mut().unwrap().state =
                DepositStateExportSpoolActiveState::Active;
            manager.persist_catalog(metadata, &catalog).await.unwrap();
        }
        assert_eq!(
            manager
                .retire_completed_certified_export_intents(&installed, &fixture.target)
                .await
                .unwrap(),
            2
        );
        assert!(
            manager
                .active_pre_import_certified_export_recovery_evidence(context)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!spool_namespace(directory.path(), spool.binding).exists());
        let releases = manager.pending_export_releases(context).await.unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].lease(), response.lease());
        drop(spool);
        drop(manager);
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        assert!(manager.pending_certified_export_heads(context).await.unwrap().is_empty());
        assert_eq!(manager.pending_export_releases(context).await.unwrap(), releases);
        // A journal-before-head cut has no durable response to release. Completion retires it
        // without manufacturing another lease, and leaves existing exact releases untouched.
        manager.record_certified_export_intent(&first_seal, &fixture.target).await.unwrap();
        let binding = certified_export_spool_binding(request, &response).unwrap();
        {
            let (metadata, mut catalog) = manager.load_catalog(binding.key).await.unwrap();
            catalog.certified_export = Some(DepositStateExportSpoolActive {
                binding,
                context,
                source: request.source(),
                requester: request.requester(),
                semantic_transition: request.semantic_transition_digest(),
                request_digest: request.digest(),
                response_digest: response.digest(),
                lease_digest: response.lease().digest(),
                state: DepositStateExportSpoolActiveState::Installing,
            });
            manager.persist_catalog(metadata, &catalog).await.unwrap();
        }
        assert_eq!(
            manager
                .retire_completed_certified_export_intents(&installed, &fixture.target)
                .await
                .unwrap(),
            1
        );
        assert!(manager.pending_certified_export_heads(context).await.unwrap().is_empty());
        assert_eq!(manager.pending_export_releases(context).await.unwrap(), releases);
        let wrong_network =
            DepositSyncSpoolManager::new(directory.path(), PartyId(4), &seed, [0xfe; 32]).unwrap();
        assert!(matches!(
            wrong_network
                .retire_completed_certified_export_intents(&installed, &fixture.target)
                .await,
            Err(DepositSyncStageError::WrongContext)
        ));
    }

    #[tokio::test]
    async fn successful_certified_export_commit_drops_dormant_intents() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x5b; 32];
        let fixture = export_evidence_fixture().await;
        let first_seal = certified_export_seal(&fixture, PartyId(1));
        let second_seal = certified_export_seal(&fixture, PartyId(2));
        let advertisement = fixture.evidence.advertisement().unwrap();
        let manager = certified_export_manager(directory.path(), &fixture, &seed);
        let first_request =
            manager.record_certified_export_intent(&first_seal, &fixture.target).await.unwrap();
        let _second_request =
            manager.record_certified_export_intent(&second_seal, &fixture.target).await.unwrap();
        let first_response = DepositStateExportHeadResponse::issue(
            first_request,
            advertisement,
            &first_seal,
            &[0x5c; 32],
        )
        .unwrap();
        let spool = manager
            .open_or_create_certified_export(
                first_request,
                &first_response,
                &first_seal,
                &fixture.target,
            )
            .await
            .unwrap();
        let binding = spool.binding;
        let marker = DepositSyncImportMarker {
            version: DEPOSIT_SYNC_IMPORT_MARKER_VERSION,
            binding,
            owner: WalletArtifactOwner::random(&mut OsRng),
            prepared_head_digest: [0x5d; 32],
            object_count: 1,
        };
        marker.validate_for(binding.key.wallet_id).unwrap();

        let _catalog_mutation = manager.catalog_mutation.lock().await;
        let (_, mut catalog) = manager.load_catalog(binding.key).await.unwrap();
        assert_eq!(catalog.certified_export_intents.len(), 2);
        catalog.certified_export.as_mut().unwrap().state =
            DepositStateExportSpoolActiveState::OwnershipReleased { marker };
        commit_certified_export_import(&mut catalog, &marker).unwrap();
        assert_eq!(
            catalog.certified_export.map(|active| active.state),
            Some(DepositStateExportSpoolActiveState::Committed { marker })
        );
        assert!(
            catalog.certified_export_intents.is_empty(),
            "terminal import success must retire every dormant failover certificate"
        );
        manager.validate_catalog(&catalog, binding.key).unwrap();
    }

    fn failed_certified_export_journal_scenario()
    -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
        // Keep the complete crash/restart scenario off the default-size Tokio test thread stack.
        // This test deliberately retains two exact seals, two full head responses, the export
        // fixture, and several storage futures across crash-cut awaits. Boxing the state machine
        // changes only where that generated future lives; every protocol transition and assertion
        // below remains identical.
        Box::pin(async move {
            let directory = tempfile::tempdir().unwrap();
            let seed = [0x61; 32];
            let fixture = export_evidence_fixture().await;
            let first_seal = certified_export_seal(&fixture, PartyId(1));
            let second_seal = certified_export_seal(&fixture, PartyId(2));
            let advertisement = fixture.evidence.advertisement().unwrap();
            let manager = certified_export_manager(directory.path(), &fixture, &seed);
            let first_request =
                Box::pin(manager.record_certified_export_intent(&first_seal, &fixture.target))
                    .await
                    .unwrap();
            let second_request =
                Box::pin(manager.record_certified_export_intent(&second_seal, &fixture.target))
                    .await
                    .unwrap();
            let first_response = DepositStateExportHeadResponse::issue(
                first_request,
                advertisement.clone(),
                &first_seal,
                &[0x62; 32],
            )
            .unwrap();
            let spool = Box::pin(manager.open_or_create_certified_export(
                first_request,
                &first_response,
                &first_seal,
                &fixture.target,
            ))
            .await
            .unwrap();
            let checkpoint = Box::pin(spool.checkpoint()).await.unwrap();
            Box::pin(manager.fail_certified_export_source(
                first_request.context(),
                PartyId(1),
                checkpoint.revision(),
                checkpoint.digest().unwrap(),
            ))
            .await
            .unwrap();
            let exact_release =
                DepositStateExportReleaseRequest::new(first_response.lease()).unwrap();
            assert_eq!(
                Box::pin(manager.pending_export_releases(first_request.context())).await.unwrap(),
                vec![exact_release]
            );
            drop(spool);
            drop(manager);

            let reopened = certified_export_manager(directory.path(), &fixture, &seed);
            assert_eq!(
                Box::pin(reopened.pending_export_releases(first_request.context())).await.unwrap(),
                vec![exact_release],
                "the failed source's release must be durable before another intent is admitted"
            );
            assert_eq!(
                Box::pin(reopened.pending_certified_export_heads(first_request.context()))
                    .await
                    .unwrap(),
                vec![second_request],
                "restart must expose the already retained competitor without re-recording its certificate"
            );

            let second_response = DepositStateExportHeadResponse::issue(
                second_request,
                advertisement,
                &second_seal,
                &[0x63; 32],
            )
            .unwrap();
            let second_spool = Box::pin(reopened.open_or_create_certified_export(
                second_request,
                &second_response,
                &second_seal,
                &fixture.target,
            ))
            .await
            .unwrap();
            assert!(
                Box::pin(reopened.pending_certified_export_heads(first_request.context()))
                    .await
                    .unwrap()
                    .is_empty(),
                "the automatically exposed competitor must become the sole active lane"
            );
            drop(second_spool);
            let wrong_release =
                DepositStateExportReleaseRequest::new(second_response.lease()).unwrap();
            let wrong_ack = DepositStateExportReleaseAck::issue(
                wrong_release,
                DepositStateExportReleaseDisposition::Released,
            )
            .unwrap();
            assert!(matches!(
                Box::pin(reopened.acknowledge_export_release(exact_release, wrong_ack)).await,
                Err(DepositSyncStageError::StateTransfer(
                    DepositStateTransferWireError::InvalidExportReleaseAck
                ))
            ));
            assert!(matches!(
                Box::pin(reopened.acknowledge_export_release(wrong_release, wrong_ack)).await,
                Err(DepositSyncStageError::UnknownRelease)
            ));
            assert_eq!(
                Box::pin(reopened.pending_export_releases(first_request.context())).await.unwrap(),
                vec![exact_release]
            );

            let exact_ack = DepositStateExportReleaseAck::issue(
                exact_release,
                DepositStateExportReleaseDisposition::Released,
            )
            .unwrap();
            Box::pin(reopened.acknowledge_export_release(exact_release, exact_ack)).await.unwrap();
            assert!(
                Box::pin(reopened.pending_export_releases(first_request.context()))
                    .await
                    .unwrap()
                    .is_empty()
            );
        })
    }

    #[tokio::test]
    async fn failed_certified_export_journals_exact_release_and_requires_exact_ack() {
        failed_certified_export_journal_scenario().await;
    }

    #[tokio::test]
    async fn manager_reopens_a_cold_reconciliation_after_the_last_database_handle_closes() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x64; 32];
        let fixture = fixture(0x65);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = manager.open_cached_binding(binding).await.unwrap();
        spool.initialize().await.unwrap();
        let reconciliation = Arc::clone(&spool.reconciliation);
        active_reconciliation_identity(&reconciliation)
            .await
            .expect("initialization must cache the reconciled stable spool");
        drop(spool);

        {
            let caches = manager.spool_cache.lock().await;
            let cached = caches
                .get(&binding.anchor)
                .expect("the process cache must retain the exact binding");
            assert!(
                cached.handle.upgrade().is_none(),
                "dropping the last spool handle must leave only the manager's weak handle"
            );
            assert!(Arc::ptr_eq(&cached.reconciliation, &reconciliation));
        }

        let reopened = manager.open_cached_binding(binding).await.unwrap();
        assert!(!Arc::ptr_eq(&reopened.reconciliation, &reconciliation));
        assert!(matches!(
            &*reconciliation.state.lock().await,
            DepositSyncSpoolReconciliationState::Retired
        ));
        assert_eq!(
            active_reconciliation_identity(&reopened.reconciliation).await,
            None,
            "closing the database handle creates an offline-tamper boundary"
        );
        reopened.load_existing_spool_head().await.unwrap();
        assert!(
            active_reconciliation_identity(&reopened.reconciliation).await.is_some(),
            "the first authenticated read after weak-handle reopen must rebuild the proof"
        );
    }

    #[tokio::test]
    async fn new_manager_starts_with_an_empty_reconciliation_cache() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x66; 32];
        let fixture = fixture(0x67);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = manager.open_cached_binding(binding).await.unwrap();
        spool.initialize().await.unwrap();
        let prior_reconciliation = Arc::clone(&spool.reconciliation);
        assert!(active_reconciliation_identity(&prior_reconciliation).await.is_some());
        drop(spool);
        drop(manager);

        let restarted = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let reopened = restarted.open_cached_binding(binding).await.unwrap();
        assert!(!Arc::ptr_eq(&prior_reconciliation, &reopened.reconciliation));
        assert_eq!(
            active_reconciliation_identity(&reopened.reconciliation).await,
            None,
            "a new manager must not inherit process-local reconciliation state"
        );
        reopened.load_existing_spool_head().await.unwrap();
        assert!(
            active_reconciliation_identity(&reopened.reconciliation).await.is_some(),
            "the first authenticated read after restart must populate the empty cache"
        );
    }

    #[tokio::test]
    async fn namespace_deletion_retires_and_evicts_reconciliation_cache() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x68; 32];
        let fixture = fixture(0x69);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = manager.open_cached_binding(binding).await.unwrap();
        spool.initialize().await.unwrap();
        let reconciliation = Arc::clone(&spool.reconciliation);
        let (metadata, head) = spool.load_existing_spool_head().await.unwrap();

        manager.delete_candidate_namespace(binding, false).await.unwrap();
        {
            let caches = manager.spool_cache.lock().await;
            assert!(
                !caches.contains_key(&binding.anchor),
                "namespace deletion must evict the exact process cache entry"
            );
        }
        {
            let state = reconciliation.state.lock().await;
            assert!(matches!(&*state, DepositSyncSpoolReconciliationState::Retired));
        }
        assert!(matches!(
            spool.reconcile_membership_index_cached(metadata, &head).await,
            Err(DepositSyncStageError::MissingReadback)
        ));
    }

    #[tokio::test]
    async fn aborted_membership_write_cools_the_reconciliation_proof() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x8b; 32];
        let fixture = fixture(0x8c);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = manager.open_cached_binding(binding).await.unwrap();
        spool.initialize().await.unwrap();
        let before = active_reconciliation_identity(&spool.reconciliation)
            .await
            .expect("initialization must leave one exact stable proof");
        let scans = spool.reconciliation.response_evidence_scans();

        let write = spool.membership.begin_write().unwrap();
        drop(write);
        spool.load_existing_spool_head().await.unwrap();

        let after = active_reconciliation_identity(&spool.reconciliation)
            .await
            .expect("the cold read must rebuild a stable proof");
        assert_eq!(
            before.membership_write_generation.checked_add(1),
            Some(after.membership_write_generation)
        );
        assert_eq!(
            spool.reconciliation.response_evidence_scans(),
            scans + 1,
            "even an aborted write attempt must force one full authenticated recomputation"
        );
        spool.load_existing_spool_head().await.unwrap();
        assert_eq!(spool.reconciliation.response_evidence_scans(), scans + 1);
    }

    #[tokio::test]
    async fn membership_write_generation_overflow_invalidates_the_populated_cache() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x93; 32];
        let fixture = fixture(0x94);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = manager.open_cached_binding(binding).await.unwrap();
        spool.initialize().await.unwrap();
        assert!(active_reconciliation_identity(&spool.reconciliation).await.is_some());
        let before_index = spool.read_index_head_with_digest().unwrap();

        spool.reconciliation.membership_write_generation.store(u64::MAX, Ordering::Release);
        assert!(matches!(
            spool.membership.begin_write(),
            Err(DepositSyncStageError::MembershipIndexDivergence)
        ));
        assert!(!spool.reconciliation.membership_write_generation_valid.load(Ordering::Acquire));
        assert_eq!(active_reconciliation_identity(&spool.reconciliation).await, None);
        assert_eq!(
            spool.read_index_head_with_digest().unwrap(),
            before_index,
            "overflow must fail before opening or mutating a Redb write transaction"
        );
        assert!(matches!(
            spool.load_existing_spool_head().await,
            Err(DepositSyncStageError::MembershipIndexDivergence)
        ));
    }

    #[tokio::test]
    async fn row_only_membership_database_commit_cannot_hit_the_reconciliation_cache() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x8d; 32];
        let fixture = fixture(0x8e);
        let requester = PartyId(1);
        let source = PartyId(2);
        let response = head_response(&fixture, source, requester);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        spool
            .merge_page([0x8f; 32], [0x90; 32], std::slice::from_ref(&object), 1, b"first-frontier")
            .await
            .unwrap();
        let evidence_request = [0x91; 32];
        spool
            .merge_page(
                evidence_request,
                [0x92; 32],
                std::slice::from_ref(&object),
                2,
                b"evidence-frontier",
            )
            .await
            .unwrap();
        let before = active_reconciliation_identity(&spool.reconciliation)
            .await
            .expect("the evidence journal must leave an exact stable proof");
        let scans = spool.reconciliation.response_evidence_scans();
        let lookup = spool.response_evidence_lookup(evidence_request).unwrap();

        let mut transaction = spool.membership.begin_write().unwrap();
        configure_spool_write(&mut transaction);
        {
            let mut evidence = transaction.open_table(SPOOL_RESPONSE_EVIDENCE_TABLE).unwrap();
            assert!(evidence.remove(lookup.as_slice()).unwrap().is_some());
        }
        transaction.commit().unwrap();

        assert!(matches!(
            spool.load_existing_spool_head().await,
            Err(DepositSyncStageError::MembershipIndexDivergence)
        ));
        assert_eq!(
            spool.reconciliation.membership_write_generation.load(Ordering::Acquire),
            before.membership_write_generation + 1
        );
        assert_eq!(
            spool.reconciliation.response_evidence_scans(),
            scans + 1,
            "the generation miss must force the row scan which detects the missing evidence"
        );
        assert_eq!(active_reconciliation_identity(&spool.reconciliation).await, None);
    }

    #[tokio::test]
    async fn resealed_stable_index_cannot_aba_hit_reconciliation_cache() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x6a; 32];
        let fixture = fixture(0x6b);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let response = head_response(&fixture, PartyId(2), PartyId(1));
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        spool
            .merge_page([0x11; 32], [0x12; 32], std::slice::from_ref(&object), 1, b"frontier-one")
            .await
            .unwrap();
        let (metadata, _) = spool.load_existing_spool_head().await.unwrap();
        let cached = active_reconciliation_identity(&spool.reconciliation)
            .await
            .expect("the committed stable page must be reconciled before the ABA mutation");
        assert_eq!(cached.head, metadata);

        {
            let _mutation = spool.mutation.lock().await;
            let stable_index = spool
                .read_index_head()
                .unwrap()
                .expect("the initialized spool must have an index head");
            let lookup = spool.membership_lookup(object.reference()).unwrap();
            let mut transaction = spool.membership.begin_write().unwrap();
            configure_spool_write(&mut transaction);
            spool.write_index_head_in_transaction(&transaction, &stable_index).unwrap();
            {
                let mut table = transaction.open_table(SPOOL_MEMBERSHIP_TABLE).unwrap();
                let encoded = {
                    let value = table
                        .get(lookup.as_slice())
                        .unwrap()
                        .expect("the committed object must have a membership record");
                    value.value().to_vec()
                };
                let mut sealed: DepositSyncSpoolSealedValue = decode_canonical(
                    &encoded,
                    MAX_DEPOSIT_SYNC_SPOOL_SEALED_VALUE_BYTES,
                    "sealed deposit sync spool membership value",
                )
                .unwrap();
                *sealed
                    .ciphertext
                    .first_mut()
                    .expect("a sealed membership record must contain authenticated ciphertext") ^=
                    1;
                let tampered = encode_canonical(
                    &sealed,
                    MAX_DEPOSIT_SYNC_SPOOL_SEALED_VALUE_BYTES,
                    "sealed deposit sync spool membership value",
                )
                .unwrap();
                table.insert(lookup.as_slice(), tampered.as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }

        let resealed = spool.membership_reconciliation_identity(metadata).unwrap();
        assert_eq!(resealed.head, cached.head);
        assert_eq!(resealed.index, cached.index);
        assert_ne!(
            resealed.sealed_index_digest, cached.sealed_index_digest,
            "resealing the same logical index must create a distinct authenticated generation"
        );
        assert!(matches!(
            spool.load_existing_spool_head().await,
            Err(DepositSyncStageError::MembershipAuthentication)
        ));
        assert_eq!(
            active_reconciliation_identity(&spool.reconciliation).await,
            None,
            "a failed full reconciliation after an ABA miss must leave no cached identity"
        );
    }

    #[tokio::test]
    async fn exact_replay_frozen_reads_materialization_and_deletion_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x71; 32];
        let fixture = fixture(0x72);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let response = head_response(&fixture, PartyId(2), PartyId(1));
        let DepositSyncSpoolAdmission::Admitted { spool, source, supporters } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        assert_eq!(source, PartyId(2));
        assert_eq!(supporters, vec![PartyId(2)]);
        let object = fixture.objects[0].clone();

        let first = spool
            .merge_page([1; 32], [2; 32], std::slice::from_ref(&object), 1, b"frontier-one")
            .await
            .unwrap();
        assert_eq!((first.pages, first.objects), (1, 1));
        assert!(matches!(
            spool.completed_object_graph_download().await,
            Err(DepositSyncStageError::IncompleteObjectGraph)
        ));
        let complete_frontier = completed_download_frontier_for_test(response.lease()).unwrap();
        let second = spool
            .merge_page([3; 32], [4; 32], std::slice::from_ref(&object), 2, &complete_frontier)
            .await
            .unwrap();
        assert_eq!((second.pages, second.objects), (1, 1));

        // A non-adjacent exact replay is O(1) and does not append a third page.
        let replay = spool
            .merge_page([1; 32], [2; 32], std::slice::from_ref(&object), 1, b"frontier-one")
            .await
            .unwrap();
        assert_eq!((replay.pages, replay.objects), (1, 1));
        assert!(matches!(
            spool
                .merge_page([1; 32], [9; 32], std::slice::from_ref(&object), 1, b"frontier-one")
                .await,
            Err(DepositSyncStageError::ResponseEquivocation)
        ));
        drop(spool);

        let DepositSyncSpoolAdmission::Admitted { spool, source, supporters } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("the durable admitted candidate must reopen");
        };
        assert_eq!(source, PartyId(2));
        assert_eq!(supporters, vec![PartyId(2)]);
        assert!(spool.contains_object(object.reference()).unwrap());
        assert_eq!(spool.load_object(object.reference()).unwrap(), Some(object.clone()));
        let completed = spool.completed_object_graph_download().await.unwrap();
        let frozen = spool.freeze(completed).await.unwrap();
        assert_eq!(frozen.object_count(), 1);
        assert_eq!(frozen.load_object(object.reference()).unwrap(), Some(object.clone()));
        drop(frozen);
        spool.begin_verification().await.unwrap();
        let fresh = spool.checkpoint().await.unwrap();
        assert_eq!(fresh.phase(), DepositSyncSpoolPhase::Verifying);
        assert!(fresh.cursor().is_empty());
        spool
            .checkpoint_verification(fresh.revision(), b"verified registry and archive cursor")
            .await
            .unwrap();
        spool.mark_verified(&[0xA5; 32]).await.unwrap();
        assert_eq!(spool.verified_summary().await.unwrap(), vec![0xA5; 32]);
        spool.begin_materialization().await.unwrap();
        assert_eq!(spool.verified_summary().await.unwrap(), vec![0xA5; 32]);
        assert_eq!(spool.next_materialization_object().await.unwrap(), Some(object.clone()));
        spool.create_import_artifact_owned(&object).await.unwrap();
        spool.acknowledge_materialized_object(object.reference()).await.unwrap();
        drop(spool);

        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("materialization progress must reopen");
        };
        assert_eq!(spool.verified_summary().await.unwrap(), vec![0xA5; 32]);
        assert!(spool.next_materialization_object().await.unwrap().is_none());
        spool.finish_materialization().await.unwrap();
        spool.mark_ready_to_cas().await.unwrap();
        assert_eq!(spool.verified_summary().await.unwrap(), vec![0xA5; 32]);
        let stale_base = spool.checkpoint().await.unwrap();
        assert!(matches!(
            spool
                .reset_verification_for_local_base(
                    stale_base.revision().saturating_add(1),
                    stale_base.digest().unwrap(),
                )
                .await,
            Err(DepositSyncStageError::InvalidSpoolTransition)
        ));
        assert!(matches!(
            spool.reset_verification_for_local_base(stale_base.revision(), [0xFF; 32]).await,
            Err(DepositSyncStageError::InvalidSpoolTransition)
        ));
        spool
            .reset_verification_for_local_base(stale_base.revision(), stale_base.digest().unwrap())
            .await
            .unwrap();
        let rebased = spool.checkpoint().await.unwrap();
        assert_eq!(rebased.phase(), DepositSyncSpoolPhase::Verifying);
        assert!(rebased.cursor().is_empty());
        assert_eq!(
            spool.membership_count().unwrap(),
            1,
            "rebasing must not mutate the durable frozen object set"
        );
        assert_eq!(spool.load_object(object.reference()).unwrap(), Some(object.clone()));
        spool.mark_verified(&[0xA5; 32]).await.unwrap();
        spool.begin_materialization().await.unwrap();
        assert_eq!(spool.next_materialization_object().await.unwrap(), Some(object.clone()));
        spool.create_import_artifact_owned(&object).await.unwrap();
        spool.acknowledge_materialized_object(object.reference()).await.unwrap();
        assert!(spool.next_materialization_object().await.unwrap().is_none());
        spool.finish_materialization().await.unwrap();
        spool.mark_ready_to_cas().await.unwrap();
        let aborted_marker = spool.import_marker().await.unwrap();
        drop(spool);
        manager.abort_prepared_import(&aborted_marker).await.unwrap();

        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("aborted import must remain verified");
        };
        assert_eq!(spool.stats().await.unwrap().phase, DepositSyncSpoolPhase::Verified);
        assert_eq!(spool.verified_summary().await.unwrap(), vec![0xA5; 32]);
        let (_, aborted_head) = spool.load_existing_spool_head().await.unwrap();
        let retained = spool
            .artifacts
            .load_artifact_owned(
                object.reference().storage_reference().unwrap(),
                aborted_head.owner,
            )
            .await
            .unwrap();
        assert_eq!(
            retained.contents.as_bytes(),
            object.bytes(),
            "pre-CAS abort must retain materialized bytes until an atomic retry or candidate deletion"
        );
        spool.begin_materialization().await.unwrap();
        assert_eq!(spool.next_materialization_object().await.unwrap(), Some(object.clone()));
        spool.create_import_artifact_owned(&object).await.unwrap();
        spool.acknowledge_materialized_object(object.reference()).await.unwrap();
        assert!(spool.next_materialization_object().await.unwrap().is_none());
        spool.finish_materialization().await.unwrap();
        spool.mark_ready_to_cas().await.unwrap();
        assert!(matches!(
            manager.discard(&fixture.advertisement).await,
            Err(DepositSyncStageError::PreparedImportDispositionRequired)
        ));
        let marker = spool.import_marker().await.unwrap();
        // Crash cut: the authenticated head journal exists, one page's permanent reservation was
        // already released, but the catalog has not yet been promoted to ReleasingOwnership.
        spool.begin_prepared_import_release(&marker).await.unwrap();
        let (_, releasing_head) = spool.load_existing_spool_head().await.unwrap();
        let permanent = object.reference().storage_reference().unwrap();
        assert!(
            spool
                .artifacts
                .release_artifact_ownership(permanent, releasing_head.owner)
                .await
                .unwrap()
        );
        assert!(
            spool.resume_prepared_import_release_page(&marker).await.unwrap(),
            "replaying the partially released final page must persist the terminal cursor"
        );
        let (_, released_head) = spool.load_existing_spool_head().await.unwrap();
        assert!(
            released_head.ownership_release.is_some_and(|release| {
                release.position.is_none() && release.remaining_pages == 0
            })
        );
        assert!(matches!(
            spool.abort_prepared_import(Some(&marker)).await,
            Err(DepositSyncStageError::PreparedImportDispositionRequired)
        ));
        let releasing_checkpoint = spool.checkpoint().await.unwrap();
        assert!(matches!(
            spool
                .reset_verification_for_local_base(
                    releasing_checkpoint.revision(),
                    releasing_checkpoint.digest().unwrap(),
                )
                .await,
            Err(DepositSyncStageError::PreparedImportDispositionRequired)
        ));
        drop(spool);
        assert!(matches!(
            manager.abort_prepared_import(&marker).await,
            Err(DepositSyncStageError::PreparedImportDispositionRequired)
        ));
        manager.release_prepared_import_ownership(&marker).await.unwrap();
        assert_eq!(
            manager.ownership_released_import(fixture.advertisement.context()).await.unwrap(),
            Some(marker)
        );
        manager.complete_prepared_import(&marker).await.unwrap();
        let releases = manager.pending_releases(fixture.advertisement.context()).await.unwrap();
        assert_eq!(releases.len(), 1);
        manager
            .acknowledge_release(DepositSyncReleaseAck::issue(releases[0]).unwrap())
            .await
            .unwrap();
        assert_eq!(manager.candidate_state(&fixture.advertisement).await.unwrap(), None);
    }

    #[tokio::test]
    async fn exact_replay_from_an_older_download_generation_advances_without_duplicate_storage() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x6B; 32];
        let fixture = fixture(0x6C);
        let requester = PartyId(1);
        let source = PartyId(2);
        let response = head_response(&fixture, source, requester);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        let request_digest = [0x6D; 32];
        let response_digest = [0x6E; 32];
        let frontier = b"source-bound-generation-frontier";
        let first = spool
            .merge_page(request_digest, response_digest, std::slice::from_ref(&object), 1, frontier)
            .await
            .unwrap();
        assert_eq!((first.pages, first.objects), (1, 1));
        assert_eq!(spool.replay_count().unwrap(), 1);

        let checkpoint = spool.checkpoint().await.unwrap();
        spool
            .reset_download_checkpoint(checkpoint.revision(), checkpoint.digest().unwrap())
            .await
            .unwrap();
        let reset = spool.checkpoint().await.unwrap();
        assert_eq!(reset.revision(), 2);
        assert!(reset.cursor().is_empty());
        let (_, reset_head) = spool.load_existing_spool_head().await.unwrap();
        assert_eq!(reset_head.download_generation_start_revision, reset.revision());
        spool.install_head_response(&response, requester).await.unwrap();
        drop(spool);
        drop(manager);

        let reopened = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let Some(DepositSyncSpoolAdmission::Admitted { spool, .. }) = Box::pin(
            reopened
                .resume_exact_claims_admission(fixture.advertisement.context(), &fixture.target),
        )
        .await
        .unwrap() else {
            panic!("the reset exact-claims candidate must resume");
        };
        let retried = spool
            .merge_page(request_digest, response_digest, std::slice::from_ref(&object), 3, frontier)
            .await
            .unwrap();
        assert_eq!((retried.pages, retried.objects), (1, 1));
        assert_eq!(spool.replay_count().unwrap(), 1);
        assert_eq!(spool.membership_count().unwrap(), 1);
        assert_eq!(spool.checkpoint().await.unwrap().revision(), 3);

        // The current generation's immediately repeated transition remains exactly idempotent;
        // neither a changed response nor a changed successor can hide behind older replay proof.
        let replayed = spool
            .merge_page(request_digest, response_digest, std::slice::from_ref(&object), 3, frontier)
            .await
            .unwrap();
        assert_eq!((replayed.pages, replayed.objects), (1, 1));
        assert!(matches!(
            spool
                .merge_page(request_digest, [0x6F; 32], std::slice::from_ref(&object), 3, frontier,)
                .await,
            Err(DepositSyncStageError::ResponseEquivocation)
        ));
        assert!(matches!(
            spool
                .merge_page(
                    request_digest,
                    response_digest,
                    std::slice::from_ref(&object),
                    3,
                    b"different-generation-frontier",
                )
                .await,
            Err(DepositSyncStageError::ReferenceFork)
        ));
        assert_eq!(spool.replay_count().unwrap(), 1);
        assert_eq!(spool.membership_count().unwrap(), 1);
        assert_eq!(spool.stats().await.unwrap().pages, 1);
    }

    #[tokio::test]
    async fn duplicate_only_response_evidence_survives_reset_and_rejects_equivocation() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x70; 32];
        let fixture = fixture(0x71);
        let requester = PartyId(1);
        let source = PartyId(2);
        let response = head_response(&fixture, source, requester);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        spool
            .merge_page(
                [0x72; 32],
                [0x73; 32],
                std::slice::from_ref(&object),
                1,
                b"first-object-frontier",
            )
            .await
            .unwrap();
        let before_duplicate = active_reconciliation_identity(&spool.reconciliation)
            .await
            .expect("the committed object page must leave a stable reconciliation proof");

        let duplicate_request = [0x74; 32];
        let duplicate_response = [0x75; 32];
        let duplicate_frontier = b"duplicate-only-frontier";
        let duplicate = spool
            .merge_page(
                duplicate_request,
                duplicate_response,
                std::slice::from_ref(&object),
                2,
                duplicate_frontier,
            )
            .await
            .unwrap();
        assert_eq!((duplicate.pages, duplicate.objects), (1, 1));
        assert_eq!(spool.replay_count().unwrap(), 1);
        assert_eq!(spool.response_evidence_count().unwrap(), 1);
        let (_, duplicate_head) = spool.load_existing_spool_head().await.unwrap();
        assert_eq!(duplicate_head.response_evidence_count, 1);
        assert_ne!(duplicate_head.response_evidence_accumulator, [0; 32]);
        let after_duplicate = active_reconciliation_identity(&spool.reconciliation)
            .await
            .expect("head-only evidence commit must transfer the reconciliation proof");
        assert_ne!(after_duplicate.head, before_duplicate.head);
        assert_ne!(after_duplicate.index, before_duplicate.index);
        spool.load_existing_spool_head().await.unwrap();
        assert_eq!(
            active_reconciliation_identity(&spool.reconciliation).await,
            Some(after_duplicate),
            "the next read must cache-hit the exact finalized evidence projection"
        );

        let checkpoint = spool.checkpoint().await.unwrap();
        spool
            .reset_download_checkpoint(checkpoint.revision(), checkpoint.digest().unwrap())
            .await
            .unwrap();
        spool.install_head_response(&response, requester).await.unwrap();
        assert!(matches!(
            spool
                .merge_page(
                    duplicate_request,
                    [0x76; 32],
                    std::slice::from_ref(&object),
                    4,
                    duplicate_frontier,
                )
                .await,
            Err(DepositSyncStageError::ResponseEquivocation)
        ));
        let replayed = spool
            .merge_page(
                duplicate_request,
                duplicate_response,
                std::slice::from_ref(&object),
                4,
                duplicate_frontier,
            )
            .await
            .unwrap();
        assert_eq!((replayed.pages, replayed.objects), (1, 1));
        assert_eq!(spool.replay_count().unwrap(), 1);
        assert_eq!(spool.response_evidence_count().unwrap(), 1);
        assert_eq!(spool.checkpoint().await.unwrap().revision(), 4);
    }

    #[tokio::test]
    async fn response_evidence_scan_is_constant_across_hot_journals_and_recomputed_on_restart() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x83; 32];
        let fixture = fixture(0x84);
        assert!(fixture.objects.len() >= 2, "fixture must exercise two append journals");
        let requester = PartyId(1);
        let source = PartyId(2);
        let response = head_response(&fixture, source, requester);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let first = fixture.objects[0].clone();
        let second = fixture.objects[1].clone();
        let first_request = [0x85; 32];
        let first_response = [0x86; 32];
        spool
            .merge_page(
                first_request,
                first_response,
                std::slice::from_ref(&first),
                1,
                b"first-frontier",
            )
            .await
            .unwrap();
        let scans_after_first_append = spool.reconciliation.response_evidence_scans();

        spool
            .merge_page(
                [0x87; 32],
                [0x88; 32],
                std::slice::from_ref(&first),
                2,
                b"evidence-frontier",
            )
            .await
            .unwrap();
        spool
            .merge_page(
                [0x89; 32],
                [0x8a; 32],
                std::slice::from_ref(&second),
                3,
                b"second-frontier",
            )
            .await
            .unwrap();
        let checkpoint = spool.checkpoint().await.unwrap();
        spool
            .reset_download_checkpoint(checkpoint.revision(), checkpoint.digest().unwrap())
            .await
            .unwrap();
        spool.install_head_response(&response, requester).await.unwrap();
        spool
            .merge_page(
                first_request,
                first_response,
                std::slice::from_ref(&first),
                5,
                b"replayed-first-frontier",
            )
            .await
            .unwrap();
        assert_eq!(
            spool.reconciliation.response_evidence_scans(),
            scans_after_first_append,
            "head-only, evidence, and append journals must transfer the exact hot proof"
        );
        let (metadata, mut deleting_head) = spool.load_existing_spool_head().await.unwrap();
        let cursor = deleting_head.checkpoint.cursor.clone();
        deleting_head.checkpoint =
            deleting_head.checkpoint.successor(DepositSyncSpoolPhase::Deleting, cursor).unwrap();
        deleting_head.scan = None;
        deleting_head.ownership_release = None;
        deleting_head.deletion = Some(DepositSyncSpoolDeletion {
            position: deleting_head.committed,
            remaining_pages: deleting_head.page_count,
            remaining_objects: deleting_head.object_count,
            pending: None,
        });
        spool.persist_spool_head(Some(metadata), &deleting_head).await.unwrap();

        drop(spool);
        drop(manager);
        let restarted = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = restarted.open_cached_binding(binding).await.unwrap();
        assert_eq!(spool.reconciliation.response_evidence_scans(), 0);
        spool.load_existing_spool_head().await.unwrap();
        assert_eq!(
            spool.reconciliation.response_evidence_scans(),
            1,
            "a mid-delete process restart must fully recompute the evidence projection once"
        );
        spool.load_existing_spool_head().await.unwrap();
        assert_eq!(spool.reconciliation.response_evidence_scans(), 1);

        spool.delete_contents(false).await.unwrap();
        assert_eq!(
            spool.reconciliation.response_evidence_scans(),
            1,
            "resumed delete journals must reuse the stable deletion proof across every page"
        );
    }

    #[tokio::test]
    async fn response_evidence_journal_recovers_both_head_cas_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x77; 32];
        let fixture = fixture(0x78);
        let requester = PartyId(1);
        let source = PartyId(2);
        let response = head_response(&fixture, source, requester);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        spool
            .merge_page(
                [0x79; 32],
                [0x7a; 32],
                std::slice::from_ref(&object),
                1,
                b"first-object-frontier",
            )
            .await
            .unwrap();

        let (_, before_prepare) = spool.load_existing_spool_head().await.unwrap();
        let rolled_back_next = before_prepare
            .checkpoint
            .successor(DepositSyncSpoolPhase::Downloading, b"rolled-back-frontier".to_vec())
            .unwrap();
        let rolled_back_transition = DepositSyncSpoolPageTransition::new(
            [0x7b; 32],
            [0x7c; 32],
            spool_objects_digest(std::slice::from_ref(&object)).unwrap(),
            &before_prepare.checkpoint,
            &rolled_back_next,
        )
        .unwrap();
        spool.prepare_response_evidence(&before_prepare, &rolled_back_transition).unwrap();
        assert_eq!(spool.response_evidence_count().unwrap(), 1);
        drop(spool);
        drop(manager);

        let restarted = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = restarted.open_cached_binding(binding).await.unwrap();
        let (_, rolled_back_head) = spool.load_existing_spool_head().await.unwrap();
        assert_eq!(rolled_back_head, before_prepare);
        assert_eq!(spool.response_evidence_count().unwrap(), 0);
        assert_eq!(
            spool.read_index_head().unwrap(),
            Some(stable_index_head(binding, &rolled_back_head))
        );

        let (metadata, mut before_finalize) = spool.load_existing_spool_head().await.unwrap();
        let finalized_next = before_finalize
            .checkpoint
            .successor(DepositSyncSpoolPhase::Downloading, b"finalized-frontier".to_vec())
            .unwrap();
        let finalized_transition = DepositSyncSpoolPageTransition::new(
            [0x7d; 32],
            [0x7e; 32],
            spool_objects_digest(std::slice::from_ref(&object)).unwrap(),
            &before_finalize.checkpoint,
            &finalized_next,
        )
        .unwrap();
        spool.prepare_response_evidence(&before_finalize, &finalized_transition).unwrap();
        before_finalize.response_evidence_count += 1;
        before_finalize.response_evidence_accumulator = xor_response_evidence_accumulator(
            before_finalize.response_evidence_accumulator,
            response_evidence_commitment(binding, &finalized_transition).unwrap(),
        );
        before_finalize.checkpoint = finalized_next;
        before_finalize.last_transition = Some(finalized_transition.clone());
        spool.persist_spool_head(Some(metadata), &before_finalize).await.unwrap();
        drop(spool);
        drop(restarted);

        let restarted = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let spool = restarted.open_cached_binding(binding).await.unwrap();
        let (_, finalized_head) = spool.load_existing_spool_head().await.unwrap();
        assert_eq!(finalized_head, before_finalize);
        assert_eq!(spool.response_evidence_count().unwrap(), 1);
        assert_eq!(
            spool.response_evidence_projection().unwrap(),
            (finalized_head.response_evidence_count, finalized_head.response_evidence_accumulator)
        );
        assert_eq!(
            spool.read_index_head().unwrap(),
            Some(stable_index_head(binding, &finalized_head))
        );
    }

    #[tokio::test]
    async fn revision_overflow_is_rejected_before_unlinking_the_source_response() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x7f; 32];
        let fixture = fixture(0x80);
        let requester = PartyId(1);
        let source = PartyId(2);
        let response = head_response(&fixture, source, requester);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let (metadata, mut head) = spool.load_existing_spool_head().await.unwrap();
        head.checkpoint.revision = u64::MAX;
        head.checkpoint.cursor.clear();
        head.last_transition = None;
        spool.persist_spool_head(Some(metadata), &head).await.unwrap();
        let digest = head.checkpoint.digest().unwrap();

        assert!(matches!(
            spool.reset_download_checkpoint(u64::MAX, digest).await,
            Err(DepositSyncStageError::InvalidSpoolTransition)
        ));
        assert_eq!(spool.head_response(requester).await.unwrap(), response);
        let invalid = DepositSyncSpoolPageTransition {
            request_digest: [0x81; 32],
            response_digest: [0x82; 32],
            objects_digest: [0x83; 32],
            expected_revision: u64::MAX,
            expected_checkpoint_digest: [0x84; 32],
            next_revision: u64::MAX,
            next_checkpoint_digest: [0x85; 32],
        };
        assert!(matches!(invalid.validate(), Err(DepositSyncStageError::InvalidSpoolTransition)));
    }

    #[tokio::test]
    async fn abort_then_discard_removes_retained_materialization_reservation() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x73; 32];
        let fixture = fixture(0x74);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let response = head_response(&fixture, PartyId(2), PartyId(1));
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        let complete_frontier = completed_download_frontier_for_test(response.lease()).unwrap();
        spool
            .merge_page(
                [0x11; 32],
                [0x12; 32],
                std::slice::from_ref(&object),
                1,
                &complete_frontier,
            )
            .await
            .unwrap();
        let completed = spool.completed_object_graph_download().await.unwrap();
        let _ = spool.freeze(completed).await.unwrap();
        spool.begin_verification().await.unwrap();
        spool.mark_verified(&[0xA5; 32]).await.unwrap();
        spool.begin_materialization().await.unwrap();
        assert_eq!(spool.next_materialization_object().await.unwrap(), Some(object.clone()));
        let permanent = spool.create_import_artifact_owned(&object).await.unwrap();
        spool.acknowledge_materialized_object(object.reference()).await.unwrap();
        assert!(spool.next_materialization_object().await.unwrap().is_none());
        spool.finish_materialization().await.unwrap();
        spool.mark_ready_to_cas().await.unwrap();
        let marker = spool.import_marker().await.unwrap();
        let (_, head) = spool.load_existing_spool_head().await.unwrap();
        drop(spool);

        manager.abort_prepared_import(&marker).await.unwrap();
        let retained = manager.artifacts.load_artifact_owned(permanent, head.owner).await.unwrap();
        assert_eq!(retained.contents.as_bytes(), object.bytes());
        manager.discard(&fixture.advertisement).await.unwrap();
        let release = manager.pending_releases(fixture.advertisement.context()).await.unwrap();
        assert_eq!(release.len(), 1);
        manager
            .acknowledge_release(DepositSyncReleaseAck::issue(release[0]).unwrap())
            .await
            .unwrap();
        assert_eq!(manager.candidate_state(&fixture.advertisement).await.unwrap(), None);
        assert!(matches!(
            manager.artifacts.load_artifact(permanent).await,
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));
    }

    #[tokio::test]
    async fn ownership_release_and_abort_race_has_one_durable_winner() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x75; 32];
        let fixture = fixture(0x76);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(1),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let response = head_response(&fixture, PartyId(2), PartyId(1));
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&response, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("one f=0 supporter must admit the candidate");
        };
        let object = fixture.objects[0].clone();
        let complete_frontier = completed_download_frontier_for_test(response.lease()).unwrap();
        spool
            .merge_page(
                [0x21; 32],
                [0x22; 32],
                std::slice::from_ref(&object),
                1,
                &complete_frontier,
            )
            .await
            .unwrap();
        let completed = spool.completed_object_graph_download().await.unwrap();
        let _ = spool.freeze(completed).await.unwrap();
        spool.begin_verification().await.unwrap();
        spool.mark_verified(&[0xA6; 32]).await.unwrap();
        spool.begin_materialization().await.unwrap();
        let materialized = spool.next_materialization_object().await.unwrap().unwrap();
        spool.create_import_artifact_owned(&materialized).await.unwrap();
        spool.acknowledge_materialized_object(materialized.reference()).await.unwrap();
        assert!(spool.next_materialization_object().await.unwrap().is_none());
        spool.finish_materialization().await.unwrap();
        spool.mark_ready_to_cas().await.unwrap();
        let marker = spool.import_marker().await.unwrap();
        drop(spool);

        let (released, aborted) = tokio::join!(
            manager.release_prepared_import_ownership(&marker),
            manager.abort_prepared_import(&marker),
        );
        assert_ne!(released.is_ok(), aborted.is_ok(), "exactly one disposition must win");
        if released.is_ok() {
            assert_eq!(
                manager.ownership_released_import(fixture.advertisement.context()).await.unwrap(),
                Some(marker)
            );
        } else {
            assert!(matches!(
                released,
                Err(DepositSyncStageError::InvalidImportMarker)
                    | Err(DepositSyncStageError::InvalidSpoolTransition)
            ));
            assert_eq!(
                manager.candidate_state(&fixture.advertisement).await.unwrap(),
                Some(DepositSyncSpoolPhase::Verified)
            );
        }
    }

    #[tokio::test]
    async fn f_plus_one_authenticated_supporters_gate_writable_spool_creation() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x81; 32];
        let fixture = fixture_with_committee(0x82, 4, 1);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(4),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let namespace = spool_namespace(directory.path(), binding);
        let response_one = head_response(&fixture, PartyId(1), PartyId(4));
        let response_two = head_response(&fixture, PartyId(2), PartyId(4));

        // A structurally valid peer-selected committee is not an admission authority. The target
        // must be the non-serializable capability reconstructed from local activation history.
        let untrusted_target = VerifiedRegistryHandoffTarget::for_test(
            Committee {
                epoch: 0,
                threshold: 1,
                members: vec![Member {
                    id: PartyId(1),
                    signing_key: [0xD1; 32],
                    encryption_key: [0xD2; 32],
                }],
            },
            0,
            [0xD3; 32],
            [0xD4; 32],
            fixture.advertisement.context().wallet(),
            [0xD5; 32],
            [0xD6; 32],
        )
        .unwrap();
        assert!(matches!(
            Box::pin(manager.open_or_create(&response_one, PartyId(1), &untrusted_target)).await,
            Err(DepositSyncStageError::WrongContext)
        ));
        assert!(!namespace.exists());

        // f matching sources can all be Byzantine, so they cannot obtain a writable spool.
        assert!(matches!(
            Box::pin(manager.open_or_create(&response_one, PartyId(1), &fixture.target))
                .await
                .unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));
        assert!(!namespace.exists());
        assert_eq!(manager.candidate_state(&fixture.advertisement).await.unwrap(), None);
        drop(manager);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            PartyId(4),
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();

        // The authenticated gate survives restart. Replaying one identity does not increase
        // support or create the candidate namespace.
        assert!(matches!(
            Box::pin(manager.open_or_create(&response_one, PartyId(1), &fixture.target))
                .await
                .unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));
        assert!(!namespace.exists());

        // f+1 matching sources guarantee at least one honest source. Source one may now be silent;
        // source two is retained in the admitted failover set and can complete the first page.
        let DepositSyncSpoolAdmission::Admitted { spool, source, supporters } =
            Box::pin(manager.open_or_create(&response_two, PartyId(2), &fixture.target))
                .await
                .unwrap()
        else {
            panic!("f+1 matching authenticated sources must admit the candidate");
        };
        assert_eq!(source, PartyId(2));
        assert_eq!(supporters, vec![PartyId(1), PartyId(2)]);
        assert!(namespace.exists());
        let object = fixture.objects[0].clone();
        let stats = spool
            .merge_page(
                [0x11; 32],
                [0x12; 32],
                std::slice::from_ref(&object),
                1,
                b"f-plus-one-frontier",
            )
            .await
            .unwrap();
        assert_eq!((stats.pages, stats.objects), (1, 1));
    }

    #[tokio::test]
    async fn exact_claims_candidate_resumes_without_another_head_request() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x83; 32];
        let fixture = fixture_with_committee(0x84, 4, 1);
        let requester = PartyId(4);
        let first = head_response(&fixture, PartyId(1), requester);
        let second = head_response(&fixture, PartyId(2), requester);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        assert!(matches!(
            Box::pin(manager.open_or_create(&first, PartyId(1), &fixture.target)).await.unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));
        let DepositSyncSpoolAdmission::Admitted { spool, source, supporters } =
            Box::pin(manager.open_or_create(&second, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("f+1 exact claims must admit the download");
        };
        assert_eq!(source, PartyId(2));
        assert_eq!(supporters, vec![PartyId(1), PartyId(2)]);
        assert_eq!(spool.head_response(requester).await.unwrap(), second);
        let complete_frontier = completed_download_frontier_for_test(second.lease()).unwrap();
        let page_count = fixture.objects.chunks(MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS).len();
        for (index, objects) in
            fixture.objects.chunks(MAX_DEPOSIT_SYNC_SPOOL_PAGE_OBJECTS).enumerate()
        {
            let ordinal = u8::try_from(index).unwrap();
            let frontier = if index + 1 == page_count {
                complete_frontier.as_slice()
            } else {
                b"incomplete exact-claims restart frontier"
            };
            spool
                .merge_page(
                    [0x8B_u8.wrapping_add(ordinal); 32],
                    [0x9B_u8.wrapping_add(ordinal); 32],
                    objects,
                    u64::try_from(index + 1).unwrap(),
                    frontier,
                )
                .await
                .unwrap();
        }
        let completed = spool.completed_object_graph_download().await.unwrap();
        let _ = spool.freeze(completed).await.unwrap();
        assert_eq!(spool.checkpoint().await.unwrap().phase(), DepositSyncSpoolPhase::Frozen);
        drop(spool);
        drop(manager);

        let reopened = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let Some(DepositSyncSpoolAdmission::Admitted { spool, source, supporters }) = Box::pin(
            reopened
                .resume_exact_claims_admission(fixture.advertisement.context(), &fixture.target),
        )
        .await
        .unwrap() else {
            panic!("restart must recover exact authority without another peer head");
        };
        assert_eq!(source, PartyId(2));
        assert_eq!(supporters, vec![PartyId(1), PartyId(2)]);
        assert_eq!(spool.head_response(requester).await.unwrap(), second);
        assert_eq!(spool.checkpoint().await.unwrap().phase(), DepositSyncSpoolPhase::Frozen);
    }

    #[tokio::test]
    async fn exact_claims_resume_fails_closed_for_changed_target_or_malformed_evidence() {
        let changed_directory = tempfile::tempdir().unwrap();
        let seed = [0x85; 32];
        let fixture = fixture_with_committee(0x86, 4, 1);
        let requester = PartyId(4);
        let first = head_response(&fixture, PartyId(1), requester);
        let second = head_response(&fixture, PartyId(2), requester);
        let manager = DepositSyncSpoolManager::new(
            changed_directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        assert!(matches!(
            Box::pin(manager.open_or_create(&first, PartyId(1), &fixture.target)).await.unwrap(),
            DepositSyncSpoolAdmission::Pending { .. }
        ));
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&second, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("fixture must admit");
        };
        drop(spool);
        drop(manager);

        let mut changed_committee = fixture.target.committee().clone();
        changed_committee.members[0].signing_key[0] ^= 0x80;
        let changed_target = VerifiedRegistryHandoffTarget::for_test(
            changed_committee,
            fixture.target.fault_bound(),
            [0x87; 32],
            [0x88; 32],
            fixture.advertisement.context().wallet(),
            [0x89; 32],
            [0x8A; 32],
        )
        .unwrap();
        let reopened = DepositSyncSpoolManager::new(
            changed_directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        assert!(
            Box::pin(
                reopened.resume_exact_claims_admission(
                    fixture.advertisement.context(),
                    &changed_target,
                )
            )
            .await
            .unwrap()
            .is_none(),
            "a changed current target must revoke serialized exact authority"
        );

        let malformed_directory = tempfile::tempdir().unwrap();
        let manager = DepositSyncSpoolManager::new(
            malformed_directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        assert!(matches!(
            Box::pin(manager.open_or_create(&first, PartyId(1), &fixture.target)).await.unwrap(),
            DepositSyncSpoolAdmission::Pending { .. }
        ));
        let DepositSyncSpoolAdmission::Admitted { spool, .. } =
            Box::pin(manager.open_or_create(&second, PartyId(2), &fixture.target)).await.unwrap()
        else {
            panic!("fixture must admit");
        };
        drop(spool);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let (metadata, mut catalog) = manager.load_catalog(binding.key).await.unwrap();
            catalog
                .active
                .as_mut()
                .unwrap()
                .certified_claims
                .get_mut(&PartyId(1))
                .unwrap()
                .response
                .owner = WalletArtifactOwner::random(&mut OsRng);
            manager.persist_catalog(metadata, &catalog).await.unwrap();
        }
        drop(manager);

        let reopened = DepositSyncSpoolManager::new(
            malformed_directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        assert!(
            Box::pin(
                reopened.resume_exact_claims_admission(
                    fixture.advertisement.context(),
                    &fixture.target,
                )
            )
            .await
            .is_err(),
            "every certified claim must be loaded and reauthenticated, including non-selected ones"
        );
    }

    #[tokio::test]
    async fn split_sticky_heads_release_a_complete_remote_round_before_repoll() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x91; 32];
        let first = fixture_with_committee_and_index(0x92, 4, 1, 1);
        let second = fixture_with_committee_and_index(0x92, 4, 1, 2);
        let requester = PartyId(4);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            first.advertisement.context().network(),
        )
        .unwrap();
        let first_response = head_response(&first, PartyId(1), requester);
        let second_response = head_response(&second, PartyId(2), requester);

        assert!(matches!(
            Box::pin(manager.open_or_create(&first_response, PartyId(1), &first.target))
                .await
                .unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));
        // n-f-1 distinct remote replies are sufficient to close the sampling round; the silent
        // third peer cannot hold the requester hostage.
        assert!(matches!(
            Box::pin(manager.open_or_create(&second_response, PartyId(2), &first.target))
                .await
                .unwrap(),
            DepositSyncSpoolAdmission::SamplingRoundComplete { round: 1 }
        ));
        drop(manager);

        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            first.advertisement.context().network(),
        )
        .unwrap();
        let releases = manager.pending_releases(first.advertisement.context()).await.unwrap();
        assert_eq!(releases.len(), 2);
        for request in releases.into_iter().filter(|request| request.source() != PartyId(1)) {
            manager
                .acknowledge_release(DepositSyncReleaseAck::issue(request).unwrap())
                .await
                .unwrap();
        }
        let stuck = manager.pending_releases(first.advertisement.context()).await.unwrap();
        assert_eq!(stuck.len(), 1);
        assert_eq!(stuck[0].source(), PartyId(1));

        let response_one = head_response(&first, PartyId(2), requester);
        let response_two = head_response(&first, PartyId(3), requester);
        assert!(matches!(
            Box::pin(manager.open_or_create(&response_one, PartyId(2), &first.target))
                .await
                .unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));
        let DepositSyncSpoolAdmission::Admitted { supporters, .. } =
            Box::pin(manager.open_or_create(&response_two, PartyId(3), &first.target))
                .await
                .unwrap()
        else {
            panic!("repolling one converged semantic family must admit");
        };
        assert_eq!(supporters, vec![PartyId(2), PartyId(3)]);
        assert_eq!(
            manager.pending_releases(first.advertisement.context()).await.unwrap()[0].source(),
            PartyId(1)
        );
    }

    #[tokio::test]
    async fn rejecting_unpromoted_prefix_attempt_quarantines_and_releases_its_only_source() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0x99; 32];
        let fixture = fixture_with_committee(0x9A, 4, 1);
        let requester = PartyId(4);
        let source = PartyId(1);
        let response = head_response(&fixture, source, requester);
        let statement_digest = [0x9B; 32];
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        assert!(matches!(
            Box::pin(manager.open_or_create(&response, source, &fixture.target)).await.unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));

        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let binding = spool_binding(&fixture.advertisement).unwrap();
            let (metadata, mut catalog) = manager.load_catalog(binding.key).await.unwrap();
            let claim = catalog.claims.remove(&source).unwrap();
            catalog.prefix_attempt = Some(DepositSyncPrefixSupportAttempt {
                binding: claim.binding,
                policy: claim.policy,
                facts: claim.facts,
                claim,
                statement_digest,
                state: DepositSyncPrefixAttemptState::Collecting,
            });
            manager.persist_catalog(metadata, &catalog).await.unwrap();
        }

        manager
            .reject_prefix_support_attempt(
                fixture.advertisement.context(),
                statement_digest,
                DepositSyncVariantRejection::SemanticInvalid,
            )
            .await
            .unwrap();
        drop(manager);

        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            fixture.advertisement.context().network(),
        )
        .unwrap();
        let releases = manager.pending_releases(fixture.advertisement.context()).await.unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].source(), source);
        let binding = spool_binding(&fixture.advertisement).unwrap();
        let (_, catalog) = manager.load_catalog(binding.key).await.unwrap();
        let failure = catalog.prefix_source_failures[&source];
        assert!(failure.permanent);
        assert_eq!(failure.retry_after_round, u64::MAX);
        assert!(
            catalog.prefix_attempt.is_none(),
            "recovery must remove only the rejected attempt after journaling its lease release"
        );
    }

    #[tokio::test]
    async fn prefix_source_cooldowns_persist_rotate_and_eventually_retry() {
        let directory = tempfile::tempdir().unwrap();
        let seed = [0xA1; 32];
        let higher = fixture_with_committee_and_index(0xA2, 4, 1, 3);
        let lower = fixture_with_committee_and_index(0xA2, 4, 1, 2);
        let requester = PartyId(4);
        let first_source = PartyId(1);
        let second_source = PartyId(2);
        let first_response = head_response(&higher, first_source, requester);
        let second_response = head_response(&lower, second_source, requester);
        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            higher.advertisement.context().network(),
        )
        .unwrap();

        assert!(matches!(
            Box::pin(manager.open_or_create(&first_response, first_source, &higher.target))
                .await
                .unwrap(),
            DepositSyncSpoolAdmission::Pending { supporters: 1, required: 2 }
        ));
        {
            let _catalog_mutation = manager.catalog_mutation.lock().await;
            let first_binding = spool_binding(&higher.advertisement).unwrap();
            let second_binding = spool_binding(&lower.advertisement).unwrap();
            assert_eq!(first_binding.key, second_binding.key);
            let (metadata, mut catalog) = manager.load_catalog(first_binding.key).await.unwrap();
            let second_policy = DepositSyncSpoolAdmissionPolicy::authenticated(
                &lower.advertisement,
                &lower.target,
                requester,
            )
            .unwrap();
            let second_facts =
                DepositSyncCandidateFacts::from_advertisement(&lower.advertisement).unwrap();
            let metadata = manager
                .install_claim_response(
                    metadata,
                    &mut catalog,
                    second_source,
                    &second_response,
                    second_binding,
                    second_policy,
                    second_facts,
                )
                .await
                .unwrap();
            assert_eq!(select_prefix_claim(&catalog).unwrap().0, first_source);

            let first_claim = catalog.claims[&first_source];
            record_prefix_source_failure(
                &mut catalog,
                first_source,
                first_claim.binding,
                first_claim.policy,
                first_claim.facts,
                DepositSyncPrefixFailureClass::Transient,
            )
            .unwrap();
            assert_eq!(
                select_prefix_claim(&catalog).unwrap().0,
                second_source,
                "the failed best tip must not win the next selection"
            );
            let second_claim = catalog.claims[&second_source];
            record_prefix_source_failure(
                &mut catalog,
                second_source,
                second_claim.binding,
                second_claim.policy,
                second_claim.facts,
                DepositSyncPrefixFailureClass::Transient,
            )
            .unwrap();
            assert!(
                select_prefix_claim(&catalog).is_none(),
                "all cooling sources must close this round instead of being retried immediately"
            );
            manager.persist_catalog(Some(metadata), &catalog).await.unwrap();
        }
        drop(manager);

        let manager = DepositSyncSpoolManager::new(
            directory.path(),
            requester,
            &seed,
            higher.advertisement.context().network(),
        )
        .unwrap();
        let first_binding = spool_binding(&higher.advertisement).unwrap();
        let (metadata, mut catalog) = manager.load_catalog(first_binding.key).await.unwrap();
        assert_eq!(catalog.prefix_source_failures.len(), 2);
        assert!(select_prefix_claim(&catalog).is_none());
        catalog.sampling_round = 1;
        assert!(select_prefix_claim(&catalog).is_none());
        catalog.sampling_round = 2;
        assert!(
            select_prefix_claim(&catalog).is_some(),
            "bounded cooldown must make transiently failed sources eligible again"
        );
        manager.persist_catalog(metadata, &catalog).await.unwrap();
    }

    #[test]
    fn checkpoint_phase_machine_and_cursor_bound_are_strict() {
        let downloading = DepositSyncSpoolCheckpoint::downloading();
        let frozen = downloading.successor(DepositSyncSpoolPhase::Frozen, Vec::new()).unwrap();
        assert!(frozen.successor(DepositSyncSpoolPhase::Materializing, Vec::new()).is_err());
        assert!(
            downloading
                .successor(
                    DepositSyncSpoolPhase::Downloading,
                    vec![0; MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES + 1],
                )
                .is_err()
        );
        assert!(
            downloading
                .successor(
                    DepositSyncSpoolPhase::Downloading,
                    vec![0; MAX_DEPOSIT_SYNC_SPOOL_CURSOR_BYTES],
                )
                .is_ok()
        );
    }
}
