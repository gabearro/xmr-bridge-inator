//! Durable source-side lifetime graph for portable deposit-index objects.
//!
//! The wallet snapshot remains the sole authority for the current portable head. This store
//! mirrors only object lifetime: immutable child edges are counted once when an object enters the
//! live graph, while the current head and every source lease contribute named-root references.
//! Replacing a named root merely queues zero-reference objects. Recursive unlinking is performed
//! in bounded redb transactions and the encrypted artifact is acknowledged only after its exact
//! authenticated file has been removed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    committee::{MAX_COMMITTEE_MEMBERS, PartyId},
    deposit_index::{
        DepositIndexError, DepositIndexHead, DepositIndexObjectId, DepositIndexReader,
        MAX_DEPOSIT_INDEX_OBJECT_BYTES, MAX_DEPOSIT_INDEX_UPDATE_BYTES,
        MAX_DEPOSIT_INDEX_UPDATE_OBJECTS, VerifiedPortableIndexObject, verify_deposit_index_head,
        verify_portable_index_object,
    },
    deposit_index_checkpoint::PortableDepositIndexHead,
    deposit_state_export::{
        DepositPostHandoffExportSealCertificate, DepositStateExportError,
        VerifiedDepositPostHandoffExportCandidate, VerifiedDepositPostHandoffExportSeal,
    },
    deposit_state_import::{
        DepositStateImportError, VerifiedStateImportCandidateTransitionBinding,
        VerifiedStateImportTransitionBinding, VerifiedStateImportedCertificate,
    },
    deposit_sync_wire::DepositSyncAdvertisement,
    deposit_wallet::DepositWalletId,
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{StoreError, WalletArtifactStore},
};

const RETENTION_VERSION: u16 = 4;
const OBJECT_RECORD_VERSION: u16 = 4;
const SOURCE_PIN_VERSION: u16 = 5;
const EXPORT_PIN_VERSION: u16 = 4;
const QUEUE_RECORD_VERSION: u16 = 4;
const RETENTION_DIRECTORY: &str = "deposit-index-retention-v4";
const RETENTION_FILE_SUFFIX: &str = ".redb";
const RETENTION_SUBKEY_DOMAIN: &[u8] =
    b"threshold-monero/deposit-index-retention/authentication/v4";
const RETENTION_MAC_KEY_DOMAIN: &str = "threshold-monero/deposit-index-retention/wallet-mac-key/v4";
const RECORD_MAC_DOMAIN: &str = "threshold-monero/deposit-index-retention/record-mac/v4";
const EXPORT_EXACT_LOOKUP_DOMAIN: &str =
    "threshold-monero/deposit-index-retention/export-exact-lookup/v4";
const ORDINARY_SOURCE_PIN_AUTHORITY_DOMAIN: &str =
    "threshold-monero/deposit-index-retention/ordinary-source-pin-authority/v1";
const CERTIFIED_EXPORT_SOURCE_PIN_AUTHORITY_DOMAIN: &str =
    "threshold-monero/deposit-index-retention/certified-export-source-pin-authority/v1";
const META_KEY: &[u8] = b"active";
const META_LABEL: &[u8] = b"meta";
const OBJECT_LABEL: &[u8] = b"object";
const PIN_LABEL: &[u8] = b"source-pin";
const RELEASED_PIN_LABEL: &[u8] = b"released-source-pin";
const EXPORT_PIN_LABEL: &[u8] = b"export-pin";
const EXPORT_INDEX_LABEL: &[u8] = b"export-index";
const EXPORT_RECLAIM_LABEL: &[u8] = b"export-reclaim";
const UNLINK_LABEL: &[u8] = b"unlink";
const DELETE_LABEL: &[u8] = b"artifact-delete";
const IMPORT_OBJECT_LABEL: &[u8] = b"import-object";
const IMPORT_STACK_LABEL: &[u8] = b"import-dfs-stack";
const IMPORT_VISITING_LABEL: &[u8] = b"import-dfs-visiting";
const IMPORT_REACHED_LABEL: &[u8] = b"import-reached";
const IMPORT_REGISTERED_LABEL: &[u8] = b"import-registered";
const IMPORT_PENDING_REF_LABEL: &[u8] = b"import-pending-reference";
const REAUTH_STACK_LABEL: &[u8] = b"reauth-dfs-stack";
const REAUTH_VISITING_LABEL: &[u8] = b"reauth-dfs-visiting";
const REAUTH_REACHED_LABEL: &[u8] = b"reauth-reached";
const REAUTH_PENDING_LABEL: &[u8] = b"reauth-pending";
const REAUTH_OBJECT_LABEL: &[u8] = b"reauth-object";
const MAX_META_BYTES: usize = 4 * 1024;
const MAX_OBJECT_RECORD_BYTES: usize = 16 * 1024;
const MAX_QUEUE_RECORD_BYTES: usize = 1024;
const MAX_EXPORT_ADVERTISEMENT_BYTES: usize = 272 * 1024;
const MAX_EXPORT_SEAL_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_EXPORT_RECORD_BYTES: usize =
    MAX_EXPORT_ADVERTISEMENT_BYTES + MAX_EXPORT_SEAL_CERTIFICATE_BYTES + 32 * 1024;
const MAX_REAUTH_OBJECT_RECORD_BYTES: usize = MAX_DEPOSIT_INDEX_OBJECT_BYTES + 1024;
#[cfg(test)]
const SYNTHETIC_EXPORT_ADVERTISEMENT: &[u8] = b"retention-v4-synthetic-export";
#[cfg(test)]
const SYNTHETIC_EXPORT_SEAL_CERTIFICATE: &[u8] = b"retention-v4-synthetic-export-seal-certificate";
/// A head response is substantially smaller than a transfer page. Keeping a separate cap prevents
/// a committee member from consuming the page-sized wire allowance in every durable lease slot.
pub const MAX_SOURCE_PIN_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_RELEASED_SOURCE_PIN_FLOORS: usize = MAX_COMMITTEE_MEMBERS * 2;
/// Each recursive graph-unlink transaction has a fixed amount of redb work.
pub const RETENTION_GC_BATCH_OBJECTS: usize = 64;
/// One imported-object descriptor page is independently authenticated and committed.
pub const RETENTION_IMPORT_BATCH_OBJECTS: usize = 256;
/// Plaintext admitted by one imported-object descriptor page.
pub const RETENTION_IMPORT_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Permanent-object verification and encrypted reads are bounded independently per turn.
pub const RETENTION_REAUTH_BATCH_OBJECTS: usize = 16;
pub const RETENTION_REAUTH_TRAVERSAL_STEPS: usize = 256;
pub const RETENTION_REAUTH_BATCH_BYTES: usize = MAX_DEPOSIT_INDEX_UPDATE_BYTES;
/// Bounded redb cache retained by one wallet's source-side lifetime graph.
pub const DEPOSIT_INDEX_RETENTION_CACHE_BYTES: usize = 16 * 1024 * 1024;

const META_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-meta-v4");
const OBJECT_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-objects-v4");
const PIN_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-source-pins-v4");
const RELEASED_PIN_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-released-source-pins-v4");
const EXPORT_PIN_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-export-pins-v4");
const EXPORT_INDEX_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-export-index-v4");
const EXPORT_RECLAIM_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-export-reclaims-v4");
const UNLINK_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-unlink-v4");
const DELETE_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-artifact-delete-v4");
const IMPORT_OBJECT_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-import-objects-v4");
const IMPORT_STACK_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-import-dfs-stack-v4");
const IMPORT_VISITING_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-import-dfs-visiting-v4");
const IMPORT_REACHED_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-import-reached-v4");
const IMPORT_REGISTERED_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-import-registered-v4");
const IMPORT_PENDING_REF_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-import-pending-refs-v4");
const REAUTH_STACK_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-reauth-stack-v4");
const REAUTH_VISITING_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-reauth-visiting-v4");
const REAUTH_REACHED_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-reauth-reached-v4");
const REAUTH_PENDING_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-reauth-pending-v4");
const REAUTH_OBJECT_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("deposit-index-retention-reauth-objects-v4");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableMeta {
    version: u16,
    wallet: DepositWalletId,
    source: PartyId,
    revision: u64,
    current_root: Option<DepositIndexObjectId>,
    object_count: u64,
    active_pin_count: u16,
    released_pin_count: u16,
    export_pin_count: u64,
    export_reclaim_count: u64,
    unlink_count: u64,
    delete_count: u64,
    authorization: Option<SourcePinAuthorization>,
    authorized_requesters: Vec<PartyId>,
    import: Option<DurableImport>,
    reauthentication: Option<DurableReauthentication>,
}

impl DurableMeta {
    fn fresh(wallet: DepositWalletId, source: PartyId) -> Self {
        Self {
            version: RETENTION_VERSION,
            wallet,
            source,
            revision: 0,
            current_root: None,
            object_count: 0,
            active_pin_count: 0,
            released_pin_count: 0,
            export_pin_count: 0,
            export_reclaim_count: 0,
            unlink_count: 0,
            delete_count: 0,
            authorization: None,
            authorized_requesters: Vec::new(),
            import: None,
            reauthentication: None,
        }
    }

    fn validate(&self, wallet: DepositWalletId, source: PartyId) -> Result<(), RetentionError> {
        if self.version != RETENTION_VERSION
            || self.wallet != wallet
            || self.source != source
            || wallet.0 == [0_u8; 32]
            || source == PartyId(0)
            || usize::from(self.active_pin_count) > MAX_COMMITTEE_MEMBERS
            || usize::from(self.released_pin_count) > MAX_RELEASED_SOURCE_PIN_FLOORS
            || self.current_root.is_some_and(|root| root.wallet_id() != wallet)
            || self.authorization.as_ref().is_some_and(|authorization| {
                authorization.committee == [0_u8; 32] || authorization.activation == [0_u8; 32]
            })
            || self.authorized_requesters.len() > MAX_COMMITTEE_MEMBERS
            || self.authorized_requesters.iter().any(|requester| *requester == PartyId(0))
            || self.authorized_requesters.windows(2).any(|pair| pair[0] >= pair[1])
            || self.authorization.is_some() != !self.authorized_requesters.is_empty()
            || self.import.as_ref().is_some_and(|import| import.validate(wallet).is_err())
            || self
                .reauthentication
                .as_ref()
                .is_some_and(|reauthentication| reauthentication.validate(wallet).is_err())
            || (self.import.is_some() && self.reauthentication.is_some())
            || self.import.as_ref().is_some_and(|import| match import.phase {
                ImportPhase::Cleanup => self.current_root != Some(import.target),
                _ => self.current_root != import.expected_old,
            })
        {
            return Err(RetentionError::InvalidDurableState);
        }
        Ok(())
    }

    fn bump_revision(&mut self) -> Result<(), RetentionError> {
        self.revision = self.revision.checked_add(1).ok_or(RetentionError::RevisionExhausted)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ImportPhase {
    Staging,
    Traversing,
    Registering,
    Publishing,
    Cleanup,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableImport {
    version: u16,
    binding: [u8; 32],
    expected_old: Option<DepositIndexObjectId>,
    target: DepositIndexObjectId,
    maximum_objects: u64,
    maximum_plaintext_bytes: u64,
    staged_objects: u64,
    staged_plaintext_bytes: u64,
    stack_depth: u64,
    visiting_count: u64,
    reached_count: u64,
    reached_import_objects: u64,
    registered_count: u64,
    pending_reference_count: u64,
    phase: ImportPhase,
}

impl DurableImport {
    fn validate(&self, wallet: DepositWalletId) -> Result<(), RetentionError> {
        authenticate_id(self.target, wallet)?;
        if self.version != RETENTION_VERSION
            || self.binding == [0_u8; 32]
            || self.maximum_objects == 0
            || self.maximum_plaintext_bytes == 0
            || self.staged_objects > self.maximum_objects
            || self.staged_plaintext_bytes > self.maximum_plaintext_bytes
            || self.reached_import_objects > self.staged_objects
            || self.registered_count > self.staged_objects
            || self.stack_depth != self.visiting_count
            || self
                .reached_count
                .checked_add(self.visiting_count)
                .is_none_or(|discovered| discovered > self.maximum_objects)
        {
            return Err(RetentionError::InvalidDurableState);
        }
        if let Some(old) = self.expected_old {
            authenticate_id(old, wallet)?;
        }
        let phase_is_valid = match self.phase {
            ImportPhase::Staging => {
                self.stack_depth == 0
                    && self.reached_count == 0
                    && self.reached_import_objects == 0
                    && self.registered_count == 0
                    && self.pending_reference_count == 0
            }
            ImportPhase::Traversing => {
                self.stack_depth != 0
                    && self.registered_count == 0
                    && self.pending_reference_count == 0
            }
            ImportPhase::Registering => {
                self.stack_depth == 0
                    && self.reached_count != 0
                    && self.reached_import_objects == self.staged_objects
            }
            ImportPhase::Publishing => {
                self.stack_depth == 0
                    && self.reached_count != 0
                    && self.reached_import_objects == self.staged_objects
                    && self.registered_count == self.staged_objects
                    && self.pending_reference_count == 0
            }
            ImportPhase::Cleanup => {
                self.stack_depth == 0
                    && self.reached_import_objects == self.staged_objects
                    && self.pending_reference_count == 0
            }
        };
        if !phase_is_valid {
            return Err(RetentionError::InvalidDurableState);
        }
        Ok(())
    }
}

/// Exact named-root authority which must remain present throughout permanent-object
/// reauthentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum PortableReauthenticationAnchor {
    Current,
    Export { semantic_transition: [u8; 32] },
}

impl PortableReauthenticationAnchor {
    fn validate(self) -> Result<(), RetentionError> {
        if matches!(
            self,
            Self::Export {
                semantic_transition
            } if semantic_transition == [0; 32]
        ) {
            return Err(RetentionError::InvalidReauthenticationBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ReauthenticationPhase {
    Traversing,
    Verified,
    CleanupRestart,
    CleanupClear,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableReauthentication {
    version: u16,
    anchor: PortableReauthenticationAnchor,
    head: PortableDepositIndexHead,
    root: DepositIndexObjectId,
    head_digest: [u8; 32],
    maximum_objects: u64,
    stack_depth: u64,
    visiting_count: u64,
    reached_count: u64,
    pending_count: u64,
    verified_count: u64,
    phase: ReauthenticationPhase,
}

impl DurableReauthentication {
    fn validate(&self, wallet: DepositWalletId) -> Result<(), RetentionError> {
        authenticate_id(self.root, wallet)?;
        self.anchor.validate()?;
        let maximum_objects = self
            .head
            .maximum_reachable_objects()
            .map_err(|_| RetentionError::InvalidDurableState)?;
        let discovered = self
            .reached_count
            .checked_add(self.visiting_count)
            .ok_or(RetentionError::InvalidDurableState)?;
        if self.version != RETENTION_VERSION
            || self.head_digest == [0; 32]
            || self.head.wallet_id() != wallet
            || self.head.root() != Some(self.root)
            || self.head.digest() != self.head_digest
            || maximum_objects != self.maximum_objects
            || self.maximum_objects == 0
            || self.stack_depth != self.visiting_count
            || self.verified_count.checked_add(self.pending_count) != Some(self.reached_count)
            || discovered > self.maximum_objects
            || match self.phase {
                ReauthenticationPhase::Traversing => {
                    self.stack_depth == 0 && self.pending_count == 0
                }
                ReauthenticationPhase::Verified
                | ReauthenticationPhase::CleanupRestart
                | ReauthenticationPhase::CleanupClear => {
                    self.stack_depth != 0
                        || self.visiting_count != 0
                        || self.pending_count != 0
                        || self.reached_count == 0
                        || self.verified_count != self.reached_count
                }
            }
        {
            return Err(RetentionError::InvalidDurableState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DfsFrameRecord {
    version: u16,
    depth: u64,
    id: DepositIndexObjectId,
    next_child: u8,
}

impl DfsFrameRecord {
    fn validate(&self, wallet: DepositWalletId, expected_depth: u64) -> Result<(), RetentionError> {
        if self.version != RETENTION_VERSION
            || self.depth != expected_depth
            || usize::from(self.next_child) > 32
        {
            return Err(RetentionError::InvalidDurableState);
        }
        authenticate_id(self.id, wallet)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ReauthenticationObjectRecord {
    version: u16,
    id: DepositIndexObjectId,
    bytes: Vec<u8>,
}

impl ReauthenticationObjectRecord {
    fn validate(&self, wallet: DepositWalletId) -> Result<(), RetentionError> {
        authenticate_id(self.id, wallet)?;
        if self.version != RETENTION_VERSION
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_DEPOSIT_INDEX_OBJECT_BYTES
        {
            return Err(RetentionError::InvalidDurableState);
        }
        self.id.storage_reference().verify_contents(&self.bytes)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PendingReferenceRecord {
    version: u16,
    id: DepositIndexObjectId,
    references: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourcePinAuthorization {
    epoch: u64,
    committee: [u8; 32],
    activation: [u8; 32],
}

impl SourcePinAuthorization {
    fn from_target(target: &VerifiedRegistryHandoffTarget) -> Self {
        Self {
            epoch: target.committee().epoch,
            committee: target.committee().digest(),
            activation: target.activation(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum SourcePinFamily {
    Ordinary,
    CertifiedExport,
}

impl SourcePinFamily {
    const fn lookup_tag(self) -> u8 {
        match self {
            Self::Ordinary => 1,
            Self::CertifiedExport => 2,
        }
    }

    fn from_lookup_tag(tag: u8) -> Result<Self, RetentionError> {
        match tag {
            1 => Ok(Self::Ordinary),
            2 => Ok(Self::CertifiedExport),
            _ => Err(RetentionError::InvalidDurableState),
        }
    }
}

/// Typed, domain-separated identity of the immutable head a requester is polling.
///
/// The wire lease remains the exact release capability. This authority is deliberately independent
/// of request-local material such as an ExportHead nonce, so changing a nonce cannot turn the same
/// certified export into durable write churn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourcePinSemanticAuthority {
    family: SourcePinFamily,
    digest: [u8; 32],
}

impl SourcePinSemanticAuthority {
    pub(crate) fn ordinary(advertisement_digest: [u8; 32]) -> Self {
        Self {
            family: SourcePinFamily::Ordinary,
            digest: source_pin_authority_digest(
                ORDINARY_SOURCE_PIN_AUTHORITY_DOMAIN,
                advertisement_digest,
            ),
        }
    }

    fn certified_export(semantic_transition: [u8; 32]) -> Self {
        Self {
            family: SourcePinFamily::CertifiedExport,
            digest: source_pin_authority_digest(
                CERTIFIED_EXPORT_SOURCE_PIN_AUTHORITY_DOMAIN,
                semantic_transition,
            ),
        }
    }
}

fn source_pin_authority_digest(domain: &str, semantic: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&semantic);
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ObjectRecord {
    version: u16,
    id: DepositIndexObjectId,
    node: bool,
    children: Vec<DepositIndexObjectId>,
    references: u64,
}

impl ObjectRecord {
    fn from_verified(id: DepositIndexObjectId, verified: VerifiedPortableIndexObject) -> Self {
        Self {
            version: OBJECT_RECORD_VERSION,
            id,
            node: verified.is_node(),
            children: verified.children().to_vec(),
            references: 0,
        }
    }

    fn validate(&self, wallet: DepositWalletId) -> Result<(), RetentionError> {
        authenticate_id(self.id, wallet)?;
        if self.version != OBJECT_RECORD_VERSION
            || self.children.len() > 32
            || self.children.iter().any(|child| child.wallet_id() != wallet)
        {
            return Err(RetentionError::InvalidDurableState);
        }
        for child in &self.children {
            authenticate_id(*child, wallet)?;
        }
        Ok(())
    }

    fn same_object(&self, candidate: &Self) -> bool {
        self.version == candidate.version
            && self.id == candidate.id
            && self.node == candidate.node
            && self.children == candidate.children
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SourcePinRecord {
    version: u16,
    wallet: DepositWalletId,
    source: PartyId,
    requester: PartyId,
    family: SourcePinFamily,
    semantic_authority: [u8; 32],
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
    root: DepositIndexObjectId,
    response: Vec<u8>,
}

impl SourcePinRecord {
    fn validate(&self, wallet: DepositWalletId, source: PartyId) -> Result<(), RetentionError> {
        if self.version != SOURCE_PIN_VERSION
            || self.wallet != wallet
            || self.source != source
            || self.requester == PartyId(0)
            || self.semantic_authority == [0_u8; 32]
            || self.context_digest == [0_u8; 32]
            || self.lease_digest == [0_u8; 32]
            || self.response.is_empty()
            || self.response.len() > MAX_SOURCE_PIN_RESPONSE_BYTES
        {
            return Err(RetentionError::InvalidDurableState);
        }
        authenticate_id(self.root, wallet)
    }

    fn matches_lease(
        &self,
        source: PartyId,
        requester: PartyId,
        context_digest: [u8; 32],
        lease_digest: [u8; 32],
    ) -> bool {
        self.source == source
            && self.requester == requester
            && self.context_digest == context_digest
            && self.lease_digest == lease_digest
    }

    fn matches_acquisition(
        &self,
        source: PartyId,
        requester: PartyId,
        authority: SourcePinSemanticAuthority,
        context_digest: [u8; 32],
        lease_digest: [u8; 32],
    ) -> bool {
        self.family == authority.family
            && self.semantic_authority == authority.digest
            && self.matches_lease(source, requester, context_digest, lease_digest)
    }
}

/// Authenticated bounded tombstone for one requester's most recently released semantic head.
///
/// It carries no object reference and exists solely to reject equal-head polling after the first
/// acquire/release pair, even if request-local nonce material creates a new wire lease. Ordinary
/// and certified-export families retain independent floors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ReleasedSourcePinRecord {
    version: u16,
    wallet: DepositWalletId,
    source: PartyId,
    requester: PartyId,
    family: SourcePinFamily,
    semantic_authority: [u8; 32],
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
}

impl ReleasedSourcePinRecord {
    fn from_active(record: &SourcePinRecord) -> Self {
        Self {
            version: SOURCE_PIN_VERSION,
            wallet: record.wallet,
            source: record.source,
            requester: record.requester,
            family: record.family,
            semantic_authority: record.semantic_authority,
            context_digest: record.context_digest,
            lease_digest: record.lease_digest,
        }
    }

    fn validate(&self, wallet: DepositWalletId, source: PartyId) -> Result<(), RetentionError> {
        if self.version != SOURCE_PIN_VERSION
            || self.wallet != wallet
            || self.source != source
            || self.requester == PartyId(0)
            || self.semantic_authority == [0_u8; 32]
            || self.context_digest == [0_u8; 32]
            || self.lease_digest == [0_u8; 32]
        {
            return Err(RetentionError::InvalidDurableState);
        }
        Ok(())
    }

    fn matches_authority(&self, authority: SourcePinSemanticAuthority) -> bool {
        self.family == authority.family && self.semantic_authority == authority.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ExportSealCertificateRecord {
    digest: [u8; 32],
    bytes: Vec<u8>,
}

impl ExportSealCertificateRecord {
    fn from_verified(seal: &VerifiedDepositPostHandoffExportSeal) -> Result<Self, RetentionError> {
        let record = Self {
            digest: seal.certificate_digest(),
            bytes: seal.canonical_certificate_bytes().to_vec(),
        };
        record.validate(seal.statement_digest())?;
        Ok(record)
    }

    fn validate(&self, seal_statement: [u8; 32]) -> Result<(), RetentionError> {
        if self.digest == [0; 32]
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_EXPORT_SEAL_CERTIFICATE_BYTES
            || seal_statement == [0; 32]
        {
            return Err(RetentionError::InvalidExportPinBinding);
        }
        #[cfg(test)]
        if self.bytes == SYNTHETIC_EXPORT_SEAL_CERTIFICATE {
            return Ok(());
        }
        let certificate = DepositPostHandoffExportSealCertificate::from_bytes(&self.bytes)?;
        if certificate.statement().digest() != seal_statement
            || certificate.digest()? != self.digest
        {
            return Err(RetentionError::InvalidExportPinBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ExportPinRecord {
    version: u16,
    wallet: DepositWalletId,
    source: PartyId,
    network: [u8; 32],
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    source_registry: [u8; 32],
    vote_slot: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_certificate: [u8; 32],
    export_context: [u8; 32],
    target_epoch: u64,
    target_committee: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    advertisement_digest: [u8; 32],
    advertisement: Vec<u8>,
    registry_checkpoint: [u8; 32],
    target_registry: [u8; 32],
    target_registry_archive: [u8; 32],
    target_registry_index_root: [u8; 32],
    target_registry_active_link: [u8; 32],
    target_registry_active_witness: [u8; 32],
    archive_event: [u8; 32],
    archive_segment: [u8; 32],
    terminal_checkpoint_sequence: u64,
    terminal_checkpoint_decision: [u8; 32],
    terminal_checkpoint_certificate: [u8; 32],
    terminal_portable_root: DepositIndexObjectId,
    terminal_portable_head: [u8; 32],
    source_party: PartyId,
    seal_statement: [u8; 32],
    seal_certificate: Option<ExportSealCertificateRecord>,
    export_binding: [u8; 32],
}

impl ExportPinRecord {
    fn from_verified_candidate(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Self, RetentionError> {
        let transition =
            VerifiedStateImportCandidateTransitionBinding::from_verified_export_candidate(
                candidate,
            )?;
        let statement = candidate.statement();
        let final_export = statement.final_export();
        final_export.validate_advertisement(advertisement)?;
        let canonical_advertisement =
            advertisement.to_bytes().map_err(|_| RetentionError::InvalidExportPinBinding)?;
        if canonical_advertisement.is_empty()
            || canonical_advertisement.len() > MAX_EXPORT_ADVERTISEMENT_BYTES
            || DepositSyncAdvertisement::from_bytes(&canonical_advertisement)
                .map_err(|_| RetentionError::InvalidExportPinBinding)?
                != *advertisement
        {
            return Err(RetentionError::InvalidExportPinBinding);
        }
        let terminal = final_export.terminal_checkpoint();
        let portable = final_export.resulting_portable_head();
        let root = portable.root().ok_or(RetentionError::InvalidExportPinBinding)?;
        let registry_archive = final_export.target_registry_archive();
        let archive = final_export.archive();
        let record = Self {
            version: EXPORT_PIN_VERSION,
            wallet: transition.wallet(),
            source: transition.source_party(),
            network: transition.network(),
            semantic_transition: transition.semantic_transition_digest(),
            transition_binding: transition.transition_binding(),
            source_registry: statement.source().digest(),
            vote_slot: statement.vote_slot_digest(),
            handoff_statement: statement.handoff_statement_digest(),
            handoff_certificate: statement.handoff_certificate_digest(),
            export_context: statement.export_capability_context(),
            target_epoch: statement.target_epoch(),
            target_committee: statement.target_committee(),
            target_activation: statement.target_activation(),
            target_certified_activation_root: statement.target_certified_activation_root(),
            advertisement_digest: final_export.advertisement_digest(),
            advertisement: canonical_advertisement,
            registry_checkpoint: final_export.registry_checkpoint_digest(),
            target_registry: registry_archive.registry_id().digest(),
            target_registry_archive: registry_archive
                .digest()
                .map_err(|_| RetentionError::InvalidExportPinBinding)?,
            target_registry_index_root: registry_archive.index_root_reference().digest(),
            target_registry_active_link: registry_archive.active_link_reference().digest(),
            target_registry_active_witness: registry_archive
                .active_witness_reference()
                .ok_or(RetentionError::InvalidExportPinBinding)?
                .digest(),
            archive_event: archive
                .event_reference()
                .ok_or(RetentionError::InvalidExportPinBinding)?
                .digest(),
            archive_segment: archive
                .segment_reference()
                .ok_or(RetentionError::InvalidExportPinBinding)?
                .digest(),
            terminal_checkpoint_sequence: terminal.sequence(),
            terminal_checkpoint_decision: terminal.decision(),
            terminal_checkpoint_certificate: final_export.terminal_checkpoint_certificate_digest(),
            terminal_portable_root: root,
            terminal_portable_head: portable.digest(),
            source_party: transition.source_party(),
            seal_statement: statement.digest(),
            seal_certificate: None,
            export_binding: final_export.digest()?,
        };
        record.validate(record.wallet, record.source)?;
        Ok(record)
    }

    fn validate(
        &self,
        wallet: DepositWalletId,
        local_source: PartyId,
    ) -> Result<(), RetentionError> {
        authenticate_id(self.terminal_portable_root, wallet)?;
        #[cfg(test)]
        if self.advertisement == SYNTHETIC_EXPORT_ADVERTISEMENT {
            return self.validate_synthetic(wallet, local_source);
        }
        let advertisement = DepositSyncAdvertisement::from_bytes(&self.advertisement)
            .map_err(|_| RetentionError::InvalidExportPinBinding)?;
        let registry_archive = advertisement.registry_archive();
        let archive = advertisement.certificate_archive();
        let checkpoint = advertisement
            .checkpoint_certificate()
            .ok_or(RetentionError::InvalidExportPinBinding)?;
        let target_active = registry_archive.registry().active();
        if self.version != EXPORT_PIN_VERSION
            || self.wallet != wallet
            || self.source != local_source
            || self.source_party != local_source
            || local_source == PartyId(0)
            || self.network == [0; 32]
            || self.semantic_transition == [0; 32]
            || self.transition_binding == [0; 32]
            || self.source_registry == [0; 32]
            || self.vote_slot == [0; 32]
            || self.handoff_statement == [0; 32]
            || self.handoff_certificate == [0; 32]
            || self.export_context == [0; 32]
            || self.target_epoch == 0
            || self.target_committee == [0; 32]
            || self.target_activation == [0; 32]
            || self.target_certified_activation_root == [0; 32]
            || self.advertisement_digest == [0; 32]
            || self.advertisement.is_empty()
            || self.advertisement.len() > MAX_EXPORT_ADVERTISEMENT_BYTES
            || advertisement.context().network() != self.network
            || advertisement.context().wallet() != wallet
            || advertisement.digest() != self.advertisement_digest
            || advertisement.registry_checkpoint_digest() != self.registry_checkpoint
            || advertisement.registry_id().digest() != self.target_registry
            || registry_archive.digest().map_err(|_| RetentionError::InvalidExportPinBinding)?
                != self.target_registry_archive
            || registry_archive.index_root_reference().digest() != self.target_registry_index_root
            || registry_archive.active_link_reference().digest() != self.target_registry_active_link
            || registry_archive
                .active_witness_reference()
                .is_none_or(|reference| reference.digest() != self.target_registry_active_witness)
            || archive
                .event_reference()
                .is_none_or(|reference| reference.digest() != self.archive_event)
            || archive
                .segment_reference()
                .is_none_or(|reference| reference.digest() != self.archive_segment)
            || target_active.epoch() != self.target_epoch
            || target_active.committee().digest() != self.target_committee
            || target_active.activation() != self.target_activation
            || target_active.certified_activation_root() != self.target_certified_activation_root
            || self.terminal_checkpoint_sequence == 0
            || self.terminal_checkpoint_decision == [0; 32]
            || checkpoint.statement().sequence() != self.terminal_checkpoint_sequence
            || checkpoint.statement().decision_digest() != self.terminal_checkpoint_decision
            || checkpoint
                .certificate_digest()
                .map_err(|_| RetentionError::InvalidExportPinBinding)?
                != self.terminal_checkpoint_certificate
            || advertisement.portable_index().root() != Some(self.terminal_portable_root)
            || advertisement.portable_index().digest() != self.terminal_portable_head
            || self.terminal_portable_head == [0; 32]
            || self.seal_statement == [0; 32]
            || self.export_binding == [0; 32]
        {
            return Err(RetentionError::InvalidExportPinBinding);
        }
        if let Some(certificate) = &self.seal_certificate {
            certificate.validate(self.seal_statement)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_synthetic(
        &self,
        wallet: DepositWalletId,
        local_source: PartyId,
    ) -> Result<(), RetentionError> {
        if self.version != EXPORT_PIN_VERSION
            || self.wallet != wallet
            || self.source != local_source
            || self.source_party != local_source
            || local_source == PartyId(0)
            || self.network == [0; 32]
            || self.semantic_transition == [0; 32]
            || self.transition_binding == [0; 32]
            || self.source_registry == [0; 32]
            || self.vote_slot == [0; 32]
            || self.handoff_statement == [0; 32]
            || self.handoff_certificate == [0; 32]
            || self.export_context == [0; 32]
            || self.target_epoch == 0
            || self.target_committee == [0; 32]
            || self.target_activation == [0; 32]
            || self.target_certified_activation_root == [0; 32]
            || self.advertisement_digest == [0; 32]
            || self.registry_checkpoint == [0; 32]
            || self.target_registry == [0; 32]
            || self.target_registry_archive == [0; 32]
            || self.target_registry_index_root == [0; 32]
            || self.target_registry_active_link == [0; 32]
            || self.target_registry_active_witness == [0; 32]
            || self.archive_event == [0; 32]
            || self.archive_segment == [0; 32]
            || self.terminal_checkpoint_sequence == 0
            || self.terminal_checkpoint_decision == [0; 32]
            || self.terminal_checkpoint_certificate == [0; 32]
            || self.terminal_portable_head == [0; 32]
            || self.seal_statement == [0; 32]
            || self.export_binding == [0; 32]
        {
            return Err(RetentionError::InvalidExportPinBinding);
        }
        if let Some(certificate) = &self.seal_certificate {
            certificate.validate(self.seal_statement)?;
        }
        Ok(())
    }

    fn matches_verified_seal(
        &self,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<bool, RetentionError> {
        let transition = VerifiedStateImportTransitionBinding::from_verified_export_seal(seal)?;
        let statement = seal.statement();
        let final_export = statement.final_export();
        let advertisement = DepositSyncAdvertisement::from_bytes(&self.advertisement)
            .map_err(|_| RetentionError::InvalidExportPinBinding)?;
        final_export.validate_advertisement(&advertisement)?;
        let terminal = final_export.terminal_checkpoint();
        let portable = final_export.resulting_portable_head();
        let registry_archive = final_export.target_registry_archive();
        let archive = final_export.archive();
        Ok(self.wallet == transition.wallet()
            && self.source == transition.source_party()
            && self.network == transition.network()
            && self.semantic_transition == transition.semantic_transition_digest()
            && self.transition_binding == transition.transition_binding()
            && self.source_registry == statement.source().digest()
            && self.vote_slot == statement.vote_slot_digest()
            && self.handoff_statement == statement.handoff_statement_digest()
            && self.handoff_certificate == statement.handoff_certificate_digest()
            && self.export_context == statement.export_capability_context()
            && self.target_epoch == statement.target_epoch()
            && self.target_committee == statement.target_committee()
            && self.target_activation == statement.target_activation()
            && self.target_certified_activation_root
                == statement.target_certified_activation_root()
            && self.advertisement_digest == final_export.advertisement_digest()
            && self.registry_checkpoint == final_export.registry_checkpoint_digest()
            && self.target_registry == registry_archive.registry_id().digest()
            && self.target_registry_archive
                == registry_archive
                    .digest()
                    .map_err(|_| RetentionError::InvalidExportPinBinding)?
            && self.target_registry_index_root == registry_archive.index_root_reference().digest()
            && self.target_registry_active_link
                == registry_archive.active_link_reference().digest()
            && Some(self.target_registry_active_witness)
                == registry_archive.active_witness_reference().map(|reference| reference.digest())
            && Some(self.archive_event)
                == archive.event_reference().map(|reference| reference.digest())
            && Some(self.archive_segment)
                == archive.segment_reference().map(|reference| reference.digest())
            && self.terminal_checkpoint_sequence == terminal.sequence()
            && self.terminal_checkpoint_decision == terminal.decision()
            && self.terminal_checkpoint_certificate
                == final_export.terminal_checkpoint_certificate_digest()
            && portable.root() == Some(self.terminal_portable_root)
            && self.terminal_portable_head == portable.digest()
            && self.source_party == transition.source_party()
            && self.seal_statement == transition.exact_seal_statement_digest()
            && self.export_binding == final_export.digest()?)
    }

    fn matches_reclaim(&self, authority: &ExportReclaimAuthority) -> bool {
        self.wallet == authority.wallet
            && self.network == authority.network
            && self.semantic_transition == authority.semantic_transition
            && self.transition_binding == authority.transition_binding
            && self.handoff_statement == authority.handoff_statement
            && self.export_context == authority.export_context
            && self.target_registry == authority.target_registry
            && self.target_epoch == authority.target_epoch
            && self.target_committee == authority.target_committee
            && self.target_activation == authority.target_activation
            && self.target_certified_activation_root == authority.target_certified_activation_root
            && self.terminal_checkpoint_sequence == authority.terminal_checkpoint_sequence
            && self.terminal_checkpoint_decision == authority.terminal_checkpoint_decision
            && self.terminal_portable_root == authority.terminal_portable_root
            && self.terminal_portable_head == authority.terminal_portable_head
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ExportIndexRecord {
    version: u16,
    wallet: DepositWalletId,
    source: PartyId,
    semantic_transition: [u8; 32],
    exact_lookup: [u8; 32],
}

impl ExportIndexRecord {
    fn validate(
        &self,
        wallet: DepositWalletId,
        source: PartyId,
        semantic_transition: [u8; 32],
    ) -> Result<(), RetentionError> {
        if self.version != EXPORT_PIN_VERSION
            || self.wallet != wallet
            || self.source != source
            || source == PartyId(0)
            || self.semantic_transition != semantic_transition
            || semantic_transition == [0; 32]
            || self.exact_lookup == [0; 32]
        {
            return Err(RetentionError::InvalidDurableState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportReclaimAuthority {
    wallet: DepositWalletId,
    network: [u8; 32],
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    handoff_statement: [u8; 32],
    export_context: [u8; 32],
    target_registry: [u8; 32],
    target_epoch: u64,
    target_committee: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    terminal_checkpoint_sequence: u64,
    terminal_checkpoint_decision: [u8; 32],
    terminal_portable_root: DepositIndexObjectId,
    terminal_portable_head: [u8; 32],
    certificate: [u8; 32],
}

impl ExportReclaimAuthority {
    fn from_verified(certificate: &VerifiedStateImportedCertificate) -> Self {
        Self {
            wallet: certificate.wallet(),
            network: certificate.network(),
            semantic_transition: certificate.semantic_transition_digest(),
            transition_binding: certificate.transition_binding(),
            handoff_statement: certificate.handoff_statement_digest(),
            export_context: certificate.handoff_export_context(),
            target_registry: certificate.target_registry_digest(),
            target_epoch: certificate.target_epoch(),
            target_committee: certificate.target_committee_digest(),
            target_activation: certificate.target_activation(),
            target_certified_activation_root: certificate.target_certified_activation_root(),
            terminal_checkpoint_sequence: certificate.terminal_checkpoint_sequence(),
            terminal_checkpoint_decision: certificate.terminal_checkpoint_decision(),
            terminal_portable_root: certificate.terminal_portable_root(),
            terminal_portable_head: certificate.terminal_portable_head_digest(),
            certificate: certificate.certificate_digest(),
        }
    }

    fn validate(&self, wallet: DepositWalletId) -> Result<(), RetentionError> {
        authenticate_id(self.terminal_portable_root, wallet)?;
        if self.wallet != wallet
            || self.network == [0; 32]
            || self.semantic_transition == [0; 32]
            || self.transition_binding == [0; 32]
            || self.handoff_statement == [0; 32]
            || self.export_context == [0; 32]
            || self.target_registry == [0; 32]
            || self.target_epoch == 0
            || self.target_committee == [0; 32]
            || self.target_activation == [0; 32]
            || self.target_certified_activation_root == [0; 32]
            || self.terminal_checkpoint_sequence == 0
            || self.terminal_checkpoint_decision == [0; 32]
            || self.terminal_portable_head == [0; 32]
            || self.certificate == [0; 32]
        {
            return Err(RetentionError::InvalidExportReclaimAuthority);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ExportReclaimRecord {
    version: u16,
    wallet: DepositWalletId,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    network: [u8; 32],
    target_registry: [u8; 32],
    target_epoch: u64,
    target_committee: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    first_certificate: [u8; 32],
    reclaimed_variants: u64,
}

impl ExportReclaimRecord {
    fn from_authority(authority: &ExportReclaimAuthority, reclaimed_variants: u64) -> Self {
        Self {
            version: EXPORT_PIN_VERSION,
            wallet: authority.wallet,
            semantic_transition: authority.semantic_transition,
            transition_binding: authority.transition_binding,
            network: authority.network,
            target_registry: authority.target_registry,
            target_epoch: authority.target_epoch,
            target_committee: authority.target_committee,
            target_activation: authority.target_activation,
            target_certified_activation_root: authority.target_certified_activation_root,
            first_certificate: authority.certificate,
            reclaimed_variants,
        }
    }

    fn validate(
        &self,
        wallet: DepositWalletId,
        semantic_transition: [u8; 32],
    ) -> Result<(), RetentionError> {
        if self.version != EXPORT_PIN_VERSION
            || self.wallet != wallet
            || self.semantic_transition != semantic_transition
            || semantic_transition == [0; 32]
            || self.transition_binding == [0; 32]
            || self.network == [0; 32]
            || self.target_registry == [0; 32]
            || self.target_epoch == 0
            || self.target_committee == [0; 32]
            || self.target_activation == [0; 32]
            || self.target_certified_activation_root == [0; 32]
            || self.first_certificate == [0; 32]
        {
            return Err(RetentionError::InvalidDurableState);
        }
        Ok(())
    }

    fn matches(&self, authority: &ExportReclaimAuthority) -> bool {
        self.wallet == authority.wallet
            && self.semantic_transition == authority.semantic_transition
            && self.transition_binding == authority.transition_binding
            && self.network == authority.network
            && self.target_registry == authority.target_registry
            && self.target_epoch == authority.target_epoch
            && self.target_committee == authority.target_committee
            && self.target_activation == authority.target_activation
            && self.target_certified_activation_root == authority.target_certified_activation_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct QueueRecord {
    version: u16,
    id: DepositIndexObjectId,
}

impl QueueRecord {
    fn new(id: DepositIndexObjectId) -> Self {
        Self { version: QUEUE_RECORD_VERSION, id }
    }

    fn validate(&self, wallet: DepositWalletId) -> Result<(), RetentionError> {
        if self.version != QUEUE_RECORD_VERSION {
            return Err(RetentionError::InvalidDurableState);
        }
        authenticate_id(self.id, wallet)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AuthenticatedRecord {
    version: u16,
    body: Vec<u8>,
    mac: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedObjectDescriptor {
    record: ObjectRecord,
}

/// Exact durable source lease returned to the QUIC serving layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSourcePin {
    wallet: DepositWalletId,
    source: PartyId,
    requester: PartyId,
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
    root: DepositIndexObjectId,
    response: Vec<u8>,
}

impl StoredSourcePin {
    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
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
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    #[must_use]
    pub const fn lease_digest(&self) -> [u8; 32] {
        self.lease_digest
    }

    #[must_use]
    pub const fn root(&self) -> DepositIndexObjectId {
        self.root
    }

    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }
}

/// Whether a head request created its durable slot or replayed the exact existing slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourcePinAcquire {
    Stored(StoredSourcePin),
    Existing(StoredSourcePin),
}

impl SourcePinAcquire {
    #[must_use]
    pub const fn pin(&self) -> &StoredSourcePin {
        match self {
            Self::Stored(pin) | Self::Existing(pin) => pin,
        }
    }
}

/// Exact/idempotent disposition suitable for an authenticated release acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePinRelease {
    Released,
    AlreadyReleased,
}

/// Exact source-specific global export root retained independently of requester leases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredExportPin {
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    source: PartyId,
    root: DepositIndexObjectId,
    advertisement_digest: [u8; 32],
    advertisement: Vec<u8>,
    seal_statement: [u8; 32],
    seal_certificate_digest: Option<[u8; 32]>,
    seal_certificate: Option<Vec<u8>>,
    export_binding: [u8; 32],
}

impl StoredExportPin {
    #[must_use]
    pub(crate) const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub(crate) const fn transition_binding(&self) -> [u8; 32] {
        self.transition_binding
    }

    #[must_use]
    pub(crate) const fn source(&self) -> PartyId {
        self.source
    }

    #[must_use]
    pub(crate) const fn root(&self) -> DepositIndexObjectId {
        self.root
    }

    #[must_use]
    pub(crate) const fn advertisement_digest(&self) -> [u8; 32] {
        self.advertisement_digest
    }

    #[must_use]
    pub(crate) fn advertisement_bytes(&self) -> &[u8] {
        &self.advertisement
    }

    #[must_use]
    pub(crate) const fn seal_statement_digest(&self) -> [u8; 32] {
        self.seal_statement
    }

    #[must_use]
    pub(crate) const fn seal_certificate_digest(&self) -> Option<[u8; 32]> {
        self.seal_certificate_digest
    }

    #[must_use]
    pub(crate) fn seal_certificate_bytes(&self) -> Option<&[u8]> {
        self.seal_certificate.as_deref()
    }

    #[must_use]
    pub(crate) const fn export_binding_digest(&self) -> [u8; 32] {
        self.export_binding
    }
}

/// Non-serializable proof that this exact candidate's global graph ownership committed before
/// any source signature can escape.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PreparedExportCandidatePin {
    wallet: DepositWalletId,
    source: PartyId,
    semantic_transition: [u8; 32],
    transition_binding: [u8; 32],
    vote_slot: [u8; 32],
    seal_statement: [u8; 32],
    advertisement: [u8; 32],
    export_binding: [u8; 32],
    root: DepositIndexObjectId,
}

impl PreparedExportCandidatePin {
    fn from_record(record: &ExportPinRecord) -> Self {
        Self {
            wallet: record.wallet,
            source: record.source,
            semantic_transition: record.semantic_transition,
            transition_binding: record.transition_binding,
            vote_slot: record.vote_slot,
            seal_statement: record.seal_statement,
            advertisement: record.advertisement_digest,
            export_binding: record.export_binding,
            root: record.terminal_portable_root,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_verified_candidate_for_test(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
    ) -> Result<Self, RetentionError> {
        let transition =
            VerifiedStateImportCandidateTransitionBinding::from_verified_export_candidate(
                candidate,
            )?;
        let statement = candidate.statement();
        let export = statement.final_export();
        let pin = Self {
            wallet: transition.wallet(),
            source: transition.source_party(),
            semantic_transition: transition.semantic_transition_digest(),
            transition_binding: transition.transition_binding(),
            vote_slot: statement.vote_slot_digest(),
            seal_statement: statement.digest(),
            advertisement: export.advertisement_digest(),
            export_binding: export.digest()?,
            root: export
                .resulting_portable_head()
                .root()
                .ok_or(RetentionError::InvalidExportPinBinding)?,
        };
        pin.authorizes(candidate)?;
        Ok(pin)
    }

    /// Candidate signing is required to call this exact gate. The type cannot be constructed or
    /// deserialized outside this module, and it is returned only after the redb commit succeeds.
    pub(crate) fn authorizes(
        &self,
        candidate: &VerifiedDepositPostHandoffExportCandidate,
    ) -> Result<(), RetentionError> {
        let transition =
            VerifiedStateImportCandidateTransitionBinding::from_verified_export_candidate(
                candidate,
            )?;
        let statement = candidate.statement();
        let export = statement.final_export();
        if self.wallet != transition.wallet()
            || self.source != transition.source_party()
            || self.semantic_transition != transition.semantic_transition_digest()
            || self.transition_binding != transition.transition_binding()
            || self.vote_slot != statement.vote_slot_digest()
            || self.seal_statement != statement.digest()
            || self.advertisement != export.advertisement_digest()
            || self.export_binding != export.digest()?
            || export.resulting_portable_head().root() != Some(self.root)
        {
            return Err(RetentionError::InvalidExportPinBinding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExportPinAcquire {
    Stored(StoredExportPin),
    Existing(StoredExportPin),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExportPinCertification {
    Certified(StoredExportPin),
    Existing(StoredExportPin),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExportPinReclaim {
    Reclaimed { variants: u64 },
    AlreadyReclaimed,
}

/// Non-serializable completion proof minted only after every permanent object under one exact
/// named portable root was reloaded and authenticated during this process lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReauthenticatedPortableRoot {
    wallet: DepositWalletId,
    source: PartyId,
    anchor: PortableReauthenticationAnchor,
    root: DepositIndexObjectId,
    head_digest: [u8; 32],
    object_count: u64,
}

impl ReauthenticatedPortableRoot {
    #[must_use]
    pub(crate) const fn root(&self) -> DepositIndexObjectId {
        self.root
    }

    #[must_use]
    pub(crate) const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    #[must_use]
    pub(crate) const fn object_count(&self) -> u64 {
        self.object_count
    }

    pub(crate) fn authorizes(
        &self,
        wallet: DepositWalletId,
        source: PartyId,
        anchor: PortableReauthenticationAnchor,
        head: &PortableDepositIndexHead,
    ) -> bool {
        self.wallet == wallet
            && self.source == source
            && self.anchor == anchor
            && head.root() == Some(self.root)
            && head.digest() == self.head_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PortableReauthenticationProgress {
    Idle,
    InProgress,
    Complete(ReauthenticatedPortableRoot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootSwapDisposition {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImportProgress {
    Staging,
    InProgress,
    Complete,
}

struct RetentionDatabase {
    database: Database,
    wallet: DepositWalletId,
    source: PartyId,
    mac_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RetentionDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetentionDatabase")
            .field("wallet", &self.wallet)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Single-writer authenticated lifetime store. The enclosing `DepositIndexStore` mutex is the
/// serialization boundary; every redb operation itself runs on Tokio's blocking pool.
pub(crate) struct DepositIndexRetentionStore {
    inner: Arc<RetentionDatabase>,
    meta: DurableMeta,
    reauthenticated: Option<ReauthenticatedPortableRoot>,
}

#[derive(Clone, Copy, Debug)]
enum RetentionOpenMode {
    Ordinary {
        expected_root: Option<DepositIndexObjectId>,
        allow_committed_transition: bool,
    },
    MarkerImport {
        binding: [u8; 32],
        target: DepositIndexObjectId,
        maximum_objects: u64,
        maximum_plaintext_bytes: u64,
    },
    ExistingRelease,
}

impl RetentionOpenMode {
    const fn expected_root(self) -> Option<DepositIndexObjectId> {
        match self {
            Self::Ordinary { expected_root, .. } => expected_root,
            Self::MarkerImport { target, .. } => Some(target),
            Self::ExistingRelease => None,
        }
    }

    const fn require_existing(self) -> bool {
        matches!(self, Self::ExistingRelease | Self::MarkerImport { .. })
    }
}

impl fmt::Debug for DepositIndexRetentionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositIndexRetentionStore")
            .field("wallet", &self.meta.wallet)
            .field("source", &self.meta.source)
            .field("revision", &self.meta.revision)
            .field("current_root", &self.meta.current_root)
            .field("objects", &self.meta.object_count)
            .field("active_pins", &self.meta.active_pin_count)
            .field("released_pin_floors", &self.meta.released_pin_count)
            .field("export_pins", &self.meta.export_pin_count)
            .field("export_reclaims", &self.meta.export_reclaim_count)
            .field("pending_unlinks", &self.meta.unlink_count)
            .field("pending_deletes", &self.meta.delete_count)
            .finish_non_exhaustive()
    }
}

impl DepositIndexRetentionStore {
    pub(crate) async fn open(
        artifacts: &WalletArtifactStore,
        wallet: DepositWalletId,
        source: PartyId,
        expected_root: Option<DepositIndexObjectId>,
        allow_committed_transition: bool,
    ) -> Result<Self, RetentionError> {
        let path = retention_path(artifacts, wallet);
        let root_key = artifacts.derive_subkey(RETENTION_SUBKEY_DOMAIN)?;
        let mac_key = derive_wallet_mac_key(&root_key, wallet, source);
        let opened = tokio::task::spawn_blocking(move || {
            open_database(
                &path,
                wallet,
                source,
                mac_key,
                RetentionOpenMode::Ordinary { expected_root, allow_committed_transition },
            )
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        Ok(opened)
    }

    /// Open only for the exact typed-marker import constructor. The mismatch authorization never
    /// escapes this call: before returning, the database either already names `target` or contains
    /// the exact durable binding which will publish it.
    pub(crate) async fn open_for_import(
        artifacts: &WalletArtifactStore,
        wallet: DepositWalletId,
        source: PartyId,
        binding: [u8; 32],
        target: DepositIndexObjectId,
        maximum_objects: u64,
        maximum_plaintext_bytes: u64,
    ) -> Result<(Self, ImportProgress), RetentionError> {
        let path = retention_path(artifacts, wallet);
        let root_key = artifacts.derive_subkey(RETENTION_SUBKEY_DOMAIN)?;
        let mac_key = derive_wallet_mac_key(&root_key, wallet, source);
        let store = tokio::task::spawn_blocking(move || {
            open_database(
                &path,
                wallet,
                source,
                mac_key,
                RetentionOpenMode::MarkerImport {
                    binding,
                    target,
                    maximum_objects,
                    maximum_plaintext_bytes,
                },
            )
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        let progress = match store.meta.import.as_ref().map(|import| import.phase) {
            None if store.meta.current_root == Some(target) => ImportProgress::Complete,
            Some(ImportPhase::Staging) => ImportProgress::Staging,
            Some(_) => ImportProgress::InProgress,
            None => return Err(RetentionError::ImportConflict),
        };
        Ok((store, progress))
    }

    /// Open only already initialized retention state without comparing a wallet-snapshot head.
    /// This is the late-release path used while Monero initialization or snapshot recovery is
    /// unavailable; it never creates a missing database.
    pub(crate) async fn open_existing_for_release(
        artifacts: &WalletArtifactStore,
        wallet: DepositWalletId,
        source: PartyId,
    ) -> Result<Self, RetentionError> {
        let path = retention_path(artifacts, wallet);
        let root_key = artifacts.derive_subkey(RETENTION_SUBKEY_DOMAIN)?;
        let mac_key = derive_wallet_mac_key(&root_key, wallet, source);
        tokio::task::spawn_blocking(move || {
            open_database(&path, wallet, source, mac_key, RetentionOpenMode::ExistingRelease)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))?
    }

    #[must_use]
    pub(crate) const fn current_root(&self) -> Option<DepositIndexObjectId> {
        self.meta.current_root
    }

    #[must_use]
    pub(crate) const fn has_import(&self) -> bool {
        self.meta.import.is_some()
    }

    pub(crate) const fn has_reauthentication(&self) -> bool {
        self.meta.reauthentication.is_some()
    }

    /// Reauthenticate the durable cursor after a blocking mutation may have committed while its
    /// async caller was cancelled. This is used only on an observed revision mismatch and keeps
    /// ordinary operation on the cached single-writer fast path.
    async fn reload_durable_meta(&mut self) -> Result<(), RetentionError> {
        let inner = Arc::clone(&self.inner);
        self.meta = tokio::task::spawn_blocking(move || reload_meta_blocking(&inner))
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        Ok(())
    }

    pub(crate) async fn apply_root_swap(
        &mut self,
        expected_old: Option<DepositIndexObjectId>,
        replacement: Option<DepositIndexObjectId>,
        objects: Vec<(DepositIndexObjectId, Vec<u8>)>,
    ) -> Result<RootSwapDisposition, RetentionError> {
        if objects.len() > MAX_DEPOSIT_INDEX_UPDATE_OBJECTS {
            return Err(RetentionError::GraphBoundExceeded);
        }
        let bytes = objects.iter().try_fold(0_usize, |total, (_, bytes)| {
            total.checked_add(bytes.len()).ok_or(RetentionError::GraphBoundExceeded)
        })?;
        if bytes > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
            return Err(RetentionError::GraphBoundExceeded);
        }
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        let (meta, disposition) = tokio::task::spawn_blocking(move || {
            apply_root_swap_blocking(&inner, &expected_meta, expected_old, replacement, objects)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.meta = meta;
        Ok(disposition)
    }

    #[cfg(test)]
    async fn begin_import(
        &mut self,
        binding: [u8; 32],
        target: DepositIndexObjectId,
        maximum_objects: u64,
        maximum_plaintext_bytes: u64,
    ) -> Result<ImportProgress, RetentionError> {
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta = tokio::task::spawn_blocking(move || {
            begin_import_blocking(
                &inner,
                &expected_meta,
                binding,
                target,
                maximum_objects,
                maximum_plaintext_bytes,
            )
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        Ok(match self.meta.import.as_ref().map(|import| import.phase) {
            None if self.meta.current_root == Some(target) => ImportProgress::Complete,
            Some(ImportPhase::Staging) => ImportProgress::Staging,
            Some(_) => ImportProgress::InProgress,
            None => return Err(RetentionError::ImportConflict),
        })
    }

    pub(crate) async fn stage_import_batch(
        &mut self,
        objects: Vec<(DepositIndexObjectId, Vec<u8>)>,
    ) -> Result<(), RetentionError> {
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta = tokio::task::spawn_blocking(move || {
            stage_import_batch_blocking(&inner, &expected_meta, objects)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        Ok(())
    }

    pub(crate) async fn seal_import(&mut self) -> Result<(), RetentionError> {
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta =
            tokio::task::spawn_blocking(move || seal_import_blocking(&inner, &expected_meta))
                .await
                .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        Ok(())
    }

    pub(crate) async fn advance_import(&mut self) -> Result<ImportProgress, RetentionError> {
        if self.meta.import.is_none() {
            return Ok(ImportProgress::Complete);
        }
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta = tokio::task::spawn_blocking(move || {
            advance_import_blocking(&inner, &expected_meta, RETENTION_GC_BATCH_OBJECTS)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        tokio::task::yield_now().await;
        Ok(if self.meta.import.is_none() {
            ImportProgress::Complete
        } else {
            ImportProgress::InProgress
        })
    }

    pub(crate) async fn acquire_source_pin(
        &mut self,
        active: &VerifiedRegistryHandoffTarget,
        semantic_authority: SourcePinSemanticAuthority,
        requester: PartyId,
        context_digest: [u8; 32],
        lease_digest: [u8; 32],
        expected_root: DepositIndexObjectId,
        response: Vec<u8>,
    ) -> Result<SourcePinAcquire, RetentionError> {
        active.committee().validate()?;
        if active.wallet() != self.meta.wallet
            || active.committee().members.iter().all(|member| member.id != requester)
            || active.committee().members.iter().all(|member| member.id != self.meta.source)
        {
            return Err(RetentionError::InactiveSourceOrRequester);
        }
        validate_pin_request(
            self.meta.wallet,
            self.meta.source,
            requester,
            semantic_authority.digest,
            context_digest,
            lease_digest,
            expected_root,
            &response,
        )?;
        let authorization = SourcePinAuthorization::from_target(active);
        let authorized_requesters =
            active.committee().members.iter().map(|member| member.id).collect::<Vec<_>>();
        for attempt in 0..2 {
            let inner = Arc::clone(&self.inner);
            let expected_meta = self.meta.clone();
            let response = response.clone();
            let authorized_requesters = authorized_requesters.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                acquire_pin_blocking(
                    &inner,
                    &expected_meta,
                    requester,
                    semantic_authority,
                    context_digest,
                    lease_digest,
                    expected_root,
                    response,
                    authorization,
                    authorized_requesters,
                )
            })
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))?;
            match outcome {
                Ok((meta, result)) => {
                    self.meta = meta;
                    return Ok(result);
                }
                Err(RetentionError::ConcurrentMutation) if attempt == 0 => {
                    self.reload_durable_meta().await?;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the bounded retry loop always returns on its final attempt")
    }

    pub(crate) async fn active_source_pin(
        &self,
        source: PartyId,
        requester: PartyId,
        context_digest: [u8; 32],
        lease_digest: [u8; 32],
    ) -> Result<Option<StoredSourcePin>, RetentionError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            lookup_pin_blocking(&inner, source, requester, context_digest, lease_digest)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))?
    }

    pub(crate) async fn source_pin_for_head(
        &self,
        source: PartyId,
        requester: PartyId,
        context_digest: [u8; 32],
    ) -> Result<Option<StoredSourcePin>, RetentionError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            lookup_pin_for_head_blocking(&inner, source, requester, context_digest)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))?
    }

    pub(crate) async fn release_source_pin(
        &mut self,
        source: PartyId,
        requester: PartyId,
        context_digest: [u8; 32],
        lease_digest: [u8; 32],
    ) -> Result<SourcePinRelease, RetentionError> {
        for attempt in 0..2 {
            let inner = Arc::clone(&self.inner);
            let expected_meta = self.meta.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                release_pin_blocking(
                    &inner,
                    &expected_meta,
                    source,
                    requester,
                    context_digest,
                    lease_digest,
                )
            })
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))?;
            match outcome {
                Ok((meta, result)) => {
                    self.meta = meta;
                    return Ok(result);
                }
                Err(RetentionError::ConcurrentMutation) if attempt == 0 => {
                    self.reload_durable_meta().await?;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the bounded retry loop always returns on its final attempt")
    }

    /// Commit one exact source-specific terminal export before any source signature can escape.
    ///
    /// Canonical advertisement bytes and every exact graph projection are authenticated in the
    /// same transaction which acquires the independent global portable-root reference.
    pub(crate) async fn prepare_export_candidate_pin(
        &mut self,
        candidate: &VerifiedDepositPostHandoffExportCandidate,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<PreparedExportCandidatePin, RetentionError> {
        let record = ExportPinRecord::from_verified_candidate(candidate, advertisement)?;
        record.validate(self.meta.wallet, self.meta.source)?;
        let prepared = PreparedExportCandidatePin::from_record(&record);
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        let (meta, _result) = tokio::task::spawn_blocking(move || {
            acquire_export_pin_blocking(&inner, &expected_meta, record)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.meta = meta;
        Ok(prepared)
    }

    /// Atomically attach the exact old-quorum certificate to an already durable candidate.
    ///
    /// Certification never creates root ownership. A missing pre-sign candidate therefore fails
    /// closed instead of recreating the signature-without-data crash window.
    pub(crate) async fn certify_export_pin(
        &mut self,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<ExportPinCertification, RetentionError> {
        let seal = seal.clone();
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        let (meta, result) = tokio::task::spawn_blocking(move || {
            certify_export_pin_blocking(&inner, &expected_meta, &seal)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.meta = meta;
        Ok(result)
    }

    /// Reauthenticate and return one certified exact export variant after restart.
    pub(crate) async fn active_export_pin(
        &self,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<Option<StoredExportPin>, RetentionError> {
        let seal = seal.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || lookup_export_pin_blocking(&inner, &seal))
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))?
    }

    /// Read one certified response bundle by its semantic transition after restart.
    ///
    /// This is read-only: the signed ExportHead handler must still acquire its independent
    /// requester lease with the exact returned response bytes before replying.
    pub(crate) async fn certified_export_pin_for_transition(
        &self,
        semantic_transition: [u8; 32],
    ) -> Result<Option<StoredExportPin>, RetentionError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            lookup_certified_export_pin_blocking(&inner, semantic_transition)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))?
    }

    /// Atomically reauthenticate one certified global export and acquire the requester's exact
    /// response lease before the caller is allowed to put those bytes on the wire.
    pub(crate) async fn acquire_certified_export_head_pin(
        &mut self,
        active: &VerifiedRegistryHandoffTarget,
        requester: PartyId,
        context_digest: [u8; 32],
        lease_digest: [u8; 32],
        expected_export: &StoredExportPin,
        response: Vec<u8>,
    ) -> Result<SourcePinAcquire, RetentionError> {
        active.committee().validate()?;
        if active.wallet() != self.meta.wallet
            || active.committee().members.iter().all(|member| member.id != requester)
            || expected_export.source() != self.meta.source
        {
            return Err(RetentionError::InactiveSourceOrRequester);
        }
        if expected_export.seal_certificate_bytes().is_none() {
            return Err(RetentionError::ExportCandidateNotPinned);
        }
        let semantic_authority = SourcePinSemanticAuthority::certified_export(
            expected_export.semantic_transition_digest(),
        );
        validate_pin_request(
            self.meta.wallet,
            self.meta.source,
            requester,
            semantic_authority.digest,
            context_digest,
            lease_digest,
            expected_export.root(),
            &response,
        )?;
        // Certified exports run while ordinary readiness is closed. Apply their authenticated
        // successor authorization here; ordinary-sync reconciliation cannot be a prerequisite.
        // This preserves live requester leases and only prunes already released historical slots.
        self.reclaim_after_handoff(active).await?;
        let authorization = SourcePinAuthorization::from_target(active);
        let authorized_requesters =
            active.committee().members.iter().map(|member| member.id).collect::<Vec<_>>();
        for attempt in 0..2 {
            let inner = Arc::clone(&self.inner);
            let expected_meta = self.meta.clone();
            let expected_export = expected_export.clone();
            let response = response.clone();
            let authorized_requesters = authorized_requesters.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                acquire_export_head_pin_blocking(
                    &inner,
                    &expected_meta,
                    requester,
                    semantic_authority,
                    context_digest,
                    lease_digest,
                    &expected_export,
                    response,
                    authorization,
                    authorized_requesters,
                )
            })
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))?;
            match outcome {
                Ok((meta, result)) => {
                    self.meta = meta;
                    return Ok(result);
                }
                Err(RetentionError::ConcurrentMutation) if attempt == 0 => {
                    self.reload_durable_meta().await?;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the bounded retry loop always returns on its final attempt")
    }

    /// Reclaim this source's exact variant only under a verified target `n-f` availability
    /// certificate. The durable semantic tombstone makes exact retries idempotent and prevents a
    /// late predecessor seal from resurrecting an already imported transition.
    pub(crate) async fn reclaim_export_roots(
        &mut self,
        certificate: &VerifiedStateImportedCertificate,
    ) -> Result<ExportPinReclaim, RetentionError> {
        let authority = ExportReclaimAuthority::from_verified(certificate);
        authority.validate(self.meta.wallet)?;
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        let (meta, result) = tokio::task::spawn_blocking(move || {
            reclaim_export_pins_blocking(&inner, &expected_meta, authority)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.meta = meta;
        Ok(result)
    }

    /// Require a pre-existing exact reclaim tombstone without creating or changing durable state.
    ///
    /// This is the only authority available to an advanced historical source-only recipient. A
    /// missing tombstone must fail closed even when the corresponding live export index is also
    /// absent: manufacturing a zero-variant tombstone here would turn an old peer replay into new
    /// completion authority.
    pub(crate) async fn require_export_reclaim_tombstone(
        &self,
        certificate: &VerifiedStateImportedCertificate,
    ) -> Result<(), RetentionError> {
        let authority = ExportReclaimAuthority::from_verified(certificate);
        authority.validate(self.meta.wallet)?;
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            require_export_reclaim_tombstone_blocking(&inner, &authority)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))?
    }

    /// Start or resume a bounded permanent-object audit for one exact currently named root.
    pub(crate) async fn begin_portable_reauthentication(
        &mut self,
        anchor: PortableReauthenticationAnchor,
        head: &PortableDepositIndexHead,
    ) -> Result<PortableReauthenticationProgress, RetentionError> {
        let root = head.root().ok_or(RetentionError::InvalidReauthenticationBinding)?;
        let maximum_objects = head
            .maximum_reachable_objects()
            .map_err(|_| RetentionError::InvalidReauthenticationBinding)?;
        let head_digest = head.digest();
        anchor.validate()?;
        if let Some(completed) = &self.reauthenticated {
            if completed.authorizes(self.meta.wallet, self.meta.source, anchor, head) {
                return Ok(PortableReauthenticationProgress::Complete(completed.clone()));
            }
            self.reauthenticated = None;
        }
        let proposed = DurableReauthentication {
            version: RETENTION_VERSION,
            anchor,
            head: head.clone(),
            root,
            head_digest,
            maximum_objects,
            stack_depth: 1,
            visiting_count: 1,
            reached_count: 0,
            pending_count: 0,
            verified_count: 0,
            phase: ReauthenticationPhase::Traversing,
        };
        proposed.validate(self.meta.wallet)?;
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta = tokio::task::spawn_blocking(move || {
            begin_reauthentication_blocking(&inner, &expected_meta, proposed)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        Ok(PortableReauthenticationProgress::InProgress)
    }

    /// Start or resume an audit using only the exact certified export bundle read back from this
    /// store. The caller cannot substitute a different logical head for the named export root.
    pub(crate) async fn begin_export_portable_reauthentication(
        &mut self,
        export: &StoredExportPin,
    ) -> Result<PortableReauthenticationProgress, RetentionError> {
        if export.source() != self.meta.source || export.seal_certificate_bytes().is_none() {
            return Err(RetentionError::InvalidReauthenticationBinding);
        }
        let advertisement = DepositSyncAdvertisement::from_bytes(export.advertisement_bytes())
            .map_err(|_| RetentionError::InvalidReauthenticationBinding)?;
        if advertisement.digest() != export.advertisement_digest()
            || advertisement.portable_index().root() != Some(export.root())
        {
            return Err(RetentionError::InvalidReauthenticationBinding);
        }
        self.begin_portable_reauthentication(
            PortableReauthenticationAnchor::Export {
                semantic_transition: export.semantic_transition_digest(),
            },
            advertisement.portable_index(),
        )
        .await
    }

    /// Advance at most one bounded traversal/read/verification batch.
    pub(crate) async fn advance_portable_reauthentication(
        &mut self,
        artifacts: &WalletArtifactStore,
    ) -> Result<PortableReauthenticationProgress, RetentionError> {
        if let Some(completed) = &self.reauthenticated {
            return Ok(PortableReauthenticationProgress::Complete(completed.clone()));
        }
        if self.meta.reauthentication.is_none() {
            return Ok(PortableReauthenticationProgress::Idle);
        }
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        let (meta, pending) = tokio::task::spawn_blocking(move || {
            prepare_reauthentication_batch_blocking(&inner, &expected_meta)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.meta = meta;
        if let Some(completed) = completed_reauthentication(&self.meta)? {
            self.reauthenticated = Some(completed.clone());
            return Ok(PortableReauthenticationProgress::Complete(completed));
        }
        if self.meta.reauthentication.is_none() {
            return Ok(PortableReauthenticationProgress::Idle);
        }
        if pending.is_empty() {
            return Ok(PortableReauthenticationProgress::InProgress);
        }

        let mut objects = Vec::with_capacity(pending.len());
        let mut plaintext_bytes = 0_usize;
        for id in pending {
            let artifact = artifacts.load_artifact(id.storage_reference()).await?;
            if artifact.reference != id.storage_reference() {
                return Err(RetentionError::InvalidDurableState);
            }
            plaintext_bytes = plaintext_bytes
                .checked_add(artifact.contents.len())
                .ok_or(RetentionError::CountOverflow)?;
            if objects.len() == RETENTION_REAUTH_BATCH_OBJECTS
                || plaintext_bytes > RETENTION_REAUTH_BATCH_BYTES
            {
                return Err(RetentionError::GraphBoundExceeded);
            }
            objects.push((id, artifact.contents.into_bytes()));
        }
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta = tokio::task::spawn_blocking(move || {
            verify_reauthentication_batch_blocking(&inner, &expected_meta, objects)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        if let Some(completed) = completed_reauthentication(&self.meta)? {
            self.reauthenticated = Some(completed.clone());
            return Ok(PortableReauthenticationProgress::Complete(completed));
        }
        Ok(PortableReauthenticationProgress::InProgress)
    }

    /// Consume one exact process-local completion token and durably request bounded scratch-state
    /// cleanup. The caller must continue advancing until [`PortableReauthenticationProgress::Idle`]
    /// before a portable-root transition can begin.
    pub(crate) async fn release_portable_reauthentication(
        &mut self,
        completed: &ReauthenticatedPortableRoot,
    ) -> Result<PortableReauthenticationProgress, RetentionError> {
        let completed = completed.clone();
        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        self.meta = tokio::task::spawn_blocking(move || {
            release_reauthentication_blocking(&inner, &expected_meta, &completed)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.reauthenticated = None;
        Ok(if self.meta.reauthentication.is_none() {
            PortableReauthenticationProgress::Idle
        } else {
            PortableReauthenticationProgress::InProgress
        })
    }

    /// Finish the old audit before replaying an authenticated, already-committed root change.
    /// Only startup journal recovery may use this: ordinary writers must wait for the audit's
    /// owner. Scratch cleanup still requires a freshly verified process-local completion token.
    pub(crate) async fn finish_reauthentication_for_committed_recovery(
        &mut self,
        artifacts: &WalletArtifactStore,
    ) -> Result<(), RetentionError> {
        let Some(audit) = &self.meta.reauthentication else {
            return Ok(());
        };
        let budget = audit
            .maximum_objects
            .checked_mul(4)
            .and_then(|turns| turns.checked_add(8))
            .ok_or(RetentionError::CountOverflow)?;
        for _ in 0..budget {
            match self.advance_portable_reauthentication(artifacts).await? {
                PortableReauthenticationProgress::Idle => return Ok(()),
                PortableReauthenticationProgress::InProgress => {}
                PortableReauthenticationProgress::Complete(completed) => {
                    self.release_portable_reauthentication(&completed).await?;
                }
            }
        }
        Err(RetentionError::InvalidDurableState)
    }

    pub(crate) fn authorizes_completed_reauthentication(
        &self,
        completed: &ReauthenticatedPortableRoot,
        anchor: PortableReauthenticationAnchor,
        head: &PortableDepositIndexHead,
    ) -> bool {
        self.reauthenticated.as_ref() == Some(completed)
            && completed.authorizes(self.meta.wallet, self.meta.source, anchor, head)
    }

    /// Advance authenticated committee authorization. Live requester leases never expire and are
    /// never inferred released from committee membership; only their exact signed Release path
    /// removes their named-root reference. Reference-free released floors for departed requesters
    /// are pruned because they protect only current-member polling cadence.
    pub(crate) async fn reclaim_after_handoff(
        &mut self,
        active: &VerifiedRegistryHandoffTarget,
    ) -> Result<usize, RetentionError> {
        active.committee().validate()?;
        if active.wallet() != self.meta.wallet {
            return Err(RetentionError::InactiveSourceOrRequester);
        }
        let authorization = SourcePinAuthorization::from_target(active);
        let active_requesters =
            active.committee().members.iter().map(|member| member.id).collect::<BTreeSet<_>>();
        for attempt in 0..2 {
            let inner = Arc::clone(&self.inner);
            let expected_meta = self.meta.clone();
            let active_requesters = active_requesters.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                advance_pin_authorization_blocking(
                    &inner,
                    &expected_meta,
                    authorization,
                    &active_requesters,
                )
            })
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))?;
            match outcome {
                Ok((meta, reclaimed)) => {
                    self.meta = meta;
                    return Ok(reclaimed);
                }
                Err(RetentionError::ConcurrentMutation) if attempt == 0 => {
                    self.reload_durable_meta().await?;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the bounded retry loop always returns on its final attempt")
    }

    /// Advance recursive unlinking by at most one bounded database batch.
    ///
    /// The result reports whether durable GC work remains. An active import may temporarily leave
    /// work pending without advancing it; a background pacemaker can safely retry on its next
    /// turn.
    pub(crate) async fn progress_gc_batch(
        &mut self,
        artifacts: &WalletArtifactStore,
    ) -> Result<bool, RetentionError> {
        // Import descriptors may deliberately stop at an existing historical graph boundary.
        // That boundary cannot be unlinked until publication gives the new root its named owner.
        if self.meta.import.is_some() {
            return Ok(self.meta.unlink_count != 0 || self.meta.delete_count != 0);
        }
        if self.meta.unlink_count == 0 && self.meta.delete_count == 0 {
            return Ok(false);
        }

        let inner = Arc::clone(&self.inner);
        let expected_meta = self.meta.clone();
        let (meta, deletions) = tokio::task::spawn_blocking(move || {
            prepare_gc_batch_blocking(&inner, &expected_meta, RETENTION_GC_BATCH_OBJECTS)
        })
        .await
        .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        self.meta = meta;

        if deletions.is_empty() {
            if self.meta.unlink_count == 0 && self.meta.delete_count == 0 {
                return Ok(false);
            }
            return Err(RetentionError::InvalidDurableState);
        }

        for id in deletions {
            artifacts.remove_artifact(id.storage_reference()).await?;
            let inner = Arc::clone(&self.inner);
            let expected_meta = self.meta.clone();
            self.meta = tokio::task::spawn_blocking(move || {
                acknowledge_delete_blocking(&inner, &expected_meta, id)
            })
            .await
            .map_err(|error| RetentionError::BlockingTask(error.to_string()))??;
        }
        tokio::task::yield_now().await;
        Ok(self.meta.unlink_count != 0 || self.meta.delete_count != 0)
    }

    /// Drain recursive unlinking cooperatively. Each turn delegates to one bounded batch so this
    /// remains appropriate for startup and explicit cleanup paths that require completion.
    pub(crate) async fn drain_gc(
        &mut self,
        artifacts: &WalletArtifactStore,
    ) -> Result<(), RetentionError> {
        if self.meta.import.is_some() {
            return Ok(());
        }
        while self.progress_gc_batch(artifacts).await? {}
        Ok(())
    }

    #[cfg(test)]
    fn counts(&self) -> (u64, u16, u64, u64) {
        (
            self.meta.object_count,
            self.meta.active_pin_count,
            self.meta.unlink_count,
            self.meta.delete_count,
        )
    }

    #[cfg(test)]
    fn released_pin_count(&self) -> u16 {
        self.meta.released_pin_count
    }

    #[cfg(test)]
    fn export_counts(&self) -> (u64, u64) {
        (self.meta.export_pin_count, self.meta.export_reclaim_count)
    }
}

fn open_database(
    path: &Path,
    wallet: DepositWalletId,
    source: PartyId,
    mac_key: Zeroizing<[u8; 32]>,
    mode: RetentionOpenMode,
) -> Result<DepositIndexRetentionStore, RetentionError> {
    if wallet.0 == [0_u8; 32] || source == PartyId(0) {
        return Err(RetentionError::InvalidDurableState);
    }
    let expected_root = mode.expected_root();
    if let Some(root) = expected_root {
        authenticate_id(root, wallet)?;
    }
    let existed = match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(RetentionError::StorageConflict);
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(RetentionError::Database(error.to_string())),
    };
    if mode.require_existing() && !existed {
        return Err(RetentionError::MissingRetentionState);
    }
    let parent = path.parent().ok_or(RetentionError::StorageConflict)?;
    std::fs::create_dir_all(parent).map_database()?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_database()?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(RetentionError::StorageConflict);
    }
    #[cfg(unix)]
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_database()?;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_database()?;
    let opened_metadata = file.metadata().map_database()?;
    let current_metadata = std::fs::symlink_metadata(path).map_database()?;
    if !opened_metadata.is_file()
        || !current_metadata.is_file()
        || !same_file_identity(&opened_metadata, &current_metadata)
    {
        return Err(RetentionError::StorageConflict);
    }
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_database()?;
    let mut builder = Database::builder();
    builder.set_cache_size(DEPOSIT_INDEX_RETENTION_CACHE_BYTES);
    let database = builder.create_file(file).map_database()?;
    let inner = Arc::new(RetentionDatabase { database, wallet, source, mac_key });

    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    initialize_tables(&transaction)?;
    let loaded = load_meta_optional(&transaction, &inner)?;
    let mut meta = match loaded {
        Some(meta) => meta,
        None => {
            if mode.require_existing() || tables_nonempty(&transaction)? || expected_root.is_some()
            {
                return Err(RetentionError::MissingRetentionState);
            }
            let fresh = DurableMeta::fresh(wallet, source);
            store_meta(&transaction, &inner, &fresh)?;
            fresh
        }
    };
    meta.validate(wallet, source)?;
    transaction.commit().map_database()?;
    validate_database_shape(&inner, &meta)?;
    validate_named_roots(&inner, &meta)?;

    match mode {
        RetentionOpenMode::Ordinary { expected_root, allow_committed_transition } => {
            if meta.current_root != expected_root && !allow_committed_transition {
                return Err(RetentionError::CurrentRootConflict);
            }
            if meta.import.is_some() {
                return Err(RetentionError::ImportInProgress);
            }
        }
        RetentionOpenMode::MarkerImport {
            binding,
            target,
            maximum_objects,
            maximum_plaintext_bytes,
        } => {
            meta = begin_import_blocking(
                &inner,
                &meta,
                binding,
                target,
                maximum_objects,
                maximum_plaintext_bytes,
            )?;
            validate_database_shape(&inner, &meta)?;
        }
        RetentionOpenMode::ExistingRelease => {}
    }
    #[cfg(unix)]
    std::fs::File::open(parent).map_database()?.sync_all().map_database()?;
    Ok(DepositIndexRetentionStore { inner, meta, reauthenticated: None })
}

fn apply_root_swap_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    expected_old: Option<DepositIndexObjectId>,
    replacement: Option<DepositIndexObjectId>,
    objects: Vec<(DepositIndexObjectId, Vec<u8>)>,
) -> Result<(DurableMeta, RootSwapDisposition), RetentionError> {
    let mut descriptors = BTreeMap::new();
    for (id, bytes) in objects {
        if descriptors.contains_key(&id) {
            return Err(RetentionError::DuplicateObject);
        }
        let verified = verify_portable_index_object(inner.wallet, id, &bytes)?;
        descriptors.insert(
            id,
            VerifiedObjectDescriptor { record: ObjectRecord::from_verified(id, verified) },
        );
    }

    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    // Committed-journal recovery may replay an already-installed root while its audit is live.
    // This authenticates the existing root without changing the graph or invalidating the audit.
    if meta.current_root == replacement {
        validate_root_in_transaction(&transaction, inner, &meta, replacement)?;
        transaction.commit().map_database()?;
        return Ok((meta, RootSwapDisposition::AlreadyApplied));
    }
    if meta.reauthentication.is_some() {
        return Err(RetentionError::ReauthenticationInProgress);
    }
    if meta.current_root != expected_old {
        return Err(RetentionError::CurrentRootConflict);
    }

    register_reachable_objects(&transaction, inner, &mut meta, replacement, &descriptors)?;
    if let Some(root) = replacement {
        add_reference(&transaction, inner, &mut meta, root)?;
        let record = load_object_required(&transaction, inner, root)?;
        if !record.node {
            return Err(RetentionError::InvalidPortableRoot);
        }
    }
    if let Some(root) = expected_old {
        remove_reference(&transaction, inner, &mut meta, root)?;
    }
    meta.current_root = replacement;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    validate_database_shape(inner, &meta)?;
    Ok((meta, RootSwapDisposition::Applied))
}

fn begin_import_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    binding: [u8; 32],
    target: DepositIndexObjectId,
    maximum_objects: u64,
    maximum_plaintext_bytes: u64,
) -> Result<DurableMeta, RetentionError> {
    authenticate_id(target, inner.wallet)?;
    if binding == [0_u8; 32] || maximum_objects == 0 || maximum_plaintext_bytes == 0 {
        return Err(RetentionError::ImportQuota);
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.current_root == Some(target) && meta.import.is_none() {
        transaction.commit().map_database()?;
        return Ok(meta);
    }
    if meta.reauthentication.is_some() {
        return Err(RetentionError::ReauthenticationInProgress);
    }
    let proposed = DurableImport {
        version: RETENTION_VERSION,
        binding,
        expected_old: meta.current_root,
        target,
        maximum_objects,
        maximum_plaintext_bytes,
        staged_objects: 0,
        staged_plaintext_bytes: 0,
        stack_depth: 0,
        visiting_count: 0,
        reached_count: 0,
        reached_import_objects: 0,
        registered_count: 0,
        pending_reference_count: 0,
        phase: ImportPhase::Staging,
    };
    proposed.validate(inner.wallet)?;
    match &meta.import {
        Some(existing)
            if existing.binding == binding
                && existing.target == target
                && existing.maximum_objects == maximum_objects
                && existing.maximum_plaintext_bytes == maximum_plaintext_bytes =>
        {
            transaction.commit().map_database()?;
            return Ok(meta);
        }
        Some(_) => return Err(RetentionError::ImportConflict),
        None => {}
    }
    if import_tables_nonempty(&transaction)? {
        return Err(RetentionError::InvalidDurableState);
    }
    meta.import = Some(proposed);
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn stage_import_batch_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    objects: Vec<(DepositIndexObjectId, Vec<u8>)>,
) -> Result<DurableMeta, RetentionError> {
    if objects.is_empty() || objects.len() > RETENTION_IMPORT_BATCH_OBJECTS {
        return Err(RetentionError::ImportBatchBound);
    }
    let mut batch_bytes = 0_u64;
    let mut descriptors = BTreeMap::new();
    for (id, bytes) in objects {
        batch_bytes = batch_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| RetentionError::ImportQuota)?)
            .ok_or(RetentionError::ImportQuota)?;
        if batch_bytes > RETENTION_IMPORT_BATCH_BYTES as u64 || descriptors.contains_key(&id) {
            return Err(RetentionError::ImportBatchBound);
        }
        let verified = verify_portable_index_object(inner.wallet, id, &bytes)?;
        descriptors.insert(
            id,
            (
                ObjectRecord::from_verified(id, verified),
                u64::try_from(bytes.len()).map_err(|_| RetentionError::ImportQuota)?,
            ),
        );
    }

    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let mut import = meta.import.clone().ok_or(RetentionError::NoImport)?;
    if import.phase != ImportPhase::Staging {
        return Err(RetentionError::ImportAlreadySealed);
    }
    for (id, (candidate, plaintext_len)) in descriptors {
        if let Some(existing) = load_object_optional(&transaction, inner, id)? {
            if !existing.same_object(&candidate) {
                return Err(RetentionError::ObjectConflict);
            }
            continue;
        }
        if let Some(existing) = load_import_object_optional(&transaction, inner, id)? {
            if !existing.same_object(&candidate) {
                return Err(RetentionError::ObjectConflict);
            }
            continue;
        }
        let next_objects =
            import.staged_objects.checked_add(1).ok_or(RetentionError::ImportQuota)?;
        let next_bytes = import
            .staged_plaintext_bytes
            .checked_add(plaintext_len)
            .ok_or(RetentionError::ImportQuota)?;
        if next_objects > import.maximum_objects || next_bytes > import.maximum_plaintext_bytes {
            return Err(RetentionError::ImportQuota);
        }
        store_import_object(&transaction, inner, &candidate)?;
        import.staged_objects = next_objects;
        import.staged_plaintext_bytes = next_bytes;
    }
    import.validate(inner.wallet)?;
    meta.import = Some(import);
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn seal_import_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
) -> Result<DurableMeta, RetentionError> {
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let mut import = meta.import.clone().ok_or(RetentionError::NoImport)?;
    if import.phase != ImportPhase::Staging {
        transaction.commit().map_database()?;
        return Ok(meta);
    }
    if load_object_optional(&transaction, inner, import.target)?.is_none()
        && load_import_object_optional(&transaction, inner, import.target)?.is_none()
    {
        return Err(RetentionError::MissingGraphObject(import.target));
    }
    insert_dfs_frame(
        &transaction,
        inner,
        &DfsFrameRecord { version: RETENTION_VERSION, depth: 0, id: import.target, next_child: 0 },
    )?;
    if !insert_temp_queue(
        &transaction,
        inner,
        IMPORT_VISITING_TABLE,
        IMPORT_VISITING_LABEL,
        import.target,
    )? {
        return Err(RetentionError::InvalidDurableState);
    }
    import.stack_depth = 1;
    import.visiting_count = 1;
    import.phase = ImportPhase::Traversing;
    meta.import = Some(import);
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn advance_import_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    limit: usize,
) -> Result<DurableMeta, RetentionError> {
    if limit == 0 || limit > RETENTION_GC_BATCH_OBJECTS {
        return Err(RetentionError::ImportBatchBound);
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let mut import = meta.import.clone().ok_or(RetentionError::NoImport)?;
    match import.phase {
        ImportPhase::Staging => return Err(RetentionError::ImportNotSealed),
        ImportPhase::Traversing => {
            advance_import_traversal(&transaction, inner, &mut import, limit)?;
        }
        ImportPhase::Registering => {
            advance_import_registration(&transaction, inner, &mut meta, &mut import, limit)?;
        }
        ImportPhase::Publishing => {
            if import.pending_reference_count != 0
                || import.registered_count != import.staged_objects
            {
                return Err(RetentionError::InvalidDurableState);
            }
            let root = load_object_required(&transaction, inner, import.target)?;
            if !root.node {
                return Err(RetentionError::InvalidPortableRoot);
            }
            add_reference(&transaction, inner, &mut meta, import.target)?;
            if let Some(old) = import.expected_old {
                remove_reference(&transaction, inner, &mut meta, old)?;
            }
            meta.current_root = Some(import.target);
            import.phase = ImportPhase::Cleanup;
        }
        ImportPhase::Cleanup => {
            advance_import_cleanup(&transaction, inner, &mut import, limit)?;
            if import.reached_count == 0
                && import.registered_count == 0
                && !import_tables_nonempty(&transaction)?
            {
                meta.import = None;
                meta.bump_revision()?;
                store_meta(&transaction, inner, &meta)?;
                transaction.commit().map_database()?;
                return Ok(meta);
            }
        }
    }
    import.validate(inner.wallet)?;
    meta.import = Some(import);
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn advance_import_traversal(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    import: &mut DurableImport,
    limit: usize,
) -> Result<(), RetentionError> {
    for _ in 0..limit {
        let depth = import.stack_depth.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
        let mut frame = load_dfs_frame(transaction, inner, depth)?;
        if !temp_queue_contains(transaction, IMPORT_VISITING_TABLE, frame.id)?
            || temp_queue_contains(transaction, IMPORT_REACHED_TABLE, frame.id)?
        {
            return Err(RetentionError::InvalidDurableState);
        }

        let (children, imported) =
            if let Some(_live) = load_object_optional(transaction, inner, frame.id)? {
                // A live object is an authenticated lifetime boundary. Its immutable child edges
                // were checked and counted when it first entered the graph, and it cannot point
                // into this not-yet-published import.
                if frame.next_child != 0 {
                    return Err(RetentionError::InvalidDurableState);
                }
                (Vec::new(), false)
            } else {
                let candidate = load_import_object_optional(transaction, inner, frame.id)?
                    .ok_or(RetentionError::MissingGraphObject(frame.id))?;
                (candidate.children, true)
            };

        let next_child = usize::from(frame.next_child);
        if next_child < children.len() {
            let child = children[next_child];
            frame.next_child =
                frame.next_child.checked_add(1).ok_or(RetentionError::InvalidDurableState)?;
            store_dfs_frame(transaction, inner, &frame, true)?;

            if temp_queue_contains(transaction, IMPORT_REACHED_TABLE, child)? {
                continue;
            }
            if temp_queue_contains(transaction, IMPORT_VISITING_TABLE, child)? {
                return Err(RetentionError::GraphCycle);
            }
            if load_object_optional(transaction, inner, child)?.is_none()
                && load_import_object_optional(transaction, inner, child)?.is_none()
            {
                return Err(RetentionError::MissingGraphObject(child));
            }

            let child_depth = import.stack_depth;
            insert_dfs_frame(
                transaction,
                inner,
                &DfsFrameRecord {
                    version: RETENTION_VERSION,
                    depth: child_depth,
                    id: child,
                    next_child: 0,
                },
            )?;
            if !insert_temp_queue(
                transaction,
                inner,
                IMPORT_VISITING_TABLE,
                IMPORT_VISITING_LABEL,
                child,
            )? {
                return Err(RetentionError::InvalidDurableState);
            }
            import.stack_depth =
                import.stack_depth.checked_add(1).ok_or(RetentionError::CountOverflow)?;
            import.visiting_count =
                import.visiting_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
            let discovered = import
                .reached_count
                .checked_add(import.visiting_count)
                .ok_or(RetentionError::CountOverflow)?;
            if discovered > import.maximum_objects {
                return Err(RetentionError::ImportQuota);
            }
            continue;
        }
        if next_child != children.len() {
            return Err(RetentionError::InvalidDurableState);
        }

        remove_dfs_frame(transaction, inner, &frame)?;
        remove_temp_queue(
            transaction,
            inner,
            IMPORT_VISITING_TABLE,
            IMPORT_VISITING_LABEL,
            frame.id,
        )?;
        import.stack_depth =
            import.stack_depth.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
        import.visiting_count =
            import.visiting_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
        if !insert_temp_queue(
            transaction,
            inner,
            IMPORT_REACHED_TABLE,
            IMPORT_REACHED_LABEL,
            frame.id,
        )? {
            return Err(RetentionError::InvalidDurableState);
        }
        import.reached_count =
            import.reached_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
        if imported {
            import.reached_import_objects = import
                .reached_import_objects
                .checked_add(1)
                .ok_or(RetentionError::CountOverflow)?;
        }
        if import.stack_depth == 0 {
            break;
        }
    }
    if import.stack_depth == 0 {
        if import.visiting_count != 0 {
            return Err(RetentionError::InvalidDurableState);
        }
        if import.reached_import_objects != import.staged_objects {
            return Err(RetentionError::UnreachableStagedObject);
        }
        import.phase = ImportPhase::Registering;
    }
    Ok(())
}

fn advance_import_registration(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    import: &mut DurableImport,
    limit: usize,
) -> Result<(), RetentionError> {
    let pending = first_import_objects(transaction, inner, limit)?;
    for candidate in pending {
        let id = candidate.id;
        if load_object_optional(transaction, inner, id)?.is_some() {
            return Err(RetentionError::ObjectConflict);
        }
        let references = take_pending_references(transaction, inner, import, id)?;
        let mut durable = candidate.clone();
        durable.references = references;
        for child in &candidate.children {
            if load_object_optional(transaction, inner, *child)?.is_some() {
                add_reference(transaction, inner, meta, *child)?;
            } else if load_import_object_optional(transaction, inner, *child)?.is_some() {
                add_pending_reference(transaction, inner, import, *child)?;
            } else {
                return Err(RetentionError::MissingGraphObject(*child));
            }
        }
        cancel_delete_if_present(transaction, inner, meta, id)?;
        store_object(transaction, inner, &durable)?;
        meta.object_count =
            meta.object_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
        remove_import_object(transaction, inner, id)?;
        insert_temp_queue(
            transaction,
            inner,
            IMPORT_REGISTERED_TABLE,
            IMPORT_REGISTERED_LABEL,
            id,
        )?;
        import.registered_count =
            import.registered_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    if import.registered_count == import.staged_objects {
        if import.pending_reference_count != 0
            || !transaction
                .open_table(IMPORT_OBJECT_TABLE)
                .map_database()?
                .is_empty()
                .map_database()?
        {
            return Err(RetentionError::InvalidDurableState);
        }
        import.phase = ImportPhase::Publishing;
    }
    Ok(())
}

fn advance_import_cleanup(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    import: &mut DurableImport,
    limit: usize,
) -> Result<(), RetentionError> {
    let reached = first_temp_queue_ids(
        transaction,
        inner,
        IMPORT_REACHED_TABLE,
        IMPORT_REACHED_LABEL,
        limit,
    )?;
    let reached_removed = reached.len();
    for id in reached {
        remove_temp_queue(transaction, inner, IMPORT_REACHED_TABLE, IMPORT_REACHED_LABEL, id)?;
        import.reached_count =
            import.reached_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    }
    let remaining = limit.saturating_sub(reached_removed);
    if remaining == 0 {
        return Ok(());
    }
    let registered = first_temp_queue_ids(
        transaction,
        inner,
        IMPORT_REGISTERED_TABLE,
        IMPORT_REGISTERED_LABEL,
        remaining,
    )?;
    for id in registered {
        remove_temp_queue(
            transaction,
            inner,
            IMPORT_REGISTERED_TABLE,
            IMPORT_REGISTERED_LABEL,
            id,
        )?;
        import.registered_count =
            import.registered_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    }
    Ok(())
}

fn register_reachable_objects(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    root: Option<DepositIndexObjectId>,
    descriptors: &BTreeMap<DepositIndexObjectId, VerifiedObjectDescriptor>,
) -> Result<(), RetentionError> {
    let Some(root) = root else {
        if descriptors.is_empty() {
            return Ok(());
        }
        return Err(RetentionError::UnreachableStagedObject);
    };
    authenticate_id(root, inner.wallet)?;

    #[derive(Clone, Copy)]
    enum Visit {
        Enter(DepositIndexObjectId),
        Exit(DepositIndexObjectId),
    }

    let mut stack = vec![Visit::Enter(root)];
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut insertion_order = Vec::new();
    while let Some(visit) = stack.pop() {
        match visit {
            Visit::Enter(id) => {
                if done.contains(&id) {
                    continue;
                }
                if !visiting.insert(id) {
                    return Err(RetentionError::GraphCycle);
                }
                let existing = load_object_optional(transaction, inner, id)?;
                let supplied = descriptors.get(&id);
                match (existing.as_ref(), supplied) {
                    (Some(found), Some(candidate)) => {
                        if !found.same_object(&candidate.record) {
                            return Err(RetentionError::ObjectConflict);
                        }
                        used.insert(id);
                    }
                    (None, Some(_)) => {
                        used.insert(id);
                    }
                    (Some(_), None) => {
                        visiting.remove(&id);
                        done.insert(id);
                        continue;
                    }
                    (None, None) => return Err(RetentionError::MissingGraphObject(id)),
                }
                let record = supplied.map_or_else(
                    || existing.expect("the match established an existing record"),
                    |candidate| candidate.record.clone(),
                );
                stack.push(Visit::Exit(id));
                for child in record.children.iter().rev() {
                    stack.push(Visit::Enter(*child));
                }
            }
            Visit::Exit(id) => {
                visiting.remove(&id);
                done.insert(id);
                if load_object_optional(transaction, inner, id)?.is_none() {
                    insertion_order.push(id);
                }
            }
        }
    }
    if used.len() != descriptors.len() {
        return Err(RetentionError::UnreachableStagedObject);
    }

    for id in insertion_order {
        let candidate = descriptors.get(&id).ok_or(RetentionError::MissingGraphObject(id))?;
        for child in &candidate.record.children {
            add_reference(transaction, inner, meta, *child)?;
        }
        cancel_delete_if_present(transaction, inner, meta, id)?;
        store_object(transaction, inner, &candidate.record)?;
        meta.object_count =
            meta.object_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    Ok(())
}

fn acquire_pin_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    requester: PartyId,
    semantic_authority: SourcePinSemanticAuthority,
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
    expected_root: DepositIndexObjectId,
    response: Vec<u8>,
    authorization: SourcePinAuthorization,
    authorized_requesters: Vec<PartyId>,
) -> Result<(DurableMeta, SourcePinAcquire), RetentionError> {
    validate_authorized_requesters(&authorized_requesters)?;
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    match meta.authorization {
        Some(current) if current.epoch > authorization.epoch => {
            return Err(RetentionError::AuthorizationRollback);
        }
        Some(current) if current.epoch == authorization.epoch && current != authorization => {
            return Err(RetentionError::AuthorizationConflict);
        }
        Some(current) if current.epoch < authorization.epoch => {
            return Err(RetentionError::AuthorizationHandoffRequired);
        }
        Some(_) if meta.authorized_requesters != authorized_requesters => {
            return Err(RetentionError::AuthorizationConflict);
        }
        Some(_) => {}
        None => {
            meta.authorization = Some(authorization);
            meta.authorized_requesters = authorized_requesters;
        }
    }
    let lookup = pin_lookup(requester);
    if let Some(record) = load_pin_optional(&transaction, inner, requester)? {
        if !record.matches_acquisition(
            inner.source,
            requester,
            semantic_authority,
            context_digest,
            lease_digest,
        ) {
            return Err(RetentionError::SourcePinConflict);
        }
        let stored = public_pin(&record)?;
        transaction.commit().map_database()?;
        return Ok((meta, SourcePinAcquire::Existing(stored)));
    }
    if let Some(released) =
        load_released_pin_optional(&transaction, inner, semantic_authority.family, requester)?
    {
        if released.matches_authority(semantic_authority) {
            return Err(RetentionError::SourcePinNotAdvanced);
        }
        if released.lease_digest == lease_digest {
            return Err(RetentionError::SourcePinBinding);
        }
        remove_released_pin(&transaction, inner, &released)?;
        meta.released_pin_count =
            meta.released_pin_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    }
    if usize::from(meta.active_pin_count) == MAX_COMMITTEE_MEMBERS {
        return Err(RetentionError::SourcePinQuota);
    }
    if meta.current_root != Some(expected_root) {
        return Err(RetentionError::CurrentRootConflict);
    }
    add_reference(&transaction, inner, &mut meta, expected_root)?;
    let record = SourcePinRecord {
        version: SOURCE_PIN_VERSION,
        wallet: inner.wallet,
        source: inner.source,
        requester,
        family: semantic_authority.family,
        semantic_authority: semantic_authority.digest,
        context_digest,
        lease_digest,
        root: expected_root,
        response,
    };
    record.validate(inner.wallet, inner.source)?;
    store_pin(&transaction, inner, lookup.as_slice(), &record)?;
    meta.active_pin_count =
        meta.active_pin_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    let stored = public_pin(&record)?;
    transaction.commit().map_database()?;
    Ok((meta, SourcePinAcquire::Stored(stored)))
}

#[allow(clippy::too_many_arguments)]
fn acquire_export_head_pin_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    requester: PartyId,
    semantic_authority: SourcePinSemanticAuthority,
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
    expected_export: &StoredExportPin,
    response: Vec<u8>,
    authorization: SourcePinAuthorization,
    authorized_requesters: Vec<PartyId>,
) -> Result<(DurableMeta, SourcePinAcquire), RetentionError> {
    validate_authorized_requesters(&authorized_requesters)?;
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    match meta.authorization {
        Some(current) if current.epoch > authorization.epoch => {
            return Err(RetentionError::AuthorizationRollback);
        }
        Some(current) if current.epoch == authorization.epoch && current != authorization => {
            return Err(RetentionError::AuthorizationConflict);
        }
        Some(current) if current.epoch < authorization.epoch => {
            return Err(RetentionError::AuthorizationHandoffRequired);
        }
        Some(_) if meta.authorized_requesters != authorized_requesters => {
            return Err(RetentionError::AuthorizationConflict);
        }
        Some(_) => {}
        None => {
            meta.authorization = Some(authorization);
            meta.authorized_requesters = authorized_requesters;
        }
    }
    let index = load_export_index_optional(
        &transaction,
        inner,
        expected_export.semantic_transition_digest(),
    )?
    .ok_or(RetentionError::ExportCandidateNotPinned)?;
    let export = load_export_pin_required(&transaction, inner, index.exact_lookup)?;
    if export.seal_certificate.is_none() || public_export_pin(&export) != *expected_export {
        return Err(RetentionError::ExportPinConflict);
    }

    let lookup = pin_lookup(requester);
    if let Some(record) = load_pin_optional(&transaction, inner, requester)? {
        if !record.matches_acquisition(
            inner.source,
            requester,
            semantic_authority,
            context_digest,
            lease_digest,
        ) || record.root != export.terminal_portable_root
            || record.response != response
        {
            return Err(RetentionError::SourcePinConflict);
        }
        let stored = public_pin(&record)?;
        transaction.commit().map_database()?;
        return Ok((meta, SourcePinAcquire::Existing(stored)));
    }
    if let Some(released) =
        load_released_pin_optional(&transaction, inner, semantic_authority.family, requester)?
    {
        if released.matches_authority(semantic_authority) {
            return Err(RetentionError::SourcePinNotAdvanced);
        }
        if released.lease_digest == lease_digest {
            return Err(RetentionError::SourcePinBinding);
        }
        remove_released_pin(&transaction, inner, &released)?;
        meta.released_pin_count =
            meta.released_pin_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    }
    if usize::from(meta.active_pin_count) == MAX_COMMITTEE_MEMBERS {
        return Err(RetentionError::SourcePinQuota);
    }
    add_reference(&transaction, inner, &mut meta, export.terminal_portable_root)?;
    let record = SourcePinRecord {
        version: SOURCE_PIN_VERSION,
        wallet: inner.wallet,
        source: inner.source,
        requester,
        family: semantic_authority.family,
        semantic_authority: semantic_authority.digest,
        context_digest,
        lease_digest,
        root: export.terminal_portable_root,
        response,
    };
    record.validate(inner.wallet, inner.source)?;
    store_pin(&transaction, inner, lookup.as_slice(), &record)?;
    meta.active_pin_count =
        meta.active_pin_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    let stored = public_pin(&record)?;
    transaction.commit().map_database()?;
    Ok((meta, SourcePinAcquire::Stored(stored)))
}

fn lookup_pin_blocking(
    inner: &RetentionDatabase,
    source: PartyId,
    requester: PartyId,
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
) -> Result<Option<StoredSourcePin>, RetentionError> {
    if source != inner.source
        || requester == PartyId(0)
        || context_digest == [0_u8; 32]
        || lease_digest == [0_u8; 32]
    {
        return Err(RetentionError::SourcePinBinding);
    }
    let transaction = inner.database.begin_read().map_database()?;
    let Some(record) = load_pin_optional_read(&transaction, inner, requester)? else {
        return Ok(None);
    };
    if !record.matches_lease(source, requester, context_digest, lease_digest) {
        return Err(RetentionError::SourcePinBinding);
    }
    public_pin(&record).map(Some)
}

fn lookup_pin_for_head_blocking(
    inner: &RetentionDatabase,
    source: PartyId,
    requester: PartyId,
    context_digest: [u8; 32],
) -> Result<Option<StoredSourcePin>, RetentionError> {
    if source != inner.source || requester == PartyId(0) || context_digest == [0_u8; 32] {
        return Err(RetentionError::SourcePinBinding);
    }
    let transaction = inner.database.begin_read().map_database()?;
    let Some(record) = load_pin_optional_read(&transaction, inner, requester)? else {
        return Ok(None);
    };
    if record.source != source
        || record.requester != requester
        || record.context_digest != context_digest
    {
        return Err(RetentionError::SourcePinBinding);
    }
    public_pin(&record).map(Some)
}

fn release_pin_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    source: PartyId,
    requester: PartyId,
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
) -> Result<(DurableMeta, SourcePinRelease), RetentionError> {
    if source != inner.source
        || requester == PartyId(0)
        || context_digest == [0_u8; 32]
        || lease_digest == [0_u8; 32]
    {
        return Err(RetentionError::SourcePinBinding);
    }
    {
        let transaction = inner.database.begin_read().map_database()?;
        let meta = authenticate_expected_meta_read(&transaction, inner, expected_meta)?;
        match load_pin_optional_read(&transaction, inner, requester)? {
            Some(record) => {
                if !record.matches_lease(source, requester, context_digest, lease_digest) {
                    return Err(RetentionError::SourcePinBinding);
                }
            }
            None => return Ok((meta, SourcePinRelease::AlreadyReleased)),
        }
    }

    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let record = load_pin_optional(&transaction, inner, requester)?
        .ok_or(RetentionError::ConcurrentMutation)?;
    if !record.matches_lease(source, requester, context_digest, lease_digest) {
        return Err(RetentionError::SourcePinBinding);
    }
    if load_released_pin_optional(&transaction, inner, record.family, requester)?.is_some() {
        return Err(RetentionError::InvalidDurableState);
    }
    remove_reference(&transaction, inner, &mut meta, record.root)?;
    remove_pin(&transaction, inner, &record)?;
    meta.active_pin_count =
        meta.active_pin_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    if meta.authorized_requesters.binary_search(&requester).is_ok() {
        let released = ReleasedSourcePinRecord::from_active(&record);
        store_released_pin(&transaction, inner, &released)?;
        meta.released_pin_count =
            meta.released_pin_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok((meta, SourcePinRelease::Released))
}

fn acquire_export_pin_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    record: ExportPinRecord,
) -> Result<(DurableMeta, ExportPinAcquire), RetentionError> {
    record.validate(inner.wallet, inner.source)?;
    if record.seal_certificate.is_some() {
        return Err(RetentionError::InvalidExportPinBinding);
    }
    let exact_lookup = export_exact_lookup(&record)?;
    let index_lookup = export_index_lookup(record.semantic_transition, inner.source)?;
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    if load_export_reclaim_optional(&transaction, inner, record.semantic_transition)?.is_some() {
        return Err(RetentionError::ExportAlreadyImported);
    }
    if let Some(index) =
        load_export_index_optional(&transaction, inner, record.semantic_transition)?
    {
        if index.exact_lookup != exact_lookup {
            return Err(RetentionError::ExportPinConflict);
        }
        let existing = load_export_pin_required(&transaction, inner, exact_lookup)?;
        let mut candidate_projection = existing.clone();
        candidate_projection.seal_certificate = None;
        if candidate_projection != record {
            return Err(RetentionError::ExportPinConflict);
        }
        let stored = public_export_pin(&existing);
        transaction.commit().map_database()?;
        return Ok((meta, ExportPinAcquire::Existing(stored)));
    }
    if load_export_pin_optional(&transaction, inner, exact_lookup)?.is_some() {
        return Err(RetentionError::InvalidDurableState);
    }
    if meta.current_root != Some(record.terminal_portable_root) {
        return Err(RetentionError::CurrentRootConflict);
    }
    let root = load_object_required(&transaction, inner, record.terminal_portable_root)?;
    if !root.node {
        return Err(RetentionError::InvalidPortableRoot);
    }

    add_reference(&transaction, inner, &mut meta, record.terminal_portable_root)?;
    store_export_pin(&transaction, inner, exact_lookup, &record)?;
    store_export_index(
        &transaction,
        inner,
        index_lookup,
        &ExportIndexRecord {
            version: EXPORT_PIN_VERSION,
            wallet: inner.wallet,
            source: inner.source,
            semantic_transition: record.semantic_transition,
            exact_lookup,
        },
    )?;
    meta.export_pin_count =
        meta.export_pin_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    let stored = public_export_pin(&record);
    transaction.commit().map_database()?;
    Ok((meta, ExportPinAcquire::Stored(stored)))
}

fn certify_export_pin_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    seal: &VerifiedDepositPostHandoffExportSeal,
) -> Result<(DurableMeta, ExportPinCertification), RetentionError> {
    let transition = VerifiedStateImportTransitionBinding::from_verified_export_seal(seal)?;
    if transition.wallet() != inner.wallet || transition.source_party() != inner.source {
        return Err(RetentionError::InvalidExportPinBinding);
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    if load_export_reclaim_optional(&transaction, inner, transition.semantic_transition_digest())?
        .is_some()
    {
        return Err(RetentionError::ExportAlreadyImported);
    }
    let index =
        load_export_index_optional(&transaction, inner, transition.semantic_transition_digest())?
            .ok_or(RetentionError::ExportCandidateNotPinned)?;
    let mut record = load_export_pin_required(&transaction, inner, index.exact_lookup)?;
    if !record.matches_verified_seal(seal)? {
        return Err(RetentionError::ExportPinConflict);
    }
    let certificate = ExportSealCertificateRecord::from_verified(seal)?;
    if let Some(existing) = &record.seal_certificate {
        if existing != &certificate {
            return Err(RetentionError::ExportPinConflict);
        }
        let stored = public_export_pin(&record);
        transaction.commit().map_database()?;
        return Ok((meta, ExportPinCertification::Existing(stored)));
    }
    record.seal_certificate = Some(certificate);
    if export_exact_lookup(&record)? != index.exact_lookup {
        return Err(RetentionError::InvalidDurableState);
    }
    store_export_pin(&transaction, inner, index.exact_lookup, &record)?;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    let stored = public_export_pin(&record);
    transaction.commit().map_database()?;
    Ok((meta, ExportPinCertification::Certified(stored)))
}

fn lookup_export_pin_blocking(
    inner: &RetentionDatabase,
    seal: &VerifiedDepositPostHandoffExportSeal,
) -> Result<Option<StoredExportPin>, RetentionError> {
    let transition = VerifiedStateImportTransitionBinding::from_verified_export_seal(seal)?;
    if transition.wallet() != inner.wallet || transition.source_party() != inner.source {
        return Err(RetentionError::InvalidExportPinBinding);
    }
    let transaction = inner.database.begin_read().map_database()?;
    let Some(index) = load_export_index_optional_read(
        &transaction,
        inner,
        transition.semantic_transition_digest(),
    )?
    else {
        return Ok(None);
    };
    let found = load_export_pin_required_read(&transaction, inner, index.exact_lookup)?;
    if !found.matches_verified_seal(seal)? {
        return Err(RetentionError::ExportPinConflict);
    }
    let expected_certificate = ExportSealCertificateRecord::from_verified(seal)?;
    let Some(stored_certificate) = &found.seal_certificate else {
        return Ok(None);
    };
    if stored_certificate != &expected_certificate {
        return Err(RetentionError::ExportPinConflict);
    }
    Ok(Some(public_export_pin(&found)))
}

fn lookup_certified_export_pin_blocking(
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<StoredExportPin>, RetentionError> {
    if semantic_transition == [0; 32] {
        return Err(RetentionError::InvalidExportPinBinding);
    }
    let transaction = inner.database.begin_read().map_database()?;
    let Some(index) = load_export_index_optional_read(&transaction, inner, semantic_transition)?
    else {
        return Ok(None);
    };
    let record = load_export_pin_required_read(&transaction, inner, index.exact_lookup)?;
    if record.seal_certificate.is_none() {
        return Ok(None);
    }
    Ok(Some(public_export_pin(&record)))
}

fn reclaim_export_pins_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    authority: ExportReclaimAuthority,
) -> Result<(DurableMeta, ExportPinReclaim), RetentionError> {
    authority.validate(inner.wallet)?;
    let index_lookup = export_index_lookup(authority.semantic_transition, inner.source)?;
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    if meta.reauthentication.as_ref().is_some_and(|reauthentication| {
        reauthentication.anchor
            == (PortableReauthenticationAnchor::Export {
                semantic_transition: authority.semantic_transition,
            })
    }) {
        return Err(RetentionError::ReauthenticationInProgress);
    }
    if let Some(reclaimed) =
        load_export_reclaim_optional(&transaction, inner, authority.semantic_transition)?
    {
        if !reclaimed.matches(&authority) {
            return Err(RetentionError::ExportReclaimConflict);
        }
        if load_export_index_optional(&transaction, inner, authority.semantic_transition)?.is_some()
        {
            return Err(RetentionError::InvalidDurableState);
        }
        transaction.commit().map_database()?;
        return Ok((meta, ExportPinReclaim::AlreadyReclaimed));
    }

    let variants = if let Some(index) =
        load_export_index_optional(&transaction, inner, authority.semantic_transition)?
    {
        let record = load_export_pin_required(&transaction, inner, index.exact_lookup)?;
        if !record.matches_reclaim(&authority) {
            return Err(RetentionError::ExportReclaimConflict);
        }
        remove_reference(&transaction, inner, &mut meta, record.terminal_portable_root)?;
        {
            let mut pins = transaction.open_table(EXPORT_PIN_TABLE).map_database()?;
            if pins.remove(index.exact_lookup.as_slice()).map_database()?.is_none() {
                return Err(RetentionError::InvalidDurableState);
            }
        }
        {
            let mut indices = transaction.open_table(EXPORT_INDEX_TABLE).map_database()?;
            if indices.remove(index_lookup.as_slice()).map_database()?.is_none() {
                return Err(RetentionError::InvalidDurableState);
            }
        }
        meta.export_pin_count =
            meta.export_pin_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
        1
    } else {
        0
    };

    let reclaimed = ExportReclaimRecord::from_authority(&authority, variants);
    store_export_reclaim(&transaction, inner, &reclaimed)?;
    meta.export_reclaim_count =
        meta.export_reclaim_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok((
        meta,
        if variants == 0 {
            ExportPinReclaim::AlreadyReclaimed
        } else {
            ExportPinReclaim::Reclaimed { variants }
        },
    ))
}

fn require_export_reclaim_tombstone_blocking(
    inner: &RetentionDatabase,
    authority: &ExportReclaimAuthority,
) -> Result<(), RetentionError> {
    authority.validate(inner.wallet)?;
    let transaction = inner.database.begin_read().map_database()?;
    let reclaimed =
        load_export_reclaim_optional_read(&transaction, inner, authority.semantic_transition)?
            .ok_or(RetentionError::ExportReclaimTombstoneMissing)?;
    if !reclaimed.matches(authority) {
        return Err(RetentionError::ExportReclaimConflict);
    }
    if load_export_index_optional_read(&transaction, inner, authority.semantic_transition)?
        .is_some()
    {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn begin_reauthentication_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    proposed: DurableReauthentication,
) -> Result<DurableMeta, RetentionError> {
    proposed.validate(inner.wallet)?;
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if meta.import.is_some() {
        return Err(RetentionError::ImportInProgress);
    }
    if let Some(existing) = &meta.reauthentication {
        if existing.anchor != proposed.anchor
            || existing.head != proposed.head
            || existing.root != proposed.root
            || existing.head_digest != proposed.head_digest
            || existing.maximum_objects != proposed.maximum_objects
        {
            return Err(RetentionError::ReauthenticationConflict);
        }
        transaction.commit().map_database()?;
        return Ok(meta);
    }
    if reauthentication_tables_nonempty(&transaction)? {
        return Err(RetentionError::InvalidDurableState);
    }
    validate_reauthentication_anchor(&transaction, inner, &meta, &proposed)?;
    let root = load_object_required(&transaction, inner, proposed.root)?;
    if !root.node || root.references == 0 {
        return Err(RetentionError::InvalidPortableRoot);
    }
    insert_reauthentication_frame(
        &transaction,
        inner,
        &DfsFrameRecord { version: RETENTION_VERSION, depth: 0, id: proposed.root, next_child: 0 },
    )?;
    if !insert_temp_queue(
        &transaction,
        inner,
        REAUTH_VISITING_TABLE,
        REAUTH_VISITING_LABEL,
        proposed.root,
    )? {
        return Err(RetentionError::InvalidDurableState);
    }
    meta.reauthentication = Some(proposed);
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn prepare_reauthentication_batch_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
) -> Result<(DurableMeta, Vec<DepositIndexObjectId>), RetentionError> {
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let mut reauthentication =
        meta.reauthentication.clone().ok_or(RetentionError::NoReauthentication)?;
    let restart_after_cleanup = match reauthentication.phase {
        ReauthenticationPhase::Verified => {
            reauthentication.phase = ReauthenticationPhase::CleanupRestart;
            true
        }
        ReauthenticationPhase::CleanupRestart => true,
        ReauthenticationPhase::CleanupClear => false,
        ReauthenticationPhase::Traversing => {
            validate_reauthentication_anchor(&transaction, inner, &meta, &reauthentication)?;
            advance_reauthentication_traversal(
                &transaction,
                inner,
                &mut reauthentication,
                RETENTION_REAUTH_TRAVERSAL_STEPS,
            )?;
            if reauthentication.stack_depth == 0
                && reauthentication.pending_count == 0
                && reauthentication.verified_count == reauthentication.reached_count
            {
                verify_reauthenticated_head(&transaction, inner, &reauthentication)?;
                reauthentication.phase = ReauthenticationPhase::Verified;
            }
            let pending =
                first_reauthentication_pending_ids(&transaction, inner, &reauthentication)?;
            reauthentication.validate(inner.wallet)?;
            meta.reauthentication = Some(reauthentication);
            meta.bump_revision()?;
            store_meta(&transaction, inner, &meta)?;
            transaction.commit().map_database()?;
            return Ok((meta, pending));
        }
    };

    let reached = first_temp_queue_ids(
        &transaction,
        inner,
        REAUTH_REACHED_TABLE,
        REAUTH_REACHED_LABEL,
        RETENTION_REAUTH_TRAVERSAL_STEPS,
    )?;
    for id in reached {
        remove_temp_queue(&transaction, inner, REAUTH_REACHED_TABLE, REAUTH_REACHED_LABEL, id)?;
        remove_reauthentication_object(&transaction, inner, id)?;
        reauthentication.reached_count = reauthentication
            .reached_count
            .checked_sub(1)
            .ok_or(RetentionError::InvalidDurableState)?;
        reauthentication.verified_count = reauthentication
            .verified_count
            .checked_sub(1)
            .ok_or(RetentionError::InvalidDurableState)?;
    }
    if reauthentication.reached_count == 0 {
        if reauthentication_tables_nonempty(&transaction)? {
            return Err(RetentionError::InvalidDurableState);
        }
        if restart_after_cleanup
            && reauthentication_anchor_matches(&transaction, inner, &meta, &reauthentication)?
        {
            insert_reauthentication_frame(
                &transaction,
                inner,
                &DfsFrameRecord {
                    version: RETENTION_VERSION,
                    depth: 0,
                    id: reauthentication.root,
                    next_child: 0,
                },
            )?;
            if !insert_temp_queue(
                &transaction,
                inner,
                REAUTH_VISITING_TABLE,
                REAUTH_VISITING_LABEL,
                reauthentication.root,
            )? {
                return Err(RetentionError::InvalidDurableState);
            }
            reauthentication.stack_depth = 1;
            reauthentication.visiting_count = 1;
            reauthentication.phase = ReauthenticationPhase::Traversing;
            meta.reauthentication = Some(reauthentication);
        } else {
            meta.reauthentication = None;
        }
    } else {
        reauthentication.validate(inner.wallet)?;
        meta.reauthentication = Some(reauthentication);
    }
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok((meta, Vec::new()))
}

fn release_reauthentication_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    completed: &ReauthenticatedPortableRoot,
) -> Result<DurableMeta, RetentionError> {
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    if completed.wallet != meta.wallet || completed.source != meta.source {
        return Err(RetentionError::InvalidReauthenticationBinding);
    }
    // Multiple readers may share a completion token. Once cleanup has finished there is
    // nothing left to release; this no-op neither restores audit authority nor removes a root.
    let Some(mut reauthentication) = meta.reauthentication.clone() else {
        return Ok(meta);
    };
    let expected = reauthentication_token(&meta, &reauthentication)?;
    if &expected != completed {
        return Err(RetentionError::ReauthenticationConflict);
    }
    match reauthentication.phase {
        ReauthenticationPhase::Verified => {
            reauthentication.phase = ReauthenticationPhase::CleanupClear;
            reauthentication.validate(inner.wallet)?;
            meta.reauthentication = Some(reauthentication);
            meta.bump_revision()?;
            store_meta(&transaction, inner, &meta)?;
        }
        ReauthenticationPhase::CleanupClear => {}
        ReauthenticationPhase::Traversing | ReauthenticationPhase::CleanupRestart => {
            return Err(RetentionError::ReauthenticationConflict);
        }
    }
    transaction.commit().map_database()?;
    Ok(meta)
}

fn advance_reauthentication_traversal(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    reauthentication: &mut DurableReauthentication,
    limit: usize,
) -> Result<(), RetentionError> {
    for _ in 0..limit {
        if reauthentication.stack_depth == 0
            || usize::try_from(reauthentication.pending_count)
                .is_ok_and(|pending| pending >= RETENTION_REAUTH_BATCH_OBJECTS)
        {
            break;
        }
        let depth = reauthentication
            .stack_depth
            .checked_sub(1)
            .ok_or(RetentionError::InvalidDurableState)?;
        let mut frame = load_reauthentication_frame(transaction, inner, depth)?;
        if !temp_queue_contains(transaction, REAUTH_VISITING_TABLE, frame.id)?
            || temp_queue_contains(transaction, REAUTH_REACHED_TABLE, frame.id)?
        {
            return Err(RetentionError::InvalidDurableState);
        }
        let record = load_object_required(transaction, inner, frame.id)?;
        let next_child = usize::from(frame.next_child);
        if next_child < record.children.len() {
            let child = record.children[next_child];
            frame.next_child =
                frame.next_child.checked_add(1).ok_or(RetentionError::InvalidDurableState)?;
            store_reauthentication_frame(transaction, inner, &frame, true)?;
            if temp_queue_contains(transaction, REAUTH_REACHED_TABLE, child)? {
                continue;
            }
            if temp_queue_contains(transaction, REAUTH_VISITING_TABLE, child)? {
                return Err(RetentionError::GraphCycle);
            }
            load_object_required(transaction, inner, child)?;
            let child_depth = reauthentication.stack_depth;
            insert_reauthentication_frame(
                transaction,
                inner,
                &DfsFrameRecord {
                    version: RETENTION_VERSION,
                    depth: child_depth,
                    id: child,
                    next_child: 0,
                },
            )?;
            if !insert_temp_queue(
                transaction,
                inner,
                REAUTH_VISITING_TABLE,
                REAUTH_VISITING_LABEL,
                child,
            )? {
                return Err(RetentionError::InvalidDurableState);
            }
            reauthentication.stack_depth =
                reauthentication.stack_depth.checked_add(1).ok_or(RetentionError::CountOverflow)?;
            reauthentication.visiting_count = reauthentication
                .visiting_count
                .checked_add(1)
                .ok_or(RetentionError::CountOverflow)?;
            let discovered = reauthentication
                .reached_count
                .checked_add(reauthentication.visiting_count)
                .ok_or(RetentionError::CountOverflow)?;
            if discovered > reauthentication.maximum_objects {
                return Err(RetentionError::ReauthenticationQuota);
            }
            continue;
        }
        if next_child != record.children.len() {
            return Err(RetentionError::InvalidDurableState);
        }
        remove_reauthentication_frame(transaction, inner, &frame)?;
        remove_temp_queue(
            transaction,
            inner,
            REAUTH_VISITING_TABLE,
            REAUTH_VISITING_LABEL,
            frame.id,
        )?;
        reauthentication.stack_depth = reauthentication
            .stack_depth
            .checked_sub(1)
            .ok_or(RetentionError::InvalidDurableState)?;
        reauthentication.visiting_count = reauthentication
            .visiting_count
            .checked_sub(1)
            .ok_or(RetentionError::InvalidDurableState)?;
        if !insert_temp_queue(
            transaction,
            inner,
            REAUTH_REACHED_TABLE,
            REAUTH_REACHED_LABEL,
            frame.id,
        )? || !insert_temp_queue(
            transaction,
            inner,
            REAUTH_PENDING_TABLE,
            REAUTH_PENDING_LABEL,
            frame.id,
        )? {
            return Err(RetentionError::InvalidDurableState);
        }
        reauthentication.reached_count =
            reauthentication.reached_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
        reauthentication.pending_count =
            reauthentication.pending_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    Ok(())
}

fn first_reauthentication_pending_ids(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    reauthentication: &DurableReauthentication,
) -> Result<Vec<DepositIndexObjectId>, RetentionError> {
    let candidates = first_temp_queue_ids(
        transaction,
        inner,
        REAUTH_PENDING_TABLE,
        REAUTH_PENDING_LABEL,
        RETENTION_REAUTH_BATCH_OBJECTS,
    )?;
    let mut ids = Vec::with_capacity(candidates.len());
    let mut plaintext_bytes = 0_usize;
    for id in candidates {
        let length =
            usize::try_from(id.plaintext_len()).map_err(|_| RetentionError::InvalidDurableState)?;
        let next = plaintext_bytes.checked_add(length).ok_or(RetentionError::CountOverflow)?;
        if next > RETENTION_REAUTH_BATCH_BYTES {
            if ids.is_empty() {
                return Err(RetentionError::GraphBoundExceeded);
            }
            break;
        }
        plaintext_bytes = next;
        ids.push(id);
    }
    if u64::try_from(ids.len()).is_ok_and(|count| count > reauthentication.pending_count) {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(ids)
}

fn verify_reauthentication_batch_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    objects: Vec<(DepositIndexObjectId, Vec<u8>)>,
) -> Result<DurableMeta, RetentionError> {
    if objects.is_empty() || objects.len() > RETENTION_REAUTH_BATCH_OBJECTS {
        return Err(RetentionError::GraphBoundExceeded);
    }
    let mut total = 0_usize;
    let mut unique = BTreeSet::new();
    for (id, bytes) in &objects {
        if !unique.insert(*id) {
            return Err(RetentionError::DuplicateObject);
        }
        total = total.checked_add(bytes.len()).ok_or(RetentionError::CountOverflow)?;
        if total > RETENTION_REAUTH_BATCH_BYTES {
            return Err(RetentionError::GraphBoundExceeded);
        }
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let mut reauthentication =
        meta.reauthentication.clone().ok_or(RetentionError::NoReauthentication)?;
    if reauthentication.phase != ReauthenticationPhase::Traversing {
        return Err(RetentionError::ReauthenticationConflict);
    }
    validate_reauthentication_anchor(&transaction, inner, &meta, &reauthentication)?;
    for (id, bytes) in objects {
        if !temp_queue_contains(&transaction, REAUTH_PENDING_TABLE, id)? {
            return Err(RetentionError::InvalidDurableState);
        }
        let expected = load_object_required(&transaction, inner, id)?;
        verify_reauthentication_object(inner, &expected, &bytes)?;
        store_reauthentication_object(
            &transaction,
            inner,
            &ReauthenticationObjectRecord { version: RETENTION_VERSION, id, bytes },
        )?;
        remove_temp_queue(&transaction, inner, REAUTH_PENDING_TABLE, REAUTH_PENDING_LABEL, id)?;
        reauthentication.pending_count = reauthentication
            .pending_count
            .checked_sub(1)
            .ok_or(RetentionError::InvalidDurableState)?;
        reauthentication.verified_count =
            reauthentication.verified_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    if reauthentication.stack_depth == 0
        && reauthentication.pending_count == 0
        && reauthentication.verified_count == reauthentication.reached_count
    {
        verify_reauthenticated_head(&transaction, inner, &reauthentication)?;
        reauthentication.phase = ReauthenticationPhase::Verified;
    }
    reauthentication.validate(inner.wallet)?;
    meta.reauthentication = Some(reauthentication);
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn verify_reauthentication_object(
    inner: &RetentionDatabase,
    expected: &ObjectRecord,
    bytes: &[u8],
) -> Result<(), RetentionError> {
    expected.id.storage_reference().verify_contents(bytes)?;
    #[cfg(test)]
    if bytes.len() == std::mem::size_of::<u64>() {
        return Ok(());
    }
    let verified = verify_portable_index_object(inner.wallet, expected.id, bytes)?;
    if verified.is_node() != expected.node || verified.children() != expected.children {
        return Err(RetentionError::ObjectConflict);
    }
    Ok(())
}

fn completed_reauthentication(
    meta: &DurableMeta,
) -> Result<Option<ReauthenticatedPortableRoot>, RetentionError> {
    let Some(reauthentication) = &meta.reauthentication else {
        return Ok(None);
    };
    reauthentication.validate(meta.wallet)?;
    if reauthentication.phase != ReauthenticationPhase::Verified {
        return Ok(None);
    }
    Ok(Some(reauthentication_token(meta, reauthentication)?))
}

fn reauthentication_token(
    meta: &DurableMeta,
    reauthentication: &DurableReauthentication,
) -> Result<ReauthenticatedPortableRoot, RetentionError> {
    reauthentication.validate(meta.wallet)?;
    if reauthentication.verified_count != reauthentication.reached_count
        || reauthentication.pending_count != 0
        || reauthentication.stack_depth != 0
        || reauthentication.reached_count == 0
    {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(ReauthenticatedPortableRoot {
        wallet: meta.wallet,
        source: meta.source,
        anchor: reauthentication.anchor,
        root: reauthentication.root,
        head_digest: reauthentication.head_digest,
        object_count: reauthentication.verified_count,
    })
}

fn validate_reauthentication_anchor(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &DurableMeta,
    reauthentication: &DurableReauthentication,
) -> Result<(), RetentionError> {
    if !reauthentication_anchor_matches(transaction, inner, meta, reauthentication)? {
        return Err(RetentionError::ReauthenticationAnchorLost);
    }
    Ok(())
}

fn reauthentication_anchor_matches(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &DurableMeta,
    reauthentication: &DurableReauthentication,
) -> Result<bool, RetentionError> {
    let named = match reauthentication.anchor {
        PortableReauthenticationAnchor::Current => meta.current_root == Some(reauthentication.root),
        PortableReauthenticationAnchor::Export { semantic_transition } => {
            let Some(index) = load_export_index_optional(transaction, inner, semantic_transition)?
            else {
                return Ok(false);
            };
            let export = load_export_pin_required(transaction, inner, index.exact_lookup)?;
            export.terminal_portable_root == reauthentication.root
                && export.terminal_portable_head == reauthentication.head_digest
        }
    };
    if !named {
        return Ok(false);
    }
    let root = load_object_required(transaction, inner, reauthentication.root)?;
    Ok(root.node && root.references != 0)
}

fn verify_reauthenticated_head(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    reauthentication: &DurableReauthentication,
) -> Result<(), RetentionError> {
    if reauthentication.verified_count != reauthentication.reached_count
        || reauthentication.pending_count != 0
        || reauthentication.stack_depth != 0
    {
        return Err(RetentionError::InvalidDurableState);
    }
    let head = DepositIndexHead::from_portable_components(
        reauthentication.head.wallet_id(),
        reauthentication.head.entry_count(),
        reauthentication.head.record_count(),
        reauthentication.head.root(),
        reauthentication.head.through_sequence(),
        reauthentication.head.ledger_head(),
        reauthentication.head.next_index(),
    )?;
    if !reauthentication
        .head
        .matches(&head)
        .map_err(|_| RetentionError::InvalidReauthenticationBinding)?
    {
        return Err(RetentionError::InvalidReauthenticationBinding);
    }
    let table = transaction.open_table(REAUTH_OBJECT_TABLE).map_database()?;
    let reader = ReauthenticationObjectReader {
        table: &table,
        wallet: inner.wallet,
        mac_key: &inner.mac_key,
    };
    verify_deposit_index_head(&reader, &head)?;
    Ok(())
}

struct ReauthenticationObjectReader<'a, T> {
    table: &'a T,
    wallet: DepositWalletId,
    mac_key: &'a [u8; 32],
}

impl<T> DepositIndexReader for ReauthenticationObjectReader<'_, T>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        let lookup = object_lookup(id).map_err(|_| DepositIndexError::ObjectAuthentication)?;
        let Some(bytes) = self
            .table
            .get(lookup.as_slice())
            .map_err(|_| DepositIndexError::ObjectAuthentication)?
        else {
            return Ok(None);
        };
        let record: ReauthenticationObjectRecord = decode_authenticated(
            self.mac_key,
            REAUTH_OBJECT_LABEL,
            lookup.as_slice(),
            bytes.value(),
            MAX_REAUTH_OBJECT_RECORD_BYTES,
        )
        .map_err(|_| DepositIndexError::ObjectAuthentication)?;
        record.validate(self.wallet).map_err(|_| DepositIndexError::ObjectAuthentication)?;
        if record.id != id {
            return Err(DepositIndexError::ObjectAuthentication);
        }
        Ok(Some(record.bytes))
    }
}

fn advance_pin_authorization_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    authorization: SourcePinAuthorization,
    active_requesters: &BTreeSet<PartyId>,
) -> Result<(DurableMeta, usize), RetentionError> {
    let authorized_requesters = active_requesters.iter().copied().collect::<Vec<_>>();
    validate_authorized_requesters(&authorized_requesters)?;
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    match meta.authorization {
        Some(current) if current.epoch > authorization.epoch => {
            return Err(RetentionError::AuthorizationRollback);
        }
        Some(current) if current.epoch == authorization.epoch && current != authorization => {
            return Err(RetentionError::AuthorizationConflict);
        }
        Some(current)
            if current == authorization && meta.authorized_requesters != authorized_requesters =>
        {
            return Err(RetentionError::AuthorizationConflict);
        }
        _ => {}
    }
    let authorization_changed = meta.authorization != Some(authorization);
    meta.authorization = Some(authorization);
    meta.authorized_requesters = authorized_requesters;
    let departed = {
        let table = transaction.open_table(RELEASED_PIN_TABLE).map_database()?;
        let mut iterator = table.iter().map_database()?;
        let mut departed = Vec::new();
        while let Some(entry) = iterator.next() {
            let (lookup, bytes) = entry.map_database()?;
            let (family, requester) = decode_released_pin_lookup(lookup.value())?;
            let record: ReleasedSourcePinRecord = decode_authenticated(
                &inner.mac_key,
                RELEASED_PIN_LABEL,
                lookup.value(),
                bytes.value(),
                4096,
            )?;
            record.validate(inner.wallet, inner.source)?;
            if record.requester != requester || record.family != family {
                return Err(RetentionError::InvalidDurableState);
            }
            if !active_requesters.contains(&requester) {
                departed.push(record);
            }
        }
        departed
    };
    for record in &departed {
        remove_released_pin(&transaction, inner, record)?;
        meta.released_pin_count =
            meta.released_pin_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    }
    if authorization_changed || !departed.is_empty() {
        meta.bump_revision()?;
        store_meta(&transaction, inner, &meta)?;
    }
    transaction.commit().map_database()?;
    Ok((meta, departed.len()))
}

fn prepare_gc_batch_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    limit: usize,
) -> Result<(DurableMeta, Vec<DepositIndexObjectId>), RetentionError> {
    if limit == 0 || limit > RETENTION_GC_BATCH_OBJECTS {
        return Err(RetentionError::GraphBoundExceeded);
    }
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    let pending = first_queue_ids(&transaction, inner, UNLINK_TABLE, UNLINK_LABEL, limit)?;
    for id in pending {
        let record = load_object_required(&transaction, inner, id)?;
        if record.references != 0 {
            return Err(RetentionError::InvalidDurableState);
        }
        {
            let mut objects = transaction.open_table(OBJECT_TABLE).map_database()?;
            if objects.remove(object_lookup(id)?.as_slice()).map_database()?.is_none() {
                return Err(RetentionError::InvalidDurableState);
            }
        }
        meta.object_count =
            meta.object_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
        for child in record.children {
            remove_reference(&transaction, inner, &mut meta, child)?;
        }
        remove_queue(&transaction, inner, &mut meta, UNLINK_TABLE, UNLINK_LABEL, id)?;
        insert_queue(&transaction, inner, &mut meta, DELETE_TABLE, DELETE_LABEL, id)?;
    }
    let deletions = first_queue_ids(&transaction, inner, DELETE_TABLE, DELETE_LABEL, limit)?;
    if expected_meta != &meta {
        meta.bump_revision()?;
        store_meta(&transaction, inner, &meta)?;
    }
    transaction.commit().map_database()?;
    Ok((meta, deletions))
}

fn acknowledge_delete_blocking(
    inner: &RetentionDatabase,
    expected_meta: &DurableMeta,
    id: DepositIndexObjectId,
) -> Result<DurableMeta, RetentionError> {
    let mut transaction = inner.database.begin_write().map_database()?;
    configure_write(&mut transaction);
    let mut meta = authenticate_expected_meta(&transaction, inner, expected_meta)?;
    remove_queue(&transaction, inner, &mut meta, DELETE_TABLE, DELETE_LABEL, id)?;
    meta.bump_revision()?;
    store_meta(&transaction, inner, &meta)?;
    transaction.commit().map_database()?;
    Ok(meta)
}

fn initialize_tables(transaction: &redb::WriteTransaction) -> Result<(), RetentionError> {
    drop(transaction.open_table(META_TABLE).map_database()?);
    drop(transaction.open_table(OBJECT_TABLE).map_database()?);
    drop(transaction.open_table(PIN_TABLE).map_database()?);
    drop(transaction.open_table(RELEASED_PIN_TABLE).map_database()?);
    drop(transaction.open_table(EXPORT_PIN_TABLE).map_database()?);
    drop(transaction.open_table(EXPORT_INDEX_TABLE).map_database()?);
    drop(transaction.open_table(EXPORT_RECLAIM_TABLE).map_database()?);
    drop(transaction.open_table(UNLINK_TABLE).map_database()?);
    drop(transaction.open_table(DELETE_TABLE).map_database()?);
    drop(transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?);
    drop(transaction.open_table(IMPORT_STACK_TABLE).map_database()?);
    drop(transaction.open_table(IMPORT_VISITING_TABLE).map_database()?);
    drop(transaction.open_table(IMPORT_REACHED_TABLE).map_database()?);
    drop(transaction.open_table(IMPORT_REGISTERED_TABLE).map_database()?);
    drop(transaction.open_table(IMPORT_PENDING_REF_TABLE).map_database()?);
    drop(transaction.open_table(REAUTH_STACK_TABLE).map_database()?);
    drop(transaction.open_table(REAUTH_VISITING_TABLE).map_database()?);
    drop(transaction.open_table(REAUTH_REACHED_TABLE).map_database()?);
    drop(transaction.open_table(REAUTH_PENDING_TABLE).map_database()?);
    drop(transaction.open_table(REAUTH_OBJECT_TABLE).map_database()?);
    Ok(())
}

fn tables_nonempty(transaction: &redb::WriteTransaction) -> Result<bool, RetentionError> {
    Ok(!transaction.open_table(OBJECT_TABLE).map_database()?.is_empty().map_database()?
        || !transaction.open_table(PIN_TABLE).map_database()?.is_empty().map_database()?
        || !transaction.open_table(RELEASED_PIN_TABLE).map_database()?.is_empty().map_database()?
        || !transaction.open_table(EXPORT_PIN_TABLE).map_database()?.is_empty().map_database()?
        || !transaction.open_table(EXPORT_INDEX_TABLE).map_database()?.is_empty().map_database()?
        || !transaction
            .open_table(EXPORT_RECLAIM_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction.open_table(UNLINK_TABLE).map_database()?.is_empty().map_database()?
        || !transaction.open_table(DELETE_TABLE).map_database()?.is_empty().map_database()?
        || !transaction
            .open_table(IMPORT_OBJECT_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction.open_table(IMPORT_STACK_TABLE).map_database()?.is_empty().map_database()?
        || !transaction
            .open_table(IMPORT_VISITING_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(IMPORT_REACHED_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(IMPORT_REGISTERED_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(IMPORT_PENDING_REF_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction.open_table(REAUTH_STACK_TABLE).map_database()?.is_empty().map_database()?
        || !transaction
            .open_table(REAUTH_VISITING_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(REAUTH_REACHED_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(REAUTH_PENDING_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(REAUTH_OBJECT_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?)
}

fn load_meta_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
) -> Result<Option<DurableMeta>, RetentionError> {
    let table = transaction.open_table(META_TABLE).map_database()?;
    let Some(value) = table.get(META_KEY).map_database()? else {
        return Ok(None);
    };
    let meta =
        decode_authenticated(&inner.mac_key, META_LABEL, META_KEY, value.value(), MAX_META_BYTES)?;
    Ok(Some(meta))
}

fn load_meta_optional_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
) -> Result<Option<DurableMeta>, RetentionError> {
    let table = transaction.open_table(META_TABLE).map_database()?;
    let Some(value) = table.get(META_KEY).map_database()? else {
        return Ok(None);
    };
    let meta =
        decode_authenticated(&inner.mac_key, META_LABEL, META_KEY, value.value(), MAX_META_BYTES)?;
    Ok(Some(meta))
}

fn store_meta(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &DurableMeta,
) -> Result<(), RetentionError> {
    meta.validate(inner.wallet, inner.source)?;
    let encoded = encode_authenticated(&inner.mac_key, META_LABEL, META_KEY, meta, MAX_META_BYTES)?;
    let mut table = transaction.open_table(META_TABLE).map_database()?;
    table.insert(META_KEY, encoded.as_slice()).map_database()?;
    Ok(())
}

fn authenticate_expected_meta(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    expected: &DurableMeta,
) -> Result<DurableMeta, RetentionError> {
    let found =
        load_meta_optional(transaction, inner)?.ok_or(RetentionError::MissingRetentionState)?;
    found.validate(inner.wallet, inner.source)?;
    if &found != expected {
        return Err(RetentionError::ConcurrentMutation);
    }
    Ok(found)
}

fn authenticate_expected_meta_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    expected: &DurableMeta,
) -> Result<DurableMeta, RetentionError> {
    let found = load_meta_optional_read(transaction, inner)?
        .ok_or(RetentionError::MissingRetentionState)?;
    found.validate(inner.wallet, inner.source)?;
    if &found != expected {
        return Err(RetentionError::ConcurrentMutation);
    }
    Ok(found)
}

fn reload_meta_blocking(inner: &RetentionDatabase) -> Result<DurableMeta, RetentionError> {
    let transaction = inner.database.begin_read().map_database()?;
    let meta = load_meta_optional_read(&transaction, inner)?
        .ok_or(RetentionError::MissingRetentionState)?;
    meta.validate(inner.wallet, inner.source)?;
    drop(transaction);
    validate_database_shape(inner, &meta)?;
    validate_named_roots(inner, &meta)?;
    Ok(meta)
}

fn validate_database_shape(
    inner: &RetentionDatabase,
    meta: &DurableMeta,
) -> Result<(), RetentionError> {
    meta.validate(inner.wallet, inner.source)?;
    let transaction = inner.database.begin_read().map_database()?;
    let objects = transaction.open_table(OBJECT_TABLE).map_database()?;
    let pins = transaction.open_table(PIN_TABLE).map_database()?;
    let released_pins = transaction.open_table(RELEASED_PIN_TABLE).map_database()?;
    let export_pins = transaction.open_table(EXPORT_PIN_TABLE).map_database()?;
    let export_index = transaction.open_table(EXPORT_INDEX_TABLE).map_database()?;
    let export_reclaims = transaction.open_table(EXPORT_RECLAIM_TABLE).map_database()?;
    let unlink = transaction.open_table(UNLINK_TABLE).map_database()?;
    let delete = transaction.open_table(DELETE_TABLE).map_database()?;
    if objects.len().map_database()? != meta.object_count
        || pins.len().map_database()? != u64::from(meta.active_pin_count)
        || released_pins.len().map_database()? != u64::from(meta.released_pin_count)
        || export_pins.len().map_database()? != meta.export_pin_count
        || export_index.len().map_database()? != meta.export_pin_count
        || export_reclaims.len().map_database()? != meta.export_reclaim_count
        || unlink.len().map_database()? != meta.unlink_count
        || delete.len().map_database()? != meta.delete_count
    {
        return Err(RetentionError::InvalidDurableState);
    }
    let import_objects = transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?;
    let import_stack = transaction.open_table(IMPORT_STACK_TABLE).map_database()?;
    let import_visiting = transaction.open_table(IMPORT_VISITING_TABLE).map_database()?;
    let import_reached = transaction.open_table(IMPORT_REACHED_TABLE).map_database()?;
    let import_registered = transaction.open_table(IMPORT_REGISTERED_TABLE).map_database()?;
    let import_pending = transaction.open_table(IMPORT_PENDING_REF_TABLE).map_database()?;
    let import_object_count = import_objects.len().map_database()?;
    let registered_count = import_registered.len().map_database()?;
    match &meta.import {
        Some(import)
            if import_stack.len().map_database()? == import.stack_depth
                && import_visiting.len().map_database()? == import.visiting_count
                && import_reached.len().map_database()? == import.reached_count
                && registered_count == import.registered_count
                && import_pending.len().map_database()? == import.pending_reference_count
                && match import.phase {
                    ImportPhase::Staging | ImportPhase::Traversing => {
                        import_object_count == import.staged_objects && registered_count == 0
                    }
                    ImportPhase::Registering | ImportPhase::Publishing => import_object_count
                        .checked_add(registered_count)
                        .is_some_and(|count| count == import.staged_objects),
                    ImportPhase::Cleanup => {
                        import_object_count == 0
                            && import.stack_depth == 0
                            && import.visiting_count == 0
                            && import.pending_reference_count == 0
                    }
                } => {}
        None if import_objects.is_empty().map_database()?
            && import_stack.is_empty().map_database()?
            && import_visiting.is_empty().map_database()?
            && import_reached.is_empty().map_database()?
            && import_registered.is_empty().map_database()?
            && import_pending.is_empty().map_database()? => {}
        _ => return Err(RetentionError::InvalidDurableState),
    }
    let reauth_stack = transaction.open_table(REAUTH_STACK_TABLE).map_database()?;
    let reauth_visiting = transaction.open_table(REAUTH_VISITING_TABLE).map_database()?;
    let reauth_reached = transaction.open_table(REAUTH_REACHED_TABLE).map_database()?;
    let reauth_pending = transaction.open_table(REAUTH_PENDING_TABLE).map_database()?;
    let reauth_objects = transaction.open_table(REAUTH_OBJECT_TABLE).map_database()?;
    match &meta.reauthentication {
        Some(reauthentication)
            if reauth_stack.len().map_database()? == reauthentication.stack_depth
                && reauth_visiting.len().map_database()? == reauthentication.visiting_count
                && reauth_reached.len().map_database()? == reauthentication.reached_count
                && reauth_pending.len().map_database()? == reauthentication.pending_count
                && reauth_objects.len().map_database()? == reauthentication.verified_count => {}
        None if reauth_stack.is_empty().map_database()?
            && reauth_visiting.is_empty().map_database()?
            && reauth_reached.is_empty().map_database()?
            && reauth_pending.is_empty().map_database()?
            && reauth_objects.is_empty().map_database()? => {}
        _ => return Err(RetentionError::InvalidDurableState),
    }
    Ok(())
}

fn validate_named_roots(
    inner: &RetentionDatabase,
    meta: &DurableMeta,
) -> Result<(), RetentionError> {
    let transaction = inner.database.begin_read().map_database()?;
    if let Some(root) = meta.current_root {
        let record = load_object_required_read(&transaction, inner, root)?;
        if !record.node || record.references == 0 {
            return Err(RetentionError::InvalidPortableRoot);
        }
    }
    let pins = transaction.open_table(PIN_TABLE).map_database()?;
    let mut active = 0_u16;
    let mut iterator = pins.iter().map_database()?;
    while let Some(entry) = iterator.next() {
        let (lookup, bytes) = entry.map_database()?;
        let requester = decode_pin_lookup(lookup.value())?;
        let record: SourcePinRecord = decode_authenticated(
            &inner.mac_key,
            PIN_LABEL,
            lookup.value(),
            bytes.value(),
            MAX_SOURCE_PIN_RESPONSE_BYTES + 4096,
        )?;
        record.validate(inner.wallet, inner.source)?;
        if record.requester != requester {
            return Err(RetentionError::InvalidDurableState);
        }
        if load_object_required_read(&transaction, inner, record.root)?.references == 0 {
            return Err(RetentionError::InvalidDurableState);
        }
        active = active.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    if active != meta.active_pin_count {
        return Err(RetentionError::InvalidDurableState);
    }
    drop(iterator);
    drop(pins);
    let released_pins = transaction.open_table(RELEASED_PIN_TABLE).map_database()?;
    let mut released = 0_u16;
    let mut iterator = released_pins.iter().map_database()?;
    while let Some(entry) = iterator.next() {
        let (lookup, bytes) = entry.map_database()?;
        let (family, requester) = decode_released_pin_lookup(lookup.value())?;
        let record: ReleasedSourcePinRecord = decode_authenticated(
            &inner.mac_key,
            RELEASED_PIN_LABEL,
            lookup.value(),
            bytes.value(),
            4096,
        )?;
        record.validate(inner.wallet, inner.source)?;
        if record.requester != requester
            || record.family != family
            || meta.authorized_requesters.binary_search(&requester).is_err()
            || load_pin_optional_read(&transaction, inner, requester)?
                .is_some_and(|active| active.family == family)
        {
            return Err(RetentionError::InvalidDurableState);
        }
        released = released.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    if released != meta.released_pin_count {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn validate_root_in_transaction(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &DurableMeta,
    root: Option<DepositIndexObjectId>,
) -> Result<(), RetentionError> {
    if meta.current_root != root {
        return Err(RetentionError::CurrentRootConflict);
    }
    if let Some(root) = root {
        let record = load_object_required(transaction, inner, root)?;
        if !record.node || record.references == 0 {
            return Err(RetentionError::InvalidPortableRoot);
        }
    }
    Ok(())
}

fn load_object_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<Option<ObjectRecord>, RetentionError> {
    let table = transaction.open_table(OBJECT_TABLE).map_database()?;
    load_object_from_table(&table, inner, id)
}

fn load_object_optional_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<Option<ObjectRecord>, RetentionError> {
    let table = transaction.open_table(OBJECT_TABLE).map_database()?;
    load_object_from_table(&table, inner, id)
}

fn load_object_from_table<T>(
    table: &T,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<Option<ObjectRecord>, RetentionError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    authenticate_id(id, inner.wallet)?;
    let lookup = object_lookup(id)?;
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record = decode_authenticated(
        &inner.mac_key,
        OBJECT_LABEL,
        lookup.as_slice(),
        bytes.value(),
        MAX_OBJECT_RECORD_BYTES,
    )?;
    let record: ObjectRecord = record;
    record.validate(inner.wallet)?;
    if record.id != id {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(Some(record))
}

fn load_object_required(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<ObjectRecord, RetentionError> {
    load_object_optional(transaction, inner, id)?.ok_or(RetentionError::MissingGraphObject(id))
}

fn load_object_required_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<ObjectRecord, RetentionError> {
    load_object_optional_read(transaction, inner, id)?.ok_or(RetentionError::MissingGraphObject(id))
}

fn store_object(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    record: &ObjectRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet)?;
    let lookup = object_lookup(record.id)?;
    let encoded = encode_authenticated(
        &inner.mac_key,
        OBJECT_LABEL,
        lookup.as_slice(),
        record,
        MAX_OBJECT_RECORD_BYTES,
    )?;
    let mut table = transaction.open_table(OBJECT_TABLE).map_database()?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn load_import_object_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<Option<ObjectRecord>, RetentionError> {
    authenticate_id(id, inner.wallet)?;
    let lookup = object_lookup(id)?;
    let table = transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?;
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record: ObjectRecord = decode_authenticated(
        &inner.mac_key,
        IMPORT_OBJECT_LABEL,
        lookup.as_slice(),
        bytes.value(),
        MAX_OBJECT_RECORD_BYTES,
    )?;
    record.validate(inner.wallet)?;
    if record.id != id || record.references != 0 {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(Some(record))
}

fn store_import_object(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    record: &ObjectRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet)?;
    if record.references != 0 {
        return Err(RetentionError::InvalidDurableState);
    }
    let lookup = object_lookup(record.id)?;
    let encoded = encode_authenticated(
        &inner.mac_key,
        IMPORT_OBJECT_LABEL,
        lookup.as_slice(),
        record,
        MAX_OBJECT_RECORD_BYTES,
    )?;
    let mut table = transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn remove_import_object(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let record: ObjectRecord = decode_authenticated(
        &inner.mac_key,
        IMPORT_OBJECT_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_OBJECT_RECORD_BYTES,
    )?;
    record.validate(inner.wallet)?;
    if record.id != id || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn first_import_objects(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    limit: usize,
) -> Result<Vec<ObjectRecord>, RetentionError> {
    let table = transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?;
    let mut records = Vec::with_capacity(limit);
    let mut iterator = table.iter().map_database()?;
    while records.len() < limit {
        let Some(entry) = iterator.next() else {
            break;
        };
        let (lookup, bytes) = entry.map_database()?;
        let record: ObjectRecord = decode_authenticated(
            &inner.mac_key,
            IMPORT_OBJECT_LABEL,
            lookup.value(),
            bytes.value(),
            MAX_OBJECT_RECORD_BYTES,
        )?;
        record.validate(inner.wallet)?;
        if record.references != 0 || object_lookup(record.id)?.as_slice() != lookup.value() {
            return Err(RetentionError::InvalidDurableState);
        }
        records.push(record);
    }
    Ok(records)
}

fn dfs_stack_lookup(depth: u64) -> [u8; 8] {
    depth.to_be_bytes()
}

fn load_dfs_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    depth: u64,
) -> Result<DfsFrameRecord, RetentionError> {
    let lookup = dfs_stack_lookup(depth);
    let table = transaction.open_table(IMPORT_STACK_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let frame: DfsFrameRecord = decode_authenticated(
        &inner.mac_key,
        IMPORT_STACK_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    frame.validate(inner.wallet, depth)?;
    Ok(frame)
}

fn insert_dfs_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    frame: &DfsFrameRecord,
) -> Result<(), RetentionError> {
    store_dfs_frame(transaction, inner, frame, false)
}

fn store_dfs_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    frame: &DfsFrameRecord,
    replace: bool,
) -> Result<(), RetentionError> {
    frame.validate(inner.wallet, frame.depth)?;
    let lookup = dfs_stack_lookup(frame.depth);
    let mut table = transaction.open_table(IMPORT_STACK_TABLE).map_database()?;
    let existing = table.get(lookup.as_slice()).map_database()?.map(|bytes| bytes.value().to_vec());
    match (replace, existing) {
        (false, None) => {}
        (true, Some(bytes)) => {
            let previous: DfsFrameRecord = decode_authenticated(
                &inner.mac_key,
                IMPORT_STACK_LABEL,
                lookup.as_slice(),
                &bytes,
                MAX_QUEUE_RECORD_BYTES,
            )?;
            previous.validate(inner.wallet, frame.depth)?;
            if previous.id != frame.id
                || previous.next_child.checked_add(1) != Some(frame.next_child)
            {
                return Err(RetentionError::InvalidDurableState);
            }
        }
        _ => return Err(RetentionError::InvalidDurableState),
    }
    let encoded = encode_authenticated(
        &inner.mac_key,
        IMPORT_STACK_LABEL,
        lookup.as_slice(),
        frame,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn remove_dfs_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    expected: &DfsFrameRecord,
) -> Result<(), RetentionError> {
    expected.validate(inner.wallet, expected.depth)?;
    let lookup = dfs_stack_lookup(expected.depth);
    let mut table = transaction.open_table(IMPORT_STACK_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let found: DfsFrameRecord = decode_authenticated(
        &inner.mac_key,
        IMPORT_STACK_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    found.validate(inner.wallet, expected.depth)?;
    if &found != expected || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn load_reauthentication_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    depth: u64,
) -> Result<DfsFrameRecord, RetentionError> {
    let lookup = dfs_stack_lookup(depth);
    let table = transaction.open_table(REAUTH_STACK_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let frame: DfsFrameRecord = decode_authenticated(
        &inner.mac_key,
        REAUTH_STACK_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    frame.validate(inner.wallet, depth)?;
    Ok(frame)
}

fn insert_reauthentication_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    frame: &DfsFrameRecord,
) -> Result<(), RetentionError> {
    store_reauthentication_frame(transaction, inner, frame, false)
}

fn store_reauthentication_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    frame: &DfsFrameRecord,
    replace: bool,
) -> Result<(), RetentionError> {
    frame.validate(inner.wallet, frame.depth)?;
    let lookup = dfs_stack_lookup(frame.depth);
    let mut table = transaction.open_table(REAUTH_STACK_TABLE).map_database()?;
    let existing = table.get(lookup.as_slice()).map_database()?.map(|bytes| bytes.value().to_vec());
    match (replace, existing) {
        (false, None) => {}
        (true, Some(bytes)) => {
            let previous: DfsFrameRecord = decode_authenticated(
                &inner.mac_key,
                REAUTH_STACK_LABEL,
                lookup.as_slice(),
                &bytes,
                MAX_QUEUE_RECORD_BYTES,
            )?;
            previous.validate(inner.wallet, frame.depth)?;
            if previous.id != frame.id
                || previous.next_child.checked_add(1) != Some(frame.next_child)
            {
                return Err(RetentionError::InvalidDurableState);
            }
        }
        _ => return Err(RetentionError::InvalidDurableState),
    }
    let encoded = encode_authenticated(
        &inner.mac_key,
        REAUTH_STACK_LABEL,
        lookup.as_slice(),
        frame,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn remove_reauthentication_frame(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    expected: &DfsFrameRecord,
) -> Result<(), RetentionError> {
    expected.validate(inner.wallet, expected.depth)?;
    let lookup = dfs_stack_lookup(expected.depth);
    let mut table = transaction.open_table(REAUTH_STACK_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let found: DfsFrameRecord = decode_authenticated(
        &inner.mac_key,
        REAUTH_STACK_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    found.validate(inner.wallet, expected.depth)?;
    if &found != expected || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn store_reauthentication_object(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    record: &ReauthenticationObjectRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet)?;
    let lookup = object_lookup(record.id)?;
    let encoded = encode_authenticated(
        &inner.mac_key,
        REAUTH_OBJECT_LABEL,
        lookup.as_slice(),
        record,
        MAX_REAUTH_OBJECT_RECORD_BYTES,
    )?;
    let mut table = transaction.open_table(REAUTH_OBJECT_TABLE).map_database()?;
    if table.get(lookup.as_slice()).map_database()?.is_some() {
        return Err(RetentionError::InvalidDurableState);
    }
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn remove_reauthentication_object(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(REAUTH_OBJECT_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let record: ReauthenticationObjectRecord = decode_authenticated(
        &inner.mac_key,
        REAUTH_OBJECT_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_REAUTH_OBJECT_RECORD_BYTES,
    )?;
    record.validate(inner.wallet)?;
    if record.id != id || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn insert_temp_queue(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    id: DepositIndexObjectId,
) -> Result<bool, RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(definition).map_database()?;
    if let Some(bytes) = table.get(lookup.as_slice()).map_database()? {
        let record: QueueRecord = decode_authenticated(
            &inner.mac_key,
            label,
            lookup.as_slice(),
            bytes.value(),
            MAX_QUEUE_RECORD_BYTES,
        )?;
        record.validate(inner.wallet)?;
        if record.id != id {
            return Err(RetentionError::InvalidDurableState);
        }
        return Ok(false);
    }
    let record = QueueRecord::new(id);
    let encoded = encode_authenticated(
        &inner.mac_key,
        label,
        lookup.as_slice(),
        &record,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(true)
}

fn remove_temp_queue(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(definition).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let record: QueueRecord = decode_authenticated(
        &inner.mac_key,
        label,
        lookup.as_slice(),
        &bytes,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    record.validate(inner.wallet)?;
    if record.id != id || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn temp_queue_contains(
    transaction: &redb::WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    id: DepositIndexObjectId,
) -> Result<bool, RetentionError> {
    let lookup = object_lookup(id)?;
    let table = transaction.open_table(definition).map_database()?;
    Ok(table.get(lookup.as_slice()).map_database()?.is_some())
}

fn first_temp_queue_ids(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    limit: usize,
) -> Result<Vec<DepositIndexObjectId>, RetentionError> {
    let table = transaction.open_table(definition).map_database()?;
    let mut ids = Vec::with_capacity(limit);
    let mut iterator = table.iter().map_database()?;
    while ids.len() < limit {
        let Some(entry) = iterator.next() else {
            break;
        };
        let (lookup, bytes) = entry.map_database()?;
        let record: QueueRecord = decode_authenticated(
            &inner.mac_key,
            label,
            lookup.value(),
            bytes.value(),
            MAX_QUEUE_RECORD_BYTES,
        )?;
        record.validate(inner.wallet)?;
        if object_lookup(record.id)?.as_slice() != lookup.value() {
            return Err(RetentionError::InvalidDurableState);
        }
        ids.push(record.id);
    }
    Ok(ids)
}

fn add_pending_reference(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    import: &mut DurableImport,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(IMPORT_PENDING_REF_TABLE).map_database()?;
    let mut record = match table.get(lookup.as_slice()).map_database()? {
        Some(bytes) => {
            let record: PendingReferenceRecord = decode_authenticated(
                &inner.mac_key,
                IMPORT_PENDING_REF_LABEL,
                lookup.as_slice(),
                bytes.value(),
                MAX_QUEUE_RECORD_BYTES,
            )?;
            if record.version != RETENTION_VERSION || record.id != id || record.references == 0 {
                return Err(RetentionError::InvalidDurableState);
            }
            record
        }
        None => {
            import.pending_reference_count = import
                .pending_reference_count
                .checked_add(1)
                .ok_or(RetentionError::CountOverflow)?;
            PendingReferenceRecord { version: RETENTION_VERSION, id, references: 0 }
        }
    };
    record.references = record.references.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    let encoded = encode_authenticated(
        &inner.mac_key,
        IMPORT_PENDING_REF_LABEL,
        lookup.as_slice(),
        &record,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn take_pending_references(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    import: &mut DurableImport,
    id: DepositIndexObjectId,
) -> Result<u64, RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(IMPORT_PENDING_REF_TABLE).map_database()?;
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(0);
    };
    let encoded = bytes.value().to_vec();
    drop(bytes);
    let record: PendingReferenceRecord = decode_authenticated(
        &inner.mac_key,
        IMPORT_PENDING_REF_LABEL,
        lookup.as_slice(),
        &encoded,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    if record.version != RETENTION_VERSION || record.id != id || record.references == 0 {
        return Err(RetentionError::InvalidDurableState);
    }
    if table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    import.pending_reference_count =
        import.pending_reference_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    Ok(record.references)
}

fn import_tables_nonempty(transaction: &redb::WriteTransaction) -> Result<bool, RetentionError> {
    Ok(!transaction.open_table(IMPORT_OBJECT_TABLE).map_database()?.is_empty().map_database()?
        || !transaction.open_table(IMPORT_STACK_TABLE).map_database()?.is_empty().map_database()?
        || !transaction
            .open_table(IMPORT_VISITING_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(IMPORT_REACHED_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(IMPORT_REGISTERED_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(IMPORT_PENDING_REF_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?)
}

fn reauthentication_tables_nonempty(
    transaction: &redb::WriteTransaction,
) -> Result<bool, RetentionError> {
    Ok(!transaction.open_table(REAUTH_STACK_TABLE).map_database()?.is_empty().map_database()?
        || !transaction
            .open_table(REAUTH_VISITING_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(REAUTH_REACHED_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(REAUTH_PENDING_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?
        || !transaction
            .open_table(REAUTH_OBJECT_TABLE)
            .map_database()?
            .is_empty()
            .map_database()?)
}

fn add_reference(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let mut record = load_object_required(transaction, inner, id)?;
    let was_zero = record.references == 0;
    record.references = record.references.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    if was_zero {
        cancel_unlink_if_present(transaction, inner, meta, id)?;
        cancel_delete_if_present(transaction, inner, meta, id)?;
    }
    store_object(transaction, inner, &record)
}

fn remove_reference(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let mut record = load_object_required(transaction, inner, id)?;
    record.references =
        record.references.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    store_object(transaction, inner, &record)?;
    if record.references == 0 {
        insert_queue(transaction, inner, meta, UNLINK_TABLE, UNLINK_LABEL, id)?;
    }
    Ok(())
}

fn load_pin_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    requester: PartyId,
) -> Result<Option<SourcePinRecord>, RetentionError> {
    let table = transaction.open_table(PIN_TABLE).map_database()?;
    load_pin_from_table(&table, inner, requester)
}

fn load_pin_optional_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    requester: PartyId,
) -> Result<Option<SourcePinRecord>, RetentionError> {
    let table = transaction.open_table(PIN_TABLE).map_database()?;
    load_pin_from_table(&table, inner, requester)
}

fn load_pin_from_table<T>(
    table: &T,
    inner: &RetentionDatabase,
    requester: PartyId,
) -> Result<Option<SourcePinRecord>, RetentionError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    if requester == PartyId(0) {
        return Err(RetentionError::SourcePinBinding);
    }
    let lookup = pin_lookup(requester);
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record: SourcePinRecord = decode_authenticated(
        &inner.mac_key,
        PIN_LABEL,
        lookup.as_slice(),
        bytes.value(),
        MAX_SOURCE_PIN_RESPONSE_BYTES + 4096,
    )?;
    record.validate(inner.wallet, inner.source)?;
    if record.requester != requester {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(Some(record))
}

fn store_pin(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    lookup: &[u8],
    record: &SourcePinRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet, inner.source)?;
    let encoded = encode_authenticated(
        &inner.mac_key,
        PIN_LABEL,
        lookup,
        record,
        MAX_SOURCE_PIN_RESPONSE_BYTES + 4096,
    )?;
    let mut table = transaction.open_table(PIN_TABLE).map_database()?;
    table.insert(lookup, encoded.as_slice()).map_database()?;
    Ok(())
}

fn remove_pin(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    expected: &SourcePinRecord,
) -> Result<(), RetentionError> {
    expected.validate(inner.wallet, inner.source)?;
    let lookup = pin_lookup(expected.requester);
    let mut table = transaction.open_table(PIN_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let found: SourcePinRecord = decode_authenticated(
        &inner.mac_key,
        PIN_LABEL,
        lookup.as_slice(),
        &bytes,
        MAX_SOURCE_PIN_RESPONSE_BYTES + 4096,
    )?;
    found.validate(inner.wallet, inner.source)?;
    if &found != expected || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn load_released_pin_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    family: SourcePinFamily,
    requester: PartyId,
) -> Result<Option<ReleasedSourcePinRecord>, RetentionError> {
    let table = transaction.open_table(RELEASED_PIN_TABLE).map_database()?;
    load_released_pin_from_table(&table, inner, family, requester)
}

fn load_released_pin_from_table<T>(
    table: &T,
    inner: &RetentionDatabase,
    family: SourcePinFamily,
    requester: PartyId,
) -> Result<Option<ReleasedSourcePinRecord>, RetentionError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    if requester == PartyId(0) {
        return Err(RetentionError::SourcePinBinding);
    }
    let lookup = released_pin_lookup(family, requester);
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record: ReleasedSourcePinRecord = decode_authenticated(
        &inner.mac_key,
        RELEASED_PIN_LABEL,
        lookup.as_slice(),
        bytes.value(),
        4096,
    )?;
    record.validate(inner.wallet, inner.source)?;
    if record.requester != requester || record.family != family {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(Some(record))
}

fn store_released_pin(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    record: &ReleasedSourcePinRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet, inner.source)?;
    let lookup = released_pin_lookup(record.family, record.requester);
    let encoded =
        encode_authenticated(&inner.mac_key, RELEASED_PIN_LABEL, lookup.as_slice(), record, 4096)?;
    let mut table = transaction.open_table(RELEASED_PIN_TABLE).map_database()?;
    if table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?.is_some() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn remove_released_pin(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    expected: &ReleasedSourcePinRecord,
) -> Result<(), RetentionError> {
    expected.validate(inner.wallet, inner.source)?;
    let lookup = released_pin_lookup(expected.family, expected.requester);
    let mut table = transaction.open_table(RELEASED_PIN_TABLE).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let found: ReleasedSourcePinRecord =
        decode_authenticated(&inner.mac_key, RELEASED_PIN_LABEL, lookup.as_slice(), &bytes, 4096)?;
    found.validate(inner.wallet, inner.source)?;
    if &found != expected || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn load_export_pin_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    exact_lookup: [u8; 32],
) -> Result<Option<ExportPinRecord>, RetentionError> {
    let table = transaction.open_table(EXPORT_PIN_TABLE).map_database()?;
    load_export_pin_from_table(&table, inner, exact_lookup)
}

fn load_export_pin_optional_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    exact_lookup: [u8; 32],
) -> Result<Option<ExportPinRecord>, RetentionError> {
    let table = transaction.open_table(EXPORT_PIN_TABLE).map_database()?;
    load_export_pin_from_table(&table, inner, exact_lookup)
}

fn load_export_pin_from_table<T>(
    table: &T,
    inner: &RetentionDatabase,
    exact_lookup: [u8; 32],
) -> Result<Option<ExportPinRecord>, RetentionError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    if exact_lookup == [0; 32] {
        return Err(RetentionError::InvalidDurableState);
    }
    let Some(bytes) = table.get(exact_lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record: ExportPinRecord = decode_authenticated(
        &inner.mac_key,
        EXPORT_PIN_LABEL,
        exact_lookup.as_slice(),
        bytes.value(),
        MAX_EXPORT_RECORD_BYTES,
    )?;
    record.validate(inner.wallet, inner.source)?;
    if export_exact_lookup(&record)? != exact_lookup {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(Some(record))
}

fn load_export_pin_required(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    exact_lookup: [u8; 32],
) -> Result<ExportPinRecord, RetentionError> {
    load_export_pin_optional(transaction, inner, exact_lookup)?
        .ok_or(RetentionError::InvalidDurableState)
}

fn load_export_pin_required_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    exact_lookup: [u8; 32],
) -> Result<ExportPinRecord, RetentionError> {
    load_export_pin_optional_read(transaction, inner, exact_lookup)?
        .ok_or(RetentionError::InvalidDurableState)
}

fn store_export_pin(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    exact_lookup: [u8; 32],
    record: &ExportPinRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet, inner.source)?;
    if exact_lookup == [0; 32] || export_exact_lookup(record)? != exact_lookup {
        return Err(RetentionError::InvalidDurableState);
    }
    let encoded = encode_authenticated(
        &inner.mac_key,
        EXPORT_PIN_LABEL,
        exact_lookup.as_slice(),
        record,
        MAX_EXPORT_RECORD_BYTES,
    )?;
    let mut table = transaction.open_table(EXPORT_PIN_TABLE).map_database()?;
    table.insert(exact_lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn load_export_index_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<ExportIndexRecord>, RetentionError> {
    let table = transaction.open_table(EXPORT_INDEX_TABLE).map_database()?;
    load_export_index_from_table(&table, inner, semantic_transition)
}

fn load_export_index_optional_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<ExportIndexRecord>, RetentionError> {
    let table = transaction.open_table(EXPORT_INDEX_TABLE).map_database()?;
    load_export_index_from_table(&table, inner, semantic_transition)
}

fn load_export_index_from_table<T>(
    table: &T,
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<ExportIndexRecord>, RetentionError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let lookup = export_index_lookup(semantic_transition, inner.source)?;
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record: ExportIndexRecord = decode_authenticated(
        &inner.mac_key,
        EXPORT_INDEX_LABEL,
        lookup.as_slice(),
        bytes.value(),
        MAX_EXPORT_RECORD_BYTES,
    )?;
    record.validate(inner.wallet, inner.source, semantic_transition)?;
    Ok(Some(record))
}

fn store_export_index(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    lookup: [u8; 34],
    record: &ExportIndexRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet, inner.source, record.semantic_transition)?;
    if export_index_lookup(record.semantic_transition, inner.source)? != lookup {
        return Err(RetentionError::InvalidDurableState);
    }
    let encoded = encode_authenticated(
        &inner.mac_key,
        EXPORT_INDEX_LABEL,
        lookup.as_slice(),
        record,
        MAX_EXPORT_RECORD_BYTES,
    )?;
    let mut table = transaction.open_table(EXPORT_INDEX_TABLE).map_database()?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn load_export_reclaim_optional(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<ExportReclaimRecord>, RetentionError> {
    let table = transaction.open_table(EXPORT_RECLAIM_TABLE).map_database()?;
    load_export_reclaim_from_table(&table, inner, semantic_transition)
}

fn load_export_reclaim_optional_read(
    transaction: &redb::ReadTransaction,
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<ExportReclaimRecord>, RetentionError> {
    let table = transaction.open_table(EXPORT_RECLAIM_TABLE).map_database()?;
    load_export_reclaim_from_table(&table, inner, semantic_transition)
}

fn load_export_reclaim_from_table<T>(
    table: &T,
    inner: &RetentionDatabase,
    semantic_transition: [u8; 32],
) -> Result<Option<ExportReclaimRecord>, RetentionError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let lookup = export_reclaim_lookup(semantic_transition)?;
    let Some(bytes) = table.get(lookup.as_slice()).map_database()? else {
        return Ok(None);
    };
    let record: ExportReclaimRecord = decode_authenticated(
        &inner.mac_key,
        EXPORT_RECLAIM_LABEL,
        lookup.as_slice(),
        bytes.value(),
        MAX_EXPORT_RECORD_BYTES,
    )?;
    record.validate(inner.wallet, semantic_transition)?;
    Ok(Some(record))
}

fn store_export_reclaim(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    record: &ExportReclaimRecord,
) -> Result<(), RetentionError> {
    record.validate(inner.wallet, record.semantic_transition)?;
    let lookup = export_reclaim_lookup(record.semantic_transition)?;
    let encoded = encode_authenticated(
        &inner.mac_key,
        EXPORT_RECLAIM_LABEL,
        lookup.as_slice(),
        record,
        MAX_EXPORT_RECORD_BYTES,
    )?;
    let mut table = transaction.open_table(EXPORT_RECLAIM_TABLE).map_database()?;
    if table.get(lookup.as_slice()).map_database()?.is_some() {
        return Err(RetentionError::InvalidDurableState);
    }
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    Ok(())
}

fn insert_queue(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(definition).map_database()?;
    if let Some(bytes) = table.get(lookup.as_slice()).map_database()? {
        let record: QueueRecord = decode_authenticated(
            &inner.mac_key,
            label,
            lookup.as_slice(),
            bytes.value(),
            MAX_QUEUE_RECORD_BYTES,
        )?;
        record.validate(inner.wallet)?;
        if record.id != id {
            return Err(RetentionError::InvalidDurableState);
        }
        return Ok(());
    }
    let record = QueueRecord::new(id);
    let encoded = encode_authenticated(
        &inner.mac_key,
        label,
        lookup.as_slice(),
        &record,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    table.insert(lookup.as_slice(), encoded.as_slice()).map_database()?;
    if label == UNLINK_LABEL {
        meta.unlink_count =
            meta.unlink_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    } else {
        meta.delete_count =
            meta.delete_count.checked_add(1).ok_or(RetentionError::CountOverflow)?;
    }
    Ok(())
}

fn remove_queue(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let mut table = transaction.open_table(definition).map_database()?;
    let bytes = table
        .get(lookup.as_slice())
        .map_database()?
        .ok_or(RetentionError::InvalidDurableState)?
        .value()
        .to_vec();
    let record: QueueRecord = decode_authenticated(
        &inner.mac_key,
        label,
        lookup.as_slice(),
        &bytes,
        MAX_QUEUE_RECORD_BYTES,
    )?;
    record.validate(inner.wallet)?;
    if record.id != id || table.remove(lookup.as_slice()).map_database()?.is_none() {
        return Err(RetentionError::InvalidDurableState);
    }
    if label == UNLINK_LABEL {
        meta.unlink_count =
            meta.unlink_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    } else {
        meta.delete_count =
            meta.delete_count.checked_sub(1).ok_or(RetentionError::InvalidDurableState)?;
    }
    Ok(())
}

fn cancel_unlink_if_present(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    cancel_queue_if_present(transaction, inner, meta, UNLINK_TABLE, UNLINK_LABEL, id)
}

fn cancel_delete_if_present(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    cancel_queue_if_present(transaction, inner, meta, DELETE_TABLE, DELETE_LABEL, id)
}

fn cancel_queue_if_present(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    meta: &mut DurableMeta,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    id: DepositIndexObjectId,
) -> Result<(), RetentionError> {
    let lookup = object_lookup(id)?;
    let table = transaction.open_table(definition).map_database()?;
    let present = table.get(lookup.as_slice()).map_database()?.is_some();
    drop(table);
    if present {
        remove_queue(transaction, inner, meta, definition, label, id)?;
    }
    Ok(())
}

fn first_queue_ids(
    transaction: &redb::WriteTransaction,
    inner: &RetentionDatabase,
    definition: TableDefinition<&[u8], &[u8]>,
    label: &[u8],
    limit: usize,
) -> Result<Vec<DepositIndexObjectId>, RetentionError> {
    let table = transaction.open_table(definition).map_database()?;
    let mut ids = Vec::with_capacity(limit);
    let mut iterator = table.iter().map_database()?;
    while ids.len() < limit {
        let Some(entry) = iterator.next() else {
            break;
        };
        let (lookup, bytes) = entry.map_database()?;
        let record: QueueRecord = decode_authenticated(
            &inner.mac_key,
            label,
            lookup.value(),
            bytes.value(),
            MAX_QUEUE_RECORD_BYTES,
        )?;
        record.validate(inner.wallet)?;
        if object_lookup(record.id)?.as_slice() != lookup.value() {
            return Err(RetentionError::InvalidDurableState);
        }
        ids.push(record.id);
    }
    Ok(ids)
}

fn public_pin(record: &SourcePinRecord) -> Result<StoredSourcePin, RetentionError> {
    record.validate(record.wallet, record.source)?;
    Ok(StoredSourcePin {
        wallet: record.wallet,
        source: record.source,
        requester: record.requester,
        context_digest: record.context_digest,
        lease_digest: record.lease_digest,
        root: record.root,
        response: record.response.clone(),
    })
}

fn public_export_pin(record: &ExportPinRecord) -> StoredExportPin {
    StoredExportPin {
        semantic_transition: record.semantic_transition,
        transition_binding: record.transition_binding,
        source: record.source,
        root: record.terminal_portable_root,
        advertisement_digest: record.advertisement_digest,
        advertisement: record.advertisement.clone(),
        seal_statement: record.seal_statement,
        seal_certificate_digest: record
            .seal_certificate
            .as_ref()
            .map(|certificate| certificate.digest),
        seal_certificate: record
            .seal_certificate
            .as_ref()
            .map(|certificate| certificate.bytes.clone()),
        export_binding: record.export_binding,
    }
}

fn validate_pin_request(
    wallet: DepositWalletId,
    source: PartyId,
    requester: PartyId,
    semantic_authority: [u8; 32],
    context_digest: [u8; 32],
    lease_digest: [u8; 32],
    root: DepositIndexObjectId,
    response: &[u8],
) -> Result<(), RetentionError> {
    authenticate_id(root, wallet)?;
    if source == PartyId(0)
        || requester == PartyId(0)
        || semantic_authority == [0_u8; 32]
        || context_digest == [0_u8; 32]
        || lease_digest == [0_u8; 32]
        || response.is_empty()
        || response.len() > MAX_SOURCE_PIN_RESPONSE_BYTES
    {
        return Err(RetentionError::SourcePinBinding);
    }
    Ok(())
}

fn validate_authorized_requesters(requesters: &[PartyId]) -> Result<(), RetentionError> {
    if requesters.is_empty()
        || requesters.len() > MAX_COMMITTEE_MEMBERS
        || requesters.iter().any(|requester| *requester == PartyId(0))
        || requesters.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn authenticate_id(
    id: DepositIndexObjectId,
    wallet: DepositWalletId,
) -> Result<(), RetentionError> {
    if id.wallet_id() != wallet
        || DepositIndexObjectId::from_storage_reference(id.storage_reference())? != id
    {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(())
}

fn object_lookup(id: DepositIndexObjectId) -> Result<Vec<u8>, RetentionError> {
    encode_canonical(&id, 256)
}

fn pin_lookup(requester: PartyId) -> [u8; 2] {
    requester.0.to_be_bytes()
}

fn released_pin_lookup(family: SourcePinFamily, requester: PartyId) -> [u8; 3] {
    let requester = requester.0.to_be_bytes();
    [family.lookup_tag(), requester[0], requester[1]]
}

fn export_exact_lookup(record: &ExportPinRecord) -> Result<[u8; 32], RetentionError> {
    let mut hasher = blake3::Hasher::new_derive_key(EXPORT_EXACT_LOOKUP_DOMAIN);
    hasher.update(&record.wallet.0);
    hasher.update(&record.source.0.to_be_bytes());
    hasher.update(&record.semantic_transition);
    hasher.update(&record.transition_binding);
    hasher.update(&record.vote_slot);
    hasher.update(&record.seal_statement);
    hasher.update(&record.export_binding);
    hasher.update(&record.advertisement_digest);
    hasher.update(&record.registry_checkpoint);
    hasher.update(&record.target_registry);
    hasher.update(&record.target_registry_archive);
    hasher.update(&record.target_registry_index_root);
    hasher.update(&record.target_registry_active_link);
    hasher.update(&record.target_registry_active_witness);
    hasher.update(&record.archive_event);
    hasher.update(&record.archive_segment);
    hasher.update(&record.terminal_portable_head);
    let root = object_lookup(record.terminal_portable_root)?;
    hasher.update(&(root.len() as u64).to_le_bytes());
    hasher.update(&root);
    Ok(*hasher.finalize().as_bytes())
}

fn export_index_lookup(
    semantic_transition: [u8; 32],
    source: PartyId,
) -> Result<[u8; 34], RetentionError> {
    if semantic_transition == [0; 32] || source == PartyId(0) {
        return Err(RetentionError::InvalidDurableState);
    }
    let mut lookup = [0_u8; 34];
    lookup[..32].copy_from_slice(&semantic_transition);
    lookup[32..].copy_from_slice(&source.0.to_be_bytes());
    Ok(lookup)
}

fn export_reclaim_lookup(semantic_transition: [u8; 32]) -> Result<[u8; 32], RetentionError> {
    if semantic_transition == [0; 32] {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(semantic_transition)
}

fn decode_pin_lookup(bytes: &[u8]) -> Result<PartyId, RetentionError> {
    let encoded: [u8; 2] = bytes.try_into().map_err(|_| RetentionError::InvalidDurableState)?;
    let requester = PartyId(u16::from_be_bytes(encoded));
    if requester == PartyId(0) {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok(requester)
}

fn decode_released_pin_lookup(bytes: &[u8]) -> Result<(SourcePinFamily, PartyId), RetentionError> {
    let encoded: [u8; 3] = bytes.try_into().map_err(|_| RetentionError::InvalidDurableState)?;
    let family = SourcePinFamily::from_lookup_tag(encoded[0])?;
    let requester = PartyId(u16::from_be_bytes([encoded[1], encoded[2]]));
    if requester == PartyId(0) {
        return Err(RetentionError::InvalidDurableState);
    }
    Ok((family, requester))
}

fn retention_path(artifacts: &WalletArtifactStore, wallet: DepositWalletId) -> PathBuf {
    artifacts.artifact_root().join(RETENTION_DIRECTORY).join(format!(
        "{}{}",
        hex::encode(wallet.0),
        RETENTION_FILE_SUFFIX
    ))
}

fn derive_wallet_mac_key(
    root_key: &[u8; 32],
    wallet: DepositWalletId,
    source: PartyId,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(root_key);
    hasher.update(RETENTION_MAC_KEY_DOMAIN.as_bytes());
    hasher.update(&wallet.0);
    hasher.update(&source.0.to_le_bytes());
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn encode_authenticated<T: Serialize>(
    key: &[u8; 32],
    label: &[u8],
    lookup: &[u8],
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, RetentionError> {
    let body = encode_canonical(value, maximum)?;
    let mac = record_mac(key, label, lookup, &body);
    encode_canonical(&AuthenticatedRecord { version: RETENTION_VERSION, body, mac }, maximum)
}

fn decode_authenticated<T: DeserializeOwned + Serialize>(
    key: &[u8; 32],
    label: &[u8],
    lookup: &[u8],
    bytes: &[u8],
    maximum: usize,
) -> Result<T, RetentionError> {
    let authenticated: AuthenticatedRecord = decode_canonical(bytes, maximum)?;
    if authenticated.version != RETENTION_VERSION {
        return Err(RetentionError::InvalidDurableState);
    }
    let expected = record_mac(key, label, lookup, &authenticated.body);
    if !bool::from(expected.ct_eq(&authenticated.mac)) {
        return Err(RetentionError::StorageAuthentication);
    }
    decode_canonical(&authenticated.body, maximum)
}

fn record_mac(key: &[u8; 32], label: &[u8], lookup: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(RECORD_MAC_DOMAIN.as_bytes());
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(lookup.len() as u64).to_le_bytes());
    hasher.update(lookup);
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

fn encode_canonical<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, RetentionError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| RetentionError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RetentionError::StorageValueTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, RetentionError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RetentionError::StorageValueTooLarge);
    }
    let (value, trailing) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| RetentionError::Serialization)?;
    if !trailing.is_empty() || encode_canonical(&value, maximum)? != bytes {
        return Err(RetentionError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn configure_write(transaction: &mut redb::WriteTransaction) {
    transaction.set_two_phase_commit(true);
    transaction.set_quick_repair(true);
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

trait DatabaseResultExt<T> {
    fn map_database(self) -> Result<T, RetentionError>;
}

impl<T, E: fmt::Display> DatabaseResultExt<T> for Result<T, E> {
    fn map_database(self) -> Result<T, RetentionError> {
        self.map_err(|error| RetentionError::Database(error.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum RetentionError {
    #[error("portable deposit-index object rejected retention: {0}")]
    Index(#[from] DepositIndexError),
    #[error("verified deposit-state export rejected retention: {0}")]
    StateExport(#[from] DepositStateExportError),
    #[error("verified deposit-state import rejected retention: {0}")]
    StateImport(#[from] DepositStateImportError),
    #[error("wallet storage rejected portable retention: {0}")]
    Storage(#[from] StoreError),
    #[error("verified committee rejected source retention: {0}")]
    Committee(#[from] crate::committee::CommitteeError),
    #[error("deposit-index retention database failed: {0}")]
    Database(String),
    #[error("deposit-index retention blocking task failed: {0}")]
    BlockingTask(String),
    #[error("deposit-index retention serialization failed")]
    Serialization,
    #[error("deposit-index retention encoding was non-canonical")]
    NonCanonicalEncoding,
    #[error("deposit-index retention value exceeded its fixed bound")]
    StorageValueTooLarge,
    #[error("deposit-index retention record authentication failed")]
    StorageAuthentication,
    #[error("deposit-index retention file or directory conflicts with a regular private database")]
    StorageConflict,
    #[error("portable checkpoint is nonempty but its retention database is absent")]
    MissingRetentionState,
    #[error("deposit-index retention durable state is malformed or incomplete")]
    InvalidDurableState,
    #[error("deposit-index retention current root conflicts with wallet-snapshot authority")]
    CurrentRootConflict,
    #[error("deposit-index retention state changed through another writer")]
    ConcurrentMutation,
    #[error("deposit-index retention revision counter is exhausted")]
    RevisionExhausted,
    #[error("deposit-index retention count is exhausted")]
    CountOverflow,
    #[error("portable retention graph exceeded its fixed update bound")]
    GraphBoundExceeded,
    #[error("portable retention import exceeded its authenticated object or plaintext quota")]
    ImportQuota,
    #[error("portable retention import batch exceeded its fixed object or plaintext bound")]
    ImportBatchBound,
    #[error("another portable retention import is already active")]
    ImportConflict,
    #[error("portable retention import is already sealed")]
    ImportAlreadySealed,
    #[error("portable retention import has not been started")]
    NoImport,
    #[error("portable retention import has not been sealed")]
    ImportNotSealed,
    #[error("portable retention import is in progress")]
    ImportInProgress,
    #[error("permanent portable-root reauthentication is already active for another head")]
    ReauthenticationConflict,
    #[error("permanent portable-root reauthentication has not been started")]
    NoReauthentication,
    #[error("permanent portable-root reauthentication binding is malformed")]
    InvalidReauthenticationBinding,
    #[error("the named current/export root disappeared during reauthentication")]
    ReauthenticationAnchorLost,
    #[error("permanent portable-root reauthentication exceeded its exact object quota")]
    ReauthenticationQuota,
    #[error("permanent portable-root reauthentication is in progress")]
    ReauthenticationInProgress,
    #[error("portable retention update contains duplicate objects")]
    DuplicateObject,
    #[error("portable retention update contains an unreachable staged object")]
    UnreachableStagedObject,
    #[error("portable retention graph contains a cycle")]
    GraphCycle,
    #[error("portable retention graph is missing object {0:?}")]
    MissingGraphObject(DepositIndexObjectId),
    #[error("portable retention object conflicts with its existing authenticated child edges")]
    ObjectConflict,
    #[error("portable retention root is not an authenticated portable HAMT node")]
    InvalidPortableRoot,
    #[error("source lease binding is malformed")]
    SourcePinBinding,
    #[error("source or requester is not in the authenticated active committee")]
    InactiveSourceOrRequester,
    #[error("source-pin committee authorization would roll back")]
    AuthorizationRollback,
    #[error("source-pin committee authorization conflicts at the same epoch")]
    AuthorizationConflict,
    #[error("source-pin committee handoff must be applied before admitting the newer epoch")]
    AuthorizationHandoffRequired,
    #[error("source requester already has a conflicting active lease")]
    SourcePinConflict,
    #[error("source advertisement has not advanced since this requester released it")]
    SourcePinNotAdvanced,
    #[error("source requester lease quota is full")]
    SourcePinQuota,
    #[error("verified export pin binding is malformed or belongs to another local source")]
    InvalidExportPinBinding,
    #[error("verified state-imported reclaim authority is malformed")]
    InvalidExportReclaimAuthority,
    #[error("the local source already pinned a different exact export for this transition")]
    ExportPinConflict,
    #[error("the exact export candidate was not durably pinned before certification")]
    ExportCandidateNotPinned,
    #[error("the target already certified this semantic transition as imported")]
    ExportAlreadyImported,
    #[error("the exact export reclaim tombstone is absent")]
    ExportReclaimTombstoneMissing,
    #[error("the target import certificate conflicts with the durable transition tombstone")]
    ExportReclaimConflict,
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        deposit_index::DEPOSIT_INDEX_ARTIFACT_KIND,
        storage::{WalletArtifactRef, WalletId},
    };

    const SOURCE: PartyId = PartyId(1);
    const SEED: [u8; 32] = [0x91; 32];

    fn wallet() -> DepositWalletId {
        DepositWalletId([0x92; 32])
    }

    fn synthetic_id(value: u64) -> DepositIndexObjectId {
        let bytes = value.to_le_bytes();
        DepositIndexObjectId::from_storage_reference(
            WalletArtifactRef::for_contents(
                WalletId(wallet().0),
                DEPOSIT_INDEX_ARTIFACT_KIND,
                &bytes,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn synthetic_record(
        id: DepositIndexObjectId,
        children: Vec<DepositIndexObjectId>,
    ) -> ObjectRecord {
        let record = ObjectRecord {
            version: OBJECT_RECORD_VERSION,
            id,
            node: true,
            children,
            references: 0,
        };
        record.validate(wallet()).unwrap();
        record
    }

    fn tagged(seed: u8, tag: u8) -> [u8; 32] {
        let value = seed.wrapping_add(tag);
        [if value == 0 { 1 } else { value }; 32]
    }

    fn synthetic_export_record(root: DepositIndexObjectId, seed: u8) -> ExportPinRecord {
        let record = ExportPinRecord {
            version: EXPORT_PIN_VERSION,
            wallet: wallet(),
            source: SOURCE,
            network: tagged(seed, 1),
            semantic_transition: tagged(seed, 2),
            transition_binding: tagged(seed, 3),
            source_registry: tagged(seed, 4),
            vote_slot: tagged(seed, 5),
            handoff_statement: tagged(seed, 6),
            handoff_certificate: tagged(seed, 7),
            export_context: tagged(seed, 8),
            target_epoch: u64::from(seed) + 1,
            target_committee: tagged(seed, 9),
            target_activation: tagged(seed, 10),
            target_certified_activation_root: tagged(seed, 11),
            advertisement_digest: tagged(seed, 12),
            advertisement: SYNTHETIC_EXPORT_ADVERTISEMENT.to_vec(),
            registry_checkpoint: tagged(seed, 13),
            target_registry: tagged(seed, 14),
            target_registry_archive: tagged(seed, 15),
            target_registry_index_root: tagged(seed, 16),
            target_registry_active_link: tagged(seed, 17),
            target_registry_active_witness: tagged(seed, 18),
            archive_event: tagged(seed, 19),
            archive_segment: tagged(seed, 20),
            terminal_checkpoint_sequence: u64::from(seed) + 1,
            terminal_checkpoint_decision: tagged(seed, 21),
            terminal_checkpoint_certificate: tagged(seed, 22),
            terminal_portable_root: root,
            terminal_portable_head: tagged(seed, 23),
            source_party: SOURCE,
            seal_statement: tagged(seed, 24),
            seal_certificate: None,
            export_binding: tagged(seed, 25),
        };
        record.validate(wallet(), SOURCE).unwrap();
        record
    }

    fn synthetic_reclaim_authority(
        record: &ExportPinRecord,
        certificate_seed: u8,
    ) -> ExportReclaimAuthority {
        let authority = ExportReclaimAuthority {
            wallet: record.wallet,
            network: record.network,
            semantic_transition: record.semantic_transition,
            transition_binding: record.transition_binding,
            handoff_statement: record.handoff_statement,
            export_context: record.export_context,
            target_registry: record.target_registry,
            target_epoch: record.target_epoch,
            target_committee: record.target_committee,
            target_activation: record.target_activation,
            target_certified_activation_root: record.target_certified_activation_root,
            terminal_checkpoint_sequence: record.terminal_checkpoint_sequence,
            terminal_checkpoint_decision: record.terminal_checkpoint_decision,
            terminal_portable_root: record.terminal_portable_root,
            terminal_portable_head: record.terminal_portable_head,
            certificate: tagged(certificate_seed, 31),
        };
        authority.validate(wallet()).unwrap();
        authority
    }

    fn acquire_synthetic_export(
        retention: &mut DepositIndexRetentionStore,
        record: ExportPinRecord,
    ) -> Result<ExportPinAcquire, RetentionError> {
        let (meta, result) =
            acquire_export_pin_blocking(&retention.inner, &retention.meta, record)?;
        retention.meta = meta;
        Ok(result)
    }

    fn certify_synthetic_export(
        retention: &mut DepositIndexRetentionStore,
        candidate: &ExportPinRecord,
    ) -> StoredExportPin {
        let exact_lookup = export_exact_lookup(candidate).unwrap();
        let mut transaction = retention.inner.database.begin_write().unwrap();
        configure_write(&mut transaction);
        let mut meta =
            authenticate_expected_meta(&transaction, &retention.inner, &retention.meta).unwrap();
        let index = load_export_index_optional(
            &transaction,
            &retention.inner,
            candidate.semantic_transition,
        )
        .unwrap()
        .unwrap();
        assert_eq!(index.exact_lookup, exact_lookup);
        let mut record =
            load_export_pin_required(&transaction, &retention.inner, exact_lookup).unwrap();
        assert_eq!(&record, candidate);
        record.seal_certificate = Some(ExportSealCertificateRecord {
            digest: [0x7d; 32],
            bytes: SYNTHETIC_EXPORT_SEAL_CERTIFICATE.to_vec(),
        });
        store_export_pin(&transaction, &retention.inner, exact_lookup, &record).unwrap();
        meta.bump_revision().unwrap();
        store_meta(&transaction, &retention.inner, &meta).unwrap();
        transaction.commit().unwrap();
        retention.meta = meta;
        public_export_pin(&record)
    }

    fn reclaim_synthetic_export(
        retention: &mut DepositIndexRetentionStore,
        authority: ExportReclaimAuthority,
    ) -> Result<ExportPinReclaim, RetentionError> {
        let (meta, result) =
            reclaim_export_pins_blocking(&retention.inner, &retention.meta, authority)?;
        retention.meta = meta;
        Ok(result)
    }

    fn require_synthetic_export_reclaim_tombstone(
        retention: &DepositIndexRetentionStore,
        authority: &ExportReclaimAuthority,
    ) -> Result<(), RetentionError> {
        require_export_reclaim_tombstone_blocking(&retention.inner, authority)
    }

    fn lookup_synthetic_export(
        retention: &DepositIndexRetentionStore,
        expected: &ExportPinRecord,
    ) -> Result<Option<StoredExportPin>, RetentionError> {
        let transaction = retention.inner.database.begin_read().map_database()?;
        let Some(index) = load_export_index_optional_read(
            &transaction,
            &retention.inner,
            expected.semantic_transition,
        )?
        else {
            return Ok(None);
        };
        let found =
            load_export_pin_required_read(&transaction, &retention.inner, index.exact_lookup)?;
        if &found != expected {
            return Err(RetentionError::ExportPinConflict);
        }
        Ok(Some(public_export_pin(&found)))
    }

    fn target(epoch: u64, parties: &[u16]) -> VerifiedRegistryHandoffTarget {
        let committee = Committee {
            epoch,
            threshold: 1,
            members: parties
                .iter()
                .map(|party| Member {
                    id: PartyId(*party),
                    signing_key: [u8::try_from(*party).unwrap(); 32],
                    encryption_key: [u8::try_from(*party + 32).unwrap(); 32],
                })
                .collect(),
        };
        VerifiedRegistryHandoffTarget::for_test(
            committee,
            0,
            [u8::try_from(epoch + 1).unwrap(); 32],
            [u8::try_from(epoch + 11).unwrap(); 32],
            wallet(),
            [0x93; 32],
            [0x94; 32],
        )
        .unwrap()
    }

    fn ordinary_authority(marker: u8) -> SourcePinSemanticAuthority {
        SourcePinSemanticAuthority::ordinary([marker; 32])
    }

    fn stage_synthetic_batch(retention: &mut DepositIndexRetentionStore, records: &[ObjectRecord]) {
        let inner = Arc::clone(&retention.inner);
        let mut transaction = inner.database.begin_write().unwrap();
        configure_write(&mut transaction);
        let mut meta = authenticate_expected_meta(&transaction, &inner, &retention.meta).unwrap();
        let mut import = meta.import.clone().unwrap();
        assert_eq!(import.phase, ImportPhase::Staging);
        for record in records {
            assert!(load_object_optional(&transaction, &inner, record.id).unwrap().is_none());
            if load_import_object_optional(&transaction, &inner, record.id).unwrap().is_some() {
                continue;
            }
            store_import_object(&transaction, &inner, record).unwrap();
            import.staged_objects += 1;
            import.staged_plaintext_bytes += record.id.plaintext_len();
        }
        import.validate(inner.wallet).unwrap();
        meta.import = Some(import);
        meta.bump_revision().unwrap();
        store_meta(&transaction, &inner, &meta).unwrap();
        transaction.commit().unwrap();
        retention.meta = meta;
    }

    fn advance_synthetic_import(
        retention: &mut DepositIndexRetentionStore,
        limit: usize,
    ) -> Result<ImportProgress, RetentionError> {
        let meta = advance_import_blocking(&retention.inner, &retention.meta, limit)?;
        retention.meta = meta;
        Ok(if retention.meta.import.is_none() {
            ImportProgress::Complete
        } else {
            ImportProgress::InProgress
        })
    }

    async fn install_synthetic_graph(
        retention: &mut DepositIndexRetentionStore,
        binding: [u8; 32],
        records: &[ObjectRecord],
    ) {
        let target = records.first().unwrap().id;
        assert_eq!(
            retention
                .begin_import(binding, target, records.len() as u64, records.len() as u64 * 8)
                .await
                .unwrap(),
            ImportProgress::Staging
        );
        for batch in records.chunks(RETENTION_IMPORT_BATCH_OBJECTS) {
            stage_synthetic_batch(retention, batch);
        }
        retention.seal_import().await.unwrap();
        while retention.advance_import().await.unwrap() != ImportProgress::Complete {}
        assert_eq!(retention.current_root(), Some(target));
    }

    #[tokio::test]
    async fn missing_database_with_nonempty_checkpoint_fails_closed() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        assert!(matches!(
            DepositIndexRetentionStore::open(
                &artifacts,
                wallet(),
                SOURCE,
                Some(synthetic_id(1)),
                false,
            )
            .await,
            Err(RetentionError::MissingRetentionState)
        ));
    }

    #[tokio::test]
    async fn batched_import_exceeds_ordinary_update_bound_and_resumes_mid_traversal() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let count = MAX_DEPOSIT_INDEX_UPDATE_OBJECTS + 1;
        let ids = (0..count).map(|index| synthetic_id(index as u64 + 1)).collect::<Vec<_>>();
        let records = ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                synthetic_record(*id, ids.get(index + 1).copied().into_iter().collect::<Vec<_>>())
            })
            .collect::<Vec<_>>();
        let binding = [0x95; 32];
        assert_eq!(
            retention.begin_import(binding, ids[0], count as u64, count as u64 * 8).await.unwrap(),
            ImportProgress::Staging
        );
        for batch in records.chunks(RETENTION_IMPORT_BATCH_OBJECTS) {
            stage_synthetic_batch(&mut retention, batch);
        }
        retention.seal_import().await.unwrap();
        for _ in 0..17 {
            assert_eq!(retention.advance_import().await.unwrap(), ImportProgress::InProgress);
        }
        drop(retention);

        let (mut restarted, progress) = DepositIndexRetentionStore::open_for_import(
            &artifacts,
            wallet(),
            SOURCE,
            binding,
            ids[0],
            count as u64,
            count as u64 * 8,
        )
        .await
        .unwrap();
        assert_eq!(progress, ImportProgress::InProgress);
        while restarted.advance_import().await.unwrap() != ImportProgress::Complete {}
        assert_eq!(restarted.current_root(), Some(ids[0]));
        assert_eq!(restarted.counts(), (count as u64, 0, 0, 0));
    }

    #[tokio::test]
    async fn batched_import_rejects_cycle_split_across_batches_after_restart() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let first = synthetic_id(0xc1);
        let second = synthetic_id(0xc2);
        let binding = [0xc3; 32];
        retention.begin_import(binding, first, 2, 16).await.unwrap();
        stage_synthetic_batch(&mut retention, &[synthetic_record(first, vec![second])]);
        stage_synthetic_batch(&mut retention, &[synthetic_record(second, vec![first])]);
        retention.seal_import().await.unwrap();

        assert_eq!(
            advance_synthetic_import(&mut retention, 1).unwrap(),
            ImportProgress::InProgress
        );
        assert_eq!(retention.meta.import.as_ref().unwrap().stack_depth, 2);
        drop(retention);

        let (mut restarted, progress) = DepositIndexRetentionStore::open_for_import(
            &artifacts,
            wallet(),
            SOURCE,
            binding,
            first,
            2,
            16,
        )
        .await
        .unwrap();
        assert_eq!(progress, ImportProgress::InProgress);
        assert!(matches!(
            advance_synthetic_import(&mut restarted, 1),
            Err(RetentionError::GraphCycle)
        ));
        drop(restarted);

        let (mut restarted_again, progress) = DepositIndexRetentionStore::open_for_import(
            &artifacts,
            wallet(),
            SOURCE,
            binding,
            first,
            2,
            16,
        )
        .await
        .unwrap();
        assert_eq!(progress, ImportProgress::InProgress);
        assert!(matches!(
            advance_synthetic_import(&mut restarted_again, 1),
            Err(RetentionError::GraphCycle)
        ));
    }

    #[tokio::test]
    async fn marker_import_open_is_exact_and_ordinary_open_never_bypasses_root_mismatch() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        drop(
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap(),
        );
        let target = synthetic_id(0xd1);
        let binding = [0xd2; 32];
        let (import, progress) = DepositIndexRetentionStore::open_for_import(
            &artifacts,
            wallet(),
            SOURCE,
            binding,
            target,
            1,
            8,
        )
        .await
        .unwrap();
        assert_eq!(progress, ImportProgress::Staging);
        drop(import);

        assert!(matches!(
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(target), false,)
                .await,
            Err(RetentionError::CurrentRootConflict)
        ));
        assert!(matches!(
            DepositIndexRetentionStore::open_for_import(
                &artifacts,
                wallet(),
                SOURCE,
                [0xd3; 32],
                target,
                1,
                8,
            )
            .await,
            Err(RetentionError::ImportConflict)
        ));
        let (_exact, progress) = DepositIndexRetentionStore::open_for_import(
            &artifacts,
            wallet(),
            SOURCE,
            binding,
            target,
            1,
            8,
        )
        .await
        .unwrap();
        assert_eq!(progress, ImportProgress::Staging);
    }

    #[tokio::test]
    async fn pinned_old_root_replays_after_advance_restart_and_live_release_stays_coherent() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        for value in [1_u64, 2, 3] {
            artifacts
                .create_artifact(
                    WalletId(wallet().0),
                    DEPOSIT_INDEX_ARTIFACT_KIND,
                    &value.to_le_bytes(),
                    &mut OsRng,
                )
                .await
                .unwrap();
        }
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let first = synthetic_record(synthetic_id(1), Vec::new());
        install_synthetic_graph(&mut retention, [0xa1; 32], std::slice::from_ref(&first)).await;
        let active = target(0, &[1, 2, 3]);
        let stored = retention
            .acquire_source_pin(
                &active,
                ordinary_authority(0xa1),
                PartyId(2),
                [0xa2; 32],
                [0xa3; 32],
                first.id,
                b"canonical head S".to_vec(),
            )
            .await
            .unwrap();
        assert!(matches!(stored, SourcePinAcquire::Stored(_)));

        let second = synthetic_record(synthetic_id(2), Vec::new());
        install_synthetic_graph(&mut retention, [0xa4; 32], std::slice::from_ref(&second)).await;
        drop(retention);
        let mut restarted =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(second.id), false)
                .await
                .unwrap();
        let replayed =
            restarted.source_pin_for_head(SOURCE, PartyId(2), [0xa2; 32]).await.unwrap().unwrap();
        assert_eq!(replayed.root(), first.id);
        assert_eq!(replayed.response(), b"canonical head S");
        assert_eq!(
            restarted.release_source_pin(SOURCE, PartyId(2), [0xa2; 32], [0xa3; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        restarted.drain_gc(&artifacts).await.unwrap();
        assert!(!artifacts.artifact_path(first.id.storage_reference()).exists());

        let third = synthetic_record(synthetic_id(3), Vec::new());
        install_synthetic_graph(&mut restarted, [0xa5; 32], std::slice::from_ref(&third)).await;
        assert!(matches!(
            restarted
                .acquire_source_pin(
                    &active,
                    ordinary_authority(0xa5),
                    PartyId(2),
                    [0xa2; 32],
                    [0xa6; 32],
                    third.id,
                    b"canonical head S+2".to_vec(),
                )
                .await
                .unwrap(),
            SourcePinAcquire::Stored(_)
        ));
    }

    #[tokio::test]
    async fn released_floor_makes_exact_head_and_release_replays_write_free_across_restart() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        artifacts
            .create_artifact(
                WalletId(wallet().0),
                DEPOSIT_INDEX_ARTIFACT_KIND,
                &17_u64.to_le_bytes(),
                &mut OsRng,
            )
            .await
            .unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let root = synthetic_record(synthetic_id(17), Vec::new());
        install_synthetic_graph(&mut retention, [0x31; 32], std::slice::from_ref(&root)).await;
        let active = target(0, &[1, 2, 3]);
        retention
            .acquire_source_pin(
                &active,
                ordinary_authority(0x31),
                PartyId(2),
                [0x32; 32],
                [0x33; 32],
                root.id,
                b"deterministic head A".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x32; 32], [0x33; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        assert_eq!(retention.released_pin_count(), 1);
        let released_revision = retention.meta.revision;
        let released_counts = retention.counts();
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x32; 32], [0x33; 32]).await.unwrap(),
            SourcePinRelease::AlreadyReleased
        );
        assert_eq!(retention.meta.revision, released_revision);
        assert_eq!(retention.counts(), released_counts);

        drop(retention);
        let mut restarted =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(root.id), false)
                .await
                .unwrap();
        assert_eq!(restarted.released_pin_count(), 1);
        let restarted_revision = restarted.meta.revision;
        assert!(matches!(
            restarted
                .acquire_source_pin(
                    &active,
                    ordinary_authority(0x31),
                    PartyId(2),
                    [0x32; 32],
                    [0x33; 32],
                    root.id,
                    b"deterministic head A".to_vec(),
                )
                .await,
            Err(RetentionError::SourcePinNotAdvanced)
        ));
        assert_eq!(restarted.meta.revision, restarted_revision);
        assert_eq!(restarted.released_pin_count(), 1);

        assert!(matches!(
            restarted
                .acquire_source_pin(
                    &active,
                    ordinary_authority(0x34),
                    PartyId(2),
                    [0x32; 32],
                    [0x34; 32],
                    root.id,
                    b"advanced head B".to_vec(),
                )
                .await
                .unwrap(),
            SourcePinAcquire::Stored(_)
        ));
        assert_eq!(restarted.released_pin_count(), 0);
        assert!(matches!(
            restarted.release_source_pin(SOURCE, PartyId(2), [0x32; 32], [0x33; 32]).await,
            Err(RetentionError::SourcePinBinding)
        ));
        assert!(
            restarted
                .active_source_pin(SOURCE, PartyId(2), [0x32; 32], [0x34; 32])
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn semantic_floors_ignore_nonce_churn_and_remain_independent_across_families() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let root = synthetic_record(synthetic_id(0x41), Vec::new());
        install_synthetic_graph(&mut retention, [0x40; 32], std::slice::from_ref(&root)).await;
        let active = target(0, &[1, 2, 3]);
        let ordinary_a = ordinary_authority(0x41);

        retention
            .acquire_source_pin(
                &active,
                ordinary_a,
                PartyId(2),
                [0x42; 32],
                [0x43; 32],
                root.id,
                b"ordinary A".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x42; 32], [0x43; 32]).await.unwrap(),
            SourcePinRelease::Released
        );

        let candidate = synthetic_export_record(root.id, 0x44);
        acquire_synthetic_export(&mut retention, candidate.clone()).unwrap();
        let certified = certify_synthetic_export(&mut retention, &candidate);
        retention
            .acquire_certified_export_head_pin(
                &active,
                PartyId(2),
                [0x45; 32],
                [0x46; 32],
                &certified,
                b"export A".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(retention.released_pin_count(), 1);
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x45; 32], [0x46; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        assert_eq!(retention.released_pin_count(), 2);

        let stable_revision = retention.meta.revision;
        assert!(matches!(
            retention
                .acquire_certified_export_head_pin(
                    &active,
                    PartyId(2),
                    [0x45; 32],
                    [0x47; 32],
                    &certified,
                    b"same export, different request nonce".to_vec(),
                )
                .await,
            Err(RetentionError::SourcePinNotAdvanced)
        ));
        assert!(matches!(
            retention
                .acquire_source_pin(
                    &active,
                    ordinary_a,
                    PartyId(2),
                    [0x42; 32],
                    [0x48; 32],
                    root.id,
                    b"same ordinary advertisement, different lease".to_vec(),
                )
                .await,
            Err(RetentionError::SourcePinNotAdvanced)
        ));
        assert_eq!(retention.meta.revision, stable_revision);
        assert_eq!(retention.released_pin_count(), 2);

        let ordinary_b = ordinary_authority(0x49);
        retention
            .acquire_source_pin(
                &active,
                ordinary_b,
                PartyId(2),
                [0x42; 32],
                [0x4a; 32],
                root.id,
                b"advanced ordinary advertisement".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(
            retention.released_pin_count(),
            1,
            "advancing ordinary authority must preserve the certified-export floor",
        );
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x42; 32], [0x4a; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        assert_eq!(retention.released_pin_count(), 2);

        let newer_floor_revision = retention.meta.revision;
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x42; 32], [0x43; 32]).await.unwrap(),
            SourcePinRelease::AlreadyReleased
        );
        assert_eq!(retention.meta.revision, newer_floor_revision);
        assert_eq!(retention.released_pin_count(), 2);
        assert!(matches!(
            retention
                .acquire_source_pin(
                    &active,
                    ordinary_b,
                    PartyId(2),
                    [0x42; 32],
                    [0x4b; 32],
                    root.id,
                    b"newer floor must survive stale release".to_vec(),
                )
                .await,
            Err(RetentionError::SourcePinNotAdvanced)
        ));

        drop(retention);
        let restarted =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(root.id), false)
                .await
                .unwrap();
        assert_eq!(restarted.released_pin_count(), 2);
    }

    #[tokio::test]
    async fn ambiguous_release_commit_reloads_the_authenticated_durable_cursor() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let root = synthetic_record(synthetic_id(0x4c), Vec::new());
        install_synthetic_graph(&mut retention, [0x4d; 32], std::slice::from_ref(&root)).await;
        let active = target(0, &[1, 2, 3]);
        let authority = ordinary_authority(0x4e);
        retention
            .acquire_source_pin(
                &active,
                authority,
                PartyId(2),
                [0x4f; 32],
                [0x50; 32],
                root.id,
                b"ambiguous release".to_vec(),
            )
            .await
            .unwrap();

        let stale_revision = retention.meta.revision;
        let (_committed_meta, disposition) = release_pin_blocking(
            &retention.inner,
            &retention.meta,
            SOURCE,
            PartyId(2),
            [0x4f; 32],
            [0x50; 32],
        )
        .unwrap();
        assert_eq!(disposition, SourcePinRelease::Released);
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x4f; 32], [0x50; 32]).await.unwrap(),
            SourcePinRelease::AlreadyReleased
        );
        assert!(retention.meta.revision > stale_revision);
        assert_eq!(retention.released_pin_count(), 1);
        assert!(matches!(
            retention
                .acquire_source_pin(
                    &active,
                    authority,
                    PartyId(2),
                    [0x4f; 32],
                    [0x51; 32],
                    root.id,
                    b"same authority after recovered commit".to_vec(),
                )
                .await,
            Err(RetentionError::SourcePinNotAdvanced)
        ));
    }

    #[tokio::test]
    async fn export_candidate_pin_and_target_reclaim_are_restart_idempotent() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let root = synthetic_record(synthetic_id(0xe1), Vec::new());
        install_synthetic_graph(&mut retention, [0xe2; 32], std::slice::from_ref(&root)).await;
        let record = synthetic_export_record(root.id, 0x31);
        let authority = synthetic_reclaim_authority(&record, 0x41);

        let missing_revision = retention.meta.revision;
        assert!(matches!(
            require_synthetic_export_reclaim_tombstone(&retention, &authority),
            Err(RetentionError::ExportReclaimTombstoneMissing)
        ));
        assert_eq!(retention.meta.revision, missing_revision);
        assert_eq!(retention.export_counts(), (0, 0));

        assert!(matches!(
            acquire_synthetic_export(&mut retention, record.clone()).unwrap(),
            ExportPinAcquire::Stored(_)
        ));
        assert!(matches!(
            acquire_synthetic_export(&mut retention, record.clone()).unwrap(),
            ExportPinAcquire::Existing(_)
        ));
        let mut conflicting = record.clone();
        conflicting.seal_statement = [0x77; 32];
        assert!(matches!(
            acquire_synthetic_export(&mut retention, conflicting),
            Err(RetentionError::ExportPinConflict)
        ));
        assert_eq!(retention.export_counts(), (1, 0));
        let pinned_revision = retention.meta.revision;
        assert!(matches!(
            require_synthetic_export_reclaim_tombstone(&retention, &authority),
            Err(RetentionError::ExportReclaimTombstoneMissing)
        ));
        assert_eq!(retention.meta.revision, pinned_revision);
        assert_eq!(retention.export_counts(), (1, 0));

        drop(retention);
        let mut restarted =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(root.id), false)
                .await
                .unwrap();
        let stored = lookup_synthetic_export(&restarted, &record).unwrap().unwrap();
        assert_eq!(stored.root(), root.id);
        assert_eq!(stored.advertisement_bytes(), SYNTHETIC_EXPORT_ADVERTISEMENT);
        assert_eq!(stored.seal_certificate_bytes(), None);

        assert_eq!(
            reclaim_synthetic_export(&mut restarted, authority.clone()).unwrap(),
            ExportPinReclaim::Reclaimed { variants: 1 }
        );
        assert_eq!(restarted.export_counts(), (0, 1));
        let reclaimed_revision = restarted.meta.revision;
        require_synthetic_export_reclaim_tombstone(&restarted, &authority).unwrap();
        assert_eq!(restarted.meta.revision, reclaimed_revision);
        assert_eq!(restarted.export_counts(), (0, 1));
        drop(restarted);

        let mut restarted_again =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(root.id), false)
                .await
                .unwrap();
        let alternate_valid_certificate = synthetic_reclaim_authority(&record, 0x42);
        let replay_revision = restarted_again.meta.revision;
        require_synthetic_export_reclaim_tombstone(&restarted_again, &alternate_valid_certificate)
            .unwrap();
        assert_eq!(restarted_again.meta.revision, replay_revision);
        assert_eq!(restarted_again.export_counts(), (0, 1));
        let mut conflicting_authority = alternate_valid_certificate.clone();
        conflicting_authority.target_activation[0] ^= 1;
        assert!(matches!(
            require_synthetic_export_reclaim_tombstone(&restarted_again, &conflicting_authority,),
            Err(RetentionError::ExportReclaimConflict)
        ));
        assert_eq!(restarted_again.meta.revision, replay_revision);
        assert_eq!(restarted_again.export_counts(), (0, 1));
        assert_eq!(
            reclaim_synthetic_export(&mut restarted_again, authority).unwrap(),
            ExportPinReclaim::AlreadyReclaimed
        );
        assert_eq!(
            reclaim_synthetic_export(&mut restarted_again, alternate_valid_certificate).unwrap(),
            ExportPinReclaim::AlreadyReclaimed
        );
        assert!(matches!(
            acquire_synthetic_export(&mut restarted_again, record),
            Err(RetentionError::ExportAlreadyImported)
        ));
        assert_eq!(restarted_again.export_counts(), (0, 1));
    }

    #[tokio::test]
    async fn preexisting_zero_variant_reclaim_tombstone_is_read_only_retry_authority() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let record = synthetic_export_record(synthetic_id(0xe3), 0x35);
        let authority = synthetic_reclaim_authority(&record, 0x43);

        // This models the current-transition reducer committing its certificate tombstone when
        // the exact source variant was already absent. Historical retry authority starts only
        // after that durable write; the read-only path below cannot manufacture it.
        assert_eq!(
            reclaim_synthetic_export(&mut retention, authority.clone()).unwrap(),
            ExportPinReclaim::AlreadyReclaimed
        );
        assert_eq!(retention.export_counts(), (0, 1));
        let committed_revision = retention.meta.revision;
        require_synthetic_export_reclaim_tombstone(&retention, &authority).unwrap();
        require_synthetic_export_reclaim_tombstone(&retention, &authority).unwrap();
        assert_eq!(retention.meta.revision, committed_revision);
        assert_eq!(retention.export_counts(), (0, 1));
        drop(retention);

        let restarted = DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
            .await
            .unwrap();
        let restart_revision = restarted.meta.revision;
        require_synthetic_export_reclaim_tombstone(&restarted, &authority).unwrap();
        assert_eq!(restarted.meta.revision, restart_revision);
        assert_eq!(restarted.export_counts(), (0, 1));
    }

    #[tokio::test]
    async fn certified_export_head_response_is_pinned_before_reply_and_survives_global_reclaim() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        for value in [0x61_u64, 0x62] {
            artifacts
                .create_artifact(
                    WalletId(wallet().0),
                    DEPOSIT_INDEX_ARTIFACT_KIND,
                    &value.to_le_bytes(),
                    &mut OsRng,
                )
                .await
                .unwrap();
        }
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let exported_root = synthetic_record(synthetic_id(0x61), Vec::new());
        install_synthetic_graph(&mut retention, [0x63; 32], std::slice::from_ref(&exported_root))
            .await;
        let candidate = synthetic_export_record(exported_root.id, 0x64);
        let candidate_pin =
            match acquire_synthetic_export(&mut retention, candidate.clone()).unwrap() {
                ExportPinAcquire::Stored(pin) => pin,
                ExportPinAcquire::Existing(_) => panic!("fresh candidate unexpectedly existed"),
            };
        // Ordinary pre-handoff reads have already installed the predecessor authorization.
        // A certified cold export must advance it before admitting a successor requester.
        retention.reclaim_after_handoff(&target(0, &[1, 2, 3])).await.unwrap();
        let active = target(1, &[1, 2, 3, 4]);
        assert!(matches!(
            retention
                .acquire_certified_export_head_pin(
                    &active,
                    PartyId(2),
                    [0x65; 32],
                    [0x66; 32],
                    &candidate_pin,
                    b"unsealed response must not escape".to_vec(),
                )
                .await,
            Err(RetentionError::ExportCandidateNotPinned)
        ));
        assert!(
            retention.source_pin_for_head(SOURCE, PartyId(2), [0x65; 32]).await.unwrap().is_none()
        );

        let certified = certify_synthetic_export(&mut retention, &candidate);
        let replacement = synthetic_record(synthetic_id(0x62), Vec::new());
        install_synthetic_graph(&mut retention, [0x67; 32], std::slice::from_ref(&replacement))
            .await;
        let response = b"canonical certified ExportHead response".to_vec();
        let acquired = retention
            .acquire_certified_export_head_pin(
                &active,
                PartyId(2),
                [0x65; 32],
                [0x66; 32],
                &certified,
                response.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(&acquired, SourcePinAcquire::Stored(_)));
        assert_eq!(acquired.pin().response(), response);
        assert_eq!(acquired.pin().root(), exported_root.id);
        drop(retention);

        let mut restarted = DepositIndexRetentionStore::open(
            &artifacts,
            wallet(),
            SOURCE,
            Some(replacement.id),
            false,
        )
        .await
        .unwrap();
        let certified_after_restart = restarted
            .certified_export_pin_for_transition(candidate.semantic_transition)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(certified_after_restart, certified);
        let retry = restarted
            .acquire_certified_export_head_pin(
                &active,
                PartyId(2),
                [0x65; 32],
                [0x66; 32],
                &certified_after_restart,
                response.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(&retry, SourcePinAcquire::Existing(_)));
        assert_eq!(retry.pin().response(), response);

        let authority = synthetic_reclaim_authority(&candidate, 0x68);
        assert_eq!(
            reclaim_synthetic_export(&mut restarted, authority).unwrap(),
            ExportPinReclaim::Reclaimed { variants: 1 }
        );
        restarted.drain_gc(&artifacts).await.unwrap();
        assert!(artifacts.artifact_path(exported_root.id.storage_reference()).exists());
        assert_eq!(
            restarted.release_source_pin(SOURCE, PartyId(2), [0x65; 32], [0x66; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        assert!(
            restarted
                .active_source_pin(SOURCE, PartyId(2), [0x65; 32], [0x66; 32])
                .await
                .unwrap()
                .is_none(),
            "an exact released export lease must immediately lose read authority"
        );
        restarted.drain_gc(&artifacts).await.unwrap();
        restarted.drain_gc(&artifacts).await.unwrap();
        assert!(!artifacts.artifact_path(exported_root.id.storage_reference()).exists());
        assert!(artifacts.artifact_path(replacement.id.storage_reference()).exists());
    }

    #[tokio::test]
    async fn requester_release_never_drops_the_independent_global_export_root() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        for value in [0xf1_u64, 0xf2] {
            artifacts
                .create_artifact(
                    WalletId(wallet().0),
                    DEPOSIT_INDEX_ARTIFACT_KIND,
                    &value.to_le_bytes(),
                    &mut OsRng,
                )
                .await
                .unwrap();
        }
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let old = synthetic_record(synthetic_id(0xf1), Vec::new());
        install_synthetic_graph(&mut retention, [0x51; 32], std::slice::from_ref(&old)).await;
        let active = target(0, &[1, 2, 3]);
        retention
            .acquire_source_pin(
                &active,
                ordinary_authority(0x51),
                PartyId(2),
                [0x52; 32],
                [0x53; 32],
                old.id,
                b"certified export head".to_vec(),
            )
            .await
            .unwrap();
        let export = synthetic_export_record(old.id, 0x54);
        acquire_synthetic_export(&mut retention, export.clone()).unwrap();

        let replacement = synthetic_record(synthetic_id(0xf2), Vec::new());
        install_synthetic_graph(&mut retention, [0x55; 32], std::slice::from_ref(&replacement))
            .await;
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0x52; 32], [0x53; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        retention.drain_gc(&artifacts).await.unwrap();
        assert!(artifacts.artifact_path(old.id.storage_reference()).exists());

        let authority = synthetic_reclaim_authority(&export, 0x56);
        assert_eq!(
            reclaim_synthetic_export(&mut retention, authority).unwrap(),
            ExportPinReclaim::Reclaimed { variants: 1 }
        );
        retention.drain_gc(&artifacts).await.unwrap();
        assert!(!artifacts.artifact_path(old.id.storage_reference()).exists());
        assert!(artifacts.artifact_path(replacement.id.storage_reference()).exists());
    }

    #[tokio::test]
    async fn export_pin_count_is_u64_and_not_bounded_by_committee_size() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let root = synthetic_record(synthetic_id(0xaa), Vec::new());
        install_synthetic_graph(&mut retention, [0xab; 32], std::slice::from_ref(&root)).await;
        let total = MAX_COMMITTEE_MEMBERS + 1;
        for index in 0..total {
            let mut record =
                synthetic_export_record(root.id, u8::try_from(index % 200 + 1).unwrap());
            let mut semantic =
                blake3::Hasher::new_derive_key("threshold-monero/retention-v4/test-semantic");
            semantic.update(&(index as u64).to_le_bytes());
            record.semantic_transition = *semantic.finalize().as_bytes();
            let mut transition =
                blake3::Hasher::new_derive_key("threshold-monero/retention-v4/test-transition");
            transition.update(&(index as u64).to_le_bytes());
            record.transition_binding = *transition.finalize().as_bytes();
            record.validate(wallet(), SOURCE).unwrap();
            assert!(matches!(
                acquire_synthetic_export(&mut retention, record).unwrap(),
                ExportPinAcquire::Stored(_)
            ));
        }
        assert_eq!(retention.export_counts(), (total as u64, 0));
        drop(retention);

        let restarted =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, Some(root.id), false)
                .await
                .unwrap();
        assert_eq!(restarted.export_counts(), (total as u64, 0));
    }

    #[tokio::test]
    async fn authenticated_handoff_retains_live_leases_and_prunes_only_departed_released_floors() {
        let directory = TempDir::new().unwrap();
        let artifacts = WalletArtifactStore::new(directory.path(), SOURCE, &SEED).unwrap();
        let mut retention =
            DepositIndexRetentionStore::open(&artifacts, wallet(), SOURCE, None, false)
                .await
                .unwrap();
        let root = synthetic_record(synthetic_id(7), Vec::new());
        install_synthetic_graph(&mut retention, [0xb1; 32], std::slice::from_ref(&root)).await;
        let initial = target(0, &[1, 2, 3]);
        for requester in [PartyId(2), PartyId(3)] {
            retention
                .acquire_source_pin(
                    &initial,
                    ordinary_authority(0xb1),
                    requester,
                    [0xb2; 32],
                    [u8::try_from(requester.0).unwrap(); 32],
                    root.id,
                    vec![u8::try_from(requester.0).unwrap()],
                )
                .await
                .unwrap();
        }
        let overlap = target(1, &[1, 2, 4]);
        assert_eq!(retention.reclaim_after_handoff(&overlap).await.unwrap(), 0);
        assert!(
            retention.source_pin_for_head(SOURCE, PartyId(2), [0xb2; 32]).await.unwrap().is_some()
        );
        assert!(
            retention.source_pin_for_head(SOURCE, PartyId(3), [0xb2; 32]).await.unwrap().is_some()
        );
        assert_eq!(
            retention.release_source_pin(SOURCE, PartyId(2), [0xb2; 32], [2; 32]).await.unwrap(),
            SourcePinRelease::Released
        );
        assert_eq!(retention.released_pin_count(), 1);
        assert!(matches!(
            retention
                .acquire_source_pin(
                    &overlap,
                    ordinary_authority(0xb3),
                    PartyId(4),
                    [0xb3; 32],
                    [4; 32],
                    root.id,
                    vec![4],
                )
                .await
                .unwrap(),
            SourcePinAcquire::Stored(_)
        ));
        assert_eq!(retention.counts().1, 2);

        // The next committee drops the requester whose exact released lease forms the replay
        // floor. That floor is no longer needed because this issuer can never authorize another
        // ordinary Head for requester 2. Live leases remain until their exact MAC-authenticated
        // Release arrives, even when their requester has departed.
        let source_removed = target(2, &[4, 5, 6]);
        assert_eq!(retention.reclaim_after_handoff(&source_removed).await.unwrap(), 1);
        assert_eq!(retention.released_pin_count(), 0);
        assert_eq!(retention.counts().1, 2);
        assert!(
            retention.source_pin_for_head(SOURCE, PartyId(3), [0xb2; 32]).await.unwrap().is_some()
        );
        for (requester, context) in [(PartyId(3), [0xb2; 32]), (PartyId(4), [0xb3; 32])] {
            assert_eq!(
                retention
                    .release_source_pin(
                        SOURCE,
                        requester,
                        context,
                        [u8::try_from(requester.0).unwrap(); 32],
                    )
                    .await
                    .unwrap(),
                SourcePinRelease::Released
            );
        }
        assert_eq!(retention.counts().1, 0);
        assert_eq!(
            retention.released_pin_count(),
            1,
            "only requester 4 remains authorized to create a released replay floor",
        );
    }
}
