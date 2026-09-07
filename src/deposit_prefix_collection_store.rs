//! Restart-safe requester-side collection of stable deposit-prefix endorsements.
//!
//! One encrypted wallet snapshot is used as a bounded reducer journal.  The synthetic wallet ID
//! binds the deployment/wallet context, the local requester, and this protocol domain, so the
//! snapshot cannot alias an application wallet.  Persisted bytes are never authority: every API
//! which can return a verified support certificate requires a freshly reconstructed
//! [`DepositPrefixCollectionAuthority`].

use std::{fmt, io, path::PathBuf, sync::Arc};

use rand_core::OsRng;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as DeError, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    committee::{CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId},
    deposit_index_checkpoint::VerifiedDepositIndexCheckpoint,
    deposit_sync_stage::{DepositSyncPrefixSupportWork, DepositSyncSpoolAdmission},
    deposit_sync_support::{
        DepositSyncPrefixSupportAttempt, DepositSyncPrefixSupportContinue,
        DepositSyncPrefixSupportProgress, DepositSyncPrefixSupportStart,
        DepositSyncSupportCertificate, DepositSyncSupportEndorsement, DepositSyncSupportError,
        DepositSyncSupportRequest, MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES,
        MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES, MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES,
        VerifiedDepositSyncSupportCertificate,
    },
    deposit_sync_wire::{
        DepositSyncContext, DepositSyncHeadRequest, DepositSyncHeadResponse,
        MAX_DEPOSIT_SYNC_WIRE_BYTES,
    },
    identity::Identity,
    key_rotation::VerifiedRegistryHandoffTarget,
    quic_transport::{DepositOperation, PeerRequest, QuicTransportError, RequestId},
    storage::{
        MAX_WALLET_SNAPSHOT_BYTES, StoreError, WalletId, WalletSnapshotMetadata,
        WalletSnapshotStore,
    },
};

const COLLECTION_VERSION: u16 = 1;
const COLLECTION_DOMAIN: [u8; 16] = *b"tm-prefix-coll01";
const COLLECTION_WALLET_ID_DOMAIN: &str =
    "threshold-monero/deposit-prefix-collection/synthetic-wallet/v1";
const COLLECTION_REQUEST_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-prefix-collection/request/v1";
const COLLECTION_HEAD_DIGEST_DOMAIN: &str = "threshold-monero/deposit-prefix-collection/head/v1";
const COLLECTION_BODY_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-prefix-collection/outbound-body/v1";
const MAX_COLLECTION_SNAPSHOT_BYTES: usize = 2 * MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES
    + MAX_DEPOSIT_SYNC_WIRE_BYTES
    + MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES
    + MAX_COMMITTEE_MEMBERS * (MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES + 256)
    + 64 * 1024;

const _: () = assert!(MAX_COLLECTION_SNAPSHOT_BYTES <= MAX_WALLET_SNAPSHOT_BYTES);

/// Live, non-serializable authority for one exact requester-side collection.
///
/// Construction rechecks the full terminal certificate capability, the stage-owned source head,
/// the current registry target, and both current local identity keys.  Durable state only stores
/// the resulting public binding and must be paired with this capability again after restart.
#[derive(Clone)]
pub struct DepositPrefixCollectionAuthority {
    context: DepositSyncContext,
    requester: PartyId,
    source: PartyId,
    attempt: DepositSyncPrefixSupportAttempt,
    binding: DurableAuthorityBinding,
    request: DepositSyncSupportRequest,
    request_bytes: Vec<u8>,
    head_bytes: Vec<u8>,
    active: VerifiedRegistryHandoffTarget,
}

impl fmt::Debug for DepositPrefixCollectionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositPrefixCollectionAuthority")
            .field("context_digest", &hex::encode(self.context.digest()))
            .field("requester", &self.requester)
            .field("source", &self.source)
            .field("attempt", &hex::encode(self.attempt.to_bytes()))
            .finish_non_exhaustive()
    }
}

impl DepositPrefixCollectionAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_context: DepositSyncContext,
        work: &DepositSyncPrefixSupportWork,
        request: DepositSyncSupportRequest,
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
    ) -> Result<Self, DepositPrefixCollectionStoreError> {
        authorize_local_identity(expected_context, active, local_identity)?;
        request.verify_terminal_capability(verified_terminal)?;
        request.statement().validate_against(active)?;
        if request.statement() != work.statement()
            || request.statement().context() != expected_context
            || request.statement().requester() != local_identity.party()
            || request.statement().source() == local_identity.party()
        {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }

        let requester = local_identity.party();
        let source = request.statement().source();
        let head_request = DepositSyncHeadRequest::new(expected_context, source, requester)?;
        let reconstructed =
            crate::deposit_sync_support::DepositSyncSupportStatement::from_head_response(
                head_request,
                work.response(),
                active,
            )?;
        if &reconstructed != work.statement() || &reconstructed != request.statement() {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }

        let request_bytes = request.to_bytes()?;
        let head_bytes = work.response().to_bytes(head_request)?;
        let attempt = DepositSyncPrefixSupportAttempt::for_request(&request)?;
        let binding = DurableAuthorityBinding::new(
            expected_context,
            requester,
            source,
            attempt,
            &request_bytes,
            request.statement().digest(),
            &head_bytes,
            verified_terminal,
            active,
            local_identity,
        )?;
        Ok(Self {
            context: expected_context,
            requester,
            source,
            attempt,
            binding,
            request,
            request_bytes,
            head_bytes,
            active: active.clone(),
        })
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
    pub const fn attempt(&self) -> DepositSyncPrefixSupportAttempt {
        self.attempt
    }

    #[must_use]
    pub const fn request(&self) -> &DepositSyncSupportRequest {
        &self.request
    }
}

/// One exact, already-journaled QUIC request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPrefixCollectionRequest {
    peer: PartyId,
    operation: DepositOperation,
    body: Vec<u8>,
    request_id: RequestId,
}

impl DepositPrefixCollectionRequest {
    #[must_use]
    pub const fn peer(&self) -> PartyId {
        self.peer
    }

    #[must_use]
    pub const fn operation(&self) -> DepositOperation {
        self.operation
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
}

/// Current durable collection state, re-authorized for this process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepositPrefixCollectionStatus {
    Collecting { attempt: DepositSyncPrefixSupportAttempt, endorsements: u16, required: u16 },
    Certified(VerifiedDepositSyncSupportCertificate),
    Admitted { attempt: DepositSyncPrefixSupportAttempt },
    Abandoned { attempt: DepositSyncPrefixSupportAttempt },
}

/// Encrypted, authenticated, single-collection requester journal.
pub struct DepositPrefixCollectionStore {
    snapshots: Arc<WalletSnapshotStore>,
    snapshot_id: WalletId,
    context: DepositSyncContext,
    local_party: PartyId,
    mutation: Mutex<()>,
}

impl fmt::Debug for DepositPrefixCollectionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DepositPrefixCollectionStore")
            .field("local_party", &self.local_party)
            .field("context_digest", &hex::encode(self.context.digest()))
            .finish_non_exhaustive()
    }
}

impl DepositPrefixCollectionStore {
    /// Open the clean-v7 snapshot namespace.  There are no migrations or legacy decoders.
    pub async fn open(
        directory: impl Into<PathBuf>,
        expected_context: DepositSyncContext,
        local_identity: &Identity,
        identity_seed: &[u8; 32],
    ) -> Result<Self, DepositPrefixCollectionStoreError> {
        let canonical =
            DepositSyncContext::new(expected_context.network(), expected_context.wallet())?;
        if canonical != expected_context
            || local_identity.party() == PartyId(0)
            || local_identity.signing_public_key() == [0; 32]
            || local_identity.encryption_public_key() == [0; 32]
            || identity_seed == &[0; 32]
        {
            return Err(DepositPrefixCollectionStoreError::InvalidIdentity);
        }
        let local_party = local_identity.party();
        let snapshot_id = collection_wallet_id(expected_context, local_party)?;
        let snapshots = WalletSnapshotStore::new(directory, local_party, identity_seed)?;
        let store = Self {
            snapshots: Arc::new(snapshots),
            snapshot_id,
            context: expected_context,
            local_party,
            mutation: Mutex::new(()),
        };
        let _guard = store.mutation.lock().await;
        if let Some(loaded) = store.load_optional().await? {
            loaded.snapshot.validate_static(store.context, store.local_party)?;
        }
        drop(_guard);
        Ok(store)
    }

    /// Recover the exact full request associated with `work`.
    ///
    /// This return value carries no authority.  The caller must independently verify its terminal
    /// checkpoint and reconstruct [`DepositPrefixCollectionAuthority`] before using it.
    pub async fn load_request_for_work(
        &self,
        work: &DepositSyncPrefixSupportWork,
        active: &VerifiedRegistryHandoffTarget,
        local_identity: &Identity,
    ) -> Result<Option<DepositSyncSupportRequest>, DepositPrefixCollectionStoreError> {
        authorize_local_identity(self.context, active, local_identity)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional().await? else {
            return Ok(None);
        };
        if let Some(collection) = loaded.snapshot.active.as_ref() {
            collection.validate_for_work(
                self.context,
                self.local_party,
                work,
                active,
                local_identity,
            )?;
            return Ok(Some(collection.request()?));
        }
        let Some(tombstone) = loaded.snapshot.tombstone.as_ref() else {
            return Ok(None);
        };
        tombstone.validate_for_work(
            self.context,
            self.local_party,
            work,
            active,
            local_identity,
        )?;
        Ok(Some(tombstone.request()?))
    }

    /// Install a fresh collection or resume the exact durable attempt.
    pub async fn begin_or_resume(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<DepositPrefixCollectionStatus, DepositPrefixCollectionStoreError> {
        self.ensure_authority(authority)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self.load_optional().await?;
        let mut snapshot = loaded
            .as_ref()
            .map(|loaded| loaded.snapshot.clone())
            .unwrap_or_else(|| DurableSnapshot::empty(self.context, self.local_party));

        if let Some(active) = snapshot.active.as_ref() {
            if active.binding == authority.binding {
                active.validate_with_authority(authority)?;
                return active.status(authority);
            }
            // `authority` can only be minted from the exact stage-owned work and an independently
            // verified terminal checkpoint.  It is therefore also the cleanup capability after
            // a crash in which the stage discarded, rejected, or promoted the previous attempt
            // before this requester journal recorded its tombstone.
            snapshot.tombstone = Some(active.abandoned_tombstone());
            snapshot.active = None;
        }
        if let Some(tombstone) = snapshot.tombstone.as_ref()
            && tombstone.binding == authority.binding
        {
            return Ok(tombstone.status());
        }

        let predecessors = snapshot
            .tombstone
            .as_ref()
            .map_or_else(Vec::new, |tombstone| tombstone.accepted.clone());
        snapshot.active = Some(DurableCollection::new(authority, &predecessors)?);
        self.persist(&mut loaded, &snapshot).await?;
        snapshot
            .active
            .as_ref()
            .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?
            .status(authority)
    }

    /// Return at most `limit` exact persisted request bodies in canonical party order.
    pub async fn pending_requests(
        &self,
        authority: &DepositPrefixCollectionAuthority,
        limit: usize,
    ) -> Result<Vec<DepositPrefixCollectionRequest>, DepositPrefixCollectionStoreError> {
        self.ensure_authority(authority)?;
        if limit == 0 || limit > MAX_COMMITTEE_MEMBERS {
            return Err(DepositPrefixCollectionStoreError::InvalidLimit);
        }
        let _guard = self.mutation.lock().await;
        let loaded = self
            .load_optional()
            .await?
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        let collection =
            loaded.snapshot.active.ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        collection.validate_with_authority(authority)?;
        collection.pending_requests(authority, limit)
    }

    /// Record one transport-authenticated peer's canonical response.
    ///
    /// `request_body` must be byte-for-byte equal to that peer's current journaled outbound
    /// request.  A stale response can therefore never roll the durable continuation cursor back.
    pub async fn record_progress(
        &self,
        authority: &DepositPrefixCollectionAuthority,
        peer: PartyId,
        operation: DepositOperation,
        request_body: &[u8],
        progress: &DepositSyncPrefixSupportProgress,
    ) -> Result<DepositPrefixCollectionStatus, DepositPrefixCollectionStoreError> {
        self.ensure_authority(authority)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional()
            .await?
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        let collection = loaded
            .snapshot
            .active
            .as_mut()
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        collection.validate_with_authority(authority)?;
        let changed =
            collection.record_progress(authority, peer, operation, request_body, progress)?;
        if changed {
            let snapshot = loaded.snapshot.clone();
            self.persist_existing(&mut loaded, &snapshot).await?;
        }
        loaded
            .snapshot
            .active
            .as_ref()
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?
            .status(authority)
    }

    /// Reconstruct a completed certificate only under current live authority.
    pub async fn certificate(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<Option<VerifiedDepositSyncSupportCertificate>, DepositPrefixCollectionStoreError>
    {
        self.ensure_authority(authority)?;
        let _guard = self.mutation.lock().await;
        let Some(loaded) = self.load_optional().await? else {
            return Ok(None);
        };
        let Some(collection) = loaded.snapshot.active.as_ref() else {
            return Ok(None);
        };
        collection.validate_with_authority(authority)?;
        Ok(collection.verified_certificate(authority)?)
    }

    /// Clear a completed collection only after the exact stage admission is visible.
    pub async fn mark_admitted_prefix(
        &self,
        authority: &DepositPrefixCollectionAuthority,
        admission: &DepositSyncSpoolAdmission,
    ) -> Result<DepositPrefixCollectionStatus, DepositPrefixCollectionStoreError> {
        self.ensure_authority(authority)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional()
            .await?
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        if let Some(tombstone) = loaded.snapshot.tombstone.as_ref()
            && tombstone.binding == authority.binding
        {
            let DurableTombstoneState::Admitted { certificate_digest } = tombstone.state else {
                return Err(DepositPrefixCollectionStoreError::WrongAdmission);
            };
            if !admission_matches(authority, admission, certificate_digest, None) {
                return Err(DepositPrefixCollectionStoreError::WrongAdmission);
            }
            return Ok(tombstone.status());
        }
        let collection = loaded
            .snapshot
            .active
            .as_ref()
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        collection.validate_with_authority(authority)?;
        let verified = collection
            .verified_certificate(authority)?
            .ok_or(DepositPrefixCollectionStoreError::CertificateIncomplete)?;
        if !admission_matches(
            authority,
            admission,
            verified.certificate_digest(),
            Some(verified.signers()),
        ) {
            return Err(DepositPrefixCollectionStoreError::WrongAdmission);
        }
        let tombstone = collection.admitted_tombstone(verified.certificate_digest());
        loaded.snapshot.active = None;
        loaded.snapshot.tombstone = Some(tombstone);
        let snapshot = loaded.snapshot.clone();
        self.persist_existing(&mut loaded, &snapshot).await?;
        Ok(loaded
            .snapshot
            .tombstone
            .as_ref()
            .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?
            .status())
    }

    /// Explicitly abandon only the exact active attempt.
    pub async fn abandon_exact(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<DepositPrefixCollectionStatus, DepositPrefixCollectionStoreError> {
        self.ensure_authority(authority)?;
        let _guard = self.mutation.lock().await;
        let mut loaded = self
            .load_optional()
            .await?
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        if let Some(tombstone) = loaded.snapshot.tombstone.as_ref()
            && tombstone.binding == authority.binding
        {
            return Ok(tombstone.status());
        }
        let collection = loaded
            .snapshot
            .active
            .as_ref()
            .ok_or(DepositPrefixCollectionStoreError::UnknownCollection)?;
        collection.validate_with_authority(authority)?;
        let tombstone = collection.abandoned_tombstone();
        loaded.snapshot.active = None;
        loaded.snapshot.tombstone = Some(tombstone);
        let snapshot = loaded.snapshot.clone();
        self.persist_existing(&mut loaded, &snapshot).await?;
        Ok(loaded
            .snapshot
            .tombstone
            .as_ref()
            .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?
            .status())
    }

    fn ensure_authority(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        if authority.context != self.context || authority.requester != self.local_party {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        authority.binding.validate_static(self.context, self.local_party)
    }

    async fn load_optional(
        &self,
    ) -> Result<Option<LoadedSnapshot>, DepositPrefixCollectionStoreError> {
        let path = self.snapshots.wallet_snapshot_path(self.snapshot_id);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(DepositPrefixCollectionStoreError::StorageConflict(path)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let loaded = self.snapshots.load_snapshot(self.snapshot_id).await?;
        let snapshot = decode_canonical::<DurableSnapshot>(
            loaded.state.as_bytes(),
            MAX_COLLECTION_SNAPSHOT_BYTES,
        )?;
        snapshot.validate_static(self.context, self.local_party)?;
        Ok(Some(LoadedSnapshot { metadata: loaded.metadata, snapshot }))
    }

    async fn persist(
        &self,
        loaded: &mut Option<LoadedSnapshot>,
        snapshot: &DurableSnapshot,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        snapshot.validate_static(self.context, self.local_party)?;
        let bytes = encode_canonical(snapshot, MAX_COLLECTION_SNAPSHOT_BYTES)?;
        let revision = match loaded.as_ref() {
            None => 0,
            Some(loaded) => loaded
                .metadata
                .revision
                .checked_add(1)
                .ok_or(DepositPrefixCollectionStoreError::RevisionExhausted)?,
        };
        let metadata =
            self.snapshots.save_snapshot(self.snapshot_id, revision, &bytes, &mut OsRng).await?;
        *loaded = Some(LoadedSnapshot { metadata, snapshot: snapshot.clone() });
        Ok(())
    }

    async fn persist_existing(
        &self,
        loaded: &mut LoadedSnapshot,
        snapshot: &DurableSnapshot,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        snapshot.validate_static(self.context, self.local_party)?;
        let bytes = encode_canonical(snapshot, MAX_COLLECTION_SNAPSHOT_BYTES)?;
        let revision = loaded
            .metadata
            .revision
            .checked_add(1)
            .ok_or(DepositPrefixCollectionStoreError::RevisionExhausted)?;
        let metadata =
            self.snapshots.save_snapshot(self.snapshot_id, revision, &bytes, &mut OsRng).await?;
        loaded.metadata = metadata;
        loaded.snapshot = snapshot.clone();
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct LoadedSnapshot {
    metadata: WalletSnapshotMetadata,
    snapshot: DurableSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableAuthorityBinding {
    context: DepositSyncContext,
    requester: PartyId,
    source: PartyId,
    attempt: DepositSyncPrefixSupportAttempt,
    request_digest: [u8; 32],
    statement_digest: [u8; 32],
    head_digest: [u8; 32],
    terminal_certificate_digest: [u8; 32],
    active_epoch: u64,
    active_committee: [u8; 32],
    active_fault_bound: u16,
    active_activation: [u8; 32],
    active_certified_activation_root: [u8; 32],
    active_key_id: [u8; 32],
    active_group_key: [u8; 32],
    identity_epoch: u64,
    identity_signing_key: [u8; 32],
    identity_encryption_key: [u8; 32],
}

impl DurableAuthorityBinding {
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: DepositSyncContext,
        requester: PartyId,
        source: PartyId,
        attempt: DepositSyncPrefixSupportAttempt,
        request_bytes: &[u8],
        statement_digest: [u8; 32],
        head_bytes: &[u8],
        verified_terminal: &VerifiedDepositIndexCheckpoint,
        active: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<Self, DepositPrefixCollectionStoreError> {
        let binding = Self {
            context,
            requester,
            source,
            attempt,
            request_digest: length_prefixed_hash(COLLECTION_REQUEST_DIGEST_DOMAIN, request_bytes),
            statement_digest,
            head_digest: length_prefixed_hash(COLLECTION_HEAD_DIGEST_DOMAIN, head_bytes),
            terminal_certificate_digest: verified_terminal.certificate_digest(),
            active_epoch: active.committee().epoch,
            active_committee: active.committee().digest(),
            active_fault_bound: active.fault_bound(),
            active_activation: active.activation(),
            active_certified_activation_root: active.certified_activation_root(),
            active_key_id: active.key_id(),
            active_group_key: active.group_key(),
            identity_epoch: identity.encryption_epoch(),
            identity_signing_key: identity.signing_public_key(),
            identity_encryption_key: identity.encryption_public_key(),
        };
        binding.validate_static(context, requester)?;
        Ok(binding)
    }

    fn validate_static(
        &self,
        expected_context: DepositSyncContext,
        expected_requester: PartyId,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        if self.context != expected_context
            || self.requester != expected_requester
            || self.requester == PartyId(0)
            || self.source == PartyId(0)
            || self.source == self.requester
            || self.attempt.to_bytes() == [0; 32]
            || self.request_digest == [0; 32]
            || self.statement_digest == [0; 32]
            || self.head_digest == [0; 32]
            || self.terminal_certificate_digest == [0; 32]
            || self.active_committee == [0; 32]
            || self.active_activation == [0; 32]
            || self.active_certified_activation_root == [0; 32]
            || self.active_key_id == [0; 32]
            || self.active_group_key == [0; 32]
            || self.identity_signing_key == [0; 32]
            || self.identity_encryption_key == [0; 32]
            || self.identity_epoch != self.active_epoch
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn validate_live(
        &self,
        active: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        authorize_local_identity(self.context, active, identity)?;
        if self.requester != identity.party()
            || self.active_epoch != active.committee().epoch
            || self.active_committee != active.committee().digest()
            || self.active_fault_bound != active.fault_bound()
            || self.active_activation != active.activation()
            || self.active_certified_activation_root != active.certified_activation_root()
            || self.active_key_id != active.key_id()
            || self.active_group_key != active.group_key()
            || self.identity_epoch != identity.encryption_epoch()
            || self.identity_signing_key != identity.signing_public_key()
            || self.identity_encryption_key != identity.encryption_public_key()
        {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableSnapshot {
    version: u16,
    domain: [u8; 16],
    context: DepositSyncContext,
    requester: PartyId,
    active: Option<DurableCollection>,
    tombstone: Option<DurableTombstone>,
}

impl DurableSnapshot {
    fn empty(context: DepositSyncContext, requester: PartyId) -> Self {
        Self {
            version: COLLECTION_VERSION,
            domain: COLLECTION_DOMAIN,
            context,
            requester,
            active: None,
            tombstone: None,
        }
    }

    fn validate_static(
        &self,
        context: DepositSyncContext,
        requester: PartyId,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        if self.version != COLLECTION_VERSION
            || self.domain != COLLECTION_DOMAIN
            || self.context != context
            || self.requester != requester
            || requester == PartyId(0)
            || self.active.is_none() && self.tombstone.is_none()
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        if let Some(active) = &self.active {
            active.validate_static(context, requester)?;
        }
        if let Some(tombstone) = &self.tombstone {
            tombstone.validate_static(context, requester)?;
        }
        if self.active.as_ref().is_some_and(|active| {
            self.tombstone.as_ref().is_some_and(|tombstone| tombstone.binding == active.binding)
        }) {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableCollection {
    binding: DurableAuthorityBinding,
    #[serde(deserialize_with = "deserialize_request_bytes")]
    request: Vec<u8>,
    #[serde(deserialize_with = "deserialize_head_bytes")]
    head: Vec<u8>,
    #[serde(deserialize_with = "deserialize_member_states")]
    members: Vec<DurableMemberState>,
    certificate: Option<DurableCertificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableMemberState {
    party: PartyId,
    accepted_attempt: Option<DepositSyncPrefixSupportAttempt>,
    outbound: DurableOutbound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DurableOutbound {
    Start {
        replaces: Option<DepositSyncPrefixSupportAttempt>,
        body_digest: [u8; 32],
    },
    Continue {
        revision: u64,
        body_digest: [u8; 32],
    },
    Endorsed {
        #[serde(deserialize_with = "deserialize_endorsement_bytes")]
        endorsement: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableCertificate {
    #[serde(deserialize_with = "deserialize_certificate_bytes")]
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableTombstone {
    binding: DurableAuthorityBinding,
    #[serde(deserialize_with = "deserialize_request_bytes")]
    request: Vec<u8>,
    #[serde(deserialize_with = "deserialize_accepted_attempts")]
    accepted: Vec<DurableAcceptedAttempt>,
    state: DurableTombstoneState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableAcceptedAttempt {
    party: PartyId,
    attempt: DepositSyncPrefixSupportAttempt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum DurableTombstoneState {
    Admitted { certificate_digest: [u8; 32] },
    Abandoned,
}

impl DurableCollection {
    fn new(
        authority: &DepositPrefixCollectionAuthority,
        predecessors: &[DurableAcceptedAttempt],
    ) -> Result<Self, DepositPrefixCollectionStoreError> {
        let mut parties =
            authority.active.committee().members.iter().map(|member| member.id).collect::<Vec<_>>();
        parties.sort_unstable();
        parties.dedup();
        if parties.len() != authority.active.committee().members.len()
            || parties.is_empty()
            || parties.len() > MAX_COMMITTEE_MEMBERS
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        let members = parties
            .into_iter()
            .map(|party| {
                let accepted_attempt = predecessors
                    .iter()
                    .find(|accepted| accepted.party == party)
                    .map(|accepted| accepted.attempt);
                let start = DepositSyncPrefixSupportStart::new(
                    authority.request.clone(),
                    accepted_attempt,
                )?;
                let body = start.to_bytes()?;
                Ok(DurableMemberState {
                    party,
                    accepted_attempt,
                    outbound: DurableOutbound::Start {
                        replaces: accepted_attempt,
                        body_digest: outbound_body_digest(
                            DepositOperation::PrefixSupportStart,
                            &body,
                        ),
                    },
                })
            })
            .collect::<Result<Vec<_>, DepositPrefixCollectionStoreError>>()?;
        let collection = Self {
            binding: authority.binding.clone(),
            request: authority.request_bytes.clone(),
            head: authority.head_bytes.clone(),
            members,
            certificate: None,
        };
        collection.validate_with_authority(authority)?;
        Ok(collection)
    }

    fn request(&self) -> Result<DepositSyncSupportRequest, DepositPrefixCollectionStoreError> {
        Ok(DepositSyncSupportRequest::from_bytes(&self.request)?)
    }

    fn head_response(&self) -> Result<DepositSyncHeadResponse, DepositPrefixCollectionStoreError> {
        let request = DepositSyncHeadRequest::new(
            self.binding.context,
            self.binding.source,
            self.binding.requester,
        )?;
        Ok(DepositSyncHeadResponse::from_bytes(request, &self.head)?)
    }

    fn validate_static(
        &self,
        context: DepositSyncContext,
        requester: PartyId,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        self.binding.validate_static(context, requester)?;
        if self.request.is_empty()
            || self.request.len() > MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES
            || self.head.is_empty()
            || self.head.len() > MAX_DEPOSIT_SYNC_WIRE_BYTES
            || length_prefixed_hash(COLLECTION_REQUEST_DIGEST_DOMAIN, &self.request)
                != self.binding.request_digest
            || length_prefixed_hash(COLLECTION_HEAD_DIGEST_DOMAIN, &self.head)
                != self.binding.head_digest
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        let request = self.request()?;
        let statement = request.statement();
        if statement.context() != context
            || statement.requester() != requester
            || statement.source() != self.binding.source
            || statement.digest() != self.binding.statement_digest
            || DepositSyncPrefixSupportAttempt::for_request(&request)? != self.binding.attempt
            || request
                .terminal_checkpoint()
                .certificate_digest()
                .map_err(DepositSyncSupportError::from)?
                != self.binding.terminal_certificate_digest
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        let head = self.head_response()?;
        let active = head.advertisement().registry_archive().registry().active();
        if head.advertisement().context() != context
            || head.advertisement().object_anchor() != statement.anchor()
            || head.lease().source() != self.binding.source
            || head.lease().requester() != requester
            || head.lease().digest() != statement.source_lease_digest()
            || active.committee().epoch != self.binding.active_epoch
            || active.committee().digest() != self.binding.active_committee
            || active.fault_bound() != self.binding.active_fault_bound
            || active.activation() != self.binding.active_activation
            || active.certified_activation_root() != self.binding.active_certified_activation_root
            || active.key_id() != self.binding.active_key_id
            || active.group_key() != self.binding.active_group_key
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }

        validate_member_order(&self.members)?;
        let required = usize::from(
            self.binding
                .active_fault_bound
                .checked_add(1)
                .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?,
        );
        if required == 0 || required > self.members.len() {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        let mut endorsed = 0_usize;
        for member in &self.members {
            member.validate_static(&request, self.binding.attempt)?;
            if matches!(&member.outbound, DurableOutbound::Endorsed { .. }) {
                endorsed += 1;
            }
        }
        match &self.certificate {
            None if endorsed < required => {}
            Some(certificate) if endorsed >= required => {
                let certificate = DepositSyncSupportCertificate::from_bytes(&certificate.bytes)?;
                if certificate.statement() != statement
                    || certificate.endorsements().len() != required
                {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
                for endorsement in certificate.endorsements() {
                    let member = self
                        .members
                        .binary_search_by_key(&endorsement.signer(), |member| member.party)
                        .ok()
                        .and_then(|index| self.members.get(index))
                        .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?;
                    let DurableOutbound::Endorsed { endorsement: durable } = &member.outbound
                    else {
                        return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                    };
                    if &postcard::to_allocvec(endorsement)
                        .map_err(|_| DepositPrefixCollectionStoreError::Serialization)?
                        != durable
                    {
                        return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                    }
                }
            }
            _ => return Err(DepositPrefixCollectionStoreError::InvalidDurableState),
        }
        Ok(())
    }

    fn validate_with_authority(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        self.validate_static(authority.context, authority.requester)?;
        if self.binding != authority.binding
            || self.request != authority.request_bytes
            || self.head != authority.head_bytes
        {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        let mut expected_parties =
            authority.active.committee().members.iter().map(|member| member.id).collect::<Vec<_>>();
        expected_parties.sort_unstable();
        if self.members.iter().map(|member| member.party).ne(expected_parties) {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }

        let mut endorsements = Vec::new();
        for member in &self.members {
            if let DurableOutbound::Endorsed { endorsement } = &member.outbound {
                let parsed = DepositSyncSupportEndorsement::from_bytes(
                    authority.request.statement(),
                    &authority.active,
                    endorsement,
                )?;
                if parsed.signer() != member.party {
                    return Err(DepositPrefixCollectionStoreError::WrongPeer);
                }
                endorsements.push(parsed);
            }
        }
        let required = usize::from(
            authority
                .active
                .fault_bound()
                .checked_add(1)
                .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?,
        );
        match &self.certificate {
            None if endorsements.len() < required => {}
            Some(durable) if endorsements.len() >= required => {
                let certificate = DepositSyncSupportCertificate::from_bytes(&durable.bytes)?;
                let verified =
                    certificate.verify(authority.request.statement(), &authority.active)?;
                let expected_signers = endorsements
                    .iter()
                    .take(required)
                    .map(|value| value.signer())
                    .collect::<Vec<_>>();
                if verified.signers() != expected_signers {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
            }
            _ => return Err(DepositPrefixCollectionStoreError::InvalidDurableState),
        }
        Ok(())
    }

    fn validate_for_work(
        &self,
        context: DepositSyncContext,
        requester: PartyId,
        work: &DepositSyncPrefixSupportWork,
        active: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        self.validate_static(context, requester)?;
        self.binding.validate_live(active, identity)?;
        let request = self.request()?;
        if request.statement() != work.statement() {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        let head_request = DepositSyncHeadRequest::new(context, self.binding.source, requester)?;
        let work_head = work.response().to_bytes(head_request)?;
        if work_head != self.head
            || length_prefixed_hash(COLLECTION_HEAD_DIGEST_DOMAIN, &work_head)
                != self.binding.head_digest
        {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        let reconstructed =
            crate::deposit_sync_support::DepositSyncSupportStatement::from_head_response(
                head_request,
                work.response(),
                active,
            )?;
        if &reconstructed != request.statement() {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        Ok(())
    }

    fn pending_requests(
        &self,
        authority: &DepositPrefixCollectionAuthority,
        limit: usize,
    ) -> Result<Vec<DepositPrefixCollectionRequest>, DepositPrefixCollectionStoreError> {
        if self.certificate.is_some() {
            return Ok(Vec::new());
        }
        let mut pending = Vec::new();
        for member in &self.members {
            if pending.len() == limit {
                break;
            }
            let Some((operation, body)) = member.outbound_body(&authority.request)? else {
                continue;
            };
            let peer = member.party;
            let request = PeerRequest::Deposit { operation, body: body.clone() };
            let request_id = RequestId::for_peer_request(
                authority.context.network(),
                authority.requester,
                peer,
                &request,
            )?;
            pending.push(DepositPrefixCollectionRequest { peer, operation, body, request_id });
        }
        Ok(pending)
    }

    fn record_progress(
        &mut self,
        authority: &DepositPrefixCollectionAuthority,
        peer: PartyId,
        operation: DepositOperation,
        request_body: &[u8],
        progress: &DepositSyncPrefixSupportProgress,
    ) -> Result<bool, DepositPrefixCollectionStoreError> {
        if self.certificate.is_some() {
            let member = self
                .members
                .binary_search_by_key(&peer, |member| member.party)
                .ok()
                .and_then(|index| self.members.get(index))
                .ok_or(DepositPrefixCollectionStoreError::WrongPeer)?;
            if member.progress_is_already_applied(authority, operation, request_body, progress)? {
                return Ok(false);
            }
            return Err(DepositPrefixCollectionStoreError::CollectionComplete);
        }
        let index = self
            .members
            .binary_search_by_key(&peer, |member| member.party)
            .map_err(|_| DepositPrefixCollectionStoreError::WrongPeer)?;
        let member =
            self.members.get_mut(index).ok_or(DepositPrefixCollectionStoreError::WrongPeer)?;
        let (expected_operation, expected_body) = member
            .outbound_body(&authority.request)?
            .ok_or(DepositPrefixCollectionStoreError::StaleRequest)?;
        if operation != expected_operation || request_body != expected_body.as_slice() {
            if member.progress_is_already_applied(authority, operation, request_body, progress)? {
                return Ok(false);
            }
            return Err(DepositPrefixCollectionStoreError::StaleRequest);
        }
        let endorsement = verify_progress(authority, operation, request_body, progress)?.cloned();

        member.accepted_attempt = Some(authority.attempt);
        match endorsement {
            Some(endorsement) => {
                if endorsement.signer() != peer {
                    return Err(DepositPrefixCollectionStoreError::WrongPeer);
                }
                member.outbound = DurableOutbound::Endorsed {
                    endorsement: endorsement
                        .to_bytes(authority.request.statement(), &authority.active)?,
                };
            }
            None => {
                let next_revision = progress
                    .next_revision()
                    .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?;
                let continuation =
                    DepositSyncPrefixSupportContinue::new(authority.attempt, next_revision)?;
                let body = continuation.to_bytes()?;
                if body == expected_body {
                    return Err(DepositPrefixCollectionStoreError::RevisionRollback);
                }
                member.outbound = DurableOutbound::Continue {
                    revision: next_revision,
                    body_digest: outbound_body_digest(
                        DepositOperation::PrefixSupportContinue,
                        &body,
                    ),
                };
            }
        }

        let required = usize::from(
            authority
                .active
                .fault_bound()
                .checked_add(1)
                .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?,
        );
        let endorsements = self
            .members
            .iter()
            .filter_map(|member| match &member.outbound {
                DurableOutbound::Endorsed { endorsement } => Some((
                    member.party,
                    DepositSyncSupportEndorsement::from_bytes(
                        authority.request.statement(),
                        &authority.active,
                        endorsement,
                    ),
                )),
                DurableOutbound::Start { .. } | DurableOutbound::Continue { .. } => None,
            })
            .map(|(party, endorsement)| {
                let endorsement = endorsement?;
                if endorsement.signer() != party {
                    return Err(DepositPrefixCollectionStoreError::WrongPeer);
                }
                Ok(endorsement)
            })
            .take(required)
            .collect::<Result<Vec<_>, DepositPrefixCollectionStoreError>>()?;
        if endorsements.len() == required {
            let certificate = DepositSyncSupportCertificate::new(
                authority.request.statement().clone(),
                endorsements,
                &authority.active,
            )?;
            self.certificate =
                Some(DurableCertificate { bytes: certificate.to_bytes(&authority.active)? });
        }
        Ok(true)
    }

    fn verified_certificate(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<Option<VerifiedDepositSyncSupportCertificate>, DepositPrefixCollectionStoreError>
    {
        let Some(durable) = &self.certificate else {
            return Ok(None);
        };
        let certificate = DepositSyncSupportCertificate::from_bytes(&durable.bytes)?;
        Ok(Some(certificate.verify(authority.request.statement(), &authority.active)?))
    }

    fn status(
        &self,
        authority: &DepositPrefixCollectionAuthority,
    ) -> Result<DepositPrefixCollectionStatus, DepositPrefixCollectionStoreError> {
        if let Some(certificate) = self.verified_certificate(authority)? {
            return Ok(DepositPrefixCollectionStatus::Certified(certificate));
        }
        let endorsements = u16::try_from(
            self.members
                .iter()
                .filter(|member| matches!(&member.outbound, DurableOutbound::Endorsed { .. }))
                .count(),
        )
        .map_err(|_| DepositPrefixCollectionStoreError::InvalidDurableState)?;
        Ok(DepositPrefixCollectionStatus::Collecting {
            attempt: self.binding.attempt,
            endorsements,
            required: self
                .binding
                .active_fault_bound
                .checked_add(1)
                .ok_or(DepositPrefixCollectionStoreError::InvalidDurableState)?,
        })
    }

    fn accepted(&self) -> Vec<DurableAcceptedAttempt> {
        self.members
            .iter()
            .filter_map(|member| {
                member
                    .accepted_attempt
                    .map(|attempt| DurableAcceptedAttempt { party: member.party, attempt })
            })
            .collect()
    }

    fn abandoned_tombstone(&self) -> DurableTombstone {
        DurableTombstone {
            binding: self.binding.clone(),
            request: self.request.clone(),
            accepted: self.accepted(),
            state: DurableTombstoneState::Abandoned,
        }
    }

    fn admitted_tombstone(&self, certificate_digest: [u8; 32]) -> DurableTombstone {
        DurableTombstone {
            binding: self.binding.clone(),
            request: self.request.clone(),
            accepted: self.accepted(),
            state: DurableTombstoneState::Admitted { certificate_digest },
        }
    }
}

impl DurableMemberState {
    fn validate_static(
        &self,
        request: &DepositSyncSupportRequest,
        attempt: DepositSyncPrefixSupportAttempt,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        if self.party == PartyId(0) {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        match &self.outbound {
            DurableOutbound::Start { replaces, body_digest } => {
                if replaces != &self.accepted_attempt {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
                let start = DepositSyncPrefixSupportStart::new(request.clone(), *replaces)?;
                let body = start.to_bytes()?;
                if outbound_body_digest(DepositOperation::PrefixSupportStart, &body) != *body_digest
                {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
            }
            DurableOutbound::Continue { revision, body_digest } => {
                if self.accepted_attempt != Some(attempt) || *revision == 0 {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
                let body = DepositSyncPrefixSupportContinue::new(attempt, *revision)?.to_bytes()?;
                if outbound_body_digest(DepositOperation::PrefixSupportContinue, &body)
                    != *body_digest
                {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
            }
            DurableOutbound::Endorsed { endorsement } => {
                if self.accepted_attempt != Some(attempt)
                    || endorsement.is_empty()
                    || endorsement.len() > MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES
                {
                    return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
                }
            }
        }
        Ok(())
    }

    fn outbound_body(
        &self,
        request: &DepositSyncSupportRequest,
    ) -> Result<Option<(DepositOperation, Vec<u8>)>, DepositPrefixCollectionStoreError> {
        let (operation, body, expected_digest) = match &self.outbound {
            DurableOutbound::Start { replaces, body_digest } => (
                DepositOperation::PrefixSupportStart,
                DepositSyncPrefixSupportStart::new(request.clone(), *replaces)?.to_bytes()?,
                *body_digest,
            ),
            DurableOutbound::Continue { revision, body_digest } => (
                DepositOperation::PrefixSupportContinue,
                DepositSyncPrefixSupportContinue::new(
                    DepositSyncPrefixSupportAttempt::for_request(request)?,
                    *revision,
                )?
                .to_bytes()?,
                *body_digest,
            ),
            DurableOutbound::Endorsed { .. } => return Ok(None),
        };
        if outbound_body_digest(operation, &body) != expected_digest {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        Ok(Some((operation, body)))
    }

    fn progress_is_already_applied(
        &self,
        authority: &DepositPrefixCollectionAuthority,
        operation: DepositOperation,
        request_body: &[u8],
        progress: &DepositSyncPrefixSupportProgress,
    ) -> Result<bool, DepositPrefixCollectionStoreError> {
        let endorsement = verify_progress(authority, operation, request_body, progress)?;
        if self.accepted_attempt != Some(authority.attempt) {
            return Ok(false);
        }
        match (endorsement, &self.outbound) {
            (None, DurableOutbound::Continue { revision, .. }) => {
                Ok(progress.next_revision() == Some(*revision))
            }
            (Some(endorsement), DurableOutbound::Endorsed { endorsement: durable }) => {
                Ok(endorsement
                    .to_bytes(authority.request.statement(), &authority.active)?
                    .as_slice()
                    == durable.as_slice())
            }
            _ => Ok(false),
        }
    }
}

fn verify_progress<'a>(
    authority: &DepositPrefixCollectionAuthority,
    operation: DepositOperation,
    request_body: &[u8],
    progress: &'a DepositSyncPrefixSupportProgress,
) -> Result<Option<&'a DepositSyncSupportEndorsement>, DepositPrefixCollectionStoreError> {
    let _ = progress.to_bytes()?;
    match operation {
        DepositOperation::PrefixSupportStart => {
            let start = DepositSyncPrefixSupportStart::from_bytes(request_body)?;
            if start.request() != &authority.request {
                return Err(DepositPrefixCollectionStoreError::StaleRequest);
            }
            Ok(progress.verify_for_start(&start, &authority.active)?)
        }
        DepositOperation::PrefixSupportContinue => {
            let continuation = DepositSyncPrefixSupportContinue::from_bytes(request_body)?;
            Ok(progress.verify_for_continue(continuation, &authority.request, &authority.active)?)
        }
        _ => Err(DepositPrefixCollectionStoreError::WrongOperation),
    }
}

impl DurableTombstone {
    fn request(&self) -> Result<DepositSyncSupportRequest, DepositPrefixCollectionStoreError> {
        Ok(DepositSyncSupportRequest::from_bytes(&self.request)?)
    }

    fn validate_static(
        &self,
        context: DepositSyncContext,
        requester: PartyId,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        self.binding.validate_static(context, requester)?;
        if self.request.is_empty()
            || self.request.len() > MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES
            || length_prefixed_hash(COLLECTION_REQUEST_DIGEST_DOMAIN, &self.request)
                != self.binding.request_digest
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        let request = self.request()?;
        if request.statement().context() != context
            || request.statement().requester() != requester
            || request.statement().source() != self.binding.source
            || request.statement().digest() != self.binding.statement_digest
            || DepositSyncPrefixSupportAttempt::for_request(&request)? != self.binding.attempt
            || request
                .terminal_checkpoint()
                .certificate_digest()
                .map_err(DepositSyncSupportError::from)?
                != self.binding.terminal_certificate_digest
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        let mut previous = None;
        for accepted in &self.accepted {
            if accepted.party == PartyId(0)
                || accepted.attempt.to_bytes() == [0; 32]
                || previous.is_some_and(|party| party >= accepted.party)
            {
                return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
            }
            previous = Some(accepted.party);
        }
        if self.accepted.len() > MAX_COMMITTEE_MEMBERS
            || matches!(
                &self.state,
                DurableTombstoneState::Admitted { certificate_digest }
                    if *certificate_digest == [0; 32]
            )
        {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        Ok(())
    }

    fn validate_for_work(
        &self,
        context: DepositSyncContext,
        requester: PartyId,
        work: &DepositSyncPrefixSupportWork,
        active: &VerifiedRegistryHandoffTarget,
        identity: &Identity,
    ) -> Result<(), DepositPrefixCollectionStoreError> {
        self.validate_static(context, requester)?;
        self.binding.validate_live(active, identity)?;
        let request = self.request()?;
        if request.statement() != work.statement() {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        let head_request = DepositSyncHeadRequest::new(context, self.binding.source, requester)?;
        let work_head = work.response().to_bytes(head_request)?;
        if length_prefixed_hash(COLLECTION_HEAD_DIGEST_DOMAIN, &work_head)
            != self.binding.head_digest
        {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        let reconstructed =
            crate::deposit_sync_support::DepositSyncSupportStatement::from_head_response(
                head_request,
                work.response(),
                active,
            )?;
        if &reconstructed != request.statement() {
            return Err(DepositPrefixCollectionStoreError::WrongAuthority);
        }
        Ok(())
    }

    fn status(&self) -> DepositPrefixCollectionStatus {
        match self.state {
            DurableTombstoneState::Admitted { .. } => {
                DepositPrefixCollectionStatus::Admitted { attempt: self.binding.attempt }
            }
            DurableTombstoneState::Abandoned => {
                DepositPrefixCollectionStatus::Abandoned { attempt: self.binding.attempt }
            }
        }
    }
}

fn validate_member_order(
    members: &[DurableMemberState],
) -> Result<(), DepositPrefixCollectionStoreError> {
    if members.is_empty() || members.len() > MAX_COMMITTEE_MEMBERS {
        return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
    }
    let mut previous = None;
    for member in members {
        if previous.is_some_and(|party| party >= member.party) {
            return Err(DepositPrefixCollectionStoreError::InvalidDurableState);
        }
        previous = Some(member.party);
    }
    Ok(())
}

fn authorize_local_identity(
    context: DepositSyncContext,
    active: &VerifiedRegistryHandoffTarget,
    identity: &Identity,
) -> Result<(), DepositPrefixCollectionStoreError> {
    let canonical = DepositSyncContext::new(context.network(), context.wallet())?;
    active.committee().validate_async_security_with_faults(active.fault_bound())?;
    let member = active.committee().member(identity.party())?;
    if canonical != context
        || active.wallet() != context.wallet()
        || identity.party() == PartyId(0)
        || identity.encryption_epoch() != active.committee().epoch
        || identity.signing_public_key() == [0; 32]
        || identity.encryption_public_key() == [0; 32]
        || member.signing_key != identity.signing_public_key()
        || member.encryption_key != identity.encryption_public_key()
    {
        return Err(DepositPrefixCollectionStoreError::InvalidIdentity);
    }
    Ok(())
}

fn admission_matches(
    authority: &DepositPrefixCollectionAuthority,
    admission: &DepositSyncSpoolAdmission,
    expected_certificate_digest: [u8; 32],
    expected_signers: Option<&[PartyId]>,
) -> bool {
    matches!(
        admission,
        DepositSyncSpoolAdmission::AdmittedPrefix {
            source,
            statement_digest,
            certificate_digest,
            endorsers,
            ..
        } if *source == authority.source
            && *statement_digest == authority.binding.statement_digest
            && *certificate_digest == expected_certificate_digest
            && expected_signers.is_none_or(|expected| endorsers.as_slice() == expected)
    )
}

fn collection_wallet_id(
    context: DepositSyncContext,
    requester: PartyId,
) -> Result<WalletId, DepositPrefixCollectionStoreError> {
    if requester == PartyId(0) {
        return Err(DepositPrefixCollectionStoreError::InvalidIdentity);
    }
    let mut hasher = blake3::Hasher::new_derive_key(COLLECTION_WALLET_ID_DOMAIN);
    hasher.update(&context.digest());
    hasher.update(&requester.0.to_le_bytes());
    let wallet = WalletId(*hasher.finalize().as_bytes());
    if wallet.0 == [0; 32] {
        return Err(DepositPrefixCollectionStoreError::KeyDerivation);
    }
    Ok(wallet)
}

fn outbound_body_digest(operation: DepositOperation, body: &[u8]) -> [u8; 32] {
    let tag = match operation {
        DepositOperation::PrefixSupportStart => 1_u8,
        DepositOperation::PrefixSupportContinue => 2_u8,
        _ => 0_u8,
    };
    let mut hasher = blake3::Hasher::new_derive_key(COLLECTION_BODY_DIGEST_DOMAIN);
    hasher.update(&[tag]);
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

fn length_prefixed_hash(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn encode_canonical<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, DepositPrefixCollectionStoreError> {
    let bytes = postcard::to_allocvec(value)
        .map_err(|_| DepositPrefixCollectionStoreError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositPrefixCollectionStoreError::StorageValueTooLarge);
    }
    Ok(bytes)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, DepositPrefixCollectionStoreError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositPrefixCollectionStoreError::StorageValueTooLarge);
    }
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| DepositPrefixCollectionStoreError::Serialization)?;
    if !trailing.is_empty() || encode_canonical(&value, maximum)? != bytes {
        return Err(DepositPrefixCollectionStoreError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn deserialize_request_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_DEPOSIT_SYNC_SUPPORT_REQUEST_BYTES,
        "deposit prefix collection request exceeds its bound",
    )
}

fn deserialize_head_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_DEPOSIT_SYNC_WIRE_BYTES,
        "deposit prefix collection head exceeds its bound",
    )
}

fn deserialize_endorsement_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_DEPOSIT_SYNC_SUPPORT_ENDORSEMENT_BYTES,
        "deposit prefix collection endorsement exceeds its bound",
    )
}

fn deserialize_certificate_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    deserialize_bounded_bytes(
        deserializer,
        MAX_DEPOSIT_SYNC_SUPPORT_CERTIFICATE_BYTES,
        "deposit prefix collection certificate exceeds its bound",
    )
}

fn deserialize_bounded_bytes<'de, D: Deserializer<'de>>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytesVisitor {
        maximum: usize,
        expectation: &'static str,
    }

    impl<'de> Visitor<'de> for BoundedBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_bytes<E: DeError>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > self.maximum {
                return Err(E::custom(self.expectation));
            }
            Ok(bytes.to_vec())
        }

        fn visit_borrowed_bytes<E: DeError>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
            self.visit_bytes(bytes)
        }

        fn visit_byte_buf<E: DeError>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > self.maximum {
                return Err(E::custom(self.expectation));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(BoundedBytesVisitor { maximum, expectation })
}

fn deserialize_member_states<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableMemberState>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_COMMITTEE_MEMBERS,
        "too many deposit prefix collection member states",
    )
}

fn deserialize_accepted_attempts<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DurableAcceptedAttempt>, D::Error> {
    deserialize_bounded_sequence(
        deserializer,
        MAX_COMMITTEE_MEMBERS,
        "too many deposit prefix collection accepted attempts",
    )
}

fn deserialize_bounded_sequence<'de, D, T>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedSequenceVisitor<T> {
        maximum: usize,
        expectation: &'static str,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundedSequenceVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedSequenceVisitor {
        maximum,
        expectation,
        marker: std::marker::PhantomData,
    })
}

#[derive(Debug, Error)]
pub enum DepositPrefixCollectionStoreError {
    #[error("deposit prefix collection support validation failed: {0}")]
    Support(#[from] DepositSyncSupportError),
    #[error("deposit prefix collection wire validation failed: {0}")]
    Wire(#[from] crate::deposit_sync_wire::DepositSyncWireError),
    #[error("deposit prefix collection committee validation failed: {0}")]
    Committee(#[from] CommitteeError),
    #[error("deposit prefix collection storage failed: {0}")]
    Storage(#[from] StoreError),
    #[error("deposit prefix collection transport binding failed: {0}")]
    Transport(#[from] QuicTransportError),
    #[error("deposit prefix collection I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("deposit prefix collection serialization failed")]
    Serialization,
    #[error("deposit prefix collection storage encoding is non-canonical")]
    NonCanonicalEncoding,
    #[error("deposit prefix collection storage value exceeds its hard bound")]
    StorageValueTooLarge,
    #[error("deposit prefix collection synthetic storage key derivation failed")]
    KeyDerivation,
    #[error("deposit prefix collection identity is not the current committee identity")]
    InvalidIdentity,
    #[error("deposit prefix collection live authority does not match the exact durable attempt")]
    WrongAuthority,
    #[error("deposit prefix collection durable state is malformed")]
    InvalidDurableState,
    #[error("the exact deposit prefix collection does not exist")]
    UnknownCollection,
    #[error("deposit prefix collection request limit is outside its hard bound")]
    InvalidLimit,
    #[error("deposit prefix collection response came from the wrong authenticated peer")]
    WrongPeer,
    #[error("deposit prefix collection used the wrong typed QUIC operation")]
    WrongOperation,
    #[error("deposit prefix collection response is for a stale or unjournaled request body")]
    StaleRequest,
    #[error("deposit prefix collection continuation attempted a revision rollback")]
    RevisionRollback,
    #[error("deposit prefix collection durable revision is exhausted")]
    RevisionExhausted,
    #[error("deposit prefix collection already has its exact f+1 certificate")]
    CollectionComplete,
    #[error("deposit prefix collection certificate is not complete")]
    CertificateIncomplete,
    #[error("deposit prefix collection stage admission does not match the exact certificate")]
    WrongAdmission,
    #[error("deposit prefix collection path is not a private regular snapshot: {0}")]
    StorageConflict(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deposit_wallet::DepositWalletId;

    fn context(network: u8, wallet: u8) -> DepositSyncContext {
        DepositSyncContext::new([network; 32], DepositWalletId([wallet; 32])).unwrap()
    }

    #[test]
    fn synthetic_snapshot_namespace_binds_context_and_requester() {
        let one = collection_wallet_id(context(1, 2), PartyId(1)).unwrap();
        let other_network = collection_wallet_id(context(3, 2), PartyId(1)).unwrap();
        let other_wallet = collection_wallet_id(context(1, 4), PartyId(1)).unwrap();
        let other_requester = collection_wallet_id(context(1, 2), PartyId(2)).unwrap();
        assert_ne!(one, other_network);
        assert_ne!(one, other_wallet);
        assert_ne!(one, other_requester);
        assert_ne!(one.0, [0; 32]);
    }

    #[test]
    fn outbound_digest_binds_route_and_changed_revision_body() {
        let start = outbound_body_digest(DepositOperation::PrefixSupportStart, b"same");
        let continuation = outbound_body_digest(DepositOperation::PrefixSupportContinue, b"same");
        let next = outbound_body_digest(DepositOperation::PrefixSupportContinue, b"different");
        assert_ne!(start, continuation);
        assert_ne!(continuation, next);
        assert_ne!(start, [0; 32]);
    }

    #[test]
    fn tombstone_preserves_each_peers_exact_last_accepted_attempt() {
        let first = DepositSyncPrefixSupportAttempt::from_bytes([1; 32]).unwrap();
        let second = DepositSyncPrefixSupportAttempt::from_bytes([2; 32]).unwrap();
        let tombstone = DurableTombstone {
            binding: DurableAuthorityBinding {
                context: context(1, 2),
                requester: PartyId(1),
                source: PartyId(2),
                attempt: second,
                request_digest: [3; 32],
                statement_digest: [4; 32],
                head_digest: [5; 32],
                terminal_certificate_digest: [6; 32],
                active_epoch: 7,
                active_committee: [8; 32],
                active_fault_bound: 1,
                active_activation: [9; 32],
                active_certified_activation_root: [10; 32],
                active_key_id: [11; 32],
                active_group_key: [12; 32],
                identity_epoch: 7,
                identity_signing_key: [13; 32],
                identity_encryption_key: [14; 32],
            },
            request: Vec::new(),
            accepted: vec![
                DurableAcceptedAttempt { party: PartyId(1), attempt: first },
                DurableAcceptedAttempt { party: PartyId(3), attempt: second },
            ],
            state: DurableTombstoneState::Abandoned,
        };
        assert_eq!(tombstone.accepted[0].attempt, first);
        assert_eq!(tombstone.accepted[1].attempt, second);
    }
}
