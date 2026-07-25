//! Crash-safe encrypted storage adapter for the compact epoch registry.
//!
//! Immutable links, witnesses, and index nodes are stored in [`WalletArtifactStore`]. The wallet
//! snapshot is the only mutable authority and embeds a [`CompactRegistryStoreCheckpoint`].
//! A mutation is ordered as follows:
//!
//! 1. fsync a canonical, self-identifying journal under a key derived from the exact old head;
//! 2. create every immutable object and authenticate an exact readback;
//! 3. install [`PreparedCompactRegistrySnapshot::checkpoint`] in the wallet-snapshot CAS;
//! 4. authenticate that exact checkpoint, remove the exact journal, and persist
//!    [`PreparedCompactRegistrySnapshot::settled_checkpoint`] in the next snapshot.
//!
//! An old snapshot can derive and abort its one possible pre-CAS journal. A target snapshot retains
//! the same exact key and completes post-CAS cleanup. Recovery never enumerates a directory or
//! replays the epoch prefix. This is a fresh-format adapter: it does not decode or translate any
//! earlier registry representation.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::PartyId,
    compact_epoch_registry::{
        COMPACT_REGISTRY_INDEX_DEPTH, RegistryHandoffCertificate, VerifiedIssuerWindow,
    },
    compact_registry_archive::{
        COMPACT_REGISTRY_APPEND_OBJECTS, COMPACT_REGISTRY_GENESIS_OBJECTS,
        COMPACT_REGISTRY_INDEX_OBJECT_READS, CompactRegistryArchiveError,
        CompactRegistryArchiveHead, CompactRegistryIndexStep, CompactRegistryObjectKind,
        CompactRegistryObjectReader, CompactRegistryObjectRef, PendingCompactRegistryMutation,
        VerifiedCompactRegistryMutation, compact_registry_index_step,
        lookup_compact_registry_epoch, lookup_verified_issuer_window,
        prepare_compact_registry_append, prepare_compact_registry_genesis,
    },
    deposit_index_checkpoint::PortableDepositIndexHead,
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{
        DepositIndexJournalKey, DepositIndexJournalScope, ProtocolStore, StoreError,
        WalletArtifactOwner, WalletArtifactStore, WalletId,
    },
};

const COMPACT_REGISTRY_STORE_CHECKPOINT_VERSION: u16 = 2;
const COMPACT_REGISTRY_MUTATION_JOURNAL_VERSION: u16 = 3;
const MAX_COMPACT_REGISTRY_CHECKPOINT_BYTES: usize = 32 * 1024;
const MAX_COMPACT_REGISTRY_JOURNAL_BYTES: usize = 1024 * 1024;

/// The largest synchronous working set used by one lookup or mutation.
///
/// Six independently selected index paths cover active-head verification plus a historical issuer
/// window. One complete staged append is included for mutation verification.
pub const MAX_COMPACT_REGISTRY_CACHE_OBJECTS: usize =
    6 * (COMPACT_REGISTRY_INDEX_OBJECT_READS + 2) + COMPACT_REGISTRY_APPEND_OBJECTS;
/// Links and witnesses dominate this conservative working-set cap. It is independent of registry
/// lifetime.
pub const MAX_COMPACT_REGISTRY_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Active head verification reads at most the active path and its immediate parent path.
pub const MAX_COMPACT_REGISTRY_STARTUP_ARTIFACT_READS: u64 =
    2 * (COMPACT_REGISTRY_INDEX_OBJECT_READS as u64 + 2);

const COMPACT_JOURNAL_KEY_DOMAIN: &str = "threshold-monero/compact-registry-store/journal-key/v2";
const COMPACT_CHECKPOINT_DIGEST_DOMAIN: &str =
    "threshold-monero/compact-registry-store/checkpoint/v2";

/// Constant-size registry authority embedded in `DepositServiceSnapshot`.
///
/// `committed_journal` is present only in the snapshot which first installs `head`. Its key is
/// retained across a crash after the snapshot CAS and removed from the next snapshot after exact
/// cleanup. A missing journal under a retained key means cleanup completed before the crash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactRegistryStoreCheckpoint {
    version: u16,
    wallet: DepositWalletId,
    head: Option<CompactRegistryArchiveHead>,
    committed_journal: Option<DepositIndexJournalKey>,
}

impl CompactRegistryStoreCheckpoint {
    /// Construct a fresh-format wallet checkpoint before compact-registry genesis.
    pub fn empty(wallet: DepositWalletId) -> Result<Self, CompactRegistryStoreError> {
        let checkpoint = Self {
            version: COMPACT_REGISTRY_STORE_CHECKPOINT_VERSION,
            wallet,
            head: None,
            committed_journal: None,
        };
        checkpoint.validate_shape()?;
        Ok(checkpoint)
    }

    /// Construct a settled checkpoint for an already materialized current-format head.
    ///
    /// The caller must still open [`CompactRegistryStore`] before exposing protocol APIs; opening
    /// performs bounded artifact readback and semantic verification.
    pub fn settled(
        wallet: DepositWalletId,
        head: CompactRegistryArchiveHead,
    ) -> Result<Self, CompactRegistryStoreError> {
        let checkpoint = Self {
            version: COMPACT_REGISTRY_STORE_CHECKPOINT_VERSION,
            wallet,
            head: Some(head),
            committed_journal: None,
        };
        checkpoint.validate_shape()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn head(&self) -> Option<&CompactRegistryArchiveHead> {
        self.head.as_ref()
    }

    #[must_use]
    pub const fn has_recovery_journal(&self) -> bool {
        self.committed_journal.is_some()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CompactRegistryStoreError> {
        self.validate_shape()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| CompactRegistryStoreError::Serialization)?;
        if bytes.len() > MAX_COMPACT_REGISTRY_CHECKPOINT_BYTES {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompactRegistryStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_COMPACT_REGISTRY_CHECKPOINT_BYTES {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        let (checkpoint, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| CompactRegistryStoreError::Serialization)?;
        if !trailing.is_empty() {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        checkpoint.validate_shape()?;
        if checkpoint.to_bytes()? != bytes {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        Ok(checkpoint)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            self.to_bytes().expect("a constructed compact-registry checkpoint is canonical");
        let mut hasher = blake3::Hasher::new_derive_key(COMPACT_CHECKPOINT_DIGEST_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    fn validate_shape(&self) -> Result<(), CompactRegistryStoreError> {
        if self.version != COMPACT_REGISTRY_STORE_CHECKPOINT_VERSION || self.wallet.0 == [0; 32] {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        match (&self.head, self.committed_journal) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(CompactRegistryStoreError::InvalidCheckpoint),
            (Some(head), journal) => {
                head.validate_shape()?;
                if head.wallet() != self.wallet {
                    return Err(CompactRegistryStoreError::InvalidCheckpoint);
                }
                if let Some(key) = journal {
                    key.validate()?;
                    if key.wallet_id != WalletId(self.wallet.0)
                        || key.scope != DepositIndexJournalScope::Portable
                        || if head.revision() == 0 {
                            key.expected_revision != 0
                        } else {
                            key.expected_revision.checked_add(1) != Some(head.revision())
                        }
                    {
                        return Err(CompactRegistryStoreError::InvalidCheckpoint);
                    }
                }
                Ok(())
            }
        }
    }

    fn settled_clone(&self) -> Self {
        let mut settled = self.clone();
        settled.committed_journal = None;
        settled
    }
}

/// Prepared registry material awaiting the wallet-snapshot CAS.
#[derive(Clone, Debug)]
pub struct PreparedCompactRegistrySnapshot {
    base_checkpoint_digest: [u8; 32],
    checkpoint: CompactRegistryStoreCheckpoint,
    settled_checkpoint: CompactRegistryStoreCheckpoint,
    journal_key: DepositIndexJournalKey,
    journal_bytes: Vec<u8>,
    staged_references: Vec<CompactRegistryObjectRef>,
    owner: WalletArtifactOwner,
    verified: VerifiedCompactRegistryMutation,
}

impl PreparedCompactRegistrySnapshot {
    /// Checkpoint that must be embedded in the exact snapshot CAS.
    #[must_use]
    pub const fn checkpoint(&self) -> &CompactRegistryStoreCheckpoint {
        &self.checkpoint
    }

    /// Journal-free checkpoint to persist in every later snapshot.
    #[must_use]
    pub const fn settled_checkpoint(&self) -> &CompactRegistryStoreCheckpoint {
        &self.settled_checkpoint
    }

    #[must_use]
    pub const fn proposed_head(&self) -> &CompactRegistryArchiveHead {
        self.verified.next_head()
    }
}

/// Bounded synchronous reader populated by the asynchronous adapter.
#[derive(Default)]
pub struct BoundedCompactRegistryReader {
    wallet: Option<DepositWalletId>,
    objects: BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    bytes: usize,
}

impl BoundedCompactRegistryReader {
    fn for_wallet(wallet: DepositWalletId) -> Self {
        Self { wallet: Some(wallet), objects: BTreeMap::new(), bytes: 0 }
    }

    fn clear(&mut self) {
        self.objects.clear();
        self.bytes = 0;
    }

    fn contains(&self, reference: CompactRegistryObjectRef) -> bool {
        self.objects.contains_key(&reference)
    }

    fn get(&self, reference: CompactRegistryObjectRef) -> Option<&[u8]> {
        self.objects.get(&reference).map(Vec::as_slice)
    }

    fn insert(
        &mut self,
        reference: CompactRegistryObjectRef,
        contents: Vec<u8>,
    ) -> Result<(), CompactRegistryStoreError> {
        if self.wallet != Some(reference.wallet()) {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        reference.verify_contents(&contents)?;
        if let Some(existing) = self.objects.get(&reference) {
            return if existing == &contents {
                Ok(())
            } else {
                Err(CompactRegistryStoreError::ObjectAuthentication)
            };
        }
        let next_bytes = self
            .bytes
            .checked_add(contents.len())
            .ok_or(CompactRegistryStoreError::CacheBoundExceeded)?;
        if self.objects.len() == MAX_COMPACT_REGISTRY_CACHE_OBJECTS
            || next_bytes > MAX_COMPACT_REGISTRY_CACHE_BYTES
        {
            return Err(CompactRegistryStoreError::CacheBoundExceeded);
        }
        self.bytes = next_bytes;
        self.objects.insert(reference, contents);
        Ok(())
    }

    fn remove(&mut self, reference: CompactRegistryObjectRef) {
        if let Some(contents) = self.objects.remove(&reference) {
            self.bytes = self.bytes.saturating_sub(contents.len());
        }
    }
}

impl CompactRegistryObjectReader for BoundedCompactRegistryReader {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        Ok(self.objects.get(&reference).cloned())
    }
}

/// Async encrypted-store adapter with a bounded synchronous verification cache.
pub struct CompactRegistryStore {
    protocol: Arc<ProtocolStore>,
    artifacts: WalletArtifactStore,
    checkpoint: CompactRegistryStoreCheckpoint,
    cache: BoundedCompactRegistryReader,
    prepared_digest: Option<[u8; 32]>,
    artifact_loads: u64,
}

impl std::fmt::Debug for CompactRegistryStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompactRegistryStore")
            .field("wallet", &self.checkpoint.wallet)
            .field("active_epoch", &self.checkpoint.head.as_ref().map(|head| head.registry_id()))
            .field("cache_objects", &self.cache.objects.len())
            .field("cache_bytes", &self.cache.bytes)
            .field("prepared", &self.prepared_digest.is_some())
            .finish_non_exhaustive()
    }
}

impl CompactRegistryStore {
    /// Open with the stores shared by the party runtime.
    ///
    /// The adapter is returned only after both crash windows have been resolved and the current
    /// head has passed bounded semantic verification.
    pub async fn open_with_stores(
        protocol: Arc<ProtocolStore>,
        artifacts: WalletArtifactStore,
        checkpoint: CompactRegistryStoreCheckpoint,
    ) -> Result<Self, CompactRegistryStoreError> {
        checkpoint.validate_shape()?;
        let wallet = checkpoint.wallet;
        let mut store = Self {
            protocol,
            artifacts,
            checkpoint,
            cache: BoundedCompactRegistryReader::for_wallet(wallet),
            prepared_digest: None,
            artifact_loads: 0,
        };
        store.recover_startup().await?;
        Ok(store)
    }

    /// Convenience constructor for a runtime which exclusively owns these store handles.
    pub async fn open(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        checkpoint: CompactRegistryStoreCheckpoint,
    ) -> Result<Self, CompactRegistryStoreError> {
        let directory = directory.into();
        let protocol = Arc::new(ProtocolStore::new(&directory, party, identity_seed)?);
        let artifacts = WalletArtifactStore::new(directory, party, identity_seed)?;
        Self::open_with_stores(protocol, artifacts, checkpoint).await
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &CompactRegistryStoreCheckpoint {
        &self.checkpoint
    }

    #[must_use]
    pub const fn head(&self) -> Option<&CompactRegistryArchiveHead> {
        self.checkpoint.head()
    }

    #[must_use]
    pub const fn artifact_load_count(&self) -> u64 {
        self.artifact_loads
    }

    /// Prepare and materialize fresh compact-registry genesis.
    pub async fn prepare_genesis(
        &mut self,
        target: &VerifiedRegistryHandoffTarget,
        first_index: DepositSubaddressIndex,
        portable_index_checkpoint: [u8; 32],
    ) -> Result<PreparedCompactRegistrySnapshot, CompactRegistryStoreError> {
        if self.checkpoint.head.is_some() {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }
        if target.wallet() != self.checkpoint.wallet {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }
        let pending =
            prepare_compact_registry_genesis(target, first_index, portable_index_checkpoint)?;
        self.prepare_mutation(pending).await
    }

    /// Prepare and materialize the unique immediate successor.
    pub async fn prepare_append(
        &mut self,
        target: &VerifiedRegistryHandoffTarget,
        certificate: RegistryHandoffCertificate,
        source_portable_head: &PortableDepositIndexHead,
    ) -> Result<PreparedCompactRegistrySnapshot, CompactRegistryStoreError> {
        if self.prepared_digest.is_some() {
            return Err(CompactRegistryStoreError::TransitionInProgress);
        }
        self.reset_cache()?;
        let head =
            self.checkpoint.head.clone().ok_or(CompactRegistryStoreError::CheckpointConflict)?;
        self.preload_head_verification(&head).await?;
        let next_epoch = head
            .registry()
            .active_epoch()
            .checked_add(1)
            .ok_or(CompactRegistryArchiveError::Overflow)?;
        self.preload_index_walk(&head, next_epoch, true).await?;
        let pending = prepare_compact_registry_append(
            &head,
            target,
            certificate,
            source_portable_head,
            &self.cache,
        )?;
        self.prepare_mutation_inner(pending, false).await
    }

    /// Materialize a protocol-core mutation and return the exact snapshot checkpoint.
    ///
    /// Prefer [`Self::prepare_genesis`] or [`Self::prepare_append`]. This boundary exists for a
    /// bootstrap/catch-up path which obtained an already validated current-format mutation.
    pub async fn prepare_mutation(
        &mut self,
        pending: PendingCompactRegistryMutation,
    ) -> Result<PreparedCompactRegistrySnapshot, CompactRegistryStoreError> {
        self.prepare_mutation_inner(pending, true).await
    }

    /// Finish only after the wallet-snapshot layer authenticated the exact target checkpoint.
    pub async fn commit_prepared(
        &mut self,
        prepared: &PreparedCompactRegistrySnapshot,
        authenticated_checkpoint: &CompactRegistryStoreCheckpoint,
    ) -> Result<(), CompactRegistryStoreError> {
        self.require_prepared(prepared)?;
        if authenticated_checkpoint != &prepared.checkpoint
            || prepared.base_checkpoint_digest != self.checkpoint.digest()
        {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }
        authenticated_checkpoint.validate_shape()?;
        let previous =
            self.checkpoint.head.as_ref().map(CompactRegistryArchiveHead::to_bytes).transpose()?;
        let committed = authenticated_checkpoint
            .head
            .as_ref()
            .ok_or(CompactRegistryStoreError::InvalidCheckpoint)?
            .to_bytes()?;
        let authorized = prepared.verified.authorize_install(previous.as_deref(), &committed)?;
        if authenticated_checkpoint.head.as_ref() != Some(&authorized)
            || authenticated_checkpoint.committed_journal != Some(prepared.journal_key)
        {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }

        // From this point the external snapshot is authoritative. Keep the retained journal key
        // in memory across every fallible cleanup step so a restart can finish exactly.
        self.checkpoint = authenticated_checkpoint.clone();
        for reference in &prepared.staged_references {
            self.artifacts
                .release_artifact_ownership(reference.storage_reference()?, prepared.owner)
                .await?;
        }
        self.protocol
            .destroy_deposit_index_journal(prepared.journal_key, &prepared.journal_bytes)
            .await?;
        self.checkpoint = prepared.settled_checkpoint.clone();
        self.prepared_digest = None;
        self.reset_cache()?;
        self.verify_current_head().await
    }

    /// Abort exact artifacts after the wallet-snapshot CAS failed.
    pub async fn abort_prepared(
        &mut self,
        prepared: &PreparedCompactRegistrySnapshot,
    ) -> Result<(), CompactRegistryStoreError> {
        self.require_prepared(prepared)?;
        if prepared.base_checkpoint_digest != self.checkpoint.digest() {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }
        for reference in &prepared.staged_references {
            self.artifacts
                .remove_artifact_if_owned(reference.storage_reference()?, prepared.owner)
                .await?;
            self.cache.remove(*reference);
        }
        self.protocol
            .destroy_deposit_index_journal(prepared.journal_key, &prepared.journal_bytes)
            .await?;
        self.prepared_digest = None;
        self.reset_cache()?;
        self.verify_current_head().await
    }

    /// Direct authenticated historical epoch lookup.
    pub async fn lookup_epoch(
        &mut self,
        epoch: u64,
    ) -> Result<crate::compact_registry_archive::VerifiedRegistryEpoch, CompactRegistryStoreError>
    {
        self.reset_cache()?;
        let head =
            self.checkpoint.head.clone().ok_or(CompactRegistryStoreError::CheckpointConflict)?;
        self.preload_head_verification(&head).await?;
        self.preload_epoch_and_parent(&head, epoch).await?;
        Ok(lookup_compact_registry_epoch(&head, epoch, &self.cache)?)
    }

    /// Direct authenticated issuer window lookup with no prefix replay.
    pub async fn lookup_issuer_window(
        &mut self,
        epoch: u64,
    ) -> Result<VerifiedIssuerWindow, CompactRegistryStoreError> {
        self.reset_cache()?;
        let head =
            self.checkpoint.head.clone().ok_or(CompactRegistryStoreError::CheckpointConflict)?;
        self.preload_head_verification(&head).await?;
        self.preload_epoch_and_parent(&head, epoch).await?;
        if epoch < head.registry().active_epoch() {
            let successor = epoch.checked_add(1).ok_or(CompactRegistryArchiveError::Overflow)?;
            self.preload_epoch_and_parent(&head, successor).await?;
        }
        Ok(lookup_verified_issuer_window(&head, epoch, &self.cache)?)
    }

    fn reset_cache(&mut self) -> Result<(), CompactRegistryStoreError> {
        if self.prepared_digest.is_some() {
            return Err(CompactRegistryStoreError::TransitionInProgress);
        }
        self.cache.clear();
        Ok(())
    }

    async fn prepare_mutation_inner(
        &mut self,
        pending: PendingCompactRegistryMutation,
        preload: bool,
    ) -> Result<PreparedCompactRegistrySnapshot, CompactRegistryStoreError> {
        if self.prepared_digest.is_some() {
            return Err(CompactRegistryStoreError::TransitionInProgress);
        }
        self.validate_pending_authority(&pending)?;
        if preload {
            self.reset_cache()?;
            if let Some(head) = self.checkpoint.head.clone() {
                self.preload_head_verification(&head).await?;
                self.preload_index_walk(
                    &head,
                    pending.proposed_head().registry().active_epoch(),
                    true,
                )
                .await?;
            }
        }
        for object in pending.staged_objects() {
            if self.cache.contains(object.reference()) {
                return Err(CompactRegistryStoreError::ObjectAuthentication);
            }
        }

        let owner = WalletArtifactOwner::random(&mut OsRng);
        let journal = CompactRegistryMutationJournal::from_pending(&pending, owner)?;
        let journal_bytes = journal.to_bytes()?;
        let journal_key = journal.journal_key()?;
        self.protocol.save_deposit_index_journal(journal_key, &journal_bytes, &mut OsRng).await?;

        if let Err(error) = self.materialize_journal(&journal).await {
            self.abort_journal_objects(&journal, journal_key, &journal_bytes).await?;
            return Err(error);
        }
        if let Err(error) = journal.verify_installed(&self.cache) {
            self.abort_journal_objects(&journal, journal_key, &journal_bytes).await?;
            return Err(error);
        }
        let staged_references = journal.objects.iter().map(|object| object.reference).collect();
        let verified = match pending.verify_staged(&self.cache) {
            Ok(verified) => verified,
            Err(error) => {
                self.abort_journal_objects(&journal, journal_key, &journal_bytes).await?;
                return Err(error.into());
            }
        };
        let checkpoint = CompactRegistryStoreCheckpoint {
            version: COMPACT_REGISTRY_STORE_CHECKPOINT_VERSION,
            wallet: self.checkpoint.wallet,
            head: Some(verified.next_head().clone()),
            committed_journal: Some(journal_key),
        };
        if let Err(error) = checkpoint
            .validate_shape()
            .and_then(|()| validate_checkpoint_successor(&self.checkpoint, &checkpoint, &journal))
        {
            self.abort_journal_objects(&journal, journal_key, &journal_bytes).await?;
            return Err(error);
        }
        let settled_checkpoint = checkpoint.settled_clone();
        let base_checkpoint_digest = self.checkpoint.digest();
        self.prepared_digest = Some(checkpoint.digest());
        Ok(PreparedCompactRegistrySnapshot {
            base_checkpoint_digest,
            checkpoint,
            settled_checkpoint,
            journal_key,
            journal_bytes,
            staged_references,
            owner,
            verified,
        })
    }

    fn validate_pending_authority(
        &self,
        pending: &PendingCompactRegistryMutation,
    ) -> Result<(), CompactRegistryStoreError> {
        let expected =
            self.checkpoint.head.as_ref().map(CompactRegistryArchiveHead::to_bytes).transpose()?;
        let expected_revision = self.checkpoint.head.as_ref().map_or(Ok(0), |head| {
            head.revision().checked_add(1).ok_or(CompactRegistryArchiveError::Overflow)
        })?;
        if pending.expected_head_bytes() != expected.as_deref()
            || pending.proposed_head().wallet() != self.checkpoint.wallet
            || pending.proposed_head().revision() != expected_revision
        {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }
        Ok(())
    }

    fn require_prepared(
        &self,
        prepared: &PreparedCompactRegistrySnapshot,
    ) -> Result<(), CompactRegistryStoreError> {
        if self.prepared_digest != Some(prepared.checkpoint.digest()) {
            return Err(CompactRegistryStoreError::CheckpointConflict);
        }
        Ok(())
    }

    async fn recover_startup(&mut self) -> Result<(), CompactRegistryStoreError> {
        // Crash window B: the target snapshot names the exact committed journal.
        if let Some(key) = self.checkpoint.committed_journal {
            if let Some(blob) = self.protocol.load_deposit_index_journal(key).await? {
                let bytes = blob.into_bytes();
                let journal = CompactRegistryMutationJournal::from_bytes(&bytes)?;
                validate_journal_binding(
                    key,
                    &journal,
                    self.checkpoint.head.as_ref(),
                    JournalPosition::Committed,
                )?;
                self.cache.clear();
                self.materialize_journal(&journal).await?;
                let target = self
                    .checkpoint
                    .head
                    .clone()
                    .ok_or(CompactRegistryStoreError::InvalidCheckpoint)?;
                self.preload_head_verification(&target).await?;
                journal.verify_installed(&self.cache)?;
                for object in &journal.objects {
                    self.artifacts
                        .release_artifact_ownership(
                            object.reference.storage_reference()?,
                            journal.owner,
                        )
                        .await?;
                }
                self.protocol.destroy_deposit_index_journal(key, &bytes).await?;
            }
            self.checkpoint = self.checkpoint.settled_clone();
        }

        // Crash window A: the old snapshot derives its only possible pending key. Validate the
        // entire target from canonical journal bytes before deleting any exact staged object.
        let pending_key =
            compact_registry_journal_key(self.checkpoint.wallet, self.checkpoint.head.as_ref())?;
        if let Some(blob) = self.protocol.load_deposit_index_journal(pending_key).await? {
            let bytes = blob.into_bytes();
            let journal = CompactRegistryMutationJournal::from_bytes(&bytes)?;
            validate_journal_binding(
                pending_key,
                &journal,
                self.checkpoint.head.as_ref(),
                JournalPosition::Pending,
            )?;
            self.cache.clear();
            if let Some(head) = self.checkpoint.head.clone() {
                self.preload_head_verification(&head).await?;
                self.preload_index_walk(
                    &head,
                    journal.next_head()?.registry().active_epoch(),
                    true,
                )
                .await?;
            }
            for object in &journal.objects {
                if self.cache.contains(object.reference) {
                    return Err(CompactRegistryStoreError::ObjectAuthentication);
                }
                self.cache.insert(object.reference, object.contents.clone())?;
            }
            journal.verify_installed(&self.cache)?;
            for object in &journal.objects {
                self.artifacts
                    .remove_artifact_if_owned(object.reference.storage_reference()?, journal.owner)
                    .await?;
                self.cache.remove(object.reference);
            }
            self.protocol.destroy_deposit_index_journal(pending_key, &bytes).await?;
        }

        self.cache.clear();
        self.verify_current_head().await
    }

    async fn verify_current_head(&mut self) -> Result<(), CompactRegistryStoreError> {
        let Some(head) = self.checkpoint.head.clone() else {
            return Ok(());
        };
        self.preload_head_verification(&head).await?;
        head.verify_bounded(&self.cache)?;
        Ok(())
    }

    async fn preload_head_verification(
        &mut self,
        head: &CompactRegistryArchiveHead,
    ) -> Result<(), CompactRegistryStoreError> {
        let active = head.registry().active_epoch();
        self.preload_epoch_path(head, active).await?;
        if active > 0 {
            self.preload_epoch_path(head, active - 1).await?;
        }
        Ok(())
    }

    async fn preload_epoch_and_parent(
        &mut self,
        head: &CompactRegistryArchiveHead,
        epoch: u64,
    ) -> Result<(), CompactRegistryStoreError> {
        self.preload_epoch_path(head, epoch).await?;
        if epoch > 0 {
            self.preload_epoch_path(head, epoch - 1).await?;
        }
        Ok(())
    }

    async fn preload_epoch_path(
        &mut self,
        head: &CompactRegistryArchiveHead,
        epoch: u64,
    ) -> Result<(), CompactRegistryStoreError> {
        if !self.preload_index_walk(head, epoch, false).await? {
            return Err(CompactRegistryArchiveError::MissingEpoch(epoch).into());
        }
        Ok(())
    }

    /// Load one fixed-depth walk. When `allow_missing` is true, an authenticated empty child ends
    /// the walk successfully and supplies the synchronous append core with every existing prefix.
    async fn preload_index_walk(
        &mut self,
        head: &CompactRegistryArchiveHead,
        epoch: u64,
        allow_missing: bool,
    ) -> Result<bool, CompactRegistryStoreError> {
        let mut reference = head.index_root_reference();
        let mut semantic_hash = head.registry_id().index_root();
        for depth in 0..=COMPACT_REGISTRY_INDEX_DEPTH {
            self.load_exact_artifact(reference).await?;
            let bytes = self
                .cache
                .get(reference)
                .ok_or(CompactRegistryStoreError::ObjectAuthentication)?
                .to_vec();
            match compact_registry_index_step(
                head.wallet(),
                epoch,
                depth,
                semantic_hash,
                reference,
                &bytes,
            )? {
                CompactRegistryIndexStep::Branch { next, next_semantic_hash } => {
                    let Some(next) = next else {
                        if allow_missing {
                            return Ok(false);
                        }
                        return Err(CompactRegistryArchiveError::MissingEpoch(epoch).into());
                    };
                    reference = next;
                    semantic_hash = next_semantic_hash;
                }
                CompactRegistryIndexStep::Leaf { link, witness, .. } => {
                    self.load_exact_artifact(link).await?;
                    if let Some(witness) = witness {
                        self.load_exact_artifact(witness).await?;
                    }
                    return Ok(true);
                }
            }
        }
        Err(CompactRegistryStoreError::ReadBoundExceeded)
    }

    async fn load_exact_artifact(
        &mut self,
        reference: CompactRegistryObjectRef,
    ) -> Result<(), CompactRegistryStoreError> {
        if self.cache.contains(reference) {
            return Ok(());
        }
        if reference.wallet() != self.checkpoint.wallet {
            return Err(CompactRegistryStoreError::InvalidCheckpoint);
        }
        let artifact = self.artifacts.load_artifact(reference.storage_reference()?).await?;
        self.artifact_loads = self.artifact_loads.saturating_add(1);
        if artifact.reference != reference.storage_reference()? {
            return Err(CompactRegistryStoreError::ObjectAuthentication);
        }
        self.cache.insert(reference, artifact.contents.into_bytes())
    }

    async fn materialize_journal(
        &mut self,
        journal: &CompactRegistryMutationJournal,
    ) -> Result<(), CompactRegistryStoreError> {
        for object in &journal.objects {
            let storage_reference = object.reference.storage_reference()?;
            let (installed, _ownership) = self
                .artifacts
                .create_artifact_owned(
                    journal.owner,
                    WalletId(self.checkpoint.wallet.0),
                    storage_reference.kind(),
                    &object.contents,
                    &mut OsRng,
                )
                .await?;
            if installed != storage_reference {
                return Err(CompactRegistryStoreError::ObjectAuthentication);
            }
            let readback = self.artifacts.load_artifact_owned(installed, journal.owner).await?;
            self.artifact_loads = self.artifact_loads.saturating_add(1);
            if readback.reference != storage_reference
                || readback.contents.as_bytes() != object.contents
            {
                return Err(CompactRegistryStoreError::ObjectAuthentication);
            }
            self.cache.insert(object.reference, readback.contents.into_bytes())?;
        }
        Ok(())
    }

    async fn abort_journal_objects(
        &mut self,
        journal: &CompactRegistryMutationJournal,
        key: DepositIndexJournalKey,
        bytes: &[u8],
    ) -> Result<(), CompactRegistryStoreError> {
        for object in &journal.objects {
            self.artifacts
                .remove_artifact_if_owned(object.reference.storage_reference()?, journal.owner)
                .await?;
            self.cache.remove(object.reference);
        }
        self.protocol.destroy_deposit_index_journal(key, bytes).await?;
        Ok(())
    }
}

impl CompactRegistryObjectReader for CompactRegistryStore {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        self.cache.load(reference)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct JournalObject {
    reference: CompactRegistryObjectRef,
    contents: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CompactRegistryMutationJournal {
    version: u16,
    wallet: DepositWalletId,
    owner: WalletArtifactOwner,
    expected_head_bytes: Option<Vec<u8>>,
    next_head_bytes: Vec<u8>,
    objects: Vec<JournalObject>,
}

impl CompactRegistryMutationJournal {
    fn from_pending(
        pending: &PendingCompactRegistryMutation,
        owner: WalletArtifactOwner,
    ) -> Result<Self, CompactRegistryStoreError> {
        let journal = Self {
            version: COMPACT_REGISTRY_MUTATION_JOURNAL_VERSION,
            wallet: pending.proposed_head().wallet(),
            owner,
            expected_head_bytes: pending.expected_head_bytes().map(ToOwned::to_owned),
            next_head_bytes: pending.proposed_head().to_bytes()?,
            objects: pending
                .staged_objects()
                .iter()
                .map(|object| JournalObject {
                    reference: object.reference(),
                    contents: object.contents().to_vec(),
                })
                .collect(),
        };
        journal.validate_shape()?;
        Ok(journal)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, CompactRegistryStoreError> {
        self.validate_shape()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| CompactRegistryStoreError::Serialization)?;
        if bytes.is_empty() || bytes.len() > MAX_COMPACT_REGISTRY_JOURNAL_BYTES {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CompactRegistryStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_COMPACT_REGISTRY_JOURNAL_BYTES {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }
        let (journal, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| CompactRegistryStoreError::Serialization)?;
        if !trailing.is_empty() {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }
        journal.validate_shape()?;
        if journal.to_bytes()? != bytes {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }
        Ok(journal)
    }

    fn validate_shape(&self) -> Result<(), CompactRegistryStoreError> {
        self.owner.validate()?;
        let next_head = CompactRegistryArchiveHead::from_bytes(&self.next_head_bytes)?;
        let expected = self
            .expected_head_bytes
            .as_deref()
            .map(CompactRegistryArchiveHead::from_bytes)
            .transpose()?;
        let expected_objects = if expected.is_some() {
            COMPACT_REGISTRY_APPEND_OBJECTS
        } else {
            COMPACT_REGISTRY_GENESIS_OBJECTS
        };
        if self.version != COMPACT_REGISTRY_MUTATION_JOURNAL_VERSION
            || self.wallet.0 == [0; 32]
            || next_head.wallet() != self.wallet
            || self.objects.len() != expected_objects
            || match &expected {
                None => next_head.revision() != 0 || next_head.registry().active_epoch() != 0,
                Some(head) => {
                    head.wallet() != self.wallet
                        || head.revision().checked_add(1) != Some(next_head.revision())
                        || head.registry().active_epoch().checked_add(1)
                            != Some(next_head.registry().active_epoch())
                }
            }
        {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }

        let mut previous = None;
        let mut links = 0;
        let mut witnesses = 0;
        let mut nodes = 0;
        for object in &self.objects {
            if object.reference.wallet() != self.wallet {
                return Err(CompactRegistryStoreError::InvalidJournal);
            }
            object.reference.verify_contents(&object.contents)?;
            if previous.is_some_and(|prior| prior >= object.reference) {
                return Err(CompactRegistryStoreError::InvalidJournal);
            }
            previous = Some(object.reference);
            match object.reference.kind() {
                CompactRegistryObjectKind::Link => links += 1,
                CompactRegistryObjectKind::HandoffWitness => witnesses += 1,
                CompactRegistryObjectKind::IndexNode => nodes += 1,
            }
        }
        let expected_witnesses = usize::from(expected.is_some());
        if links != 1
            || witnesses != expected_witnesses
            || nodes != COMPACT_REGISTRY_INDEX_OBJECT_READS
        {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }
        Ok(())
    }

    fn journal_key(&self) -> Result<DepositIndexJournalKey, CompactRegistryStoreError> {
        let expected = self
            .expected_head_bytes
            .as_deref()
            .map(CompactRegistryArchiveHead::from_bytes)
            .transpose()?;
        compact_registry_journal_key(self.wallet, expected.as_ref())
    }

    fn next_head(&self) -> Result<CompactRegistryArchiveHead, CompactRegistryStoreError> {
        Ok(CompactRegistryArchiveHead::from_bytes(&self.next_head_bytes)?)
    }

    fn verify_installed(
        &self,
        reader: &BoundedCompactRegistryReader,
    ) -> Result<(), CompactRegistryStoreError> {
        let staged = self.objects.iter().map(|object| object.reference).collect::<BTreeSet<_>>();
        let tracking = TrackingReader {
            inner: reader,
            staged: &staged,
            touched: RefCell::new(BTreeSet::new()),
        };
        let next_head = self.next_head()?;
        next_head.verify_bounded(&tracking)?;
        if let Some(expected_bytes) = &self.expected_head_bytes {
            let expected = CompactRegistryArchiveHead::from_bytes(expected_bytes)?;
            let active = lookup_compact_registry_epoch(
                &next_head,
                next_head.registry().active_epoch(),
                &tracking,
            )?;
            let parent = lookup_compact_registry_epoch(
                &next_head,
                expected.registry().active_epoch(),
                &tracking,
            )?;
            if active.link().parent_chain_root() != expected.registry_id().chain_root()
                || active.link().parent_index_root() != expected.registry_id().index_root()
                || parent.link_reference() != expected.active_link_reference()
                || parent.witness_reference() != expected.active_witness_reference()
            {
                return Err(CompactRegistryStoreError::InvalidJournal);
            }
        }
        if *tracking.touched.borrow() != staged {
            return Err(CompactRegistryStoreError::InvalidJournal);
        }
        Ok(())
    }
}

struct TrackingReader<'a> {
    inner: &'a BoundedCompactRegistryReader,
    staged: &'a BTreeSet<CompactRegistryObjectRef>,
    touched: RefCell<BTreeSet<CompactRegistryObjectRef>>,
}

impl CompactRegistryObjectReader for TrackingReader<'_> {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        if self.staged.contains(&reference) {
            self.touched.borrow_mut().insert(reference);
        }
        self.inner.load(reference)
    }
}

fn compact_registry_journal_key(
    wallet: DepositWalletId,
    head: Option<&CompactRegistryArchiveHead>,
) -> Result<DepositIndexJournalKey, CompactRegistryStoreError> {
    if wallet.0 == [0; 32] || head.is_some_and(|head| head.wallet() != wallet) {
        return Err(CompactRegistryStoreError::InvalidCheckpoint);
    }
    let mut hasher = blake3::Hasher::new_derive_key(COMPACT_JOURNAL_KEY_DOMAIN);
    hasher.update(&wallet.0);
    match head {
        None => {
            hasher.update(&[0]);
        }
        Some(head) => {
            hasher.update(&[1]);
            hasher.update(&head.revision().to_le_bytes());
            hasher.update(&head.digest()?);
        }
    }
    let key = DepositIndexJournalKey {
        wallet_id: WalletId(wallet.0),
        scope: DepositIndexJournalScope::Portable,
        expected_revision: head.map_or(0, CompactRegistryArchiveHead::revision),
        expected_head_digest: *hasher.finalize().as_bytes(),
    };
    key.validate()?;
    Ok(key)
}

#[derive(Clone, Copy)]
enum JournalPosition {
    Pending,
    Committed,
}

fn validate_journal_binding(
    key: DepositIndexJournalKey,
    journal: &CompactRegistryMutationJournal,
    authoritative: Option<&CompactRegistryArchiveHead>,
    position: JournalPosition,
) -> Result<(), CompactRegistryStoreError> {
    let authoritative_bytes =
        authoritative.map(CompactRegistryArchiveHead::to_bytes).transpose()?;
    if journal.journal_key()? != key
        || match position {
            JournalPosition::Pending => {
                journal.expected_head_bytes.as_deref() != authoritative_bytes.as_deref()
            }
            JournalPosition::Committed => {
                authoritative_bytes.as_deref() != Some(journal.next_head_bytes.as_slice())
            }
        }
    {
        return Err(CompactRegistryStoreError::CheckpointConflict);
    }
    Ok(())
}

fn validate_checkpoint_successor(
    previous: &CompactRegistryStoreCheckpoint,
    next: &CompactRegistryStoreCheckpoint,
    journal: &CompactRegistryMutationJournal,
) -> Result<(), CompactRegistryStoreError> {
    previous.validate_shape()?;
    next.validate_shape()?;
    if previous.wallet != next.wallet
        || previous.committed_journal.is_some()
        || next.committed_journal != Some(journal.journal_key()?)
    {
        return Err(CompactRegistryStoreError::CheckpointConflict);
    }
    validate_journal_binding(
        journal.journal_key()?,
        journal,
        previous.head.as_ref(),
        JournalPosition::Pending,
    )?;
    if next.head.as_ref() != Some(&journal.next_head()?) {
        return Err(CompactRegistryStoreError::CheckpointConflict);
    }
    Ok(())
}

/// Storage failures fail closed; no registry-dependent API should be exposed until open/recovery
/// succeeds.
#[derive(Debug, Error)]
pub enum CompactRegistryStoreError {
    #[error("compact registry archive rejected durable state: {0}")]
    Archive(#[from] CompactRegistryArchiveError),
    #[error("encrypted storage rejected durable state: {0}")]
    Storage(#[from] StoreError),
    #[error("compact registry checkpoint is malformed")]
    InvalidCheckpoint,
    #[error("compact registry mutation journal is malformed")]
    InvalidJournal,
    #[error("compact registry checkpoint CAS or journal binding conflicts")]
    CheckpointConflict,
    #[error("another compact registry snapshot transition is in progress")]
    TransitionInProgress,
    #[error("compact registry synchronous cache exceeded its hard bound")]
    CacheBoundExceeded,
    #[error("compact registry preload exceeded its hard read bound")]
    ReadBoundExceeded,
    #[error("compact registry object readback did not authenticate")]
    ObjectAuthentication,
    #[error("compact registry checkpoint or journal serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_epoch_registry::RegistryHandoffStatement,
        deposit_index::{
            DepositIndexBuilder, DepositIndexError, DepositIndexHead, DepositIndexObjectId,
            DepositIndexReader,
        },
        deposit_ledger::{CertifiedLedgerEntry, LedgerStatement},
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    const PARTY: PartyId = PartyId(7);
    const SEED: [u8; 32] = [0x91; 32];

    fn wallet() -> DepositWalletId {
        DepositWalletId([0x92; 32])
    }

    fn index(address: u32) -> DepositSubaddressIndex {
        DepositSubaddressIndex::new(0, address).unwrap()
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn identities(epoch: u64) -> Vec<Identity> {
        (1_u16..=4)
            .map(|party| {
                let party = PartyId(party);
                let signing_seed = [u8::try_from(party.0).unwrap(); 32];
                Identity::from_test_secrets(
                    party,
                    epoch,
                    &signing_seed,
                    test_x25519_secret(party, epoch),
                )
                .unwrap()
            })
            .collect()
    }

    fn committee(epoch: u64, identities: &[Identity]) -> Committee {
        Committee {
            epoch,
            threshold: 2,
            members: identities
                .iter()
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

    fn authority(
        committee: Committee,
        activation: [u8; 32],
        certified_activation_root: [u8; 32],
    ) -> VerifiedRegistryHandoffTarget {
        VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            activation,
            certified_activation_root,
            wallet(),
            [0xa3; 32],
            [0xa4; 32],
        )
        .unwrap()
    }

    #[derive(Default)]
    struct PortableObjects {
        objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    }

    impl DepositIndexReader for PortableObjects {
        fn load_index_object(
            &self,
            id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(self.objects.get(&id).cloned())
        }
    }

    async fn open_empty(directory: &TempDir) -> CompactRegistryStore {
        CompactRegistryStore::open(
            directory.path(),
            PARTY,
            &SEED,
            CompactRegistryStoreCheckpoint::empty(wallet()).unwrap(),
        )
        .await
        .unwrap()
    }

    async fn prepare_genesis_for(
        store: &mut CompactRegistryStore,
    ) -> PreparedCompactRegistrySnapshot {
        let source = identities(0);
        let portable = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        let target = authority(committee(0, &source), [0x93; 32], [0xa1; 32]);
        store.prepare_genesis(&target, index(1), portable.digest()).await.unwrap()
    }

    fn handoff(
        head: &CompactRegistryArchiveHead,
        source: &[Identity],
        target: &VerifiedRegistryHandoffTarget,
    ) -> (RegistryHandoffCertificate, PortableDepositIndexHead) {
        let local_portable = DepositIndexHead::empty_portable(head.wallet(), index(1)).unwrap();
        let anchor = local_portable.portable_anchor().unwrap();
        let terminal_sequence = anchor.through_sequence().checked_add(1).unwrap();
        let previous_ledger_head = anchor.ledger_head();
        let next_index = anchor.next_index();
        let portable = PortableDepositIndexHead::from_head(&local_portable).unwrap();
        let statement = RegistryHandoffStatement::new(
            head.registry(),
            terminal_sequence,
            previous_ledger_head,
            portable.digest(),
            target,
            next_index,
        )
        .unwrap();
        let witnesses = source
            .iter()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        head.registry().active().committee(),
                        statement.session(),
                        None,
                        statement.terminal_sequence(),
                        statement.signing_payload(),
                    )
                    .unwrap()
            })
            .collect();
        let certificate = RegistryHandoffCertificate::new(statement, witnesses).unwrap();

        let ledger_statement = LedgerStatement::handoff(
            head.registry(),
            terminal_sequence,
            previous_ledger_head,
            portable.digest(),
            target,
            next_index,
        )
        .unwrap();
        let attestations = source
            .iter()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        head.registry().active().committee(),
                        ledger_statement.slot_session(),
                        None,
                        ledger_statement.sequence,
                        ledger_statement.attestation_payload().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let entry = CertifiedLedgerEntry { statement: ledger_statement, attestations };
        let portable_store = PortableObjects::default();
        let mut builder = DepositIndexBuilder::new(&portable_store, local_portable).unwrap();
        builder.apply_verified_active_entry(&entry, head.registry(), None).unwrap();
        let update = builder.finish().unwrap().unwrap();
        assert_eq!(
            update.next_head().portable_anchor().unwrap().through_sequence(),
            terminal_sequence
        );
        (certificate, portable)
    }

    #[tokio::test]
    async fn abort_preserves_a_preexisting_staged_registry_object() {
        let directory = TempDir::new().unwrap();
        let mut store = open_empty(&directory).await;
        let source = identities(0);
        let portable = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        let target = authority(committee(0, &source), [0x93; 32], [0xa1; 32]);
        let pending =
            prepare_compact_registry_genesis(&target, index(1), portable.digest()).unwrap();
        let preexisting = pending.staged_objects().first().unwrap();
        let preexisting_reference = preexisting.reference().storage_reference().unwrap();
        let preexisting_contents = preexisting.contents().to_vec();
        let staged_references = pending
            .staged_objects()
            .iter()
            .map(|object| object.reference().storage_reference().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            store
                .artifacts
                .create_artifact(
                    WalletId(wallet().0),
                    preexisting_reference.kind(),
                    &preexisting_contents,
                    &mut OsRng,
                )
                .await
                .unwrap(),
            preexisting_reference
        );

        let prepared = store.prepare_mutation(pending).await.unwrap();
        store.abort_prepared(&prepared).await.unwrap();

        assert_eq!(
            store.artifacts.load_artifact(preexisting_reference).await.unwrap().contents.as_bytes(),
            preexisting_contents.as_slice()
        );
        for reference in staged_references {
            assert_eq!(
                store.artifacts.artifact_path(reference).exists(),
                reference == preexisting_reference
            );
        }
    }

    #[tokio::test]
    async fn old_snapshot_finds_and_aborts_exact_pre_cas_objects_without_a_scan() {
        let directory = TempDir::new().unwrap();
        let old = CompactRegistryStoreCheckpoint::empty(wallet()).unwrap();
        let mut store =
            CompactRegistryStore::open(directory.path(), PARTY, &SEED, old.clone()).await.unwrap();
        let prepared = prepare_genesis_for(&mut store).await;
        let journal_path = store.protocol.deposit_index_journal_path(prepared.journal_key);
        let artifact_paths = prepared
            .staged_references
            .iter()
            .map(|reference| store.artifacts.artifact_path(reference.storage_reference().unwrap()))
            .collect::<Vec<_>>();
        assert!(journal_path.is_file());
        assert!(artifact_paths.iter().all(|path| path.is_file()));

        // Model a crash after a partial retry cleanup: absence of one exact object is idempotent.
        store
            .artifacts
            .remove_artifact_if_owned(
                prepared.staged_references[0].storage_reference().unwrap(),
                prepared.owner,
            )
            .await
            .unwrap();
        drop(prepared);
        drop(store);

        let recovered =
            CompactRegistryStore::open(directory.path(), PARTY, &SEED, old).await.unwrap();
        assert!(recovered.head().is_none());
        assert!(!recovered.checkpoint().has_recovery_journal());
        assert!(!journal_path.exists());
        assert!(artifact_paths.iter().all(|path| !path.exists()));
    }

    #[tokio::test]
    async fn target_snapshot_finishes_post_cas_recovery_and_direct_lookup() {
        let directory = TempDir::new().unwrap();
        let mut store = open_empty(&directory).await;
        let prepared = prepare_genesis_for(&mut store).await;
        let target = prepared.checkpoint().clone();
        assert_eq!(prepared.proposed_head().revision(), 0);
        assert_eq!(target.head().unwrap().revision(), 0);
        assert_eq!(prepared.journal_key.expected_revision, 0);
        let journal_path = store.protocol.deposit_index_journal_path(prepared.journal_key);
        drop(prepared);
        drop(store);

        let mut recovered =
            CompactRegistryStore::open(directory.path(), PARTY, &SEED, target).await.unwrap();
        assert!(!journal_path.exists());
        assert!(!recovered.checkpoint().has_recovery_journal());
        assert_eq!(recovered.head().unwrap().revision(), 0);
        assert_eq!(recovered.head().unwrap().registry().active_epoch(), 0);
        assert_eq!(recovered.lookup_epoch(0).await.unwrap().link().epoch(), 0);
        assert!(
            recovered.artifact_load_count()
                <= 2 * MAX_COMPACT_REGISTRY_STARTUP_ARTIFACT_READS
                    + MAX_COMPACT_REGISTRY_STARTUP_ARTIFACT_READS
        );
    }

    #[tokio::test]
    async fn exact_snapshot_readback_commits_append_and_historical_window() {
        let directory = TempDir::new().unwrap();
        let mut store = open_empty(&directory).await;
        let genesis = prepare_genesis_for(&mut store).await;
        let genesis_target = genesis.checkpoint().clone();
        store.commit_prepared(&genesis, &genesis_target).await.unwrap();

        let source = identities(0);
        let target_identities = identities(1);
        let target = authority(committee(1, &target_identities), [0x96; 32], [0xa2; 32]);
        let (certificate, portable) = handoff(store.head().unwrap(), &source, &target);
        let append = store.prepare_append(&target, certificate, &portable).await.unwrap();
        let append_target = append.checkpoint().clone();
        assert!(append_target.has_recovery_journal());
        store.commit_prepared(&append, &append_target).await.unwrap();
        assert!(!store.checkpoint().has_recovery_journal());
        assert_eq!(store.head().unwrap().registry().active_epoch(), 1);

        let historical = store.lookup_issuer_window(0).await.unwrap();
        assert_eq!(historical.issuer().epoch(), 0);
        assert!(historical.terminal().is_some());
        let active = store.lookup_issuer_window(1).await.unwrap();
        assert_eq!(active.issuer().epoch(), 1);
        assert!(active.terminal().is_none());
    }

    #[tokio::test]
    async fn compact_journal_key_is_domain_separated_from_deposit_index_journal() {
        let directory = TempDir::new().unwrap();
        let mut store = open_empty(&directory).await;
        let prepared = prepare_genesis_for(&mut store).await;
        let compact_key = prepared.journal_key;

        let deposit_head = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        let deposit_key = DepositIndexJournalKey {
            wallet_id: WalletId(wallet().0),
            scope: DepositIndexJournalScope::Portable,
            expected_revision: deposit_head.revision(),
            expected_head_digest: deposit_head.digest(),
        };
        assert_eq!(compact_key.expected_revision, deposit_key.expected_revision);
        assert_ne!(compact_key, deposit_key);
        assert_ne!(
            store.protocol.deposit_index_journal_path(compact_key),
            store.protocol.deposit_index_journal_path(deposit_key)
        );

        let deposit_bytes = b"domain-separated-deposit-index-journal/v1";
        store
            .protocol
            .save_deposit_index_journal(deposit_key, deposit_bytes, &mut OsRng)
            .await
            .unwrap();
        assert!(store.protocol.load_deposit_index_journal(compact_key).await.unwrap().is_some());
        assert_eq!(
            store
                .protocol
                .load_deposit_index_journal(deposit_key)
                .await
                .unwrap()
                .unwrap()
                .as_bytes(),
            deposit_bytes
        );

        store.abort_prepared(&prepared).await.unwrap();
        assert!(store.protocol.load_deposit_index_journal(compact_key).await.unwrap().is_none());
        assert!(store.protocol.load_deposit_index_journal(deposit_key).await.unwrap().is_some());
        store.protocol.destroy_deposit_index_journal(deposit_key, deposit_bytes).await.unwrap();
    }

    #[tokio::test]
    async fn wrong_snapshot_checkpoint_cannot_authorize_head_installation() {
        let directory = TempDir::new().unwrap();
        let mut store = open_empty(&directory).await;
        let old = store.checkpoint().clone();
        let prepared = prepare_genesis_for(&mut store).await;
        assert!(matches!(
            store.commit_prepared(&prepared, &old).await,
            Err(CompactRegistryStoreError::CheckpointConflict)
        ));
        store.abort_prepared(&prepared).await.unwrap();
        assert!(store.head().is_none());
    }
}
