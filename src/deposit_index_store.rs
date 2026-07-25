//! Crash-safe encrypted storage adapter for [`crate::deposit_index`].
//!
//! Index nodes and values are immutable [`WalletArtifactStore`] objects. The only mutable
//! authority is the deposit-service wallet snapshot, which embeds a compact
//! [`DepositIndexStoreCheckpoint`]. A transition is ordered as:
//!
//! 1. fsync an exact old-head-bound journal in [`ProtocolStore`];
//! 2. create every immutable object and authenticate an exact readback;
//! 3. install the reducer and target index heads in one wallet-snapshot CAS;
//! 4. remove only the journal's exact obsolete objects, then remove the exact journal.
//!
//! Before step 3 the old head remains authoritative. On restart it derives at most one pending
//! journal key per namespace and aborts that transition. After step 3 the snapshot retains the
//! exact journal key, so restart finishes committed cleanup without a directory or lifetime-tree
//! scan. The adapter is not returned to callers until this bounded recovery has completed.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::PartyId,
    compact_epoch_registry::CompactEpochRegistry,
    deposit_index::{
        DepositIndexBuilder, DepositIndexCommitStore, DepositIndexError, DepositIndexHead,
        DepositIndexNamespace, DepositIndexObjectId, DepositIndexReader, DepositIndexRecovery,
        DepositIndexUpdate, LocalDepositSafetyRecord, LocalSafetyQuery, LocalSafetyValue,
        MAX_DEPOSIT_INDEX_QUERY_READS, MAX_DEPOSIT_INDEX_UPDATE_VERIFICATION_READS,
        PortableAllocationQuery, PortableAllocationRecord, PortableStateQuery, PortableStateRecord,
        SignedDepositObservationSlot, SignedIndexCheckpointSlot, StagedDepositIndexUpdate,
        lookup_local_safety, lookup_portable_allocation, lookup_portable_state,
        missing_staged_verification_objects, next_local_safety_query_object,
        next_portable_query_object, next_portable_state_query_object,
    },
    deposit_index_checkpoint::VerifiedDepositIndexCheckpoint,
    deposit_ledger::{
        DepositObservationStatement, LedgerError,
        sign_deposit_observation_attestation_after_readback,
    },
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
    identity::{Identity, SignedEnvelope},
    storage::{
        DepositIndexJournalKey, DepositIndexJournalScope, MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
        ProtocolStore, StoreError, WalletArtifactOwner, WalletArtifactStore, WalletId,
    },
};

const DEPOSIT_INDEX_STORE_CHECKPOINT_VERSION: u16 = 1;
const DEPOSIT_INDEX_MUTATION_JOURNAL_VERSION: u16 = 1;
const MAX_INDEX_NAMESPACES: usize = 2;
const MAX_INDEX_CACHE_OBJECTS: usize = MAX_DEPOSIT_INDEX_UPDATE_VERIFICATION_READS;
const MAX_INDEX_CACHE_BYTES: usize = 256 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 4096;

/// Non-serializable authority for importing one n-f-certified portable logical head.
///
/// The exact local `DepositIndexHead` is reconstructed from the verified certificate rather than
/// accepted from sync bytes. The caller must still persist every semantically verified object
/// reachable from this head before installing the returned store checkpoint in the wallet
/// snapshot.
#[derive(Clone, Debug)]
pub struct VerifiedPortableIndexImport {
    head: DepositIndexHead,
}

impl VerifiedPortableIndexImport {
    /// Reconstruct the sole current-format local head certified by a verified quorum checkpoint.
    pub fn from_certified_checkpoint(
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<Self, DepositIndexStoreError> {
        let logical = checkpoint.resulting_head();
        let head =
            logical.to_index_head().map_err(|_| DepositIndexStoreError::InvalidPortableImport)?;
        if checkpoint.sequence() == 0
            || checkpoint.ledger_sequence() != logical.through_sequence()
            || checkpoint.ledger_decision() != logical.ledger_head()
            || checkpoint.context().wallet_id() != logical.wallet_id()
            || head.revision() != 0
            || head.root().is_none()
            || !logical.matches(&head).map_err(|_| DepositIndexStoreError::InvalidPortableImport)?
        {
            return Err(DepositIndexStoreError::InvalidPortableImport);
        }
        Ok(Self { head })
    }

    #[cfg(test)]
    fn from_authenticated_head_for_test(
        head: &DepositIndexHead,
    ) -> Result<Self, DepositIndexStoreError> {
        let logical = crate::deposit_index_checkpoint::PortableDepositIndexHead::from_head(head)
            .map_err(|_| DepositIndexStoreError::InvalidPortableImport)?;
        let head =
            logical.to_index_head().map_err(|_| DepositIndexStoreError::InvalidPortableImport)?;
        if logical.through_sequence() == 0 || head.root().is_none() {
            return Err(DepositIndexStoreError::InvalidPortableImport);
        }
        Ok(Self { head })
    }
}

/// Compact index authority embedded in the encrypted deposit-service snapshot.
///
/// `committed_journals` contains only transitions whose target heads are already installed by
/// that same wallet-snapshot CAS. It is deliberately tiny; the separately sealed journal retains
/// the bounded (up to 16 MiB) staged transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexStoreCheckpoint {
    version: u16,
    wallet: DepositWalletId,
    party: PartyId,
    portable: DepositIndexHead,
    local_safety: DepositIndexHead,
    committed_journals: BTreeMap<DepositIndexJournalScope, DepositIndexJournalKey>,
}

impl DepositIndexStoreCheckpoint {
    /// Construct the exact fresh-deployment roots.
    ///
    /// The portable namespace always starts before sequence one at the wallet-domain genesis
    /// ledger head. Callers cannot inject an arbitrary replay anchor through this constructor.
    pub fn empty(
        wallet: DepositWalletId,
        party: PartyId,
        first_index: DepositSubaddressIndex,
    ) -> Result<Self, DepositIndexStoreError> {
        let checkpoint = Self {
            version: DEPOSIT_INDEX_STORE_CHECKPOINT_VERSION,
            wallet,
            party,
            portable: DepositIndexHead::empty_portable(wallet, first_index)?,
            local_safety: DepositIndexHead::empty_local_safety(wallet, party)?,
            committed_journals: BTreeMap::new(),
        };
        checkpoint.validate_shape()?;
        Ok(checkpoint)
    }

    /// Replace only the portable authority of an exact fresh party checkpoint.
    ///
    /// This is a fresh-replica import, not a general head setter. The base must be settled and
    /// contain the canonical empty portable and party-local safety roots. Genesis needs no import:
    /// callers must retain the existing fresh checkpoint after comparing its logical portable
    /// head with the verified genesis advertisement.
    pub fn import_verified_portable(
        &self,
        import: &VerifiedPortableIndexImport,
    ) -> Result<Self, DepositIndexStoreError> {
        self.validate_shape()?;
        let anchor =
            self.portable.portable_anchor().ok_or(DepositIndexStoreError::InvalidPortableImport)?;
        let expected_portable = DepositIndexHead::empty_portable(self.wallet, anchor.next_index())?;
        let expected_local = DepositIndexHead::empty_local_safety(self.wallet, self.party)?;
        if !self.committed_journals.is_empty()
            || self.portable != expected_portable
            || self.local_safety != expected_local
            || import.head.namespace() != (DepositIndexNamespace::Portable { wallet: self.wallet })
            || import.head.revision() != 0
            || import.head.root().is_none()
            || import.head.portable_anchor().is_none_or(|imported| imported.through_sequence() == 0)
        {
            return Err(DepositIndexStoreError::InvalidPortableImport);
        }
        let checkpoint = Self {
            version: DEPOSIT_INDEX_STORE_CHECKPOINT_VERSION,
            wallet: self.wallet,
            party: self.party,
            portable: import.head.clone(),
            local_safety: self.local_safety.clone(),
            committed_journals: BTreeMap::new(),
        };
        checkpoint.validate_shape()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn party(&self) -> PartyId {
        self.party
    }

    #[must_use]
    pub const fn portable_head(&self) -> &DepositIndexHead {
        &self.portable
    }

    #[must_use]
    pub const fn local_safety_head(&self) -> &DepositIndexHead {
        &self.local_safety
    }

    #[must_use]
    pub fn has_recovery_journal(&self) -> bool {
        !self.committed_journals.is_empty()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexStoreError> {
        self.validate_shape()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositIndexStoreError::Serialization)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        let (checkpoint, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexStoreError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        checkpoint.validate_shape()?;
        if checkpoint.to_bytes()? != bytes {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        Ok(checkpoint)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = self.to_bytes().expect("a constructed deposit-index checkpoint is canonical");
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/deposit-index-store/checkpoint/v1");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    fn validate_shape(&self) -> Result<(), DepositIndexStoreError> {
        let portable_namespace = DepositIndexNamespace::Portable { wallet: self.wallet };
        let local_namespace =
            DepositIndexNamespace::LocalSafety { wallet: self.wallet, party: self.party };
        if self.version != DEPOSIT_INDEX_STORE_CHECKPOINT_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.party == PartyId(0)
            || self.portable.namespace() != portable_namespace
            || self.local_safety.namespace() != local_namespace
            || self.committed_journals.len() > MAX_INDEX_NAMESPACES
            || self.portable.root().is_some_and(|root| root.wallet_id() != self.wallet)
            || self.local_safety.root().is_some_and(|root| root.wallet_id() != self.wallet)
        {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        for (scope, key) in &self.committed_journals {
            key.validate()?;
            if key.wallet_id != WalletId(self.wallet.0)
                || key.scope != *scope
                || key.expected_revision.checked_add(1) != Some(self.head(*scope).revision())
            {
                return Err(DepositIndexStoreError::InvalidCheckpoint);
            }
        }
        Ok(())
    }

    fn head(&self, scope: DepositIndexJournalScope) -> &DepositIndexHead {
        match scope {
            DepositIndexJournalScope::Portable => &self.portable,
            DepositIndexJournalScope::LocalSafety => &self.local_safety,
        }
    }

    fn replace_head(&mut self, scope: DepositIndexJournalScope, head: DepositIndexHead) {
        match scope {
            DepositIndexJournalScope::Portable => self.portable = head,
            DepositIndexJournalScope::LocalSafety => self.local_safety = head,
        }
    }

    fn settled(mut self) -> Self {
        self.committed_journals.clear();
        self
    }

    fn validate_successor(&self, previous: &Self) -> Result<(), DepositIndexStoreError> {
        self.validate_shape()?;
        previous.validate_shape()?;
        if self.wallet != previous.wallet
            || self.party != previous.party
            || self.committed_journals.is_empty()
        {
            return Err(DepositIndexStoreError::CheckpointConflict);
        }
        for scope in [DepositIndexJournalScope::Portable, DepositIndexJournalScope::LocalSafety] {
            let changed = self.head(scope) != previous.head(scope);
            if changed != self.committed_journals.contains_key(&scope) {
                return Err(DepositIndexStoreError::CheckpointConflict);
            }
        }
        Ok(())
    }
}

/// Prepared material which must be installed only after its exact checkpoint was read back from
/// the deposit wallet snapshot.
#[derive(Debug)]
pub struct PreparedDepositIndexSnapshot {
    base_checkpoint_digest: [u8; 32],
    checkpoint: DepositIndexStoreCheckpoint,
    settled_checkpoint: DepositIndexStoreCheckpoint,
    journals: BTreeMap<DepositIndexJournalScope, PreparedJournal>,
}

impl PreparedDepositIndexSnapshot {
    #[must_use]
    pub const fn checkpoint(&self) -> &DepositIndexStoreCheckpoint {
        &self.checkpoint
    }

    /// Return the compact journal-free checkpoint after successful preparation cleanup.
    ///
    /// This is the form subsequent wallet snapshots must persist. The checkpoint carried by
    /// [`PreparedDepositIndexSnapshot`] remains intentionally unsettled so a crash immediately
    /// after its CAS can discover the exact cleanup journal.
    #[must_use]
    pub const fn settled_checkpoint(&self) -> &DepositIndexStoreCheckpoint {
        &self.settled_checkpoint
    }
}

#[derive(Debug)]
struct PreparedJournal {
    key: DepositIndexJournalKey,
    bytes: Vec<u8>,
    staged: StagedDepositIndexUpdate,
    owner: WalletArtifactOwner,
}

/// Bounded synchronous cache in front of async encrypted artifact I/O.
pub struct DepositIndexStore {
    protocol: Arc<ProtocolStore>,
    artifacts: WalletArtifactStore,
    checkpoint: DepositIndexStoreCheckpoint,
    heads: BTreeMap<DepositIndexNamespace, DepositIndexHead>,
    cache: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    cache_bytes: usize,
    active_pins: BTreeSet<DepositIndexObjectId>,
    pending_removals: BTreeSet<DepositIndexObjectId>,
    prepared_digest: Option<[u8; 32]>,
    artifact_loads: u64,
}

/// Private-constructor proof that one exact checkpoint signing slot is present under the
/// wallet-snapshot-authoritative party-local index head.
///
/// The token is intentionally non-serializable. Only [`DepositIndexStore`] can construct it after
/// an exact durable-head readback, so checkpoint code cannot turn a merely staged mutation into a
/// signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignedIndexCheckpointSlot {
    wallet: DepositWalletId,
    party: PartyId,
    slot: SignedIndexCheckpointSlot,
    authoritative_head: [u8; 32],
}

impl VerifiedSignedIndexCheckpointSlot {
    /// Exact pre-signing reservation time authenticated from the committed local-safety slot.
    pub(crate) const fn reserved_at(&self) -> u64 {
        self.slot.reserved_at()
    }

    pub(crate) fn authorizes(
        &self,
        wallet: DepositWalletId,
        party: PartyId,
        slot: SignedIndexCheckpointSlot,
    ) -> bool {
        self.wallet == wallet
            && self.party == party
            && self.slot == slot
            && self.authoritative_head != [0; 32]
    }
}

/// Private-constructor proof that both exact observation reservations are present under the
/// wallet-snapshot-authoritative settled local-safety head.
///
/// The token is intentionally non-serializable and cannot be reconstructed from staged mutation
/// bytes. The ledger signer accepts it only when the wallet, party, statement fact, output, and
/// one-time key all match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedSignedDepositObservationSlot {
    wallet: DepositWalletId,
    party: PartyId,
    slot: SignedDepositObservationSlot,
    authoritative_head: [u8; 32],
}

impl VerifiedSignedDepositObservationSlot {
    pub(crate) fn authorizes(
        &self,
        wallet: DepositWalletId,
        party: PartyId,
        statement: &DepositObservationStatement,
    ) -> bool {
        self.wallet == wallet
            && self.party == party
            && self.slot.matches_statement(statement)
            && self.authoritative_head != [0; 32]
    }
}

impl std::fmt::Debug for DepositIndexStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DepositIndexStore")
            .field("wallet", &self.checkpoint.wallet)
            .field("party", &self.checkpoint.party)
            .field("cache_objects", &self.cache.len())
            .field("cache_bytes", &self.cache_bytes)
            .field("prepared", &self.prepared_digest.is_some())
            .finish_non_exhaustive()
    }
}

impl DepositIndexStore {
    /// Open with stores shared by the party runtime. No API becomes available until both committed
    /// and pre-CAS crash windows have been resolved.
    pub async fn open_with_stores(
        protocol: Arc<ProtocolStore>,
        artifacts: WalletArtifactStore,
        checkpoint: DepositIndexStoreCheckpoint,
    ) -> Result<Self, DepositIndexStoreError> {
        checkpoint.validate_shape()?;
        let mut store = Self {
            protocol,
            artifacts,
            heads: BTreeMap::from([
                (checkpoint.portable.namespace(), checkpoint.portable.clone()),
                (checkpoint.local_safety.namespace(), checkpoint.local_safety.clone()),
            ]),
            checkpoint,
            cache: BTreeMap::new(),
            cache_bytes: 0,
            active_pins: BTreeSet::new(),
            pending_removals: BTreeSet::new(),
            prepared_digest: None,
            artifact_loads: 0,
        };
        store.recover_startup().await?;
        Ok(store)
    }

    /// Convenience constructor for a runtime which exclusively owns this protocol-store handle.
    /// A server which already has a `ProtocolStore` should use [`Self::open_with_stores`] and share
    /// the existing instance.
    pub async fn open(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
        checkpoint: DepositIndexStoreCheckpoint,
    ) -> Result<Self, DepositIndexStoreError> {
        if checkpoint.party != party {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        let directory = directory.into();
        let protocol = Arc::new(ProtocolStore::new(&directory, party, identity_seed)?);
        let artifacts = WalletArtifactStore::new(directory, party, identity_seed)?;
        Self::open_with_stores(protocol, artifacts, checkpoint).await
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &DepositIndexStoreCheckpoint {
        &self.checkpoint
    }

    #[must_use]
    pub fn portable_head(&self) -> &DepositIndexHead {
        &self.checkpoint.portable
    }

    #[must_use]
    pub fn local_safety_head(&self) -> &DepositIndexHead {
        &self.checkpoint.local_safety
    }

    #[must_use]
    pub const fn artifact_load_count(&self) -> u64 {
        self.artifact_loads
    }

    /// Discard query working data while retaining at most the two authenticated roots.
    pub fn reset_bounded_cache(&mut self) -> Result<(), DepositIndexStoreError> {
        if self.prepared_digest.is_some() {
            return Err(DepositIndexStoreError::TransitionInProgress);
        }
        let roots = self.heads.values().filter_map(DepositIndexHead::root).collect::<BTreeSet<_>>();
        self.cache.retain(|id, _| roots.contains(id));
        self.cache_bytes = self.cache.values().map(Vec::len).sum();
        Ok(())
    }

    /// Async-load one bounded portable Merkle path into the synchronous core cache.
    pub async fn preload_portable_query(
        &mut self,
        query: &PortableAllocationQuery,
    ) -> Result<(), DepositIndexStoreError> {
        let head = self.checkpoint.portable.clone();
        for _ in 0..MAX_DEPOSIT_INDEX_QUERY_READS {
            let Some(id) = next_portable_query_object(self, &head, query)? else {
                return Ok(());
            };
            self.load_exact_artifact(id).await?;
        }
        if next_portable_query_object(self, &head, query)?.is_some() {
            return Err(DepositIndexStoreError::ReadBoundExceeded);
        }
        Ok(())
    }

    /// Async-load one bounded portable ledger/terminal-state path.
    pub async fn preload_portable_state_query(
        &mut self,
        query: PortableStateQuery,
    ) -> Result<(), DepositIndexStoreError> {
        let head = self.checkpoint.portable.clone();
        for _ in 0..MAX_DEPOSIT_INDEX_QUERY_READS {
            let Some(id) = next_portable_state_query_object(self, &head, query)? else {
                return Ok(());
            };
            self.load_exact_artifact(id).await?;
        }
        if next_portable_state_query_object(self, &head, query)?.is_some() {
            return Err(DepositIndexStoreError::ReadBoundExceeded);
        }
        Ok(())
    }

    /// Async-load one bounded party-local safety Merkle path.
    pub async fn preload_local_safety_query(
        &mut self,
        query: LocalSafetyQuery,
    ) -> Result<(), DepositIndexStoreError> {
        let head = self.checkpoint.local_safety.clone();
        for _ in 0..MAX_DEPOSIT_INDEX_QUERY_READS {
            let Some(id) = next_local_safety_query_object(self, &head, query)? else {
                return Ok(());
            };
            self.load_exact_artifact(id).await?;
        }
        if next_local_safety_query_object(self, &head, query)?.is_some() {
            return Err(DepositIndexStoreError::ReadBoundExceeded);
        }
        Ok(())
    }

    /// Authenticated direct portable lookup with no allocation enumeration.
    pub async fn lookup_portable(
        &mut self,
        query: &PortableAllocationQuery,
    ) -> Result<Option<PortableAllocationRecord>, DepositIndexStoreError> {
        self.reset_bounded_cache()?;
        self.preload_portable_query(query).await?;
        Ok(lookup_portable_allocation(self, &self.checkpoint.portable, query)?)
    }

    /// Authenticated direct portable ledger/terminal lookup with no history enumeration.
    pub async fn lookup_portable_state(
        &mut self,
        query: PortableStateQuery,
    ) -> Result<Option<PortableStateRecord>, DepositIndexStoreError> {
        self.reset_bounded_cache()?;
        self.preload_portable_state_query(query).await?;
        Ok(lookup_portable_state(self, &self.checkpoint.portable, query)?)
    }

    /// Authenticated direct local-safety lookup.
    pub async fn lookup_local_safety(
        &mut self,
        query: LocalSafetyQuery,
    ) -> Result<Option<LocalDepositSafetyRecord>, DepositIndexStoreError> {
        self.reset_bounded_cache()?;
        self.preload_local_safety_query(query).await?;
        Ok(lookup_local_safety(self, &self.checkpoint.local_safety, query)?)
    }

    /// Authenticate the exact retained checkpoint tombstone only after its local-safety head is
    /// the journal-free authority installed by the enclosing wallet-snapshot CAS.
    ///
    /// The caller supplies only the immutable sequence key. The returned token retains the exact
    /// persisted reservation time and decision fields; checkpoint signing then compares all of
    /// them against its independently reconstructed statement. This makes restart retries reuse
    /// the original pre-deadline reservation instead of inventing a new timestamp.
    pub async fn authenticate_signed_index_checkpoint_slot(
        &mut self,
        checkpoint_sequence: u64,
    ) -> Result<VerifiedSignedIndexCheckpointSlot, DepositIndexStoreError> {
        self.reset_bounded_cache()?;
        if self.checkpoint.has_recovery_journal()
            || self.heads.get(&self.checkpoint.local_safety.namespace())
                != Some(&self.checkpoint.local_safety)
        {
            return Err(DepositIndexStoreError::UncommittedSigningSlot);
        }
        let query = LocalSafetyQuery::SignedIndexCheckpointSlot(checkpoint_sequence);
        self.preload_local_safety_query(query).await?;
        let authoritative = self.checkpoint.local_safety.clone();
        let Some(record) = lookup_local_safety(self, &authoritative, query)? else {
            return Err(DepositIndexStoreError::UncommittedSigningSlot);
        };
        let LocalSafetyValue::SignedIndexCheckpointSlot(found) = record.value() else {
            return Err(DepositIndexStoreError::UncommittedSigningSlot);
        };
        found.validate()?;
        Ok(VerifiedSignedIndexCheckpointSlot {
            wallet: self.checkpoint.wallet,
            party: self.checkpoint.party,
            slot: *found,
            authoritative_head: authoritative.digest(),
        })
    }

    /// Sign an observation only after exact paired-slot readback from the settled wallet snapshot.
    ///
    /// A prepared transition and a recovery-journal checkpoint are both rejected: immutable
    /// objects which have merely been staged never authorize a signature.
    pub async fn sign_deposit_observation_attestation(
        &mut self,
        identity: &Identity,
        registry: &CompactEpochRegistry,
        statement: &DepositObservationStatement,
    ) -> Result<SignedEnvelope, DepositIndexStoreError> {
        statement.validate_active(registry)?;
        let authorization = self.authenticate_signed_deposit_observation_slot(statement).await?;
        Ok(sign_deposit_observation_attestation_after_readback(
            identity,
            registry,
            statement,
            &authorization,
        )?)
    }

    async fn authenticate_signed_deposit_observation_slot(
        &mut self,
        statement: &DepositObservationStatement,
    ) -> Result<VerifiedSignedDepositObservationSlot, DepositIndexStoreError> {
        self.reset_bounded_cache()?;
        if self.checkpoint.has_recovery_journal()
            || self.heads.get(&self.checkpoint.local_safety.namespace())
                != Some(&self.checkpoint.local_safety)
            || statement.wallet_id() != self.checkpoint.wallet
        {
            return Err(DepositIndexStoreError::UncommittedDepositObservationSlot);
        }

        let output_query = LocalSafetyQuery::SignedDepositObservationOutput(statement.output());
        let key_query = LocalSafetyQuery::SignedDepositObservationKey(statement.output_key());
        self.preload_local_safety_query(output_query).await?;
        self.preload_local_safety_query(key_query).await?;
        let authoritative = self.checkpoint.local_safety.clone();
        let Some(output_record) = lookup_local_safety(self, &authoritative, output_query)? else {
            return Err(DepositIndexStoreError::UncommittedDepositObservationSlot);
        };
        let Some(key_record) = lookup_local_safety(self, &authoritative, key_query)? else {
            return Err(DepositIndexStoreError::UncommittedDepositObservationSlot);
        };
        if output_record.wallet_id() != self.checkpoint.wallet
            || output_record.party() != self.checkpoint.party
            || key_record.wallet_id() != self.checkpoint.wallet
            || key_record.party() != self.checkpoint.party
        {
            return Err(DepositIndexStoreError::UncommittedDepositObservationSlot);
        }
        let (
            LocalSafetyValue::SignedDepositObservationOutput(output_slot),
            LocalSafetyValue::SignedDepositObservationKey(key_slot),
        ) = (output_record.value(), key_record.value())
        else {
            return Err(DepositIndexStoreError::UncommittedDepositObservationSlot);
        };
        if output_slot != key_slot || !output_slot.matches_statement(statement) {
            return Err(DepositIndexStoreError::UncommittedDepositObservationSlot);
        }
        Ok(VerifiedSignedDepositObservationSlot {
            wallet: self.checkpoint.wallet,
            party: self.checkpoint.party,
            slot: *output_slot,
            authoritative_head: authoritative.digest(),
        })
    }

    /// Fsync journals and immutable artifacts while the old heads remain authoritative.
    ///
    /// The returned checkpoint must be included in the exact deposit-service snapshot which also
    /// contains the reducer changes. Only its authenticated readback may be passed to
    /// [`Self::commit_prepared`].
    pub async fn prepare_snapshot(
        &mut self,
        updates: Vec<DepositIndexUpdate>,
    ) -> Result<PreparedDepositIndexSnapshot, DepositIndexStoreError> {
        if self.prepared_digest.is_some()
            || updates.is_empty()
            || updates.len() > MAX_INDEX_NAMESPACES
        {
            return Err(DepositIndexStoreError::TransitionInProgress);
        }
        let base_checkpoint_digest = self.checkpoint.digest();
        let mut prepared_journals = BTreeMap::new();
        let mut scopes = BTreeSet::new();
        for update in updates {
            let scope = scope_for_namespace(update.expected_head().namespace())?;
            if !scopes.insert(scope)
                || self.heads.get(&update.expected_head().namespace())
                    != Some(update.expected_head())
            {
                return Err(DepositIndexStoreError::CheckpointConflict);
            }
            let staged = update.stage(self)?;
            self.preload_staged(&staged, false).await?;
            staged.verify_staged(self)?;
            let owner = WalletArtifactOwner::random(&mut OsRng);
            let bytes = DepositIndexMutationJournal::new(owner, staged.clone()).to_bytes()?;
            let key = journal_key(update.expected_head(), scope)?;
            prepared_journals.insert(scope, PreparedJournal { key, bytes, staged, owner });
        }

        let mut saved = Vec::new();
        for journal in prepared_journals.values() {
            if let Err(error) = self
                .protocol
                .save_deposit_index_journal(journal.key, &journal.bytes, &mut OsRng)
                .await
            {
                self.destroy_saved_journals(&prepared_journals, &saved).await?;
                return Err(error.into());
            }
            saved.push(journal.key.scope);
        }
        for journal in prepared_journals.values() {
            if let Err(error) =
                self.materialize_update(journal.staged.update(), journal.owner).await
            {
                self.abort_materialized(&prepared_journals).await?;
                return Err(error);
            }
        }

        let mut checkpoint = self.checkpoint.clone().settled();
        for (scope, journal) in &prepared_journals {
            checkpoint.replace_head(*scope, journal.staged.update().next_head().clone());
            checkpoint.committed_journals.insert(*scope, journal.key);
        }
        checkpoint.validate_successor(&self.checkpoint.clone().settled())?;
        self.prepared_digest = Some(checkpoint.digest());
        let settled_checkpoint = checkpoint.clone().settled();
        Ok(PreparedDepositIndexSnapshot {
            base_checkpoint_digest,
            checkpoint,
            settled_checkpoint,
            journals: prepared_journals,
        })
    }

    /// Abort after the wallet-snapshot CAS failed. Cleanup uses only exact journal object lists.
    pub async fn abort_prepared(
        &mut self,
        prepared: &PreparedDepositIndexSnapshot,
    ) -> Result<(), DepositIndexStoreError> {
        self.require_prepared(prepared)?;
        self.abort_materialized(&prepared.journals).await?;
        self.prepared_digest = None;
        self.active_pins.clear();
        self.pending_removals.clear();
        self.reset_bounded_cache()?;
        Ok(())
    }

    /// Finish a transition only after the exact target checkpoint was authenticated from the
    /// wallet-snapshot CAS.
    pub async fn commit_prepared(
        &mut self,
        prepared: &PreparedDepositIndexSnapshot,
        authenticated_checkpoint: &DepositIndexStoreCheckpoint,
    ) -> Result<(), DepositIndexStoreError> {
        self.require_prepared(prepared)?;
        if authenticated_checkpoint != &prepared.checkpoint
            || prepared.base_checkpoint_digest != self.checkpoint.digest()
        {
            return Err(DepositIndexStoreError::CheckpointConflict);
        }
        authenticated_checkpoint.validate_successor(&self.checkpoint.clone().settled())?;
        self.install_heads(authenticated_checkpoint);
        self.active_pins = prepared
            .journals
            .values()
            .flat_map(|journal| journal.staged.update().staged_objects().map(|(id, _)| id))
            .collect();
        for journal in prepared.journals.values() {
            self.preload_staged(&journal.staged, true).await?;
            if journal.staged.recover(self)? != DepositIndexRecovery::Committed {
                return Err(DepositIndexStoreError::CheckpointConflict);
            }
        }
        self.flush_pending_removals().await?;
        for journal in prepared.journals.values() {
            self.release_materialized(journal.staged.update(), journal.owner).await?;
            self.protocol.destroy_deposit_index_journal(journal.key, &journal.bytes).await?;
        }
        self.checkpoint = authenticated_checkpoint.clone().settled();
        self.prepared_digest = None;
        self.active_pins.clear();
        self.reset_bounded_cache()?;
        Ok(())
    }

    async fn recover_startup(&mut self) -> Result<(), DepositIndexStoreError> {
        // Crash window B: the wallet snapshot installed the target head and retained the exact
        // old-head journal key. Missing means cleanup completed before the crash.
        let committed = self.checkpoint.committed_journals.clone();
        for (scope, key) in committed {
            if let Some(blob) = self.protocol.load_deposit_index_journal(key).await? {
                let bytes = blob.into_bytes();
                let journal = DepositIndexMutationJournal::from_bytes(&bytes)?;
                let staged = journal.staged();
                validate_journal_binding(
                    key,
                    staged,
                    self.checkpoint.head(scope),
                    JournalPosition::Committed,
                )?;
                self.materialize_update(staged.update(), journal.owner()).await?;
                self.active_pins = staged.update().staged_objects().map(|(id, _)| id).collect();
                self.preload_staged(staged, true).await?;
                if staged.recover(self)? != DepositIndexRecovery::Committed {
                    return Err(DepositIndexStoreError::CheckpointConflict);
                }
                self.flush_pending_removals().await?;
                self.release_materialized(staged.update(), journal.owner()).await?;
                self.protocol.destroy_deposit_index_journal(key, &bytes).await?;
                self.active_pins.clear();
            }
        }
        self.checkpoint = self.checkpoint.clone().settled();

        // Crash window A: journals/artifacts exist but the snapshot still authenticates the old
        // head. Probe exactly one derivable key per scope, verify it, and abort its exact objects.
        for scope in [DepositIndexJournalScope::Portable, DepositIndexJournalScope::LocalSafety] {
            let key = journal_key(self.checkpoint.head(scope), scope)?;
            if let Some(blob) = self.protocol.load_deposit_index_journal(key).await? {
                let bytes = blob.into_bytes();
                let journal = DepositIndexMutationJournal::from_bytes(&bytes)?;
                let staged = journal.staged();
                validate_journal_binding(
                    key,
                    staged,
                    self.checkpoint.head(scope),
                    JournalPosition::Pending,
                )?;
                self.materialize_update(staged.update(), journal.owner()).await?;
                self.preload_staged(staged, false).await?;
                staged.verify_staged(self)?;
                for (id, _) in staged.update().staged_objects() {
                    if !self.index_object_is_pinned(id)? {
                        self.artifacts
                            .remove_artifact_if_owned(id.storage_reference(), journal.owner())
                            .await?;
                    } else {
                        self.artifacts
                            .release_artifact_ownership(id.storage_reference(), journal.owner())
                            .await?;
                    }
                    self.remove_cached(id);
                }
                self.protocol.destroy_deposit_index_journal(key, &bytes).await?;
            }
        }
        self.validate_current_roots().await?;
        self.reset_bounded_cache()?;
        Ok(())
    }

    async fn validate_current_roots(&mut self) -> Result<(), DepositIndexStoreError> {
        let heads = self.heads.values().cloned().collect::<Vec<_>>();
        for head in heads {
            if let Some(root) = head.root() {
                self.load_exact_artifact(root).await?;
            }
            drop(DepositIndexBuilder::new(self, head)?);
        }
        Ok(())
    }

    async fn preload_staged(
        &mut self,
        staged: &StagedDepositIndexUpdate,
        committed: bool,
    ) -> Result<(), DepositIndexStoreError> {
        let missing = missing_staged_verification_objects(self, staged, committed)?;
        if missing.len() > MAX_DEPOSIT_INDEX_UPDATE_VERIFICATION_READS {
            return Err(DepositIndexStoreError::ReadBoundExceeded);
        }
        for id in missing {
            self.load_exact_artifact(id).await?;
        }
        if !missing_staged_verification_objects(self, staged, committed)?.is_empty() {
            return Err(DepositIndexStoreError::ReadBoundExceeded);
        }
        Ok(())
    }

    async fn load_exact_artifact(
        &mut self,
        id: DepositIndexObjectId,
    ) -> Result<(), DepositIndexStoreError> {
        if self.cache.contains_key(&id) {
            return Ok(());
        }
        if id.wallet_id() != self.checkpoint.wallet {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        let artifact = self.artifacts.load_artifact(id.storage_reference()).await?;
        self.artifact_loads = self.artifact_loads.saturating_add(1);
        self.insert_cache(id, artifact.contents.into_bytes())
    }

    async fn materialize_update(
        &mut self,
        update: &DepositIndexUpdate,
        owner: WalletArtifactOwner,
    ) -> Result<(), DepositIndexStoreError> {
        for (id, bytes) in update.staged_objects() {
            let (reference, _ownership) = self
                .artifacts
                .create_artifact_owned(
                    owner,
                    WalletId(self.checkpoint.wallet.0),
                    id.storage_reference().kind(),
                    bytes,
                    &mut OsRng,
                )
                .await?;
            if reference != id.storage_reference() {
                return Err(DepositIndexStoreError::ObjectAuthentication);
            }
            let readback = self.artifacts.load_artifact_owned(reference, owner).await?;
            self.artifact_loads = self.artifact_loads.saturating_add(1);
            if readback.contents.as_bytes() != bytes {
                return Err(DepositIndexStoreError::ObjectAuthentication);
            }
            self.insert_cache(id, readback.contents.into_bytes())?;
        }
        Ok(())
    }

    async fn release_materialized(
        &self,
        update: &DepositIndexUpdate,
        owner: WalletArtifactOwner,
    ) -> Result<(), DepositIndexStoreError> {
        for (id, _) in update.staged_objects() {
            self.artifacts.release_artifact_ownership(id.storage_reference(), owner).await?;
        }
        Ok(())
    }

    async fn abort_materialized(
        &mut self,
        journals: &BTreeMap<DepositIndexJournalScope, PreparedJournal>,
    ) -> Result<(), DepositIndexStoreError> {
        for journal in journals.values() {
            for (id, _) in journal.staged.update().staged_objects() {
                if !self.index_object_is_pinned(id)? {
                    self.artifacts
                        .remove_artifact_if_owned(id.storage_reference(), journal.owner)
                        .await?;
                } else {
                    self.artifacts
                        .release_artifact_ownership(id.storage_reference(), journal.owner)
                        .await?;
                }
                self.remove_cached(id);
            }
            self.protocol.destroy_deposit_index_journal(journal.key, &journal.bytes).await?;
        }
        Ok(())
    }

    async fn destroy_saved_journals(
        &self,
        journals: &BTreeMap<DepositIndexJournalScope, PreparedJournal>,
        saved: &[DepositIndexJournalScope],
    ) -> Result<(), DepositIndexStoreError> {
        for scope in saved {
            let journal = journals.get(scope).ok_or(DepositIndexStoreError::InvalidCheckpoint)?;
            self.protocol.destroy_deposit_index_journal(journal.key, &journal.bytes).await?;
        }
        Ok(())
    }

    async fn flush_pending_removals(&mut self) -> Result<(), DepositIndexStoreError> {
        let removals = std::mem::take(&mut self.pending_removals);
        for id in removals {
            self.artifacts.remove_artifact(id.storage_reference()).await?;
            self.remove_cached(id);
        }
        Ok(())
    }

    fn require_prepared(
        &self,
        prepared: &PreparedDepositIndexSnapshot,
    ) -> Result<(), DepositIndexStoreError> {
        if self.prepared_digest != Some(prepared.checkpoint.digest()) {
            return Err(DepositIndexStoreError::CheckpointConflict);
        }
        Ok(())
    }

    fn install_heads(&mut self, checkpoint: &DepositIndexStoreCheckpoint) {
        self.heads.insert(checkpoint.portable.namespace(), checkpoint.portable.clone());
        self.heads.insert(checkpoint.local_safety.namespace(), checkpoint.local_safety.clone());
    }

    fn insert_cache(
        &mut self,
        id: DepositIndexObjectId,
        bytes: Vec<u8>,
    ) -> Result<(), DepositIndexStoreError> {
        id.storage_reference().verify_contents(&bytes)?;
        if let Some(existing) = self.cache.get(&id) {
            return if existing == &bytes {
                Ok(())
            } else {
                Err(DepositIndexStoreError::ObjectAuthentication)
            };
        }
        let next_bytes = self
            .cache_bytes
            .checked_add(bytes.len())
            .ok_or(DepositIndexStoreError::CacheBoundExceeded)?;
        if self.cache.len() == MAX_INDEX_CACHE_OBJECTS || next_bytes > MAX_INDEX_CACHE_BYTES {
            return Err(DepositIndexStoreError::CacheBoundExceeded);
        }
        self.cache_bytes = next_bytes;
        self.cache.insert(id, bytes);
        Ok(())
    }

    fn remove_cached(&mut self, id: DepositIndexObjectId) {
        if let Some(bytes) = self.cache.remove(&id) {
            self.cache_bytes = self.cache_bytes.saturating_sub(bytes.len());
        }
    }
}

impl DepositIndexReader for DepositIndexStore {
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        Ok(self.cache.get(&id).cloned())
    }
}

impl DepositIndexCommitStore for DepositIndexStore {
    fn load_index_head(
        &self,
        namespace: DepositIndexNamespace,
    ) -> Result<Option<DepositIndexHead>, DepositIndexError> {
        Ok(self.heads.get(&namespace).cloned())
    }

    fn stage_index_object(
        &mut self,
        id: DepositIndexObjectId,
        bytes: &[u8],
    ) -> Result<bool, DepositIndexError> {
        id.storage_reference().verify_contents(bytes)?;
        if let Some(existing) = self.cache.get(&id) {
            if existing != bytes {
                return Err(DepositIndexError::ObjectAuthentication);
            }
            return Ok(false);
        }
        self.insert_cache(id, bytes.to_vec()).map_err(store_error_into_index)?;
        Ok(true)
    }

    fn compare_and_swap_index_head(
        &mut self,
        expected: &DepositIndexHead,
        replacement: &DepositIndexHead,
    ) -> Result<bool, DepositIndexError> {
        if expected.namespace() != replacement.namespace()
            || self.heads.get(&expected.namespace()) != Some(expected)
        {
            return Ok(false);
        }
        self.heads.insert(replacement.namespace(), replacement.clone());
        Ok(true)
    }

    fn remove_index_object(&mut self, id: DepositIndexObjectId) -> Result<(), DepositIndexError> {
        self.pending_removals.insert(id);
        Ok(())
    }

    fn index_object_is_pinned(&self, id: DepositIndexObjectId) -> Result<bool, DepositIndexError> {
        Ok(self.active_pins.contains(&id)
            || self.heads.values().any(|head| head.root() == Some(id)))
    }
}

/// Store-level envelope which binds cleanup ownership to the exact journal before any immutable
/// object is reserved or written.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositIndexMutationJournal {
    version: u16,
    owner: WalletArtifactOwner,
    staged: StagedDepositIndexUpdate,
}

impl DepositIndexMutationJournal {
    fn new(owner: WalletArtifactOwner, staged: StagedDepositIndexUpdate) -> Self {
        Self { version: DEPOSIT_INDEX_MUTATION_JOURNAL_VERSION, owner, staged }
    }

    fn validate(&self) -> Result<(), DepositIndexStoreError> {
        self.owner.validate()?;
        self.staged.to_bytes()?;
        if self.version != DEPOSIT_INDEX_MUTATION_JOURNAL_VERSION {
            return Err(DepositIndexStoreError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexStoreError> {
        self.validate()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositIndexStoreError::Serialization)?;
        if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_JOURNAL_BYTES {
            return Err(DepositIndexStoreError::Serialization);
        }
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_JOURNAL_BYTES {
            return Err(DepositIndexStoreError::Serialization);
        }
        let (journal, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexStoreError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexStoreError::Serialization);
        }
        journal.validate()?;
        if journal.to_bytes()? != bytes {
            return Err(DepositIndexStoreError::Serialization);
        }
        Ok(journal)
    }

    const fn owner(&self) -> WalletArtifactOwner {
        self.owner
    }

    const fn staged(&self) -> &StagedDepositIndexUpdate {
        &self.staged
    }
}

fn scope_for_namespace(
    namespace: DepositIndexNamespace,
) -> Result<DepositIndexJournalScope, DepositIndexStoreError> {
    match namespace {
        DepositIndexNamespace::Portable { .. } => Ok(DepositIndexJournalScope::Portable),
        DepositIndexNamespace::LocalSafety { .. } => Ok(DepositIndexJournalScope::LocalSafety),
    }
}

fn journal_key(
    head: &DepositIndexHead,
    scope: DepositIndexJournalScope,
) -> Result<DepositIndexJournalKey, DepositIndexStoreError> {
    if scope_for_namespace(head.namespace())? != scope {
        return Err(DepositIndexStoreError::InvalidCheckpoint);
    }
    let key = DepositIndexJournalKey {
        wallet_id: WalletId(head.namespace().wallet().0),
        scope,
        expected_revision: head.revision(),
        expected_head_digest: head.digest(),
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
    staged: &StagedDepositIndexUpdate,
    authoritative: &DepositIndexHead,
    position: JournalPosition,
) -> Result<(), DepositIndexStoreError> {
    let expected = staged.update().expected_head();
    let next = staged.update().next_head();
    if journal_key(expected, key.scope)? != key
        || match position {
            JournalPosition::Pending => authoritative != expected,
            JournalPosition::Committed => authoritative != next,
        }
    {
        return Err(DepositIndexStoreError::CheckpointConflict);
    }
    Ok(())
}

fn store_error_into_index(error: DepositIndexStoreError) -> DepositIndexError {
    match error {
        DepositIndexStoreError::Index(error) => error,
        DepositIndexStoreError::Storage(error) => DepositIndexError::Store(error),
        _ => DepositIndexError::UpdateTooLarge,
    }
}

/// Storage failures are fail-closed; callers must not expose deposit APIs until recovery succeeds.
#[derive(Debug, Error)]
pub enum DepositIndexStoreError {
    #[error("deposit index core rejected durable state: {0}")]
    Index(#[from] DepositIndexError),
    #[error("deposit ledger rejected observation signing: {0}")]
    Ledger(#[from] LedgerError),
    #[error("encrypted storage rejected durable state: {0}")]
    Storage(#[from] StoreError),
    #[error("deposit index checkpoint is malformed")]
    InvalidCheckpoint,
    #[error("verified portable index import is invalid for this fresh party checkpoint")]
    InvalidPortableImport,
    #[error("deposit index checkpoint CAS or journal binding conflicts")]
    CheckpointConflict,
    #[error("another deposit index snapshot transition is already in progress")]
    TransitionInProgress,
    #[error("deposit index cache object or byte bound was exceeded")]
    CacheBoundExceeded,
    #[error("deposit index preload exceeded its hard read bound")]
    ReadBoundExceeded,
    #[error("deposit index object readback did not authenticate")]
    ObjectAuthentication,
    #[error("checkpoint signing slot is not present under the committed wallet-snapshot head")]
    UncommittedSigningSlot,
    #[error(
        "deposit observation slots are not both present under the committed wallet-snapshot head"
    )]
    UncommittedDepositObservationSlot,
    #[error("deposit index checkpoint serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_registry_archive::prepare_compact_registry_genesis,
        config::NetworkKind,
        deposit_index::LocalSafetyQuery,
        deposit_ledger::{
            CertifiedLedgerEntry, LedgerRequestId, LedgerStatement, RequestBinding,
            genesis_head as ledger_genesis_head,
        },
        deposit_wallet::{
            ChainPoint, DepositAddressDeriver, DepositSubaddressIndex, WalletOutputId,
        },
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    const PARTY: PartyId = PartyId(7);
    const SEED: [u8; 32] = [0x71; 32];

    fn wallet() -> DepositWalletId {
        DepositWalletId([0x72; 32])
    }

    fn initial_checkpoint() -> DepositIndexStoreCheckpoint {
        DepositIndexStoreCheckpoint::empty(wallet(), PARTY, index(1)).unwrap()
    }

    fn index(minor: u32) -> DepositSubaddressIndex {
        DepositSubaddressIndex::new(0, minor).unwrap()
    }

    #[test]
    fn fresh_checkpoint_cannot_inject_a_ledger_anchor() {
        let checkpoint = initial_checkpoint();
        let anchor = checkpoint.portable_head().portable_anchor().unwrap();
        assert_eq!(anchor.through_sequence(), 0);
        assert_eq!(anchor.ledger_head(), ledger_genesis_head(wallet()));
        assert_eq!(anchor.next_index(), index(1));
        assert_eq!(checkpoint.portable_head().revision(), 0);
        assert_eq!(checkpoint.portable_head().entry_count(), 0);
        assert_eq!(checkpoint.portable_head().record_count(), 0);
    }

    #[tokio::test]
    async fn verified_portable_import_preserves_fresh_local_safety_and_survives_restart() {
        let directory = TempDir::new().unwrap();
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let wallet = deriver.wallet_id();
        let fresh = DepositIndexStoreCheckpoint::empty(wallet, PARTY, index(1)).unwrap();
        let mut source =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, fresh.clone()).await.unwrap();
        let (update, request) = portable_allocation_update(&source, &deriver);
        let prepared = source.prepare_snapshot(vec![update]).await.unwrap();
        let target = prepared.checkpoint().clone();
        source.commit_prepared(&prepared, &target).await.unwrap();
        let source_logical = crate::deposit_index_checkpoint::PortableDepositIndexHead::from_head(
            source.portable_head(),
        )
        .unwrap();
        let import =
            VerifiedPortableIndexImport::from_authenticated_head_for_test(source.portable_head())
                .unwrap();
        assert!(matches!(
            source.checkpoint().import_verified_portable(&import),
            Err(DepositIndexStoreError::InvalidPortableImport)
        ));
        drop(source);

        let imported = fresh.import_verified_portable(&import).unwrap();
        assert!(!imported.has_recovery_journal());
        assert_eq!(imported.portable_head().revision(), 0);
        assert_eq!(
            imported.local_safety_head(),
            &DepositIndexHead::empty_local_safety(wallet, PARTY).unwrap()
        );
        assert_eq!(
            crate::deposit_index_checkpoint::PortableDepositIndexHead::from_head(
                imported.portable_head()
            )
            .unwrap(),
            source_logical
        );
        assert_eq!(
            DepositIndexStoreCheckpoint::from_bytes(&imported.to_bytes().unwrap()).unwrap(),
            imported
        );
        let missing_objects = TempDir::new().unwrap();
        assert!(
            DepositIndexStore::open(missing_objects.path(), PARTY, &SEED, imported.clone(),)
                .await
                .is_err()
        );

        let mut opened = DepositIndexStore::open(directory.path(), PARTY, &SEED, imported.clone())
            .await
            .unwrap();
        assert!(
            opened
                .lookup_portable(&PortableAllocationQuery::Request(request))
                .await
                .unwrap()
                .is_some()
        );
        drop(opened);
        let mut restarted =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, imported).await.unwrap();
        assert!(
            restarted
                .lookup_portable(&PortableAllocationQuery::Request(request))
                .await
                .unwrap()
                .is_some()
        );
        drop(restarted);

        assert!(matches!(
            initial_checkpoint().import_verified_portable(&import),
            Err(DepositIndexStoreError::InvalidPortableImport)
        ));
        let mut local_store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, fresh.clone()).await.unwrap();
        let local_update =
            first_used_update(&local_store, fresh.local_safety_head().clone(), [0x44]);
        let prepared = local_store.prepare_snapshot(vec![local_update]).await.unwrap();
        let target = prepared.checkpoint().clone();
        local_store.commit_prepared(&prepared, &target).await.unwrap();
        assert!(matches!(
            local_store.checkpoint().import_verified_portable(&import),
            Err(DepositIndexStoreError::InvalidPortableImport)
        ));
    }

    fn first_used_update(
        store: &DepositIndexStore,
        head: DepositIndexHead,
        values: impl IntoIterator<Item = u32>,
    ) -> DepositIndexUpdate {
        let mut builder = DepositIndexBuilder::new(store, head).unwrap();
        for value in values {
            assert!(builder.mark_first_used(index(value), 1_700_000_000).unwrap());
        }
        builder.finish().unwrap().unwrap()
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0xa5; 32];
        // Keep the identity discriminator away from X25519's clamped low byte.
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn portable_allocation_update(
        store: &DepositIndexStore,
        deriver: &DepositAddressDeriver,
    ) -> (DepositIndexUpdate, LedgerRequestId) {
        let identities = (1_u16..=4)
            .map(|value| {
                let party = PartyId(value);
                let signing_seed = [u8::try_from(value).unwrap(); 32];
                Identity::from_test_secrets(party, 0, &signing_seed, test_x25519_secret(party, 0))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let committee = Committee {
            epoch: 0,
            threshold: 2,
            members: identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let head = store.portable_head().clone();
        let first_index = head.portable_anchor().unwrap().next_index();
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee.clone(),
            1,
            [0x31; 32],
            [0x32; 32],
            deriver.wallet_id(),
            [0x33; 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, first_index, head.digest()).unwrap();
        let registry = pending.proposed_head().registry();
        let request = LedgerRequestId([0x34; 32]);
        let statement = LedgerStatement::allocation(
            registry,
            1,
            ledger_genesis_head(deriver.wallet_id()),
            request,
            RequestBinding([0x35; 32]),
            deriver.derive(first_index),
            ChainPoint::new(0, [0x36; 32]).unwrap(),
            1_700_000_000,
        )
        .unwrap();
        let payload = statement.attestation_payload().unwrap();
        let attestations = identities
            .iter()
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
        let mut builder = DepositIndexBuilder::new(store, head).unwrap();
        assert!(builder.apply_verified_active_entry(&entry, registry, None).unwrap());
        (builder.finish().unwrap().unwrap(), request)
    }

    fn observation_signing_fixture(
        deriver: &DepositAddressDeriver,
        index_root: [u8; 32],
    ) -> (CompactEpochRegistry, LedgerStatement, Identity, Identity) {
        let mut identities = (PARTY.0..=PARTY.0 + 3)
            .map(|value| {
                let party = PartyId(value);
                Identity::from_test_secrets(
                    party,
                    0,
                    &[u8::try_from(value).unwrap(); 32],
                    test_x25519_secret(party, 0),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let committee = Committee {
            epoch: 0,
            threshold: 2,
            members: identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            [0x81; 32],
            [0x82; 32],
            deriver.wallet_id(),
            [0x83; 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let pending = prepare_compact_registry_genesis(&target, index(1), index_root).unwrap();
        let registry = pending.proposed_head().registry().clone();
        let allocation = LedgerStatement::allocation(
            &registry,
            1,
            ledger_genesis_head(deriver.wallet_id()),
            LedgerRequestId([0x84; 32]),
            RequestBinding([0x85; 32]),
            deriver.derive(index(1)),
            ChainPoint::new(1, [0x86; 32]).unwrap(),
            1_700_000_000,
        )
        .unwrap();
        let signer = identities.remove(0);
        let other_party = identities.remove(0);
        (registry, allocation, signer, other_party)
    }

    fn checkpoint_slot_at(marker: u8, reserved_at: u64) -> SignedIndexCheckpointSlot {
        SignedIndexCheckpointSlot::new(
            1,
            [marker; 32],
            [marker.wrapping_add(1); 32],
            [marker.wrapping_add(2); 32],
            [marker.wrapping_add(3); 32],
            reserved_at,
        )
        .unwrap()
    }

    fn checkpoint_slot(marker: u8) -> SignedIndexCheckpointSlot {
        checkpoint_slot_at(marker, 1_700_000_000)
    }

    #[tokio::test]
    async fn checkpoint_slot_authorization_requires_committed_readback_and_survives_restart() {
        let directory = TempDir::new().unwrap();
        let old = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, old.clone()).await.unwrap();
        let slot = checkpoint_slot(0x41);
        assert!(matches!(
            store.authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence()).await,
            Err(DepositIndexStoreError::UncommittedSigningSlot)
        ));

        let mut builder =
            DepositIndexBuilder::new(&store, old.local_safety_head().clone()).unwrap();
        assert!(builder.record_signed_index_checkpoint_slot(slot).unwrap());
        let update = builder.finish().unwrap().unwrap();
        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
        assert!(matches!(
            store.authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence()).await,
            Err(DepositIndexStoreError::TransitionInProgress)
        ));
        let authenticated = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &authenticated).await.unwrap();
        let authorization = store
            .authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence())
            .await
            .unwrap();
        assert!(authorization.authorizes(wallet(), PARTY, slot));
        assert_eq!(authorization.reserved_at(), slot.reserved_at());
        assert!(!authorization.authorizes(
            wallet(),
            PARTY,
            checkpoint_slot_at(0x41, slot.reserved_at() + 1),
        ));

        let settled = store.checkpoint().clone();
        drop(store);
        let mut restarted =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, settled).await.unwrap();
        let restarted_authorization = restarted
            .authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence())
            .await
            .unwrap();
        assert!(restarted_authorization.authorizes(wallet(), PARTY, slot));

        let mut idempotent =
            DepositIndexBuilder::new(&restarted, restarted.local_safety_head().clone()).unwrap();
        assert!(!idempotent.record_signed_index_checkpoint_slot(slot).unwrap());
        assert!(idempotent.finish().unwrap().is_none());

        let mut conflicting =
            DepositIndexBuilder::new(&restarted, restarted.local_safety_head().clone()).unwrap();
        assert!(matches!(
            conflicting.record_signed_index_checkpoint_slot(checkpoint_slot(0x51)),
            Err(DepositIndexError::IndexCheckpointSlotAlreadySigned)
        ));
    }

    #[tokio::test]
    async fn observation_signing_requires_exact_paired_slots_under_the_settled_snapshot() {
        let directory = TempDir::new().unwrap();
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(73_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(29_u64).to_bytes()),
        )
        .unwrap();
        let initial =
            DepositIndexStoreCheckpoint::empty(deriver.wallet_id(), PARTY, index(1)).unwrap();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, initial).await.unwrap();
        let (registry, allocation, signer, other_party) =
            observation_signing_fixture(&deriver, store.portable_head().digest());
        let output = WalletOutputId { transaction: [0x91; 32], index_in_transaction: 4 };
        let output_key = [0x92; 32];
        let amount = 700_000_u64;
        let statement = DepositObservationStatement::new(
            &registry,
            &allocation,
            output,
            output_key,
            42,
            amount,
            ChainPoint::new(100, [0x93; 32]).unwrap(),
            1_700_000_100,
            ChainPoint::new(109, [0x94; 32]).unwrap(),
            10,
        )
        .unwrap();
        statement.validate_active(&registry).unwrap();

        assert!(matches!(
            store.sign_deposit_observation_attestation(&signer, &registry, &statement).await,
            Err(DepositIndexStoreError::UncommittedDepositObservationSlot)
        ));

        let mut builder =
            DepositIndexBuilder::new(&store, store.local_safety_head().clone()).unwrap();
        assert!(builder.bind_output(output, output_key, Some(index(1)), amount).unwrap());
        assert!(builder.record_signed_deposit_observation(&statement).unwrap());
        let update = builder.finish().unwrap().unwrap();
        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
        assert!(matches!(
            store.sign_deposit_observation_attestation(&signer, &registry, &statement).await,
            Err(DepositIndexStoreError::TransitionInProgress)
        ));
        let authenticated = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &authenticated).await.unwrap();
        assert!(!store.checkpoint().has_recovery_journal());

        let output_record = store
            .lookup_local_safety(LocalSafetyQuery::SignedDepositObservationOutput(output))
            .await
            .unwrap()
            .unwrap();
        let key_record = store
            .lookup_local_safety(LocalSafetyQuery::SignedDepositObservationKey(output_key))
            .await
            .unwrap()
            .unwrap();
        let LocalSafetyValue::SignedDepositObservationOutput(output_slot) = output_record.value()
        else {
            panic!("output alias did not retain its observation slot");
        };
        let LocalSafetyValue::SignedDepositObservationKey(key_slot) = key_record.value() else {
            panic!("one-time-key alias did not retain its observation slot");
        };
        assert_eq!(output_slot, key_slot);
        assert!(output_slot.matches_statement(&statement));

        let envelope = store
            .sign_deposit_observation_attestation(&signer, &registry, &statement)
            .await
            .unwrap();
        Identity::verify_envelope(registry.active().committee(), PARTY, &envelope).unwrap();

        let later_horizon = DepositObservationStatement::new(
            &registry,
            &allocation,
            output,
            output_key,
            statement.index_on_blockchain(),
            amount,
            statement.observed_block(),
            statement.block_timestamp(),
            ChainPoint::new(110, [0x95; 32]).unwrap(),
            11,
        )
        .unwrap();
        assert_eq!(later_horizon.fact_digest(), statement.fact_digest());
        assert_ne!(later_horizon.digest(), statement.digest());
        store
            .sign_deposit_observation_attestation(&signer, &registry, &later_horizon)
            .await
            .unwrap();

        assert!(matches!(
            store.sign_deposit_observation_attestation(&other_party, &registry, &statement).await,
            Err(DepositIndexStoreError::Ledger(LedgerError::DepositObservationReservationRequired))
        ));

        let different_fact = DepositObservationStatement::new(
            &registry,
            &allocation,
            output,
            output_key,
            43,
            amount,
            statement.observed_block(),
            statement.block_timestamp(),
            statement.confirmation_horizon(),
            statement.confirmation_depth(),
        )
        .unwrap();
        assert!(matches!(
            store.sign_deposit_observation_attestation(&signer, &registry, &different_fact).await,
            Err(DepositIndexStoreError::UncommittedDepositObservationSlot)
        ));

        let settled = store.checkpoint().clone();
        drop(store);
        let mut restarted =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, settled).await.unwrap();
        restarted
            .sign_deposit_observation_attestation(&signer, &registry, &statement)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn abort_preserves_a_preexisting_staged_index_object() {
        let directory = TempDir::new().unwrap();
        let old = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, old.clone()).await.unwrap();
        let update = first_used_update(&store, old.local_safety.clone(), [7]);
        let (preexisting_id, preexisting_contents) = update.staged_objects().next().unwrap();
        let preexisting_contents = preexisting_contents.to_vec();
        let preexisting_reference = preexisting_id.storage_reference();
        let staged_references =
            update.staged_objects().map(|(id, _)| id.storage_reference()).collect::<Vec<_>>();
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

        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
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
    async fn old_snapshot_derives_and_aborts_pre_cas_journal_without_scan() {
        let directory = TempDir::new().unwrap();
        let old = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, old.clone()).await.unwrap();
        let update = first_used_update(&store, old.local_safety.clone(), [1]);
        let object_refs =
            update.staged_objects().map(|(id, _)| id.storage_reference()).collect::<Vec<_>>();
        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
        let key = prepared.journals[&DepositIndexJournalScope::LocalSafety].key;
        let protocol_path = store.protocol.deposit_index_journal_path(key);
        assert!(protocol_path.is_file());
        drop(prepared);
        drop(store);

        let recovered = DepositIndexStore::open(directory.path(), PARTY, &SEED, old).await.unwrap();
        assert!(!protocol_path.exists());
        let artifacts = WalletArtifactStore::new(directory.path(), PARTY, &SEED).unwrap();
        assert!(
            object_refs.into_iter().all(|reference| !artifacts.artifact_path(reference).exists())
        );
        assert!(!recovered.checkpoint().has_recovery_journal());
    }

    #[tokio::test]
    async fn target_snapshot_retains_exact_key_and_finishes_post_cas_recovery() {
        let directory = TempDir::new().unwrap();
        let old = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, old.clone()).await.unwrap();
        let update = first_used_update(&store, old.local_safety.clone(), [2]);
        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
        let target = prepared.checkpoint().clone();
        assert!(target.has_recovery_journal());
        assert!(!prepared.settled_checkpoint().has_recovery_journal());
        assert_eq!(prepared.settled_checkpoint().local_safety_head(), target.local_safety_head());
        let key = prepared.journals[&DepositIndexJournalScope::LocalSafety].key;
        let journal_path = store.protocol.deposit_index_journal_path(key);
        drop(prepared);
        drop(store);

        let mut recovered =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, target).await.unwrap();
        assert!(!journal_path.exists());
        assert!(
            recovered
                .lookup_local_safety(LocalSafetyQuery::FirstUsed(index(2)))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn cleanup_is_idempotent_after_partial_post_cas_unlink() {
        let directory = TempDir::new().unwrap();
        let old = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, old.clone()).await.unwrap();
        let first = first_used_update(&store, old.local_safety.clone(), [3]);
        let prepared = store.prepare_snapshot(vec![first]).await.unwrap();
        let first_target = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &first_target).await.unwrap();

        let second = first_used_update(&store, store.local_safety_head().clone(), [4]);
        let prepared = store.prepare_snapshot(vec![second]).await.unwrap();
        let target = prepared.checkpoint().clone();
        let obsolete = prepared.journals[&DepositIndexJournalScope::LocalSafety]
            .staged
            .update()
            .obsolete_objects()
            .next()
            .unwrap();
        store.artifacts.remove_artifact(obsolete.storage_reference()).await.unwrap();
        drop(prepared);
        drop(store);

        let mut recovered =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, target).await.unwrap();
        assert!(
            recovered
                .lookup_local_safety(LocalSafetyQuery::FirstUsed(index(4)))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn settled_restart_and_direct_query_have_constant_bounds() {
        let directory = TempDir::new().unwrap();
        let initial = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, initial.clone()).await.unwrap();
        let update = first_used_update(&store, initial.local_safety.clone(), 1..=128);
        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
        let target = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &target).await.unwrap();
        let settled = store.checkpoint().clone();
        drop(prepared);
        drop(store);

        let mut restarted =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, settled).await.unwrap();
        let startup_reads = restarted.artifact_load_count();
        assert!(startup_reads <= 2);
        assert!(
            restarted
                .lookup_local_safety(LocalSafetyQuery::FirstUsed(index(127)))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            restarted.artifact_load_count() - startup_reads <= MAX_DEPOSIT_INDEX_QUERY_READS as u64
        );
        assert_eq!(
            restarted.lookup_portable_state(PortableStateQuery::NextSweepSequence).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn unauthenticated_checkpoint_cannot_cross_the_head_cas() {
        let directory = TempDir::new().unwrap();
        let initial = initial_checkpoint();
        let mut store =
            DepositIndexStore::open(directory.path(), PARTY, &SEED, initial.clone()).await.unwrap();
        let update = first_used_update(&store, initial.local_safety.clone(), [9]);
        let prepared = store.prepare_snapshot(vec![update]).await.unwrap();
        assert!(matches!(
            store.commit_prepared(&prepared, &initial).await,
            Err(DepositIndexStoreError::CheckpointConflict)
        ));
        store.abort_prepared(&prepared).await.unwrap();
    }
}
