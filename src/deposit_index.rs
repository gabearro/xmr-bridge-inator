//! Authenticated, content-addressed lookup indexes for certified deposit allocations.
//!
//! The portable tree stores every exact ledger statement and all permanent consolidation safety
//! facts. Certificate witness vectors are deliberately excluded, so two replicas which accepted
//! different valid `n-f` witness subsets derive the same root. Allocation sequence, request,
//! canonical address, subaddress index, and compressed spend-key aliases point at one immutable
//! value. Terminal family/id aliases, input claims, signing-session tombstones, and sweep
//! high-water records make replay safety independently provable without rescanning the archive.
//!
//! Party-local safety facts use a distinct root and namespace. An address's earliest observed
//! timestamp is monotonic, and an output ID is permanently bound to one `(subaddress, amount)`
//! pair even if its containing block or global output index changes after a reorganization.
//!
//! Both roots use a sparse 16-way Merkle HAMT. Branches contain a bitmap and densely packed child
//! hashes; leaves contain at most 32 sorted full keys. Updates are applied as:
//!
//! 1. durably retain the [`DepositIndexUpdate`] journal;
//! 2. stage every content-addressed object;
//! 3. call [`StagedDepositIndexUpdate::verify_staged`];
//! 4. compare-and-swap the head with [`StagedDepositIndexUpdate::commit_head`];
//! 5. call [`StagedDepositIndexUpdate::cleanup`], then remove the journal.
//!
//! Recovery may call [`StagedDepositIndexUpdate::recover`] at any point. A portable head is only a
//! cache until its `(through_sequence, ledger_head, root)` tuple is authenticated by an external
//! ledger checkpoint or handoff certificate; otherwise a joining party must still replay the
//! complete certified archive.

#[cfg(test)]
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use monero_wallet::address::{MoneroAddress, Network};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::{PartyId, SessionId},
    compact_epoch_registry::{CompactEpochRegistry, VerifiedIssuerWindow},
    config::NetworkKind,
    consolidation_roast::RoastAttemptPrefixSeal,
    deposit_archive::{
        CERTIFIED_LEDGER_ENTRY_ARTIFACT, DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT, MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        MAX_DEPOSIT_ARCHIVE_EVENT_BYTES, MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
        VerifiedDepositArchiveLedgerLocator,
    },
    deposit_consolidation::ConsolidationId,
    deposit_index_checkpoint::VerifiedDepositIndexCheckpoint,
    deposit_ledger::{
        AllocationStatement, CertifiedDepositObservation, CertifiedLedgerEntry,
        DepositObservationStatement, LedgerError, LedgerPayload, LedgerRequestId, LedgerStatement,
        RequestBinding, UNUSED_ALLOCATION_TTL_SECONDS,
    },
    deposit_wallet::{
        CanonicalDepositAddress, ChainPoint, DepositSubaddressIndex, DepositWalletError,
        DepositWalletId, SweepId, WalletOutputId,
    },
    storage::{StoreError, WalletArtifactKind, WalletArtifactRef, WalletId},
};

const INDEX_HEAD_VERSION: u16 = 1;
const INDEX_OBJECT_VERSION: u16 = 4;
const INDEX_PROOF_VERSION: u16 = 1;
const INDEX_UPDATE_VERSION: u16 = 2;
const PRIMARY_HAMT_DEPTH: u8 = 64;
// A second, domain-separated 256-bit route is used only after a complete primary hash collision.
// This keeps collision handling canonical without permitting an oversized collision leaf.
const MAX_HAMT_DEPTH: u8 = 128;
pub const MAX_DEPOSIT_INDEX_LEAF_ENTRIES: usize = 32;
/// One sequence value may retain a complete canonical signed Monero transaction.
pub const MAX_DEPOSIT_INDEX_OBJECT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DEPOSIT_INDEX_PROOF_OBJECTS: usize = MAX_HAMT_DEPTH as usize + 1;
pub const MAX_DEPOSIT_INDEX_PROOF_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS: usize = 256;
pub const MAX_DEPOSIT_INDEX_UPDATE_OBJECTS: usize = 32_768;
pub const MAX_DEPOSIT_INDEX_TOUCHED_KEYS: usize = 16_384;
pub const MAX_DEPOSIT_INDEX_VERIFICATION_OBJECTS: usize = 131_072;
pub const MAX_DEPOSIT_INDEX_UPDATE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DEPOSIT_INDEX_QUERY_READS: usize = MAX_DEPOSIT_INDEX_PROOF_OBJECTS + 1;
pub const MAX_DEPOSIT_INDEX_UPDATE_VERIFICATION_READS: usize =
    MAX_DEPOSIT_INDEX_UPDATE_OBJECTS + 2 * MAX_DEPOSIT_INDEX_VERIFICATION_OBJECTS;
pub const MAX_DEPOSIT_INDEX_TERMINAL_INPUTS: usize = 1_024;

/// Dedicated current-format encrypted artifact kind for every deposit-index node and value.
pub const DEPOSIT_INDEX_ARTIFACT_KIND: WalletArtifactKind = WalletArtifactKind(0xd100);

/// Complete, restart-loadable content address of one canonical index node or value object.
///
/// The wrapped wallet artifact reference includes the wallet, kind, exact plaintext length, and
/// digest. A durable head can therefore locate its root directly after restart without retaining
/// a separate lifetime digest-to-path map.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DepositIndexObjectId(WalletArtifactRef);

impl DepositIndexObjectId {
    pub fn from_storage_reference(reference: WalletArtifactRef) -> Result<Self, DepositIndexError> {
        let id = Self(reference);
        id.validate()?;
        Ok(id)
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0.digest()
    }

    #[must_use]
    pub const fn plaintext_len(self) -> u64 {
        self.0.plaintext_len()
    }

    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        DepositWalletId(self.0.wallet_id().0)
    }

    #[must_use]
    pub const fn storage_reference(self) -> WalletArtifactRef {
        self.0
    }

    fn validate(self) -> Result<(), DepositIndexError> {
        let canonical = WalletArtifactRef::from_parts(
            self.0.wallet_id(),
            self.0.kind(),
            self.0.plaintext_len(),
            self.0.digest(),
        )
        .map_err(|_| DepositIndexError::InvalidObjectId)?;
        let length = usize::try_from(self.0.plaintext_len())
            .map_err(|_| DepositIndexError::InvalidObjectId)?;
        if canonical != self.0
            || self.0.kind() != DEPOSIT_INDEX_ARTIFACT_KIND
            || self.0.wallet_id().0 == [0; 32]
            || self.0.digest() == [0; 32]
            || length == 0
            || length > MAX_DEPOSIT_INDEX_OBJECT_BYTES
        {
            return Err(DepositIndexError::InvalidObjectId);
        }
        Ok(())
    }
}

/// Stable namespace key. It never includes a mutable root or revision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DepositIndexNamespace {
    Portable { wallet: DepositWalletId },
    LocalSafety { wallet: DepositWalletId, party: PartyId },
}

impl DepositIndexNamespace {
    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        match self {
            Self::Portable { wallet } | Self::LocalSafety { wallet, .. } => wallet,
        }
    }

    fn validate(self) -> Result<(), DepositIndexError> {
        if self.wallet().0 == [0; 32] || matches!(self, Self::LocalSafety { party: PartyId(0), .. })
        {
            return Err(DepositIndexError::InvalidHead);
        }
        Ok(())
    }
}

/// Exact certified-ledger coverage represented by a portable index root.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableLedgerAnchor {
    through_sequence: u64,
    ledger_head: [u8; 32],
    next_index: DepositSubaddressIndex,
}

impl PortableLedgerAnchor {
    #[must_use]
    pub const fn through_sequence(self) -> u64 {
        self.through_sequence
    }

    #[must_use]
    pub const fn ledger_head(self) -> [u8; 32] {
        self.ledger_head
    }

    #[must_use]
    pub const fn next_index(self) -> DepositSubaddressIndex {
        self.next_index
    }

    fn validate(self) -> Result<(), DepositIndexError> {
        if self.ledger_head == [0; 32] {
            return Err(DepositIndexError::InvalidHead);
        }
        Ok(())
    }
}

/// Mutable authenticated head stored through a caller-owned CAS boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexHead {
    version: u16,
    namespace: DepositIndexNamespace,
    revision: u64,
    entries: u64,
    records: u64,
    root: Option<DepositIndexObjectId>,
    portable_anchor: Option<PortableLedgerAnchor>,
}

impl DepositIndexHead {
    /// Create the sole empty portable state at this wallet's exact ledger genesis.
    pub fn empty_portable(
        wallet: DepositWalletId,
        next_index: DepositSubaddressIndex,
    ) -> Result<Self, DepositIndexError> {
        let head = Self {
            version: INDEX_HEAD_VERSION,
            namespace: DepositIndexNamespace::Portable { wallet },
            revision: 0,
            entries: 0,
            records: 0,
            root: None,
            portable_anchor: Some(PortableLedgerAnchor {
                through_sequence: 0,
                ledger_head: crate::deposit_ledger::genesis_head(wallet),
                next_index,
            }),
        };
        head.validate_shape()?;
        Ok(head)
    }

    /// Create an empty party-local, permanent safety index.
    pub fn empty_local_safety(
        wallet: DepositWalletId,
        party: PartyId,
    ) -> Result<Self, DepositIndexError> {
        let head = Self {
            version: INDEX_HEAD_VERSION,
            namespace: DepositIndexNamespace::LocalSafety { wallet, party },
            revision: 0,
            entries: 0,
            records: 0,
            root: None,
            portable_anchor: None,
        };
        head.validate_shape()?;
        Ok(head)
    }

    /// Reconstruct a revision-zero local view of one independently authenticated logical
    /// portable head. The caller must compare [`Self::digest`] with the signed checkpoint digest
    /// before using the result as authority.
    pub(crate) fn from_portable_components(
        wallet: DepositWalletId,
        entries: u64,
        records: u64,
        root: Option<DepositIndexObjectId>,
        through_sequence: u64,
        ledger_head: [u8; 32],
        next_index: DepositSubaddressIndex,
    ) -> Result<Self, DepositIndexError> {
        let head = Self {
            version: INDEX_HEAD_VERSION,
            namespace: DepositIndexNamespace::Portable { wallet },
            revision: 0,
            entries,
            records,
            root,
            portable_anchor: Some(PortableLedgerAnchor {
                through_sequence,
                ledger_head,
                next_index,
            }),
        };
        head.validate_shape()?;
        Ok(head)
    }

    #[must_use]
    pub const fn namespace(&self) -> DepositIndexNamespace {
        self.namespace
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entries
    }

    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.records
    }

    #[must_use]
    pub const fn root(&self) -> Option<DepositIndexObjectId> {
        self.root
    }

    #[must_use]
    pub const fn portable_anchor(&self) -> Option<PortableLedgerAnchor> {
        self.portable_anchor
    }

    /// Digest suitable for binding the complete head into a checkpoint or handoff certificate.
    /// The party-local CAS revision is deliberately excluded: batching choices must not change a
    /// consensus-visible portable commitment.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        #[derive(Serialize)]
        struct LogicalHeadCommitment {
            version: u16,
            namespace: DepositIndexNamespace,
            entries: u64,
            records: u64,
            root: Option<DepositIndexObjectId>,
            portable_anchor: Option<PortableLedgerAnchor>,
        }
        let bytes = postcard::to_allocvec(&LogicalHeadCommitment {
            version: self.version,
            namespace: self.namespace,
            entries: self.entries,
            records: self.records,
            root: self.root,
            portable_anchor: self.portable_anchor,
        })
        .expect("index head serialization is infallible");
        derive_hash("threshold-monero/deposit-index/head/v1", &bytes)
    }

    fn validate_shape(&self) -> Result<(), DepositIndexError> {
        self.namespace.validate()?;
        if self.version != INDEX_HEAD_VERSION
            || (self.entries == 0) != self.root.is_none()
            || (self.entries == 0) != (self.records == 0)
            || match self.namespace {
                DepositIndexNamespace::Portable { .. } => self.records > self.entries,
                DepositIndexNamespace::LocalSafety { .. } => self.records != self.entries,
            }
            || match (self.namespace, self.portable_anchor) {
                (DepositIndexNamespace::Portable { wallet }, Some(anchor)) => {
                    anchor.validate().is_err()
                        || anchor.through_sequence == u64::MAX
                        || if self.root.is_none() {
                            anchor.through_sequence != 0
                                || anchor.ledger_head != crate::deposit_ledger::genesis_head(wallet)
                        } else {
                            anchor.through_sequence == 0
                        }
                }
                (DepositIndexNamespace::LocalSafety { .. }, None) => false,
                _ => true,
            }
        {
            return Err(DepositIndexError::InvalidHead);
        }
        if let Some(root) = self.root {
            root.validate()?;
            if root.wallet_id() != self.namespace.wallet() {
                return Err(DepositIndexError::InvalidHead);
            }
        }
        Ok(())
    }
}

/// Exact witness-independent allocation value referenced by all four portable aliases.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableAllocationRecord {
    version: u16,
    statement: LedgerStatement,
}

impl PortableAllocationRecord {
    /// Verify an archived certificate under an authenticated issuer window, then discard its
    /// variable witness vector.
    pub fn from_verified_entry(
        entry: &CertifiedLedgerEntry,
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<Self, DepositIndexError> {
        entry.verify(issuer_window, historical_issuer)?;
        Self::from_statement(entry.statement.clone())
    }

    /// Verify a live certificate against the compact active head, then discard its variable
    /// witness vector.
    pub fn from_verified_active_entry(
        entry: &CertifiedLedgerEntry,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<Self, DepositIndexError> {
        entry.verify_active(registry, historical_issuer)?;
        Self::from_statement(entry.statement.clone())
    }

    fn from_statement(statement: LedgerStatement) -> Result<Self, DepositIndexError> {
        let record = Self { version: INDEX_OBJECT_VERSION, statement };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn statement(&self) -> &LedgerStatement {
        &self.statement
    }

    #[must_use]
    pub fn allocation(&self) -> &AllocationStatement {
        let LedgerPayload::Allocation(allocation) = &self.statement.payload else {
            unreachable!("validated portable allocation record")
        };
        allocation
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.statement.wallet
    }

    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement.digest()
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        let LedgerPayload::Allocation(allocation) = &self.statement.payload else {
            return Err(DepositIndexError::InvalidPortableRecord);
        };
        allocation.address.validate()?;
        ChainPoint::new(allocation.recognition_anchor.height, allocation.recognition_anchor.hash)
            .map_err(|_| DepositIndexError::InvalidPortableRecord)?;
        let _spend_key = subaddress_spend_key(&allocation.address)?;
        if self.version != INDEX_OBJECT_VERSION
            || self.statement.wallet.0 == [0; 32]
            || self.statement.sequence == 0
            || self.statement.previous == [0; 32]
            || self.statement.issuer_committee == [0; 32]
            || self.statement.issuer_activation == [0; 32]
            || allocation.address.wallet_id() != self.statement.wallet
            || allocation.request.0 == [0; 32]
            || allocation.binding.0 == [0; 32]
            || allocation.expires_at
                != allocation
                    .created_at
                    .checked_add(UNUSED_ALLOCATION_TTL_SECONDS)
                    .ok_or(DepositIndexError::InvalidPortableRecord)?
        {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        Ok(())
    }
}

/// Witness-independent n-f-certified output fact retained under output and one-time-key aliases.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableDepositOutputRecord {
    version: u16,
    wallet: DepositWalletId,
    allocation_sequence: u64,
    allocation_statement: [u8; 32],
    index: DepositSubaddressIndex,
    output: WalletOutputId,
    output_key: [u8; 32],
    index_on_blockchain: u64,
    amount_atomic_units: u64,
    observed_block: ChainPoint,
    block_timestamp: u64,
    /// Canonical minimum certificate statement digest for this identical semantic fact.
    observation: [u8; 32],
}

impl PortableDepositOutputRecord {
    fn from_observation(
        statement: &DepositObservationStatement,
    ) -> Result<Self, DepositIndexError> {
        let record = Self {
            version: INDEX_OBJECT_VERSION,
            wallet: statement.wallet_id(),
            allocation_sequence: statement.allocation_sequence(),
            allocation_statement: statement.allocation_statement(),
            index: statement.index(),
            output: statement.output(),
            output_key: statement.output_key(),
            index_on_blockchain: statement.index_on_blockchain(),
            amount_atomic_units: statement.amount_atomic_units(),
            observed_block: statement.observed_block(),
            block_timestamp: statement.block_timestamp(),
            observation: statement.digest(),
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn allocation_sequence(&self) -> u64 {
        self.allocation_sequence
    }

    #[must_use]
    pub const fn allocation_statement(&self) -> [u8; 32] {
        self.allocation_statement
    }

    #[must_use]
    pub const fn index(&self) -> DepositSubaddressIndex {
        self.index
    }

    #[must_use]
    pub const fn output(&self) -> WalletOutputId {
        self.output
    }

    #[must_use]
    pub const fn output_key(&self) -> [u8; 32] {
        self.output_key
    }

    #[must_use]
    pub const fn index_on_blockchain(&self) -> u64 {
        self.index_on_blockchain
    }

    #[must_use]
    pub const fn amount_atomic_units(&self) -> u64 {
        self.amount_atomic_units
    }

    #[must_use]
    pub const fn observed_block(&self) -> ChainPoint {
        self.observed_block
    }

    #[must_use]
    pub const fn block_timestamp(&self) -> u64 {
        self.block_timestamp
    }

    #[must_use]
    pub const fn observation_digest(&self) -> [u8; 32] {
        self.observation
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        ChainPoint::new(self.observed_block.height, self.observed_block.hash)
            .map_err(|_| DepositIndexError::InvalidPortableObservation)?;
        if self.version != INDEX_OBJECT_VERSION
            || self.wallet.0 == [0; 32]
            || self.allocation_sequence == 0
            || self.allocation_statement == [0; 32]
            || self.output.transaction == [0; 32]
            || self.output_key == [0; 32]
            || self.observation == [0; 32]
        {
            return Err(DepositIndexError::InvalidPortableObservation);
        }
        Ok(())
    }

    fn same_binding(&self, other: &Self) -> bool {
        self.wallet == other.wallet
            && self.allocation_sequence == other.allocation_sequence
            && self.allocation_statement == other.allocation_statement
            && self.index == other.index
            && self.output == other.output
            && self.output_key == other.output_key
            && self.index_on_blockchain == other.index_on_blockchain
            && self.amount_atomic_units == other.amount_atomic_units
            && self.observed_block == other.observed_block
            && self.block_timestamp == other.block_timestamp
    }

    fn canonical_merge(&self, candidate: &Self) -> Result<Self, DepositIndexError> {
        if !self.same_binding(candidate) {
            return Err(DepositIndexError::PortableObservationConflict);
        }
        Ok(if candidate.observation < self.observation { candidate.clone() } else { self.clone() })
    }
}

/// Permanent portable proof that one allocated address has been used at least once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableFirstUseRecord {
    version: u16,
    wallet: DepositWalletId,
    allocation_sequence: u64,
    allocation_statement: [u8; 32],
    index: DepositSubaddressIndex,
    output: WalletOutputId,
    observed_block: ChainPoint,
    block_timestamp: u64,
    observation: [u8; 32],
}

impl PortableFirstUseRecord {
    fn from_output(output: &PortableDepositOutputRecord) -> Result<Self, DepositIndexError> {
        let record = Self {
            version: INDEX_OBJECT_VERSION,
            wallet: output.wallet,
            allocation_sequence: output.allocation_sequence,
            allocation_statement: output.allocation_statement,
            index: output.index,
            output: output.output,
            observed_block: output.observed_block,
            block_timestamp: output.block_timestamp,
            observation: output.observation,
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn allocation_sequence(&self) -> u64 {
        self.allocation_sequence
    }

    #[must_use]
    pub const fn allocation_statement(&self) -> [u8; 32] {
        self.allocation_statement
    }

    #[must_use]
    pub const fn index(&self) -> DepositSubaddressIndex {
        self.index
    }

    #[must_use]
    pub const fn output(&self) -> WalletOutputId {
        self.output
    }

    #[must_use]
    pub const fn observed_block(&self) -> ChainPoint {
        self.observed_block
    }

    #[must_use]
    pub const fn block_timestamp(&self) -> u64 {
        self.block_timestamp
    }

    #[must_use]
    pub const fn observation_digest(&self) -> [u8; 32] {
        self.observation
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        ChainPoint::new(self.observed_block.height, self.observed_block.hash)
            .map_err(|_| DepositIndexError::InvalidPortableObservation)?;
        if self.version != INDEX_OBJECT_VERSION
            || self.wallet.0 == [0; 32]
            || self.allocation_sequence == 0
            || self.allocation_statement == [0; 32]
            || self.output.transaction == [0; 32]
            || self.observation == [0; 32]
        {
            return Err(DepositIndexError::InvalidPortableObservation);
        }
        Ok(())
    }

    fn canonical_key(&self) -> (u64, [u8; 32], WalletOutputId, [u8; 32]) {
        (self.observed_block.height, self.observed_block.hash, self.output, self.observation)
    }

    fn canonical_merge(&self, candidate: &Self) -> Result<Self, DepositIndexError> {
        if self.wallet != candidate.wallet
            || self.allocation_sequence != candidate.allocation_sequence
            || self.allocation_statement != candidate.allocation_statement
            || self.index != candidate.index
        {
            return Err(DepositIndexError::PortableObservationConflict);
        }
        Ok(if candidate.canonical_key() < self.canonical_key() {
            candidate.clone()
        } else {
            self.clone()
        })
    }
}

/// Exact witness-independent ledger statement retained under its global sequence number.
///
/// Allocation statements use [`PortableAllocationRecord`] instead so the sequence and all
/// allocation aliases share one content-addressed value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableLedgerStatementRecord {
    version: u16,
    statement: LedgerStatement,
}

impl PortableLedgerStatementRecord {
    fn from_statement(statement: LedgerStatement) -> Result<Self, DepositIndexError> {
        let record = Self { version: INDEX_OBJECT_VERSION, statement };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn statement(&self) -> &LedgerStatement {
        &self.statement
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.statement.wallet
    }

    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement.digest()
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.version != INDEX_OBJECT_VERSION
            || self.statement.wallet.0 == [0; 32]
            || self.statement.sequence == 0
            || self.statement.previous == [0; 32]
            || self.statement.issuer_committee == [0; 32]
            || self.statement.issuer_activation == [0; 32]
            || matches!(&self.statement.payload, LedgerPayload::Allocation(_))
        {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        Ok(())
    }
}

/// Permanent proof that a ROAST family was closed even if its historical transaction is later
/// recognized on the canonical chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableAbandonmentEvidence {
    statement_sequence: u64,
    statement_digest: [u8; 32],
    roast_family: [u8; 32],
    attempt_prefix: RoastAttemptPrefixSeal,
    terminal_attempt: u64,
    terminal_session: SessionId,
}

impl PortableAbandonmentEvidence {
    #[must_use]
    pub const fn statement_sequence(&self) -> u64 {
        self.statement_sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn roast_family(&self) -> [u8; 32] {
        self.roast_family
    }

    #[must_use]
    pub const fn attempt_prefix(&self) -> RoastAttemptPrefixSeal {
        self.attempt_prefix
    }

    #[must_use]
    pub const fn terminal_attempt(&self) -> u64 {
        self.terminal_attempt
    }

    #[must_use]
    pub const fn terminal_session(&self) -> SessionId {
        self.terminal_session
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.statement_sequence == 0
            || self.statement_digest == [0; 32]
            || self.roast_family == [0; 32]
            || self.attempt_prefix.family() != self.roast_family
            || self.attempt_prefix.family_anchor() == [0; 32]
            || self.attempt_prefix.accumulator() == [0; 32]
            || self.attempt_prefix.closed_through_attempt() != self.terminal_attempt
            || self.attempt_prefix.closed_through_view().checked_add(1)
                != Some(self.terminal_attempt)
            || self.terminal_attempt == 0
            || self.terminal_session.0 == [0; 32]
        {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        Ok(())
    }
}

/// Current terminal state for one wallet sweep family.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PortableConsolidationStatus {
    Completed {
        statement_sequence: u64,
        statement_digest: [u8; 32],
        attempt: u64,
        session: SessionId,
        transaction: [u8; 32],
    },
    Abandoned {
        evidence: PortableAbandonmentEvidence,
    },
    LateSettled {
        settlement_sequence: u64,
        settlement_digest: [u8; 32],
        historical_attempt: u64,
        historical_session: SessionId,
        transaction: [u8; 32],
        /// Never removed when late settlement becomes the current outcome.
        abandonment: PortableAbandonmentEvidence,
    },
}

/// Authenticated current status addressed by both authorization ID and wallet [`SweepId`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableConsolidationTerminalRecord {
    version: u16,
    wallet: DepositWalletId,
    consolidation: ConsolidationId,
    sweep: SweepId,
    sweep_sequence: u64,
    inputs: Vec<WalletOutputId>,
    attempt_high_water: u64,
    status: PortableConsolidationStatus,
}

impl PortableConsolidationTerminalRecord {
    fn from_terminal_statement(statement: &LedgerStatement) -> Result<Self, DepositIndexError> {
        let digest = statement.digest();
        let record = match &statement.payload {
            LedgerPayload::ConsolidationCompletion(completion) => {
                if completion.authorization().wallet_id() != statement.wallet
                    || completion.plan().wallet != statement.wallet
                    || completion.plan().id != completion.authorization().sweep_id()
                    || completion.authorization().input_count()
                        != u32::try_from(completion.inputs().len())
                            .map_err(|_| DepositIndexError::InvalidPortableTerminal)?
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                Self {
                    version: INDEX_OBJECT_VERSION,
                    wallet: statement.wallet,
                    consolidation: completion.id(),
                    sweep: completion.authorization().sweep_id(),
                    sweep_sequence: completion.plan().sequence,
                    inputs: completion.inputs().to_vec(),
                    attempt_high_water: completion.attempt().attempt(),
                    status: PortableConsolidationStatus::Completed {
                        statement_sequence: statement.sequence,
                        statement_digest: digest,
                        attempt: completion.attempt().attempt(),
                        session: completion.attempt().session(),
                        transaction: completion.transaction_id(),
                    },
                }
            }
            LedgerPayload::ConsolidationAbandonment(abandonment) => {
                if abandonment.authorization().wallet_id() != statement.wallet
                    || abandonment.authorization().input_count()
                        != u32::try_from(abandonment.inputs().len())
                            .map_err(|_| DepositIndexError::InvalidPortableTerminal)?
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                let evidence = PortableAbandonmentEvidence {
                    statement_sequence: statement.sequence,
                    statement_digest: digest,
                    roast_family: abandonment.family(),
                    attempt_prefix: abandonment.attempt_prefix(),
                    terminal_attempt: abandonment.attempt().attempt(),
                    terminal_session: abandonment.attempt().session(),
                };
                Self {
                    version: INDEX_OBJECT_VERSION,
                    wallet: statement.wallet,
                    consolidation: abandonment.id(),
                    sweep: abandonment.authorization().sweep_id(),
                    sweep_sequence: abandonment.sweep_sequence(),
                    inputs: abandonment.inputs().to_vec(),
                    attempt_high_water: abandonment.attempt_prefix().closed_through_attempt(),
                    status: PortableConsolidationStatus::Abandoned { evidence },
                }
            }
            _ => return Err(DepositIndexError::InvalidPortableTerminal),
        };
        record.validate()?;
        Ok(record)
    }

    fn settle_late(
        &self,
        statement: &LedgerStatement,
    ) -> Result<PortableConsolidationTerminalRecord, DepositIndexError> {
        let LedgerPayload::LateConsolidationSettlement(settlement) = &statement.payload else {
            return Err(DepositIndexError::InvalidPortableTerminal);
        };
        let PortableConsolidationStatus::Abandoned { evidence } = &self.status else {
            return Err(DepositIndexError::TerminalConflict);
        };
        let completion = settlement.historical_completion();
        if statement.wallet != self.wallet
            || settlement.id() != self.consolidation
            || completion.authorization().sweep_id() != self.sweep
            || completion.authorization().wallet_id() != self.wallet
            || completion.plan().wallet != self.wallet
            || completion.plan().id != self.sweep
            || completion.plan().sequence != self.sweep_sequence
            || completion.inputs() != self.inputs.as_slice()
            || settlement.abandonment_statement() != evidence.statement_digest
            || completion.attempt().attempt() > evidence.terminal_attempt
            || (completion.attempt().session() == evidence.terminal_session
                && completion.attempt().attempt() != evidence.terminal_attempt)
        {
            return Err(DepositIndexError::TerminalConflict);
        }
        let record = Self {
            version: INDEX_OBJECT_VERSION,
            wallet: self.wallet,
            consolidation: self.consolidation,
            sweep: self.sweep,
            sweep_sequence: self.sweep_sequence,
            inputs: self.inputs.clone(),
            attempt_high_water: self.attempt_high_water.max(evidence.terminal_attempt),
            status: PortableConsolidationStatus::LateSettled {
                settlement_sequence: statement.sequence,
                settlement_digest: statement.digest(),
                historical_attempt: completion.attempt().attempt(),
                historical_session: completion.attempt().session(),
                transaction: completion.transaction_id(),
                abandonment: evidence.clone(),
            },
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn consolidation_id(&self) -> ConsolidationId {
        self.consolidation
    }

    #[must_use]
    pub const fn sweep_id(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub const fn sweep_sequence(&self) -> u64 {
        self.sweep_sequence
    }

    #[must_use]
    pub fn inputs(&self) -> &[WalletOutputId] {
        &self.inputs
    }

    #[must_use]
    pub const fn attempt_high_water(&self) -> u64 {
        self.attempt_high_water
    }

    #[must_use]
    pub const fn status(&self) -> &PortableConsolidationStatus {
        &self.status
    }

    /// Stable digest of the exact witness-independent portable terminal value.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self)
            .expect("validated portable terminal serialization is infallible");
        derive_hash("threshold-monero/deposit-index/portable-terminal/v1", &bytes)
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.version != INDEX_OBJECT_VERSION
            || self.wallet.0 == [0; 32]
            || self.consolidation.0 == [0; 32]
            || self.sweep.0 == [0; 32]
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_DEPOSIT_INDEX_TERMINAL_INPUTS
            || self.inputs.iter().any(|output| output.transaction == [0; 32])
            || self.inputs.windows(2).any(|pair| pair[0] >= pair[1])
            || self.attempt_high_water == 0
        {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        match &self.status {
            PortableConsolidationStatus::Completed {
                statement_sequence,
                statement_digest,
                attempt,
                session,
                transaction,
            } => {
                if *statement_sequence == 0
                    || *statement_digest == [0; 32]
                    || *attempt == 0
                    || self.attempt_high_water < *attempt
                    || session.0 == [0; 32]
                    || *transaction == [0; 32]
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
            PortableConsolidationStatus::Abandoned { evidence } => {
                evidence.validate()?;
                if self.attempt_high_water != evidence.terminal_attempt {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
            PortableConsolidationStatus::LateSettled {
                settlement_sequence,
                settlement_digest,
                historical_attempt,
                historical_session,
                transaction,
                abandonment,
            } => {
                abandonment.validate()?;
                if *settlement_sequence <= abandonment.statement_sequence
                    || *settlement_digest == [0; 32]
                    || *historical_attempt == 0
                    || *historical_attempt > abandonment.terminal_attempt
                    || historical_session.0 == [0; 32]
                    || *transaction == [0; 32]
                    || self.attempt_high_water < abandonment.terminal_attempt
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
        }
        Ok(())
    }

    fn current_statement_reference(&self) -> (u64, [u8; 32]) {
        match &self.status {
            PortableConsolidationStatus::Completed {
                statement_sequence, statement_digest, ..
            } => (*statement_sequence, *statement_digest),
            PortableConsolidationStatus::Abandoned { evidence } => {
                (evidence.statement_sequence, evidence.statement_digest)
            }
            PortableConsolidationStatus::LateSettled {
                settlement_sequence,
                settlement_digest,
                ..
            } => (*settlement_sequence, *settlement_digest),
        }
    }

    fn abandonment_reference(&self) -> Option<(u64, [u8; 32])> {
        match &self.status {
            PortableConsolidationStatus::Abandoned { evidence }
            | PortableConsolidationStatus::LateSettled { abandonment: evidence, .. } => {
                Some((evidence.statement_sequence, evidence.statement_digest))
            }
            PortableConsolidationStatus::Completed { .. } => None,
        }
    }

    fn required_session_tombstones(&self) -> Vec<(SessionId, u64, u64, [u8; 32])> {
        match &self.status {
            PortableConsolidationStatus::Completed {
                statement_sequence,
                statement_digest,
                attempt,
                session,
                ..
            } => vec![(*session, *attempt, *statement_sequence, *statement_digest)],
            PortableConsolidationStatus::Abandoned { evidence } => vec![(
                evidence.terminal_session,
                evidence.terminal_attempt,
                evidence.statement_sequence,
                evidence.statement_digest,
            )],
            PortableConsolidationStatus::LateSettled {
                settlement_sequence,
                settlement_digest,
                historical_attempt,
                historical_session,
                abandonment,
                ..
            } => {
                let mut sessions = vec![(
                    abandonment.terminal_session,
                    abandonment.terminal_attempt,
                    abandonment.statement_sequence,
                    abandonment.statement_digest,
                )];
                if *historical_session != abandonment.terminal_session {
                    sessions.push((
                        *historical_session,
                        *historical_attempt,
                        *settlement_sequence,
                        *settlement_digest,
                    ));
                }
                sessions
            }
        }
    }
}

/// Permanent first terminal claim of one scanner output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableOutputClaimRecord {
    version: u16,
    wallet: DepositWalletId,
    output: WalletOutputId,
    consolidation: ConsolidationId,
    sweep: SweepId,
    statement_sequence: u64,
    statement_digest: [u8; 32],
}

impl PortableOutputClaimRecord {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn output(&self) -> WalletOutputId {
        self.output
    }

    #[must_use]
    pub const fn consolidation_id(&self) -> ConsolidationId {
        self.consolidation
    }

    #[must_use]
    pub const fn sweep_id(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub const fn statement_sequence(&self) -> u64 {
        self.statement_sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.version != INDEX_OBJECT_VERSION
            || self.wallet.0 == [0; 32]
            || self.output.transaction == [0; 32]
            || self.consolidation.0 == [0; 32]
            || self.sweep.0 == [0; 32]
            || self.statement_sequence == 0
            || self.statement_digest == [0; 32]
        {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        Ok(())
    }
}

/// Permanent portable tombstone for a signing session exposed by a certified terminal statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableSigningSessionTombstone {
    version: u16,
    wallet: DepositWalletId,
    session: SessionId,
    consolidation: ConsolidationId,
    sweep: SweepId,
    attempt: u64,
    statement_sequence: u64,
    statement_digest: [u8; 32],
}

impl PortableSigningSessionTombstone {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn consolidation_id(&self) -> ConsolidationId {
        self.consolidation
    }

    #[must_use]
    pub const fn sweep_id(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn statement_sequence(&self) -> u64 {
        self.statement_sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.version != INDEX_OBJECT_VERSION
            || self.wallet.0 == [0; 32]
            || self.session.0 == [0; 32]
            || self.consolidation.0 == [0; 32]
            || self.sweep.0 == [0; 32]
            || self.attempt == 0
            || self.statement_sequence == 0
            || self.statement_digest == [0; 32]
        {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        Ok(())
    }
}

/// Portable monotonic high-water for assigning future sweep-plan sequence numbers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableSweepHighWaterRecord {
    version: u16,
    wallet: DepositWalletId,
    next_sweep_sequence: u64,
}

impl PortableSweepHighWaterRecord {
    #[must_use]
    pub const fn next_sweep_sequence(&self) -> u64 {
        self.next_sweep_sequence
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.version != INDEX_OBJECT_VERSION
            || self.wallet.0 == [0; 32]
            || self.next_sweep_sequence == 0
        {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        Ok(())
    }
}

/// Party-local permanent no-double-sign tombstone for one global ledger sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedLedgerSlot {
    sequence: u64,
    statement_digest: [u8; 32],
}

impl SignedLedgerSlot {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn statement_digest(self) -> [u8; 32] {
        self.statement_digest
    }

    fn validate(self) -> Result<(), DepositIndexError> {
        if self.sequence == 0 || self.statement_digest == [0; 32] {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        Ok(())
    }
}

/// Permanent local no-double-attest binding for one certified output observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedDepositObservationSlot {
    allocation_statement: [u8; 32],
    observation_fact: [u8; 32],
    output: WalletOutputId,
    output_key: [u8; 32],
}

impl SignedDepositObservationSlot {
    fn from_statement(statement: &DepositObservationStatement) -> Self {
        Self {
            allocation_statement: statement.allocation_statement(),
            observation_fact: statement.fact_digest(),
            output: statement.output(),
            output_key: statement.output_key(),
        }
    }

    /// Match every issuer-independent field which was durably reserved before signing.
    ///
    /// This is crate-visible so the wallet-snapshot store can authenticate an exact committed
    /// readback without exposing a raw slot constructor.
    pub(crate) fn matches_statement(self, statement: &DepositObservationStatement) -> bool {
        self.allocation_statement == statement.allocation_statement()
            && self.observation_fact == statement.fact_digest()
            && self.output == statement.output()
            && self.output_key == statement.output_key()
    }

    #[must_use]
    pub const fn allocation_statement(self) -> [u8; 32] {
        self.allocation_statement
    }

    #[must_use]
    pub const fn observation_fact(self) -> [u8; 32] {
        self.observation_fact
    }

    #[must_use]
    pub const fn output(self) -> WalletOutputId {
        self.output
    }

    #[must_use]
    pub const fn output_key(self) -> [u8; 32] {
        self.output_key
    }

    fn validate(self) -> Result<(), DepositIndexError> {
        if self.allocation_statement == [0; 32]
            || self.observation_fact == [0; 32]
            || self.output.transaction == [0; 32]
            || self.output_key == [0; 32]
        {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        Ok(())
    }
}

/// Party-local permanent no-double-sign tombstone for one deposit-index checkpoint sequence.
///
/// The slot commits every witness-independent value which can distinguish two checkpoint
/// decisions at the same sequence. Wallet and party bindings live in the enclosing
/// [`LocalDepositSafetyRecord`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedIndexCheckpointSlot {
    checkpoint_sequence: u64,
    ledger_decision: [u8; 32],
    previous_logical_head: [u8; 32],
    resulting_logical_head: [u8; 32],
    decision: [u8; 32],
    /// Exact local admission instant durably burned before the checkpoint witness is exposed.
    reserved_at: u64,
}

impl SignedIndexCheckpointSlot {
    pub(crate) fn new(
        checkpoint_sequence: u64,
        ledger_decision: [u8; 32],
        previous_logical_head: [u8; 32],
        resulting_logical_head: [u8; 32],
        decision: [u8; 32],
        reserved_at: u64,
    ) -> Result<Self, DepositIndexError> {
        let slot = Self {
            checkpoint_sequence,
            ledger_decision,
            previous_logical_head,
            resulting_logical_head,
            decision,
            reserved_at,
        };
        slot.validate()?;
        Ok(slot)
    }

    #[must_use]
    pub const fn checkpoint_sequence(self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn ledger_decision(self) -> [u8; 32] {
        self.ledger_decision
    }

    #[must_use]
    pub const fn previous_logical_head(self) -> [u8; 32] {
        self.previous_logical_head
    }

    #[must_use]
    pub const fn resulting_logical_head(self) -> [u8; 32] {
        self.resulting_logical_head
    }

    #[must_use]
    pub const fn decision(self) -> [u8; 32] {
        self.decision
    }

    #[must_use]
    pub const fn reserved_at(self) -> u64 {
        self.reserved_at
    }

    pub(crate) fn validate(self) -> Result<(), DepositIndexError> {
        if self.checkpoint_sequence == 0
            || self.ledger_decision == [0; 32]
            || self.previous_logical_head == [0; 32]
            || self.resulting_logical_head == [0; 32]
            || self.decision == [0; 32]
            || self.reserved_at == 0
            || self.reserved_at > 253_402_300_799
        {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        Ok(())
    }
}

/// Party-local locator for one exact archive-authorized ledger/checkpoint event.
///
/// Witness-bearing artifacts are deliberately excluded from the portable root because honest
/// replicas may retain different valid `n-f` witness subsets for the same decisions. Live
/// insertion is authorized only by [`VerifiedDepositArchiveLedgerLocator`]; these serialized
/// fields exist solely so the already-authorized local safety journal can replay exactly after a
/// restart. A caller cannot substitute the current/latest checkpoint for the historical one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertifiedEntryLocator {
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

impl CertifiedEntryLocator {
    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
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

    fn validate(self, wallet: DepositWalletId) -> Result<(), DepositIndexError> {
        if self.wallet != wallet
            || self.wallet.0 == [0; 32]
            || self.checkpoint_sequence == 0
            || self.checkpoint_decision == [0; 32]
            || self.checkpoint_certificate_digest == [0; 32]
            || self.ledger_sequence == 0
            || self.ledger_statement == [0; 32]
            || self.checkpoint_sequence < self.ledger_sequence
        {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        validate_locator_reference(
            self.event_artifact,
            wallet,
            DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
            MAX_DEPOSIT_ARCHIVE_EVENT_BYTES,
        )?;
        validate_locator_reference(
            self.ledger_artifact,
            wallet,
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES,
        )?;
        validate_locator_reference(
            self.checkpoint_artifact,
            wallet,
            DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
            MAX_DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT_BYTES,
        )?;
        Ok(())
    }
}

fn validate_locator_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
    kind: WalletArtifactKind,
    maximum: usize,
) -> Result<(), DepositIndexError> {
    let canonical = WalletArtifactRef::from_parts(
        reference.wallet_id(),
        reference.kind(),
        reference.plaintext_len(),
        reference.digest(),
    )?;
    let length = usize::try_from(canonical.plaintext_len())
        .map_err(|_| DepositIndexError::InvalidLocalSafetyRecord)?;
    if canonical != reference
        || canonical.wallet_id() != WalletId(wallet.0)
        || canonical.kind() != kind
        || length == 0
        || length > maximum
    {
        return Err(DepositIndexError::InvalidLocalSafetyRecord);
    }
    Ok(())
}

/// Immutable value in the party-local safety tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LocalSafetyValue {
    ProposedIndex {
        index: DepositSubaddressIndex,
        request: LedgerRequestId,
        binding: RequestBinding,
    },
    ReservedRequest {
        request: LedgerRequestId,
        binding: RequestBinding,
        index: DepositSubaddressIndex,
    },
    FirstUsed {
        index: DepositSubaddressIndex,
        first_used_at: u64,
    },
    OutputBinding {
        output: WalletOutputId,
        output_key: [u8; 32],
        subaddress: Option<DepositSubaddressIndex>,
        amount_atomic_units: u64,
    },
    OneTimeOutputKey {
        output_key: [u8; 32],
        output: WalletOutputId,
        subaddress: Option<DepositSubaddressIndex>,
        amount_atomic_units: u64,
    },
    SigningSessionTombstone {
        consolidation: ConsolidationId,
        sweep: SweepId,
        attempt: u64,
        session: SessionId,
        evidence: [u8; 32],
    },
    AttemptHighWater {
        consolidation: ConsolidationId,
        sweep: SweepId,
        through_attempt: u64,
    },
    NextSweepSequence {
        next_sequence: u64,
    },
    SignedDepositObservationOutput(SignedDepositObservationSlot),
    SignedDepositObservationKey(SignedDepositObservationSlot),
    SignedLedgerSlot(SignedLedgerSlot),
    SignedIndexCheckpointSlot(SignedIndexCheckpointSlot),
    CertifiedEntryLocator(CertifiedEntryLocator),
    CertifiedCheckpointLocator(CertifiedEntryLocator),
}

/// Party- and wallet-bound local safety record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocalDepositSafetyRecord {
    version: u16,
    wallet: DepositWalletId,
    party: PartyId,
    value: LocalSafetyValue,
}

impl LocalDepositSafetyRecord {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn party(&self) -> PartyId {
        self.party
    }

    #[must_use]
    pub const fn value(&self) -> &LocalSafetyValue {
        &self.value
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        if self.version != INDEX_OBJECT_VERSION || self.wallet.0 == [0; 32] || self.party.0 == 0 {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        match &self.value {
            LocalSafetyValue::ProposedIndex { request, binding, .. }
            | LocalSafetyValue::ReservedRequest { request, binding, .. } => {
                if request.0 == [0; 32] || binding.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
            LocalSafetyValue::FirstUsed { first_used_at, .. } => {
                if *first_used_at == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
            LocalSafetyValue::OutputBinding { output, output_key, amount_atomic_units, .. }
            | LocalSafetyValue::OneTimeOutputKey {
                output, output_key, amount_atomic_units, ..
            } => {
                if output.transaction == [0; 32]
                    || *output_key == [0; 32]
                    || *amount_atomic_units == 0
                {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
            LocalSafetyValue::SigningSessionTombstone {
                consolidation,
                sweep,
                attempt,
                session,
                evidence,
            } => {
                if consolidation.0 == [0; 32]
                    || sweep.0 == [0; 32]
                    || *attempt == 0
                    || session.0 == [0; 32]
                    || *evidence == [0; 32]
                {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
            LocalSafetyValue::AttemptHighWater { consolidation, sweep, through_attempt } => {
                if consolidation.0 == [0; 32] || sweep.0 == [0; 32] || *through_attempt == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
            LocalSafetyValue::NextSweepSequence { next_sequence } => {
                if *next_sequence == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
            LocalSafetyValue::SignedDepositObservationOutput(slot)
            | LocalSafetyValue::SignedDepositObservationKey(slot) => slot.validate()?,
            LocalSafetyValue::SignedLedgerSlot(slot) => slot.validate()?,
            LocalSafetyValue::SignedIndexCheckpointSlot(slot) => slot.validate()?,
            LocalSafetyValue::CertifiedEntryLocator(locator)
            | LocalSafetyValue::CertifiedCheckpointLocator(locator) => {
                locator.validate(self.wallet)?
            }
        }
        Ok(())
    }
}

/// Canonical full alias key retained in every leaf. The separately derived 256-bit hash chooses
/// the HAMT path; it is never treated as proof that two full keys are equal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
enum CanonicalIndexKey {
    PortableSequence {
        wallet: DepositWalletId,
        sequence: u64,
    },
    PortableRequest {
        wallet: DepositWalletId,
        request: LedgerRequestId,
    },
    PortableAddress {
        wallet: DepositWalletId,
        address: String,
    },
    PortableIndex {
        wallet: DepositWalletId,
        index: DepositSubaddressIndex,
    },
    PortableSubaddressSpendKey {
        wallet: DepositWalletId,
        spend_key: [u8; 32],
    },
    PortableFirstUsed {
        wallet: DepositWalletId,
        index: DepositSubaddressIndex,
    },
    PortableObservedOutput {
        wallet: DepositWalletId,
        output: WalletOutputId,
    },
    PortableObservedOneTimeOutputKey {
        wallet: DepositWalletId,
        output_key: [u8; 32],
    },
    PortableConsolidation {
        wallet: DepositWalletId,
        consolidation: ConsolidationId,
    },
    PortableSweep {
        wallet: DepositWalletId,
        sweep: SweepId,
    },
    PortableClaimedOutput {
        wallet: DepositWalletId,
        output: WalletOutputId,
    },
    PortableSigningSession {
        wallet: DepositWalletId,
        session: SessionId,
    },
    PortableNextSweepSequence {
        wallet: DepositWalletId,
    },
    LocalProposedIndex {
        wallet: DepositWalletId,
        party: PartyId,
        index: DepositSubaddressIndex,
    },
    LocalReservedRequest {
        wallet: DepositWalletId,
        party: PartyId,
        request: LedgerRequestId,
    },
    LocalFirstUsed {
        wallet: DepositWalletId,
        party: PartyId,
        index: DepositSubaddressIndex,
    },
    LocalOutput {
        wallet: DepositWalletId,
        party: PartyId,
        output: WalletOutputId,
    },
    LocalOneTimeOutputKey {
        wallet: DepositWalletId,
        party: PartyId,
        output_key: [u8; 32],
    },
    LocalSigningSession {
        wallet: DepositWalletId,
        party: PartyId,
        session: SessionId,
    },
    LocalAttemptHighWater {
        wallet: DepositWalletId,
        party: PartyId,
        sweep: SweepId,
    },
    LocalNextSweepSequence {
        wallet: DepositWalletId,
        party: PartyId,
    },
    LocalSignedDepositObservationOutput {
        wallet: DepositWalletId,
        party: PartyId,
        output: WalletOutputId,
    },
    LocalSignedDepositObservationKey {
        wallet: DepositWalletId,
        party: PartyId,
        output_key: [u8; 32],
    },
    LocalSignedLedgerSlot {
        wallet: DepositWalletId,
        party: PartyId,
        sequence: u64,
    },
    LocalSignedIndexCheckpointSlot {
        wallet: DepositWalletId,
        party: PartyId,
        checkpoint_sequence: u64,
    },
    LocalCertifiedEntryLocator {
        wallet: DepositWalletId,
        party: PartyId,
        sequence: u64,
    },
    LocalCertifiedCheckpointLocator {
        wallet: DepositWalletId,
        party: PartyId,
        checkpoint_sequence: u64,
    },
}

impl CanonicalIndexKey {
    fn namespace(&self) -> DepositIndexNamespace {
        match self {
            Self::PortableSequence { wallet, .. }
            | Self::PortableRequest { wallet, .. }
            | Self::PortableAddress { wallet, .. }
            | Self::PortableIndex { wallet, .. }
            | Self::PortableSubaddressSpendKey { wallet, .. }
            | Self::PortableFirstUsed { wallet, .. }
            | Self::PortableObservedOutput { wallet, .. }
            | Self::PortableObservedOneTimeOutputKey { wallet, .. }
            | Self::PortableConsolidation { wallet, .. }
            | Self::PortableSweep { wallet, .. }
            | Self::PortableClaimedOutput { wallet, .. }
            | Self::PortableSigningSession { wallet, .. }
            | Self::PortableNextSweepSequence { wallet } => {
                DepositIndexNamespace::Portable { wallet: *wallet }
            }
            Self::LocalProposedIndex { wallet, party, .. }
            | Self::LocalReservedRequest { wallet, party, .. }
            | Self::LocalFirstUsed { wallet, party, .. }
            | Self::LocalOutput { wallet, party, .. }
            | Self::LocalOneTimeOutputKey { wallet, party, .. }
            | Self::LocalSigningSession { wallet, party, .. }
            | Self::LocalAttemptHighWater { wallet, party, .. }
            | Self::LocalNextSweepSequence { wallet, party }
            | Self::LocalSignedDepositObservationOutput { wallet, party, .. }
            | Self::LocalSignedDepositObservationKey { wallet, party, .. }
            | Self::LocalSignedLedgerSlot { wallet, party, .. }
            | Self::LocalSignedIndexCheckpointSlot { wallet, party, .. }
            | Self::LocalCertifiedEntryLocator { wallet, party, .. }
            | Self::LocalCertifiedCheckpointLocator { wallet, party, .. } => {
                DepositIndexNamespace::LocalSafety { wallet: *wallet, party: *party }
            }
        }
    }

    fn path_hash(&self) -> Result<[u8; 32], DepositIndexError> {
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositIndexError::Serialization)?;
        #[cfg(test)]
        if let Some(forced) =
            TEST_FORCED_PATH_HASHES.with(|hashes| hashes.borrow().get(&bytes).copied())
        {
            return Ok(forced);
        }
        Ok(derive_hash("threshold-monero/deposit-index/alias-key/v1", &bytes))
    }
}

#[cfg(test)]
thread_local! {
    static TEST_FORCED_PATH_HASHES: RefCell<BTreeMap<Vec<u8>, [u8; 32]>> =
        const { RefCell::new(BTreeMap::new()) };
}

#[cfg(test)]
fn force_test_path_hash(
    key: &CanonicalIndexKey,
    path_hash: [u8; 32],
) -> Result<(), DepositIndexError> {
    let bytes = postcard::to_allocvec(key).map_err(|_| DepositIndexError::Serialization)?;
    TEST_FORCED_PATH_HASHES.with(|hashes| {
        hashes.borrow_mut().insert(bytes, path_hash);
    });
    Ok(())
}

#[cfg(test)]
fn clear_test_path_hashes() {
    TEST_FORCED_PATH_HASHES.with(|hashes| hashes.borrow_mut().clear());
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HamtEntry {
    path_hash: [u8; 32],
    key: CanonicalIndexKey,
    value: DepositIndexObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum HamtNodeBody {
    Leaf { entries: Vec<HamtEntry> },
    Branch { bitmap: u16, children: Vec<DepositIndexObjectId> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HamtNode {
    version: u16,
    namespace: DepositIndexNamespace,
    depth: u8,
    entries: u64,
    body: HamtNodeBody,
}

impl HamtNode {
    fn validate_shape(&self) -> Result<(), DepositIndexError> {
        self.namespace.validate()?;
        if self.version != INDEX_OBJECT_VERSION || self.depth > MAX_HAMT_DEPTH || self.entries == 0
        {
            return Err(DepositIndexError::InvalidNode);
        }
        match &self.body {
            HamtNodeBody::Leaf { entries } => {
                if entries.is_empty() || entries.len() > MAX_DEPOSIT_INDEX_LEAF_ENTRIES {
                    return Err(DepositIndexError::InvalidNode);
                }
                if self.entries != entries.len() as u64 {
                    return Err(DepositIndexError::InvalidNode);
                }
                let mut previous: Option<&CanonicalIndexKey> = None;
                for entry in entries {
                    entry.value.validate()?;
                    if entry.key.namespace() != self.namespace
                        || entry.path_hash != entry.key.path_hash()?
                        || previous.is_some_and(|key| key >= &entry.key)
                    {
                        return Err(DepositIndexError::InvalidNode);
                    }
                    previous = Some(&entry.key);
                }
            }
            HamtNodeBody::Branch { bitmap, children } => {
                if self.depth >= MAX_HAMT_DEPTH
                    || *bitmap == 0
                    || children.len() != bitmap.count_ones() as usize
                    || self.entries <= MAX_DEPOSIT_INDEX_LEAF_ENTRIES as u64
                {
                    return Err(DepositIndexError::InvalidNode);
                }
                for child in children {
                    child.validate()?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum StoredIndexObject {
    Node(HamtNode),
    PortableAllocation(PortableAllocationRecord),
    PortableLedgerStatement(PortableLedgerStatementRecord),
    PortableFirstUse(PortableFirstUseRecord),
    PortableDepositOutput(PortableDepositOutputRecord),
    PortableTerminal(PortableConsolidationTerminalRecord),
    PortableOutputClaim(PortableOutputClaimRecord),
    PortableSigningSession(PortableSigningSessionTombstone),
    PortableSweepHighWater(PortableSweepHighWaterRecord),
    LocalSafety(LocalDepositSafetyRecord),
}

impl StoredIndexObject {
    fn wallet_id(&self) -> DepositWalletId {
        match self {
            Self::Node(node) => node.namespace.wallet(),
            Self::PortableAllocation(record) => record.wallet_id(),
            Self::PortableLedgerStatement(record) => record.wallet_id(),
            Self::PortableFirstUse(record) => record.wallet_id(),
            Self::PortableDepositOutput(record) => record.wallet_id(),
            Self::PortableTerminal(record) => record.wallet,
            Self::PortableOutputClaim(record) => record.wallet,
            Self::PortableSigningSession(record) => record.wallet,
            Self::PortableSweepHighWater(record) => record.wallet,
            Self::LocalSafety(record) => record.wallet_id(),
        }
    }

    fn validate(&self) -> Result<(), DepositIndexError> {
        match self {
            Self::Node(node) => node.validate_shape(),
            Self::PortableAllocation(record) => record.validate(),
            Self::PortableLedgerStatement(record) => record.validate(),
            Self::PortableFirstUse(record) => record.validate(),
            Self::PortableDepositOutput(record) => record.validate(),
            Self::PortableTerminal(record) => record.validate(),
            Self::PortableOutputClaim(record) => record.validate(),
            Self::PortableSigningSession(record) => record.validate(),
            Self::PortableSweepHighWater(record) => record.validate(),
            Self::LocalSafety(record) => record.validate(),
        }
    }
}

fn derive_hash(domain: &'static str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn encode_object(
    object: &StoredIndexObject,
) -> Result<(DepositIndexObjectId, Vec<u8>), DepositIndexError> {
    object.validate()?;
    let bytes = postcard::to_allocvec(object).map_err(|_| DepositIndexError::Serialization)?;
    if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_OBJECT_BYTES {
        return Err(DepositIndexError::ObjectTooLarge);
    }
    let storage = WalletArtifactRef::for_contents(
        WalletId(object.wallet_id().0),
        DEPOSIT_INDEX_ARTIFACT_KIND,
        &bytes,
    )?;
    let id = DepositIndexObjectId(storage);
    id.validate()?;
    Ok((id, bytes))
}

fn decode_object(
    expected: DepositIndexObjectId,
    bytes: &[u8],
) -> Result<StoredIndexObject, DepositIndexError> {
    expected.validate()?;
    if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_OBJECT_BYTES {
        return Err(DepositIndexError::ObjectTooLarge);
    }
    expected
        .storage_reference()
        .verify_contents(bytes)
        .map_err(|_| DepositIndexError::ObjectAuthentication)?;
    let (object, trailing) = postcard::take_from_bytes::<StoredIndexObject>(bytes)
        .map_err(|_| DepositIndexError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositIndexError::NonCanonicalObject);
    }
    object.validate()?;
    let (canonical_id, canonical) = encode_object(&object)?;
    if canonical_id != expected || canonical != bytes {
        return Err(DepositIndexError::NonCanonicalObject);
    }
    Ok(object)
}

/// Canonically verified portable-index object used by bounded transfer reachability checks.
///
/// The token is intentionally not deserializable. Party-local safety values are rejected before
/// any caller can return their plaintext to a remote peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPortableIndexObject {
    node: bool,
    children: Vec<DepositIndexObjectId>,
}

impl VerifiedPortableIndexObject {
    #[must_use]
    pub const fn is_node(&self) -> bool {
        self.node
    }

    #[must_use]
    pub fn children(&self) -> &[DepositIndexObjectId] {
        &self.children
    }
}

/// Authenticate and canonically decode one exact portable-index object and expose only its
/// bounded child edges. A local-safety node or value fails closed even though it uses the same
/// encrypted artifact kind.
pub fn verify_portable_index_object(
    wallet: DepositWalletId,
    expected: DepositIndexObjectId,
    bytes: &[u8],
) -> Result<VerifiedPortableIndexObject, DepositIndexError> {
    if wallet.0 == [0; 32] || expected.wallet_id() != wallet {
        return Err(DepositIndexError::InvalidObjectId);
    }
    let object = decode_object(expected, bytes)?;
    let (node, children) = match object {
        StoredIndexObject::Node(node) => {
            if node.namespace != (DepositIndexNamespace::Portable { wallet }) {
                return Err(DepositIndexError::InvalidHead);
            }
            let children = match node.body {
                HamtNodeBody::Leaf { entries } => {
                    entries.into_iter().map(|entry| entry.value).collect()
                }
                HamtNodeBody::Branch { children, .. } => children,
            };
            (true, children)
        }
        StoredIndexObject::PortableAllocation(record) if record.wallet_id() == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableLedgerStatement(record) if record.wallet_id() == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableFirstUse(record) if record.wallet_id() == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableDepositOutput(record) if record.wallet_id() == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableTerminal(record) if record.wallet == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableOutputClaim(record) if record.wallet == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableSigningSession(record) if record.wallet == wallet => {
            (false, Vec::new())
        }
        StoredIndexObject::PortableSweepHighWater(record) if record.wallet == wallet => {
            (false, Vec::new())
        }
        _ => return Err(DepositIndexError::InvalidHead),
    };
    Ok(VerifiedPortableIndexObject { node, children })
}

fn digest_nibble(digest: [u8; 32], depth: u8) -> Result<u8, DepositIndexError> {
    if depth >= PRIMARY_HAMT_DEPTH {
        return Err(DepositIndexError::DepthExhausted);
    }
    let byte = digest[usize::from(depth / 2)];
    Ok(if depth % 2 == 0 { byte >> 4 } else { byte & 0x0f })
}

fn routing_nibble(
    path_hash: [u8; 32],
    key: &CanonicalIndexKey,
    depth: u8,
) -> Result<u8, DepositIndexError> {
    if depth < PRIMARY_HAMT_DEPTH {
        return digest_nibble(path_hash, depth);
    }
    if depth >= MAX_HAMT_DEPTH {
        return Err(DepositIndexError::DepthExhausted);
    }
    let key_bytes = postcard::to_allocvec(key).map_err(|_| DepositIndexError::Serialization)?;
    let mut collision_material = Vec::with_capacity(40 + key_bytes.len());
    collision_material.extend_from_slice(&path_hash);
    collision_material.extend_from_slice(&(key_bytes.len() as u64).to_le_bytes());
    collision_material.extend_from_slice(&key_bytes);
    let collision_hash =
        derive_hash("threshold-monero/deposit-index/collision-route/v1", &collision_material);
    digest_nibble(collision_hash, depth - PRIMARY_HAMT_DEPTH)
}

fn bitmap_position(bitmap: u16, slot: u8) -> usize {
    let lower = if slot == 0 { 0 } else { bitmap & ((1_u16 << slot) - 1) };
    lower.count_ones() as usize
}

fn increment_subaddress_index(
    index: DepositSubaddressIndex,
) -> Result<DepositSubaddressIndex, DepositIndexError> {
    let address =
        index.address().checked_add(1).ok_or(DepositIndexError::SubaddressIndexExhausted)?;
    Ok(DepositSubaddressIndex::new(index.account(), address)?)
}

fn sequence_alias(wallet: DepositWalletId, sequence: u64) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableSequence { wallet, sequence }
}

fn request_alias(wallet: DepositWalletId, request: LedgerRequestId) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableRequest { wallet, request }
}

fn address_alias(wallet: DepositWalletId, address: &CanonicalDepositAddress) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableAddress { wallet, address: address.as_str().to_owned() }
}

fn index_alias(wallet: DepositWalletId, index: DepositSubaddressIndex) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableIndex { wallet, index }
}

fn portable_first_used_alias(
    wallet: DepositWalletId,
    index: DepositSubaddressIndex,
) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableFirstUsed { wallet, index }
}

fn portable_observed_output_alias(
    wallet: DepositWalletId,
    output: WalletOutputId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableObservedOutput { wallet, output }
}

fn portable_observed_output_key_alias(
    wallet: DepositWalletId,
    output_key: [u8; 32],
) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableObservedOneTimeOutputKey { wallet, output_key }
}

pub(crate) fn subaddress_spend_key(
    address: &CanonicalDepositAddress,
) -> Result<[u8; 32], DepositIndexError> {
    address.validate()?;
    let network = match address.network() {
        NetworkKind::Regtest | NetworkKind::Mainnet => Network::Mainnet,
        NetworkKind::Testnet => Network::Testnet,
    };
    let parsed = MoneroAddress::from_str(network, address.as_str())
        .map_err(|_| DepositIndexError::InvalidPortableRecord)?;
    if !parsed.is_subaddress() {
        return Err(DepositIndexError::InvalidPortableRecord);
    }
    Ok(parsed.spend().compress().to_bytes())
}

fn subaddress_spend_key_alias(
    wallet: DepositWalletId,
    spend_key: [u8; 32],
) -> Result<CanonicalIndexKey, DepositIndexError> {
    if spend_key == [0; 32] {
        return Err(DepositIndexError::InvalidPortableRecord);
    }
    Ok(CanonicalIndexKey::PortableSubaddressSpendKey { wallet, spend_key })
}

fn consolidation_alias(
    wallet: DepositWalletId,
    consolidation: ConsolidationId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableConsolidation { wallet, consolidation }
}

fn sweep_alias(wallet: DepositWalletId, sweep: SweepId) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableSweep { wallet, sweep }
}

fn claimed_output_alias(wallet: DepositWalletId, output: WalletOutputId) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableClaimedOutput { wallet, output }
}

fn portable_signing_session_alias(
    wallet: DepositWalletId,
    session: SessionId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableSigningSession { wallet, session }
}

fn portable_next_sweep_sequence_alias(wallet: DepositWalletId) -> CanonicalIndexKey {
    CanonicalIndexKey::PortableNextSweepSequence { wallet }
}

fn proposed_index_alias(
    wallet: DepositWalletId,
    party: PartyId,
    index: DepositSubaddressIndex,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalProposedIndex { wallet, party, index }
}

fn reserved_request_alias(
    wallet: DepositWalletId,
    party: PartyId,
    request: LedgerRequestId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalReservedRequest { wallet, party, request }
}

fn used_alias(
    wallet: DepositWalletId,
    party: PartyId,
    index: DepositSubaddressIndex,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalFirstUsed { wallet, party, index }
}

fn output_alias(
    wallet: DepositWalletId,
    party: PartyId,
    output: WalletOutputId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalOutput { wallet, party, output }
}

fn one_time_output_key_alias(
    wallet: DepositWalletId,
    party: PartyId,
    output_key: [u8; 32],
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalOneTimeOutputKey { wallet, party, output_key }
}

fn local_signing_session_alias(
    wallet: DepositWalletId,
    party: PartyId,
    session: SessionId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalSigningSession { wallet, party, session }
}

fn local_attempt_high_water_alias(
    wallet: DepositWalletId,
    party: PartyId,
    sweep: SweepId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalAttemptHighWater { wallet, party, sweep }
}

fn local_next_sweep_sequence_alias(wallet: DepositWalletId, party: PartyId) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalNextSweepSequence { wallet, party }
}

fn local_signed_observation_output_alias(
    wallet: DepositWalletId,
    party: PartyId,
    output: WalletOutputId,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalSignedDepositObservationOutput { wallet, party, output }
}

fn local_signed_observation_key_alias(
    wallet: DepositWalletId,
    party: PartyId,
    output_key: [u8; 32],
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalSignedDepositObservationKey { wallet, party, output_key }
}

fn local_signed_ledger_slot_alias(
    wallet: DepositWalletId,
    party: PartyId,
    sequence: u64,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalSignedLedgerSlot { wallet, party, sequence }
}

fn local_signed_index_checkpoint_slot_alias(
    wallet: DepositWalletId,
    party: PartyId,
    checkpoint_sequence: u64,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalSignedIndexCheckpointSlot { wallet, party, checkpoint_sequence }
}

fn local_certified_entry_locator_alias(
    wallet: DepositWalletId,
    party: PartyId,
    sequence: u64,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalCertifiedEntryLocator { wallet, party, sequence }
}

fn local_certified_checkpoint_locator_alias(
    wallet: DepositWalletId,
    party: PartyId,
    checkpoint_sequence: u64,
) -> CanonicalIndexKey {
    CanonicalIndexKey::LocalCertifiedCheckpointLocator { wallet, party, checkpoint_sequence }
}

/// Read-only content-addressed object source.
pub trait DepositIndexReader {
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError>;
}

/// Mutation surface required by the staged/verified/CAS/cleanup state machine.
pub trait DepositIndexCommitStore: DepositIndexReader {
    fn load_index_head(
        &self,
        namespace: DepositIndexNamespace,
    ) -> Result<Option<DepositIndexHead>, DepositIndexError>;

    /// Return `true` only if this call created the object. Existing bytes must be identical.
    fn stage_index_object(
        &mut self,
        id: DepositIndexObjectId,
        bytes: &[u8],
    ) -> Result<bool, DepositIndexError>;

    fn compare_and_swap_index_head(
        &mut self,
        expected: &DepositIndexHead,
        replacement: &DepositIndexHead,
    ) -> Result<bool, DepositIndexError>;

    fn remove_index_object(&mut self, id: DepositIndexObjectId) -> Result<(), DepositIndexError>;

    /// Return true when an installed root or another active staging manifest still references the
    /// object. Storage adapters should maintain this as generation/reference metadata; cleanup
    /// must not discover it by rescanning the complete lifetime tree.
    fn index_object_is_pinned(&self, id: DepositIndexObjectId) -> Result<bool, DepositIndexError>;
}

fn load_object<R: DepositIndexReader + ?Sized>(
    reader: &R,
    id: DepositIndexObjectId,
) -> Result<(StoredIndexObject, Vec<u8>), DepositIndexError> {
    let bytes = reader.load_index_object(id)?.ok_or(DepositIndexError::MissingObject)?;
    let object = decode_object(id, &bytes)?;
    Ok((object, bytes))
}

#[derive(Default)]
struct TreeValidation {
    reachable: BTreeSet<DepositIndexObjectId>,
    values: BTreeMap<DepositIndexObjectId, BTreeSet<CanonicalIndexKey>>,
}

fn validate_prefix(
    path_hash: [u8; 32],
    key: &CanonicalIndexKey,
    prefix: &[u8],
) -> Result<(), DepositIndexError> {
    for (depth, expected) in prefix.iter().copied().enumerate() {
        let depth = u8::try_from(depth).map_err(|_| DepositIndexError::InvalidNode)?;
        if routing_nibble(path_hash, key, depth)? != expected {
            return Err(DepositIndexError::InvalidNode);
        }
    }
    Ok(())
}

fn validate_tree_node<R: DepositIndexReader + ?Sized>(
    reader: &R,
    namespace: DepositIndexNamespace,
    id: DepositIndexObjectId,
    depth: u8,
    prefix: &mut Vec<u8>,
    validation: &mut TreeValidation,
) -> Result<u64, DepositIndexError> {
    if !validation.reachable.insert(id) {
        return Err(DepositIndexError::InvalidNode);
    }
    let (object, _) = load_object(reader, id)?;
    let StoredIndexObject::Node(node) = object else {
        return Err(DepositIndexError::InvalidNode);
    };
    if node.namespace != namespace || node.depth != depth || prefix.len() != usize::from(depth) {
        return Err(DepositIndexError::InvalidNode);
    }
    let counted = match &node.body {
        HamtNodeBody::Leaf { entries } => {
            for entry in entries {
                validate_prefix(entry.path_hash, &entry.key, prefix)?;
                validation.values.entry(entry.value).or_default().insert(entry.key.clone());
            }
            entries.len() as u64
        }
        HamtNodeBody::Branch { bitmap, children } => {
            let mut counted = 0_u64;
            let mut child_index = 0_usize;
            for slot in 0_u8..16 {
                if bitmap & (1_u16 << slot) == 0 {
                    continue;
                }
                prefix.push(slot);
                counted = counted
                    .checked_add(validate_tree_node(
                        reader,
                        namespace,
                        children[child_index],
                        depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?,
                        prefix,
                        validation,
                    )?)
                    .ok_or(DepositIndexError::InvalidEntryCoverage)?;
                prefix.pop();
                child_index += 1;
            }
            counted
        }
    };
    if counted != node.entries {
        return Err(DepositIndexError::InvalidEntryCoverage);
    }
    Ok(counted)
}

fn portable_record_aliases(
    record: &PortableAllocationRecord,
) -> Result<[CanonicalIndexKey; 5], DepositIndexError> {
    let allocation = record.allocation();
    Ok([
        sequence_alias(record.wallet_id(), record.statement.sequence),
        request_alias(record.wallet_id(), allocation.request),
        address_alias(record.wallet_id(), &allocation.address),
        index_alias(record.wallet_id(), allocation.address.index()),
        subaddress_spend_key_alias(record.wallet_id(), subaddress_spend_key(&allocation.address)?)?,
    ])
}

fn terminal_record_aliases(record: &PortableConsolidationTerminalRecord) -> [CanonicalIndexKey; 2] {
    [
        consolidation_alias(record.wallet, record.consolidation),
        sweep_alias(record.wallet, record.sweep),
    ]
}

fn portable_statement_key(record: &PortableLedgerStatementRecord) -> CanonicalIndexKey {
    sequence_alias(record.wallet_id(), record.statement.sequence)
}

fn portable_first_use_key(record: &PortableFirstUseRecord) -> CanonicalIndexKey {
    portable_first_used_alias(record.wallet, record.index)
}

fn portable_deposit_output_aliases(record: &PortableDepositOutputRecord) -> [CanonicalIndexKey; 2] {
    [
        portable_observed_output_alias(record.wallet, record.output),
        portable_observed_output_key_alias(record.wallet, record.output_key),
    ]
}

fn portable_output_claim_key(record: &PortableOutputClaimRecord) -> CanonicalIndexKey {
    claimed_output_alias(record.wallet, record.output)
}

fn portable_session_tombstone_key(record: &PortableSigningSessionTombstone) -> CanonicalIndexKey {
    portable_signing_session_alias(record.wallet, record.session)
}

fn portable_sweep_high_water_key(record: &PortableSweepHighWaterRecord) -> CanonicalIndexKey {
    portable_next_sweep_sequence_alias(record.wallet)
}

fn safety_record_alias(record: &LocalDepositSafetyRecord) -> CanonicalIndexKey {
    match &record.value {
        LocalSafetyValue::ProposedIndex { index, .. } => {
            proposed_index_alias(record.wallet, record.party, *index)
        }
        LocalSafetyValue::ReservedRequest { request, .. } => {
            reserved_request_alias(record.wallet, record.party, *request)
        }
        LocalSafetyValue::FirstUsed { index, .. } => {
            used_alias(record.wallet, record.party, *index)
        }
        LocalSafetyValue::OutputBinding { output, .. } => {
            output_alias(record.wallet, record.party, *output)
        }
        LocalSafetyValue::OneTimeOutputKey { output_key, .. } => {
            one_time_output_key_alias(record.wallet, record.party, *output_key)
        }
        LocalSafetyValue::SigningSessionTombstone { session, .. } => {
            local_signing_session_alias(record.wallet, record.party, *session)
        }
        LocalSafetyValue::AttemptHighWater { sweep, .. } => {
            local_attempt_high_water_alias(record.wallet, record.party, *sweep)
        }
        LocalSafetyValue::NextSweepSequence { .. } => {
            local_next_sweep_sequence_alias(record.wallet, record.party)
        }
        LocalSafetyValue::SignedDepositObservationOutput(slot) => {
            local_signed_observation_output_alias(record.wallet, record.party, slot.output)
        }
        LocalSafetyValue::SignedDepositObservationKey(slot) => {
            local_signed_observation_key_alias(record.wallet, record.party, slot.output_key)
        }
        LocalSafetyValue::SignedLedgerSlot(slot) => {
            local_signed_ledger_slot_alias(record.wallet, record.party, slot.sequence)
        }
        LocalSafetyValue::SignedIndexCheckpointSlot(slot) => {
            local_signed_index_checkpoint_slot_alias(
                record.wallet,
                record.party,
                slot.checkpoint_sequence,
            )
        }
        LocalSafetyValue::CertifiedEntryLocator(locator) => local_certified_entry_locator_alias(
            record.wallet,
            record.party,
            locator.ledger_sequence,
        ),
        LocalSafetyValue::CertifiedCheckpointLocator(locator) => {
            local_certified_checkpoint_locator_alias(
                record.wallet,
                record.party,
                locator.checkpoint_sequence,
            )
        }
    }
}

fn safety_record_counterpart(record: &LocalDepositSafetyRecord) -> Option<CanonicalIndexKey> {
    match record.value {
        LocalSafetyValue::ProposedIndex { request, .. } => {
            Some(reserved_request_alias(record.wallet, record.party, request))
        }
        LocalSafetyValue::ReservedRequest { index, .. } => {
            Some(proposed_index_alias(record.wallet, record.party, index))
        }
        LocalSafetyValue::OutputBinding { output_key, .. } => {
            Some(one_time_output_key_alias(record.wallet, record.party, output_key))
        }
        LocalSafetyValue::OneTimeOutputKey { output, .. } => {
            Some(output_alias(record.wallet, record.party, output))
        }
        LocalSafetyValue::SignedDepositObservationOutput(slot) => {
            Some(local_signed_observation_key_alias(record.wallet, record.party, slot.output_key))
        }
        LocalSafetyValue::SignedDepositObservationKey(slot) => {
            Some(local_signed_observation_output_alias(record.wallet, record.party, slot.output))
        }
        LocalSafetyValue::CertifiedEntryLocator(locator) => {
            Some(local_certified_checkpoint_locator_alias(
                record.wallet,
                record.party,
                locator.checkpoint_sequence,
            ))
        }
        LocalSafetyValue::CertifiedCheckpointLocator(locator) => {
            Some(local_certified_entry_locator_alias(
                record.wallet,
                record.party,
                locator.ledger_sequence,
            ))
        }
        LocalSafetyValue::FirstUsed { .. }
        | LocalSafetyValue::SigningSessionTombstone { .. }
        | LocalSafetyValue::AttemptHighWater { .. }
        | LocalSafetyValue::NextSweepSequence { .. }
        | LocalSafetyValue::SignedLedgerSlot(_)
        | LocalSafetyValue::SignedIndexCheckpointSlot(_) => None,
    }
}

fn safety_records_are_counterparts(
    left: &LocalDepositSafetyRecord,
    right: &LocalDepositSafetyRecord,
) -> bool {
    if left.wallet != right.wallet || left.party != right.party {
        return false;
    }
    match (&left.value, &right.value) {
        (
            LocalSafetyValue::ProposedIndex { index, request, binding },
            LocalSafetyValue::ReservedRequest {
                request: other_request,
                binding: other_binding,
                index: other_index,
            },
        )
        | (
            LocalSafetyValue::ReservedRequest {
                request: other_request,
                binding: other_binding,
                index: other_index,
            },
            LocalSafetyValue::ProposedIndex { index, request, binding },
        ) => index == other_index && request == other_request && binding == other_binding,
        (
            LocalSafetyValue::OutputBinding { output, output_key, subaddress, amount_atomic_units },
            LocalSafetyValue::OneTimeOutputKey {
                output_key: other_key,
                output: other_output,
                subaddress: other_subaddress,
                amount_atomic_units: other_amount,
            },
        )
        | (
            LocalSafetyValue::OneTimeOutputKey {
                output_key: other_key,
                output: other_output,
                subaddress: other_subaddress,
                amount_atomic_units: other_amount,
            },
            LocalSafetyValue::OutputBinding { output, output_key, subaddress, amount_atomic_units },
        ) => {
            output == other_output
                && output_key == other_key
                && subaddress == other_subaddress
                && amount_atomic_units == other_amount
        }
        (
            LocalSafetyValue::SignedDepositObservationOutput(left),
            LocalSafetyValue::SignedDepositObservationKey(right),
        )
        | (
            LocalSafetyValue::SignedDepositObservationKey(right),
            LocalSafetyValue::SignedDepositObservationOutput(left),
        ) => left == right,
        (
            LocalSafetyValue::CertifiedEntryLocator(left),
            LocalSafetyValue::CertifiedCheckpointLocator(right),
        )
        | (
            LocalSafetyValue::CertifiedCheckpointLocator(right),
            LocalSafetyValue::CertifiedEntryLocator(left),
        ) => left == right,
        _ => false,
    }
}

fn validate_value_coverage<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    validation: &mut TreeValidation,
) -> Result<(), DepositIndexError> {
    let mut records = 0_u64;
    let mut statements = BTreeMap::<u64, LedgerStatement>::new();
    let mut portable_first_use = BTreeMap::<DepositSubaddressIndex, PortableFirstUseRecord>::new();
    let mut portable_observed_outputs =
        BTreeMap::<WalletOutputId, PortableDepositOutputRecord>::new();
    let mut portable_observed_output_keys = BTreeMap::<[u8; 32], WalletOutputId>::new();
    let mut terminals = BTreeMap::<ConsolidationId, PortableConsolidationTerminalRecord>::new();
    let mut terminal_sweeps = BTreeMap::<SweepId, ConsolidationId>::new();
    let mut claims = BTreeMap::<WalletOutputId, PortableOutputClaimRecord>::new();
    let mut sessions = BTreeMap::<SessionId, PortableSigningSessionTombstone>::new();
    let mut portable_sweep_high_water = None::<PortableSweepHighWaterRecord>;
    let mut proposed = BTreeMap::<DepositSubaddressIndex, (LedgerRequestId, RequestBinding)>::new();
    let mut reserved = BTreeMap::<LedgerRequestId, (RequestBinding, DepositSubaddressIndex)>::new();
    let mut outputs =
        BTreeMap::<WalletOutputId, ([u8; 32], Option<DepositSubaddressIndex>, u64)>::new();
    let mut output_keys =
        BTreeMap::<[u8; 32], (WalletOutputId, Option<DepositSubaddressIndex>, u64)>::new();
    let mut local_sessions =
        BTreeMap::<SessionId, (ConsolidationId, SweepId, u64, [u8; 32])>::new();
    let mut local_attempt_high_water = BTreeMap::<SweepId, (ConsolidationId, u64)>::new();
    let mut local_next_sweep_sequence = None::<u64>;
    let mut signed_observation_outputs =
        BTreeMap::<WalletOutputId, SignedDepositObservationSlot>::new();
    let mut signed_observation_keys = BTreeMap::<[u8; 32], SignedDepositObservationSlot>::new();
    let mut signed_ledger_slots = BTreeMap::<u64, [u8; 32]>::new();
    let mut signed_index_checkpoint_slots = BTreeMap::<u64, SignedIndexCheckpointSlot>::new();
    let mut certified_entry_locators = BTreeMap::<u64, CertifiedEntryLocator>::new();
    let mut certified_checkpoint_locators = BTreeMap::<u64, CertifiedEntryLocator>::new();
    let mut locator_event_artifacts = BTreeSet::<WalletArtifactRef>::new();
    let mut locator_ledger_artifacts = BTreeSet::<WalletArtifactRef>::new();
    let mut locator_checkpoint_artifacts = BTreeSet::<WalletArtifactRef>::new();
    for (id, keys) in &validation.values {
        if !validation.reachable.insert(*id) {
            return Err(DepositIndexError::InvalidEntryCoverage);
        }
        let (object, _) = load_object(reader, *id)?;
        match (head.namespace, object) {
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableAllocation(record),
            ) => {
                if record.wallet_id() != wallet {
                    return Err(DepositIndexError::InvalidPortableRecord);
                }
                let aliases = BTreeSet::from(portable_record_aliases(&record)?);
                if keys != &aliases {
                    return Err(DepositIndexError::IncompleteAliasSet);
                }
                if statements.insert(record.statement.sequence, record.statement).is_some() {
                    return Err(DepositIndexError::InvalidEntryCoverage);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableLedgerStatement(record),
            ) => {
                if record.wallet_id() != wallet
                    || keys.len() != 1
                    || !keys.contains(&portable_statement_key(&record))
                    || statements.insert(record.statement.sequence, record.statement).is_some()
                {
                    return Err(DepositIndexError::InvalidEntryCoverage);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableFirstUse(record),
            ) => {
                if record.wallet != wallet
                    || keys.len() != 1
                    || !keys.contains(&portable_first_use_key(&record))
                    || portable_first_use.insert(record.index, record).is_some()
                {
                    return Err(DepositIndexError::InvalidPortableObservation);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableDepositOutput(record),
            ) => {
                if record.wallet != wallet
                    || keys != &BTreeSet::from(portable_deposit_output_aliases(&record))
                    || portable_observed_output_keys
                        .insert(record.output_key, record.output)
                        .is_some()
                    || portable_observed_outputs.insert(record.output, record).is_some()
                {
                    return Err(DepositIndexError::InvalidPortableObservation);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableTerminal(record),
            ) => {
                if record.wallet != wallet
                    || keys != &BTreeSet::from(terminal_record_aliases(&record))
                    || terminals.insert(record.consolidation, record.clone()).is_some()
                    || terminal_sweeps.insert(record.sweep, record.consolidation).is_some()
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableOutputClaim(record),
            ) => {
                if record.wallet != wallet
                    || keys.len() != 1
                    || !keys.contains(&portable_output_claim_key(&record))
                    || claims.insert(record.output, record).is_some()
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableSigningSession(record),
            ) => {
                if record.wallet != wallet
                    || keys.len() != 1
                    || !keys.contains(&portable_session_tombstone_key(&record))
                    || sessions.insert(record.session, record).is_some()
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableSweepHighWater(record),
            ) => {
                if record.wallet != wallet
                    || keys.len() != 1
                    || !keys.contains(&portable_sweep_high_water_key(&record))
                    || portable_sweep_high_water.replace(record).is_some()
                {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
            }
            (
                DepositIndexNamespace::LocalSafety { wallet, party },
                StoredIndexObject::LocalSafety(record),
            ) => {
                if record.wallet != wallet
                    || record.party != party
                    || keys.len() != 1
                    || !keys.contains(&safety_record_alias(&record))
                {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                match record.value {
                    LocalSafetyValue::ProposedIndex { index, request, binding } => {
                        if proposed.insert(index, (request, binding)).is_some() {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::ReservedRequest { request, binding, index } => {
                        if reserved.insert(request, (binding, index)).is_some() {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::OutputBinding {
                        output,
                        output_key,
                        subaddress,
                        amount_atomic_units,
                    } => {
                        if outputs
                            .insert(output, (output_key, subaddress, amount_atomic_units))
                            .is_some()
                        {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::OneTimeOutputKey {
                        output_key,
                        output,
                        subaddress,
                        amount_atomic_units,
                    } => {
                        if output_keys
                            .insert(output_key, (output, subaddress, amount_atomic_units))
                            .is_some()
                        {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::FirstUsed { .. } => {}
                    LocalSafetyValue::SigningSessionTombstone {
                        consolidation,
                        sweep,
                        attempt,
                        session,
                        evidence,
                    } => {
                        if local_sessions
                            .insert(session, (consolidation, sweep, attempt, evidence))
                            .is_some()
                        {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::AttemptHighWater {
                        consolidation,
                        sweep,
                        through_attempt,
                    } => {
                        if local_attempt_high_water
                            .insert(sweep, (consolidation, through_attempt))
                            .is_some()
                        {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::NextSweepSequence { next_sequence } => {
                        if local_next_sweep_sequence.replace(next_sequence).is_some() {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::SignedDepositObservationOutput(slot) => {
                        if signed_observation_outputs.insert(slot.output, slot).is_some() {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::SignedDepositObservationKey(slot) => {
                        if signed_observation_keys.insert(slot.output_key, slot).is_some() {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::SignedLedgerSlot(slot) => {
                        if signed_ledger_slots
                            .insert(slot.sequence, slot.statement_digest)
                            .is_some()
                        {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::SignedIndexCheckpointSlot(slot) => {
                        if signed_index_checkpoint_slots
                            .insert(slot.checkpoint_sequence, slot)
                            .is_some()
                        {
                            return Err(DepositIndexError::InvalidLocalSafetyRecord);
                        }
                    }
                    LocalSafetyValue::CertifiedEntryLocator(locator) => {
                        if certified_entry_locators
                            .insert(locator.ledger_sequence, locator)
                            .is_some()
                            || !locator_event_artifacts.insert(locator.event_artifact)
                            || !locator_ledger_artifacts.insert(locator.ledger_artifact)
                            || !locator_checkpoint_artifacts.insert(locator.checkpoint_artifact)
                        {
                            return Err(DepositIndexError::CertifiedEntryLocatorConflict);
                        }
                    }
                    LocalSafetyValue::CertifiedCheckpointLocator(locator) => {
                        if certified_checkpoint_locators
                            .insert(locator.checkpoint_sequence, locator)
                            .is_some()
                        {
                            return Err(DepositIndexError::CertifiedEntryLocatorConflict);
                        }
                    }
                }
            }
            _ => return Err(DepositIndexError::InvalidEntryCoverage),
        }
        records = records.checked_add(1).ok_or(DepositIndexError::InvalidEntryCoverage)?;
    }
    if records != head.records {
        return Err(DepositIndexError::InvalidEntryCoverage);
    }
    for record in portable_observed_outputs.values() {
        let Some(allocation_statement) = statements.get(&record.allocation_sequence) else {
            return Err(DepositIndexError::InvalidPortableObservation);
        };
        let LedgerPayload::Allocation(allocation) = &allocation_statement.payload else {
            return Err(DepositIndexError::InvalidPortableObservation);
        };
        if allocation_statement.digest() != record.allocation_statement
            || allocation.address.index() != record.index
            || record.observed_block.height < allocation.recognition_anchor.height
            || portable_observed_output_keys.get(&record.output_key) != Some(&record.output)
        {
            return Err(DepositIndexError::InvalidPortableObservation);
        }
    }
    for record in portable_first_use.values() {
        let Some(output) = portable_observed_outputs.get(&record.output) else {
            return Err(DepositIndexError::InvalidPortableObservation);
        };
        if record.wallet != output.wallet
            || record.allocation_sequence != output.allocation_sequence
            || record.allocation_statement != output.allocation_statement
            || record.index != output.index
            || record.observed_block != output.observed_block
            || record.block_timestamp != output.block_timestamp
        {
            return Err(DepositIndexError::InvalidPortableObservation);
        }
    }
    if proposed.len() != reserved.len()
        || proposed
            .iter()
            .any(|(index, (request, binding))| reserved.get(request) != Some(&(*binding, *index)))
        || outputs.len() != output_keys.len()
        || outputs.iter().any(|(output, (output_key, subaddress, amount))| {
            output_keys.get(output_key) != Some(&(*output, *subaddress, *amount))
        })
        || signed_observation_outputs.len() != signed_observation_keys.len()
        || signed_observation_outputs
            .values()
            .any(|slot| signed_observation_keys.get(&slot.output_key) != Some(slot))
        || certified_entry_locators.len() != certified_checkpoint_locators.len()
        || certified_entry_locators.values().any(|locator| {
            certified_checkpoint_locators.get(&locator.checkpoint_sequence) != Some(locator)
        })
    {
        return Err(DepositIndexError::IncompleteLocalSafetyPair);
    }
    for (_session, (consolidation, sweep, attempt, _evidence)) in &local_sessions {
        let Some((high_water_id, through_attempt)) = local_attempt_high_water.get(sweep) else {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        };
        if high_water_id != consolidation || attempt > through_attempt {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
    }
    let _local_next_sweep_sequence = local_next_sweep_sequence;
    if signed_ledger_slots.iter().any(|(sequence, digest)| {
        certified_entry_locators
            .get(sequence)
            .is_some_and(|locator| locator.ledger_statement != *digest)
    }) {
        return Err(DepositIndexError::LedgerSlotAlreadySigned);
    }
    if certified_entry_locators.values().any(|locator| {
        signed_index_checkpoint_slots.get(&locator.checkpoint_sequence).is_some_and(|slot| {
            slot.decision != locator.checkpoint_decision
                || slot.ledger_decision != locator.ledger_statement
        })
    }) {
        return Err(DepositIndexError::IndexCheckpointSlotAlreadySigned);
    }

    if let DepositIndexNamespace::Portable { wallet } = head.namespace {
        let anchor = head.portable_anchor.ok_or(DepositIndexError::InvalidHead)?;
        if let Some((&last_sequence, last_statement)) = statements.last_key_value() {
            let (&first_sequence, first_statement) =
                statements.first_key_value().ok_or(DepositIndexError::InvalidEntryCoverage)?;
            if first_sequence != 1
                || first_statement.previous != crate::deposit_ledger::genesis_head(wallet)
                || last_sequence != anchor.through_sequence
                || last_statement.digest() != anchor.ledger_head
            {
                return Err(DepositIndexError::InvalidEntryCoverage);
            }
            let ordered = statements.values().collect::<Vec<_>>();
            for pair in ordered.windows(2) {
                if pair[0].sequence.checked_add(1) != Some(pair[1].sequence)
                    || pair[1].previous != pair[0].digest()
                {
                    return Err(DepositIndexError::LedgerAnchorMismatch);
                }
            }
            let mut expected_index = None::<DepositSubaddressIndex>;
            for statement in ordered {
                match &statement.payload {
                    LedgerPayload::Allocation(allocation) => {
                        if expected_index
                            .is_some_and(|expected| allocation.address.index() != expected)
                        {
                            return Err(DepositIndexError::AllocationIndexMismatch);
                        }
                        expected_index =
                            Some(increment_subaddress_index(allocation.address.index())?);
                    }
                    LedgerPayload::Handoff(handoff) => {
                        if expected_index.is_some_and(|expected| handoff.next_index() != expected) {
                            return Err(DepositIndexError::AllocationIndexMismatch);
                        }
                        expected_index = Some(handoff.next_index());
                    }
                    LedgerPayload::HandoffFence(_)
                    | LedgerPayload::ConsolidationCompletion(_)
                    | LedgerPayload::ConsolidationAbandonment(_)
                    | LedgerPayload::LateConsolidationSettlement(_) => {}
                }
            }
            if expected_index.is_some_and(|expected| expected != anchor.next_index) {
                return Err(DepositIndexError::AllocationIndexMismatch);
            }
        } else if anchor.through_sequence != 0
            || anchor.ledger_head != crate::deposit_ledger::genesis_head(wallet)
        {
            return Err(DepositIndexError::InvalidEntryCoverage);
        }
        let mut expected_claims = BTreeMap::<WalletOutputId, PortableOutputClaimRecord>::new();
        let mut expected_sessions = BTreeMap::<SessionId, PortableSigningSessionTombstone>::new();
        for terminal in terminals.values() {
            if terminal_sweeps.get(&terminal.sweep) != Some(&terminal.consolidation) {
                return Err(DepositIndexError::InvalidPortableTerminal);
            }
            let (current_sequence, current_digest) = terminal.current_statement_reference();
            let current_statement =
                statements.get(&current_sequence).ok_or(DepositIndexError::InvalidEntryCoverage)?;
            if current_statement.digest() != current_digest {
                return Err(DepositIndexError::InvalidEntryCoverage);
            }
            let reconstructed = match &terminal.status {
                PortableConsolidationStatus::Completed { .. }
                | PortableConsolidationStatus::Abandoned { .. } => {
                    PortableConsolidationTerminalRecord::from_terminal_statement(current_statement)?
                }
                PortableConsolidationStatus::LateSettled { abandonment, .. } => {
                    let abandonment_statement = statements
                        .get(&abandonment.statement_sequence)
                        .ok_or(DepositIndexError::InvalidEntryCoverage)?;
                    if abandonment_statement.digest() != abandonment.statement_digest {
                        return Err(DepositIndexError::InvalidEntryCoverage);
                    }
                    PortableConsolidationTerminalRecord::from_terminal_statement(
                        abandonment_statement,
                    )?
                    .settle_late(current_statement)?
                }
            };
            if reconstructed != *terminal {
                return Err(DepositIndexError::InvalidPortableTerminal);
            }
            let (claim_sequence, claim_digest) =
                terminal.abandonment_reference().unwrap_or((current_sequence, current_digest));
            for output in &terminal.inputs {
                let claim = PortableOutputClaimRecord {
                    version: INDEX_OBJECT_VERSION,
                    wallet: terminal.wallet,
                    output: *output,
                    consolidation: terminal.consolidation,
                    sweep: terminal.sweep,
                    statement_sequence: claim_sequence,
                    statement_digest: claim_digest,
                };
                if expected_claims.insert(*output, claim).is_some() {
                    return Err(DepositIndexError::OutputAlreadyClaimed);
                }
            }
            for (session, attempt, sequence, digest) in terminal.required_session_tombstones() {
                let tombstone = PortableSigningSessionTombstone {
                    version: INDEX_OBJECT_VERSION,
                    wallet: terminal.wallet,
                    session,
                    consolidation: terminal.consolidation,
                    sweep: terminal.sweep,
                    attempt,
                    statement_sequence: sequence,
                    statement_digest: digest,
                };
                if expected_sessions.insert(session, tombstone).is_some() {
                    return Err(DepositIndexError::SigningSessionAlreadyUsed);
                }
            }
        }
        if claims != expected_claims || sessions != expected_sessions {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        let expected_next = terminals
            .values()
            .map(|terminal| terminal.sweep_sequence)
            .max()
            .map(|maximum| maximum.checked_add(1).ok_or(DepositIndexError::SweepSequenceExhausted))
            .transpose()?;
        if portable_sweep_high_water.as_ref().map(|record| record.next_sweep_sequence)
            != expected_next
        {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
    }
    Ok(())
}

fn validate_index_head<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
) -> Result<TreeValidation, DepositIndexError> {
    head.validate_shape()?;
    let mut validation = TreeValidation::default();
    let counted = if let Some(root) = head.root {
        validate_tree_node(reader, head.namespace, root, 0, &mut Vec::new(), &mut validation)?
    } else {
        0
    };
    if counted != head.entries {
        return Err(DepositIndexError::InvalidEntryCoverage);
    }
    validate_value_coverage(reader, head, &mut validation)?;
    Ok(validation)
}

/// Authenticate every reachable node/value and all cross-alias invariants for one exact head.
pub fn verify_deposit_index_head<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
) -> Result<(), DepositIndexError> {
    validate_index_head(reader, head).map(|_| ())
}

fn validate_root_shape<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
) -> Result<(), DepositIndexError> {
    head.validate_shape()?;
    let Some(root) = head.root else {
        return Ok(());
    };
    let (object, _) = load_object(reader, root)?;
    let StoredIndexObject::Node(node) = object else {
        return Err(DepositIndexError::InvalidNode);
    };
    if node.namespace != head.namespace || node.depth != 0 || node.entries != head.entries {
        return Err(DepositIndexError::InvalidEntryCoverage);
    }
    Ok(())
}

fn proved_value<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    key: CanonicalIndexKey,
) -> Result<Option<StoredIndexObject>, DepositIndexError> {
    let proof = build_proof(reader, head, key)?;
    verify_proof(head, &proof)
}

fn validate_portable_terminal_links<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    terminal: &PortableConsolidationTerminalRecord,
) -> Result<(), DepositIndexError> {
    terminal.validate()?;
    let (terminal_id, _) = encode_object(&StoredIndexObject::PortableTerminal(terminal.clone()))?;
    for alias in terminal_record_aliases(terminal) {
        let proof = build_proof(reader, head, alias)?;
        let Some(StoredIndexObject::PortableTerminal(found)) = verify_proof(head, &proof)? else {
            return Err(DepositIndexError::IncompleteAliasSet);
        };
        let (found_id, _) = encode_object(&StoredIndexObject::PortableTerminal(found))?;
        if found_id != terminal_id {
            return Err(DepositIndexError::AliasConflict);
        }
    }
    let (current_sequence, current_digest) = terminal.current_statement_reference();
    let current = proved_value(reader, head, sequence_alias(terminal.wallet, current_sequence))?
        .ok_or(DepositIndexError::InvalidEntryCoverage)?;
    let current_statement = match current {
        StoredIndexObject::PortableAllocation(record) => record.statement,
        StoredIndexObject::PortableLedgerStatement(record) => record.statement,
        _ => return Err(DepositIndexError::InvalidEntryCoverage),
    };
    if current_statement.digest() != current_digest {
        return Err(DepositIndexError::InvalidEntryCoverage);
    }
    let reconstructed = match &terminal.status {
        PortableConsolidationStatus::Completed { .. }
        | PortableConsolidationStatus::Abandoned { .. } => {
            PortableConsolidationTerminalRecord::from_terminal_statement(&current_statement)?
        }
        PortableConsolidationStatus::LateSettled { abandonment, .. } => {
            let abandoned = proved_value(
                reader,
                head,
                sequence_alias(terminal.wallet, abandonment.statement_sequence),
            )?
            .ok_or(DepositIndexError::InvalidEntryCoverage)?;
            let abandonment_statement = match abandoned {
                StoredIndexObject::PortableLedgerStatement(record) => record.statement,
                _ => return Err(DepositIndexError::InvalidEntryCoverage),
            };
            if abandonment_statement.digest() != abandonment.statement_digest {
                return Err(DepositIndexError::InvalidEntryCoverage);
            }
            PortableConsolidationTerminalRecord::from_terminal_statement(&abandonment_statement)?
                .settle_late(&current_statement)?
        }
    };
    if reconstructed != *terminal {
        return Err(DepositIndexError::InvalidPortableTerminal);
    }

    let (claim_sequence, claim_digest) =
        terminal.abandonment_reference().unwrap_or((current_sequence, current_digest));
    for output in &terminal.inputs {
        let Some(StoredIndexObject::PortableOutputClaim(claim)) =
            proved_value(reader, head, claimed_output_alias(terminal.wallet, *output))?
        else {
            return Err(DepositIndexError::OutputAlreadyClaimed);
        };
        if claim.output != *output
            || claim.consolidation != terminal.consolidation
            || claim.sweep != terminal.sweep
            || claim.statement_sequence != claim_sequence
            || claim.statement_digest != claim_digest
        {
            return Err(DepositIndexError::OutputAlreadyClaimed);
        }
    }
    for (session, attempt, sequence, digest) in terminal.required_session_tombstones() {
        let Some(StoredIndexObject::PortableSigningSession(tombstone)) =
            proved_value(reader, head, portable_signing_session_alias(terminal.wallet, session))?
        else {
            return Err(DepositIndexError::SigningSessionAlreadyUsed);
        };
        if tombstone.session != session
            || tombstone.consolidation != terminal.consolidation
            || tombstone.sweep != terminal.sweep
            || tombstone.attempt != attempt
            || tombstone.statement_sequence != sequence
            || tombstone.statement_digest != digest
        {
            return Err(DepositIndexError::SigningSessionAlreadyUsed);
        }
    }
    let Some(StoredIndexObject::PortableSweepHighWater(high_water)) =
        proved_value(reader, head, portable_next_sweep_sequence_alias(terminal.wallet))?
    else {
        return Err(DepositIndexError::InvalidPortableTerminal);
    };
    if high_water.next_sweep_sequence <= terminal.sweep_sequence {
        return Err(DepositIndexError::SweepSequenceRegression);
    }
    Ok(())
}

fn validate_touched_paths<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    touched: &BTreeSet<CanonicalIndexKey>,
) -> Result<(), DepositIndexError> {
    let mut portable_records = BTreeMap::<DepositIndexObjectId, PortableAllocationRecord>::new();
    let mut portable_terminals =
        BTreeMap::<ConsolidationId, PortableConsolidationTerminalRecord>::new();
    let mut local_records = Vec::<LocalDepositSafetyRecord>::new();
    for key in touched {
        let proof = build_proof(reader, head, key.clone())?;
        let object = verify_proof(head, &proof)?.ok_or(DepositIndexError::InvalidEntryCoverage)?;
        match (head.namespace, object) {
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableAllocation(record),
            ) if record.wallet_id() == wallet => {
                let (id, _) =
                    encode_object(&StoredIndexObject::PortableAllocation(record.clone()))?;
                portable_records.insert(id, record);
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableLedgerStatement(record),
            ) if record.wallet_id() == wallet && portable_statement_key(&record) == *key => {}
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableFirstUse(record),
            ) if record.wallet_id() == wallet && portable_first_use_key(&record) == *key => {}
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableDepositOutput(record),
            ) if record.wallet_id() == wallet
                && portable_deposit_output_aliases(&record).contains(key) => {}
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableTerminal(record),
            ) if record.wallet == wallet && terminal_record_aliases(&record).contains(key) => {
                portable_terminals.insert(record.consolidation, record);
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableOutputClaim(record),
            ) if record.wallet == wallet && portable_output_claim_key(&record) == *key => {
                let Some(StoredIndexObject::PortableTerminal(terminal)) =
                    proved_value(reader, head, consolidation_alias(wallet, record.consolidation))?
                else {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                };
                portable_terminals.insert(terminal.consolidation, terminal);
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableSigningSession(record),
            ) if record.wallet == wallet && portable_session_tombstone_key(&record) == *key => {
                let Some(StoredIndexObject::PortableTerminal(terminal)) =
                    proved_value(reader, head, consolidation_alias(wallet, record.consolidation))?
                else {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                };
                portable_terminals.insert(terminal.consolidation, terminal);
            }
            (
                DepositIndexNamespace::Portable { wallet },
                StoredIndexObject::PortableSweepHighWater(record),
            ) if record.wallet == wallet && portable_sweep_high_water_key(&record) == *key => {}
            (
                DepositIndexNamespace::LocalSafety { wallet, party },
                StoredIndexObject::LocalSafety(record),
            ) if record.wallet == wallet
                && record.party == party
                && safety_record_alias(&record) == *key =>
            {
                local_records.push(record);
            }
            _ => return Err(DepositIndexError::InvalidEntryCoverage),
        }
    }
    for (record_id, record) in portable_records {
        for alias in portable_record_aliases(&record)? {
            let proof = build_proof(reader, head, alias)?;
            let Some(StoredIndexObject::PortableAllocation(found)) = verify_proof(head, &proof)?
            else {
                return Err(DepositIndexError::IncompleteAliasSet);
            };
            let (found_id, _) = encode_object(&StoredIndexObject::PortableAllocation(found))?;
            if found_id != record_id {
                return Err(DepositIndexError::AliasConflict);
            }
        }
    }
    for terminal in portable_terminals.values() {
        validate_portable_terminal_links(reader, head, terminal)?;
    }
    for record in local_records {
        if let LocalSafetyValue::SigningSessionTombstone { consolidation, sweep, attempt, .. } =
            &record.value
        {
            let proof = build_proof(
                reader,
                head,
                local_attempt_high_water_alias(record.wallet, record.party, *sweep),
            )?;
            let Some(StoredIndexObject::LocalSafety(high_water)) = verify_proof(head, &proof)?
            else {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            };
            if !matches!(
                high_water.value,
                LocalSafetyValue::AttemptHighWater {
                    consolidation: found_id,
                    sweep: found_sweep,
                    through_attempt,
                } if found_id == *consolidation
                    && found_sweep == *sweep
                    && through_attempt >= *attempt
            ) {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            }
        }
        match &record.value {
            LocalSafetyValue::SignedLedgerSlot(slot) => {
                let proof = build_proof(
                    reader,
                    head,
                    local_certified_entry_locator_alias(record.wallet, record.party, slot.sequence),
                )?;
                if let Some(object) = verify_proof(head, &proof)? {
                    let StoredIndexObject::LocalSafety(locator) = object else {
                        return Err(DepositIndexError::InvalidLocalSafetyRecord);
                    };
                    if !matches!(
                        locator.value,
                        LocalSafetyValue::CertifiedEntryLocator(found)
                            if found.ledger_sequence == slot.sequence
                                && found.ledger_statement == slot.statement_digest
                    ) {
                        return Err(DepositIndexError::LedgerSlotAlreadySigned);
                    }
                }
            }
            LocalSafetyValue::SignedIndexCheckpointSlot(slot) => {
                let proof = build_proof(
                    reader,
                    head,
                    local_certified_checkpoint_locator_alias(
                        record.wallet,
                        record.party,
                        slot.checkpoint_sequence,
                    ),
                )?;
                if let Some(object) = verify_proof(head, &proof)? {
                    let StoredIndexObject::LocalSafety(locator) = object else {
                        return Err(DepositIndexError::InvalidLocalSafetyRecord);
                    };
                    if !matches!(
                        locator.value,
                        LocalSafetyValue::CertifiedCheckpointLocator(found)
                            if found.checkpoint_sequence == slot.checkpoint_sequence
                                && found.checkpoint_decision == slot.decision
                                && found.ledger_statement == slot.ledger_decision
                    ) {
                        return Err(DepositIndexError::IndexCheckpointSlotAlreadySigned);
                    }
                }
            }
            LocalSafetyValue::CertifiedEntryLocator(locator) => {
                let proof = build_proof(
                    reader,
                    head,
                    local_signed_ledger_slot_alias(
                        record.wallet,
                        record.party,
                        locator.ledger_sequence,
                    ),
                )?;
                if let Some(object) = verify_proof(head, &proof)? {
                    let StoredIndexObject::LocalSafety(slot) = object else {
                        return Err(DepositIndexError::InvalidLocalSafetyRecord);
                    };
                    if !matches!(
                        slot.value,
                        LocalSafetyValue::SignedLedgerSlot(found)
                            if found.sequence == locator.ledger_sequence
                                && found.statement_digest == locator.ledger_statement
                    ) {
                        return Err(DepositIndexError::LedgerSlotAlreadySigned);
                    }
                }
            }
            LocalSafetyValue::CertifiedCheckpointLocator(locator) => {
                let proof = build_proof(
                    reader,
                    head,
                    local_signed_index_checkpoint_slot_alias(
                        record.wallet,
                        record.party,
                        locator.checkpoint_sequence,
                    ),
                )?;
                if let Some(object) = verify_proof(head, &proof)? {
                    let StoredIndexObject::LocalSafety(slot) = object else {
                        return Err(DepositIndexError::InvalidLocalSafetyRecord);
                    };
                    if !matches!(
                        slot.value,
                        LocalSafetyValue::SignedIndexCheckpointSlot(found)
                            if found.checkpoint_sequence == locator.checkpoint_sequence
                                && found.decision == locator.checkpoint_decision
                                && found.ledger_decision == locator.ledger_statement
                    ) {
                        return Err(DepositIndexError::IndexCheckpointSlotAlreadySigned);
                    }
                }
            }
            _ => {}
        }
        let Some(counterpart_key) = safety_record_counterpart(&record) else {
            continue;
        };
        let proof = build_proof(reader, head, counterpart_key)?;
        let Some(StoredIndexObject::LocalSafety(counterpart)) = verify_proof(head, &proof)? else {
            return Err(DepositIndexError::IncompleteLocalSafetyPair);
        };
        if !safety_records_are_counterparts(&record, &counterpart) {
            return Err(DepositIndexError::IncompleteLocalSafetyPair);
        }
    }
    Ok(())
}

fn collect_verification_objects<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    touched: &BTreeSet<CanonicalIndexKey>,
) -> Result<BTreeSet<DepositIndexObjectId>, DepositIndexError> {
    let mut objects = BTreeSet::new();
    if let Some(root) = head.root {
        objects.insert(root);
    }
    for key in touched {
        let proof = build_proof(reader, head, key.clone())?;
        objects.extend(proof.path.into_iter().map(|object| object.id));
        if let Some(value) = proof.value {
            objects.insert(value.id);
        }
        if objects.len() > MAX_DEPOSIT_INDEX_VERIFICATION_OBJECTS {
            return Err(DepositIndexError::UpdateTooLarge);
        }
    }
    Ok(objects)
}

struct OverlayReader<'a, R: DepositIndexReader + ?Sized> {
    base: &'a R,
    staged: &'a BTreeMap<DepositIndexObjectId, Vec<u8>>,
}

impl<R: DepositIndexReader + ?Sized> DepositIndexReader for OverlayReader<'_, R> {
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        self.staged
            .get(&id)
            .cloned()
            .map_or_else(|| self.base.load_index_object(id), |bytes| Ok(Some(bytes)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteDisposition {
    Inserted,
    Replaced(DepositIndexObjectId),
    Unchanged,
}

/// Deterministic batch builder over one authenticated old head.
pub struct DepositIndexBuilder<'a, R: DepositIndexReader + ?Sized> {
    base: &'a R,
    expected: DepositIndexHead,
    next: DepositIndexHead,
    staged: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    staged_bytes: usize,
    obsolete: BTreeSet<DepositIndexObjectId>,
    touched: BTreeSet<CanonicalIndexKey>,
    operations: Vec<IndexMutation>,
    changed: bool,
}

impl<'a, R: DepositIndexReader + ?Sized> DepositIndexBuilder<'a, R> {
    pub fn new(base: &'a R, expected: DepositIndexHead) -> Result<Self, DepositIndexError> {
        validate_root_shape(base, &expected)?;
        Ok(Self {
            base,
            next: expected.clone(),
            expected,
            staged: BTreeMap::new(),
            staged_bytes: 0,
            obsolete: BTreeSet::new(),
            touched: BTreeSet::new(),
            operations: Vec::new(),
            changed: false,
        })
    }

    #[must_use]
    pub const fn candidate_head(&self) -> &DepositIndexHead {
        &self.next
    }

    /// Apply one unsigned statement to a pristine candidate and issue its pre-signing index proof.
    ///
    /// This performs the same complete alias, terminal, output-claim, session, sweep, and
    /// allocation-high-water checks as certified application. It intentionally does not verify a
    /// quorum certificate; callers must pair it with active-ledger validation before signing.
    pub fn preflight_ledger_statement(
        &mut self,
        statement: &LedgerStatement,
    ) -> Result<VerifiedDepositIndexPreflight, DepositIndexError> {
        if self.changed
            || self.next != self.expected
            || !self.staged.is_empty()
            || !self.obsolete.is_empty()
            || !self.touched.is_empty()
            || !self.operations.is_empty()
        {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let expected_head = self.expected.clone();
        if !self.apply_portable_statement(statement.clone())? {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let [IndexMutation::ApplyLedgerStatement(applied)] = self.operations.as_slice() else {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        };
        if applied != statement {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        // `finish` advances the party-local CAS revision after semantic application. Capture that
        // finalized head here as well; otherwise an honest pre-signing token can never match the
        // exact certified transition it authorized even though their portable digests agree.
        let mut candidate_head = self.next.clone();
        candidate_head.revision =
            self.expected.revision.checked_add(1).ok_or(DepositIndexError::InvalidHead)?;
        candidate_head.validate_shape()?;
        Ok(VerifiedDepositIndexPreflight {
            expected_head,
            candidate_head,
            statement_sequence: statement.sequence,
            statement_digest: statement.digest(),
        })
    }

    /// Read the exact terminal value from the candidate overlay before its head is committed.
    ///
    /// Callers use this after applying a verified terminal entry and before atomically retiring
    /// worker-side evidence. It also exposes the current `Abandoned` value immediately before a
    /// late settlement so both sides of that transition can be bound into one persistence step.
    pub fn candidate_portable_terminal(
        &self,
        consolidation: ConsolidationId,
    ) -> Result<Option<PortableConsolidationTerminalRecord>, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        if consolidation.0 == [0; 32] {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }
        self.load_terminal(&consolidation_alias(wallet, consolidation))
            .map(|value| value.map(|(_, terminal)| terminal))
    }

    fn overlay(&self) -> OverlayReader<'_, R> {
        OverlayReader { base: self.base, staged: &self.staged }
    }

    fn store_object(
        &mut self,
        object: StoredIndexObject,
    ) -> Result<DepositIndexObjectId, DepositIndexError> {
        let (id, bytes) = encode_object(&object)?;
        if let Some(existing) = self.staged.get(&id) {
            if existing != &bytes {
                return Err(DepositIndexError::ObjectAuthentication);
            }
            return Ok(id);
        }
        if let Some(existing) = self.base.load_index_object(id)? {
            if existing != bytes {
                return Err(DepositIndexError::ObjectAuthentication);
            }
            decode_object(id, &existing)?;
        } else {
            let next_bytes = self
                .staged_bytes
                .checked_add(bytes.len())
                .ok_or(DepositIndexError::UpdateTooLarge)?;
            if self.staged.len() >= MAX_DEPOSIT_INDEX_UPDATE_OBJECTS
                || next_bytes > MAX_DEPOSIT_INDEX_UPDATE_BYTES
            {
                return Err(DepositIndexError::UpdateTooLarge);
            }
            self.staged_bytes = next_bytes;
            self.staged.insert(id, bytes);
        }
        Ok(id)
    }

    fn load_node(&self, id: DepositIndexObjectId) -> Result<HamtNode, DepositIndexError> {
        let (object, _) = load_object(&self.overlay(), id)?;
        let StoredIndexObject::Node(node) = object else {
            return Err(DepositIndexError::InvalidNode);
        };
        Ok(node)
    }

    fn load_value(&self, id: DepositIndexObjectId) -> Result<StoredIndexObject, DepositIndexError> {
        let (object, _) = load_object(&self.overlay(), id)?;
        if matches!(object, StoredIndexObject::Node(_)) {
            return Err(DepositIndexError::InvalidEntryCoverage);
        }
        Ok(object)
    }

    fn retire_if_persisted(&mut self, id: DepositIndexObjectId) {
        if let Some(bytes) = self.staged.remove(&id) {
            self.staged_bytes = self
                .staged_bytes
                .checked_sub(bytes.len())
                .expect("staged byte accounting cannot underflow");
        } else {
            self.obsolete.insert(id);
        }
    }

    fn build_subtree(
        &mut self,
        depth: u8,
        entries: Vec<HamtEntry>,
    ) -> Result<DepositIndexObjectId, DepositIndexError> {
        if entries.is_empty() {
            return Err(DepositIndexError::InvalidNode);
        }
        if entries.len() <= MAX_DEPOSIT_INDEX_LEAF_ENTRIES {
            return self.store_object(StoredIndexObject::Node(HamtNode {
                version: INDEX_OBJECT_VERSION,
                namespace: self.next.namespace,
                depth,
                entries: entries.len() as u64,
                body: HamtNodeBody::Leaf { entries },
            }));
        }
        if depth >= MAX_HAMT_DEPTH {
            return Err(DepositIndexError::DepthExhausted);
        }
        let total = entries.len() as u64;
        let mut groups = BTreeMap::<u8, Vec<HamtEntry>>::new();
        for entry in entries {
            groups
                .entry(routing_nibble(entry.path_hash, &entry.key, depth)?)
                .or_default()
                .push(entry);
        }
        let mut bitmap = 0_u16;
        let mut children = Vec::with_capacity(groups.len());
        for (slot, group) in groups {
            bitmap |= 1_u16 << slot;
            children.push(self.build_subtree(
                depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?,
                group,
            )?);
        }
        self.store_object(StoredIndexObject::Node(HamtNode {
            version: INDEX_OBJECT_VERSION,
            namespace: self.next.namespace,
            depth,
            entries: total,
            body: HamtNodeBody::Branch { bitmap, children },
        }))
    }

    fn write_at(
        &mut self,
        current: Option<DepositIndexObjectId>,
        depth: u8,
        entry: HamtEntry,
    ) -> Result<(DepositIndexObjectId, WriteDisposition), DepositIndexError> {
        let Some(current_id) = current else {
            let id = self.build_subtree(depth, vec![entry])?;
            return Ok((id, WriteDisposition::Inserted));
        };
        let node = self.load_node(current_id)?;
        if node.namespace != self.next.namespace || node.depth != depth {
            return Err(DepositIndexError::InvalidNode);
        }
        match node.body {
            HamtNodeBody::Leaf { mut entries } => {
                let disposition = match entries.binary_search_by(|item| item.key.cmp(&entry.key)) {
                    Ok(position) if entries[position].value == entry.value => {
                        return Ok((current_id, WriteDisposition::Unchanged));
                    }
                    Ok(position) => {
                        let old = entries[position].value;
                        entries[position] = entry;
                        WriteDisposition::Replaced(old)
                    }
                    Err(position) => {
                        entries.insert(position, entry);
                        WriteDisposition::Inserted
                    }
                };
                let replacement = self.build_subtree(depth, entries)?;
                self.retire_if_persisted(current_id);
                Ok((replacement, disposition))
            }
            HamtNodeBody::Branch { mut bitmap, mut children } => {
                let slot = routing_nibble(entry.path_hash, &entry.key, depth)?;
                let mask = 1_u16 << slot;
                let position = bitmap_position(bitmap, slot);
                let child = (bitmap & mask != 0).then(|| children[position]);
                let (replacement_child, disposition) = self.write_at(
                    child,
                    depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?,
                    entry,
                )?;
                if disposition == WriteDisposition::Unchanged {
                    return Ok((current_id, disposition));
                }
                if child.is_some() {
                    children[position] = replacement_child;
                } else {
                    bitmap |= mask;
                    children.insert(position, replacement_child);
                }
                let entries = match disposition {
                    WriteDisposition::Inserted => node
                        .entries
                        .checked_add(1)
                        .ok_or(DepositIndexError::InvalidEntryCoverage)?,
                    WriteDisposition::Replaced(_) | WriteDisposition::Unchanged => node.entries,
                };
                let replacement = self.store_object(StoredIndexObject::Node(HamtNode {
                    version: INDEX_OBJECT_VERSION,
                    namespace: self.next.namespace,
                    depth,
                    entries,
                    body: HamtNodeBody::Branch { bitmap, children },
                }))?;
                self.retire_if_persisted(current_id);
                Ok((replacement, disposition))
            }
        }
    }

    fn lookup_value(
        &self,
        key: &CanonicalIndexKey,
    ) -> Result<Option<DepositIndexObjectId>, DepositIndexError> {
        if key.namespace() != self.next.namespace {
            return Err(DepositIndexError::InvalidHead);
        }
        let path_hash = key.path_hash()?;
        let mut current = self.next.root;
        let mut depth = 0_u8;
        while let Some(id) = current {
            let node = self.load_node(id)?;
            if node.namespace != self.next.namespace || node.depth != depth {
                return Err(DepositIndexError::InvalidNode);
            }
            match node.body {
                HamtNodeBody::Leaf { entries } => {
                    return Ok(entries
                        .binary_search_by(|entry| entry.key.cmp(key))
                        .ok()
                        .map(|position| entries[position].value));
                }
                HamtNodeBody::Branch { bitmap, children } => {
                    let slot = routing_nibble(path_hash, key, depth)?;
                    let mask = 1_u16 << slot;
                    if bitmap & mask == 0 {
                        return Ok(None);
                    }
                    current = Some(children[bitmap_position(bitmap, slot)]);
                    depth = depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?;
                }
            }
        }
        Ok(None)
    }

    fn set_value(
        &mut self,
        key: CanonicalIndexKey,
        value: DepositIndexObjectId,
    ) -> Result<WriteDisposition, DepositIndexError> {
        if key.namespace() != self.next.namespace {
            return Err(DepositIndexError::InvalidHead);
        }
        let entry = HamtEntry { path_hash: key.path_hash()?, key: key.clone(), value };
        let (root, disposition) = self.write_at(self.next.root, 0, entry)?;
        self.next.root = Some(root);
        match disposition {
            WriteDisposition::Inserted => {
                self.next.entries = self
                    .next
                    .entries
                    .checked_add(1)
                    .ok_or(DepositIndexError::InvalidEntryCoverage)?;
                self.changed = true;
            }
            WriteDisposition::Replaced(old) => {
                self.retire_if_persisted(old);
                self.changed = true;
            }
            WriteDisposition::Unchanged => {}
        }
        if disposition != WriteDisposition::Unchanged {
            self.touched.insert(key);
        }
        Ok(disposition)
    }

    fn insert_portable_record(
        &mut self,
        record: PortableAllocationRecord,
    ) -> Result<bool, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        if record.wallet_id() != wallet {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        let (record_id, _) = encode_object(&StoredIndexObject::PortableAllocation(record.clone()))?;
        let aliases = portable_record_aliases(&record)?;
        if aliases.iter().cloned().collect::<BTreeSet<_>>().len() != aliases.len() {
            return Err(DepositIndexError::AliasConflict);
        }
        let existing =
            aliases.iter().map(|key| self.lookup_value(key)).collect::<Result<Vec<_>, _>>()?;
        if existing.iter().all(|value| *value == Some(record_id)) {
            return Ok(false);
        }
        if existing.iter().any(Option::is_some) {
            return if existing.iter().all(|value| value.is_none() || *value == Some(record_id)) {
                Err(DepositIndexError::IncompleteAliasSet)
            } else {
                Err(DepositIndexError::AliasConflict)
            };
        }
        let stored = self.store_object(StoredIndexObject::PortableAllocation(record))?;
        debug_assert_eq!(stored, record_id);
        for key in aliases {
            if self.set_value(key, record_id)? != WriteDisposition::Inserted {
                return Err(DepositIndexError::AliasConflict);
            }
        }
        self.next.records =
            self.next.records.checked_add(1).ok_or(DepositIndexError::InvalidEntryCoverage)?;
        Ok(true)
    }

    fn insert_new_portable_value(
        &mut self,
        object: StoredIndexObject,
        aliases: Vec<CanonicalIndexKey>,
    ) -> Result<bool, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        if object.wallet_id() != wallet
            || aliases.is_empty()
            || aliases.iter().any(|key| key.namespace() != self.next.namespace)
            || aliases.iter().cloned().collect::<BTreeSet<_>>().len() != aliases.len()
        {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        let (object_id, _) = encode_object(&object)?;
        let existing =
            aliases.iter().map(|key| self.lookup_value(key)).collect::<Result<Vec<_>, _>>()?;
        if existing.iter().all(|value| *value == Some(object_id)) {
            return Ok(false);
        }
        if existing.iter().any(Option::is_some) {
            return if existing.iter().all(|value| value.is_none() || *value == Some(object_id)) {
                Err(DepositIndexError::IncompleteAliasSet)
            } else {
                Err(DepositIndexError::AliasConflict)
            };
        }
        let stored = self.store_object(object)?;
        debug_assert_eq!(stored, object_id);
        for key in aliases {
            if self.set_value(key, object_id)? != WriteDisposition::Inserted {
                return Err(DepositIndexError::AliasConflict);
            }
        }
        self.next.records =
            self.next.records.checked_add(1).ok_or(DepositIndexError::InvalidEntryCoverage)?;
        Ok(true)
    }

    fn replace_portable_value(
        &mut self,
        old_id: DepositIndexObjectId,
        object: StoredIndexObject,
        aliases: Vec<CanonicalIndexKey>,
    ) -> Result<(), DepositIndexError> {
        let (new_id, _) = encode_object(&object)?;
        if new_id == old_id {
            return Ok(());
        }
        if aliases
            .iter()
            .map(|key| self.lookup_value(key))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|found| *found != Some(old_id))
        {
            return Err(DepositIndexError::IncompleteAliasSet);
        }
        let stored = self.store_object(object)?;
        debug_assert_eq!(stored, new_id);
        for key in aliases {
            if self.set_value(key, new_id)? != WriteDisposition::Replaced(old_id) {
                return Err(DepositIndexError::AliasConflict);
            }
        }
        Ok(())
    }

    fn load_portable_value(
        &self,
        key: &CanonicalIndexKey,
    ) -> Result<Option<(DepositIndexObjectId, StoredIndexObject)>, DepositIndexError> {
        let Some(id) = self.lookup_value(key)? else {
            return Ok(None);
        };
        Ok(Some((id, self.load_value(id)?)))
    }

    fn current_portable_sweep_high_water(
        &self,
        wallet: DepositWalletId,
    ) -> Result<Option<(DepositIndexObjectId, PortableSweepHighWaterRecord)>, DepositIndexError>
    {
        match self.load_portable_value(&portable_next_sweep_sequence_alias(wallet))? {
            Some((id, StoredIndexObject::PortableSweepHighWater(record))) => {
                record.validate()?;
                Ok(Some((id, record)))
            }
            None => Ok(None),
            _ => Err(DepositIndexError::InvalidPortableTerminal),
        }
    }

    fn advance_portable_sweep_high_water(
        &mut self,
        wallet: DepositWalletId,
        sweep_sequence: u64,
    ) -> Result<(), DepositIndexError> {
        let next_sweep_sequence =
            sweep_sequence.checked_add(1).ok_or(DepositIndexError::SweepSequenceExhausted)?;
        let replacement = PortableSweepHighWaterRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            next_sweep_sequence,
        };
        let key = portable_next_sweep_sequence_alias(wallet);
        match self.current_portable_sweep_high_water(wallet)? {
            Some((_id, current)) if current.next_sweep_sequence > sweep_sequence => {
                Err(DepositIndexError::SweepSequenceRegression)
            }
            Some((id, current)) if current.next_sweep_sequence == next_sweep_sequence => {
                let (replacement_id, _) =
                    encode_object(&StoredIndexObject::PortableSweepHighWater(replacement))?;
                if id != replacement_id {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                Ok(())
            }
            Some((id, _)) => self.replace_portable_value(
                id,
                StoredIndexObject::PortableSweepHighWater(replacement),
                vec![key],
            ),
            None => {
                self.insert_new_portable_value(
                    StoredIndexObject::PortableSweepHighWater(replacement),
                    vec![key],
                )?;
                Ok(())
            }
        }
    }

    fn make_output_claims(
        terminal: &PortableConsolidationTerminalRecord,
    ) -> Vec<PortableOutputClaimRecord> {
        let (statement_sequence, statement_digest) = terminal.current_statement_reference();
        terminal
            .inputs
            .iter()
            .copied()
            .map(|output| PortableOutputClaimRecord {
                version: INDEX_OBJECT_VERSION,
                wallet: terminal.wallet,
                output,
                consolidation: terminal.consolidation,
                sweep: terminal.sweep,
                statement_sequence,
                statement_digest,
            })
            .collect()
    }

    fn make_session_tombstone(
        terminal: &PortableConsolidationTerminalRecord,
        session: SessionId,
        attempt: u64,
        statement_sequence: u64,
        statement_digest: [u8; 32],
    ) -> PortableSigningSessionTombstone {
        PortableSigningSessionTombstone {
            version: INDEX_OBJECT_VERSION,
            wallet: terminal.wallet,
            session,
            consolidation: terminal.consolidation,
            sweep: terminal.sweep,
            attempt,
            statement_sequence,
            statement_digest,
        }
    }

    fn load_terminal(
        &self,
        key: &CanonicalIndexKey,
    ) -> Result<
        Option<(DepositIndexObjectId, PortableConsolidationTerminalRecord)>,
        DepositIndexError,
    > {
        match self.load_portable_value(key)? {
            Some((id, StoredIndexObject::PortableTerminal(record))) => Ok(Some((id, record))),
            None => Ok(None),
            _ => Err(DepositIndexError::InvalidPortableTerminal),
        }
    }

    fn insert_initial_terminal(
        &mut self,
        terminal: PortableConsolidationTerminalRecord,
    ) -> Result<(), DepositIndexError> {
        terminal.validate()?;
        let aliases = terminal_record_aliases(&terminal).to_vec();
        if aliases
            .iter()
            .map(|key| self.lookup_value(key))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(Option::is_some)
        {
            return Err(DepositIndexError::TerminalConflict);
        }
        for claim in Self::make_output_claims(&terminal) {
            if self.lookup_value(&portable_output_claim_key(&claim))?.is_some() {
                return Err(DepositIndexError::OutputAlreadyClaimed);
            }
        }
        let required_sessions = terminal.required_session_tombstones();
        for (session, ..) in &required_sessions {
            if self
                .lookup_value(&portable_signing_session_alias(terminal.wallet, *session))?
                .is_some()
            {
                return Err(DepositIndexError::SigningSessionAlreadyUsed);
            }
        }
        if self
            .current_portable_sweep_high_water(terminal.wallet)?
            .is_some_and(|(_, high_water)| high_water.next_sweep_sequence > terminal.sweep_sequence)
        {
            return Err(DepositIndexError::SweepSequenceRegression);
        }

        self.insert_new_portable_value(
            StoredIndexObject::PortableTerminal(terminal.clone()),
            aliases,
        )?;
        for claim in Self::make_output_claims(&terminal) {
            self.insert_new_portable_value(
                StoredIndexObject::PortableOutputClaim(claim.clone()),
                vec![portable_output_claim_key(&claim)],
            )?;
        }
        for (session, attempt, sequence, digest) in required_sessions {
            let tombstone =
                Self::make_session_tombstone(&terminal, session, attempt, sequence, digest);
            self.insert_new_portable_value(
                StoredIndexObject::PortableSigningSession(tombstone.clone()),
                vec![portable_session_tombstone_key(&tombstone)],
            )?;
        }
        self.advance_portable_sweep_high_water(terminal.wallet, terminal.sweep_sequence)
    }

    fn apply_late_terminal(
        &mut self,
        statement: &LedgerStatement,
    ) -> Result<(), DepositIndexError> {
        let LedgerPayload::LateConsolidationSettlement(settlement) = &statement.payload else {
            return Err(DepositIndexError::InvalidPortableTerminal);
        };
        let wallet = statement.wallet;
        let id_key = consolidation_alias(wallet, settlement.id());
        let Some((old_id, prior)) = self.load_terminal(&id_key)? else {
            return Err(DepositIndexError::TerminalConflict);
        };
        let sweep_key = sweep_alias(wallet, prior.sweep);
        if self.lookup_value(&sweep_key)? != Some(old_id) {
            return Err(DepositIndexError::IncompleteAliasSet);
        }
        let next = prior.settle_late(statement)?;
        for claim in Self::make_output_claims(&prior) {
            let Some((_claim_id, StoredIndexObject::PortableOutputClaim(found))) =
                self.load_portable_value(&portable_output_claim_key(&claim))?
            else {
                return Err(DepositIndexError::OutputAlreadyClaimed);
            };
            if found.consolidation != prior.consolidation
                || found.sweep != prior.sweep
                || found.output != claim.output
            {
                return Err(DepositIndexError::OutputAlreadyClaimed);
            }
        }
        let required = next.required_session_tombstones();
        for (session, attempt, sequence, digest) in &required {
            if let Some((_id, object)) =
                self.load_portable_value(&portable_signing_session_alias(wallet, *session))?
            {
                let StoredIndexObject::PortableSigningSession(found) = object else {
                    return Err(DepositIndexError::SigningSessionAlreadyUsed);
                };
                let expected =
                    Self::make_session_tombstone(&next, *session, *attempt, *sequence, *digest);
                if found != expected {
                    return Err(DepositIndexError::SigningSessionAlreadyUsed);
                }
            }
        }
        let Some((_high_water_id, high_water)) = self.current_portable_sweep_high_water(wallet)?
        else {
            return Err(DepositIndexError::InvalidPortableTerminal);
        };
        if high_water.next_sweep_sequence <= prior.sweep_sequence {
            return Err(DepositIndexError::InvalidPortableTerminal);
        }

        self.replace_portable_value(
            old_id,
            StoredIndexObject::PortableTerminal(next.clone()),
            terminal_record_aliases(&next).to_vec(),
        )?;
        for (session, attempt, sequence, digest) in required {
            if self.lookup_value(&portable_signing_session_alias(wallet, session))?.is_none() {
                let tombstone =
                    Self::make_session_tombstone(&next, session, attempt, sequence, digest);
                self.insert_new_portable_value(
                    StoredIndexObject::PortableSigningSession(tombstone.clone()),
                    vec![portable_session_tombstone_key(&tombstone)],
                )?;
            }
        }
        Ok(())
    }

    /// Apply one contiguous archived ledger entry under its authenticated issuer window.
    ///
    /// Every statement is retained under its sequence. Terminal statements additionally update
    /// the family/id status, permanent output claims, signing-session tombstones, and sweep
    /// high-water in the same candidate root.
    pub fn apply_verified_entry(
        &mut self,
        entry: &CertifiedLedgerEntry,
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<bool, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        entry.verify(issuer_window, historical_issuer)?;
        if entry.statement.wallet != wallet {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        self.apply_portable_statement(entry.statement.clone())
    }

    /// Apply one contiguous live ledger entry against the compact active registry.
    ///
    /// This path is required for a prospective handoff: an active issuer window has no terminal
    /// seal until the handoff has been appended to the compact registry archive.
    pub fn apply_verified_active_entry(
        &mut self,
        entry: &CertifiedLedgerEntry,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<bool, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        entry.verify_active(registry, historical_issuer)?;
        if entry.statement.wallet != wallet {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        self.apply_portable_statement(entry.statement.clone())
    }

    /// Merge one n-f-certified confirmed output into portable first-use/output state.
    pub fn apply_verified_deposit_observation(
        &mut self,
        certificate: &CertifiedDepositObservation,
        issuer_window: &VerifiedIssuerWindow,
    ) -> Result<bool, DepositIndexError> {
        certificate.verify(issuer_window)?;
        self.apply_portable_deposit_observation(certificate.statement.clone())
    }

    /// Active-issuer form of [`Self::apply_verified_deposit_observation`].
    pub fn apply_verified_active_deposit_observation(
        &mut self,
        certificate: &CertifiedDepositObservation,
        registry: &CompactEpochRegistry,
    ) -> Result<bool, DepositIndexError> {
        certificate.verify_active(registry)?;
        self.apply_portable_deposit_observation(certificate.statement.clone())
    }

    fn apply_portable_deposit_observation(
        &mut self,
        statement: DepositObservationStatement,
    ) -> Result<bool, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        let candidate = PortableDepositOutputRecord::from_observation(&statement)?;
        if candidate.wallet != wallet {
            return Err(DepositIndexError::InvalidPortableObservation);
        }
        let allocation_key = sequence_alias(wallet, candidate.allocation_sequence);
        let Some((_allocation_id, StoredIndexObject::PortableAllocation(allocation_record))) =
            self.load_portable_value(&allocation_key)?
        else {
            return Err(DepositIndexError::InvalidPortableObservation);
        };
        let allocation = allocation_record.allocation();
        if allocation_record.statement_digest() != candidate.allocation_statement
            || allocation.address.index() != candidate.index
            || candidate.observed_block.height < allocation.recognition_anchor.height
        {
            return Err(DepositIndexError::InvalidPortableObservation);
        }

        self.ensure_mutation_capacity()?;
        let output_aliases = portable_deposit_output_aliases(&candidate).to_vec();
        let existing_output = self.load_portable_value(&output_aliases[0])?;
        let existing_key = self.load_portable_value(&output_aliases[1])?;
        let mut changed = match (existing_output, existing_key) {
            (None, None) => self.insert_new_portable_value(
                StoredIndexObject::PortableDepositOutput(candidate.clone()),
                output_aliases.clone(),
            )?,
            (
                Some((output_id, StoredIndexObject::PortableDepositOutput(found_output))),
                Some((key_id, StoredIndexObject::PortableDepositOutput(found_key))),
            ) if output_id == key_id && found_output == found_key => {
                let canonical = found_output.canonical_merge(&candidate)?;
                if canonical == found_output {
                    false
                } else {
                    self.replace_portable_value(
                        output_id,
                        StoredIndexObject::PortableDepositOutput(canonical),
                        output_aliases.clone(),
                    )?;
                    true
                }
            }
            (Some(_), Some(_)) => {
                return Err(DepositIndexError::PortableObservationConflict);
            }
            (Some((_, StoredIndexObject::PortableDepositOutput(found))), None)
                if found.output == candidate.output && found.output_key != candidate.output_key =>
            {
                return Err(DepositIndexError::PortableObservationConflict);
            }
            (None, Some((_, StoredIndexObject::PortableDepositOutput(found))))
                if found.output_key == candidate.output_key && found.output != candidate.output =>
            {
                return Err(DepositIndexError::PortableObservationConflict);
            }
            _ => return Err(DepositIndexError::IncompleteAliasSet),
        };

        let first_candidate = PortableFirstUseRecord::from_output(&candidate)?;
        let first_alias = portable_first_use_key(&first_candidate);
        match self.load_portable_value(&first_alias)? {
            None => {
                changed |= self.insert_new_portable_value(
                    StoredIndexObject::PortableFirstUse(first_candidate),
                    vec![first_alias],
                )?;
            }
            Some((first_id, StoredIndexObject::PortableFirstUse(found))) => {
                let canonical = found.canonical_merge(&first_candidate)?;
                if canonical != found {
                    self.replace_portable_value(
                        first_id,
                        StoredIndexObject::PortableFirstUse(canonical),
                        vec![first_alias],
                    )?;
                    changed = true;
                }
            }
            Some(_) => return Err(DepositIndexError::PortableObservationConflict),
        }
        if changed {
            // Semantic replay reloads the allocation which authorizes this observation. Retain
            // that read dependency in the bounded verification set so a cold/restarted store can
            // authenticate the update without relying on a warm builder cache.
            self.touched.insert(allocation_key);
            self.changed = true;
            self.operations.push(IndexMutation::ApplyDepositObservation(statement));
        }
        Ok(changed)
    }

    fn apply_portable_statement(
        &mut self,
        statement: LedgerStatement,
    ) -> Result<bool, DepositIndexError> {
        let DepositIndexNamespace::Portable { wallet } = self.next.namespace else {
            return Err(DepositIndexError::InvalidHead);
        };
        if statement.wallet != wallet {
            return Err(DepositIndexError::InvalidPortableRecord);
        }
        let mut anchor = self.next.portable_anchor.ok_or(DepositIndexError::InvalidHead)?;
        let digest = statement.digest();
        if statement.sequence == anchor.through_sequence && digest == anchor.ledger_head {
            let (record_id, aliases) = match &statement.payload {
                LedgerPayload::Allocation(_) => {
                    let record = PortableAllocationRecord::from_statement(statement.clone())?;
                    let aliases = portable_record_aliases(&record)?.to_vec();
                    let (id, _) = encode_object(&StoredIndexObject::PortableAllocation(record))?;
                    (id, aliases)
                }
                _ => {
                    let record = PortableLedgerStatementRecord::from_statement(statement.clone())?;
                    let key = portable_statement_key(&record);
                    let (id, _) =
                        encode_object(&StoredIndexObject::PortableLedgerStatement(record))?;
                    (id, vec![key])
                }
            };
            if !aliases.iter().all(|key| self.lookup_value(key).ok() == Some(Some(record_id))) {
                return Err(DepositIndexError::InvalidEntryCoverage);
            }
            match &statement.payload {
                LedgerPayload::ConsolidationCompletion(completion) => {
                    let expected =
                        PortableConsolidationTerminalRecord::from_terminal_statement(&statement)?;
                    let Some((_id, terminal)) =
                        self.load_terminal(&consolidation_alias(wallet, completion.id()))?
                    else {
                        return Err(DepositIndexError::InvalidPortableTerminal);
                    };
                    if terminal != expected {
                        return Err(DepositIndexError::TerminalConflict);
                    }
                    validate_portable_terminal_links(&self.overlay(), &self.next, &terminal)?;
                }
                LedgerPayload::ConsolidationAbandonment(abandonment) => {
                    let expected =
                        PortableConsolidationTerminalRecord::from_terminal_statement(&statement)?;
                    let Some((_id, terminal)) =
                        self.load_terminal(&consolidation_alias(wallet, abandonment.id()))?
                    else {
                        return Err(DepositIndexError::InvalidPortableTerminal);
                    };
                    if terminal != expected {
                        return Err(DepositIndexError::TerminalConflict);
                    }
                    validate_portable_terminal_links(&self.overlay(), &self.next, &terminal)?;
                }
                LedgerPayload::LateConsolidationSettlement(settlement) => {
                    let Some((_id, terminal)) =
                        self.load_terminal(&consolidation_alias(wallet, settlement.id()))?
                    else {
                        return Err(DepositIndexError::InvalidPortableTerminal);
                    };
                    if terminal.current_statement_reference()
                        != (statement.sequence, statement.digest())
                    {
                        return Err(DepositIndexError::TerminalConflict);
                    }
                    validate_portable_terminal_links(&self.overlay(), &self.next, &terminal)?;
                }
                LedgerPayload::Allocation(_)
                | LedgerPayload::HandoffFence(_)
                | LedgerPayload::Handoff(_) => {}
            }
            return Ok(false);
        }
        if statement.sequence
            != anchor
                .through_sequence
                .checked_add(1)
                .ok_or(DepositIndexError::LedgerAnchorMismatch)?
            || statement.previous != anchor.ledger_head
        {
            return Err(DepositIndexError::LedgerAnchorMismatch);
        }
        let next_index = match &statement.payload {
            LedgerPayload::Allocation(allocation) => {
                if allocation.address.index() != anchor.next_index {
                    return Err(DepositIndexError::AllocationIndexMismatch);
                }
                increment_subaddress_index(anchor.next_index)?
            }
            LedgerPayload::Handoff(handoff) => {
                if handoff.next_index() != anchor.next_index {
                    return Err(DepositIndexError::AllocationIndexMismatch);
                }
                anchor.next_index
            }
            LedgerPayload::HandoffFence(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => anchor.next_index,
        };
        self.ensure_mutation_capacity()?;
        // Encode and authenticate the sequence value before any derived terminal write. This
        // guarantees the complete terminal mutation fits the per-object bound.
        let sequence_object = match &statement.payload {
            LedgerPayload::Allocation(_) => StoredIndexObject::PortableAllocation(
                PortableAllocationRecord::from_statement(statement.clone())?,
            ),
            _ => StoredIndexObject::PortableLedgerStatement(
                PortableLedgerStatementRecord::from_statement(statement.clone())?,
            ),
        };
        let (sequence_id, _) = encode_object(&sequence_object)?;
        let sequence_key = sequence_alias(wallet, statement.sequence);
        if let Some(existing) = self.lookup_value(&sequence_key)? {
            return if existing == sequence_id {
                Err(DepositIndexError::IncompleteAliasSet)
            } else {
                Err(DepositIndexError::AliasConflict)
            };
        }

        match &statement.payload {
            LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_) => {
                self.insert_initial_terminal(
                    PortableConsolidationTerminalRecord::from_terminal_statement(&statement)?,
                )?;
            }
            LedgerPayload::LateConsolidationSettlement(_) => {
                self.apply_late_terminal(&statement)?;
            }
            LedgerPayload::Allocation(_)
            | LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_) => {}
        }
        match sequence_object {
            StoredIndexObject::PortableAllocation(record) => {
                self.insert_portable_record(record)?;
            }
            StoredIndexObject::PortableLedgerStatement(record) => {
                self.insert_new_portable_value(
                    StoredIndexObject::PortableLedgerStatement(record),
                    vec![sequence_key],
                )?;
            }
            _ => unreachable!("constructed sequence object"),
        }
        anchor.through_sequence = statement.sequence;
        anchor.ledger_head = digest;
        anchor.next_index = next_index;
        self.next.portable_anchor = Some(anchor);
        self.changed = true;
        self.operations.push(IndexMutation::ApplyLedgerStatement(statement));
        Ok(true)
    }

    fn safety_namespace(&self) -> Result<(DepositWalletId, PartyId), DepositIndexError> {
        match self.next.namespace {
            DepositIndexNamespace::LocalSafety { wallet, party } => Ok((wallet, party)),
            DepositIndexNamespace::Portable { .. } => Err(DepositIndexError::InvalidHead),
        }
    }

    fn ensure_mutation_capacity(&self) -> Result<(), DepositIndexError> {
        if self.operations.len() >= MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS {
            return Err(DepositIndexError::TooManyMutations);
        }
        Ok(())
    }

    fn load_local_record(
        &self,
        key: &CanonicalIndexKey,
    ) -> Result<Option<LocalDepositSafetyRecord>, DepositIndexError> {
        let Some(id) = self.lookup_value(key)? else {
            return Ok(None);
        };
        let StoredIndexObject::LocalSafety(record) = self.load_value(id)? else {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        };
        record.validate()?;
        Ok(Some(record))
    }

    fn insert_local_record(
        &mut self,
        record: LocalDepositSafetyRecord,
    ) -> Result<(), DepositIndexError> {
        record.validate()?;
        let key = safety_record_alias(&record);
        if self.lookup_value(&key)?.is_some() {
            return Err(DepositIndexError::AliasConflict);
        }
        let value = self.store_object(StoredIndexObject::LocalSafety(record))?;
        if self.set_value(key, value)? != WriteDisposition::Inserted {
            return Err(DepositIndexError::AliasConflict);
        }
        self.next.records =
            self.next.records.checked_add(1).ok_or(DepositIndexError::InvalidEntryCoverage)?;
        Ok(())
    }

    /// Permanently bind a request/binding pair to one locally proposed subaddress index.
    ///
    /// The two redundant safety records are inserted atomically into the candidate head. This
    /// prevents a restart from reusing either the request or index even before portable ledger
    /// certification completes.
    pub fn reserve_allocation_proposal(
        &mut self,
        request: LedgerRequestId,
        binding: RequestBinding,
        index: DepositSubaddressIndex,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        if request.0 == [0; 32] || binding.0 == [0; 32] {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        let proposed_key = proposed_index_alias(wallet, party, index);
        let reserved_key = reserved_request_alias(wallet, party, request);
        let proposed = self.load_local_record(&proposed_key)?;
        let reserved = self.load_local_record(&reserved_key)?;
        match (proposed, reserved) {
            (None, None) => {}
            (Some(left), Some(right))
                if matches!(
                    left.value,
                    LocalSafetyValue::ProposedIndex {
                        index: found_index,
                        request: found_request,
                        binding: found_binding,
                    } if found_index == index
                        && found_request == request
                        && found_binding == binding
                ) && matches!(
                    right.value,
                    LocalSafetyValue::ReservedRequest {
                        request: found_request,
                        binding: found_binding,
                        index: found_index,
                    } if found_request == request
                        && found_binding == binding
                        && found_index == index
                ) =>
            {
                return Ok(false);
            }
            (Some(_), Some(_)) => return Err(DepositIndexError::AliasConflict),
            _ => return Err(DepositIndexError::AliasConflict),
        }
        self.ensure_mutation_capacity()?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::ProposedIndex { index, request, binding },
        })?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::ReservedRequest { request, binding, index },
        })?;
        self.operations.push(IndexMutation::ReserveAllocationProposal { request, binding, index });
        Ok(true)
    }

    /// Permanently retain the earliest observed timestamp for an address.
    pub fn mark_first_used(
        &mut self,
        index: DepositSubaddressIndex,
        observed_at: u64,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        if observed_at == 0 {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        let key = used_alias(wallet, party, index);
        if let Some(existing_id) = self.lookup_value(&key)? {
            let StoredIndexObject::LocalSafety(existing) = self.load_value(existing_id)? else {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            };
            let LocalSafetyValue::FirstUsed { index: existing_index, first_used_at } =
                existing.value
            else {
                return Err(DepositIndexError::AliasConflict);
            };
            if existing_index != index {
                return Err(DepositIndexError::AliasConflict);
            }
            if first_used_at <= observed_at {
                return Ok(false);
            }
        }
        self.ensure_mutation_capacity()?;
        let record = LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::FirstUsed { index, first_used_at: observed_at },
        };
        let value = self.store_object(StoredIndexObject::LocalSafety(record))?;
        let disposition = self.set_value(key, value)?;
        if disposition == WriteDisposition::Inserted {
            self.next.records =
                self.next.records.checked_add(1).ok_or(DepositIndexError::InvalidEntryCoverage)?;
        }
        if disposition != WriteDisposition::Unchanged {
            self.operations.push(IndexMutation::MarkFirstUsed { index, observed_at });
        }
        Ok(disposition != WriteDisposition::Unchanged)
    }

    /// Permanently bind one output ID to the immutable viewing-key-derived deposit facts.
    pub fn bind_output(
        &mut self,
        output: WalletOutputId,
        output_key: [u8; 32],
        subaddress: Option<DepositSubaddressIndex>,
        amount_atomic_units: u64,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        if output.transaction == [0; 32] || output_key == [0; 32] || amount_atomic_units == 0 {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        let output_alias_key = output_alias(wallet, party, output);
        let one_time_alias_key = one_time_output_key_alias(wallet, party, output_key);
        let by_output = self.load_local_record(&output_alias_key)?;
        let by_key = self.load_local_record(&one_time_alias_key)?;
        match (by_output, by_key) {
            (Some(output_record), Some(key_record))
                if matches!(
                    output_record.value,
                LocalSafetyValue::OutputBinding {
                    output: existing_output,
                    output_key: existing_key,
                    subaddress: existing_subaddress,
                    amount_atomic_units: existing_amount,
                } if existing_output == output
                    && existing_key == output_key
                    && existing_subaddress == subaddress
                    && existing_amount == amount_atomic_units
                ) && matches!(
                    key_record.value,
                    LocalSafetyValue::OneTimeOutputKey {
                        output_key: existing_key,
                        output: existing_output,
                        subaddress: existing_subaddress,
                        amount_atomic_units: existing_amount,
                    } if existing_key == output_key
                        && existing_output == output
                        && existing_subaddress == subaddress
                        && existing_amount == amount_atomic_units
                ) =>
            {
                return Ok(false);
            }
            (None, None) => {}
            (Some(_), Some(_)) => return Err(DepositIndexError::AliasConflict),
            _ => return Err(DepositIndexError::AliasConflict),
        }
        self.ensure_mutation_capacity()?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::OutputBinding {
                output,
                output_key,
                subaddress,
                amount_atomic_units,
            },
        })?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::OneTimeOutputKey {
                output_key,
                output,
                subaddress,
                amount_atomic_units,
            },
        })?;
        self.operations.push(IndexMutation::BindOutput {
            output,
            output_key,
            subaddress,
            amount_atomic_units,
        });
        Ok(true)
    }

    /// Permanently reserve this party's signature for one exact confirmed-output fact.
    ///
    /// The viewing-key-derived output and one-time-key bindings must already be present in the
    /// same authenticated local-safety head. The redundant reservation aliases are then inserted
    /// atomically before the caller releases a signature. The issuer is intentionally excluded
    /// from the slot: an uncertified fact may be retried under a successor issuer, while any
    /// change to the chain fact itself remains a permanent conflict.
    pub fn record_signed_deposit_observation(
        &mut self,
        statement: &DepositObservationStatement,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        if statement.wallet_id() != wallet {
            return Err(DepositIndexError::InvalidDepositObservationBinding);
        }
        let slot = SignedDepositObservationSlot::from_statement(statement);
        slot.validate()?;

        let output_binding = self.load_local_record(&output_alias(wallet, party, slot.output))?;
        let key_binding =
            self.load_local_record(&one_time_output_key_alias(wallet, party, slot.output_key))?;
        if !matches!(
            output_binding.as_ref().map(LocalDepositSafetyRecord::value),
            Some(LocalSafetyValue::OutputBinding {
                output,
                output_key,
                subaddress: Some(subaddress),
                amount_atomic_units,
            }) if *output == slot.output
                && *output_key == slot.output_key
                && *subaddress == statement.index()
                && *amount_atomic_units == statement.amount_atomic_units()
        ) || !matches!(
            key_binding.as_ref().map(LocalDepositSafetyRecord::value),
            Some(LocalSafetyValue::OneTimeOutputKey {
                output_key,
                output,
                subaddress: Some(subaddress),
                amount_atomic_units,
            }) if *output_key == slot.output_key
                && *output == slot.output
                && *subaddress == statement.index()
                && *amount_atomic_units == statement.amount_atomic_units()
        ) {
            return Err(DepositIndexError::InvalidDepositObservationBinding);
        }

        let output_key = local_signed_observation_output_alias(wallet, party, slot.output);
        let one_time_key = local_signed_observation_key_alias(wallet, party, slot.output_key);
        let by_output = self.load_local_record(&output_key)?;
        let by_one_time_key = self.load_local_record(&one_time_key)?;
        match (by_output, by_one_time_key) {
            (None, None) => {}
            (Some(left), Some(right))
                if matches!(
                    left.value,
                    LocalSafetyValue::SignedDepositObservationOutput(found) if found == slot
                ) && matches!(
                    right.value,
                    LocalSafetyValue::SignedDepositObservationKey(found) if found == slot
                ) =>
            {
                return Ok(false);
            }
            (Some(_), Some(_)) => {
                return Err(DepositIndexError::DepositObservationAlreadySigned);
            }
            _ => return Err(DepositIndexError::IncompleteLocalSafetyPair),
        }

        self.ensure_mutation_capacity()?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::SignedDepositObservationOutput(slot),
        })?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::SignedDepositObservationKey(slot),
        })?;
        self.operations.push(IndexMutation::RecordSignedDepositObservation(statement.clone()));
        Ok(true)
    }

    /// Permanently burn one locally released signing session and monotonically advance its sweep
    /// family's absolute attempt high-water.
    ///
    /// This is the integration point for coordinator/ROAST evidence which is stronger than the
    /// winner-only attempt exposed by an ordinary portable completion statement. Backfilling a
    /// previously archived session below an already higher high-water is allowed, but no session
    /// may ever be rebound to another attempt or consolidation.
    pub fn record_signing_session_tombstone(
        &mut self,
        consolidation: ConsolidationId,
        sweep: SweepId,
        attempt: u64,
        session: SessionId,
        evidence: [u8; 32],
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        let tombstone = LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::SigningSessionTombstone {
                consolidation,
                sweep,
                attempt,
                session,
                evidence,
            },
        };
        tombstone.validate()?;
        let session_key = local_signing_session_alias(wallet, party, session);
        let high_water_key = local_attempt_high_water_alias(wallet, party, sweep);
        let existing_session = self.load_local_record(&session_key)?;
        let existing_high_water = self.load_local_record(&high_water_key)?;
        if let Some(existing) = &existing_session
            && existing != &tombstone
        {
            return Err(DepositIndexError::SigningSessionAlreadyUsed);
        }
        let through_attempt = match &existing_high_water {
            Some(LocalDepositSafetyRecord {
                value:
                    LocalSafetyValue::AttemptHighWater {
                        consolidation: found_id,
                        sweep: found_sweep,
                        through_attempt,
                    },
                ..
            }) if *found_id == consolidation && *found_sweep == sweep => *through_attempt,
            Some(_) => return Err(DepositIndexError::TerminalConflict),
            None => 0,
        };
        if existing_session.is_some() && through_attempt >= attempt {
            return Ok(false);
        }
        self.ensure_mutation_capacity()?;
        if existing_session.is_none() {
            self.insert_local_record(tombstone)?;
        }
        if through_attempt < attempt {
            let high_water = LocalDepositSafetyRecord {
                version: INDEX_OBJECT_VERSION,
                wallet,
                party,
                value: LocalSafetyValue::AttemptHighWater {
                    consolidation,
                    sweep,
                    through_attempt: attempt,
                },
            };
            let value = self.store_object(StoredIndexObject::LocalSafety(high_water))?;
            let disposition = self.set_value(high_water_key, value)?;
            match disposition {
                WriteDisposition::Inserted => {
                    self.next.records = self
                        .next
                        .records
                        .checked_add(1)
                        .ok_or(DepositIndexError::InvalidEntryCoverage)?;
                }
                WriteDisposition::Replaced(_) => {}
                WriteDisposition::Unchanged => {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
            }
        }
        self.operations.push(IndexMutation::RecordSigningSession {
            consolidation,
            sweep,
            attempt,
            session,
            evidence,
        });
        Ok(true)
    }

    /// Persist the next locally assignable sweep-plan sequence after reservation.
    pub fn advance_next_sweep_sequence(
        &mut self,
        next_sequence: u64,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        if next_sequence == 0 {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        let key = local_next_sweep_sequence_alias(wallet, party);
        let current = self.load_local_record(&key)?;
        match current.as_ref().map(LocalDepositSafetyRecord::value) {
            Some(LocalSafetyValue::NextSweepSequence { next_sequence: found })
                if *found == next_sequence =>
            {
                return Ok(false);
            }
            Some(LocalSafetyValue::NextSweepSequence { next_sequence: found })
                if *found < next_sequence => {}
            Some(LocalSafetyValue::NextSweepSequence { .. }) => {
                return Err(DepositIndexError::SweepSequenceRegression);
            }
            Some(_) => return Err(DepositIndexError::InvalidLocalSafetyRecord),
            None => {}
        }
        self.ensure_mutation_capacity()?;
        let record = LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::NextSweepSequence { next_sequence },
        };
        let value = self.store_object(StoredIndexObject::LocalSafety(record))?;
        let disposition = self.set_value(key, value)?;
        if disposition == WriteDisposition::Inserted {
            self.next.records =
                self.next.records.checked_add(1).ok_or(DepositIndexError::InvalidEntryCoverage)?;
        }
        if disposition == WriteDisposition::Unchanged {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        self.operations.push(IndexMutation::AdvanceNextSweepSequence { next_sequence });
        Ok(true)
    }

    /// Permanently bind this party's ledger signature at `sequence` to one statement digest.
    pub fn record_signed_ledger_slot(
        &mut self,
        sequence: u64,
        statement_digest: [u8; 32],
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        let slot = SignedLedgerSlot { sequence, statement_digest };
        slot.validate()?;
        let key = local_signed_ledger_slot_alias(wallet, party, sequence);
        if let Some(existing) = self.load_local_record(&key)? {
            return match existing.value {
                LocalSafetyValue::SignedLedgerSlot(found) if found == slot => Ok(false),
                _ => Err(DepositIndexError::LedgerSlotAlreadySigned),
            };
        }
        if let Some(locator) =
            self.load_local_record(&local_certified_entry_locator_alias(wallet, party, sequence))?
        {
            let LocalSafetyValue::CertifiedEntryLocator(locator) = locator.value else {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            };
            if locator.ledger_statement != statement_digest {
                return Err(DepositIndexError::LedgerSlotAlreadySigned);
            }
        }
        self.ensure_mutation_capacity()?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::SignedLedgerSlot(slot),
        })?;
        self.operations.push(IndexMutation::RecordSignedLedgerSlot { sequence, statement_digest });
        Ok(true)
    }

    /// Permanently bind this party's checkpoint signature at one checkpoint sequence.
    pub fn record_signed_index_checkpoint_slot(
        &mut self,
        slot: SignedIndexCheckpointSlot,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        slot.validate()?;
        let key = local_signed_index_checkpoint_slot_alias(wallet, party, slot.checkpoint_sequence);
        if let Some(existing) = self.load_local_record(&key)? {
            return match existing.value {
                LocalSafetyValue::SignedIndexCheckpointSlot(found) if found == slot => Ok(false),
                _ => Err(DepositIndexError::IndexCheckpointSlotAlreadySigned),
            };
        }
        if let Some(locator) = self.load_local_record(&local_certified_checkpoint_locator_alias(
            wallet,
            party,
            slot.checkpoint_sequence,
        ))? {
            let LocalSafetyValue::CertifiedCheckpointLocator(locator) = locator.value else {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            };
            if locator.checkpoint_decision != slot.decision
                || locator.ledger_statement != slot.ledger_decision
            {
                return Err(DepositIndexError::IndexCheckpointSlotAlreadySigned);
            }
        }
        self.ensure_mutation_capacity()?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::SignedIndexCheckpointSlot(slot),
        })?;
        self.operations.push(IndexMutation::RecordSignedIndexCheckpointSlot(slot));
        Ok(true)
    }

    /// Retain a party-local content address for one exact witness-bearing certified entry.
    pub fn record_certified_entry_locator(
        &mut self,
        verified: VerifiedDepositArchiveLedgerLocator,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, _) = self.safety_namespace()?;
        if verified.wallet_id() != wallet {
            return Err(DepositIndexError::InvalidLocalSafetyRecord);
        }
        self.record_certified_entry_locator_fields(CertifiedEntryLocator {
            wallet: verified.wallet_id(),
            checkpoint_sequence: verified.checkpoint_sequence(),
            checkpoint_decision: verified.checkpoint_decision(),
            checkpoint_certificate_digest: verified.checkpoint_certificate_digest(),
            ledger_sequence: verified.ledger_sequence(),
            ledger_statement: verified.ledger_statement(),
            event_artifact: verified.event_artifact(),
            ledger_artifact: verified.ledger_artifact(),
            checkpoint_artifact: verified.checkpoint_artifact(),
        })
    }

    fn record_certified_entry_locator_fields(
        &mut self,
        locator: CertifiedEntryLocator,
    ) -> Result<bool, DepositIndexError> {
        let (wallet, party) = self.safety_namespace()?;
        locator.validate(wallet)?;
        let ledger_key =
            local_certified_entry_locator_alias(wallet, party, locator.ledger_sequence);
        let checkpoint_key =
            local_certified_checkpoint_locator_alias(wallet, party, locator.checkpoint_sequence);
        let by_ledger = self.load_local_record(&ledger_key)?;
        let by_checkpoint = self.load_local_record(&checkpoint_key)?;
        match (by_ledger, by_checkpoint) {
            (None, None) => {}
            (Some(ledger), Some(checkpoint))
                if matches!(
                    ledger.value,
                    LocalSafetyValue::CertifiedEntryLocator(found) if found == locator
                ) && matches!(
                    checkpoint.value,
                    LocalSafetyValue::CertifiedCheckpointLocator(found) if found == locator
                ) =>
            {
                return Ok(false);
            }
            (Some(_), Some(_)) => {
                return Err(DepositIndexError::CertifiedEntryLocatorConflict);
            }
            (Some(ledger), None)
                if matches!(
                    ledger.value,
                    LocalSafetyValue::CertifiedEntryLocator(found) if found == locator
                ) =>
            {
                return Err(DepositIndexError::IncompleteLocalSafetyPair);
            }
            (None, Some(checkpoint))
                if matches!(
                    checkpoint.value,
                    LocalSafetyValue::CertifiedCheckpointLocator(found) if found == locator
                ) =>
            {
                return Err(DepositIndexError::IncompleteLocalSafetyPair);
            }
            _ => return Err(DepositIndexError::CertifiedEntryLocatorConflict),
        }
        if let Some(slot) = self.load_local_record(&local_signed_ledger_slot_alias(
            wallet,
            party,
            locator.ledger_sequence,
        ))? {
            let LocalSafetyValue::SignedLedgerSlot(slot) = slot.value else {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            };
            if slot.statement_digest != locator.ledger_statement {
                return Err(DepositIndexError::LedgerSlotAlreadySigned);
            }
        }
        if let Some(slot) = self.load_local_record(&local_signed_index_checkpoint_slot_alias(
            wallet,
            party,
            locator.checkpoint_sequence,
        ))? {
            let LocalSafetyValue::SignedIndexCheckpointSlot(slot) = slot.value else {
                return Err(DepositIndexError::InvalidLocalSafetyRecord);
            };
            if slot.decision != locator.checkpoint_decision
                || slot.ledger_decision != locator.ledger_statement
            {
                return Err(DepositIndexError::IndexCheckpointSlotAlreadySigned);
            }
        }
        self.ensure_mutation_capacity()?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::CertifiedEntryLocator(locator),
        })?;
        self.insert_local_record(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet,
            party,
            value: LocalSafetyValue::CertifiedCheckpointLocator(locator),
        })?;
        self.operations.push(IndexMutation::RecordCertifiedEntryLocator(locator));
        Ok(true)
    }

    /// Finalize one atomic root transition. `None` means the complete batch was idempotent.
    pub fn finish(mut self) -> Result<Option<DepositIndexUpdate>, DepositIndexError> {
        if !self.changed {
            return Ok(None);
        }
        self.next.revision =
            self.expected.revision.checked_add(1).ok_or(DepositIndexError::InvalidHead)?;
        self.next.validate_shape()?;
        validate_root_shape(&self.overlay(), &self.next)?;
        validate_touched_paths(&self.overlay(), &self.next, &self.touched)?;
        let expected_verification =
            collect_verification_objects(self.base, &self.expected, &self.touched)?;
        let next_verification =
            collect_verification_objects(&self.overlay(), &self.next, &self.touched)?;
        let update = DepositIndexUpdate {
            version: INDEX_UPDATE_VERSION,
            expected: self.expected,
            next: self.next,
            objects: self.staged,
            obsolete: self.obsolete,
            touched: self.touched,
            expected_verification,
            next_verification,
            operations: self.operations,
        };
        update.validate_shape()?;
        Ok(Some(update))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum IndexMutation {
    ApplyLedgerStatement(LedgerStatement),
    ApplyDepositObservation(DepositObservationStatement),
    RecordSignedDepositObservation(DepositObservationStatement),
    ReserveAllocationProposal {
        request: LedgerRequestId,
        binding: RequestBinding,
        index: DepositSubaddressIndex,
    },
    MarkFirstUsed {
        index: DepositSubaddressIndex,
        observed_at: u64,
    },
    BindOutput {
        output: WalletOutputId,
        output_key: [u8; 32],
        subaddress: Option<DepositSubaddressIndex>,
        amount_atomic_units: u64,
    },
    RecordSigningSession {
        consolidation: ConsolidationId,
        sweep: SweepId,
        attempt: u64,
        session: SessionId,
        evidence: [u8; 32],
    },
    AdvanceNextSweepSequence {
        next_sequence: u64,
    },
    RecordSignedLedgerSlot {
        sequence: u64,
        statement_digest: [u8; 32],
    },
    RecordSignedIndexCheckpointSlot(SignedIndexCheckpointSlot),
    RecordCertifiedEntryLocator(CertifiedEntryLocator),
}

/// In-process proof that one unsigned statement passed every authenticated portable-index
/// conflict check against one exact old head.
///
/// The token is deliberately non-serializable and has no public constructor. It grants no
/// certificate authority; ledger validation and quorum signing remain separate requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositIndexPreflight {
    expected_head: DepositIndexHead,
    candidate_head: DepositIndexHead,
    statement_sequence: u64,
    statement_digest: [u8; 32],
}

impl VerifiedDepositIndexPreflight {
    #[must_use]
    pub const fn expected_head(&self) -> &DepositIndexHead {
        &self.expected_head
    }

    #[must_use]
    pub const fn candidate_head(&self) -> &DepositIndexHead {
        &self.candidate_head
    }

    #[must_use]
    pub const fn statement_sequence(&self) -> u64 {
        self.statement_sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub fn expected_head_digest(&self) -> [u8; 32] {
        self.expected_head.digest()
    }

    #[must_use]
    pub fn candidate_head_digest(&self) -> [u8; 32] {
        self.candidate_head.digest()
    }
}

/// In-process authorization that one exact ledger statement produces one exact portable head.
///
/// This type is deliberately not serializable or publicly constructible. A restart must reload
/// the retained [`DepositIndexUpdate`], verify it again, and reissue the token before advancing a
/// compact ledger cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositIndexTransition {
    expected_head: DepositIndexHead,
    resulting_head: DepositIndexHead,
    statement_sequence: u64,
    statement_digest: [u8; 32],
}

impl VerifiedDepositIndexTransition {
    #[must_use]
    pub const fn expected_head(&self) -> &DepositIndexHead {
        &self.expected_head
    }

    #[must_use]
    pub const fn resulting_head(&self) -> &DepositIndexHead {
        &self.resulting_head
    }

    #[must_use]
    pub const fn statement_sequence(&self) -> u64 {
        self.statement_sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub fn expected_head_digest(&self) -> [u8; 32] {
        self.expected_head.digest()
    }

    #[must_use]
    pub fn resulting_head_digest(&self) -> [u8; 32] {
        self.resulting_head.digest()
    }

    /// Require the certified transition to be exactly the candidate authorized before signing.
    #[must_use]
    pub fn matches_preflight(&self, preflight: &VerifiedDepositIndexPreflight) -> bool {
        self.expected_head == preflight.expected_head
            && self.resulting_head == preflight.candidate_head
            && self.statement_sequence == preflight.statement_sequence
            && self.statement_digest == preflight.statement_digest
    }
}

/// Verified portable-head change which a scanner may adopt without trusting service-supplied
/// digests or recognition heights.
///
/// Allocation anchors are extracted from the semantically replayed update. Observation-only and
/// terminal-only changes advance the pinned portable head without forcing a historical rescan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPortableScannerTransition {
    wallet: DepositWalletId,
    expected_head: [u8; 32],
    resulting_head: [u8; 32],
    through_sequence: u64,
    allocation_anchors: Vec<ChainPoint>,
}

/// Authenticated complete portable view used when a fresh join has no transition journals.
///
/// This token is deliberately non-serializable. It can only be constructed by matching the exact
/// logical head in a fully verified n-f checkpoint and semantically traversing every reachable
/// object and alias in that head. Allocation recognition anchors therefore cannot be omitted by a
/// peer which supplies the downloaded object graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPortableScannerSnapshot {
    wallet: DepositWalletId,
    head: [u8; 32],
    through_sequence: u64,
    allocation_anchors: Vec<ChainPoint>,
}

/// Exact observation-only portable transition authorized for independent checkpointing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositObservationIndexTransition {
    expected_head: DepositIndexHead,
    resulting_head: DepositIndexHead,
    observation_statement: [u8; 32],
}

impl VerifiedDepositObservationIndexTransition {
    #[must_use]
    pub const fn expected_head(&self) -> &DepositIndexHead {
        &self.expected_head
    }

    #[must_use]
    pub const fn resulting_head(&self) -> &DepositIndexHead {
        &self.resulting_head
    }

    #[must_use]
    pub const fn observation_statement(&self) -> [u8; 32] {
        self.observation_statement
    }
}

impl VerifiedPortableScannerTransition {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn expected_head_digest(&self) -> [u8; 32] {
        self.expected_head
    }

    #[must_use]
    pub const fn resulting_head_digest(&self) -> [u8; 32] {
        self.resulting_head
    }

    #[must_use]
    pub const fn through_sequence(&self) -> u64 {
        self.through_sequence
    }

    #[must_use]
    pub fn allocation_anchors(&self) -> &[ChainPoint] {
        &self.allocation_anchors
    }
}

impl VerifiedPortableScannerSnapshot {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head
    }

    #[must_use]
    pub const fn through_sequence(&self) -> u64 {
        self.through_sequence
    }

    #[must_use]
    pub fn allocation_anchors(&self) -> &[ChainPoint] {
        &self.allocation_anchors
    }
}

/// Bind a complete imported portable object graph to one exact verified checkpoint.
///
/// The full tree is traversed and all cross-alias invariants are checked. This is intentionally
/// more expensive than transition-journal verification and is reserved for fresh-join or
/// journal-loss recovery.
pub fn verify_portable_scanner_snapshot<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    checkpoint: &VerifiedDepositIndexCheckpoint,
) -> Result<VerifiedPortableScannerSnapshot, DepositIndexError> {
    if !checkpoint
        .resulting_head()
        .matches(head)
        .map_err(|_| DepositIndexError::InvalidVerifiedTransition)?
    {
        return Err(DepositIndexError::InvalidVerifiedTransition);
    }
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidVerifiedTransition);
    };
    if checkpoint.context().wallet_id() != wallet {
        return Err(DepositIndexError::InvalidVerifiedTransition);
    }
    let validation = validate_index_head(reader, head)?;
    let mut allocation_anchors = Vec::new();
    for id in validation.values.keys().copied() {
        let (object, _) = load_object(reader, id)?;
        if let StoredIndexObject::PortableAllocation(record) = object {
            if record.wallet_id() != wallet {
                return Err(DepositIndexError::InvalidPortableRecord);
            }
            allocation_anchors.push(record.allocation().recognition_anchor);
        }
    }
    allocation_anchors.sort_unstable();
    allocation_anchors.dedup();
    let through_sequence =
        head.portable_anchor.ok_or(DepositIndexError::InvalidVerifiedTransition)?.through_sequence;
    Ok(VerifiedPortableScannerSnapshot {
        wallet,
        head: head.digest(),
        through_sequence,
        allocation_anchors,
    })
}

/// Serializable transition journal retained until cleanup completes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexUpdate {
    version: u16,
    expected: DepositIndexHead,
    next: DepositIndexHead,
    objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    obsolete: BTreeSet<DepositIndexObjectId>,
    touched: BTreeSet<CanonicalIndexKey>,
    expected_verification: BTreeSet<DepositIndexObjectId>,
    next_verification: BTreeSet<DepositIndexObjectId>,
    operations: Vec<IndexMutation>,
}

impl DepositIndexUpdate {
    #[must_use]
    pub const fn expected_head(&self) -> &DepositIndexHead {
        &self.expected
    }

    #[must_use]
    pub const fn next_head(&self) -> &DepositIndexHead {
        &self.next
    }

    #[must_use]
    pub fn staged_object_count(&self) -> usize {
        self.objects.len()
    }

    #[must_use]
    pub fn obsolete_object_count(&self) -> usize {
        self.obsolete.len()
    }

    pub fn staged_objects(
        &self,
    ) -> impl ExactSizeIterator<Item = (DepositIndexObjectId, &[u8])> + '_ {
        self.objects.iter().map(|(id, bytes)| (*id, bytes.as_slice()))
    }

    pub fn obsolete_objects(&self) -> impl ExactSizeIterator<Item = DepositIndexObjectId> + '_ {
        self.obsolete.iter().copied()
    }

    pub fn expected_verification_objects(
        &self,
    ) -> impl ExactSizeIterator<Item = DepositIndexObjectId> + '_ {
        self.expected_verification.iter().copied()
    }

    pub fn next_verification_objects(
        &self,
    ) -> impl ExactSizeIterator<Item = DepositIndexObjectId> + '_ {
        self.next_verification.iter().copied()
    }

    #[must_use]
    pub fn touched_key_count(&self) -> usize {
        self.touched.len()
    }

    #[must_use]
    pub fn mutation_count(&self) -> usize {
        self.operations.len()
    }

    /// Deterministically replay this journal from its expected authenticated head and require the
    /// exact candidate head, object set, retirements, touched keys, and bounded verification sets.
    ///
    /// Canonical decoding and [`Self::to_bytes`] only establish shape. Checkpoint or handoff
    /// signers must call this semantic verifier before binding [`Self::next_head`].
    pub fn verify_semantic_transition<R: DepositIndexReader + ?Sized>(
        &self,
        reader: &R,
    ) -> Result<(), DepositIndexError> {
        self.validate_shape()?;
        verify_update_transition(reader, self)
    }

    /// Verify and authorize the sole exact portable ledger transition in this update.
    ///
    /// A generic successful semantic replay is insufficient for cursor advancement: the caller's
    /// statement must be byte-for-byte the one and only ledger operation in the journal.
    pub fn verify_ledger_transition<R: DepositIndexReader + ?Sized>(
        &self,
        reader: &R,
        statement: &LedgerStatement,
    ) -> Result<VerifiedDepositIndexTransition, DepositIndexError> {
        self.verify_semantic_transition(reader)?;
        if !matches!(self.expected.namespace, DepositIndexNamespace::Portable { .. })
            || self.expected.namespace != self.next.namespace
        {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let [IndexMutation::ApplyLedgerStatement(applied)] = self.operations.as_slice() else {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        };
        if applied != statement {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let resulting_anchor =
            self.next.portable_anchor.ok_or(DepositIndexError::InvalidVerifiedTransition)?;
        if resulting_anchor.through_sequence != statement.sequence
            || resulting_anchor.ledger_head != statement.digest()
        {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        Ok(VerifiedDepositIndexTransition {
            expected_head: self.expected.clone(),
            resulting_head: self.next.clone(),
            statement_sequence: statement.sequence,
            statement_digest: statement.digest(),
        })
    }

    /// Reverify the retained update after certification and bind it to the exact pre-signing
    /// candidate.
    pub fn verify_ledger_transition_for_preflight<R: DepositIndexReader + ?Sized>(
        &self,
        reader: &R,
        statement: &LedgerStatement,
        preflight: &VerifiedDepositIndexPreflight,
    ) -> Result<VerifiedDepositIndexTransition, DepositIndexError> {
        let transition = self.verify_ledger_transition(reader, statement)?;
        if !transition.matches_preflight(preflight) {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        Ok(transition)
    }

    /// Rebuild and authenticate a portable update before handing its new allocation view to the
    /// persistent scanner.
    pub fn verify_portable_scanner_transition<R: DepositIndexReader + ?Sized>(
        &self,
        reader: &R,
    ) -> Result<VerifiedPortableScannerTransition, DepositIndexError> {
        self.verify_semantic_transition(reader)?;
        let DepositIndexNamespace::Portable { wallet } = self.expected.namespace else {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        };
        if self.next.namespace != self.expected.namespace {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let mut allocation_anchors = Vec::new();
        for operation in &self.operations {
            match operation {
                IndexMutation::ApplyLedgerStatement(statement) => {
                    if let LedgerPayload::Allocation(allocation) = &statement.payload {
                        allocation_anchors.push(allocation.recognition_anchor);
                    }
                }
                IndexMutation::ApplyDepositObservation(_) => {}
                _ => return Err(DepositIndexError::InvalidVerifiedTransition),
            }
        }
        allocation_anchors.sort_unstable();
        allocation_anchors.dedup();
        let through_sequence = self
            .next
            .portable_anchor
            .ok_or(DepositIndexError::InvalidVerifiedTransition)?
            .through_sequence;
        Ok(VerifiedPortableScannerTransition {
            wallet,
            expected_head: self.expected.digest(),
            resulting_head: self.next.digest(),
            through_sequence,
            allocation_anchors,
        })
    }

    /// Verify that this update contains exactly one independently certified observation and no
    /// hidden ledger/local-safety mutation. This token is the checkpoint lane's ordering input.
    pub fn verify_deposit_observation_transition<R: DepositIndexReader + ?Sized>(
        &self,
        reader: &R,
        statement: &DepositObservationStatement,
    ) -> Result<VerifiedDepositObservationIndexTransition, DepositIndexError> {
        self.verify_semantic_transition(reader)?;
        if !matches!(self.expected.namespace, DepositIndexNamespace::Portable { .. })
            || self.expected.namespace != self.next.namespace
        {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let [IndexMutation::ApplyDepositObservation(applied)] = self.operations.as_slice() else {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        };
        if applied != statement {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        let expected_anchor =
            self.expected.portable_anchor.ok_or(DepositIndexError::InvalidVerifiedTransition)?;
        let resulting_anchor =
            self.next.portable_anchor.ok_or(DepositIndexError::InvalidVerifiedTransition)?;
        if resulting_anchor != expected_anchor {
            return Err(DepositIndexError::InvalidVerifiedTransition);
        }
        Ok(VerifiedDepositObservationIndexTransition {
            expected_head: self.expected.clone(),
            resulting_head: self.next.clone(),
            observation_statement: statement.digest(),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexError> {
        self.validate_shape()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositIndexError::Serialization)?;
        if bytes.len() > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
            return Err(DepositIndexError::UpdateTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexError> {
        if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
            return Err(DepositIndexError::UpdateTooLarge);
        }
        let (update, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexError::NonCanonicalObject);
        }
        update.validate_shape()?;
        if update.to_bytes()? != bytes {
            return Err(DepositIndexError::NonCanonicalObject);
        }
        Ok(update)
    }

    fn validate_shape(&self) -> Result<(), DepositIndexError> {
        self.expected.validate_shape()?;
        self.next.validate_shape()?;
        if self.version != INDEX_UPDATE_VERSION
            || self.expected.namespace != self.next.namespace
            || self.next.revision
                != self.expected.revision.checked_add(1).ok_or(DepositIndexError::InvalidHead)?
            || self.expected == self.next
            || self.objects.len() > MAX_DEPOSIT_INDEX_UPDATE_OBJECTS
            || self.obsolete.len() > MAX_DEPOSIT_INDEX_UPDATE_OBJECTS
            || self.touched.len() > MAX_DEPOSIT_INDEX_TOUCHED_KEYS
            || self.expected_verification.len() > MAX_DEPOSIT_INDEX_VERIFICATION_OBJECTS
            || self.next_verification.len() > MAX_DEPOSIT_INDEX_VERIFICATION_OBJECTS
            || self.operations.is_empty()
            || self.operations.len() > MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS
            || self.touched.iter().any(|key| key.namespace() != self.expected.namespace)
        {
            return Err(DepositIndexError::InvalidHead);
        }
        let mut total = 0_usize;
        for (id, bytes) in &self.objects {
            decode_object(*id, bytes)?;
            total = total.checked_add(bytes.len()).ok_or(DepositIndexError::UpdateTooLarge)?;
            if total > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
                return Err(DepositIndexError::UpdateTooLarge);
            }
        }
        for id in &self.obsolete {
            id.validate()?;
        }
        for id in self.expected_verification.iter().chain(self.next_verification.iter()) {
            id.validate()?;
            if id.wallet_id() != self.expected.namespace.wallet() {
                return Err(DepositIndexError::InvalidObjectId);
            }
        }
        if self.expected.root.is_some_and(|root| !self.expected_verification.contains(&root))
            || self.next.root.is_some_and(|root| !self.next_verification.contains(&root))
        {
            return Err(DepositIndexError::InvalidEntryCoverage);
        }
        let encoded = postcard::to_allocvec(self).map_err(|_| DepositIndexError::Serialization)?;
        if encoded.len() > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
            return Err(DepositIndexError::UpdateTooLarge);
        }
        Ok(())
    }

    /// Stage every immutable object and authenticate its exact readback before returning.
    pub fn stage<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &mut S,
    ) -> Result<StagedDepositIndexUpdate, DepositIndexError> {
        self.validate_shape()?;
        if store.load_index_head(self.expected.namespace)? != Some(self.expected.clone()) {
            return Err(DepositIndexError::CasConflict);
        }
        for (id, bytes) in &self.objects {
            let _created = store.stage_index_object(*id, bytes)?;
            let readback = store.load_index_object(*id)?.ok_or(DepositIndexError::MissingObject)?;
            if &readback != bytes {
                return Err(DepositIndexError::ObjectAuthentication);
            }
            decode_object(*id, &readback)?;
        }
        let staged_objects = self.objects.keys().copied().collect();
        Ok(StagedDepositIndexUpdate {
            version: INDEX_UPDATE_VERSION,
            update: self.clone(),
            staged_objects,
        })
    }
}

struct HiddenObjectReader<'a, R: DepositIndexReader + ?Sized> {
    base: &'a R,
    hidden: &'a BTreeSet<DepositIndexObjectId>,
}

impl<R: DepositIndexReader + ?Sized> DepositIndexReader for HiddenObjectReader<'_, R> {
    fn load_index_object(
        &self,
        id: DepositIndexObjectId,
    ) -> Result<Option<Vec<u8>>, DepositIndexError> {
        if self.hidden.contains(&id) { Ok(None) } else { self.base.load_index_object(id) }
    }
}

fn verify_update_transition<R: DepositIndexReader + ?Sized>(
    reader: &R,
    update: &DepositIndexUpdate,
) -> Result<(), DepositIndexError> {
    let hidden = update.objects.keys().copied().collect::<BTreeSet<_>>();
    let replay_reader = HiddenObjectReader { base: reader, hidden: &hidden };
    let mut builder = DepositIndexBuilder::new(&replay_reader, update.expected.clone())?;
    for operation in &update.operations {
        match operation {
            IndexMutation::ApplyLedgerStatement(statement) => {
                builder.apply_portable_statement(statement.clone())?;
            }
            IndexMutation::ApplyDepositObservation(statement) => {
                builder.apply_portable_deposit_observation(statement.clone())?;
            }
            IndexMutation::RecordSignedDepositObservation(statement) => {
                builder.record_signed_deposit_observation(statement)?;
            }
            IndexMutation::ReserveAllocationProposal { request, binding, index } => {
                builder.reserve_allocation_proposal(*request, *binding, *index)?;
            }
            IndexMutation::MarkFirstUsed { index, observed_at } => {
                builder.mark_first_used(*index, *observed_at)?;
            }
            IndexMutation::BindOutput { output, output_key, subaddress, amount_atomic_units } => {
                builder.bind_output(*output, *output_key, *subaddress, *amount_atomic_units)?;
            }
            IndexMutation::RecordSigningSession {
                consolidation,
                sweep,
                attempt,
                session,
                evidence,
            } => {
                builder.record_signing_session_tombstone(
                    *consolidation,
                    *sweep,
                    *attempt,
                    *session,
                    *evidence,
                )?;
            }
            IndexMutation::AdvanceNextSweepSequence { next_sequence } => {
                builder.advance_next_sweep_sequence(*next_sequence)?;
            }
            IndexMutation::RecordSignedLedgerSlot { sequence, statement_digest } => {
                builder.record_signed_ledger_slot(*sequence, *statement_digest)?;
            }
            IndexMutation::RecordSignedIndexCheckpointSlot(slot) => {
                builder.record_signed_index_checkpoint_slot(*slot)?;
            }
            IndexMutation::RecordCertifiedEntryLocator(locator) => {
                builder.record_certified_entry_locator_fields(*locator)?;
            }
        }
    }
    let replayed = builder.finish()?.ok_or(DepositIndexError::InvalidEntryCoverage)?;
    if replayed.next != update.next
        || replayed.objects != update.objects
        || replayed.obsolete != update.obsolete
        || replayed.touched != update.touched
        || replayed.expected_verification != update.expected_verification
        || replayed.next_verification != update.next_verification
        || replayed.operations != update.operations
    {
        return Err(DepositIndexError::InvalidEntryCoverage);
    }
    Ok(())
}

/// Durable staged-update state used for crash recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedDepositIndexUpdate {
    version: u16,
    update: DepositIndexUpdate,
    staged_objects: BTreeSet<DepositIndexObjectId>,
}

/// Result of replaying an uncertain staged update after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepositIndexRecovery {
    Committed,
    Superseded,
}

impl StagedDepositIndexUpdate {
    #[must_use]
    pub const fn update(&self) -> &DepositIndexUpdate {
        &self.update
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexError> {
        self.validate_shape()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositIndexError::Serialization)?;
        if bytes.len() > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
            return Err(DepositIndexError::UpdateTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexError> {
        if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_UPDATE_BYTES {
            return Err(DepositIndexError::UpdateTooLarge);
        }
        let (staged, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexError::NonCanonicalObject);
        }
        staged.validate_shape()?;
        if staged.to_bytes()? != bytes {
            return Err(DepositIndexError::NonCanonicalObject);
        }
        Ok(staged)
    }

    fn validate_shape(&self) -> Result<(), DepositIndexError> {
        self.update.validate_shape()?;
        if self.version != INDEX_UPDATE_VERSION
            || self.staged_objects != self.update.objects.keys().copied().collect::<BTreeSet<_>>()
        {
            return Err(DepositIndexError::InvalidHead);
        }
        Ok(())
    }

    /// Independently reload and authenticate the complete candidate tree and semantic alias set.
    pub fn verify_staged<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &S,
    ) -> Result<(), DepositIndexError> {
        self.validate_shape()?;
        for (id, expected) in &self.update.objects {
            let bytes = store.load_index_object(*id)?.ok_or(DepositIndexError::MissingObject)?;
            if &bytes != expected {
                return Err(DepositIndexError::ObjectAuthentication);
            }
            decode_object(*id, &bytes)?;
        }
        validate_root_shape(store, &self.update.next)?;
        validate_touched_paths(store, &self.update.next, &self.update.touched)?;
        verify_update_transition(store, &self.update)
    }

    fn verify_committed<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &S,
    ) -> Result<(), DepositIndexError> {
        self.validate_shape()?;
        for (id, expected) in &self.update.objects {
            let bytes = store.load_index_object(*id)?.ok_or(DepositIndexError::MissingObject)?;
            if &bytes != expected {
                return Err(DepositIndexError::ObjectAuthentication);
            }
            decode_object(*id, &bytes)?;
        }
        validate_root_shape(store, &self.update.next)?;
        validate_touched_paths(store, &self.update.next, &self.update.touched)
    }

    /// Install the candidate head with an exact old-head CAS. Replaying an already won CAS is
    /// idempotent.
    pub fn commit_head<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &mut S,
    ) -> Result<(), DepositIndexError> {
        self.verify_staged(store)?;
        let current = store.load_index_head(self.update.expected.namespace)?;
        if current == Some(self.update.next.clone()) {
            return Ok(());
        }
        if current != Some(self.update.expected.clone())
            || !store.compare_and_swap_index_head(&self.update.expected, &self.update.next)?
        {
            return Err(DepositIndexError::CasConflict);
        }
        if store.load_index_head(self.update.next.namespace)? != Some(self.update.next.clone()) {
            return Err(DepositIndexError::CasConflict);
        }
        Ok(())
    }

    /// Remove only exact objects unreachable from every installed index head.
    pub fn cleanup<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &mut S,
    ) -> Result<(), DepositIndexError> {
        if store.load_index_head(self.update.next.namespace)? != Some(self.update.next.clone()) {
            return Err(DepositIndexError::CasConflict);
        }
        let garbage = self
            .update
            .obsolete
            .iter()
            .chain(self.staged_objects.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        for id in garbage {
            if !store.index_object_is_pinned(id)? {
                store.remove_index_object(id)?;
            }
        }
        Ok(())
    }

    fn cleanup_superseded<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &mut S,
    ) -> Result<(), DepositIndexError> {
        for id in &self.staged_objects {
            if !store.index_object_is_pinned(*id)? {
                store.remove_index_object(*id)?;
            }
        }
        Ok(())
    }

    /// Resolve an uncertain crash window from durable objects plus the current CAS head.
    pub fn recover<S: DepositIndexCommitStore + ?Sized>(
        &self,
        store: &mut S,
    ) -> Result<DepositIndexRecovery, DepositIndexError> {
        self.validate_shape()?;
        let current = store
            .load_index_head(self.update.expected.namespace)?
            .ok_or(DepositIndexError::InvalidHead)?;
        if current == self.update.next {
            // The installed head is authenticated by the sealed snapshot/checkpoint. Rechecking
            // only this update's objects and touched paths keeps ordinary restart work bounded;
            // `verify_deposit_index_head` remains available for explicit whole-history audits.
            self.verify_committed(store)?;
            self.cleanup(store)?;
            return Ok(DepositIndexRecovery::Committed);
        }
        if current == self.update.expected {
            self.verify_staged(store)?;
            self.commit_head(store)?;
            self.cleanup(store)?;
            return Ok(DepositIndexRecovery::Committed);
        }
        self.cleanup_superseded(store)?;
        Ok(DepositIndexRecovery::Superseded)
    }
}

/// Portable alias to prove or query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortableAllocationQuery {
    Request(LedgerRequestId),
    Address(CanonicalDepositAddress),
    Index(DepositSubaddressIndex),
    SubaddressSpendKey([u8; 32]),
}

impl PortableAllocationQuery {
    fn key(&self, wallet: DepositWalletId) -> Result<CanonicalIndexKey, DepositIndexError> {
        match self {
            Self::Request(request) => {
                if request.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableRecord);
                }
                Ok(request_alias(wallet, *request))
            }
            Self::Address(address) => {
                address.validate()?;
                if address.wallet_id() != wallet {
                    return Err(DepositIndexError::InvalidPortableRecord);
                }
                Ok(address_alias(wallet, address))
            }
            Self::Index(index) => Ok(index_alias(wallet, *index)),
            Self::SubaddressSpendKey(spend_key) => subaddress_spend_key_alias(wallet, *spend_key),
        }
    }

    fn matches(&self, record: &PortableAllocationRecord) -> bool {
        match self {
            Self::Request(request) => record.allocation().request == *request,
            Self::Address(address) => record.allocation().address == *address,
            Self::Index(index) => record.allocation().address.index() == *index,
            Self::SubaddressSpendKey(expected) => {
                subaddress_spend_key(&record.allocation().address)
                    .is_ok_and(|actual| actual == *expected)
            }
        }
    }
}

/// Portable sequence/terminal safety fact to prove or query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortableStateQuery {
    Sequence(u64),
    FirstUsed(DepositSubaddressIndex),
    ObservedOutput(WalletOutputId),
    ObservedOneTimeOutputKey([u8; 32]),
    Consolidation(ConsolidationId),
    Sweep(SweepId),
    ClaimedOutput(WalletOutputId),
    SigningSession(SessionId),
    NextSweepSequence,
}

impl PortableStateQuery {
    fn key(self, wallet: DepositWalletId) -> Result<CanonicalIndexKey, DepositIndexError> {
        Ok(match self {
            Self::Sequence(sequence) => {
                if sequence == 0 {
                    return Err(DepositIndexError::InvalidPortableRecord);
                }
                sequence_alias(wallet, sequence)
            }
            Self::FirstUsed(index) => portable_first_used_alias(wallet, index),
            Self::ObservedOutput(output) => {
                if output.transaction == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableObservation);
                }
                portable_observed_output_alias(wallet, output)
            }
            Self::ObservedOneTimeOutputKey(output_key) => {
                if output_key == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableObservation);
                }
                portable_observed_output_key_alias(wallet, output_key)
            }
            Self::Consolidation(consolidation) => {
                if consolidation.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                consolidation_alias(wallet, consolidation)
            }
            Self::Sweep(sweep) => {
                if sweep.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                sweep_alias(wallet, sweep)
            }
            Self::ClaimedOutput(output) => {
                if output.transaction == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                claimed_output_alias(wallet, output)
            }
            Self::SigningSession(session) => {
                if session.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidPortableTerminal);
                }
                portable_signing_session_alias(wallet, session)
            }
            Self::NextSweepSequence => portable_next_sweep_sequence_alias(wallet),
        })
    }
}

/// Party-local safety alias to prove or query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSafetyQuery {
    ProposedIndex(DepositSubaddressIndex),
    ReservedRequest(LedgerRequestId),
    FirstUsed(DepositSubaddressIndex),
    Output(WalletOutputId),
    OneTimeOutputKey([u8; 32]),
    SigningSession(SessionId),
    AttemptHighWater(SweepId),
    NextSweepSequence,
    SignedDepositObservationOutput(WalletOutputId),
    SignedDepositObservationKey([u8; 32]),
    SignedLedgerSlot(u64),
    SignedIndexCheckpointSlot(u64),
    CertifiedEntryLocator(u64),
    CertifiedCheckpointLocator(u64),
}

impl LocalSafetyQuery {
    fn key(
        self,
        wallet: DepositWalletId,
        party: PartyId,
    ) -> Result<CanonicalIndexKey, DepositIndexError> {
        Ok(match self {
            Self::ProposedIndex(index) => proposed_index_alias(wallet, party, index),
            Self::ReservedRequest(request) => {
                if request.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                reserved_request_alias(wallet, party, request)
            }
            Self::FirstUsed(index) => used_alias(wallet, party, index),
            Self::Output(output) => {
                if output.transaction == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                output_alias(wallet, party, output)
            }
            Self::OneTimeOutputKey(output_key) => {
                if output_key == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                one_time_output_key_alias(wallet, party, output_key)
            }
            Self::SigningSession(session) => {
                if session.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_signing_session_alias(wallet, party, session)
            }
            Self::AttemptHighWater(sweep) => {
                if sweep.0 == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_attempt_high_water_alias(wallet, party, sweep)
            }
            Self::NextSweepSequence => local_next_sweep_sequence_alias(wallet, party),
            Self::SignedDepositObservationOutput(output) => {
                if output.transaction == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_signed_observation_output_alias(wallet, party, output)
            }
            Self::SignedDepositObservationKey(output_key) => {
                if output_key == [0; 32] {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_signed_observation_key_alias(wallet, party, output_key)
            }
            Self::SignedLedgerSlot(sequence) => {
                if sequence == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_signed_ledger_slot_alias(wallet, party, sequence)
            }
            Self::SignedIndexCheckpointSlot(checkpoint_sequence) => {
                if checkpoint_sequence == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_signed_index_checkpoint_slot_alias(wallet, party, checkpoint_sequence)
            }
            Self::CertifiedEntryLocator(sequence) => {
                if sequence == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_certified_entry_locator_alias(wallet, party, sequence)
            }
            Self::CertifiedCheckpointLocator(checkpoint_sequence) => {
                if checkpoint_sequence == 0 {
                    return Err(DepositIndexError::InvalidLocalSafetyRecord);
                }
                local_certified_checkpoint_locator_alias(wallet, party, checkpoint_sequence)
            }
        })
    }

    fn matches(self, record: &LocalDepositSafetyRecord) -> bool {
        match (self, &record.value) {
            (Self::ProposedIndex(expected), LocalSafetyValue::ProposedIndex { index, .. }) => {
                expected == *index
            }
            (
                Self::ReservedRequest(expected),
                LocalSafetyValue::ReservedRequest { request, .. },
            ) => expected == *request,
            (Self::FirstUsed(expected), LocalSafetyValue::FirstUsed { index, .. }) => {
                expected == *index
            }
            (Self::Output(expected), LocalSafetyValue::OutputBinding { output, .. }) => {
                expected == *output
            }
            (
                Self::OneTimeOutputKey(expected),
                LocalSafetyValue::OneTimeOutputKey { output_key, .. },
            ) => expected == *output_key,
            (
                Self::SigningSession(expected),
                LocalSafetyValue::SigningSessionTombstone { session, .. },
            ) => expected == *session,
            (
                Self::AttemptHighWater(expected),
                LocalSafetyValue::AttemptHighWater { sweep, .. },
            ) => expected == *sweep,
            (Self::NextSweepSequence, LocalSafetyValue::NextSweepSequence { .. }) => true,
            (
                Self::SignedDepositObservationOutput(expected),
                LocalSafetyValue::SignedDepositObservationOutput(slot),
            ) => expected == slot.output,
            (
                Self::SignedDepositObservationKey(expected),
                LocalSafetyValue::SignedDepositObservationKey(slot),
            ) => expected == slot.output_key,
            (Self::SignedLedgerSlot(expected), LocalSafetyValue::SignedLedgerSlot(slot)) => {
                expected == slot.sequence
            }
            (
                Self::SignedIndexCheckpointSlot(expected),
                LocalSafetyValue::SignedIndexCheckpointSlot(slot),
            ) => expected == slot.checkpoint_sequence,
            (
                Self::CertifiedEntryLocator(expected),
                LocalSafetyValue::CertifiedEntryLocator(locator),
            ) => expected == locator.ledger_sequence,
            (
                Self::CertifiedCheckpointLocator(expected),
                LocalSafetyValue::CertifiedCheckpointLocator(locator),
            ) => expected == locator.checkpoint_sequence,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ProofObject {
    id: DepositIndexObjectId,
    bytes: Vec<u8>,
}

/// Bounded Merkle path proving exact presence or absence against one trusted head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexProof {
    version: u16,
    namespace: DepositIndexNamespace,
    key: CanonicalIndexKey,
    path: Vec<ProofObject>,
    value: Option<ProofObject>,
}

impl DepositIndexProof {
    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexError> {
        self.validate_bounds()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| DepositIndexError::Serialization)?;
        if bytes.len() > MAX_DEPOSIT_INDEX_PROOF_BYTES {
            return Err(DepositIndexError::InvalidProof);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexError> {
        if bytes.is_empty() || bytes.len() > MAX_DEPOSIT_INDEX_PROOF_BYTES {
            return Err(DepositIndexError::InvalidProof);
        }
        let (proof, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexError::InvalidProof);
        }
        proof.validate_bounds()?;
        if proof.to_bytes()? != bytes {
            return Err(DepositIndexError::InvalidProof);
        }
        Ok(proof)
    }

    fn validate_bounds(&self) -> Result<(), DepositIndexError> {
        self.namespace.validate()?;
        if self.version != INDEX_PROOF_VERSION
            || self.key.namespace() != self.namespace
            || self.path.len() > MAX_DEPOSIT_INDEX_PROOF_OBJECTS
        {
            return Err(DepositIndexError::InvalidProof);
        }
        let total =
            self.path.iter().chain(self.value.iter()).try_fold(0_usize, |total, object| {
                object.id.validate()?;
                if object.bytes.is_empty() || object.bytes.len() > MAX_DEPOSIT_INDEX_OBJECT_BYTES {
                    return Err(DepositIndexError::InvalidProof);
                }
                total.checked_add(object.bytes.len()).ok_or(DepositIndexError::InvalidProof)
            })?;
        if total > MAX_DEPOSIT_INDEX_PROOF_BYTES {
            return Err(DepositIndexError::InvalidProof);
        }
        Ok(())
    }
}

fn next_missing_query_object<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    key: &CanonicalIndexKey,
) -> Result<Option<DepositIndexObjectId>, DepositIndexError> {
    head.validate_shape()?;
    if key.namespace() != head.namespace {
        return Err(DepositIndexError::InvalidProof);
    }
    let path_hash = key.path_hash()?;
    let mut current = head.root;
    let mut depth = 0_u8;
    let mut reads = 0_usize;
    while let Some(id) = current {
        if reads >= MAX_DEPOSIT_INDEX_QUERY_READS {
            return Err(DepositIndexError::InvalidProof);
        }
        reads += 1;
        let Some(bytes) = reader.load_index_object(id)? else {
            return Ok(Some(id));
        };
        let object = decode_object(id, &bytes)?;
        let StoredIndexObject::Node(node) = object else {
            return Err(DepositIndexError::InvalidNode);
        };
        if node.namespace != head.namespace || node.depth != depth {
            return Err(DepositIndexError::InvalidNode);
        }
        match node.body {
            HamtNodeBody::Leaf { entries } => {
                let Ok(position) = entries.binary_search_by(|entry| entry.key.cmp(key)) else {
                    return Ok(None);
                };
                let value = entries[position].value;
                let Some(value_bytes) = reader.load_index_object(value)? else {
                    return Ok(Some(value));
                };
                if matches!(decode_object(value, &value_bytes)?, StoredIndexObject::Node(_)) {
                    return Err(DepositIndexError::InvalidEntryCoverage);
                }
                return Ok(None);
            }
            HamtNodeBody::Branch { bitmap, children } => {
                let slot = routing_nibble(path_hash, key, depth)?;
                let mask = 1_u16 << slot;
                if bitmap & mask == 0 {
                    return Ok(None);
                }
                current = Some(children[bitmap_position(bitmap, slot)]);
                depth = depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?;
            }
        }
    }
    Ok(None)
}

/// Return the next exact encrypted artifact which must be asynchronously loaded before a portable
/// query can be answered by the synchronous core. Each call performs at most
/// [`MAX_DEPOSIT_INDEX_QUERY_READS`] cache reads, and one query can require no more than that many
/// distinct asynchronous artifact loads.
pub fn next_portable_query_object<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: &PortableAllocationQuery,
) -> Result<Option<DepositIndexObjectId>, DepositIndexError> {
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    next_missing_query_object(reader, head, &query.key(wallet)?)
}

/// Bounded-preload counterpart for sequence and terminal-state queries.
pub fn next_portable_state_query_object<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: PortableStateQuery,
) -> Result<Option<DepositIndexObjectId>, DepositIndexError> {
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    next_missing_query_object(reader, head, &query.key(wallet)?)
}

/// Local-safety counterpart of [`next_portable_query_object`].
pub fn next_local_safety_query_object<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: LocalSafetyQuery,
) -> Result<Option<DepositIndexObjectId>, DepositIndexError> {
    let DepositIndexNamespace::LocalSafety { wallet, party } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    next_missing_query_object(reader, head, &query.key(wallet, party)?)
}

/// Return one exact artifact missing from the bounded staged-transition verification working set.
///
/// With `committed = false`, both expected and candidate paths are covered for deterministic
/// replay before CAS. With `committed = true`, only the installed candidate paths are required.
/// The adapter repeatedly async-loads the returned full artifact reference into its bounded cache,
/// then invokes the synchronous verification/recovery method.
pub fn next_missing_staged_verification_object<R: DepositIndexReader + ?Sized>(
    reader: &R,
    staged: &StagedDepositIndexUpdate,
    committed: bool,
) -> Result<Option<DepositIndexObjectId>, DepositIndexError> {
    Ok(missing_staged_verification_objects(reader, staged, committed)?.into_iter().next())
}

/// Enumerate the complete bounded preload set in one pass.
///
/// This is preferable to repeatedly calling [`next_missing_staged_verification_object`] when a
/// restart begins with an empty cache because it performs at most
/// [`MAX_DEPOSIT_INDEX_UPDATE_VERIFICATION_READS`] synchronous cache lookups.
pub fn missing_staged_verification_objects<R: DepositIndexReader + ?Sized>(
    reader: &R,
    staged: &StagedDepositIndexUpdate,
    committed: bool,
) -> Result<Vec<DepositIndexObjectId>, DepositIndexError> {
    staged.validate_shape()?;
    let mut required = staged
        .update
        .objects
        .keys()
        .copied()
        .chain(staged.update.next_verification.iter().copied())
        .collect::<BTreeSet<_>>();
    if !committed {
        required.extend(staged.update.expected_verification.iter().copied());
    }
    let mut missing = Vec::new();
    for id in required {
        match reader.load_index_object(id)? {
            Some(bytes) => {
                if let Some(expected) = staged.update.objects.get(&id)
                    && expected != &bytes
                {
                    return Err(DepositIndexError::ObjectAuthentication);
                }
                decode_object(id, &bytes)?;
            }
            None => missing.push(id),
        }
    }
    Ok(missing)
}

fn build_proof<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    key: CanonicalIndexKey,
) -> Result<DepositIndexProof, DepositIndexError> {
    head.validate_shape()?;
    if key.namespace() != head.namespace {
        return Err(DepositIndexError::InvalidProof);
    }
    let path_hash = key.path_hash()?;
    let mut proof = DepositIndexProof {
        version: INDEX_PROOF_VERSION,
        namespace: head.namespace,
        key,
        path: Vec::new(),
        value: None,
    };
    let mut current = head.root;
    let mut depth = 0_u8;
    while let Some(id) = current {
        if proof.path.len() == MAX_DEPOSIT_INDEX_PROOF_OBJECTS {
            return Err(DepositIndexError::InvalidProof);
        }
        let (object, bytes) = load_object(reader, id)?;
        let StoredIndexObject::Node(node) = object else {
            return Err(DepositIndexError::InvalidNode);
        };
        if node.namespace != head.namespace || node.depth != depth {
            return Err(DepositIndexError::InvalidNode);
        }
        proof.path.push(ProofObject { id, bytes });
        match node.body {
            HamtNodeBody::Leaf { entries } => {
                if let Ok(position) = entries.binary_search_by(|entry| entry.key.cmp(&proof.key)) {
                    let value_id = entries[position].value;
                    let (_, value_bytes) = load_object(reader, value_id)?;
                    proof.value = Some(ProofObject { id: value_id, bytes: value_bytes });
                }
                break;
            }
            HamtNodeBody::Branch { bitmap, children } => {
                let slot = routing_nibble(path_hash, &proof.key, depth)?;
                let mask = 1_u16 << slot;
                if bitmap & mask == 0 {
                    break;
                }
                current = Some(children[bitmap_position(bitmap, slot)]);
                depth = depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?;
            }
        }
    }
    proof.validate_bounds()?;
    Ok(proof)
}

fn verify_proof_object(object: &ProofObject) -> Result<StoredIndexObject, DepositIndexError> {
    decode_object(object.id, &object.bytes)
}

fn verify_proof(
    head: &DepositIndexHead,
    proof: &DepositIndexProof,
) -> Result<Option<StoredIndexObject>, DepositIndexError> {
    head.validate_shape()?;
    proof.validate_bounds()?;
    if proof.namespace != head.namespace {
        return Err(DepositIndexError::InvalidProof);
    }
    if proof.key.namespace() != head.namespace {
        return Err(DepositIndexError::InvalidProof);
    }
    let path_hash = proof.key.path_hash()?;
    let Some(root) = head.root else {
        return if proof.path.is_empty() && proof.value.is_none() {
            Ok(None)
        } else {
            Err(DepositIndexError::InvalidProof)
        };
    };
    if proof.path.first().map(|object| object.id) != Some(root) {
        return Err(DepositIndexError::InvalidProof);
    }
    let mut expected = root;
    let mut depth = 0_u8;
    let mut prefix = Vec::new();
    for (position, proof_node) in proof.path.iter().enumerate() {
        if proof_node.id != expected {
            return Err(DepositIndexError::InvalidProof);
        }
        let StoredIndexObject::Node(node) = verify_proof_object(proof_node)? else {
            return Err(DepositIndexError::InvalidProof);
        };
        if node.namespace != head.namespace || node.depth != depth {
            return Err(DepositIndexError::InvalidProof);
        }
        match node.body {
            HamtNodeBody::Leaf { entries } => {
                if position + 1 != proof.path.len() {
                    return Err(DepositIndexError::InvalidProof);
                }
                for entry in &entries {
                    validate_prefix(entry.path_hash, &entry.key, &prefix)?;
                }
                return match entries.binary_search_by(|entry| entry.key.cmp(&proof.key)) {
                    Ok(entry_position) => {
                        let value = proof.value.as_ref().ok_or(DepositIndexError::InvalidProof)?;
                        if value.id != entries[entry_position].value {
                            return Err(DepositIndexError::InvalidProof);
                        }
                        let object = verify_proof_object(value)?;
                        if matches!(object, StoredIndexObject::Node(_)) {
                            return Err(DepositIndexError::InvalidProof);
                        }
                        Ok(Some(object))
                    }
                    Err(_) if proof.value.is_none() => Ok(None),
                    Err(_) => Err(DepositIndexError::InvalidProof),
                };
            }
            HamtNodeBody::Branch { bitmap, children } => {
                let slot = routing_nibble(path_hash, &proof.key, depth)?;
                let mask = 1_u16 << slot;
                if bitmap & mask == 0 {
                    return if position + 1 == proof.path.len() && proof.value.is_none() {
                        Ok(None)
                    } else {
                        Err(DepositIndexError::InvalidProof)
                    };
                }
                prefix.push(slot);
                expected = children[bitmap_position(bitmap, slot)];
                depth = depth.checked_add(1).ok_or(DepositIndexError::DepthExhausted)?;
            }
        }
    }
    Err(DepositIndexError::InvalidProof)
}

/// Build a portable membership/absence proof from authenticated local objects.
pub fn prove_portable_allocation<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: &PortableAllocationQuery,
) -> Result<DepositIndexProof, DepositIndexError> {
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    build_proof(reader, head, query.key(wallet)?)
}

/// Verify an exact portable membership/absence proof against the supplied trusted head.
pub fn verify_portable_allocation_proof(
    head: &DepositIndexHead,
    query: &PortableAllocationQuery,
    proof: &DepositIndexProof,
) -> Result<Option<PortableAllocationRecord>, DepositIndexError> {
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    if proof.key != query.key(wallet)? {
        return Err(DepositIndexError::InvalidProof);
    }
    match verify_proof(head, proof)? {
        Some(StoredIndexObject::PortableAllocation(record))
            if record.wallet_id() == wallet && query.matches(&record) =>
        {
            Ok(Some(record))
        }
        None => Ok(None),
        _ => Err(DepositIndexError::InvalidProof),
    }
}

/// Authenticated local lookup implemented by constructing and verifying the same bounded proof a
/// remote consumer would receive.
pub fn lookup_portable_allocation<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: &PortableAllocationQuery,
) -> Result<Option<PortableAllocationRecord>, DepositIndexError> {
    let proof = prove_portable_allocation(reader, head, query)?;
    verify_portable_allocation_proof(head, query, &proof)
}

/// Typed value returned by a [`PortableStateQuery`] proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortableStateRecord {
    Statement(LedgerStatement),
    FirstUse(PortableFirstUseRecord),
    DepositOutput(PortableDepositOutputRecord),
    Terminal(PortableConsolidationTerminalRecord),
    OutputClaim(PortableOutputClaimRecord),
    SigningSession(PortableSigningSessionTombstone),
    SweepHighWater(PortableSweepHighWaterRecord),
}

/// Build a bounded membership/absence proof for an exact portable state key.
pub fn prove_portable_state<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: PortableStateQuery,
) -> Result<DepositIndexProof, DepositIndexError> {
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    build_proof(reader, head, query.key(wallet)?)
}

/// Verify a portable sequence/terminal proof against one trusted logical head.
pub fn verify_portable_state_proof(
    head: &DepositIndexHead,
    query: PortableStateQuery,
    proof: &DepositIndexProof,
) -> Result<Option<PortableStateRecord>, DepositIndexError> {
    let DepositIndexNamespace::Portable { wallet } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    if proof.key != query.key(wallet)? {
        return Err(DepositIndexError::InvalidProof);
    }
    let record = match (query, verify_proof(head, proof)?) {
        (
            PortableStateQuery::Sequence(sequence),
            Some(StoredIndexObject::PortableAllocation(value)),
        ) if value.wallet_id() == wallet && value.statement.sequence == sequence => {
            PortableStateRecord::Statement(value.statement)
        }
        (
            PortableStateQuery::Sequence(sequence),
            Some(StoredIndexObject::PortableLedgerStatement(value)),
        ) if value.wallet_id() == wallet && value.statement.sequence == sequence => {
            PortableStateRecord::Statement(value.statement)
        }
        (
            PortableStateQuery::FirstUsed(index),
            Some(StoredIndexObject::PortableFirstUse(value)),
        ) if value.wallet == wallet && value.index == index => PortableStateRecord::FirstUse(value),
        (
            PortableStateQuery::ObservedOutput(output),
            Some(StoredIndexObject::PortableDepositOutput(value)),
        ) if value.wallet == wallet && value.output == output => {
            PortableStateRecord::DepositOutput(value)
        }
        (
            PortableStateQuery::ObservedOneTimeOutputKey(output_key),
            Some(StoredIndexObject::PortableDepositOutput(value)),
        ) if value.wallet == wallet && value.output_key == output_key => {
            PortableStateRecord::DepositOutput(value)
        }
        (
            PortableStateQuery::Consolidation(consolidation),
            Some(StoredIndexObject::PortableTerminal(value)),
        ) if value.wallet == wallet && value.consolidation == consolidation => {
            PortableStateRecord::Terminal(value)
        }
        (PortableStateQuery::Sweep(sweep), Some(StoredIndexObject::PortableTerminal(value)))
            if value.wallet == wallet && value.sweep == sweep =>
        {
            PortableStateRecord::Terminal(value)
        }
        (
            PortableStateQuery::ClaimedOutput(output),
            Some(StoredIndexObject::PortableOutputClaim(value)),
        ) if value.wallet == wallet && value.output == output => {
            PortableStateRecord::OutputClaim(value)
        }
        (
            PortableStateQuery::SigningSession(session),
            Some(StoredIndexObject::PortableSigningSession(value)),
        ) if value.wallet == wallet && value.session == session => {
            PortableStateRecord::SigningSession(value)
        }
        (
            PortableStateQuery::NextSweepSequence,
            Some(StoredIndexObject::PortableSweepHighWater(value)),
        ) if value.wallet == wallet => PortableStateRecord::SweepHighWater(value),
        (_, None) => return Ok(None),
        _ => return Err(DepositIndexError::InvalidProof),
    };
    Ok(Some(record))
}

pub fn lookup_portable_state<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: PortableStateQuery,
) -> Result<Option<PortableStateRecord>, DepositIndexError> {
    let proof = prove_portable_state(reader, head, query)?;
    verify_portable_state_proof(head, query, &proof)
}

pub fn prove_local_safety<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: LocalSafetyQuery,
) -> Result<DepositIndexProof, DepositIndexError> {
    let DepositIndexNamespace::LocalSafety { wallet, party } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    build_proof(reader, head, query.key(wallet, party)?)
}

pub fn verify_local_safety_proof(
    head: &DepositIndexHead,
    query: LocalSafetyQuery,
    proof: &DepositIndexProof,
) -> Result<Option<LocalDepositSafetyRecord>, DepositIndexError> {
    let DepositIndexNamespace::LocalSafety { wallet, party } = head.namespace else {
        return Err(DepositIndexError::InvalidHead);
    };
    if proof.key != query.key(wallet, party)? {
        return Err(DepositIndexError::InvalidProof);
    }
    match verify_proof(head, proof)? {
        Some(StoredIndexObject::LocalSafety(record))
            if record.wallet == wallet && record.party == party && query.matches(&record) =>
        {
            Ok(Some(record))
        }
        None => Ok(None),
        _ => Err(DepositIndexError::InvalidProof),
    }
}

pub fn lookup_local_safety<R: DepositIndexReader + ?Sized>(
    reader: &R,
    head: &DepositIndexHead,
    query: LocalSafetyQuery,
) -> Result<Option<LocalDepositSafetyRecord>, DepositIndexError> {
    let proof = prove_local_safety(reader, head, query)?;
    verify_local_safety_proof(head, query, &proof)
}

/// Errors are fail-closed: no malformed object or partial alias set may become authoritative.
#[derive(Debug, Error)]
pub enum DepositIndexError {
    #[error("deposit index head is malformed or belongs to another namespace")]
    InvalidHead,
    #[error("content-addressed object identifier is invalid")]
    InvalidObjectId,
    #[error("content-addressed object bytes do not match their identifier")]
    ObjectAuthentication,
    #[error("index object is empty or exceeds its canonical bound")]
    ObjectTooLarge,
    #[error("index object encoding is not canonical")]
    NonCanonicalObject,
    #[error("HAMT node shape, depth, prefix, or ordering is invalid")]
    InvalidNode,
    #[error("the complete 256-bit HAMT path was exhausted")]
    DepthExhausted,
    #[error("a referenced content-addressed object is missing")]
    MissingObject,
    #[error("portable allocation record is malformed")]
    InvalidPortableRecord,
    #[error("portable certified deposit observation is malformed")]
    InvalidPortableObservation,
    #[error("portable deposit output or first-use fact conflicts with an existing binding")]
    PortableObservationConflict,
    #[error("portable consolidation terminal record or cross-link is malformed")]
    InvalidPortableTerminal,
    #[error("party-local deposit safety record is malformed")]
    InvalidLocalSafetyRecord,
    #[error("an alias is already bound to another immutable value")]
    AliasConflict,
    #[error("a portable record's required alias or cross-link set is incomplete")]
    IncompleteAliasSet,
    #[error("a party-local proposal or output safety pair is incomplete")]
    IncompleteLocalSafetyPair,
    #[error("a consolidation ID or sweep family already has a different terminal outcome")]
    TerminalConflict,
    #[error("a consolidation input is already permanently claimed")]
    OutputAlreadyClaimed,
    #[error("a signing session is already permanently tombstoned")]
    SigningSessionAlreadyUsed,
    #[error("a sweep sequence regressed below its permanent high-water")]
    SweepSequenceRegression,
    #[error("the sweep sequence high-water is exhausted")]
    SweepSequenceExhausted,
    #[error("the portable allocation index does not match its exact high-water")]
    AllocationIndexMismatch,
    #[error("the portable allocation index address component is exhausted")]
    SubaddressIndexExhausted,
    #[error("this party already signed a different statement at the ledger sequence")]
    LedgerSlotAlreadySigned,
    #[error("this party already signed a different deposit-index checkpoint at this sequence")]
    IndexCheckpointSlotAlreadySigned,
    #[error("the locally authenticated output does not match the proposed deposit observation")]
    InvalidDepositObservationBinding,
    #[error("this party already attested to a conflicting fact for this output or one-time key")]
    DepositObservationAlreadySigned,
    #[error("the certified-entry sequence is already bound to another local artifact")]
    CertifiedEntryLocatorConflict,
    #[error("ledger coverage is non-contiguous or forks the indexed ledger head")]
    LedgerAnchorMismatch,
    #[error("the update does not authorize exactly the supplied portable ledger transition")]
    InvalidVerifiedTransition,
    #[error("index entry count or value alias coverage is inconsistent")]
    InvalidEntryCoverage,
    #[error("staged update exceeds its object-count or byte bound")]
    UpdateTooLarge,
    #[error("deposit index update exceeds its mutation bound")]
    TooManyMutations,
    #[error("index update compare-and-swap lost to another head")]
    CasConflict,
    #[error("index proof does not authenticate exact presence or absence")]
    InvalidProof,
    #[error("index serialization failed")]
    Serialization,
    #[error("certified ledger validation failed: {0}")]
    Ledger(#[from] LedgerError),
    #[error("canonical deposit address validation failed: {0}")]
    Wallet(#[from] DepositWalletError),
    #[error("wallet artifact storage validation failed: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeMap, HashMap};
    use std::io::Cursor;

    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use frost::{
        Participant, ThresholdKeys, ThresholdParams,
        curve::{Ciphersuite, Ed25519},
        dkg::Interpolation,
    };
    use monero_wallet::{
        OutputWithDecoys,
        address::AddressType,
        ed25519::{Commitment, Point, Scalar as WalletScalar},
        interface::FeeRate,
        ringct::{RctType, clsag::Decoys},
        send::{Change, SignableTransaction},
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use serde::{Serialize, de::DeserializeOwned};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_epoch_registry::{
            CompactEpochRegistry, VerifiedIssuerWindow, compact_registry_genesis_ledger_head,
        },
        compact_registry_archive::{
            CompactRegistryArchiveError, CompactRegistryObjectReader, CompactRegistryObjectRef,
            lookup_verified_issuer_window, prepare_compact_registry_genesis,
        },
        config::NetworkKind,
        consolidation_consensus::{
            CONSOLIDATION_INTENT_APPLICATION, ConsolidationIntent, ConsolidationIntentCertificate,
        },
        consolidation_roast::{
            RoastAttemptPrefixFrontier, RoastViewPlan, deterministic_roast_family_digest,
        },
        deposit_consensus::{
            CommitCertificate, ConsensusBinding, ConsensusMessageBody, Vote, sign_consensus_message,
        },
        deposit_consolidation::{
            AttemptBinding, OpaqueIntentBinding, SignedTransactionBinding,
            TransactionAuthorization, consolidation_input_set_binding,
            consolidation_signed_bytes_binding,
        },
        deposit_consolidation_wire::{
            ConsolidationAttemptWireBinding, ConsolidationConsensusSlot,
            PortableFamilyKeyImageBinding, PortableKeyImageBindingAttestation,
            PortableKeyImageBindingCertificate,
        },
        deposit_ledger::{ConsolidationCompletionStatement, LateConsolidationSettlementStatement},
        deposit_wallet::{
            ChainPoint, DepositAddressDeriver, SignedSweepTransaction, derive_sweep_signing_session,
        },
        deposit_worker::SweepPlan,
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
        signing::{FrostlassSigner, SigningContext, threshold_group_key},
    };

    type FrostScalar = <Ed25519 as Ciphersuite>::F;

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0xa6; 32];
        // Keep the identity discriminator away from X25519's clamped low byte.
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    #[derive(Default)]
    struct MemoryStore {
        objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
        heads: BTreeMap<DepositIndexNamespace, DepositIndexHead>,
        explicit_pins: BTreeSet<DepositIndexObjectId>,
        installed_pins: BTreeSet<DepositIndexObjectId>,
        stage_calls: usize,
        fail_stage_call: Option<usize>,
        load_calls: Cell<usize>,
    }

    impl MemoryStore {
        fn with_head(head: DepositIndexHead) -> Self {
            Self { heads: BTreeMap::from([(head.namespace(), head)]), ..Self::default() }
        }

        fn collect_reachable(
            &self,
            id: DepositIndexObjectId,
            reachable: &mut BTreeSet<DepositIndexObjectId>,
        ) -> Result<(), DepositIndexError> {
            if !reachable.insert(id) {
                return Ok(());
            }
            let bytes = self.objects.get(&id).ok_or(DepositIndexError::MissingObject)?;
            match decode_object(id, bytes)? {
                StoredIndexObject::Node(node) => match node.body {
                    HamtNodeBody::Leaf { entries } => {
                        for entry in entries {
                            self.collect_reachable(entry.value, reachable)?;
                        }
                    }
                    HamtNodeBody::Branch { children, .. } => {
                        for child in children {
                            self.collect_reachable(child, reachable)?;
                        }
                    }
                },
                StoredIndexObject::PortableAllocation(_)
                | StoredIndexObject::PortableLedgerStatement(_)
                | StoredIndexObject::PortableFirstUse(_)
                | StoredIndexObject::PortableDepositOutput(_)
                | StoredIndexObject::PortableTerminal(_)
                | StoredIndexObject::PortableOutputClaim(_)
                | StoredIndexObject::PortableSigningSession(_)
                | StoredIndexObject::PortableSweepHighWater(_)
                | StoredIndexObject::LocalSafety(_) => {}
            }
            Ok(())
        }

        fn reachable_from_heads(
            &self,
        ) -> Result<BTreeSet<DepositIndexObjectId>, DepositIndexError> {
            let mut reachable = self.explicit_pins.clone();
            for head in self.heads.values() {
                if let Some(root) = head.root() {
                    self.collect_reachable(root, &mut reachable)?;
                }
            }
            Ok(reachable)
        }

        fn assert_no_unreachable_objects(&self) {
            let reachable = self.reachable_from_heads().unwrap();
            assert_eq!(self.objects.keys().copied().collect::<BTreeSet<_>>(), reachable);
        }
    }

    impl DepositIndexReader for MemoryStore {
        fn load_index_object(
            &self,
            id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            self.load_calls.set(self.load_calls.get() + 1);
            Ok(self.objects.get(&id).cloned())
        }
    }

    impl DepositIndexCommitStore for MemoryStore {
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
            self.stage_calls += 1;
            if self.fail_stage_call == Some(self.stage_calls) {
                return Err(DepositIndexError::MissingObject);
            }
            if let Some(existing) = self.objects.get(&id) {
                if existing != bytes {
                    return Err(DepositIndexError::ObjectAuthentication);
                }
                return Ok(false);
            }
            self.objects.insert(id, bytes.to_vec());
            Ok(true)
        }

        fn compare_and_swap_index_head(
            &mut self,
            expected: &DepositIndexHead,
            replacement: &DepositIndexHead,
        ) -> Result<bool, DepositIndexError> {
            if self.heads.get(&expected.namespace()) != Some(expected) {
                return Ok(false);
            }
            self.heads.insert(replacement.namespace(), replacement.clone());
            self.installed_pins = self.reachable_from_heads()?;
            Ok(true)
        }

        fn remove_index_object(
            &mut self,
            id: DepositIndexObjectId,
        ) -> Result<(), DepositIndexError> {
            self.objects.remove(&id);
            Ok(())
        }

        fn index_object_is_pinned(
            &self,
            id: DepositIndexObjectId,
        ) -> Result<bool, DepositIndexError> {
            Ok(self.explicit_pins.contains(&id) || self.installed_pins.contains(&id))
        }
    }

    #[derive(Default)]
    struct MemoryRegistryStore {
        objects: BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    }

    impl CompactRegistryObjectReader for MemoryRegistryStore {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            Ok(self.objects.get(&reference).cloned())
        }
    }

    fn commit_update(store: &mut MemoryStore, update: DepositIndexUpdate) -> DepositIndexHead {
        let staged = update.stage(store).unwrap();
        staged.verify_staged(store).unwrap();
        staged.commit_head(store).unwrap();
        staged.cleanup(store).unwrap();
        let head = staged.update().next_head().clone();
        verify_deposit_index_head(store, &head).unwrap();
        store.assert_no_unreachable_objects();
        head
    }

    fn wallet() -> DepositWalletId {
        DepositWalletId([9; 32])
    }

    fn local_head() -> DepositIndexHead {
        DepositIndexHead::empty_local_safety(wallet(), PartyId(7)).unwrap()
    }

    fn index(value: u32) -> DepositSubaddressIndex {
        DepositSubaddressIndex::new(0, value).unwrap()
    }

    fn registry_target(
        wallet: DepositWalletId,
        committee: Committee,
        fault_bound: u16,
        activation: [u8; 32],
    ) -> VerifiedRegistryHandoffTarget {
        VerifiedRegistryHandoffTarget::for_test(
            committee,
            fault_bound,
            activation,
            [0xd1; 32],
            wallet,
            [0xd2; 32],
            [0xd3; 32],
        )
        .unwrap()
    }

    fn output(value: u8) -> WalletOutputId {
        WalletOutputId { transaction: [value; 32], index_in_transaction: u64::from(value) }
    }

    fn ordered_output(value: u32) -> WalletOutputId {
        let mut transaction = [0_u8; 32];
        transaction[28..].copy_from_slice(&value.to_be_bytes());
        WalletOutputId { transaction, index_in_transaction: u64::from(value) }
    }

    #[test]
    fn rootless_portable_head_is_only_the_exact_nonterminal_genesis() {
        let genesis = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        verify_deposit_index_head(&MemoryStore::with_head(genesis.clone()), &genesis).unwrap();

        let mut truncated = genesis.clone();
        truncated.portable_anchor.as_mut().unwrap().through_sequence = 1;
        truncated.portable_anchor.as_mut().unwrap().ledger_head = [0x41; 32];
        assert!(matches!(truncated.validate_shape(), Err(DepositIndexError::InvalidHead)));

        let mut wrong_genesis = genesis.clone();
        wrong_genesis.portable_anchor.as_mut().unwrap().ledger_head = [0x42; 32];
        assert!(matches!(wrong_genesis.validate_shape(), Err(DepositIndexError::InvalidHead)));

        let mut terminal = genesis;
        terminal.portable_anchor.as_mut().unwrap().through_sequence = u64::MAX;
        terminal.portable_anchor.as_mut().unwrap().ledger_head = [0x43; 32];
        assert!(matches!(terminal.validate_shape(), Err(DepositIndexError::InvalidHead)));
    }

    fn wire_decode<T: DeserializeOwned, S: Serialize>(wire: &S) -> T {
        postcard::from_bytes(&postcard::to_allocvec(wire).unwrap()).unwrap()
    }

    #[derive(Serialize)]
    struct SignedSweepTransactionWire {
        transaction: [u8; 32],
        bytes: Vec<u8>,
    }

    #[derive(Serialize)]
    struct CompletionWire {
        version: u16,
        plan: SweepPlan,
        authorization: TransactionAuthorization,
        attempt: AttemptBinding,
        signed: SignedTransactionBinding,
        signed_transaction: SignedSweepTransaction,
    }

    #[derive(Serialize)]
    struct LateSettlementWire {
        version: u16,
        abandonment_statement: [u8; 32],
        historical_completion: ConsolidationCompletionStatement,
        inclusion: ChainPoint,
        observation_tip: ChainPoint,
        finality_depth: u32,
    }

    #[derive(Serialize)]
    struct LedgerStatementWire {
        version: u16,
        wallet: DepositWalletId,
        sequence: u64,
        previous: [u8; 32],
        issuer_epoch: u64,
        issuer_committee: [u8; 32],
        issuer_activation: [u8; 32],
        payload: LedgerPayload,
    }

    fn fake_completion_statement(
        sequence: u64,
        previous: [u8; 32],
        sweep_sequence: u64,
        attempt_number: u64,
        session: SessionId,
        inputs: Vec<WalletOutputId>,
    ) -> LedgerStatement {
        let total = u64::try_from(inputs.len()).unwrap() + 10_000;
        let mut plan = SweepPlan {
            id: SweepId([1; 32]),
            wallet: wallet(),
            sequence: sweep_sequence,
            epoch: 0,
            destination_binding: [0x4a; 32],
            at_tip: ChainPoint::new(10, [0x4b; 32]).unwrap(),
            inputs,
            total_input_atomic_units: total,
        };
        plan.id = SweepId(sweep_plan_commitment_for_test(&plan));
        let authorization = TransactionAuthorization::new(
            wallet(),
            plan.id,
            OpaqueIntentBinding([0x42; 32]),
            consolidation_input_set_binding(&plan.inputs),
            plan.destination_binding,
            [0x44; 32],
            u32::try_from(plan.inputs.len()).unwrap(),
            total,
            1,
            2,
        )
        .unwrap();
        let attempt = AttemptBinding::new(
            attempt_number,
            0,
            [0x45; 32],
            [0x46; 32],
            [0x47; 32],
            authorization.root_group_key(),
            2,
            vec![PartyId(1), PartyId(2)],
            [0x48; 32],
            session,
            [0x49; 32],
        )
        .unwrap();
        let transaction = [0x4c; 32];
        let signed_transaction =
            wire_decode::<SignedSweepTransaction, _>(&SignedSweepTransactionWire {
                transaction,
                bytes: vec![1],
            });
        let signed = SignedTransactionBinding {
            authorization: authorization.digest(),
            attempt: attempt_number,
            attempt_binding: attempt.digest(),
            session,
            signing_context: attempt.signing_context(),
            opaque_intent: authorization.opaque_intent(),
            transaction,
            exact_bytes: [0x4d; 32],
            exact_bytes_len: 1,
        };
        let completion = wire_decode::<ConsolidationCompletionStatement, _>(&CompletionWire {
            version: 1,
            plan,
            authorization,
            attempt,
            signed,
            signed_transaction,
        });
        wire_decode::<LedgerStatement, _>(&LedgerStatementWire {
            version: 1,
            wallet: wallet(),
            sequence,
            previous,
            issuer_epoch: 0,
            issuer_committee: [0x4e; 32],
            issuer_activation: [0x4f; 32],
            payload: LedgerPayload::ConsolidationCompletion(completion),
        })
    }

    fn single_party_threshold_keys() -> ThresholdKeys<Ed25519> {
        let participant = Participant::new(1).unwrap();
        let secret = FrostScalar::from(42_u64);
        ThresholdKeys::new(
            ThresholdParams::new(1, 1, participant).unwrap(),
            Interpolation::Lagrange,
            Zeroizing::new(secret),
            HashMap::from([(participant, <Ed25519 as Ciphersuite>::generator() * secret)]),
        )
        .unwrap()
    }

    fn one_party_committee() -> (Committee, BTreeMap<PartyId, Identity>) {
        let party = PartyId(1);
        let signing_seed = [0xb0; 32];
        let identity =
            Identity::from_test_secrets(party, 0, &signing_seed, test_x25519_secret(party, 0))
                .unwrap();
        let committee = Committee {
            epoch: 0,
            threshold: 1,
            members: vec![Member {
                id: party,
                signing_key: identity.signing_public_key(),
                encryption_key: identity.encryption_public_key(),
            }],
        }
        .canonicalized()
        .unwrap();
        (committee, BTreeMap::from([(party, identity)]))
    }

    fn legal_transaction_input(
        keys: &ThresholdKeys<Ed25519>,
        input_index: usize,
    ) -> (OutputWithDecoys, u64) {
        let input_index = u64::try_from(input_index).unwrap();
        let amount = 10_000_000_u64 + input_index * 1_000;
        let key_offset = Scalar::from(9_u64 + input_index * 4);
        let output_key =
            Point::from(keys.original_group_key().0 + ED25519_BASEPOINT_POINT * key_offset);
        let commitment =
            Commitment::new(WalletScalar::from(Scalar::from(77_u64 + input_index)), amount);
        let ring = (0_u64..16)
            .map(|position| {
                if position == 5 {
                    [output_key, commitment.commit()]
                } else {
                    let discriminator = input_index * 1_000 + position;
                    [
                        Point::from(
                            ED25519_BASEPOINT_POINT * Scalar::from(200_u64 + discriminator),
                        ),
                        Commitment::new(
                            WalletScalar::from(Scalar::from(300_u64 + discriminator)),
                            1_000 + discriminator,
                        )
                        .commit(),
                    ]
                }
            })
            .collect::<Vec<_>>();
        let decoys = Decoys::new(
            (0_u64..16).map(|position| 1 + input_index * 32 + position).collect(),
            5,
            ring,
        )
        .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&output_key.compress().to_bytes());
        WalletScalar::from(key_offset).write(&mut bytes).unwrap();
        commitment.write(&mut bytes).unwrap();
        decoys.write(&mut bytes).unwrap();
        let mut reader = Cursor::new(bytes.as_slice());
        let input = OutputWithDecoys::read(&mut reader).unwrap();
        assert_eq!(usize::try_from(reader.position()).unwrap(), bytes.len());
        (input, amount)
    }

    fn sweep_plan_commitment_for_test(plan: &SweepPlan) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-plan/v1");
        hasher.update(&plan.wallet.0);
        hasher.update(&plan.sequence.to_le_bytes());
        hasher.update(&plan.epoch.to_le_bytes());
        hasher.update(&plan.destination_binding);
        hasher.update(&plan.at_tip.height.to_le_bytes());
        hasher.update(&plan.at_tip.hash);
        hasher.update(&(plan.inputs.len() as u64).to_le_bytes());
        for input in &plan.inputs {
            hasher.update(&input.transaction);
            hasher.update(&input.index_in_transaction.to_le_bytes());
        }
        hasher.update(&plan.total_input_atomic_units.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    struct LegalCompletionFixture {
        initial: DepositIndexHead,
        registry: CompactEpochRegistry,
        issuer_window: VerifiedIssuerWindow,
        committee: Committee,
        identities: BTreeMap<PartyId, Identity>,
        entry: CertifiedLedgerEntry,
    }

    fn legal_completion_fixture(input_count: usize) -> LegalCompletionFixture {
        assert!(input_count > 0);
        let wallet = wallet();
        let ledger_head = compact_registry_genesis_ledger_head(wallet);
        let initial = DepositIndexHead::empty_portable(wallet, index(1)).unwrap();
        let (committee, identities) = one_party_committee();
        let keys = single_party_threshold_keys();
        let group_key = threshold_group_key(&keys);
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee.clone(),
            0,
            [0xb1; 32],
            [0xd1; 32],
            wallet,
            [0xd2; 32],
            group_key,
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, index(1), initial.digest()).unwrap();
        let registry = pending.proposed_head().registry().clone();
        let registry_store = MemoryRegistryStore {
            objects: pending
                .staged_objects()
                .iter()
                .map(|object| (object.reference(), object.contents().to_vec()))
                .collect(),
        };
        let issuer_window =
            lookup_verified_issuer_window(pending.proposed_head(), 0, &registry_store).unwrap();

        let (transaction_inputs, amounts): (Vec<_>, Vec<_>) =
            (0..input_count).map(|input| legal_transaction_input(&keys, input)).unzip();
        let total_input_atomic_units = amounts.into_iter().sum::<u64>();
        let first_destination = MoneroAddress::new(
            Network::Mainnet,
            AddressType::Legacy,
            Point::from(ED25519_BASEPOINT_POINT * Scalar::from(301_u64)),
            Point::from(ED25519_BASEPOINT_POINT * Scalar::from(302_u64)),
        );
        let second_destination = MoneroAddress::new(
            Network::Mainnet,
            AddressType::Legacy,
            Point::from(ED25519_BASEPOINT_POINT * Scalar::from(401_u64)),
            Point::from(ED25519_BASEPOINT_POINT * Scalar::from(402_u64)),
        );
        let fee_rate = FeeRate::new(1, 1).unwrap();
        let draft = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            Zeroizing::new([0xb2; 32]),
            transaction_inputs.clone(),
            vec![(first_destination.clone(), 100_000), (second_destination.clone(), 200_000)],
            Change::fingerprintable(None),
            vec![],
            fee_rate,
        )
        .unwrap();
        let fee = draft.necessary_fee();
        let second_amount =
            total_input_atomic_units.checked_sub(fee + 100_000).expect("fixture funds its fee");
        let signable = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            Zeroizing::new([0xb2; 32]),
            transaction_inputs,
            vec![(first_destination, 100_000), (second_destination, second_amount)],
            Change::fingerprintable(None),
            vec![],
            fee_rate,
        )
        .unwrap();
        assert_eq!(signable.necessary_fee(), fee);

        let inputs =
            (1..=u32::try_from(input_count).unwrap()).map(ordered_output).collect::<Vec<_>>();
        let mut plan = SweepPlan {
            id: SweepId([1; 32]),
            wallet,
            sequence: 9,
            epoch: 0,
            destination_binding: [0xb3; 32],
            at_tip: ChainPoint::new(100, [0xb4; 32]).unwrap(),
            inputs,
            total_input_atomic_units,
        };
        plan.id = SweepId(sweep_plan_commitment_for_test(&plan));
        assert_ne!(plan.id.0, [0; 32]);
        let session = derive_sweep_signing_session(wallet, plan.id, 1).unwrap();
        let mut rng = ChaCha20Rng::from_seed([0xb5; 32]);
        let (awaiting, _) = FrostlassSigner::start_in_session(
            signable,
            keys,
            &committee,
            PartyId(1),
            [PartyId(1)],
            group_key,
            session,
            &mut rng,
        )
        .unwrap();
        let signing_context = awaiting.context().into_bytes();
        let (finalizer, _) =
            awaiting.bind_transaction_bound([]).unwrap().release_bound_signature_share().unwrap();
        let transaction = finalizer.complete_bound([]).unwrap();
        let transaction_id = transaction.hash();
        let signed_transaction =
            SignedSweepTransaction::from_transaction(&transaction, Some(transaction_id)).unwrap();
        let authorization = TransactionAuthorization::new(
            wallet,
            plan.id,
            OpaqueIntentBinding([0xb6; 32]),
            consolidation_input_set_binding(&plan.inputs),
            plan.destination_binding,
            group_key,
            u32::try_from(plan.inputs.len()).unwrap(),
            total_input_atomic_units,
            fee,
            fee,
        )
        .unwrap();
        let attempt = AttemptBinding::new(
            1,
            0,
            registry.id().digest(),
            committee.digest(),
            registry.active().activation(),
            group_key,
            committee.threshold,
            vec![PartyId(1)],
            [0xb7; 32],
            session,
            signing_context,
        )
        .unwrap();
        let signed = SignedTransactionBinding {
            authorization: authorization.digest(),
            attempt: attempt.attempt(),
            attempt_binding: attempt.digest(),
            session,
            signing_context,
            opaque_intent: authorization.opaque_intent(),
            transaction: transaction_id,
            exact_bytes: consolidation_signed_bytes_binding(signed_transaction.as_bytes()),
            exact_bytes_len: u32::try_from(signed_transaction.as_bytes().len()).unwrap(),
        };
        let statement = LedgerStatement::consolidation_completion(
            &registry,
            1,
            ledger_head,
            plan,
            authorization,
            attempt,
            signed,
            signed_transaction,
        )
        .unwrap();
        let entry = certificate_with_witnesses(&statement, &committee, &identities, &[PartyId(1)]);
        entry.verify_active(&registry, None).unwrap();
        entry.verify(&issuer_window, None).unwrap();
        LegalCompletionFixture { initial, registry, issuer_window, committee, identities, entry }
    }

    #[derive(Serialize)]
    struct PortableKeyImageValueWire {
        sweep: SweepId,
        inputs: Vec<WalletOutputId>,
        key_images: Vec<[u8; 32]>,
        family_digest: [u8; 32],
        unsigned_transaction_digest: [u8; 32],
        signing_context: SigningContext,
        preprocess_set_digest: [u8; 32],
    }

    #[derive(Serialize)]
    struct PortableKeyImageProvenanceWire {
        version: u16,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        origin: PartyId,
    }

    #[derive(Serialize)]
    struct PortableKeyImagePayloadWire<'a> {
        domain: &'a str,
        provenance: &'a PortableKeyImageProvenanceWire,
        value: &'a PortableFamilyKeyImageBinding,
    }

    fn legal_abandonment_statement(
        fixture: &LegalCompletionFixture,
        sequence: u64,
        previous: [u8; 32],
    ) -> LedgerStatement {
        let LedgerPayload::ConsolidationCompletion(completion) = &fixture.entry.statement.payload
        else {
            panic!("fixture must contain a completion");
        };
        let authorization = completion.authorization().clone();
        let attempt = completion.attempt().clone();
        let network = [0xb8; 32];
        let consensus_binding = ConsensusBinding {
            domain: [0xb9; 32],
            application: CONSOLIDATION_INTENT_APPLICATION.to_vec(),
            wallet: wallet().0,
            network,
            registry: fixture.registry.id().digest(),
            activation: fixture.registry.active().activation(),
        };
        let slot = ConsolidationConsensusSlot::new(
            consensus_binding,
            &fixture.committee,
            0,
            0,
            1,
            sequence,
            previous,
        )
        .unwrap();
        let view_plan =
            RoastViewPlan::derive(&slot, &fixture.committee, 0, &authorization).unwrap();
        assert_eq!(view_plan.attempt(), attempt.attempt());
        assert_eq!(view_plan.signers(), attempt.signers());
        assert_eq!(view_plan.signing_session(), attempt.session());
        let binding =
            ConsolidationAttemptWireBinding::new(&authorization, &attempt, view_plan.relay_seed())
                .unwrap();
        let context = slot.consensus_context().unwrap();
        let intent =
            ConsolidationIntent::new(&context, authorization.clone(), attempt.clone()).unwrap();
        let value = intent.to_consensus_value().unwrap();
        let witness = sign_consensus_message(
            &context,
            &fixture.identities[&PartyId(1)],
            ConsensusMessageBody::Precommit(Vote { view: 0, value: value.digest() }),
        )
        .unwrap();
        let commit = CommitCertificate::from_witnesses(&context, 0, value, vec![witness]).unwrap();
        let intent_certificate =
            ConsolidationIntentCertificate::new(context.clone(), commit).unwrap();
        let family = deterministic_roast_family_digest(
            slot.binding(),
            &fixture.committee,
            0,
            &authorization,
            slot.family_anchor(),
        );
        let mut frontier = RoastAttemptPrefixFrontier::empty();
        frontier
            .append_certified_attempt(
                family,
                slot.family_anchor(),
                &slot,
                &context,
                &intent,
                &intent_certificate,
            )
            .unwrap();
        let attempt_prefix =
            RoastAttemptPrefixSeal::from_frontier(family, slot.family_anchor(), &frontier).unwrap();
        let signing_context = wire_decode::<SigningContext, _>(&attempt.signing_context());
        let key_images = completion
            .inputs()
            .iter()
            .enumerate()
            .map(|(position, _)| {
                let mut image = [0xba; 32];
                image[..8].copy_from_slice(&u64::try_from(position + 1).unwrap().to_le_bytes());
                image
            })
            .collect::<Vec<_>>();
        let key_image_value =
            wire_decode::<PortableFamilyKeyImageBinding, _>(&PortableKeyImageValueWire {
                sweep: authorization.sweep_id(),
                inputs: completion.inputs().to_vec(),
                key_images,
                family_digest: family,
                unsigned_transaction_digest: [0xbb; 32],
                signing_context,
                preprocess_set_digest: [0xbc; 32],
            });
        let provenance = PortableKeyImageProvenanceWire {
            version: 1,
            quic_network_id: network,
            attempt: binding.clone(),
            origin: PartyId(1),
        };
        let payload = postcard::to_allocvec(&PortableKeyImagePayloadWire {
            domain: "threshold-monero/deposit-consolidation/key-image-binding-attestation/v1",
            provenance: &provenance,
            value: &key_image_value,
        })
        .unwrap();
        let envelope = fixture.identities[&PartyId(1)]
            .sign_envelope(
                &fixture.committee,
                attempt.session(),
                None,
                0x544d_434b_494d_4731,
                payload,
            )
            .unwrap();
        let key_image_attestation = wire_decode::<PortableKeyImageBindingAttestation, _>(&envelope);
        let key_images = PortableKeyImageBindingCertificate::from_attestations(
            &fixture.committee,
            0,
            network,
            &binding,
            vec![key_image_attestation],
        )
        .unwrap();
        LedgerStatement::consolidation_abandonment(
            &fixture.registry,
            sequence,
            previous,
            family,
            attempt_prefix,
            slot,
            binding,
            key_images,
            authorization,
            attempt,
            completion.plan().sequence,
            completion.inputs().to_vec(),
            vec![completion.inputs()[0]],
            ChainPoint::new(20, [0xbd; 32]).unwrap(),
            ChainPoint::new(30, [0xbe; 32]).unwrap(),
            10,
        )
        .unwrap()
    }

    struct ForcedHashGuard;

    impl ForcedHashGuard {
        fn new() -> Self {
            clear_test_path_hashes();
            Self
        }
    }

    impl Drop for ForcedHashGuard {
        fn drop(&mut self) {
            clear_test_path_hashes();
        }
    }

    fn force_first_used_collisions(count: u32, digest: [u8; 32]) {
        for value in 1..=count {
            force_test_path_hash(&used_alias(wallet(), PartyId(7), index(value)), digest).unwrap();
        }
    }

    fn max_depth_and_leaf_bound(store: &MemoryStore, id: DepositIndexObjectId) -> (u8, usize) {
        let object = decode_object(id, store.objects.get(&id).unwrap()).unwrap();
        let StoredIndexObject::Node(node) = object else {
            panic!("tree root must be a node");
        };
        match node.body {
            HamtNodeBody::Leaf { entries } => (node.depth, entries.len()),
            HamtNodeBody::Branch { children, .. } => children
                .into_iter()
                .map(|child| max_depth_and_leaf_bound(store, child))
                .fold((node.depth, 0), |(max_depth, max_leaf), (depth, leaf)| {
                    (max_depth.max(depth), max_leaf.max(leaf))
                }),
        }
    }

    #[test]
    fn full_keys_survive_primary_hash_collisions_and_roots_are_canonical() {
        let _guard = ForcedHashGuard::new();
        force_first_used_collisions(41, [0x5a; 32]);

        let initial = local_head();
        let mut forward_store = MemoryStore::with_head(initial.clone());
        let mut forward = DepositIndexBuilder::new(&forward_store, initial.clone()).unwrap();
        for value in 1..=41 {
            assert!(forward.mark_first_used(index(value), 10_000 + u64::from(value)).unwrap());
        }
        let forward_update = forward.finish().unwrap().unwrap();
        let forward_head = commit_update(&mut forward_store, forward_update);

        let mut reverse_store = MemoryStore::with_head(initial.clone());
        let mut reverse = DepositIndexBuilder::new(&reverse_store, initial).unwrap();
        for value in (1..=41).rev() {
            assert!(reverse.mark_first_used(index(value), 10_000 + u64::from(value)).unwrap());
        }
        let reverse_update = reverse.finish().unwrap().unwrap();
        let reverse_head = commit_update(&mut reverse_store, reverse_update);

        assert_eq!(forward_head.root(), reverse_head.root());
        assert_eq!(forward_head.digest(), reverse_head.digest());
        let (max_depth, max_leaf) =
            max_depth_and_leaf_bound(&forward_store, forward_head.root().unwrap());
        assert!(max_depth > PRIMARY_HAMT_DEPTH);
        assert!(max_leaf <= MAX_DEPOSIT_INDEX_LEAF_ENTRIES);

        for value in 1..=41 {
            let found = lookup_local_safety(
                &forward_store,
                &forward_head,
                LocalSafetyQuery::FirstUsed(index(value)),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                found.value(),
                &LocalSafetyValue::FirstUsed {
                    index: index(value),
                    first_used_at: 10_000 + u64::from(value),
                }
            );
        }

        force_test_path_hash(&used_alias(wallet(), PartyId(7), index(99)), [0x5a; 32]).unwrap();
        let absence = prove_local_safety(
            &forward_store,
            &forward_head,
            LocalSafetyQuery::FirstUsed(index(99)),
        )
        .unwrap();
        assert!(
            verify_local_safety_proof(
                &forward_head,
                LocalSafetyQuery::FirstUsed(index(99)),
                &absence,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn local_safety_pairs_are_atomic_idempotent_and_conflict_safe() {
        let initial = local_head();
        let mut store = MemoryStore::with_head(initial.clone());
        let request = LedgerRequestId([1; 32]);
        let binding = RequestBinding([2; 32]);
        let output_id = output(3);
        let output_key = [4; 32];
        let root_output = output(9);
        let root_output_key = [10; 32];
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        assert!(builder.reserve_allocation_proposal(request, binding, index(5)).unwrap());
        assert!(builder.mark_first_used(index(5), 50).unwrap());
        assert!(builder.bind_output(output_id, output_key, Some(index(5)), 42).unwrap());
        assert!(builder.bind_output(root_output, root_output_key, None, 43).unwrap());
        let update = builder.finish().unwrap().unwrap();
        let head = commit_update(&mut store, update);
        assert_eq!(head.entry_count(), 7);
        assert_eq!(head.record_count(), 7);

        for query in [
            LocalSafetyQuery::ProposedIndex(index(5)),
            LocalSafetyQuery::ReservedRequest(request),
            LocalSafetyQuery::FirstUsed(index(5)),
            LocalSafetyQuery::Output(output_id),
            LocalSafetyQuery::OneTimeOutputKey(output_key),
            LocalSafetyQuery::Output(root_output),
            LocalSafetyQuery::OneTimeOutputKey(root_output_key),
        ] {
            assert!(lookup_local_safety(&store, &head, query).unwrap().is_some());
        }
        assert!(matches!(
            lookup_local_safety(&store, &head, LocalSafetyQuery::Output(root_output))
                .unwrap()
                .unwrap()
                .value(),
            LocalSafetyValue::OutputBinding { subaddress: None, .. }
        ));

        let mut idempotent = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(!idempotent.reserve_allocation_proposal(request, binding, index(5)).unwrap());
        assert!(!idempotent.mark_first_used(index(5), 51).unwrap());
        assert!(!idempotent.bind_output(output_id, output_key, Some(index(5)), 42).unwrap());
        assert!(!idempotent.bind_output(root_output, root_output_key, None, 43).unwrap());
        assert!(idempotent.finish().unwrap().is_none());

        let mut request_conflict = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            request_conflict.reserve_allocation_proposal(request, binding, index(6)),
            Err(DepositIndexError::AliasConflict)
        ));
        let mut index_conflict = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            index_conflict
                .reserve_allocation_proposal(LedgerRequestId([6; 32]), binding, index(5),),
            Err(DepositIndexError::AliasConflict)
        ));
        let mut output_conflict = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            output_conflict.bind_output(output_id, [7; 32], Some(index(5)), 42),
            Err(DepositIndexError::AliasConflict)
        ));
        let mut key_conflict = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            key_conflict.bind_output(output(8), output_key, Some(index(5)), 42),
            Err(DepositIndexError::AliasConflict)
        ));
        let mut root_classification_conflict =
            DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            root_classification_conflict.bind_output(
                root_output,
                root_output_key,
                Some(index(9)),
                43,
            ),
            Err(DepositIndexError::AliasConflict)
        ));
        let mut root_key_conflict = DepositIndexBuilder::new(&store, head).unwrap();
        assert!(matches!(
            root_key_conflict.bind_output(output(10), root_output_key, None, 43),
            Err(DepositIndexError::AliasConflict)
        ));
    }

    #[test]
    fn local_session_and_sequence_high_waters_are_monotonic() {
        let initial = local_head();
        let mut store = MemoryStore::with_head(initial.clone());
        let consolidation = ConsolidationId([0x31; 32]);
        let sweep = SweepId([0x32; 32]);
        let session_three = SessionId([0x33; 32]);
        let session_one = SessionId([0x34; 32]);
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        assert!(
            builder
                .record_signing_session_tombstone(
                    consolidation,
                    sweep,
                    3,
                    session_three,
                    [0x35; 32],
                )
                .unwrap()
        );
        assert!(
            builder
                .record_signing_session_tombstone(consolidation, sweep, 1, session_one, [0x36; 32],)
                .unwrap()
        );
        assert!(builder.advance_next_sweep_sequence(8).unwrap());
        let update = builder.finish().unwrap().unwrap();
        let head = commit_update(&mut store, update);
        let attempt = lookup_local_safety(&store, &head, LocalSafetyQuery::AttemptHighWater(sweep))
            .unwrap()
            .unwrap();
        assert!(matches!(
            attempt.value(),
            LocalSafetyValue::AttemptHighWater { through_attempt: 3, .. }
        ));
        assert!(
            lookup_local_safety(&store, &head, LocalSafetyQuery::SigningSession(session_one),)
                .unwrap()
                .is_some()
        );
        let mut regression = DepositIndexBuilder::new(&store, head).unwrap();
        assert!(matches!(
            regression.advance_next_sweep_sequence(7),
            Err(DepositIndexError::SweepSequenceRegression)
        ));
    }

    #[test]
    fn current_archive_locator_is_immutable_wallet_bound_and_cross_checked() {
        let initial = local_head();
        let mut store = MemoryStore::with_head(initial.clone());
        let digest = [0x37; 32];
        let certificate = WalletArtifactRef::for_contents(
            WalletId(wallet().0),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            b"exact local certificate witness set",
        )
        .unwrap();
        let locator_for =
            |sequence: u64, statement: [u8; 32], ledger_artifact: WalletArtifactRef| {
                CertifiedEntryLocator {
                    wallet: wallet(),
                    checkpoint_sequence: sequence,
                    checkpoint_decision: [0x35; 32],
                    checkpoint_certificate_digest: [0x36; 32],
                    ledger_sequence: sequence,
                    ledger_statement: statement,
                    event_artifact: WalletArtifactRef::for_contents(
                        WalletId(wallet().0),
                        DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
                        &[0x41, u8::try_from(sequence).unwrap()],
                    )
                    .unwrap(),
                    ledger_artifact,
                    checkpoint_artifact: WalletArtifactRef::for_contents(
                        WalletId(wallet().0),
                        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
                        &[0x42, u8::try_from(sequence).unwrap()],
                    )
                    .unwrap(),
                }
            };
        let locator = locator_for(1, digest, certificate);
        let checkpoint_slot = SignedIndexCheckpointSlot::new(
            1,
            digest,
            [0x31; 32],
            [0x32; 32],
            locator.checkpoint_decision,
            1,
        )
        .unwrap();
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        assert!(builder.record_signed_ledger_slot(1, digest).unwrap());
        assert!(builder.record_signed_index_checkpoint_slot(checkpoint_slot).unwrap());
        assert!(builder.record_certified_entry_locator_fields(locator).unwrap());
        let update = builder.finish().unwrap().unwrap();
        let head = commit_update(&mut store, update);

        let signed = lookup_local_safety(&store, &head, LocalSafetyQuery::SignedLedgerSlot(1))
            .unwrap()
            .unwrap();
        assert_eq!(
            signed.value(),
            &LocalSafetyValue::SignedLedgerSlot(SignedLedgerSlot {
                sequence: 1,
                statement_digest: digest,
            })
        );
        let located =
            lookup_local_safety(&store, &head, LocalSafetyQuery::CertifiedEntryLocator(1))
                .unwrap()
                .unwrap();
        assert_eq!(located.value(), &LocalSafetyValue::CertifiedEntryLocator(locator));
        let located_by_checkpoint =
            lookup_local_safety(&store, &head, LocalSafetyQuery::CertifiedCheckpointLocator(1))
                .unwrap()
                .unwrap();
        assert_eq!(
            located_by_checkpoint.value(),
            &LocalSafetyValue::CertifiedCheckpointLocator(locator)
        );
        assert_eq!(locator.wallet_id(), wallet());
        assert_eq!(locator.ledger_sequence(), 1);
        assert_eq!(locator.ledger_statement(), digest);
        assert_eq!(locator.checkpoint_sequence(), 1);
        assert_eq!(locator.checkpoint_decision(), [0x35; 32]);
        assert_eq!(locator.checkpoint_certificate_digest(), [0x36; 32]);
        assert_eq!(locator.event_artifact(), locator.event_artifact);
        assert_eq!(locator.ledger_artifact(), certificate);
        assert_eq!(locator.checkpoint_artifact(), locator.checkpoint_artifact);

        let mut idempotent = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(!idempotent.record_signed_ledger_slot(1, digest).unwrap());
        assert!(!idempotent.record_signed_index_checkpoint_slot(checkpoint_slot).unwrap());
        assert!(!idempotent.record_certified_entry_locator_fields(locator).unwrap());
        assert!(idempotent.finish().unwrap().is_none());

        let mut double_sign = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            double_sign.record_signed_ledger_slot(1, [0x38; 32]),
            Err(DepositIndexError::LedgerSlotAlreadySigned)
        ));
        let other_certificate = WalletArtifactRef::for_contents(
            WalletId(wallet().0),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            b"different witness subset",
        )
        .unwrap();
        let mut locator_conflict = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(matches!(
            locator_conflict.record_certified_entry_locator_fields(locator_for(
                1,
                digest,
                other_certificate,
            )),
            Err(DepositIndexError::CertifiedEntryLocatorConflict)
        ));
        let oversized = WalletArtifactRef::from_parts(
            WalletId(wallet().0),
            CERTIFIED_LEDGER_ENTRY_ARTIFACT,
            u64::try_from(MAX_CERTIFIED_ENTRY_ARTIFACT_BYTES + 1).unwrap(),
            [0x39; 32],
        )
        .unwrap();
        let mut invalid_locator = DepositIndexBuilder::new(&store, head).unwrap();
        assert!(matches!(
            invalid_locator
                .record_certified_entry_locator_fields(locator_for(2, [0x3a; 32], oversized,)),
            Err(DepositIndexError::InvalidLocalSafetyRecord)
        ));

        let second_initial = local_head();
        let second_store = MemoryStore::with_head(second_initial.clone());
        let mut locator_first = DepositIndexBuilder::new(&second_store, second_initial).unwrap();
        locator_first
            .record_certified_entry_locator_fields(locator_for(2, digest, certificate))
            .unwrap();
        assert!(matches!(
            locator_first.record_signed_ledger_slot(2, [0x3b; 32]),
            Err(DepositIndexError::LedgerSlotAlreadySigned)
        ));
        let conflicting_late_checkpoint =
            SignedIndexCheckpointSlot::new(2, digest, [0x31; 32], [0x32; 32], [0x99; 32], 1)
                .unwrap();
        assert!(matches!(
            locator_first.record_signed_index_checkpoint_slot(conflicting_late_checkpoint),
            Err(DepositIndexError::IndexCheckpointSlotAlreadySigned)
        ));

        let third_initial = local_head();
        let third_store = MemoryStore::with_head(third_initial.clone());
        let conflicting_checkpoint_slot =
            SignedIndexCheckpointSlot::new(1, digest, [0x31; 32], [0x32; 32], [0x99; 32], 1)
                .unwrap();
        let mut checkpoint_conflict =
            DepositIndexBuilder::new(&third_store, third_initial).unwrap();
        checkpoint_conflict
            .record_signed_index_checkpoint_slot(conflicting_checkpoint_slot)
            .unwrap();
        assert!(matches!(
            checkpoint_conflict.record_certified_entry_locator_fields(locator),
            Err(DepositIndexError::IndexCheckpointSlotAlreadySigned)
        ));

        let fourth_initial = local_head();
        let fourth_store = MemoryStore::with_head(fourth_initial.clone());
        let mut duplicate_checkpoint =
            DepositIndexBuilder::new(&fourth_store, fourth_initial).unwrap();
        let mut first_ledger_checkpoint_five = locator;
        first_ledger_checkpoint_five.checkpoint_sequence = 5;
        duplicate_checkpoint
            .record_certified_entry_locator_fields(first_ledger_checkpoint_five)
            .unwrap();
        let mut second_ledger_same_checkpoint = locator_for(2, [0x44; 32], other_certificate);
        second_ledger_same_checkpoint.checkpoint_sequence = 5;
        assert!(matches!(
            duplicate_checkpoint
                .record_certified_entry_locator_fields(second_ledger_same_checkpoint),
            Err(DepositIndexError::CertifiedEntryLocatorConflict)
        ));

        let fifth_initial = local_head();
        let fifth_store = MemoryStore::with_head(fifth_initial.clone());
        let mut foreign = locator;
        foreign.wallet = DepositWalletId([0xfe; 32]);
        let mut foreign_builder = DepositIndexBuilder::new(&fifth_store, fifth_initial).unwrap();
        assert!(matches!(
            foreign_builder.record_certified_entry_locator_fields(foreign),
            Err(DepositIndexError::InvalidLocalSafetyRecord)
        ));
    }

    fn identities(epoch: u64) -> (Committee, BTreeMap<PartyId, Identity>) {
        let identities = (1_u16..=4)
            .map(|value| {
                let party = PartyId(value);
                let signing_seed = [u8::try_from(value).unwrap(); 32];
                (
                    party,
                    Identity::from_test_secrets(
                        party,
                        epoch,
                        &signing_seed,
                        test_x25519_secret(party, epoch),
                    )
                    .unwrap(),
                )
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

    fn certificate_with_witnesses(
        statement: &LedgerStatement,
        committee: &Committee,
        identities: &BTreeMap<PartyId, Identity>,
        witnesses: &[PartyId],
    ) -> CertifiedLedgerEntry {
        let payload = statement.attestation_payload().unwrap();
        let mut attestations = witnesses
            .iter()
            .map(|party| {
                identities[party]
                    .sign_envelope(
                        committee,
                        statement.slot_session(),
                        None,
                        statement.sequence,
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        attestations.sort_by_key(|envelope| envelope.from);
        CertifiedLedgerEntry { statement: statement.clone(), attestations }
    }

    fn portable_fixture() -> (
        DepositIndexHead,
        CompactEpochRegistry,
        VerifiedIssuerWindow,
        CertifiedLedgerEntry,
        CertifiedLedgerEntry,
        PortableAllocationQuery,
        PortableAllocationQuery,
        PortableAllocationQuery,
        PortableAllocationQuery,
    ) {
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let wallet = deriver.wallet_id();
        let ledger_head = compact_registry_genesis_ledger_head(wallet);
        let initial = DepositIndexHead::empty_portable(wallet, index(1)).unwrap();
        let (committee, identities) = identities(0);
        let target = registry_target(wallet, committee.clone(), 1, [8; 32]);
        let pending =
            prepare_compact_registry_genesis(&target, index(1), initial.digest()).unwrap();
        let registry = pending.proposed_head().registry().clone();
        let registry_store = MemoryRegistryStore {
            objects: pending
                .staged_objects()
                .iter()
                .map(|object| (object.reference(), object.contents().to_vec()))
                .collect(),
        };
        let issuer_window =
            lookup_verified_issuer_window(pending.proposed_head(), 0, &registry_store).unwrap();
        let request = LedgerRequestId([10; 32]);
        let address = deriver.derive(index(1));
        let spend_key = subaddress_spend_key(&address).unwrap();
        let statement = LedgerStatement::allocation(
            &registry,
            1,
            ledger_head,
            request,
            RequestBinding([11; 32]),
            address.clone(),
            ChainPoint::new(0, [0x93; 32]).unwrap(),
            1_000,
        )
        .unwrap();
        let first = certificate_with_witnesses(
            &statement,
            &committee,
            &identities,
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        let second = certificate_with_witnesses(
            &statement,
            &committee,
            &identities,
            &[PartyId(2), PartyId(3), PartyId(4)],
        );
        first.verify(&issuer_window, None).unwrap();
        second.verify(&issuer_window, None).unwrap();
        (
            initial,
            registry,
            issuer_window,
            first,
            second,
            PortableAllocationQuery::Request(request),
            PortableAllocationQuery::Address(address),
            PortableAllocationQuery::Index(index(1)),
            PortableAllocationQuery::SubaddressSpendKey(spend_key),
        )
    }

    #[test]
    fn portable_root_excludes_certificate_witness_choices_and_all_aliases_match() {
        let (
            initial,
            _registry,
            issuer_window,
            first,
            second,
            by_request,
            by_address,
            by_index,
            by_spend_key,
        ) = portable_fixture();
        let mut first_store = MemoryStore::with_head(initial.clone());
        let mut first_builder = DepositIndexBuilder::new(&first_store, initial.clone()).unwrap();
        assert!(first_builder.apply_verified_entry(&first, &issuer_window, None).unwrap());
        let first_update = first_builder.finish().unwrap().unwrap();
        let authorization =
            first_update.verify_ledger_transition(&first_store, &first.statement).unwrap();
        assert_eq!(authorization.expected_head(), &initial);
        assert_eq!(authorization.statement_sequence(), first.statement.sequence);
        assert_eq!(authorization.statement_digest(), first.statement.digest());
        assert_eq!(authorization.resulting_head_digest(), first_update.next_head().digest());
        let mut wrong_statement = first.statement.clone();
        wrong_statement.previous = [0x91; 32];
        assert!(matches!(
            first_update.verify_ledger_transition(&first_store, &wrong_statement),
            Err(DepositIndexError::InvalidVerifiedTransition)
        ));
        let first_head = commit_update(&mut first_store, first_update);

        let mut second_store = MemoryStore::with_head(initial.clone());
        let mut second_builder = DepositIndexBuilder::new(&second_store, initial).unwrap();
        assert!(second_builder.apply_verified_entry(&second, &issuer_window, None).unwrap());
        let second_update = second_builder.finish().unwrap().unwrap();
        let second_head = commit_update(&mut second_store, second_update);

        assert_ne!(first.attestations, second.attestations);
        assert_eq!(first_head.root(), second_head.root());
        assert_eq!(first_head.digest(), second_head.digest());
        assert_eq!(first_head.portable_anchor().unwrap().next_index(), index(2));
        let request_record =
            lookup_portable_allocation(&first_store, &first_head, &by_request).unwrap().unwrap();
        let address_record =
            lookup_portable_allocation(&first_store, &first_head, &by_address).unwrap().unwrap();
        let index_record =
            lookup_portable_allocation(&first_store, &first_head, &by_index).unwrap().unwrap();
        let spend_key_record =
            lookup_portable_allocation(&first_store, &first_head, &by_spend_key).unwrap().unwrap();
        assert_eq!(request_record, address_record);
        assert_eq!(request_record, index_record);
        assert_eq!(request_record, spend_key_record);
        assert_eq!(
            lookup_portable_state(&first_store, &first_head, PortableStateQuery::Sequence(1))
                .unwrap(),
            Some(PortableStateRecord::Statement(first.statement.clone()))
        );
        assert_eq!(first_head.entry_count(), 5);
        assert_eq!(first_head.record_count(), 1);
        let root = first_head.root().unwrap();
        assert_eq!(root.wallet_id(), first.statement.wallet);
        assert_eq!(root.storage_reference().kind(), DEPOSIT_INDEX_ARTIFACT_KIND);
        root.storage_reference().verify_contents(first_store.objects.get(&root).unwrap()).unwrap();

        let mut proof = prove_portable_allocation(&first_store, &first_head, &by_request).unwrap();
        proof.value.as_mut().unwrap().bytes[0] ^= 1;
        assert!(matches!(
            verify_portable_allocation_proof(&first_head, &by_request, &proof),
            Err(DepositIndexError::ObjectAuthentication)
                | Err(DepositIndexError::Serialization)
                | Err(DepositIndexError::NonCanonicalObject)
        ));
    }

    #[test]
    fn preflight_rejects_exhausted_local_revision_before_issuing_authorization() {
        let (mut initial, _, _, first, _, _, _, _, _) = portable_fixture();
        initial.revision = u64::MAX;
        let store = MemoryStore::with_head(initial.clone());
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();

        assert!(matches!(
            builder.preflight_ledger_statement(&first.statement),
            Err(DepositIndexError::InvalidHead)
        ));
    }

    #[test]
    fn portable_anchor_enforces_allocation_progression_and_handoff_equality() {
        let (initial, registry, issuer_window, first, _, _, _, _, _) = portable_fixture();
        let wrong_initial =
            DepositIndexHead::empty_portable(first.statement.wallet, index(2)).unwrap();
        let wrong_store = MemoryStore::with_head(wrong_initial.clone());
        let mut wrong_allocation = DepositIndexBuilder::new(&wrong_store, wrong_initial).unwrap();
        assert!(matches!(
            wrong_allocation.apply_verified_entry(&first, &issuer_window, None),
            Err(DepositIndexError::AllocationIndexMismatch)
        ));

        let mut store = MemoryStore::with_head(initial.clone());
        let mut allocation = DepositIndexBuilder::new(&store, initial).unwrap();
        allocation.apply_verified_entry(&first, &issuer_window, None).unwrap();
        let allocation_update = allocation.finish().unwrap().unwrap();
        let allocation_head = commit_update(&mut store, allocation_update);
        assert_eq!(allocation_head.portable_anchor().unwrap().next_index(), index(2));

        let (target, _) = identities(1);
        let target = registry_target(first.statement.wallet, target, 1, [0x81; 32]);
        let previous = allocation_head.portable_anchor().unwrap().ledger_head();
        let wrong_handoff = LedgerStatement::handoff(
            &registry,
            2,
            previous,
            allocation_head.digest(),
            &target,
            index(3),
        )
        .unwrap();
        let mut wrong = DepositIndexBuilder::new(&store, allocation_head.clone()).unwrap();
        assert!(matches!(
            wrong.apply_portable_statement(wrong_handoff),
            Err(DepositIndexError::AllocationIndexMismatch)
        ));

        let handoff = LedgerStatement::handoff(
            &registry,
            2,
            previous,
            allocation_head.digest(),
            &target,
            index(2),
        )
        .unwrap();
        let (source_committee, source_identities) = identities(0);
        assert_eq!(&source_committee, registry.active().committee());
        let handoff_entry = certificate_with_witnesses(
            &handoff,
            &source_committee,
            &source_identities,
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        handoff_entry.verify_active(&registry, None).unwrap();
        let mut correct = DepositIndexBuilder::new(&store, allocation_head).unwrap();
        correct.apply_verified_active_entry(&handoff_entry, &registry, None).unwrap();
        let handoff_update = correct.finish().unwrap().unwrap();
        let handoff_head = commit_update(&mut store, handoff_update);
        assert_eq!(handoff_head.portable_anchor().unwrap().next_index(), index(2));

        let exhausted = DepositSubaddressIndex::new(0, u32::MAX).unwrap();
        assert!(matches!(
            increment_subaddress_index(exhausted),
            Err(DepositIndexError::SubaddressIndexExhausted)
        ));
    }

    #[test]
    fn allocation_records_reject_zero_common_statement_commitments() {
        let (_, _, _, first, _, _, _, _, _) = portable_fixture();
        for corrupt in 0_u8..3 {
            let mut statement = first.statement.clone();
            match corrupt {
                0 => statement.previous = [0; 32],
                1 => statement.issuer_committee = [0; 32],
                2 => statement.issuer_activation = [0; 32],
                _ => unreachable!(),
            }
            assert!(matches!(
                PortableAllocationRecord::from_statement(statement),
                Err(DepositIndexError::InvalidPortableRecord)
            ));
        }
    }

    #[test]
    fn staged_updates_recover_before_and_after_cas_and_collect_garbage() {
        let initial = local_head();
        let mut store = MemoryStore::with_head(initial.clone());
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        builder
            .reserve_allocation_proposal(
                LedgerRequestId([21; 32]),
                RequestBinding([22; 32]),
                index(1),
            )
            .unwrap();
        builder.bind_output(output(23), [24; 32], Some(index(1)), 25).unwrap();
        let update = builder.finish().unwrap().unwrap();
        let update = DepositIndexUpdate::from_bytes(&update.to_bytes().unwrap()).unwrap();
        let staged = update.stage(&mut store).unwrap();
        let staged = StagedDepositIndexUpdate::from_bytes(&staged.to_bytes().unwrap()).unwrap();

        assert_eq!(staged.recover(&mut store).unwrap(), DepositIndexRecovery::Committed);
        let installed = staged.update().next_head().clone();
        verify_deposit_index_head(&store, &installed).unwrap();
        store.assert_no_unreachable_objects();

        // A restart after CAS and cleanup is idempotent even though the old root is gone.
        assert_eq!(staged.recover(&mut store).unwrap(), DepositIndexRecovery::Committed);
        store.assert_no_unreachable_objects();
    }

    #[test]
    fn committed_recovery_reads_only_the_bounded_delta_after_a_long_history() {
        let initial = local_head();
        let mut store = MemoryStore::with_head(initial.clone());
        let mut history = DepositIndexBuilder::new(&store, initial).unwrap();
        // More than the 64-entry hot replay window used by the surrounding state machines.
        for value in 1..=96 {
            history.mark_first_used(index(value), u64::from(value)).unwrap();
        }
        let history_update = history.finish().unwrap().unwrap();
        let historical_head = commit_update(&mut store, history_update);

        let mut delta = DepositIndexBuilder::new(&store, historical_head).unwrap();
        delta.mark_first_used(index(97), 97).unwrap();
        let staged = delta.finish().unwrap().unwrap().stage(&mut store).unwrap();
        staged.commit_head(&mut store).unwrap();

        store.load_calls.set(0);
        assert_eq!(staged.recover(&mut store).unwrap(), DepositIndexRecovery::Committed);
        let reads = store.load_calls.get();
        assert!(reads < 64, "committed recovery read {reads} objects for a one-record delta");
        store.assert_no_unreachable_objects();
    }

    #[test]
    fn partial_stage_is_replayable_and_losing_cas_cleans_only_unpinned_candidates() {
        let initial = local_head();
        let mut partial_store = MemoryStore::with_head(initial.clone());
        let mut builder = DepositIndexBuilder::new(&partial_store, initial.clone()).unwrap();
        builder.mark_first_used(index(1), 1).unwrap();
        let update = builder.finish().unwrap().unwrap();
        partial_store.fail_stage_call = Some(2);
        assert!(matches!(
            update.clone().stage(&mut partial_store),
            Err(DepositIndexError::MissingObject)
        ));
        partial_store.fail_stage_call = None;
        let staged = update.stage(&mut partial_store).unwrap();
        assert_eq!(staged.recover(&mut partial_store).unwrap(), DepositIndexRecovery::Committed);
        partial_store.assert_no_unreachable_objects();

        let mut race_store = MemoryStore::with_head(initial.clone());
        let mut loser_builder = DepositIndexBuilder::new(&race_store, initial.clone()).unwrap();
        loser_builder.mark_first_used(index(2), 2).unwrap();
        let loser = loser_builder.finish().unwrap().unwrap().stage(&mut race_store).unwrap();
        let loser_objects = loser.staged_objects.clone();

        let mut winner_builder = DepositIndexBuilder::new(&race_store, initial).unwrap();
        winner_builder.mark_first_used(index(3), 3).unwrap();
        let winner = winner_builder.finish().unwrap().unwrap().stage(&mut race_store).unwrap();
        winner.commit_head(&mut race_store).unwrap();
        winner.cleanup(&mut race_store).unwrap();
        assert_eq!(loser.recover(&mut race_store).unwrap(), DepositIndexRecovery::Superseded);
        let pinned = race_store.reachable_from_heads().unwrap();
        assert!(
            loser_objects
                .iter()
                .all(|id| pinned.contains(id) || !race_store.objects.contains_key(id))
        );
        race_store.assert_no_unreachable_objects();
    }

    #[test]
    fn large_canonical_terminal_certificate_commits_through_verified_path() {
        const INPUTS: usize = 32;
        let fixture = legal_completion_fixture(INPUTS);
        fixture.entry.verify(&fixture.issuer_window, None).unwrap();
        let LedgerPayload::ConsolidationCompletion(completion) = &fixture.entry.statement.payload
        else {
            panic!("fixture must contain a completion");
        };
        assert_eq!(completion.plan().id.0, sweep_plan_commitment_for_test(completion.plan()));
        let transaction = completion.signed_transaction().transaction().unwrap();
        let monero_oxide::transaction::Transaction::V2 { prefix, proofs: Some(proofs) } =
            transaction
        else {
            panic!("fixture must contain a complete RingCT transaction");
        };
        assert_eq!(proofs.rct_type(), RctType::ClsagBulletproofPlus);
        assert_eq!(prefix.inputs.len(), INPUTS);
        assert_eq!(prefix.outputs.len(), 2);

        let mut store = MemoryStore::with_head(fixture.initial.clone());
        let preflight = {
            let mut preflight_builder =
                DepositIndexBuilder::new(&store, fixture.initial.clone()).unwrap();
            preflight_builder.preflight_ledger_statement(&fixture.entry.statement).unwrap()
        };
        assert_eq!(preflight.expected_head(), &fixture.initial);
        assert_eq!(preflight.statement_digest(), fixture.entry.statement.digest());
        let mut builder = DepositIndexBuilder::new(&store, fixture.initial.clone()).unwrap();
        assert!(
            builder.apply_verified_active_entry(&fixture.entry, &fixture.registry, None).unwrap()
        );
        let candidate = builder.candidate_portable_terminal(completion.id()).unwrap().unwrap();
        assert_eq!(candidate.inputs().len(), INPUTS);
        assert!(matches!(
            candidate.status(),
            PortableConsolidationStatus::Completed { transaction, .. }
                if *transaction == completion.transaction_id()
        ));
        let update = builder.finish().unwrap().unwrap();
        let retained_update = update.to_bytes().unwrap();
        drop(preflight);
        let update = DepositIndexUpdate::from_bytes(&retained_update).unwrap();
        let regenerated_preflight = {
            let mut builder =
                DepositIndexBuilder::new(&store, update.expected_head().clone()).unwrap();
            builder.preflight_ledger_statement(&fixture.entry.statement).unwrap()
        };
        assert_eq!(regenerated_preflight.candidate_head(), update.next_head());
        let authorization = update
            .verify_ledger_transition_for_preflight(
                &store,
                &fixture.entry.statement,
                &regenerated_preflight,
            )
            .unwrap();
        assert_eq!(authorization.expected_head(), &fixture.initial);
        assert_eq!(authorization.resulting_head(), update.next_head());
        assert!(update.touched_key_count() >= INPUTS + 5);
        assert!(update.staged_object_count() <= MAX_DEPOSIT_INDEX_UPDATE_OBJECTS);
        assert!(update.to_bytes().unwrap().len() <= MAX_DEPOSIT_INDEX_UPDATE_BYTES);
        let head = commit_update(&mut store, update);
        assert_eq!(
            lookup_portable_state(
                &store,
                &head,
                PortableStateQuery::Consolidation(completion.id()),
            )
            .unwrap(),
            Some(PortableStateRecord::Terminal(candidate))
        );
    }

    #[test]
    fn maximum_terminal_batch_fits_atomic_update_bounds() {
        let previous = compact_registry_genesis_ledger_head(wallet());
        let initial = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        let store = MemoryStore::with_head(initial.clone());
        let inputs =
            (1..=MAX_DEPOSIT_INDEX_TERMINAL_INPUTS as u32).map(ordered_output).collect::<Vec<_>>();
        let statement = fake_completion_statement(1, previous, 7, 1, SessionId([0x51; 32]), inputs);
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        assert!(builder.apply_portable_statement(statement).unwrap());
        let update = builder.finish().unwrap().unwrap();
        assert_eq!(update.mutation_count(), 1);
        assert!(update.touched_key_count() >= MAX_DEPOSIT_INDEX_TERMINAL_INPUTS + 5);
        assert!(update.touched_key_count() <= MAX_DEPOSIT_INDEX_TOUCHED_KEYS);
        assert!(update.staged_object_count() <= MAX_DEPOSIT_INDEX_UPDATE_OBJECTS);
        assert!(update.to_bytes().unwrap().len() <= MAX_DEPOSIT_INDEX_UPDATE_BYTES);
        update.verify_semantic_transition(&store).unwrap();
    }

    #[test]
    fn late_settlement_retains_abandonment_claims_sessions_and_high_water() {
        let fixture = legal_completion_fixture(2);
        let LedgerPayload::ConsolidationCompletion(completion) = &fixture.entry.statement.payload
        else {
            panic!("fixture must contain completion");
        };
        // Materialize the complete prefix instead of fabricating a rootless head at sequence four.
        // The portable head's authenticated root must cover every ledger decision from genesis.
        let genesis = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        let mut store = MemoryStore::with_head(genesis.clone());
        let mut initial = genesis;
        let mut initial_ledger_head = compact_registry_genesis_ledger_head(wallet());
        for sequence in 1_u64..=4 {
            let prefix_statement = fake_completion_statement(
                sequence,
                initial_ledger_head,
                sequence - 1,
                1,
                SessionId([u8::try_from(0x60 + sequence).unwrap(); 32]),
                vec![ordered_output(u32::try_from(sequence + 100).unwrap())],
            );
            let mut prefix = DepositIndexBuilder::new(&store, initial).unwrap();
            assert!(prefix.apply_portable_statement(prefix_statement.clone()).unwrap());
            let prefix_update = prefix.finish().unwrap().unwrap();
            initial = commit_update(&mut store, prefix_update);
            initial_ledger_head = prefix_statement.digest();
        }
        let abandonment = legal_abandonment_statement(&fixture, 5, initial_ledger_head);
        let abandonment_digest = abandonment.digest();
        let settlement =
            wire_decode::<LateConsolidationSettlementStatement, _>(&LateSettlementWire {
                version: 1,
                abandonment_statement: abandonment_digest,
                historical_completion: completion.clone(),
                inclusion: ChainPoint::new(20, [0x68; 32]).unwrap(),
                observation_tip: ChainPoint::new(30, [0x69; 32]).unwrap(),
                finality_depth: 10,
            });
        let late_statement = wire_decode::<LedgerStatement, _>(&LedgerStatementWire {
            version: 1,
            wallet: wallet(),
            sequence: 6,
            previous: abandonment_digest,
            issuer_epoch: 1,
            issuer_committee: [0x6b; 32],
            issuer_activation: [0x6c; 32],
            payload: LedgerPayload::LateConsolidationSettlement(settlement),
        });

        let mut abandon_builder = DepositIndexBuilder::new(&store, initial.clone()).unwrap();
        assert!(abandon_builder.apply_portable_statement(abandonment.clone()).unwrap());
        let abandoned =
            abandon_builder.candidate_portable_terminal(completion.id()).unwrap().unwrap();
        assert!(matches!(
            abandoned.status(),
            PortableConsolidationStatus::Abandoned { evidence }
                if evidence.statement_sequence() == 5
                    && evidence.statement_digest() == abandonment_digest
        ));
        let abandonment_update = abandon_builder.finish().unwrap().unwrap();
        let abandonment_authorization =
            abandonment_update.verify_ledger_transition(&store, &abandonment).unwrap();
        assert_eq!(abandonment_authorization.expected_head(), &initial);
        let abandonment_head = commit_update(&mut store, abandonment_update);

        let mut settlement_builder =
            DepositIndexBuilder::new(&store, abandonment_head.clone()).unwrap();
        assert!(
            settlement_builder
                .candidate_portable_terminal(completion.id())
                .unwrap()
                .is_some_and(|record| record == abandoned)
        );
        assert!(settlement_builder.apply_portable_statement(late_statement.clone()).unwrap());
        let terminal =
            settlement_builder.candidate_portable_terminal(completion.id()).unwrap().unwrap();
        assert_eq!(terminal.attempt_high_water(), abandoned.attempt_high_water());
        assert!(matches!(
            terminal.status(),
            PortableConsolidationStatus::LateSettled { abandonment, .. }
                if abandonment.statement_digest() == abandonment_digest
        ));
        let settlement_update = settlement_builder.finish().unwrap().unwrap();
        let settlement_authorization =
            settlement_update.verify_ledger_transition(&store, &late_statement).unwrap();
        assert_eq!(settlement_authorization.expected_head_digest(), abandonment_head.digest());
        let settled_head = commit_update(&mut store, settlement_update);
        assert_eq!(settled_head.portable_anchor().unwrap().through_sequence(), 6);
        assert_eq!(settled_head.portable_anchor().unwrap().ledger_head(), late_statement.digest());
        assert_eq!(
            lookup_portable_state(&store, &settled_head, PortableStateQuery::Sequence(5)).unwrap(),
            Some(PortableStateRecord::Statement(abandonment.clone()))
        );
        assert_eq!(
            lookup_portable_state(&store, &settled_head, PortableStateQuery::Sequence(6)).unwrap(),
            Some(PortableStateRecord::Statement(late_statement))
        );
        assert_eq!(
            lookup_portable_state(
                &store,
                &settled_head,
                PortableStateQuery::Consolidation(completion.id()),
            )
            .unwrap(),
            Some(PortableStateRecord::Terminal(terminal.clone()))
        );
        for output in abandoned.inputs() {
            let Some(PortableStateRecord::OutputClaim(found)) = lookup_portable_state(
                &store,
                &settled_head,
                PortableStateQuery::ClaimedOutput(*output),
            )
            .unwrap() else {
                panic!("original output claim must remain");
            };
            assert_eq!(found.statement_sequence(), 5);
            assert_eq!(found.statement_digest(), abandonment_digest);
            assert_eq!(found.consolidation_id(), completion.id());
            assert_eq!(found.sweep_id(), completion.authorization().sweep_id());
        }
        let session = completion.attempt().session();
        let Some(PortableStateRecord::SigningSession(tombstone)) = lookup_portable_state(
            &store,
            &settled_head,
            PortableStateQuery::SigningSession(session),
        )
        .unwrap() else {
            panic!("abandonment signing session must remain tombstoned");
        };
        assert_eq!(tombstone.statement_sequence(), 5);
        assert_eq!(tombstone.statement_digest(), abandonment_digest);
        let Some(PortableStateRecord::SweepHighWater(high_water)) =
            lookup_portable_state(&store, &settled_head, PortableStateQuery::NextSweepSequence)
                .unwrap()
        else {
            panic!("sweep high-water must remain");
        };
        assert_eq!(high_water.next_sweep_sequence(), completion.plan().sequence + 1);
    }

    #[test]
    fn exact_duplicate_terminal_replay_checks_every_derived_link() {
        let previous = compact_registry_genesis_ledger_head(wallet());
        let initial = DepositIndexHead::empty_portable(wallet(), index(1)).unwrap();
        let mut store = MemoryStore::with_head(initial.clone());
        let input = ordered_output(1);
        let statement =
            fake_completion_statement(1, previous, 0, 1, SessionId([0x71; 32]), vec![input]);
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        builder.apply_portable_statement(statement.clone()).unwrap();
        let update = builder.finish().unwrap().unwrap();
        let head = commit_update(&mut store, update);

        let mut duplicate = DepositIndexBuilder::new(&store, head.clone()).unwrap();
        assert!(!duplicate.apply_portable_statement(statement.clone()).unwrap());
        assert!(duplicate.finish().unwrap().is_none());

        let claim_proof =
            prove_portable_state(&store, &head, PortableStateQuery::ClaimedOutput(input)).unwrap();
        let missing_claim = claim_proof.value.unwrap().id;
        store.objects.remove(&missing_claim);
        let mut corrupt = DepositIndexBuilder::new(&store, head).unwrap();
        assert!(matches!(
            corrupt.apply_portable_statement(statement),
            Err(DepositIndexError::MissingObject)
        ));
    }

    #[test]
    fn maximum_output_binding_slice_fits_atomic_update_bounds() {
        let _guard = ForcedHashGuard::new();
        let initial = local_head();
        let store = MemoryStore::with_head(initial.clone());
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        for value in 1..=u32::try_from(MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS).unwrap() {
            let mut output_key = [0_u8; 32];
            output_key[28..].copy_from_slice(&value.to_be_bytes());
            force_test_path_hash(
                &output_alias(wallet(), PartyId(7), ordered_output(value)),
                [0x7a; 32],
            )
            .unwrap();
            force_test_path_hash(
                &one_time_output_key_alias(wallet(), PartyId(7), output_key),
                [0x7a; 32],
            )
            .unwrap();
            assert!(
                builder
                    .bind_output(
                        ordered_output(value),
                        output_key,
                        Some(index(value)),
                        u64::from(value),
                    )
                    .unwrap()
            );
        }
        let update = builder.finish().unwrap().unwrap();
        assert_eq!(update.mutation_count(), MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS);
        assert_eq!(update.touched_key_count(), 2 * MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS);
        assert!(update.staged_object_count() <= MAX_DEPOSIT_INDEX_UPDATE_OBJECTS);
        assert!(update.to_bytes().unwrap().len() <= MAX_DEPOSIT_INDEX_UPDATE_BYTES);
        update.verify_semantic_transition(&store).unwrap();
    }

    #[test]
    fn mutation_and_proof_bounds_fail_closed() {
        assert!(MAX_DEPOSIT_INDEX_TOUCHED_KEYS >= MAX_DEPOSIT_INDEX_TERMINAL_INPUTS + 5);
        let initial = local_head();
        let store = MemoryStore::with_head(initial.clone());
        let mut builder = DepositIndexBuilder::new(&store, initial).unwrap();
        for value in 1..=u32::try_from(MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS).unwrap() {
            assert!(builder.mark_first_used(index(value), u64::from(value)).unwrap());
        }
        assert!(matches!(
            builder.mark_first_used(
                index(u32::try_from(MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS).unwrap() + 1),
                u64::try_from(MAX_DEPOSIT_INDEX_UPDATE_MUTATIONS).unwrap() + 1,
            ),
            Err(DepositIndexError::TooManyMutations)
        ));
        let mut oversized_update = builder.finish().unwrap().unwrap();
        oversized_update.touched.clear();
        for value in 1..=u32::try_from(MAX_DEPOSIT_INDEX_TOUCHED_KEYS + 1).unwrap() {
            oversized_update.touched.insert(used_alias(wallet(), PartyId(7), index(value)));
        }
        assert!(matches!(oversized_update.to_bytes(), Err(DepositIndexError::InvalidHead)));

        let empty = local_head();
        let mut oversized = DepositIndexProof {
            version: INDEX_PROOF_VERSION,
            namespace: empty.namespace(),
            key: used_alias(wallet(), PartyId(7), index(1)),
            path: Vec::new(),
            value: None,
        };
        let dummy = StoredIndexObject::LocalSafety(LocalDepositSafetyRecord {
            version: INDEX_OBJECT_VERSION,
            wallet: wallet(),
            party: PartyId(7),
            value: LocalSafetyValue::FirstUsed { index: index(1), first_used_at: 1 },
        });
        let (id, bytes) = encode_object(&dummy).unwrap();
        oversized.path = vec![ProofObject { id, bytes }; MAX_DEPOSIT_INDEX_PROOF_OBJECTS + 1];
        assert!(matches!(oversized.to_bytes(), Err(DepositIndexError::InvalidProof)));
    }
}
