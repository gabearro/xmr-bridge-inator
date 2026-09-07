//! Fixed-depth authenticated set of every receiver key reserved or certified by the network.
//!
//! The consensus commitment and wire proof use a 256-level sparse Merkle tree. The production
//! prover stores the same tree as a compressed Patricia trie in redb: unary paths are implicit,
//! only branching nodes and leaves are durable, and a read transaction expands a proof back to
//! exactly 256 sibling hashes. A live update has an authenticated active head and at most one
//! authenticated staged successor. Promotion atomically replaces the head and removes path nodes
//! which the successor no longer references, so live durable state is `2 * leaf_count - 1` nodes.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::OpenOptions,
    path::Path,
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(test)]
use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::committee::{MAX_COMMITTEE_MEMBERS, PartyId};

const ACCUMULATOR_VERSION: u16 = 2;
const BATCH_PROOF_VERSION: u16 = 1;
const PATRICIA_NODE_VERSION: u16 = 1;
const DURABLE_HEAD_VERSION: u16 = 1;
const STAGED_HEAD_VERSION: u16 = 1;
const TREE_DEPTH: usize = 256;
const PATH_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/path/v1";
const EMPTY_LEAF_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/empty-leaf/v1";
const LEAF_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/leaf/v1";
const NODE_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/node/v1";
const COMMITMENT_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/commitment/v2";
const STORAGE_NODE_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/patricia-node/v1";
const HEAD_KEY_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/head-key/v1";
const HEAD_MAC_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/head-mac/v1";
const STAGE_BINDING_DOMAIN: &str =
    "threshold-monero/receiver-key-accumulator/certificate-binding/v1";
const SELECTION_DIGEST_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/selection/v1";
const PROOF_DIGEST_DOMAIN: &str = "threshold-monero/receiver-key-accumulator/proof/v1";
const ACTIVE_HEAD_LABEL: &[u8] = b"active";
const STAGED_HEAD_LABEL: &[u8] = b"staged";
const ACTIVE_HEAD_KEY: &[u8] = b"active";
const STAGED_HEAD_KEY: &[u8] = b"staged";
const MAX_NODE_RECORD_BYTES: usize = 512;
const MAX_ACTIVE_HEAD_BYTES: usize = 1024;
const MAX_STAGED_HEAD_BYTES: usize = 512 * 1024;
const MAX_CHANGED_NODES: usize = MAX_COMMITTEE_MEMBERS * (TREE_DEPTH + 2);

const NODE_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("receiver-key-patricia-nodes-v1");
const HEAD_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("receiver-key-heads-v1");

thread_local! {
    static DEFAULT_HASH_CACHE: RefCell<Option<([u8; 32], Arc<Vec<[u8; 32]>>)>> =
        const { RefCell::new(None) };
}

/// redb cache retained by one production receiver-key accumulator.
pub const RECEIVER_KEY_ACCUMULATOR_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Exact hash payload in a maximum-size proof.
pub const MAX_RECEIVER_KEY_BATCH_PROOF_HASH_BYTES: usize = MAX_COMMITTEE_MEMBERS * TREE_DEPTH * 32;
/// Canonical proof cap: fixed hash payload plus two commitments and bounded postcard framing.
pub const MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES: usize =
    MAX_RECEIVER_KEY_BATCH_PROOF_HASH_BYTES + 4 * 1024;

/// Constant-size commitment carried by rotation policy and authenticated epoch history.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiverKeyAccumulatorCommitment {
    version: u16,
    network: [u8; 32],
    through_epoch: u64,
    leaf_count: u64,
    root: [u8; 32],
}

impl ReceiverKeyAccumulatorCommitment {
    /// Compute the epoch-zero commitment without creating or opening durable storage.
    pub fn from_bootstrap_keys(
        network: [u8; 32],
        keys: &[(PartyId, [u8; 32])],
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        Ok(build_initial_state(network, 0, keys)?.0.commitment)
    }

    pub fn validate(self) -> Result<(), ReceiverKeyAccumulatorError> {
        if self.version != ACCUMULATOR_VERSION {
            return Err(ReceiverKeyAccumulatorError::UnsupportedVersion);
        }
        if self.network == [0_u8; 32] || self.root == [0_u8; 32] || self.leaf_count == 0 {
            return Err(ReceiverKeyAccumulatorError::InvalidCommitment);
        }
        Ok(())
    }

    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn through_epoch(self) -> u64 {
        self.through_epoch
    }

    #[must_use]
    pub const fn leaf_count(self) -> u64 {
        self.leaf_count
    }

    #[must_use]
    pub const fn root(self) -> [u8; 32] {
        self.root
    }

    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(COMMITMENT_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.network);
        hasher.update(&self.through_epoch.to_le_bytes());
        hasher.update(&self.leaf_count.to_le_bytes());
        hasher.update(&self.root);
        *hasher.finalize().as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        network: [u8; 32],
        through_epoch: u64,
        leaf_count: u64,
        root: [u8; 32],
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        let commitment =
            Self { version: ACCUMULATOR_VERSION, network, through_epoch, leaf_count, root };
        commitment.validate()?;
        Ok(commitment)
    }
}

/// Domain-separated binding between a staged accumulator successor and one verified certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiverKeyStageBinding([u8; 32]);

impl ReceiverKeyStageBinding {
    pub fn for_certificate(
        context_digest: [u8; 32],
        certificate_semantic_digest: [u8; 32],
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        if context_digest == [0_u8; 32] || certificate_semantic_digest == [0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidStageBinding);
        }
        let mut hasher = blake3::Hasher::new_derive_key(STAGE_BINDING_DOMAIN);
        hasher.update(&context_digest);
        hasher.update(&certificate_semantic_digest);
        Self::from_digest(*hasher.finalize().as_bytes())
    }

    pub fn from_digest(digest: [u8; 32]) -> Result<Self, ReceiverKeyAccumulatorError> {
        if digest == [0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidStageBinding);
        }
        Ok(Self(digest))
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }

    fn validate(self) -> Result<(), ReceiverKeyAccumulatorError> {
        if self.0 == [0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidStageBinding);
        }
        Ok(())
    }
}

/// Public restart/reconciliation view of the one possible staged successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverKeyAccumulatorStagedUpdate {
    binding: ReceiverKeyStageBinding,
    prior: ReceiverKeyAccumulatorCommitment,
    next: ReceiverKeyAccumulatorCommitment,
}

impl ReceiverKeyAccumulatorStagedUpdate {
    #[must_use]
    pub const fn binding(self) -> ReceiverKeyStageBinding {
        self.binding
    }

    #[must_use]
    pub const fn prior(self) -> ReceiverKeyAccumulatorCommitment {
        self.prior
    }

    #[must_use]
    pub const fn next(self) -> ReceiverKeyAccumulatorCommitment {
        self.next
    }
}

/// Result of reconciling a crash-durable staged successor against durable certificate authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverKeyAccumulatorReconcile {
    Clean,
    Retained(ReceiverKeyAccumulatorStagedUpdate),
    Promoted(ReceiverKeyAccumulatorCommitment),
}

/// Lightweight result of a read-only preview. It owns no historical prover state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiverKeyAccumulatorPreview {
    commitment: ReceiverKeyAccumulatorCommitment,
}

impl ReceiverKeyAccumulatorPreview {
    #[must_use]
    pub const fn commitment(self) -> ReceiverKeyAccumulatorCommitment {
        self.commitment
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
struct NodeId([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PatriciaRef {
    id: NodeId,
    depth: u16,
    prefix: [u8; 32],
    sparse_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum PatriciaNodeRecord {
    Leaf {
        version: u16,
        network: [u8; 32],
        path: [u8; 32],
        party: PartyId,
        receiver_key: [u8; 32],
        first_epoch: u64,
    },
    Branch {
        version: u16,
        network: [u8; 32],
        depth: u16,
        prefix: [u8; 32],
        left: PatriciaRef,
        right: PatriciaRef,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableActiveHead {
    version: u16,
    network: [u8; 32],
    bootstrap_digest: [u8; 32],
    revision: u64,
    commitment: ReceiverKeyAccumulatorCommitment,
    root: PatriciaRef,
    node_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableStagedHead {
    version: u16,
    prior_revision: u64,
    prior: ReceiverKeyAccumulatorCommitment,
    binding: ReceiverKeyStageBinding,
    selection_digest: [u8; 32],
    proof_digest: [u8; 32],
    selected_count: u16,
    next: DurableActiveHead,
    #[serde(deserialize_with = "deserialize_changed_node_ids")]
    created: Vec<NodeId>,
    #[serde(deserialize_with = "deserialize_changed_node_ids")]
    retired: Vec<NodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedValue<'a> {
    #[serde(borrow)]
    body: &'a [u8],
    mac: [u8; 32],
}

struct ComputedUpdate {
    proof: ReceiverKeyBatchUpdateProof,
    next_commitment: ReceiverKeyAccumulatorCommitment,
    next_root: PatriciaRef,
    writes: BTreeMap<NodeId, PatriciaNodeRecord>,
    retired: BTreeSet<NodeId>,
}

struct PatriciaOverlay {
    network: [u8; 32],
    writes: BTreeMap<NodeId, PatriciaNodeRecord>,
    retired: BTreeSet<NodeId>,
}

impl PatriciaOverlay {
    fn new(network: [u8; 32]) -> Self {
        Self { network, writes: BTreeMap::new(), retired: BTreeSet::new() }
    }

    fn insert<F>(
        &mut self,
        current: Option<PatriciaRef>,
        party: PartyId,
        key: [u8; 32],
        first_epoch: u64,
        load: &mut F,
    ) -> Result<PatriciaRef, ReceiverKeyAccumulatorError>
    where
        F: FnMut(NodeId) -> Result<PatriciaNodeRecord, ReceiverKeyAccumulatorError>,
    {
        let path = receiver_key_path(self.network, key);
        let leaf = PatriciaNodeRecord::Leaf {
            version: PATRICIA_NODE_VERSION,
            network: self.network,
            path,
            party,
            receiver_key: key,
            first_epoch,
        };
        let Some(current) = current else {
            return self.put(leaf);
        };

        let common = common_prefix_len(path, current.prefix, usize::from(current.depth));
        if common < usize::from(current.depth) {
            let new_leaf = self.put(leaf)?;
            return self.branch(common, path, current, new_leaf);
        }

        let record = self.load(current, load)?;
        match record {
            PatriciaNodeRecord::Leaf { receiver_key, .. } => {
                if receiver_key == key {
                    Err(ReceiverKeyAccumulatorError::KeyAlreadyUsed)
                } else {
                    Err(ReceiverKeyAccumulatorError::PathCollision)
                }
            }
            PatriciaNodeRecord::Branch { depth, prefix, left, right, .. } => {
                let branch_depth = usize::from(depth);
                let copied = if bit_at(path, branch_depth) {
                    let replacement = self.insert(Some(right), party, key, first_epoch, load)?;
                    PatriciaNodeRecord::Branch {
                        version: PATRICIA_NODE_VERSION,
                        network: self.network,
                        depth,
                        prefix,
                        left,
                        right: replacement,
                    }
                } else {
                    let replacement = self.insert(Some(left), party, key, first_epoch, load)?;
                    PatriciaNodeRecord::Branch {
                        version: PATRICIA_NODE_VERSION,
                        network: self.network,
                        depth,
                        prefix,
                        left: replacement,
                        right,
                    }
                };
                self.retire(current.id);
                self.put(copied)
            }
        }
    }

    fn branch(
        &mut self,
        depth: usize,
        new_path: [u8; 32],
        existing: PatriciaRef,
        new_leaf: PatriciaRef,
    ) -> Result<PatriciaRef, ReceiverKeyAccumulatorError> {
        let (left, right) =
            if bit_at(new_path, depth) { (existing, new_leaf) } else { (new_leaf, existing) };
        self.put(PatriciaNodeRecord::Branch {
            version: PATRICIA_NODE_VERSION,
            network: self.network,
            depth: u16::try_from(depth).map_err(|_| ReceiverKeyAccumulatorError::InvalidNode)?,
            prefix: masked_prefix(new_path, depth),
            left,
            right,
        })
    }

    fn load<F>(
        &self,
        reference: PatriciaRef,
        load: &mut F,
    ) -> Result<PatriciaNodeRecord, ReceiverKeyAccumulatorError>
    where
        F: FnMut(NodeId) -> Result<PatriciaNodeRecord, ReceiverKeyAccumulatorError>,
    {
        let record = if let Some(record) = self.writes.get(&reference.id) {
            record.clone()
        } else {
            load(reference.id)?
        };
        validate_node_record(self.network, reference, &record)?;
        Ok(record)
    }

    fn put(
        &mut self,
        record: PatriciaNodeRecord,
    ) -> Result<PatriciaRef, ReceiverKeyAccumulatorError> {
        let reference = reference_for_record(self.network, &record)?;
        if let Some(existing) = self.writes.insert(reference.id, record.clone())
            && existing != record
        {
            return Err(ReceiverKeyAccumulatorError::StorageConflict);
        }
        Ok(reference)
    }

    fn retire(&mut self, id: NodeId) {
        if self.writes.remove(&id).is_none() {
            self.retired.insert(id);
        }
    }
}

/// Current-only Patricia prover with an authenticated active head and one staged successor.
///
/// This type deliberately does not implement `Clone`. A preview uses a redb read transaction and a
/// bounded copy-on-write overlay containing only changed Patricia paths.
pub struct ReceiverKeyAccumulatorStore {
    database: Database,
    network: [u8; 32],
    mac_key: Zeroizing<[u8; 32]>,
    active: DurableActiveHead,
    staged: Option<DurableStagedHead>,
    #[cfg(test)]
    external_proof_verifications: u64,
}

impl fmt::Debug for ReceiverKeyAccumulatorStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiverKeyAccumulatorStore")
            .field("network", &self.network)
            .field("commitment", &self.active.commitment)
            .field("staged", &self.staged.as_ref().map(public_staged))
            .finish_non_exhaustive()
    }
}

impl ReceiverKeyAccumulatorStore {
    /// Open or initialize the production accumulator database.
    ///
    /// `authentication_key` must be a stable secret for this party and independent of public
    /// network data. The caller's exclusive party-state lease must be held for the lifetime of
    /// this store.
    pub fn open(
        path: impl AsRef<Path>,
        network: [u8; 32],
        bootstrap_keys: &[(PartyId, [u8; 32])],
        authentication_key: &[u8; 32],
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        if authentication_key == &[0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidAuthenticationKey);
        }
        let (initial, nodes) = build_initial_state(network, 0, bootstrap_keys)?;
        if let Some(parent) = path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_database()?;
        }
        if let Ok(metadata) = std::fs::symlink_metadata(path.as_ref())
            && (!metadata.file_type().is_file() || metadata.file_type().is_symlink())
        {
            return Err(ReceiverKeyAccumulatorError::StorageConflict);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path.as_ref()).map_database()?;
        let opened_metadata = file.metadata().map_database()?;
        let current_metadata = std::fs::symlink_metadata(path.as_ref()).map_database()?;
        if !opened_metadata.is_file()
            || !current_metadata.is_file()
            || !same_file_identity(&opened_metadata, &current_metadata)
        {
            return Err(ReceiverKeyAccumulatorError::StorageConflict);
        }
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o600)).map_database()?;
        let mut builder = Database::builder();
        builder.set_cache_size(RECEIVER_KEY_ACCUMULATOR_CACHE_BYTES);
        let database = builder.create_file(file).map_database()?;
        let store =
            Self::initialize_or_load(database, network, authentication_key, initial, nodes)?;
        #[cfg(unix)]
        if let Some(parent) = path.as_ref().parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::File::open(parent).map_database()?.sync_all().map_database()?;
        }
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn from_entries_at_epoch(
        network: [u8; 32],
        through_epoch: u64,
        keys: &[(PartyId, [u8; 32])],
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        Self::in_memory(network, through_epoch, keys)
    }

    #[cfg(test)]
    fn in_memory(
        network: [u8; 32],
        through_epoch: u64,
        keys: &[(PartyId, [u8; 32])],
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        let (initial, nodes) = build_initial_state(network, through_epoch, keys)?;
        let mut builder = Database::builder();
        builder.set_cache_size(RECEIVER_KEY_ACCUMULATOR_CACHE_BYTES);
        let database = builder.create_with_backend(InMemoryBackend::new()).map_database()?;
        let authentication_key = blake3::derive_key(
            "threshold-monero/receiver-key-accumulator/in-memory-auth/v1",
            &network,
        );
        Self::initialize_or_load(database, network, &authentication_key, initial, nodes)
    }

    fn initialize_or_load(
        database: Database,
        network: [u8; 32],
        authentication_key: &[u8; 32],
        initial: DurableActiveHead,
        initial_nodes: BTreeMap<NodeId, PatriciaNodeRecord>,
    ) -> Result<Self, ReceiverKeyAccumulatorError> {
        let mac_key = derive_head_key(authentication_key, network);
        let mut transaction = database.begin_write().map_database()?;
        configure_write(&mut transaction);
        let head_table = transaction.open_table(HEAD_TABLE).map_database()?;
        let active_present = head_table.get(ACTIVE_HEAD_KEY).map_database()?.is_some();
        if !active_present && !head_table.is_empty().map_database()? {
            return Err(ReceiverKeyAccumulatorError::StorageConflict);
        }
        drop(head_table);
        if !active_present {
            {
                let mut nodes = transaction.open_table(NODE_TABLE).map_database()?;
                if !nodes.is_empty().map_database()? {
                    return Err(ReceiverKeyAccumulatorError::StorageConflict);
                }
                for (id, record) in &initial_nodes {
                    let encoded = encode_canonical(record)?;
                    nodes.insert(id.0.as_slice(), encoded.as_slice()).map_database()?;
                }
            }
            {
                let mut heads = transaction.open_table(HEAD_TABLE).map_database()?;
                if heads.get(STAGED_HEAD_KEY).map_database()?.is_some() {
                    return Err(ReceiverKeyAccumulatorError::StorageConflict);
                }
                let encoded = encode_authenticated(
                    &mac_key,
                    ACTIVE_HEAD_LABEL,
                    &initial,
                    MAX_ACTIVE_HEAD_BYTES,
                )?;
                heads.insert(ACTIVE_HEAD_KEY, encoded.as_slice()).map_database()?;
            }
        }
        transaction.commit().map_database()?;

        let (active, staged) =
            load_durable_state(&database, network, initial.bootstrap_digest, &mac_key)?;
        Ok(Self {
            database,
            network,
            mac_key,
            active,
            staged,
            #[cfg(test)]
            external_proof_verifications: 0,
        })
    }

    /// The active history-tip commitment. A certified-but-unactivated successor remains available
    /// only through [`Self::staged_update`] until authenticated history authorizes promotion.
    #[must_use]
    pub const fn commitment(&self) -> ReceiverKeyAccumulatorCommitment {
        self.active.commitment
    }

    #[must_use]
    pub const fn live_node_count(&self) -> u64 {
        self.active.node_count
    }

    pub fn stored_node_count(&self) -> Result<u64, ReceiverKeyAccumulatorError> {
        let transaction = self.database.begin_read().map_database()?;
        let nodes = transaction.open_table(NODE_TABLE).map_database()?;
        nodes.len().map_database()
    }

    #[cfg(test)]
    const fn external_proof_verification_count(&self) -> u64 {
        self.external_proof_verifications
    }

    /// Fallible membership lookup used by production control flow.
    pub fn try_contains_key(&self, key: [u8; 32]) -> Result<bool, ReceiverKeyAccumulatorError> {
        if key == [0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidKey);
        }
        let transaction = self.database.begin_read().map_database()?;
        let nodes = transaction.open_table(NODE_TABLE).map_database()?;
        let mut load = |id: NodeId| load_node(&nodes, id);
        contains_path(self.network, self.active.root, key, &mut load)
    }

    pub fn preview(
        &self,
        target_epoch: u64,
        selected: &[(PartyId, [u8; 32])],
    ) -> Result<
        (ReceiverKeyBatchUpdateProof, ReceiverKeyAccumulatorPreview),
        ReceiverKeyAccumulatorError,
    > {
        let computed = self.compute_update(target_epoch, selected)?;
        Ok((computed.proof, ReceiverKeyAccumulatorPreview { commitment: computed.next_commitment }))
    }

    /// Durably stage one proof already bound by the caller to a verified certificate.
    ///
    /// The active commitment remains authoritative until [`Self::reconcile_staged`] observes that
    /// authenticated epoch history names this successor.
    pub fn stage_verified_update(
        &mut self,
        target_epoch: u64,
        selected: &[(PartyId, [u8; 32])],
        proof: &ReceiverKeyBatchUpdateProof,
        binding: ReceiverKeyStageBinding,
    ) -> Result<ReceiverKeyAccumulatorStagedUpdate, ReceiverKeyAccumulatorError> {
        binding.validate()?;
        let proof_digest = proof_digest(proof)?;
        let selection_digest = selection_digest(selected)?;

        if let Some(staged) = &self.staged {
            if staged.binding == binding
                && staged.prior == self.active.commitment
                && proof.prior() == staged.prior
                && proof.next() == staged.next.commitment
                && target_epoch == staged.next.commitment.through_epoch()
                && staged.proof_digest == proof_digest
                && staged.selection_digest == selection_digest
                && usize::from(staged.selected_count) == selected.len()
            {
                authenticate_live_heads(&self.database, &self.mac_key, &self.active, Some(staged))?;
                return Ok(public_staged(staged));
            }
            return Err(ReceiverKeyAccumulatorError::StagedUpdateConflict);
        }

        #[cfg(test)]
        {
            self.external_proof_verifications += 1;
        }
        let expected = proof.verify(&self.active.commitment, target_epoch, selected)?;
        let computed = self.compute_update(target_epoch, selected)?;
        if computed.proof != *proof || computed.next_commitment != expected {
            return Err(ReceiverKeyAccumulatorError::StorageProofMismatch);
        }
        let selected_count = u16::try_from(selected.len())
            .map_err(|_| ReceiverKeyAccumulatorError::InvalidProofShape)?;
        let next_node_count = expected_node_count(expected.leaf_count)?;
        let next = DurableActiveHead {
            version: DURABLE_HEAD_VERSION,
            network: self.network,
            bootstrap_digest: self.active.bootstrap_digest,
            revision: self
                .active
                .revision
                .checked_add(1)
                .ok_or(ReceiverKeyAccumulatorError::RevisionExhausted)?,
            commitment: expected,
            root: computed.next_root,
            node_count: next_node_count,
        };

        let mut created = Vec::with_capacity(computed.writes.len());
        let retired = computed.retired.iter().copied().collect::<Vec<_>>();
        if computed.writes.len() > MAX_CHANGED_NODES || retired.len() > MAX_CHANGED_NODES {
            return Err(ReceiverKeyAccumulatorError::ChangedNodeLimit);
        }

        let mut transaction = self.database.begin_write().map_database()?;
        configure_write(&mut transaction);
        authenticate_transaction_heads(&transaction, &self.mac_key, &self.active, None)?;
        {
            let mut nodes = transaction.open_table(NODE_TABLE).map_database()?;
            if nodes.len().map_database()? != self.active.node_count {
                return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
            }
            for retired_id in &retired {
                if nodes.get(retired_id.0.as_slice()).map_database()?.is_none() {
                    return Err(ReceiverKeyAccumulatorError::MissingNode);
                }
            }
            for (id, record) in &computed.writes {
                if nodes.get(id.0.as_slice()).map_database()?.is_some() {
                    return Err(ReceiverKeyAccumulatorError::StorageConflict);
                }
                let encoded = encode_canonical(record)?;
                nodes.insert(id.0.as_slice(), encoded.as_slice()).map_database()?;
                created.push(*id);
            }
            let expected_staged_count = self
                .active
                .node_count
                .checked_add(
                    u64::try_from(created.len())
                        .map_err(|_| ReceiverKeyAccumulatorError::InvalidNodeCount)?,
                )
                .ok_or(ReceiverKeyAccumulatorError::InvalidNodeCount)?;
            if nodes.len().map_database()? != expected_staged_count {
                return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
            }
        }
        validate_node_delta(created.len(), retired.len(), selected.len())?;
        let staged = DurableStagedHead {
            version: STAGED_HEAD_VERSION,
            prior_revision: self.active.revision,
            prior: self.active.commitment,
            binding,
            selection_digest,
            proof_digest,
            selected_count,
            next,
            created,
            retired,
        };
        validate_staged_head(self.network, &self.active, &staged)?;
        {
            let mut heads = transaction.open_table(HEAD_TABLE).map_database()?;
            if heads.get(STAGED_HEAD_KEY).map_database()?.is_some() {
                return Err(ReceiverKeyAccumulatorError::StagedUpdateConflict);
            }
            let encoded = encode_authenticated(
                &self.mac_key,
                STAGED_HEAD_LABEL,
                &staged,
                MAX_STAGED_HEAD_BYTES,
            )?;
            heads.insert(STAGED_HEAD_KEY, encoded.as_slice()).map_database()?;
        }
        transaction.commit().map_database()?;
        self.staged = Some(staged);
        Ok(public_staged(self.staged.as_ref().expect("staged head was assigned")))
    }

    /// Atomically promote the staged successor and delete every superseded Patricia path node.
    ///
    /// Promotion is private so callers cannot advance the active head using the public certificate
    /// binding alone. [`Self::reconcile_staged`] is the production authority gate.
    fn promote_staged(
        &mut self,
        binding: ReceiverKeyStageBinding,
    ) -> Result<ReceiverKeyAccumulatorCommitment, ReceiverKeyAccumulatorError> {
        binding.validate()?;
        let staged = self.staged.clone().ok_or(ReceiverKeyAccumulatorError::NoStagedUpdate)?;
        if staged.binding != binding {
            return Err(ReceiverKeyAccumulatorError::StagedUpdateConflict);
        }

        let mut transaction = self.database.begin_write().map_database()?;
        configure_write(&mut transaction);
        authenticate_transaction_heads(&transaction, &self.mac_key, &self.active, Some(&staged))?;
        {
            let mut nodes = transaction.open_table(NODE_TABLE).map_database()?;
            for id in &staged.created {
                validate_stored_node_id(self.network, &nodes, *id)?;
            }
            for id in &staged.retired {
                if nodes.remove(id.0.as_slice()).map_database()?.is_none() {
                    return Err(ReceiverKeyAccumulatorError::MissingNode);
                }
            }
            if nodes.len().map_database()? != staged.next.node_count {
                return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
            }
        }
        {
            let mut heads = transaction.open_table(HEAD_TABLE).map_database()?;
            let encoded = encode_authenticated(
                &self.mac_key,
                ACTIVE_HEAD_LABEL,
                &staged.next,
                MAX_ACTIVE_HEAD_BYTES,
            )?;
            heads.insert(ACTIVE_HEAD_KEY, encoded.as_slice()).map_database()?;
            if heads.remove(STAGED_HEAD_KEY).map_database()?.is_none() {
                return Err(ReceiverKeyAccumulatorError::NoStagedUpdate);
            }
        }
        transaction.commit().map_database()?;
        self.active = staged.next;
        self.staged = None;
        Ok(self.active.commitment)
    }

    /// Explicitly discard a staged successor without changing the active commitment.
    ///
    /// Normal restart reconciliation never calls this method. The caller must first establish
    /// through an authenticated administrative recovery path that the bound certificate is not
    /// authoritative.
    #[cfg(test)]
    pub(crate) fn discard_staged(
        &mut self,
        binding: ReceiverKeyStageBinding,
    ) -> Result<(), ReceiverKeyAccumulatorError> {
        binding.validate()?;
        let staged = self.staged.clone().ok_or(ReceiverKeyAccumulatorError::NoStagedUpdate)?;
        if staged.binding != binding {
            return Err(ReceiverKeyAccumulatorError::StagedUpdateConflict);
        }

        let mut transaction = self.database.begin_write().map_database()?;
        configure_write(&mut transaction);
        authenticate_transaction_heads(&transaction, &self.mac_key, &self.active, Some(&staged))?;
        {
            let mut nodes = transaction.open_table(NODE_TABLE).map_database()?;
            for id in &staged.created {
                if nodes.remove(id.0.as_slice()).map_database()?.is_none() {
                    return Err(ReceiverKeyAccumulatorError::MissingNode);
                }
            }
            if nodes.len().map_database()? != self.active.node_count {
                return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
            }
        }
        {
            let mut heads = transaction.open_table(HEAD_TABLE).map_database()?;
            if heads.remove(STAGED_HEAD_KEY).map_database()?.is_none() {
                return Err(ReceiverKeyAccumulatorError::NoStagedUpdate);
            }
        }
        transaction.commit().map_database()?;
        self.staged = None;
        Ok(())
    }

    /// Reconcile the possible crash-durable stage against authenticated epoch history.
    ///
    /// A terminal certificate may be durable one epoch before its activation. While history still
    /// names the active commitment, a matching staged certificate is retained but not promoted.
    /// Promotion is authorized only after authenticated history names the staged successor.
    pub fn reconcile_staged(
        &mut self,
        authenticated_history_tip: ReceiverKeyAccumulatorCommitment,
        terminal_binding: Option<ReceiverKeyStageBinding>,
    ) -> Result<ReceiverKeyAccumulatorReconcile, ReceiverKeyAccumulatorError> {
        authenticated_history_tip.validate()?;
        if authenticated_history_tip.network() != self.network {
            return Err(ReceiverKeyAccumulatorError::StorageConflict);
        }
        let Some(staged) = self.staged_update() else {
            return if authenticated_history_tip == self.active.commitment {
                Ok(ReceiverKeyAccumulatorReconcile::Clean)
            } else {
                Err(ReceiverKeyAccumulatorError::HistoryTipMismatch)
            };
        };
        let binding = terminal_binding.ok_or(ReceiverKeyAccumulatorError::MissingStageAuthority)?;
        if binding != staged.binding {
            return Err(ReceiverKeyAccumulatorError::StagedUpdateConflict);
        }
        if authenticated_history_tip == staged.prior {
            Ok(ReceiverKeyAccumulatorReconcile::Retained(staged))
        } else if authenticated_history_tip == staged.next {
            Ok(ReceiverKeyAccumulatorReconcile::Promoted(self.promote_staged(binding)?))
        } else {
            Err(ReceiverKeyAccumulatorError::HistoryTipMismatch)
        }
    }

    #[must_use]
    pub fn staged_update(&self) -> Option<ReceiverKeyAccumulatorStagedUpdate> {
        self.staged.as_ref().map(public_staged)
    }

    #[cfg(test)]
    pub(crate) fn prove_and_apply(
        &mut self,
        target_epoch: u64,
        selected: &[(PartyId, [u8; 32])],
    ) -> Result<ReceiverKeyBatchUpdateProof, ReceiverKeyAccumulatorError> {
        let (proof, _) = self.preview(target_epoch, selected)?;
        let binding = test_binding(&proof)?;
        self.stage_verified_update(target_epoch, selected, &proof, binding)?;
        self.promote_staged(binding)?;
        Ok(proof)
    }

    #[cfg(test)]
    pub(crate) fn apply_verified_update(
        &mut self,
        target_epoch: u64,
        selected: &[(PartyId, [u8; 32])],
        proof: &ReceiverKeyBatchUpdateProof,
    ) -> Result<ReceiverKeyAccumulatorCommitment, ReceiverKeyAccumulatorError> {
        let binding = test_binding(proof)?;
        self.stage_verified_update(target_epoch, selected, proof, binding)?;
        self.promote_staged(binding)
    }

    fn compute_update(
        &self,
        target_epoch: u64,
        selected: &[(PartyId, [u8; 32])],
    ) -> Result<ComputedUpdate, ReceiverKeyAccumulatorError> {
        self.active.commitment.validate()?;
        if self.active.commitment.through_epoch.checked_add(1) != Some(target_epoch) {
            return Err(ReceiverKeyAccumulatorError::WrongTargetEpoch);
        }
        validate_selected(selected)?;

        let transaction = self.database.begin_read().map_database()?;
        let nodes = transaction.open_table(NODE_TABLE).map_database()?;
        let mut load = |id: NodeId| load_node(&nodes, id);
        let mut paths = Vec::with_capacity(selected.len());
        for (_, key) in selected {
            paths.push(ReceiverKeyNonMembershipPath {
                siblings: non_membership_path(self.network, self.active.root, *key, &mut load)?,
            });
        }

        let mut overlay = PatriciaOverlay::new(self.network);
        let mut root = self.active.root;
        for (party, key) in selected {
            root = overlay.insert(Some(root), *party, *key, target_epoch, &mut load)?;
        }
        retain_reachable_overlay(root, &mut overlay.writes, &mut overlay.retired)?;
        let next_commitment = ReceiverKeyAccumulatorCommitment {
            version: ACCUMULATOR_VERSION,
            network: self.network,
            through_epoch: target_epoch,
            leaf_count: self
                .active
                .commitment
                .leaf_count
                .checked_add(
                    u64::try_from(selected.len())
                        .map_err(|_| ReceiverKeyAccumulatorError::LeafCountExhausted)?,
                )
                .ok_or(ReceiverKeyAccumulatorError::LeafCountExhausted)?,
            root: lift_ref(self.network, root, 0)?,
        };
        next_commitment.validate()?;
        let proof = ReceiverKeyBatchUpdateProof {
            version: BATCH_PROOF_VERSION,
            prior: self.active.commitment,
            next: next_commitment,
            paths,
        };
        validate_node_delta(overlay.writes.len(), overlay.retired.len(), selected.len())?;
        Ok(ComputedUpdate {
            proof,
            next_commitment,
            next_root: root,
            writes: overlay.writes,
            retired: overlay.retired,
        })
    }
}

fn retain_reachable_overlay(
    root: PatriciaRef,
    writes: &mut BTreeMap<NodeId, PatriciaNodeRecord>,
    retired: &mut BTreeSet<NodeId>,
) -> Result<(), ReceiverKeyAccumulatorError> {
    let candidates = std::mem::take(writes);
    let mut reachable = BTreeSet::new();
    let mut referenced = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(reference) = pending.pop() {
        referenced.insert(reference.id);
        let Some(record) = candidates.get(&reference.id) else {
            continue;
        };
        if !reachable.insert(reference.id) {
            continue;
        }
        if let PatriciaNodeRecord::Branch { left, right, .. } = record {
            pending.push(*left);
            pending.push(*right);
        }
    }
    for id in reachable {
        let record = candidates.get(&id).ok_or(ReceiverKeyAccumulatorError::MissingNode)?.clone();
        writes.insert(id, record);
    }
    retired.retain(|id| !referenced.contains(id));
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverKeyNonMembershipPath {
    #[serde(deserialize_with = "deserialize_receiver_key_path_siblings")]
    siblings: Vec<[u8; 32]>,
}

/// Self-contained, history-independent proof for one exact selected committee.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiverKeyBatchUpdateProof {
    version: u16,
    prior: ReceiverKeyAccumulatorCommitment,
    next: ReceiverKeyAccumulatorCommitment,
    #[serde(deserialize_with = "deserialize_receiver_key_paths")]
    paths: Vec<ReceiverKeyNonMembershipPath>,
}

impl ReceiverKeyBatchUpdateProof {
    #[must_use]
    pub const fn prior(&self) -> ReceiverKeyAccumulatorCommitment {
        self.prior
    }

    #[must_use]
    pub const fn next(&self) -> ReceiverKeyAccumulatorCommitment {
        self.next
    }

    pub fn verify(
        &self,
        expected_prior: &ReceiverKeyAccumulatorCommitment,
        target_epoch: u64,
        selected: &[(PartyId, [u8; 32])],
    ) -> Result<ReceiverKeyAccumulatorCommitment, ReceiverKeyAccumulatorError> {
        expected_prior.validate()?;
        self.prior.validate()?;
        self.next.validate()?;
        validate_selected(selected)?;
        if self.version != BATCH_PROOF_VERSION {
            return Err(ReceiverKeyAccumulatorError::UnsupportedVersion);
        }
        if self.prior != *expected_prior {
            return Err(ReceiverKeyAccumulatorError::WrongPriorCommitment);
        }
        if self.prior.network != self.next.network
            || self.prior.through_epoch.checked_add(1) != Some(target_epoch)
            || self.next.through_epoch != target_epoch
            || self.prior.leaf_count.checked_add(selected.len() as u64)
                != Some(self.next.leaf_count)
        {
            return Err(ReceiverKeyAccumulatorError::WrongNextCommitment);
        }
        if self.paths.len() != selected.len()
            || self.paths.len() > MAX_COMMITTEE_MEMBERS
            || self.paths.iter().any(|path| path.siblings.len() != TREE_DEPTH)
        {
            return Err(ReceiverKeyAccumulatorError::InvalidProofShape);
        }

        let network = self.prior.network;
        let defaults = default_hashes(network);
        let mut frontier = BTreeMap::<NodePosition, [u8; 32]>::new();
        for ((_, key), proof) in selected.iter().zip(&self.paths) {
            let path = receiver_key_path(network, *key);
            let mut old = defaults[TREE_DEPTH];
            for depth in (0..TREE_DEPTH).rev() {
                let sibling = proof.siblings[depth];
                let position = NodePosition::sibling(path, depth);
                if sibling != defaults[depth + 1] {
                    if let Some(existing) = frontier.insert(position, sibling)
                        && existing != sibling
                    {
                        return Err(ReceiverKeyAccumulatorError::InconsistentProof);
                    }
                }
                old = if bit_at(path, depth) {
                    receiver_key_node_hash(network, depth, sibling, old)
                } else {
                    receiver_key_node_hash(network, depth, old, sibling)
                };
            }
            if old != self.prior.root {
                return Err(ReceiverKeyAccumulatorError::KeyAlreadyUsed);
            }
        }

        let mut nodes = frontier;
        for ((party, key), _) in selected.iter().zip(&self.paths) {
            let path = receiver_key_path(network, *key);
            let leaf_position = NodePosition::for_path(path, TREE_DEPTH);
            if nodes.contains_key(&leaf_position) {
                return Err(ReceiverKeyAccumulatorError::KeyAlreadyUsed);
            }
            let mut current = receiver_key_leaf_hash(network, path, *party, *key, target_epoch);
            nodes.insert(leaf_position, current);
            for depth in (0..TREE_DEPTH).rev() {
                let sibling = nodes
                    .get(&NodePosition::sibling(path, depth))
                    .copied()
                    .unwrap_or(defaults[depth + 1]);
                current = if bit_at(path, depth) {
                    receiver_key_node_hash(network, depth, sibling, current)
                } else {
                    receiver_key_node_hash(network, depth, current, sibling)
                };
                nodes.insert(NodePosition::for_path(path, depth), current);
            }
        }
        let actual_root =
            nodes.get(&NodePosition::for_path([0_u8; 32], 0)).copied().unwrap_or(defaults[0]);
        if actual_root != self.next.root {
            return Err(ReceiverKeyAccumulatorError::WrongNextCommitment);
        }
        Ok(self.next)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ReceiverKeyAccumulatorError> {
        self.validate_encoding_shape()?;
        let bytes = encode_canonical(self)?;
        if bytes.len() > MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES {
            return Err(ReceiverKeyAccumulatorError::ProofTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReceiverKeyAccumulatorError> {
        decode_canonical(bytes, MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES).and_then(
            |proof: Self| {
                proof.validate_encoding_shape()?;
                Ok(proof)
            },
        )
    }

    fn validate_encoding_shape(&self) -> Result<(), ReceiverKeyAccumulatorError> {
        if self.version != BATCH_PROOF_VERSION {
            return Err(ReceiverKeyAccumulatorError::UnsupportedVersion);
        }
        self.prior.validate()?;
        self.next.validate()?;
        if self.paths.is_empty()
            || self.paths.len() > MAX_COMMITTEE_MEMBERS
            || self.paths.iter().any(|path| path.siblings.len() != TREE_DEPTH)
            || self.prior.network != self.next.network
            || self.prior.through_epoch.checked_add(1) != Some(self.next.through_epoch)
            || self.prior.leaf_count.checked_add(self.paths.len() as u64)
                != Some(self.next.leaf_count)
        {
            return Err(ReceiverKeyAccumulatorError::InvalidProofShape);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NodePosition {
    depth: u16,
    prefix: [u8; 32],
}

impl NodePosition {
    fn for_path(path: [u8; 32], depth: usize) -> Self {
        Self {
            depth: u16::try_from(depth).expect("tree depth fits u16"),
            prefix: masked_prefix(path, depth),
        }
    }

    fn sibling(path: [u8; 32], parent_depth: usize) -> Self {
        let mut sibling = path;
        toggle_bit(&mut sibling, parent_depth);
        Self::for_path(sibling, parent_depth + 1)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReceiverKeyAccumulatorError {
    #[error("unsupported receiver-key accumulator version")]
    UnsupportedVersion,
    #[error("invalid receiver-key accumulator commitment")]
    InvalidCommitment,
    #[error("invalid receiver-key bootstrap set")]
    InvalidBootstrapSet,
    #[error("receiver-key entry has an invalid party identifier")]
    InvalidParty,
    #[error("invalid receiver key")]
    InvalidKey,
    #[error("receiver key was already reserved or certified")]
    KeyAlreadyUsed,
    #[error("two receiver keys derived the same accumulator path")]
    PathCollision,
    #[error("receiver-key batch has duplicate parties or keys")]
    DuplicateSelection,
    #[error("receiver-key batch is not in strictly increasing party order")]
    NonCanonicalSelection,
    #[error("receiver-key accumulator target epoch is not contiguous")]
    WrongTargetEpoch,
    #[error("receiver-key accumulator proof has the wrong predecessor")]
    WrongPriorCommitment,
    #[error("receiver-key accumulator proof has the wrong successor")]
    WrongNextCommitment,
    #[error("receiver-key accumulator proof has an invalid shape")]
    InvalidProofShape,
    #[error("receiver-key accumulator proof contains inconsistent paths")]
    InconsistentProof,
    #[error("receiver-key accumulator leaf count is exhausted")]
    LeafCountExhausted,
    #[error("receiver-key accumulator durable revision is exhausted")]
    RevisionExhausted,
    #[error("receiver-key accumulator serialization failed")]
    Serialization,
    #[error("receiver-key accumulator proof exceeds its fixed bound")]
    ProofTooLarge,
    #[error("receiver-key accumulator encoding has trailing bytes")]
    TrailingBytes,
    #[error("receiver-key accumulator encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("receiver-key accumulator database operation failed: {0}")]
    Database(String),
    #[error("receiver-key accumulator storage authentication key is invalid")]
    InvalidAuthenticationKey,
    #[error("receiver-key accumulator durable value exceeds its fixed bound")]
    StorageValueTooLarge,
    #[error("receiver-key accumulator head authentication failed")]
    StorageAuthentication,
    #[error("receiver-key accumulator durable state conflicts with the requested state")]
    StorageConflict,
    #[error("receiver-key accumulator node is missing")]
    MissingNode,
    #[error("receiver-key accumulator Patricia node is invalid")]
    InvalidNode,
    #[error("receiver-key accumulator durable node count is invalid")]
    InvalidNodeCount,
    #[error("receiver-key accumulator changed-node bound was exceeded")]
    ChangedNodeLimit,
    #[error("receiver-key accumulator storage and supplied proof differ")]
    StorageProofMismatch,
    #[error("receiver-key accumulator stage binding is invalid")]
    InvalidStageBinding,
    #[error("receiver-key accumulator already has a conflicting staged update")]
    StagedUpdateConflict,
    #[error("receiver-key accumulator has no staged update")]
    NoStagedUpdate,
    #[error("authenticated epoch history does not match the accumulator lifecycle")]
    HistoryTipMismatch,
    #[error("staged receiver-key update lacks its authenticated terminal certificate")]
    MissingStageAuthority,
}

trait DatabaseResultExt<T> {
    fn map_database(self) -> Result<T, ReceiverKeyAccumulatorError>;
}

impl<T, E: fmt::Display> DatabaseResultExt<T> for Result<T, E> {
    fn map_database(self) -> Result<T, ReceiverKeyAccumulatorError> {
        self.map_err(|error| ReceiverKeyAccumulatorError::Database(error.to_string()))
    }
}

fn configure_write(transaction: &mut redb::WriteTransaction) {
    transaction.set_two_phase_commit(true);
    transaction.set_quick_repair(true);
}

fn derive_head_key(authentication_key: &[u8; 32], network: [u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(authentication_key);
    hasher.update(HEAD_KEY_DOMAIN.as_bytes());
    hasher.update(&network);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn encode_authenticated<T: Serialize>(
    key: &[u8; 32],
    label: &[u8],
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ReceiverKeyAccumulatorError> {
    let body = encode_canonical(value)?;
    let mac = head_mac(key, label, &body);
    let encoded = encode_canonical(&AuthenticatedValue { body: &body, mac })?;
    if encoded.len() > maximum {
        return Err(ReceiverKeyAccumulatorError::StorageValueTooLarge);
    }
    Ok(encoded)
}

fn decode_authenticated<T: DeserializeOwned + Serialize>(
    key: &[u8; 32],
    label: &[u8],
    bytes: &[u8],
    maximum: usize,
) -> Result<T, ReceiverKeyAccumulatorError> {
    if bytes.len() > maximum {
        return Err(ReceiverKeyAccumulatorError::StorageValueTooLarge);
    }
    let (authenticated, trailing) = postcard::take_from_bytes::<AuthenticatedValue<'_>>(bytes)
        .map_err(|_| ReceiverKeyAccumulatorError::Serialization)?;
    if !trailing.is_empty() {
        return Err(ReceiverKeyAccumulatorError::TrailingBytes);
    }
    if encode_canonical(&authenticated)? != bytes {
        return Err(ReceiverKeyAccumulatorError::NonCanonicalEncoding);
    }
    let expected = head_mac(key, label, authenticated.body);
    if !bool::from(expected.ct_eq(&authenticated.mac)) {
        return Err(ReceiverKeyAccumulatorError::StorageAuthentication);
    }
    decode_canonical(authenticated.body, maximum)
}

fn head_mac(key: &[u8; 32], label: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(HEAD_MAC_DOMAIN.as_bytes());
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

fn read_bounded_table_value<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    key: &[u8],
    maximum: usize,
) -> Result<Option<Vec<u8>>, ReceiverKeyAccumulatorError> {
    let Some(value) = table.get(key).map_database()? else {
        return Ok(None);
    };
    let bytes = value.value();
    if bytes.len() > maximum {
        return Err(ReceiverKeyAccumulatorError::StorageValueTooLarge);
    }
    Ok(Some(bytes.to_vec()))
}

fn load_durable_state(
    database: &Database,
    network: [u8; 32],
    bootstrap_digest: [u8; 32],
    mac_key: &[u8; 32],
) -> Result<(DurableActiveHead, Option<DurableStagedHead>), ReceiverKeyAccumulatorError> {
    let transaction = database.begin_read().map_database()?;
    let heads = transaction.open_table(HEAD_TABLE).map_database()?;
    let active_bytes = read_bounded_table_value(&heads, ACTIVE_HEAD_KEY, MAX_ACTIVE_HEAD_BYTES)?
        .ok_or(ReceiverKeyAccumulatorError::StorageConflict)?;
    let staged_bytes = read_bounded_table_value(&heads, STAGED_HEAD_KEY, MAX_STAGED_HEAD_BYTES)?;
    let expected_head_count = 1_u64 + u64::from(staged_bytes.is_some());
    if heads.len().map_database()? != expected_head_count {
        return Err(ReceiverKeyAccumulatorError::StorageConflict);
    }
    drop(heads);
    let active: DurableActiveHead =
        decode_authenticated(mac_key, ACTIVE_HEAD_LABEL, &active_bytes, MAX_ACTIVE_HEAD_BYTES)?;
    validate_active_head(network, bootstrap_digest, &active)?;
    let staged = staged_bytes
        .as_deref()
        .map(|bytes| {
            decode_authenticated::<DurableStagedHead>(
                mac_key,
                STAGED_HEAD_LABEL,
                bytes,
                MAX_STAGED_HEAD_BYTES,
            )
        })
        .transpose()?;
    if let Some(staged) = &staged {
        validate_staged_head(network, &active, staged)?;
    }

    let nodes = transaction.open_table(NODE_TABLE).map_database()?;
    let expected_count = active
        .node_count
        .checked_add(staged.as_ref().map_or(0, |value| value.created.len() as u64))
        .ok_or(ReceiverKeyAccumulatorError::InvalidNodeCount)?;
    if nodes.len().map_database()? != expected_count {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    let active_ids = reachable_node_ids(network, &nodes, active.root, active.node_count)?;
    if u64::try_from(active_ids.len()).map_err(|_| ReceiverKeyAccumulatorError::InvalidNodeCount)?
        != active.node_count
    {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    let reachable = if let Some(staged) = &staged {
        let next_ids =
            reachable_node_ids(network, &nodes, staged.next.root, staged.next.node_count)?;
        if u64::try_from(next_ids.len())
            .map_err(|_| ReceiverKeyAccumulatorError::InvalidNodeCount)?
            != staged.next.node_count
        {
            return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
        }
        let created = staged.created.iter().copied().collect::<BTreeSet<_>>();
        let retired = staged.retired.iter().copied().collect::<BTreeSet<_>>();
        let expected_created = next_ids.difference(&active_ids).copied().collect::<BTreeSet<_>>();
        let expected_retired = active_ids.difference(&next_ids).copied().collect::<BTreeSet<_>>();
        if created != expected_created || retired != expected_retired {
            return Err(ReceiverKeyAccumulatorError::StorageConflict);
        }
        active_ids.union(&next_ids).copied().collect::<BTreeSet<_>>()
    } else {
        active_ids
    };
    if u64::try_from(reachable.len()).map_err(|_| ReceiverKeyAccumulatorError::InvalidNodeCount)?
        != expected_count
    {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    Ok((active, staged))
}

fn authenticate_transaction_heads(
    transaction: &redb::WriteTransaction,
    mac_key: &[u8; 32],
    expected_active: &DurableActiveHead,
    expected_staged: Option<&DurableStagedHead>,
) -> Result<(), ReceiverKeyAccumulatorError> {
    let heads = transaction.open_table(HEAD_TABLE).map_database()?;
    authenticate_head_table(&heads, mac_key, expected_active, expected_staged)
}

fn authenticate_live_heads(
    database: &Database,
    mac_key: &[u8; 32],
    expected_active: &DurableActiveHead,
    expected_staged: Option<&DurableStagedHead>,
) -> Result<(), ReceiverKeyAccumulatorError> {
    let transaction = database.begin_read().map_database()?;
    let heads = transaction.open_table(HEAD_TABLE).map_database()?;
    authenticate_head_table(&heads, mac_key, expected_active, expected_staged)
}

fn authenticate_head_table<T: ReadableTable<&'static [u8], &'static [u8]>>(
    heads: &T,
    mac_key: &[u8; 32],
    expected_active: &DurableActiveHead,
    expected_staged: Option<&DurableStagedHead>,
) -> Result<(), ReceiverKeyAccumulatorError> {
    let active_bytes = read_bounded_table_value(heads, ACTIVE_HEAD_KEY, MAX_ACTIVE_HEAD_BYTES)?
        .ok_or(ReceiverKeyAccumulatorError::StorageConflict)?;
    let staged_bytes = read_bounded_table_value(heads, STAGED_HEAD_KEY, MAX_STAGED_HEAD_BYTES)?;
    let expected_head_count = 1_u64 + u64::from(expected_staged.is_some());
    if heads.len().map_database()? != expected_head_count {
        return Err(ReceiverKeyAccumulatorError::StorageConflict);
    }
    let active: DurableActiveHead =
        decode_authenticated(mac_key, ACTIVE_HEAD_LABEL, &active_bytes, MAX_ACTIVE_HEAD_BYTES)?;
    let staged = staged_bytes
        .as_deref()
        .map(|bytes| {
            decode_authenticated::<DurableStagedHead>(
                mac_key,
                STAGED_HEAD_LABEL,
                bytes,
                MAX_STAGED_HEAD_BYTES,
            )
        })
        .transpose()?;
    if &active != expected_active || staged.as_ref() != expected_staged {
        return Err(ReceiverKeyAccumulatorError::StorageConflict);
    }
    Ok(())
}

fn validate_active_head(
    network: [u8; 32],
    bootstrap_digest: [u8; 32],
    head: &DurableActiveHead,
) -> Result<(), ReceiverKeyAccumulatorError> {
    if head.version != DURABLE_HEAD_VERSION
        || head.network != network
        || head.bootstrap_digest != bootstrap_digest
        || head.commitment.network != network
    {
        return Err(ReceiverKeyAccumulatorError::StorageConflict);
    }
    head.commitment.validate()?;
    validate_ref_shape(head.root)?;
    if lift_ref(network, head.root, 0)? != head.commitment.root
        || head.node_count != expected_node_count(head.commitment.leaf_count)?
    {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    Ok(())
}

fn validate_staged_head(
    network: [u8; 32],
    active: &DurableActiveHead,
    staged: &DurableStagedHead,
) -> Result<(), ReceiverKeyAccumulatorError> {
    staged.binding.validate()?;
    let selected_count = usize::from(staged.selected_count);
    let expected_revision =
        active.revision.checked_add(1).ok_or(ReceiverKeyAccumulatorError::RevisionExhausted)?;
    let expected_epoch = active
        .commitment
        .through_epoch
        .checked_add(1)
        .ok_or(ReceiverKeyAccumulatorError::WrongTargetEpoch)?;
    let expected_leaves = active
        .commitment
        .leaf_count
        .checked_add(selected_count as u64)
        .ok_or(ReceiverKeyAccumulatorError::LeafCountExhausted)?;
    if staged.version != STAGED_HEAD_VERSION
        || staged.prior_revision != active.revision
        || staged.prior != active.commitment
        || staged.selection_digest == [0_u8; 32]
        || staged.proof_digest == [0_u8; 32]
        || selected_count == 0
        || selected_count > MAX_COMMITTEE_MEMBERS
        || staged.created.len() > MAX_CHANGED_NODES
        || staged.retired.len() > MAX_CHANGED_NODES
        || staged.next.revision != expected_revision
        || staged.next.bootstrap_digest != active.bootstrap_digest
        || staged.next.commitment.through_epoch != expected_epoch
        || staged.next.commitment.leaf_count != expected_leaves
    {
        return Err(ReceiverKeyAccumulatorError::StorageConflict);
    }
    validate_active_head(network, active.bootstrap_digest, &staged.next)?;
    validate_node_delta(staged.created.len(), staged.retired.len(), selected_count)?;
    let created = staged.created.iter().copied().collect::<BTreeSet<_>>();
    let retired = staged.retired.iter().copied().collect::<BTreeSet<_>>();
    if created.len() != staged.created.len()
        || retired.len() != staged.retired.len()
        || !created.is_disjoint(&retired)
    {
        return Err(ReceiverKeyAccumulatorError::StorageConflict);
    }
    Ok(())
}

fn public_staged(staged: &DurableStagedHead) -> ReceiverKeyAccumulatorStagedUpdate {
    ReceiverKeyAccumulatorStagedUpdate {
        binding: staged.binding,
        prior: staged.prior,
        next: staged.next.commitment,
    }
}

fn validate_node_delta(
    created: usize,
    retired: usize,
    selected: usize,
) -> Result<(), ReceiverKeyAccumulatorError> {
    let expected_delta =
        selected.checked_mul(2).ok_or(ReceiverKeyAccumulatorError::ChangedNodeLimit)?;
    if created > MAX_CHANGED_NODES
        || retired > MAX_CHANGED_NODES
        || created.checked_sub(retired) != Some(expected_delta)
    {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    Ok(())
}

fn expected_node_count(leaf_count: u64) -> Result<u64, ReceiverKeyAccumulatorError> {
    leaf_count
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(ReceiverKeyAccumulatorError::InvalidNodeCount)
}

fn build_initial_state(
    network: [u8; 32],
    through_epoch: u64,
    keys: &[(PartyId, [u8; 32])],
) -> Result<(DurableActiveHead, BTreeMap<NodeId, PatriciaNodeRecord>), ReceiverKeyAccumulatorError>
{
    validate_bootstrap_keys(network, keys)?;
    let mut canonical = keys.to_vec();
    canonical.sort_unstable_by_key(|(_, key)| receiver_key_path(network, *key));
    let mut overlay = PatriciaOverlay::new(network);
    let mut root = None;
    let mut absent = |_id: NodeId| Err(ReceiverKeyAccumulatorError::MissingNode);
    for (party, key) in canonical {
        root = Some(overlay.insert(root, party, key, through_epoch, &mut absent)?);
    }
    let root = root.ok_or(ReceiverKeyAccumulatorError::InvalidBootstrapSet)?;
    retain_reachable_overlay(root, &mut overlay.writes, &mut overlay.retired)?;
    if !overlay.retired.is_empty() {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    let commitment = ReceiverKeyAccumulatorCommitment {
        version: ACCUMULATOR_VERSION,
        network,
        through_epoch,
        leaf_count: keys.len() as u64,
        root: lift_ref(network, root, 0)?,
    };
    commitment.validate()?;
    let node_count = u64::try_from(overlay.writes.len())
        .map_err(|_| ReceiverKeyAccumulatorError::InvalidNodeCount)?;
    if node_count != expected_node_count(commitment.leaf_count)? {
        return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
    }
    let head = DurableActiveHead {
        version: DURABLE_HEAD_VERSION,
        network,
        bootstrap_digest: commitment.digest(),
        revision: 0,
        commitment,
        root,
        node_count,
    };
    Ok((head, overlay.writes))
}

fn contains_path<F>(
    network: [u8; 32],
    mut current: PatriciaRef,
    key: [u8; 32],
    load: &mut F,
) -> Result<bool, ReceiverKeyAccumulatorError>
where
    F: FnMut(NodeId) -> Result<PatriciaNodeRecord, ReceiverKeyAccumulatorError>,
{
    let path = receiver_key_path(network, key);
    loop {
        if common_prefix_len(path, current.prefix, usize::from(current.depth))
            < usize::from(current.depth)
        {
            return Ok(false);
        }
        let record = load(current.id)?;
        validate_node_record(network, current, &record)?;
        match record {
            PatriciaNodeRecord::Leaf { receiver_key, .. } => {
                if receiver_key != key {
                    return Err(ReceiverKeyAccumulatorError::PathCollision);
                }
                return Ok(true);
            }
            PatriciaNodeRecord::Branch { depth, left, right, .. } => {
                current = if bit_at(path, usize::from(depth)) { right } else { left };
            }
        }
    }
}

fn non_membership_path<F>(
    network: [u8; 32],
    mut current: PatriciaRef,
    key: [u8; 32],
    load: &mut F,
) -> Result<Vec<[u8; 32]>, ReceiverKeyAccumulatorError>
where
    F: FnMut(NodeId) -> Result<PatriciaNodeRecord, ReceiverKeyAccumulatorError>,
{
    let path = receiver_key_path(network, key);
    let defaults = default_hashes(network);
    let mut siblings = (0..TREE_DEPTH).map(|depth| defaults[depth + 1]).collect::<Vec<_>>();
    loop {
        let current_depth = usize::from(current.depth);
        let common = common_prefix_len(path, current.prefix, current_depth);
        if common < current_depth {
            siblings[common] = lift_ref(network, current, common + 1)?;
            return Ok(siblings);
        }
        let record = load(current.id)?;
        validate_node_record(network, current, &record)?;
        match record {
            PatriciaNodeRecord::Leaf { receiver_key, .. } => {
                return if receiver_key == key {
                    Err(ReceiverKeyAccumulatorError::KeyAlreadyUsed)
                } else {
                    Err(ReceiverKeyAccumulatorError::PathCollision)
                };
            }
            PatriciaNodeRecord::Branch { depth, left, right, .. } => {
                let depth = usize::from(depth);
                if bit_at(path, depth) {
                    siblings[depth] = lift_ref(network, left, depth + 1)?;
                    current = right;
                } else {
                    siblings[depth] = lift_ref(network, right, depth + 1)?;
                    current = left;
                }
            }
        }
    }
}

fn reference_for_record(
    network: [u8; 32],
    record: &PatriciaNodeRecord,
) -> Result<PatriciaRef, ReceiverKeyAccumulatorError> {
    let (depth, prefix, sparse_hash) = match record {
        PatriciaNodeRecord::Leaf {
            version,
            network: record_network,
            path,
            party,
            receiver_key,
            first_epoch,
        } => {
            if *version != PATRICIA_NODE_VERSION
                || *record_network != network
                || party.0 == 0
                || *receiver_key == [0_u8; 32]
                || receiver_key_path(network, *receiver_key) != *path
            {
                return Err(ReceiverKeyAccumulatorError::InvalidNode);
            }
            (
                TREE_DEPTH as u16,
                *path,
                receiver_key_leaf_hash(network, *path, *party, *receiver_key, *first_epoch),
            )
        }
        PatriciaNodeRecord::Branch {
            version,
            network: record_network,
            depth,
            prefix,
            left,
            right,
        } => {
            let depth_usize = usize::from(*depth);
            if *version != PATRICIA_NODE_VERSION
                || *record_network != network
                || depth_usize >= TREE_DEPTH
                || masked_prefix(*prefix, depth_usize) != *prefix
            {
                return Err(ReceiverKeyAccumulatorError::InvalidNode);
            }
            validate_ref_shape(*left)?;
            validate_ref_shape(*right)?;
            if usize::from(left.depth) <= depth_usize
                || usize::from(right.depth) <= depth_usize
                || masked_prefix(left.prefix, depth_usize) != *prefix
                || masked_prefix(right.prefix, depth_usize) != *prefix
                || bit_at(left.prefix, depth_usize)
                || !bit_at(right.prefix, depth_usize)
            {
                return Err(ReceiverKeyAccumulatorError::InvalidNode);
            }
            let left_hash = lift_ref(network, *left, depth_usize + 1)?;
            let right_hash = lift_ref(network, *right, depth_usize + 1)?;
            (*depth, *prefix, receiver_key_node_hash(network, depth_usize, left_hash, right_hash))
        }
    };
    let encoded = encode_canonical(record)?;
    if encoded.len() > MAX_NODE_RECORD_BYTES {
        return Err(ReceiverKeyAccumulatorError::InvalidNode);
    }
    let mut hasher = blake3::Hasher::new_derive_key(STORAGE_NODE_DOMAIN);
    hasher.update(&network);
    hasher.update(&encoded);
    let id = NodeId(*hasher.finalize().as_bytes());
    Ok(PatriciaRef { id, depth, prefix, sparse_hash })
}

fn validate_node_record(
    network: [u8; 32],
    expected: PatriciaRef,
    record: &PatriciaNodeRecord,
) -> Result<(), ReceiverKeyAccumulatorError> {
    if reference_for_record(network, record)? != expected {
        return Err(ReceiverKeyAccumulatorError::InvalidNode);
    }
    Ok(())
}

fn validate_ref_shape(reference: PatriciaRef) -> Result<(), ReceiverKeyAccumulatorError> {
    let depth = usize::from(reference.depth);
    if depth > TREE_DEPTH
        || reference.id.0 == [0_u8; 32]
        || reference.sparse_hash == [0_u8; 32]
        || masked_prefix(reference.prefix, depth) != reference.prefix
    {
        return Err(ReceiverKeyAccumulatorError::InvalidNode);
    }
    Ok(())
}

fn lift_ref(
    network: [u8; 32],
    reference: PatriciaRef,
    target_depth: usize,
) -> Result<[u8; 32], ReceiverKeyAccumulatorError> {
    validate_ref_shape(reference)?;
    let native_depth = usize::from(reference.depth);
    if target_depth > native_depth {
        return Err(ReceiverKeyAccumulatorError::InvalidNode);
    }
    let defaults = default_hashes(network);
    let mut current = reference.sparse_hash;
    for depth in (target_depth..native_depth).rev() {
        let empty = defaults[depth + 1];
        current = if bit_at(reference.prefix, depth) {
            receiver_key_node_hash(network, depth, empty, current)
        } else {
            receiver_key_node_hash(network, depth, current, empty)
        };
    }
    Ok(current)
}

fn load_node<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    id: NodeId,
) -> Result<PatriciaNodeRecord, ReceiverKeyAccumulatorError> {
    let value = table
        .get(id.0.as_slice())
        .map_database()?
        .ok_or(ReceiverKeyAccumulatorError::MissingNode)?;
    let bytes = value.value();
    if bytes.len() > MAX_NODE_RECORD_BYTES {
        return Err(ReceiverKeyAccumulatorError::StorageValueTooLarge);
    }
    decode_canonical(bytes, MAX_NODE_RECORD_BYTES)
}

fn reachable_node_ids<T: ReadableTable<&'static [u8], &'static [u8]>>(
    network: [u8; 32],
    table: &T,
    root: PatriciaRef,
    maximum: u64,
) -> Result<BTreeSet<NodeId>, ReceiverKeyAccumulatorError> {
    let mut reachable = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(reference) = pending.pop() {
        if !reachable.insert(reference.id) {
            return Err(ReceiverKeyAccumulatorError::InvalidNode);
        }
        if u64::try_from(reachable.len())
            .map_err(|_| ReceiverKeyAccumulatorError::InvalidNodeCount)?
            > maximum
        {
            return Err(ReceiverKeyAccumulatorError::InvalidNodeCount);
        }
        let record = load_node(table, reference.id)?;
        validate_node_record(network, reference, &record)?;
        if let PatriciaNodeRecord::Branch { left, right, .. } = record {
            pending.push(left);
            pending.push(right);
        }
    }
    Ok(reachable)
}

fn validate_stored_node_id<T: ReadableTable<&'static [u8], &'static [u8]>>(
    network: [u8; 32],
    table: &T,
    id: NodeId,
) -> Result<(), ReceiverKeyAccumulatorError> {
    let record = load_node(table, id)?;
    if reference_for_record(network, &record)?.id != id {
        return Err(ReceiverKeyAccumulatorError::InvalidNode);
    }
    Ok(())
}

fn validate_selected(selected: &[(PartyId, [u8; 32])]) -> Result<(), ReceiverKeyAccumulatorError> {
    if selected.is_empty() || selected.len() > MAX_COMMITTEE_MEMBERS {
        return Err(ReceiverKeyAccumulatorError::InvalidProofShape);
    }
    let mut parties = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut previous_party = None;
    for (party, key) in selected {
        if party.0 == 0 {
            return Err(ReceiverKeyAccumulatorError::InvalidParty);
        }
        if key == &[0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidKey);
        }
        if !parties.insert(*party) || !keys.insert(*key) {
            return Err(ReceiverKeyAccumulatorError::DuplicateSelection);
        }
        if previous_party.is_some_and(|previous| previous >= *party) {
            return Err(ReceiverKeyAccumulatorError::NonCanonicalSelection);
        }
        previous_party = Some(*party);
    }
    Ok(())
}

fn validate_bootstrap_keys(
    network: [u8; 32],
    keys: &[(PartyId, [u8; 32])],
) -> Result<(), ReceiverKeyAccumulatorError> {
    if network == [0_u8; 32] || keys.is_empty() || keys.len() > MAX_COMMITTEE_MEMBERS {
        return Err(ReceiverKeyAccumulatorError::InvalidBootstrapSet);
    }
    let mut parties = BTreeSet::new();
    let mut receiver_keys = BTreeSet::new();
    for (party, key) in keys {
        if party.0 == 0 {
            return Err(ReceiverKeyAccumulatorError::InvalidParty);
        }
        if key == &[0_u8; 32] {
            return Err(ReceiverKeyAccumulatorError::InvalidKey);
        }
        if !parties.insert(*party) || !receiver_keys.insert(*key) {
            return Err(ReceiverKeyAccumulatorError::DuplicateSelection);
        }
    }
    Ok(())
}

fn selection_digest(
    selected: &[(PartyId, [u8; 32])],
) -> Result<[u8; 32], ReceiverKeyAccumulatorError> {
    validate_selected(selected)?;
    let mut hasher = blake3::Hasher::new_derive_key(SELECTION_DIGEST_DOMAIN);
    hasher.update(&(selected.len() as u64).to_le_bytes());
    for (party, key) in selected {
        hasher.update(&party.0.to_le_bytes());
        hasher.update(key);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn proof_digest(
    proof: &ReceiverKeyBatchUpdateProof,
) -> Result<[u8; 32], ReceiverKeyAccumulatorError> {
    let encoded = proof.to_bytes()?;
    let mut hasher = blake3::Hasher::new_derive_key(PROOF_DIGEST_DOMAIN);
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
fn test_binding(
    proof: &ReceiverKeyBatchUpdateProof,
) -> Result<ReceiverKeyStageBinding, ReceiverKeyAccumulatorError> {
    ReceiverKeyStageBinding::from_digest(proof_digest(proof)?)
}

fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ReceiverKeyAccumulatorError> {
    postcard::to_allocvec(value).map_err(|_| ReceiverKeyAccumulatorError::Serialization)
}

fn decode_canonical<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, ReceiverKeyAccumulatorError> {
    if bytes.len() > maximum {
        return Err(ReceiverKeyAccumulatorError::ProofTooLarge);
    }
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| ReceiverKeyAccumulatorError::Serialization)?;
    if !trailing.is_empty() {
        return Err(ReceiverKeyAccumulatorError::TrailingBytes);
    }
    if encode_canonical(&value)? != bytes {
        return Err(ReceiverKeyAccumulatorError::NonCanonicalEncoding);
    }
    Ok(value)
}

fn deserialize_changed_node_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<NodeId>, D::Error> {
    struct NodeIdsVisitor;

    impl<'de> Visitor<'de> for NodeIdsVisitor {
        type Value = Vec<NodeId>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_CHANGED_NODES} changed Patricia node identifiers")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > MAX_CHANGED_NODES) {
                return Err(A::Error::custom(
                    "receiver-key stage has too many changed node identifiers",
                ));
            }
            let mut ids =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_CHANGED_NODES));
            while let Some(id) = sequence.next_element()? {
                if ids.len() == MAX_CHANGED_NODES {
                    return Err(A::Error::custom(
                        "receiver-key stage has too many changed node identifiers",
                    ));
                }
                ids.push(id);
            }
            Ok(ids)
        }
    }

    deserializer.deserialize_seq(NodeIdsVisitor)
}

fn deserialize_receiver_key_path_siblings<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<[u8; 32]>, D::Error> {
    struct SiblingsVisitor;

    impl<'de> Visitor<'de> for SiblingsVisitor {
        type Value = Vec<[u8; 32]>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "exactly {TREE_DEPTH} sparse-Merkle sibling hashes")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > TREE_DEPTH) {
                return Err(A::Error::custom("receiver-key path has too many sibling hashes"));
            }
            let mut siblings =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(TREE_DEPTH));
            while let Some(sibling) = sequence.next_element()? {
                if siblings.len() == TREE_DEPTH {
                    return Err(A::Error::custom("receiver-key path has too many sibling hashes"));
                }
                siblings.push(sibling);
            }
            if siblings.len() != TREE_DEPTH {
                return Err(A::Error::custom(
                    "receiver-key path must contain exactly 256 sibling hashes",
                ));
            }
            Ok(siblings)
        }
    }

    deserializer.deserialize_seq(SiblingsVisitor)
}

fn deserialize_receiver_key_paths<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ReceiverKeyNonMembershipPath>, D::Error> {
    struct PathsVisitor;

    impl<'de> Visitor<'de> for PathsVisitor {
        type Value = Vec<ReceiverKeyNonMembershipPath>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_COMMITTEE_MEMBERS} receiver-key non-membership paths")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > MAX_COMMITTEE_MEMBERS) {
                return Err(A::Error::custom(
                    "receiver-key batch has too many non-membership paths",
                ));
            }
            let mut paths =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_COMMITTEE_MEMBERS));
            while let Some(path) = sequence.next_element()? {
                if paths.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::custom(
                        "receiver-key batch has too many non-membership paths",
                    ));
                }
                paths.push(path);
            }
            Ok(paths)
        }
    }

    deserializer.deserialize_seq(PathsVisitor)
}

fn receiver_key_path(network: [u8; 32], key: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PATH_DOMAIN);
    hasher.update(&network);
    hasher.update(&key);
    *hasher.finalize().as_bytes()
}

fn receiver_key_leaf_hash(
    network: [u8; 32],
    path: [u8; 32],
    party: PartyId,
    key: [u8; 32],
    first_epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(LEAF_DOMAIN);
    hasher.update(&network);
    hasher.update(&path);
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&key);
    hasher.update(&first_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn receiver_key_node_hash(
    network: [u8; 32],
    depth: usize,
    left: [u8; 32],
    right: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(NODE_DOMAIN);
    hasher.update(&network);
    hasher.update(&(depth as u16).to_le_bytes());
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

fn default_hashes(network: [u8; 32]) -> Arc<Vec<[u8; 32]>> {
    DEFAULT_HASH_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some((cached_network, defaults)) = cache.as_ref()
            && *cached_network == network
        {
            return defaults.clone();
        }
        let mut defaults = vec![[0_u8; 32]; TREE_DEPTH + 1];
        let mut leaf = blake3::Hasher::new_derive_key(EMPTY_LEAF_DOMAIN);
        leaf.update(&network);
        defaults[TREE_DEPTH] = *leaf.finalize().as_bytes();
        for depth in (0..TREE_DEPTH).rev() {
            defaults[depth] =
                receiver_key_node_hash(network, depth, defaults[depth + 1], defaults[depth + 1]);
        }
        let defaults = Arc::new(defaults);
        *cache = Some((network, defaults.clone()));
        defaults
    })
}

fn common_prefix_len(left: [u8; 32], right: [u8; 32], maximum: usize) -> usize {
    (0..maximum).find(|depth| bit_at(left, *depth) != bit_at(right, *depth)).unwrap_or(maximum)
}

fn masked_prefix(mut path: [u8; 32], depth: usize) -> [u8; 32] {
    debug_assert!(depth <= TREE_DEPTH);
    let full = depth / 8;
    let remainder = depth % 8;
    if remainder == 0 {
        for byte in &mut path[full..] {
            *byte = 0;
        }
    } else {
        path[full] &= 0xff_u8 << (8 - remainder);
        for byte in &mut path[full + 1..] {
            *byte = 0;
        }
    }
    path
}

fn bit_at(path: [u8; 32], depth: usize) -> bool {
    ((path[depth / 8] >> (7 - depth % 8)) & 1) == 1
}

fn toggle_bit(path: &mut [u8; 32], depth: usize) {
    path[depth / 8] ^= 1 << (7 - depth % 8);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};
    use serde::Deserialize;
    use tempfile::{TempDir, tempdir};

    use super::*;

    fn keys(start: u8, count: u16) -> Vec<(PartyId, [u8; 32])> {
        (1..=count).map(|party| (PartyId(party), [start.wrapping_add(party as u8); 32])).collect()
    }

    fn binding(byte: u8) -> ReceiverKeyStageBinding {
        ReceiverKeyStageBinding::from_digest([byte; 32]).unwrap()
    }

    fn postcard_usize(mut value: usize) -> Vec<u8> {
        let mut encoded = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            encoded.push(byte);
            if value == 0 {
                return encoded;
            }
        }
    }

    fn test_store(
        network: [u8; 32],
        initial: &[(PartyId, [u8; 32])],
    ) -> (TempDir, ReceiverKeyAccumulatorStore) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let authentication_key = blake3::derive_key(
            "threshold-monero/receiver-key-accumulator/test-storage-auth/v1",
            &network,
        );
        let store =
            ReceiverKeyAccumulatorStore::open(path, network, initial, &authentication_key).unwrap();
        (directory, store)
    }

    #[derive(Clone)]
    struct FullSparseReference {
        network: [u8; 32],
        through_epoch: u64,
        leaf_count: u64,
        nodes: BTreeMap<NodePosition, [u8; 32]>,
    }

    impl FullSparseReference {
        fn new(network: [u8; 32], initial: &[(PartyId, [u8; 32])]) -> Self {
            let mut reference =
                Self { network, through_epoch: 0, leaf_count: 0, nodes: BTreeMap::new() };
            for (party, key) in initial {
                reference.insert(*party, *key, 0);
            }
            reference
        }

        fn insert(&mut self, party: PartyId, key: [u8; 32], epoch: u64) {
            let defaults = default_hashes(self.network);
            let path = receiver_key_path(self.network, key);
            let mut current = receiver_key_leaf_hash(self.network, path, party, key, epoch);
            self.nodes.insert(NodePosition::for_path(path, TREE_DEPTH), current);
            for depth in (0..TREE_DEPTH).rev() {
                let sibling = self
                    .nodes
                    .get(&NodePosition::sibling(path, depth))
                    .copied()
                    .unwrap_or(defaults[depth + 1]);
                current = if bit_at(path, depth) {
                    receiver_key_node_hash(self.network, depth, sibling, current)
                } else {
                    receiver_key_node_hash(self.network, depth, current, sibling)
                };
                self.nodes.insert(NodePosition::for_path(path, depth), current);
            }
            self.leaf_count += 1;
            self.through_epoch = epoch;
        }

        fn commitment(&self) -> ReceiverKeyAccumulatorCommitment {
            ReceiverKeyAccumulatorCommitment {
                version: ACCUMULATOR_VERSION,
                network: self.network,
                through_epoch: self.through_epoch,
                leaf_count: self.leaf_count,
                root: self.nodes[&NodePosition::for_path([0_u8; 32], 0)],
            }
        }
    }

    #[test]
    fn batch_update_is_bounded_and_rejects_reuse_across_owners() {
        let network = [0x41; 32];
        let (_directory, mut store) = test_store(network, &keys(10, 10));
        let next = keys(40, 10);
        let proof = store.prove_and_apply(1, &next).unwrap();
        assert!(proof.to_bytes().unwrap().len() <= MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES);
        assert_eq!(proof.next(), store.commitment());
        assert_eq!(
            store.preview(2, &[(PartyId(1), next[7].1)]).unwrap_err(),
            ReceiverKeyAccumulatorError::KeyAlreadyUsed
        );
    }

    #[test]
    fn proof_tampering_and_wrong_predecessor_fail_closed() {
        let network = [0x51; 32];
        let (_directory, store) = test_store(network, &keys(5, 4));
        let selected = keys(50, 4);
        let (proof, _) = store.preview(1, &selected).unwrap();
        let mut wrong = proof.clone();
        wrong.paths[0].siblings[0][0] ^= 1;
        assert!(wrong.verify(&store.commitment(), 1, &selected).is_err());

        let (_other_directory, other) = test_store([0x52; 32], &keys(5, 4));
        assert!(proof.verify(&other.commitment(), 1, &selected).is_err());
    }

    #[test]
    fn bootstrap_order_is_irrelevant_and_matches_full_sparse_reference() {
        let network = [0x5a; 32];
        let canonical = keys(5, 10);
        let mut reordered = canonical.clone();
        reordered.reverse();
        let expected = FullSparseReference::new(network, &canonical).commitment();
        assert_eq!(
            ReceiverKeyAccumulatorCommitment::from_bootstrap_keys(network, &canonical).unwrap(),
            expected
        );
        assert_eq!(
            ReceiverKeyAccumulatorCommitment::from_bootstrap_keys(network, &reordered).unwrap(),
            expected
        );
    }

    #[test]
    fn randomized_patricia_roots_equal_full_sparse_reference() {
        let network = [0x63; 32];
        let initial = keys(1, 4);
        let (_directory, mut store) = test_store(network, &initial);
        let mut reference = FullSparseReference::new(network, &initial);
        let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
        for epoch in 1_u64..=64 {
            let selected = (1_u16..=4)
                .map(|party| {
                    let mut key = [0_u8; 32];
                    rng.fill_bytes(&mut key);
                    key[0] |= 1;
                    (PartyId(party), key)
                })
                .collect::<Vec<_>>();
            let proof = store.prove_and_apply(epoch, &selected).unwrap();
            proof.verify(&reference.commitment(), epoch, &selected).unwrap();
            for (party, key) in selected {
                reference.insert(party, key, epoch);
            }
            assert_eq!(store.commitment(), reference.commitment());
            assert_eq!(store.live_node_count(), 2 * store.commitment().leaf_count() - 1);
            assert_eq!(store.stored_node_count().unwrap(), store.live_node_count());
        }
    }

    #[test]
    fn durable_stage_survives_reopen_and_promotes_with_exact_node_count() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x71; 32];
        let initial = keys(1, 4);
        let authentication_key = [0xa1; 32];
        let selected = keys(30, 4);
        let expected;
        {
            let mut store =
                ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                    .unwrap();
            let prior = store.commitment();
            let (proof, preview) = store.preview(1, &selected).unwrap();
            expected = preview.commitment();
            store.stage_verified_update(1, &selected, &proof, binding(1)).unwrap();
            assert_eq!(store.commitment(), prior);
            assert_eq!(store.staged_update().unwrap().next(), expected);
            assert!(store.stored_node_count().unwrap() > store.live_node_count());
        }
        {
            let mut reopened =
                ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                    .unwrap();
            assert_eq!(reopened.staged_update().unwrap().next(), expected);
            let prior = reopened.commitment();
            assert_eq!(
                reopened.reconcile_staged(prior, Some(binding(1))).unwrap(),
                ReceiverKeyAccumulatorReconcile::Retained(reopened.staged_update().unwrap())
            );
            assert_eq!(
                reopened.reconcile_staged(expected, Some(binding(1))).unwrap(),
                ReceiverKeyAccumulatorReconcile::Promoted(expected)
            );
            assert_eq!(reopened.stored_node_count().unwrap(), reopened.live_node_count());
        }
        let reopened =
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap();
        assert_eq!(reopened.commitment(), expected);
        assert!(reopened.staged_update().is_none());
    }

    #[test]
    fn exact_staged_retry_authenticates_without_reverifying_the_proof() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x7c; 32];
        let initial = keys(1, 4);
        let authentication_key = [0x61; 32];
        let selected = keys(30, 4);
        let stage_binding = binding(9);
        let proof;
        {
            let mut store =
                ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                    .unwrap();
            proof = store.preview(1, &selected).unwrap().0;
            assert_eq!(store.external_proof_verification_count(), 0);
            let expected =
                store.stage_verified_update(1, &selected, &proof, stage_binding).unwrap();
            assert_eq!(store.external_proof_verification_count(), 1);
            assert_eq!(
                store.stage_verified_update(1, &selected, &proof, stage_binding).unwrap(),
                expected
            );
            assert_eq!(store.external_proof_verification_count(), 1);

            let mut changed_proof = proof.clone();
            changed_proof.paths[0].siblings[0][0] ^= 1;
            assert_eq!(
                store
                    .stage_verified_update(1, &selected, &changed_proof, stage_binding)
                    .unwrap_err(),
                ReceiverKeyAccumulatorError::StagedUpdateConflict
            );
            let mut changed_selection = selected.clone();
            changed_selection[0].1[0] ^= 1;
            assert_eq!(
                store
                    .stage_verified_update(1, &changed_selection, &proof, stage_binding)
                    .unwrap_err(),
                ReceiverKeyAccumulatorError::StagedUpdateConflict
            );
            assert_eq!(
                store.stage_verified_update(1, &selected, &proof, binding(10)).unwrap_err(),
                ReceiverKeyAccumulatorError::StagedUpdateConflict
            );
            assert_eq!(store.external_proof_verification_count(), 1);
        }

        let mut reopened =
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap();
        assert_eq!(reopened.external_proof_verification_count(), 0);
        reopened.stage_verified_update(1, &selected, &proof, stage_binding).unwrap();
        assert_eq!(
            reopened.external_proof_verification_count(),
            0,
            "the authenticated durable stage is the proof authority for an exact restart retry"
        );
    }

    #[test]
    fn reopen_rejects_missing_descendant_hidden_by_orphan_padding() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x7d; 32];
        let initial = keys(1, 4);
        let authentication_key = [0x71; 32];
        let store =
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap();
        let victim = {
            let transaction = store.database.begin_read().unwrap();
            let nodes = transaction.open_table(NODE_TABLE).unwrap();
            match load_node(&nodes, store.active.root.id).unwrap() {
                PatriciaNodeRecord::Branch { left, .. } => left.id,
                PatriciaNodeRecord::Leaf { .. } => panic!("four bootstrap keys require a branch"),
            }
        };
        let orphan_record = PatriciaNodeRecord::Leaf {
            version: PATRICIA_NODE_VERSION,
            network,
            path: receiver_key_path(network, [0xee; 32]),
            party: PartyId(99),
            receiver_key: [0xee; 32],
            first_epoch: 99,
        };
        let orphan = reference_for_record(network, &orphan_record).unwrap();
        assert_ne!(orphan.id, victim);
        {
            let mut transaction = store.database.begin_write().unwrap();
            configure_write(&mut transaction);
            {
                let mut nodes = transaction.open_table(NODE_TABLE).unwrap();
                assert!(nodes.remove(victim.0.as_slice()).unwrap().is_some());
                assert!(nodes.get(orphan.id.0.as_slice()).unwrap().is_none());
                let encoded = encode_canonical(&orphan_record).unwrap();
                nodes.insert(orphan.id.0.as_slice(), encoded.as_slice()).unwrap();
                assert_eq!(nodes.len().unwrap(), store.active.node_count);
            }
            transaction.commit().unwrap();
        }
        drop(store);

        assert_eq!(
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap_err(),
            ReceiverKeyAccumulatorError::MissingNode
        );
    }

    #[test]
    fn conflicting_stage_fails_and_uncertified_stage_can_be_discarded() {
        let network = [0x72; 32];
        let (_directory, mut store) = test_store(network, &keys(1, 4));
        let selected = keys(20, 4);
        let (proof, _) = store.preview(1, &selected).unwrap();
        let prior = store.commitment();
        store.stage_verified_update(1, &selected, &proof, binding(2)).unwrap();
        assert_eq!(
            store.stage_verified_update(1, &selected, &proof, binding(3)).unwrap_err(),
            ReceiverKeyAccumulatorError::StagedUpdateConflict
        );
        assert_eq!(
            store.reconcile_staged(prior, None).unwrap_err(),
            ReceiverKeyAccumulatorError::MissingStageAuthority
        );
        store.discard_staged(binding(2)).unwrap();
        assert_eq!(store.commitment(), prior);
        assert_eq!(store.stored_node_count().unwrap(), store.live_node_count());
    }

    #[test]
    fn staged_discard_survives_restart_without_changing_the_active_root() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x78; 32];
        let initial = keys(1, 4);
        let authentication_key = [0x31; 32];
        let prior;
        {
            let mut store =
                ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                    .unwrap();
            prior = store.commitment();
            let selected = keys(20, 4);
            let (proof, _) = store.preview(1, &selected).unwrap();
            store.stage_verified_update(1, &selected, &proof, binding(8)).unwrap();
        }
        {
            let mut reopened =
                ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                    .unwrap();
            reopened.discard_staged(binding(8)).unwrap();
            assert_eq!(reopened.commitment(), prior);
            assert_eq!(reopened.stored_node_count().unwrap(), reopened.live_node_count());
        }
        let reopened =
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap();
        assert_eq!(reopened.commitment(), prior);
        assert!(reopened.staged_update().is_none());
    }

    #[test]
    fn wrong_authentication_key_cannot_open_durable_heads() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x73; 32];
        let initial = keys(1, 4);
        drop(ReceiverKeyAccumulatorStore::open(&path, network, &initial, &[0x11; 32]).unwrap());
        assert_eq!(
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &[0x12; 32]).unwrap_err(),
            ReceiverKeyAccumulatorError::StorageAuthentication
        );
    }

    #[test]
    fn zero_storage_authentication_key_is_rejected_before_file_creation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        assert_eq!(
            ReceiverKeyAccumulatorStore::open(&path, [0x79; 32], &keys(1, 4), &[0_u8; 32])
                .unwrap_err(),
            ReceiverKeyAccumulatorError::InvalidAuthenticationKey
        );
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn accumulator_file_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"must remain untouched").unwrap();
        let path = directory.path().join("receiver-keys.redb");
        symlink(&target, &path).unwrap();

        assert_eq!(
            ReceiverKeyAccumulatorStore::open(&path, [0x7b; 32], &keys(1, 4), &[0x51; 32])
                .unwrap_err(),
            ReceiverKeyAccumulatorError::StorageConflict
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"must remain untouched");
    }

    #[test]
    fn oversized_durable_head_is_rejected_before_reopen_copy() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x74; 32];
        let initial = keys(1, 4);
        let authentication_key = [0x21; 32];
        let store =
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap();
        {
            let mut transaction = store.database.begin_write().unwrap();
            configure_write(&mut transaction);
            {
                let mut heads = transaction.open_table(HEAD_TABLE).unwrap();
                let oversized = vec![0_u8; MAX_ACTIVE_HEAD_BYTES + 1];
                heads.insert(ACTIVE_HEAD_KEY, oversized.as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }
        drop(store);

        assert_eq!(
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap_err(),
            ReceiverKeyAccumulatorError::StorageValueTooLarge
        );
    }

    #[test]
    fn unexpected_durable_head_key_is_not_accepted_as_hidden_state() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("receiver-keys.redb");
        let network = [0x7a; 32];
        let initial = keys(1, 4);
        let authentication_key = [0x41; 32];
        let store =
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap();
        {
            let mut transaction = store.database.begin_write().unwrap();
            configure_write(&mut transaction);
            {
                let mut heads = transaction.open_table(HEAD_TABLE).unwrap();
                heads.insert(b"unexpected".as_slice(), b"hidden".as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }
        drop(store);

        assert_eq!(
            ReceiverKeyAccumulatorStore::open(&path, network, &initial, &authentication_key)
                .unwrap_err(),
            ReceiverKeyAccumulatorError::StorageConflict
        );
    }

    #[test]
    fn durable_vector_decoders_reject_hostile_lengths_before_allocation() {
        #[derive(Deserialize)]
        struct NodeIdsOnly(
            #[serde(deserialize_with = "deserialize_changed_node_ids")]
            #[allow(dead_code)]
            Vec<NodeId>,
        );

        let oversized_body = postcard_usize(MAX_STAGED_HEAD_BYTES + 1);
        assert!(postcard::from_bytes::<AuthenticatedValue<'_>>(&oversized_body).is_err());
        let oversized_node_ids = postcard_usize(MAX_CHANGED_NODES + 1);
        assert!(postcard::from_bytes::<NodeIdsOnly>(&oversized_node_ids).is_err());
    }

    #[test]
    fn oversized_staged_head_and_node_fail_closed_during_live_use() {
        let network = [0x75; 32];
        let (_directory, mut store) = test_store(network, &keys(1, 4));
        let selected = keys(20, 4);
        let (proof, _) = store.preview(1, &selected).unwrap();
        store.stage_verified_update(1, &selected, &proof, binding(5)).unwrap();
        {
            let mut transaction = store.database.begin_write().unwrap();
            configure_write(&mut transaction);
            {
                let mut heads = transaction.open_table(HEAD_TABLE).unwrap();
                let oversized = vec![0_u8; MAX_STAGED_HEAD_BYTES + 1];
                heads.insert(STAGED_HEAD_KEY, oversized.as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert_eq!(
            store.stage_verified_update(1, &selected, &proof, binding(5)).unwrap_err(),
            ReceiverKeyAccumulatorError::StorageValueTooLarge
        );
        assert_eq!(
            store.promote_staged(binding(5)).unwrap_err(),
            ReceiverKeyAccumulatorError::StorageValueTooLarge
        );

        let network = [0x76; 32];
        let (_directory, store) = test_store(network, &keys(1, 4));
        {
            let mut transaction = store.database.begin_write().unwrap();
            configure_write(&mut transaction);
            {
                let mut nodes = transaction.open_table(NODE_TABLE).unwrap();
                let oversized = vec![0_u8; MAX_NODE_RECORD_BYTES + 1];
                nodes.insert(store.active.root.id.0.as_slice(), oversized.as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }
        assert_eq!(
            store.try_contains_key([2_u8; 32]).unwrap_err(),
            ReceiverKeyAccumulatorError::StorageValueTooLarge
        );
    }

    #[test]
    fn staging_refuses_a_competing_authenticated_active_head() {
        let network = [0x77; 32];
        let (_directory, mut store) = test_store(network, &keys(1, 4));
        let selected = keys(20, 4);
        let (proof, _) = store.preview(1, &selected).unwrap();
        let mut competing = store.active.clone();
        competing.revision += 1;
        {
            let mut transaction = store.database.begin_write().unwrap();
            configure_write(&mut transaction);
            {
                let mut heads = transaction.open_table(HEAD_TABLE).unwrap();
                let encoded = encode_authenticated(
                    &store.mac_key,
                    ACTIVE_HEAD_LABEL,
                    &competing,
                    MAX_ACTIVE_HEAD_BYTES,
                )
                .unwrap();
                heads.insert(ACTIVE_HEAD_KEY, encoded.as_slice()).unwrap();
            }
            transaction.commit().unwrap();
        }

        assert_eq!(
            store.stage_verified_update(1, &selected, &proof, binding(7)).unwrap_err(),
            ReceiverKeyAccumulatorError::StorageConflict
        );
        let transaction = store.database.begin_read().unwrap();
        let heads = transaction.open_table(HEAD_TABLE).unwrap();
        assert!(heads.get(STAGED_HEAD_KEY).unwrap().is_none());
    }

    #[test]
    fn encoded_size_does_not_depend_on_prior_epoch_count() {
        let network = [0x61; 32];
        let (_directory, mut store) = test_store(network, &keys(1, 4));
        for epoch in 1_u64..=200 {
            let selected = (1_u16..=4)
                .map(|party| {
                    let mut key = [0_u8; 32];
                    key[..8].copy_from_slice(&epoch.to_le_bytes());
                    key[8..10].copy_from_slice(&party.to_le_bytes());
                    (PartyId(party), key)
                })
                .collect::<Vec<_>>();
            let proof = store.prove_and_apply(epoch, &selected).unwrap();
            assert_eq!(proof.paths.len(), 4);
            assert!(proof.paths.iter().all(|path| path.siblings.len() == TREE_DEPTH));
            assert!(proof.to_bytes().unwrap().len() <= MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES);
        }
    }
}
