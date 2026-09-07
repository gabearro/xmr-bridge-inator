//! Authenticated, unbounded epoch history with a bounded mutable suffix.
//!
//! The epoch history is a protocol safety object, not a cache. Every activation extends a
//! root-linked chain. A transition for epoch `e + 1` must commit to [`EpochHistoryParent`] for
//! epoch `e`; that prevents an activation/reshare certificate from being transplanted onto a
//! forked or truncated history. Old entries are copied into immutable content-addressed objects
//! and indexed by a persistent 64-level binary trie. Consequently, direct historical lookup is
//! bounded by 65 index-node reads plus the entry named by the leaf and does not replay the prefix.
//!
//! Mutations deliberately use a three-step contract:
//!
//! 1. install and fsync every [`StagedEpochHistoryObject`];
//! 2. CAS the exact [`VerifiedEpochHistoryMutation::next_state_bytes`] against
//!    [`VerifiedEpochHistoryMutation::expected_revision`];
//! 3. only after read-back proves that exact CAS won may the caller apply the returned cleanup.
//!
//! A crash before step 2 leaves unreachable, harmless objects. A crash after step 2 leaves
//! redundant hot/source records, and cleanup can be retried. Retirement, identity, high-water,
//! session, and nonce negative records remain in their independently keyed durable stores; epoch
//! compaction never enumerates or deletes them. AVSS successor-supersession closures are local
//! authenticated metadata and never influence the consensus root.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::receiver_key_accumulator::ReceiverKeyAccumulatorCommitment;
use crate::storage::{WalletArtifactKind, WalletArtifactRef, WalletId};

const HISTORY_STATE_VERSION: u16 = 2;
const HISTORY_HEAD_VERSION: u16 = 2;
const HISTORY_ENTRY_VERSION: u16 = 2;
const HISTORY_PARENT_VERSION: u16 = 2;
const HISTORY_REFERENCE_VERSION: u16 = 2;
const HISTORY_INDEX_NODE_VERSION: u16 = 2;
const HISTORY_SUPERSESSION_VERSION: u16 = 2;
const HISTORY_CATCHUP_VERSION: u16 = 2;

const HISTORY_ENTRY_ROOT_DOMAIN: &[u8] = b"threshold-monero/epoch-history/entry-root/v2";
const HISTORY_PARENT_BINDING_DOMAIN: &[u8] = b"threshold-monero/epoch-history/transition-parent/v2";
const HISTORY_GENESIS_ANCHOR_DOMAIN: &[u8] = b"threshold-monero/epoch-history/genesis-anchor/v2";
const HISTORY_OUTBOX_ROOT_DOMAIN: &[u8] = b"threshold-monero/epoch-history/avss-outbox-closure/v2";

/// Maximum number of entries kept in the mutable suffix.
///
/// This is a per-snapshot resource bound, not a lifetime epoch bound. Tests and small deployments
/// may use a policy of one or two epochs.
pub const MAX_HOT_EPOCH_HISTORY_ENTRIES: u16 = 256;
/// Bound on the authenticated mutable epoch-history snapshot.
pub const MAX_EPOCH_HISTORY_STATE_BYTES: usize = 4 * 1024 * 1024;
/// Bound on one canonical epoch entry. Large certificate bytes live in separate objects.
pub const MAX_EPOCH_HISTORY_ENTRY_BYTES: usize = 256 * 1024;
/// Bound matching the current durable activation-certificate format.
pub const MAX_EPOCH_ACTIVATION_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// Bound on one current key-rotation certificate artifact.
pub const MAX_EPOCH_KEY_ROTATION_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// Exact number of trie branches traversed for a `u64` epoch key.
pub const EPOCH_HISTORY_INDEX_DEPTH: u8 = 64;
/// Maximum immutable objects read by one direct cold lookup.
///
/// The authenticated path contains one branch per key bit plus one leaf, followed by the epoch
/// entry named by that leaf. Certificate payloads are fetched separately only when the caller
/// needs them.
pub const MAX_EPOCH_HISTORY_COLD_LOOKUP_OBJECTS: usize = EPOCH_HISTORY_INDEX_DEPTH as usize + 2;
/// Maximum payload carried by one authenticated QUIC history-object response.
pub const MAX_EPOCH_HISTORY_CHUNK_BYTES: u32 = 256 * 1024;
/// Maximum number of object-chunk requests needed to reconstruct one immediate successor.
///
/// A successor names one activation artifact and, at most, one key-rotation artifact. Requiring
/// full-size chunks except for the final chunk makes this a hard request-count bound instead of a
/// hint a Byzantine source can defeat with one-byte replies.
pub const MAX_EPOCH_HISTORY_OBJECT_CHUNKS_PER_SUCCESSOR: usize = MAX_EPOCH_ACTIVATION_ARTIFACT_BYTES
    .div_ceil(MAX_EPOCH_HISTORY_CHUNK_BYTES as usize)
    + MAX_EPOCH_KEY_ROTATION_ARTIFACT_BYTES.div_ceil(MAX_EPOCH_HISTORY_CHUNK_BYTES as usize);
/// One manifest request plus all bounded object-chunk requests for one immediate successor.
pub const MAX_EPOCH_HISTORY_REQUESTS_PER_SOURCE: usize =
    1 + MAX_EPOCH_HISTORY_OBJECT_CHUNKS_PER_SUCCESSOR;

/// Deployment policy for the bounded mutable suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistoryPolicy {
    hot_entries: u16,
}

impl EpochHistoryPolicy {
    pub fn new(hot_entries: u16) -> Result<Self, EpochHistoryError> {
        if hot_entries == 0 || hot_entries > MAX_HOT_EPOCH_HISTORY_ENTRIES {
            return Err(EpochHistoryError::InvalidPolicy);
        }
        Ok(Self { hot_entries })
    }

    #[must_use]
    pub const fn hot_entries(self) -> u16 {
        self.hot_entries
    }

    fn validate(self) -> Result<(), EpochHistoryError> {
        Self::new(self.hot_entries).map(|_| ())
    }
}

/// The authenticated history tip which the next DKG/reshare and activation statement must bind.
///
/// The genesis DKG uses a domain-separated `(network, key_id)` anchor. Every later transition uses
/// the exact certified tip.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistoryParent {
    version: u16,
    network: [u8; 32],
    key_id: [u8; 32],
    epoch: Option<u64>,
    root: [u8; 32],
}

impl EpochHistoryParent {
    pub fn genesis(network: [u8; 32], key_id: [u8; 32]) -> Result<Self, EpochHistoryError> {
        if network == [0_u8; 32] || key_id == [0_u8; 32] {
            return Err(EpochHistoryError::InvalidParent);
        }
        let root = genesis_anchor(network, key_id);
        let parent = Self { version: HISTORY_PARENT_VERSION, network, key_id, epoch: None, root };
        parent.validate()?;
        Ok(parent)
    }

    fn tip(
        network: [u8; 32],
        key_id: [u8; 32],
        epoch: u64,
        root: [u8; 32],
    ) -> Result<Self, EpochHistoryError> {
        let parent =
            Self { version: HISTORY_PARENT_VERSION, network, key_id, epoch: Some(epoch), root };
        parent.validate()?;
        Ok(parent)
    }

    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn key_id(self) -> [u8; 32] {
        self.key_id
    }

    #[must_use]
    pub const fn epoch(self) -> Option<u64> {
        self.epoch
    }

    #[must_use]
    pub const fn root(self) -> [u8; 32] {
        self.root
    }

    /// Stable binding to add to the AVSS transition, activation value, and signed activation
    /// statement. The entry root itself is computed after the activation certificate exists, so
    /// binding the predecessor avoids a circular construction.
    pub fn transition_binding(self) -> Result<[u8; 32], EpochHistoryError> {
        self.validate()?;
        let bytes = encode_bounded(&self, 128, "epoch history parent")?;
        Ok(domain_hash(HISTORY_PARENT_BINDING_DOMAIN, &[&bytes]))
    }

    fn validate(self) -> Result<(), EpochHistoryError> {
        if self.version != HISTORY_PARENT_VERSION
            || self.network == [0_u8; 32]
            || self.key_id == [0_u8; 32]
            || self.root == [0_u8; 32]
            || (self.epoch.is_none() && self.root != genesis_anchor(self.network, self.key_id))
        {
            return Err(EpochHistoryError::InvalidParent);
        }
        Ok(())
    }
}

/// Type tag included in every content address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(u8)]
pub enum EpochHistoryObjectKind {
    ActivationCertificate = 1,
    KeyRotationCertificate = 2,
    EpochEntry = 3,
    IndexNode = 4,
}

impl EpochHistoryObjectKind {
    const fn maximum_bytes(self) -> usize {
        match self {
            Self::ActivationCertificate => MAX_EPOCH_ACTIVATION_ARTIFACT_BYTES,
            Self::KeyRotationCertificate => MAX_EPOCH_KEY_ROTATION_ARTIFACT_BYTES,
            Self::EpochEntry => MAX_EPOCH_HISTORY_ENTRY_BYTES,
            Self::IndexNode => 1024,
        }
    }

    const fn storage_kind(self) -> WalletArtifactKind {
        WalletArtifactKind(match self {
            Self::ActivationCertificate => 0xe101,
            Self::KeyRotationCertificate => 0xe102,
            Self::EpochEntry => 0xe103,
            Self::IndexNode => 0xe104,
        })
    }
}

/// Portable, network-bound content address for one immutable history object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EpochHistoryObjectRef {
    version: u16,
    network: [u8; 32],
    kind: EpochHistoryObjectKind,
    plaintext_len: u64,
    digest: [u8; 32],
}

impl EpochHistoryObjectRef {
    pub fn for_contents(
        network: [u8; 32],
        kind: EpochHistoryObjectKind,
        contents: &[u8],
    ) -> Result<Self, EpochHistoryError> {
        if network == [0_u8; 32] || contents.is_empty() {
            return Err(EpochHistoryError::InvalidObjectReference);
        }
        if contents.len() > kind.maximum_bytes() {
            return Err(EpochHistoryError::ObjectTooLarge {
                kind: "epoch history object",
                actual: contents.len(),
                maximum: kind.maximum_bytes(),
            });
        }
        let plaintext_len =
            u64::try_from(contents.len()).map_err(|_| EpochHistoryError::Serialization)?;
        let storage =
            WalletArtifactRef::for_contents(WalletId(network), kind.storage_kind(), contents)
                .map_err(|_| EpochHistoryError::InvalidObjectReference)?;
        let digest = storage.digest();
        Ok(Self { version: HISTORY_REFERENCE_VERSION, network, kind, plaintext_len, digest })
    }

    pub fn verify_contents(self, contents: &[u8]) -> Result<(), EpochHistoryError> {
        self.validate()?;
        let expected = Self::for_contents(self.network, self.kind, contents)?;
        if expected != self {
            return Err(EpochHistoryError::ObjectAuthentication);
        }
        Ok(())
    }

    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn kind(self) -> EpochHistoryObjectKind {
        self.kind
    }

    #[must_use]
    pub const fn plaintext_len(self) -> u64 {
        self.plaintext_len
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    /// Deterministic encrypted-store address for this history object.
    pub fn storage_reference(self) -> Result<WalletArtifactRef, EpochHistoryError> {
        self.validate()?;
        WalletArtifactRef::from_parts(
            WalletId(self.network),
            self.kind.storage_kind(),
            self.plaintext_len,
            self.digest,
        )
        .map_err(|_| EpochHistoryError::InvalidObjectReference)
    }

    fn validate(self) -> Result<(), EpochHistoryError> {
        let length = usize::try_from(self.plaintext_len)
            .map_err(|_| EpochHistoryError::InvalidObjectReference)?;
        if self.version != HISTORY_REFERENCE_VERSION
            || self.network == [0_u8; 32]
            || self.plaintext_len == 0
            || length > self.kind.maximum_bytes()
            || self.digest == [0_u8; 32]
        {
            return Err(EpochHistoryError::InvalidObjectReference);
        }
        Ok(())
    }
}

/// Exact immutable object which must be installed before the next state CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedEpochHistoryObject {
    reference: EpochHistoryObjectRef,
    contents: Vec<u8>,
}

impl StagedEpochHistoryObject {
    #[must_use]
    pub const fn reference(&self) -> EpochHistoryObjectRef {
        self.reference
    }

    #[must_use]
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

/// Read-only view of installed immutable objects.
///
/// A production adapter may preload the fixed 65-node path plus its named entry asynchronously
/// before using this synchronous protocol core.
pub trait EpochHistoryObjectReader {
    fn load(&self, reference: EpochHistoryObjectRef) -> Result<Option<Vec<u8>>, EpochHistoryError>;
}

/// One authenticated step while asynchronously preloading a direct cold-index path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochHistoryIndexStep {
    Branch { next: Option<EpochHistoryObjectRef> },
    Leaf { entry: EpochHistoryObjectRef, consensus_root: [u8; 32] },
}

/// Authenticate one index object and select the unique next reference for `epoch`.
///
/// This small cursor API lets an async storage adapter load at most 65 objects without exposing
/// trie internals or replaying the cold prefix.
pub fn epoch_history_index_step(
    network: [u8; 32],
    epoch: u64,
    depth: u8,
    reference: EpochHistoryObjectRef,
    contents: &[u8],
) -> Result<EpochHistoryIndexStep, EpochHistoryError> {
    if depth > EPOCH_HISTORY_INDEX_DEPTH
        || reference.network != network
        || reference.kind != EpochHistoryObjectKind::IndexNode
    {
        return Err(EpochHistoryError::BrokenIndex);
    }
    reference.verify_contents(contents)?;
    let node = EpochIndexNode::from_bytes(contents)?;
    if node.network != network {
        return Err(EpochHistoryError::BrokenIndex);
    }
    if depth == EPOCH_HISTORY_INDEX_DEPTH {
        let EpochIndexNodeBody::Leaf { epoch: actual, consensus_root, entry } = node.body else {
            return Err(EpochHistoryError::BrokenIndex);
        };
        if actual != epoch {
            return Err(EpochHistoryError::MissingEpoch(epoch));
        }
        return Ok(EpochHistoryIndexStep::Leaf { entry, consensus_root });
    }
    let EpochIndexNodeBody::Branch { depth: actual, left, right } = node.body else {
        return Err(EpochHistoryError::BrokenIndex);
    };
    if actual != depth {
        return Err(EpochHistoryError::BrokenIndex);
    }
    let shift = u32::from(EPOCH_HISTORY_INDEX_DEPTH - depth - 1);
    let next = if ((epoch >> shift) & 1) == 0 { left } else { right };
    Ok(EpochHistoryIndexStep::Branch { next })
}

/// Permanent proof that a certified successor authorizes closing secret AVSS catch-up work for its
/// predecessor transition. Source-only/non-target replicas may apply it as soon as the containing
/// epoch entry wins the history CAS. A predecessor target which has not reconstructed its own share
/// delays local cleanup until finalization; global certification is not proof of local recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvssSuccessorSupersession {
    version: u16,
    predecessor_epoch: u64,
    predecessor_entry_root: [u8; 32],
    predecessor_transition: [u8; 32],
    predecessor_session: [u8; 32],
    successor_epoch: u64,
    successor_activation: [u8; 32],
    superseded_outbox_count: u32,
    superseded_outbox_root: [u8; 32],
}

impl AvssSuccessorSupersession {
    pub fn new(
        predecessor_epoch: u64,
        predecessor_entry_root: [u8; 32],
        predecessor_transition: [u8; 32],
        predecessor_session: [u8; 32],
        successor_epoch: u64,
        successor_activation: [u8; 32],
        superseded_outbox_digests: &[[u8; 32]],
    ) -> Result<Self, EpochHistoryError> {
        let expected_successor =
            predecessor_epoch.checked_add(1).ok_or(EpochHistoryError::EpochExhausted)?;
        if successor_epoch != expected_successor
            || predecessor_entry_root == [0_u8; 32]
            || predecessor_transition == [0_u8; 32]
            || predecessor_session == [0_u8; 32]
            || successor_activation == [0_u8; 32]
        {
            return Err(EpochHistoryError::InvalidSupersession);
        }
        let mut digests = superseded_outbox_digests.to_vec();
        if digests.iter().any(|digest| *digest == [0_u8; 32]) {
            return Err(EpochHistoryError::InvalidSupersession);
        }
        digests.sort_unstable();
        digests.dedup();
        let superseded_outbox_count =
            u32::try_from(digests.len()).map_err(|_| EpochHistoryError::InvalidSupersession)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(HISTORY_OUTBOX_ROOT_DOMAIN);
        hasher.update(&predecessor_session);
        hasher.update(&superseded_outbox_count.to_le_bytes());
        for digest in &digests {
            hasher.update(digest);
        }
        let superseded_outbox_root = *hasher.finalize().as_bytes();
        let closure = Self {
            version: HISTORY_SUPERSESSION_VERSION,
            predecessor_epoch,
            predecessor_entry_root,
            predecessor_transition,
            predecessor_session,
            successor_epoch,
            successor_activation,
            superseded_outbox_count,
            superseded_outbox_root,
        };
        closure.validate()?;
        Ok(closure)
    }

    #[must_use]
    pub const fn predecessor_epoch(self) -> u64 {
        self.predecessor_epoch
    }

    #[must_use]
    pub const fn predecessor_session(self) -> [u8; 32] {
        self.predecessor_session
    }

    #[must_use]
    pub const fn predecessor_transition(self) -> [u8; 32] {
        self.predecessor_transition
    }

    #[must_use]
    pub const fn predecessor_entry_root(self) -> [u8; 32] {
        self.predecessor_entry_root
    }

    #[must_use]
    pub const fn successor_epoch(self) -> u64 {
        self.successor_epoch
    }

    #[must_use]
    pub const fn successor_activation(self) -> [u8; 32] {
        self.successor_activation
    }

    #[must_use]
    pub const fn superseded_outbox_count(self) -> u32 {
        self.superseded_outbox_count
    }

    #[must_use]
    pub const fn superseded_outbox_root(self) -> [u8; 32] {
        self.superseded_outbox_root
    }

    fn validate(self) -> Result<(), EpochHistoryError> {
        if self.version != HISTORY_SUPERSESSION_VERSION
            || self.predecessor_epoch.checked_add(1) != Some(self.successor_epoch)
            || self.predecessor_entry_root == [0_u8; 32]
            || self.predecessor_transition == [0_u8; 32]
            || self.predecessor_session == [0_u8; 32]
            || self.successor_activation == [0_u8; 32]
            || self.superseded_outbox_root == [0_u8; 32]
        {
            return Err(EpochHistoryError::InvalidSupersession);
        }
        Ok(())
    }
}

/// Current activation inputs used to build one root-linked history entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochHistoryEntryInput {
    pub epoch: u64,
    pub parent: EpochHistoryParent,
    pub transition_digest: [u8; 32],
    pub activation_digest: [u8; 32],
    pub avss_transcript_digest: [u8; 32],
    /// Authenticated global set of every receiver key used through this epoch.
    pub receiver_keys: ReceiverKeyAccumulatorCommitment,
    /// Digest of the canonical key-rotation context/value, excluding certificate witnesses.
    pub key_rotation_digest: Option<[u8; 32]>,
    pub activation_certificate: Vec<u8>,
    pub key_rotation_certificate: Option<Vec<u8>>,
    pub predecessor_supersession: Option<AvssSuccessorSupersession>,
}

/// Root-linked epoch record. All large payloads are exact content-addressed artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistoryEntry {
    version: u16,
    network: [u8; 32],
    key_id: [u8; 32],
    epoch: u64,
    previous_root: [u8; 32],
    transition_digest: [u8; 32],
    activation_digest: [u8; 32],
    avss_transcript_digest: [u8; 32],
    receiver_keys: ReceiverKeyAccumulatorCommitment,
    key_rotation_digest: Option<[u8; 32]>,
    activation_certificate: EpochHistoryObjectRef,
    key_rotation_certificate: Option<EpochHistoryObjectRef>,
    predecessor_supersession: Option<AvssSuccessorSupersession>,
}

impl EpochHistoryEntry {
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn previous_root(&self) -> [u8; 32] {
        self.previous_root
    }

    #[must_use]
    pub const fn transition_digest(&self) -> [u8; 32] {
        self.transition_digest
    }

    #[must_use]
    pub const fn activation_digest(&self) -> [u8; 32] {
        self.activation_digest
    }

    #[must_use]
    pub const fn receiver_keys(&self) -> ReceiverKeyAccumulatorCommitment {
        self.receiver_keys
    }

    #[must_use]
    pub const fn activation_certificate(&self) -> EpochHistoryObjectRef {
        self.activation_certificate
    }

    #[must_use]
    pub const fn key_rotation_certificate(&self) -> Option<EpochHistoryObjectRef> {
        self.key_rotation_certificate
    }

    #[must_use]
    pub const fn predecessor_supersession(&self) -> Option<AvssSuccessorSupersession> {
        self.predecessor_supersession
    }

    /// Build the bounded public manifest used to retrieve this entry's exact certificate objects.
    pub fn catchup_manifest(&self) -> Result<EpochHistoryCatchupManifest, EpochHistoryError> {
        let parent = if self.epoch == 0 {
            EpochHistoryParent::genesis(self.network, self.key_id)?
        } else {
            EpochHistoryParent::tip(self.network, self.key_id, self.epoch - 1, self.previous_root)?
        };
        EpochHistoryCatchupManifest::new(
            parent,
            self.consensus_link(),
            self.activation_certificate,
            self.key_rotation_certificate,
        )
    }

    pub fn root(&self) -> Result<[u8; 32], EpochHistoryError> {
        self.validate()?;
        self.consensus_link().root()
    }

    /// Witness-independent fields shared by every honest party.
    ///
    /// Exact activation/key-rotation certificate bytes and local AVSS outbox cleanup proofs
    /// intentionally remain outside this value and therefore outside the root used by the next
    /// transition. Independently indexed negative records are not enumerated by epoch history.
    #[must_use]
    pub const fn consensus_link(&self) -> EpochHistoryLink {
        EpochHistoryLink {
            version: HISTORY_ENTRY_VERSION,
            network: self.network,
            key_id: self.key_id,
            epoch: self.epoch,
            previous_root: self.previous_root,
            transition_digest: self.transition_digest,
            activation_digest: self.activation_digest,
            avss_transcript_digest: self.avss_transcript_digest,
            receiver_keys: self.receiver_keys,
            key_rotation_digest: self.key_rotation_digest,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, EpochHistoryError> {
        self.validate()?;
        encode_bounded(self, MAX_EPOCH_HISTORY_ENTRY_BYTES, "epoch history entry")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EpochHistoryError> {
        let entry = decode_canonical_bounded::<Self>(
            bytes,
            MAX_EPOCH_HISTORY_ENTRY_BYTES,
            "epoch history entry",
        )?;
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> Result<(), EpochHistoryError> {
        self.receiver_keys.validate().map_err(|_| EpochHistoryError::InvalidEntry)?;
        if self.version != HISTORY_ENTRY_VERSION
            || self.network == [0_u8; 32]
            || self.key_id == [0_u8; 32]
            || self.previous_root == [0_u8; 32]
            || (self.epoch == 0 && self.previous_root != genesis_anchor(self.network, self.key_id))
            || self.transition_digest == [0_u8; 32]
            || self.activation_digest == [0_u8; 32]
            || self.avss_transcript_digest == [0_u8; 32]
            || self.receiver_keys.network() != self.network
            || self.receiver_keys.through_epoch() != self.epoch
            || self.key_rotation_digest == Some([0_u8; 32])
        {
            return Err(EpochHistoryError::InvalidEntry);
        }
        self.activation_certificate.validate()?;
        if self.activation_certificate.network != self.network
            || self.activation_certificate.kind != EpochHistoryObjectKind::ActivationCertificate
        {
            return Err(EpochHistoryError::InvalidEntry);
        }
        if let Some(rotation) = self.key_rotation_certificate {
            rotation.validate()?;
            if rotation.network != self.network
                || rotation.kind != EpochHistoryObjectKind::KeyRotationCertificate
            {
                return Err(EpochHistoryError::InvalidEntry);
            }
        }
        if self.key_rotation_digest.is_some() != self.key_rotation_certificate.is_some() {
            return Err(EpochHistoryError::InvalidEntry);
        }
        match (self.epoch, self.predecessor_supersession) {
            (0, None) => {}
            (0, Some(_)) | (_, None) => return Err(EpochHistoryError::InvalidSupersession),
            (_, Some(closure)) => {
                closure.validate()?;
                if closure.successor_epoch != self.epoch
                    || closure.successor_activation != self.activation_digest
                    || closure.predecessor_entry_root != self.previous_root
                {
                    return Err(EpochHistoryError::InvalidSupersession);
                }
            }
        }
        Ok(())
    }
}

/// Authenticated, bounded epoch-history pull request.
///
/// `Next` asks for the unique immediate successor of a locally trusted parent. `ObjectChunk`
/// retrieves only an object named by that successor manifest, preventing the artifact store from
/// becoming a general content oracle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EpochHistoryCatchupQuery {
    Next {
        version: u16,
        parent: EpochHistoryParent,
    },
    ObjectChunk {
        version: u16,
        manifest: EpochHistoryCatchupManifest,
        reference: EpochHistoryObjectRef,
        offset: u64,
        maximum_bytes: u32,
    },
}

impl EpochHistoryCatchupQuery {
    pub fn next(parent: EpochHistoryParent) -> Result<Self, EpochHistoryError> {
        parent.validate()?;
        Ok(Self::Next { version: HISTORY_CATCHUP_VERSION, parent })
    }

    pub fn object_chunk(
        manifest: EpochHistoryCatchupManifest,
        reference: EpochHistoryObjectRef,
        offset: u64,
        maximum_bytes: u32,
    ) -> Result<Self, EpochHistoryError> {
        manifest.validate()?;
        if !manifest.references().contains(&reference)
            || offset >= reference.plaintext_len()
            || maximum_bytes == 0
            || maximum_bytes > MAX_EPOCH_HISTORY_CHUNK_BYTES
        {
            return Err(EpochHistoryError::InvalidCatchup);
        }
        Ok(Self::ObjectChunk {
            version: HISTORY_CATCHUP_VERSION,
            manifest,
            reference,
            offset,
            maximum_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), EpochHistoryError> {
        match self {
            Self::Next { version, parent } => {
                if *version != HISTORY_CATCHUP_VERSION {
                    return Err(EpochHistoryError::InvalidCatchup);
                }
                parent.validate()
            }
            Self::ObjectChunk { version, manifest, reference, offset, maximum_bytes } => {
                if *version != HISTORY_CATCHUP_VERSION
                    || !manifest.references().contains(reference)
                    || *offset >= reference.plaintext_len()
                    || *maximum_bytes == 0
                    || *maximum_bytes > MAX_EPOCH_HISTORY_CHUNK_BYTES
                {
                    return Err(EpochHistoryError::InvalidCatchup);
                }
                manifest.validate()
            }
        }
    }

    /// Exact object bytes a conforming source must return for this query.
    ///
    /// Returning fewer bytes is not useful flow control: the request already carries the
    /// receiver's accepted maximum. Rejecting short non-final chunks prevents a Byzantine peer
    /// from expanding one bounded artifact into millions of authenticated round trips.
    #[must_use]
    pub fn expected_object_chunk_bytes(&self) -> Option<usize> {
        let Self::ObjectChunk { reference, offset, maximum_bytes, .. } = self else {
            return None;
        };
        let remaining = reference.plaintext_len().saturating_sub(*offset);
        Some(
            usize::try_from(remaining.min(u64::from(*maximum_bytes)))
                .expect("u32-bounded chunk length fits usize"),
        )
    }
}

/// Immediate-successor metadata. Its link becomes authoritative only after the exact activation
/// certificate object has been reconstructed and quorum-verified against the caller's trusted
/// parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistoryCatchupManifest {
    version: u16,
    parent: EpochHistoryParent,
    link: EpochHistoryLink,
    activation_certificate: EpochHistoryObjectRef,
    key_rotation_certificate: Option<EpochHistoryObjectRef>,
}

impl EpochHistoryCatchupManifest {
    pub fn new(
        parent: EpochHistoryParent,
        link: EpochHistoryLink,
        activation_certificate: EpochHistoryObjectRef,
        key_rotation_certificate: Option<EpochHistoryObjectRef>,
    ) -> Result<Self, EpochHistoryError> {
        let manifest = Self {
            version: HISTORY_CATCHUP_VERSION,
            parent,
            link,
            activation_certificate,
            key_rotation_certificate,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    #[must_use]
    pub const fn parent(self) -> EpochHistoryParent {
        self.parent
    }

    #[must_use]
    pub const fn link(self) -> EpochHistoryLink {
        self.link
    }

    #[must_use]
    pub const fn activation_certificate(self) -> EpochHistoryObjectRef {
        self.activation_certificate
    }

    #[must_use]
    pub const fn key_rotation_certificate(self) -> Option<EpochHistoryObjectRef> {
        self.key_rotation_certificate
    }

    pub fn references(self) -> Vec<EpochHistoryObjectRef> {
        let mut references = vec![self.activation_certificate];
        references.extend(self.key_rotation_certificate);
        references
    }

    fn validate(self) -> Result<(), EpochHistoryError> {
        self.parent.validate()?;
        self.link.validate()?;
        self.activation_certificate.validate()?;
        if self.version != HISTORY_CATCHUP_VERSION
            || self.parent.network != self.link.network
            || self.parent.key_id != self.link.key_id
            || self.parent.root != self.link.previous_root
            || self
                .parent
                .epoch
                .map_or(self.link.epoch != 0, |epoch| epoch.checked_add(1) != Some(self.link.epoch))
            || self.activation_certificate.network != self.link.network
            || self.activation_certificate.kind != EpochHistoryObjectKind::ActivationCertificate
            || self.link.key_rotation_digest.is_some() != self.key_rotation_certificate.is_some()
        {
            return Err(EpochHistoryError::InvalidCatchup);
        }
        if let Some(reference) = self.key_rotation_certificate {
            reference.validate()?;
            if reference.network != self.link.network
                || reference.kind != EpochHistoryObjectKind::KeyRotationCertificate
            {
                return Err(EpochHistoryError::InvalidCatchup);
            }
        }
        Ok(())
    }
}

/// Bounded authenticated response to [`EpochHistoryCatchupQuery`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EpochHistoryCatchupReply {
    Next {
        version: u16,
        manifest: Option<EpochHistoryCatchupManifest>,
        current_parent: EpochHistoryParent,
    },
    ObjectChunk {
        version: u16,
        reference: EpochHistoryObjectRef,
        offset: u64,
        total_bytes: u64,
        bytes: Vec<u8>,
    },
}

impl EpochHistoryCatchupReply {
    pub fn next(
        manifest: Option<EpochHistoryCatchupManifest>,
        current_parent: EpochHistoryParent,
    ) -> Result<Self, EpochHistoryError> {
        current_parent.validate()?;
        if let Some(manifest) = manifest {
            manifest.validate()?;
        }
        Ok(Self::Next { version: HISTORY_CATCHUP_VERSION, manifest, current_parent })
    }

    pub fn object_chunk(
        reference: EpochHistoryObjectRef,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, EpochHistoryError> {
        reference.validate()?;
        let chunk_len =
            u64::try_from(bytes.len()).map_err(|_| EpochHistoryError::InvalidCatchup)?;
        if bytes.is_empty()
            || bytes.len() > MAX_EPOCH_HISTORY_CHUNK_BYTES as usize
            || offset.checked_add(chunk_len).is_none_or(|end| end > reference.plaintext_len())
        {
            return Err(EpochHistoryError::InvalidCatchup);
        }
        Ok(Self::ObjectChunk {
            version: HISTORY_CATCHUP_VERSION,
            reference,
            offset,
            total_bytes: reference.plaintext_len(),
            bytes,
        })
    }

    pub fn validate(&self) -> Result<(), EpochHistoryError> {
        match self {
            Self::Next { version, manifest, current_parent } => {
                if *version != HISTORY_CATCHUP_VERSION {
                    return Err(EpochHistoryError::InvalidCatchup);
                }
                current_parent.validate()?;
                if let Some(manifest) = manifest {
                    manifest.validate()?;
                }
                Ok(())
            }
            Self::ObjectChunk { version, reference, offset, total_bytes, bytes } => {
                reference.validate()?;
                let chunk_len =
                    u64::try_from(bytes.len()).map_err(|_| EpochHistoryError::InvalidCatchup)?;
                if *version != HISTORY_CATCHUP_VERSION
                    || *total_bytes != reference.plaintext_len()
                    || bytes.is_empty()
                    || bytes.len() > MAX_EPOCH_HISTORY_CHUNK_BYTES as usize
                    || offset.checked_add(chunk_len).is_none_or(|end| end > *total_bytes)
                {
                    return Err(EpochHistoryError::InvalidCatchup);
                }
                Ok(())
            }
        }
    }

    /// Validate this reply against the exact authenticated request which elicited it.
    ///
    /// General structural validation deliberately cannot infer the requested chunk size. This
    /// request-bound check supplies the missing replay/context and progress invariant.
    pub fn validate_for_query(
        &self,
        query: &EpochHistoryCatchupQuery,
    ) -> Result<(), EpochHistoryError> {
        query.validate()?;
        self.validate()?;
        match (query, self) {
            (
                EpochHistoryCatchupQuery::Next { parent, .. },
                Self::Next { manifest, current_parent, .. },
            ) => {
                if current_parent.network != parent.network
                    || current_parent.key_id != parent.key_id
                    || manifest.is_some_and(|manifest| manifest.parent != *parent)
                {
                    return Err(EpochHistoryError::InvalidCatchup);
                }
                Ok(())
            }
            (
                EpochHistoryCatchupQuery::ObjectChunk { reference, offset, .. },
                Self::ObjectChunk {
                    reference: actual_reference, offset: actual_offset, bytes, ..
                },
            ) => {
                if actual_reference != reference
                    || actual_offset != offset
                    || Some(bytes.len()) != query.expected_object_chunk_bytes()
                {
                    return Err(EpochHistoryError::InvalidCatchup);
                }
                Ok(())
            }
            _ => Err(EpochHistoryError::InvalidCatchup),
        }
    }
}

/// The only fields allowed to influence the consensus history root.
///
/// This value is shared even when honest parties retain different certificate witness subsets or
/// have different local tombstones/outbox residue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistoryLink {
    version: u16,
    network: [u8; 32],
    key_id: [u8; 32],
    epoch: u64,
    previous_root: [u8; 32],
    transition_digest: [u8; 32],
    activation_digest: [u8; 32],
    avss_transcript_digest: [u8; 32],
    receiver_keys: ReceiverKeyAccumulatorCommitment,
    key_rotation_digest: Option<[u8; 32]>,
}

impl EpochHistoryLink {
    pub fn new(
        network: [u8; 32],
        key_id: [u8; 32],
        epoch: u64,
        previous_root: [u8; 32],
        transition_digest: [u8; 32],
        activation_digest: [u8; 32],
        avss_transcript_digest: [u8; 32],
        receiver_keys: ReceiverKeyAccumulatorCommitment,
        key_rotation_digest: Option<[u8; 32]>,
    ) -> Result<Self, EpochHistoryError> {
        let link = Self {
            version: HISTORY_ENTRY_VERSION,
            network,
            key_id,
            epoch,
            previous_root,
            transition_digest,
            activation_digest,
            avss_transcript_digest,
            receiver_keys,
            key_rotation_digest,
        };
        link.validate()?;
        Ok(link)
    }

    pub fn root(self) -> Result<[u8; 32], EpochHistoryError> {
        self.validate()?;
        let bytes = encode_bounded(&self, 512, "epoch history consensus link")?;
        Ok(domain_hash(HISTORY_ENTRY_ROOT_DOMAIN, &[&bytes]))
    }

    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn previous_root(self) -> [u8; 32] {
        self.previous_root
    }

    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn key_id(self) -> [u8; 32] {
        self.key_id
    }

    #[must_use]
    pub const fn transition_digest(self) -> [u8; 32] {
        self.transition_digest
    }

    #[must_use]
    pub const fn activation_digest(self) -> [u8; 32] {
        self.activation_digest
    }

    #[must_use]
    pub const fn avss_transcript_digest(self) -> [u8; 32] {
        self.avss_transcript_digest
    }

    #[must_use]
    pub const fn receiver_keys(self) -> ReceiverKeyAccumulatorCommitment {
        self.receiver_keys
    }

    #[must_use]
    pub const fn key_rotation_digest(self) -> Option<[u8; 32]> {
        self.key_rotation_digest
    }

    /// Parent context which the immediate successor transition must commit.
    pub fn successor_parent(self) -> Result<EpochHistoryParent, EpochHistoryError> {
        EpochHistoryParent::tip(self.network, self.key_id, self.epoch, self.root()?)
    }

    fn validate(self) -> Result<(), EpochHistoryError> {
        self.receiver_keys.validate().map_err(|_| EpochHistoryError::InvalidEntry)?;
        if self.version != HISTORY_ENTRY_VERSION
            || self.network == [0_u8; 32]
            || self.key_id == [0_u8; 32]
            || self.previous_root == [0_u8; 32]
            || (self.epoch == 0 && self.previous_root != genesis_anchor(self.network, self.key_id))
            || self.transition_digest == [0_u8; 32]
            || self.activation_digest == [0_u8; 32]
            || self.avss_transcript_digest == [0_u8; 32]
            || self.receiver_keys.network() != self.network
            || self.receiver_keys.through_epoch() != self.epoch
            || self.key_rotation_digest == Some([0_u8; 32])
        {
            return Err(EpochHistoryError::InvalidEntry);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EpochHistoryHead {
    version: u16,
    network: [u8; 32],
    key_id: [u8; 32],
    policy: EpochHistoryPolicy,
    revision: u64,
    cold_through: Option<u64>,
    cold_consensus_root: [u8; 32],
    cold_index_root: Option<EpochHistoryObjectRef>,
    tip_epoch: Option<u64>,
    tip_consensus_root: [u8; 32],
}

impl EpochHistoryHead {
    fn validate(self) -> Result<(), EpochHistoryError> {
        self.policy.validate()?;
        let genesis = genesis_anchor(self.network, self.key_id);
        if self.version != HISTORY_HEAD_VERSION
            || self.network == [0_u8; 32]
            || self.key_id == [0_u8; 32]
            || self.tip_consensus_root == [0_u8; 32]
            || (self.tip_epoch.is_none() && self.tip_consensus_root != genesis)
            || self.cold_through.is_none() != self.cold_index_root.is_none()
            || (self.cold_through.is_none() && self.cold_consensus_root != genesis)
            || (self.cold_through.is_some() && self.cold_consensus_root == [0_u8; 32])
        {
            return Err(EpochHistoryError::InvalidHead);
        }
        if let Some(index) = self.cold_index_root {
            index.validate()?;
            if index.network != self.network || index.kind != EpochHistoryObjectKind::IndexNode {
                return Err(EpochHistoryError::InvalidHead);
            }
        }
        Ok(())
    }
}

/// Compact mutable epoch-history state. Its hot suffix is bounded; its cold prefix is unbounded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochHistoryState {
    version: u16,
    head: EpochHistoryHead,
    hot: Vec<EpochHistoryEntry>,
}

impl EpochHistoryState {
    pub fn new(
        network: [u8; 32],
        key_id: [u8; 32],
        policy: EpochHistoryPolicy,
    ) -> Result<Self, EpochHistoryError> {
        policy.validate()?;
        if network == [0_u8; 32] || key_id == [0_u8; 32] {
            return Err(EpochHistoryError::InvalidHead);
        }
        let genesis = genesis_anchor(network, key_id);
        let state = Self {
            version: HISTORY_STATE_VERSION,
            head: EpochHistoryHead {
                version: HISTORY_HEAD_VERSION,
                network,
                key_id,
                policy,
                revision: 0,
                cold_through: None,
                cold_consensus_root: genesis,
                cold_index_root: None,
                tip_epoch: None,
                tip_consensus_root: genesis,
            },
            hot: Vec::new(),
        };
        state.validate()?;
        Ok(state)
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.head.network
    }

    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.head.key_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.head.revision
    }

    #[must_use]
    pub const fn policy(&self) -> EpochHistoryPolicy {
        self.head.policy
    }

    #[must_use]
    pub const fn cold_through(&self) -> Option<u64> {
        self.head.cold_through
    }

    #[must_use]
    pub const fn cold_index_root(&self) -> Option<EpochHistoryObjectRef> {
        self.head.cold_index_root
    }

    #[must_use]
    pub const fn tip_epoch(&self) -> Option<u64> {
        self.head.tip_epoch
    }

    #[must_use]
    pub fn hot_entries(&self) -> &[EpochHistoryEntry] {
        &self.hot
    }

    /// Bounded immutable payload references needed to validate the hot suffix on restart.
    pub fn hot_object_references(&self) -> Vec<EpochHistoryObjectRef> {
        let mut references = Vec::with_capacity(self.hot.len().saturating_mul(2));
        for entry in &self.hot {
            references.push(entry.activation_certificate);
            if let Some(rotation) = entry.key_rotation_certificate {
                references.push(rotation);
            }
        }
        references
    }

    pub fn parent(&self) -> Result<EpochHistoryParent, EpochHistoryError> {
        match self.head.tip_epoch {
            Some(epoch) => EpochHistoryParent::tip(
                self.head.network,
                self.head.key_id,
                epoch,
                self.head.tip_consensus_root,
            ),
            None => EpochHistoryParent::genesis(self.head.network, self.head.key_id),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, EpochHistoryError> {
        self.validate()?;
        encode_bounded(self, MAX_EPOCH_HISTORY_STATE_BYTES, "epoch history state")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EpochHistoryError> {
        let state = decode_canonical_bounded::<Self>(
            bytes,
            MAX_EPOCH_HISTORY_STATE_BYTES,
            "epoch history state",
        )?;
        state.validate()?;
        Ok(state)
    }

    /// Prepare an append and any required hot-to-cold compaction.
    ///
    /// The reader is used only for existing immutable trie nodes. No lifetime-sized enumeration is
    /// performed. The returned state cannot be committed safely until `verify_staged` succeeds.
    pub fn prepare_append<R: EpochHistoryObjectReader>(
        &self,
        input: EpochHistoryEntryInput,
        reader: &R,
    ) -> Result<PendingEpochHistoryMutation, EpochHistoryError> {
        self.validate()?;
        let expected_epoch = self
            .head
            .tip_epoch
            .map_or(Ok(0), |epoch| epoch.checked_add(1).ok_or(EpochHistoryError::EpochExhausted))?;
        let expected_parent = self.parent()?;
        if input.epoch != expected_epoch {
            return Err(EpochHistoryError::EpochSequence {
                expected: expected_epoch,
                actual: input.epoch,
            });
        }
        if input.parent != expected_parent {
            return Err(EpochHistoryError::ParentMismatch);
        }
        if let Some(previous) = self.hot.last() {
            let closure =
                input.predecessor_supersession.ok_or(EpochHistoryError::InvalidSupersession)?;
            if closure.predecessor_epoch != previous.epoch
                || closure.predecessor_entry_root != previous.root()?
                || closure.predecessor_transition != previous.transition_digest
            {
                return Err(EpochHistoryError::InvalidSupersession);
            }
        } else if input.predecessor_supersession.is_some() {
            return Err(EpochHistoryError::InvalidSupersession);
        }

        let mut staged = BTreeMap::new();
        let entry = build_entry(self.head.network, self.head.key_id, input, &mut staged)?;
        let entry_root = entry.root()?;
        let supersession = entry.predecessor_supersession;

        let mut next = self.clone();
        next.head.revision =
            next.head.revision.checked_add(1).ok_or(EpochHistoryError::RevisionExhausted)?;
        next.head.tip_epoch = Some(entry.epoch);
        next.head.tip_consensus_root = entry_root;
        next.hot.push(entry);

        let mut coldified_epochs = Vec::new();
        while next.hot.len() > usize::from(next.head.policy.hot_entries) {
            let cold = next.hot.remove(0);
            let expected_cold = next.head.cold_through.map_or(Ok(0), |epoch| {
                epoch.checked_add(1).ok_or(EpochHistoryError::EpochExhausted)
            })?;
            if cold.epoch != expected_cold {
                return Err(EpochHistoryError::BrokenChain);
            }
            let cold_root = cold.root()?;
            let cold_bytes = cold.to_bytes()?;
            let cold_reference = stage_object(
                next.head.network,
                EpochHistoryObjectKind::EpochEntry,
                cold_bytes,
                &mut staged,
            )?;
            let index_root = insert_index(
                next.head.network,
                next.head.cold_index_root,
                cold.epoch,
                cold_root,
                cold_reference,
                &mut staged,
                reader,
            )?;
            next.head.cold_through = Some(cold.epoch);
            next.head.cold_consensus_root = cold_root;
            next.head.cold_index_root = Some(index_root);
            coldified_epochs.push(cold.epoch);
        }
        next.validate()?;

        Ok(PendingEpochHistoryMutation {
            expected_revision: self.head.revision,
            next,
            staged: staged
                .into_iter()
                .map(|(reference, contents)| StagedEpochHistoryObject { reference, contents })
                .collect(),
            cleanup: EpochHistoryCleanup {
                coldified_epochs,
                superseded_avss: supersession.into_iter().collect(),
            },
        })
    }

    /// Direct lookup from the hot suffix or authenticated cold trie.
    pub fn lookup<R: EpochHistoryObjectReader>(
        &self,
        epoch: u64,
        reader: &R,
    ) -> Result<Option<EpochHistoryEntry>, EpochHistoryError> {
        self.validate()?;
        if self.head.tip_epoch.is_none_or(|tip| epoch > tip) {
            return Ok(None);
        }
        if self.head.cold_through.is_some_and(|cold| epoch <= cold) {
            let index = self.head.cold_index_root.ok_or(EpochHistoryError::InvalidHead)?;
            let entry = lookup_cold_entry(index, epoch, reader)?;
            if entry.network != self.head.network
                || entry.key_id != self.head.key_id
                || entry.epoch != epoch
            {
                return Err(EpochHistoryError::BrokenIndex);
            }
            return Ok(Some(entry));
        }
        Ok(self.hot.iter().find(|entry| entry.epoch == epoch).cloned())
    }

    /// Restart validation authenticates the compact head, the cold tail (which is root-linked to
    /// the hot suffix), all bounded hot payload references, and exact canonical state bytes. The
    /// cold trie root commits to the complete prefix; individual older artifacts are checked on
    /// direct access rather than replayed at startup.
    pub fn verify_restart<R: EpochHistoryObjectReader>(
        &self,
        reader: &R,
    ) -> Result<(), EpochHistoryError> {
        self.validate()?;
        if let Some(cold_epoch) = self.head.cold_through {
            let entry = self.lookup(cold_epoch, reader)?.ok_or(EpochHistoryError::BrokenIndex)?;
            if entry.root()? != self.head.cold_consensus_root {
                return Err(EpochHistoryError::BrokenChain);
            }
        }
        for entry in &self.hot {
            verify_entry_objects(entry, reader)?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), EpochHistoryError> {
        self.head.validate()?;
        if self.version != HISTORY_STATE_VERSION
            || self.hot.len() > usize::from(self.head.policy.hot_entries)
            || self.hot.len() > usize::from(MAX_HOT_EPOCH_HISTORY_ENTRIES)
        {
            return Err(EpochHistoryError::InvalidState);
        }

        let genesis = genesis_anchor(self.head.network, self.head.key_id);
        if self.head.tip_epoch.is_none() {
            if !self.hot.is_empty()
                || self.head.cold_through.is_some()
                || self.head.tip_consensus_root != genesis
            {
                return Err(EpochHistoryError::InvalidState);
            }
            return Ok(());
        }
        if self.hot.is_empty() {
            return Err(EpochHistoryError::InvalidState);
        }

        let mut expected_epoch = self
            .head
            .cold_through
            .map_or(Ok(0), |epoch| epoch.checked_add(1).ok_or(EpochHistoryError::EpochExhausted))?;
        let mut expected_root =
            if self.head.cold_through.is_some() { self.head.cold_consensus_root } else { genesis };
        for entry in &self.hot {
            entry.validate()?;
            if entry.network != self.head.network
                || entry.key_id != self.head.key_id
                || entry.epoch != expected_epoch
                || entry.previous_root != expected_root
            {
                return Err(EpochHistoryError::BrokenChain);
            }
            expected_root = entry.root()?;
            expected_epoch =
                expected_epoch.checked_add(1).ok_or(EpochHistoryError::EpochExhausted)?;
        }
        let last = self.hot.last().ok_or(EpochHistoryError::InvalidState)?;
        if self.head.tip_epoch != Some(last.epoch) || self.head.tip_consensus_root != expected_root
        {
            return Err(EpochHistoryError::BrokenChain);
        }
        Ok(())
    }
}

/// Mutation whose immutable objects have not yet been proven durable.
#[derive(Clone, Debug)]
pub struct PendingEpochHistoryMutation {
    expected_revision: u64,
    next: EpochHistoryState,
    staged: Vec<StagedEpochHistoryObject>,
    cleanup: EpochHistoryCleanup,
}

impl PendingEpochHistoryMutation {
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    #[must_use]
    pub fn staged_objects(&self) -> &[StagedEpochHistoryObject] {
        &self.staged
    }

    /// Prove every referenced object was installed exactly before exposing state bytes for CAS.
    pub fn verify_staged<R: EpochHistoryObjectReader>(
        self,
        reader: &R,
    ) -> Result<VerifiedEpochHistoryMutation, EpochHistoryError> {
        for object in &self.staged {
            let contents = load_required(reader, object.reference)?;
            if contents != object.contents {
                return Err(EpochHistoryError::ObjectAuthentication);
            }
        }
        self.next.verify_restart(reader)?;
        let next_state_bytes = self.next.to_bytes()?;
        Ok(VerifiedEpochHistoryMutation {
            expected_revision: self.expected_revision,
            next_state_bytes,
            next_state: self.next,
            cleanup: self.cleanup,
        })
    }
}

/// Mutation safe to use as the next authenticated state CAS value.
#[derive(Clone, Debug)]
pub struct VerifiedEpochHistoryMutation {
    expected_revision: u64,
    next_state_bytes: Vec<u8>,
    next_state: EpochHistoryState,
    cleanup: EpochHistoryCleanup,
}

impl VerifiedEpochHistoryMutation {
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    #[must_use]
    pub fn next_state_bytes(&self) -> &[u8] {
        &self.next_state_bytes
    }

    #[must_use]
    pub const fn next_state(&self) -> &EpochHistoryState {
        &self.next_state
    }

    /// Authorize deletion/supersession only after storage returns the exact committed bytes.
    pub fn authorize_cleanup(
        &self,
        committed_state_bytes: &[u8],
    ) -> Result<EpochHistoryCleanup, EpochHistoryError> {
        let committed = EpochHistoryState::from_bytes(committed_state_bytes)?;
        if committed_state_bytes != self.next_state_bytes
            || committed.revision() != self.expected_revision.saturating_add(1)
        {
            return Err(EpochHistoryError::CasNotCommitted);
        }
        Ok(self.cleanup.clone())
    }
}

/// Idempotent post-CAS work.
///
/// Independently indexed retirement, identity, high-water, session, and nonce records never
/// appear here and therefore cannot be removed by epoch compaction regardless of their count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochHistoryCleanup {
    coldified_epochs: Vec<u64>,
    superseded_avss: Vec<AvssSuccessorSupersession>,
}

impl EpochHistoryCleanup {
    /// Hot/source activation records which may now be removed because the cold object is live.
    #[must_use]
    pub fn coldified_epochs(&self) -> &[u64] {
        &self.coldified_epochs
    }

    /// Secret AVSS catch-up outbox families whose cleanup is now authorized. An unfinished local
    /// target reducer remains live until that replica independently finalizes its share.
    #[must_use]
    pub fn superseded_avss(&self) -> &[AvssSuccessorSupersession] {
        &self.superseded_avss
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EpochIndexNode {
    version: u16,
    network: [u8; 32],
    body: EpochIndexNodeBody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum EpochIndexNodeBody {
    Branch { depth: u8, left: Option<EpochHistoryObjectRef>, right: Option<EpochHistoryObjectRef> },
    Leaf { epoch: u64, consensus_root: [u8; 32], entry: EpochHistoryObjectRef },
}

impl EpochIndexNode {
    fn validate(&self) -> Result<(), EpochHistoryError> {
        if self.version != HISTORY_INDEX_NODE_VERSION || self.network == [0_u8; 32] {
            return Err(EpochHistoryError::BrokenIndex);
        }
        match self.body {
            EpochIndexNodeBody::Branch { depth, left, right } => {
                if depth >= EPOCH_HISTORY_INDEX_DEPTH || (left.is_none() && right.is_none()) {
                    return Err(EpochHistoryError::BrokenIndex);
                }
                for child in [left, right].into_iter().flatten() {
                    child.validate()?;
                    if child.network != self.network
                        || child.kind != EpochHistoryObjectKind::IndexNode
                    {
                        return Err(EpochHistoryError::BrokenIndex);
                    }
                }
            }
            EpochIndexNodeBody::Leaf { consensus_root, entry, .. } => {
                entry.validate()?;
                if consensus_root == [0_u8; 32]
                    || entry.network != self.network
                    || entry.kind != EpochHistoryObjectKind::EpochEntry
                {
                    return Err(EpochHistoryError::BrokenIndex);
                }
            }
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>, EpochHistoryError> {
        self.validate()?;
        encode_bounded(self, 1024, "epoch history index node")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, EpochHistoryError> {
        let node = decode_canonical_bounded::<Self>(bytes, 1024, "epoch history index node")?;
        node.validate()?;
        Ok(node)
    }
}

fn build_entry(
    network: [u8; 32],
    key_id: [u8; 32],
    input: EpochHistoryEntryInput,
    staged: &mut BTreeMap<EpochHistoryObjectRef, Vec<u8>>,
) -> Result<EpochHistoryEntry, EpochHistoryError> {
    input.parent.validate()?;
    if input.parent.network != network || input.parent.key_id != key_id {
        return Err(EpochHistoryError::ParentMismatch);
    }
    let activation_certificate = stage_object(
        network,
        EpochHistoryObjectKind::ActivationCertificate,
        input.activation_certificate,
        staged,
    )?;
    let key_rotation_certificate = input
        .key_rotation_certificate
        .map(|bytes| {
            stage_object(network, EpochHistoryObjectKind::KeyRotationCertificate, bytes, staged)
        })
        .transpose()?;

    let entry = EpochHistoryEntry {
        version: HISTORY_ENTRY_VERSION,
        network,
        key_id,
        epoch: input.epoch,
        previous_root: input.parent.root,
        transition_digest: input.transition_digest,
        activation_digest: input.activation_digest,
        avss_transcript_digest: input.avss_transcript_digest,
        receiver_keys: input.receiver_keys,
        key_rotation_digest: input.key_rotation_digest,
        activation_certificate,
        key_rotation_certificate,
        predecessor_supersession: input.predecessor_supersession,
    };
    entry.validate()?;
    Ok(entry)
}

fn stage_object(
    network: [u8; 32],
    kind: EpochHistoryObjectKind,
    contents: Vec<u8>,
    staged: &mut BTreeMap<EpochHistoryObjectRef, Vec<u8>>,
) -> Result<EpochHistoryObjectRef, EpochHistoryError> {
    let reference = EpochHistoryObjectRef::for_contents(network, kind, &contents)?;
    if let Some(existing) = staged.insert(reference, contents.clone()) {
        if existing != contents {
            return Err(EpochHistoryError::ObjectAuthentication);
        }
    }
    Ok(reference)
}

fn insert_index<R: EpochHistoryObjectReader>(
    network: [u8; 32],
    current: Option<EpochHistoryObjectRef>,
    epoch: u64,
    consensus_root: [u8; 32],
    entry: EpochHistoryObjectRef,
    staged: &mut BTreeMap<EpochHistoryObjectRef, Vec<u8>>,
    reader: &R,
) -> Result<EpochHistoryObjectRef, EpochHistoryError> {
    insert_index_at(network, current, 0, epoch, consensus_root, entry, staged, reader)
}

#[allow(clippy::too_many_arguments)]
fn insert_index_at<R: EpochHistoryObjectReader>(
    network: [u8; 32],
    mut current: Option<EpochHistoryObjectRef>,
    mut depth: u8,
    epoch: u64,
    consensus_root: [u8; 32],
    entry: EpochHistoryObjectRef,
    staged: &mut BTreeMap<EpochHistoryObjectRef, Vec<u8>>,
    reader: &R,
) -> Result<EpochHistoryObjectRef, EpochHistoryError> {
    // Iterative descent plus bottom-up rebuild. Self-recursion here previously reserved one
    // debug-build frame per index level inside already-deep async poll chains and overflowed
    // default 2 MiB worker stacks; an explicit sibling stack keeps the frame flat.
    struct PendingBranch {
        depth: u8,
        sibling: Option<EpochHistoryObjectRef>,
        selected_is_left: bool,
    }
    let mut pending =
        Vec::with_capacity(usize::from(EPOCH_HISTORY_INDEX_DEPTH.saturating_sub(depth)));

    while depth < EPOCH_HISTORY_INDEX_DEPTH {
        let (left, right) = if let Some(reference) = current {
            let existing = load_index_node(reference, staged, reader)?;
            match existing.body {
                EpochIndexNodeBody::Branch { depth: actual, left, right }
                    if actual == depth && existing.network == network =>
                {
                    (left, right)
                }
                _ => return Err(EpochHistoryError::BrokenIndex),
            }
        } else {
            (None, None)
        };

        let shift = u32::from(EPOCH_HISTORY_INDEX_DEPTH - depth - 1);
        let selected_is_left = ((epoch >> shift) & 1) == 0;
        let (selected, sibling) = if selected_is_left { (left, right) } else { (right, left) };
        pending.push(PendingBranch { depth, sibling, selected_is_left });
        current = selected;
        depth += 1;
    }

    let leaf = EpochIndexNode {
        version: HISTORY_INDEX_NODE_VERSION,
        network,
        body: EpochIndexNodeBody::Leaf { epoch, consensus_root, entry },
    };
    let mut reference = if let Some(reference) = current {
        let existing = load_index_node(reference, staged, reader)?;
        if existing == leaf {
            reference
        } else {
            return Err(EpochHistoryError::DuplicateEpoch);
        }
    } else {
        stage_index_node(leaf, staged)?
    };

    while let Some(PendingBranch { depth, sibling, selected_is_left }) = pending.pop() {
        let child = Some(reference);
        let (left, right) = if selected_is_left { (child, sibling) } else { (sibling, child) };
        reference = stage_index_node(
            EpochIndexNode {
                version: HISTORY_INDEX_NODE_VERSION,
                network,
                body: EpochIndexNodeBody::Branch { depth, left, right },
            },
            staged,
        )?;
    }
    Ok(reference)
}

fn stage_index_node(
    node: EpochIndexNode,
    staged: &mut BTreeMap<EpochHistoryObjectRef, Vec<u8>>,
) -> Result<EpochHistoryObjectRef, EpochHistoryError> {
    let network = node.network;
    let bytes = node.to_bytes()?;
    stage_object(network, EpochHistoryObjectKind::IndexNode, bytes, staged)
}

fn load_index_node<R: EpochHistoryObjectReader>(
    reference: EpochHistoryObjectRef,
    staged: &BTreeMap<EpochHistoryObjectRef, Vec<u8>>,
    reader: &R,
) -> Result<EpochIndexNode, EpochHistoryError> {
    if reference.kind != EpochHistoryObjectKind::IndexNode {
        return Err(EpochHistoryError::BrokenIndex);
    }
    let bytes = if let Some(bytes) = staged.get(&reference) {
        reference.verify_contents(bytes)?;
        bytes.clone()
    } else {
        load_required(reader, reference)?
    };
    EpochIndexNode::from_bytes(&bytes)
}

fn lookup_cold_entry<R: EpochHistoryObjectReader>(
    root: EpochHistoryObjectRef,
    epoch: u64,
    reader: &R,
) -> Result<EpochHistoryEntry, EpochHistoryError> {
    let mut current = root;
    for depth in 0..EPOCH_HISTORY_INDEX_DEPTH {
        let bytes = load_required(reader, current)?;
        let node = EpochIndexNode::from_bytes(&bytes)?;
        let EpochIndexNodeBody::Branch { depth: actual, left, right } = node.body else {
            return Err(EpochHistoryError::BrokenIndex);
        };
        if node.network != root.network || actual != depth {
            return Err(EpochHistoryError::BrokenIndex);
        }
        let shift = u32::from(EPOCH_HISTORY_INDEX_DEPTH - depth - 1);
        current = if ((epoch >> shift) & 1) == 0 { left } else { right }
            .ok_or(EpochHistoryError::MissingEpoch(epoch))?;
    }
    let leaf_bytes = load_required(reader, current)?;
    let leaf = EpochIndexNode::from_bytes(&leaf_bytes)?;
    let EpochIndexNodeBody::Leaf { epoch: actual, consensus_root, entry } = leaf.body else {
        return Err(EpochHistoryError::BrokenIndex);
    };
    if actual != epoch || leaf.network != root.network {
        return Err(EpochHistoryError::BrokenIndex);
    }
    let entry_bytes = load_required(reader, entry)?;
    let decoded = EpochHistoryEntry::from_bytes(&entry_bytes)?;
    if decoded.epoch != epoch || decoded.root()? != consensus_root {
        return Err(EpochHistoryError::BrokenIndex);
    }
    Ok(decoded)
}

fn verify_entry_objects<R: EpochHistoryObjectReader>(
    entry: &EpochHistoryEntry,
    reader: &R,
) -> Result<(), EpochHistoryError> {
    load_required(reader, entry.activation_certificate)?;
    if let Some(rotation) = entry.key_rotation_certificate {
        load_required(reader, rotation)?;
    }
    Ok(())
}

fn load_required<R: EpochHistoryObjectReader>(
    reader: &R,
    reference: EpochHistoryObjectRef,
) -> Result<Vec<u8>, EpochHistoryError> {
    reference.validate()?;
    let contents = reader.load(reference)?.ok_or(EpochHistoryError::MissingObject(reference))?;
    reference.verify_contents(&contents)?;
    Ok(contents)
}

fn genesis_anchor(network: [u8; 32], key_id: [u8; 32]) -> [u8; 32] {
    domain_hash(HISTORY_GENESIS_ANCHOR_DOMAIN, &[&network, &key_id])
}

fn domain_hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, EpochHistoryError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| EpochHistoryError::Serialization)?;
    if bytes.len() > maximum {
        return Err(EpochHistoryError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn decode_canonical_bounded<T>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, EpochHistoryError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() > maximum {
        return Err(EpochHistoryError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    let (value, trailing) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| EpochHistoryError::Serialization)?;
    if !trailing.is_empty() {
        return Err(EpochHistoryError::TrailingBytes { kind, trailing: trailing.len() });
    }
    if postcard::to_allocvec(&value).map_err(|_| EpochHistoryError::Serialization)? != bytes {
        return Err(EpochHistoryError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

#[derive(Debug, Error)]
pub enum EpochHistoryError {
    #[error("epoch history serialization failed")]
    Serialization,
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{0} encoding is not canonical")]
    NonCanonicalEncoding(&'static str),
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("epoch history policy is invalid")]
    InvalidPolicy,
    #[error("epoch history parent is invalid")]
    InvalidParent,
    #[error("epoch history parent does not match the authenticated tip")]
    ParentMismatch,
    #[error("epoch history head is invalid")]
    InvalidHead,
    #[error("epoch history state is invalid")]
    InvalidState,
    #[error("epoch history entry is invalid")]
    InvalidEntry,
    #[error("AVSS successor-supersession closure is invalid")]
    InvalidSupersession,
    #[error("epoch history object reference is invalid")]
    InvalidObjectReference,
    #[error("epoch history object failed content authentication")]
    ObjectAuthentication,
    #[error("epoch history object {0:?} is missing")]
    MissingObject(EpochHistoryObjectRef),
    #[error("epoch history expected epoch {expected}, got {actual}")]
    EpochSequence { expected: u64, actual: u64 },
    #[error("epoch history chain is broken")]
    BrokenChain,
    #[error("epoch history index is broken")]
    BrokenIndex,
    #[error("epoch {0} is absent from the authenticated cold index")]
    MissingEpoch(u64),
    #[error("epoch already has a different authenticated cold entry")]
    DuplicateEpoch,
    #[error("epoch number space is exhausted")]
    EpochExhausted,
    #[error("epoch history revision space is exhausted")]
    RevisionExhausted,
    #[error("the exact epoch-history CAS has not been observed")]
    CasNotCommitted,
    #[error("epoch-history catch-up message is invalid")]
    InvalidCatchup,
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Clone, Default)]
    struct MemoryObjects(BTreeMap<EpochHistoryObjectRef, Vec<u8>>);

    impl EpochHistoryObjectReader for MemoryObjects {
        fn load(
            &self,
            reference: EpochHistoryObjectRef,
        ) -> Result<Option<Vec<u8>>, EpochHistoryError> {
            Ok(self.0.get(&reference).cloned())
        }
    }

    impl MemoryObjects {
        fn install(&mut self, pending: &PendingEpochHistoryMutation) {
            for object in pending.staged_objects() {
                if let Some(existing) =
                    self.0.insert(object.reference(), object.contents().to_vec())
                {
                    assert_eq!(existing, object.contents());
                }
            }
        }
    }

    struct CountingObjects<'a> {
        objects: &'a MemoryObjects,
        reads: RefCell<Vec<EpochHistoryObjectKind>>,
    }

    impl<'a> CountingObjects<'a> {
        fn new(objects: &'a MemoryObjects) -> Self {
            Self { objects, reads: RefCell::new(Vec::new()) }
        }

        fn take_reads(&self) -> Vec<EpochHistoryObjectKind> {
            std::mem::take(&mut *self.reads.borrow_mut())
        }
    }

    impl EpochHistoryObjectReader for CountingObjects<'_> {
        fn load(
            &self,
            reference: EpochHistoryObjectRef,
        ) -> Result<Option<Vec<u8>>, EpochHistoryError> {
            self.reads.borrow_mut().push(reference.kind());
            self.objects.load(reference)
        }
    }

    const NETWORK: [u8; 32] = [0x11; 32];
    const KEY_ID: [u8; 32] = [0x22; 32];

    const fn digest(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    fn receiver_keys_for(epoch: u64) -> ReceiverKeyAccumulatorCommitment {
        let mut root = digest(0xe0);
        root[..8].copy_from_slice(&epoch.to_le_bytes());
        root[8..16].copy_from_slice(&epoch.wrapping_mul(0x9e37_79b9).to_le_bytes());
        ReceiverKeyAccumulatorCommitment::for_test(
            NETWORK,
            epoch,
            epoch.checked_add(1).expect("small test epoch"),
            root,
        )
        .expect("valid test receiver-key commitment")
    }

    fn input_for(
        state: &EpochHistoryState,
        objects: &MemoryObjects,
        epoch: u64,
    ) -> EpochHistoryEntryInput {
        let tag = u8::try_from(epoch).expect("small test epoch");
        let predecessor_supersession = if epoch == 0 {
            None
        } else {
            let previous =
                state.lookup(epoch - 1, objects).expect("lookup").expect("previous epoch");
            Some(
                AvssSuccessorSupersession::new(
                    epoch - 1,
                    previous.root().expect("previous root"),
                    previous.transition_digest(),
                    digest(0x80_u8.wrapping_add(tag)),
                    epoch,
                    digest(0x40_u8.wrapping_add(tag)),
                    &[digest(0xa0_u8.wrapping_add(tag)), digest(0xb0_u8.wrapping_add(tag))],
                )
                .expect("supersession"),
            )
        };
        EpochHistoryEntryInput {
            epoch,
            parent: state.parent().expect("parent"),
            transition_digest: digest(0x20_u8.wrapping_add(tag)),
            activation_digest: digest(0x40_u8.wrapping_add(tag)),
            avss_transcript_digest: digest(0x60_u8.wrapping_add(tag)),
            receiver_keys: receiver_keys_for(epoch),
            key_rotation_digest: (epoch % 2 == 1).then(|| digest(0x70_u8.wrapping_add(tag))),
            activation_certificate: vec![0xc0_u8.wrapping_add(tag); 64],
            key_rotation_certificate: (epoch % 2 == 1).then(|| vec![0xd0_u8.wrapping_add(tag); 48]),
            predecessor_supersession,
        }
    }

    fn commit(
        state: &EpochHistoryState,
        input: EpochHistoryEntryInput,
        objects: &mut MemoryObjects,
    ) -> (EpochHistoryState, EpochHistoryCleanup) {
        let pending = state.prepare_append(input, objects).expect("prepare");
        objects.install(&pending);
        let verified = pending.verify_staged(objects).expect("verify staged");
        assert_eq!(verified.expected_revision(), state.revision());
        let bytes = verified.next_state_bytes().to_vec();
        let cleanup = verified.authorize_cleanup(&bytes).expect("authorize cleanup");
        let next = EpochHistoryState::from_bytes(&bytes).expect("restart decode");
        next.verify_restart(objects).expect("restart verify");
        (next, cleanup)
    }

    #[test]
    fn consensus_root_excludes_witnesses_and_local_outboxes() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let objects = MemoryObjects::default();

        let mut left_staged = BTreeMap::new();
        let mut right_staged = BTreeMap::new();
        let mut left = input_for(&state, &objects, 0);
        let mut right = left.clone();
        left.activation_certificate = b"witness-set-a".to_vec();
        right.activation_certificate = b"different-witness-order-and-subset".to_vec();
        let left = build_entry(NETWORK, KEY_ID, left, &mut left_staged).expect("left entry");
        let right = build_entry(NETWORK, KEY_ID, right, &mut right_staged).expect("right entry");
        assert_ne!(left.to_bytes().expect("bytes"), right.to_bytes().expect("bytes"));
        assert_eq!(left.consensus_link(), right.consensus_link());
        assert_eq!(left.root().expect("root"), right.root().expect("root"));

        let mut state_a = state.clone();
        let mut state_b = state;
        state_a.hot.push(left.clone());
        state_b.hot.push(right.clone());
        for state in [&mut state_a, &mut state_b] {
            state.head.revision = 1;
            state.head.tip_epoch = Some(0);
            state.head.tip_consensus_root = left.root().expect("root");
            state.validate().expect("valid local state");
        }

        let mut epoch_one_a = input_for(&state_a, &MemoryObjects::default(), 1);
        let mut epoch_one_b = input_for(&state_b, &MemoryObjects::default(), 1);
        epoch_one_a.predecessor_supersession = Some(
            AvssSuccessorSupersession::new(
                0,
                left.root().expect("root"),
                left.transition_digest(),
                digest(0x81),
                1,
                epoch_one_a.activation_digest,
                &[digest(0x91)],
            )
            .expect("closure a"),
        );
        epoch_one_b.predecessor_supersession = Some(
            AvssSuccessorSupersession::new(
                0,
                right.root().expect("root"),
                right.transition_digest(),
                digest(0x81),
                1,
                epoch_one_b.activation_digest,
                &[digest(0x92), digest(0x93), digest(0x94)],
            )
            .expect("closure b"),
        );
        epoch_one_a.activation_certificate = b"activation witnesses a".to_vec();
        epoch_one_b.activation_certificate = b"activation witnesses b".to_vec();
        let a =
            build_entry(NETWORK, KEY_ID, epoch_one_a, &mut BTreeMap::new()).expect("epoch one a");
        let b =
            build_entry(NETWORK, KEY_ID, epoch_one_b, &mut BTreeMap::new()).expect("epoch one b");
        assert_ne!(a.predecessor_supersession(), b.predecessor_supersession());
        assert_eq!(a.root().expect("root a"), b.root().expect("root b"));
    }

    #[test]
    fn consensus_root_binds_the_exact_receiver_key_accumulator() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let objects = MemoryObjects::default();
        let left = input_for(&state, &objects, 0);
        let mut right = left.clone();
        right.receiver_keys =
            ReceiverKeyAccumulatorCommitment::for_test(NETWORK, 0, 2, digest(0xf1))
                .expect("alternate valid accumulator");

        let left = build_entry(NETWORK, KEY_ID, left, &mut BTreeMap::new()).expect("left entry");
        let right = build_entry(NETWORK, KEY_ID, right, &mut BTreeMap::new()).expect("right entry");
        assert_ne!(left.receiver_keys(), right.receiver_keys());
        assert_ne!(left.consensus_link(), right.consensus_link());
        assert_ne!(left.root().expect("left root"), right.root().expect("right root"));
    }

    #[test]
    fn genesis_anchor_separates_network_and_key_id() {
        let a = EpochHistoryParent::genesis(NETWORK, KEY_ID).expect("a");
        let b = EpochHistoryParent::genesis(digest(0x12), KEY_ID).expect("b");
        let c = EpochHistoryParent::genesis(NETWORK, digest(0x23)).expect("c");
        assert_ne!(a.root(), [0_u8; 32]);
        assert_ne!(a.root(), b.root());
        assert_ne!(a.root(), c.root());
        assert_ne!(a.transition_binding().expect("binding"), b.transition_binding().expect("b"));
    }

    #[test]
    fn receiver_key_accumulator_must_match_history_network_and_epoch() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let objects = MemoryObjects::default();

        let mut wrong_network = input_for(&state, &objects, 0);
        wrong_network.receiver_keys =
            ReceiverKeyAccumulatorCommitment::for_test(digest(0x12), 0, 1, digest(0xe1))
                .expect("valid foreign accumulator");
        assert!(matches!(
            state.prepare_append(wrong_network, &objects),
            Err(EpochHistoryError::InvalidEntry)
        ));

        let mut wrong_epoch = input_for(&state, &objects, 0);
        wrong_epoch.receiver_keys =
            ReceiverKeyAccumulatorCommitment::for_test(NETWORK, 1, 2, digest(0xe2))
                .expect("valid future accumulator");
        assert!(matches!(
            state.prepare_append(wrong_epoch, &objects),
            Err(EpochHistoryError::InvalidEntry)
        ));
    }

    #[test]
    fn tiny_hot_policy_keeps_unbounded_directly_addressable_history() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let mut state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let mut objects = MemoryObjects::default();

        for epoch in 0..10 {
            let input = input_for(&state, &objects, epoch);
            let (next, cleanup) = commit(&state, input, &mut objects);
            state = next;
            assert!(state.hot_entries().len() <= 2);
            if epoch < 2 {
                assert!(cleanup.coldified_epochs().is_empty());
            } else {
                assert_eq!(cleanup.coldified_epochs(), &[epoch - 2]);
            }
            if epoch == 0 {
                assert!(cleanup.superseded_avss().is_empty());
            } else {
                assert_eq!(cleanup.superseded_avss()[0].predecessor_epoch(), epoch - 1);
            }
        }

        assert_eq!(state.tip_epoch(), Some(9));
        assert_eq!(state.cold_through(), Some(7));
        assert_eq!(
            state.hot_entries().iter().map(EpochHistoryEntry::epoch).collect::<Vec<_>>(),
            [8, 9]
        );
        for epoch in 0..10 {
            assert_eq!(
                state.lookup(epoch, &objects).expect("lookup").expect("entry").epoch(),
                epoch
            );
        }
        assert!(state.lookup(10, &objects).expect("future lookup").is_none());

        let restarted = EpochHistoryState::from_bytes(&state.to_bytes().expect("encode"))
            .expect("restart state");
        restarted.verify_restart(&objects).expect("restart verify");
        assert_eq!(restarted.parent().expect("parent"), state.parent().expect("parent"));
    }

    #[test]
    fn direct_lookup_reads_no_hot_artifacts_and_only_one_cold_path() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let mut state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let mut objects = MemoryObjects::default();
        for epoch in 0..4 {
            let input = input_for(&state, &objects, epoch);
            (state, _) = commit(&state, input, &mut objects);
        }
        assert_eq!(state.cold_through(), Some(1));
        assert_eq!(
            state.hot_entries().iter().map(EpochHistoryEntry::epoch).collect::<Vec<_>>(),
            [2, 3]
        );

        let counting = CountingObjects::new(&objects);
        assert_eq!(state.lookup(3, &counting).expect("hot lookup").expect("hot entry").epoch(), 3);
        assert!(
            counting.take_reads().is_empty(),
            "a direct hot lookup must not load certificate or index artifacts"
        );

        assert_eq!(
            state.lookup(0, &counting).expect("cold lookup").expect("cold entry").epoch(),
            0
        );
        let reads = counting.take_reads();
        assert_eq!(reads.len(), MAX_EPOCH_HISTORY_COLD_LOOKUP_OBJECTS);
        assert_eq!(
            reads.iter().filter(|kind| **kind == EpochHistoryObjectKind::IndexNode).count(),
            usize::from(EPOCH_HISTORY_INDEX_DEPTH) + 1
        );
        assert_eq!(
            reads.iter().filter(|kind| **kind == EpochHistoryObjectKind::EpochEntry).count(),
            1
        );
        assert!(
            !reads.iter().any(|kind| {
                matches!(
                    kind,
                    EpochHistoryObjectKind::ActivationCertificate
                        | EpochHistoryObjectKind::KeyRotationCertificate
                )
            }),
            "direct cold lookup must not preload certificate payloads"
        );
    }

    #[test]
    fn history_remains_restartable_beyond_its_configured_hot_window() {
        let policy = EpochHistoryPolicy::new(64).expect("policy");
        let mut state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let mut objects = MemoryObjects::default();

        for epoch in 0..72 {
            let input = input_for(&state, &objects, epoch);
            (state, _) = commit(&state, input, &mut objects);
        }

        assert_eq!(state.tip_epoch(), Some(71));
        assert_eq!(state.cold_through(), Some(7));
        assert_eq!(state.hot_entries().len(), 64);
        for epoch in 0..72 {
            assert_eq!(
                state.lookup(epoch, &objects).expect("lookup").expect("entry").epoch(),
                epoch
            );
        }

        let restarted = EpochHistoryState::from_bytes(&state.to_bytes().expect("state bytes"))
            .expect("restart decode");
        restarted.verify_restart(&objects).expect("restart verification");
        assert_eq!(restarted.parent().expect("restart parent"), state.parent().expect("parent"));
    }

    #[test]
    fn catchup_is_immediate_bounded_and_manifest_scoped() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let mut state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let mut objects = MemoryObjects::default();
        for epoch in 0..5 {
            let input = input_for(&state, &objects, epoch);
            (state, _) = commit(&state, input, &mut objects);
        }

        // Epoch one is cold, but it remains directly addressable and yields the same bounded
        // successor manifest as a hot entry.
        let entry = state.lookup(1, &objects).expect("lookup").expect("entry");
        let manifest = entry.catchup_manifest().expect("manifest");
        assert_eq!(manifest.parent().epoch(), Some(0));
        assert_eq!(manifest.parent().root(), entry.previous_root());
        assert_eq!(manifest.link(), entry.consensus_link());
        assert_eq!(manifest.link().receiver_keys(), entry.receiver_keys());
        assert!(
            EpochHistoryCatchupQuery::next(manifest.parent())
                .expect("next query")
                .validate()
                .is_ok()
        );

        let activation = manifest.activation_certificate();
        let activation_bytes = objects.0.get(&activation).expect("activation object");
        let request = EpochHistoryCatchupQuery::object_chunk(
            manifest,
            activation,
            0,
            MAX_EPOCH_HISTORY_CHUNK_BYTES,
        )
        .expect("chunk query");
        request.validate().expect("valid chunk query");
        let reply = EpochHistoryCatchupReply::object_chunk(activation, 0, activation_bytes.clone())
            .expect("chunk reply");
        reply.validate().expect("valid chunk reply");
        reply.validate_for_query(&request).expect("full requested chunk is bound to its query");
        assert!(activation_bytes.len() > 1);
        let one_byte_reply =
            EpochHistoryCatchupReply::object_chunk(activation, 0, activation_bytes[..1].to_vec())
                .expect("structurally valid short reply");
        assert!(matches!(
            one_byte_reply.validate_for_query(&request),
            Err(EpochHistoryError::InvalidCatchup)
        ));
        assert_eq!(MAX_EPOCH_HISTORY_REQUESTS_PER_SOURCE, 65);

        let unrelated = EpochHistoryObjectRef::for_contents(
            NETWORK,
            EpochHistoryObjectKind::ActivationCertificate,
            b"not named by the manifest",
        )
        .expect("unrelated reference");
        assert!(matches!(
            EpochHistoryCatchupQuery::object_chunk(
                manifest,
                unrelated,
                0,
                MAX_EPOCH_HISTORY_CHUNK_BYTES,
            ),
            Err(EpochHistoryError::InvalidCatchup)
        ));
        assert!(matches!(
            EpochHistoryCatchupQuery::object_chunk(
                manifest,
                activation,
                activation.plaintext_len(),
                MAX_EPOCH_HISTORY_CHUNK_BYTES,
            ),
            Err(EpochHistoryError::InvalidCatchup)
        ));
        assert!(matches!(
            EpochHistoryCatchupQuery::object_chunk(
                manifest,
                activation,
                0,
                MAX_EPOCH_HISTORY_CHUNK_BYTES + 1,
            ),
            Err(EpochHistoryError::InvalidCatchup)
        ));

        let mut wrong_parent = manifest;
        wrong_parent.parent = EpochHistoryParent::genesis(NETWORK, KEY_ID).expect("genesis");
        assert!(matches!(wrong_parent.validate(), Err(EpochHistoryError::InvalidCatchup)));
    }

    #[test]
    fn more_than_4096_independent_negative_records_cannot_block_activation() {
        let policy = EpochHistoryPolicy::new(1).expect("policy");
        let mut state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let mut objects = MemoryObjects::default();
        // Models independently keyed retirement/tombstone/high-water records. Epoch history has
        // no field or code path which enumerates this set.
        let independent_negative_records = (0_u32..10_000)
            .map(|ordinal| (ordinal, ordinal.to_le_bytes()))
            .collect::<BTreeMap<_, _>>();
        let before = independent_negative_records.clone();
        let zero = input_for(&state, &objects, 0);
        (state, _) = commit(&state, zero, &mut objects);
        let one = input_for(&state, &objects, 1);
        let (next, cleanup) = commit(&state, one, &mut objects);
        state = next;
        assert_eq!(cleanup.coldified_epochs(), &[0]);
        assert_eq!(independent_negative_records, before);
        assert_eq!(state.tip_epoch(), Some(1));
    }

    #[test]
    fn crash_tails_are_idempotent_and_cleanup_requires_exact_cas() {
        let policy = EpochHistoryPolicy::new(1).expect("policy");
        let mut state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let mut objects = MemoryObjects::default();
        let genesis_bytes = state.to_bytes().expect("genesis bytes");
        let input = input_for(&state, &objects, 0);

        // Crash after staging but before the state CAS: unreachable objects do not change state.
        let pending = state.prepare_append(input.clone(), &objects).expect("pending");
        objects.install(&pending);
        let restarted = EpochHistoryState::from_bytes(&genesis_bytes).expect("old state");
        assert_eq!(restarted.tip_epoch(), None);
        let retry = restarted.prepare_append(input, &objects).expect("retry");
        assert_eq!(pending.staged_objects(), retry.staged_objects());

        // CAS succeeds but cleanup is interrupted: restart observes the new state and cleanup can
        // be authorized again from exact bytes.
        let verified = retry.verify_staged(&objects).expect("verified");
        let committed = verified.next_state_bytes().to_vec();
        assert!(verified.authorize_cleanup(&genesis_bytes).is_err());
        let first_cleanup = verified.authorize_cleanup(&committed).expect("cleanup");
        let after_crash = EpochHistoryState::from_bytes(&committed).expect("committed state");
        after_crash.verify_restart(&objects).expect("restart verification");
        assert_eq!(verified.authorize_cleanup(&committed).expect("retry cleanup"), first_cleanup);
        state = after_crash;

        // Force epoch zero cold, then prove a referenced-object loss fails closed on direct use.
        let one = input_for(&state, &objects, 1);
        (state, _) = commit(&state, one, &mut objects);
        let cold = state.lookup(0, &objects).expect("cold lookup").expect("cold entry");
        objects.0.remove(&cold.activation_certificate());
        assert!(matches!(state.verify_restart(&objects), Ok(())));
        // Startup authenticates the cold tail entry/index but intentionally does not read every
        // archived payload; the exact historical certificate fails closed when requested.
        assert!(matches!(
            load_required(&objects, cold.activation_certificate()),
            Err(EpochHistoryError::MissingObject(_))
        ));
    }

    #[test]
    fn every_pre_accumulator_history_schema_is_rejected() {
        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let objects = MemoryObjects::default();
        let entry =
            build_entry(NETWORK, KEY_ID, input_for(&state, &objects, 0), &mut BTreeMap::new())
                .expect("entry");

        let mut old_parent = EpochHistoryParent::genesis(NETWORK, KEY_ID).expect("parent");
        old_parent.version = HISTORY_PARENT_VERSION - 1;
        assert!(matches!(old_parent.validate(), Err(EpochHistoryError::InvalidParent)));

        let mut old_reference = entry.activation_certificate();
        old_reference.version = HISTORY_REFERENCE_VERSION - 1;
        assert!(matches!(old_reference.validate(), Err(EpochHistoryError::InvalidObjectReference)));

        let mut old_entry = entry.clone();
        old_entry.version = HISTORY_ENTRY_VERSION - 1;
        let old_entry_bytes = postcard::to_allocvec(&old_entry).expect("old entry bytes");
        assert!(matches!(
            EpochHistoryEntry::from_bytes(&old_entry_bytes),
            Err(EpochHistoryError::InvalidEntry)
        ));

        let mut old_link = entry.consensus_link();
        old_link.version = HISTORY_ENTRY_VERSION - 1;
        assert!(matches!(old_link.root(), Err(EpochHistoryError::InvalidEntry)));

        let mut old_manifest = entry.catchup_manifest().expect("manifest");
        old_manifest.version = HISTORY_CATCHUP_VERSION - 1;
        assert!(matches!(old_manifest.validate(), Err(EpochHistoryError::InvalidCatchup)));

        let mut old_query =
            EpochHistoryCatchupQuery::next(state.parent().expect("state parent")).expect("query");
        let EpochHistoryCatchupQuery::Next { version, .. } = &mut old_query else {
            panic!("next query");
        };
        *version = HISTORY_CATCHUP_VERSION - 1;
        assert!(matches!(old_query.validate(), Err(EpochHistoryError::InvalidCatchup)));

        let mut old_supersession = AvssSuccessorSupersession::new(
            0,
            entry.root().expect("entry root"),
            entry.transition_digest(),
            digest(0x81),
            1,
            digest(0x41),
            &[digest(0xa1)],
        )
        .expect("supersession");
        old_supersession.version = HISTORY_SUPERSESSION_VERSION - 1;
        assert!(matches!(old_supersession.validate(), Err(EpochHistoryError::InvalidSupersession)));

        let mut old_index = EpochIndexNode {
            version: HISTORY_INDEX_NODE_VERSION - 1,
            network: NETWORK,
            body: EpochIndexNodeBody::Leaf {
                epoch: 0,
                consensus_root: entry.root().expect("entry root"),
                entry: EpochHistoryObjectRef::for_contents(
                    NETWORK,
                    EpochHistoryObjectKind::EpochEntry,
                    &entry.to_bytes().expect("entry bytes"),
                )
                .expect("entry reference"),
            },
        };
        assert!(matches!(old_index.validate(), Err(EpochHistoryError::BrokenIndex)));
        old_index.version = HISTORY_INDEX_NODE_VERSION;
        old_index.validate().expect("current index");

        let mut old_head = state.head;
        old_head.version = HISTORY_HEAD_VERSION - 1;
        assert!(matches!(old_head.validate(), Err(EpochHistoryError::InvalidHead)));

        let mut old_state = state;
        old_state.version = HISTORY_STATE_VERSION - 1;
        let old_state_bytes = postcard::to_allocvec(&old_state).expect("old state bytes");
        assert!(matches!(
            EpochHistoryState::from_bytes(&old_state_bytes),
            Err(EpochHistoryError::InvalidState)
        ));
    }

    #[test]
    fn wrong_parent_versions_and_metadata_mismatches_fail_closed() {
        assert!(EpochHistoryPolicy::new(0).is_err());
        assert!(EpochHistoryPolicy::new(MAX_HOT_EPOCH_HISTORY_ENTRIES + 1).is_err());

        let policy = EpochHistoryPolicy::new(2).expect("policy");
        let state = EpochHistoryState::new(NETWORK, KEY_ID, policy).expect("state");
        let objects = MemoryObjects::default();
        let mut wrong_parent = input_for(&state, &objects, 0);
        wrong_parent.parent = EpochHistoryParent::genesis(digest(0x19), KEY_ID).expect("parent");
        assert!(matches!(
            state.prepare_append(wrong_parent, &objects),
            Err(EpochHistoryError::ParentMismatch)
        ));

        let mut mismatched_rotation = input_for(&state, &objects, 0);
        mismatched_rotation.key_rotation_digest = Some(digest(0x55));
        assert!(matches!(
            state.prepare_append(mismatched_rotation, &objects),
            Err(EpochHistoryError::InvalidEntry)
        ));

        let mut future = input_for(&state, &objects, 0);
        future.epoch = 1;
        assert!(matches!(
            state.prepare_append(future, &objects),
            Err(EpochHistoryError::EpochSequence { .. })
        ));

        let mut unsupported = state;
        unsupported.version = HISTORY_STATE_VERSION + 1;
        let bytes = postcard::to_allocvec(&unsupported).expect("serialize unsupported state");
        assert!(matches!(
            EpochHistoryState::from_bytes(&bytes),
            Err(EpochHistoryError::InvalidState)
        ));
    }
}
