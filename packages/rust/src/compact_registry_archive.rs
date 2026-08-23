//! Fixed-depth authenticated storage for [`CompactEpochRegistry`].
//!
//! The mutable head contains one active committee and three content references.  Every historical
//! epoch lives in an immutable object selected through a 64-level persistent binary index, so
//! successful lookup and append work are bounded independently of wallet lifetime.
//!
//! Mutation ordering is intentional:
//!
//! 1. install and fsync every [`StagedCompactRegistryObject`];
//! 2. call [`PendingCompactRegistryMutation::verify_staged`];
//! 3. CAS the exact [`VerifiedCompactRegistryMutation::next_head_bytes`] against the exact
//!    [`VerifiedCompactRegistryMutation::expected_head_bytes`].
//!
//! A pre-CAS crash leaves only unreachable immutable objects.  A post-CAS restart validates a
//! bounded active transition and its fixed-depth index paths; it never replays the epoch prefix.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    compact_epoch_registry::{
        COMPACT_REGISTRY_INDEX_DEPTH, CompactEpochRegistry, CompactRegistryError,
        RegistryHandoffCertificate, RegistryId, RegistryLink, VerifiedIssuerWindow,
        compact_registry_empty_index_hash_at, compact_registry_empty_index_root,
        compact_registry_index_branch_hash, compact_registry_index_leaf_hash,
    },
    deposit_index_checkpoint::PortableDepositIndexHead,
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
    key_rotation::VerifiedRegistryHandoffTarget,
    storage::{WalletArtifactKind, WalletArtifactRef, WalletId},
};

pub const COMPACT_REGISTRY_ARCHIVE_HEAD_VERSION: u16 = 2;
pub const COMPACT_REGISTRY_ARCHIVE_REFERENCE_VERSION: u16 = 2;
pub const COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION: u16 = 2;

pub const MAX_COMPACT_REGISTRY_HEAD_BYTES: usize = 16 * 1024;
pub const MAX_COMPACT_REGISTRY_LINK_BYTES: usize = 16 * 1024;
pub const MAX_COMPACT_REGISTRY_WITNESS_BYTES: usize = 256 * 1024;
pub const MAX_COMPACT_REGISTRY_INDEX_NODE_BYTES: usize = 2 * 1024;
pub const MAX_COMPLETE_COMPACT_REGISTRY_GRAPH_CURSOR_BYTES: usize = 4 * 1024;

/// Genesis stages one link plus 65 index nodes.  Every append additionally stages one witness.
pub const COMPACT_REGISTRY_GENESIS_OBJECTS: usize = COMPACT_REGISTRY_INDEX_DEPTH as usize + 2;
pub const COMPACT_REGISTRY_APPEND_OBJECTS: usize = COMPACT_REGISTRY_INDEX_DEPTH as usize + 3;
/// A successful index lookup always reads 64 branches and one leaf.
pub const COMPACT_REGISTRY_INDEX_OBJECT_READS: usize = COMPACT_REGISTRY_INDEX_DEPTH as usize + 1;

const HEAD_DIGEST_DOMAIN: &str = "threshold-monero/compact-registry-archive-head/v2";
const COMPLETE_GRAPH_CURSOR_VERSION: u16 = 1;
const COMPLETE_GRAPH_FRONTIER_SLOTS: usize = COMPACT_REGISTRY_INDEX_DEPTH as usize + 1;

/// Type tag included in every immutable content address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(u8)]
pub enum CompactRegistryObjectKind {
    Link = 1,
    HandoffWitness = 2,
    IndexNode = 3,
}

impl CompactRegistryObjectKind {
    const fn maximum_bytes(self) -> usize {
        match self {
            Self::Link => MAX_COMPACT_REGISTRY_LINK_BYTES,
            Self::HandoffWitness => MAX_COMPACT_REGISTRY_WITNESS_BYTES,
            Self::IndexNode => MAX_COMPACT_REGISTRY_INDEX_NODE_BYTES,
        }
    }

    const fn storage_kind(self) -> WalletArtifactKind {
        WalletArtifactKind(match self {
            Self::Link => 0xe201,
            Self::HandoffWitness => 0xe202,
            Self::IndexNode => 0xe203,
        })
    }
}

/// Portable wallet-bound address of one immutable compact-registry object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CompactRegistryObjectRef {
    version: u16,
    wallet: DepositWalletId,
    kind: CompactRegistryObjectKind,
    plaintext_len: u64,
    digest: [u8; 32],
}

impl CompactRegistryObjectRef {
    pub fn for_contents(
        wallet: DepositWalletId,
        kind: CompactRegistryObjectKind,
        contents: &[u8],
    ) -> Result<Self, CompactRegistryArchiveError> {
        if wallet.0 == [0_u8; 32] || contents.is_empty() {
            return Err(CompactRegistryArchiveError::InvalidObjectReference);
        }
        if contents.len() > kind.maximum_bytes() {
            return Err(CompactRegistryArchiveError::ObjectTooLarge {
                kind: "compact registry object",
                actual: contents.len(),
                maximum: kind.maximum_bytes(),
            });
        }
        let plaintext_len = u64::try_from(contents.len())
            .map_err(|_| CompactRegistryArchiveError::Serialization)?;
        let storage =
            WalletArtifactRef::for_contents(WalletId(wallet.0), kind.storage_kind(), contents)
                .map_err(|_| CompactRegistryArchiveError::InvalidObjectReference)?;
        let reference = Self {
            version: COMPACT_REGISTRY_ARCHIVE_REFERENCE_VERSION,
            wallet,
            kind,
            plaintext_len,
            digest: storage.digest(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn verify_contents(self, contents: &[u8]) -> Result<(), CompactRegistryArchiveError> {
        self.validate()?;
        if Self::for_contents(self.wallet, self.kind, contents)? != self {
            return Err(CompactRegistryArchiveError::ObjectAuthentication);
        }
        Ok(())
    }

    pub fn storage_reference(self) -> Result<WalletArtifactRef, CompactRegistryArchiveError> {
        self.validate()?;
        WalletArtifactRef::from_parts(
            WalletId(self.wallet.0),
            self.kind.storage_kind(),
            self.plaintext_len,
            self.digest,
        )
        .map_err(|_| CompactRegistryArchiveError::InvalidObjectReference)
    }

    fn validate(self) -> Result<(), CompactRegistryArchiveError> {
        let length = usize::try_from(self.plaintext_len)
            .map_err(|_| CompactRegistryArchiveError::InvalidObjectReference)?;
        if self.version != COMPACT_REGISTRY_ARCHIVE_REFERENCE_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.plaintext_len == 0
            || length > self.kind.maximum_bytes()
            || self.digest == [0_u8; 32]
        {
            return Err(CompactRegistryArchiveError::InvalidObjectReference);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn kind(self) -> CompactRegistryObjectKind {
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
}

/// Exact immutable object which must be durable before the head CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedCompactRegistryObject {
    reference: CompactRegistryObjectRef,
    contents: Vec<u8>,
}

impl StagedCompactRegistryObject {
    #[must_use]
    pub const fn reference(&self) -> CompactRegistryObjectRef {
        self.reference
    }

    #[must_use]
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }
}

/// Read-only view of installed immutable objects.
///
/// An asynchronous encrypted-store adapter can preload the bounded paths before calling this
/// synchronous protocol core.
pub trait CompactRegistryObjectReader {
    fn load(
        &self,
        reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError>;
}

/// One authenticated step while an asynchronous adapter preloads a direct index path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactRegistryIndexStep {
    Branch {
        next: Option<CompactRegistryObjectRef>,
        next_semantic_hash: [u8; 32],
    },
    Leaf {
        link_root: [u8; 32],
        link: CompactRegistryObjectRef,
        witness: Option<CompactRegistryObjectRef>,
    },
}

/// Canonically decoded compact-registry object used only for ordered reachability checks.
///
/// This token is not deserializable. Its child set comes exclusively from exact,
/// content-authenticated object bytes, so a transfer handler can reject arbitrary same-wallet
/// references before returning their plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCompactRegistryObject {
    children: Vec<CompactRegistryObjectRef>,
}

impl VerifiedCompactRegistryObject {
    #[must_use]
    pub fn children(&self) -> &[CompactRegistryObjectRef] {
        &self.children
    }
}

/// Exact semantic position of one object in a compact-registry traversal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum CompactRegistryTraversalTarget {
    Index { reference: CompactRegistryObjectRef, depth: u8, semantic_hash: [u8; 32] },
    Link { reference: CompactRegistryObjectRef, epoch: u64, chain_root: [u8; 32] },
    HandoffWitness { reference: CompactRegistryObjectRef, target_epoch: u64 },
}

impl CompactRegistryTraversalTarget {
    #[must_use]
    pub const fn reference(self) -> CompactRegistryObjectRef {
        match self {
            Self::Index { reference, .. }
            | Self::Link { reference, .. }
            | Self::HandoffWitness { reference, .. } => reference,
        }
    }
}

/// Authenticate one compact-registry object at an exact semantic position and derive only its
/// exact successor positions.
pub fn verify_compact_registry_traversal_object(
    target: CompactRegistryTraversalTarget,
    contents: &[u8],
) -> Result<Vec<CompactRegistryTraversalTarget>, CompactRegistryArchiveError> {
    let reference = target.reference();
    reference.verify_contents(contents)?;
    match target {
        CompactRegistryTraversalTarget::Index { reference, depth, semantic_hash } => {
            if reference.kind != CompactRegistryObjectKind::IndexNode
                || depth > COMPACT_REGISTRY_INDEX_DEPTH
                || semantic_hash == [0; 32]
            {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            let node = CompactRegistryIndexNode::from_bytes(contents)?;
            if node.wallet != reference.wallet || node.semantic_hash()? != semantic_hash {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            match node.body {
                CompactRegistryIndexNodeBody::Branch { depth: actual, left, right } => {
                    if actual != depth || depth == COMPACT_REGISTRY_INDEX_DEPTH {
                        return Err(CompactRegistryArchiveError::BrokenIndex);
                    }
                    let child_depth =
                        depth.checked_add(1).ok_or(CompactRegistryArchiveError::BrokenIndex)?;
                    Ok([left, right]
                        .into_iter()
                        .filter_map(|child| {
                            child.object.map(|reference| CompactRegistryTraversalTarget::Index {
                                reference,
                                depth: child_depth,
                                semantic_hash: child.semantic_hash,
                            })
                        })
                        .collect())
                }
                CompactRegistryIndexNodeBody::Leaf { epoch, link_root, link, witness } => {
                    if depth != COMPACT_REGISTRY_INDEX_DEPTH {
                        return Err(CompactRegistryArchiveError::BrokenIndex);
                    }
                    let mut children = Vec::with_capacity(2);
                    children.push(CompactRegistryTraversalTarget::Link {
                        reference: link,
                        epoch,
                        chain_root: link_root,
                    });
                    children.extend(witness.map(|reference| {
                        CompactRegistryTraversalTarget::HandoffWitness {
                            reference,
                            target_epoch: epoch,
                        }
                    }));
                    Ok(children)
                }
            }
        }
        CompactRegistryTraversalTarget::Link { reference, epoch, chain_root } => {
            if reference.kind != CompactRegistryObjectKind::Link || chain_root == [0; 32] {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            let link = decode_canonical_bounded::<RegistryLink>(
                contents,
                MAX_COMPACT_REGISTRY_LINK_BYTES,
                "compact registry link",
            )?;
            link.validate()?;
            if link.wallet() != reference.wallet
                || link.epoch() != epoch
                || link.chain_root()? != chain_root
            {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            Ok(Vec::new())
        }
        CompactRegistryTraversalTarget::HandoffWitness { reference, target_epoch } => {
            if reference.kind != CompactRegistryObjectKind::HandoffWitness || target_epoch == 0 {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            let certificate = decode_canonical_bounded::<RegistryHandoffCertificate>(
                contents,
                MAX_COMPACT_REGISTRY_WITNESS_BYTES,
                "compact registry handoff witness",
            )?;
            if certificate.statement().wallet() != reference.wallet
                || certificate.statement().target_epoch() != target_epoch
            {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            Ok(Vec::new())
        }
    }
}

/// Authenticate and canonically decode one compact-registry object, returning only its bounded
/// content-addressed child edges.
pub fn verify_compact_registry_object(
    reference: CompactRegistryObjectRef,
    contents: &[u8],
) -> Result<VerifiedCompactRegistryObject, CompactRegistryArchiveError> {
    reference.verify_contents(contents)?;
    let children = match reference.kind {
        CompactRegistryObjectKind::Link => {
            let link = decode_canonical_bounded::<RegistryLink>(
                contents,
                MAX_COMPACT_REGISTRY_LINK_BYTES,
                "compact registry link",
            )?;
            link.validate()?;
            if link.wallet() != reference.wallet {
                return Err(CompactRegistryArchiveError::ObjectAuthentication);
            }
            Vec::new()
        }
        CompactRegistryObjectKind::HandoffWitness => {
            let certificate = decode_canonical_bounded::<RegistryHandoffCertificate>(
                contents,
                MAX_COMPACT_REGISTRY_WITNESS_BYTES,
                "compact registry handoff witness",
            )?;
            if certificate.statement().wallet() != reference.wallet {
                return Err(CompactRegistryArchiveError::ObjectAuthentication);
            }
            Vec::new()
        }
        CompactRegistryObjectKind::IndexNode => {
            let node = CompactRegistryIndexNode::from_bytes(contents)?;
            if node.wallet != reference.wallet {
                return Err(CompactRegistryArchiveError::ObjectAuthentication);
            }
            match node.body {
                CompactRegistryIndexNodeBody::Branch { left, right, .. } => {
                    [left.object, right.object].into_iter().flatten().collect()
                }
                CompactRegistryIndexNodeBody::Leaf { link, witness, .. } => {
                    let mut children = Vec::with_capacity(2);
                    children.push(link);
                    children.extend(witness);
                    children
                }
            }
        }
    };
    Ok(VerifiedCompactRegistryObject { children })
}

/// Authenticate one supplied index object and choose the unique next reference for `epoch`.
///
/// This exposes no mutable trie internals.  It lets a `WalletArtifactStore` adapter perform the
/// same fixed 65 reads asynchronously, cache the exact plaintexts in a bounded map, and then call
/// the synchronous verification APIs in this module.
pub fn compact_registry_index_step(
    wallet: DepositWalletId,
    epoch: u64,
    depth: u8,
    expected_semantic_hash: [u8; 32],
    reference: CompactRegistryObjectRef,
    contents: &[u8],
) -> Result<CompactRegistryIndexStep, CompactRegistryArchiveError> {
    if depth > COMPACT_REGISTRY_INDEX_DEPTH
        || reference.wallet != wallet
        || reference.kind != CompactRegistryObjectKind::IndexNode
    {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    reference.verify_contents(contents)?;
    let node = CompactRegistryIndexNode::from_bytes(contents)?;
    if node.wallet != wallet || node.semantic_hash()? != expected_semantic_hash {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    if depth == COMPACT_REGISTRY_INDEX_DEPTH {
        let CompactRegistryIndexNodeBody::Leaf { epoch: actual, link_root, link, witness } =
            node.body
        else {
            return Err(CompactRegistryArchiveError::BrokenIndex);
        };
        if actual != epoch {
            return Err(CompactRegistryArchiveError::MissingEpoch(epoch));
        }
        return Ok(CompactRegistryIndexStep::Leaf { link_root, link, witness });
    }
    let CompactRegistryIndexNodeBody::Branch { depth: actual, left, right } = node.body else {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    };
    if actual != depth {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    let shift = u32::from(COMPACT_REGISTRY_INDEX_DEPTH - depth - 1);
    let selected = if ((epoch >> shift) & 1) == 0 { left } else { right };
    Ok(CompactRegistryIndexStep::Branch {
        next: selected.object,
        next_semantic_hash: selected.semantic_hash,
    })
}

/// Constant-size authoritative archive head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactRegistryArchiveHead {
    version: u16,
    wallet: DepositWalletId,
    /// Zero-based CAS generation. Epochs are contiguous from genesis, so this is exactly the
    /// active epoch and remains representable when the terminal epoch is `u64::MAX`.
    revision: u64,
    registry: CompactEpochRegistry,
    index_root: CompactRegistryObjectRef,
    active_link: CompactRegistryObjectRef,
    active_witness: Option<CompactRegistryObjectRef>,
}

impl CompactRegistryArchiveHead {
    pub fn validate_shape(&self) -> Result<(), CompactRegistryArchiveError> {
        self.registry.validate()?;
        self.index_root.validate()?;
        self.active_link.validate()?;
        if self.version != COMPACT_REGISTRY_ARCHIVE_HEAD_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.revision != archive_revision_for_epoch(self.registry.active_epoch())
            || self.registry.wallet() != self.wallet
            || self.index_root.wallet != self.wallet
            || self.index_root.kind != CompactRegistryObjectKind::IndexNode
            || self.active_link.wallet != self.wallet
            || self.active_link.kind != CompactRegistryObjectKind::Link
        {
            return Err(CompactRegistryArchiveError::InvalidHead);
        }
        if let Some(witness) = self.active_witness {
            witness.validate()?;
            if witness.wallet != self.wallet
                || witness.kind != CompactRegistryObjectKind::HandoffWitness
            {
                return Err(CompactRegistryArchiveError::InvalidHead);
            }
        }
        Ok(())
    }

    /// Verify the semantic index root, active link, and (for a successor) its old-quorum
    /// root-bound witness.  Work is bounded by at most two fixed-depth paths.
    pub fn verify_bounded<R: CompactRegistryObjectReader>(
        &self,
        reader: &R,
    ) -> Result<(), CompactRegistryArchiveError> {
        self.validate_shape()?;
        let active = verify_epoch_at(self, self.registry.active_epoch(), reader)?;
        let reconstructed =
            CompactEpochRegistry::from_link(&active.link, self.registry.id().index_root())?;
        if reconstructed != self.registry
            || active.link_reference != self.active_link
            || active.witness_reference != self.active_witness
            || active.prior_index_root != active.link.parent_index_root()
        {
            return Err(CompactRegistryArchiveError::InvalidHead);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CompactRegistryArchiveError> {
        self.validate_shape()?;
        encode_bounded(self, MAX_COMPACT_REGISTRY_HEAD_BYTES, "compact registry head")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompactRegistryArchiveError> {
        let head = decode_canonical_bounded::<Self>(
            bytes,
            MAX_COMPACT_REGISTRY_HEAD_BYTES,
            "compact registry head",
        )?;
        head.validate_shape()?;
        Ok(head)
    }

    #[must_use]
    pub fn digest(&self) -> Result<[u8; 32], CompactRegistryArchiveError> {
        let bytes = self.to_bytes()?;
        let mut hasher = blake3::Hasher::new_derive_key(HEAD_DIGEST_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn registry(&self) -> &CompactEpochRegistry {
        &self.registry
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.registry.id()
    }

    #[must_use]
    pub const fn index_root_reference(&self) -> CompactRegistryObjectRef {
        self.index_root
    }

    #[must_use]
    pub const fn active_link_reference(&self) -> CompactRegistryObjectRef {
        self.active_link
    }

    #[must_use]
    pub const fn active_witness_reference(&self) -> Option<CompactRegistryObjectRef> {
        self.active_witness
    }
}

const fn archive_revision_for_epoch(active_epoch: u64) -> u64 {
    active_epoch
}

/// One directly authenticated historical epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRegistryEpoch {
    link: RegistryLink,
    link_reference: CompactRegistryObjectRef,
    witness: Option<RegistryHandoffCertificate>,
    witness_reference: Option<CompactRegistryObjectRef>,
    /// Root obtained by replacing this leaf with the canonical empty slot.  It is checked against
    /// the active link's signed parent root during head verification.
    prior_index_root: [u8; 32],
}

impl VerifiedRegistryEpoch {
    #[must_use]
    pub const fn link(&self) -> &RegistryLink {
        &self.link
    }

    #[must_use]
    pub const fn link_reference(&self) -> CompactRegistryObjectRef {
        self.link_reference
    }

    #[must_use]
    pub const fn witness(&self) -> Option<&RegistryHandoffCertificate> {
        self.witness.as_ref()
    }

    #[must_use]
    pub const fn witness_reference(&self) -> Option<CompactRegistryObjectRef> {
        self.witness_reference
    }
}

/// Canonical restart state for complete historical compact-registry verification.
///
/// One call to [`verify_complete_compact_registry_graph_step`] authenticates exactly one epoch,
/// so work remains bounded by at most two fixed-depth index paths and two bounded witness
/// decodes. The sparse-Merkle frontier proves that the authenticated index contains exactly the
/// contiguous prefix already checked, rather than merely proving that each queried leaf exists.
///
/// Cursor bytes are resumable progress, not an independently authenticated wire proof. Production
/// callers must store them under the same authenticated local state which binds the exact archive
/// head. A completion capability is returned only by the step verifier and is never serializable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompleteCompactRegistryGraphCursor {
    version: u16,
    head_digest: [u8; 32],
    registry: RegistryId,
    verified_epochs: u128,
    frontier: Vec<Option<[u8; 32]>>,
}

impl CompleteCompactRegistryGraphCursor {
    pub fn new(head: &CompactRegistryArchiveHead) -> Result<Self, CompactRegistryArchiveError> {
        head.validate_shape()?;
        let cursor = Self {
            version: COMPLETE_GRAPH_CURSOR_VERSION,
            head_digest: head.digest()?,
            registry: head.registry_id(),
            verified_epochs: 0,
            frontier: vec![None; COMPLETE_GRAPH_FRONTIER_SLOTS],
        };
        cursor.validate_for(head)?;
        Ok(cursor)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CompactRegistryArchiveError> {
        self.validate_shape()?;
        encode_bounded(
            self,
            MAX_COMPLETE_COMPACT_REGISTRY_GRAPH_CURSOR_BYTES,
            "complete compact registry graph cursor",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompactRegistryArchiveError> {
        let cursor: Self = decode_canonical_bounded(
            bytes,
            MAX_COMPLETE_COMPACT_REGISTRY_GRAPH_CURSOR_BYTES,
            "complete compact registry graph cursor",
        )?;
        cursor.validate_shape()?;
        Ok(cursor)
    }

    #[must_use]
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.registry
    }

    #[must_use]
    pub const fn verified_epochs(&self) -> u128 {
        self.verified_epochs
    }

    #[must_use]
    pub fn next_epoch(&self) -> Option<u64> {
        let total = complete_registry_epoch_count(self.registry.active_epoch());
        (self.verified_epochs < total).then(|| u64::try_from(self.verified_epochs).ok()).flatten()
    }

    fn validate_shape(&self) -> Result<(), CompactRegistryArchiveError> {
        self.registry.validate()?;
        let total = complete_registry_epoch_count(self.registry.active_epoch());
        if self.version != COMPLETE_GRAPH_CURSOR_VERSION
            || self.head_digest == [0; 32]
            || self.verified_epochs >= total
            || self.frontier.len() != COMPLETE_GRAPH_FRONTIER_SLOTS
        {
            return Err(CompactRegistryArchiveError::InvalidCompleteGraphCursor);
        }
        validate_complete_graph_frontier(self.verified_epochs, &self.frontier)
    }

    fn validate_for(
        &self,
        head: &CompactRegistryArchiveHead,
    ) -> Result<(), CompactRegistryArchiveError> {
        self.validate_shape()?;
        head.validate_shape()?;
        if self.head_digest != head.digest()? || self.registry != head.registry_id() {
            return Err(CompactRegistryArchiveError::WrongCompleteGraphHead);
        }
        Ok(())
    }

    fn prefix_index_root(&self) -> Result<[u8; 32], CompactRegistryArchiveError> {
        complete_graph_frontier_root(self.registry.wallet(), self.verified_epochs, &self.frontier)
    }

    fn append_verified_link(
        &mut self,
        epoch: u64,
        link_root: [u8; 32],
    ) -> Result<(), CompactRegistryArchiveError> {
        if self.verified_epochs != u128::from(epoch) || link_root == [0; 32] {
            return Err(CompactRegistryArchiveError::InvalidCompleteGraphCursor);
        }
        let mut height = 0_usize;
        let mut subtree =
            compact_registry_index_leaf_hash(self.registry.wallet(), epoch, link_root);
        while height < usize::from(COMPACT_REGISTRY_INDEX_DEPTH)
            && ((self.verified_epochs >> height) & 1) == 1
        {
            let left = self.frontier[height]
                .take()
                .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?;
            let depth = COMPACT_REGISTRY_INDEX_DEPTH
                .checked_sub(
                    u8::try_from(height)
                        .map_err(|_| CompactRegistryArchiveError::InvalidCompleteGraphCursor)?
                        .checked_add(1)
                        .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?,
                )
                .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?;
            subtree =
                compact_registry_index_branch_hash(self.registry.wallet(), depth, left, subtree);
            height += 1;
        }
        if self.frontier.get(height).is_none_or(Option::is_some) {
            return Err(CompactRegistryArchiveError::InvalidCompleteGraphCursor);
        }
        self.frontier[height] = Some(subtree);
        self.verified_epochs =
            self.verified_epochs.checked_add(1).ok_or(CompactRegistryArchiveError::Overflow)?;
        validate_complete_graph_frontier(self.verified_epochs, &self.frontier)
    }
}

/// Non-serializable proof that every epoch in one exact compact-registry head was authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCompleteCompactRegistryGraph {
    head_digest: [u8; 32],
    registry: RegistryId,
    verified_epochs: u128,
}

impl VerifiedCompleteCompactRegistryGraph {
    #[must_use]
    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.registry
    }

    #[must_use]
    pub const fn verified_epochs(&self) -> u128 {
        self.verified_epochs
    }

    pub fn authenticates(
        &self,
        head: &CompactRegistryArchiveHead,
    ) -> Result<bool, CompactRegistryArchiveError> {
        Ok(self.head_digest == head.digest()? && self.registry == head.registry_id())
    }
}

/// Result of one bounded complete-history verification step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompleteCompactRegistryGraphStep {
    Pending(CompleteCompactRegistryGraphCursor),
    Complete(VerifiedCompleteCompactRegistryGraph),
}

/// Authenticate one exact historical epoch and advance the restart cursor.
///
/// Completion additionally proves that rebuilding the sparse semantic index from only epochs
/// `0..=active` yields the head's exact `RegistryId::index_root`. Missing epochs, duplicate or
/// extra leaves, and index entries not justified by the certified handoff chain therefore fail
/// closed even when a bounded active-head verification would not visit them.
pub fn verify_complete_compact_registry_graph_step<R: CompactRegistryObjectReader>(
    head: &CompactRegistryArchiveHead,
    mut cursor: CompleteCompactRegistryGraphCursor,
    reader: &R,
) -> Result<CompleteCompactRegistryGraphStep, CompactRegistryArchiveError> {
    cursor.validate_for(head)?;
    let epoch =
        cursor.next_epoch().ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?;
    let prefix_root = cursor.prefix_index_root()?;
    let verified = verify_epoch_at(head, epoch, reader)?;
    if verified.link.parent_index_root() != prefix_root {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    let link_root = verified.link.chain_root()?;
    cursor.append_verified_link(epoch, link_root)?;

    if epoch != head.registry().active_epoch() {
        return Ok(CompleteCompactRegistryGraphStep::Pending(cursor));
    }

    let reconstructed_root = cursor.prefix_index_root()?;
    let reconstructed = CompactEpochRegistry::from_link(&verified.link, reconstructed_root)?;
    if reconstructed != *head.registry()
        || reconstructed_root != head.registry_id().index_root()
        || verified.link_reference != head.active_link_reference()
        || verified.witness_reference != head.active_witness_reference()
        || verified.prior_index_root != prefix_root
    {
        return Err(CompactRegistryArchiveError::InvalidHead);
    }
    Ok(CompleteCompactRegistryGraphStep::Complete(VerifiedCompleteCompactRegistryGraph {
        head_digest: cursor.head_digest,
        registry: cursor.registry,
        verified_epochs: cursor.verified_epochs,
    }))
}

const fn complete_registry_epoch_count(active_epoch: u64) -> u128 {
    active_epoch as u128 + 1
}

fn validate_complete_graph_frontier(
    verified_epochs: u128,
    frontier: &[Option<[u8; 32]>],
) -> Result<(), CompactRegistryArchiveError> {
    let maximum_count = 1_u128 << COMPACT_REGISTRY_INDEX_DEPTH;
    if verified_epochs > maximum_count || frontier.len() != COMPLETE_GRAPH_FRONTIER_SLOTS {
        return Err(CompactRegistryArchiveError::InvalidCompleteGraphCursor);
    }
    for (height, root) in frontier.iter().enumerate() {
        let expected = ((verified_epochs >> height) & 1) == 1;
        if root.is_some() != expected || root.is_some_and(|root| root == [0; 32]) {
            return Err(CompactRegistryArchiveError::InvalidCompleteGraphCursor);
        }
    }
    Ok(())
}

fn complete_graph_frontier_root(
    wallet: DepositWalletId,
    verified_epochs: u128,
    frontier: &[Option<[u8; 32]>],
) -> Result<[u8; 32], CompactRegistryArchiveError> {
    validate_complete_graph_frontier(verified_epochs, frontier)?;
    let maximum_count = 1_u128 << COMPACT_REGISTRY_INDEX_DEPTH;
    if verified_epochs == maximum_count {
        return frontier[usize::from(COMPACT_REGISTRY_INDEX_DEPTH)]
            .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor);
    }

    let mut root = compact_registry_empty_index_hash_at(wallet, COMPACT_REGISTRY_INDEX_DEPTH);
    for height in 0..usize::from(COMPACT_REGISTRY_INDEX_DEPTH) {
        let height = u8::try_from(height)
            .map_err(|_| CompactRegistryArchiveError::InvalidCompleteGraphCursor)?;
        let depth = COMPACT_REGISTRY_INDEX_DEPTH
            .checked_sub(
                height
                    .checked_add(1)
                    .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?,
            )
            .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?;
        let empty_right = compact_registry_empty_index_hash_at(
            wallet,
            depth.checked_add(1).ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?,
        );
        let (left, right) = if ((verified_epochs >> height) & 1) == 1 {
            (
                frontier[usize::from(height)]
                    .ok_or(CompactRegistryArchiveError::InvalidCompleteGraphCursor)?,
                root,
            )
        } else {
            (root, empty_right)
        };
        root = if left == empty_right && right == empty_right {
            compact_registry_empty_index_hash_at(wallet, depth)
        } else {
            compact_registry_index_branch_hash(wallet, depth, left, right)
        };
    }
    Ok(root)
}

/// Build a fresh current-format compact registry.  The returned objects are not yet durable.
pub fn prepare_compact_registry_genesis(
    target: &VerifiedRegistryHandoffTarget,
    first_index: DepositSubaddressIndex,
    portable_index_checkpoint: [u8; 32],
) -> Result<PendingCompactRegistryMutation, CompactRegistryArchiveError> {
    let wallet = target.wallet();
    let link = RegistryLink::genesis(target, first_index, portable_index_checkpoint)?;
    let mut staged = BTreeMap::new();
    let link_bytes =
        encode_bounded(&link, MAX_COMPACT_REGISTRY_LINK_BYTES, "compact registry link")?;
    let link_reference =
        stage_object(wallet, CompactRegistryObjectKind::Link, link_bytes, &mut staged)?;
    let (index_root, index_hash) = insert_index(
        wallet,
        None,
        compact_registry_empty_index_root(wallet),
        link.epoch(),
        link.chain_root()?,
        link_reference,
        None,
        &mut staged,
        &EmptyCompactRegistryReader,
    )?;
    let registry = CompactEpochRegistry::from_link(&link, index_hash)?;
    let head = CompactRegistryArchiveHead {
        version: COMPACT_REGISTRY_ARCHIVE_HEAD_VERSION,
        wallet,
        revision: archive_revision_for_epoch(registry.active_epoch()),
        registry,
        index_root,
        active_link: link_reference,
        active_witness: None,
    };
    head.validate_shape()?;
    let staged = staged
        .into_iter()
        .map(|(reference, contents)| StagedCompactRegistryObject { reference, contents })
        .collect::<Vec<_>>();
    if staged.len() != COMPACT_REGISTRY_GENESIS_OBJECTS {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    Ok(PendingCompactRegistryMutation { expected_head_bytes: None, next: head, staged })
}

/// Prepare the unique immediate successor of `head`.
///
/// The current head is fully verified first.  `certificate` must sign that exact
/// `(chain_root,index_root)` source identity, preventing fork and prefix transplants.
/// `source_portable_head` must be the independently authenticated logical head loaded from the
/// same snapshot; every anchor field and its digest are matched before any successor is staged.
pub fn prepare_compact_registry_append<R: CompactRegistryObjectReader>(
    head: &CompactRegistryArchiveHead,
    target: &VerifiedRegistryHandoffTarget,
    certificate: RegistryHandoffCertificate,
    source_portable_head: &PortableDepositIndexHead,
    reader: &R,
) -> Result<PendingCompactRegistryMutation, CompactRegistryArchiveError> {
    head.verify_bounded(reader)?;
    let statement = certificate.statement();
    if source_portable_head.wallet_id() != head.wallet()
        || source_portable_head.digest() != statement.source_portable_index()
        || source_portable_head
            .through_sequence()
            .checked_add(1)
            .ok_or(CompactRegistryArchiveError::Overflow)?
            != statement.terminal_sequence()
        || source_portable_head.ledger_head() != statement.previous_ledger_head()
        || source_portable_head.next_index() != statement.next_index()
    {
        return Err(CompactRegistryArchiveError::PortableCheckpointMismatch);
    }
    let link = RegistryLink::successor(head.registry(), target, &certificate)?;
    let expected_head_bytes = Some(head.to_bytes()?);
    let mut staged = BTreeMap::new();
    let witness_bytes = encode_bounded(
        &certificate,
        MAX_COMPACT_REGISTRY_WITNESS_BYTES,
        "compact registry handoff witness",
    )?;
    let witness_reference = stage_object(
        head.wallet,
        CompactRegistryObjectKind::HandoffWitness,
        witness_bytes,
        &mut staged,
    )?;
    let link_bytes =
        encode_bounded(&link, MAX_COMPACT_REGISTRY_LINK_BYTES, "compact registry link")?;
    let link_reference =
        stage_object(head.wallet, CompactRegistryObjectKind::Link, link_bytes, &mut staged)?;
    let (index_root, index_hash) = insert_index(
        head.wallet,
        Some(head.index_root),
        head.registry.id().index_root(),
        link.epoch(),
        link.chain_root()?,
        link_reference,
        Some(witness_reference),
        &mut staged,
        reader,
    )?;
    let registry = CompactEpochRegistry::from_link(&link, index_hash)?;
    let next = CompactRegistryArchiveHead {
        version: COMPACT_REGISTRY_ARCHIVE_HEAD_VERSION,
        wallet: head.wallet,
        revision: archive_revision_for_epoch(registry.active_epoch()),
        registry,
        index_root,
        active_link: link_reference,
        active_witness: Some(witness_reference),
    };
    next.validate_shape()?;
    let staged = staged
        .into_iter()
        .map(|(reference, contents)| StagedCompactRegistryObject { reference, contents })
        .collect::<Vec<_>>();
    if staged.len() != COMPACT_REGISTRY_APPEND_OBJECTS {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    Ok(PendingCompactRegistryMutation { expected_head_bytes, next, staged })
}

/// Verify and return one epoch without replaying any earlier prefix.
pub fn lookup_compact_registry_epoch<R: CompactRegistryObjectReader>(
    head: &CompactRegistryArchiveHead,
    epoch: u64,
    reader: &R,
) -> Result<VerifiedRegistryEpoch, CompactRegistryArchiveError> {
    head.verify_bounded(reader)?;
    verify_epoch_at(head, epoch, reader)
}

/// Verify and return the exact issuance window for one historical or active epoch.
pub fn lookup_verified_issuer_window<R: CompactRegistryObjectReader>(
    head: &CompactRegistryArchiveHead,
    epoch: u64,
    reader: &R,
) -> Result<VerifiedIssuerWindow, CompactRegistryArchiveError> {
    head.verify_bounded(reader)?;
    if epoch > head.registry.active_epoch() {
        return Err(CompactRegistryArchiveError::MissingEpoch(epoch));
    }
    let issuer = verify_epoch_at(head, epoch, reader)?;
    if epoch == head.registry.active_epoch() {
        return Ok(VerifiedIssuerWindow::from_links(
            &issuer.link,
            head.registry.id().index_root(),
            None,
        )?);
    }
    let successor_epoch = epoch.checked_add(1).ok_or(CompactRegistryArchiveError::Overflow)?;
    let successor = verify_epoch_at(head, successor_epoch, reader)?;
    Ok(VerifiedIssuerWindow::from_links(
        &issuer.link,
        successor.link.parent_index_root(),
        Some(&successor.link),
    )?)
}

/// Mutation whose immutable objects have not yet been proven durable.
#[derive(Clone, Debug)]
pub struct PendingCompactRegistryMutation {
    expected_head_bytes: Option<Vec<u8>>,
    next: CompactRegistryArchiveHead,
    staged: Vec<StagedCompactRegistryObject>,
}

impl PendingCompactRegistryMutation {
    #[must_use]
    pub fn expected_head_bytes(&self) -> Option<&[u8]> {
        self.expected_head_bytes.as_deref()
    }

    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.next.revision.saturating_sub(1)
    }

    #[must_use]
    pub fn staged_objects(&self) -> &[StagedCompactRegistryObject] {
        &self.staged
    }

    #[must_use]
    pub const fn proposed_head(&self) -> &CompactRegistryArchiveHead {
        &self.next
    }

    /// Prove every staged object was installed exactly and the bounded restart verifier accepts
    /// the resulting head before exposing bytes to the CAS adapter.
    pub fn verify_staged<R: CompactRegistryObjectReader>(
        self,
        reader: &R,
    ) -> Result<VerifiedCompactRegistryMutation, CompactRegistryArchiveError> {
        for object in &self.staged {
            let installed = load_required(reader, object.reference)?;
            if installed != object.contents {
                return Err(CompactRegistryArchiveError::ObjectAuthentication);
            }
        }
        self.next.verify_bounded(reader)?;
        let next_head_bytes = self.next.to_bytes()?;
        Ok(VerifiedCompactRegistryMutation {
            expected_head_bytes: self.expected_head_bytes,
            next_head_bytes,
            next: self.next,
        })
    }
}

/// Mutation whose exact next head is safe to offer to a durable compare-and-swap.
#[derive(Clone, Debug)]
pub struct VerifiedCompactRegistryMutation {
    expected_head_bytes: Option<Vec<u8>>,
    next_head_bytes: Vec<u8>,
    next: CompactRegistryArchiveHead,
}

impl VerifiedCompactRegistryMutation {
    #[must_use]
    pub fn expected_head_bytes(&self) -> Option<&[u8]> {
        self.expected_head_bytes.as_deref()
    }

    #[must_use]
    pub fn next_head_bytes(&self) -> &[u8] {
        &self.next_head_bytes
    }

    #[must_use]
    pub const fn next_head(&self) -> &CompactRegistryArchiveHead {
        &self.next
    }

    /// Accept only the exact old and new bytes associated with this verified mutation.
    ///
    /// The storage adapter calls this after a successful exact compare-and-swap read-back.  It is
    /// deliberately not a revision-only check.
    pub fn authorize_install(
        &self,
        observed_previous: Option<&[u8]>,
        committed: &[u8],
    ) -> Result<CompactRegistryArchiveHead, CompactRegistryArchiveError> {
        if observed_previous != self.expected_head_bytes.as_deref()
            || committed != self.next_head_bytes
        {
            return Err(CompactRegistryArchiveError::CasNotCommitted);
        }
        let decoded = CompactRegistryArchiveHead::from_bytes(committed)?;
        if decoded != self.next {
            return Err(CompactRegistryArchiveError::CasNotCommitted);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IndexChild {
    semantic_hash: [u8; 32],
    object: Option<CompactRegistryObjectRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CompactRegistryIndexNode {
    version: u16,
    wallet: DepositWalletId,
    body: CompactRegistryIndexNodeBody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum CompactRegistryIndexNodeBody {
    Branch {
        depth: u8,
        left: IndexChild,
        right: IndexChild,
    },
    Leaf {
        epoch: u64,
        link_root: [u8; 32],
        link: CompactRegistryObjectRef,
        witness: Option<CompactRegistryObjectRef>,
    },
}

impl CompactRegistryIndexNode {
    fn validate(&self) -> Result<(), CompactRegistryArchiveError> {
        if self.version != COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION
            || self.wallet.0 == [0_u8; 32]
        {
            return Err(CompactRegistryArchiveError::BrokenIndex);
        }
        match self.body {
            CompactRegistryIndexNodeBody::Branch { depth, left, right } => {
                if depth >= COMPACT_REGISTRY_INDEX_DEPTH {
                    return Err(CompactRegistryArchiveError::BrokenIndex);
                }
                validate_child(self.wallet, depth + 1, left)?;
                validate_child(self.wallet, depth + 1, right)?;
                if left.object.is_none() && right.object.is_none() {
                    return Err(CompactRegistryArchiveError::BrokenIndex);
                }
            }
            CompactRegistryIndexNodeBody::Leaf { link_root, link, witness, .. } => {
                link.validate()?;
                if link_root == [0_u8; 32]
                    || link.wallet != self.wallet
                    || link.kind != CompactRegistryObjectKind::Link
                {
                    return Err(CompactRegistryArchiveError::BrokenIndex);
                }
                if let Some(witness) = witness {
                    witness.validate()?;
                    if witness.wallet != self.wallet
                        || witness.kind != CompactRegistryObjectKind::HandoffWitness
                    {
                        return Err(CompactRegistryArchiveError::BrokenIndex);
                    }
                }
            }
        }
        Ok(())
    }

    fn semantic_hash(&self) -> Result<[u8; 32], CompactRegistryArchiveError> {
        self.validate()?;
        Ok(match self.body {
            CompactRegistryIndexNodeBody::Branch { depth, left, right } => {
                compact_registry_index_branch_hash(
                    self.wallet,
                    depth,
                    left.semantic_hash,
                    right.semantic_hash,
                )
            }
            CompactRegistryIndexNodeBody::Leaf { epoch, link_root, .. } => {
                compact_registry_index_leaf_hash(self.wallet, epoch, link_root)
            }
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, CompactRegistryArchiveError> {
        self.validate()?;
        encode_bounded(self, MAX_COMPACT_REGISTRY_INDEX_NODE_BYTES, "compact registry index node")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CompactRegistryArchiveError> {
        let node = decode_canonical_bounded::<Self>(
            bytes,
            MAX_COMPACT_REGISTRY_INDEX_NODE_BYTES,
            "compact registry index node",
        )?;
        node.validate()?;
        Ok(node)
    }
}

fn validate_child(
    wallet: DepositWalletId,
    depth: u8,
    child: IndexChild,
) -> Result<(), CompactRegistryArchiveError> {
    let empty = compact_registry_empty_index_hash_at(wallet, depth);
    match child.object {
        None if child.semantic_hash != empty => Err(CompactRegistryArchiveError::BrokenIndex),
        None => Ok(()),
        Some(reference) => {
            reference.validate()?;
            if child.semantic_hash == [0_u8; 32]
                || child.semantic_hash == empty
                || reference.wallet != wallet
                || reference.kind != CompactRegistryObjectKind::IndexNode
            {
                return Err(CompactRegistryArchiveError::BrokenIndex);
            }
            Ok(())
        }
    }
}

fn stage_object(
    wallet: DepositWalletId,
    kind: CompactRegistryObjectKind,
    contents: Vec<u8>,
    staged: &mut BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
) -> Result<CompactRegistryObjectRef, CompactRegistryArchiveError> {
    let reference = CompactRegistryObjectRef::for_contents(wallet, kind, &contents)?;
    if let Some(existing) = staged.insert(reference, contents.clone()) {
        if existing != contents {
            return Err(CompactRegistryArchiveError::ObjectAuthentication);
        }
    }
    Ok(reference)
}

#[allow(clippy::too_many_arguments)]
fn insert_index<R: CompactRegistryObjectReader>(
    wallet: DepositWalletId,
    current: Option<CompactRegistryObjectRef>,
    current_hash: [u8; 32],
    epoch: u64,
    link_root: [u8; 32],
    link: CompactRegistryObjectRef,
    witness: Option<CompactRegistryObjectRef>,
    staged: &mut BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    reader: &R,
) -> Result<(CompactRegistryObjectRef, [u8; 32]), CompactRegistryArchiveError> {
    insert_index_at(
        wallet,
        current,
        current_hash,
        0,
        epoch,
        link_root,
        link,
        witness,
        staged,
        reader,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_index_at<R: CompactRegistryObjectReader>(
    wallet: DepositWalletId,
    mut current: Option<CompactRegistryObjectRef>,
    mut current_hash: [u8; 32],
    mut depth: u8,
    epoch: u64,
    link_root: [u8; 32],
    link: CompactRegistryObjectRef,
    witness: Option<CompactRegistryObjectRef>,
    staged: &mut BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    reader: &R,
) -> Result<(CompactRegistryObjectRef, [u8; 32]), CompactRegistryArchiveError> {
    // Iterative descent plus bottom-up rebuild. Self-recursion here previously reserved one
    // debug-build frame per index level (depth 64) inside already-deep async poll chains and
    // overflowed default 2 MiB worker stacks; an explicit sibling stack keeps the frame flat.
    struct PendingBranch {
        depth: u8,
        sibling: IndexChild,
        selected_is_left: bool,
    }
    let mut pending =
        Vec::with_capacity(usize::from(COMPACT_REGISTRY_INDEX_DEPTH.saturating_sub(depth)));

    while depth < COMPACT_REGISTRY_INDEX_DEPTH {
        let empty_child = compact_registry_empty_index_hash_at(wallet, depth + 1);
        let (left, right) = match current {
            None => {
                if current_hash != compact_registry_empty_index_hash_at(wallet, depth) {
                    return Err(CompactRegistryArchiveError::BrokenIndex);
                }
                (
                    IndexChild { semantic_hash: empty_child, object: None },
                    IndexChild { semantic_hash: empty_child, object: None },
                )
            }
            Some(reference) => {
                let node = load_index_node(reference, staged, reader)?;
                if node.semantic_hash()? != current_hash || node.wallet != wallet {
                    return Err(CompactRegistryArchiveError::BrokenIndex);
                }
                match node.body {
                    CompactRegistryIndexNodeBody::Branch { depth: actual, left, right }
                        if actual == depth =>
                    {
                        (left, right)
                    }
                    _ => return Err(CompactRegistryArchiveError::BrokenIndex),
                }
            }
        };

        let shift = u32::from(COMPACT_REGISTRY_INDEX_DEPTH - depth - 1);
        let selected_is_left = ((epoch >> shift) & 1) == 0;
        let (selected, sibling) = if selected_is_left { (left, right) } else { (right, left) };
        pending.push(PendingBranch { depth, sibling, selected_is_left });
        current = selected.object;
        current_hash = selected.semantic_hash;
        depth += 1;
    }

    let (mut reference, mut semantic_hash) = if let Some(reference) = current {
        let existing = load_index_node(reference, staged, reader)?;
        let expected = CompactRegistryIndexNode {
            version: COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION,
            wallet,
            body: CompactRegistryIndexNodeBody::Leaf { epoch, link_root, link, witness },
        };
        if existing == expected && existing.semantic_hash()? == current_hash {
            (reference, current_hash)
        } else {
            return Err(CompactRegistryArchiveError::DuplicateEpoch(epoch));
        }
    } else {
        if current_hash != compact_registry_empty_index_hash_at(wallet, depth) {
            return Err(CompactRegistryArchiveError::BrokenIndex);
        }
        let leaf = CompactRegistryIndexNode {
            version: COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION,
            wallet,
            body: CompactRegistryIndexNodeBody::Leaf { epoch, link_root, link, witness },
        };
        let semantic_hash = leaf.semantic_hash()?;
        (stage_index_node(leaf, staged)?, semantic_hash)
    };

    while let Some(PendingBranch { depth, sibling, selected_is_left }) = pending.pop() {
        let child = IndexChild { semantic_hash, object: Some(reference) };
        let (left, right) = if selected_is_left { (child, sibling) } else { (sibling, child) };
        let branch = CompactRegistryIndexNode {
            version: COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION,
            wallet,
            body: CompactRegistryIndexNodeBody::Branch { depth, left, right },
        };
        semantic_hash = branch.semantic_hash()?;
        reference = stage_index_node(branch, staged)?;
    }
    Ok((reference, semantic_hash))
}

fn stage_index_node(
    node: CompactRegistryIndexNode,
    staged: &mut BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
) -> Result<CompactRegistryObjectRef, CompactRegistryArchiveError> {
    let wallet = node.wallet;
    let bytes = node.to_bytes()?;
    stage_object(wallet, CompactRegistryObjectKind::IndexNode, bytes, staged)
}

fn load_index_node<R: CompactRegistryObjectReader>(
    reference: CompactRegistryObjectRef,
    staged: &BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    reader: &R,
) -> Result<CompactRegistryIndexNode, CompactRegistryArchiveError> {
    if reference.kind != CompactRegistryObjectKind::IndexNode {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    let bytes = if let Some(bytes) = staged.get(&reference) {
        reference.verify_contents(bytes)?;
        bytes.clone()
    } else {
        load_required(reader, reference)?
    };
    CompactRegistryIndexNode::from_bytes(&bytes)
}

#[derive(Clone, Copy)]
struct IndexLeaf {
    link_root: [u8; 32],
    link: CompactRegistryObjectRef,
    witness: Option<CompactRegistryObjectRef>,
    prior_index_root: [u8; 32],
}

fn lookup_index_leaf<R: CompactRegistryObjectReader>(
    wallet: DepositWalletId,
    root_reference: CompactRegistryObjectRef,
    root_hash: [u8; 32],
    epoch: u64,
    reader: &R,
) -> Result<IndexLeaf, CompactRegistryArchiveError> {
    let mut current_reference = root_reference;
    let mut expected_hash = root_hash;
    let mut ancestry = Vec::with_capacity(usize::from(COMPACT_REGISTRY_INDEX_DEPTH));
    for depth in 0..COMPACT_REGISTRY_INDEX_DEPTH {
        let node = load_index_node(current_reference, &BTreeMap::new(), reader)?;
        if node.wallet != wallet || node.semantic_hash()? != expected_hash {
            return Err(CompactRegistryArchiveError::BrokenIndex);
        }
        let CompactRegistryIndexNodeBody::Branch { depth: actual, left, right } = node.body else {
            return Err(CompactRegistryArchiveError::BrokenIndex);
        };
        if actual != depth {
            return Err(CompactRegistryArchiveError::BrokenIndex);
        }
        let shift = u32::from(COMPACT_REGISTRY_INDEX_DEPTH - depth - 1);
        let selected_left = ((epoch >> shift) & 1) == 0;
        let (selected, sibling_hash) =
            if selected_left { (left, right.semantic_hash) } else { (right, left.semantic_hash) };
        ancestry.push((depth, selected_left, sibling_hash));
        current_reference =
            selected.object.ok_or(CompactRegistryArchiveError::MissingEpoch(epoch))?;
        expected_hash = selected.semantic_hash;
    }
    let leaf = load_index_node(current_reference, &BTreeMap::new(), reader)?;
    if leaf.wallet != wallet || leaf.semantic_hash()? != expected_hash {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    let CompactRegistryIndexNodeBody::Leaf { epoch: actual, link_root, link, witness } = leaf.body
    else {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    };
    if actual != epoch {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    // Reconstruct the unique semantic root before this leaf was inserted.  Canonical empty
    // subtrees use their dedicated empty hash instead of materializing all-empty branch objects.
    let mut prior_index_root =
        compact_registry_empty_index_hash_at(wallet, COMPACT_REGISTRY_INDEX_DEPTH);
    for (depth, selected_left, sibling_hash) in ancestry.into_iter().rev() {
        let empty_child = compact_registry_empty_index_hash_at(wallet, depth + 1);
        let (left, right) = if selected_left {
            (prior_index_root, sibling_hash)
        } else {
            (sibling_hash, prior_index_root)
        };
        prior_index_root = if left == empty_child && right == empty_child {
            compact_registry_empty_index_hash_at(wallet, depth)
        } else {
            compact_registry_index_branch_hash(wallet, depth, left, right)
        };
    }
    Ok(IndexLeaf { link_root, link, witness, prior_index_root })
}

fn load_raw_epoch<R: CompactRegistryObjectReader>(
    head: &CompactRegistryArchiveHead,
    epoch: u64,
    reader: &R,
) -> Result<VerifiedRegistryEpoch, CompactRegistryArchiveError> {
    let leaf = lookup_index_leaf(
        head.wallet,
        head.index_root,
        head.registry.id().index_root(),
        epoch,
        reader,
    )?;
    let link_bytes = load_required(reader, leaf.link)?;
    let link = decode_canonical_bounded::<RegistryLink>(
        &link_bytes,
        MAX_COMPACT_REGISTRY_LINK_BYTES,
        "compact registry link",
    )?;
    link.validate()?;
    if link.wallet() != head.wallet || link.epoch() != epoch || link.chain_root()? != leaf.link_root
    {
        return Err(CompactRegistryArchiveError::BrokenIndex);
    }
    let witness = leaf
        .witness
        .map(|reference| {
            let bytes = load_required(reader, reference)?;
            decode_canonical_bounded::<RegistryHandoffCertificate>(
                &bytes,
                MAX_COMPACT_REGISTRY_WITNESS_BYTES,
                "compact registry handoff witness",
            )
        })
        .transpose()?;
    Ok(VerifiedRegistryEpoch {
        link,
        link_reference: leaf.link,
        witness,
        witness_reference: leaf.witness,
        prior_index_root: leaf.prior_index_root,
    })
}

fn verify_epoch_at<R: CompactRegistryObjectReader>(
    head: &CompactRegistryArchiveHead,
    epoch: u64,
    reader: &R,
) -> Result<VerifiedRegistryEpoch, CompactRegistryArchiveError> {
    let target = load_raw_epoch(head, epoch, reader)?;
    match target.link.parent_epoch() {
        None => {
            if target.witness.is_some() || target.witness_reference.is_some() {
                return Err(CompactRegistryArchiveError::InvalidWitness);
            }
        }
        Some(parent_epoch) => {
            let witness =
                target.witness.as_ref().ok_or(CompactRegistryArchiveError::InvalidWitness)?;
            let parent = load_raw_epoch(head, parent_epoch, reader)?;
            if parent.link.chain_root()? != target.link.parent_chain_root()
                || parent.link.epoch().checked_add(1) != Some(target.link.epoch())
            {
                return Err(CompactRegistryArchiveError::BrokenChain);
            }
            let source =
                CompactEpochRegistry::from_link(&parent.link, target.link.parent_index_root())?;
            RegistryLink::verify_certified_successor(&source, &target.link, witness)?;
        }
    }
    Ok(target)
}

fn load_required<R: CompactRegistryObjectReader>(
    reader: &R,
    reference: CompactRegistryObjectRef,
) -> Result<Vec<u8>, CompactRegistryArchiveError> {
    reference.validate()?;
    let bytes =
        reader.load(reference)?.ok_or(CompactRegistryArchiveError::MissingObject(reference))?;
    reference.verify_contents(&bytes)?;
    Ok(bytes)
}

struct EmptyCompactRegistryReader;

impl CompactRegistryObjectReader for EmptyCompactRegistryReader {
    fn load(
        &self,
        _reference: CompactRegistryObjectRef,
    ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
        Ok(None)
    }
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, CompactRegistryArchiveError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|_| CompactRegistryArchiveError::Serialization)?;
    if bytes.len() > maximum {
        return Err(CompactRegistryArchiveError::ObjectTooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

fn decode_canonical_bounded<T>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, CompactRegistryArchiveError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CompactRegistryArchiveError::ObjectTooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    let (value, trailing) = postcard::take_from_bytes::<T>(bytes)
        .map_err(|_| CompactRegistryArchiveError::Serialization)?;
    if !trailing.is_empty() {
        return Err(CompactRegistryArchiveError::TrailingBytes { kind, trailing: trailing.len() });
    }
    if postcard::to_allocvec(&value).map_err(|_| CompactRegistryArchiveError::Serialization)?
        != bytes
    {
        return Err(CompactRegistryArchiveError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

#[derive(Debug, Error)]
pub enum CompactRegistryArchiveError {
    #[error("compact registry semantic error: {0}")]
    Registry(#[from] CompactRegistryError),
    #[error("compact registry serialization failed")]
    Serialization,
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{0} encoding is not canonical")]
    NonCanonicalEncoding(&'static str),
    #[error("compact registry object reference is malformed")]
    InvalidObjectReference,
    #[error("compact registry object failed content authentication")]
    ObjectAuthentication,
    #[error("required compact registry object {0:?} is missing")]
    MissingObject(CompactRegistryObjectRef),
    #[error("compact registry archive head is malformed")]
    InvalidHead,
    #[error("compact registry authenticated index is malformed")]
    BrokenIndex,
    #[error("compact registry semantic chain is malformed")]
    BrokenChain,
    #[error("epoch {0} is absent from the authenticated index")]
    MissingEpoch(u64),
    #[error("epoch {0} already has another authenticated value")]
    DuplicateEpoch(u64),
    #[error("complete compact-registry graph cursor is malformed")]
    InvalidCompleteGraphCursor,
    #[error("complete compact-registry graph cursor names another exact archive head")]
    WrongCompleteGraphHead,
    #[error("handoff witness is missing, unexpected, or malformed")]
    InvalidWitness,
    #[error("handoff does not bind the exact authenticated pre-terminal portable index head")]
    PortableCheckpointMismatch,
    #[error("the exact old/new head compare-and-swap did not commit")]
    CasNotCommitted,
    #[error("integer overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use super::*;
    use crate::{
        committee::{Committee, Member, PartyId},
        compact_epoch_registry::RegistryHandoffStatement,
        deposit_index::{
            DepositIndexBuilder, DepositIndexError, DepositIndexHead, DepositIndexObjectId,
            DepositIndexReader,
        },
        deposit_ledger::{CertifiedLedgerEntry, LedgerStatement},
        identity::Identity,
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    #[derive(Default)]
    struct MemoryObjects {
        objects: BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
        reads: Cell<usize>,
    }

    impl MemoryObjects {
        fn install(&mut self, pending: &PendingCompactRegistryMutation) {
            for object in pending.staged_objects() {
                self.objects.insert(object.reference(), object.contents().to_vec());
            }
        }

        fn install_prefix(&mut self, pending: &PendingCompactRegistryMutation, count: usize) {
            for object in pending.staged_objects().iter().take(count) {
                self.objects.insert(object.reference(), object.contents().to_vec());
            }
        }

        fn reset_reads(&self) {
            self.reads.set(0);
        }

        fn reads(&self) -> usize {
            self.reads.get()
        }
    }

    impl CompactRegistryObjectReader for MemoryObjects {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.objects.get(&reference).cloned())
        }
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
        wallet: DepositWalletId,
        committee: Committee,
        activation: [u8; 32],
        certified_activation_root: [u8; 32],
    ) -> VerifiedRegistryHandoffTarget {
        VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            activation,
            certified_activation_root,
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap()
    }

    fn successor_authority(
        wallet: DepositWalletId,
        committee: Committee,
    ) -> VerifiedRegistryHandoffTarget {
        let epoch = committee.epoch;
        authority(
            wallet,
            committee,
            [u8::try_from(epoch + 20).unwrap_or(201); 32],
            [u8::try_from(epoch + 40).unwrap_or(202); 32],
        )
    }

    fn initial_portable(wallet: DepositWalletId) -> DepositIndexHead {
        DepositIndexHead::empty_portable(wallet, DepositSubaddressIndex::new(0, 1).unwrap())
            .unwrap()
    }

    fn commit(
        store: &mut MemoryObjects,
        pending: PendingCompactRegistryMutation,
    ) -> CompactRegistryArchiveHead {
        let expected = pending.expected_head_bytes().map(|bytes| bytes.to_vec());
        store.install(&pending);
        let verified = pending.verify_staged(store).unwrap();
        let committed = verified.next_head_bytes().to_vec();
        verified.authorize_install(expected.as_deref(), &committed).unwrap()
    }

    fn genesis(
        wallet: DepositWalletId,
    ) -> (MemoryObjects, CompactRegistryArchiveHead, Vec<Identity>) {
        let identities = identities(0);
        let portable =
            DepositIndexHead::empty_portable(wallet, DepositSubaddressIndex::new(0, 1).unwrap())
                .unwrap();
        let target = authority(wallet, committee(0, &identities), [7_u8; 32], [17_u8; 32]);
        let pending = prepare_compact_registry_genesis(
            &target,
            DepositSubaddressIndex::new(0, 1).unwrap(),
            portable.digest(),
        )
        .unwrap();
        assert_eq!(pending.staged_objects().len(), COMPACT_REGISTRY_GENESIS_OBJECTS);
        assert_eq!(pending.proposed_head().revision(), 0);
        let mut store = MemoryObjects::default();
        let head = commit(&mut store, pending);
        (store, head, identities)
    }

    fn handoff(
        head: &CompactRegistryArchiveHead,
        source_identities: &[Identity],
        target: &VerifiedRegistryHandoffTarget,
        subset: &[usize],
        portable_store: &mut PortableObjects,
        local_portable: DepositIndexHead,
    ) -> (RegistryHandoffCertificate, PortableDepositIndexHead, DepositIndexHead) {
        let anchor = local_portable.portable_anchor().unwrap();
        let sequence = anchor.through_sequence().checked_add(1).unwrap();
        let previous = anchor.ledger_head();
        let next_index = anchor.next_index();
        let portable = PortableDepositIndexHead::from_head(&local_portable).unwrap();
        let source_state = crate::deposit_state_export::DepositHandoffStateBinding::new(
            Some([0xb1; 32]),
            portable.clone(),
        )
        .unwrap();
        let statement = RegistryHandoffStatement::new(
            head.registry(),
            sequence,
            previous,
            source_state.clone(),
            target,
            next_index,
        )
        .unwrap();
        let witnesses = subset
            .iter()
            .map(|index| {
                source_identities[*index]
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
        let certificate = RegistryHandoffCertificate::new(statement.clone(), witnesses).unwrap();

        let ledger_statement = LedgerStatement::handoff(
            head.registry(),
            sequence,
            previous,
            source_state,
            target,
            next_index,
        )
        .unwrap();
        let attestations = subset
            .iter()
            .map(|index| {
                source_identities[*index]
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
        let mut builder = DepositIndexBuilder::new(portable_store, local_portable).unwrap();
        builder.apply_verified_active_entry(&entry, head.registry(), None).unwrap();
        let update = builder.finish().unwrap().unwrap();
        for (id, bytes) in update.staged_objects() {
            portable_store.objects.insert(id, bytes.to_vec());
        }
        let resulting = update.next_head().clone();
        (certificate, portable, resulting)
    }

    fn first_handoff(
        head: &CompactRegistryArchiveHead,
        source_identities: &[Identity],
        target: &VerifiedRegistryHandoffTarget,
        subset: &[usize],
    ) -> (RegistryHandoffCertificate, PortableDepositIndexHead) {
        let mut portable_store = PortableObjects::default();
        let (certificate, portable, _) = handoff(
            head,
            source_identities,
            target,
            subset,
            &mut portable_store,
            initial_portable(head.wallet()),
        );
        (certificate, portable)
    }

    fn registry_lifetime(
        wallet: DepositWalletId,
        active_epoch: u64,
    ) -> (MemoryObjects, CompactRegistryArchiveHead) {
        let (mut store, mut head, mut source_identities) = genesis(wallet);
        let mut portable_store = PortableObjects::default();
        let mut local_portable = initial_portable(wallet);
        for epoch in 1..=active_epoch {
            let target_identities = identities(epoch);
            let target = successor_authority(wallet, committee(epoch, &target_identities));
            let (certificate, portable, resulting_portable) = handoff(
                &head,
                &source_identities,
                &target,
                &[0, 1, 2],
                &mut portable_store,
                local_portable,
            );
            let pending =
                prepare_compact_registry_append(&head, &target, certificate, &portable, &store)
                    .unwrap();
            head = commit(&mut store, pending);
            source_identities = target_identities;
            local_portable = resulting_portable;
        }
        (store, head)
    }

    fn complete_registry_verification(
        head: &CompactRegistryArchiveHead,
        store: &MemoryObjects,
        mut cursor: CompleteCompactRegistryGraphCursor,
    ) -> VerifiedCompleteCompactRegistryGraph {
        loop {
            match verify_complete_compact_registry_graph_step(head, cursor, store).unwrap() {
                CompleteCompactRegistryGraphStep::Pending(next) => cursor = next,
                CompleteCompactRegistryGraphStep::Complete(verified) => return verified,
            }
        }
    }

    fn rewrite_index_leaf(
        store: &mut MemoryObjects,
        head: &mut CompactRegistryArchiveHead,
        key: u64,
        rewrite: impl FnOnce(
            u64,
            [u8; 32],
            CompactRegistryObjectRef,
            Option<CompactRegistryObjectRef>,
        ) -> CompactRegistryIndexNodeBody,
    ) {
        let mut reference = head.index_root_reference();
        let mut path = Vec::with_capacity(usize::from(COMPACT_REGISTRY_INDEX_DEPTH));
        for depth in 0..COMPACT_REGISTRY_INDEX_DEPTH {
            let node = CompactRegistryIndexNode::from_bytes(store.objects.get(&reference).unwrap())
                .unwrap();
            let CompactRegistryIndexNodeBody::Branch { depth: actual, left, right } = node.body
            else {
                panic!("index path ended before its leaf");
            };
            assert_eq!(actual, depth);
            let shift = u32::from(COMPACT_REGISTRY_INDEX_DEPTH - depth - 1);
            let selected_is_left = ((key >> shift) & 1) == 0;
            let (selected, sibling) = if selected_is_left { (left, right) } else { (right, left) };
            path.push((depth, selected_is_left, sibling));
            reference = selected.object.expect("test epoch exists");
        }

        let leaf =
            CompactRegistryIndexNode::from_bytes(store.objects.get(&reference).unwrap()).unwrap();
        let CompactRegistryIndexNodeBody::Leaf { epoch, link_root, link, witness } = leaf.body
        else {
            panic!("index path did not end in a leaf");
        };
        assert_eq!(epoch, key);
        let mut staged = BTreeMap::new();
        let forged_leaf = CompactRegistryIndexNode {
            version: COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION,
            wallet: head.wallet(),
            body: rewrite(epoch, link_root, link, witness),
        };
        let mut semantic_hash = forged_leaf.semantic_hash().unwrap();
        let mut object = stage_object(
            head.wallet(),
            CompactRegistryObjectKind::IndexNode,
            forged_leaf.to_bytes().unwrap(),
            &mut staged,
        )
        .unwrap();
        for (depth, selected_is_left, sibling) in path.into_iter().rev() {
            let replacement = IndexChild { semantic_hash, object: Some(object) };
            let (left, right) =
                if selected_is_left { (replacement, sibling) } else { (sibling, replacement) };
            let parent = CompactRegistryIndexNode {
                version: COMPACT_REGISTRY_ARCHIVE_INDEX_NODE_VERSION,
                wallet: head.wallet(),
                body: CompactRegistryIndexNodeBody::Branch { depth, left, right },
            };
            semantic_hash = parent.semantic_hash().unwrap();
            object = stage_object(
                head.wallet(),
                CompactRegistryObjectKind::IndexNode,
                parent.to_bytes().unwrap(),
                &mut staged,
            )
            .unwrap();
        }
        store.objects.extend(staged);
        head.index_root = object;
        let active_link = decode_canonical_bounded::<RegistryLink>(
            store.objects.get(&head.active_link_reference()).unwrap(),
            MAX_COMPACT_REGISTRY_LINK_BYTES,
            "compact registry link",
        )
        .unwrap();
        head.registry = CompactEpochRegistry::from_link(&active_link, semantic_hash).unwrap();
        head.validate_shape().unwrap();
    }

    #[test]
    fn complete_verifier_authenticates_zero_operation_historical_epochs() {
        let wallet = DepositWalletId([0x31; 32]);
        // Every predecessor hands off immediately. Epochs one and two therefore have no
        // allocations, observations, or consolidation operations between activation and handoff.
        let (store, head) = registry_lifetime(wallet, 3);
        let cursor = CompleteCompactRegistryGraphCursor::new(&head).unwrap();
        let verified = complete_registry_verification(&head, &store, cursor);
        assert!(verified.authenticates(&head).unwrap());
        assert_eq!(verified.head_digest(), head.digest().unwrap());
        assert_eq!(verified.registry_id(), head.registry_id());
        assert_eq!(verified.verified_epochs(), 4);
    }

    #[test]
    fn complete_verifier_rejects_a_tampered_historical_witness() {
        let wallet = DepositWalletId([0x32; 32]);
        let (mut store, mut head) = registry_lifetime(wallet, 2);
        let epoch = lookup_compact_registry_epoch(&head, 1, &store).unwrap();
        let certificate = epoch.witness().unwrap();
        let mut witnesses = certificate.witnesses().to_vec();
        witnesses[0].signature[0] ^= 1;
        let tampered =
            RegistryHandoffCertificate::new(certificate.statement().clone(), witnesses).unwrap();
        let tampered_bytes = tampered.to_bytes().unwrap();
        RegistryHandoffCertificate::from_bytes(&tampered_bytes).unwrap();
        let tampered_reference = CompactRegistryObjectRef::for_contents(
            wallet,
            CompactRegistryObjectKind::HandoffWitness,
            &tampered_bytes,
        )
        .unwrap();
        store.objects.insert(tampered_reference, tampered_bytes);
        rewrite_index_leaf(&mut store, &mut head, 1, |epoch, link_root, link, _witness| {
            CompactRegistryIndexNodeBody::Leaf {
                epoch,
                link_root,
                link,
                witness: Some(tampered_reference),
            }
        });

        let cursor = CompleteCompactRegistryGraphCursor::new(&head).unwrap();
        let CompleteCompactRegistryGraphStep::Pending(cursor) =
            verify_complete_compact_registry_graph_step(&head, cursor, &store).unwrap()
        else {
            panic!("genesis cannot complete a three-epoch graph");
        };
        assert!(matches!(
            verify_complete_compact_registry_graph_step(&head, cursor, &store),
            Err(CompactRegistryArchiveError::Registry(_))
        ));
    }

    #[test]
    fn complete_verifier_rejects_a_missing_epoch_and_duplicate_leaf_label() {
        let wallet = DepositWalletId([0x33; 32]);
        let (mut store, mut head) = registry_lifetime(wallet, 1);
        // The path for epoch one now contains a second leaf labelled epoch zero. The expected
        // epoch is absent even though every object remains content-authenticated under the forged
        // exact head.
        rewrite_index_leaf(&mut store, &mut head, 1, |_epoch, link_root, link, witness| {
            CompactRegistryIndexNodeBody::Leaf { epoch: 0, link_root, link, witness }
        });
        let cursor = CompleteCompactRegistryGraphCursor::new(&head).unwrap();
        let CompleteCompactRegistryGraphStep::Pending(cursor) =
            verify_complete_compact_registry_graph_step(&head, cursor, &store).unwrap()
        else {
            panic!("genesis cannot complete a two-epoch graph");
        };
        assert!(matches!(
            verify_complete_compact_registry_graph_step(&head, cursor, &store),
            Err(CompactRegistryArchiveError::MissingEpoch(1))
                | Err(CompactRegistryArchiveError::BrokenIndex)
        ));
    }

    #[test]
    fn complete_verifier_resumes_from_a_canonical_restart_cursor() {
        let wallet = DepositWalletId([0x34; 32]);
        let (store, head) = registry_lifetime(wallet, 3);
        let cursor = CompleteCompactRegistryGraphCursor::new(&head).unwrap();
        let CompleteCompactRegistryGraphStep::Pending(cursor) =
            verify_complete_compact_registry_graph_step(&head, cursor, &store).unwrap()
        else {
            panic!("genesis cannot complete a four-epoch graph");
        };
        assert_eq!(cursor.verified_epochs(), 1);
        assert_eq!(cursor.next_epoch(), Some(1));
        let bytes = cursor.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_COMPLETE_COMPACT_REGISTRY_GRAPH_CURSOR_BYTES);
        let restarted = CompleteCompactRegistryGraphCursor::from_bytes(&bytes).unwrap();
        assert_eq!(restarted, cursor);

        let mut other_exact_head = head.clone();
        other_exact_head.active_witness =
            lookup_compact_registry_epoch(&head, 2, &store).unwrap().witness_reference();
        assert_eq!(other_exact_head.registry_id(), head.registry_id());
        assert_ne!(other_exact_head.digest().unwrap(), head.digest().unwrap());
        assert!(matches!(
            verify_complete_compact_registry_graph_step(
                &other_exact_head,
                restarted.clone(),
                &store
            ),
            Err(CompactRegistryArchiveError::WrongCompleteGraphHead)
        ));

        let verified = complete_registry_verification(&head, &store, restarted);
        assert!(verified.authenticates(&head).unwrap());
        assert_eq!(verified.verified_epochs(), 4);
    }

    #[test]
    fn witness_subsets_change_objects_but_not_registry_roots() {
        let wallet = DepositWalletId([1_u8; 32]);
        let (store, head, source_identities) = genesis(wallet);
        let target_identities = identities(1);
        let target = successor_authority(wallet, committee(1, &target_identities));
        let (left_certificate, portable) =
            first_handoff(&head, &source_identities, &target, &[0, 1, 2]);
        let (right_certificate, right_portable) =
            first_handoff(&head, &source_identities, &target, &[0, 1, 3]);
        assert_eq!(portable, right_portable);
        let left =
            prepare_compact_registry_append(&head, &target, left_certificate, &portable, &store)
                .unwrap();
        let right =
            prepare_compact_registry_append(&head, &target, right_certificate, &portable, &store)
                .unwrap();
        assert_eq!(left.proposed_head().registry_id(), right.proposed_head().registry_id());
        assert_ne!(
            left.proposed_head().active_witness_reference(),
            right.proposed_head().active_witness_reference()
        );
        assert_ne!(
            left.proposed_head().index_root_reference(),
            right.proposed_head().index_root_reference()
        );
        assert_eq!(left.staged_objects().len(), COMPACT_REGISTRY_APPEND_OBJECTS);
        assert_eq!(right.staged_objects().len(), COMPACT_REGISTRY_APPEND_OBJECTS);
    }

    #[test]
    fn append_rejects_a_stale_or_mismatched_portable_checkpoint() {
        let wallet = DepositWalletId([3_u8; 32]);
        let (store, head, source_identities) = genesis(wallet);
        let target_identities = identities(1);
        let target = successor_authority(wallet, committee(1, &target_identities));
        let (certificate, _) = first_handoff(&head, &source_identities, &target, &[0, 1, 2]);
        let statement = certificate.statement();
        let wrong_index = DepositSubaddressIndex::new(
            statement.next_index().account(),
            statement.next_index().address() + 1,
        )
        .unwrap();
        let wrong_local_portable = DepositIndexHead::empty_portable(wallet, wrong_index).unwrap();
        let wrong_portable = PortableDepositIndexHead::from_head(&wrong_local_portable).unwrap();
        assert!(matches!(
            prepare_compact_registry_append(&head, &target, certificate, &wrong_portable, &store,),
            Err(CompactRegistryArchiveError::PortableCheckpointMismatch)
        ));
    }

    #[test]
    fn direct_lookup_and_windows_work_after_multiple_epochs() {
        let wallet = DepositWalletId([1_u8; 32]);
        let (mut store, mut head, mut source_identities) = genesis(wallet);
        let mut portable_store = PortableObjects::default();
        let mut local_portable = initial_portable(wallet);
        for epoch in 1..=3 {
            let target_identities = identities(epoch);
            let target = successor_authority(wallet, committee(epoch, &target_identities));
            let (certificate, portable, resulting_portable) = handoff(
                &head,
                &source_identities,
                &target,
                &[0, 1, 2],
                &mut portable_store,
                local_portable,
            );
            let pending =
                prepare_compact_registry_append(&head, &target, certificate, &portable, &store)
                    .unwrap();
            assert_eq!(pending.staged_objects().len(), COMPACT_REGISTRY_APPEND_OBJECTS);
            head = commit(&mut store, pending);
            assert_eq!(head.revision(), epoch);
            assert_eq!(head.revision(), head.registry().active_epoch());
            source_identities = target_identities;
            local_portable = resulting_portable;
        }
        head.verify_bounded(&store).unwrap();
        for epoch in 0..=3 {
            let found = lookup_compact_registry_epoch(&head, epoch, &store).unwrap();
            assert_eq!(found.link().epoch(), epoch);
            let window = lookup_verified_issuer_window(&head, epoch, &store).unwrap();
            assert_eq!(window.issuer().epoch(), epoch);
            assert_eq!(window.terminal().is_none(), epoch == 3);
        }
    }

    #[test]
    fn fixed_depth_index_has_constant_work_over_thousands_of_epochs() {
        let wallet = DepositWalletId([4_u8; 32]);
        let mut store = MemoryObjects::default();
        let mut root_reference = None;
        let mut root_hash = compact_registry_empty_index_root(wallet);
        for epoch in 0_u64..2_048 {
            let mut staged = BTreeMap::new();
            let mut contents = b"synthetic-link-v1/".to_vec();
            contents.extend_from_slice(&epoch.to_le_bytes());
            let link = stage_object(wallet, CompactRegistryObjectKind::Link, contents, &mut staged)
                .unwrap();
            let link_root = *blake3::hash(&epoch.to_le_bytes()).as_bytes();
            let (next_reference, next_hash) = insert_index(
                wallet,
                root_reference,
                root_hash,
                epoch,
                link_root,
                link,
                None,
                &mut staged,
                &store,
            )
            .unwrap();
            assert_eq!(
                staged
                    .keys()
                    .filter(|reference| reference.kind() == CompactRegistryObjectKind::IndexNode)
                    .count(),
                COMPACT_REGISTRY_INDEX_OBJECT_READS
            );
            for (reference, bytes) in staged {
                store.objects.insert(reference, bytes);
            }
            root_reference = Some(next_reference);
            root_hash = next_hash;

            store.reset_reads();
            let leaf = lookup_index_leaf(wallet, root_reference.unwrap(), root_hash, epoch, &store)
                .unwrap();
            assert_eq!(leaf.link_root, link_root);
            assert_eq!(store.reads(), COMPACT_REGISTRY_INDEX_OBJECT_READS);
        }
    }

    #[test]
    fn head_encoding_stays_bounded_across_thousands_of_revisions() {
        let (_, head, _) = genesis(DepositWalletId([8_u8; 32]));
        let mut largest = 0;
        for revision in 0..=4_096 {
            let mut synthetic_lifetime_head = head.clone();
            synthetic_lifetime_head.revision = revision;
            // This is a wire-size test, so encode synthetic generations directly. Shape validation
            // separately requires the revision to equal the active epoch.
            let bytes = postcard::to_allocvec(&synthetic_lifetime_head).unwrap();
            largest = largest.max(bytes.len());
            assert!(bytes.len() <= MAX_COMPACT_REGISTRY_HEAD_BYTES);
        }
        // The encoding may gain a few varint bytes as counters grow, but never one entry per
        // epoch.  This deliberately permits a future bounded committee encoding adjustment.
        assert!(largest < 4 * 1024);
    }

    #[test]
    fn zero_based_revision_represents_the_terminal_epoch_without_overflow() {
        assert_eq!(archive_revision_for_epoch(0), 0);
        assert_eq!(
            archive_revision_for_epoch(crate::compact_epoch_registry::FINAL_COMPACT_REGISTRY_EPOCH),
            u64::MAX
        );

        let (_, mut head, _) = genesis(DepositWalletId([9_u8; 32]));
        head.revision = 1;
        assert!(matches!(head.validate_shape(), Err(CompactRegistryArchiveError::InvalidHead)));
    }

    #[test]
    fn fork_transplant_and_partial_staging_are_rejected() {
        let wallet = DepositWalletId([1_u8; 32]);
        let (mut store, head, source_identities) = genesis(wallet);
        let target_identities = identities(1);
        let target = successor_authority(wallet, committee(1, &target_identities));
        let (certificate, portable) = first_handoff(&head, &source_identities, &target, &[0, 1, 2]);
        let pending =
            prepare_compact_registry_append(&head, &target, certificate.clone(), &portable, &store)
                .unwrap();

        assert!(pending.clone().verify_staged(&store).is_err());
        store.install_prefix(&pending, pending.staged_objects().len() - 1);
        assert!(pending.clone().verify_staged(&store).is_err());
        let retry =
            prepare_compact_registry_append(&head, &target, certificate.clone(), &portable, &store)
                .unwrap();
        assert_eq!(retry.proposed_head(), pending.proposed_head());
        assert_eq!(retry.staged_objects(), pending.staged_objects());
        store.install(&pending);
        let verified = pending.clone().verify_staged(&store).unwrap();
        let expected = pending.expected_head_bytes().unwrap().to_vec();
        assert!(
            verified
                .authorize_install(Some(&expected), head.to_bytes().unwrap().as_slice())
                .is_err()
        );
        let next_bytes = verified.next_head_bytes().to_vec();
        let next = verified.authorize_install(Some(&expected), &next_bytes).unwrap();
        next.verify_bounded(&store).unwrap();

        let (other_store, other_head, _) = genesis(DepositWalletId([2_u8; 32]));
        assert!(
            prepare_compact_registry_append(
                &other_head,
                &target,
                certificate,
                &portable,
                &other_store,
            )
            .is_err()
        );
    }

    #[test]
    fn head_rejects_an_index_with_entries_after_the_claimed_active_epoch() {
        let wallet = DepositWalletId([6_u8; 32]);
        let (mut store, head, _) = genesis(wallet);
        let active_link_bytes = store.objects.get(&head.active_link).unwrap();
        let active_link = decode_canonical_bounded::<RegistryLink>(
            active_link_bytes,
            MAX_COMPACT_REGISTRY_LINK_BYTES,
            "compact registry link",
        )
        .unwrap();

        let mut staged = BTreeMap::new();
        let extra_link = stage_object(
            wallet,
            CompactRegistryObjectKind::Link,
            b"unauthorized-future-link".to_vec(),
            &mut staged,
        )
        .unwrap();
        let (forged_root_reference, forged_root) = insert_index(
            wallet,
            Some(head.index_root),
            head.registry.id().index_root(),
            99,
            [99_u8; 32],
            extra_link,
            None,
            &mut staged,
            &store,
        )
        .unwrap();
        for (reference, bytes) in staged {
            store.objects.insert(reference, bytes);
        }
        let mut forged = head.clone();
        forged.index_root = forged_root_reference;
        forged.registry = CompactEpochRegistry::from_link(&active_link, forged_root).unwrap();
        forged.validate_shape().unwrap();
        assert!(forged.verify_bounded(&store).is_err());
    }

    #[test]
    fn tampering_and_noncanonical_head_bytes_fail_closed() {
        let wallet = DepositWalletId([1_u8; 32]);
        let (mut store, head, _) = genesis(wallet);
        let reference = head.active_link_reference();
        store.objects.get_mut(&reference).unwrap()[0] ^= 1;
        assert!(head.verify_bounded(&store).is_err());

        let mut head_bytes = head.to_bytes().unwrap();
        head_bytes.push(0);
        assert!(CompactRegistryArchiveHead::from_bytes(&head_bytes).is_err());
        assert!(head_bytes.len() <= MAX_COMPACT_REGISTRY_HEAD_BYTES + 1);
    }
}
