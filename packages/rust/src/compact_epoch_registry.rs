//! Constant-head, witness-independent epoch-registry semantics.
//!
//! This is the sole registry format. A deployment starts with this bounded encoding and fails
//! closed on every other representation.
//!
//! The authenticated index which retains historical links is implemented by
//! `compact_registry_archive`.  This file owns the semantic commitments shared by every replica.
//! In particular, exact quorum-witness vectors are never hashed into a [`RegistryId`] or
//! [`RegistryLink`].  Two valid `n-f` witness subsets therefore name the same registry state.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::{Committee, CommitteeError, SessionId},
    deposit_state_export::{DepositHandoffStateBinding, DepositStateExportError},
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
    identity::{Identity, IdentityError, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
};

pub const COMPACT_EPOCH_REGISTRY_VERSION: u16 = 2;
pub const COMPACT_REGISTRY_ID_VERSION: u16 = 2;
pub const COMPACT_REGISTRY_LINK_VERSION: u16 = 2;
pub const COMPACT_ACTIVE_ISSUER_VERSION: u16 = 2;
pub const COMPACT_HANDOFF_STATEMENT_VERSION: u16 = 3;
pub const COMPACT_HANDOFF_CERTIFICATE_VERSION: u16 = 3;
pub const VERIFIED_ISSUER_WINDOW_VERSION: u16 = 2;
const MAX_COMPACT_HANDOFF_CERTIFICATE_BYTES: usize = 64 * 1024;

/// A `u64` key always consumes exactly this many authenticated branch decisions.
pub const COMPACT_REGISTRY_INDEX_DEPTH: u8 = 64;
/// The index covers every representable epoch without an archive-policy cap.  As with the rest of
/// the protocol's `u64` counters, `u64::MAX` is an explicit terminal value: a successor request
/// fails with [`CompactRegistryError::Overflow`] instead of wrapping to genesis.
pub const FINAL_COMPACT_REGISTRY_EPOCH: u64 = u64::MAX;

const REGISTRY_ID_DOMAIN: &str = "threshold-monero/compact-registry-id/v2";
const LINK_DOMAIN: &str = "threshold-monero/compact-registry-link/v2";
const HANDOFF_STATEMENT_DOMAIN: &str = "threshold-monero/compact-registry-handoff-statement/v3";
const HANDOFF_SESSION_DOMAIN: &[u8] = b"threshold-monero/compact-registry-handoff-session/v3";
const HANDOFF_CERTIFICATE_DOMAIN: &str = "threshold-monero/compact-registry-handoff-certificate/v3";
const HANDOFF_EXPORT_CAPABILITY_DOMAIN: &str =
    "threshold-monero/compact-registry-handoff-export-capability/v1";
const GENESIS_PARENT_DOMAIN: &str = "threshold-monero/compact-registry-genesis-parent/v2";
const GENESIS_LEDGER_HEAD_DOMAIN: &str = "threshold-monero/compact-registry-ledger-genesis/v2";
const INDEX_EMPTY_LEAF_DOMAIN: &str = "threshold-monero/compact-registry-index-empty-leaf/v2";
const INDEX_EMPTY_BRANCH_DOMAIN: &str = "threshold-monero/compact-registry-index-empty-branch/v2";
const INDEX_LEAF_DOMAIN: &str = "threshold-monero/compact-registry-index-leaf/v2";
const INDEX_BRANCH_DOMAIN: &str = "threshold-monero/compact-registry-index-branch/v2";

/// Fixed-size semantic identity of the active registry state.
///
/// `index_root` is the semantic root of the fixed-depth authenticated epoch index.  It excludes
/// storage references and quorum witness vectors.  `chain_root` commits to the complete ordered
/// semantic link chain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RegistryId {
    version: u16,
    wallet: DepositWalletId,
    active_epoch: u64,
    chain_root: [u8; 32],
    index_root: [u8; 32],
}

impl RegistryId {
    pub(crate) fn new(
        wallet: DepositWalletId,
        active_epoch: u64,
        chain_root: [u8; 32],
        index_root: [u8; 32],
    ) -> Result<Self, CompactRegistryError> {
        let id = Self {
            version: COMPACT_REGISTRY_ID_VERSION,
            wallet,
            active_epoch,
            chain_root,
            index_root,
        };
        id.validate()?;
        Ok(id)
    }

    pub fn validate(&self) -> Result<(), CompactRegistryError> {
        if self.version != COMPACT_REGISTRY_ID_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.chain_root == [0_u8; 32]
            || self.index_root == [0_u8; 32]
        {
            return Err(CompactRegistryError::InvalidRegistryId);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn active_epoch(self) -> u64 {
        self.active_epoch
    }

    #[must_use]
    pub const fn chain_root(self) -> [u8; 32] {
        self.chain_root
    }

    #[must_use]
    pub const fn index_root(self) -> [u8; 32] {
        self.index_root
    }

    /// Domain-separated digest used when a fixed-size registry identity is embedded elsewhere.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(REGISTRY_ID_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        hasher.update(&self.active_epoch.to_le_bytes());
        hasher.update(&self.chain_root);
        hasher.update(&self.index_root);
        *hasher.finalize().as_bytes()
    }
}

/// One witness-independent semantic link in the epoch chain.
///
/// For a successor, `parent_index_root` is the authenticated index root *after* the parent was
/// installed, while `parent_chain_root` is the parent's semantic chain root.  The signed handoff
/// digest binds both roots through [`RegistryHandoffStatement::source`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryLink {
    version: u16,
    wallet: DepositWalletId,
    parent_epoch: Option<u64>,
    parent_chain_root: [u8; 32],
    parent_index_root: [u8; 32],
    key_id: [u8; 32],
    group_key: [u8; 32],
    committee: Committee,
    fault_bound: u16,
    activation: [u8; 32],
    certified_activation_root: [u8; 32],
    start_sequence: u64,
    first_index: DepositSubaddressIndex,
    predecessor_ledger_head: [u8; 32],
    /// Witness-independent digest of the portable deposit-index head immediately before genesis
    /// or the terminal handoff statement.
    portable_index_checkpoint: [u8; 32],
    handoff_statement: Option<[u8; 32]>,
}

impl RegistryLink {
    /// Construct a canonical genesis link. No alternate registry or genesis digest is
    /// accepted. The non-serializable target capability can only be created after the epoch-zero
    /// DKG activation certificate and configured Monero wallet binding have both been verified.
    pub fn genesis(
        target: &VerifiedRegistryHandoffTarget,
        first_index: DepositSubaddressIndex,
        portable_index_checkpoint: [u8; 32],
    ) -> Result<Self, CompactRegistryError> {
        let wallet = target.wallet();
        let committee = target.committee().clone().canonicalized()?;
        if committee.epoch != 0 {
            return Err(CompactRegistryError::InvalidGenesis);
        }
        let link = Self {
            version: COMPACT_REGISTRY_LINK_VERSION,
            wallet,
            parent_epoch: None,
            parent_chain_root: compact_registry_genesis_parent(wallet),
            parent_index_root: compact_registry_empty_index_root(wallet),
            key_id: target.key_id(),
            group_key: target.group_key(),
            committee,
            fault_bound: target.fault_bound(),
            activation: target.activation(),
            certified_activation_root: target.certified_activation_root(),
            start_sequence: 1,
            first_index,
            predecessor_ledger_head: compact_registry_genesis_ledger_head(wallet),
            portable_index_checkpoint,
            handoff_statement: None,
        };
        link.validate()?;
        Ok(link)
    }

    /// Derive the unique semantic successor authenticated by `certificate`.
    pub fn successor(
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        certificate: &RegistryHandoffCertificate,
    ) -> Result<Self, CompactRegistryError> {
        source.validate()?;
        let target_committee = target.committee().clone().canonicalized()?;
        validate_fault_bound(&target_committee, target.fault_bound())?;
        certificate.verify(source)?;
        let statement = certificate.statement();
        if target.wallet() != source.wallet()
            || target.key_id() != source.active.key_id
            || target.group_key() != source.active.group_key
            || statement.target_committee != target_committee.digest()
            || statement.target_fault_bound != target.fault_bound()
            || statement.target_activation != target.activation()
            || statement.target_key_id != target.key_id()
            || statement.target_group_key != target.group_key()
            || statement.target_certified_activation_root != target.certified_activation_root()
        {
            return Err(CompactRegistryError::WrongHandoffTarget);
        }
        let start_sequence =
            statement.terminal_sequence.checked_add(1).ok_or(CompactRegistryError::Overflow)?;
        let link = Self {
            version: COMPACT_REGISTRY_LINK_VERSION,
            wallet: source.id.wallet,
            parent_epoch: Some(source.id.active_epoch),
            parent_chain_root: source.id.chain_root,
            parent_index_root: source.id.index_root,
            key_id: target.key_id(),
            group_key: target.group_key(),
            committee: target_committee,
            fault_bound: target.fault_bound(),
            activation: target.activation(),
            certified_activation_root: target.certified_activation_root(),
            start_sequence,
            first_index: statement.next_index,
            predecessor_ledger_head: statement.digest(),
            portable_index_checkpoint: statement.source_portable_index,
            handoff_statement: Some(statement.digest()),
        };
        Self::verify_certified_successor(source, &link, certificate)?;
        Ok(link)
    }

    /// Re-authenticate a serialized successor using its old-quorum certificate.
    ///
    /// This is deliberately a verifier, not a raw constructor: archive replay can validate
    /// persisted bytes without manufacturing the non-serializable activation capability required
    /// at the live mutation boundary.
    pub(crate) fn verify_certified_successor(
        source: &CompactEpochRegistry,
        candidate: &Self,
        certificate: &RegistryHandoffCertificate,
    ) -> Result<(), CompactRegistryError> {
        source.validate()?;
        candidate.validate()?;
        certificate.verify(source)?;
        let statement = certificate.statement();
        let expected_start =
            statement.terminal_sequence.checked_add(1).ok_or(CompactRegistryError::Overflow)?;
        if candidate.wallet != source.wallet()
            || candidate.parent_epoch != Some(source.active_epoch())
            || candidate.parent_chain_root != source.id.chain_root
            || candidate.parent_index_root != source.id.index_root
            || candidate.key_id != source.active.key_id
            || candidate.group_key != source.active.group_key
            || candidate.committee.epoch != statement.target_epoch
            || candidate.committee.digest() != statement.target_committee
            || candidate.fault_bound != statement.target_fault_bound
            || candidate.activation != statement.target_activation
            || candidate.certified_activation_root != statement.target_certified_activation_root
            || candidate.key_id != statement.target_key_id
            || candidate.group_key != statement.target_group_key
            || candidate.start_sequence != expected_start
            || candidate.first_index != statement.next_index
            || candidate.predecessor_ledger_head != statement.digest()
            || candidate.portable_index_checkpoint != statement.source_portable_index
            || candidate.handoff_statement != Some(statement.digest())
        {
            return Err(CompactRegistryError::WrongHandoffTarget);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CompactRegistryError> {
        if self.version != COMPACT_REGISTRY_LINK_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.key_id == [0_u8; 32]
            || self.group_key == [0_u8; 32]
            || self.activation == [0_u8; 32]
            || self.certified_activation_root == [0_u8; 32]
            || self.parent_chain_root == [0_u8; 32]
            || self.parent_index_root == [0_u8; 32]
            || self.predecessor_ledger_head == [0_u8; 32]
            || self.portable_index_checkpoint == [0_u8; 32]
            || self.start_sequence == 0
        {
            return Err(CompactRegistryError::InvalidLink);
        }
        self.committee.validate()?;
        if self.committee.clone().canonicalized()? != self.committee {
            return Err(CompactRegistryError::NonCanonicalCommittee);
        }
        validate_fault_bound(&self.committee, self.fault_bound)?;
        match (self.parent_epoch, self.handoff_statement) {
            (None, None) => {
                if self.committee.epoch != 0
                    || self.start_sequence != 1
                    || self.parent_chain_root != compact_registry_genesis_parent(self.wallet)
                    || self.parent_index_root != compact_registry_empty_index_root(self.wallet)
                    || self.predecessor_ledger_head
                        != compact_registry_genesis_ledger_head(self.wallet)
                {
                    return Err(CompactRegistryError::InvalidGenesis);
                }
            }
            (Some(parent_epoch), Some(statement_digest)) => {
                if parent_epoch.checked_add(1) != Some(self.committee.epoch)
                    || statement_digest == [0_u8; 32]
                    || statement_digest != self.predecessor_ledger_head
                    || self.start_sequence <= 1
                {
                    return Err(CompactRegistryError::InvalidLink);
                }
            }
            _ => return Err(CompactRegistryError::InvalidLink),
        }
        Ok(())
    }

    /// Chain commitment.  Exact handoff witnesses and local archive references are intentionally
    /// absent.
    pub fn chain_root(&self) -> Result<[u8; 32], CompactRegistryError> {
        // `Committee::digest` assumes a validated committee.  Keep that assumption inside this
        // fallible boundary so malformed untrusted link bytes can never turn into a panic.
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key(LINK_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        match self.parent_epoch {
            None => {
                hasher.update(&[0]);
            }
            Some(epoch) => {
                hasher.update(&[1]);
                hasher.update(&epoch.to_le_bytes());
            }
        }
        hasher.update(&self.parent_chain_root);
        hasher.update(&self.parent_index_root);
        hasher.update(&self.key_id);
        hasher.update(&self.group_key);
        hasher.update(&self.committee.epoch.to_le_bytes());
        hasher.update(&self.committee.digest());
        hasher.update(&self.fault_bound.to_le_bytes());
        hasher.update(&self.activation);
        hasher.update(&self.certified_activation_root);
        hasher.update(&self.start_sequence.to_le_bytes());
        hasher.update(&self.first_index.account().to_le_bytes());
        hasher.update(&self.first_index.address().to_le_bytes());
        hasher.update(&self.predecessor_ledger_head);
        hasher.update(&self.portable_index_checkpoint);
        match self.handoff_statement {
            None => {
                hasher.update(&[0]);
            }
            Some(digest) => {
                hasher.update(&[1]);
                hasher.update(&digest);
            }
        }
        Ok(*hasher.finalize().as_bytes())
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.committee.epoch
    }

    #[must_use]
    pub const fn parent_epoch(&self) -> Option<u64> {
        self.parent_epoch
    }

    #[must_use]
    pub const fn parent_chain_root(&self) -> [u8; 32] {
        self.parent_chain_root
    }

    #[must_use]
    pub const fn parent_index_root(&self) -> [u8; 32] {
        self.parent_index_root
    }

    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    #[must_use]
    pub const fn group_key(&self) -> [u8; 32] {
        self.group_key
    }

    #[must_use]
    pub const fn committee(&self) -> &Committee {
        &self.committee
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub const fn activation(&self) -> [u8; 32] {
        self.activation
    }

    #[must_use]
    pub const fn activation_binding(&self) -> [u8; 32] {
        self.activation
    }

    #[must_use]
    pub const fn certified_activation_root(&self) -> [u8; 32] {
        self.certified_activation_root
    }

    #[must_use]
    pub const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    #[must_use]
    pub const fn first_index(&self) -> DepositSubaddressIndex {
        self.first_index
    }

    #[must_use]
    pub const fn predecessor_ledger_head(&self) -> [u8; 32] {
        self.predecessor_ledger_head
    }

    #[must_use]
    pub const fn portable_index_checkpoint(&self) -> [u8; 32] {
        self.portable_index_checkpoint
    }

    #[must_use]
    pub const fn handoff_statement(&self) -> Option<[u8; 32]> {
        self.handoff_statement
    }
}

/// Bounded active issuer material retained directly in the compact head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActiveIssuer {
    version: u16,
    id: RegistryId,
    key_id: [u8; 32],
    group_key: [u8; 32],
    committee: Committee,
    fault_bound: u16,
    activation: [u8; 32],
    certified_activation_root: [u8; 32],
    start_sequence: u64,
    first_index: DepositSubaddressIndex,
    predecessor_ledger_head: [u8; 32],
    portable_index_checkpoint: [u8; 32],
}

impl ActiveIssuer {
    pub(crate) fn from_link(
        link: &RegistryLink,
        index_root: [u8; 32],
    ) -> Result<Self, CompactRegistryError> {
        link.validate()?;
        let id = RegistryId::new(link.wallet, link.epoch(), link.chain_root()?, index_root)?;
        let active = Self {
            version: COMPACT_ACTIVE_ISSUER_VERSION,
            id,
            key_id: link.key_id,
            group_key: link.group_key,
            committee: link.committee.clone(),
            fault_bound: link.fault_bound,
            activation: link.activation,
            certified_activation_root: link.certified_activation_root,
            start_sequence: link.start_sequence,
            first_index: link.first_index,
            predecessor_ledger_head: link.predecessor_ledger_head,
            portable_index_checkpoint: link.portable_index_checkpoint,
        };
        active.validate()?;
        Ok(active)
    }

    pub fn validate(&self) -> Result<(), CompactRegistryError> {
        if self.version != COMPACT_ACTIVE_ISSUER_VERSION
            || self.id.active_epoch != self.committee.epoch
            || self.key_id == [0_u8; 32]
            || self.group_key == [0_u8; 32]
            || self.activation == [0_u8; 32]
            || self.certified_activation_root == [0_u8; 32]
            || self.start_sequence == 0
            || self.predecessor_ledger_head == [0_u8; 32]
            || self.portable_index_checkpoint == [0_u8; 32]
        {
            return Err(CompactRegistryError::InvalidActiveIssuer);
        }
        self.id.validate()?;
        self.committee.validate()?;
        if self.committee.clone().canonicalized()? != self.committee {
            return Err(CompactRegistryError::NonCanonicalCommittee);
        }
        validate_fault_bound(&self.committee, self.fault_bound)
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.id
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.id.wallet
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.id.active_epoch
    }

    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    #[must_use]
    pub const fn group_key(&self) -> [u8; 32] {
        self.group_key
    }

    #[must_use]
    pub const fn committee(&self) -> &Committee {
        &self.committee
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub const fn activation(&self) -> [u8; 32] {
        self.activation
    }

    #[must_use]
    pub const fn activation_binding(&self) -> [u8; 32] {
        self.activation
    }

    #[must_use]
    pub const fn certified_activation_root(&self) -> [u8; 32] {
        self.certified_activation_root
    }

    #[must_use]
    pub const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    #[must_use]
    pub const fn first_index(&self) -> DepositSubaddressIndex {
        self.first_index
    }

    #[must_use]
    pub const fn predecessor_ledger_head(&self) -> [u8; 32] {
        self.predecessor_ledger_head
    }

    #[must_use]
    pub const fn portable_index_checkpoint(&self) -> [u8; 32] {
        self.portable_index_checkpoint
    }
}

/// Constant-head registry state.  Its serialized size is bounded by one committee and does not
/// grow with the number of epochs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactEpochRegistry {
    version: u16,
    id: RegistryId,
    active: ActiveIssuer,
}

impl CompactEpochRegistry {
    pub(crate) fn from_link(
        link: &RegistryLink,
        index_root: [u8; 32],
    ) -> Result<Self, CompactRegistryError> {
        let active = ActiveIssuer::from_link(link, index_root)?;
        let registry = Self { version: COMPACT_EPOCH_REGISTRY_VERSION, id: active.id, active };
        registry.validate()?;
        Ok(registry)
    }

    pub fn validate(&self) -> Result<(), CompactRegistryError> {
        if self.version != COMPACT_EPOCH_REGISTRY_VERSION || self.id != self.active.id {
            return Err(CompactRegistryError::InvalidRegistry);
        }
        self.id.validate()?;
        self.active.validate()
    }

    /// Authenticate this compact head against a server-issued activation capability.
    ///
    /// A fresh joiner must call this (or compare the same fields to an explicitly configured trust
    /// anchor) before treating archive bytes as an authority. Structural registry validation alone
    /// intentionally cannot prove that the committed activation root was quorum certified.
    pub fn verify_active_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), CompactRegistryError> {
        self.validate()?;
        if self.wallet() != target.wallet()
            || self.active_epoch() != target.committee().epoch
            || self.active.key_id != target.key_id()
            || self.active.group_key != target.group_key()
            || self.active.committee.digest() != target.committee().digest()
            || self.active.fault_bound != target.fault_bound()
            || self.active.activation != target.activation()
            || self.active.certified_activation_root != target.certified_activation_root()
        {
            return Err(CompactRegistryError::WrongActivationAuthority);
        }
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> RegistryId {
        self.id
    }

    #[must_use]
    pub const fn active(&self) -> &ActiveIssuer {
        &self.active
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.id.wallet
    }

    #[must_use]
    pub const fn active_epoch(&self) -> u64 {
        self.id.active_epoch
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.id.digest()
    }
}

/// Root-bound terminal statement signed by the retiring issuer.
///
/// The source identity includes both the semantic chain root and the authenticated index root.
/// Consequently a certificate cannot be transplanted onto another fork, another witness-derived
/// logical state, or an earlier/later source head. `source_state` binds the complete
/// witness-independent logical [`crate::deposit_index::DepositIndexHead`] immediately before the
/// terminal statement. Exact source-specific archive and certificate references are deliberately
/// excluded and enter a separate post-handoff export seal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryHandoffStatement {
    version: u16,
    wallet: DepositWalletId,
    source: RegistryId,
    source_key_id: [u8; 32],
    source_group_key: [u8; 32],
    source_committee: [u8; 32],
    source_activation: [u8; 32],
    source_certified_activation_root: [u8; 32],
    terminal_sequence: u64,
    previous_ledger_head: [u8; 32],
    source_portable_index: [u8; 32],
    source_state: DepositHandoffStateBinding,
    export_capability_context: [u8; 32],
    target_epoch: u64,
    target_key_id: [u8; 32],
    target_group_key: [u8; 32],
    target_committee: [u8; 32],
    target_fault_bound: u16,
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    next_index: DepositSubaddressIndex,
}

fn handoff_export_capability_context(
    source: &CompactEpochRegistry,
    state: &DepositHandoffStateBinding,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<[u8; 32], CompactRegistryError> {
    handoff_export_capability_context_from_parts(
        source.id(),
        source.active().certified_activation_root(),
        state,
        target.committee().epoch,
        target.committee().digest(),
        target.activation(),
        target.certified_activation_root(),
    )
}

fn handoff_export_capability_context_from_parts(
    source: RegistryId,
    source_certified_activation_root: [u8; 32],
    state: &DepositHandoffStateBinding,
    target_epoch: u64,
    target_committee: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
) -> Result<[u8; 32], CompactRegistryError> {
    source.validate()?;
    state.validate()?;
    if source_certified_activation_root == [0; 32]
        || target_committee == [0; 32]
        || target_activation == [0; 32]
        || target_certified_activation_root == [0; 32]
    {
        return Err(CompactRegistryError::InvalidHandoffStatement);
    }
    let mut hasher = blake3::Hasher::new_derive_key(HANDOFF_EXPORT_CAPABILITY_DOMAIN);
    hasher.update(&source.digest());
    hasher.update(&source_certified_activation_root);
    hasher.update(&state.digest()?);
    hasher.update(&target_epoch.to_le_bytes());
    hasher.update(&target_committee);
    hasher.update(&target_activation);
    hasher.update(&target_certified_activation_root);
    Ok(*hasher.finalize().as_bytes())
}

impl RegistryHandoffStatement {
    pub fn new(
        source: &CompactEpochRegistry,
        terminal_sequence: u64,
        previous_ledger_head: [u8; 32],
        source_state: DepositHandoffStateBinding,
        target: &VerifiedRegistryHandoffTarget,
        next_index: DepositSubaddressIndex,
    ) -> Result<Self, CompactRegistryError> {
        source.validate()?;
        let target_committee = target.committee().clone().canonicalized()?;
        validate_fault_bound(&target_committee, target.fault_bound())?;
        if target.wallet() != source.wallet()
            || target.key_id() != source.active.key_id
            || target.group_key() != source.active.group_key
        {
            return Err(CompactRegistryError::WrongHandoffTarget);
        }
        source_state.validate()?;
        if source_state.portable_head().wallet_id() != source.wallet() {
            return Err(CompactRegistryError::InvalidHandoffStatement);
        }
        let source_portable_index = source_state.portable_head().digest();
        let export_capability_context =
            handoff_export_capability_context(source, &source_state, target)?;
        let statement = Self {
            version: COMPACT_HANDOFF_STATEMENT_VERSION,
            wallet: source.wallet(),
            source: source.id(),
            source_key_id: source.active.key_id,
            source_group_key: source.active.group_key,
            source_committee: source.active.committee.digest(),
            source_activation: source.active.activation,
            source_certified_activation_root: source.active.certified_activation_root,
            terminal_sequence,
            previous_ledger_head,
            source_portable_index,
            source_state,
            export_capability_context,
            target_epoch: target_committee.epoch,
            target_key_id: target.key_id(),
            target_group_key: target.group_key(),
            target_committee: target_committee.digest(),
            target_fault_bound: target.fault_bound(),
            target_activation: target.activation(),
            target_certified_activation_root: target.certified_activation_root(),
            next_index,
        };
        statement.validate_against(source)?;
        Ok(statement)
    }

    pub fn validate_against(
        &self,
        source: &CompactEpochRegistry,
    ) -> Result<(), CompactRegistryError> {
        source.validate()?;
        self.source.validate()?;
        self.source_state.validate()?;
        // Every handoff creates a successor whose first ledger sequence is terminal + 1.  Keeping
        // this check in the signed-statement validator prevents a quorum from certifying an
        // otherwise well-formed transition which no successor can install.
        self.terminal_sequence.checked_add(1).ok_or(CompactRegistryError::Overflow)?;
        if self.version != COMPACT_HANDOFF_STATEMENT_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.wallet != source.wallet()
            || self.source != source.id()
            || self.source_key_id != source.active.key_id
            || self.source_group_key != source.active.group_key
            || self.source_committee != source.active.committee.digest()
            || self.source_activation != source.active.activation
            || self.source_certified_activation_root != source.active.certified_activation_root
            || self.source_key_id == [0_u8; 32]
            || self.source_group_key == [0_u8; 32]
            || self.source_activation == [0_u8; 32]
            || self.source_certified_activation_root == [0_u8; 32]
            || self.terminal_sequence < source.active.start_sequence
            || self.previous_ledger_head == [0_u8; 32]
            || self.source_portable_index == [0_u8; 32]
            || self.source_state.portable_head().wallet_id() != self.wallet
            || self.source_state.portable_head().digest() != self.source_portable_index
            || self.source_state.terminal_checkpoint_decision().is_none()
            || self.source_state.portable_head().through_sequence().checked_add(1)
                != Some(self.terminal_sequence)
            || self.source_state.portable_head().ledger_head() != self.previous_ledger_head
            || self.source_state.portable_head().next_index() != self.next_index
            || self.export_capability_context == [0_u8; 32]
            || self.target_epoch
                != source.active_epoch().checked_add(1).ok_or(CompactRegistryError::Overflow)?
            || self.target_committee == [0_u8; 32]
            || self.target_key_id != self.source_key_id
            || self.target_group_key != self.source_group_key
            || self.target_activation == [0_u8; 32]
            || self.target_certified_activation_root == [0_u8; 32]
        {
            return Err(CompactRegistryError::InvalidHandoffStatement);
        }
        let expected_export_context = handoff_export_capability_context_from_parts(
            self.source,
            self.source_certified_activation_root,
            &self.source_state,
            self.target_epoch,
            self.target_committee,
            self.target_activation,
            self.target_certified_activation_root,
        )?;
        if self.export_capability_context != expected_export_context {
            return Err(CompactRegistryError::InvalidHandoffStatement);
        }
        Ok(())
    }

    /// Explicit field commitment; Rust struct layout and witness serialization cannot redefine it.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(HANDOFF_STATEMENT_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        hasher.update(&self.source.digest());
        hasher.update(&self.source_key_id);
        hasher.update(&self.source_group_key);
        hasher.update(&self.source_committee);
        hasher.update(&self.source_activation);
        hasher.update(&self.source_certified_activation_root);
        hasher.update(&self.terminal_sequence.to_le_bytes());
        hasher.update(&self.previous_ledger_head);
        hasher.update(&self.source_portable_index);
        hasher.update(
            &self
                .source_state
                .digest()
                .expect("validated handoff state binding has a canonical digest"),
        );
        hasher.update(&self.export_capability_context);
        hasher.update(&self.target_epoch.to_le_bytes());
        hasher.update(&self.target_key_id);
        hasher.update(&self.target_group_key);
        hasher.update(&self.target_committee);
        hasher.update(&self.target_fault_bound.to_le_bytes());
        hasher.update(&self.target_activation);
        hasher.update(&self.target_certified_activation_root);
        hasher.update(&self.next_index.account().to_le_bytes());
        hasher.update(&self.next_index.address().to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    #[must_use]
    pub fn session(&self) -> SessionId {
        SessionId::derive(HANDOFF_SESSION_DOMAIN, &self.digest())
    }

    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        self.digest().to_vec()
    }

    #[must_use]
    pub const fn source(&self) -> RegistryId {
        self.source
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn source_committee(&self) -> [u8; 32] {
        self.source_committee
    }

    #[must_use]
    pub const fn source_key_id(&self) -> [u8; 32] {
        self.source_key_id
    }

    #[must_use]
    pub const fn source_group_key(&self) -> [u8; 32] {
        self.source_group_key
    }

    #[must_use]
    pub const fn source_activation(&self) -> [u8; 32] {
        self.source_activation
    }

    #[must_use]
    pub const fn source_certified_activation_root(&self) -> [u8; 32] {
        self.source_certified_activation_root
    }

    #[must_use]
    pub const fn terminal_sequence(&self) -> u64 {
        self.terminal_sequence
    }

    #[must_use]
    pub const fn previous_ledger_head(&self) -> [u8; 32] {
        self.previous_ledger_head
    }

    #[must_use]
    pub const fn source_portable_index(&self) -> [u8; 32] {
        self.source_portable_index
    }

    #[must_use]
    pub const fn source_state(&self) -> &DepositHandoffStateBinding {
        &self.source_state
    }

    /// Witness-independent transition context authorizing source-specific read-only export seals.
    ///
    /// This commits the source registry ID and activation root, the full semantic portable state,
    /// and the target epoch, committee, activation, and certified activation-history root.
    #[must_use]
    pub const fn export_capability_context(&self) -> [u8; 32] {
        self.export_capability_context
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub const fn target_key_id(&self) -> [u8; 32] {
        self.target_key_id
    }

    #[must_use]
    pub const fn target_group_key(&self) -> [u8; 32] {
        self.target_group_key
    }

    #[must_use]
    pub const fn target_committee(&self) -> [u8; 32] {
        self.target_committee
    }

    #[must_use]
    pub const fn target_fault_bound(&self) -> u16 {
        self.target_fault_bound
    }

    #[must_use]
    pub const fn target_activation(&self) -> [u8; 32] {
        self.target_activation
    }

    #[must_use]
    pub const fn target_certified_activation_root(&self) -> [u8; 32] {
        self.target_certified_activation_root
    }

    #[must_use]
    pub const fn next_index(&self) -> DepositSubaddressIndex {
        self.next_index
    }
}

/// Exact old-quorum witness artifact.  Its witness vector is stored separately from semantic
/// registry links and authenticated before a staged head may be installed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryHandoffCertificate {
    version: u16,
    statement: RegistryHandoffStatement,
    witnesses: Vec<SignedEnvelope>,
}

impl RegistryHandoffCertificate {
    /// Canonicalize witness order.  Exactly `n-f` distinct broadcast signatures are required by
    /// [`Self::verify`].
    pub fn new(
        statement: RegistryHandoffStatement,
        mut witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, CompactRegistryError> {
        witnesses.sort_by_key(|witness| witness.from);
        let certificate =
            Self { version: COMPACT_HANDOFF_CERTIFICATE_VERSION, statement, witnesses };
        if certificate.witnesses.windows(2).any(|pair| pair[0].from == pair[1].from) {
            return Err(CompactRegistryError::DuplicateWitness);
        }
        Ok(certificate)
    }

    pub fn verify(&self, source: &CompactEpochRegistry) -> Result<(), CompactRegistryError> {
        if self.version != COMPACT_HANDOFF_CERTIFICATE_VERSION {
            return Err(CompactRegistryError::InvalidHandoffCertificate);
        }
        self.statement.validate_against(source)?;
        let committee = source.active.committee();
        let required = committee
            .n()
            .checked_sub(source.active.fault_bound())
            .ok_or(CompactRegistryError::InvalidFaultBound)?;
        if self.witnesses.len() != usize::from(required) {
            return Err(CompactRegistryError::WrongWitnessCount {
                actual: self.witnesses.len(),
                required: usize::from(required),
            });
        }
        let verifier =
            committee.members.first().ok_or(CompactRegistryError::InvalidHandoffCertificate)?.id;
        let expected_session = self.statement.session();
        let expected_payload = self.statement.signing_payload();
        let mut signers = BTreeSet::new();
        let mut previous = None;
        for witness in &self.witnesses {
            if previous.is_some_and(|party| party >= witness.from)
                || !signers.insert(witness.from)
                || witness.to.is_some()
                || witness.session != expected_session
                || witness.sequence != self.statement.terminal_sequence
                || witness.payload != expected_payload
            {
                return Err(CompactRegistryError::InvalidHandoffCertificate);
            }
            Identity::verify_envelope(committee, verifier, witness)?;
            previous = Some(witness.from);
        }
        Ok(())
    }

    /// Canonical bounded bytes of this exact witness-set-specific certificate.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CompactRegistryError> {
        if self.version != COMPACT_HANDOFF_CERTIFICATE_VERSION {
            return Err(CompactRegistryError::InvalidHandoffCertificate);
        }
        let bytes = postcard::to_allocvec(self).map_err(|_| CompactRegistryError::Serialization)?;
        if bytes.is_empty() || bytes.len() > MAX_COMPACT_HANDOFF_CERTIFICATE_BYTES {
            return Err(CompactRegistryError::HandoffCertificateTooLarge);
        }
        Ok(bytes)
    }

    /// Decode one exact certificate artifact without accepting trailing or alternate encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CompactRegistryError> {
        if bytes.is_empty() || bytes.len() > MAX_COMPACT_HANDOFF_CERTIFICATE_BYTES {
            return Err(CompactRegistryError::HandoffCertificateTooLarge);
        }
        let (certificate, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| CompactRegistryError::Serialization)?;
        if !trailing.is_empty() {
            return Err(CompactRegistryError::TrailingBytes);
        }
        if certificate.to_bytes()? != bytes {
            return Err(CompactRegistryError::NonCanonicalEncoding);
        }
        Ok(certificate)
    }

    /// Domain-separated commitment to the exact canonical witness-bearing artifact.
    pub fn digest(&self) -> Result<[u8; 32], CompactRegistryError> {
        let bytes = self.to_bytes()?;
        let mut hasher = blake3::Hasher::new_derive_key(HANDOFF_CERTIFICATE_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    #[must_use]
    pub const fn statement(&self) -> &RegistryHandoffStatement {
        &self.statement
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }
}

/// Exact terminal seal of a historical issuer window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerTerminalSeal {
    pub sequence: u64,
    pub statement_digest: [u8; 32],
    pub successor_epoch: u64,
}

/// Directly authenticated issuer window returned by the archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedIssuerWindow {
    version: u16,
    issuer: ActiveIssuer,
    terminal: Option<IssuerTerminalSeal>,
}

impl VerifiedIssuerWindow {
    pub(crate) fn from_links(
        issuer: &RegistryLink,
        index_root_after_issuer: [u8; 32],
        successor: Option<&RegistryLink>,
    ) -> Result<Self, CompactRegistryError> {
        let active = ActiveIssuer::from_link(issuer, index_root_after_issuer)?;
        let terminal = match successor {
            None => None,
            Some(successor) => {
                successor.validate()?;
                let digest =
                    successor.handoff_statement.ok_or(CompactRegistryError::InvalidIssuerWindow)?;
                if successor.wallet != issuer.wallet
                    || successor.parent_epoch != Some(issuer.epoch())
                    || successor.parent_chain_root != issuer.chain_root()?
                    || successor.parent_index_root != index_root_after_issuer
                    || successor.epoch()
                        != issuer.epoch().checked_add(1).ok_or(CompactRegistryError::Overflow)?
                    || successor.start_sequence <= issuer.start_sequence
                    || successor.predecessor_ledger_head != digest
                {
                    return Err(CompactRegistryError::InvalidIssuerWindow);
                }
                Some(IssuerTerminalSeal {
                    sequence: successor
                        .start_sequence
                        .checked_sub(1)
                        .ok_or(CompactRegistryError::InvalidIssuerWindow)?,
                    statement_digest: digest,
                    successor_epoch: successor.epoch(),
                })
            }
        };
        let window = Self { version: VERIFIED_ISSUER_WINDOW_VERSION, issuer: active, terminal };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), CompactRegistryError> {
        if self.version != VERIFIED_ISSUER_WINDOW_VERSION {
            return Err(CompactRegistryError::InvalidIssuerWindow);
        }
        self.issuer.validate()?;
        if let Some(terminal) = self.terminal {
            if terminal.sequence < self.issuer.start_sequence
                || terminal.statement_digest == [0_u8; 32]
                || terminal.successor_epoch
                    != self.issuer.epoch().checked_add(1).ok_or(CompactRegistryError::Overflow)?
            {
                return Err(CompactRegistryError::InvalidIssuerWindow);
            }
        }
        Ok(())
    }

    /// Check a complete issuer binding against this window.  The terminal sequence is sealed to
    /// one exact handoff digest; active windows have no upper bound.
    ///
    /// Requiring the wallet, epoch, committee digest, and activation digest in this API avoids a
    /// caller accidentally applying a valid sequence range to a statement from another issuer.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_statement(
        &self,
        wallet: DepositWalletId,
        issuer_epoch: u64,
        issuer_committee: [u8; 32],
        issuer_activation: [u8; 32],
        sequence: u64,
        statement_digest: [u8; 32],
    ) -> Result<(), CompactRegistryError> {
        self.validate()?;
        if wallet != self.issuer.wallet()
            || issuer_epoch != self.issuer.epoch()
            || issuer_committee != self.issuer.committee().digest()
            || issuer_activation != self.issuer.activation()
            || sequence < self.issuer.start_sequence
            || statement_digest == [0_u8; 32]
        {
            return Err(CompactRegistryError::OutsideIssuerWindow);
        }
        if let Some(terminal) = self.terminal {
            if sequence > terminal.sequence
                || (sequence == terminal.sequence && statement_digest != terminal.statement_digest)
            {
                return Err(CompactRegistryError::OutsideIssuerWindow);
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn issuer(&self) -> &ActiveIssuer {
        &self.issuer
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<IssuerTerminalSeal> {
        self.terminal
    }
}

/// Pinned parent of every new-format compact genesis link.
#[must_use]
pub fn compact_registry_genesis_parent(wallet: DepositWalletId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(GENESIS_PARENT_DOMAIN);
    hasher.update(&COMPACT_REGISTRY_LINK_VERSION.to_le_bytes());
    hasher.update(&wallet.0);
    *hasher.finalize().as_bytes()
}

/// Pinned empty ledger head for the compact registry format.
#[must_use]
pub fn compact_registry_genesis_ledger_head(wallet: DepositWalletId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(GENESIS_LEDGER_HEAD_DOMAIN);
    hasher.update(&COMPACT_HANDOFF_STATEMENT_VERSION.to_le_bytes());
    hasher.update(&wallet.0);
    *hasher.finalize().as_bytes()
}

#[must_use]
pub fn compact_registry_empty_index_root(wallet: DepositWalletId) -> [u8; 32] {
    compact_registry_empty_index_hash_at(wallet, 0)
}

/// Empty subtree hash at `depth`, where depth zero is the root and depth 64 is a leaf slot.
#[must_use]
pub(crate) fn compact_registry_empty_index_hash_at(wallet: DepositWalletId, depth: u8) -> [u8; 32] {
    assert!(depth <= COMPACT_REGISTRY_INDEX_DEPTH, "compact index depth is bounded");
    std::thread_local! {
        // One public wallet's constants per thread; untrusted wallet IDs cannot grow this cache.
        static EMPTY_HASHES: std::cell::RefCell<Option<(DepositWalletId, [[u8; 32]; 65])>> =
            const { std::cell::RefCell::new(None) };
    }
    EMPTY_HASHES.with_borrow_mut(|cached| {
        let (cached_wallet, hashes) =
            cached.get_or_insert_with(|| (wallet, empty_index_hashes(wallet)));
        if *cached_wallet != wallet {
            *cached_wallet = wallet;
            *hashes = empty_index_hashes(wallet);
        }
        hashes[usize::from(depth)]
    })
}

fn empty_index_hashes(wallet: DepositWalletId) -> [[u8; 32]; 65] {
    let mut hashes = [[0; 32]; 65];
    let mut hasher = blake3::Hasher::new_derive_key(INDEX_EMPTY_LEAF_DOMAIN);
    hasher.update(&COMPACT_REGISTRY_INDEX_DEPTH.to_le_bytes());
    hasher.update(&wallet.0);
    let mut hash = *hasher.finalize().as_bytes();
    hashes[usize::from(COMPACT_REGISTRY_INDEX_DEPTH)] = hash;
    for branch_depth in (0..COMPACT_REGISTRY_INDEX_DEPTH).rev() {
        let mut branch = blake3::Hasher::new_derive_key(INDEX_EMPTY_BRANCH_DOMAIN);
        branch.update(&branch_depth.to_le_bytes());
        branch.update(&wallet.0);
        branch.update(&hash);
        branch.update(&hash);
        hash = *branch.finalize().as_bytes();
        hashes[usize::from(branch_depth)] = hash;
    }
    hashes
}

#[must_use]
pub(crate) fn compact_registry_index_leaf_hash(
    wallet: DepositWalletId,
    epoch: u64,
    link_root: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(INDEX_LEAF_DOMAIN);
    hasher.update(&COMPACT_REGISTRY_INDEX_DEPTH.to_le_bytes());
    hasher.update(&wallet.0);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&link_root);
    *hasher.finalize().as_bytes()
}

#[must_use]
pub(crate) fn compact_registry_index_branch_hash(
    wallet: DepositWalletId,
    depth: u8,
    left: [u8; 32],
    right: [u8; 32],
) -> [u8; 32] {
    debug_assert!(depth < COMPACT_REGISTRY_INDEX_DEPTH);
    let mut hasher = blake3::Hasher::new_derive_key(INDEX_BRANCH_DOMAIN);
    hasher.update(&depth.to_le_bytes());
    hasher.update(&wallet.0);
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

fn validate_fault_bound(
    committee: &Committee,
    fault_bound: u16,
) -> Result<(), CompactRegistryError> {
    committee.validate_async_security_with_faults(fault_bound).map_err(|error| match error {
        CommitteeError::InvalidFaultBound => CompactRegistryError::InvalidFaultBound,
        other => CompactRegistryError::Committee(other),
    })
}

#[derive(Debug, Error)]
pub enum CompactRegistryError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("deposit state export error: {0}")]
    StateExport(#[from] DepositStateExportError),
    #[error("registry id is malformed")]
    InvalidRegistryId,
    #[error("registry link is malformed")]
    InvalidLink,
    #[error("compact registry is malformed")]
    InvalidRegistry,
    #[error("active issuer is malformed")]
    InvalidActiveIssuer,
    #[error("genesis link is malformed")]
    InvalidGenesis,
    #[error("committee is not in canonical party order")]
    NonCanonicalCommittee,
    #[error("committee/fault bound does not satisfy asynchronous security")]
    InvalidFaultBound,
    #[error("handoff statement is malformed or not bound to the exact source roots")]
    InvalidHandoffStatement,
    #[error("handoff certificate is malformed")]
    InvalidHandoffCertificate,
    #[error("handoff certificate serialization failed")]
    Serialization,
    #[error("handoff certificate exceeds its allocation bound")]
    HandoffCertificateTooLarge,
    #[error("handoff certificate encoding has trailing bytes")]
    TrailingBytes,
    #[error("handoff certificate encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("handoff target does not match the supplied target activation")]
    WrongHandoffTarget,
    #[error("compact registry is not bound to the supplied certified activation authority")]
    WrongActivationAuthority,
    #[error("handoff witness signer appears more than once")]
    DuplicateWitness,
    #[error("handoff has {actual} witnesses; exactly {required} are required")]
    WrongWitnessCount { actual: usize, required: usize },
    #[error("issuer window is malformed")]
    InvalidIssuerWindow,
    #[error("statement is outside the authenticated issuer window")]
    OutsideIssuerWindow,
    #[error("integer overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    #[test]
    fn cached_empty_hashes_match_the_wire_hashes_across_wallet_changes() {
        use super::*;
        for wallet in [DepositWalletId([1; 32]), DepositWalletId([2; 32]), DepositWalletId([1; 32])]
        {
            for depth in 0..=COMPACT_REGISTRY_INDEX_DEPTH {
                let mut leaf = blake3::Hasher::new_derive_key(INDEX_EMPTY_LEAF_DOMAIN);
                leaf.update(&COMPACT_REGISTRY_INDEX_DEPTH.to_le_bytes());
                leaf.update(&wallet.0);
                let mut expected = *leaf.finalize().as_bytes();
                for branch_depth in (depth..COMPACT_REGISTRY_INDEX_DEPTH).rev() {
                    let mut branch = blake3::Hasher::new_derive_key(INDEX_EMPTY_BRANCH_DOMAIN);
                    branch.update(&branch_depth.to_le_bytes());
                    branch.update(&wallet.0);
                    branch.update(&expected);
                    branch.update(&expected);
                    expected = *branch.finalize().as_bytes();
                }
                assert_eq!(compact_registry_empty_index_hash_at(wallet, depth), expected);
                assert_eq!(compact_registry_empty_index_hash_at(wallet, depth), expected);
            }
        }
    }

    use super::*;
    use crate::{
        committee::{Member, PartyId},
        deposit_index::{DEPOSIT_INDEX_ARTIFACT_KIND, DepositIndexHead, DepositIndexObjectId},
        deposit_index_checkpoint::PortableDepositIndexHead,
        identity::Identity,
        storage::{WalletArtifactRef, WalletId},
    };

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

    fn genesis(
        wallet: DepositWalletId,
        committee: Committee,
    ) -> (RegistryLink, CompactEpochRegistry) {
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            [7_u8; 32],
            [17_u8; 32],
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap();
        let link =
            RegistryLink::genesis(&target, DepositSubaddressIndex::new(0, 1).unwrap(), [6_u8; 32])
                .unwrap();
        let registry = CompactEpochRegistry::from_link(&link, [9_u8; 32]).unwrap();
        (link, registry)
    }

    fn target(
        wallet: DepositWalletId,
        committee: Committee,
        activation: [u8; 32],
    ) -> VerifiedRegistryHandoffTarget {
        VerifiedRegistryHandoffTarget::for_test(
            committee,
            1,
            activation,
            [18_u8; 32],
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap()
    }

    fn statement(
        source: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> RegistryHandoffStatement {
        let next_index = DepositSubaddressIndex::new(0, 9).unwrap();
        let source_state = handoff_source_state(source.wallet(), next_index);
        RegistryHandoffStatement::new(source, 10, [11_u8; 32], source_state, target, next_index)
            .unwrap()
    }

    fn handoff_source_state(
        wallet: DepositWalletId,
        next_index: DepositSubaddressIndex,
    ) -> DepositHandoffStateBinding {
        let reference = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            DEPOSIT_INDEX_ARTIFACT_KIND,
            b"compact-registry-handoff-test-root",
        )
        .unwrap();
        let portable = DepositIndexHead::from_portable_components(
            wallet,
            1,
            1,
            Some(DepositIndexObjectId::from_storage_reference(reference).unwrap()),
            9,
            [11_u8; 32],
            next_index,
        )
        .unwrap();
        DepositHandoffStateBinding::new(
            Some([13_u8; 32]),
            PortableDepositIndexHead::from_head(&portable).unwrap(),
        )
        .unwrap()
    }

    fn certificate(
        statement: RegistryHandoffStatement,
        source_committee: &Committee,
        identities: &[Identity],
        parties: &[usize],
    ) -> RegistryHandoffCertificate {
        let witnesses = parties
            .iter()
            .map(|index| {
                identities[*index]
                    .sign_envelope(
                        source_committee,
                        statement.session(),
                        None,
                        statement.terminal_sequence(),
                        statement.signing_payload(),
                    )
                    .unwrap()
            })
            .collect();
        RegistryHandoffCertificate::new(statement, witnesses).unwrap()
    }

    #[test]
    fn divergent_quorum_witness_subsets_have_identical_semantic_roots() {
        let wallet = DepositWalletId([1_u8; 32]);
        let source_identities = identities(0);
        let source_committee = committee(0, &source_identities);
        let (_, source) = genesis(wallet, source_committee.clone());
        let target_identities = identities(1);
        let target = target(wallet, committee(1, &target_identities), [12_u8; 32]);
        let statement = statement(&source, &target);
        let left =
            certificate(statement.clone(), &source_committee, &source_identities, &[0, 1, 2]);
        let right = certificate(statement, &source_committee, &source_identities, &[0, 1, 3]);
        left.verify(&source).unwrap();
        right.verify(&source).unwrap();
        assert_ne!(left.witnesses(), right.witnesses());

        let left_link = RegistryLink::successor(&source, &target, &left).unwrap();
        let right_link = RegistryLink::successor(&source, &target, &right).unwrap();
        assert_eq!(left_link, right_link);
        assert_eq!(left_link.chain_root().unwrap(), right_link.chain_root().unwrap());
    }

    #[test]
    fn root_bound_statement_rejects_fork_and_wallet_transplants() {
        let source_identities = identities(0);
        let source_committee = committee(0, &source_identities);
        let (source_link, source) = genesis(DepositWalletId([1_u8; 32]), source_committee.clone());
        let (_, other_wallet) = genesis(DepositWalletId([2_u8; 32]), source_committee.clone());
        let index_fork = CompactEpochRegistry::from_link(&source_link, [8_u8; 32]).unwrap();
        let fork_target = VerifiedRegistryHandoffTarget::for_test(
            source_committee.clone(),
            1,
            [99_u8; 32],
            [17_u8; 32],
            DepositWalletId([1_u8; 32]),
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap();
        let fork_link = RegistryLink::genesis(
            &fork_target,
            DepositSubaddressIndex::new(0, 1).unwrap(),
            [6_u8; 32],
        )
        .unwrap();
        let fork = CompactEpochRegistry::from_link(&fork_link, [9_u8; 32]).unwrap();
        let target = target(DepositWalletId([1_u8; 32]), committee(1, &identities(1)), [12_u8; 32]);
        let handoff = statement(&source, &target);
        let certificate = certificate(handoff, &source_committee, &source_identities, &[0, 1, 2]);

        assert!(certificate.verify(&other_wallet).is_err());
        assert!(certificate.verify(&index_fork).is_err());
        assert!(certificate.verify(&fork).is_err());
        assert!(RegistryLink::successor(&source, &target, &certificate).is_ok());
        for invalid_source in [&other_wallet, &index_fork, &fork] {
            assert!(RegistryLink::successor(invalid_source, &target, &certificate).is_err());
        }
        let mut invalid_signature = certificate.clone();
        invalid_signature.witnesses[0].signature[0] ^= 1;
        assert!(RegistryLink::successor(&source, &target, &invalid_signature).is_err());
        let mut missing_witness = certificate;
        missing_witness.witnesses.pop();
        assert!(RegistryLink::successor(&source, &target, &missing_witness).is_err());
    }

    #[test]
    fn handoff_rejects_terminal_ledger_sequence_before_signing() {
        let source_identities = identities(0);
        let source_committee = committee(0, &source_identities);
        let (_, source) = genesis(DepositWalletId([1_u8; 32]), source_committee);
        let target = target(DepositWalletId([1_u8; 32]), committee(1, &identities(1)), [12_u8; 32]);
        let next_index = DepositSubaddressIndex::new(0, 9).unwrap();
        let source_state = handoff_source_state(source.wallet(), next_index);

        assert!(matches!(
            RegistryHandoffStatement::new(
                &source,
                u64::MAX,
                [11_u8; 32],
                source_state,
                &target,
                next_index,
            ),
            Err(CompactRegistryError::Overflow)
        ));
    }

    #[test]
    fn terminal_window_seals_exact_handoff_digest() {
        let wallet = DepositWalletId([1_u8; 32]);
        let source_identities = identities(0);
        let source_committee = committee(0, &source_identities);
        let (source_link, source) = genesis(wallet, source_committee.clone());
        let target = target(wallet, committee(1, &identities(1)), [12_u8; 32]);
        let statement = statement(&source, &target);
        let certificate =
            certificate(statement.clone(), &source_committee, &source_identities, &[0, 1, 2]);
        let successor = RegistryLink::successor(&source, &target, &certificate).unwrap();
        let window = VerifiedIssuerWindow::from_links(
            &source_link,
            source.id().index_root(),
            Some(&successor),
        )
        .unwrap();
        let seal = window.terminal().unwrap();
        assert_eq!(seal.sequence, statement.terminal_sequence());
        window
            .authorize_statement(
                wallet,
                source_link.epoch(),
                source_link.committee().digest(),
                source_link.activation(),
                seal.sequence,
                statement.digest(),
            )
            .unwrap();
        assert!(
            window
                .authorize_statement(
                    wallet,
                    source_link.epoch(),
                    source_link.committee().digest(),
                    source_link.activation(),
                    seal.sequence,
                    [33_u8; 32],
                )
                .is_err()
        );
        assert!(
            window
                .authorize_statement(
                    wallet,
                    source_link.epoch(),
                    source_link.committee().digest(),
                    source_link.activation(),
                    seal.sequence + 1,
                    statement.digest(),
                )
                .is_err()
        );
    }

    #[test]
    fn certified_activation_root_is_part_of_genesis_and_handoff_authority() {
        let wallet = DepositWalletId([1_u8; 32]);
        let source_identities = identities(0);
        let source_committee = committee(0, &source_identities);
        let source_a = VerifiedRegistryHandoffTarget::for_test(
            source_committee.clone(),
            1,
            [7_u8; 32],
            [17_u8; 32],
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap();
        let source_b = VerifiedRegistryHandoffTarget::for_test(
            source_committee.clone(),
            1,
            [7_u8; 32],
            [18_u8; 32],
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap();
        let link_a = RegistryLink::genesis(
            &source_a,
            DepositSubaddressIndex::new(0, 1).unwrap(),
            [6_u8; 32],
        )
        .unwrap();
        let link_b = RegistryLink::genesis(
            &source_b,
            DepositSubaddressIndex::new(0, 1).unwrap(),
            [6_u8; 32],
        )
        .unwrap();
        assert_ne!(link_a.chain_root().unwrap(), link_b.chain_root().unwrap());
        let source = CompactEpochRegistry::from_link(&link_a, [9_u8; 32]).unwrap();
        source.verify_active_target(&source_a).unwrap();
        assert!(matches!(
            source.verify_active_target(&source_b),
            Err(CompactRegistryError::WrongActivationAuthority)
        ));

        let target_committee = committee(1, &identities(1));
        let target_a = VerifiedRegistryHandoffTarget::for_test(
            target_committee.clone(),
            1,
            [12_u8; 32],
            [28_u8; 32],
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap();
        let target_b = VerifiedRegistryHandoffTarget::for_test(
            target_committee,
            1,
            [12_u8; 32],
            [29_u8; 32],
            wallet,
            [27_u8; 32],
            [37_u8; 32],
        )
        .unwrap();
        let statement = statement(&source, &target_a);
        let certificate = certificate(statement, &source_committee, &source_identities, &[0, 1, 2]);
        assert!(RegistryLink::successor(&source, &target_a, &certificate).is_ok());
        assert!(matches!(
            RegistryLink::successor(&source, &target_b, &certificate),
            Err(CompactRegistryError::WrongHandoffTarget)
        ));
    }

    #[test]
    fn empty_root_and_semantic_hashes_are_wallet_and_position_bound() {
        let wallet = DepositWalletId([1_u8; 32]);
        let other = DepositWalletId([2_u8; 32]);
        assert_ne!(
            compact_registry_empty_index_root(wallet),
            compact_registry_empty_index_root(other)
        );
        assert_ne!(
            compact_registry_index_leaf_hash(wallet, 1, [3_u8; 32]),
            compact_registry_index_leaf_hash(wallet, 2, [3_u8; 32])
        );
        assert_ne!(
            compact_registry_index_branch_hash(wallet, 0, [4_u8; 32], [5_u8; 32]),
            compact_registry_index_branch_hash(wallet, 1, [4_u8; 32], [5_u8; 32])
        );
    }
}
