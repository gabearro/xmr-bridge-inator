//! Target-quorum availability certificates for a completed deposit-state import.
//!
//! A post-handoff export seal is source-specific: honest predecessor members can retain different
//! archive artifacts for the same terminal checkpoint. Target acknowledgements therefore sign
//! only the common semantic transition. The non-serializable completion capability used to create
//! an acknowledgement still authenticates one exact local seal variant and its reopened state.
//! This prevents Byzantine sources from fragmenting an `n-f` target quorum across equivalent
//! witness variants.
//!
//! A verified certificate authorizes target deposit readiness and reclamation of predecessor
//! export pins for this transition. It never authorizes threshold-share or X25519 retirement,
//! requester-lease cleanup, spool admission, or any other key-lifecycle transition.

use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, Member, PartyId, SessionId},
    compact_epoch_registry::{
        CompactEpochRegistry, CompactRegistryError, RegistryHandoffCertificate, RegistryId,
        RegistryLink,
    },
    deposit_index::DepositIndexObjectId,
    deposit_index_checkpoint::PortableDepositIndexHead,
    deposit_service::AuthenticatedReopenedCertifiedExport,
    deposit_state_export::{
        DepositStateExportBinding, DepositStateExportError,
        VerifiedDepositPostHandoffExportCandidate, VerifiedDepositPostHandoffExportSeal,
        VerifiedPreImportDepositStateExportSeal, post_handoff_export_semantic_transition_digest,
    },
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
    identity::{Identity, IdentityError, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
};

pub const DEPOSIT_STATE_IMPORTED_VERSION: u16 = 1;
pub const MAX_DEPOSIT_STATE_IMPORTED_STATEMENT_BYTES: usize = 32 * 1024;
pub const MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES: usize = 8 * 1024;
pub const MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES: usize = 256 * 1024;

const STATE_IMPORTED_STATEMENT_DOMAIN: [u8; 16] = *b"tm-import-stmt01";
const STATE_IMPORTED_ACK_DOMAIN: [u8; 16] = *b"tm-import-ack001";
const STATE_IMPORTED_CERTIFICATE_DOMAIN: [u8; 16] = *b"tm-import-cert01";
const STATE_IMPORTED_STATEMENT_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-imported-statement/v1";
const STATE_IMPORTED_CERTIFIED_TRANSITION_DOMAIN: &str =
    "threshold-monero/deposit-state-imported-certified-transition-binding/v1";
const STATE_IMPORTED_ACK_SESSION_DOMAIN: &[u8] = b"threshold-monero/deposit-state-imported-ack/v1";
const STATE_IMPORTED_CERTIFICATE_DIGEST_DOMAIN: &str =
    "threshold-monero/deposit-state-imported-certificate/v1";

/// Common target-quorum statement for one semantic post-handoff state.
///
/// Source party IDs, archive event/segment references, and exact old-quorum witness subsets are
/// intentionally absent. Those fields identify interchangeable availability variants and signing
/// them here could prevent honest target members from combining their acknowledgements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DepositStateImportedStatement {
    version: u16,
    domain: [u8; 16],
    network: [u8; 32],
    wallet: DepositWalletId,
    semantic_transition: [u8; 32],
    source_registry: RegistryId,
    source_epoch: u64,
    source_committee: [u8; 32],
    source_fault_bound: u16,
    source_key_id: [u8; 32],
    source_group_key: [u8; 32],
    source_activation: [u8; 32],
    source_certified_activation_root: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_export_context: [u8; 32],
    handoff_terminal_sequence: u64,
    handoff_next_index: DepositSubaddressIndex,
    target_registry: RegistryId,
    target_epoch: u64,
    target_committee: Committee,
    target_fault_bound: u16,
    target_key_id: [u8; 32],
    target_group_key: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    terminal_checkpoint_sequence: u64,
    terminal_checkpoint_decision: [u8; 32],
    portable_head: PortableDepositIndexHead,
}

#[derive(Deserialize)]
struct BoundedCommittee {
    epoch: u64,
    threshold: u16,
    #[serde(deserialize_with = "deserialize_members")]
    members: Vec<Member>,
}

impl From<BoundedCommittee> for Committee {
    fn from(value: BoundedCommittee) -> Self {
        Self { epoch: value.epoch, threshold: value.threshold, members: value.members }
    }
}

#[derive(Deserialize)]
struct DepositStateImportedStatementRepr {
    version: u16,
    domain: [u8; 16],
    network: [u8; 32],
    wallet: DepositWalletId,
    semantic_transition: [u8; 32],
    source_registry: RegistryId,
    source_epoch: u64,
    source_committee: [u8; 32],
    source_fault_bound: u16,
    source_key_id: [u8; 32],
    source_group_key: [u8; 32],
    source_activation: [u8; 32],
    source_certified_activation_root: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_export_context: [u8; 32],
    handoff_terminal_sequence: u64,
    handoff_next_index: DepositSubaddressIndex,
    target_registry: RegistryId,
    target_epoch: u64,
    target_committee: BoundedCommittee,
    target_fault_bound: u16,
    target_key_id: [u8; 32],
    target_group_key: [u8; 32],
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    terminal_checkpoint_sequence: u64,
    terminal_checkpoint_decision: [u8; 32],
    portable_head: PortableDepositIndexHead,
}

impl<'de> Deserialize<'de> for DepositStateImportedStatement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = DepositStateImportedStatementRepr::deserialize(deserializer)?;
        Ok(Self {
            version: value.version,
            domain: value.domain,
            network: value.network,
            wallet: value.wallet,
            semantic_transition: value.semantic_transition,
            source_registry: value.source_registry,
            source_epoch: value.source_epoch,
            source_committee: value.source_committee,
            source_fault_bound: value.source_fault_bound,
            source_key_id: value.source_key_id,
            source_group_key: value.source_group_key,
            source_activation: value.source_activation,
            source_certified_activation_root: value.source_certified_activation_root,
            handoff_statement: value.handoff_statement,
            handoff_export_context: value.handoff_export_context,
            handoff_terminal_sequence: value.handoff_terminal_sequence,
            handoff_next_index: value.handoff_next_index,
            target_registry: value.target_registry,
            target_epoch: value.target_epoch,
            target_committee: value.target_committee.into(),
            target_fault_bound: value.target_fault_bound,
            target_key_id: value.target_key_id,
            target_group_key: value.target_group_key,
            target_activation: value.target_activation,
            target_certified_activation_root: value.target_certified_activation_root,
            terminal_checkpoint_sequence: value.terminal_checkpoint_sequence,
            terminal_checkpoint_decision: value.terminal_checkpoint_decision,
            portable_head: value.portable_head,
        })
    }
}

impl DepositStateImportedStatement {
    /// Construct the one common target statement from an old-quorum-authenticated exact export.
    ///
    /// Different predecessor sources may provide different exact seal certificates and archive
    /// references. Every such seal must nevertheless project to this same semantic statement.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_export_seal(
        network: [u8; 32],
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<Self, DepositStateImportError> {
        seal.validate_target(target)?;
        let sealed = seal.statement();
        let transition = handoff.statement();
        let final_export = sealed.final_export();
        if sealed.network() != network
            || sealed.source() != source.id()
            || sealed.handoff_statement_digest() != transition.digest()
            || sealed.handoff_certificate_digest() != handoff.digest()?
            || sealed.export_capability_context() != transition.export_capability_context()
            || sealed.target_epoch() != target.committee().epoch
            || sealed.target_committee() != target.committee().digest()
            || sealed.target_activation() != target.activation()
            || sealed.target_certified_activation_root() != target.certified_activation_root()
            || final_export.archive().wallet_id() != source.wallet()
            || final_export.resulting_portable_head().wallet_id() != source.wallet()
        {
            return Err(DepositStateImportError::WrongExportSeal);
        }
        let statement = Self::from_final_export(network, source, handoff, target, final_export)?;
        if sealed.semantic_transition_digest() != statement.semantic_transition {
            return Err(DepositStateImportError::WrongExportSeal);
        }
        Ok(statement)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_final_export(
        network: [u8; 32],
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        final_export: &DepositStateExportBinding,
    ) -> Result<Self, DepositStateImportError> {
        final_export.validate()?;
        let terminal = final_export.terminal_checkpoint();
        let target_registry = final_export.target_registry_archive().registry();
        Self::from_semantic_parts(
            network,
            source,
            handoff,
            target_registry,
            target,
            terminal.sequence(),
            terminal.decision(),
            final_export.resulting_portable_head().clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_semantic_parts(
        network: [u8; 32],
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
        terminal_checkpoint_sequence: u64,
        terminal_checkpoint_decision: [u8; 32],
        portable_head: PortableDepositIndexHead,
    ) -> Result<Self, DepositStateImportError> {
        source.validate()?;
        handoff.verify(source)?;
        target_registry.verify_active_target(target)?;
        let handoff_statement = handoff.statement();
        let target_committee = target.committee().clone().canonicalized()?;
        let mut statement = Self {
            version: DEPOSIT_STATE_IMPORTED_VERSION,
            domain: STATE_IMPORTED_STATEMENT_DOMAIN,
            network,
            wallet: source.wallet(),
            semantic_transition: [0; 32],
            source_registry: source.id(),
            source_epoch: source.active_epoch(),
            source_committee: source.active().committee().digest(),
            source_fault_bound: source.active().fault_bound(),
            source_key_id: source.active().key_id(),
            source_group_key: source.active().group_key(),
            source_activation: source.active().activation(),
            source_certified_activation_root: source.active().certified_activation_root(),
            handoff_statement: handoff_statement.digest(),
            handoff_export_context: handoff_statement.export_capability_context(),
            handoff_terminal_sequence: handoff_statement.terminal_sequence(),
            handoff_next_index: handoff_statement.next_index(),
            target_registry: target_registry.id(),
            target_epoch: target.committee().epoch,
            target_committee,
            target_fault_bound: target.fault_bound(),
            target_key_id: target.key_id(),
            target_group_key: target.group_key(),
            target_activation: target.activation(),
            target_certified_activation_root: target.certified_activation_root(),
            terminal_checkpoint_sequence,
            terminal_checkpoint_decision,
            portable_head,
        };
        statement.semantic_transition = statement.expected_semantic_transition()?;
        statement.validate_against(source, handoff, target_registry, target)?;
        Ok(statement)
    }

    fn expected_semantic_transition(&self) -> Result<[u8; 32], DepositStateImportError> {
        Ok(post_handoff_export_semantic_transition_digest(
            self.network,
            self.source_registry,
            self.source_certified_activation_root,
            self.handoff_statement,
            self.handoff_export_context,
            self.target_registry,
            self.terminal_checkpoint_decision,
            &self.portable_head,
        )?)
    }

    fn validate_static(&self) -> Result<(), DepositStateImportError> {
        self.target_committee.validate_async_security_with_faults(self.target_fault_bound)?;
        if self.target_committee.clone().canonicalized()? != self.target_committee {
            return Err(DepositStateImportError::NonCanonicalTargetCommittee);
        }
        self.portable_head
            .maximum_reachable_objects()
            .map_err(|_| DepositStateImportError::InvalidPortableHead)?;
        self.source_registry.validate()?;
        self.target_registry.validate()?;
        let Some(root) = self.portable_head.root() else {
            return Err(DepositStateImportError::InvalidPortableHead);
        };
        if self.version != DEPOSIT_STATE_IMPORTED_VERSION
            || self.domain != STATE_IMPORTED_STATEMENT_DOMAIN
            || self.network == [0; 32]
            || self.wallet.0 == [0; 32]
            || self.source_registry.wallet() != self.wallet
            || self.source_registry.active_epoch() != self.source_epoch
            || self.target_registry.wallet() != self.wallet
            || self.target_registry.active_epoch() != self.target_epoch
            || self.semantic_transition == [0; 32]
            || self.semantic_transition != self.expected_semantic_transition()?
            || self.source_committee == [0; 32]
            || self.source_key_id == [0; 32]
            || self.source_group_key == [0; 32]
            || self.source_activation == [0; 32]
            || self.source_certified_activation_root == [0; 32]
            || self.handoff_statement == [0; 32]
            || self.handoff_export_context == [0; 32]
            || self.handoff_terminal_sequence == 0
            || self.target_epoch
                != self
                    .source_epoch
                    .checked_add(1)
                    .ok_or(DepositStateImportError::InvalidStatement)?
            || self.target_committee.epoch != self.target_epoch
            || self.target_key_id == [0; 32]
            || self.target_group_key == [0; 32]
            || self.target_activation == [0; 32]
            || self.target_certified_activation_root == [0; 32]
            || self.terminal_checkpoint_sequence == 0
            || self.terminal_checkpoint_sequence < self.handoff_terminal_sequence
            || self.terminal_checkpoint_decision == [0; 32]
            || self.portable_head.wallet_id() != self.wallet
            || root.wallet_id() != self.wallet
            || self.portable_head.through_sequence() != self.handoff_terminal_sequence
            || self.portable_head.ledger_head() != self.handoff_statement
            || self.portable_head.next_index() != self.handoff_next_index
        {
            return Err(DepositStateImportError::InvalidStatement);
        }
        Ok(())
    }

    fn validate_against(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateImportError> {
        self.validate_static()?;
        source.validate()?;
        handoff.verify(source)?;
        target_registry.verify_active_target(target)?;
        let handoff_statement = handoff.statement();
        if self.wallet != source.wallet()
            || self.source_registry != source.id()
            || self.source_epoch != source.active_epoch()
            || self.source_committee != source.active().committee().digest()
            || self.source_fault_bound != source.active().fault_bound()
            || self.source_key_id != source.active().key_id()
            || self.source_group_key != source.active().group_key()
            || self.source_activation != source.active().activation()
            || self.source_certified_activation_root != source.active().certified_activation_root()
            || self.handoff_statement != handoff_statement.digest()
            || self.handoff_export_context != handoff_statement.export_capability_context()
            || self.handoff_terminal_sequence != handoff_statement.terminal_sequence()
            || self.handoff_next_index != handoff_statement.next_index()
            || self.target_registry != target_registry.id()
            || self.target_epoch != target.committee().epoch
            || self.target_committee != *target.committee()
            || self.target_fault_bound != target.fault_bound()
            || self.target_key_id != target.key_id()
            || self.target_group_key != target.group_key()
            || self.target_activation != target.activation()
            || self.target_certified_activation_root != target.certified_activation_root()
        {
            return Err(DepositStateImportError::WrongTransition);
        }
        let successor = RegistryLink::successor(source, target, handoff)?;
        let expected =
            CompactEpochRegistry::from_link(&successor, target_registry.id().index_root())?;
        if expected != *target_registry {
            return Err(DepositStateImportError::WrongTransition);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateImportError> {
        self.validate_static()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_STATEMENT_BYTES,
            "deposit state imported statement",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositStateImportError> {
        let statement: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_STATEMENT_BYTES,
            "deposit state imported statement",
        )?;
        statement.validate_static()?;
        Ok(statement)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            self.to_bytes().expect("validated state-imported statement serializes canonically");
        length_prefixed_hash(STATE_IMPORTED_STATEMENT_DIGEST_DOMAIN, &bytes)
    }

    #[must_use]
    pub fn transition_binding(&self) -> [u8; 32] {
        certified_transition_binding(self.network, self.wallet, self.semantic_transition)
    }

    #[must_use]
    pub fn session(&self) -> SessionId {
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(&self.handoff_statement);
        material.extend_from_slice(&self.handoff_export_context);
        material.extend_from_slice(&self.transition_binding());
        SessionId::derive(STATE_IMPORTED_ACK_SESSION_DOMAIN, &material)
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn handoff_statement_digest(&self) -> [u8; 32] {
        self.handoff_statement
    }

    #[must_use]
    pub const fn handoff_export_context(&self) -> [u8; 32] {
        self.handoff_export_context
    }

    #[must_use]
    pub fn target_registry_digest(&self) -> [u8; 32] {
        self.target_registry.digest()
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub const fn target_committee(&self) -> &Committee {
        &self.target_committee
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
    pub const fn terminal_checkpoint_sequence(&self) -> u64 {
        self.terminal_checkpoint_sequence
    }

    #[must_use]
    pub const fn terminal_checkpoint_decision(&self) -> [u8; 32] {
        self.terminal_checkpoint_decision
    }

    #[must_use]
    pub const fn portable_head(&self) -> &PortableDepositIndexHead {
        &self.portable_head
    }
}

/// Non-serializable transition key available before a predecessor emits its first export-seal
/// signature.
///
/// Source retention uses this capability to pin the exact candidate's reachable graph before any
/// signature can escape. The later exact seal certificate upgrades the same transition; it does
/// not choose a different retention key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedStateImportCandidateTransitionBinding {
    network: [u8; 32],
    wallet: DepositWalletId,
    source_party: PartyId,
    semantic_transition: [u8; 32],
    transition: [u8; 32],
}

impl VerifiedStateImportCandidateTransitionBinding {
    pub fn from_verified_export_candidate(
        candidate: &VerifiedDepositPostHandoffExportCandidate,
    ) -> Result<Self, DepositStateImportError> {
        let statement = candidate.statement();
        let network = statement.network();
        let wallet = statement.source().wallet();
        let semantic_transition = statement.semantic_transition_digest();
        let transition = certified_transition_binding(network, wallet, semantic_transition);
        if network == [0; 32]
            || wallet.0 == [0; 32]
            || statement.source_party() == PartyId(0)
            || semantic_transition == [0; 32]
            || transition == [0; 32]
        {
            return Err(DepositStateImportError::WrongExportSeal);
        }
        Ok(Self {
            network,
            wallet,
            source_party: statement.source_party(),
            semantic_transition,
            transition,
        })
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn source_party(&self) -> PartyId {
        self.source_party
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn transition_binding(&self) -> [u8; 32] {
        self.transition
    }
}

/// Non-serializable bridge from one exact predecessor export to the future common target
/// certificate.
///
/// A retention store can pin the exact `source_party`/seal certificate under
/// [`Self::transition_binding`]. Target acknowledgement certificates expose the same binding even
/// when their honest signers imported different exact source variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedStateImportTransitionBinding {
    network: [u8; 32],
    wallet: DepositWalletId,
    source_party: PartyId,
    exact_seal_statement: [u8; 32],
    exact_seal_certificate: [u8; 32],
    semantic_transition: [u8; 32],
    transition: [u8; 32],
}

impl VerifiedStateImportTransitionBinding {
    pub fn from_verified_export_seal(
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<Self, DepositStateImportError> {
        Self::from_verified_export_seal_parts(
            seal.statement(),
            seal.statement_digest(),
            seal.certificate_digest(),
        )
    }

    /// Project the exact transition binding needed for bounded pre-import reads.
    ///
    /// This does not upgrade the cold-target token into import, registry-CAS, readiness, or
    /// `StateImported` authority.
    pub(crate) fn from_verified_pre_import_export_seal(
        seal: &VerifiedPreImportDepositStateExportSeal,
    ) -> Result<Self, DepositStateImportError> {
        Self::from_verified_export_seal_parts(
            seal.statement(),
            seal.statement_digest(),
            seal.certificate_digest(),
        )
    }

    fn from_verified_export_seal_parts(
        statement: &crate::deposit_state_export::DepositPostHandoffExportSealStatement,
        exact_seal_statement: [u8; 32],
        exact_seal_certificate: [u8; 32],
    ) -> Result<Self, DepositStateImportError> {
        let network = statement.network();
        let wallet = statement.source().wallet();
        let semantic_transition = statement.semantic_transition_digest();
        let transition = certified_transition_binding(network, wallet, semantic_transition);
        if network == [0; 32]
            || wallet.0 == [0; 32]
            || statement.source_party() == PartyId(0)
            || exact_seal_statement == [0; 32]
            || exact_seal_certificate == [0; 32]
            || semantic_transition == [0; 32]
            || transition == [0; 32]
        {
            return Err(DepositStateImportError::WrongExportSeal);
        }
        Ok(Self {
            network,
            wallet,
            source_party: statement.source_party(),
            exact_seal_statement,
            exact_seal_certificate,
            semantic_transition,
            transition,
        })
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn source_party(&self) -> PartyId {
        self.source_party
    }

    #[must_use]
    pub const fn exact_seal_statement_digest(&self) -> [u8; 32] {
        self.exact_seal_statement
    }

    #[must_use]
    pub const fn exact_seal_certificate_digest(&self) -> [u8; 32] {
        self.exact_seal_certificate
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn transition_binding(&self) -> [u8; 32] {
        self.transition
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositStateImportedAckBody {
    version: u16,
    domain: [u8; 16],
    statement: [u8; 32],
    transition: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_export_context: [u8; 32],
    terminal_checkpoint_sequence: u64,
    terminal_checkpoint_decision: [u8; 32],
    portable_head: [u8; 32],
}

impl DepositStateImportedAckBody {
    fn for_statement(statement: &DepositStateImportedStatement) -> Self {
        Self {
            version: DEPOSIT_STATE_IMPORTED_VERSION,
            domain: STATE_IMPORTED_ACK_DOMAIN,
            statement: statement.digest(),
            transition: statement.transition_binding(),
            handoff_statement: statement.handoff_statement,
            handoff_export_context: statement.handoff_export_context,
            terminal_checkpoint_sequence: statement.terminal_checkpoint_sequence,
            terminal_checkpoint_decision: statement.terminal_checkpoint_decision,
            portable_head: statement.portable_head.digest(),
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>, DepositStateImportError> {
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES,
            "deposit state imported acknowledgement body",
        )
    }
}

/// One stable-identity target-member acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateImportedAck {
    version: u16,
    domain: [u8; 16],
    envelope: SignedEnvelope,
}

impl DepositStateImportedAck {
    /// Sign only after the exact imported variant has survived durable readback.
    pub fn sign(
        completed: &VerifiedDepositStateImport,
        signer: &Identity,
    ) -> Result<Self, DepositStateImportError> {
        let statement = &completed.statement;
        let member = statement.target_committee.member(signer.party())?;
        if member.signing_key != signer.signing_public_key() {
            return Err(DepositStateImportError::WrongSigner);
        }
        let envelope = signer.sign_envelope(
            &statement.target_committee,
            statement.session(),
            None,
            statement.terminal_checkpoint_sequence,
            DepositStateImportedAckBody::for_statement(statement).to_bytes()?,
        )?;
        let ack = Self {
            version: DEPOSIT_STATE_IMPORTED_VERSION,
            domain: STATE_IMPORTED_ACK_DOMAIN,
            envelope,
        };
        ack.verify(statement)?;
        Ok(ack)
    }

    fn validate_shape(
        &self,
        statement: &DepositStateImportedStatement,
    ) -> Result<(), DepositStateImportError> {
        let expected = DepositStateImportedAckBody::for_statement(statement).to_bytes()?;
        if self.version != DEPOSIT_STATE_IMPORTED_VERSION
            || self.domain != STATE_IMPORTED_ACK_DOMAIN
            || self.envelope.to.is_some()
            || self.envelope.session != statement.session()
            || self.envelope.sequence != statement.terminal_checkpoint_sequence
            || self.envelope.payload != expected
        {
            return Err(DepositStateImportError::InvalidAck);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        statement: &DepositStateImportedStatement,
    ) -> Result<PartyId, DepositStateImportError> {
        statement.validate_static()?;
        self.validate_shape(statement)?;
        let verifier = statement
            .target_committee
            .members
            .first()
            .ok_or(DepositStateImportError::InvalidAck)?
            .id;
        Identity::verify_envelope(&statement.target_committee, verifier, &self.envelope)?;
        Ok(self.envelope.from)
    }

    pub fn to_bytes(
        &self,
        statement: &DepositStateImportedStatement,
    ) -> Result<Vec<u8>, DepositStateImportError> {
        self.verify(statement)?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES,
            "deposit state imported acknowledgement",
        )
    }

    pub fn from_bytes(
        statement: &DepositStateImportedStatement,
        bytes: &[u8],
    ) -> Result<Self, DepositStateImportError> {
        let ack: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_ACK_BYTES,
            "deposit state imported acknowledgement",
        )?;
        ack.verify(statement)?;
        Ok(ack)
    }

    #[must_use]
    pub const fn signer(&self) -> PartyId {
        self.envelope.from
    }
}

/// Exactly `n-f` distinct target acknowledgements in increasing stable-party order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateImportedCertificate {
    version: u16,
    domain: [u8; 16],
    statement: DepositStateImportedStatement,
    #[serde(deserialize_with = "deserialize_acks")]
    acknowledgements: Vec<DepositStateImportedAck>,
}

impl DepositStateImportedCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        statement: DepositStateImportedStatement,
        mut acknowledgements: Vec<DepositStateImportedAck>,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Self, DepositStateImportError> {
        statement.validate_against(source, handoff, target_registry, target)?;
        acknowledgements.sort_by_key(DepositStateImportedAck::signer);
        let certificate = Self {
            version: DEPOSIT_STATE_IMPORTED_VERSION,
            domain: STATE_IMPORTED_CERTIFICATE_DOMAIN,
            statement,
            acknowledgements,
        };
        certificate.verify(source, handoff, target_registry, target)?;
        Ok(certificate)
    }

    /// Construct a target-quorum certificate from the non-serializable capability proving this
    /// exact semantic import was durably completed and reopened.
    ///
    /// The capability already crossed source-registry, handoff, exact-seal, complete-graph, and
    /// durable-reopen verification. Requiring it again prevents a restart journal from treating
    /// its serialized statement as authority while avoiding a second caller-supplied source graph
    /// at the target ACK reducer.
    pub fn from_completed_import(
        completed: &VerifiedDepositStateImport,
        mut acknowledgements: Vec<DepositStateImportedAck>,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<Self, DepositStateImportError> {
        validate_completed_import_target(completed, target)?;
        acknowledgements.sort_by_key(DepositStateImportedAck::signer);
        let certificate = Self {
            version: DEPOSIT_STATE_IMPORTED_VERSION,
            domain: STATE_IMPORTED_CERTIFICATE_DOMAIN,
            statement: completed.statement.clone(),
            acknowledgements,
        };
        certificate.verify_completed_import(completed, target)?;
        Ok(certificate)
    }

    fn validate_embedded(&self) -> Result<(), DepositStateImportError> {
        self.statement.validate_static()?;
        let required = self
            .statement
            .target_committee
            .n()
            .checked_sub(self.statement.target_fault_bound)
            .ok_or(DepositStateImportError::InvalidCertificate)?;
        if self.version != DEPOSIT_STATE_IMPORTED_VERSION
            || self.domain != STATE_IMPORTED_CERTIFICATE_DOMAIN
        {
            return Err(DepositStateImportError::InvalidCertificate);
        }
        if self.acknowledgements.len() != usize::from(required) {
            return Err(DepositStateImportError::WrongAckCount {
                actual: self.acknowledgements.len(),
                required: usize::from(required),
            });
        }
        let mut previous = None;
        for ack in &self.acknowledgements {
            let signer = ack.verify(&self.statement)?;
            if previous.is_some_and(|party| party >= signer) {
                return Err(DepositStateImportError::NonCanonicalAcks);
            }
            previous = Some(signer);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target_registry: &CompactEpochRegistry,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedStateImportedCertificate, DepositStateImportError> {
        self.validate_embedded()?;
        self.statement.validate_against(source, handoff, target_registry, target)?;
        self.verified()
    }

    /// Reverify a durable target ACK certificate against a freshly re-minted completed-import
    /// capability and the locally authenticated current target.
    pub fn verify_completed_import(
        &self,
        completed: &VerifiedDepositStateImport,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedStateImportedCertificate, DepositStateImportError> {
        self.validate_embedded()?;
        validate_completed_import_target(completed, target)?;
        if self.statement != completed.statement {
            return Err(DepositStateImportError::WrongTransition);
        }
        self.verified()
    }

    fn verified(&self) -> Result<VerifiedStateImportedCertificate, DepositStateImportError> {
        let bytes = encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES,
            "deposit state imported certificate",
        )?;
        Ok(VerifiedStateImportedCertificate {
            statement: self.statement.clone(),
            certificate_bytes: bytes.clone(),
            network: self.statement.network,
            wallet: self.statement.wallet,
            transition: self.statement.transition_binding(),
            semantic_transition: self.statement.semantic_transition,
            handoff_statement: self.statement.handoff_statement,
            handoff_export_context: self.statement.handoff_export_context,
            target_registry: self.statement.target_registry.digest(),
            target_epoch: self.statement.target_epoch,
            target_committee: self.statement.target_committee.digest(),
            target_activation: self.statement.target_activation,
            target_certified_activation_root: self.statement.target_certified_activation_root,
            terminal_checkpoint_sequence: self.statement.terminal_checkpoint_sequence,
            terminal_checkpoint_decision: self.statement.terminal_checkpoint_decision,
            terminal_portable_root: self
                .statement
                .portable_head
                .root()
                .ok_or(DepositStateImportError::InvalidPortableHead)?,
            terminal_portable_head: self.statement.portable_head.digest(),
            certificate: length_prefixed_hash(STATE_IMPORTED_CERTIFICATE_DIGEST_DOMAIN, &bytes),
            signers: self.acknowledgements.iter().map(DepositStateImportedAck::signer).collect(),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateImportError> {
        self.validate_embedded()?;
        encode_bounded(
            self,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES,
            "deposit state imported certificate",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositStateImportError> {
        let certificate: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_STATE_IMPORTED_CERTIFICATE_BYTES,
            "deposit state imported certificate",
        )?;
        certificate.validate_embedded()?;
        Ok(certificate)
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositStateImportedStatement {
        &self.statement
    }

    #[must_use]
    pub fn acknowledgements(&self) -> &[DepositStateImportedAck] {
        &self.acknowledgements
    }
}

/// Non-serializable proof that one exact seal variant was fully imported and reopened.
///
/// Construction requires the service's cold, complete-graph reopen capability and the matching
/// old-quorum seal. The exact source variant is deliberately retained locally but omitted from
/// the signed semantic statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositStateImport {
    statement: DepositStateImportedStatement,
    exact_seal_statement: [u8; 32],
    exact_seal_certificate: [u8; 32],
}

impl VerifiedDepositStateImport {
    /// Test-only construction from the same verified export inputs used by the production reopen
    /// path. Production code must additionally present the durable reopen capability.
    #[cfg(test)]
    pub(crate) fn from_verified_export_seal_for_test(
        network: [u8; 32],
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        seal: &VerifiedDepositPostHandoffExportSeal,
    ) -> Result<Self, DepositStateImportError> {
        let statement = DepositStateImportedStatement::from_verified_export_seal(
            network, source, handoff, target, seal,
        )?;
        Ok(Self {
            statement,
            exact_seal_statement: seal.statement_digest(),
            exact_seal_certificate: seal.certificate_digest(),
        })
    }

    /// Mint acknowledgement authority only after one exact sealed import has been committed,
    /// its temporary spool has been released, the import marker has been cleared by CAS, and the
    /// final successor advertisement has been authenticated again from durable storage.
    ///
    /// The service supplies a non-serializable durable-reopen capability; equality with the
    /// old-quorum-authenticated exact seal is checked here. Merely possessing either an
    /// advertisement or a seal certificate is insufficient.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn after_authenticated_reopen(
        statement: &DepositStateImportedStatement,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        seal: &VerifiedDepositPostHandoffExportSeal,
        reopened: &AuthenticatedReopenedCertifiedExport,
    ) -> Result<Self, DepositStateImportError> {
        let expected = DepositStateImportedStatement::from_verified_export_seal(
            statement.network,
            source,
            handoff,
            target,
            seal,
        )?;
        let sealed = seal.statement();
        if &expected != statement
            || reopened.seal_statement_digest() != sealed.digest()
            || reopened.seal_certificate_digest() != seal.certificate_digest()
            || reopened.source_party() != sealed.source_party()
            || reopened.source_registry() != sealed.source()
            || reopened.target_epoch() != sealed.target_epoch()
            || reopened.semantic_transition_digest() != sealed.semantic_transition_digest()
            || reopened.advertisement_digest() != sealed.final_export().advertisement_digest()
            || sealed.final_export().validate_advertisement(reopened.advertisement()).is_err()
        {
            return Err(DepositStateImportError::IncompleteImport);
        }
        Ok(Self {
            statement: statement.clone(),
            exact_seal_statement: sealed.digest(),
            exact_seal_certificate: seal.certificate_digest(),
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositStateImportedStatement {
        &self.statement
    }

    #[must_use]
    pub(crate) const fn exact_seal_statement_digest(&self) -> [u8; 32] {
        self.exact_seal_statement
    }

    #[must_use]
    pub(crate) const fn exact_seal_certificate_digest(&self) -> [u8; 32] {
        self.exact_seal_certificate
    }
}

fn validate_completed_import_target(
    completed: &VerifiedDepositStateImport,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<(), DepositStateImportError> {
    let statement = completed.statement();
    statement.validate_static()?;
    target.committee().validate_async_security_with_faults(target.fault_bound())?;
    if statement.target_epoch != target.committee().epoch
        || statement.target_committee != *target.committee()
        || statement.target_fault_bound != target.fault_bound()
        || statement.target_key_id != target.key_id()
        || statement.target_group_key != target.group_key()
        || statement.target_activation != target.activation()
        || statement.target_certified_activation_root != target.certified_activation_root()
        || statement.wallet != target.wallet()
        || completed.exact_seal_statement == [0; 32]
        || completed.exact_seal_certificate == [0; 32]
    {
        return Err(DepositStateImportError::WrongTransition);
    }
    Ok(())
}

/// Verified `n-f` target availability authority.
///
/// This token gates target deposit readiness and transition-wide predecessor export-pin
/// reclamation only. In particular it is not a share-retirement, receiver-key-retirement,
/// requester-lease, or spool-admission capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStateImportedCertificate {
    statement: DepositStateImportedStatement,
    certificate_bytes: Vec<u8>,
    network: [u8; 32],
    wallet: DepositWalletId,
    transition: [u8; 32],
    semantic_transition: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_export_context: [u8; 32],
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
    signers: Vec<PartyId>,
}

impl VerifiedStateImportedCertificate {
    /// Complete canonical semantic statement for durable re-verification after restart.
    #[must_use]
    pub const fn statement(&self) -> &DepositStateImportedStatement {
        &self.statement
    }

    /// Exact canonical target certificate artifact for durable journaling and readback.
    #[must_use]
    pub fn certificate_bytes(&self) -> &[u8] {
        &self.certificate_bytes
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn transition_binding(&self) -> [u8; 32] {
        self.transition
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    #[must_use]
    pub const fn handoff_statement_digest(&self) -> [u8; 32] {
        self.handoff_statement
    }

    #[must_use]
    pub const fn handoff_export_context(&self) -> [u8; 32] {
        self.handoff_export_context
    }

    #[must_use]
    pub const fn target_registry_digest(&self) -> [u8; 32] {
        self.target_registry
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub const fn target_committee_digest(&self) -> [u8; 32] {
        self.target_committee
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
    pub const fn terminal_checkpoint_sequence(&self) -> u64 {
        self.terminal_checkpoint_sequence
    }

    #[must_use]
    pub const fn terminal_checkpoint_decision(&self) -> [u8; 32] {
        self.terminal_checkpoint_decision
    }

    #[must_use]
    pub const fn terminal_portable_root(&self) -> DepositIndexObjectId {
        self.terminal_portable_root
    }

    #[must_use]
    pub const fn terminal_portable_head_digest(&self) -> [u8; 32] {
        self.terminal_portable_head
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }
}

fn deserialize_members<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Member>, D::Error> {
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "committee members")
}

fn deserialize_acks<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DepositStateImportedAck>, D::Error> {
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "state-imported acknowledgements")
}

fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        maximum: usize,
        kind: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundedVecVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {} {}", self.maximum, self.kind)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if let Some(length) = sequence.size_hint()
                && length > self.maximum
            {
                return Err(A::Error::invalid_length(length, &self));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(A::Error::invalid_length(self.maximum.saturating_add(1), &self));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor { maximum, kind, marker: PhantomData })
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, DepositStateImportError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| DepositStateImportError::Serialization)?;
    if bytes.len() > maximum {
        return Err(DepositStateImportError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    Ok(bytes)
}

fn decode_canonical_bounded<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    maximum: usize,
    kind: &'static str,
) -> Result<T, DepositStateImportError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DepositStateImportError::ObjectTooLarge { kind, actual: bytes.len(), maximum });
    }
    let (value, trailing) =
        postcard::take_from_bytes(bytes).map_err(|_| DepositStateImportError::Serialization)?;
    if !trailing.is_empty() {
        return Err(DepositStateImportError::TrailingBytes { kind, trailing: trailing.len() });
    }
    if postcard::to_allocvec(&value).map_err(|_| DepositStateImportError::Serialization)? != bytes {
        return Err(DepositStateImportError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

fn length_prefixed_hash(domain: &'static str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn certified_transition_binding(
    network: [u8; 32],
    wallet: DepositWalletId,
    semantic_transition: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(STATE_IMPORTED_CERTIFIED_TRANSITION_DOMAIN);
    hasher.update(&DEPOSIT_STATE_IMPORTED_VERSION.to_le_bytes());
    hasher.update(&network);
    hasher.update(&wallet.0);
    hasher.update(&semantic_transition);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error)]
pub enum DepositStateImportError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("compact registry error: {0}")]
    CompactRegistry(#[from] CompactRegistryError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("deposit post-handoff export error: {0}")]
    StateExport(#[from] DepositStateExportError),
    #[error("state-imported statement is malformed")]
    InvalidStatement,
    #[error("state-imported statement belongs to another handoff or target")]
    WrongTransition,
    #[error("verified post-handoff export seal does not project to this semantic transition")]
    WrongExportSeal,
    #[error("completed import does not match the authenticated reopened successor state")]
    IncompleteImport,
    #[error("state-imported target committee is not canonically ordered")]
    NonCanonicalTargetCommittee,
    #[error("state-imported portable head is malformed")]
    InvalidPortableHead,
    #[error("state-imported acknowledgement signer is not the configured target identity")]
    WrongSigner,
    #[error("state-imported acknowledgement is malformed or belongs to another statement")]
    InvalidAck,
    #[error(
        "state-imported certificate has {actual} acknowledgements; exact n-f requires {required}"
    )]
    WrongAckCount { actual: usize, required: usize },
    #[error("state-imported acknowledgements are not strictly ordered by unique party ID")]
    NonCanonicalAcks,
    #[error("state-imported certificate is malformed")]
    InvalidCertificate,
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("state-imported serialization failed")]
    Serialization,
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{0} encoding is not canonical")]
    NonCanonicalEncoding(&'static str),
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        committee::Member,
        deposit_index::{DEPOSIT_INDEX_ARTIFACT_KIND, DepositIndexHead},
        deposit_state_export::DepositHandoffStateBinding,
        storage::{WalletArtifactRef, WalletId},
    };

    const NETWORK: [u8; 32] = [0x41; 32];
    const KEY_ID: [u8; 32] = [0x42; 32];
    const GROUP_KEY: [u8; 32] = [0x43; 32];
    const CHECKPOINT_DECISION: [u8; 32] = [0x44; 32];

    fn signing_seed(party: PartyId) -> [u8; 32] {
        let mut seed = [0x51; 32];
        seed[0..2].copy_from_slice(&party.0.to_le_bytes());
        seed
    }

    fn x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x61; 32];
        secret[2..10].copy_from_slice(&epoch.to_le_bytes());
        secret[10..12].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn identity(party: PartyId, epoch: u64) -> Identity {
        Identity::from_test_secrets(party, epoch, &signing_seed(party), x25519_secret(party, epoch))
            .unwrap()
    }

    fn member(identity: &Identity) -> Member {
        Member {
            id: identity.party(),
            signing_key: identity.signing_public_key(),
            encryption_key: identity.encryption_public_key(),
        }
    }

    fn index(address: u32) -> DepositSubaddressIndex {
        DepositSubaddressIndex::new(0, address).unwrap()
    }

    fn portable_head(
        wallet: DepositWalletId,
        entries: u64,
        through_sequence: u64,
        ledger_head: [u8; 32],
        next_index: DepositSubaddressIndex,
        tag: u8,
    ) -> PortableDepositIndexHead {
        let reference = WalletArtifactRef::for_contents(
            WalletId(wallet.0),
            DEPOSIT_INDEX_ARTIFACT_KIND,
            &[tag],
        )
        .unwrap();
        let root = DepositIndexObjectId::from_storage_reference(reference).unwrap();
        let head = DepositIndexHead::from_portable_components(
            wallet,
            entries,
            entries,
            Some(root),
            through_sequence,
            ledger_head,
            next_index,
        )
        .unwrap();
        PortableDepositIndexHead::from_head(&head).unwrap()
    }

    struct Fixture {
        source: CompactEpochRegistry,
        handoff: RegistryHandoffCertificate,
        target_registry: CompactEpochRegistry,
        target: VerifiedRegistryHandoffTarget,
        target_identities: BTreeMap<PartyId, Identity>,
        statement: DepositStateImportedStatement,
        completed: VerifiedDepositStateImport,
        portable_head: PortableDepositIndexHead,
    }

    impl Fixture {
        fn acknowledgements(&self, parties: &[u16]) -> Vec<DepositStateImportedAck> {
            parties
                .iter()
                .map(|party| {
                    DepositStateImportedAck::sign(
                        &self.completed,
                        self.target_identities.get(&PartyId(*party)).unwrap(),
                    )
                    .unwrap()
                })
                .collect()
        }
    }

    fn fixture() -> Fixture {
        let wallet = DepositWalletId([0x71; 32]);
        let source_identities = (1_u16..=4)
            .map(|value| {
                let party = PartyId(value);
                (party, identity(party, 0))
            })
            .collect::<BTreeMap<_, _>>();

        // Nine stable identities exist. The predecessor is 1..=4 and the configured non-source
        // eligibility pool is 5..=9. Selecting 6..=9 leaves one spare and is genuinely disjoint.
        let eligible_target_identities = (5_u16..=9)
            .map(|value| {
                let party = PartyId(value);
                (party, identity(party, 1))
            })
            .collect::<BTreeMap<_, _>>();
        let selected = [PartyId(6), PartyId(7), PartyId(8), PartyId(9)];
        let source_parties = source_identities.keys().copied().collect::<BTreeSet<_>>();
        let eligible_parties = eligible_target_identities.keys().copied().collect::<BTreeSet<_>>();
        let selected_parties = selected.into_iter().collect::<BTreeSet<_>>();
        assert_eq!(source_parties.len() + eligible_parties.len(), 9);
        assert_eq!(eligible_parties.len(), 5);
        assert!(source_parties.is_disjoint(&eligible_parties));
        assert!(source_parties.is_disjoint(&selected_parties));
        assert!(selected_parties.is_subset(&eligible_parties));

        let source_committee = Committee {
            epoch: 0,
            threshold: 2,
            members: source_identities.values().map(member).collect(),
        }
        .canonicalized()
        .unwrap();
        let target_identities = selected
            .into_iter()
            .map(|party| (party, identity(party, 1)))
            .collect::<BTreeMap<_, _>>();
        let target_committee = Committee {
            epoch: 1,
            threshold: 2,
            members: target_identities.values().map(member).collect(),
        }
        .canonicalized()
        .unwrap();
        source_committee.validate_async_security_with_faults(1).unwrap();
        target_committee.validate_async_security_with_faults(1).unwrap();

        // There are no deposit allocations. The allocation high-water therefore remains at the
        // genesis first index while the portable HAMT still records a fence and terminal handoff.
        let first_index = index(1);
        let next_index = first_index;
        let empty = DepositIndexHead::empty_portable(wallet, first_index).unwrap();
        let empty = PortableDepositIndexHead::from_head(&empty).unwrap();
        let source_target = VerifiedRegistryHandoffTarget::for_test(
            source_committee.clone(),
            1,
            [0x81; 32],
            [0x82; 32],
            wallet,
            KEY_ID,
            GROUP_KEY,
        )
        .unwrap();
        let genesis = RegistryLink::genesis(&source_target, first_index, empty.digest()).unwrap();
        let source = CompactEpochRegistry::from_link(&genesis, [0x83; 32]).unwrap();
        let target = VerifiedRegistryHandoffTarget::for_test(
            target_committee,
            1,
            [0x84; 32],
            [0x85; 32],
            wallet,
            KEY_ID,
            GROUP_KEY,
        )
        .unwrap();
        let fence_head = portable_head(wallet, 1, 1, [0x87; 32], next_index, 0x88);
        let source_state =
            DepositHandoffStateBinding::new(Some([0x89; 32]), fence_head.clone()).unwrap();
        let handoff_statement = crate::compact_epoch_registry::RegistryHandoffStatement::new(
            &source,
            2,
            fence_head.ledger_head(),
            source_state,
            &target,
            next_index,
        )
        .unwrap();
        let handoff_witnesses = source_identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        &source_committee,
                        handoff_statement.session(),
                        None,
                        handoff_statement.terminal_sequence(),
                        handoff_statement.signing_payload(),
                    )
                    .unwrap()
            })
            .collect();
        let handoff =
            RegistryHandoffCertificate::new(handoff_statement, handoff_witnesses).unwrap();
        handoff.verify(&source).unwrap();
        let successor = RegistryLink::successor(&source, &target, &handoff).unwrap();
        let target_registry = CompactEpochRegistry::from_link(&successor, [0x86; 32]).unwrap();
        let portable = portable_head(wallet, 2, 2, handoff.statement().digest(), next_index, 0x91);
        assert_eq!(portable.entry_count(), 2);
        assert_eq!(portable.record_count(), 2);
        assert_eq!(portable.next_index(), first_index);
        let statement = DepositStateImportedStatement::from_semantic_parts(
            NETWORK,
            &source,
            &handoff,
            &target_registry,
            &target,
            2,
            CHECKPOINT_DECISION,
            portable.clone(),
        )
        .unwrap();
        let completed = VerifiedDepositStateImport {
            statement: statement.clone(),
            exact_seal_statement: [0x93; 32],
            exact_seal_certificate: [0x94; 32],
        };
        Fixture {
            source,
            handoff,
            target_registry,
            target,
            target_identities,
            statement,
            completed,
            portable_head: portable,
        }
    }

    #[test]
    fn disjoint_zero_deposit_handoff_requires_exact_target_n_minus_f_quorum() {
        let fixture = fixture();
        let insufficient = DepositStateImportedCertificate::new(
            fixture.statement.clone(),
            fixture.acknowledgements(&[6]),
            &fixture.source,
            &fixture.handoff,
            &fixture.target_registry,
            &fixture.target,
        )
        .unwrap_err();
        assert!(matches!(
            insufficient,
            DepositStateImportError::WrongAckCount { actual: 1, required: 3 }
        ));

        let certificate = DepositStateImportedCertificate::new(
            fixture.statement.clone(),
            fixture.acknowledgements(&[8, 6, 7]),
            &fixture.source,
            &fixture.handoff,
            &fixture.target_registry,
            &fixture.target,
        )
        .unwrap();
        assert_eq!(
            certificate
                .acknowledgements()
                .iter()
                .map(DepositStateImportedAck::signer)
                .collect::<Vec<_>>(),
            vec![PartyId(6), PartyId(7), PartyId(8)]
        );
        let canonical = certificate.to_bytes().unwrap();
        let decoded = DepositStateImportedCertificate::from_bytes(&canonical).unwrap();
        assert_eq!(decoded, certificate);
        let verified = decoded
            .verify(&fixture.source, &fixture.handoff, &fixture.target_registry, &fixture.target)
            .unwrap();
        assert_eq!(verified.signers().len(), 3);
        assert_eq!(verified.certificate_bytes(), canonical);
        assert_ne!(verified.certificate_digest(), [0; 32]);
        assert_eq!(verified.transition_binding(), fixture.statement.transition_binding());
        assert_eq!(verified.terminal_portable_head_digest(), fixture.portable_head.digest());
    }

    #[test]
    fn duplicate_and_noncanonical_acknowledgements_are_rejected() {
        let fixture = fixture();
        let ack = fixture.acknowledgements(&[6]).pop().unwrap();
        let duplicate = DepositStateImportedCertificate::new(
            fixture.statement.clone(),
            vec![ack.clone(), ack, fixture.acknowledgements(&[7]).pop().unwrap()],
            &fixture.source,
            &fixture.handoff,
            &fixture.target_registry,
            &fixture.target,
        )
        .unwrap_err();
        assert!(matches!(duplicate, DepositStateImportError::NonCanonicalAcks));

        let mut acknowledgements = fixture.acknowledgements(&[6, 7, 8]);
        acknowledgements.reverse();
        let noncanonical = DepositStateImportedCertificate {
            version: DEPOSIT_STATE_IMPORTED_VERSION,
            domain: STATE_IMPORTED_CERTIFICATE_DOMAIN,
            statement: fixture.statement,
            acknowledgements,
        };
        let bytes = postcard::to_allocvec(&noncanonical).unwrap();
        assert!(matches!(
            DepositStateImportedCertificate::from_bytes(&bytes),
            Err(DepositStateImportError::NonCanonicalAcks)
        ));
    }

    #[test]
    fn canonical_decoders_reject_trailing_bytes() {
        let fixture = fixture();
        let certificate = DepositStateImportedCertificate::new(
            fixture.statement.clone(),
            fixture.acknowledgements(&[6, 7, 8]),
            &fixture.source,
            &fixture.handoff,
            &fixture.target_registry,
            &fixture.target,
        )
        .unwrap();
        let mut bytes = certificate.to_bytes().unwrap();
        bytes.push(0);
        assert!(matches!(
            DepositStateImportedCertificate::from_bytes(&bytes),
            Err(DepositStateImportError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn acknowledgements_cannot_replay_across_target_handoff_or_portable_root() {
        let fixture = fixture();
        let ack = fixture.acknowledgements(&[6]).pop().unwrap();

        let mut another_target = fixture.statement.clone();
        another_target.target_activation = [0xa1; 32];
        another_target.semantic_transition = another_target.expected_semantic_transition().unwrap();
        assert!(matches!(ack.verify(&another_target), Err(DepositStateImportError::InvalidAck)));

        let mut another_handoff = fixture.statement.clone();
        another_handoff.handoff_export_context = [0xa2; 32];
        another_handoff.semantic_transition =
            another_handoff.expected_semantic_transition().unwrap();
        assert!(matches!(ack.verify(&another_handoff), Err(DepositStateImportError::InvalidAck)));

        let mut another_root = fixture.statement;
        another_root.portable_head = portable_head(
            another_root.wallet,
            another_root.portable_head.entry_count(),
            another_root.handoff_terminal_sequence,
            another_root.handoff_statement,
            another_root.handoff_next_index,
            0xa3,
        );
        another_root.semantic_transition = another_root.expected_semantic_transition().unwrap();
        assert!(matches!(ack.verify(&another_root), Err(DepositStateImportError::InvalidAck)));
    }
}
