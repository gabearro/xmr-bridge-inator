//! Immutable source-state authority committed by a deposit-registry handoff.
//!
//! A disjoint successor cannot reconstruct the portable ledger from the registry transition
//! alone. The retiring quorum therefore signs the exact archive head and terminal portable-index
//! checkpoint which its read-only export capability will serve after threshold-share retirement.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    committee::{Committee, PartyId, SessionId},
    compact_epoch_registry::{
        CompactEpochRegistry, RegistryHandoffCertificate, RegistryId, RegistryLink,
    },
    compact_registry_archive::{
        CompactRegistryArchiveHead, CompactRegistryObjectReader, lookup_compact_registry_epoch,
    },
    compact_registry_store::CompactRegistryStoreCheckpoint,
    deposit_archive::{
        CERTIFIED_LEDGER_ENTRY_ARTIFACT, DEPOSIT_ARCHIVE_EVENT_ARTIFACT,
        DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT, DepositArchiveAppend, DepositArchiveEvent,
        DepositArchiveHead, DepositArchiveOperation, DepositArchiveSegment,
    },
    deposit_index_checkpoint::{
        DepositIndexCheckpointCertificate, DepositIndexCheckpointOperation,
        PortableDepositIndexHead, VerifiedDepositIndexCheckpoint,
    },
    deposit_index_retention::PreparedExportCandidatePin,
    deposit_index_store::VerifiedRemoteExportSealVoteGate,
    deposit_ledger::CertifiedLedgerEntry,
    deposit_sync_wire::DepositSyncAdvertisement,
    identity::{EnvelopeSigner, EnvelopeSignerScope, Identity, IdentityError, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
    keys::EpochPublic,
    storage::{WalletArtifactRef, WalletId},
};

const EXPORT_BINDING_VERSION: u16 = 2;
const EXPORT_BINDING_DOMAIN: &str = "threshold-monero/deposit-state-export-binding/v2";
const HANDOFF_STATE_BINDING_VERSION: u16 = 1;
const HANDOFF_STATE_BINDING_DOMAIN: &str = "threshold-monero/deposit-handoff-state-binding/v1";
const POST_HANDOFF_EXPORT_SEAL_STATEMENT_VERSION: u16 = 1;
const POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_VERSION: u16 = 1;
const POST_HANDOFF_EXPORT_SEAL_STATEMENT_DOMAIN: &str =
    "threshold-monero/deposit-post-handoff-export-seal-statement/v1";
const POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DOMAIN: &str =
    "threshold-monero/deposit-post-handoff-export-seal-certificate/v1";
const POST_HANDOFF_EXPORT_SEAL_SEMANTIC_DOMAIN: &str =
    "threshold-monero/deposit-post-handoff-export-semantic-transition/v1";
const POST_HANDOFF_EXPORT_SEAL_VOTE_SLOT_DOMAIN: &str =
    "threshold-monero/deposit-post-handoff-export-vote-slot/v1";
const POST_HANDOFF_EXPORT_SEAL_SESSION_DOMAIN: &[u8] =
    b"threshold-monero/deposit-post-handoff-export-seal-session/v1";
pub(crate) const MAX_POST_HANDOFF_EXPORT_SEAL_BYTES: usize = 64 * 1024;

/// Witness-independent portable state committed by the terminal handoff consensus value.
///
/// Exact archive events and checkpoint certificate bytes cannot appear here: two honest replicas
/// may certify the same semantic decision with different valid `n-f` witness subsets. Those exact
/// source-specific references are committed only by a post-handoff export seal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositHandoffStateBinding {
    version: u16,
    terminal_checkpoint_decision: Option<[u8; 32]>,
    portable_head: PortableDepositIndexHead,
}

impl DepositHandoffStateBinding {
    pub fn new(
        terminal_checkpoint_decision: Option<[u8; 32]>,
        portable_head: PortableDepositIndexHead,
    ) -> Result<Self, DepositStateExportError> {
        let binding = Self {
            version: HANDOFF_STATE_BINDING_VERSION,
            terminal_checkpoint_decision,
            portable_head,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), DepositStateExportError> {
        self.portable_head
            .maximum_reachable_objects()
            .map_err(|_| DepositStateExportError::InvalidHandoffBinding)?;
        if self.version != HANDOFF_STATE_BINDING_VERSION
            || self.terminal_checkpoint_decision.is_none_or(|decision| decision == [0; 32])
        {
            return Err(DepositStateExportError::InvalidHandoffBinding);
        }
        Ok(())
    }

    #[must_use]
    pub const fn terminal_checkpoint_decision(&self) -> Option<[u8; 32]> {
        self.terminal_checkpoint_decision
    }

    #[must_use]
    pub const fn portable_head(&self) -> &PortableDepositIndexHead {
        &self.portable_head
    }

    pub fn digest(&self) -> Result<[u8; 32], DepositStateExportError> {
        self.validate()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositStateExportError::Serialization)?;
        let mut hasher = blake3::Hasher::new_derive_key(HANDOFF_STATE_BINDING_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Latest certified checkpoint named by the source archive head.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportCheckpoint {
    sequence: u64,
    event: WalletArtifactRef,
    decision: [u8; 32],
}

impl DepositStateExportCheckpoint {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn event(self) -> WalletArtifactRef {
        self.event
    }

    #[must_use]
    pub const fn decision(self) -> [u8; 32] {
        self.decision
    }
}

/// Exact settled successor state which a target must import before deposit issuance becomes ready.
///
/// The exact advertisement digest binds the complete transfer manifest without copying its
/// potentially large checkpoint certificate into every seal statement. The explicit projections
/// are the roots needed for bounded validation and restart reopening.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositStateExportBinding {
    version: u16,
    advertisement_digest: [u8; 32],
    registry_checkpoint_digest: [u8; 32],
    target_registry_archive: CompactRegistryArchiveHead,
    archive: DepositArchiveHead,
    terminal_checkpoint: DepositStateExportCheckpoint,
    terminal_checkpoint_certificate: [u8; 32],
    resulting_portable_head: PortableDepositIndexHead,
}

impl DepositStateExportBinding {
    pub fn from_advertisement(
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<Self, DepositStateExportError> {
        advertisement.to_bytes().map_err(|_| DepositStateExportError::InvalidBinding)?;
        let archive = advertisement.certificate_archive();
        let certificate = advertisement
            .checkpoint_certificate()
            .ok_or(DepositStateExportError::InvalidBinding)?;
        let event = archive.event_reference().ok_or(DepositStateExportError::InvalidBinding)?;
        let binding = Self {
            version: EXPORT_BINDING_VERSION,
            advertisement_digest: advertisement.digest(),
            registry_checkpoint_digest: advertisement.registry_checkpoint_digest(),
            target_registry_archive: advertisement.registry_archive().clone(),
            archive,
            terminal_checkpoint: DepositStateExportCheckpoint {
                sequence: certificate.statement().sequence(),
                event,
                decision: certificate.statement().decision_digest(),
            },
            terminal_checkpoint_certificate: certificate
                .certificate_digest()
                .map_err(|_| DepositStateExportError::InvalidBinding)?,
            resulting_portable_head: advertisement.portable_index().clone(),
        };
        binding.validate()?;
        binding.validate_advertisement(advertisement)?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), DepositStateExportError> {
        self.target_registry_archive
            .validate_shape()
            .map_err(|_| DepositStateExportError::InvalidBinding)?;
        self.archive.validate().map_err(|_| DepositStateExportError::InvalidBinding)?;
        self.terminal_checkpoint
            .event
            .validate()
            .map_err(|_| DepositStateExportError::InvalidBinding)?;
        self.resulting_portable_head
            .maximum_reachable_objects()
            .map_err(|_| DepositStateExportError::InvalidBinding)?;
        let reconstructed = CompactRegistryStoreCheckpoint::settled(
            self.target_registry_archive.wallet(),
            self.target_registry_archive.clone(),
        )
        .map_err(|_| DepositStateExportError::InvalidBinding)?;
        if self.version != EXPORT_BINDING_VERSION
            || self.advertisement_digest == [0; 32]
            || self.registry_checkpoint_digest == [0; 32]
            || reconstructed.digest() != self.registry_checkpoint_digest
            || self.archive.is_empty()
            || self.archive.wallet_id() != self.target_registry_archive.wallet()
            || self.archive.event_reference() != Some(self.terminal_checkpoint.event)
            || self.archive.segment_reference().is_none()
            || self.terminal_checkpoint.sequence != self.archive.len()
            || self.terminal_checkpoint.decision == [0; 32]
            || self.terminal_checkpoint_certificate == [0; 32]
            || self.resulting_portable_head.wallet_id() != self.archive.wallet_id()
            || self.resulting_portable_head.through_sequence() == 0
        {
            return Err(DepositStateExportError::InvalidBinding);
        }
        Ok(())
    }

    pub fn validate_advertisement(
        &self,
        advertisement: &DepositSyncAdvertisement,
    ) -> Result<(), DepositStateExportError> {
        self.validate()?;
        advertisement.to_bytes().map_err(|_| DepositStateExportError::InvalidBinding)?;
        let checkpoint = advertisement
            .checkpoint_certificate()
            .ok_or(DepositStateExportError::InvalidBinding)?;
        if advertisement.digest() != self.advertisement_digest
            || advertisement.registry_checkpoint_digest() != self.registry_checkpoint_digest
            || advertisement.registry_archive() != &self.target_registry_archive
            || advertisement.certificate_archive() != self.archive
            || advertisement.portable_index() != &self.resulting_portable_head
            || checkpoint.statement().sequence() != self.terminal_checkpoint.sequence
            || checkpoint.statement().decision_digest() != self.terminal_checkpoint.decision
            || checkpoint
                .certificate_digest()
                .map_err(|_| DepositStateExportError::InvalidBinding)?
                != self.terminal_checkpoint_certificate
        {
            return Err(DepositStateExportError::InvalidBinding);
        }
        Ok(())
    }

    #[must_use]
    pub const fn advertisement_digest(&self) -> [u8; 32] {
        self.advertisement_digest
    }

    #[must_use]
    pub const fn registry_checkpoint_digest(&self) -> [u8; 32] {
        self.registry_checkpoint_digest
    }

    #[must_use]
    pub const fn target_registry_archive(&self) -> &CompactRegistryArchiveHead {
        &self.target_registry_archive
    }

    #[must_use]
    pub const fn archive(&self) -> DepositArchiveHead {
        self.archive
    }

    #[must_use]
    pub const fn terminal_checkpoint(&self) -> DepositStateExportCheckpoint {
        self.terminal_checkpoint
    }

    #[must_use]
    pub const fn terminal_checkpoint_certificate_digest(&self) -> [u8; 32] {
        self.terminal_checkpoint_certificate
    }

    #[must_use]
    pub const fn resulting_portable_head(&self) -> &PortableDepositIndexHead {
        &self.resulting_portable_head
    }

    pub fn digest(&self) -> Result<[u8; 32], DepositStateExportError> {
        self.validate()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositStateExportError::Serialization)?;
        let mut hasher = blake3::Hasher::new_derive_key(EXPORT_BINDING_DOMAIN);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Source-specific exact post-terminal archive authority signed by the retiring committee.
///
/// `source_party` names the predecessor replica which promises to serve this exact graph. Different
/// honest sources may have different archive/certificate references because an `n-f` witness set
/// is not unique. The semantic transition digest deliberately excludes those exact references so
/// successor import acknowledgements can aggregate across all honest source variants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealStatement {
    version: u16,
    network: [u8; 32],
    source_party: PartyId,
    source: RegistryId,
    source_committee: [u8; 32],
    source_fault_bound: u16,
    source_certified_activation_root: [u8; 32],
    handoff_statement: [u8; 32],
    handoff_certificate: [u8; 32],
    export_capability_context: [u8; 32],
    final_export: DepositStateExportBinding,
    terminal_operation_artifact: WalletArtifactRef,
    terminal_checkpoint_artifact: WalletArtifactRef,
    terminal_checkpoint_certificate: [u8; 32],
    target_epoch: u64,
    target_key_id: [u8; 32],
    target_group_key: [u8; 32],
    target_committee: [u8; 32],
    target_fault_bound: u16,
    target_activation: [u8; 32],
    target_certified_activation_root: [u8; 32],
    semantic_transition: [u8; 32],
    vote_slot: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifiedPostHandoffExportTerminal {
    wallet: crate::deposit_wallet::DepositWalletId,
    checkpoint_sequence: u64,
    checkpoint_decision: [u8; 32],
    checkpoint_certificate: [u8; 32],
    ledger_sequence: u64,
    ledger_statement: [u8; 32],
    event_artifact: WalletArtifactRef,
    ledger_artifact: WalletArtifactRef,
    checkpoint_artifact: WalletArtifactRef,
}

impl DepositPostHandoffExportSealStatement {
    fn from_verified_append<R: CompactRegistryObjectReader>(
        network: [u8; 32],
        source_party: PartyId,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        final_export: DepositStateExportBinding,
        advertisement: &DepositSyncAdvertisement,
        registry_reader: &R,
        append: &DepositArchiveAppend,
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<Self, DepositStateExportError> {
        let locator = append.verified_ledger_locator();
        if append.head != final_export.archive()
            || append.event_artifact != locator.event_artifact()
            || append.entry_artifact != locator.ledger_artifact()
            || append.checkpoint_artifact != locator.checkpoint_artifact()
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }
        Self::from_verified_terminal(
            network,
            source_party,
            source,
            handoff,
            target,
            final_export,
            advertisement,
            registry_reader,
            VerifiedPostHandoffExportTerminal {
                wallet: locator.wallet_id(),
                checkpoint_sequence: locator.checkpoint_sequence(),
                checkpoint_decision: locator.checkpoint_decision(),
                checkpoint_certificate: locator.checkpoint_certificate_digest(),
                ledger_sequence: locator.ledger_sequence(),
                ledger_statement: locator.ledger_statement(),
                event_artifact: locator.event_artifact(),
                ledger_artifact: locator.ledger_artifact(),
                checkpoint_artifact: locator.checkpoint_artifact(),
            },
            checkpoint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_verified_terminal<R: CompactRegistryObjectReader>(
        network: [u8; 32],
        source_party: PartyId,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        final_export: DepositStateExportBinding,
        advertisement: &DepositSyncAdvertisement,
        registry_reader: &R,
        verified_terminal: VerifiedPostHandoffExportTerminal,
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<Self, DepositStateExportError> {
        source.validate().map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        handoff.verify(source).map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        source
            .active()
            .committee()
            .member(source_party)
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        final_export.validate()?;
        final_export.validate_advertisement(advertisement)?;

        let transition = handoff.statement();
        let successor_epoch = lookup_compact_registry_epoch(
            final_export.target_registry_archive(),
            target.committee().epoch,
            registry_reader,
        )
        .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let expected_link = RegistryLink::successor(source, target, handoff)
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let terminal = final_export.terminal_checkpoint();
        let portable = final_export.resulting_portable_head();
        if network == [0; 32]
            || advertisement.context().network() != network
            || advertisement.context().wallet() != source.wallet()
            || final_export.target_registry_archive().registry().active_epoch()
                != target.committee().epoch
            || successor_epoch.link() != &expected_link
            || successor_epoch.link_reference()
                != final_export.target_registry_archive().active_link_reference()
            || successor_epoch.witness() != Some(handoff)
            || successor_epoch.witness_reference()
                != final_export.target_registry_archive().active_witness_reference()
            || final_export.archive().event_reference() != Some(verified_terminal.event_artifact)
            || terminal.sequence() != final_export.archive().len()
            || terminal.sequence() != verified_terminal.checkpoint_sequence
            || terminal.event() != verified_terminal.event_artifact
            || terminal.decision() != verified_terminal.checkpoint_decision
            || verified_terminal.wallet != source.wallet()
            || verified_terminal.ledger_sequence != transition.terminal_sequence()
            || verified_terminal.ledger_statement != transition.digest()
            || checkpoint.context().network() != network
            || checkpoint.context().wallet_id() != source.wallet()
            || checkpoint.context().registry_digest() != source.digest()
            || checkpoint.context().activation_digest() != source.active().activation()
            || checkpoint.context().epoch() != source.active_epoch()
            || checkpoint.context().committee_digest() != source.active().committee().digest()
            || checkpoint.sequence() != verified_terminal.checkpoint_sequence
            || checkpoint.decision_digest() != verified_terminal.checkpoint_decision
            || checkpoint.certificate_digest() != verified_terminal.checkpoint_certificate
            || checkpoint.certificate_digest()
                != final_export.terminal_checkpoint_certificate_digest()
            || checkpoint.operation()
                != (DepositIndexCheckpointOperation::Ledger { statement: transition.digest() })
            || checkpoint.ledger_sequence() != transition.terminal_sequence()
            || checkpoint.ledger_decision() != transition.digest()
            || checkpoint.resulting_head() != portable
            || portable.through_sequence() != transition.terminal_sequence()
            || portable.ledger_head() != transition.digest()
            || portable.next_index() != transition.next_index()
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }

        let semantic_transition = post_handoff_export_semantic_transition_digest(
            network,
            source.id(),
            source.active().certified_activation_root(),
            transition.digest(),
            transition.export_capability_context(),
            final_export.target_registry_archive().registry_id(),
            terminal.decision(),
            portable,
        )?;
        let vote_slot = export_seal_vote_slot_digest(
            semantic_transition,
            source_party,
            transition.target_epoch(),
        );
        let statement = Self {
            version: POST_HANDOFF_EXPORT_SEAL_STATEMENT_VERSION,
            network,
            source_party,
            source: source.id(),
            source_committee: source.active().committee().digest(),
            source_fault_bound: source.active().fault_bound(),
            source_certified_activation_root: source.active().certified_activation_root(),
            handoff_statement: transition.digest(),
            handoff_certificate: handoff
                .digest()
                .map_err(|_| DepositStateExportError::InvalidSealStatement)?,
            export_capability_context: transition.export_capability_context(),
            final_export,
            terminal_operation_artifact: verified_terminal.ledger_artifact,
            terminal_checkpoint_artifact: verified_terminal.checkpoint_artifact,
            terminal_checkpoint_certificate: verified_terminal.checkpoint_certificate,
            target_epoch: transition.target_epoch(),
            target_key_id: transition.target_key_id(),
            target_group_key: transition.target_group_key(),
            target_committee: transition.target_committee(),
            target_fault_bound: transition.target_fault_bound(),
            target_activation: transition.target_activation(),
            target_certified_activation_root: transition.target_certified_activation_root(),
            semantic_transition,
            vote_slot,
        };
        statement.validate_against(source, handoff)?;
        Ok(statement)
    }

    fn validate_intrinsic(&self) -> Result<(), DepositStateExportError> {
        self.source.validate().map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        self.final_export.validate()?;
        let terminal = self.final_export.terminal_checkpoint();
        let portable = self.final_export.resulting_portable_head();
        let target_registry = self.final_export.target_registry_archive().registry();
        let target_active = target_registry.active();
        for (reference, kind) in [
            (terminal.event(), DEPOSIT_ARCHIVE_EVENT_ARTIFACT),
            (self.terminal_operation_artifact, CERTIFIED_LEDGER_ENTRY_ARTIFACT),
            (self.terminal_checkpoint_artifact, DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT),
        ] {
            reference.validate().map_err(|_| DepositStateExportError::InvalidSealStatement)?;
            if reference.wallet_id() != WalletId(self.source.wallet().0) || reference.kind() != kind
            {
                return Err(DepositStateExportError::InvalidSealStatement);
            }
        }
        if self.version != POST_HANDOFF_EXPORT_SEAL_STATEMENT_VERSION
            || self.network == [0; 32]
            || self.source_party.0 == 0
            || self.source_committee == [0; 32]
            || self.source_certified_activation_root == [0; 32]
            || self.handoff_statement == [0; 32]
            || self.handoff_certificate == [0; 32]
            || self.export_capability_context == [0; 32]
            || self.terminal_checkpoint_certificate == [0; 32]
            || self.terminal_checkpoint_certificate
                != self.final_export.terminal_checkpoint_certificate_digest()
            || self.target_epoch
                != self
                    .source
                    .active_epoch()
                    .checked_add(1)
                    .ok_or(DepositStateExportError::InvalidSealStatement)?
            || self.target_key_id == [0; 32]
            || self.target_group_key == [0; 32]
            || self.target_committee == [0; 32]
            || self.target_activation == [0; 32]
            || self.target_certified_activation_root == [0; 32]
            || self.final_export.archive().wallet_id() != self.source.wallet()
            || self.final_export.archive().event_reference() != Some(terminal.event())
            || terminal.sequence() != self.final_export.archive().len()
            || portable.wallet_id() != self.source.wallet()
            || portable.through_sequence() == 0
            || portable.ledger_head() != self.handoff_statement
            || target_registry.wallet() != self.source.wallet()
            || target_active.epoch() != self.target_epoch
            || target_active.key_id() != self.target_key_id
            || target_active.group_key() != self.target_group_key
            || target_active.committee().digest() != self.target_committee
            || target_active.fault_bound() != self.target_fault_bound
            || target_active.activation() != self.target_activation
            || target_active.certified_activation_root() != self.target_certified_activation_root
            || target_active.start_sequence().checked_sub(1) != Some(portable.through_sequence())
            || target_active.predecessor_ledger_head() != self.handoff_statement
            || target_active.first_index() != portable.next_index()
            || self.final_export.target_registry_archive().active_witness_reference().is_none()
            || self.semantic_transition == [0; 32]
            || self.vote_slot == [0; 32]
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }
        let expected_semantic = post_handoff_export_semantic_transition_digest(
            self.network,
            self.source,
            self.source_certified_activation_root,
            self.handoff_statement,
            self.export_capability_context,
            target_registry.id(),
            terminal.decision(),
            portable,
        )?;
        if self.semantic_transition != expected_semantic
            || self.vote_slot
                != export_seal_vote_slot_digest(
                    expected_semantic,
                    self.source_party,
                    self.target_epoch,
                )
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
    ) -> Result<(), DepositStateExportError> {
        self.validate_intrinsic()?;
        source.validate().map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        handoff.verify(source).map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let transition = handoff.statement();
        source
            .active()
            .committee()
            .member(self.source_party)
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        if self.source != source.id()
            || self.source_committee != source.active().committee().digest()
            || self.source_fault_bound != source.active().fault_bound()
            || self.source_certified_activation_root != source.active().certified_activation_root()
            || self.handoff_statement != transition.digest()
            || self.handoff_certificate
                != handoff.digest().map_err(|_| DepositStateExportError::InvalidSealStatement)?
            || self.export_capability_context != transition.export_capability_context()
            || self.target_epoch != transition.target_epoch()
            || self.target_key_id != transition.target_key_id()
            || self.target_group_key != transition.target_group_key()
            || self.target_committee != transition.target_committee()
            || self.target_fault_bound != transition.target_fault_bound()
            || self.target_activation != transition.target_activation()
            || self.target_certified_activation_root
                != transition.target_certified_activation_root()
            || self
                .final_export
                .target_registry_archive()
                .registry()
                .active()
                .portable_index_checkpoint()
                != transition.source_portable_index()
            || self.final_export.resulting_portable_head().through_sequence()
                != transition.terminal_sequence()
            || self.final_export.resulting_portable_head().next_index() != transition.next_index()
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(self).expect("validated export seal statement serializes");
        length_prefixed_hash(POST_HANDOFF_EXPORT_SEAL_STATEMENT_DOMAIN, &bytes)
    }

    #[must_use]
    pub fn session(&self) -> SessionId {
        SessionId::derive(POST_HANDOFF_EXPORT_SEAL_SESSION_DOMAIN, &self.vote_slot)
    }

    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        self.digest().to_vec()
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn source_party(&self) -> PartyId {
        self.source_party
    }

    #[must_use]
    pub const fn source(&self) -> RegistryId {
        self.source
    }

    #[must_use]
    pub const fn source_committee(&self) -> [u8; 32] {
        self.source_committee
    }

    #[must_use]
    pub const fn source_fault_bound(&self) -> u16 {
        self.source_fault_bound
    }

    #[must_use]
    pub const fn source_certified_activation_root(&self) -> [u8; 32] {
        self.source_certified_activation_root
    }

    #[must_use]
    pub const fn handoff_statement_digest(&self) -> [u8; 32] {
        self.handoff_statement
    }

    #[must_use]
    pub const fn handoff_certificate_digest(&self) -> [u8; 32] {
        self.handoff_certificate
    }

    #[must_use]
    pub const fn export_capability_context(&self) -> [u8; 32] {
        self.export_capability_context
    }

    #[must_use]
    pub const fn final_export(&self) -> &DepositStateExportBinding {
        &self.final_export
    }

    #[must_use]
    pub const fn terminal_operation_artifact(&self) -> WalletArtifactRef {
        self.terminal_operation_artifact
    }

    #[must_use]
    pub const fn terminal_checkpoint_artifact(&self) -> WalletArtifactRef {
        self.terminal_checkpoint_artifact
    }

    #[must_use]
    pub const fn terminal_checkpoint_certificate_digest(&self) -> [u8; 32] {
        self.terminal_checkpoint_certificate
    }

    #[must_use]
    pub const fn semantic_transition_digest(&self) -> [u8; 32] {
        self.semantic_transition
    }

    /// Durable single-vote slot shared by all exact variants advertised for this serving source.
    #[must_use]
    pub const fn vote_slot_digest(&self) -> [u8; 32] {
        self.vote_slot
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
}

/// Non-serializable proof that this party authenticated the exact terminal ledger/checkpoint
/// artifacts and their post-CAS archive/index head before signing.
#[derive(Clone, Debug)]
pub struct VerifiedDepositPostHandoffExportCandidate {
    statement: DepositPostHandoffExportSealStatement,
}

impl VerifiedDepositPostHandoffExportCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_append<R: CompactRegistryObjectReader>(
        network: [u8; 32],
        source_party: PartyId,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        final_export: DepositStateExportBinding,
        advertisement: &DepositSyncAdvertisement,
        registry_reader: &R,
        append: &DepositArchiveAppend,
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<Self, DepositStateExportError> {
        Ok(Self {
            statement: DepositPostHandoffExportSealStatement::from_verified_append(
                network,
                source_party,
                source,
                handoff,
                target,
                final_export,
                advertisement,
                registry_reader,
                append,
                checkpoint,
            )?,
        })
    }

    /// Reconstruct one source-specific candidate solely from independently authenticated
    /// predecessor/target authority and exact content-addressed evidence.
    ///
    /// No serialized seal statement or certified export head is accepted as authority here. The
    /// caller supplies canonical decoded objects; this constructor verifies their exact content
    /// addresses, the terminal handoff ledger certificate, the active checkpoint certificate
    /// anchored at the advertised portable head, and the target-registry proof before minting the
    /// non-serializable candidate capability.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_remote_evidence<R: CompactRegistryObjectReader>(
        network: [u8; 32],
        source_party: PartyId,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
        target: &VerifiedRegistryHandoffTarget,
        advertisement: &DepositSyncAdvertisement,
        registry_reader: &R,
        archive_segment_reference: WalletArtifactRef,
        archive_segment: &DepositArchiveSegment,
        archive_event_reference: WalletArtifactRef,
        archive_event: DepositArchiveEvent,
        terminal_ledger_reference: WalletArtifactRef,
        terminal_ledger: &CertifiedLedgerEntry,
        checkpoint: &DepositIndexCheckpointCertificate,
    ) -> Result<Self, DepositStateExportError> {
        let final_export = DepositStateExportBinding::from_advertisement(advertisement)?;
        let archive_head = final_export.archive();
        let wallet = source.wallet();
        let segment_bytes = archive_segment
            .to_bytes()
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let event_bytes =
            archive_event.to_bytes().map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let ledger_bytes = terminal_ledger
            .to_bytes()
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let checkpoint_bytes =
            checkpoint.to_bytes().map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let checkpoint_reference = archive_event.checkpoint_reference();
        for (reference, kind, bytes) in [
            (
                archive_segment_reference,
                crate::deposit_archive::DEPOSIT_ARCHIVE_SEGMENT_ARTIFACT,
                segment_bytes.as_slice(),
            ),
            (archive_event_reference, DEPOSIT_ARCHIVE_EVENT_ARTIFACT, event_bytes.as_slice()),
            (terminal_ledger_reference, CERTIFIED_LEDGER_ENTRY_ARTIFACT, ledger_bytes.as_slice()),
            (
                checkpoint_reference,
                DEPOSIT_INDEX_CHECKPOINT_CERTIFICATE_ARTIFACT,
                checkpoint_bytes.as_slice(),
            ),
        ] {
            if reference.wallet_id() != WalletId(wallet.0) || reference.kind() != kind {
                return Err(DepositStateExportError::InvalidSealStatement);
            }
            reference
                .verify_contents(bytes)
                .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        }
        if archive_head.segment_reference() != Some(archive_segment_reference)
            || archive_head.event_reference() != Some(archive_event_reference)
            || archive_segment.wallet_id() != wallet
            || archive_segment.end_ordinal().ok() != Some(archive_head.len())
            || archive_segment.event_references().last().copied() != Some(archive_event_reference)
            || archive_event.wallet_id() != wallet
            || archive_event.ordinal().checked_add(1) != Some(archive_head.len())
            || archive_event.operation() != DepositArchiveOperation::Ledger
            || archive_event.operation_reference() != terminal_ledger_reference
            || terminal_ledger.statement.wallet != wallet
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }

        let verified_ledger = terminal_ledger
            .verify_active(source, None)
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        verified_ledger
            .verify_exact_certificate(terminal_ledger)
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let exact_handoff = terminal_ledger
            .registry_handoff_certificate(source)
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        if &exact_handoff != handoff {
            return Err(DepositStateExportError::InvalidSealStatement);
        }
        let verified_checkpoint = checkpoint
            .verify_active_anchored(
                network,
                source,
                None,
                terminal_ledger,
                final_export.resulting_portable_head(),
            )
            .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
        let checkpoint_statement = checkpoint.statement();
        let checkpoint_signers =
            checkpoint.witnesses().iter().map(|witness| witness.from).collect::<Vec<_>>();
        if checkpoint_statement.context() != verified_checkpoint.context()
            || checkpoint_statement.sequence() != verified_checkpoint.sequence()
            || checkpoint_statement.decision_digest() != verified_checkpoint.decision_digest()
            || checkpoint_statement.operation() != verified_checkpoint.operation()
            || checkpoint_statement.ledger_sequence() != verified_checkpoint.ledger_sequence()
            || checkpoint_statement.ledger_decision() != verified_checkpoint.ledger_decision()
            || checkpoint_statement.update_digest() != verified_checkpoint.update_digest()
            || checkpoint_statement.resulting_head() != verified_checkpoint.resulting_head()
            || checkpoint
                .certificate_digest()
                .map_err(|_| DepositStateExportError::InvalidSealStatement)?
                != verified_checkpoint.certificate_digest()
            || checkpoint_signers != verified_checkpoint.signers()
        {
            return Err(DepositStateExportError::InvalidSealStatement);
        }

        Ok(Self {
            statement: DepositPostHandoffExportSealStatement::from_verified_terminal(
                network,
                source_party,
                source,
                handoff,
                target,
                final_export,
                advertisement,
                registry_reader,
                VerifiedPostHandoffExportTerminal {
                    wallet,
                    checkpoint_sequence: checkpoint_statement.sequence(),
                    checkpoint_decision: checkpoint_statement.decision_digest(),
                    checkpoint_certificate: verified_checkpoint.certificate_digest(),
                    ledger_sequence: terminal_ledger.statement.sequence,
                    ledger_statement: terminal_ledger.statement.digest(),
                    event_artifact: archive_event_reference,
                    ledger_artifact: terminal_ledger_reference,
                    checkpoint_artifact: checkpoint_reference,
                },
                &verified_checkpoint,
            )?,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        &self.statement
    }

    pub(crate) fn sign_as_source(
        &self,
        identity: &dyn EnvelopeSigner,
        source: &CompactEpochRegistry,
        prepared_pin: &PreparedExportCandidatePin,
    ) -> Result<SignedEnvelope, DepositStateExportError> {
        self.statement.validate_intrinsic()?;
        prepared_pin
            .authorizes(self)
            .map_err(|_| DepositStateExportError::ExportNotDurablyPinned)?;
        if identity.party() != self.statement.source_party {
            return Err(DepositStateExportError::WrongSealSigner);
        }
        self.sign_after_authorization(identity, source)
    }

    pub(crate) fn sign_as_remote(
        &self,
        identity: &dyn EnvelopeSigner,
        source: &CompactEpochRegistry,
        verified_local_state: &VerifiedRemoteExportSealVoteGate,
    ) -> Result<SignedEnvelope, DepositStateExportError> {
        self.statement.validate_intrinsic()?;
        verified_local_state
            .authorize(self, identity.party())
            .map_err(|_| DepositStateExportError::RemoteExportStateNotVerified)?;
        self.sign_after_authorization(identity, source)
    }

    fn sign_after_authorization(
        &self,
        identity: &dyn EnvelopeSigner,
        source: &CompactEpochRegistry,
    ) -> Result<SignedEnvelope, DepositStateExportError> {
        if !matches!(identity.scope(), EnvelopeSignerScope::Full | EnvelopeSignerScope::HandoffOnly)
        {
            return Err(DepositStateExportError::WrongSealSigner);
        }
        let member = source
            .active()
            .committee()
            .member(identity.party())
            .map_err(|_| DepositStateExportError::WrongSealSigner)?;
        if source.id() != self.statement.source
            || member.signing_key != identity.signing_public_key()
        {
            return Err(DepositStateExportError::WrongSealSigner);
        }
        Ok(identity.sign_envelope(
            source.active().committee(),
            self.statement.session(),
            None,
            self.statement.final_export.terminal_checkpoint().sequence(),
            self.statement.signing_payload(),
        )?)
    }
}

/// Exact old-committee `n-f` certificate for one source-specific post-handoff export.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositPostHandoffExportSealCertificate {
    version: u16,
    statement: DepositPostHandoffExportSealStatement,
    #[serde(deserialize_with = "deserialize_seal_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl DepositPostHandoffExportSealCertificate {
    pub fn new(
        statement: DepositPostHandoffExportSealStatement,
        mut witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, DepositStateExportError> {
        statement.validate_intrinsic()?;
        witnesses.sort_by_key(|witness| witness.from);
        if witnesses.windows(2).any(|pair| pair[0].from == pair[1].from) {
            return Err(DepositStateExportError::DuplicateSealWitness);
        }
        Ok(Self { version: POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_VERSION, statement, witnesses })
    }

    pub fn verify(
        &self,
        source: &CompactEpochRegistry,
        handoff: &RegistryHandoffCertificate,
    ) -> Result<VerifiedDepositPostHandoffExportSeal, DepositStateExportError> {
        let canonical = self.to_bytes()?;
        self.statement.validate_against(source, handoff)?;
        let signers = self
            .verify_exact_witnesses(source.active().committee(), source.active().fault_bound())?;
        let certificate_digest =
            length_prefixed_hash(POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DOMAIN, &canonical);
        Ok(VerifiedDepositPostHandoffExportSeal {
            certificate: self.clone(),
            canonical,
            certificate_digest,
            signers,
        })
    }

    /// Verify only the old-quorum and globally authenticated epoch bindings required to bootstrap
    /// a cold target's bounded, read-only export download.
    ///
    /// This deliberately does not verify the compact-registry handoff and therefore cannot mint a
    /// [`VerifiedDepositPostHandoffExportSeal`]. The caller must load `source` and `target` from
    /// authenticated epoch history, and must upgrade through [`Self::verify`] against the frozen
    /// downloaded registry graph before any import, registry CAS, or state-imported
    /// acknowledgement.
    pub(crate) fn verify_pre_import(
        &self,
        network: [u8; 32],
        source: &EpochPublic,
        source_fault_bound: u16,
        source_certified_activation_root: [u8; 32],
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<VerifiedPreImportDepositStateExportSeal, DepositStateExportError> {
        let canonical = self.to_bytes()?;
        source.validate().map_err(|_| DepositStateExportError::InvalidSealCertificate)?;
        source
            .committee
            .validate_async_security_with_faults(source_fault_bound)
            .map_err(|_| DepositStateExportError::InvalidSealCertificate)?;
        target
            .committee()
            .validate_async_security_with_faults(target.fault_bound())
            .map_err(|_| DepositStateExportError::WrongSealTarget)?;

        let statement = self.statement();
        let source_epoch = source.committee.epoch;
        if network == [0; 32]
            || statement.network != network
            || source_certified_activation_root == [0; 32]
            || statement.source.wallet() != target.wallet()
            || statement.source.active_epoch() != source_epoch
            || source_epoch.checked_add(1) != Some(target.committee().epoch)
            || statement.source_committee != source.committee.digest()
            || statement.source_fault_bound != source_fault_bound
            || statement.source_certified_activation_root != source_certified_activation_root
            || source.key_id != target.key_id()
            || source.group_key_bytes() != target.group_key()
            || source.committee.member(statement.source_party).is_err()
        {
            return Err(DepositStateExportError::InvalidSealCertificate);
        }
        validate_seal_target(statement, target)?;
        statement
            .final_export
            .target_registry_archive()
            .registry()
            .verify_active_target(target)
            .map_err(|_| DepositStateExportError::WrongSealTarget)?;

        let signers = self.verify_exact_witnesses(&source.committee, source_fault_bound)?;
        let certificate_digest =
            length_prefixed_hash(POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DOMAIN, &canonical);
        Ok(VerifiedPreImportDepositStateExportSeal {
            certificate: self.clone(),
            canonical,
            certificate_digest,
            signers,
        })
    }

    fn verify_exact_witnesses(
        &self,
        committee: &Committee,
        fault_bound: u16,
    ) -> Result<Vec<PartyId>, DepositStateExportError> {
        committee
            .validate_async_security_with_faults(fault_bound)
            .map_err(|_| DepositStateExportError::InvalidSealCertificate)?;
        committee
            .member(self.statement.source_party)
            .map_err(|_| DepositStateExportError::InvalidSealCertificate)?;
        let required = committee
            .n()
            .checked_sub(fault_bound)
            .ok_or(DepositStateExportError::InvalidSealCertificate)?;
        if self.witnesses.len() != usize::from(required)
            || !self.witnesses.iter().any(|witness| witness.from == self.statement.source_party)
        {
            return Err(DepositStateExportError::WrongSealWitnessCount);
        }
        let verifier =
            committee.members.first().ok_or(DepositStateExportError::InvalidSealCertificate)?.id;
        let session = self.statement.session();
        let payload = self.statement.signing_payload();
        let sequence = self.statement.final_export.terminal_checkpoint().sequence();
        let mut signers = Vec::with_capacity(self.witnesses.len());
        let mut previous = None;
        for witness in &self.witnesses {
            if previous.is_some_and(|party| party >= witness.from)
                || witness.to.is_some()
                || witness.session != session
                || witness.sequence != sequence
                || witness.payload != payload
                || Identity::verify_envelope(committee, verifier, witness).is_err()
            {
                return Err(DepositStateExportError::InvalidSealCertificate);
            }
            signers.push(witness.from);
            previous = Some(witness.from);
        }
        Ok(signers)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositStateExportError> {
        if self.version != POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_VERSION {
            return Err(DepositStateExportError::InvalidSealCertificate);
        }
        self.statement.validate_intrinsic()?;
        if self.witnesses.len() > crate::committee::MAX_COMMITTEE_MEMBERS
            || self.witnesses.windows(2).any(|pair| pair[0].from >= pair[1].from)
        {
            return Err(DepositStateExportError::InvalidSealCertificate);
        }
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositStateExportError::Serialization)?;
        if bytes.is_empty() || bytes.len() > MAX_POST_HANDOFF_EXPORT_SEAL_BYTES {
            return Err(DepositStateExportError::SealCertificateTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositStateExportError> {
        if bytes.is_empty() || bytes.len() > MAX_POST_HANDOFF_EXPORT_SEAL_BYTES {
            return Err(DepositStateExportError::SealCertificateTooLarge);
        }
        let (certificate, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositStateExportError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositStateExportError::TrailingSealBytes);
        }
        if certificate.to_bytes()? != bytes {
            return Err(DepositStateExportError::NonCanonicalSeal);
        }
        Ok(certificate)
    }

    pub fn digest(&self) -> Result<[u8; 32], DepositStateExportError> {
        Ok(length_prefixed_hash(POST_HANDOFF_EXPORT_SEAL_CERTIFICATE_DOMAIN, &self.to_bytes()?))
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        &self.statement
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }
}

/// Fully old-quorum-authenticated exact source export. This capability is never deserializable.
#[derive(Clone, Debug)]
pub struct VerifiedDepositPostHandoffExportSeal {
    certificate: DepositPostHandoffExportSealCertificate,
    canonical: Vec<u8>,
    certificate_digest: [u8; 32],
    signers: Vec<PartyId>,
}

impl VerifiedDepositPostHandoffExportSeal {
    #[must_use]
    pub const fn certificate(&self) -> &DepositPostHandoffExportSealCertificate {
        &self.certificate
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        self.certificate.statement()
    }

    #[must_use]
    pub fn canonical_certificate_bytes(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement().digest()
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }

    pub fn validate_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateExportError> {
        validate_seal_target(self.statement(), target)
    }
}

/// Old-quorum-authenticated authority for bounded pre-import reads by a cold target.
///
/// This token is intentionally neither serializable nor convertible to
/// [`VerifiedDepositPostHandoffExportSeal`]. Its only consumers may durably prepare/replay the
/// exact export-head request and stage content-addressed graph objects. Full handoff and graph
/// verification remains mandatory before state adoption.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedPreImportDepositStateExportSeal {
    certificate: DepositPostHandoffExportSealCertificate,
    canonical: Vec<u8>,
    certificate_digest: [u8; 32],
    signers: Vec<PartyId>,
}

impl VerifiedPreImportDepositStateExportSeal {
    #[must_use]
    pub(crate) const fn certificate(&self) -> &DepositPostHandoffExportSealCertificate {
        &self.certificate
    }

    #[must_use]
    pub(crate) const fn statement(&self) -> &DepositPostHandoffExportSealStatement {
        self.certificate.statement()
    }

    #[must_use]
    pub(crate) fn canonical_certificate_bytes(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub(crate) const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub(crate) fn statement_digest(&self) -> [u8; 32] {
        self.statement().digest()
    }

    #[must_use]
    pub(crate) fn signers(&self) -> &[PartyId] {
        &self.signers
    }

    pub(crate) fn validate_target(
        &self,
        target: &VerifiedRegistryHandoffTarget,
    ) -> Result<(), DepositStateExportError> {
        target
            .committee()
            .validate_async_security_with_faults(target.fault_bound())
            .map_err(|_| DepositStateExportError::WrongSealTarget)?;
        validate_seal_target(self.statement(), target)?;
        self.statement()
            .final_export()
            .target_registry_archive()
            .registry()
            .verify_active_target(target)
            .map_err(|_| DepositStateExportError::WrongSealTarget)
    }
}

fn validate_seal_target(
    statement: &DepositPostHandoffExportSealStatement,
    target: &VerifiedRegistryHandoffTarget,
) -> Result<(), DepositStateExportError> {
    if target.wallet() != statement.source.wallet()
        || target.committee().epoch != statement.target_epoch
        || target.committee().digest() != statement.target_committee
        || target.key_id() != statement.target_key_id
        || target.group_key() != statement.target_group_key
        || target.fault_bound() != statement.target_fault_bound
        || target.activation() != statement.target_activation
        || target.certified_activation_root() != statement.target_certified_activation_root
    {
        return Err(DepositStateExportError::WrongSealTarget);
    }
    Ok(())
}

pub(crate) fn post_handoff_export_semantic_transition_digest(
    network: [u8; 32],
    source: RegistryId,
    source_certified_activation_root: [u8; 32],
    handoff_statement: [u8; 32],
    export_capability_context: [u8; 32],
    target_registry: RegistryId,
    terminal_checkpoint_decision: [u8; 32],
    portable: &PortableDepositIndexHead,
) -> Result<[u8; 32], DepositStateExportError> {
    portable
        .maximum_reachable_objects()
        .map_err(|_| DepositStateExportError::InvalidSealStatement)?;
    if network == [0; 32]
        || source_certified_activation_root == [0; 32]
        || handoff_statement == [0; 32]
        || export_capability_context == [0; 32]
        || target_registry.wallet() != source.wallet()
        || target_registry.active_epoch()
            != source
                .active_epoch()
                .checked_add(1)
                .ok_or(DepositStateExportError::InvalidSealStatement)?
        || terminal_checkpoint_decision == [0; 32]
        || portable.wallet_id() != source.wallet()
    {
        return Err(DepositStateExportError::InvalidSealStatement);
    }
    let portable_bytes =
        postcard::to_allocvec(portable).map_err(|_| DepositStateExportError::Serialization)?;
    let mut hasher = blake3::Hasher::new_derive_key(POST_HANDOFF_EXPORT_SEAL_SEMANTIC_DOMAIN);
    hasher.update(&network);
    hasher.update(&source.digest());
    hasher.update(&source_certified_activation_root);
    hasher.update(&handoff_statement);
    hasher.update(&export_capability_context);
    hasher.update(&target_registry.digest());
    hasher.update(&terminal_checkpoint_decision);
    hasher.update(&(portable_bytes.len() as u64).to_le_bytes());
    hasher.update(&portable_bytes);
    Ok(*hasher.finalize().as_bytes())
}

pub(crate) fn export_seal_vote_slot_digest(
    semantic_transition: [u8; 32],
    source_party: PartyId,
    target_epoch: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(POST_HANDOFF_EXPORT_SEAL_VOTE_SLOT_DOMAIN);
    hasher.update(&semantic_transition);
    hasher.update(&source_party.0.to_le_bytes());
    hasher.update(&target_epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn length_prefixed_hash(domain: &'static str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn deserialize_seal_witnesses<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SignedEnvelope>, D::Error> {
    struct SealWitnessVisitor;

    impl<'de> Visitor<'de> for SealWitnessVisitor {
        type Value = Vec<SignedEnvelope>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} post-handoff export seal witnesses",
                crate::committee::MAX_COMMITTEE_MEMBERS
            )
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let maximum = crate::committee::MAX_COMMITTEE_MEMBERS;
            if sequence.size_hint().is_some_and(|hint| hint > maximum) {
                return Err(A::Error::invalid_length(maximum.saturating_add(1), &self));
            }
            let mut witnesses = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(maximum));
            while let Some(witness) = sequence.next_element()? {
                if witnesses.len() == maximum {
                    return Err(A::Error::invalid_length(maximum.saturating_add(1), &self));
                }
                witnesses.push(witness);
            }
            Ok(witnesses)
        }
    }

    deserializer.deserialize_seq(SealWitnessVisitor)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DepositStateExportError {
    #[error("deposit handoff state binding is invalid")]
    InvalidHandoffBinding,
    #[error("deposit state export binding is invalid")]
    InvalidBinding,
    #[error("deposit state export binding serialization failed")]
    Serialization,
    #[error("post-handoff export seal statement is invalid")]
    InvalidSealStatement,
    #[error("post-handoff export seal certificate is invalid")]
    InvalidSealCertificate,
    #[error("post-handoff export seal signer is not authorized")]
    WrongSealSigner,
    #[error("post-handoff export candidate is not durably pinned before signing")]
    ExportNotDurablyPinned,
    #[error("remote post-handoff export vote lacks an exact reauthenticated local-state gate")]
    RemoteExportStateNotVerified,
    #[error("post-handoff export seal target differs from the trusted activation")]
    WrongSealTarget,
    #[error("post-handoff export seal witness appears more than once")]
    DuplicateSealWitness,
    #[error("post-handoff export seal has the wrong old-committee witness count")]
    WrongSealWitnessCount,
    #[error("post-handoff export seal certificate exceeds its allocation bound")]
    SealCertificateTooLarge,
    #[error("post-handoff export seal certificate has trailing bytes")]
    TrailingSealBytes,
    #[error("post-handoff export seal certificate encoding is not canonical")]
    NonCanonicalSeal,
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};

    use super::*;
    use crate::{
        deposit_state_transfer_wire::tests::{ExportEvidenceFixture, export_evidence_fixture},
        keys::PointBytes,
    };

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn source_identity(party: PartyId, epoch: u64) -> Identity {
        let value = u8::try_from(party.0).expect("test party fits u8");
        let mut signing_seed = [value; 32];
        signing_seed[0] ^= u8::try_from(epoch).expect("test epoch fits u8");
        Identity::from_test_secrets(party, epoch, &signing_seed, test_x25519_secret(party, epoch))
            .expect("test identity")
    }

    fn source_public(source: &CompactEpochRegistry) -> EpochPublic {
        let committee = source.active().committee().clone();
        assert_eq!(committee.threshold, 2, "fixture uses a linear sharing polynomial");
        let group_key = PointBytes(source.active().group_key());
        let group = group_key.parse().expect("fixture group key");
        let slope = ED25519_BASEPOINT_POINT * Scalar::from(7_u64);
        let verification_shares = (1..=committee.n())
            .map(|index| {
                let party = committee.party_for_frost_index(index).expect("test FROST index");
                let share = group + slope * Scalar::from(u64::from(index));
                (party, PointBytes::from(share))
            })
            .collect::<BTreeMap<_, _>>();
        let public = EpochPublic {
            key_id: source.active().key_id(),
            committee,
            verification_shares,
            group_key,
        };
        public.validate().expect("test epoch public");
        public
    }

    fn seal_vote(fixture: &ExportEvidenceFixture, party: PartyId) -> SignedEnvelope {
        let statement = fixture.candidate.statement();
        if party == statement.source_party() {
            return fixture.source_self_vote.clone();
        }
        source_identity(party, fixture.source.active_epoch())
            .sign_envelope(
                fixture.source.active().committee(),
                statement.session(),
                None,
                statement.final_export().terminal_checkpoint().sequence(),
                statement.signing_payload(),
            )
            .expect("test seal vote")
    }

    fn seal_certificate(
        fixture: &ExportEvidenceFixture,
        include_source: bool,
    ) -> DepositPostHandoffExportSealCertificate {
        let source_party = fixture.candidate.statement().source_party();
        let required = fixture
            .source
            .active()
            .committee()
            .n()
            .checked_sub(fixture.source.active().fault_bound())
            .expect("valid fixture fault bound");
        let witnesses = fixture
            .source
            .active()
            .committee()
            .members
            .iter()
            .map(|member| member.id)
            .filter(|party| include_source || *party != source_party)
            .take(usize::from(required))
            .map(|party| seal_vote(fixture, party))
            .collect();
        DepositPostHandoffExportSealCertificate::new(
            fixture.candidate.statement().clone(),
            witnesses,
        )
        .expect("test seal certificate")
    }

    fn target_with(
        fixture: &ExportEvidenceFixture,
        committee: Committee,
        certified_activation_root: [u8; 32],
    ) -> VerifiedRegistryHandoffTarget {
        VerifiedRegistryHandoffTarget::for_test(
            committee,
            fixture.target.fault_bound(),
            fixture.target.activation(),
            certified_activation_root,
            fixture.target.wallet(),
            fixture.target.key_id(),
            fixture.target.group_key(),
        )
        .expect("test target")
    }

    #[tokio::test]
    async fn cold_pre_import_seal_is_exact_and_distinct_from_full_import_authority() {
        let fixture = export_evidence_fixture().await;
        let source = source_public(&fixture.source);
        let certificate = seal_certificate(&fixture, true);
        let canonical = certificate.to_bytes().unwrap();
        let certificate = DepositPostHandoffExportSealCertificate::from_bytes(&canonical).unwrap();
        let source_root = fixture.source.active().certified_activation_root();

        let pre_import = certificate
            .verify_pre_import(
                fixture.network,
                &source,
                fixture.source.active().fault_bound(),
                source_root,
                &fixture.target,
            )
            .unwrap();
        let full = certificate.verify(&fixture.source, &fixture.handoff).unwrap();

        assert_eq!(pre_import.certificate(), &certificate);
        assert_eq!(pre_import.statement(), certificate.statement());
        assert_eq!(pre_import.canonical_certificate_bytes(), canonical);
        assert_eq!(pre_import.certificate_digest(), certificate.digest().unwrap());
        assert_eq!(pre_import.statement_digest(), certificate.statement().digest());
        assert_eq!(pre_import.signers(), full.signers());
        pre_import.validate_target(&fixture.target).unwrap();
    }

    #[tokio::test]
    async fn cold_pre_import_seal_rejects_wrong_authority_epoch_and_witnesses() {
        let fixture = export_evidence_fixture().await;
        let source = source_public(&fixture.source);
        let source_fault_bound = fixture.source.active().fault_bound();
        let source_root = fixture.source.active().certified_activation_root();
        let certificate = seal_certificate(&fixture, true);

        assert!(
            certificate
                .verify_pre_import(fixture.network, &source, 0, source_root, &fixture.target,)
                .is_err()
        );
        assert!(
            certificate
                .verify_pre_import(
                    fixture.network,
                    &source,
                    source_fault_bound,
                    [0xa1; 32],
                    &fixture.target,
                )
                .is_err()
        );

        let mut wrong_source_committee = source.clone();
        let first = wrong_source_committee.committee.members[0].signing_key;
        wrong_source_committee.committee.members[0].signing_key =
            wrong_source_committee.committee.members[1].signing_key;
        wrong_source_committee.committee.members[1].signing_key = first;
        wrong_source_committee.validate().unwrap();
        assert!(
            certificate
                .verify_pre_import(
                    fixture.network,
                    &wrong_source_committee,
                    source_fault_bound,
                    source_root,
                    &fixture.target,
                )
                .is_err()
        );

        let mut wrong_source_key = source.clone();
        wrong_source_key.key_id = [0xa2; 32];
        wrong_source_key.validate().unwrap();
        assert!(
            certificate
                .verify_pre_import(
                    fixture.network,
                    &wrong_source_key,
                    source_fault_bound,
                    source_root,
                    &fixture.target,
                )
                .is_err()
        );

        let wrong_target_root =
            target_with(&fixture, fixture.target.committee().clone(), [0xa3; 32]);
        assert!(
            certificate
                .verify_pre_import(
                    fixture.network,
                    &source,
                    source_fault_bound,
                    source_root,
                    &wrong_target_root,
                )
                .is_err()
        );

        let mut wrong_target_committee = fixture.target.committee().clone();
        wrong_target_committee.epoch = wrong_target_committee.epoch.checked_add(1).unwrap();
        let wrong_target = target_with(
            &fixture,
            wrong_target_committee,
            fixture.target.certified_activation_root(),
        );
        assert!(
            certificate
                .verify_pre_import(
                    fixture.network,
                    &source,
                    source_fault_bound,
                    source_root,
                    &wrong_target,
                )
                .is_err()
        );

        let mut wrong_network = fixture.network;
        wrong_network[0] ^= 1;
        assert!(
            certificate
                .verify_pre_import(
                    wrong_network,
                    &source,
                    source_fault_bound,
                    source_root,
                    &fixture.target,
                )
                .is_err()
        );

        let missing_source_vote = seal_certificate(&fixture, false);
        assert!(matches!(
            missing_source_vote.verify_pre_import(
                fixture.network,
                &source,
                source_fault_bound,
                source_root,
                &fixture.target,
            ),
            Err(DepositStateExportError::WrongSealWitnessCount)
        ));

        let mut bad_signature = certificate.clone();
        bad_signature.witnesses[0].signature[0] ^= 1;
        assert!(matches!(
            bad_signature.verify_pre_import(
                fixture.network,
                &source,
                source_fault_bound,
                source_root,
                &fixture.target,
            ),
            Err(DepositStateExportError::InvalidSealCertificate)
        ));

        let mut wrong_source_epoch = source;
        wrong_source_epoch.committee.epoch =
            wrong_source_epoch.committee.epoch.checked_add(1).unwrap();
        wrong_source_epoch.validate().unwrap();
        assert!(
            certificate
                .verify_pre_import(
                    fixture.network,
                    &wrong_source_epoch,
                    source_fault_bound,
                    source_root,
                    &fixture.target,
                )
                .is_err()
        );
    }
}
