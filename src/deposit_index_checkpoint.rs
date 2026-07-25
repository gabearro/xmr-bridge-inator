//! Current-format quorum checkpoints for the portable deposit index.
//!
//! A checkpoint certifies public logical state, never a party's local CAS journal. In particular,
//! [`DepositIndexHead::revision`](crate::deposit_index::DepositIndexHead::revision), staged object
//! manifests, and witness selection are excluded from every decision digest. This lets honest
//! replicas with different local revisions converge on one checkpoint.

use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    compact_epoch_registry::{
        ActiveIssuer, CompactEpochRegistry, CompactRegistryError, VerifiedIssuerWindow,
    },
    deposit_consensus::{
        CommitCertificate, ConsensusBinding, ConsensusContext, ConsensusError, ConsensusValue,
    },
    deposit_index::{
        DepositIndexError, DepositIndexHead, DepositIndexNamespace, DepositIndexObjectId,
        DepositIndexReader, DepositIndexUpdate, SignedIndexCheckpointSlot,
        VerifiedDepositIndexPreflight, VerifiedDepositObservationIndexTransition,
    },
    deposit_index_store::VerifiedSignedIndexCheckpointSlot,
    deposit_ledger::{
        CertifiedDepositObservation, CertifiedLedgerEntry, CompactLedgerCursor, LedgerError,
        LedgerPayload, LedgerStatement, genesis_head as ledger_genesis_head,
    },
    deposit_wallet::{DepositSubaddressIndex, DepositWalletId},
    identity::{Identity, IdentityError, SignedEnvelope},
};

const LOGICAL_HEAD_VERSION: u16 = 1;
const CONTEXT_VERSION: u16 = 1;
const STATEMENT_VERSION: u16 = 1;
const CERTIFICATE_VERSION: u16 = 2;
const CONSENSUS_VALUE_VERSION: u16 = 1;
const MAX_STATEMENT_BYTES: usize = 4 * 1024;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_SIGNING_TIMESTAMP: u64 = 253_402_300_799;
const CHECKPOINT_SESSION_DOMAIN: &[u8] = b"deposit-index-checkpoint-slot/v1";
const HEAD_DIGEST_DOMAIN: &str = "threshold-monero/deposit-index/head/v1";
const CONTEXT_DIGEST_DOMAIN: &str = "threshold-monero/deposit-index-checkpoint-context/v1";
const UPDATE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-index-semantic-update/v1";
const DECISION_DIGEST_DOMAIN: &str = "threshold-monero/deposit-index-checkpoint-decision/v1";
const CERTIFICATE_DIGEST_DOMAIN: &str = "threshold-monero/deposit-index-checkpoint-certificate/v2";
const CHECKPOINT_CONSENSUS_APPLICATION: &[u8] = b"deposit-index-checkpoint/v1";
const CHECKPOINT_CONSENSUS_DOMAIN: &str =
    "threshold-monero/deposit-index-checkpoint-consensus-domain/v1";
const CHECKPOINT_CONSENSUS_SESSION_DOMAIN: &str =
    "threshold-monero/deposit-index-checkpoint-consensus-session/v1";

/// The deposit ledger's current n-f decision certificate.
pub type LedgerCertificate = CertifiedLedgerEntry;

/// One independently authorized operation competing for the next portable-index checkpoint.
///
/// The complete authority certificate is carried inside the Byzantine-agreement value. A
/// terminal BA certificate can therefore initialize a lagging reducer which never observed the
/// candidate gossip, without trusting arrival order or an unauthenticated operation digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositIndexCheckpointCandidate {
    Ledger(CertifiedLedgerEntry),
    DepositObservation(CertifiedDepositObservation),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositIndexCheckpointConsensusValue {
    version: u16,
    candidate: DepositIndexCheckpointCandidate,
}

impl DepositIndexCheckpointCandidate {
    /// Encode this complete authority certificate as one canonical opaque BA value.
    pub fn to_consensus_value(&self) -> Result<ConsensusValue, DepositIndexCheckpointError> {
        let value = DepositIndexCheckpointConsensusValue {
            version: CONSENSUS_VALUE_VERSION,
            candidate: self.clone(),
        };
        Ok(ConsensusValue::new(
            postcard::to_allocvec(&value)
                .map_err(|_| DepositIndexCheckpointError::Serialization)?,
        )?)
    }

    /// Decode one canonical checkpoint-operation BA value.
    pub fn from_consensus_value(
        value: &ConsensusValue,
    ) -> Result<Self, DepositIndexCheckpointError> {
        value.validate()?;
        let (decoded, trailing) =
            postcard::take_from_bytes::<DepositIndexCheckpointConsensusValue>(value.as_bytes())
                .map_err(|_| DepositIndexCheckpointError::Serialization)?;
        if !trailing.is_empty()
            || decoded.version != CONSENSUS_VALUE_VERSION
            || postcard::to_allocvec(&decoded)
                .map_err(|_| DepositIndexCheckpointError::Serialization)?
                != value.as_bytes()
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        Ok(decoded.candidate)
    }

    #[must_use]
    pub fn operation(&self) -> DepositIndexCheckpointOperation {
        match self {
            Self::Ledger(entry) => {
                DepositIndexCheckpointOperation::Ledger { statement: entry.statement.digest() }
            }
            Self::DepositObservation(observation) => {
                DepositIndexCheckpointOperation::DepositObservation {
                    statement: observation.statement.digest(),
                }
            }
        }
    }

    fn verify_active(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<(), DepositIndexCheckpointError> {
        match self {
            Self::Ledger(entry) => {
                entry.verify_active(registry, historical_issuer)?;
            }
            Self::DepositObservation(observation) => {
                let verified = observation.verify_active(registry)?;
                if verified.signers().len() != usize::from(verified.required()) {
                    return Err(DepositIndexCheckpointError::InvalidSelection);
                }
            }
        }
        Ok(())
    }

    fn verify_archived(
        &self,
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<(), DepositIndexCheckpointError> {
        match self {
            Self::Ledger(entry) => {
                entry.verify(issuer_window, historical_issuer)?;
            }
            Self::DepositObservation(observation) => {
                let verified = observation.verify(issuer_window)?;
                if verified.signers().len() != usize::from(verified.required()) {
                    return Err(DepositIndexCheckpointError::InvalidSelection);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LogicalAnchor {
    through_sequence: u64,
    ledger_head: [u8; 32],
    next_index: DepositSubaddressIndex,
}

/// Consensus-safe representation of a complete portable index head.
///
/// The full root artifact reference is retained, while the party-local CAS revision is
/// deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableDepositIndexHead {
    version: u16,
    namespace: DepositIndexNamespace,
    entries: u64,
    records: u64,
    root: Option<DepositIndexObjectId>,
    anchor: LogicalAnchor,
    digest: [u8; 32],
}

impl PortableDepositIndexHead {
    /// Project a local head into its witness-independent portable representation.
    pub fn from_head(head: &DepositIndexHead) -> Result<Self, DepositIndexCheckpointError> {
        let DepositIndexNamespace::Portable { .. } = head.namespace() else {
            return Err(DepositIndexCheckpointError::InvalidLogicalHead);
        };
        let anchor =
            head.portable_anchor().ok_or(DepositIndexCheckpointError::InvalidLogicalHead)?;
        let logical = Self {
            version: LOGICAL_HEAD_VERSION,
            namespace: head.namespace(),
            entries: head.entry_count(),
            records: head.record_count(),
            root: head.root(),
            anchor: LogicalAnchor {
                through_sequence: anchor.through_sequence(),
                ledger_head: anchor.ledger_head(),
                next_index: anchor.next_index(),
            },
            digest: head.digest(),
        };
        logical.validate()?;
        Ok(logical)
    }

    /// Check a local head against every signed logical field. Local revision is ignored.
    pub fn matches(&self, head: &DepositIndexHead) -> Result<bool, DepositIndexCheckpointError> {
        self.validate()?;
        Ok(self == &Self::from_head(head)?)
    }

    fn validate(&self) -> Result<(), DepositIndexCheckpointError> {
        let DepositIndexNamespace::Portable { wallet } = self.namespace else {
            return Err(DepositIndexCheckpointError::InvalidLogicalHead);
        };
        if self.version != LOGICAL_HEAD_VERSION
            || wallet.0 == [0; 32]
            || self.anchor.ledger_head == [0; 32]
            || self.anchor.through_sequence == u64::MAX
            || (self.entries == 0) != self.root.is_none()
            || (self.entries == 0) != (self.records == 0)
            || self.records > self.entries
            || if self.root.is_none() {
                self.anchor.through_sequence != 0
                    || self.anchor.ledger_head != ledger_genesis_head(wallet)
            } else {
                self.anchor.through_sequence == 0
            }
        {
            return Err(DepositIndexCheckpointError::InvalidLogicalHead);
        }
        if let Some(root) = self.root {
            if root.wallet_id() != wallet
                || DepositIndexObjectId::from_storage_reference(root.storage_reference())? != root
            {
                return Err(DepositIndexCheckpointError::InvalidLogicalHead);
            }
        }
        if self.digest != logical_head_digest(self)? {
            return Err(DepositIndexCheckpointError::InvalidLogicalHead);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.namespace.wallet()
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
    pub const fn through_sequence(&self) -> u64 {
        self.anchor.through_sequence
    }

    #[must_use]
    pub const fn ledger_head(&self) -> [u8; 32] {
        self.anchor.ledger_head
    }

    #[must_use]
    pub const fn next_index(&self) -> DepositSubaddressIndex {
        self.anchor.next_index
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Reconstruct the revision-zero index head used for bounded proof-path loading.
    ///
    /// The signed logical digest is checked again after reconstruction, so party-local revision
    /// state can never be injected through a portable checkpoint.
    pub fn to_index_head(&self) -> Result<DepositIndexHead, DepositIndexCheckpointError> {
        self.validate()?;
        let head = DepositIndexHead::from_portable_components(
            self.wallet_id(),
            self.entries,
            self.records,
            self.root,
            self.anchor.through_sequence,
            self.anchor.ledger_head,
            self.anchor.next_index,
        )?;
        if head.digest() != self.digest {
            return Err(DepositIndexCheckpointError::InvalidLogicalHead);
        }
        Ok(head)
    }
}

fn logical_head_digest(
    head: &PortableDepositIndexHead,
) -> Result<[u8; 32], DepositIndexCheckpointError> {
    // This exactly mirrors DepositIndexHead::digest's current logical input. Struct field names
    // are not encoded by postcard; field order and types are intentionally identical.
    #[derive(Serialize)]
    struct LogicalHeadCommitment {
        version: u16,
        namespace: DepositIndexNamespace,
        entries: u64,
        records: u64,
        root: Option<DepositIndexObjectId>,
        portable_anchor: Option<LogicalAnchor>,
    }
    let bytes = postcard::to_allocvec(&LogicalHeadCommitment {
        version: LOGICAL_HEAD_VERSION,
        namespace: head.namespace,
        entries: head.entries,
        records: head.records,
        root: head.root,
        portable_anchor: Some(head.anchor),
    })
    .map_err(|_| DepositIndexCheckpointError::Serialization)?;
    Ok(length_prefixed_hash(HEAD_DIGEST_DOMAIN, &bytes))
}

fn checkpoint_consensus_domain() -> [u8; 32] {
    *blake3::Hasher::new_derive_key(CHECKPOINT_CONSENSUS_DOMAIN).finalize().as_bytes()
}

fn checkpoint_consensus_session(
    binding: &ConsensusBinding,
    committee: &Committee,
    fault_bound: u16,
    checkpoint_sequence: u64,
    previous_head: [u8; 32],
) -> Result<SessionId, DepositIndexCheckpointError> {
    let mut hasher = blake3::Hasher::new_derive_key(CHECKPOINT_CONSENSUS_SESSION_DOMAIN);
    hasher.update(&binding.domain);
    hasher.update(&(binding.application.len() as u64).to_le_bytes());
    hasher.update(&binding.application);
    hasher.update(&binding.wallet);
    hasher.update(&binding.network);
    hasher.update(&binding.registry);
    hasher.update(&binding.activation);
    hasher.update(&committee.digest());
    hasher.update(&fault_bound.to_le_bytes());
    hasher.update(&checkpoint_sequence.to_le_bytes());
    hasher.update(&previous_head);
    let session = SessionId(*hasher.finalize().as_bytes());
    if session.0 == [0; 32] {
        return Err(DepositIndexCheckpointError::InvalidSelection);
    }
    Ok(session)
}

fn checkpoint_consensus_context_for_issuer(
    network: [u8; 32],
    issuer: &ActiveIssuer,
    checkpoint_sequence: u64,
    previous_head: [u8; 32],
) -> Result<ConsensusContext, DepositIndexCheckpointError> {
    if network == [0; 32] || checkpoint_sequence == 0 || previous_head == [0; 32] {
        return Err(DepositIndexCheckpointError::InvalidSelection);
    }
    let binding = ConsensusBinding {
        domain: checkpoint_consensus_domain(),
        application: CHECKPOINT_CONSENSUS_APPLICATION.to_vec(),
        wallet: issuer.wallet().0,
        network,
        registry: issuer.registry_id().digest(),
        activation: issuer.activation_binding(),
    };
    let session = checkpoint_consensus_session(
        &binding,
        issuer.committee(),
        issuer.fault_bound(),
        checkpoint_sequence,
        previous_head,
    )?;
    Ok(ConsensusContext::new(
        binding,
        session,
        issuer.committee().clone(),
        issuer.fault_bound(),
        checkpoint_sequence,
        checkpoint_sequence,
        previous_head,
    )?)
}

/// Construct the sole current-format Byzantine-agreement context for the next checkpoint slot.
pub fn deposit_index_checkpoint_consensus_context(
    network: [u8; 32],
    registry: &CompactEpochRegistry,
    checkpoint_sequence: u64,
    previous_head: &PortableDepositIndexHead,
) -> Result<ConsensusContext, DepositIndexCheckpointError> {
    previous_head.validate()?;
    if registry.wallet() != previous_head.wallet_id() {
        return Err(DepositIndexCheckpointError::InvalidSelection);
    }
    deposit_index_checkpoint_consensus_context_from_digest(
        network,
        registry,
        checkpoint_sequence,
        previous_head.digest(),
    )
}

/// Digest-only form used by a restored reducer whose authenticated portable head is held by the
/// outer index-store checkpoint.
pub fn deposit_index_checkpoint_consensus_context_from_digest(
    network: [u8; 32],
    registry: &CompactEpochRegistry,
    checkpoint_sequence: u64,
    previous_head: [u8; 32],
) -> Result<ConsensusContext, DepositIndexCheckpointError> {
    registry.validate()?;
    checkpoint_consensus_context_for_issuer(
        network,
        registry.active(),
        checkpoint_sequence,
        previous_head,
    )
}

/// Exact deployment and issuer context repeated in every checkpoint decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointContext {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    registry: [u8; 32],
    activation: [u8; 32],
    epoch: u64,
    committee: [u8; 32],
    committee_size: u16,
    threshold: u16,
    fault_bound: u16,
}

impl DepositIndexCheckpointContext {
    fn expected_active(
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        ledger: &LedgerCertificate,
    ) -> Result<Self, DepositIndexCheckpointError> {
        if network == [0; 32] {
            return Err(DepositIndexCheckpointError::InvalidNetwork);
        }
        registry.validate()?;
        ledger.verify_active(registry, historical_issuer)?;
        Self::expected_for_issuer(network, registry.active(), ledger)
    }

    fn expected_archived(
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        ledger: &LedgerCertificate,
    ) -> Result<Self, DepositIndexCheckpointError> {
        if network == [0; 32] {
            return Err(DepositIndexCheckpointError::InvalidNetwork);
        }
        issuer_window.validate()?;
        ledger.verify(issuer_window, historical_issuer)?;
        Self::expected_for_issuer(network, issuer_window.issuer(), ledger)
    }

    fn expected_active_observation(
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        observation: &CertifiedDepositObservation,
    ) -> Result<Self, DepositIndexCheckpointError> {
        if network == [0; 32] {
            return Err(DepositIndexCheckpointError::InvalidNetwork);
        }
        registry.validate()?;
        let verified = observation.verify_active(registry)?;
        if verified.signers().len() != usize::from(verified.required()) {
            return Err(DepositIndexCheckpointError::WrongObservationDecision);
        }
        Self::expected_for_observation_issuer(network, registry.active(), observation)
    }

    fn expected_archived_observation(
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        observation: &CertifiedDepositObservation,
    ) -> Result<Self, DepositIndexCheckpointError> {
        if network == [0; 32] {
            return Err(DepositIndexCheckpointError::InvalidNetwork);
        }
        issuer_window.validate()?;
        let verified = observation.verify(issuer_window)?;
        if verified.signers().len() != usize::from(verified.required()) {
            return Err(DepositIndexCheckpointError::WrongObservationDecision);
        }
        Self::expected_for_observation_issuer(network, issuer_window.issuer(), observation)
    }

    fn expected_for_issuer(
        network: [u8; 32],
        issuer: &ActiveIssuer,
        ledger: &LedgerCertificate,
    ) -> Result<Self, DepositIndexCheckpointError> {
        let committee = issuer.committee();
        let context = Self {
            version: CONTEXT_VERSION,
            wallet: ledger.statement.wallet,
            network,
            registry: issuer.registry_id().digest(),
            activation: ledger.statement.issuer_activation,
            epoch: ledger.statement.issuer_epoch,
            committee: ledger.statement.issuer_committee,
            committee_size: committee.n(),
            threshold: committee.threshold,
            fault_bound: issuer.fault_bound(),
        };
        context.validate_static()?;
        if context.activation != issuer.activation()
            || context.committee != committee.digest()
            || context.wallet != issuer.wallet()
            || context.epoch != issuer.epoch()
        {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(context)
    }

    fn expected_for_observation_issuer(
        network: [u8; 32],
        issuer: &ActiveIssuer,
        observation: &CertifiedDepositObservation,
    ) -> Result<Self, DepositIndexCheckpointError> {
        let statement = &observation.statement;
        let committee = issuer.committee();
        let context = Self {
            version: CONTEXT_VERSION,
            wallet: statement.wallet_id(),
            network,
            registry: issuer.registry_id().digest(),
            activation: statement.issuer_activation(),
            epoch: statement.issuer_epoch(),
            committee: statement.issuer_committee(),
            committee_size: committee.n(),
            threshold: committee.threshold,
            fault_bound: issuer.fault_bound(),
        };
        context.validate_static()?;
        if context.activation != issuer.activation()
            || context.committee != committee.digest()
            || context.wallet != issuer.wallet()
            || context.epoch != issuer.epoch()
        {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(context)
    }

    fn validate_static(&self) -> Result<(), DepositIndexCheckpointError> {
        if self.version != CONTEXT_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.registry == [0; 32]
            || self.activation == [0; 32]
            || self.committee == [0; 32]
            || self.committee_size == 0
            || usize::from(self.committee_size) > MAX_COMMITTEE_MEMBERS
            || self.threshold == 0
            || self.threshold > self.committee_size
            || self.committee_size < self.fault_bound.saturating_mul(3).saturating_add(1)
        {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(())
    }

    fn validate_exact_active(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        ledger: &LedgerCertificate,
    ) -> Result<(), DepositIndexCheckpointError> {
        if self != &Self::expected_active(network, registry, historical_issuer, ledger)? {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(())
    }

    fn validate_exact_archived(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        ledger: &LedgerCertificate,
    ) -> Result<(), DepositIndexCheckpointError> {
        if self != &Self::expected_archived(network, issuer_window, historical_issuer, ledger)? {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(())
    }

    fn validate_exact_active_observation(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositIndexCheckpointError> {
        if self != &Self::expected_active_observation(network, registry, observation)? {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(())
    }

    fn validate_exact_archived_observation(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositIndexCheckpointError> {
        if self != &Self::expected_archived_observation(network, issuer_window, observation)? {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        Ok(())
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry
    }

    #[must_use]
    pub const fn activation_digest(&self) -> [u8; 32] {
        self.activation
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn committee_digest(&self) -> [u8; 32] {
        self.committee
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub const fn quorum(&self) -> u16 {
        self.committee_size - self.fault_bound
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("checkpoint context serialization");
        length_prefixed_hash(CONTEXT_DIGEST_DOMAIN, &bytes)
    }
}

/// Authentication mode for the immediately preceding logical head.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositIndexCheckpointParent {
    /// Allowed only for sequence one over the empty ledger/index genesis head.
    Genesis,
    /// Witness-independent decision digest of the verified preceding checkpoint.
    Certified { decision: [u8; 32] },
}

/// Exactly one portable operation ordered by a checkpoint decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DepositIndexCheckpointOperation {
    /// One globally ordered ledger statement advanced the portable ledger anchor.
    Ledger { statement: [u8; 32] },
    /// One independently certified confirmed-output observation changed only portable aliases.
    DepositObservation { statement: [u8; 32] },
}

impl DepositIndexCheckpointOperation {
    fn validate(self) -> Result<(), DepositIndexCheckpointError> {
        let statement = match self {
            Self::Ledger { statement } | Self::DepositObservation { statement } => statement,
        };
        if statement == [0; 32] {
            return Err(DepositIndexCheckpointError::InvalidTransition);
        }
        Ok(())
    }

    #[must_use]
    pub const fn statement_digest(self) -> [u8; 32] {
        match self {
            Self::Ledger { statement } | Self::DepositObservation { statement } => statement,
        }
    }
}

/// One witness-independent, post-ledger index decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointStatement {
    version: u16,
    context: DepositIndexCheckpointContext,
    checkpoint_sequence: u64,
    parent: DepositIndexCheckpointParent,
    previous_head: PortableDepositIndexHead,
    operation: DepositIndexCheckpointOperation,
    ledger_sequence: u64,
    ledger_decision: [u8; 32],
    update_digest: [u8; 32],
    resulting_head: PortableDepositIndexHead,
}

impl DepositIndexCheckpointStatement {
    /// Admit a fresh signing reservation and reconstruct its sole checkpoint statement.
    ///
    /// Allocation admission is accepted only strictly before its client-visible creation time.
    /// After this succeeds, persist [`Self::signing_slot`] with the same `now`.
    pub fn for_transition<R: DepositIndexReader + ?Sized>(
        now: u64,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
        preflight: &VerifiedDepositIndexPreflight,
        update: &DepositIndexUpdate,
        reader: &R,
    ) -> Result<Self, DepositIndexCheckpointError> {
        let statement = Self::reconstruct_transition(
            network,
            registry,
            historical_issuer,
            previous,
            ledger,
            preflight,
            update,
            reader,
        )?;
        statement.validate_timely_signing_admission(now, ledger)?;
        Ok(statement)
    }

    /// Deterministically reconstruct the portable decision without applying a wall-clock
    /// admission rule. This is used only after an exact persisted signing reservation has been
    /// authenticated; fresh reservations must enter through [`Self::for_transition`].
    #[allow(clippy::too_many_arguments)]
    fn reconstruct_transition<R: DepositIndexReader + ?Sized>(
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
        preflight: &VerifiedDepositIndexPreflight,
        update: &DepositIndexUpdate,
        reader: &R,
    ) -> Result<Self, DepositIndexCheckpointError> {
        // Deterministically replay the complete local journal, but never place its bytes or local
        // revisions in the portable decision.
        let verified_update =
            update.verify_ledger_transition_for_preflight(reader, &ledger.statement, preflight)?;
        let context = DepositIndexCheckpointContext::expected_active(
            network,
            registry,
            historical_issuer,
            ledger,
        )?;
        let previous_head = PortableDepositIndexHead::from_head(verified_update.expected_head())?;
        let resulting_head = PortableDepositIndexHead::from_head(verified_update.resulting_head())?;
        let (checkpoint_sequence, parent) = Self::next_parent(previous)?;
        let ledger_decision = ledger.statement.digest();
        let operation = DepositIndexCheckpointOperation::Ledger { statement: ledger_decision };
        let update_digest = semantic_update_digest(
            &previous_head,
            checkpoint_sequence,
            operation,
            ledger.statement.sequence,
            ledger_decision,
            &resulting_head,
        );
        let statement = Self {
            version: STATEMENT_VERSION,
            context,
            checkpoint_sequence,
            parent,
            previous_head,
            operation,
            ledger_sequence: ledger.statement.sequence,
            ledger_decision,
            update_digest,
            resulting_head,
        };
        statement.validate_exact_active(network, registry, historical_issuer, previous, ledger)?;
        Ok(statement)
    }

    fn next_parent(
        previous: Option<&VerifiedDepositIndexCheckpoint>,
    ) -> Result<(u64, DepositIndexCheckpointParent), DepositIndexCheckpointError> {
        match previous {
            None => Ok((1, DepositIndexCheckpointParent::Genesis)),
            Some(previous) => Ok((
                previous
                    .sequence
                    .checked_add(1)
                    .ok_or(DepositIndexCheckpointError::InvalidTransition)?,
                DepositIndexCheckpointParent::Certified { decision: previous.decision },
            )),
        }
    }

    /// Reverify this portable statement against one exact local semantic transition without
    /// reapplying fresh-reservation wall-clock admission.
    ///
    /// This is the certificate adoption/recovery path. Timeliness is already carried by the n-f
    /// witness set whose honest members required durable pre-deadline signing reservations.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_transition<R: DepositIndexReader + ?Sized>(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
        preflight: &VerifiedDepositIndexPreflight,
        update: &DepositIndexUpdate,
        reader: &R,
    ) -> Result<(), DepositIndexCheckpointError> {
        if self
            != &Self::reconstruct_transition(
                network,
                registry,
                historical_issuer,
                previous,
                ledger,
                preflight,
                update,
                reader,
            )?
        {
            return Err(DepositIndexCheckpointError::WrongExpectedStatement);
        }
        Ok(())
    }

    /// Admit a fresh observation-checkpoint reservation under the current active issuer.
    pub fn for_deposit_observation_transition(
        now: u64,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> Result<Self, DepositIndexCheckpointError> {
        Self::validate_signing_time(now)?;
        Self::reconstruct_deposit_observation_transition(
            network,
            registry,
            previous,
            observation,
            transition,
        )
    }

    fn reconstruct_deposit_observation_transition(
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> Result<Self, DepositIndexCheckpointError> {
        observation.verify_active(registry)?;
        if transition.observation_statement() != observation.statement.digest() {
            return Err(DepositIndexCheckpointError::WrongObservationDecision);
        }
        let context = DepositIndexCheckpointContext::expected_active_observation(
            network,
            registry,
            observation,
        )?;
        let previous_head = PortableDepositIndexHead::from_head(transition.expected_head())?;
        let resulting_head = PortableDepositIndexHead::from_head(transition.resulting_head())?;
        let (checkpoint_sequence, parent) = Self::next_parent(previous)?;
        let operation = DepositIndexCheckpointOperation::DepositObservation {
            statement: observation.statement.digest(),
        };
        let ledger_sequence = resulting_head.through_sequence();
        let ledger_decision = resulting_head.ledger_head();
        let update_digest = semantic_update_digest(
            &previous_head,
            checkpoint_sequence,
            operation,
            ledger_sequence,
            ledger_decision,
            &resulting_head,
        );
        let statement = Self {
            version: STATEMENT_VERSION,
            context,
            checkpoint_sequence,
            parent,
            previous_head,
            operation,
            ledger_sequence,
            ledger_decision,
            update_digest,
            resulting_head,
        };
        statement.validate_exact_active_deposit_observation(
            network,
            registry,
            previous,
            observation,
            transition,
        )?;
        Ok(statement)
    }

    /// Reverify an observation checkpoint against the exact certified observation and
    /// semantically verified observation-only index transition.
    pub fn verify_deposit_observation_transition(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> Result<(), DepositIndexCheckpointError> {
        if self
            != &Self::reconstruct_deposit_observation_transition(
                network,
                registry,
                previous,
                observation,
                transition,
            )?
        {
            return Err(DepositIndexCheckpointError::WrongExpectedStatement);
        }
        Ok(())
    }

    /// Enforce the local signer deadline without placing wall-clock state in the portable
    /// checkpoint decision. Certificate verification remains time-independent.
    fn validate_timely_signing_admission(
        &self,
        now: u64,
        ledger: &LedgerCertificate,
    ) -> Result<(), DepositIndexCheckpointError> {
        Self::validate_signing_time(now)?;
        if let LedgerPayload::Allocation(allocation) = &ledger.statement.payload
            && now >= allocation.created_at
        {
            return Err(DepositIndexCheckpointError::AllocationCheckpointDeadlineElapsed);
        }
        Ok(())
    }

    fn validate_signing_time(now: u64) -> Result<(), DepositIndexCheckpointError> {
        if now == 0 || now > MAX_SIGNING_TIMESTAMP {
            return Err(DepositIndexCheckpointError::InvalidSigningTime);
        }
        Ok(())
    }

    fn validate_internal(&self) -> Result<(), DepositIndexCheckpointError> {
        if self.version != STATEMENT_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        self.context.validate_static()?;
        self.operation.validate()?;
        self.previous_head.validate()?;
        self.resulting_head.validate()?;
        if self.checkpoint_sequence == 0
            || self.previous_head.wallet_id() != self.context.wallet
            || self.resulting_head.wallet_id() != self.context.wallet
            || self.resulting_head.through_sequence() != self.ledger_sequence
            || self.resulting_head.ledger_head() != self.ledger_decision
            || self.resulting_head.entry_count() < self.previous_head.entry_count()
            || self.resulting_head.record_count() < self.previous_head.record_count()
            || self.update_digest
                != semantic_update_digest(
                    &self.previous_head,
                    self.checkpoint_sequence,
                    self.operation,
                    self.ledger_sequence,
                    self.ledger_decision,
                    &self.resulting_head,
                )
        {
            return Err(DepositIndexCheckpointError::InvalidTransition);
        }
        match self.operation {
            DepositIndexCheckpointOperation::Ledger { statement } => {
                if statement != self.ledger_decision
                    || self.previous_head.through_sequence().checked_add(1)
                        != Some(self.ledger_sequence)
                {
                    return Err(DepositIndexCheckpointError::InvalidTransition);
                }
            }
            DepositIndexCheckpointOperation::DepositObservation { .. } => {
                if self.ledger_sequence == 0
                    || !matches!(self.parent, DepositIndexCheckpointParent::Certified { .. })
                    || self.previous_head.through_sequence() != self.ledger_sequence
                    || self.previous_head.ledger_head() != self.ledger_decision
                    || self.previous_head.next_index() != self.resulting_head.next_index()
                {
                    return Err(DepositIndexCheckpointError::InvalidTransition);
                }
            }
        }
        match self.parent {
            DepositIndexCheckpointParent::Genesis => {
                if self.checkpoint_sequence != 1
                    || self.previous_head.through_sequence() != 0
                    || self.previous_head.ledger_head() != ledger_genesis_head(self.context.wallet)
                    || self.previous_head.entry_count() != 0
                    || self.previous_head.record_count() != 0
                    || self.previous_head.root().is_some()
                {
                    return Err(DepositIndexCheckpointError::WrongParent);
                }
            }
            DepositIndexCheckpointParent::Certified { decision } => {
                if self.checkpoint_sequence == 1 || decision == [0; 32] {
                    return Err(DepositIndexCheckpointError::WrongParent);
                }
            }
        }
        Ok(())
    }

    fn validate_exact_active(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.context.validate_exact_active(network, registry, historical_issuer, ledger)?;
        self.validate_exact_for_issuer(registry.active(), previous, ledger)
    }

    fn validate_exact_archived(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.context.validate_exact_archived(network, issuer_window, historical_issuer, ledger)?;
        self.validate_exact_for_issuer(issuer_window.issuer(), previous, ledger)
    }

    fn validate_anchored_archived(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        ledger: &LedgerCertificate,
        authenticated_current_head: &PortableDepositIndexHead,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.context.validate_exact_archived(network, issuer_window, historical_issuer, ledger)?;
        self.validate_anchored_for_issuer(
            issuer_window.issuer(),
            ledger,
            authenticated_current_head,
        )
    }

    fn validate_exact_for_issuer(
        &self,
        issuer: &ActiveIssuer,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.validate_internal()?;
        if self.operation
            != (DepositIndexCheckpointOperation::Ledger { statement: ledger.statement.digest() })
            || self.ledger_sequence != ledger.statement.sequence
            || self.ledger_decision != ledger.statement.digest()
            || self.previous_head.ledger_head() != ledger.statement.previous
        {
            return Err(DepositIndexCheckpointError::WrongLedgerDecision);
        }
        self.validate_parent_for_issuer(issuer, previous)
    }

    fn validate_parent_for_issuer(
        &self,
        issuer: &ActiveIssuer,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
    ) -> Result<(), DepositIndexCheckpointError> {
        match (self.parent, previous) {
            (DepositIndexCheckpointParent::Genesis, None)
                if issuer.epoch() == 0
                    && issuer.start_sequence() == 1
                    && issuer.first_index() == self.previous_head.next_index() => {}
            (DepositIndexCheckpointParent::Certified { decision }, Some(previous))
                if decision == previous.decision
                    && self.previous_head == previous.resulting_head
                    && previous.context.wallet == self.context.wallet
                    && previous.context.network == self.context.network
                    && previous.sequence.checked_add(1) == Some(self.checkpoint_sequence) => {}
            _ => return Err(DepositIndexCheckpointError::WrongParent),
        }
        Ok(())
    }

    fn validate_exact_active_deposit_observation(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.validate_exact_active_deposit_observation_certificate(
            network,
            registry,
            previous,
            observation,
        )?;
        let expected_head = PortableDepositIndexHead::from_head(transition.expected_head())?;
        let resulting_head = PortableDepositIndexHead::from_head(transition.resulting_head())?;
        if transition.observation_statement() != observation.statement.digest()
            || self.previous_head != expected_head
            || self.resulting_head != resulting_head
        {
            return Err(DepositIndexCheckpointError::WrongObservationDecision);
        }
        Ok(())
    }

    fn validate_exact_active_deposit_observation_certificate(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.context.validate_exact_active_observation(network, registry, observation)?;
        self.validate_exact_deposit_observation_for_issuer(registry.active(), previous, observation)
    }

    fn validate_exact_archived_deposit_observation(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.context.validate_exact_archived_observation(network, issuer_window, observation)?;
        self.validate_exact_deposit_observation_for_issuer(
            issuer_window.issuer(),
            previous,
            observation,
        )
    }

    fn validate_exact_deposit_observation_for_issuer(
        &self,
        issuer: &ActiveIssuer,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.validate_internal()?;
        if self.operation
            != (DepositIndexCheckpointOperation::DepositObservation {
                statement: observation.statement.digest(),
            })
            || !matches!(self.parent, DepositIndexCheckpointParent::Certified { .. })
        {
            return Err(DepositIndexCheckpointError::WrongObservationDecision);
        }
        self.validate_parent_for_issuer(issuer, previous)
    }

    fn validate_anchored_deposit_observation_for_issuer(
        &self,
        observation: &CertifiedDepositObservation,
        authenticated_current_head: &PortableDepositIndexHead,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.validate_internal()?;
        authenticated_current_head.validate()?;
        if self.operation
            != (DepositIndexCheckpointOperation::DepositObservation {
                statement: observation.statement.digest(),
            })
            || &self.resulting_head != authenticated_current_head
            || !matches!(self.parent, DepositIndexCheckpointParent::Certified { .. })
        {
            return Err(DepositIndexCheckpointError::WrongObservationDecision);
        }
        Ok(())
    }

    /// Validate a bounded latest-checkpoint proof against an independently authenticated current
    /// portable head. The signed parent decision remains committed by this statement, but callers
    /// need not replay the preceding checkpoint-certificate prefix.
    fn validate_anchored_for_issuer(
        &self,
        issuer: &ActiveIssuer,
        ledger: &LedgerCertificate,
        authenticated_current_head: &PortableDepositIndexHead,
    ) -> Result<(), DepositIndexCheckpointError> {
        self.validate_internal()?;
        authenticated_current_head.validate()?;
        if self.operation
            != (DepositIndexCheckpointOperation::Ledger { statement: ledger.statement.digest() })
            || self.ledger_sequence != ledger.statement.sequence
            || self.ledger_decision != ledger.statement.digest()
            || self.previous_head.ledger_head() != ledger.statement.previous
        {
            return Err(DepositIndexCheckpointError::WrongLedgerDecision);
        }
        if &self.resulting_head != authenticated_current_head {
            return Err(DepositIndexCheckpointError::WrongAuthenticatedHead);
        }
        if self.ledger_sequence == issuer.start_sequence()
            && (self.previous_head.ledger_head() != issuer.predecessor_ledger_head()
                || self.previous_head.next_index() != issuer.first_index())
        {
            return Err(DepositIndexCheckpointError::WrongParent);
        }
        match self.parent {
            DepositIndexCheckpointParent::Genesis
                if issuer.epoch() == 0
                    && issuer.start_sequence() == 1
                    && issuer.first_index() == self.previous_head.next_index() => {}
            DepositIndexCheckpointParent::Certified { .. } => {}
            _ => return Err(DepositIndexCheckpointError::WrongParent),
        }
        Ok(())
    }

    /// Sign only after independently reconstructing the exact ledger-to-index transition and
    /// consuming a durable-readback authorization for this party's exact checkpoint slot.
    ///
    /// `now` may be later than an allocation's creation time during crash recovery. Timely
    /// admission is established by the authenticated slot's immutable `reserved_at`, never by
    /// replacing it with the retry clock.
    fn sign_expected<R: DepositIndexReader + ?Sized>(
        &self,
        now: u64,
        identity: &Identity,
        authorization: &VerifiedSignedIndexCheckpointSlot,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
        preflight: &VerifiedDepositIndexPreflight,
        update: &DepositIndexUpdate,
        reader: &R,
    ) -> Result<SignedEnvelope, DepositIndexCheckpointError> {
        Self::validate_signing_time(now)?;
        self.verify_transition(
            network,
            registry,
            historical_issuer,
            previous,
            ledger,
            preflight,
            update,
            reader,
        )?;
        let reserved_at = authorization.reserved_at();
        if now < reserved_at {
            return Err(DepositIndexCheckpointError::InvalidSigningTime);
        }
        self.validate_timely_signing_admission(reserved_at, ledger)?;
        if !authorization.authorizes(
            self.context.wallet,
            identity.party(),
            self.signing_slot(reserved_at)?,
        ) {
            return Err(DepositIndexCheckpointError::UncommittedSigningSlot);
        }
        Ok(identity.sign_envelope(
            registry.active().committee(),
            self.slot_session(),
            None,
            self.checkpoint_sequence,
            self.to_bytes()?,
        )?)
    }

    fn sign_expected_deposit_observation(
        &self,
        now: u64,
        identity: &Identity,
        authorization: &VerifiedSignedIndexCheckpointSlot,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> Result<SignedEnvelope, DepositIndexCheckpointError> {
        Self::validate_signing_time(now)?;
        self.verify_deposit_observation_transition(
            network,
            registry,
            previous,
            observation,
            transition,
        )?;
        let reserved_at = authorization.reserved_at();
        Self::validate_signing_time(reserved_at)?;
        if now < reserved_at {
            return Err(DepositIndexCheckpointError::InvalidSigningTime);
        }
        if !authorization.authorizes(
            self.context.wallet,
            identity.party(),
            self.signing_slot(reserved_at)?,
        ) {
            return Err(DepositIndexCheckpointError::UncommittedSigningSlot);
        }
        Ok(identity.sign_envelope(
            registry.active().committee(),
            self.slot_session(),
            None,
            self.checkpoint_sequence,
            self.to_bytes()?,
        )?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexCheckpointError> {
        self.validate_internal()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositIndexCheckpointError::Serialization)?;
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(DepositIndexCheckpointError::StatementTooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexCheckpointError> {
        if bytes.is_empty() || bytes.len() > MAX_STATEMENT_BYTES {
            return Err(DepositIndexCheckpointError::StatementTooLarge);
        }
        let (statement, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexCheckpointError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexCheckpointError::TrailingBytes);
        }
        statement.validate_internal()?;
        if statement.to_bytes()? != bytes {
            return Err(DepositIndexCheckpointError::NonCanonicalEncoding);
        }
        Ok(statement)
    }

    #[must_use]
    pub fn slot_session(&self) -> SessionId {
        let mut material = Vec::with_capacity(72);
        material.extend_from_slice(&self.context.digest());
        material.extend_from_slice(&self.checkpoint_sequence.to_le_bytes());
        SessionId::derive(CHECKPOINT_SESSION_DOMAIN, &material)
    }

    #[must_use]
    pub fn decision_digest(&self) -> [u8; 32] {
        let bytes = postcard::to_allocvec(self).expect("checkpoint statement serialization");
        length_prefixed_hash(DECISION_DIGEST_DOMAIN, &bytes)
    }

    /// Exact party-local tombstone which must be committed before this statement can be signed.
    ///
    /// `reserved_at` is the current time accepted by [`Self::for_transition`] on the first
    /// admission. Retried signing must authenticate and reuse this exact serialized value.
    pub fn signing_slot(
        &self,
        reserved_at: u64,
    ) -> Result<SignedIndexCheckpointSlot, DepositIndexCheckpointError> {
        self.validate_internal()?;
        Ok(SignedIndexCheckpointSlot::new(
            self.checkpoint_sequence,
            self.ledger_decision,
            self.previous_head.digest(),
            self.resulting_head.digest(),
            self.decision_digest(),
            reserved_at,
        )?)
    }

    #[must_use]
    pub const fn context(&self) -> &DepositIndexCheckpointContext {
        &self.context
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    #[must_use]
    pub const fn parent(&self) -> DepositIndexCheckpointParent {
        self.parent
    }

    #[must_use]
    pub const fn operation(&self) -> DepositIndexCheckpointOperation {
        self.operation
    }

    #[must_use]
    pub const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn ledger_decision(&self) -> [u8; 32] {
        self.ledger_decision
    }

    #[must_use]
    pub const fn update_digest(&self) -> [u8; 32] {
        self.update_digest
    }

    #[must_use]
    pub const fn previous_head(&self) -> &PortableDepositIndexHead {
        &self.previous_head
    }

    #[must_use]
    pub const fn resulting_head(&self) -> &PortableDepositIndexHead {
        &self.resulting_head
    }
}

/// Produce the semantic transition digest shared by replicas with different local journals.
#[must_use]
pub fn semantic_update_digest(
    previous: &PortableDepositIndexHead,
    checkpoint_sequence: u64,
    operation: DepositIndexCheckpointOperation,
    ledger_sequence: u64,
    ledger_decision: [u8; 32],
    resulting: &PortableDepositIndexHead,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(UPDATE_DIGEST_DOMAIN);
    hasher.update(&STATEMENT_VERSION.to_le_bytes());
    hasher.update(&previous.wallet_id().0);
    hasher.update(&checkpoint_sequence.to_le_bytes());
    match operation {
        DepositIndexCheckpointOperation::Ledger { statement } => {
            hasher.update(&[0]);
            hasher.update(&statement);
        }
        DepositIndexCheckpointOperation::DepositObservation { statement } => {
            hasher.update(&[1]);
            hasher.update(&statement);
        }
    }
    hasher.update(&ledger_sequence.to_le_bytes());
    hasher.update(&ledger_decision);
    hasher.update(&previous.digest());
    hasher.update(&previous.through_sequence().to_le_bytes());
    hasher.update(&previous.ledger_head());
    hasher.update(&resulting.digest());
    hasher.update(&resulting.through_sequence().to_le_bytes());
    hasher.update(&resulting.ledger_head());
    *hasher.finalize().as_bytes()
}

/// Sign and return the deterministic statement plus this party's witness.
///
/// This is the retained-slot path. `now` is the retry clock; the allocation deadline is checked
/// against the authenticated slot's original reservation time.
pub fn sign_checkpoint_transition<R: DepositIndexReader + ?Sized>(
    now: u64,
    identity: &Identity,
    authorization: &VerifiedSignedIndexCheckpointSlot,
    network: [u8; 32],
    registry: &CompactEpochRegistry,
    historical_issuer: Option<&VerifiedIssuerWindow>,
    previous: Option<&VerifiedDepositIndexCheckpoint>,
    ledger: &LedgerCertificate,
    preflight: &VerifiedDepositIndexPreflight,
    update: &DepositIndexUpdate,
    reader: &R,
) -> Result<(DepositIndexCheckpointStatement, SignedEnvelope), DepositIndexCheckpointError> {
    let statement = DepositIndexCheckpointStatement::reconstruct_transition(
        network,
        registry,
        historical_issuer,
        previous,
        ledger,
        preflight,
        update,
        reader,
    )?;
    let witness = statement.sign_expected(
        now,
        identity,
        authorization,
        network,
        registry,
        historical_issuer,
        previous,
        ledger,
        preflight,
        update,
        reader,
    )?;
    Ok((statement, witness))
}

/// Sign one observation-only checkpoint using its exact durable anti-equivocation slot.
#[allow(clippy::too_many_arguments)]
pub fn sign_deposit_observation_checkpoint_transition(
    now: u64,
    identity: &Identity,
    authorization: &VerifiedSignedIndexCheckpointSlot,
    network: [u8; 32],
    registry: &CompactEpochRegistry,
    previous: Option<&VerifiedDepositIndexCheckpoint>,
    observation: &CertifiedDepositObservation,
    transition: &VerifiedDepositObservationIndexTransition,
) -> Result<(DepositIndexCheckpointStatement, SignedEnvelope), DepositIndexCheckpointError> {
    let statement = DepositIndexCheckpointStatement::reconstruct_deposit_observation_transition(
        network,
        registry,
        previous,
        observation,
        transition,
    )?;
    let witness = statement.sign_expected_deposit_observation(
        now,
        identity,
        authorization,
        network,
        registry,
        previous,
        observation,
        transition,
    )?;
    Ok((statement, witness))
}

/// Exact, canonically ordered n-f issuer witnesses for one post-state decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositIndexCheckpointCertificate {
    version: u16,
    statement: DepositIndexCheckpointStatement,
    /// Byzantine-agreed complete operation authority. Checkpoint witnesses sign the deterministic
    /// statement produced by this selected operation; retaining the commit certificate makes
    /// catch-up independent of a party's losing or absent local proposal lane.
    selection: CommitCertificate,
    #[serde(deserialize_with = "deserialize_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl DepositIndexCheckpointCertificate {
    pub fn from_witnesses(
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
        statement: DepositIndexCheckpointStatement,
        selection: CommitCertificate,
        witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, DepositIndexCheckpointError> {
        let certificate = Self { version: CERTIFICATE_VERSION, statement, selection, witnesses };
        certificate.verify_active(network, registry, historical_issuer, previous, ledger)?;
        Ok(certificate)
    }

    pub fn from_deposit_observation_witnesses(
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
        statement: DepositIndexCheckpointStatement,
        selection: CommitCertificate,
        witnesses: Vec<SignedEnvelope>,
    ) -> Result<Self, DepositIndexCheckpointError> {
        let certificate = Self { version: CERTIFICATE_VERSION, statement, selection, witnesses };
        certificate.verify_active_deposit_observation(network, registry, previous, observation)?;
        Ok(certificate)
    }

    fn verify_active_selection(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<DepositIndexCheckpointCandidate, DepositIndexCheckpointError> {
        let context = deposit_index_checkpoint_consensus_context(
            network,
            registry,
            self.statement.sequence(),
            self.statement.previous_head(),
        )?;
        self.selection.verify(&context)?;
        let candidate =
            DepositIndexCheckpointCandidate::from_consensus_value(self.selection.value())?;
        candidate.verify_active(registry, historical_issuer)?;
        if candidate.operation() != self.statement.operation() {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        Ok(candidate)
    }

    fn verify_archived_selection(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<DepositIndexCheckpointCandidate, DepositIndexCheckpointError> {
        issuer_window.validate()?;
        let context = checkpoint_consensus_context_for_issuer(
            network,
            issuer_window.issuer(),
            self.statement.sequence(),
            self.statement.previous_head().digest(),
        )?;
        self.selection.verify(&context)?;
        let candidate =
            DepositIndexCheckpointCandidate::from_consensus_value(self.selection.value())?;
        candidate.verify_archived(issuer_window, historical_issuer)?;
        if candidate.operation() != self.statement.operation() {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        Ok(candidate)
    }

    /// Verify a live decision against the compact active issuer.
    pub fn verify_active(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_active_selection(network, registry, historical_issuer)?
            != DepositIndexCheckpointCandidate::Ledger(ledger.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.validate_exact_active(
            network,
            registry,
            historical_issuer,
            previous,
            ledger,
        )?;
        self.verify_for_issuer(registry.active())
    }

    /// Verify a retained decision against one independently authenticated archive window.
    pub fn verify_archived(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        ledger: &LedgerCertificate,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_archived_selection(network, issuer_window, historical_issuer)?
            != DepositIndexCheckpointCandidate::Ledger(ledger.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.validate_exact_archived(
            network,
            issuer_window,
            historical_issuer,
            previous,
            ledger,
        )?;
        self.verify_for_issuer(issuer_window.issuer())
    }

    /// Verify an observation-only decision against the current compact active issuer.
    pub fn verify_active_deposit_observation(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_active_selection(network, registry, None)?
            != DepositIndexCheckpointCandidate::DepositObservation(observation.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.validate_exact_active_deposit_observation_certificate(
            network,
            registry,
            previous,
            observation,
        )?;
        self.verify_for_issuer(registry.active())
    }

    /// Verify a retained observation-only decision against its authenticated historical issuer.
    pub fn verify_archived_deposit_observation(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        previous: Option<&VerifiedDepositIndexCheckpoint>,
        observation: &CertifiedDepositObservation,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_archived_selection(network, issuer_window, None)?
            != DepositIndexCheckpointCandidate::DepositObservation(observation.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.validate_exact_archived_deposit_observation(
            network,
            issuer_window,
            previous,
            observation,
        )?;
        self.verify_for_issuer(issuer_window.issuer())
    }

    /// Verify the latest observation checkpoint against the active issuer and exact current head
    /// without replaying the preceding checkpoint prefix.
    pub fn verify_active_deposit_observation_anchored(
        &self,
        network: [u8; 32],
        registry: &CompactEpochRegistry,
        observation: &CertifiedDepositObservation,
        authenticated_current_head: &PortableDepositIndexHead,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_active_selection(network, registry, None)?
            != DepositIndexCheckpointCandidate::DepositObservation(observation.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.context.validate_exact_active_observation(network, registry, observation)?;
        self.statement.validate_anchored_deposit_observation_for_issuer(
            observation,
            authenticated_current_head,
        )?;
        self.verify_for_issuer(registry.active())
    }

    /// Historical-issuer form of
    /// [`Self::verify_active_deposit_observation_anchored`].
    pub fn verify_archived_deposit_observation_anchored(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        observation: &CertifiedDepositObservation,
        authenticated_current_head: &PortableDepositIndexHead,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_archived_selection(network, issuer_window, None)?
            != DepositIndexCheckpointCandidate::DepositObservation(observation.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.context.validate_exact_archived_observation(
            network,
            issuer_window,
            observation,
        )?;
        self.statement.validate_anchored_deposit_observation_for_issuer(
            observation,
            authenticated_current_head,
        )?;
        self.verify_for_issuer(issuer_window.issuer())
    }

    /// Verify the latest retained decision against an authenticated issuer window and exact
    /// current portable head, without replaying the preceding checkpoint-certificate prefix.
    ///
    /// `authenticated_current_head` must come from the caller's independently authenticated
    /// archive/index snapshot. This method verifies its exact equality to the n-f signed result.
    pub fn verify_anchored(
        &self,
        network: [u8; 32],
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        ledger: &LedgerCertificate,
        authenticated_current_head: &PortableDepositIndexHead,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        if self.verify_archived_selection(network, issuer_window, historical_issuer)?
            != DepositIndexCheckpointCandidate::Ledger(ledger.clone())
        {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        self.statement.validate_anchored_archived(
            network,
            issuer_window,
            historical_issuer,
            ledger,
            authenticated_current_head,
        )?;
        self.verify_for_issuer(issuer_window.issuer())
    }

    fn verify_for_issuer(
        &self,
        issuer: &ActiveIssuer,
    ) -> Result<VerifiedDepositIndexCheckpoint, DepositIndexCheckpointError> {
        self.validate_witness_shape()?;
        let payload = self.statement.to_bytes()?;
        let session = self.statement.slot_session();
        let mut signers = Vec::with_capacity(self.witnesses.len());
        for witness in &self.witnesses {
            Identity::verify_envelope(issuer.committee(), witness.from, witness)?;
            if witness.to.is_some()
                || witness.session != session
                || witness.sequence != self.statement.checkpoint_sequence
                || witness.payload != payload
            {
                return Err(DepositIndexCheckpointError::InvalidWitness);
            }
            signers.push(witness.from);
        }
        Ok(VerifiedDepositIndexCheckpoint {
            context: self.statement.context.clone(),
            sequence: self.statement.checkpoint_sequence,
            decision: self.statement.decision_digest(),
            certificate: self.certificate_digest()?,
            operation: self.statement.operation,
            ledger_sequence: self.statement.ledger_sequence,
            ledger_decision: self.statement.ledger_decision,
            update_digest: self.statement.update_digest,
            resulting_head: self.statement.resulting_head.clone(),
            signers,
        })
    }

    fn validate_witness_shape(&self) -> Result<(), DepositIndexCheckpointError> {
        self.statement.validate_internal()?;
        self.selection.value().validate()?;
        let candidate =
            DepositIndexCheckpointCandidate::from_consensus_value(self.selection.value())?;
        if candidate.operation() != self.statement.operation() {
            return Err(DepositIndexCheckpointError::InvalidSelection);
        }
        let required = usize::from(self.statement.context.quorum());
        if self.witnesses.len() != required {
            return Err(DepositIndexCheckpointError::WrongWitnessCount {
                actual: self.witnesses.len(),
                required,
            });
        }
        if self.witnesses.windows(2).any(|pair| pair[0].from >= pair[1].from) {
            return Err(DepositIndexCheckpointError::NonCanonicalWitnesses);
        }
        let expected_payload = self.statement.to_bytes()?;
        if self.witnesses.iter().any(|witness| {
            witness.to.is_some()
                || witness.session != self.statement.slot_session()
                || witness.sequence != self.statement.checkpoint_sequence
                || witness.payload != expected_payload
        }) {
            return Err(DepositIndexCheckpointError::InvalidWitness);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, DepositIndexCheckpointError> {
        if self.version != CERTIFICATE_VERSION {
            return Err(DepositIndexCheckpointError::UnsupportedVersion);
        }
        self.validate_witness_shape()?;
        let bytes =
            postcard::to_allocvec(self).map_err(|_| DepositIndexCheckpointError::Serialization)?;
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(DepositIndexCheckpointError::CertificateTooLarge);
        }
        Ok(bytes)
    }

    /// Witness-set-specific digest of this exact canonical certificate artifact.
    ///
    /// Unlike the statement decision, this distinguishes different valid n-f witness subsets and
    /// lets an archive capability remain bound to the exact certificate which was verified.
    pub fn certificate_digest(&self) -> Result<[u8; 32], DepositIndexCheckpointError> {
        let bytes = self.to_bytes()?;
        Ok(length_prefixed_hash(CERTIFICATE_DIGEST_DOMAIN, &bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DepositIndexCheckpointError> {
        if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(DepositIndexCheckpointError::CertificateTooLarge);
        }
        let (certificate, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| DepositIndexCheckpointError::Serialization)?;
        if !trailing.is_empty() {
            return Err(DepositIndexCheckpointError::TrailingBytes);
        }
        certificate.validate_witness_shape()?;
        if certificate.to_bytes()? != bytes {
            return Err(DepositIndexCheckpointError::NonCanonicalEncoding);
        }
        Ok(certificate)
    }

    #[must_use]
    pub const fn statement(&self) -> &DepositIndexCheckpointStatement {
        &self.statement
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }

    /// The portable BA certificate which selected this checkpoint's complete operation.
    #[must_use]
    pub const fn selection(&self) -> &CommitCertificate {
        &self.selection
    }

    /// Decode the selected complete authority certificate after canonical shape validation.
    pub fn selected_candidate(
        &self,
    ) -> Result<DepositIndexCheckpointCandidate, DepositIndexCheckpointError> {
        DepositIndexCheckpointCandidate::from_consensus_value(self.selection.value())
    }
}

/// Trusted output of full certificate verification. It is intentionally not deserializable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositIndexCheckpoint {
    context: DepositIndexCheckpointContext,
    sequence: u64,
    decision: [u8; 32],
    certificate: [u8; 32],
    operation: DepositIndexCheckpointOperation,
    ledger_sequence: u64,
    ledger_decision: [u8; 32],
    update_digest: [u8; 32],
    resulting_head: PortableDepositIndexHead,
    signers: Vec<PartyId>,
}

impl VerifiedDepositIndexCheckpoint {
    #[must_use]
    pub const fn context(&self) -> &DepositIndexCheckpointContext {
        &self.context
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn decision_digest(&self) -> [u8; 32] {
        self.decision
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate
    }

    #[must_use]
    pub const fn operation(&self) -> DepositIndexCheckpointOperation {
        self.operation
    }

    #[must_use]
    pub const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn ledger_decision(&self) -> [u8; 32] {
        self.ledger_decision
    }

    #[must_use]
    pub const fn update_digest(&self) -> [u8; 32] {
        self.update_digest
    }

    #[must_use]
    pub const fn resulting_head(&self) -> &PortableDepositIndexHead {
        &self.resulting_head
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }

    /// Restore the bounded live cursor from this authenticated logical head.
    ///
    /// A checkpoint issued by the current registry must carry that exact registry identity. The
    /// terminal checkpoint of the immediately preceding issuer is also accepted at the new
    /// activation boundary, where the successor binds its ledger predecessor and first index.
    pub fn compact_cursor(
        &self,
        registry: &CompactEpochRegistry,
        last_statement: Option<&LedgerStatement>,
    ) -> Result<CompactLedgerCursor, DepositIndexCheckpointError> {
        registry.validate()?;
        if self.context.wallet_id() != registry.wallet() {
            return Err(DepositIndexCheckpointError::WrongContext);
        }
        if self.context.registry_digest() != registry.digest() {
            let active = registry.active();
            if active.start_sequence()
                != self
                    .ledger_sequence
                    .checked_add(1)
                    .ok_or(DepositIndexCheckpointError::InvalidTransition)?
                || active.predecessor_ledger_head() != self.ledger_decision
                || active.first_index() != self.resulting_head.next_index()
            {
                return Err(DepositIndexCheckpointError::WrongContext);
            }
        }
        Ok(CompactLedgerCursor::from_authenticated_portable_head(
            registry,
            &self.resulting_head,
            last_statement,
        )?)
    }
}

fn deserialize_witnesses<'de, D>(deserializer: D) -> Result<Vec<SignedEnvelope>, D::Error>
where
    D: Deserializer<'de>,
{
    struct WitnessVisitor;

    impl<'de> Visitor<'de> for WitnessVisitor {
        type Value = Vec<SignedEnvelope>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded vector of checkpoint witnesses")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut witnesses = Vec::new();
            while let Some(witness) = sequence.next_element()? {
                if witnesses.len() == MAX_COMMITTEE_MEMBERS {
                    return Err(A::Error::custom("too many checkpoint witnesses"));
                }
                witnesses.push(witness);
            }
            Ok(witnesses)
        }
    }

    deserializer.deserialize_seq(WitnessVisitor)
}

fn length_prefixed_hash(domain: &'static str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error)]
pub enum DepositIndexCheckpointError {
    #[error("compact registry error: {0}")]
    CompactRegistry(#[from] CompactRegistryError),
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("checkpoint-operation consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),
    #[error("deposit index error: {0}")]
    DepositIndex(#[from] DepositIndexError),
    #[error("checkpoint format version is unsupported")]
    UnsupportedVersion,
    #[error("checkpoint network identifier must be nonzero")]
    InvalidNetwork,
    #[error("checkpoint logical head is malformed")]
    InvalidLogicalHead,
    #[error("checkpoint context differs from the authenticated ledger issuer context")]
    WrongContext,
    #[error("checkpoint does not bind the supplied committed ledger decision")]
    WrongLedgerDecision,
    #[error("checkpoint does not bind the supplied certified deposit observation")]
    WrongObservationDecision,
    #[error("checkpoint does not carry the Byzantine-agreed complete operation authority")]
    InvalidSelection,
    #[error("checkpoint result differs from the independently authenticated current index head")]
    WrongAuthenticatedHead,
    #[error("checkpoint does not extend the verified preceding checkpoint")]
    WrongParent,
    #[error("checkpoint transition is malformed or non-monotonic")]
    InvalidTransition,
    #[error("checkpoint statement differs from the independently reconstructed transition")]
    WrongExpectedStatement,
    #[error("checkpoint signing time is invalid")]
    InvalidSigningTime,
    #[error("allocation checkpoint signing did not complete before client-visible creation time")]
    AllocationCheckpointDeadlineElapsed,
    #[error("checkpoint signing slot has not been committed and authenticated for this party")]
    UncommittedSigningSlot,
    #[error("checkpoint has {actual} witnesses; exact n-f quorum requires {required}")]
    WrongWitnessCount { actual: usize, required: usize },
    #[error("checkpoint witnesses are not strictly ordered by unique party ID")]
    NonCanonicalWitnesses,
    #[error("checkpoint witness is not bound to the exact context and statement")]
    InvalidWitness,
    #[error("checkpoint statement exceeds its current-format size bound")]
    StatementTooLarge,
    #[error("checkpoint certificate exceeds its current-format size bound")]
    CertificateTooLarge,
    #[error("checkpoint serialization failed")]
    Serialization,
    #[error("checkpoint encoding has trailing bytes")]
    TrailingBytes,
    #[error("checkpoint encoding is not canonical")]
    NonCanonicalEncoding,
}

#[cfg(test)]
pub(crate) fn certify_checkpoint_candidate_for_test(
    network: [u8; 32],
    registry: &CompactEpochRegistry,
    checkpoint_sequence: u64,
    previous_head: &PortableDepositIndexHead,
    candidate: DepositIndexCheckpointCandidate,
    identities: &std::collections::BTreeMap<PartyId, Identity>,
) -> CommitCertificate {
    use std::collections::VecDeque;

    use crate::deposit_consensus::DepositConsensus;

    let context = deposit_index_checkpoint_consensus_context(
        network,
        registry,
        checkpoint_sequence,
        previous_head,
    )
    .unwrap();
    let value = candidate.to_consensus_value().unwrap();
    let mut reducers = identities
        .keys()
        .copied()
        .map(|party| (party, DepositConsensus::new(context.clone(), party).unwrap()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut queue = VecDeque::new();
    for (party, reducer) in &mut reducers {
        let step = reducer.start(&identities[party], value.clone()).unwrap();
        queue.extend(step.broadcast);
        if let Some(commit) = step.commit {
            return commit;
        }
    }
    while let Some(envelope) = queue.pop_front() {
        for (party, reducer) in &mut reducers {
            let step =
                reducer.handle_structurally_valid(&identities[party], envelope.clone()).unwrap();
            queue.extend(step.broadcast);
            if let Some(commit) = step.commit {
                return commit;
            }
        }
    }
    panic!("test checkpoint consensus did not commit");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_registry_archive::{
            CompactRegistryArchiveError, CompactRegistryObjectReader, CompactRegistryObjectRef,
            lookup_verified_issuer_window, prepare_compact_registry_genesis,
        },
        config::NetworkKind,
        deposit_index::{DepositIndexBuilder, DepositIndexReader},
        deposit_index_store::{
            DepositIndexStore, DepositIndexStoreCheckpoint, VerifiedPortableIndexImport,
        },
        deposit_ledger::{
            DepositObservationStatement, LedgerRequestId, LedgerStatement, RequestBinding,
            sign_deposit_observation_attestation,
        },
        deposit_wallet::{
            ChainPoint, DepositAddressDeriver, DepositSubaddressIndex, WalletOutputId,
        },
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    const SIGNING_NOW: u64 = 999;

    #[derive(Clone, Copy)]
    struct EmptyReader;

    impl DepositIndexReader for EmptyReader {
        fn load_index_object(
            &self,
            _id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(None)
        }
    }

    #[derive(Clone, Default)]
    struct MemoryIndexReader {
        objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    }

    impl MemoryIndexReader {
        fn apply(&mut self, update: &DepositIndexUpdate) {
            for id in update.obsolete_objects() {
                self.objects.remove(&id);
            }
            self.objects
                .extend(update.staged_objects().map(|(id, contents)| (id, contents.to_vec())));
        }
    }

    impl DepositIndexReader for MemoryIndexReader {
        fn load_index_object(
            &self,
            id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(self.objects.get(&id).cloned())
        }
    }

    #[derive(Default)]
    struct RegistryReader {
        objects: BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    }

    impl CompactRegistryObjectReader for RegistryReader {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            Ok(self.objects.get(&reference).cloned())
        }
    }

    struct Fixture {
        network: [u8; 32],
        registry: CompactEpochRegistry,
        issuer_window: VerifiedIssuerWindow,
        ledger: LedgerCertificate,
        preflight: VerifiedDepositIndexPreflight,
        update: DepositIndexUpdate,
        identities: BTreeMap<PartyId, Identity>,
        reader: EmptyReader,
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0x58; 32];
        secret[1..9].copy_from_slice(&epoch.to_le_bytes());
        secret[9..11].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    fn identities() -> (Committee, BTreeMap<PartyId, Identity>) {
        let identities = (1_u16..=4)
            .map(|value| {
                let party = PartyId(value);
                let signing_seed = [u8::try_from(value).unwrap(); 32];
                let identity = Identity::from_test_secrets(
                    party,
                    0,
                    &signing_seed,
                    test_x25519_secret(party, 0),
                )
                .unwrap();
                (party, identity)
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
        (Committee { epoch: 0, threshold: 2, members }, identities)
    }

    fn ledger_certificate(
        statement: LedgerStatement,
        committee: &Committee,
        identities: &BTreeMap<PartyId, Identity>,
    ) -> LedgerCertificate {
        let payload = statement.attestation_payload().unwrap();
        let attestations = identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        committee,
                        statement.slot_session(),
                        None,
                        statement.sequence,
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect();
        LedgerCertificate { statement, attestations }
    }

    fn make_fixture(request_byte: u8) -> Fixture {
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        let deriver = DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap();
        let wallet = deriver.wallet_id();
        let (committee, identities) = identities();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let head = DepositIndexHead::empty_portable(wallet, first_index).unwrap();
        let target = VerifiedRegistryHandoffTarget::for_test(
            committee.clone(),
            1,
            [8; 32],
            [9; 32],
            wallet,
            [10; 32],
            deriver.root_spend_key(),
        )
        .unwrap();
        let pending =
            prepare_compact_registry_genesis(&target, first_index, head.digest()).unwrap();
        let registry = pending.proposed_head().registry().clone();
        let registry_reader = RegistryReader {
            objects: pending
                .staged_objects()
                .iter()
                .map(|object| (object.reference(), object.contents().to_vec()))
                .collect(),
        };
        let issuer_window =
            lookup_verified_issuer_window(pending.proposed_head(), 0, &registry_reader).unwrap();
        let statement = LedgerStatement::allocation(
            &registry,
            1,
            ledger_genesis_head(wallet),
            LedgerRequestId([request_byte; 32]),
            RequestBinding([request_byte.wrapping_add(1); 32]),
            deriver.derive(first_index),
            ChainPoint::new(0, [0x6b; 32]).unwrap(),
            1_000,
        )
        .unwrap();
        let ledger = ledger_certificate(statement, &committee, &identities);
        ledger.verify_active(&registry, None).unwrap();
        let reader = EmptyReader;
        let mut preflight_builder = DepositIndexBuilder::new(&reader, head.clone()).unwrap();
        let preflight = preflight_builder.preflight_ledger_statement(&ledger.statement).unwrap();
        let mut builder = DepositIndexBuilder::new(&reader, head).unwrap();
        assert!(builder.apply_verified_active_entry(&ledger, &registry, None).unwrap());
        let update = builder.finish().unwrap().unwrap();
        update
            .verify_ledger_transition_for_preflight(&reader, &ledger.statement, &preflight)
            .unwrap();
        Fixture {
            network: [0x55; 32],
            registry,
            issuer_window,
            ledger,
            preflight,
            update,
            identities,
            reader,
        }
    }

    fn checkpoint(fixture: &Fixture) -> DepositIndexCheckpointCertificate {
        let statement = DepositIndexCheckpointStatement::for_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        let selection = certify_checkpoint_candidate_for_test(
            fixture.network,
            &fixture.registry,
            statement.sequence(),
            statement.previous_head(),
            DepositIndexCheckpointCandidate::Ledger(fixture.ledger.clone()),
            &fixture.identities,
        );
        let witnesses = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence(),
                        statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        DepositIndexCheckpointCertificate::from_witnesses(
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            statement,
            selection,
            witnesses,
        )
        .unwrap()
    }

    fn certified_observation(
        fixture: &Fixture,
        output_byte: u8,
        output_key_byte: u8,
        observed_height: u64,
    ) -> CertifiedDepositObservation {
        let statement = DepositObservationStatement::new(
            &fixture.registry,
            &fixture.ledger.statement,
            WalletOutputId {
                transaction: [output_byte; 32],
                index_in_transaction: u64::from(output_byte),
            },
            [output_key_byte; 32],
            u64::from(output_byte),
            1_000 + u64::from(output_byte),
            ChainPoint::new(observed_height, [output_byte; 32]).unwrap(),
            900 + u64::from(output_byte),
            ChainPoint::new(observed_height + 9, [output_key_byte; 32]).unwrap(),
            10,
        )
        .unwrap();
        let attestations = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                sign_deposit_observation_attestation(identity, &fixture.registry, &statement)
                    .unwrap()
            })
            .collect();
        let observation = CertifiedDepositObservation { statement, attestations };
        observation.verify_active(&fixture.registry).unwrap();
        observation
    }

    fn allocation_reader(fixture: &Fixture) -> MemoryIndexReader {
        let mut reader = MemoryIndexReader::default();
        reader.apply(&fixture.update);
        reader
    }

    fn observation_update(
        fixture: &Fixture,
        reader: &MemoryIndexReader,
        head: DepositIndexHead,
        observation: &CertifiedDepositObservation,
    ) -> (DepositIndexUpdate, VerifiedDepositObservationIndexTransition) {
        let mut builder = DepositIndexBuilder::new(reader, head).unwrap();
        assert!(
            builder
                .apply_verified_active_deposit_observation(observation, &fixture.registry)
                .unwrap()
        );
        let update = builder.finish().unwrap().unwrap();
        let transition =
            update.verify_deposit_observation_transition(reader, &observation.statement).unwrap();
        (update, transition)
    }

    fn observation_checkpoint(
        fixture: &Fixture,
        previous: &VerifiedDepositIndexCheckpoint,
        observation: &CertifiedDepositObservation,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> DepositIndexCheckpointCertificate {
        let statement = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            Some(previous),
            observation,
            transition,
        )
        .unwrap();
        let selection = certify_checkpoint_candidate_for_test(
            fixture.network,
            &fixture.registry,
            statement.sequence(),
            statement.previous_head(),
            DepositIndexCheckpointCandidate::DepositObservation(observation.clone()),
            &fixture.identities,
        );
        let witnesses = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        statement.slot_session(),
                        None,
                        statement.sequence(),
                        statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        DepositIndexCheckpointCertificate::from_deposit_observation_witnesses(
            fixture.network,
            &fixture.registry,
            Some(previous),
            observation,
            statement,
            selection,
            witnesses,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn checkpoint_slot_is_durable_before_signing_and_conflict_survives_restart() {
        let fixture = make_fixture(0x23);
        let statement = DepositIndexCheckpointStatement::for_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        let identity = fixture.identities.values().next().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = DepositIndexStoreCheckpoint::empty(
            statement.context().wallet_id(),
            identity.party(),
            statement.previous_head().next_index(),
        )
        .unwrap();
        let mut store =
            DepositIndexStore::open(directory.path(), identity.party(), &[0xa5; 32], checkpoint)
                .await
                .unwrap();
        let slot = statement.signing_slot(SIGNING_NOW).unwrap();
        assert!(matches!(
            store.authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence()).await,
            Err(crate::deposit_index_store::DepositIndexStoreError::UncommittedSigningSlot)
        ));

        let mut builder =
            DepositIndexBuilder::new(&store, store.local_safety_head().clone()).unwrap();
        assert!(builder.record_signed_index_checkpoint_slot(slot).unwrap());
        let local_update = builder.finish().unwrap().unwrap();
        let prepared = store.prepare_snapshot(vec![local_update]).await.unwrap();
        let authenticated = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &authenticated).await.unwrap();
        let authorization = store
            .authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence())
            .await
            .unwrap();
        let (rebuilt, witness) = sign_checkpoint_transition(
            SIGNING_NOW,
            identity,
            &authorization,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        assert_eq!(rebuilt, statement);
        Identity::verify_envelope(
            fixture.registry.active().committee(),
            identity.party(),
            &witness,
        )
        .unwrap();

        let settled = store.checkpoint().clone();
        drop(store);
        let mut restarted =
            DepositIndexStore::open(directory.path(), identity.party(), &[0xa5; 32], settled)
                .await
                .unwrap();
        let restarted_authorization = restarted
            .authenticate_signed_index_checkpoint_slot(slot.checkpoint_sequence())
            .await
            .unwrap();
        let (_, retried) = sign_checkpoint_transition(
            SIGNING_NOW,
            identity,
            &restarted_authorization,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        assert_eq!(retried, witness);
        let (_, retry_after_creation) = sign_checkpoint_transition(
            1_001,
            identity,
            &restarted_authorization,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        assert_eq!(retry_after_creation, witness);

        let conflicting = SignedIndexCheckpointSlot::new(
            slot.checkpoint_sequence(),
            slot.ledger_decision(),
            slot.previous_logical_head(),
            slot.resulting_logical_head(),
            [0xee; 32],
            slot.reserved_at(),
        )
        .unwrap();
        let mut conflict =
            DepositIndexBuilder::new(&restarted, restarted.local_safety_head().clone()).unwrap();
        assert!(matches!(
            conflict.record_signed_index_checkpoint_slot(conflicting),
            Err(DepositIndexError::IndexCheckpointSlotAlreadySigned)
        ));
        let different_reservation = statement.signing_slot(SIGNING_NOW - 2).unwrap();
        let mut reservation_conflict =
            DepositIndexBuilder::new(&restarted, restarted.local_safety_head().clone()).unwrap();
        assert!(matches!(
            reservation_conflict.record_signed_index_checkpoint_slot(different_reservation),
            Err(DepositIndexError::IndexCheckpointSlotAlreadySigned)
        ));
    }

    #[tokio::test]
    async fn post_deadline_persisted_reservation_cannot_authorize_signing() {
        let fixture = make_fixture(0x25);
        let statement = DepositIndexCheckpointStatement::for_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            &fixture.preflight,
            &fixture.update,
            &fixture.reader,
        )
        .unwrap();
        let identity = fixture.identities.values().next().unwrap();
        let late_slot = statement.signing_slot(1_000).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = DepositIndexStoreCheckpoint::empty(
            statement.context().wallet_id(),
            identity.party(),
            statement.previous_head().next_index(),
        )
        .unwrap();
        let mut store =
            DepositIndexStore::open(directory.path(), identity.party(), &[0xa6; 32], checkpoint)
                .await
                .unwrap();
        let mut builder =
            DepositIndexBuilder::new(&store, store.local_safety_head().clone()).unwrap();
        assert!(builder.record_signed_index_checkpoint_slot(late_slot).unwrap());
        let prepared =
            store.prepare_snapshot(vec![builder.finish().unwrap().unwrap()]).await.unwrap();
        let authenticated = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &authenticated).await.unwrap();
        let authorization = store
            .authenticate_signed_index_checkpoint_slot(late_slot.checkpoint_sequence())
            .await
            .unwrap();
        assert!(matches!(
            sign_checkpoint_transition(
                1_001,
                identity,
                &authorization,
                fixture.network,
                &fixture.registry,
                None,
                None,
                &fixture.ledger,
                &fixture.preflight,
                &fixture.update,
                &fixture.reader,
            ),
            Err(DepositIndexCheckpointError::AllocationCheckpointDeadlineElapsed)
        ));
    }

    #[test]
    fn allocation_checkpoint_admission_is_strictly_before_creation_time() {
        let fixture = make_fixture(0x24);
        assert!(
            DepositIndexCheckpointStatement::for_transition(
                SIGNING_NOW,
                fixture.network,
                &fixture.registry,
                None,
                None,
                &fixture.ledger,
                &fixture.preflight,
                &fixture.update,
                &fixture.reader,
            )
            .is_ok()
        );
        assert!(matches!(
            DepositIndexCheckpointStatement::for_transition(
                1_000,
                fixture.network,
                &fixture.registry,
                None,
                None,
                &fixture.ledger,
                &fixture.preflight,
                &fixture.update,
                &fixture.reader,
            ),
            Err(DepositIndexCheckpointError::AllocationCheckpointDeadlineElapsed)
        ));
        assert!(matches!(
            DepositIndexCheckpointStatement::for_transition(
                0,
                fixture.network,
                &fixture.registry,
                None,
                None,
                &fixture.ledger,
                &fixture.preflight,
                &fixture.update,
                &fixture.reader,
            ),
            Err(DepositIndexCheckpointError::InvalidSigningTime)
        ));
    }

    #[test]
    fn observation_checkpoint_advances_only_checkpoint_order_and_supports_fresh_sync() {
        let fixture = make_fixture(0x34);
        let ledger_checkpoint = checkpoint(&fixture);
        let previous = ledger_checkpoint
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap();
        let reader = allocation_reader(&fixture);
        let observation = certified_observation(&fixture, 0x41, 0x51, 20);
        let (update, transition) =
            observation_update(&fixture, &reader, fixture.update.next_head().clone(), &observation);
        let certificate = observation_checkpoint(&fixture, &previous, &observation, &transition);
        let verified = certificate
            .verify_active_deposit_observation(
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &observation,
            )
            .unwrap();
        let mut oversized_observation = observation.clone();
        oversized_observation.attestations.push(
            sign_deposit_observation_attestation(
                fixture.identities.values().nth(3).unwrap(),
                &fixture.registry,
                &oversized_observation.statement,
            )
            .unwrap(),
        );
        oversized_observation.verify_active(&fixture.registry).unwrap();
        assert!(matches!(
            DepositIndexCheckpointStatement::for_deposit_observation_transition(
                SIGNING_NOW,
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &oversized_observation,
                &transition,
            ),
            Err(DepositIndexCheckpointError::WrongObservationDecision)
        ));

        assert_eq!(verified.sequence(), 2);
        assert_eq!(verified.ledger_sequence(), 1);
        assert_eq!(
            verified.operation(),
            DepositIndexCheckpointOperation::DepositObservation {
                statement: observation.statement.digest(),
            }
        );
        assert_eq!(
            verified.resulting_head().through_sequence(),
            previous.resulting_head().through_sequence()
        );
        assert_eq!(
            verified.resulting_head().ledger_head(),
            previous.resulting_head().ledger_head()
        );
        assert_eq!(verified.resulting_head().next_index(), previous.resulting_head().next_index());
        assert_ne!(verified.resulting_head().digest(), previous.resulting_head().digest());
        assert!(verified.resulting_head().matches(update.next_head()).unwrap());
        let cursor =
            verified.compact_cursor(&fixture.registry, Some(&fixture.ledger.statement)).unwrap();
        assert_eq!(cursor.next_sequence(), 2);

        let bytes = certificate.to_bytes().unwrap();
        let decoded = DepositIndexCheckpointCertificate::from_bytes(&bytes).unwrap();
        assert_eq!(
            decoded
                .verify_archived_deposit_observation(
                    fixture.network,
                    &fixture.issuer_window,
                    Some(&previous),
                    &observation,
                )
                .unwrap(),
            verified
        );
        assert_eq!(
            decoded
                .verify_active_deposit_observation_anchored(
                    fixture.network,
                    &fixture.registry,
                    &observation,
                    verified.resulting_head(),
                )
                .unwrap(),
            verified
        );
        assert!(matches!(
            decoded.verify_active_deposit_observation_anchored(
                fixture.network,
                &fixture.registry,
                &observation,
                previous.resulting_head(),
            ),
            Err(DepositIndexCheckpointError::WrongObservationDecision)
        ));

        let import = VerifiedPortableIndexImport::from_certified_checkpoint(&verified).unwrap();
        let fresh = DepositIndexStoreCheckpoint::empty(
            verified.context().wallet_id(),
            PartyId(4),
            fixture.update.expected_head().portable_anchor().unwrap().next_index(),
        )
        .unwrap();
        let imported = fresh.import_verified_portable(&import).unwrap();
        assert!(verified.resulting_head().matches(imported.portable_head()).unwrap());
    }

    #[tokio::test]
    async fn observation_checkpoint_slot_survives_restart_and_authorizes_only_exact_statement() {
        let fixture = make_fixture(0x35);
        let previous = checkpoint(&fixture)
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap();
        let reader = allocation_reader(&fixture);
        let observation = certified_observation(&fixture, 0x42, 0x52, 21);
        let (_update, transition) =
            observation_update(&fixture, &reader, fixture.update.next_head().clone(), &observation);
        let statement = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            Some(&previous),
            &observation,
            &transition,
        )
        .unwrap();
        let identity = fixture.identities.values().next().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = DepositIndexStoreCheckpoint::empty(
            statement.context().wallet_id(),
            identity.party(),
            fixture.update.expected_head().portable_anchor().unwrap().next_index(),
        )
        .unwrap();
        let mut store =
            DepositIndexStore::open(directory.path(), identity.party(), &[0xb5; 32], checkpoint)
                .await
                .unwrap();
        let slot = statement.signing_slot(SIGNING_NOW).unwrap();
        let mut builder =
            DepositIndexBuilder::new(&store, store.local_safety_head().clone()).unwrap();
        assert!(builder.record_signed_index_checkpoint_slot(slot).unwrap());
        let prepared =
            store.prepare_snapshot(vec![builder.finish().unwrap().unwrap()]).await.unwrap();
        let authenticated = prepared.checkpoint().clone();
        store.commit_prepared(&prepared, &authenticated).await.unwrap();
        let settled = store.checkpoint().clone();
        drop(store);

        let mut restarted =
            DepositIndexStore::open(directory.path(), identity.party(), &[0xb5; 32], settled)
                .await
                .unwrap();
        let authorization = restarted
            .authenticate_signed_index_checkpoint_slot(statement.sequence())
            .await
            .unwrap();
        let (rebuilt, witness) = sign_deposit_observation_checkpoint_transition(
            SIGNING_NOW + 100,
            identity,
            &authorization,
            fixture.network,
            &fixture.registry,
            Some(&previous),
            &observation,
            &transition,
        )
        .unwrap();
        assert_eq!(rebuilt, statement);
        Identity::verify_envelope(
            fixture.registry.active().committee(),
            identity.party(),
            &witness,
        )
        .unwrap();

        let conflicting_observation = certified_observation(&fixture, 0x62, 0x72, 22);
        let (_conflicting_update, conflicting_transition) = observation_update(
            &fixture,
            &reader,
            fixture.update.next_head().clone(),
            &conflicting_observation,
        );
        assert!(matches!(
            sign_deposit_observation_checkpoint_transition(
                SIGNING_NOW + 100,
                identity,
                &authorization,
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &conflicting_observation,
                &conflicting_transition,
            ),
            Err(DepositIndexCheckpointError::UncommittedSigningSlot)
        ));
    }

    #[test]
    fn duplicate_observation_is_idempotent_and_output_or_key_conflicts_fail_closed() {
        let fixture = make_fixture(0x36);
        let mut reader = allocation_reader(&fixture);
        let observation = certified_observation(&fixture, 0x43, 0x53, 22);
        let (update, _transition) =
            observation_update(&fixture, &reader, fixture.update.next_head().clone(), &observation);
        reader.apply(&update);

        let mut duplicate = DepositIndexBuilder::new(&reader, update.next_head().clone()).unwrap();
        assert!(
            !duplicate
                .apply_verified_active_deposit_observation(&observation, &fixture.registry)
                .unwrap()
        );
        assert!(duplicate.finish().unwrap().is_none());

        let conflicting_key = certified_observation(&fixture, 0x43, 0x63, 22);
        let mut by_output = DepositIndexBuilder::new(&reader, update.next_head().clone()).unwrap();
        let output_conflict = by_output
            .apply_verified_active_deposit_observation(&conflicting_key, &fixture.registry)
            .unwrap_err();
        assert!(
            matches!(output_conflict, DepositIndexError::PortableObservationConflict),
            "unexpected output conflict: {output_conflict:?}"
        );

        let conflicting_output = certified_observation(&fixture, 0x63, 0x53, 23);
        let mut by_key = DepositIndexBuilder::new(&reader, update.next_head().clone()).unwrap();
        assert!(matches!(
            by_key
                .apply_verified_active_deposit_observation(&conflicting_output, &fixture.registry,),
            Err(DepositIndexError::PortableObservationConflict)
        ));
    }

    #[tokio::test]
    async fn concurrent_observations_rebase_in_checkpoint_order_and_converge_canonically() {
        let fixture = make_fixture(0x37);
        let base_reader = allocation_reader(&fixture);
        let observation_a = certified_observation(&fixture, 0x44, 0x54, 24);
        let observation_b = certified_observation(&fixture, 0x45, 0x55, 25);
        let (update_a, transition_a) = observation_update(
            &fixture,
            &base_reader,
            fixture.update.next_head().clone(),
            &observation_a,
        );
        let (update_b, transition_b) = observation_update(
            &fixture,
            &base_reader,
            fixture.update.next_head().clone(),
            &observation_b,
        );
        let previous = checkpoint(&fixture)
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap();
        let statement_a = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            Some(&previous),
            &observation_a,
            &transition_a,
        )
        .unwrap();
        let stale_statement_b =
            DepositIndexCheckpointStatement::for_deposit_observation_transition(
                SIGNING_NOW,
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &observation_b,
                &transition_b,
            )
            .unwrap();
        assert_eq!(statement_a.sequence(), 2);
        assert_eq!(stale_statement_b.sequence(), 2);
        assert_ne!(statement_a.decision_digest(), stale_statement_b.decision_digest());

        let certificate_a =
            observation_checkpoint(&fixture, &previous, &observation_a, &transition_a);
        let verified_a = certificate_a
            .verify_active_deposit_observation(
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &observation_a,
            )
            .unwrap();
        let mut reader_ab = base_reader.clone();
        reader_ab.apply(&update_a);
        let (rebased_b, rebased_transition_b) =
            observation_update(&fixture, &reader_ab, update_a.next_head().clone(), &observation_b);
        let rebased_statement_b =
            DepositIndexCheckpointStatement::for_deposit_observation_transition(
                SIGNING_NOW,
                fixture.network,
                &fixture.registry,
                Some(&verified_a),
                &observation_b,
                &rebased_transition_b,
            )
            .unwrap();
        assert_eq!(rebased_statement_b.sequence(), 3);
        assert!(matches!(
            stale_statement_b.verify_deposit_observation_transition(
                fixture.network,
                &fixture.registry,
                Some(&verified_a),
                &observation_b,
                &rebased_transition_b,
            ),
            Err(DepositIndexCheckpointError::WrongExpectedStatement)
        ));

        let mut reader_ba = base_reader.clone();
        reader_ba.apply(&update_b);
        let (rebased_a, _rebased_transition_a) =
            observation_update(&fixture, &reader_ba, update_b.next_head().clone(), &observation_a);
        assert_eq!(
            PortableDepositIndexHead::from_head(rebased_b.next_head()).unwrap(),
            PortableDepositIndexHead::from_head(rebased_a.next_head()).unwrap()
        );

        let directory = tempfile::tempdir().unwrap();
        let identity = fixture.identities.values().next().unwrap();
        let initial = DepositIndexStoreCheckpoint::empty(
            fixture.ledger.statement.wallet,
            identity.party(),
            fixture.update.expected_head().portable_anchor().unwrap().next_index(),
        )
        .unwrap();
        let mut store =
            DepositIndexStore::open(directory.path(), identity.party(), &[0xb7; 32], initial)
                .await
                .unwrap();
        let allocation = store.prepare_snapshot(vec![fixture.update.clone()]).await.unwrap();
        let allocation_target = allocation.checkpoint().clone();
        store.commit_prepared(&allocation, &allocation_target).await.unwrap();
        let winner = store.prepare_snapshot(vec![update_a.clone()]).await.unwrap();
        let winner_target = winner.checkpoint().clone();
        store.commit_prepared(&winner, &winner_target).await.unwrap();
        assert!(matches!(
            store.prepare_snapshot(vec![update_b]).await,
            Err(crate::deposit_index_store::DepositIndexStoreError::CheckpointConflict)
        ));
    }

    #[test]
    fn empty_logical_head_matches_without_signing_local_revision() {
        let wallet = DepositWalletId([7; 32]);
        let head =
            DepositIndexHead::empty_portable(wallet, DepositSubaddressIndex::new(0, 1).unwrap())
                .unwrap();
        let logical = PortableDepositIndexHead::from_head(&head).unwrap();
        assert!(logical.matches(&head).unwrap());
        assert_eq!(logical.wallet_id(), wallet);
        assert_eq!(logical.through_sequence(), 0);
        assert_eq!(logical.root(), None);
        assert_eq!(logical.digest(), head.digest());
    }

    #[test]
    fn logical_head_rejects_rootless_non_genesis_and_terminal_anchors() {
        let head = DepositIndexHead::empty_portable(
            DepositWalletId([7; 32]),
            DepositSubaddressIndex::new(0, 1).unwrap(),
        )
        .unwrap();
        let mut truncated = PortableDepositIndexHead::from_head(&head).unwrap();
        truncated.anchor.through_sequence = 1;
        truncated.anchor.ledger_head = [0x71; 32];
        truncated.digest = logical_head_digest(&truncated).unwrap();
        assert!(matches!(
            truncated.validate(),
            Err(DepositIndexCheckpointError::InvalidLogicalHead)
        ));

        let mut terminal = PortableDepositIndexHead::from_head(&head).unwrap();
        terminal.anchor.through_sequence = u64::MAX;
        terminal.anchor.ledger_head = [0x72; 32];
        terminal.digest = logical_head_digest(&terminal).unwrap();
        assert!(matches!(
            terminal.validate(),
            Err(DepositIndexCheckpointError::InvalidLogicalHead)
        ));
    }

    #[test]
    fn semantic_update_digest_binds_both_heads_and_ledger_decision() {
        let fixture = make_fixture(0x31);
        let first = PortableDepositIndexHead::from_head(fixture.update.expected_head()).unwrap();
        let second = PortableDepositIndexHead::from_head(fixture.update.next_head()).unwrap();
        let ledger = fixture.ledger.statement.digest();
        let operation = DepositIndexCheckpointOperation::Ledger { statement: ledger };
        let digest = semantic_update_digest(&first, 1, operation, 1, ledger, &second);
        assert_eq!(digest, semantic_update_digest(&first, 1, operation, 1, ledger, &second));
        assert_ne!(
            digest,
            semantic_update_digest(
                &first,
                1,
                DepositIndexCheckpointOperation::Ledger { statement: [5; 32] },
                1,
                ledger,
                &second,
            )
        );
        assert_ne!(digest, semantic_update_digest(&first, 2, operation, 1, ledger, &second));
        assert_ne!(digest, semantic_update_digest(&first, 1, operation, 2, ledger, &second));
    }

    #[test]
    fn opposite_valid_operation_delivery_converges_and_selection_survives_restart() {
        use crate::deposit_consensus::DepositConsensus;

        let fixture = make_fixture(0x71);
        let previous_certificate = checkpoint(&fixture);
        let previous = previous_certificate
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap();
        let reader = allocation_reader(&fixture);
        let observation_a = certified_observation(&fixture, 0x72, 0x82, 42);
        let observation_b = certified_observation(&fixture, 0x73, 0x83, 43);
        let (_, transition_a) = observation_update(
            &fixture,
            &reader,
            fixture.update.next_head().clone(),
            &observation_a,
        );
        let (_, transition_b) = observation_update(
            &fixture,
            &reader,
            fixture.update.next_head().clone(),
            &observation_b,
        );
        let candidate_a =
            DepositIndexCheckpointCandidate::DepositObservation(observation_a.clone());
        let candidate_b =
            DepositIndexCheckpointCandidate::DepositObservation(observation_b.clone());
        let value_a = candidate_a.to_consensus_value().unwrap();
        let value_b = candidate_b.to_consensus_value().unwrap();
        let context = deposit_index_checkpoint_consensus_context(
            fixture.network,
            &fixture.registry,
            2,
            previous.resulting_head(),
        )
        .unwrap();

        let mut reducers = fixture
            .identities
            .keys()
            .copied()
            .map(|party| (party, DepositConsensus::new(context.clone(), party).unwrap()))
            .collect::<BTreeMap<_, _>>();
        let mut pending = Vec::new();
        for (party, reducer) in &mut reducers {
            // Half the honest parties learn A first and half learn B first. Party 2 is the
            // deterministic view-zero leader for sequence two and proposes A.
            let local = if party.0 <= 2 { value_a.clone() } else { value_b.clone() };
            pending.extend(reducer.start(&fixture.identities[party], local).unwrap().broadcast);
        }
        for _ in 0..16 {
            if reducers.values().all(|reducer| reducer.commit().is_some()) {
                break;
            }
            let inbound = std::mem::take(&mut pending);
            for (party, reducer) in &mut reducers {
                let messages: Box<dyn Iterator<Item = &SignedEnvelope>> = if party.0 % 2 == 0 {
                    Box::new(inbound.iter().rev())
                } else {
                    Box::new(inbound.iter())
                };
                for envelope in messages {
                    if reducer.commit().is_some() {
                        break;
                    }
                    let step = reducer
                        .handle_with_value_validator(
                            &fixture.identities[party],
                            envelope.clone(),
                            |value| value == &value_a || value == &value_b,
                        )
                        .unwrap();
                    pending.extend(step.broadcast);
                }
            }
        }
        assert!(reducers.values().all(|reducer| reducer.commit().is_some()));
        let decision = reducers[&PartyId(1)].commit().unwrap().digest();
        assert!(reducers.values().all(|reducer| {
            reducer.commit().is_some_and(|commit| {
                commit.digest() == decision
                    && DepositIndexCheckpointCandidate::from_consensus_value(commit.value())
                        .is_ok_and(|candidate| candidate == candidate_a)
            })
        }));

        let mut restored = BTreeMap::new();
        for (party, reducer) in reducers {
            let bytes = postcard::to_allocvec(&reducer).unwrap();
            let (decoded, trailing) =
                postcard::take_from_bytes::<DepositConsensus>(&bytes).unwrap();
            assert!(trailing.is_empty());
            decoded
                .validate_application_values(|value| value == &value_a || value == &value_b)
                .unwrap();
            assert_eq!(decoded.commit().unwrap().digest(), decision);
            restored.insert(party, decoded);
        }

        let selected_statement =
            DepositIndexCheckpointStatement::for_deposit_observation_transition(
                SIGNING_NOW,
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &observation_a,
                &transition_a,
            )
            .unwrap();
        let losing_statement = DepositIndexCheckpointStatement::for_deposit_observation_transition(
            SIGNING_NOW,
            fixture.network,
            &fixture.registry,
            Some(&previous),
            &observation_b,
            &transition_b,
        )
        .unwrap();
        let selection = restored[&PartyId(1)].commit().unwrap().clone();
        let selected_witnesses = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        selected_statement.slot_session(),
                        None,
                        selected_statement.sequence(),
                        selected_statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let certificate = DepositIndexCheckpointCertificate::from_deposit_observation_witnesses(
            fixture.network,
            &fixture.registry,
            Some(&previous),
            &observation_a,
            selected_statement,
            selection.clone(),
            selected_witnesses,
        )
        .unwrap();
        let round_trip =
            DepositIndexCheckpointCertificate::from_bytes(&certificate.to_bytes().unwrap())
                .unwrap();
        round_trip
            .verify_active_deposit_observation(
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &observation_a,
            )
            .unwrap();

        let losing_witnesses = fixture
            .identities
            .values()
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        losing_statement.slot_session(),
                        None,
                        losing_statement.sequence(),
                        losing_statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            DepositIndexCheckpointCertificate::from_deposit_observation_witnesses(
                fixture.network,
                &fixture.registry,
                Some(&previous),
                &observation_b,
                losing_statement,
                selection,
                losing_witnesses,
            ),
            Err(DepositIndexCheckpointError::InvalidSelection)
        ));
    }

    #[test]
    fn exact_n_minus_f_certificate_round_trips_and_verifies_end_to_end() {
        let fixture = make_fixture(10);
        let certificate = checkpoint(&fixture);
        let verified = certificate
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap();
        assert_eq!(verified.sequence(), 1);
        assert_eq!(verified.signers(), &[PartyId(1), PartyId(2), PartyId(3)]);
        assert_eq!(verified.ledger_decision(), fixture.ledger.statement.digest());
        assert!(verified.resulting_head().matches(fixture.update.next_head()).unwrap());
        assert_eq!(verified.certificate_digest(), certificate.certificate_digest().unwrap());
        let alternate_statement = certificate.statement().clone();
        let alternate_witnesses = fixture
            .identities
            .values()
            .filter(|identity| identity.party() != PartyId(3))
            .take(3)
            .map(|identity| {
                identity
                    .sign_envelope(
                        fixture.registry.active().committee(),
                        alternate_statement.slot_session(),
                        None,
                        alternate_statement.sequence(),
                        alternate_statement.to_bytes().unwrap(),
                    )
                    .unwrap()
            })
            .collect();
        let alternate = DepositIndexCheckpointCertificate::from_witnesses(
            fixture.network,
            &fixture.registry,
            None,
            None,
            &fixture.ledger,
            alternate_statement,
            certificate.selection().clone(),
            alternate_witnesses,
        )
        .unwrap();
        let alternate_verified = alternate
            .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger)
            .unwrap();
        assert_eq!(alternate_verified.decision_digest(), verified.decision_digest());
        assert_ne!(alternate_verified.certificate_digest(), verified.certificate_digest());
        let cursor =
            verified.compact_cursor(&fixture.registry, Some(&fixture.ledger.statement)).unwrap();
        assert_eq!(cursor.head(), fixture.ledger.statement.digest());
        assert_eq!(cursor.next_sequence(), 2);

        let bytes = certificate.to_bytes().unwrap();
        let decoded = DepositIndexCheckpointCertificate::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, certificate);
        assert_eq!(
            decoded
                .verify_active(fixture.network, &fixture.registry, None, None, &fixture.ledger,)
                .unwrap(),
            verified
        );
    }

    #[test]
    fn latest_checkpoint_verifies_directly_against_authenticated_current_head() {
        let fixture = make_fixture(0x11);
        let certificate = checkpoint(&fixture);
        let resulting = PortableDepositIndexHead::from_head(fixture.update.next_head()).unwrap();
        let verified = certificate
            .verify_anchored(
                fixture.network,
                &fixture.issuer_window,
                None,
                &fixture.ledger,
                &resulting,
            )
            .unwrap();
        assert_eq!(verified.resulting_head(), &resulting);

        let stale = PortableDepositIndexHead::from_head(fixture.update.expected_head()).unwrap();
        assert!(matches!(
            certificate.verify_anchored(
                fixture.network,
                &fixture.issuer_window,
                None,
                &fixture.ledger,
                &stale,
            ),
            Err(DepositIndexCheckpointError::WrongAuthenticatedHead)
        ));
    }

    #[test]
    fn certificate_rejects_same_slot_ledger_fork_and_foreign_network() {
        let fixture = make_fixture(20);
        let fork = make_fixture(21);
        let certificate = checkpoint(&fixture);
        // The certificate now embeds the BA commit certificate that selected this checkpoint's
        // ledger operation. A same-slot ledger fork no longer matches the selected candidate, so
        // verification fails at the selection gate with InvalidSelection before it can reach the
        // per-statement ledger-decision comparison.
        assert!(matches!(
            certificate.verify_active(fixture.network, &fixture.registry, None, None, &fork.ledger),
            Err(DepositIndexCheckpointError::InvalidSelection)
        ));
        // A foreign network changes the recomputed consensus context, so the embedded commit
        // certificate's bound context digest no longer matches and the selection gate rejects it
        // as an invalid certificate before the statement's own context check would run.
        assert!(matches!(
            certificate.verify_active([0x56; 32], &fixture.registry, None, None, &fixture.ledger),
            Err(DepositIndexCheckpointError::Consensus(ConsensusError::InvalidCertificate(_)))
        ));
    }

    #[test]
    fn logical_checkpoint_converges_across_local_cas_revisions() {
        #[derive(Serialize)]
        struct AnchorEncoding {
            through_sequence: u64,
            ledger_head: [u8; 32],
            next_index: DepositSubaddressIndex,
        }
        #[derive(Serialize)]
        struct HeadEncoding {
            version: u16,
            namespace: DepositIndexNamespace,
            revision: u64,
            entries: u64,
            records: u64,
            root: Option<DepositIndexObjectId>,
            portable_anchor: Option<AnchorEncoding>,
        }

        fn head_at_revision(wallet: DepositWalletId, revision: u64) -> DepositIndexHead {
            let bytes = postcard::to_allocvec(&HeadEncoding {
                version: 1,
                namespace: DepositIndexNamespace::Portable { wallet },
                revision,
                entries: 0,
                records: 0,
                root: None,
                portable_anchor: Some(AnchorEncoding {
                    through_sequence: 0,
                    ledger_head: ledger_genesis_head(wallet),
                    next_index: DepositSubaddressIndex::new(0, 1).unwrap(),
                }),
            })
            .unwrap();
            postcard::from_bytes(&bytes).unwrap()
        }

        let wallet = DepositWalletId([0x44; 32]);
        let low_revision = head_at_revision(wallet, 3);
        let high_revision = head_at_revision(wallet, 90);
        assert_ne!(low_revision.revision(), high_revision.revision());
        assert_eq!(low_revision.digest(), high_revision.digest());
        assert_eq!(
            PortableDepositIndexHead::from_head(&low_revision).unwrap(),
            PortableDepositIndexHead::from_head(&high_revision).unwrap()
        );
    }
}
