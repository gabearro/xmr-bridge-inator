//! Immutable cold storage for certified ROAST attempts.
//!
//! A [`ConsolidationRoast`](crate::consolidation_roast::ConsolidationRoast) deliberately keeps a
//! bounded hot/replay window.  This archive retains the exact certificate-bearing attempt proof
//! before that window is compacted.  Attempt records, transaction mappings, sparse-index nodes and
//! commits are content addressed and encrypted by [`WalletArtifactStore`].  A caller stages every
//! object first, authenticates readback, and only then installs the returned compact head in the
//! same wallet-snapshot compare-and-swap as the reducer compaction.  A crash before that CAS leaves
//! harmless unreachable immutable objects; the old head and all of its index roots remain valid.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    marker::PhantomData,
    path::PathBuf,
};

use rand_core::{CryptoRng, RngCore};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, Error as DeError, SeqAccess, Visitor},
};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, PartyId, SessionId},
    consolidation_consensus::{
        ConsolidationConsensusError, ConsolidationIntent, ConsolidationIntentCertificate,
    },
    consolidation_roast::{
        ConsolidationRoastError, RoastAttemptPrefixFrontier, RoastAttemptPrefixPeak,
        RoastAttemptPrefixSeal, RoastViewPlan, certified_roast_attempt_leaf,
        deterministic_roast_family_digest, roast_attempt_prefix_parent,
    },
    deposit_consensus::ConsensusContext,
    deposit_consolidation::{SignedTransactionBinding, consolidation_input_set_binding},
    deposit_consolidation_wire::{
        ConsolidationAttemptWireBinding, ConsolidationConsensusSlot, ConsolidationWireError,
        PortableKeyImageBindingCertificate, PortableSignedTransactionAttestation,
    },
    deposit_wallet::{DepositWalletError, DepositWalletId, SignedSweepTransaction},
    deposit_worker::{
        DepositWorkerError, SweepPlan, canonical_sweep_transaction_key_images,
        canonicalize_certified_sweep_key_images,
    },
    identity::{Identity, IdentityError, SignedEnvelope},
    roast_history_consistency::{
        RoastArchiveHistoryConsistencyProof, RoastArchiveHistoryError, RoastArchiveHistoryFrontier,
        RoastArchiveHistorySummary, RoastArchiveSemanticState,
        VerifiedRoastArchiveHistoryConsistency,
    },
    storage::{
        DepositIndexJournalKey, DepositIndexJournalScope, MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
        MAX_WALLET_ARTIFACT_BYTES, ProtocolStore, StoreError, WalletArtifactKind,
        WalletArtifactOwner, WalletArtifactRef, WalletArtifactStore, WalletId,
    },
};

const ATTEMPT_RECORD_VERSION: u16 = 1;
const ARCHIVE_HEAD_VERSION: u16 = 2;
const ARCHIVE_COMMIT_VERSION: u16 = 2;
const INDEX_NODE_VERSION: u16 = 2;
const TRANSACTION_MAPPING_VERSION: u16 = 2;
const ARTIFACT_CHUNK_VERSION: u16 = 1;
const PREFIX_MMR_NODE_VERSION: u16 = 1;
const PREFIX_MMR_FRONTIER_VERSION: u16 = 1;
const PREFIX_MEMBERSHIP_PROOF_VERSION: u16 = 1;
const PORTABLE_COMPLETION_PROOF_VERSION: u16 = 2;
const ARCHIVE_HISTORY_NODE_VERSION: u16 = 1;
const ARCHIVE_CHECKPOINT_STATEMENT_VERSION: u16 = 1;
const ARCHIVE_CHECKPOINT_CERTIFICATE_VERSION: u16 = 1;
const MAX_ROAST_ARCHIVE_CHECKPOINT_STATEMENT_BYTES: usize = 4 * 1024;
const MAX_ROAST_ARCHIVE_CHECKPOINT_CERTIFICATE_BYTES: usize = 128 * 1024;
const ARCHIVE_CHECKPOINT_SESSION_DOMAIN: &[u8] = b"roast-archive-checkpoint-slot/v1";
const ROAST_ARCHIVE_STAGE_JOURNAL_VERSION: u16 = 2;

/// One complete certificate-bearing attempt proof.
pub const ROAST_ATTEMPT_RECORD_ARTIFACT: WalletArtifactKind = WalletArtifactKind(5);
/// One node in either immutable Patricia index.
pub const ROAST_SPARSE_INDEX_NODE_ARTIFACT: WalletArtifactKind = WalletArtifactKind(6);
/// One transaction-to-attempt mapping retaining the exact signed binding.
pub const ROAST_TRANSACTION_MAPPING_ARTIFACT: WalletArtifactKind = WalletArtifactKind(7);
/// One immutable archive-head transition.
pub const ROAST_ARCHIVE_COMMIT_ARTIFACT: WalletArtifactKind = WalletArtifactKind(8);
/// One immutable semantic-attempt MMR node.
pub const ROAST_PREFIX_MMR_NODE_ARTIFACT: WalletArtifactKind = WalletArtifactKind(9);
/// One per-family MMR frontier with content-addressed peak references.
pub const ROAST_PREFIX_MMR_FRONTIER_ARTIFACT: WalletArtifactKind = WalletArtifactKind(10);
/// One immutable node in the archive-transition history MMR.
pub const ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT: WalletArtifactKind = WalletArtifactKind(11);

/// Per-object bound for a certified attempt.  It remains below the generic wallet-artifact bound.
pub const MAX_ROAST_ATTEMPT_RECORD_BYTES: usize = 32 * 1024 * 1024;
/// Sparse nodes contain two content addresses at most.
pub const MAX_ROAST_SPARSE_INDEX_NODE_BYTES: usize = 4 * 1024;
/// Transaction mappings contain a fixed-size signed binding and two content commitments.
pub const MAX_ROAST_TRANSACTION_MAPPING_BYTES: usize = 16 * 1024 * 1024;
/// Archive commits contain roots, counters, and at most 64 transition-history MMR peaks.
pub const MAX_ROAST_ARCHIVE_COMMIT_BYTES: usize = 16 * 1024;
/// MMR nodes contain at most two child references and one semantic digest.
pub const MAX_ROAST_PREFIX_MMR_NODE_BYTES: usize = 4 * 1024;
/// A u64-sized MMR has at most 64 peaks.
pub const MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES: usize = 16 * 1024;
/// History nodes contain at most two child content addresses.
pub const MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES: usize = 4 * 1024;
/// Maximum plaintext bytes in one authenticated transfer response.
pub const MAX_ROAST_ARTIFACT_CHUNK_BYTES: usize = 1024 * 1024;
/// A single snapshot transaction never needs to evict an unbounded number of attempt bodies.
pub const MAX_ROAST_ATTEMPTS_PER_STAGE: usize = 256;
/// Maximum direct references returned for one archive DAG object.
pub const MAX_ROAST_ARTIFACT_DEPENDENCIES: usize = 68;
/// Maximum canonical bytes in one portable full late-settlement completion proof.
pub const MAX_ROAST_PORTABLE_COMPLETION_PROOF_BYTES: usize = 56 * 1024 * 1024;
const MAX_ROAST_ARCHIVE_SKIP_LEVELS: usize = u64::BITS as usize;
const MAX_ARCHIVED_ENDORSEMENTS: usize = MAX_COMMITTEE_MEMBERS;
const MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS: usize = 180_000;
const MAX_ROAST_ARCHIVE_STAGE_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Exact immutable proof for one absolute ROAST view/attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptArchiveRecord {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    family: [u8; 32],
    family_anchor: [u8; 32],
    view: u64,
    attempt: u64,
    slot: ConsolidationConsensusSlot,
    context: ConsensusContext,
    intent: ConsolidationIntent,
    intent_certificate: ConsolidationIntentCertificate,
    wire_binding: ConsolidationAttemptWireBinding,
    /// Complete all-selected authorization, when this view reached that phase before eviction.
    ///
    /// A digest-only placeholder is deliberately not a current-format option. Such a commitment
    /// cannot independently authorize a late settlement after the hot reducer is gone.
    key_image_certificate: Option<PortableKeyImageBindingCertificate>,
}

impl RoastAttemptArchiveRecord {
    /// Construct and fully verify one cold attempt proof.
    pub fn new(
        slot: ConsolidationConsensusSlot,
        context: ConsensusContext,
        intent: ConsolidationIntent,
        intent_certificate: ConsolidationIntentCertificate,
        wire_binding: ConsolidationAttemptWireBinding,
        key_image_certificate: Option<PortableKeyImageBindingCertificate>,
    ) -> Result<Self, RoastAttemptArchiveError> {
        let wallet = DepositWalletId(context.binding().wallet);
        let network = context.binding().network;
        let family_anchor = slot.family_anchor();
        let family = deterministic_roast_family_digest(
            slot.binding(),
            slot.committee(),
            slot.fault_bound(),
            intent.authorization(),
            family_anchor,
        );
        let view = slot.roast_view();
        let attempt = intent.attempt().attempt();
        let record = Self {
            version: ATTEMPT_RECORD_VERSION,
            wallet,
            network,
            family,
            family_anchor,
            view,
            attempt,
            slot,
            context,
            intent,
            intent_certificate,
            wire_binding,
            key_image_certificate,
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn family_anchor(&self) -> [u8; 32] {
        self.family_anchor
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn slot(&self) -> &ConsolidationConsensusSlot {
        &self.slot
    }

    #[must_use]
    pub const fn context(&self) -> &ConsensusContext {
        &self.context
    }

    #[must_use]
    pub const fn intent(&self) -> &ConsolidationIntent {
        &self.intent
    }

    #[must_use]
    pub const fn intent_certificate(&self) -> &ConsolidationIntentCertificate {
        &self.intent_certificate
    }

    #[must_use]
    pub const fn wire_binding(&self) -> &ConsolidationAttemptWireBinding {
        &self.wire_binding
    }

    #[must_use]
    pub const fn key_image_certificate(&self) -> Option<&PortableKeyImageBindingCertificate> {
        self.key_image_certificate.as_ref()
    }

    /// Require complete key-image provenance for a late-settlement proof.
    pub fn require_full_key_image_certificate(
        &self,
    ) -> Result<&PortableKeyImageBindingCertificate, RoastAttemptArchiveError> {
        self.key_image_certificate
            .as_ref()
            .ok_or(RoastAttemptArchiveError::MissingFullKeyImageCertificate)
    }

    /// Stable digest of the exact canonical proof bytes.
    pub fn digest(&self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        let bytes = self.to_bytes()?;
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/roast-attempt-archive/record/v1");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Witness-independent digest used by the globally sequenced semantic archive.
    pub fn semantic_digest(&self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        self.validate()?;
        let attempt = certified_roast_attempt_leaf(
            self.family,
            self.family_anchor,
            &self.slot,
            &self.context,
            &self.intent,
            &self.intent_certificate,
        )?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/roast-attempt-archive/semantic-record/v1",
        );
        hasher.update(&attempt);
        match &self.key_image_certificate {
            None => {
                hasher.update(&[0]);
            }
            Some(certificate) => {
                let value = certificate.verify(
                    self.slot.committee(),
                    self.slot.fault_bound(),
                    self.network,
                    &self.wire_binding,
                )?;
                let bytes = postcard::to_allocvec(value)
                    .map_err(|_| RoastAttemptArchiveError::Serialization)?;
                hasher.update(&[1]);
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(&bytes);
            }
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Verify every redundant binding and both portable certificates.
    pub fn validate(&self) -> Result<(), RoastAttemptArchiveError> {
        if self.version != ATTEMPT_RECORD_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.family == [0; 32]
            || self.family_anchor == [0; 32]
            || self.context.binding().wallet != self.wallet.0
            || self.context.binding().network != self.network
            || self.slot.binding() != self.context.binding()
            || self.slot.family_anchor() != self.family_anchor
            || self.slot.roast_view() != self.view
            || self.intent.attempt().attempt() != self.attempt
            || self.view.checked_add(1) != Some(self.attempt)
        {
            return Err(RoastAttemptArchiveError::InvalidAttemptRecord);
        }

        self.slot.verify_context(&self.context)?;
        self.intent_certificate.verify_expected(&self.context, &self.intent)?;
        let plan = RoastViewPlan::derive(
            &self.slot,
            self.slot.committee(),
            self.slot.fault_bound(),
            self.intent.authorization(),
        )?;
        let expected_wire = ConsolidationAttemptWireBinding::new(
            self.intent.authorization(),
            self.intent.attempt(),
            plan.relay_seed(),
        )?;
        if self.wire_binding != expected_wire
            || self.wire_binding.attempt() != self.intent.attempt()
            || self.wire_binding.authorization_digest() != self.intent.authorization().digest()
            || self.wire_binding.consolidation_id() != self.intent.authorization().id()
            || plan.view() != self.view
            || plan.attempt() != self.attempt
            || plan.signing_session() != self.intent.attempt().session()
            || plan.signers() != self.intent.attempt().signers()
            || deterministic_roast_family_digest(
                self.slot.binding(),
                self.slot.committee(),
                self.slot.fault_bound(),
                self.intent.authorization(),
                self.family_anchor,
            ) != self.family
        {
            return Err(RoastAttemptArchiveError::InvalidAttemptRecord);
        }

        if let Some(certificate) = &self.key_image_certificate {
            let key_images = certificate.verify(
                self.slot.committee(),
                self.slot.fault_bound(),
                self.network,
                &self.wire_binding,
            )?;
            let input_count = usize::try_from(self.intent.authorization().input_count())
                .map_err(|_| RoastAttemptArchiveError::InvalidAttemptRecord)?;
            if key_images.sweep() != self.intent.authorization().sweep_id()
                || key_images.inputs().len() != input_count
                || consolidation_input_set_binding(key_images.inputs())
                    != self.intent.authorization().input_set()
                || key_images.signing_context().into_bytes()
                    != self.intent.attempt().signing_context()
            {
                return Err(RoastAttemptArchiveError::InvalidAttemptRecord);
            }
        }
        Ok(())
    }

    /// Canonical bounded representation stored and transferred by content address.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RoastAttemptArchiveError> {
        self.validate()?;
        encode_bounded(self, MAX_ROAST_ATTEMPT_RECORD_BYTES, "ROAST attempt record")
    }

    /// Decode canonical bytes and reverify the complete proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RoastAttemptArchiveError> {
        let record: Self = decode_canonical_bounded(
            bytes,
            MAX_ROAST_ATTEMPT_RECORD_BYTES,
            "ROAST attempt record",
        )?;
        record.validate()?;
        Ok(record)
    }
}

/// Fixed-size snapshot pointer to both persistent sparse indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptArchiveHead {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    generation: u64,
    attempt_count: u64,
    transaction_count: u64,
    family_count: u64,
    view_root: Option<WalletArtifactRef>,
    transaction_root: Option<WalletArtifactRef>,
    family_root: Option<WalletArtifactRef>,
    semantic_view_root: [u8; 32],
    semantic_transaction_root: [u8; 32],
    semantic_family_root: [u8; 32],
    history_root: [u8; 32],
    commit: Option<WalletArtifactRef>,
}

impl RoastAttemptArchiveHead {
    /// Construct the sole empty head for a wallet/network domain.
    pub fn empty(
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<Self, RoastAttemptArchiveError> {
        let history_root = RoastArchiveHistoryFrontier::empty(wallet, network)?.root();
        let head = Self {
            version: ARCHIVE_HEAD_VERSION,
            wallet,
            network,
            generation: 0,
            attempt_count: 0,
            transaction_count: 0,
            family_count: 0,
            view_root: None,
            transaction_root: None,
            family_root: None,
            semantic_view_root: sparse_index_empty_digest(SparseIndexNamespace::View),
            semantic_transaction_root: sparse_index_empty_digest(SparseIndexNamespace::Transaction),
            semantic_family_root: sparse_index_empty_digest(SparseIndexNamespace::Family),
            history_root,
            commit: None,
        };
        head.validate()?;
        Ok(head)
    }

    #[must_use]
    pub const fn wallet_id(self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network_id(self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn attempt_count(self) -> u64 {
        self.attempt_count
    }

    #[must_use]
    pub const fn transaction_count(self) -> u64 {
        self.transaction_count
    }

    #[must_use]
    pub const fn family_count(self) -> u64 {
        self.family_count
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.attempt_count == 0
    }

    #[must_use]
    pub const fn view_root(self) -> Option<WalletArtifactRef> {
        self.view_root
    }

    #[must_use]
    pub const fn transaction_root(self) -> Option<WalletArtifactRef> {
        self.transaction_root
    }

    #[must_use]
    pub const fn family_root(self) -> Option<WalletArtifactRef> {
        self.family_root
    }

    #[must_use]
    pub const fn history_root(self) -> [u8; 32] {
        self.history_root
    }

    #[must_use]
    pub const fn semantic_view_root(self) -> [u8; 32] {
        self.semantic_view_root
    }

    #[must_use]
    pub const fn semantic_transaction_root(self) -> [u8; 32] {
        self.semantic_transaction_root
    }

    #[must_use]
    pub const fn semantic_family_root(self) -> [u8; 32] {
        self.semantic_family_root
    }

    /// Witness- and artifact-layout-independent state committed by archive checkpoints.
    pub fn semantic_state(self) -> Result<RoastArchiveSemanticState, RoastAttemptArchiveError> {
        Ok(RoastArchiveSemanticState::new(
            self.wallet,
            self.network,
            self.generation,
            self.attempt_count,
            self.transaction_count,
            self.family_count,
            self.semantic_view_root,
            (self.transaction_count != 0).then_some(self.semantic_transaction_root),
            self.semantic_family_root,
        )?)
    }

    pub fn semantic_digest(self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        Ok(self.semantic_state()?.digest())
    }

    #[must_use]
    pub const fn commit_reference(self) -> Option<WalletArtifactRef> {
        self.commit
    }

    /// Stable CAS value for this exact compact head.
    #[must_use]
    pub fn digest(self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/roast-attempt-archive/head/v2");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        hasher.update(&self.network);
        hasher.update(&self.generation.to_le_bytes());
        hasher.update(&self.attempt_count.to_le_bytes());
        hasher.update(&self.transaction_count.to_le_bytes());
        hasher.update(&self.family_count.to_le_bytes());
        hash_optional_reference(&mut hasher, self.view_root);
        hash_optional_reference(&mut hasher, self.transaction_root);
        hash_optional_reference(&mut hasher, self.family_root);
        hasher.update(&self.semantic_view_root);
        hasher.update(&self.semantic_transaction_root);
        hasher.update(&self.semantic_family_root);
        hasher.update(&self.history_root);
        hash_optional_reference(&mut hasher, self.commit);
        *hasher.finalize().as_bytes()
    }

    /// Validate the bounded snapshot shape. Store-backed APIs additionally authenticate `commit`.
    pub fn validate(self) -> Result<(), RoastAttemptArchiveError> {
        if self.version != ARCHIVE_HEAD_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || (self.attempt_count == 0) != self.view_root.is_none()
            || (self.transaction_count == 0) != self.transaction_root.is_none()
            || (self.family_count == 0) != self.family_root.is_none()
            || (self.attempt_count == 0) != (self.family_count == 0)
            || self.family_count > self.attempt_count
            || (self.attempt_count == 0)
                != (self.semantic_view_root
                    == sparse_index_empty_digest(SparseIndexNamespace::View))
            || (self.transaction_count == 0)
                != (self.semantic_transaction_root
                    == sparse_index_empty_digest(SparseIndexNamespace::Transaction))
            || (self.family_count == 0)
                != (self.semantic_family_root
                    == sparse_index_empty_digest(SparseIndexNamespace::Family))
            || (self.generation == 0) != self.commit.is_none()
            || (self.generation == 0) != (self.attempt_count == 0)
            || self.history_root == [0; 32]
            || self.digest() == [0; 32]
        {
            return Err(RoastAttemptArchiveError::InvalidArchiveHead);
        }
        if self.generation == 0
            && self.history_root
                != RoastArchiveHistoryFrontier::empty(self.wallet, self.network)?.root()
        {
            return Err(RoastAttemptArchiveError::InvalidArchiveHead);
        }
        self.semantic_state()?;
        if let Some(reference) = self.view_root {
            validate_reference(
                reference,
                self.wallet,
                ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
            )?;
        }
        if let Some(reference) = self.transaction_root {
            validate_reference(
                reference,
                self.wallet,
                ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
            )?;
        }
        if let Some(reference) = self.family_root {
            validate_reference(
                reference,
                self.wallet,
                ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
            )?;
        }
        if let Some(reference) = self.commit {
            validate_reference(
                reference,
                self.wallet,
                ROAST_ARCHIVE_COMMIT_ARTIFACT,
                MAX_ROAST_ARCHIVE_COMMIT_BYTES,
            )?;
        }
        Ok(())
    }
}

/// Witness-independent archive endpoint signed by one exact epoch committee.
///
/// Local encrypted artifact references are intentionally absent. Replicas which retain different
/// valid certificate-witness subsets therefore still sign the same semantic endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastArchiveCheckpointStatement {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    registry: [u8; 32],
    activation: [u8; 32],
    issuer_epoch: u64,
    issuer_committee: [u8; 32],
    committee_size: u16,
    threshold: u16,
    fault_bound: u16,
    state: RoastArchiveSemanticState,
    history_root: [u8; 32],
}

impl RoastArchiveCheckpointStatement {
    /// Construct the only endpoint statement for this local head and issuer context.
    #[allow(clippy::too_many_arguments)]
    pub fn for_head(
        head: RoastAttemptArchiveHead,
        committee: &Committee,
        fault_bound: u16,
        registry: [u8; 32],
        activation: [u8; 32],
    ) -> Result<Self, RoastAttemptArchiveError> {
        head.validate()?;
        committee.validate_async_security_with_faults(fault_bound)?;
        let statement = Self {
            version: ARCHIVE_CHECKPOINT_STATEMENT_VERSION,
            wallet: head.wallet,
            network: head.network,
            registry,
            activation,
            issuer_epoch: committee.epoch,
            issuer_committee: committee.digest(),
            committee_size: committee.n(),
            threshold: committee.threshold,
            fault_bound,
            state: head.semantic_state()?,
            history_root: head.history_root,
        };
        statement.validate_exact(
            committee,
            fault_bound,
            registry,
            activation,
            head.wallet,
            head.network,
        )?;
        Ok(statement)
    }

    fn validate_shape(&self) -> Result<(), RoastAttemptArchiveError> {
        self.state.validate()?;
        if self.version != ARCHIVE_CHECKPOINT_STATEMENT_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.registry == [0; 32]
            || self.activation == [0; 32]
            || self.issuer_committee == [0; 32]
            || self.committee_size == 0
            || usize::from(self.committee_size) > MAX_COMMITTEE_MEMBERS
            || self.threshold == 0
            || self.threshold > self.committee_size
            || self.committee_size < self.fault_bound.saturating_mul(3).saturating_add(1)
            || self.threshold <= self.fault_bound
            || self.threshold
                > self.committee_size.saturating_sub(self.fault_bound.saturating_mul(2))
            || self.state.wallet_id() != self.wallet
            || self.state.network_id() != self.network
            || self.history_root == [0; 32]
        {
            return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_exact(
        &self,
        committee: &Committee,
        fault_bound: u16,
        registry: [u8; 32],
        activation: [u8; 32],
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<(), RoastAttemptArchiveError> {
        self.validate_shape()?;
        committee.validate_async_security_with_faults(fault_bound)?;
        if self.wallet != wallet
            || self.network != network
            || self.registry != registry
            || self.activation != activation
            || self.issuer_epoch != committee.epoch
            || self.issuer_committee != committee.digest()
            || self.committee_size != committee.n()
            || self.threshold != committee.threshold
            || self.fault_bound != fault_bound
        {
            return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
        }
        Ok(())
    }

    /// Globally sequenced slot shared by all competing statements for one wallet generation.
    ///
    /// Issuer context and state are deliberately excluded. A party which overlaps an epoch
    /// transition cannot sign two different meanings for the same global archive generation.
    #[must_use]
    pub fn slot_session(&self) -> SessionId {
        let mut material = Vec::with_capacity(72);
        material.extend_from_slice(&self.wallet.0);
        material.extend_from_slice(&self.network);
        material.extend_from_slice(&self.state.generation().to_le_bytes());
        SessionId::derive(ARCHIVE_CHECKPOINT_SESSION_DOMAIN, &material)
    }

    #[must_use]
    pub fn decision_digest(&self) -> [u8; 32] {
        let bytes =
            postcard::to_allocvec(self).expect("validated archive checkpoint is serializable");
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/roast-archive-checkpoint/decision/v1");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RoastAttemptArchiveError> {
        self.validate_shape()?;
        encode_bounded(
            self,
            MAX_ROAST_ARCHIVE_CHECKPOINT_STATEMENT_BYTES,
            "ROAST archive checkpoint statement",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RoastAttemptArchiveError> {
        let statement: Self = decode_canonical_bounded(
            bytes,
            MAX_ROAST_ARCHIVE_CHECKPOINT_STATEMENT_BYTES,
            "ROAST archive checkpoint statement",
        )?;
        statement.validate_shape()?;
        Ok(statement)
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
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
    pub const fn issuer_epoch(&self) -> u64 {
        self.issuer_epoch
    }

    #[must_use]
    pub const fn issuer_committee(&self) -> [u8; 32] {
        self.issuer_committee
    }

    #[must_use]
    pub const fn fault_bound(&self) -> u16 {
        self.fault_bound
    }

    #[must_use]
    pub const fn semantic_state(&self) -> RoastArchiveSemanticState {
        self.state
    }

    #[must_use]
    pub const fn history_root(&self) -> [u8; 32] {
        self.history_root
    }
}

/// Canonically ordered `n-f` signatures over one semantic archive endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastArchiveCheckpointCertificate {
    version: u16,
    statement: RoastArchiveCheckpointStatement,
    #[serde(deserialize_with = "deserialize_archive_checkpoint_witnesses")]
    witnesses: Vec<SignedEnvelope>,
}

impl RoastArchiveCheckpointCertificate {
    fn validate_wire_shape(&self) -> Result<(), RoastAttemptArchiveError> {
        self.statement.validate_shape()?;
        let required = usize::from(
            self.statement
                .committee_size
                .checked_sub(self.statement.fault_bound)
                .ok_or(RoastAttemptArchiveError::InvalidCheckpointCertificate)?,
        );
        let payload = self.statement.to_bytes()?;
        if self.version != ARCHIVE_CHECKPOINT_CERTIFICATE_VERSION
            || self.witnesses.len() != required
            || self.witnesses.len() > MAX_COMMITTEE_MEMBERS
            || self.witnesses.windows(2).any(|pair| pair[0].from >= pair[1].from)
            || self.witnesses.iter().any(|witness| {
                witness.to.is_some()
                    || witness.committee != self.statement.issuer_committee
                    || witness.epoch != self.statement.issuer_epoch
                    || witness.session != self.statement.slot_session()
                    || witness.sequence != self.statement.state.generation()
                    || witness.payload != payload
            })
        {
            return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_witnesses(
        statement: RoastArchiveCheckpointStatement,
        mut witnesses: Vec<SignedEnvelope>,
        committee: &Committee,
        fault_bound: u16,
        registry: [u8; 32],
        activation: [u8; 32],
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<Self, RoastAttemptArchiveError> {
        witnesses.sort_unstable_by_key(|witness| witness.from);
        let certificate =
            Self { version: ARCHIVE_CHECKPOINT_CERTIFICATE_VERSION, statement, witnesses };
        certificate.verify(committee, fault_bound, registry, activation, wallet, network)?;
        Ok(certificate)
    }

    /// Verify exact epoch context and all `n-f` endpoint signatures.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        committee: &Committee,
        fault_bound: u16,
        registry: [u8; 32],
        activation: [u8; 32],
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<VerifiedRoastArchiveCheckpoint, RoastAttemptArchiveError> {
        if self.version != ARCHIVE_CHECKPOINT_CERTIFICATE_VERSION {
            return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
        }
        self.statement.validate_exact(
            committee,
            fault_bound,
            registry,
            activation,
            wallet,
            network,
        )?;
        let required = usize::from(
            committee
                .n()
                .checked_sub(fault_bound)
                .ok_or(RoastAttemptArchiveError::InvalidCheckpointCertificate)?,
        );
        self.validate_wire_shape()?;
        if self.witnesses.len() != required {
            return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
        }
        let payload = self.statement.to_bytes()?;
        let session = self.statement.slot_session();
        let sequence = self.statement.state.generation();
        let mut signers = Vec::with_capacity(required);
        for witness in &self.witnesses {
            Identity::verify_envelope(committee, witness.from, witness)?;
            if witness.to.is_some()
                || witness.session != session
                || witness.sequence != sequence
                || witness.payload != payload
            {
                return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
            }
            signers.push(witness.from);
        }
        Ok(VerifiedRoastArchiveCheckpoint { statement: self.statement.clone(), signers })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RoastAttemptArchiveError> {
        self.validate_wire_shape()?;
        encode_bounded(
            self,
            MAX_ROAST_ARCHIVE_CHECKPOINT_CERTIFICATE_BYTES,
            "ROAST archive checkpoint certificate",
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RoastAttemptArchiveError> {
        let certificate: Self = decode_canonical_bounded(
            bytes,
            MAX_ROAST_ARCHIVE_CHECKPOINT_CERTIFICATE_BYTES,
            "ROAST archive checkpoint certificate",
        )?;
        certificate.validate_wire_shape()?;
        Ok(certificate)
    }

    #[must_use]
    pub const fn statement(&self) -> &RoastArchiveCheckpointStatement {
        &self.statement
    }

    #[must_use]
    pub fn witnesses(&self) -> &[SignedEnvelope] {
        &self.witnesses
    }
}

/// Trusted result of exact endpoint-certificate verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRoastArchiveCheckpoint {
    statement: RoastArchiveCheckpointStatement,
    signers: Vec<PartyId>,
}

impl VerifiedRoastArchiveCheckpoint {
    #[must_use]
    pub const fn statement(&self) -> &RoastArchiveCheckpointStatement {
        &self.statement
    }

    #[must_use]
    pub const fn semantic_state(&self) -> RoastArchiveSemanticState {
        self.statement.state
    }

    #[must_use]
    pub const fn history_root(&self) -> [u8; 32] {
        self.statement.history_root
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ArchiveHistoryNodeBody {
    Leaf,
    Parent { left: WalletArtifactRef, right: WalletArtifactRef },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ArchiveHistoryNode {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    summary: RoastArchiveHistorySummary,
    body: ArchiveHistoryNodeBody,
}

impl ArchiveHistoryNode {
    fn width(self) -> Result<u64, RoastAttemptArchiveError> {
        self.summary
            .end_generation()
            .checked_sub(self.summary.start_generation())
            .ok_or(RoastAttemptArchiveError::InvalidHistoryMmr)
    }

    fn validate_shape(self) -> Result<(), RoastAttemptArchiveError> {
        let width = self.width()?;
        if self.version != ARCHIVE_HISTORY_NODE_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || width == 0
            || self.summary.digest() == [0; 32]
        {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        match self.body {
            ArchiveHistoryNodeBody::Leaf => {
                if self.summary.height() != 0 {
                    return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
                }
            }
            ArchiveHistoryNodeBody::Parent { left, right } => {
                if self.summary.height() == 0 || left == right {
                    return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
                }
                validate_reference(
                    left,
                    self.wallet,
                    ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT,
                    MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
                )?;
                validate_reference(
                    right,
                    self.wallet,
                    ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT,
                    MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastAttemptArchiveCommit {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    generation: u64,
    previous_commit: Option<WalletArtifactRef>,
    previous_head_digest: [u8; 32],
    previous_semantic_state: [u8; 32],
    attempt_count: u64,
    transaction_count: u64,
    family_count: u64,
    view_root: WalletArtifactRef,
    transaction_root: Option<WalletArtifactRef>,
    family_root: WalletArtifactRef,
    semantic_view_root: [u8; 32],
    semantic_transaction_root: [u8; 32],
    semantic_family_root: [u8; 32],
    history_frontier: RoastArchiveHistoryFrontier,
    #[serde(deserialize_with = "deserialize_history_peak_references")]
    history_peak_nodes: Vec<WalletArtifactRef>,
}

impl RoastAttemptArchiveCommit {
    fn head(&self, reference: WalletArtifactRef) -> RoastAttemptArchiveHead {
        RoastAttemptArchiveHead {
            version: ARCHIVE_HEAD_VERSION,
            wallet: self.wallet,
            network: self.network,
            generation: self.generation,
            attempt_count: self.attempt_count,
            transaction_count: self.transaction_count,
            family_count: self.family_count,
            view_root: Some(self.view_root),
            transaction_root: self.transaction_root,
            family_root: Some(self.family_root),
            semantic_view_root: self.semantic_view_root,
            semantic_transaction_root: self.semantic_transaction_root,
            semantic_family_root: self.semantic_family_root,
            history_root: self.history_frontier.root(),
            commit: Some(reference),
        }
    }

    fn semantic_state(&self) -> Result<RoastArchiveSemanticState, RoastAttemptArchiveError> {
        Ok(RoastArchiveSemanticState::new(
            self.wallet,
            self.network,
            self.generation,
            self.attempt_count,
            self.transaction_count,
            self.family_count,
            self.semantic_view_root,
            (self.transaction_count != 0).then_some(self.semantic_transaction_root),
            self.semantic_family_root,
        )?)
    }

    fn validate(&self) -> Result<(), RoastAttemptArchiveError> {
        self.history_frontier.validate_endpoint(self.semantic_state()?)?;
        if self.version != ARCHIVE_COMMIT_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.generation == 0
            || self.previous_head_digest == [0; 32]
            || self.previous_semantic_state == [0; 32]
            || self.attempt_count == 0
            || self.family_count == 0
            || self.family_count > self.attempt_count
            || (self.generation == 1) != self.previous_commit.is_none()
            || (self.transaction_count == 0) != self.transaction_root.is_none()
            || (self.transaction_count == 0)
                != (self.semantic_transaction_root
                    == sparse_index_empty_digest(SparseIndexNamespace::Transaction))
            || self.semantic_view_root == sparse_index_empty_digest(SparseIndexNamespace::View)
            || self.semantic_family_root == sparse_index_empty_digest(SparseIndexNamespace::Family)
            || self.history_frontier.leaf_count() != self.generation
            || self.history_frontier.peaks().len() != self.history_peak_nodes.len()
            || self.history_peak_nodes.len() > MAX_ROAST_ARCHIVE_SKIP_LEVELS
            || self.history_peak_nodes.iter().copied().collect::<BTreeSet<_>>().len()
                != self.history_peak_nodes.len()
        {
            return Err(RoastAttemptArchiveError::InvalidArchiveCommit);
        }
        validate_reference(
            self.view_root,
            self.wallet,
            ROAST_SPARSE_INDEX_NODE_ARTIFACT,
            MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
        )?;
        validate_reference(
            self.family_root,
            self.wallet,
            ROAST_SPARSE_INDEX_NODE_ARTIFACT,
            MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
        )?;
        if let Some(reference) = self.transaction_root {
            validate_reference(
                reference,
                self.wallet,
                ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
            )?;
        }
        if let Some(reference) = self.previous_commit {
            validate_reference(
                reference,
                self.wallet,
                ROAST_ARCHIVE_COMMIT_ARTIFACT,
                MAX_ROAST_ARCHIVE_COMMIT_BYTES,
            )?;
        }
        for reference in &self.history_peak_nodes {
            validate_reference(
                *reference,
                self.wallet,
                ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT,
                MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum SparseIndexNamespace {
    View,
    Transaction,
    Family,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum SparseIndexKey {
    View { family: [u8; 32], view: u64 },
    Transaction { family: [u8; 32], transaction: [u8; 32] },
    Family { family: [u8; 32] },
}

impl SparseIndexKey {
    const fn namespace(self) -> SparseIndexNamespace {
        match self {
            Self::View { .. } => SparseIndexNamespace::View,
            Self::Transaction { .. } => SparseIndexNamespace::Transaction,
            Self::Family { .. } => SparseIndexNamespace::Family,
        }
    }

    fn digest(self) -> [u8; 32] {
        let mut hasher = match self {
            Self::View { .. } => blake3::Hasher::new_derive_key(
                "threshold-monero/roast-attempt-archive/view-index/v1",
            ),
            Self::Transaction { .. } => blake3::Hasher::new_derive_key(
                "threshold-monero/roast-attempt-archive/transaction-index/v1",
            ),
            Self::Family { .. } => blake3::Hasher::new_derive_key(
                "threshold-monero/roast-attempt-archive/family-index/v1",
            ),
        };
        match self {
            Self::View { family, view } => {
                hasher.update(&family);
                hasher.update(&view.to_le_bytes());
            }
            Self::Transaction { family, transaction } => {
                hasher.update(&family);
                hasher.update(&transaction);
            }
            Self::Family { family } => {
                hasher.update(&family);
            }
        }
        *hasher.finalize().as_bytes()
    }
}

fn sparse_index_leaf_digest(key: SparseIndexKey, value_semantic_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/roast-attempt-archive/semantic-leaf/v1");
    hasher.update(&[key.namespace() as u8]);
    hasher.update(&key.digest());
    hasher.update(&value_semantic_digest);
    *hasher.finalize().as_bytes()
}

fn sparse_index_parent_digest(
    namespace: SparseIndexNamespace,
    bit: u16,
    left: [u8; 32],
    right: [u8; 32],
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/roast-attempt-archive/semantic-parent/v1");
    hasher.update(&[namespace as u8]);
    hasher.update(&bit.to_le_bytes());
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

fn sparse_index_empty_digest(namespace: SparseIndexNamespace) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/roast-attempt-archive/semantic-empty/v1");
    hasher.update(&[namespace as u8]);
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum SparseIndexBody {
    Leaf { key: SparseIndexKey, value: WalletArtifactRef },
    Branch { bit: u16, left: WalletArtifactRef, right: WalletArtifactRef },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SparseIndexNode {
    version: u16,
    wallet: DepositWalletId,
    namespace: SparseIndexNamespace,
    semantic_digest: [u8; 32],
    body: SparseIndexBody,
}

impl SparseIndexNode {
    fn leaf(
        wallet: DepositWalletId,
        key: SparseIndexKey,
        value: WalletArtifactRef,
        value_semantic_digest: [u8; 32],
    ) -> Self {
        let semantic_digest = sparse_index_leaf_digest(key, value_semantic_digest);
        Self {
            version: INDEX_NODE_VERSION,
            wallet,
            namespace: key.namespace(),
            semantic_digest,
            body: SparseIndexBody::Leaf { key, value },
        }
    }

    fn branch(
        wallet: DepositWalletId,
        namespace: SparseIndexNamespace,
        bit: u16,
        left: WalletArtifactRef,
        left_semantic_digest: [u8; 32],
        right: WalletArtifactRef,
        right_semantic_digest: [u8; 32],
    ) -> Self {
        let semantic_digest =
            sparse_index_parent_digest(namespace, bit, left_semantic_digest, right_semantic_digest);
        Self {
            version: INDEX_NODE_VERSION,
            wallet,
            namespace,
            semantic_digest,
            body: SparseIndexBody::Branch { bit, left, right },
        }
    }

    fn validate(&self) -> Result<(), RoastAttemptArchiveError> {
        if self.version != INDEX_NODE_VERSION
            || self.wallet.0 == [0; 32]
            || self.semantic_digest == [0; 32]
        {
            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
        }
        match self.body {
            SparseIndexBody::Leaf { key, value } => {
                if key.namespace() != self.namespace {
                    return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                }
                let (kind, maximum) = match key {
                    SparseIndexKey::View { family, .. } => {
                        if family == [0; 32] {
                            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                        }
                        (ROAST_ATTEMPT_RECORD_ARTIFACT, MAX_ROAST_ATTEMPT_RECORD_BYTES)
                    }
                    SparseIndexKey::Transaction { family, transaction } => {
                        if family == [0; 32] || transaction == [0; 32] {
                            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                        }
                        (ROAST_TRANSACTION_MAPPING_ARTIFACT, MAX_ROAST_TRANSACTION_MAPPING_BYTES)
                    }
                    SparseIndexKey::Family { family } => {
                        if family == [0; 32] {
                            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                        }
                        (ROAST_PREFIX_MMR_FRONTIER_ARTIFACT, MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES)
                    }
                };
                validate_reference(value, self.wallet, kind, maximum)?;
            }
            SparseIndexBody::Branch { bit, left, right } => {
                if bit >= 256 || left == right {
                    return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                }
                validate_reference(
                    left,
                    self.wallet,
                    ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                    MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
                )?;
                validate_reference(
                    right,
                    self.wallet,
                    ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                    MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum PrefixMmrNodeBody {
    Leaf { attempt_record: WalletArtifactRef },
    Parent { left: WalletArtifactRef, right: WalletArtifactRef },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PrefixMmrNode {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    family: [u8; 32],
    start_view: u64,
    height: u8,
    digest: [u8; 32],
    body: PrefixMmrNodeBody,
}

impl PrefixMmrNode {
    fn leaf(
        record: &RoastAttemptArchiveRecord,
        attempt_record: WalletArtifactRef,
        digest: [u8; 32],
    ) -> Self {
        Self {
            version: PREFIX_MMR_NODE_VERSION,
            wallet: record.wallet,
            network: record.network,
            family: record.family,
            start_view: record.view,
            height: 0,
            digest,
            body: PrefixMmrNodeBody::Leaf { attempt_record },
        }
    }

    fn parent(
        wallet: DepositWalletId,
        network: [u8; 32],
        family: [u8; 32],
        start_view: u64,
        height: u8,
        digest: [u8; 32],
        left: WalletArtifactRef,
        right: WalletArtifactRef,
    ) -> Self {
        Self {
            version: PREFIX_MMR_NODE_VERSION,
            wallet,
            network,
            family,
            start_view,
            height,
            digest,
            body: PrefixMmrNodeBody::Parent { left, right },
        }
    }

    fn width(self) -> Result<u64, RoastAttemptArchiveError> {
        1_u64.checked_shl(u32::from(self.height)).ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)
    }

    fn validate_shape(self) -> Result<(), RoastAttemptArchiveError> {
        let width = self.width()?;
        if self.version != PREFIX_MMR_NODE_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.family == [0; 32]
            || self.digest == [0; 32]
            || self.start_view.checked_add(width).is_none()
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
        }
        match self.body {
            PrefixMmrNodeBody::Leaf { attempt_record } => {
                if self.height != 0 {
                    return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
                }
                validate_reference(
                    attempt_record,
                    self.wallet,
                    ROAST_ATTEMPT_RECORD_ARTIFACT,
                    MAX_ROAST_ATTEMPT_RECORD_BYTES,
                )?;
            }
            PrefixMmrNodeBody::Parent { left, right } => {
                if self.height == 0 || left == right {
                    return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
                }
                validate_reference(
                    left,
                    self.wallet,
                    ROAST_PREFIX_MMR_NODE_ARTIFACT,
                    MAX_ROAST_PREFIX_MMR_NODE_BYTES,
                )?;
                validate_reference(
                    right,
                    self.wallet,
                    ROAST_PREFIX_MMR_NODE_ARTIFACT,
                    MAX_ROAST_PREFIX_MMR_NODE_BYTES,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PrefixMmrFrontierArtifact {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    family: [u8; 32],
    family_anchor: [u8; 32],
    #[serde(deserialize_with = "deserialize_prefix_frontier")]
    frontier: RoastAttemptPrefixFrontier,
    #[serde(deserialize_with = "deserialize_peak_references")]
    peak_nodes: Vec<WalletArtifactRef>,
}

impl PrefixMmrFrontierArtifact {
    fn validate_shape(&self) -> Result<(), RoastAttemptArchiveError> {
        let root = self.frontier.root()?;
        if self.version != PREFIX_MMR_FRONTIER_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.family == [0; 32]
            || self.family_anchor == [0; 32]
            || root == [0; 32]
            || self.frontier.peaks().len() != self.peak_nodes.len()
            || self.peak_nodes.len() > MAX_ROAST_ARCHIVE_SKIP_LEVELS
            || self.peak_nodes.iter().copied().collect::<BTreeSet<_>>().len()
                != self.peak_nodes.len()
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
        }
        for reference in &self.peak_nodes {
            validate_reference(
                *reference,
                self.wallet,
                ROAST_PREFIX_MMR_NODE_ARTIFACT,
                MAX_ROAST_PREFIX_MMR_NODE_BYTES,
            )?;
        }
        Ok(())
    }

    fn semantic_digest(&self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        self.validate_shape()?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/roast-attempt-archive/semantic-family-frontier/v1",
        );
        hasher.update(&self.wallet.0);
        hasher.update(&self.network);
        hasher.update(&self.family);
        hasher.update(&self.family_anchor);
        hasher.update(&self.frontier.leaf_count().to_le_bytes());
        hasher.update(&self.frontier.root()?);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Direct transaction lookup result stored independently of the immutable attempt record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastTransactionArchiveMapping {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    family: [u8; 32],
    family_anchor: [u8; 32],
    transaction: [u8; 32],
    view: u64,
    attempt: u64,
    attempt_record: WalletArtifactRef,
    attempt_record_digest: [u8; 32],
    plan: SweepPlan,
    signed: SignedTransactionBinding,
    signed_transaction: SignedSweepTransaction,
    key_images: PortableKeyImageBindingCertificate,
    #[serde(deserialize_with = "deserialize_archived_endorsements")]
    endorsements: Vec<PortableSignedTransactionAttestation>,
}

impl RoastTransactionArchiveMapping {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn family_anchor(&self) -> [u8; 32] {
        self.family_anchor
    }

    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 32] {
        self.transaction
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn attempt_record_reference(&self) -> WalletArtifactRef {
        self.attempt_record
    }

    #[must_use]
    pub const fn attempt_record_digest(&self) -> [u8; 32] {
        self.attempt_record_digest
    }

    #[must_use]
    pub const fn plan(&self) -> &SweepPlan {
        &self.plan
    }

    #[must_use]
    pub const fn signed_binding(&self) -> SignedTransactionBinding {
        self.signed
    }

    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedSweepTransaction {
        &self.signed_transaction
    }

    #[must_use]
    pub const fn key_image_certificate(&self) -> &PortableKeyImageBindingCertificate {
        &self.key_images
    }

    #[must_use]
    pub fn endorsements(&self) -> &[PortableSignedTransactionAttestation] {
        &self.endorsements
    }

    /// Stable digest of the full canonical transaction proof graph.
    pub fn digest(&self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        self.validate_shape()?;
        let bytes =
            encode_bounded(self, MAX_ROAST_TRANSACTION_MAPPING_BYTES, "ROAST transaction mapping")?;
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/roast-attempt-archive/mapping/v2");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn semantic_digest(
        &self,
        record: &RoastAttemptArchiveRecord,
    ) -> Result<[u8; 32], RoastAttemptArchiveError> {
        self.validate_record(record, self.attempt_record)?;
        let key_images = self.key_images.verify(
            record.slot.committee(),
            record.slot.fault_bound(),
            record.network,
            &record.wire_binding,
        )?;
        let key_image_bytes = postcard::to_allocvec(key_images)
            .map_err(|_| RoastAttemptArchiveError::Serialization)?;
        let signed_bytes = postcard::to_allocvec(&self.signed)
            .map_err(|_| RoastAttemptArchiveError::Serialization)?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/roast-attempt-archive/semantic-transaction/v1",
        );
        hasher.update(&record.semantic_digest()?);
        hasher.update(&self.plan.commitment());
        hasher.update(&(signed_bytes.len() as u64).to_le_bytes());
        hasher.update(&signed_bytes);
        hasher.update(&(key_image_bytes.len() as u64).to_le_bytes());
        hasher.update(&key_image_bytes);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate_shape(&self) -> Result<(), RoastAttemptArchiveError> {
        let canonical = SignedSweepTransaction::from_bytes(
            self.signed_transaction.as_bytes().to_vec(),
            Some(self.transaction),
        )?;
        if self.version != TRANSACTION_MAPPING_VERSION
            || self.wallet.0 == [0; 32]
            || self.network == [0; 32]
            || self.family == [0; 32]
            || self.family_anchor == [0; 32]
            || self.transaction == [0; 32]
            || self.attempt == 0
            || self.view.checked_add(1) != Some(self.attempt)
            || self.attempt_record_digest == [0; 32]
            || self.signed.transaction() != self.transaction
            || self.signed.attempt() != self.attempt
            || self.signed.authorization_digest() == [0; 32]
            || self.signed.attempt_binding_digest() == [0; 32]
            || self.signed.session().0 == [0; 32]
            || self.signed.signing_context() == [0; 32]
            || self.signed.opaque_intent().0 == [0; 32]
            || self.signed.exact_bytes_digest() == [0; 32]
            || self.signed.exact_bytes_len() == 0
            || canonical != self.signed_transaction
            || self.endorsements.is_empty()
            || self.endorsements.len() > MAX_ARCHIVED_ENDORSEMENTS
            || self.endorsements.windows(2).any(|pair| pair[0].origin() >= pair[1].origin())
        {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        validate_reference(
            self.attempt_record,
            self.wallet,
            ROAST_ATTEMPT_RECORD_ARTIFACT,
            MAX_ROAST_ATTEMPT_RECORD_BYTES,
        )
    }

    fn validate_record(
        &self,
        record: &RoastAttemptArchiveRecord,
        record_reference: WalletArtifactRef,
    ) -> Result<(), RoastAttemptArchiveError> {
        self.validate_shape()?;
        record.validate()?;
        self.plan.validate_public()?;
        let required_endorsements = usize::from(record.slot.fault_bound())
            .checked_add(1)
            .ok_or(RoastAttemptArchiveError::InvalidTransactionMapping)?;
        let key_images = self.key_images.verify(
            record.slot.committee(),
            record.slot.fault_bound(),
            record.network,
            &record.wire_binding,
        )?;
        if self.wallet != record.wallet
            || self.network != record.network
            || self.family != record.family
            || self.family_anchor != record.family_anchor
            || self.view != record.view
            || self.attempt != record.attempt
            || self.attempt_record != record_reference
            || self.attempt_record_digest != record.digest()?
            || self.plan.wallet != record.wallet
            || self.plan.id != record.intent.authorization().sweep_id()
            || self.plan.epoch != record.intent.attempt().epoch()
            || self.plan.destination_binding != record.intent.authorization().destination_policy()
            || self.plan.inputs.len()
                != usize::try_from(record.intent.authorization().input_count())
                    .map_err(|_| RoastAttemptArchiveError::InvalidTransactionMapping)?
            || consolidation_input_set_binding(&self.plan.inputs)
                != record.intent.authorization().input_set()
            || self.plan.total_input_atomic_units
                != record.intent.authorization().total_input_atomic_units()
            || self.signed.authorization_digest() != record.intent.authorization().digest()
            || self.signed.attempt_binding_digest() != record.intent.attempt().digest()
            || self.signed.session() != record.intent.attempt().session()
            || self.signed.signing_context() != record.intent.attempt().signing_context()
            || self.signed.opaque_intent() != record.intent.authorization().opaque_intent()
            || self.signed_transaction.transaction_id() != self.transaction
            || self.endorsements.len() != required_endorsements
            || record
                .key_image_certificate
                .as_ref()
                .is_some_and(|certificate| certificate != &self.key_images)
            || key_images.sweep() != record.intent.authorization().sweep_id()
            || key_images.inputs() != self.plan.inputs.as_slice()
            || key_images.inputs().len()
                != usize::try_from(record.intent.authorization().input_count())
                    .map_err(|_| RoastAttemptArchiveError::InvalidTransactionMapping)?
            || consolidation_input_set_binding(key_images.inputs())
                != record.intent.authorization().input_set()
            || key_images.signing_context().into_bytes()
                != record.intent.attempt().signing_context()
        {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        for endorsement in &self.endorsements {
            endorsement.verify(record.slot.committee(), record.network, &record.wire_binding)?;
            if endorsement.signed().binding() != self.signed
                || endorsement.signed().transaction() != &self.signed_transaction
            {
                return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
            }
        }
        let transaction_key_images =
            canonical_sweep_transaction_key_images(&self.signed_transaction)?;
        let certified_key_images =
            canonicalize_certified_sweep_key_images(key_images.key_images())?;
        if transaction_key_images != certified_key_images {
            return Err(RoastAttemptArchiveError::TransactionKeyImageMismatch);
        }
        Ok(())
    }
}

/// API-unforgeable proof that one exact transaction mapping is a member of an authenticated
/// archive head and is consistent with its independently indexed attempt record.
///
/// Fields are private and the type is not deserializable. Safe callers can obtain it only through
/// [`RoastAttemptArchiveStore::load_transaction`], after the full certificate graph and both
/// Patricia membership paths have been verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArchivedRoastTransaction {
    head: RoastAttemptArchiveHead,
    mapping: RoastTransactionArchiveMapping,
    attempt: RoastAttemptArchiveRecord,
}

impl VerifiedArchivedRoastTransaction {
    #[must_use]
    pub const fn archive_head(&self) -> RoastAttemptArchiveHead {
        self.head
    }

    #[must_use]
    pub const fn mapping(&self) -> &RoastTransactionArchiveMapping {
        &self.mapping
    }

    #[must_use]
    pub const fn attempt_record(&self) -> &RoastAttemptArchiveRecord {
        &self.attempt
    }
}

/// One sibling in a bottom-up MMR inclusion path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptPrefixSibling {
    height: u8,
    sibling_on_left: bool,
    digest: [u8; 32],
}

impl RoastAttemptPrefixSibling {
    #[must_use]
    pub const fn height(self) -> u8 {
        self.height
    }

    #[must_use]
    pub const fn sibling_on_left(self) -> bool {
        self.sibling_on_left
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Portable, bounded proof that one semantic certified-attempt leaf belongs to an exact terminal
/// ROAST prefix. Every BA voter can verify this without access to the proposer's archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastAttemptPrefixMembershipProof {
    version: u16,
    family: [u8; 32],
    family_anchor: [u8; 32],
    view: u64,
    attempt: u64,
    semantic_leaf: [u8; 32],
    #[serde(deserialize_with = "deserialize_prefix_siblings")]
    siblings: Vec<RoastAttemptPrefixSibling>,
    #[serde(deserialize_with = "deserialize_prefix_peaks")]
    peaks: Vec<RoastAttemptPrefixPeak>,
}

impl RoastAttemptPrefixMembershipProof {
    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn family_anchor(&self) -> [u8; 32] {
        self.family_anchor
    }

    #[must_use]
    pub const fn view(&self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn semantic_leaf(&self) -> [u8; 32] {
        self.semantic_leaf
    }

    #[must_use]
    pub fn siblings(&self) -> &[RoastAttemptPrefixSibling] {
        &self.siblings
    }

    #[must_use]
    pub fn peaks(&self) -> &[RoastAttemptPrefixPeak] {
        &self.peaks
    }

    /// Pure verification against the exact prefix selected by terminal BA.
    pub fn verify(
        &self,
        seal: RoastAttemptPrefixSeal,
    ) -> Result<RoastAttemptPrefixMemberBinding, RoastAttemptArchiveError> {
        if self.version != PREFIX_MEMBERSHIP_PROOF_VERSION
            || self.family == [0; 32]
            || self.family_anchor == [0; 32]
            || self.semantic_leaf == [0; 32]
            || self.view.checked_add(1) != Some(self.attempt)
            || self.family != seal.family()
            || self.family_anchor != seal.family_anchor()
            || self.view > seal.closed_through_view()
            || self.attempt > seal.closed_through_attempt()
            || self.siblings.len() > MAX_ROAST_ARCHIVE_SKIP_LEVELS
            || self.peaks.len() > MAX_ROAST_ARCHIVE_SKIP_LEVELS
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        let frontier = RoastAttemptPrefixFrontier::from_peaks(
            seal.closed_through_attempt(),
            self.peaks.clone(),
        )
        .map_err(RoastAttemptArchiveError::Roast)?;
        seal.verify_frontier(&frontier)?;

        let mut peak_start = 0_u64;
        let mut target_peak = None;
        for peak in &self.peaks {
            let width = 1_u64
                .checked_shl(u32::from(peak.height()))
                .ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?;
            let peak_end = peak_start
                .checked_add(width)
                .ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?;
            if self.view >= peak_start && self.view < peak_end {
                target_peak = Some((*peak, peak_start));
                break;
            }
            peak_start = peak_end;
        }
        let (target_peak, peak_start) =
            target_peak.ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?;
        if self.siblings.len() != usize::from(target_peak.height()) {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }

        let offset = self
            .view
            .checked_sub(peak_start)
            .ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?;
        let mut digest = self.semantic_leaf;
        for (level, sibling) in self.siblings.iter().copied().enumerate() {
            let height = u8::try_from(level)
                .map_err(|_| RoastAttemptArchiveError::InvalidPrefixMembership)?;
            let sibling_on_left = offset & (1_u64 << u32::from(height)) != 0;
            if sibling.height != height
                || sibling.sibling_on_left != sibling_on_left
                || sibling.digest == [0; 32]
            {
                return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
            }
            let parent_height =
                height.checked_add(1).ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?;
            digest = if sibling_on_left {
                roast_attempt_prefix_parent(parent_height, sibling.digest, digest)
            } else {
                roast_attempt_prefix_parent(parent_height, digest, sibling.digest)
            };
        }
        if digest != target_peak.digest() {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        Ok(RoastAttemptPrefixMemberBinding {
            family: self.family,
            family_anchor: self.family_anchor,
            view: self.view,
            attempt: self.attempt,
            semantic_leaf: self.semantic_leaf,
            prefix_accumulator: seal.accumulator(),
        })
    }

    /// Verify both portable MMR membership and the complete certified attempt that defines its
    /// semantic leaf.
    pub fn verify_record(
        &self,
        seal: RoastAttemptPrefixSeal,
        record: &RoastAttemptArchiveRecord,
    ) -> Result<RoastAttemptPrefixMemberBinding, RoastAttemptArchiveError> {
        record.validate()?;
        let semantic_leaf = certified_roast_attempt_leaf(
            record.family,
            record.family_anchor,
            &record.slot,
            &record.context,
            &record.intent,
            &record.intent_certificate,
        )?;
        if self.family != record.family
            || self.family_anchor != record.family_anchor
            || self.view != record.view
            || self.attempt != record.attempt
            || self.semantic_leaf != semantic_leaf
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        self.verify(seal)
    }

    /// Stable commitment suitable for BA evidence and persisted late-settlement state.
    pub fn digest(&self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        let bytes = encode_bounded(
            self,
            MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES,
            "ROAST prefix membership proof",
        )?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/roast-attempt-archive/prefix-membership-proof/v1",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Semantic coordinates authenticated by a portable prefix-membership proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoastAttemptPrefixMemberBinding {
    family: [u8; 32],
    family_anchor: [u8; 32],
    view: u64,
    attempt: u64,
    semantic_leaf: [u8; 32],
    prefix_accumulator: [u8; 32],
}

impl RoastAttemptPrefixMemberBinding {
    #[must_use]
    pub const fn family(self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn family_anchor(self) -> [u8; 32] {
        self.family_anchor
    }

    #[must_use]
    pub const fn view(self) -> u64 {
        self.view
    }

    #[must_use]
    pub const fn attempt(self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn semantic_leaf(self) -> [u8; 32] {
        self.semantic_leaf
    }

    #[must_use]
    pub const fn prefix_accumulator(self) -> [u8; 32] {
        self.prefix_accumulator
    }
}

/// Complete portable evidence needed by every Byzantine late-settlement voter.
///
/// The record proves the n-f certified intent, the mapping proves the all-selected key images and
/// canonical f+1 transaction endorsements, and `membership` proves that exact semantic attempt
/// belongs to the terminal prefix. A membership proof alone is never transaction authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortableRoastTransactionCompletionProof {
    version: u16,
    record: RoastAttemptArchiveRecord,
    mapping: RoastTransactionArchiveMapping,
    membership: RoastAttemptPrefixMembershipProof,
}

impl PortableRoastTransactionCompletionProof {
    #[must_use]
    pub const fn record(&self) -> &RoastAttemptArchiveRecord {
        &self.record
    }

    #[must_use]
    pub const fn mapping(&self) -> &RoastTransactionArchiveMapping {
        &self.mapping
    }

    #[must_use]
    pub const fn membership(&self) -> &RoastAttemptPrefixMembershipProof {
        &self.membership
    }

    /// Purely verify the full completion graph against voter-local expected coordinates and the
    /// exact terminal prefix seal selected by BA.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_expected(
        &self,
        seal: RoastAttemptPrefixSeal,
        expected_wallet: DepositWalletId,
        expected_network: [u8; 32],
        expected_family: [u8; 32],
        expected_transaction: [u8; 32],
    ) -> Result<VerifiedPortableRoastTransactionCompletion, RoastAttemptArchiveError> {
        if self.version != PORTABLE_COMPLETION_PROOF_VERSION
            || expected_wallet.0 == [0; 32]
            || expected_network == [0; 32]
            || expected_family == [0; 32]
            || expected_transaction == [0; 32]
            || expected_family != seal.family()
            || self.record.wallet != expected_wallet
            || self.record.network != expected_network
            || self.record.family != expected_family
            || self.mapping.wallet != expected_wallet
            || self.mapping.network != expected_network
            || self.mapping.family != expected_family
            || self.mapping.transaction != expected_transaction
        {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        self.record.validate()?;
        let record_bytes = self.record.to_bytes()?;
        self.mapping.attempt_record.verify_contents(&record_bytes)?;
        self.mapping.validate_record(&self.record, self.mapping.attempt_record)?;
        let member = self.membership.verify_record(seal, &self.record)?;
        let evidence_digest = self.digest()?;
        if evidence_digest == [0; 32] {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        Ok(VerifiedPortableRoastTransactionCompletion {
            proof: self.clone(),
            member,
            evidence_digest,
        })
    }

    /// Canonical bounded representation for QUIC chunking and Byzantine evidence.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RoastAttemptArchiveError> {
        encode_bounded(
            self,
            MAX_ROAST_PORTABLE_COMPLETION_PROOF_BYTES,
            "portable ROAST transaction completion proof",
        )
    }

    /// Decode the current format without allocating beyond the component and outer hard bounds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RoastAttemptArchiveError> {
        decode_canonical_bounded(
            bytes,
            MAX_ROAST_PORTABLE_COMPLETION_PROOF_BYTES,
            "portable ROAST transaction completion proof",
        )
    }

    pub fn digest(&self) -> Result<[u8; 32], RoastAttemptArchiveError> {
        let bytes = self.to_bytes()?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/roast-attempt-archive/portable-completion-proof/v2",
        );
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// API-unforgeable result of pure, full portable completion verification.
///
/// This token is suitable for BA admission. The worker still requires the separate local
/// [`VerifiedArchivedPrefixTransaction`] at commit time so portable evidence cannot bypass durable
/// archive membership/readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPortableRoastTransactionCompletion {
    proof: PortableRoastTransactionCompletionProof,
    member: RoastAttemptPrefixMemberBinding,
    evidence_digest: [u8; 32],
}

impl VerifiedPortableRoastTransactionCompletion {
    #[must_use]
    pub const fn proof(&self) -> &PortableRoastTransactionCompletionProof {
        &self.proof
    }

    #[must_use]
    pub const fn member(&self) -> RoastAttemptPrefixMemberBinding {
        self.member
    }

    #[must_use]
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 32] {
        self.proof.mapping.transaction
    }
}

/// API-unforgeable proof that an archived transaction's exact certified attempt is a member of
/// the terminal semantic MMR root selected by abandonment BA.
///
/// This, rather than a raw archive mapping or numeric high-water comparison, is the only archive
/// token suitable for worker late-settlement adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArchivedPrefixTransaction {
    transaction: VerifiedArchivedRoastTransaction,
    prefix_seal: RoastAttemptPrefixSeal,
    membership_proof: RoastAttemptPrefixMembershipProof,
    membership_digest: [u8; 32],
}

impl VerifiedArchivedPrefixTransaction {
    #[must_use]
    pub const fn archived_transaction(&self) -> &VerifiedArchivedRoastTransaction {
        &self.transaction
    }

    #[must_use]
    pub const fn attempt_record(&self) -> &RoastAttemptArchiveRecord {
        self.transaction.attempt_record()
    }

    #[must_use]
    pub const fn mapping(&self) -> &RoastTransactionArchiveMapping {
        self.transaction.mapping()
    }

    #[must_use]
    pub const fn prefix_seal(&self) -> RoastAttemptPrefixSeal {
        self.prefix_seal
    }

    #[must_use]
    pub const fn membership_proof(&self) -> &RoastAttemptPrefixMembershipProof {
        &self.membership_proof
    }

    /// Stable commitment persisted beside a late-settlement worker record.
    #[must_use]
    pub const fn membership_digest(&self) -> [u8; 32] {
        self.membership_digest
    }
}

/// Result of staging immutable objects before the caller's wallet-snapshot CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoastAttemptArchiveStage {
    pub head: RoastAttemptArchiveHead,
    /// Content-addressed objects absent while producing `head`.
    ///
    /// Objects already present before staging are referenced but deliberately omitted. These exact
    /// references become journaled reservation candidates before any of them is materialized.
    /// A concurrent writer may still install an identical object before reservation; that object
    /// is treated as pre-existing and is never deleted by abort recovery.
    pub created: Vec<WalletArtifactRef>,
    pub changed: bool,
    base_head_digest: [u8; 32],
}

impl RoastAttemptArchiveStage {
    #[must_use]
    pub const fn base_head_digest(&self) -> [u8; 32] {
        self.base_head_digest
    }

    /// Compare the caller's current snapshot head immediately before its snapshot CAS.
    ///
    /// This method does not mutate a global archive pointer. The returned head becomes authoritative
    /// only if the caller atomically persists it with the reducer state that evicted the proof.
    pub fn ensure_cas(
        &self,
        current: RoastAttemptArchiveHead,
    ) -> Result<RoastAttemptArchiveHead, RoastAttemptArchiveError> {
        current.validate()?;
        self.head.validate()?;
        if current.digest() != self.base_head_digest
            || current.wallet != self.head.wallet
            || current.network != self.head.network
        {
            return Err(RoastAttemptArchiveError::HeadCasMismatch);
        }
        Ok(self.head)
    }

    /// Compose two dependency-ordered stages while retaining the original snapshot CAS base.
    ///
    /// This is required when an eviction archives the attempt and its completed transaction in
    /// two immutable-object steps: the caller installs only the composed final head atomically
    /// with hot-body pruning, never the intermediate head.
    pub fn compose(self, next: RoastAttemptArchiveStage) -> Result<Self, RoastAttemptArchiveError> {
        if next.base_head_digest != self.head.digest()
            || self.head.wallet != next.head.wallet
            || self.head.network != next.head.network
        {
            return Err(RoastAttemptArchiveError::HeadCasMismatch);
        }
        let created = self
            .created
            .into_iter()
            .chain(next.created)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if created.len() > MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS {
            return Err(RoastAttemptArchiveError::TooManyJournalArtifacts {
                actual: created.len(),
                maximum: MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS,
            });
        }
        Ok(Self {
            head: next.head,
            created,
            changed: self.changed || next.changed,
            base_head_digest: self.base_head_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RoastArchiveStageJournal {
    version: u16,
    wallet: DepositWalletId,
    network: [u8; 32],
    owner: WalletArtifactOwner,
    base: RoastAttemptArchiveHead,
    target: RoastAttemptArchiveHead,
    #[serde(deserialize_with = "deserialize_archive_journal_artifacts")]
    candidates: Vec<WalletArtifactRef>,
}

impl RoastArchiveStageJournal {
    fn from_stage(
        base: RoastAttemptArchiveHead,
        stage: &RoastAttemptArchiveStage,
        owner: WalletArtifactOwner,
    ) -> Result<Self, RoastAttemptArchiveError> {
        stage.ensure_cas(base)?;
        let mut candidates = stage.created.clone();
        candidates.sort_unstable();
        candidates.dedup();
        let journal = Self {
            version: ROAST_ARCHIVE_STAGE_JOURNAL_VERSION,
            wallet: base.wallet,
            network: base.network,
            owner,
            base,
            target: stage.head,
            candidates,
        };
        journal.validate()?;
        Ok(journal)
    }

    fn validate(&self) -> Result<(), RoastAttemptArchiveError> {
        self.base.validate()?;
        self.target.validate()?;
        self.owner.validate()?;
        if self.version != ROAST_ARCHIVE_STAGE_JOURNAL_VERSION
            || self.wallet != self.base.wallet
            || self.wallet != self.target.wallet
            || self.network != self.base.network
            || self.network != self.target.network
            || self.base.generation >= self.target.generation
            || self.candidates.len() > MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS
            || self.candidates.windows(2).any(|pair| pair[0] >= pair[1])
            || self.candidates.iter().any(|reference| {
                reference.wallet_id() != WalletId(self.wallet.0)
                    || validate_roast_reference_bounds(*reference).is_err()
            })
        {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        Ok(())
    }

    fn key(&self) -> Result<DepositIndexJournalKey, RoastAttemptArchiveError> {
        roast_archive_journal_key(self.wallet, self.network)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, RoastAttemptArchiveError> {
        self.validate()?;
        encode_bounded(self, MAX_DEPOSIT_INDEX_JOURNAL_BYTES, "ROAST archive stage journal")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, RoastAttemptArchiveError> {
        let journal: Self = decode_canonical_bounded(
            bytes,
            MAX_DEPOSIT_INDEX_JOURNAL_BYTES,
            "ROAST archive stage journal",
        )?;
        journal.validate()?;
        Ok(journal)
    }
}

/// Durable bridge between immutable archive staging and the wallet-snapshot CAS.
#[derive(Clone, Debug)]
pub struct PreparedRoastAttemptArchiveStage {
    stage: RoastAttemptArchiveStage,
    journal_key: DepositIndexJournalKey,
    journal_bytes: Vec<u8>,
    owner: WalletArtifactOwner,
}

impl PreparedRoastAttemptArchiveStage {
    #[must_use]
    pub const fn head(&self) -> RoastAttemptArchiveHead {
        self.stage.head
    }

    #[must_use]
    pub const fn base_head_digest(&self) -> [u8; 32] {
        self.stage.base_head_digest
    }
}

/// Result of replaying the single old-head-derivable archive journal at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoastArchiveJournalRecovery {
    None,
    Aborted,
    Committed,
}

/// Bounded request for one plaintext content-addressed object chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastArtifactChunkRequest {
    version: u16,
    pub reference: WalletArtifactRef,
    pub offset: u64,
    pub maximum_bytes: u32,
}

impl RoastArtifactChunkRequest {
    pub fn new(
        reference: WalletArtifactRef,
        offset: u64,
        maximum_bytes: u32,
    ) -> Result<Self, RoastAttemptArchiveError> {
        let request = Self { version: ARTIFACT_CHUNK_VERSION, reference, offset, maximum_bytes };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), RoastAttemptArchiveError> {
        let maximum = usize::try_from(self.maximum_bytes)
            .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
        validate_roast_reference_bounds(self.reference)?;
        if self.version != ARTIFACT_CHUNK_VERSION
            || maximum != MAX_ROAST_ARTIFACT_CHUNK_BYTES
            || self.offset >= self.reference.plaintext_len()
            || self.offset % u64::try_from(MAX_ROAST_ARTIFACT_CHUNK_BYTES).unwrap() != 0
        {
            return Err(RoastAttemptArchiveError::InvalidArtifactChunk);
        }
        Ok(())
    }
}

/// One ordered plaintext transfer chunk. Complete assembly is authenticated by `reference`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoastArtifactChunk {
    version: u16,
    pub reference: WalletArtifactRef,
    pub offset: u64,
    #[serde(deserialize_with = "deserialize_artifact_chunk_bytes")]
    pub bytes: Vec<u8>,
    pub complete: bool,
}

impl RoastArtifactChunk {
    fn validate(&self) -> Result<(), RoastAttemptArchiveError> {
        let length = u64::try_from(self.bytes.len())
            .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RoastAttemptArchiveError::InvalidArtifactChunk)?;
        validate_roast_reference_bounds(self.reference)?;
        let expected_length = usize::try_from(
            self.reference
                .plaintext_len()
                .saturating_sub(self.offset)
                .min(u64::try_from(MAX_ROAST_ARTIFACT_CHUNK_BYTES).unwrap()),
        )
        .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
        if self.version != ARTIFACT_CHUNK_VERSION
            || self.bytes.is_empty()
            || self.bytes.len() != expected_length
            || self.offset >= self.reference.plaintext_len()
            || self.offset % u64::try_from(MAX_ROAST_ARTIFACT_CHUNK_BYTES).unwrap() != 0
            || end > self.reference.plaintext_len()
            || self.complete != (end == self.reference.plaintext_len())
        {
            return Err(RoastAttemptArchiveError::InvalidArtifactChunk);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct IndexTraceFrame {
    reference: WalletArtifactRef,
    node: SparseIndexNode,
    went_right: bool,
}

struct IndexTrace {
    frames: Vec<IndexTraceFrame>,
    leaf_reference: WalletArtifactRef,
    leaf: SparseIndexNode,
}

#[derive(Debug)]
struct RoastArchiveObjectPlan {
    base: RoastAttemptArchiveHead,
    current: RoastAttemptArchiveHead,
    objects: BTreeMap<WalletArtifactRef, Vec<u8>>,
    total_bytes: usize,
    sealed: bool,
}

/// Per-party encrypted backing store for the immutable cold archive.
#[derive(Debug)]
pub struct RoastAttemptArchiveStore {
    artifacts: WalletArtifactStore,
    party: PartyId,
    object_plan: Mutex<Option<RoastArchiveObjectPlan>>,
    artifact_owner: Mutex<Option<WalletArtifactOwner>>,
}

impl RoastAttemptArchiveStore {
    pub fn new(
        directory: impl Into<PathBuf>,
        party: PartyId,
        identity_seed: &[u8; 32],
    ) -> Result<Self, RoastAttemptArchiveError> {
        Ok(Self {
            artifacts: WalletArtifactStore::new(directory, party, identity_seed)?,
            party,
            object_plan: Mutex::new(None),
            artifact_owner: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn artifact_path(&self, reference: WalletArtifactRef) -> PathBuf {
        self.artifacts.artifact_path(reference)
    }

    /// Authenticate an exact compact head and its bounded semantic-history frontier.
    ///
    /// This accepts only a locally trusted snapshot endpoint. A peer endpoint must additionally
    /// pass [`Self::verify_transferred_head`] with an `n-f` checkpoint and bounded consistency proof.
    pub async fn verify_head(
        &self,
        head: RoastAttemptArchiveHead,
    ) -> Result<(), RoastAttemptArchiveError> {
        self.require_head(head).await
    }

    /// Durably reserve the global `(wallet, network, generation)` slot, then sign its exact state.
    ///
    /// The protocol-store tombstone is persisted before the signature is returned. An exact retry
    /// is idempotent; a competing statement for the same generation conflicts after restart as
    /// well as in-process.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_checkpoint<R: RngCore + CryptoRng>(
        &self,
        protocols: &ProtocolStore,
        identity: &Identity,
        head: RoastAttemptArchiveHead,
        committee: &Committee,
        fault_bound: u16,
        registry: [u8; 32],
        activation: [u8; 32],
        rng: &mut R,
    ) -> Result<(RoastArchiveCheckpointStatement, SignedEnvelope), RoastAttemptArchiveError> {
        self.require_head(head).await?;
        if self.party != identity.party() || protocols.party_id() != self.party {
            return Err(RoastAttemptArchiveError::CheckpointStorePartyMismatch);
        }
        let statement = RoastArchiveCheckpointStatement::for_head(
            head,
            committee,
            fault_bound,
            registry,
            activation,
        )?;
        let purpose = statement.decision_digest();
        protocols.save_session_tombstone(statement.slot_session(), &purpose, rng).await?;
        let witness = identity.sign_envelope(
            committee,
            statement.slot_session(),
            None,
            statement.state.generation(),
            statement.to_bytes()?,
        )?;
        Ok((statement, witness))
    }

    /// Durably journal the complete absent-object plan, then materialize it before snapshot CAS.
    ///
    /// Staging itself performs no artifact writes. Objects which already existed when the plan was
    /// built are referenced by the resulting head but excluded from both the journal and cleanup.
    /// Journal candidates are only cleanup-owned after an exact durable reservation succeeds.
    pub async fn prepare_stage<R: RngCore + CryptoRng>(
        &self,
        protocols: &ProtocolStore,
        base: RoastAttemptArchiveHead,
        stage: RoastAttemptArchiveStage,
        rng: &mut R,
    ) -> Result<Option<PreparedRoastAttemptArchiveStage>, RoastAttemptArchiveError> {
        self.prepare_stage_inner(protocols, base, stage, rng, None).await
    }

    async fn prepare_stage_inner<R: RngCore + CryptoRng>(
        &self,
        protocols: &ProtocolStore,
        base: RoastAttemptArchiveHead,
        stage: RoastAttemptArchiveStage,
        rng: &mut R,
        crash_after_artifact_write: Option<usize>,
    ) -> Result<Option<PreparedRoastAttemptArchiveStage>, RoastAttemptArchiveError> {
        if protocols.party_id() != self.party {
            return Err(RoastAttemptArchiveError::CheckpointStorePartyMismatch);
        }
        if self.artifact_owner.lock().await.is_some() {
            return Err(RoastAttemptArchiveError::ArchiveStageInProgress);
        }
        self.require_head(base).await?;
        stage.ensure_cas(base)?;
        if !stage.changed {
            return if stage.head == base && stage.created.is_empty() {
                Ok(None)
            } else {
                Err(RoastAttemptArchiveError::InvalidStageJournal)
            };
        }
        if stage.created.len() > MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS {
            return Err(RoastAttemptArchiveError::TooManyJournalArtifacts {
                actual: stage.created.len(),
                maximum: MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS,
            });
        }

        {
            let guard = self.object_plan.lock().await;
            let plan = guard.as_ref().ok_or(RoastAttemptArchiveError::ArchiveStageInProgress)?;
            Self::validate_object_plan(plan, base, &stage)?;
        }

        // Authenticate the entire target DAG while every new object is still available only from
        // the bounded in-memory overlay. No filesystem object exists at this point.
        self.require_head(stage.head).await?;
        self.verify_local_ancestry(base, stage.head).await?;

        let owner = WalletArtifactOwner::random(rng);
        let journal = RoastArchiveStageJournal::from_stage(base, &stage, owner)?;
        let journal_key = journal.key()?;
        let journal_bytes = journal.to_bytes()?;
        let objects = {
            let mut guard = self.object_plan.lock().await;
            let plan = guard.as_mut().ok_or(RoastAttemptArchiveError::ArchiveStageInProgress)?;
            Self::validate_object_plan(plan, base, &stage)?;
            if crash_after_artifact_write.is_some_and(|cut| cut > plan.objects.len()) {
                return Err(RoastAttemptArchiveError::InvalidStageJournal);
            }
            plan.sealed = true;
            plan.total_bytes = 0;
            std::mem::take(&mut plan.objects)
        };
        protocols.save_deposit_index_journal(journal_key, &journal_bytes, rng).await?;
        let durable = protocols
            .load_deposit_index_journal(journal_key)
            .await?
            .ok_or(RoastAttemptArchiveError::InvalidStageJournal)?;
        if durable.as_bytes() != journal_bytes {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        {
            let mut active = self.artifact_owner.lock().await;
            if active.is_some() {
                return Err(RoastAttemptArchiveError::ArchiveStageInProgress);
            }
            *active = Some(owner);
        }

        if crash_after_artifact_write == Some(0) {
            return Err(RoastAttemptArchiveError::InjectedArchiveStageCrash {
                completed_writes: 0,
            });
        }
        for (index, (reference, bytes)) in objects.into_iter().enumerate() {
            let (installed_reference, _ownership) = self
                .artifacts
                .create_artifact_owned(owner, reference.wallet_id(), reference.kind(), &bytes, rng)
                .await?;
            if installed_reference != reference {
                return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
            }
            let completed_writes = index + 1;
            if crash_after_artifact_write == Some(completed_writes) {
                return Err(RoastAttemptArchiveError::InjectedArchiveStageCrash {
                    completed_writes,
                });
            }

            let restored = self.artifacts.load_artifact_owned(reference, owner).await?;
            if restored.contents.as_bytes() != bytes {
                return Err(RoastAttemptArchiveError::ReadbackMismatch);
            }
        }

        // Drop the overlay before the final authentication so this check can only succeed from
        // the durable immutable objects which the snapshot CAS is about to reference.
        *self.object_plan.lock().await = None;
        self.require_head(stage.head).await?;
        Ok(Some(PreparedRoastAttemptArchiveStage { stage, journal_key, journal_bytes, owner }))
    }

    #[cfg(test)]
    async fn prepare_stage_with_crash_after_artifact_write<R: RngCore + CryptoRng>(
        &self,
        protocols: &ProtocolStore,
        base: RoastAttemptArchiveHead,
        stage: RoastAttemptArchiveStage,
        rng: &mut R,
        completed_writes: usize,
    ) -> Result<Option<PreparedRoastAttemptArchiveStage>, RoastAttemptArchiveError> {
        self.prepare_stage_inner(protocols, base, stage, rng, Some(completed_writes)).await
    }

    /// Finish a prepared stage after authenticating the exact post-CAS snapshot head.
    pub async fn commit_prepared_stage(
        &self,
        protocols: &ProtocolStore,
        prepared: &PreparedRoastAttemptArchiveStage,
        authenticated_head: RoastAttemptArchiveHead,
    ) -> Result<(), RoastAttemptArchiveError> {
        if protocols.party_id() != self.party || authenticated_head != prepared.stage.head {
            return Err(RoastAttemptArchiveError::StageJournalHeadMismatch);
        }
        let journal = self.require_exact_stage_journal(protocols, prepared).await?;
        self.activate_artifact_owner(journal.owner).await?;
        self.require_head(authenticated_head).await?;
        for reference in &journal.candidates {
            self.artifacts.release_artifact_ownership(*reference, journal.owner).await?;
        }
        protocols
            .destroy_deposit_index_journal(prepared.journal_key, &prepared.journal_bytes)
            .await?;
        self.clear_artifact_owner(journal.owner).await?;
        Ok(())
    }

    /// Abort a prepared stage after authenticating that the old snapshot head remains authoritative.
    pub async fn abort_prepared_stage(
        &self,
        protocols: &ProtocolStore,
        prepared: &PreparedRoastAttemptArchiveStage,
        authenticated_head: RoastAttemptArchiveHead,
    ) -> Result<(), RoastAttemptArchiveError> {
        let journal = self.require_exact_stage_journal(protocols, prepared).await?;
        if protocols.party_id() != self.party || authenticated_head != journal.base {
            return Err(RoastAttemptArchiveError::StageJournalHeadMismatch);
        }
        self.activate_artifact_owner(journal.owner).await?;
        self.require_head(authenticated_head).await?;
        for reference in &journal.candidates {
            self.artifacts.remove_artifact_if_owned(*reference, journal.owner).await?;
        }
        protocols
            .destroy_deposit_index_journal(prepared.journal_key, &prepared.journal_bytes)
            .await?;
        self.clear_artifact_owner(journal.owner).await?;
        Ok(())
    }

    /// Replay the one fixed, wallet-scoped archive journal without directory enumeration.
    pub async fn recover_stage_journal(
        &self,
        protocols: &ProtocolStore,
        authenticated_head: RoastAttemptArchiveHead,
    ) -> Result<RoastArchiveJournalRecovery, RoastAttemptArchiveError> {
        if protocols.party_id() != self.party {
            return Err(RoastAttemptArchiveError::CheckpointStorePartyMismatch);
        }
        authenticated_head.validate()?;
        let key = roast_archive_journal_key(authenticated_head.wallet, authenticated_head.network)?;
        let Some(blob) = protocols.load_deposit_index_journal(key).await? else {
            *self.object_plan.lock().await = None;
            *self.artifact_owner.lock().await = None;
            self.require_head(authenticated_head).await?;
            return Ok(RoastArchiveJournalRecovery::None);
        };
        // Recovery authenticates only durable state. A same-process simulated crash must not be
        // able to satisfy target-head checks from the abandoned in-memory overlay.
        *self.object_plan.lock().await = None;
        let bytes = blob.into_bytes();
        let journal = RoastArchiveStageJournal::from_bytes(&bytes)?;
        if journal.key()? != key {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        self.activate_artifact_owner(journal.owner).await?;
        let outcome = if authenticated_head == journal.base {
            self.require_head(authenticated_head).await?;
            for reference in &journal.candidates {
                self.artifacts.remove_artifact_if_owned(*reference, journal.owner).await?;
            }
            RoastArchiveJournalRecovery::Aborted
        } else if authenticated_head == journal.target {
            self.require_head(journal.target).await?;
            for reference in &journal.candidates {
                self.artifacts.release_artifact_ownership(*reference, journal.owner).await?;
            }
            RoastArchiveJournalRecovery::Committed
        } else {
            return Err(RoastAttemptArchiveError::StageJournalHeadMismatch);
        };
        protocols.destroy_deposit_index_journal(key, &bytes).await?;
        self.clear_artifact_owner(journal.owner).await?;
        Ok(outcome)
    }

    async fn require_exact_stage_journal(
        &self,
        protocols: &ProtocolStore,
        prepared: &PreparedRoastAttemptArchiveStage,
    ) -> Result<RoastArchiveStageJournal, RoastAttemptArchiveError> {
        let durable = protocols
            .load_deposit_index_journal(prepared.journal_key)
            .await?
            .ok_or(RoastAttemptArchiveError::InvalidStageJournal)?;
        if durable.as_bytes() != prepared.journal_bytes {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        let journal = RoastArchiveStageJournal::from_bytes(durable.as_bytes())?;
        if journal.key()? != prepared.journal_key
            || journal.base.digest() != prepared.stage.base_head_digest
            || journal.target != prepared.stage.head
            || journal.candidates != prepared.stage.created
            || journal.owner != prepared.owner
        {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        Ok(journal)
    }

    async fn activate_artifact_owner(
        &self,
        owner: WalletArtifactOwner,
    ) -> Result<(), RoastAttemptArchiveError> {
        let mut active = self.artifact_owner.lock().await;
        match *active {
            Some(current) if current == owner => Ok(()),
            Some(_) => Err(RoastAttemptArchiveError::ArchiveStageInProgress),
            None => {
                *active = Some(owner);
                Ok(())
            }
        }
    }

    async fn clear_artifact_owner(
        &self,
        owner: WalletArtifactOwner,
    ) -> Result<(), RoastAttemptArchiveError> {
        let mut active = self.artifact_owner.lock().await;
        if *active != Some(owner) {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        *active = None;
        Ok(())
    }

    async fn ensure_object_plan(
        &self,
        current: RoastAttemptArchiveHead,
    ) -> Result<bool, RoastAttemptArchiveError> {
        current.validate()?;
        if self.artifact_owner.lock().await.is_some() {
            return Err(RoastAttemptArchiveError::ArchiveStageInProgress);
        }
        let mut guard = self.object_plan.lock().await;
        match guard.as_ref() {
            Some(plan) if plan.current == current && !plan.sealed => Ok(false),
            // The authoritative snapshot still names the original base, so a new operation from
            // that base safely abandons the prior memory-only branch. No journal or artifact
            // exists until `prepare_stage` seals the plan.
            Some(plan) if plan.base == current && !plan.sealed => {
                *guard = Some(RoastArchiveObjectPlan {
                    base: current,
                    current,
                    objects: BTreeMap::new(),
                    total_bytes: 0,
                    sealed: false,
                });
                Ok(true)
            }
            Some(_) => Err(RoastAttemptArchiveError::ArchiveStageInProgress),
            None => {
                *guard = Some(RoastArchiveObjectPlan {
                    base: current,
                    current,
                    objects: BTreeMap::new(),
                    total_bytes: 0,
                    sealed: false,
                });
                Ok(true)
            }
        }
    }

    fn validate_object_plan(
        plan: &RoastArchiveObjectPlan,
        base: RoastAttemptArchiveHead,
        stage: &RoastAttemptArchiveStage,
    ) -> Result<(), RoastAttemptArchiveError> {
        let candidates = plan.objects.keys().copied().collect::<Vec<_>>();
        let total_bytes = plan
            .objects
            .values()
            .try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()))
            .ok_or(RoastAttemptArchiveError::ArchiveStageResourceLimit)?;
        if plan.sealed
            || plan.base != base
            || plan.current != stage.head
            || candidates != stage.created
            || plan.total_bytes != total_bytes
            || total_bytes > MAX_ROAST_ARCHIVE_STAGE_TOTAL_BYTES
        {
            return Err(RoastAttemptArchiveError::InvalidStageJournal);
        }
        for (reference, bytes) in &plan.objects {
            if WalletArtifactRef::for_contents(reference.wallet_id(), reference.kind(), bytes)?
                != *reference
            {
                return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
            }
        }
        Ok(())
    }

    async fn finish_object_plan_stage(
        &self,
        started: bool,
        result: &Result<RoastAttemptArchiveStage, RoastAttemptArchiveError>,
    ) -> Result<(), RoastAttemptArchiveError> {
        let mut guard = self.object_plan.lock().await;
        match result {
            Ok(stage) if stage.changed => {
                let plan =
                    guard.as_mut().ok_or(RoastAttemptArchiveError::ArchiveStageInProgress)?;
                if plan.sealed
                    || plan.current.digest() != stage.base_head_digest
                    || plan.base.wallet != stage.head.wallet
                    || plan.base.network != stage.head.network
                {
                    *guard = None;
                    return Err(RoastAttemptArchiveError::ArchiveStageInProgress);
                }
                plan.current = stage.head;
            }
            Ok(_) if started => {
                *guard = None;
            }
            Ok(_) => {}
            Err(_) => {
                *guard = None;
            }
        }
        Ok(())
    }

    async fn plan_artifact<R: RngCore + CryptoRng>(
        &self,
        wallet: WalletId,
        kind: WalletArtifactKind,
        bytes: &[u8],
        _rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        let reference = WalletArtifactRef::for_contents(wallet, kind, bytes)?;
        {
            let guard = self.object_plan.lock().await;
            let plan = guard.as_ref().ok_or(RoastAttemptArchiveError::ArchiveStageInProgress)?;
            if plan.sealed {
                return Err(RoastAttemptArchiveError::ArchiveStageInProgress);
            }
            if let Some(existing) = plan.objects.get(&reference) {
                if existing.as_slice() != bytes {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                return Ok(reference);
            }
        }

        match self.artifacts.load_artifact(reference).await {
            Ok(existing) => {
                if existing.contents.as_bytes() != bytes {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                return Ok(reference);
            }
            Err(StoreError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let mut guard = self.object_plan.lock().await;
        let plan = guard.as_mut().ok_or(RoastAttemptArchiveError::ArchiveStageInProgress)?;
        if plan.sealed {
            return Err(RoastAttemptArchiveError::ArchiveStageInProgress);
        }
        if let Some(existing) = plan.objects.get(&reference) {
            if existing.as_slice() != bytes {
                return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
            }
            return Ok(reference);
        }
        let total_bytes = plan
            .total_bytes
            .checked_add(bytes.len())
            .ok_or(RoastAttemptArchiveError::ArchiveStageResourceLimit)?;
        if plan.objects.len() == MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS
            || total_bytes > MAX_ROAST_ARCHIVE_STAGE_TOTAL_BYTES
        {
            return Err(RoastAttemptArchiveError::ArchiveStageResourceLimit);
        }
        plan.objects.insert(reference, bytes.to_vec());
        plan.total_bytes = total_bytes;
        created.insert(reference);
        Ok(reference)
    }

    async fn load_artifact_bytes(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<Vec<u8>, RoastAttemptArchiveError> {
        if let Some(bytes) = self
            .object_plan
            .lock()
            .await
            .as_ref()
            .and_then(|plan| plan.objects.get(&reference))
            .cloned()
        {
            return Ok(bytes);
        }
        let owner = *self.artifact_owner.lock().await;
        let artifact = match owner {
            Some(owner) => self.artifacts.load_artifact_owned(reference, owner).await?,
            None => self.artifacts.load_artifact(reference).await?,
        };
        Ok(artifact.contents.as_bytes().to_vec())
    }

    /// Stage and authenticate one or more immutable attempt proofs.
    pub async fn stage_attempts<R: RngCore + CryptoRng>(
        &self,
        current_head: RoastAttemptArchiveHead,
        records: &[RoastAttemptArchiveRecord],
        rng: &mut R,
    ) -> Result<RoastAttemptArchiveStage, RoastAttemptArchiveError> {
        let started = self.ensure_object_plan(current_head).await?;
        let result = self.stage_attempts_inner(current_head, records, rng).await;
        self.finish_object_plan_stage(started, &result).await?;
        result
    }

    async fn stage_attempts_inner<R: RngCore + CryptoRng>(
        &self,
        current_head: RoastAttemptArchiveHead,
        records: &[RoastAttemptArchiveRecord],
        rng: &mut R,
    ) -> Result<RoastAttemptArchiveStage, RoastAttemptArchiveError> {
        self.require_head(current_head).await?;
        if records.len() > MAX_ROAST_ATTEMPTS_PER_STAGE {
            return Err(RoastAttemptArchiveError::TooManyAttemptsInStage {
                actual: records.len(),
                maximum: MAX_ROAST_ATTEMPTS_PER_STAGE,
            });
        }
        let base_head_digest = current_head.digest();
        let mut view_root = current_head.view_root;
        let transaction_root = current_head.transaction_root;
        let mut family_root = current_head.family_root;
        let mut attempt_count = current_head.attempt_count;
        let mut family_count = current_head.family_count;
        let mut created = BTreeSet::new();
        let mut inserted = Vec::new();
        let mut ordered = records.iter().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|record| (record.family, record.view));

        for record in ordered {
            record.validate()?;
            if record.wallet != current_head.wallet || record.network != current_head.network {
                return Err(RoastAttemptArchiveError::WrongArchiveDomain);
            }
            let key = SparseIndexKey::View { family: record.family, view: record.view };
            if let Some(reference) = self.index_lookup(view_root, current_head.wallet, key).await? {
                let existing = self.load_attempt_record(reference).await?;
                if &existing != record {
                    return Err(RoastAttemptArchiveError::ConflictingAttemptRecord {
                        family: record.family,
                        view: record.view,
                    });
                }
                continue;
            }

            let bytes = record.to_bytes()?;
            let reference = self
                .plan_artifact(
                    WalletId(current_head.wallet.0),
                    ROAST_ATTEMPT_RECORD_ARTIFACT,
                    &bytes,
                    rng,
                    &mut created,
                )
                .await?;
            let family_key = SparseIndexKey::Family { family: record.family };
            let existing_frontier =
                self.index_lookup(family_root, current_head.wallet, family_key).await?;
            let frontier_reference = self
                .append_prefix_frontier(existing_frontier, record, reference, rng, &mut created)
                .await?;
            let frontier_semantic_digest =
                self.load_prefix_frontier(frontier_reference).await?.semantic_digest()?;
            family_root = Some(if existing_frontier.is_some() {
                self.index_replace(
                    family_root.ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?,
                    current_head.wallet,
                    family_key,
                    frontier_reference,
                    frontier_semantic_digest,
                    rng,
                    &mut created,
                )
                .await?
            } else {
                self.index_insert(
                    family_root,
                    current_head.wallet,
                    family_key,
                    frontier_reference,
                    frontier_semantic_digest,
                    rng,
                    &mut created,
                )
                .await?
            });
            if existing_frontier.is_none() {
                family_count = family_count
                    .checked_add(1)
                    .ok_or(RoastAttemptArchiveError::ArchiveCounterExhausted)?;
            }
            view_root = Some(
                self.index_insert(
                    view_root,
                    current_head.wallet,
                    key,
                    reference,
                    record.semantic_digest()?,
                    rng,
                    &mut created,
                )
                .await?,
            );
            attempt_count = attempt_count
                .checked_add(1)
                .ok_or(RoastAttemptArchiveError::ArchiveCounterExhausted)?;
            inserted.push(record.clone());
        }

        if inserted.is_empty() {
            return Ok(RoastAttemptArchiveStage {
                head: current_head,
                created: Vec::new(),
                changed: false,
                base_head_digest,
            });
        }
        let view_root = view_root.ok_or(RoastAttemptArchiveError::InvalidSparseIndex)?;
        let family_root = family_root.ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
        let head = self
            .stage_commit(
                current_head,
                attempt_count,
                current_head.transaction_count,
                family_count,
                view_root,
                transaction_root,
                family_root,
                rng,
                &mut created,
            )
            .await?;
        self.require_head(head).await?;
        for expected in &inserted {
            let found = self
                .load_view(head, expected.wallet, expected.family, expected.view)
                .await?
                .ok_or(RoastAttemptArchiveError::ReadbackMismatch)?;
            if &found != expected {
                return Err(RoastAttemptArchiveError::ReadbackMismatch);
            }
            let frontier = self.load_family_frontier(head, expected.family).await?;
            if frontier.frontier.leaf_count() <= expected.view {
                return Err(RoastAttemptArchiveError::ReadbackMismatch);
            }
        }
        Ok(RoastAttemptArchiveStage {
            head,
            created: created.into_iter().collect(),
            changed: true,
            base_head_digest,
        })
    }

    /// Stage a direct transaction lookup after validating a complete self-contained completion
    /// proof against the exact archived attempt.
    ///
    /// The complete public sweep plan is authenticated against the certified authorization and
    /// all-selected key-image certificate. The transaction ID and public binding are derived from
    /// the byte-exact canonical transaction carried by the endorsements. Callers cannot install an
    /// unauthenticated plan or `SignedTransactionBinding`.
    pub async fn stage_transaction_mapping<R: RngCore + CryptoRng>(
        &self,
        current_head: RoastAttemptArchiveHead,
        family: [u8; 32],
        view: u64,
        plan: SweepPlan,
        key_images: PortableKeyImageBindingCertificate,
        endorsements: Vec<PortableSignedTransactionAttestation>,
        rng: &mut R,
    ) -> Result<RoastAttemptArchiveStage, RoastAttemptArchiveError> {
        let started = self.ensure_object_plan(current_head).await?;
        let result = self
            .stage_transaction_mapping_inner(
                current_head,
                family,
                view,
                plan,
                key_images,
                endorsements,
                rng,
            )
            .await;
        self.finish_object_plan_stage(started, &result).await?;
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn stage_transaction_mapping_inner<R: RngCore + CryptoRng>(
        &self,
        current_head: RoastAttemptArchiveHead,
        family: [u8; 32],
        view: u64,
        plan: SweepPlan,
        key_images: PortableKeyImageBindingCertificate,
        endorsements: Vec<PortableSignedTransactionAttestation>,
        rng: &mut R,
    ) -> Result<RoastAttemptArchiveStage, RoastAttemptArchiveError> {
        self.require_head(current_head).await?;
        if family == [0; 32] || endorsements.is_empty() {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        let (attempt_record, attempt_reference) = self
            .load_view_with_reference(current_head, current_head.wallet, family, view)
            .await?
            .ok_or(RoastAttemptArchiveError::AttemptRecordNotFound { family, view })?;
        let first =
            endorsements.first().ok_or(RoastAttemptArchiveError::InvalidTransactionMapping)?;
        let signed = first.signed().binding();
        let signed_transaction = first.signed().transaction().clone();
        let transaction = signed_transaction.transaction_id();
        let mapping = RoastTransactionArchiveMapping {
            version: TRANSACTION_MAPPING_VERSION,
            wallet: current_head.wallet,
            network: current_head.network,
            family,
            family_anchor: attempt_record.family_anchor,
            transaction,
            view,
            attempt: attempt_record.attempt,
            attempt_record: attempt_reference,
            attempt_record_digest: attempt_record.digest()?,
            plan,
            signed,
            signed_transaction,
            key_images,
            endorsements,
        };
        mapping.validate_record(&attempt_record, attempt_reference)?;
        let base_head_digest = current_head.digest();
        let key = SparseIndexKey::Transaction { family, transaction };
        if let Some(reference) =
            self.index_lookup(current_head.transaction_root, current_head.wallet, key).await?
        {
            let existing = self.load_transaction_mapping(reference).await?;
            if existing != mapping {
                return Err(RoastAttemptArchiveError::ConflictingTransactionMapping {
                    family,
                    transaction,
                });
            }
            return Ok(RoastAttemptArchiveStage {
                head: current_head,
                created: Vec::new(),
                changed: false,
                base_head_digest,
            });
        }

        let bytes = encode_bounded(
            &mapping,
            MAX_ROAST_TRANSACTION_MAPPING_BYTES,
            "ROAST transaction mapping",
        )?;
        let mut created = BTreeSet::new();
        let mapping_reference = self
            .plan_artifact(
                WalletId(current_head.wallet.0),
                ROAST_TRANSACTION_MAPPING_ARTIFACT,
                &bytes,
                rng,
                &mut created,
            )
            .await?;
        let mapping_semantic_digest = mapping.semantic_digest(&attempt_record)?;
        let transaction_root = self
            .index_insert(
                current_head.transaction_root,
                current_head.wallet,
                key,
                mapping_reference,
                mapping_semantic_digest,
                rng,
                &mut created,
            )
            .await?;
        let transaction_count = current_head
            .transaction_count
            .checked_add(1)
            .ok_or(RoastAttemptArchiveError::ArchiveCounterExhausted)?;
        let view_root =
            current_head.view_root.ok_or(RoastAttemptArchiveError::InvalidArchiveHead)?;
        let family_root =
            current_head.family_root.ok_or(RoastAttemptArchiveError::InvalidArchiveHead)?;
        let head = self
            .stage_commit(
                current_head,
                current_head.attempt_count,
                transaction_count,
                current_head.family_count,
                view_root,
                Some(transaction_root),
                family_root,
                rng,
                &mut created,
            )
            .await?;
        self.require_head(head).await?;
        let restored = self
            .load_transaction(head, current_head.wallet, family, transaction)
            .await?
            .ok_or(RoastAttemptArchiveError::ReadbackMismatch)?;
        if restored.mapping != mapping || restored.attempt != attempt_record {
            return Err(RoastAttemptArchiveError::ReadbackMismatch);
        }
        Ok(RoastAttemptArchiveStage {
            head,
            created: created.into_iter().collect(),
            changed: true,
            base_head_digest,
        })
    }

    /// Direct `(wallet, family, absolute view)` lookup through at most 256 Patricia nodes.
    pub async fn load_view(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        family: [u8; 32],
        view: u64,
    ) -> Result<Option<RoastAttemptArchiveRecord>, RoastAttemptArchiveError> {
        Ok(self
            .load_view_with_reference(head, wallet, family, view)
            .await?
            .map(|(record, _)| record))
    }

    /// Direct absolute-attempt lookup (`attempt == view + 1`).
    pub async fn load_attempt(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        family: [u8; 32],
        attempt: u64,
    ) -> Result<Option<RoastAttemptArchiveRecord>, RoastAttemptArchiveError> {
        let view = attempt.checked_sub(1).ok_or(RoastAttemptArchiveError::InvalidAttemptNumber)?;
        self.load_view(head, wallet, family, view).await
    }

    /// Direct `(wallet, family, txid)` lookup returning both the mapping and its exact proof.
    pub async fn load_transaction(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        family: [u8; 32],
        transaction: [u8; 32],
    ) -> Result<Option<VerifiedArchivedRoastTransaction>, RoastAttemptArchiveError> {
        self.require_head(head).await?;
        if wallet != head.wallet {
            return Err(RoastAttemptArchiveError::WrongArchiveDomain);
        }
        let key = SparseIndexKey::Transaction { family, transaction };
        let Some(reference) = self.index_lookup(head.transaction_root, wallet, key).await? else {
            return Ok(None);
        };
        let mapping = self.load_transaction_mapping(reference).await?;
        if mapping.wallet != wallet
            || mapping.network != head.network
            || mapping.family != family
            || mapping.transaction != transaction
        {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        let attempt = self.load_attempt_record(mapping.attempt_record).await?;
        mapping.validate_record(&attempt, mapping.attempt_record)?;
        let indexed_attempt = self
            .index_lookup(
                head.view_root,
                wallet,
                SparseIndexKey::View { family, view: mapping.view },
            )
            .await?
            .ok_or(RoastAttemptArchiveError::InvalidTransactionMapping)?;
        if indexed_attempt != mapping.attempt_record {
            return Err(RoastAttemptArchiveError::InvalidTransactionMapping);
        }
        Ok(Some(VerifiedArchivedRoastTransaction { head, mapping, attempt }))
    }

    /// Verify an exact archived transaction against the terminal semantic attempt-prefix root.
    ///
    /// The returned private-field token proves all of: authenticated archive-head membership,
    /// exact view and txid indexes, full key-image/candidate evidence, and logarithmic MMR
    /// membership in `prefix_seal`.
    pub async fn verify_prefix_transaction(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        prefix_seal: RoastAttemptPrefixSeal,
        transaction: [u8; 32],
    ) -> Result<VerifiedArchivedPrefixTransaction, RoastAttemptArchiveError> {
        self.require_head(head).await?;
        if wallet != head.wallet || prefix_seal.family() == [0; 32] {
            return Err(RoastAttemptArchiveError::WrongArchiveDomain);
        }
        let verified = self
            .load_transaction(head, wallet, prefix_seal.family(), transaction)
            .await?
            .ok_or(RoastAttemptArchiveError::TransactionNotFound {
                family: prefix_seal.family(),
                transaction,
            })?;
        let record = verified.attempt_record();
        if record.family != prefix_seal.family()
            || record.family_anchor != prefix_seal.family_anchor()
            || record.view > prefix_seal.closed_through_view()
            || record.attempt > prefix_seal.closed_through_attempt()
            || record.view.checked_add(1) != Some(record.attempt)
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        let frontier_reference = self
            .index_lookup(
                head.family_root,
                wallet,
                SparseIndexKey::Family { family: prefix_seal.family() },
            )
            .await?
            .ok_or(RoastAttemptArchiveError::MissingPrefixFrontier {
                family: prefix_seal.family(),
            })?;
        let frontier = self.load_prefix_frontier(frontier_reference).await?;
        if frontier.wallet != wallet
            || frontier.network != head.network
            || frontier.family != prefix_seal.family()
            || frontier.family_anchor != prefix_seal.family_anchor()
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        // Terminal closure means exact full-frontier equality is required. A descendant frontier
        // is not accepted even when the requested view is numerically below its high-water.
        prefix_seal.verify_frontier(&frontier.frontier)?;
        let membership_proof = self
            .verify_prefix_membership_path(&frontier, verified.mapping.attempt_record, record)
            .await?;
        membership_proof.verify_record(prefix_seal, record)?;
        let mapping_digest = verified.mapping.digest()?;
        let record_digest = record.digest()?;
        let proof_digest = membership_proof.digest()?;
        let mut hasher = blake3::Hasher::new_derive_key(
            "threshold-monero/roast-attempt-archive/verified-prefix-transaction/v1",
        );
        hasher.update(&head.digest());
        hasher.update(&frontier_reference.digest());
        hasher.update(&prefix_seal.family());
        hasher.update(&prefix_seal.family_anchor());
        hasher.update(&prefix_seal.closed_through_view().to_le_bytes());
        hasher.update(&prefix_seal.closed_through_attempt().to_le_bytes());
        hasher.update(&prefix_seal.accumulator());
        hasher.update(&record_digest);
        hasher.update(&mapping_digest);
        hasher.update(&proof_digest);
        let membership_digest = *hasher.finalize().as_bytes();
        if membership_digest == [0; 32] {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        Ok(VerifiedArchivedPrefixTransaction {
            transaction: verified,
            prefix_seal,
            membership_proof,
            membership_digest,
        })
    }

    /// Export the bounded proof carried in a Byzantine late-settlement proposal. The proof itself
    /// is portable; every receiver calls [`RoastAttemptPrefixMembershipProof::verify`] or
    /// [`RoastAttemptPrefixMembershipProof::verify_record`] without trusting this store.
    pub async fn export_prefix_transaction_proof(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        prefix_seal: RoastAttemptPrefixSeal,
        transaction: [u8; 32],
    ) -> Result<RoastAttemptPrefixMembershipProof, RoastAttemptArchiveError> {
        Ok(self
            .verify_prefix_transaction(head, wallet, prefix_seal, transaction)
            .await?
            .membership_proof)
    }

    /// Export the complete portable graph a remote Byzantine voter needs to authorize the exact
    /// transaction, not merely its semantic attempt leaf.
    pub async fn export_portable_transaction_completion(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        prefix_seal: RoastAttemptPrefixSeal,
        transaction: [u8; 32],
    ) -> Result<PortableRoastTransactionCompletionProof, RoastAttemptArchiveError> {
        let verified =
            self.verify_prefix_transaction(head, wallet, prefix_seal, transaction).await?;
        let proof = PortableRoastTransactionCompletionProof {
            version: PORTABLE_COMPLETION_PROOF_VERSION,
            record: verified.transaction.attempt.clone(),
            mapping: verified.transaction.mapping.clone(),
            membership: verified.membership_proof.clone(),
        };
        proof.verify_expected(
            prefix_seal,
            wallet,
            head.network,
            prefix_seal.family(),
            transaction,
        )?;
        Ok(proof)
    }

    /// Export a bounded semantic-history proof between two locally authenticated heads.
    ///
    /// The proof contains at most 128 dyadic summaries and never walks the commit lifetime.
    pub async fn export_history_consistency(
        &self,
        source: RoastAttemptArchiveHead,
        target: RoastAttemptArchiveHead,
    ) -> Result<RoastArchiveHistoryConsistencyProof, RoastAttemptArchiveError> {
        self.require_head(source).await?;
        self.require_head(target).await?;
        if source.wallet != target.wallet
            || source.network != target.network
            || source.generation > target.generation
        {
            return Err(RoastAttemptArchiveError::InvalidHistoryConsistencyProof);
        }
        let source_frontier = self.history_frontier_for_head(source).await?;
        let suffix = self.history_suffix_for_head(target, source.generation).await?;
        let proof = RoastArchiveHistoryConsistencyProof::new(
            &source_frontier,
            source.semantic_state()?,
            &suffix,
        )?;
        proof.verify(
            source.semantic_state()?,
            source.history_root,
            target.semantic_state()?,
            target.history_root,
        )?;
        Ok(proof)
    }

    /// Verify bounded ancestry between two locally authenticated endpoints.
    pub async fn verify_local_ancestry(
        &self,
        source: RoastAttemptArchiveHead,
        target: RoastAttemptArchiveHead,
    ) -> Result<VerifiedRoastArchiveHistoryConsistency, RoastAttemptArchiveError> {
        let proof = self.export_history_consistency(source, target).await?;
        Ok(proof.verify(
            source.semantic_state()?,
            source.history_root,
            target.semantic_state()?,
            target.history_root,
        )?)
    }

    /// Authenticate a transferred target before it may replace the local snapshot endpoint.
    ///
    /// Object content addresses alone are not authority. The target must exactly match an `n-f`
    /// certified semantic endpoint and extend the locally trusted source under a bounded proof.
    pub async fn verify_transferred_head(
        &self,
        source: RoastAttemptArchiveHead,
        target: RoastAttemptArchiveHead,
        checkpoint: &VerifiedRoastArchiveCheckpoint,
        proof: &RoastArchiveHistoryConsistencyProof,
    ) -> Result<VerifiedRoastArchiveHistoryConsistency, RoastAttemptArchiveError> {
        self.require_head(source).await?;
        self.require_head(target).await?;
        if target.semantic_state()? != checkpoint.semantic_state()
            || target.history_root != checkpoint.history_root()
        {
            return Err(RoastAttemptArchiveError::InvalidCheckpointCertificate);
        }
        Ok(proof.verify(
            source.semantic_state()?,
            source.history_root,
            checkpoint.semantic_state(),
            checkpoint.history_root(),
        )?)
    }

    /// Read one bounded plaintext object chunk for authenticated QUIC transfer.
    pub async fn artifact_chunk(
        &self,
        request: RoastArtifactChunkRequest,
    ) -> Result<RoastArtifactChunk, RoastAttemptArchiveError> {
        request.validate()?;
        let bytes = self.load_artifact_bytes(request.reference).await?;
        let start = usize::try_from(request.offset)
            .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
        let maximum = usize::try_from(request.maximum_bytes)
            .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
        let end = start.saturating_add(maximum).min(bytes.len());
        let chunk = RoastArtifactChunk {
            version: ARTIFACT_CHUNK_VERSION,
            reference: request.reference,
            offset: request.offset,
            bytes: bytes[start..end].to_vec(),
            complete: end == bytes.len(),
        };
        chunk.validate()?;
        Ok(chunk)
    }

    /// Return the bounded direct dependency set for one authenticated archive DAG object.
    ///
    /// Peer catch-up requests these references and persists leaves first. `previous_commit` is a
    /// support terminal: callers do not recursively expand it. History peak nodes are transferred
    /// only as the bounded current frontier; consistency proofs carry any additional dyadic suffix
    /// summaries needed to authenticate ancestry. No direct response grows with archive lifetime.
    pub async fn artifact_dependencies(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<Vec<WalletArtifactRef>, RoastAttemptArchiveError> {
        validate_roast_reference_bounds(reference)?;
        let mut dependencies = match reference.kind() {
            ROAST_ATTEMPT_RECORD_ARTIFACT => {
                self.load_attempt_record(reference).await?;
                Vec::new()
            }
            ROAST_TRANSACTION_MAPPING_ARTIFACT => {
                let mapping = self.load_transaction_mapping(reference).await?;
                vec![mapping.attempt_record]
            }
            ROAST_SPARSE_INDEX_NODE_ARTIFACT => {
                let bytes = self.load_artifact_bytes(reference).await?;
                let node: SparseIndexNode = decode_canonical_bounded(
                    &bytes,
                    MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
                    "ROAST sparse index node",
                )?;
                node.validate()?;
                match node.body {
                    SparseIndexBody::Leaf { value, .. } => vec![value],
                    SparseIndexBody::Branch { left, right, .. } => vec![left, right],
                }
            }
            ROAST_ARCHIVE_COMMIT_ARTIFACT => {
                let commit = self.load_commit(reference).await?;
                let mut references = vec![commit.view_root, commit.family_root];
                references.extend(commit.transaction_root);
                references.extend(commit.previous_commit);
                references.extend(commit.history_peak_nodes);
                references
            }
            ROAST_PREFIX_MMR_NODE_ARTIFACT => {
                let node = self.load_prefix_mmr_node(reference).await?;
                match node.body {
                    PrefixMmrNodeBody::Leaf { attempt_record } => vec![attempt_record],
                    PrefixMmrNodeBody::Parent { left, right } => vec![left, right],
                }
            }
            ROAST_PREFIX_MMR_FRONTIER_ARTIFACT => {
                self.load_prefix_frontier(reference).await?.peak_nodes
            }
            ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT => {
                let bytes = self.load_artifact_bytes(reference).await?;
                let node: ArchiveHistoryNode = decode_canonical_bounded(
                    &bytes,
                    MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
                    "ROAST archive history node",
                )?;
                node.validate_shape()?;
                if WalletId(node.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                match node.body {
                    ArchiveHistoryNodeBody::Leaf => Vec::new(),
                    ArchiveHistoryNodeBody::Parent { left, right } => vec![left, right],
                }
            }
            _ => return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch),
        };
        dependencies.sort_unstable();
        dependencies.dedup();
        if dependencies.len() > MAX_ROAST_ARTIFACT_DEPENDENCIES {
            return Err(RoastAttemptArchiveError::TooManyArtifactDependencies {
                actual: dependencies.len(),
                maximum: MAX_ROAST_ARTIFACT_DEPENDENCIES,
            });
        }
        Ok(dependencies)
    }

    /// Authenticate and locally encrypt one complete object assembled from peer chunks.
    pub async fn persist_transferred_artifact<R: RngCore + CryptoRng>(
        &self,
        reference: WalletArtifactRef,
        bytes: &[u8],
        rng: &mut R,
    ) -> Result<(), RoastAttemptArchiveError> {
        if !is_roast_artifact_kind(reference.kind()) {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        validate_roast_reference_bounds(reference)?;
        reference.verify_contents(bytes)?;
        // Decode and verify already-addressed data-DAG dependencies before persisting. Peer
        // catch-up therefore transfers leaves before index nodes and roots before its selected
        // commit. The immediate predecessor is a bounded support terminal. Callers authenticate a
        // peer endpoint with an n-f checkpoint and a history consistency proof before installation.
        match reference.kind() {
            ROAST_ATTEMPT_RECORD_ARTIFACT => {
                let record = RoastAttemptArchiveRecord::from_bytes(bytes)?;
                if WalletId(record.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
            }
            ROAST_SPARSE_INDEX_NODE_ARTIFACT => {
                let node: SparseIndexNode = decode_canonical_bounded(
                    bytes,
                    MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
                    "ROAST sparse index node",
                )?;
                node.validate()?;
                if WalletId(node.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                match node.body {
                    SparseIndexBody::Leaf { key, value } => {
                        let value_semantic_digest = match key {
                            SparseIndexKey::View { family, view } => {
                                let record = self.load_attempt_record(value).await?;
                                if record.wallet != node.wallet
                                    || record.family != family
                                    || record.view != view
                                {
                                    return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                                }
                                record.semantic_digest()?
                            }
                            SparseIndexKey::Transaction { family, transaction } => {
                                let mapping = self.load_transaction_mapping(value).await?;
                                let record =
                                    self.load_attempt_record(mapping.attempt_record).await?;
                                mapping.validate_record(&record, mapping.attempt_record)?;
                                if mapping.wallet != node.wallet
                                    || mapping.family != family
                                    || mapping.transaction != transaction
                                {
                                    return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                                }
                                mapping.semantic_digest(&record)?
                            }
                            SparseIndexKey::Family { family } => {
                                let frontier = self.load_prefix_frontier(value).await?;
                                if frontier.wallet != node.wallet || frontier.family != family {
                                    return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                                }
                                frontier.semantic_digest()?
                            }
                        };
                        if node.semantic_digest
                            != sparse_index_leaf_digest(key, value_semantic_digest)
                        {
                            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                        }
                    }
                    SparseIndexBody::Branch { bit, left, right } => {
                        let left = self.load_index_node(left, node.wallet, node.namespace).await?;
                        let right =
                            self.load_index_node(right, node.wallet, node.namespace).await?;
                        if node.semantic_digest
                            != sparse_index_parent_digest(
                                node.namespace,
                                bit,
                                left.semantic_digest,
                                right.semantic_digest,
                            )
                        {
                            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                        }
                    }
                }
            }
            ROAST_TRANSACTION_MAPPING_ARTIFACT => {
                let mapping: RoastTransactionArchiveMapping = decode_canonical_bounded(
                    bytes,
                    MAX_ROAST_TRANSACTION_MAPPING_BYTES,
                    "ROAST transaction mapping",
                )?;
                mapping.validate_shape()?;
                if WalletId(mapping.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                let record = self.load_attempt_record(mapping.attempt_record).await?;
                mapping.validate_record(&record, mapping.attempt_record)?;
            }
            ROAST_ARCHIVE_COMMIT_ARTIFACT => {
                let commit: RoastAttemptArchiveCommit = decode_canonical_bounded(
                    bytes,
                    MAX_ROAST_ARCHIVE_COMMIT_BYTES,
                    "ROAST archive commit",
                )?;
                commit.validate()?;
                if WalletId(commit.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                let view = self
                    .load_index_node(commit.view_root, commit.wallet, SparseIndexNamespace::View)
                    .await?;
                let family = self
                    .load_index_node(
                        commit.family_root,
                        commit.wallet,
                        SparseIndexNamespace::Family,
                    )
                    .await?;
                if view.semantic_digest != commit.semantic_view_root
                    || family.semantic_digest != commit.semantic_family_root
                {
                    return Err(RoastAttemptArchiveError::InvalidArchiveCommit);
                }
                match commit.transaction_root {
                    Some(transaction_root) => {
                        let transaction = self
                            .load_index_node(
                                transaction_root,
                                commit.wallet,
                                SparseIndexNamespace::Transaction,
                            )
                            .await?;
                        if transaction.semantic_digest != commit.semantic_transaction_root {
                            return Err(RoastAttemptArchiveError::InvalidArchiveCommit);
                        }
                    }
                    None if commit.semantic_transaction_root
                        != sparse_index_empty_digest(SparseIndexNamespace::Transaction) =>
                    {
                        return Err(RoastAttemptArchiveError::InvalidArchiveCommit);
                    }
                    None => {}
                }
                self.verify_commit_transition(&commit).await?;
                self.verify_history_frontier(&commit).await?;
            }
            ROAST_PREFIX_MMR_NODE_ARTIFACT => {
                let node: PrefixMmrNode = decode_canonical_bounded(
                    bytes,
                    MAX_ROAST_PREFIX_MMR_NODE_BYTES,
                    "ROAST prefix MMR node",
                )?;
                if WalletId(node.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                self.verify_prefix_mmr_node(node).await?;
            }
            ROAST_PREFIX_MMR_FRONTIER_ARTIFACT => {
                let frontier: PrefixMmrFrontierArtifact = decode_canonical_bounded(
                    bytes,
                    MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES,
                    "ROAST prefix MMR frontier",
                )?;
                if WalletId(frontier.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                self.verify_prefix_frontier(&frontier).await?;
            }
            ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT => {
                let node: ArchiveHistoryNode = decode_canonical_bounded(
                    bytes,
                    MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
                    "ROAST archive history node",
                )?;
                if WalletId(node.wallet.0) != reference.wallet_id() {
                    return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
                }
                // Transferred frontier/support nodes may arrive without their descendants. Their
                // semantic digest is authenticated by the endpoint certificate; proof paths verify
                // child equations when they are actually used.
                node.validate_shape()?;
            }
            _ => return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch),
        }
        let stored = self
            .artifacts
            .create_artifact(reference.wallet_id(), reference.kind(), bytes, rng)
            .await?;
        if stored != reference {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        Ok(())
    }

    async fn load_view_with_reference(
        &self,
        head: RoastAttemptArchiveHead,
        wallet: DepositWalletId,
        family: [u8; 32],
        view: u64,
    ) -> Result<Option<(RoastAttemptArchiveRecord, WalletArtifactRef)>, RoastAttemptArchiveError>
    {
        self.require_head(head).await?;
        if wallet != head.wallet || family == [0; 32] {
            return Err(RoastAttemptArchiveError::WrongArchiveDomain);
        }
        let key = SparseIndexKey::View { family, view };
        let Some(reference) = self.index_lookup(head.view_root, wallet, key).await? else {
            return Ok(None);
        };
        let record = self.load_attempt_record(reference).await?;
        if record.wallet != wallet
            || record.network != head.network
            || record.family != family
            || record.view != view
        {
            return Err(RoastAttemptArchiveError::InvalidAttemptRecord);
        }
        Ok(Some((record, reference)))
    }

    async fn load_family_frontier(
        &self,
        head: RoastAttemptArchiveHead,
        family: [u8; 32],
    ) -> Result<PrefixMmrFrontierArtifact, RoastAttemptArchiveError> {
        self.require_head(head).await?;
        if family == [0; 32] {
            return Err(RoastAttemptArchiveError::WrongArchiveDomain);
        }
        let reference = self
            .index_lookup(head.family_root, head.wallet, SparseIndexKey::Family { family })
            .await?
            .ok_or(RoastAttemptArchiveError::MissingPrefixFrontier { family })?;
        let frontier = self.load_prefix_frontier(reference).await?;
        if frontier.wallet != head.wallet
            || frontier.network != head.network
            || frontier.family != family
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
        }
        Ok(frontier)
    }

    async fn append_prefix_frontier<R: RngCore + CryptoRng>(
        &self,
        existing: Option<WalletArtifactRef>,
        record: &RoastAttemptArchiveRecord,
        attempt_record: WalletArtifactRef,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        let mut archived = match existing {
            Some(reference) => self.load_prefix_frontier(reference).await?,
            None => PrefixMmrFrontierArtifact {
                version: PREFIX_MMR_FRONTIER_VERSION,
                wallet: record.wallet,
                network: record.network,
                family: record.family,
                family_anchor: record.family_anchor,
                frontier: RoastAttemptPrefixFrontier::empty(),
                peak_nodes: Vec::new(),
            },
        };
        if archived.wallet != record.wallet
            || archived.network != record.network
            || archived.family != record.family
            || archived.family_anchor != record.family_anchor
            || archived.frontier.leaf_count() != record.view
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
        }
        let leaf_digest = certified_roast_attempt_leaf(
            record.family,
            record.family_anchor,
            &record.slot,
            &record.context,
            &record.intent,
            &record.intent_certificate,
        )?;
        let mut current = PrefixMmrNode::leaf(record, attempt_record, leaf_digest);
        let mut current_reference = self.create_prefix_mmr_node(current, rng, created).await?;
        let previous_count = archived.frontier.leaf_count();
        let mut height = 0_u8;
        while previous_count & (1_u64 << u32::from(height)) != 0 {
            let left_reference =
                archived.peak_nodes.pop().ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
            let left = self.load_prefix_mmr_node(left_reference).await?;
            if left.wallet != record.wallet
                || left.network != record.network
                || left.family != record.family
                || left.height != height
                || left.start_view.checked_add(left.width()?) != Some(current.start_view)
            {
                return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
            }
            height = height.checked_add(1).ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
            let digest = roast_attempt_prefix_parent(height, left.digest, current.digest);
            current = PrefixMmrNode::parent(
                record.wallet,
                record.network,
                record.family,
                left.start_view,
                height,
                digest,
                left_reference,
                current_reference,
            );
            current_reference = self.create_prefix_mmr_node(current, rng, created).await?;
        }
        archived.peak_nodes.push(current_reference);
        archived.frontier.append_certified_attempt(
            record.family,
            record.family_anchor,
            &record.slot,
            &record.context,
            &record.intent,
            &record.intent_certificate,
        )?;
        self.create_prefix_frontier(archived, rng, created).await
    }

    async fn create_prefix_mmr_node<R: RngCore + CryptoRng>(
        &self,
        node: PrefixMmrNode,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        self.verify_prefix_mmr_node(node).await?;
        let bytes =
            encode_bounded(&node, MAX_ROAST_PREFIX_MMR_NODE_BYTES, "ROAST prefix MMR node")?;
        let reference = self
            .plan_artifact(
                WalletId(node.wallet.0),
                ROAST_PREFIX_MMR_NODE_ARTIFACT,
                &bytes,
                rng,
                created,
            )
            .await?;
        let restored = self.load_prefix_mmr_node(reference).await?;
        if restored != node {
            return Err(RoastAttemptArchiveError::ReadbackMismatch);
        }
        Ok(reference)
    }

    async fn create_prefix_frontier<R: RngCore + CryptoRng>(
        &self,
        frontier: PrefixMmrFrontierArtifact,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        self.verify_prefix_frontier(&frontier).await?;
        let bytes = encode_bounded(
            &frontier,
            MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES,
            "ROAST prefix MMR frontier",
        )?;
        let reference = self
            .plan_artifact(
                WalletId(frontier.wallet.0),
                ROAST_PREFIX_MMR_FRONTIER_ARTIFACT,
                &bytes,
                rng,
                created,
            )
            .await?;
        let restored = self.load_prefix_frontier(reference).await?;
        if restored != frontier {
            return Err(RoastAttemptArchiveError::ReadbackMismatch);
        }
        Ok(reference)
    }

    async fn stage_commit<R: RngCore + CryptoRng>(
        &self,
        previous: RoastAttemptArchiveHead,
        attempt_count: u64,
        transaction_count: u64,
        family_count: u64,
        view_root: WalletArtifactRef,
        transaction_root: Option<WalletArtifactRef>,
        family_root: WalletArtifactRef,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<RoastAttemptArchiveHead, RoastAttemptArchiveError> {
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(RoastAttemptArchiveError::ArchiveCounterExhausted)?;
        let semantic_view_root = self
            .load_index_node(view_root, previous.wallet, SparseIndexNamespace::View)
            .await?
            .semantic_digest;
        let semantic_transaction_root = match transaction_root {
            None => sparse_index_empty_digest(SparseIndexNamespace::Transaction),
            Some(reference) => {
                self.load_index_node(reference, previous.wallet, SparseIndexNamespace::Transaction)
                    .await?
                    .semantic_digest
            }
        };
        let semantic_family_root = self
            .load_index_node(family_root, previous.wallet, SparseIndexNamespace::Family)
            .await?
            .semantic_digest;
        let (history_frontier, history_peak_nodes) = match previous.commit {
            None => {
                (RoastArchiveHistoryFrontier::empty(previous.wallet, previous.network)?, Vec::new())
            }
            Some(reference) => {
                let commit = self.load_commit(reference).await?;
                (commit.history_frontier, commit.history_peak_nodes)
            }
        };
        let mut commit = RoastAttemptArchiveCommit {
            version: ARCHIVE_COMMIT_VERSION,
            wallet: previous.wallet,
            network: previous.network,
            generation,
            previous_commit: previous.commit,
            previous_head_digest: previous.digest(),
            previous_semantic_state: previous.semantic_digest()?,
            attempt_count,
            transaction_count,
            family_count,
            view_root,
            transaction_root,
            family_root,
            semantic_view_root,
            semantic_transaction_root,
            semantic_family_root,
            history_frontier,
            history_peak_nodes,
        };
        let transition =
            RoastArchiveHistorySummary::leaf(previous.semantic_state()?, commit.semantic_state()?)?;
        let (history_frontier, history_peak_nodes) = self
            .append_history_transition(
                commit.wallet,
                commit.network,
                commit.generation,
                transition,
                commit.history_frontier,
                commit.history_peak_nodes,
                rng,
                created,
            )
            .await?;
        commit.history_frontier = history_frontier;
        commit.history_peak_nodes = history_peak_nodes;
        commit.validate()?;
        let bytes =
            encode_bounded(&commit, MAX_ROAST_ARCHIVE_COMMIT_BYTES, "ROAST archive commit")?;
        let reference = self
            .plan_artifact(
                WalletId(previous.wallet.0),
                ROAST_ARCHIVE_COMMIT_ARTIFACT,
                &bytes,
                rng,
                created,
            )
            .await?;
        let restored = self.load_commit(reference).await?;
        if restored != commit {
            return Err(RoastAttemptArchiveError::ReadbackMismatch);
        }
        let head = commit.head(reference);
        head.validate()?;
        Ok(head)
    }

    async fn require_head(
        &self,
        head: RoastAttemptArchiveHead,
    ) -> Result<(), RoastAttemptArchiveError> {
        head.validate()?;
        let Some(reference) = head.commit else {
            return Ok(());
        };
        let commit = self.load_commit(reference).await?;
        if commit.head(reference) != head {
            return Err(RoastAttemptArchiveError::InvalidArchiveHead);
        }
        let view = self
            .load_index_node(commit.view_root, commit.wallet, SparseIndexNamespace::View)
            .await?;
        let family = self
            .load_index_node(commit.family_root, commit.wallet, SparseIndexNamespace::Family)
            .await?;
        if view.semantic_digest != commit.semantic_view_root
            || family.semantic_digest != commit.semantic_family_root
        {
            return Err(RoastAttemptArchiveError::InvalidArchiveHead);
        }
        if let Some(transaction_root) = commit.transaction_root {
            let transaction = self
                .load_index_node(transaction_root, commit.wallet, SparseIndexNamespace::Transaction)
                .await?;
            if transaction.semantic_digest != commit.semantic_transaction_root {
                return Err(RoastAttemptArchiveError::InvalidArchiveHead);
            }
        } else if commit.semantic_transaction_root
            != sparse_index_empty_digest(SparseIndexNamespace::Transaction)
        {
            return Err(RoastAttemptArchiveError::InvalidArchiveHead);
        }
        self.verify_commit_transition(&commit).await?;
        self.verify_history_frontier(&commit).await?;
        Ok(())
    }

    async fn verify_commit_transition(
        &self,
        commit: &RoastAttemptArchiveCommit,
    ) -> Result<(), RoastAttemptArchiveError> {
        if commit.generation == 1 {
            let empty = RoastAttemptArchiveHead::empty(commit.wallet, commit.network)?;
            if commit.previous_commit.is_some()
                || commit.previous_head_digest != empty.digest()
                || commit.previous_semantic_state != empty.semantic_digest()?
                || commit.transaction_count != 0
                || commit.attempt_count == 0
                || commit.family_count == 0
                || commit.family_count > commit.attempt_count
                || commit.attempt_count > u64::try_from(MAX_ROAST_ATTEMPTS_PER_STAGE).unwrap()
            {
                return Err(RoastAttemptArchiveError::BrokenCommitChain);
            }
        } else {
            let previous_reference =
                commit.previous_commit.ok_or(RoastAttemptArchiveError::BrokenCommitChain)?;
            let previous = self.load_commit(previous_reference).await?;
            let previous_head = previous.head(previous_reference);
            let attempt_delta = commit
                .attempt_count
                .checked_sub(previous.attempt_count)
                .ok_or(RoastAttemptArchiveError::BrokenCommitChain)?;
            let transaction_delta = commit
                .transaction_count
                .checked_sub(previous.transaction_count)
                .ok_or(RoastAttemptArchiveError::BrokenCommitChain)?;
            let family_delta = commit
                .family_count
                .checked_sub(previous.family_count)
                .ok_or(RoastAttemptArchiveError::BrokenCommitChain)?;
            if previous.wallet != commit.wallet
                || previous.network != commit.network
                || previous.generation.checked_add(1) != Some(commit.generation)
                || previous_head.digest() != commit.previous_head_digest
                || previous_head.semantic_digest()? != commit.previous_semantic_state
                || previous.attempt_count > commit.attempt_count
                || previous.transaction_count > commit.transaction_count
                || previous.family_count > commit.family_count
                || (previous.attempt_count == commit.attempt_count
                    && previous.transaction_count == commit.transaction_count)
                || (previous.attempt_count != commit.attempt_count
                    && previous.transaction_count != commit.transaction_count)
                || (previous.attempt_count == commit.attempt_count
                    && previous.view_root != commit.view_root)
                || (attempt_delta != 0 && previous.view_root == commit.view_root)
                || (attempt_delta == 0
                    && (family_delta != 0 || previous.family_root != commit.family_root))
                || (attempt_delta != 0 && previous.family_root == commit.family_root)
                || family_delta > attempt_delta
                || (previous.transaction_count == commit.transaction_count
                    && previous.transaction_root != commit.transaction_root)
                || (transaction_delta != 0 && previous.transaction_root == commit.transaction_root)
                || (attempt_delta != 0
                    && attempt_delta > u64::try_from(MAX_ROAST_ATTEMPTS_PER_STAGE).unwrap())
                || (transaction_delta != 0 && transaction_delta != 1)
            {
                return Err(RoastAttemptArchiveError::BrokenCommitChain);
            }
        }
        let (previous_state, mut expected_history) = if commit.generation == 1 {
            let empty = RoastAttemptArchiveHead::empty(commit.wallet, commit.network)?;
            (
                empty.semantic_state()?,
                RoastArchiveHistoryFrontier::empty(commit.wallet, commit.network)?,
            )
        } else {
            let previous_reference =
                commit.previous_commit.ok_or(RoastAttemptArchiveError::BrokenCommitChain)?;
            let previous = self.load_commit(previous_reference).await?;
            (previous.semantic_state()?, previous.history_frontier)
        };
        expected_history.append_transition(previous_state, commit.semantic_state()?)?;
        if expected_history != commit.history_frontier {
            return Err(RoastAttemptArchiveError::BrokenCommitChain);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_history_transition<R: RngCore + CryptoRng>(
        &self,
        wallet: DepositWalletId,
        network: [u8; 32],
        generation: u64,
        transition: RoastArchiveHistorySummary,
        mut frontier: RoastArchiveHistoryFrontier,
        mut peak_nodes: Vec<WalletArtifactRef>,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<(RoastArchiveHistoryFrontier, Vec<WalletArtifactRef>), RoastAttemptArchiveError>
    {
        frontier.validate()?;
        if generation == 0
            || frontier.leaf_count().checked_add(1) != Some(generation)
            || frontier.peaks().len() != peak_nodes.len()
            || transition.height() != 0
            || transition.start_generation() != frontier.leaf_count()
            || transition.end_generation() != generation
        {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        let mut node = ArchiveHistoryNode {
            version: ARCHIVE_HISTORY_NODE_VERSION,
            wallet,
            network,
            summary: transition,
            body: ArchiveHistoryNodeBody::Leaf,
        };
        let mut reference = self.create_history_node(node, rng, created).await?;
        let previous_count = frontier.leaf_count();
        let previous_peaks = frontier.peaks().to_vec();
        let mut merged = 0_usize;
        while previous_count & (1_u64 << u32::from(node.summary.height())) != 0 {
            let left_peak = *previous_peaks
                .get(
                    previous_peaks
                        .len()
                        .checked_sub(merged + 1)
                        .ok_or(RoastAttemptArchiveError::InvalidHistoryMmr)?,
                )
                .ok_or(RoastAttemptArchiveError::InvalidHistoryMmr)?;
            let left_reference =
                peak_nodes.pop().ok_or(RoastAttemptArchiveError::InvalidHistoryMmr)?;
            let left = self.load_history_node(left_reference, wallet, network).await?;
            self.verify_history_node(left).await?;
            if left.summary != left_peak {
                return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
            }
            let parent =
                RoastArchiveHistorySummary::merge(wallet, network, left.summary, node.summary)?;
            node = ArchiveHistoryNode {
                version: ARCHIVE_HISTORY_NODE_VERSION,
                wallet,
                network,
                summary: parent,
                body: ArchiveHistoryNodeBody::Parent { left: left_reference, right: reference },
            };
            reference = self.create_history_node(node, rng, created).await?;
            merged =
                merged.checked_add(1).ok_or(RoastAttemptArchiveError::ArchiveCounterExhausted)?;
        }
        frontier.append_summary(transition)?;
        peak_nodes.push(reference);
        if frontier.peaks().len() != peak_nodes.len()
            || frontier.peaks().last().copied() != Some(node.summary)
        {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        Ok((frontier, peak_nodes))
    }

    async fn create_history_node<R: RngCore + CryptoRng>(
        &self,
        node: ArchiveHistoryNode,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        node.validate_shape()?;
        let bytes = encode_bounded(
            &node,
            MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
            "ROAST archive history node",
        )?;
        let reference = self
            .plan_artifact(
                WalletId(node.wallet.0),
                ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT,
                &bytes,
                rng,
                created,
            )
            .await?;
        let restored = self.load_history_node(reference, node.wallet, node.network).await?;
        if restored != node {
            return Err(RoastAttemptArchiveError::ReadbackMismatch);
        }
        Ok(reference)
    }

    async fn load_history_node(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
        network: [u8; 32],
    ) -> Result<ArchiveHistoryNode, RoastAttemptArchiveError> {
        validate_reference(
            reference,
            wallet,
            ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT,
            MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let node: ArchiveHistoryNode = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
            "ROAST archive history node",
        )?;
        node.validate_shape()?;
        if node.wallet != wallet || node.network != network {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        Ok(node)
    }

    async fn verify_history_node(
        &self,
        node: ArchiveHistoryNode,
    ) -> Result<(), RoastAttemptArchiveError> {
        node.validate_shape()?;
        let ArchiveHistoryNodeBody::Parent { left, right } = node.body else {
            return Ok(());
        };
        let left = self.load_history_node(left, node.wallet, node.network).await?;
        let right = self.load_history_node(right, node.wallet, node.network).await?;
        let expected = RoastArchiveHistorySummary::merge(
            node.wallet,
            node.network,
            left.summary,
            right.summary,
        )?;
        if expected != node.summary {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        Ok(())
    }

    async fn verify_history_frontier(
        &self,
        commit: &RoastAttemptArchiveCommit,
    ) -> Result<(), RoastAttemptArchiveError> {
        commit.history_frontier.validate_endpoint(commit.semantic_state()?)?;
        if commit.history_frontier.leaf_count() != commit.generation
            || commit.history_frontier.peaks().len() != commit.history_peak_nodes.len()
        {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        for (peak, reference) in commit
            .history_frontier
            .peaks()
            .iter()
            .copied()
            .zip(commit.history_peak_nodes.iter().copied())
        {
            let node = self.load_history_node(reference, commit.wallet, commit.network).await?;
            self.verify_history_node(node).await?;
            if node.summary != peak {
                return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
            }
        }
        Ok(())
    }

    async fn history_frontier_for_head(
        &self,
        head: RoastAttemptArchiveHead,
    ) -> Result<RoastArchiveHistoryFrontier, RoastAttemptArchiveError> {
        match head.commit {
            None => Ok(RoastArchiveHistoryFrontier::empty(head.wallet, head.network)?),
            Some(reference) => {
                let commit = self.load_commit(reference).await?;
                if commit.head(reference) != head {
                    return Err(RoastAttemptArchiveError::InvalidArchiveHead);
                }
                Ok(commit.history_frontier)
            }
        }
    }

    async fn history_suffix_for_head(
        &self,
        target: RoastAttemptArchiveHead,
        source_generation: u64,
    ) -> Result<Vec<RoastArchiveHistorySummary>, RoastAttemptArchiveError> {
        if source_generation > target.generation {
            return Err(RoastAttemptArchiveError::InvalidHistoryConsistencyProof);
        }
        if source_generation == target.generation {
            return Ok(Vec::new());
        }
        let reference =
            target.commit.ok_or(RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?;
        let commit = self.load_commit(reference).await?;
        if commit.head(reference) != target {
            return Err(RoastAttemptArchiveError::InvalidArchiveHead);
        }
        let mut cursor = source_generation;
        let mut suffix = Vec::new();
        while cursor < target.generation {
            let remaining = target
                .generation
                .checked_sub(cursor)
                .ok_or(RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?;
            let remaining_height =
                u8::try_from(63_u32.saturating_sub(remaining.leading_zeros()))
                    .map_err(|_| RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?;
            let alignment_height = if cursor == 0 {
                63
            } else {
                u8::try_from(cursor.trailing_zeros().min(63))
                    .map_err(|_| RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?
            };
            let height = remaining_height.min(alignment_height);
            let summary = self.history_summary_from_commit(&commit, cursor, height).await?;
            cursor = summary.end_generation();
            suffix.push(summary);
            if suffix.len() > (u64::BITS as usize) * 2 {
                return Err(RoastAttemptArchiveError::InvalidHistoryConsistencyProof);
            }
        }
        Ok(suffix)
    }

    async fn history_summary_from_commit(
        &self,
        commit: &RoastAttemptArchiveCommit,
        start_generation: u64,
        height: u8,
    ) -> Result<RoastArchiveHistorySummary, RoastAttemptArchiveError> {
        let width = 1_u64
            .checked_shl(u32::from(height))
            .ok_or(RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?;
        let end_generation = start_generation
            .checked_add(width)
            .ok_or(RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?;
        let (peak, peak_reference) = commit
            .history_frontier
            .peaks()
            .iter()
            .copied()
            .zip(commit.history_peak_nodes.iter().copied())
            .find(|(peak, _)| {
                peak.start_generation() <= start_generation
                    && peak.end_generation() >= end_generation
            })
            .ok_or(RoastAttemptArchiveError::InvalidHistoryConsistencyProof)?;
        let mut node =
            self.load_history_node(peak_reference, commit.wallet, commit.network).await?;
        if node.summary != peak {
            return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
        }
        while node.summary.height() > height {
            let ArchiveHistoryNodeBody::Parent { left, right } = node.body else {
                return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
            };
            let left_node = self.load_history_node(left, commit.wallet, commit.network).await?;
            let right_node = self.load_history_node(right, commit.wallet, commit.network).await?;
            if RoastArchiveHistorySummary::merge(
                commit.wallet,
                commit.network,
                left_node.summary,
                right_node.summary,
            )? != node.summary
            {
                return Err(RoastAttemptArchiveError::InvalidHistoryMmr);
            }
            node = if start_generation < left_node.summary.end_generation() {
                left_node
            } else {
                right_node
            };
        }
        if node.summary.height() != height
            || node.summary.start_generation() != start_generation
            || node.summary.end_generation() != end_generation
        {
            return Err(RoastAttemptArchiveError::InvalidHistoryConsistencyProof);
        }
        Ok(node.summary)
    }

    async fn load_commit(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<RoastAttemptArchiveCommit, RoastAttemptArchiveError> {
        validate_reference_kind(
            reference,
            ROAST_ARCHIVE_COMMIT_ARTIFACT,
            MAX_ROAST_ARCHIVE_COMMIT_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let commit: RoastAttemptArchiveCommit = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_ARCHIVE_COMMIT_BYTES,
            "ROAST archive commit",
        )?;
        commit.validate()?;
        if WalletId(commit.wallet.0) != reference.wallet_id() {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        Ok(commit)
    }

    async fn load_attempt_record(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<RoastAttemptArchiveRecord, RoastAttemptArchiveError> {
        validate_reference_kind(
            reference,
            ROAST_ATTEMPT_RECORD_ARTIFACT,
            MAX_ROAST_ATTEMPT_RECORD_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let record = RoastAttemptArchiveRecord::from_bytes(&bytes)?;
        if WalletId(record.wallet.0) != reference.wallet_id() {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        Ok(record)
    }

    async fn load_transaction_mapping(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<RoastTransactionArchiveMapping, RoastAttemptArchiveError> {
        validate_reference_kind(
            reference,
            ROAST_TRANSACTION_MAPPING_ARTIFACT,
            MAX_ROAST_TRANSACTION_MAPPING_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let mapping: RoastTransactionArchiveMapping = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_TRANSACTION_MAPPING_BYTES,
            "ROAST transaction mapping",
        )?;
        mapping.validate_shape()?;
        if WalletId(mapping.wallet.0) != reference.wallet_id() {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        Ok(mapping)
    }

    async fn load_prefix_mmr_node(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<PrefixMmrNode, RoastAttemptArchiveError> {
        validate_reference_kind(
            reference,
            ROAST_PREFIX_MMR_NODE_ARTIFACT,
            MAX_ROAST_PREFIX_MMR_NODE_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let node: PrefixMmrNode = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_PREFIX_MMR_NODE_BYTES,
            "ROAST prefix MMR node",
        )?;
        if WalletId(node.wallet.0) != reference.wallet_id() {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        self.verify_prefix_mmr_node(node).await?;
        Ok(node)
    }

    async fn verify_prefix_mmr_node(
        &self,
        node: PrefixMmrNode,
    ) -> Result<(), RoastAttemptArchiveError> {
        node.validate_shape()?;
        match node.body {
            PrefixMmrNodeBody::Leaf { attempt_record } => {
                let record = self.load_attempt_record(attempt_record).await?;
                let expected = certified_roast_attempt_leaf(
                    record.family,
                    record.family_anchor,
                    &record.slot,
                    &record.context,
                    &record.intent,
                    &record.intent_certificate,
                )?;
                if record.wallet != node.wallet
                    || record.network != node.network
                    || record.family != node.family
                    || record.view != node.start_view
                    || expected != node.digest
                {
                    return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
                }
            }
            PrefixMmrNodeBody::Parent { left, right } => {
                let left = self.load_prefix_mmr_node_shallow(left).await?;
                let right = self.load_prefix_mmr_node_shallow(right).await?;
                let child_height =
                    node.height.checked_sub(1).ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
                if left.wallet != node.wallet
                    || right.wallet != node.wallet
                    || left.network != node.network
                    || right.network != node.network
                    || left.family != node.family
                    || right.family != node.family
                    || left.height != child_height
                    || right.height != child_height
                    || left.start_view != node.start_view
                    || left.start_view.checked_add(left.width()?) != Some(right.start_view)
                    || roast_attempt_prefix_parent(node.height, left.digest, right.digest)
                        != node.digest
                {
                    return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
                }
            }
        }
        Ok(())
    }

    async fn load_prefix_mmr_node_shallow(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<PrefixMmrNode, RoastAttemptArchiveError> {
        validate_reference_kind(
            reference,
            ROAST_PREFIX_MMR_NODE_ARTIFACT,
            MAX_ROAST_PREFIX_MMR_NODE_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let node: PrefixMmrNode = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_PREFIX_MMR_NODE_BYTES,
            "ROAST prefix MMR node",
        )?;
        node.validate_shape()?;
        if WalletId(node.wallet.0) != reference.wallet_id() {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        Ok(node)
    }

    async fn load_prefix_frontier(
        &self,
        reference: WalletArtifactRef,
    ) -> Result<PrefixMmrFrontierArtifact, RoastAttemptArchiveError> {
        validate_reference_kind(
            reference,
            ROAST_PREFIX_MMR_FRONTIER_ARTIFACT,
            MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let frontier: PrefixMmrFrontierArtifact = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES,
            "ROAST prefix MMR frontier",
        )?;
        if WalletId(frontier.wallet.0) != reference.wallet_id() {
            return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
        }
        self.verify_prefix_frontier(&frontier).await?;
        Ok(frontier)
    }

    async fn verify_prefix_frontier(
        &self,
        frontier: &PrefixMmrFrontierArtifact,
    ) -> Result<(), RoastAttemptArchiveError> {
        frontier.validate_shape()?;
        let mut expected_start = 0_u64;
        for (peak, reference) in
            frontier.frontier.peaks().iter().zip(frontier.peak_nodes.iter().copied())
        {
            let node = self.load_prefix_mmr_node(reference).await?;
            if node.wallet != frontier.wallet
                || node.network != frontier.network
                || node.family != frontier.family
                || node.start_view != expected_start
                || node.height != peak.height()
                || node.digest != peak.digest()
            {
                return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
            }
            expected_start = expected_start
                .checked_add(node.width()?)
                .ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
        }
        if expected_start != frontier.frontier.leaf_count() {
            return Err(RoastAttemptArchiveError::InvalidPrefixMmr);
        }
        Ok(())
    }

    async fn verify_prefix_membership_path(
        &self,
        frontier: &PrefixMmrFrontierArtifact,
        expected_attempt_reference: WalletArtifactRef,
        expected_record: &RoastAttemptArchiveRecord,
    ) -> Result<RoastAttemptPrefixMembershipProof, RoastAttemptArchiveError> {
        self.verify_prefix_frontier(frontier).await?;
        if expected_record.family != frontier.family
            || expected_record.family_anchor != frontier.family_anchor
        {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        let target = expected_record.view;
        let mut selected = None;
        let mut start = 0_u64;
        for (peak, reference) in
            frontier.frontier.peaks().iter().zip(frontier.peak_nodes.iter().copied())
        {
            let width = 1_u64
                .checked_shl(u32::from(peak.height()))
                .ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
            let end = start.checked_add(width).ok_or(RoastAttemptArchiveError::InvalidPrefixMmr)?;
            if target >= start && target < end {
                selected = Some((reference, peak.digest(), peak.height()));
                break;
            }
            start = end;
        }
        let (mut reference, expected_peak, expected_height) =
            selected.ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?;
        let mut siblings = Vec::with_capacity(usize::from(expected_height));
        let semantic_leaf = loop {
            let node = self.load_prefix_mmr_node(reference).await?;
            if node.height == 0 {
                let PrefixMmrNodeBody::Leaf { attempt_record } = node.body else {
                    return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
                };
                if attempt_record != expected_attempt_reference
                    || node.start_view != target
                    || node.family != expected_record.family
                    || node.digest
                        != certified_roast_attempt_leaf(
                            expected_record.family,
                            expected_record.family_anchor,
                            &expected_record.slot,
                            &expected_record.context,
                            &expected_record.intent,
                            &expected_record.intent_certificate,
                        )?
                {
                    return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
                }
                break node.digest;
            }
            let PrefixMmrNodeBody::Parent { left, right } = node.body else {
                return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
            };
            let left_node = self.load_prefix_mmr_node_shallow(left).await?;
            let right_node = self.load_prefix_mmr_node_shallow(right).await?;
            let midpoint = right_node.start_view;
            if target < midpoint {
                siblings.push(RoastAttemptPrefixSibling {
                    height: right_node.height,
                    sibling_on_left: false,
                    digest: right_node.digest,
                });
                reference = left;
            } else {
                siblings.push(RoastAttemptPrefixSibling {
                    height: left_node.height,
                    sibling_on_left: true,
                    digest: left_node.digest,
                });
                reference = right;
            }
        };
        let peak = self
            .load_prefix_mmr_node(
                selected.ok_or(RoastAttemptArchiveError::InvalidPrefixMembership)?.0,
            )
            .await?;
        if peak.height != expected_height || peak.digest != expected_peak {
            return Err(RoastAttemptArchiveError::InvalidPrefixMembership);
        }
        siblings.reverse();
        let proof = RoastAttemptPrefixMembershipProof {
            version: PREFIX_MEMBERSHIP_PROOF_VERSION,
            family: expected_record.family,
            family_anchor: expected_record.family_anchor,
            view: expected_record.view,
            attempt: expected_record.attempt,
            semantic_leaf,
            siblings,
            peaks: frontier.frontier.peaks().to_vec(),
        };
        proof.verify_record(
            RoastAttemptPrefixSeal::from_frontier(
                frontier.family,
                frontier.family_anchor,
                &frontier.frontier,
            )?,
            expected_record,
        )?;
        Ok(proof)
    }

    async fn load_index_node(
        &self,
        reference: WalletArtifactRef,
        wallet: DepositWalletId,
        namespace: SparseIndexNamespace,
    ) -> Result<SparseIndexNode, RoastAttemptArchiveError> {
        validate_reference(
            reference,
            wallet,
            ROAST_SPARSE_INDEX_NODE_ARTIFACT,
            MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
        )?;
        let bytes = self.load_artifact_bytes(reference).await?;
        let node: SparseIndexNode = decode_canonical_bounded(
            &bytes,
            MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
            "ROAST sparse index node",
        )?;
        node.validate()?;
        if node.wallet != wallet || node.namespace != namespace {
            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
        }
        Ok(node)
    }

    async fn create_index_node<R: RngCore + CryptoRng>(
        &self,
        node: SparseIndexNode,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        node.validate()?;
        let bytes =
            encode_bounded(&node, MAX_ROAST_SPARSE_INDEX_NODE_BYTES, "ROAST sparse index node")?;
        let reference = self
            .plan_artifact(
                WalletId(node.wallet.0),
                ROAST_SPARSE_INDEX_NODE_ARTIFACT,
                &bytes,
                rng,
                created,
            )
            .await?;
        let restored = self.load_index_node(reference, node.wallet, node.namespace).await?;
        if restored != node {
            return Err(RoastAttemptArchiveError::ReadbackMismatch);
        }
        Ok(reference)
    }

    async fn create_index_branch<R: RngCore + CryptoRng>(
        &self,
        wallet: DepositWalletId,
        namespace: SparseIndexNamespace,
        bit: u16,
        left: WalletArtifactRef,
        right: WalletArtifactRef,
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        let left_node = self.load_index_node(left, wallet, namespace).await?;
        let right_node = self.load_index_node(right, wallet, namespace).await?;
        self.create_index_node(
            SparseIndexNode::branch(
                wallet,
                namespace,
                bit,
                left,
                left_node.semantic_digest,
                right,
                right_node.semantic_digest,
            ),
            rng,
            created,
        )
        .await
    }

    async fn index_lookup(
        &self,
        root: Option<WalletArtifactRef>,
        wallet: DepositWalletId,
        key: SparseIndexKey,
    ) -> Result<Option<WalletArtifactRef>, RoastAttemptArchiveError> {
        let Some(mut reference) = root else {
            return Ok(None);
        };
        let key_digest = key.digest();
        let namespace = key.namespace();
        let mut previous_bit = None;
        for _ in 0..=256 {
            let node = self.load_index_node(reference, wallet, namespace).await?;
            match node.body {
                SparseIndexBody::Leaf { key: found, value } => {
                    if found == key {
                        return Ok(Some(value));
                    }
                    if found.digest() == key_digest {
                        return Err(RoastAttemptArchiveError::SparseIndexKeyCollision);
                    }
                    return Ok(None);
                }
                SparseIndexBody::Branch { bit, left, right } => {
                    if previous_bit.is_some_and(|previous| bit <= previous) {
                        return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                    }
                    previous_bit = Some(bit);
                    reference = if digest_bit(key_digest, bit)? { right } else { left };
                }
            }
        }
        Err(RoastAttemptArchiveError::InvalidSparseIndex)
    }

    async fn trace_index(
        &self,
        root: WalletArtifactRef,
        wallet: DepositWalletId,
        key: SparseIndexKey,
    ) -> Result<IndexTrace, RoastAttemptArchiveError> {
        let key_digest = key.digest();
        let namespace = key.namespace();
        let mut reference = root;
        let mut frames = Vec::new();
        let mut previous_bit = None;
        for _ in 0..=256 {
            let node = self.load_index_node(reference, wallet, namespace).await?;
            match node.body {
                SparseIndexBody::Leaf { .. } => {
                    return Ok(IndexTrace { frames, leaf_reference: reference, leaf: node });
                }
                SparseIndexBody::Branch { bit, left, right } => {
                    if previous_bit.is_some_and(|previous| bit <= previous) {
                        return Err(RoastAttemptArchiveError::InvalidSparseIndex);
                    }
                    previous_bit = Some(bit);
                    let went_right = digest_bit(key_digest, bit)?;
                    frames.push(IndexTraceFrame { reference, node, went_right });
                    reference = if went_right { right } else { left };
                }
            }
        }
        Err(RoastAttemptArchiveError::InvalidSparseIndex)
    }

    async fn index_insert<R: RngCore + CryptoRng>(
        &self,
        root: Option<WalletArtifactRef>,
        wallet: DepositWalletId,
        key: SparseIndexKey,
        value: WalletArtifactRef,
        value_semantic_digest: [u8; 32],
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        let namespace = key.namespace();
        let leaf = SparseIndexNode::leaf(wallet, key, value, value_semantic_digest);
        let Some(root) = root else {
            return self.create_index_node(leaf, rng, created).await;
        };
        let trace = self.trace_index(root, wallet, key).await?;
        let SparseIndexBody::Leaf { key: found, value: found_value } = trace.leaf.body else {
            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
        };
        if found == key {
            return if found_value == value && trace.leaf.semantic_digest == leaf.semantic_digest {
                Ok(root)
            } else {
                Err(RoastAttemptArchiveError::ConflictingSparseIndexValue)
            };
        }
        let key_digest = key.digest();
        let found_digest = found.digest();
        let differing_bit = first_differing_bit(key_digest, found_digest)
            .ok_or(RoastAttemptArchiveError::SparseIndexKeyCollision)?;
        let prefix_length = trace
            .frames
            .iter()
            .take_while(|frame| match frame.node.body {
                SparseIndexBody::Branch { bit, .. } => bit < differing_bit,
                SparseIndexBody::Leaf { .. } => false,
            })
            .count();
        let subtree =
            trace.frames.get(prefix_length).map_or(trace.leaf_reference, |frame| frame.reference);
        let new_leaf = self.create_index_node(leaf, rng, created).await?;
        let new_is_right = digest_bit(key_digest, differing_bit)?;
        if digest_bit(found_digest, differing_bit)? == new_is_right {
            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
        }
        let (left, right) = if new_is_right { (subtree, new_leaf) } else { (new_leaf, subtree) };
        let mut rewritten = self
            .create_index_branch(wallet, namespace, differing_bit, left, right, rng, created)
            .await?;

        for frame in trace.frames[..prefix_length].iter().rev() {
            let SparseIndexBody::Branch { bit, left, right } = frame.node.body else {
                return Err(RoastAttemptArchiveError::InvalidSparseIndex);
            };
            let (left, right) =
                if frame.went_right { (left, rewritten) } else { (rewritten, right) };
            rewritten =
                self.create_index_branch(wallet, namespace, bit, left, right, rng, created).await?;
        }
        Ok(rewritten)
    }

    async fn index_replace<R: RngCore + CryptoRng>(
        &self,
        root: WalletArtifactRef,
        wallet: DepositWalletId,
        key: SparseIndexKey,
        value: WalletArtifactRef,
        value_semantic_digest: [u8; 32],
        rng: &mut R,
        created: &mut BTreeSet<WalletArtifactRef>,
    ) -> Result<WalletArtifactRef, RoastAttemptArchiveError> {
        let trace = self.trace_index(root, wallet, key).await?;
        let SparseIndexBody::Leaf { key: found, value: previous } = trace.leaf.body else {
            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
        };
        if found != key {
            return Err(RoastAttemptArchiveError::InvalidSparseIndex);
        }
        let leaf = SparseIndexNode::leaf(wallet, key, value, value_semantic_digest);
        if previous == value && trace.leaf.semantic_digest == leaf.semantic_digest {
            return Ok(root);
        }
        let mut rewritten = self.create_index_node(leaf, rng, created).await?;
        for frame in trace.frames.iter().rev() {
            let SparseIndexBody::Branch { bit, left, right } = frame.node.body else {
                return Err(RoastAttemptArchiveError::InvalidSparseIndex);
            };
            let (left, right) =
                if frame.went_right { (left, rewritten) } else { (rewritten, right) };
            rewritten = self
                .create_index_branch(wallet, key.namespace(), bit, left, right, rng, created)
                .await?;
        }
        Ok(rewritten)
    }
}

/// Assemble exact ordered chunks and authenticate the complete content address.
pub fn assemble_roast_artifact_chunks(
    reference: WalletArtifactRef,
    chunks: &[RoastArtifactChunk],
) -> Result<Vec<u8>, RoastAttemptArchiveError> {
    let capacity = usize::try_from(reference.plaintext_len())
        .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
    if !is_roast_artifact_kind(reference.kind())
        || validate_roast_reference_bounds(reference).is_err()
        || capacity > MAX_WALLET_ARTIFACT_BYTES
        || chunks.is_empty()
    {
        return Err(RoastAttemptArchiveError::InvalidArtifactChunk);
    }
    let mut bytes = Vec::with_capacity(capacity);
    let mut next_offset = 0_u64;
    let expected_chunks = capacity.div_ceil(MAX_ROAST_ARTIFACT_CHUNK_BYTES);
    if chunks.len() != expected_chunks {
        return Err(RoastAttemptArchiveError::InvalidArtifactChunk);
    }
    for (position, chunk) in chunks.iter().enumerate() {
        chunk.validate()?;
        if chunk.reference != reference
            || chunk.offset != next_offset
            || (chunk.complete && position + 1 != chunks.len())
        {
            return Err(RoastAttemptArchiveError::InvalidArtifactChunk);
        }
        bytes.extend_from_slice(&chunk.bytes);
        next_offset = u64::try_from(bytes.len())
            .map_err(|_| RoastAttemptArchiveError::InvalidArtifactChunk)?;
    }
    if !chunks.last().is_some_and(|chunk| chunk.complete) {
        return Err(RoastAttemptArchiveError::InvalidArtifactChunk);
    }
    reference.verify_contents(&bytes)?;
    Ok(bytes)
}

fn deserialize_peak_references<'de, D>(deserializer: D) -> Result<Vec<WalletArtifactRef>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_capped_sequence(
        deserializer,
        MAX_ROAST_ARCHIVE_SKIP_LEVELS,
        "at most 64 ROAST MMR peak references",
    )
}

fn deserialize_history_peak_references<'de, D>(
    deserializer: D,
) -> Result<Vec<WalletArtifactRef>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_peak_references(deserializer)
}

fn deserialize_archive_checkpoint_witnesses<'de, D>(
    deserializer: D,
) -> Result<Vec<SignedEnvelope>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_capped_sequence(
        deserializer,
        MAX_COMMITTEE_MEMBERS,
        "at most the maximum committee size in archive checkpoint witnesses",
    )
}

fn deserialize_archive_journal_artifacts<'de, D>(
    deserializer: D,
) -> Result<Vec<WalletArtifactRef>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_capped_sequence(
        deserializer,
        MAX_ROAST_ARCHIVE_JOURNAL_ARTIFACTS,
        "a bounded ROAST archive stage artifact manifest",
    )
}

fn deserialize_prefix_frontier<'de, D>(
    deserializer: D,
) -> Result<RoastAttemptPrefixFrontier, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct BoundedFrontier {
        leaf_count: u64,
        #[serde(deserialize_with = "deserialize_prefix_peaks")]
        peaks: Vec<RoastAttemptPrefixPeak>,
    }

    let decoded = BoundedFrontier::deserialize(deserializer)?;
    RoastAttemptPrefixFrontier::from_peaks(decoded.leaf_count, decoded.peaks)
        .map_err(D::Error::custom)
}

fn deserialize_prefix_peaks<'de, D>(
    deserializer: D,
) -> Result<Vec<RoastAttemptPrefixPeak>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_capped_sequence(
        deserializer,
        MAX_ROAST_ARCHIVE_SKIP_LEVELS,
        "at most 64 ROAST MMR peaks",
    )
}

fn deserialize_prefix_siblings<'de, D>(
    deserializer: D,
) -> Result<Vec<RoastAttemptPrefixSibling>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_capped_sequence(
        deserializer,
        MAX_ROAST_ARCHIVE_SKIP_LEVELS,
        "at most 64 ROAST MMR siblings",
    )
}

fn deserialize_archived_endorsements<'de, D>(
    deserializer: D,
) -> Result<Vec<PortableSignedTransactionAttestation>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_capped_sequence(
        deserializer,
        MAX_ARCHIVED_ENDORSEMENTS,
        "a bounded ROAST endorsement set",
    )
}

fn deserialize_artifact_chunk_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ChunkBytesVisitor;

    impl<'de> Visitor<'de> for ChunkBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX_ROAST_ARTIFACT_CHUNK_BYTES} archive chunk bytes")
        }

        fn visit_bytes<E: DeError>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > MAX_ROAST_ARTIFACT_CHUNK_BYTES {
                return Err(E::custom("archive chunk exceeds the maximum"));
            }
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: DeError>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > MAX_ROAST_ARTIFACT_CHUNK_BYTES {
                return Err(E::custom("archive chunk exceeds the maximum"));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > MAX_ROAST_ARTIFACT_CHUNK_BYTES) {
                return Err(A::Error::custom("archive chunk exceeds the maximum"));
            }
            let mut bytes = Vec::with_capacity(
                sequence.size_hint().unwrap_or(0).min(MAX_ROAST_ARTIFACT_CHUNK_BYTES),
            );
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_ROAST_ARTIFACT_CHUNK_BYTES {
                    return Err(A::Error::custom("archive chunk exceeds the maximum"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_byte_buf(ChunkBytesVisitor)
}

fn deserialize_capped_sequence<'de, D, T>(
    deserializer: D,
    maximum: usize,
    expectation: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct CappedSequenceVisitor<T> {
        maximum: usize,
        expectation: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for CappedSequenceVisitor<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|length| length > self.maximum) {
                return Err(A::Error::custom(self.expectation));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.maximum {
                    return Err(A::Error::custom(self.expectation));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(CappedSequenceVisitor {
        maximum,
        expectation,
        marker: PhantomData,
    })
}

fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    kind: &'static str,
) -> Result<Vec<u8>, RoastAttemptArchiveError> {
    let bytes =
        postcard::to_allocvec(value).map_err(|_| RoastAttemptArchiveError::Serialization)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RoastAttemptArchiveError::ObjectTooLarge {
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
) -> Result<T, RoastAttemptArchiveError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(RoastAttemptArchiveError::ObjectTooLarge {
            kind,
            actual: bytes.len(),
            maximum,
        });
    }
    let (value, trailing) =
        postcard::take_from_bytes(bytes).map_err(|_| RoastAttemptArchiveError::Serialization)?;
    if !trailing.is_empty() {
        return Err(RoastAttemptArchiveError::TrailingBytes { kind, trailing: trailing.len() });
    }
    if postcard::to_allocvec(&value).map_err(|_| RoastAttemptArchiveError::Serialization)? != bytes
    {
        return Err(RoastAttemptArchiveError::NonCanonicalEncoding(kind));
    }
    Ok(value)
}

fn validate_reference(
    reference: WalletArtifactRef,
    wallet: DepositWalletId,
    kind: WalletArtifactKind,
    maximum: usize,
) -> Result<(), RoastAttemptArchiveError> {
    if reference.wallet_id() != WalletId(wallet.0) {
        return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
    }
    validate_reference_kind(reference, kind, maximum)
}

fn validate_reference_kind(
    reference: WalletArtifactRef,
    kind: WalletArtifactKind,
    maximum: usize,
) -> Result<(), RoastAttemptArchiveError> {
    let canonical = WalletArtifactRef::from_parts(
        reference.wallet_id(),
        reference.kind(),
        reference.plaintext_len(),
        reference.digest(),
    )?;
    let length = usize::try_from(reference.plaintext_len())
        .map_err(|_| RoastAttemptArchiveError::ArtifactReferenceMismatch)?;
    if canonical != reference
        || reference.wallet_id().0 == [0; 32]
        || reference.kind() != kind
        || length == 0
        || length > maximum
    {
        return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch);
    }
    Ok(())
}

fn validate_roast_reference_bounds(
    reference: WalletArtifactRef,
) -> Result<(), RoastAttemptArchiveError> {
    let maximum = match reference.kind() {
        ROAST_ATTEMPT_RECORD_ARTIFACT => MAX_ROAST_ATTEMPT_RECORD_BYTES,
        ROAST_SPARSE_INDEX_NODE_ARTIFACT => MAX_ROAST_SPARSE_INDEX_NODE_BYTES,
        ROAST_TRANSACTION_MAPPING_ARTIFACT => MAX_ROAST_TRANSACTION_MAPPING_BYTES,
        ROAST_ARCHIVE_COMMIT_ARTIFACT => MAX_ROAST_ARCHIVE_COMMIT_BYTES,
        ROAST_PREFIX_MMR_NODE_ARTIFACT => MAX_ROAST_PREFIX_MMR_NODE_BYTES,
        ROAST_PREFIX_MMR_FRONTIER_ARTIFACT => MAX_ROAST_PREFIX_MMR_FRONTIER_BYTES,
        ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT => MAX_ROAST_ARCHIVE_HISTORY_NODE_BYTES,
        _ => return Err(RoastAttemptArchiveError::ArtifactReferenceMismatch),
    };
    validate_reference_kind(reference, reference.kind(), maximum)
}

fn roast_archive_journal_key(
    wallet: DepositWalletId,
    network: [u8; 32],
) -> Result<DepositIndexJournalKey, RoastAttemptArchiveError> {
    if wallet.0 == [0; 32] || network == [0; 32] {
        return Err(RoastAttemptArchiveError::InvalidStageJournal);
    }
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/roast-archive/stage-journal-key/v1");
    hasher.update(&wallet.0);
    hasher.update(&network);
    let key = DepositIndexJournalKey {
        wallet_id: WalletId(wallet.0),
        // The storage record type predates archive journals. The application domain in
        // `expected_head_digest` makes this namespace disjoint from deposit-index and compact
        // registry journals while retaining the fixed no-enumeration probe API.
        scope: DepositIndexJournalScope::Portable,
        expected_revision: 0,
        expected_head_digest: *hasher.finalize().as_bytes(),
    };
    key.validate()?;
    Ok(key)
}

fn is_roast_artifact_kind(kind: WalletArtifactKind) -> bool {
    matches!(
        kind,
        ROAST_ATTEMPT_RECORD_ARTIFACT
            | ROAST_SPARSE_INDEX_NODE_ARTIFACT
            | ROAST_TRANSACTION_MAPPING_ARTIFACT
            | ROAST_ARCHIVE_COMMIT_ARTIFACT
            | ROAST_PREFIX_MMR_NODE_ARTIFACT
            | ROAST_PREFIX_MMR_FRONTIER_ARTIFACT
            | ROAST_ARCHIVE_HISTORY_NODE_ARTIFACT
    )
}

fn digest_bit(digest: [u8; 32], bit: u16) -> Result<bool, RoastAttemptArchiveError> {
    if bit >= 256 {
        return Err(RoastAttemptArchiveError::InvalidSparseIndex);
    }
    let byte = usize::from(bit / 8);
    let shift = 7 - (bit % 8);
    Ok((digest[byte] & (1 << shift)) != 0)
}

fn first_differing_bit(left: [u8; 32], right: [u8; 32]) -> Option<u16> {
    left.iter().zip(right).enumerate().find_map(|(index, (left, right))| {
        let difference = *left ^ right;
        if difference == 0 {
            None
        } else {
            Some(
                u16::try_from(index).expect("32-byte index fits u16") * 8
                    + u16::try_from(difference.leading_zeros()).expect("u8 leading zeros fit u16"),
            )
        }
    })
}

fn hash_optional_reference(hasher: &mut blake3::Hasher, reference: Option<WalletArtifactRef>) {
    match reference {
        None => {
            hasher.update(&[0]);
        }
        Some(reference) => {
            hasher.update(&[1]);
            hasher.update(&reference.wallet_id().0);
            hasher.update(&reference.kind().tag().to_le_bytes());
            hasher.update(&reference.plaintext_len().to_le_bytes());
            hasher.update(&reference.digest());
        }
    }
}

#[derive(Debug, Error)]
pub enum RoastAttemptArchiveError {
    #[error("ROAST attempt archive storage failed: {0}")]
    Store(#[from] StoreError),
    #[error("archive checkpoint committee is invalid: {0}")]
    Committee(#[from] CommitteeError),
    #[error("archive checkpoint identity signature is invalid: {0}")]
    Identity(#[from] IdentityError),
    #[error("archive history consistency is invalid: {0}")]
    History(#[from] RoastArchiveHistoryError),
    #[error("consolidation intent certificate is invalid: {0}")]
    ConsolidationConsensus(#[from] ConsolidationConsensusError),
    #[error("ROAST view proof is invalid: {0}")]
    Roast(#[from] ConsolidationRoastError),
    #[error("consolidation wire binding is invalid: {0}")]
    Wire(#[from] ConsolidationWireError),
    #[error("archived signed transaction is invalid: {0}")]
    DepositWallet(#[from] DepositWalletError),
    #[error("archived transaction key images are invalid: {0}")]
    DepositWorker(#[from] DepositWorkerError),
    #[error("archive serialization failed")]
    Serialization,
    #[error("{kind} encoding has {trailing} trailing bytes")]
    TrailingBytes { kind: &'static str, trailing: usize },
    #[error("{0} encoding is non-canonical")]
    NonCanonicalEncoding(&'static str),
    #[error("{kind} has {actual} bytes; maximum is {maximum}")]
    ObjectTooLarge { kind: &'static str, actual: usize, maximum: usize },
    #[error("the ROAST attempt archive head is invalid")]
    InvalidArchiveHead,
    #[error("the immutable ROAST archive commit is invalid")]
    InvalidArchiveCommit,
    #[error("the immutable ROAST commit ancestry is broken")]
    BrokenCommitChain,
    #[error("the certified ROAST attempt record is invalid")]
    InvalidAttemptRecord,
    #[error("the ROAST transaction mapping is invalid")]
    InvalidTransactionMapping,
    #[error("the requested archive belongs to another wallet or network")]
    WrongArchiveDomain,
    #[error("the ROAST sparse index is malformed")]
    InvalidSparseIndex,
    #[error("the ROAST semantic attempt-prefix MMR is malformed")]
    InvalidPrefixMmr,
    #[error("the archive transition-history MMR is malformed")]
    InvalidHistoryMmr,
    #[error("the archive transition-history consistency proof is invalid")]
    InvalidHistoryConsistencyProof,
    #[error("the archive endpoint checkpoint certificate is invalid")]
    InvalidCheckpointCertificate,
    #[error("archive, protocol store, and signing identity must belong to the same party")]
    CheckpointStorePartyMismatch,
    #[error("the durable ROAST archive stage journal is malformed or missing")]
    InvalidStageJournal,
    #[error("another ROAST archive object plan is already active or sealed")]
    ArchiveStageInProgress,
    #[error("the bounded ROAST archive object plan exceeded its object or byte limit")]
    ArchiveStageResourceLimit,
    #[error(
        "injected ROAST archive process crash after {completed_writes} immutable artifact writes"
    )]
    InjectedArchiveStageCrash { completed_writes: usize },
    #[error(
        "the durable ROAST archive stage journal does not match the authenticated snapshot head"
    )]
    StageJournalHeadMismatch,
    #[error("ROAST family {family:?} has no archived semantic prefix frontier")]
    MissingPrefixFrontier { family: [u8; 32] },
    #[error("the archived attempt is not a member of the exact terminal prefix seal")]
    InvalidPrefixMembership,
    #[error("two logical sparse-index keys have the same 256-bit digest")]
    SparseIndexKeyCollision,
    #[error("one sparse-index key was assigned two immutable values")]
    ConflictingSparseIndexValue,
    #[error("ROAST attempt {view} in family {family:?} conflicts with its immutable archive")]
    ConflictingAttemptRecord { family: [u8; 32], view: u64 },
    #[error(
        "transaction {transaction:?} in ROAST family {family:?} conflicts with its immutable mapping"
    )]
    ConflictingTransactionMapping { family: [u8; 32], transaction: [u8; 32] },
    #[error("ROAST attempt view {view} in family {family:?} is not archived")]
    AttemptRecordNotFound { family: [u8; 32], view: u64 },
    #[error("transaction {transaction:?} is not archived in ROAST family {family:?}")]
    TransactionNotFound { family: [u8; 32], transaction: [u8; 32] },
    #[error("attempt numbers start at one")]
    InvalidAttemptNumber,
    #[error("the ROAST archive exhausted a monotonic u64 counter")]
    ArchiveCounterExhausted,
    #[error("attempt stage has {actual} records; maximum is {maximum}")]
    TooManyAttemptsInStage { actual: usize, maximum: usize },
    #[error("archive object has {actual} direct dependencies; maximum is {maximum}")]
    TooManyArtifactDependencies { actual: usize, maximum: usize },
    #[error("archive stage journal has {actual} artifacts; maximum is {maximum}")]
    TooManyJournalArtifacts { actual: usize, maximum: usize },
    #[error("immutable artifact readback did not match staged bytes")]
    ReadbackMismatch,
    #[error("the wallet snapshot archive head changed before compare-and-swap")]
    HeadCasMismatch,
    #[error("the archive artifact reference has the wrong wallet, kind, or length")]
    ArtifactReferenceMismatch,
    #[error("the archive artifact transfer chunk is invalid, out of order, or incomplete")]
    InvalidArtifactChunk,
    #[error("a full key-image certificate is required for late-settlement provenance")]
    MissingFullKeyImageCertificate,
    #[error("the signed transaction key images do not match the all-selected certificate")]
    TransactionKeyImageMismatch,
}

#[cfg(test)]
mod tests {
    use monero_oxide::{
        ed25519::CompressedPoint,
        transaction::{Input, Timelock, Transaction, TransactionPrefix},
    };
    use rand_core::OsRng;
    use serde::Serialize;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        consolidation_consensus::CONSOLIDATION_INTENT_APPLICATION,
        deposit_consensus::{
            CommitCertificate, ConsensusBinding, ConsensusMessageBody, ConsensusValue, Vote,
            sign_consensus_message,
        },
        deposit_consolidation::{
            AttemptBinding, OpaqueIntentBinding, TransactionAuthorization,
            consolidation_input_set_binding,
        },
        deposit_consolidation_wire::{
            PortableFamilyKeyImageBinding, PortableKeyImageBindingAttestation,
        },
        deposit_wallet::{ChainPoint, SweepId, WalletOutputId},
        identity::{Identity, SignedEnvelope},
        signing::SigningContext,
    };

    struct Fixture {
        identities: Vec<Identity>,
        committee: Committee,
        plan: SweepPlan,
        authorization: TransactionAuthorization,
        inputs: Vec<WalletOutputId>,
        binding: ConsensusBinding,
        family_anchor: [u8; 32],
    }

    fn test_x25519_secret(party: PartyId, epoch: u64) -> [u8; 32] {
        let mut secret = [0xa4; 32];
        secret[2..10].copy_from_slice(&epoch.to_le_bytes());
        // X25519 clamps the low three bits of byte zero, so small party IDs stored
        // at the start of the scalar collapse to the same test public key.
        secret[10..12].copy_from_slice(&party.0.to_le_bytes());
        secret
    }

    impl Fixture {
        fn new() -> Self {
            let identities = (1_u16..=4)
                .map(|party| {
                    let party = PartyId(party);
                    let signing_seed = [u8::try_from(party.0).unwrap(); 32];
                    Identity::from_test_secrets(
                        party,
                        7,
                        &signing_seed,
                        test_x25519_secret(party, 7),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let members = identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect();
            let committee = Committee { epoch: 7, threshold: 2, members };
            committee.validate_async_security_with_faults(1).unwrap();
            let inputs = vec![WalletOutputId { transaction: [0x60; 32], index_in_transaction: 7 }];
            let mut plan = SweepPlan {
                id: SweepId([0; 32]),
                wallet: DepositWalletId([0x22; 32]),
                sequence: 1,
                epoch: committee.epoch,
                destination_binding: [0x64; 32],
                at_tip: ChainPoint::new(100, [0x63; 32]).unwrap(),
                inputs: inputs.clone(),
                total_input_atomic_units: 50_000,
            };
            plan.id = SweepId(plan.commitment());
            plan.validate_public().unwrap();
            let authorization = TransactionAuthorization::new(
                DepositWalletId([0x22; 32]),
                plan.id,
                OpaqueIntentBinding([0x62; 32]),
                consolidation_input_set_binding(&inputs),
                [0x64; 32],
                [0x65; 32],
                1,
                50_000,
                1_000,
                2_000,
            )
            .unwrap();
            let binding = ConsensusBinding {
                domain: [0x11; 32],
                application: CONSOLIDATION_INTENT_APPLICATION.to_vec(),
                wallet: [0x22; 32],
                network: [0x33; 32],
                registry: [0x44; 32],
                activation: [0x55; 32],
            };
            let genesis =
                ConsolidationConsensusSlot::new(binding.clone(), &committee, 1, 0, 0, 1, [0; 32])
                    .unwrap();
            Self {
                identities,
                committee,
                plan,
                authorization,
                inputs,
                binding,
                family_anchor: genesis.family_anchor(),
            }
        }

        fn record(&self, view: u64, variant: u8) -> RoastAttemptArchiveRecord {
            let slot = if view == 0 {
                ConsolidationConsensusSlot::new(
                    self.binding.clone(),
                    &self.committee,
                    1,
                    0,
                    0,
                    1,
                    [0; 32],
                )
                .unwrap()
            } else {
                ConsolidationConsensusSlot::new_successor(
                    self.binding.clone(),
                    &self.committee,
                    1,
                    self.family_anchor,
                    view,
                    view,
                    view + 1,
                    [u8::try_from(view).unwrap(); 32],
                )
                .unwrap()
            };
            let context = slot.consensus_context().unwrap();
            let plan =
                RoastViewPlan::derive(&slot, &self.committee, 1, &self.authorization).unwrap();
            let worker_byte = u8::try_from(view + 1).unwrap().wrapping_add(variant);
            let context_byte = u8::try_from(view + 0x80).unwrap().wrapping_add(variant);
            let attempt = AttemptBinding::new(
                plan.attempt(),
                context.epoch(),
                context.binding().registry,
                context.committee().digest(),
                context.binding().activation,
                self.authorization.root_group_key(),
                context.committee().threshold,
                plan.signers().to_vec(),
                [worker_byte; 32],
                plan.signing_session(),
                [context_byte; 32],
            )
            .unwrap();
            let intent =
                ConsolidationIntent::new(&context, self.authorization.clone(), attempt).unwrap();
            let value = intent.to_consensus_value().unwrap();
            let certificate = self.commit_certificate(&context, value);
            let intent_certificate =
                ConsolidationIntentCertificate::new(context.clone(), certificate).unwrap();
            let wire_binding = ConsolidationAttemptWireBinding::new(
                &self.authorization,
                intent.attempt(),
                plan.relay_seed(),
            )
            .unwrap();
            RoastAttemptArchiveRecord::new(
                slot,
                context,
                intent,
                intent_certificate,
                wire_binding,
                None,
            )
            .unwrap()
        }

        fn commit_certificate(
            &self,
            context: &ConsensusContext,
            value: ConsensusValue,
        ) -> CommitCertificate {
            let witnesses = self
                .identities
                .iter()
                .take(context.quorum())
                .map(|identity| {
                    sign_consensus_message(
                        context,
                        identity,
                        ConsensusMessageBody::Precommit(Vote { view: 0, value: value.digest() }),
                    )
                    .unwrap()
                })
                .collect();
            CommitCertificate::from_witnesses(context, 0, value, witnesses).unwrap()
        }

        fn identity(&self, party: PartyId) -> &Identity {
            self.identities.iter().find(|identity| identity.party() == party).unwrap()
        }

        fn key_image_certificate(
            &self,
            record: &RoastAttemptArchiveRecord,
        ) -> PortableKeyImageBindingCertificate {
            let signing_context: SigningContext =
                postcard::from_bytes(&record.intent().attempt().signing_context()).unwrap();
            // A worker sweep family and its public ROAST family use different domains. Derive a
            // stable, nonzero worker-domain fixture so archive tests exercise that distinction.
            let worker_family_digest = {
                let mut hasher =
                    blake3::Hasher::new_derive_key("threshold-monero/deposit-sweep-family/v1");
                hasher.update(b"roast-attempt-archive-fixture");
                hasher.update(&record.family());
                *hasher.finalize().as_bytes()
            };
            assert_ne!(worker_family_digest, record.family());
            let encoded = postcard::to_allocvec(&PortableKeyImageValueFixture {
                sweep: self.authorization.sweep_id(),
                inputs: self.inputs.clone(),
                key_images: vec![CompressedPoint::G.to_bytes()],
                family_digest: worker_family_digest,
                unsigned_transaction_digest: [0x91; 32],
                signing_context,
                preprocess_set_digest: [0x92; 32],
            })
            .unwrap();
            let value: PortableFamilyKeyImageBinding = postcard::from_bytes(&encoded).unwrap();
            let attestations = record
                .intent()
                .attempt()
                .signers()
                .iter()
                .map(|party| {
                    let provenance = PortableKeyImageProvenanceFixture {
                        version: 1,
                        quic_network_id: record.network_id(),
                        attempt: record.wire_binding().clone(),
                        origin: *party,
                    };
                    let payload = postcard::to_allocvec(&PortableKeyImagePayloadFixture {
                        domain:
                            "threshold-monero/deposit-consolidation/key-image-binding-attestation/v1",
                        provenance: &provenance,
                        value: &value,
                    })
                    .unwrap();
                    let envelope = self
                        .identity(*party)
                        .sign_envelope(
                            &self.committee,
                            record.intent().attempt().session(),
                            None,
                            0x544d_434b_494d_4731,
                            payload,
                        )
                        .unwrap();
                    decode_key_image_attestation(envelope)
                })
                .collect();
            PortableKeyImageBindingCertificate::from_attestations(
                &self.committee,
                1,
                record.network_id(),
                record.wire_binding(),
                attestations,
            )
            .unwrap()
        }

        fn endorsements(
            &self,
            record: &RoastAttemptArchiveRecord,
            transaction: &SignedSweepTransaction,
        ) -> Vec<PortableSignedTransactionAttestation> {
            record
                .intent()
                .attempt()
                .signers()
                .iter()
                .take(2)
                .map(|party| {
                    PortableSignedTransactionAttestation::sign(
                        self.identity(*party),
                        &self.committee,
                        record.network_id(),
                        record.wire_binding().clone(),
                        transaction.clone(),
                    )
                    .unwrap()
                })
                .collect()
        }
    }

    #[derive(Serialize)]
    struct PortableKeyImageValueFixture {
        sweep: SweepId,
        inputs: Vec<WalletOutputId>,
        key_images: Vec<[u8; 32]>,
        family_digest: [u8; 32],
        unsigned_transaction_digest: [u8; 32],
        signing_context: SigningContext,
        preprocess_set_digest: [u8; 32],
    }

    #[derive(Serialize)]
    struct PortableKeyImageProvenanceFixture {
        version: u16,
        quic_network_id: [u8; 32],
        attempt: ConsolidationAttemptWireBinding,
        origin: PartyId,
    }

    #[derive(Serialize)]
    struct PortableKeyImagePayloadFixture<'a> {
        domain: &'a str,
        provenance: &'a PortableKeyImageProvenanceFixture,
        value: &'a PortableFamilyKeyImageBinding,
    }

    fn decode_key_image_attestation(
        envelope: SignedEnvelope,
    ) -> PortableKeyImageBindingAttestation {
        postcard::from_bytes(&postcard::to_allocvec(&envelope).unwrap()).unwrap()
    }

    fn signed_transaction(extra_bytes: usize) -> SignedSweepTransaction {
        let transaction = Transaction::V2 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::None,
                inputs: vec![Input::ToKey {
                    amount: None,
                    key_offsets: (1_u64..=16).collect(),
                    key_image: CompressedPoint::G,
                }],
                outputs: vec![],
                extra: vec![0xA3; extra_bytes],
            },
            proofs: None,
        };
        SignedSweepTransaction::from_transaction(&transaction, None).unwrap()
    }

    async fn artifact_plaintext(
        store: &RoastAttemptArchiveStore,
        reference: WalletArtifactRef,
    ) -> Vec<u8> {
        let mut chunks = Vec::new();
        let mut offset = 0_u64;
        while offset < reference.plaintext_len() {
            let request = RoastArtifactChunkRequest::new(
                reference,
                offset,
                u32::try_from(MAX_ROAST_ARTIFACT_CHUNK_BYTES).unwrap(),
            )
            .unwrap();
            let chunk = store.artifact_chunk(request).await.unwrap();
            offset += u64::try_from(chunk.bytes.len()).unwrap();
            chunks.push(chunk);
        }
        assemble_roast_artifact_chunks(reference, &chunks).unwrap()
    }

    #[tokio::test]
    async fn cold_index_retrieves_view_one_after_more_than_sixty_four_views_and_restart() {
        let fixture = Fixture::new();
        let records = (0..66).map(|view| fixture.record(view, 0)).collect::<Vec<_>>();
        let family = records[0].family();
        assert!(records.iter().all(|record| record.family() == family));
        let directory = tempdir().unwrap();
        let identity_seed = [0xA5; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty = RoastAttemptArchiveHead::empty(records[0].wallet_id(), records[0].network_id())
            .unwrap();

        let staged = store.stage_attempts(empty, &records, &mut OsRng).await.unwrap();
        assert!(staged.changed);
        assert_eq!(staged.head.attempt_count(), 66);
        assert_eq!(staged.ensure_cas(empty).unwrap(), staged.head);
        assert!(staged.ensure_cas(staged.head).is_err());
        store.verify_local_ancestry(empty, staged.head).await.unwrap();
        assert_eq!(
            store.load_view(staged.head, records[0].wallet_id(), family, 1).await.unwrap(),
            Some(records[1].clone()),
        );
        assert_eq!(
            store.load_attempt(staged.head, records[0].wallet_id(), family, 2).await.unwrap(),
            Some(records[1].clone()),
        );
        let prepared = store
            .prepare_stage(&protocols, empty, staged.clone(), &mut OsRng)
            .await
            .unwrap()
            .unwrap();
        store.commit_prepared_stage(&protocols, &prepared, staged.head).await.unwrap();

        drop(store);
        drop(protocols);
        let restarted =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let restarted_protocols =
            ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted.load_view(staged.head, records[0].wallet_id(), family, 1).await.unwrap(),
            Some(records[1].clone()),
        );

        let signed_transaction = signed_transaction(8);
        let transaction = signed_transaction.transaction_id();
        let key_images = fixture.key_image_certificate(&records[1]);
        let endorsements = fixture.endorsements(&records[1], &signed_transaction);
        let mapped = restarted
            .stage_transaction_mapping(
                staged.head,
                family,
                1,
                fixture.plan.clone(),
                key_images,
                endorsements,
                &mut OsRng,
            )
            .await
            .unwrap();
        let composed = staged.clone().compose(mapped.clone()).unwrap();
        assert_eq!(composed.ensure_cas(empty).unwrap(), mapped.head);
        assert!(mapped.ensure_cas(empty).is_err());
        let archived = restarted
            .load_transaction(mapped.head, records[0].wallet_id(), family, transaction)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(archived.attempt_record(), &records[1]);
        assert_eq!(archived.mapping().attempt_record_digest(), records[1].digest().unwrap());
        assert_eq!(archived.mapping().signed_transaction(), &signed_transaction);
        assert_eq!(archived.archive_head(), mapped.head);
        let mut semantic_frontier = RoastAttemptPrefixFrontier::empty();
        for record in &records {
            semantic_frontier
                .append_certified_attempt(
                    record.family(),
                    record.family_anchor(),
                    record.slot(),
                    record.context(),
                    record.intent(),
                    record.intent_certificate(),
                )
                .unwrap();
        }
        let seal = RoastAttemptPrefixSeal::from_frontier(
            family,
            records[0].family_anchor(),
            &semantic_frontier,
        )
        .unwrap();
        let prefix_verified = restarted
            .verify_prefix_transaction(mapped.head, records[0].wallet_id(), seal, transaction)
            .await
            .unwrap();
        assert_eq!(prefix_verified.attempt_record(), &records[1]);
        assert_eq!(prefix_verified.prefix_seal(), seal);
        assert_ne!(prefix_verified.membership_digest(), [0; 32]);
        let portable = prefix_verified.membership_proof().clone();
        let binding = portable.verify_record(seal, &records[1]).unwrap();
        assert_eq!(binding.family(), family);
        assert_eq!(binding.view(), 1);
        assert_eq!(binding.attempt(), 2);
        assert_eq!(binding.prefix_accumulator(), seal.accumulator());
        assert_eq!(
            restarted
                .export_prefix_transaction_proof(
                    mapped.head,
                    records[0].wallet_id(),
                    seal,
                    transaction,
                )
                .await
                .unwrap(),
            portable,
        );
        let encoded = postcard::to_allocvec(&portable).unwrap();
        let restored: RoastAttemptPrefixMembershipProof = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(restored.verify(seal).unwrap(), binding);
        let mut tampered = portable.clone();
        tampered.siblings[0].digest[0] ^= 1;
        assert!(matches!(
            tampered.verify(seal),
            Err(RoastAttemptArchiveError::InvalidPrefixMembership)
        ));
        let mut oversized = portable;
        oversized.siblings =
            vec![
                RoastAttemptPrefixSibling { height: 0, sibling_on_left: false, digest: [1; 32] };
                MAX_ROAST_ARCHIVE_SKIP_LEVELS + 1
            ];
        let oversized = postcard::to_allocvec(&oversized).unwrap();
        assert!(postcard::from_bytes::<RoastAttemptPrefixMembershipProof>(&oversized).is_err());
        let completion = restarted
            .export_portable_transaction_completion(
                mapped.head,
                records[0].wallet_id(),
                seal,
                transaction,
            )
            .await
            .unwrap();
        let portable_verified = completion
            .verify_expected(
                seal,
                records[0].wallet_id(),
                records[0].network_id(),
                family,
                transaction,
            )
            .unwrap();
        assert_eq!(completion.mapping().plan(), &fixture.plan);
        assert_eq!(portable_verified.transaction_id(), transaction);
        assert_eq!(portable_verified.member(), binding);
        assert_ne!(portable_verified.evidence_digest(), [0; 32]);
        let mut wrong_plan_completion = completion.clone();
        wrong_plan_completion.mapping.plan.sequence += 1;
        assert!(
            wrong_plan_completion
                .verify_expected(
                    seal,
                    records[0].wallet_id(),
                    records[0].network_id(),
                    family,
                    transaction,
                )
                .is_err()
        );
        let encoded = completion.to_bytes().unwrap();
        let restored = PortableRoastTransactionCompletionProof::from_bytes(&encoded).unwrap();
        assert_eq!(
            restored
                .verify_expected(
                    seal,
                    records[0].wallet_id(),
                    records[0].network_id(),
                    family,
                    transaction,
                )
                .unwrap()
                .evidence_digest(),
            portable_verified.evidence_digest(),
        );
        let mut tampered_completion = completion;
        tampered_completion.mapping.transaction[0] ^= 1;
        assert!(
            tampered_completion
                .verify_expected(
                    seal,
                    records[0].wallet_id(),
                    records[0].network_id(),
                    family,
                    transaction,
                )
                .is_err()
        );
        let mut shorter_frontier = RoastAttemptPrefixFrontier::empty();
        for record in &records[..2] {
            shorter_frontier
                .append_certified_attempt(
                    record.family(),
                    record.family_anchor(),
                    record.slot(),
                    record.context(),
                    record.intent(),
                    record.intent_certificate(),
                )
                .unwrap();
        }
        let shorter_seal = RoastAttemptPrefixSeal::from_frontier(
            family,
            records[0].family_anchor(),
            &shorter_frontier,
        )
        .unwrap();
        assert!(matches!(
            restarted
                .verify_prefix_transaction(
                    mapped.head,
                    records[0].wallet_id(),
                    shorter_seal,
                    transaction,
                )
                .await,
            Err(RoastAttemptArchiveError::Roast(_))
        ));
        restarted.verify_local_ancestry(staged.head, mapped.head).await.unwrap();
        let prepared = restarted
            .prepare_stage(&restarted_protocols, staged.head, mapped.clone(), &mut OsRng)
            .await
            .unwrap()
            .unwrap();
        restarted
            .commit_prepared_stage(&restarted_protocols, &prepared, mapped.head)
            .await
            .unwrap();

        drop(restarted);
        drop(restarted_protocols);
        let restarted =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted
                .load_transaction(mapped.head, records[0].wallet_id(), family, transaction)
                .await
                .unwrap()
                .unwrap()
                .attempt_record(),
            &records[1],
        );
    }

    #[tokio::test]
    async fn exact_duplicate_is_idempotent_but_same_view_conflict_fails() {
        let fixture = Fixture::new();
        let first = fixture.record(0, 0);
        let conflicting = fixture.record(0, 1);
        assert_eq!(first.family(), conflicting.family());
        assert_ne!(first, conflicting);
        let directory = tempdir().unwrap();
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &[0xB5; 32]).unwrap();
        let empty = RoastAttemptArchiveHead::empty(first.wallet_id(), first.network_id()).unwrap();
        let staged =
            store.stage_attempts(empty, std::slice::from_ref(&first), &mut OsRng).await.unwrap();
        let duplicate = store
            .stage_attempts(staged.head, std::slice::from_ref(&first), &mut OsRng)
            .await
            .unwrap();
        assert!(!duplicate.changed);
        assert_eq!(duplicate.head, staged.head);
        assert!(matches!(
            store.stage_attempts(staged.head, &[conflicting], &mut OsRng).await,
            Err(RoastAttemptArchiveError::ConflictingAttemptRecord { .. })
        ));
    }

    #[tokio::test]
    async fn transaction_mapping_requires_exact_full_evidence_and_is_idempotent() {
        let fixture = Fixture::new();
        let record = fixture.record(0, 0);
        let family = record.family();
        let directory = tempdir().unwrap();
        let identity_seed = [0xC5; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(record.wallet_id(), record.network_id()).unwrap();
        let attempts =
            store.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await.unwrap();
        let prepared = store
            .prepare_stage(&protocols, empty, attempts.clone(), &mut OsRng)
            .await
            .unwrap()
            .unwrap();
        store.commit_prepared_stage(&protocols, &prepared, attempts.head).await.unwrap();
        let transaction = signed_transaction(16);
        let certificate = fixture.key_image_certificate(&record);
        let endorsements = fixture.endorsements(&record, &transaction);
        let certified_key_images = certificate
            .verify(&fixture.committee, 1, record.network_id(), record.wire_binding())
            .unwrap();
        assert_ne!(certified_key_images.family_digest(), family);

        assert!(matches!(
            store
                .stage_transaction_mapping(
                    attempts.head,
                    family,
                    0,
                    fixture.plan.clone(),
                    certificate.clone(),
                    endorsements[..1].to_vec(),
                    &mut OsRng,
                )
                .await,
            Err(RoastAttemptArchiveError::InvalidTransactionMapping)
        ));

        let mut reversed = endorsements.clone();
        reversed.reverse();
        assert!(matches!(
            store
                .stage_transaction_mapping(
                    attempts.head,
                    family,
                    0,
                    fixture.plan.clone(),
                    certificate.clone(),
                    reversed,
                    &mut OsRng,
                )
                .await,
            Err(RoastAttemptArchiveError::InvalidTransactionMapping)
        ));

        let mut wrong_plan = fixture.plan.clone();
        wrong_plan.sequence += 1;
        assert!(
            store
                .stage_transaction_mapping(
                    attempts.head,
                    family,
                    0,
                    wrong_plan,
                    certificate.clone(),
                    endorsements.clone(),
                    &mut OsRng,
                )
                .await
                .is_err()
        );

        let different_transaction = signed_transaction(17);
        let mut split = endorsements.clone();
        split[1] = PortableSignedTransactionAttestation::sign(
            fixture.identity(split[1].origin()),
            &fixture.committee,
            record.network_id(),
            record.wire_binding().clone(),
            different_transaction,
        )
        .unwrap();
        assert!(matches!(
            store
                .stage_transaction_mapping(
                    attempts.head,
                    family,
                    0,
                    fixture.plan.clone(),
                    certificate.clone(),
                    split,
                    &mut OsRng,
                )
                .await,
            Err(RoastAttemptArchiveError::InvalidTransactionMapping)
        ));

        let staged = store
            .stage_transaction_mapping(
                attempts.head,
                family,
                0,
                fixture.plan.clone(),
                certificate.clone(),
                endorsements.clone(),
                &mut OsRng,
            )
            .await
            .unwrap();
        let duplicate = store
            .stage_transaction_mapping(
                staged.head,
                family,
                0,
                fixture.plan.clone(),
                certificate,
                endorsements,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert!(!duplicate.changed);
        assert_eq!(duplicate.head, staged.head);
        let verified = store
            .load_transaction(staged.head, record.wallet_id(), family, transaction.transaction_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(verified.mapping().signed_transaction(), &transaction);
        assert_eq!(verified.mapping().plan(), &fixture.plan);
        assert_eq!(verified.mapping().endorsements().len(), 2);
    }

    #[tokio::test]
    async fn every_materialization_crash_boundary_recovers_without_leaking_objects() {
        let fixture = Fixture::new();
        let record = fixture.record(0, 0);
        let identity_seed = [0xD5; 32];
        let probe_directory = tempdir().unwrap();
        let probe =
            RoastAttemptArchiveStore::new(probe_directory.path(), PartyId(1), &identity_seed)
                .unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(record.wallet_id(), record.network_id()).unwrap();
        let probe_stage =
            probe.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await.unwrap();
        let write_count = probe_stage.created.len();
        assert!(write_count > 0);
        drop(probe);
        drop(probe_directory);

        for crash_after in 0..=write_count {
            let directory = tempdir().unwrap();
            let store = RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed)
                .unwrap();
            let protocols =
                ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
            let stage = store
                .stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng)
                .await
                .unwrap();
            assert_eq!(stage.created.len(), write_count);
            let target = stage.head;
            let candidates = stage.created.clone();
            for reference in &candidates {
                assert!(!tokio::fs::try_exists(store.artifact_path(*reference)).await.unwrap());
            }

            assert!(matches!(
                store
                    .prepare_stage_with_crash_after_artifact_write(
                        &protocols,
                        empty,
                        stage,
                        &mut OsRng,
                        crash_after,
                    )
                    .await,
                Err(RoastAttemptArchiveError::InjectedArchiveStageCrash {
                    completed_writes,
                }) if completed_writes == crash_after
            ));
            drop(store);
            drop(protocols);

            let restarted =
                RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed)
                    .unwrap();
            let restarted_protocols =
                ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
            assert_eq!(
                restarted.recover_stage_journal(&restarted_protocols, empty).await.unwrap(),
                RoastArchiveJournalRecovery::Aborted
            );
            restarted.verify_head(empty).await.unwrap();
            assert!(restarted.verify_head(target).await.is_err());
            for reference in candidates {
                assert!(!tokio::fs::try_exists(restarted.artifact_path(reference)).await.unwrap());
            }
        }
    }

    #[tokio::test]
    async fn journal_before_reservation_race_preserves_foreign_exact_artifact() {
        let fixture = Fixture::new();
        let record = fixture.record(0, 0);
        let directory = tempdir().unwrap();
        let identity_seed = [0xD3; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(record.wallet_id(), record.network_id()).unwrap();
        let stage =
            store.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await.unwrap();
        let reference = stage.created[0];
        let raced_bytes = store.load_artifact_bytes(reference).await.unwrap();

        assert!(matches!(
            store
                .prepare_stage_with_crash_after_artifact_write(
                    &protocols, empty, stage, &mut OsRng, 0,
                )
                .await,
            Err(RoastAttemptArchiveError::InjectedArchiveStageCrash { completed_writes: 0 })
        ));

        let racer =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            racer
                .artifacts
                .create_artifact(reference.wallet_id(), reference.kind(), &raced_bytes, &mut OsRng,)
                .await
                .unwrap(),
            reference
        );
        drop(store);
        drop(protocols);
        drop(racer);

        let restarted =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let restarted_protocols =
            ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted.recover_stage_journal(&restarted_protocols, empty).await.unwrap(),
            RoastArchiveJournalRecovery::Aborted
        );
        assert!(tokio::fs::try_exists(restarted.artifact_path(reference)).await.unwrap());
        assert_eq!(
            restarted.artifacts.load_artifact(reference).await.unwrap().contents.as_bytes(),
            raced_bytes.as_slice(),
        );
    }

    #[tokio::test]
    async fn foreign_planner_is_blocked_until_owner_abort_finishes() {
        let fixture = Fixture::new();
        let record = fixture.record(0, 0);
        let directory = tempdir().unwrap();
        let identity_seed = [0xD2; 32];
        let owner =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(record.wallet_id(), record.network_id()).unwrap();
        let stage =
            owner.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await.unwrap();
        let candidates = stage.created.clone();
        let prepared =
            owner.prepare_stage(&protocols, empty, stage, &mut OsRng).await.unwrap().unwrap();

        let foreign =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert!(matches!(
            foreign.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await,
            Err(RoastAttemptArchiveError::Store(
                StoreError::WalletArtifactReservationConflict { .. }
            ))
        ));

        owner.abort_prepared_stage(&protocols, &prepared, empty).await.unwrap();
        for reference in candidates {
            assert!(!tokio::fs::try_exists(owner.artifact_path(reference)).await.unwrap());
        }
        assert!(
            foreign
                .stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng)
                .await
                .unwrap()
                .changed
        );
    }

    #[tokio::test]
    async fn post_cas_restart_keeps_committed_archive_artifacts_and_clears_journal() {
        let fixture = Fixture::new();
        let record = fixture.record(0, 0);
        let directory = tempdir().unwrap();
        let identity_seed = [0xD4; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(record.wallet_id(), record.network_id()).unwrap();
        let stage =
            store.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await.unwrap();
        let target = stage.head;
        let candidates = stage.created.clone();
        store.prepare_stage(&protocols, empty, stage, &mut OsRng).await.unwrap().unwrap();
        drop(store);
        drop(protocols);

        let restarted =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let restarted_protocols =
            ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        assert_eq!(
            restarted.recover_stage_journal(&restarted_protocols, target).await.unwrap(),
            RoastArchiveJournalRecovery::Committed
        );
        restarted.verify_head(target).await.unwrap();
        for reference in candidates {
            assert!(tokio::fs::try_exists(restarted.artifact_path(reference)).await.unwrap());
        }
        assert_eq!(
            restarted.recover_stage_journal(&restarted_protocols, target).await.unwrap(),
            RoastArchiveJournalRecovery::None
        );
    }

    #[tokio::test]
    async fn bounded_history_ancestry_handles_long_history_and_detects_forks() {
        let fixture = Fixture::new();
        let records = (0..70).map(|view| fixture.record(view, 0)).collect::<Vec<_>>();
        let directory = tempdir().unwrap();
        let identity_seed = [0xD6; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty = RoastAttemptArchiveHead::empty(records[0].wallet_id(), records[0].network_id())
            .unwrap();
        let mut head = empty;
        let mut heads = vec![empty];
        let mut aggregate: Option<RoastAttemptArchiveStage> = None;
        for record in &records {
            let stage =
                store.stage_attempts(head, std::slice::from_ref(record), &mut OsRng).await.unwrap();
            head = stage.ensure_cas(head).unwrap();
            heads.push(head);
            aggregate = Some(match aggregate {
                None => stage,
                Some(previous) => previous.compose(stage).unwrap(),
            });
        }
        let aggregate = aggregate.unwrap();
        let prepared =
            store.prepare_stage(&protocols, empty, aggregate, &mut OsRng).await.unwrap().unwrap();
        store.commit_prepared_stage(&protocols, &prepared, head).await.unwrap();
        assert_eq!(head.generation(), 70);
        for generation in [0_usize, 1, 2, 17, 33, 69, 70] {
            let proof = store.export_history_consistency(heads[generation], head).await.unwrap();
            assert!(proof.suffix().len() <= (u64::BITS as usize) * 2);
            store.verify_local_ancestry(heads[generation], head).await.unwrap();
        }

        let fork_record = fixture.record(35, 1);
        let fork = store.stage_attempts(heads[35], &[fork_record], &mut OsRng).await.unwrap().head;
        store.verify_local_ancestry(heads[35], fork).await.unwrap();
        assert!(store.verify_local_ancestry(heads[36], fork).await.is_err());
        assert!(store.verify_local_ancestry(fork, head).await.is_err());
    }

    #[tokio::test]
    async fn fork_summary_cannot_be_spliced_into_bounded_history_proof() {
        let fixture = Fixture::new();
        let main_records = (0..5).map(|view| fixture.record(view, 0)).collect::<Vec<_>>();
        let directory = tempdir().unwrap();
        let identity_seed = [0xD8; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty = RoastAttemptArchiveHead::empty(
            main_records[0].wallet_id(),
            main_records[0].network_id(),
        )
        .unwrap();
        let mut main_heads = vec![empty];
        let mut aggregate: Option<RoastAttemptArchiveStage> = None;
        for record in &main_records {
            let stage = store
                .stage_attempts(
                    *main_heads.last().unwrap(),
                    std::slice::from_ref(record),
                    &mut OsRng,
                )
                .await
                .unwrap();
            main_heads.push(stage.head);
            aggregate = Some(match aggregate {
                None => stage,
                Some(previous) => previous.compose(stage).unwrap(),
            });
        }
        let prepared = store
            .prepare_stage(&protocols, empty, aggregate.unwrap(), &mut OsRng)
            .await
            .unwrap()
            .unwrap();
        store.commit_prepared_stage(&protocols, &prepared, main_heads[5]).await.unwrap();
        let fork =
            store.stage_attempts(empty, &[fixture.record(0, 1)], &mut OsRng).await.unwrap().head;
        let proof = store.export_history_consistency(empty, main_heads[5]).await.unwrap();
        assert!(
            proof
                .verify(
                    fork.semantic_state().unwrap(),
                    fork.history_root(),
                    main_heads[5].semantic_state().unwrap(),
                    main_heads[5].history_root(),
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn checkpoint_is_n_minus_f_and_generation_slot_survives_restart() {
        let fixture = Fixture::new();
        let directory = tempdir().unwrap();
        let identity_seed = [1; 32];
        let store =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let protocols = ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(fixture.plan.wallet, fixture.binding.network).unwrap();
        let main_stage =
            store.stage_attempts(empty, &[fixture.record(0, 0)], &mut OsRng).await.unwrap();
        let main = main_stage.head;
        let prepared =
            store.prepare_stage(&protocols, empty, main_stage, &mut OsRng).await.unwrap().unwrap();
        store.commit_prepared_stage(&protocols, &prepared, main).await.unwrap();
        let fork =
            store.stage_attempts(empty, &[fixture.record(0, 1)], &mut OsRng).await.unwrap().head;
        let (statement, first) = store
            .sign_checkpoint(
                &protocols,
                fixture.identity(PartyId(1)),
                main,
                &fixture.committee,
                1,
                fixture.binding.registry,
                fixture.binding.activation,
                &mut OsRng,
            )
            .await
            .unwrap();
        let payload = statement.to_bytes().unwrap();
        let mut witnesses = vec![first];
        for party in [PartyId(2), PartyId(3)] {
            witnesses.push(
                fixture
                    .identity(party)
                    .sign_envelope(
                        &fixture.committee,
                        statement.slot_session(),
                        None,
                        main.generation(),
                        payload.clone(),
                    )
                    .unwrap(),
            );
        }
        let certificate = RoastArchiveCheckpointCertificate::from_witnesses(
            statement.clone(),
            witnesses,
            &fixture.committee,
            1,
            fixture.binding.registry,
            fixture.binding.activation,
            fixture.plan.wallet,
            fixture.binding.network,
        )
        .unwrap();
        assert_eq!(
            certificate
                .verify(
                    &fixture.committee,
                    1,
                    fixture.binding.registry,
                    fixture.binding.activation,
                    fixture.plan.wallet,
                    fixture.binding.network,
                )
                .unwrap()
                .signers()
                .len(),
            3
        );
        assert!(
            store
                .sign_checkpoint(
                    &protocols,
                    fixture.identity(PartyId(1)),
                    fork,
                    &fixture.committee,
                    1,
                    fixture.binding.registry,
                    fixture.binding.activation,
                    &mut OsRng,
                )
                .await
                .is_err()
        );
        drop(store);
        drop(protocols);

        let restarted =
            RoastAttemptArchiveStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let restarted_protocols =
            ProtocolStore::new(directory.path(), PartyId(1), &identity_seed).unwrap();
        let (retried, _) = restarted
            .sign_checkpoint(
                &restarted_protocols,
                fixture.identity(PartyId(1)),
                main,
                &fixture.committee,
                1,
                fixture.binding.registry,
                fixture.binding.activation,
                &mut OsRng,
            )
            .await
            .unwrap();
        assert_eq!(retried, statement);
    }

    #[tokio::test]
    async fn patricia_root_is_insertion_order_independent_and_stage_is_bounded() {
        let fixture = Fixture::new();
        let records = (0..20).map(|view| fixture.record(view, 0)).collect::<Vec<_>>();
        let first_dir = tempdir().unwrap();
        let second_dir = tempdir().unwrap();
        let first =
            RoastAttemptArchiveStore::new(first_dir.path(), PartyId(1), &[0xD7; 32]).unwrap();
        let second =
            RoastAttemptArchiveStore::new(second_dir.path(), PartyId(1), &[0xD7; 32]).unwrap();
        let empty = RoastAttemptArchiveHead::empty(records[0].wallet_id(), records[0].network_id())
            .unwrap();
        let forward = first.stage_attempts(empty, &records, &mut OsRng).await.unwrap();
        let mut reversed = records.clone();
        reversed.reverse();
        let backward = second.stage_attempts(empty, &reversed, &mut OsRng).await.unwrap();
        assert_eq!(forward.head, backward.head);

        let oversized = vec![records[0].clone(); MAX_ROAST_ATTEMPTS_PER_STAGE + 1];
        assert!(matches!(
            first.stage_attempts(forward.head, &oversized, &mut OsRng).await,
            Err(RoastAttemptArchiveError::TooManyAttemptsInStage { .. })
        ));
    }

    #[tokio::test]
    async fn fixed_grid_chunk_transfer_authenticates_multi_chunk_mapping_and_rejects_gaps() {
        let fixture = Fixture::new();
        let record = fixture.record(0, 0);
        let family = record.family();
        let source_dir = tempdir().unwrap();
        let destination_dir = tempdir().unwrap();
        let identity_seed = [0xE5; 32];
        let source =
            RoastAttemptArchiveStore::new(source_dir.path(), PartyId(1), &identity_seed).unwrap();
        let empty =
            RoastAttemptArchiveHead::empty(record.wallet_id(), record.network_id()).unwrap();
        let attempts =
            source.stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng).await.unwrap();
        let transaction = signed_transaction(700_000);
        let mapping = source
            .stage_transaction_mapping(
                attempts.head,
                family,
                0,
                fixture.plan.clone(),
                fixture.key_image_certificate(&record),
                fixture.endorsements(&record, &transaction),
                &mut OsRng,
            )
            .await
            .unwrap();
        let mapping_reference = mapping
            .created
            .iter()
            .copied()
            .find(|reference| reference.kind() == ROAST_TRANSACTION_MAPPING_ARTIFACT)
            .unwrap();
        assert!(
            mapping_reference.plaintext_len()
                > u64::try_from(MAX_ROAST_ARTIFACT_CHUNK_BYTES).unwrap()
        );
        let mut chunks = Vec::new();
        let mut offset = 0_u64;
        while offset < mapping_reference.plaintext_len() {
            let request = RoastArtifactChunkRequest::new(
                mapping_reference,
                offset,
                u32::try_from(MAX_ROAST_ARTIFACT_CHUNK_BYTES).unwrap(),
            )
            .unwrap();
            let chunk = source.artifact_chunk(request).await.unwrap();
            offset += u64::try_from(chunk.bytes.len()).unwrap();
            chunks.push(chunk);
        }
        let bytes = assemble_roast_artifact_chunks(mapping_reference, &chunks).unwrap();
        let mut missing = chunks.clone();
        missing.remove(0);
        assert!(assemble_roast_artifact_chunks(mapping_reference, &missing).is_err());
        let mut corrupted = chunks.clone();
        corrupted[0].bytes[0] ^= 1;
        assert!(assemble_roast_artifact_chunks(mapping_reference, &corrupted).is_err());

        let destination =
            RoastAttemptArchiveStore::new(destination_dir.path(), PartyId(1), &identity_seed)
                .unwrap();
        // Mapping transfer is dependency ordered and therefore fails closed until its exact
        // attempt record has been transferred.
        assert!(
            destination
                .persist_transferred_artifact(mapping_reference, &bytes, &mut OsRng)
                .await
                .is_err()
        );
        let mut pending =
            attempts.created.iter().chain(mapping.created.iter()).copied().collect::<BTreeSet<_>>();
        while !pending.is_empty() {
            let mut progressed = false;
            for reference in pending.iter().copied().collect::<Vec<_>>() {
                assert!(
                    source.artifact_dependencies(reference).await.unwrap().len()
                        <= MAX_ROAST_ARTIFACT_DEPENDENCIES
                );
                let plaintext = artifact_plaintext(&source, reference).await;
                if destination
                    .persist_transferred_artifact(reference, &plaintext, &mut OsRng)
                    .await
                    .is_ok()
                {
                    pending.remove(&reference);
                    progressed = true;
                }
            }
            assert!(progressed, "dependency-ordered transfer made no progress");
        }

        // Replaying the exact transition over pre-existing objects must reference, but never
        // journal or delete, even the multi-chunk signed-transaction/certificate mapping.
        let replay_attempts = destination
            .stage_attempts(empty, std::slice::from_ref(&record), &mut OsRng)
            .await
            .unwrap();
        let replay_mapping = destination
            .stage_transaction_mapping(
                replay_attempts.head,
                family,
                0,
                fixture.plan.clone(),
                fixture.key_image_certificate(&record),
                fixture.endorsements(&record, &transaction),
                &mut OsRng,
            )
            .await
            .unwrap();
        let replay = replay_attempts.compose(replay_mapping).unwrap();
        assert!(replay.created.is_empty());
        let destination_protocols =
            ProtocolStore::new(destination_dir.path(), PartyId(1), &identity_seed).unwrap();
        let prepared = destination
            .prepare_stage(&destination_protocols, empty, replay, &mut OsRng)
            .await
            .unwrap()
            .unwrap();
        destination.abort_prepared_stage(&destination_protocols, &prepared, empty).await.unwrap();
        assert!(tokio::fs::try_exists(destination.artifact_path(mapping_reference)).await.unwrap());

        destination.verify_head(mapping.head).await.unwrap();
        let restored = destination
            .load_transaction(
                mapping.head,
                record.wallet_id(),
                family,
                transaction.transaction_id(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.mapping().signed_transaction(), &transaction);
        drop(destination);
        let restarted =
            RoastAttemptArchiveStore::new(destination_dir.path(), PartyId(1), &identity_seed)
                .unwrap();
        restarted.verify_head(mapping.head).await.unwrap();
    }

    #[test]
    fn record_encoding_is_canonical_current_format_and_requires_full_provenance() {
        let fixture = Fixture::new();
        let mut record = fixture.record(0, 0);
        let certificate = fixture.key_image_certificate(&record);
        record.key_image_certificate = Some(certificate);
        record.validate().unwrap();
        assert!(record.require_full_key_image_certificate().is_ok());
        let bytes = record.to_bytes().unwrap();
        assert_eq!(RoastAttemptArchiveRecord::from_bytes(&bytes).unwrap(), record);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(RoastAttemptArchiveRecord::from_bytes(&trailing).is_err());

        let mut obsolete = fixture.record(0, 0);
        obsolete.version = 0;
        assert!(matches!(obsolete.validate(), Err(RoastAttemptArchiveError::InvalidAttemptRecord)));
    }

    #[test]
    fn patricia_bit_helpers_cover_msb_and_lsb() {
        let mut left = [0_u8; 32];
        let mut right = [0_u8; 32];
        right[0] = 0x80;
        assert_eq!(first_differing_bit(left, right), Some(0));
        assert!(digest_bit(right, 0).unwrap());
        right = left;
        right[31] = 1;
        assert_eq!(first_differing_bit(left, right), Some(255));
        assert!(digest_bit(right, 255).unwrap());
        left[31] = 1;
        assert_eq!(first_differing_bit(left, right), None);
    }
}
