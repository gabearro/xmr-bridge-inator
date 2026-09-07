//! Portable, wallet-bound certified allocation and consolidation ledger spanning proactive epochs.
//!
//! The ledger is deliberately separate from party-local persistence revisions and signer locks.
//! Every certified statement occupies one global sequence slot. An epoch transition occupies that
//! same slot namespace, so an old quorum must certify a terminal handoff before the new quorum can
//! issue allocations or consolidation completions. Certificate witnesses are excluded from
//! statement hashes.

use std::collections::BTreeSet;

use curve25519_dalek::{edwards::CompressedEdwardsY, traits::IsIdentity};
use monero_oxide::{
    ringct::RctType,
    transaction::{Input as MoneroInput, Transaction as MoneroTransaction},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::{CommitteeError, PartyId, SessionId},
    compact_epoch_registry::{
        ActiveIssuer, CompactEpochRegistry, CompactRegistryError, RegistryHandoffCertificate,
        RegistryHandoffStatement, RegistryId, VerifiedIssuerWindow,
        compact_registry_genesis_ledger_head,
    },
    consolidation_roast::{RoastAttemptPrefixSeal, deterministic_roast_family_digest},
    deposit_consolidation::{
        AttemptBinding, ConsolidationError, ConsolidationId, SignedTransactionBinding,
        TransactionAuthorization, consolidation_input_set_binding,
        consolidation_signed_bytes_binding,
    },
    deposit_consolidation_wire::{
        ConsolidationAttemptWireBinding, ConsolidationConsensusSlot,
        PortableKeyImageBindingCertificate,
    },
    deposit_index::{
        VerifiedDepositIndexPreflight, VerifiedDepositIndexTransition,
        VerifiedDepositObservationIndexTransition,
    },
    deposit_index_checkpoint::{
        DepositIndexCheckpointOperation, PortableDepositIndexHead, VerifiedDepositIndexCheckpoint,
    },
    deposit_index_store::VerifiedSignedDepositObservationSlot,
    deposit_state_export::DepositHandoffStateBinding,
    deposit_wallet::{
        CanonicalDepositAddress, ChainPoint, DepositSubaddressIndex, DepositWalletId,
        SignedSweepTransaction, VerifiedRecognitionAnchor, WalletOutputId,
    },
    deposit_worker::SweepPlan,
    identity::{Identity, IdentityError, SignedEnvelope},
    key_rotation::VerifiedRegistryHandoffTarget,
};

const STATEMENT_VERSION: u16 = 3;
const ATTESTATION_VERSION: u16 = 1;
const MAX_ATTESTATION_BYTES: usize = 192;
const MAX_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;
const DEPOSIT_OBSERVATION_VERSION: u16 = 1;
const DEPOSIT_OBSERVATION_ATTESTATION_VERSION: u16 = 1;
const CONSOLIDATION_COMPLETION_VERSION: u16 = 1;
const CONSOLIDATION_ABANDONMENT_VERSION: u16 = 1;
const LATE_CONSOLIDATION_SETTLEMENT_VERSION: u16 = 1;
const HANDOFF_FENCE_VERSION: u16 = 1;
const MAX_CONSOLIDATION_INPUTS: usize = 1_024;
const MAX_UNIX_TIMESTAMP: u64 = 253_402_300_799;

/// Unused allocations stop being client-usable after exactly thirty days.
pub const UNUSED_ALLOCATION_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Maximum tolerated absolute clock skew when an honest party first reserves an allocation.
pub const MAX_ALLOCATION_CLOCK_SKEW_SECONDS: u64 = 300;
/// Minimum future lead honest signers require for n-f ledger and index certification.
pub const MIN_ALLOCATION_CERTIFICATION_LEAD_SECONDS: u64 = 30;

/// One confirmed output observation which permanently activates an allocation.
///
/// This lane is independent of the globally ordered allocation ledger. Its exact output and
/// one-time-key conflicts are merged into the portable authenticated index; an n-f certificate
/// makes the fact independent of any one party's scanner database.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DepositObservationStatement {
    version: u16,
    wallet: DepositWalletId,
    issuer_epoch: u64,
    issuer_committee: [u8; 32],
    issuer_activation: [u8; 32],
    allocation_sequence: u64,
    allocation_statement: [u8; 32],
    index: DepositSubaddressIndex,
    output: WalletOutputId,
    output_key: [u8; 32],
    index_on_blockchain: u64,
    amount_atomic_units: u64,
    observed_block: ChainPoint,
    block_timestamp: u64,
    confirmation_horizon: ChainPoint,
    confirmation_depth: u32,
}

impl DepositObservationStatement {
    /// Construct an observation under the currently active issuer.
    ///
    /// Construction only establishes public shape and allocation binding. A signer must
    /// independently match it against its authenticated confirmed scanner before attesting.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: &CompactEpochRegistry,
        allocation_statement: &LedgerStatement,
        output: WalletOutputId,
        output_key: [u8; 32],
        index_on_blockchain: u64,
        amount_atomic_units: u64,
        observed_block: ChainPoint,
        block_timestamp: u64,
        confirmation_horizon: ChainPoint,
        confirmation_depth: u32,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        let LedgerPayload::Allocation(allocation) = &allocation_statement.payload else {
            return Err(LedgerError::InvalidDepositObservation);
        };
        if allocation_statement.wallet != registry.wallet() {
            return Err(LedgerError::RegistryMismatch);
        }
        let issuer = registry.active();
        let statement = Self {
            version: DEPOSIT_OBSERVATION_VERSION,
            wallet: registry.wallet(),
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            allocation_sequence: allocation_statement.sequence,
            allocation_statement: allocation_statement.digest(),
            index: allocation.address.index(),
            output,
            output_key,
            index_on_blockchain,
            amount_atomic_units,
            observed_block,
            block_timestamp,
            confirmation_horizon,
            confirmation_depth,
        };
        validate_deposit_observation_static(&statement)?;
        Ok(statement)
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
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
    pub const fn issuer_activation(&self) -> [u8; 32] {
        self.issuer_activation
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
    pub const fn confirmation_horizon(&self) -> ChainPoint {
        self.confirmation_horizon
    }

    #[must_use]
    pub const fn confirmation_depth(&self) -> u32 {
        self.confirmation_depth
    }

    /// Validate this persisted pending statement against the currently active issuer.
    ///
    /// This performs the same public shape and issuer checks used by attestation verification,
    /// without signing or accepting any unauthenticated local reservation state.
    pub fn validate_active(&self, registry: &CompactEpochRegistry) -> Result<(), LedgerError> {
        registry.validate()?;
        validate_deposit_observation_static(self)?;
        validate_deposit_observation_issuer(self, registry.active())
    }

    /// Reissue the same confirmed-output fact under the current active issuer.
    ///
    /// Only the issuer epoch, committee, and activation are replaced. The allocation binding,
    /// output fact, and confirmation context remain byte-for-byte unchanged so the permanent local
    /// fact tombstone continues to authorize the retry.
    pub fn reissue_for_active(&self, registry: &CompactEpochRegistry) -> Result<Self, LedgerError> {
        registry.validate()?;
        validate_deposit_observation_static(self)?;
        if self.wallet != registry.wallet() {
            return Err(LedgerError::RegistryMismatch);
        }
        let active = registry.active();
        let mut reissued = self.clone();
        reissued.issuer_epoch = active.epoch();
        reissued.issuer_committee = active.committee().digest();
        reissued.issuer_activation = active.activation();
        reissued.validate_active(registry)?;
        if reissued.fact_digest() != self.fact_digest() {
            return Err(LedgerError::InvalidDepositObservation);
        }
        Ok(reissued)
    }

    /// Issuer-independent digest of the exact chain fact.
    ///
    /// This remains stable when an uncertified observation has to be retried at a later confirmed
    /// horizon or by the successor committee during handoff. Confirmation horizon/depth are
    /// certificate context, not a different output fact. Party-local no-double-attest storage
    /// binds this digest before releasing any issuer-specific signature.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/deposit-observation-fact/v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        hasher.update(&self.allocation_sequence.to_le_bytes());
        hasher.update(&self.allocation_statement);
        hasher.update(&self.index.account().to_le_bytes());
        hasher.update(&self.index.address().to_le_bytes());
        hasher.update(&self.output.transaction);
        hasher.update(&self.output.index_in_transaction.to_le_bytes());
        hasher.update(&self.output_key);
        hasher.update(&self.index_on_blockchain.to_le_bytes());
        hasher.update(&self.amount_atomic_units.to_le_bytes());
        hasher.update(&self.observed_block.height.to_le_bytes());
        hasher.update(&self.observed_block.hash);
        hasher.update(&self.block_timestamp.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Witness-independent, issuer-specific statement digest used by certificates and portable
    /// output records.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/deposit-observation-statement/v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        hasher.update(&self.issuer_epoch.to_le_bytes());
        hasher.update(&self.issuer_committee);
        hasher.update(&self.issuer_activation);
        hasher.update(&self.fact_digest());
        hasher.update(&self.confirmation_horizon.height.to_le_bytes());
        hasher.update(&self.confirmation_horizon.hash);
        hasher.update(&self.confirmation_depth.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    #[must_use]
    pub fn session(&self) -> SessionId {
        let mut material = Vec::with_capacity(104);
        material.extend_from_slice(&self.wallet.0);
        material.extend_from_slice(&self.allocation_sequence.to_le_bytes());
        material.extend_from_slice(&self.output.transaction);
        material.extend_from_slice(&self.output.index_in_transaction.to_le_bytes());
        material.extend_from_slice(&self.output_key);
        SessionId::derive(b"deposit-observation/v1", &material)
    }

    fn attestation_payload(&self) -> Result<Vec<u8>, LedgerError> {
        let attestation = DepositObservationAttestation {
            version: DEPOSIT_OBSERVATION_ATTESTATION_VERSION,
            wallet: self.wallet,
            allocation_sequence: self.allocation_sequence,
            output: self.output,
            statement: self.digest(),
        };
        let bytes = postcard::to_allocvec(&attestation).map_err(|_| LedgerError::Serialization)?;
        if bytes.len() > MAX_ATTESTATION_BYTES {
            return Err(LedgerError::AttestationTooLarge);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DepositObservationAttestation {
    version: u16,
    wallet: DepositWalletId,
    allocation_sequence: u64,
    output: WalletOutputId,
    statement: [u8; 32],
}

/// An n-f certificate for one exact confirmed output observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertifiedDepositObservation {
    pub statement: DepositObservationStatement,
    /// Strictly ordered by sender. Witness choice never changes portable state.
    pub attestations: Vec<SignedEnvelope>,
}

impl CertifiedDepositObservation {
    /// Verify against the issuer window which certified this observation.
    pub fn verify(
        &self,
        issuer_window: &VerifiedIssuerWindow,
    ) -> Result<VerifiedDepositObservationCertificate, LedgerError> {
        issuer_window.validate()?;
        validate_deposit_observation_static(&self.statement)?;
        validate_deposit_observation_issuer(&self.statement, issuer_window.issuer())?;
        verify_deposit_observation_witnesses(self, issuer_window.issuer())
    }

    /// Verify a prospective certificate against the compact active issuer.
    pub fn verify_active(
        &self,
        registry: &CompactEpochRegistry,
    ) -> Result<VerifiedDepositObservationCertificate, LedgerError> {
        registry.validate()?;
        validate_deposit_observation_static(&self.statement)?;
        validate_deposit_observation_issuer(&self.statement, registry.active())?;
        verify_deposit_observation_witnesses(self, registry.active())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let bytes = postcard::to_allocvec(self).map_err(|_| LedgerError::Serialization)?;
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(LedgerError::CertificateTooLarge);
        }
        Ok(bytes)
    }

    /// Domain-separated commitment to the exact canonical certificate bytes, including witnesses.
    pub fn certificate_digest(&self) -> Result<[u8; 32], LedgerError> {
        exact_certificate_digest(
            "threshold-monero/certified-deposit-observation/v1",
            &self.to_bytes()?,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(LedgerError::CertificateTooLarge);
        }
        let (value, trailing) =
            postcard::take_from_bytes::<Self>(bytes).map_err(|_| LedgerError::Deserialization)?;
        if !trailing.is_empty() {
            return Err(LedgerError::TrailingBytes(trailing.len()));
        }
        if value.to_bytes()?.as_slice() != bytes {
            return Err(LedgerError::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

/// Result of authenticating one observation certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDepositObservationCertificate {
    wallet: DepositWalletId,
    allocation_sequence: u64,
    output: WalletOutputId,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    signers: BTreeSet<PartyId>,
    required: u16,
}

impl VerifiedDepositObservationCertificate {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn allocation_sequence(&self) -> u64 {
        self.allocation_sequence
    }

    #[must_use]
    pub const fn output(&self) -> WalletOutputId {
        self.output
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub const fn signers(&self) -> &BTreeSet<PartyId> {
        &self.signers
    }

    #[must_use]
    pub const fn required(&self) -> u16 {
        self.required
    }

    /// Prove this verification capability was issued for these exact canonical certificate bytes.
    pub fn verify_exact_certificate(
        &self,
        certificate: &CertifiedDepositObservation,
    ) -> Result<(), LedgerError> {
        let signers =
            certificate.attestations.iter().map(|envelope| envelope.from).collect::<BTreeSet<_>>();
        if certificate.statement.wallet_id() != self.wallet
            || certificate.statement.allocation_sequence() != self.allocation_sequence
            || certificate.statement.output() != self.output
            || certificate.statement.digest() != self.statement_digest
            || certificate.certificate_digest()? != self.certificate_digest
            || signers != self.signers
        {
            return Err(LedgerError::VerificationCapabilityMismatch);
        }
        Ok(())
    }
}

/// Verify one prospective observation witness without treating raw network bytes as authority.
pub fn verify_deposit_observation_attestation(
    statement: &DepositObservationStatement,
    registry: &CompactEpochRegistry,
    envelope: &SignedEnvelope,
) -> Result<PartyId, LedgerError> {
    registry.validate()?;
    validate_deposit_observation_static(statement)?;
    validate_deposit_observation_issuer(statement, registry.active())?;
    let expected = statement.attestation_payload()?;
    if envelope.to.is_some() || envelope.payload.len() > MAX_ATTESTATION_BYTES {
        return Err(LedgerError::InvalidAttestation);
    }
    let verifier = registry
        .active()
        .committee()
        .members
        .first()
        .map(|member| member.id)
        .ok_or(LedgerError::InvalidRegistry)?;
    Identity::verify_envelope(registry.active().committee(), verifier, envelope)?;
    if envelope.session != statement.session()
        || envelope.sequence != statement.allocation_sequence
        || envelope.payload != expected
    {
        return Err(LedgerError::InvalidAttestation);
    }
    Ok(envelope.from)
}

fn sign_deposit_observation_attestation_inner(
    identity: &Identity,
    registry: &CompactEpochRegistry,
    statement: &DepositObservationStatement,
) -> Result<SignedEnvelope, LedgerError> {
    identity
        .sign_envelope(
            registry.active().committee(),
            statement.session(),
            None,
            statement.allocation_sequence(),
            statement.attestation_payload()?,
        )
        .map_err(LedgerError::Identity)
}

/// Sign one exact observation only after the durable store authenticated its paired local slots.
pub(crate) fn sign_deposit_observation_attestation_after_readback(
    identity: &Identity,
    registry: &CompactEpochRegistry,
    statement: &DepositObservationStatement,
    authorization: &VerifiedSignedDepositObservationSlot,
) -> Result<SignedEnvelope, LedgerError> {
    statement.validate_active(registry)?;
    if !authorization.authorizes(statement.wallet_id(), identity.party(), statement) {
        return Err(LedgerError::DepositObservationReservationRequired);
    }
    sign_deposit_observation_attestation_inner(identity, registry, statement)
}

/// Test-fixture signer for constructing certificates in modules which exercise later protocol
/// layers. Production builds expose only the durable-readback-gated store method.
#[cfg(test)]
pub(crate) fn sign_deposit_observation_attestation(
    identity: &Identity,
    registry: &CompactEpochRegistry,
    statement: &DepositObservationStatement,
) -> Result<SignedEnvelope, LedgerError> {
    statement.validate_active(registry)?;
    sign_deposit_observation_attestation_inner(identity, registry, statement)
}

/// Stable idempotency key supplied by the deposit client.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LedgerRequestId(pub [u8; 32]);

/// Commitment to the client and policy data associated with a request ID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestBinding(pub [u8; 32]);

/// Client allocation payload in one ledger slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllocationStatement {
    pub request: LedgerRequestId,
    pub binding: RequestBinding,
    pub address: CanonicalDepositAddress,
    /// Exact confirmed chain point from which every party must recognize this allocation.
    ///
    /// A party may not sign this statement until its authenticated local scanner contains this
    /// point.  After certification, scanners backfill the closed interval beginning at this
    /// anchor before treating the portable allocation head as live.
    pub recognition_anchor: ChainPoint,
    /// Scheduled client-visible issuance time.
    ///
    /// The quorum must finish certification before this instant and release the certified
    /// address no earlier than it.  This makes the complete unused lifetime independent of
    /// certificate assembly latency.
    pub created_at: u64,
    pub expires_at: u64,
}

/// Terminal old-epoch payload which authorizes exactly one successor epoch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffStatement {
    transition: RegistryHandoffStatement,
}

impl HandoffStatement {
    #[must_use]
    pub const fn transition(&self) -> &RegistryHandoffStatement {
        &self.transition
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.transition.target_epoch()
    }

    #[must_use]
    pub const fn target_committee(&self) -> [u8; 32] {
        self.transition.target_committee()
    }

    #[must_use]
    pub const fn target_fault_bound(&self) -> u16 {
        self.transition.target_fault_bound()
    }

    #[must_use]
    pub const fn target_activation(&self) -> [u8; 32] {
        self.transition.target_activation()
    }

    /// Allocation high-water mark; handoff consumes a sequence but no subaddress index.
    #[must_use]
    pub const fn next_index(&self) -> DepositSubaddressIndex {
        self.transition.next_index()
    }

    /// Digest of the authenticated portable index head immediately before this terminal slot.
    #[must_use]
    pub const fn source_portable_index(&self) -> [u8; 32] {
        self.transition.source_portable_index()
    }
}

/// Quorum-certified finite scanner frontier for one pending epoch transition.
///
/// This non-terminal ledger decision precedes the terminal [`HandoffStatement`]. It freezes the
/// canonical confirmed-chain prefix which the retiring issuer may checkpoint. Observations after
/// `cutoff` remain discoverable but cannot delay the terminal handoff and are reissued by the
/// successor issuer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HandoffFenceStatement {
    version: u16,
    target_epoch: u64,
    target_committee: [u8; 32],
    target_activation: [u8; 32],
    cutoff: ChainPoint,
}

impl HandoffFenceStatement {
    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_epoch
    }

    #[must_use]
    pub const fn target_committee(&self) -> [u8; 32] {
        self.target_committee
    }

    #[must_use]
    pub const fn target_activation(&self) -> [u8; 32] {
        self.target_activation
    }

    #[must_use]
    pub const fn cutoff(&self) -> ChainPoint {
        self.cutoff
    }
}

/// A quorum-certified, byte-exact completion of one root-wallet consolidation sweep.
///
/// This contains only public authorization material and the already signed transaction. Private
/// decoys, offsets, and outgoing-view material remain committed by `authorization.opaque_intent`
/// and are never copied into the portable ledger.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationCompletionStatement {
    version: u16,
    /// Exact mature-input plan independently reconstructed by every signer.
    pub plan: SweepPlan,
    /// Exact public transaction policy and private-intent commitment.
    pub authorization: TransactionAuthorization,
    /// Exact epoch, signer set, FROSTLASS session, and signing-context binding.
    pub attempt: AttemptBinding,
    /// Public commitment to the completed transaction and the attempt which produced it.
    pub signed: SignedTransactionBinding,
    /// Canonical Monero transaction bytes retained forever for deterministic rebroadcast/audit.
    pub signed_transaction: SignedSweepTransaction,
}

impl ConsolidationCompletionStatement {
    /// Reconstruct the historical public completion carried by a successor-issued late
    /// settlement. This does not itself confer authority: [`LedgerStatement::late_consolidation_settlement`]
    /// validates the complete graph against the historical epoch, while the service separately
    /// requires archive-prefix membership and current-chain inclusion certificates.
    pub(crate) fn from_archived_components(
        plan: SweepPlan,
        authorization: TransactionAuthorization,
        attempt: AttemptBinding,
        signed: SignedTransactionBinding,
        signed_transaction: SignedSweepTransaction,
    ) -> Self {
        Self {
            version: CONSOLIDATION_COMPLETION_VERSION,
            plan,
            authorization,
            attempt,
            signed,
            signed_transaction,
        }
    }

    /// Stable authorization-derived identity of this completion.
    #[must_use]
    pub const fn id(&self) -> ConsolidationId {
        self.authorization.id()
    }

    #[must_use]
    pub const fn plan(&self) -> &SweepPlan {
        &self.plan
    }

    #[must_use]
    pub const fn authorization(&self) -> &TransactionAuthorization {
        &self.authorization
    }

    #[must_use]
    pub const fn attempt(&self) -> &AttemptBinding {
        &self.attempt
    }

    #[must_use]
    pub const fn signed_binding(&self) -> SignedTransactionBinding {
        self.signed
    }

    #[must_use]
    pub const fn signed_transaction(&self) -> &SignedSweepTransaction {
        &self.signed_transaction
    }

    /// Sorted, unique scanner output identities permanently claimed by this completion.
    #[must_use]
    pub fn inputs(&self) -> &[WalletOutputId] {
        &self.plan.inputs
    }

    /// Transaction ID parsed from the exact canonical bytes.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 32] {
        self.signed.transaction
    }
}

/// Quorum-certified closure of an unsigned nonce lineage whose inputs disappeared on the
/// canonical chain. This is a liveness fence, never authority to reuse a nonce, key image, input,
/// or signing session. A later fully validated old-family transaction may still supersede this
/// closure by canonical inclusion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationAbandonmentStatement {
    version: u16,
    family: [u8; 32],
    attempt_prefix: RoastAttemptPrefixSeal,
    slot: ConsolidationConsensusSlot,
    binding: ConsolidationAttemptWireBinding,
    key_images: PortableKeyImageBindingCertificate,
    authorization: TransactionAuthorization,
    attempt: AttemptBinding,
    sweep_sequence: u64,
    inputs: Vec<WalletOutputId>,
    missing_inputs: Vec<WalletOutputId>,
    ancestor: ChainPoint,
    observation_tip: ChainPoint,
    finality_depth: u32,
}

impl ConsolidationAbandonmentStatement {
    #[must_use]
    pub const fn id(&self) -> ConsolidationId {
        self.authorization.id()
    }

    #[must_use]
    pub const fn family(&self) -> [u8; 32] {
        self.family
    }

    #[must_use]
    pub const fn attempt_prefix(&self) -> RoastAttemptPrefixSeal {
        self.attempt_prefix
    }

    #[must_use]
    pub const fn slot(&self) -> &ConsolidationConsensusSlot {
        &self.slot
    }

    #[must_use]
    pub const fn binding(&self) -> &ConsolidationAttemptWireBinding {
        &self.binding
    }

    #[must_use]
    pub const fn key_images(&self) -> &PortableKeyImageBindingCertificate {
        &self.key_images
    }

    #[must_use]
    pub const fn authorization(&self) -> &TransactionAuthorization {
        &self.authorization
    }

    #[must_use]
    pub const fn attempt(&self) -> &AttemptBinding {
        &self.attempt
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
    pub fn missing_inputs(&self) -> &[WalletOutputId] {
        &self.missing_inputs
    }

    #[must_use]
    pub const fn ancestor(&self) -> ChainPoint {
        self.ancestor
    }

    #[must_use]
    pub const fn observation_tip(&self) -> ChainPoint {
        self.observation_tip
    }

    #[must_use]
    pub const fn finality_depth(&self) -> u32 {
        self.finality_depth
    }
}

/// A current committee's portable recognition that the exact transaction from a historically
/// abandoned nonce lineage later reached the canonical chain. This settles the old family without
/// allowing the retired committee to issue a new ledger statement or authorizing any replacement
/// spend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LateConsolidationSettlementStatement {
    version: u16,
    abandonment_statement: [u8; 32],
    historical_completion: ConsolidationCompletionStatement,
    inclusion: ChainPoint,
    observation_tip: ChainPoint,
    finality_depth: u32,
}

impl LateConsolidationSettlementStatement {
    #[must_use]
    pub const fn id(&self) -> ConsolidationId {
        self.historical_completion.id()
    }

    #[must_use]
    pub const fn abandonment_statement(&self) -> [u8; 32] {
        self.abandonment_statement
    }

    #[must_use]
    pub const fn historical_completion(&self) -> &ConsolidationCompletionStatement {
        &self.historical_completion
    }

    #[must_use]
    pub const fn inclusion(&self) -> ChainPoint {
        self.inclusion
    }

    #[must_use]
    pub const fn observation_tip(&self) -> ChainPoint {
        self.observation_tip
    }

    #[must_use]
    pub const fn finality_depth(&self) -> u32 {
        self.finality_depth
    }
}

/// One globally ordered ledger operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LedgerPayload {
    Allocation(AllocationStatement),
    HandoffFence(HandoffFenceStatement),
    Handoff(HandoffStatement),
    ConsolidationCompletion(ConsolidationCompletionStatement),
    ConsolidationAbandonment(ConsolidationAbandonmentStatement),
    LateConsolidationSettlement(LateConsolidationSettlementStatement),
}

/// Canonical statement signed by an epoch quorum.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LedgerStatement {
    version: u16,
    pub wallet: DepositWalletId,
    pub sequence: u64,
    pub previous: [u8; 32],
    pub issuer_epoch: u64,
    pub issuer_committee: [u8; 32],
    pub issuer_activation: [u8; 32],
    pub payload: LedgerPayload,
}

impl LedgerStatement {
    /// Construct an allocation statement for the registry's active issuer and next slot.
    pub fn allocation(
        registry: &CompactEpochRegistry,
        sequence: u64,
        previous: [u8; 32],
        request: LedgerRequestId,
        binding: RequestBinding,
        address: CanonicalDepositAddress,
        recognition_anchor: ChainPoint,
        created_at: u64,
    ) -> Result<Self, LedgerError> {
        let expires_at = created_at
            .checked_add(UNUSED_ALLOCATION_TTL_SECONDS)
            .ok_or(LedgerError::InvalidTime)?;
        registry.validate()?;
        let issuer = registry.active();
        let statement = Self {
            version: STATEMENT_VERSION,
            wallet: registry.wallet(),
            sequence,
            previous,
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            payload: LedgerPayload::Allocation(AllocationStatement {
                request,
                binding,
                address,
                recognition_anchor,
                created_at,
                expires_at,
            }),
        };
        validate_statement_static(&statement)?;
        Ok(statement)
    }

    /// Construct the certified finite scanner frontier for a pending handoff.
    pub fn handoff_fence(
        registry: &CompactEpochRegistry,
        sequence: u64,
        previous: [u8; 32],
        target: &VerifiedRegistryHandoffTarget,
        cutoff: ChainPoint,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        ChainPoint::new(cutoff.height, cutoff.hash)
            .map_err(|_| LedgerError::InvalidHandoffFence)?;
        let issuer = registry.active();
        if target.wallet() != registry.wallet()
            || target.committee().epoch
                != issuer.epoch().checked_add(1).ok_or(LedgerError::InvalidHandoffFence)?
            || target.key_id() != issuer.key_id()
            || target.group_key() != issuer.group_key()
        {
            return Err(LedgerError::InvalidHandoffFence);
        }
        let statement = Self {
            version: STATEMENT_VERSION,
            wallet: registry.wallet(),
            sequence,
            previous,
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            payload: LedgerPayload::HandoffFence(HandoffFenceStatement {
                version: HANDOFF_FENCE_VERSION,
                target_epoch: target.committee().epoch,
                target_committee: target.committee().digest(),
                target_activation: target.activation(),
                cutoff,
            }),
        };
        validate_statement_static(&statement)?;
        Ok(statement)
    }

    /// Construct a terminal handoff statement in the active old epoch.
    pub fn handoff(
        registry: &CompactEpochRegistry,
        sequence: u64,
        previous: [u8; 32],
        source_state: DepositHandoffStateBinding,
        target: &VerifiedRegistryHandoffTarget,
        next_index: DepositSubaddressIndex,
    ) -> Result<Self, LedgerError> {
        let transition = RegistryHandoffStatement::new(
            registry,
            sequence,
            previous,
            source_state,
            target,
            next_index,
        )?;
        let issuer = registry.active();
        let statement = Self {
            version: STATEMENT_VERSION,
            wallet: registry.wallet(),
            sequence,
            previous,
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            payload: LedgerPayload::Handoff(HandoffStatement { transition }),
        };
        validate_statement_static(&statement)?;
        Ok(statement)
    }

    /// Construct a completed consolidation statement for the registry's active issuer.
    ///
    /// The constructor validates the exact plan/authorization/attempt/transaction graph before a
    /// party may persist a signer lock for this global ledger slot.
    #[allow(clippy::too_many_arguments)]
    pub fn consolidation_completion(
        registry: &CompactEpochRegistry,
        sequence: u64,
        previous: [u8; 32],
        plan: SweepPlan,
        authorization: TransactionAuthorization,
        attempt: AttemptBinding,
        signed: SignedTransactionBinding,
        signed_transaction: SignedSweepTransaction,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        let issuer = registry.active();
        let statement = Self {
            version: STATEMENT_VERSION,
            wallet: registry.wallet(),
            sequence,
            previous,
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            payload: LedgerPayload::ConsolidationCompletion(ConsolidationCompletionStatement {
                version: CONSOLIDATION_COMPLETION_VERSION,
                plan,
                authorization,
                attempt,
                signed,
                signed_transaction,
            }),
        };
        validate_statement_static(&statement)?;
        validate_consolidation_completion(&statement, issuer)?;
        Ok(statement)
    }

    /// Construct a portable post-nonce input-reorg closure for the active issuer.
    #[allow(clippy::too_many_arguments)]
    pub fn consolidation_abandonment(
        registry: &CompactEpochRegistry,
        sequence: u64,
        previous: [u8; 32],
        family: [u8; 32],
        attempt_prefix: RoastAttemptPrefixSeal,
        slot: ConsolidationConsensusSlot,
        binding: ConsolidationAttemptWireBinding,
        key_images: PortableKeyImageBindingCertificate,
        authorization: TransactionAuthorization,
        attempt: AttemptBinding,
        sweep_sequence: u64,
        inputs: Vec<WalletOutputId>,
        missing_inputs: Vec<WalletOutputId>,
        ancestor: ChainPoint,
        observation_tip: ChainPoint,
        finality_depth: u32,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        let issuer = registry.active();
        let statement = Self {
            version: STATEMENT_VERSION,
            wallet: registry.wallet(),
            sequence,
            previous,
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            payload: LedgerPayload::ConsolidationAbandonment(ConsolidationAbandonmentStatement {
                version: CONSOLIDATION_ABANDONMENT_VERSION,
                family,
                attempt_prefix,
                slot,
                binding,
                key_images,
                authorization,
                attempt,
                sweep_sequence,
                inputs,
                missing_inputs,
                ancestor,
                observation_tip,
                finality_depth,
            }),
        };
        validate_statement_static(&statement)?;
        validate_consolidation_abandonment(&statement, issuer)?;
        Ok(statement)
    }

    /// Construct a current-issuer settlement for a transaction from a historically abandoned
    /// family. Replay validation later binds `abandonment_statement` to the exact certified
    /// abandonment already present in the ledger prefix.
    #[allow(clippy::too_many_arguments)]
    pub fn late_consolidation_settlement(
        registry: &CompactEpochRegistry,
        historical_issuer: &VerifiedIssuerWindow,
        sequence: u64,
        previous: [u8; 32],
        abandonment_statement: [u8; 32],
        historical_completion: ConsolidationCompletionStatement,
        inclusion: ChainPoint,
        observation_tip: ChainPoint,
        finality_depth: u32,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        let issuer = registry.active();
        let statement = Self {
            version: STATEMENT_VERSION,
            wallet: registry.wallet(),
            sequence,
            previous,
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            payload: LedgerPayload::LateConsolidationSettlement(
                LateConsolidationSettlementStatement {
                    version: LATE_CONSOLIDATION_SETTLEMENT_VERSION,
                    abandonment_statement,
                    historical_completion,
                    inclusion,
                    observation_tip,
                    finality_depth,
                },
            ),
        };
        validate_statement_static(&statement)?;
        validate_late_consolidation_settlement(&statement, Some(historical_issuer))?;
        Ok(statement)
    }

    /// Hash only the canonical statement, never its variable witness set.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        // The registry transition is the terminal ledger statement, rather than a second nested
        // statement with another hash. Its digest commits the exact source roots and is therefore
        // also the ledger head inherited by the successor.
        if let LedgerPayload::Handoff(handoff) = &self.payload {
            return handoff.transition.digest();
        }
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/deposit-ledger-statement/v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.wallet.0);
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&self.previous);
        hasher.update(&self.issuer_epoch.to_le_bytes());
        hasher.update(&self.issuer_committee);
        hasher.update(&self.issuer_activation);
        match &self.payload {
            LedgerPayload::Allocation(allocation) => {
                hasher.update(&[0]);
                hasher.update(&allocation.request.0);
                hasher.update(&allocation.binding.0);
                hasher.update(&allocation.address.wallet_id().0);
                hasher.update(&network_tag(allocation.address.network()).to_le_bytes());
                hasher.update(&allocation.address.index().account().to_le_bytes());
                hasher.update(&allocation.address.index().address().to_le_bytes());
                let address = allocation.address.as_str().as_bytes();
                hasher.update(&(address.len() as u64).to_le_bytes());
                hasher.update(address);
                hasher.update(&allocation.recognition_anchor.height.to_le_bytes());
                hasher.update(&allocation.recognition_anchor.hash);
                hasher.update(&allocation.created_at.to_le_bytes());
                hasher.update(&allocation.expires_at.to_le_bytes());
            }
            LedgerPayload::HandoffFence(fence) => {
                hasher.update(&[1]);
                hasher.update(&fence.version.to_le_bytes());
                hasher.update(&fence.target_epoch.to_le_bytes());
                hasher.update(&fence.target_committee);
                hasher.update(&fence.target_activation);
                hasher.update(&fence.cutoff.height.to_le_bytes());
                hasher.update(&fence.cutoff.hash);
            }
            LedgerPayload::Handoff(_) => unreachable!("handoff digest returned above"),
            LedgerPayload::ConsolidationCompletion(completion) => {
                hasher.update(&[2]);
                hash_consolidation_completion(&mut hasher, completion);
            }
            LedgerPayload::ConsolidationAbandonment(abandonment) => {
                hasher.update(&[3]);
                hash_consolidation_abandonment(&mut hasher, abandonment);
            }
            LedgerPayload::LateConsolidationSettlement(settlement) => {
                hasher.update(&[4]);
                hash_late_consolidation_settlement(&mut hasher, settlement);
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// All competing statements at one slot share this session ID.
    #[must_use]
    pub fn slot_session(&self) -> SessionId {
        if let LedgerPayload::Handoff(handoff) = &self.payload {
            return handoff.transition.session();
        }
        let mut material = Vec::with_capacity(40);
        material.extend_from_slice(&self.wallet.0);
        material.extend_from_slice(&self.sequence.to_le_bytes());
        SessionId::derive(b"deposit-ledger-slot/v1", &material)
    }

    /// Exact payload signed by one ledger witness.
    ///
    /// Handoff witnesses use the compact registry payload directly, allowing the same exact
    /// envelope vector to become a [`RegistryHandoffCertificate`]. Other statements retain the
    /// bounded ledger-attestation body.
    pub fn attestation_payload(&self) -> Result<Vec<u8>, LedgerError> {
        match &self.payload {
            LedgerPayload::Handoff(handoff) => Ok(handoff.transition.signing_payload()),
            _ => LedgerAttestation::for_statement(self).encode(),
        }
    }
}

/// Exact slot/digest body carried by each signed broadcast envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LedgerAttestation {
    version: u16,
    wallet: DepositWalletId,
    sequence: u64,
    statement: [u8; 32],
}

impl LedgerAttestation {
    /// Construct the canonical body for a statement.
    #[must_use]
    pub fn for_statement(statement: &LedgerStatement) -> Self {
        Self {
            version: ATTESTATION_VERSION,
            wallet: statement.wallet,
            sequence: statement.sequence,
            statement: statement.digest(),
        }
    }

    /// Encode the bounded canonical wire body.
    pub fn encode(self) -> Result<Vec<u8>, LedgerError> {
        let bytes = postcard::to_allocvec(&self).map_err(|_| LedgerError::Serialization)?;
        if bytes.len() > MAX_ATTESTATION_BYTES {
            return Err(LedgerError::AttestationTooLarge);
        }
        Ok(bytes)
    }
}

/// An n-f certificate for one canonical statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertifiedLedgerEntry {
    pub statement: LedgerStatement,
    /// Strictly ordered by sender. Extra valid witnesses do not change the ledger head.
    pub attestations: Vec<SignedEnvelope>,
}

impl CertifiedLedgerEntry {
    /// Verify against one directly authenticated historical or active issuer window.
    ///
    /// A late settlement additionally supplies the independently loaded historical issuer whose
    /// public transaction graph is being recognized.
    pub fn verify(
        &self,
        issuer_window: &VerifiedIssuerWindow,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<VerifiedEntry, LedgerError> {
        issuer_window.validate()?;
        validate_statement_static(&self.statement)?;
        let issuer = issuer_window.issuer();
        validate_statement_issuer(&self.statement, issuer)?;
        issuer_window.authorize_statement(
            self.statement.wallet,
            self.statement.issuer_epoch,
            self.statement.issuer_committee,
            self.statement.issuer_activation,
            self.statement.sequence,
            self.statement.digest(),
        )?;
        if matches!(&self.statement.payload, LedgerPayload::Handoff(_))
            && !issuer_window.terminal().is_some_and(|terminal| {
                terminal.sequence == self.statement.sequence
                    && terminal.statement_digest == self.statement.digest()
            })
        {
            return Err(LedgerError::InvalidHandoff);
        }
        validate_handoff_for_issuer(&self.statement, issuer)?;
        validate_consolidation_completion(&self.statement, issuer)?;
        validate_consolidation_abandonment(&self.statement, issuer)?;
        validate_late_consolidation_settlement(&self.statement, historical_issuer)?;
        verify_witnesses(self, issuer)
    }

    /// Verify a prospective/current certificate against the compact active head.
    pub fn verify_active(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
    ) -> Result<VerifiedEntry, LedgerError> {
        validate_statement_for_active(registry, &self.statement, historical_issuer)?;
        verify_witnesses(self, registry.active())
    }

    /// Convert an already verified terminal ledger certificate into the exact compact-registry
    /// witness object. Handoff ledger witnesses intentionally sign the compact transition payload.
    pub fn registry_handoff_certificate(
        &self,
        source: &CompactEpochRegistry,
    ) -> Result<RegistryHandoffCertificate, LedgerError> {
        self.verify_active(source, None)?;
        let LedgerPayload::Handoff(handoff) = &self.statement.payload else {
            return Err(LedgerError::InvalidHandoff);
        };
        let certificate =
            RegistryHandoffCertificate::new(handoff.transition.clone(), self.attestations.clone())?;
        certificate.verify(source)?;
        Ok(certificate)
    }

    /// Canonically serialize one bounded certificate.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let bytes = postcard::to_allocvec(self).map_err(|_| LedgerError::Serialization)?;
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(LedgerError::CertificateTooLarge);
        }
        Ok(bytes)
    }

    /// Domain-separated commitment to the exact canonical certificate bytes, including witnesses.
    pub fn certificate_digest(&self) -> Result<[u8; 32], LedgerError> {
        exact_certificate_digest("threshold-monero/certified-ledger-entry/v1", &self.to_bytes()?)
    }

    /// Decode one exact canonical certificate without accepting trailing or alternate encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(LedgerError::CertificateTooLarge);
        }
        let (value, trailing) =
            postcard::take_from_bytes::<Self>(bytes).map_err(|_| LedgerError::Deserialization)?;
        if !trailing.is_empty() {
            return Err(LedgerError::TrailingBytes(trailing.len()));
        }
        if value.to_bytes()?.as_slice() != bytes {
            return Err(LedgerError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Authenticate an allocation and its exact n-f portable-index checkpoint.
    ///
    /// The returned value intentionally does not expose the address. Honest checkpoint signers
    /// require an immutable signing reservation from before `created_at`; a retry may complete the
    /// checkpoint later but remains tied to that pre-visibility reservation. The verified n-f
    /// checkpoint is therefore the portable timely-admission proof. The service releases it
    /// through [`VerifiedAllocationIssuanceSchedule::release_at`].
    pub fn verify_allocation_issuance_schedule(
        &self,
        issuer_window: &VerifiedIssuerWindow,
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<VerifiedAllocationIssuanceSchedule, LedgerError> {
        self.verify(issuer_window, None)?;
        VerifiedAllocationIssuanceSchedule::from_verified_entry(self, checkpoint)
    }

    /// Active-issuer form of [`Self::verify_allocation_issuance_schedule`].
    pub fn verify_active_allocation_issuance_schedule(
        &self,
        registry: &CompactEpochRegistry,
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<VerifiedAllocationIssuanceSchedule, LedgerError> {
        self.verify_active(registry, None)?;
        VerifiedAllocationIssuanceSchedule::from_verified_entry(self, checkpoint)
    }
}

/// API-unforgeable schedule whose checkpoint witnesses required pre-visibility reservations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAllocationIssuanceSchedule {
    wallet: DepositWalletId,
    sequence: u64,
    statement: [u8; 32],
    address: CanonicalDepositAddress,
    visible_at: u64,
    expires_at: u64,
}

impl VerifiedAllocationIssuanceSchedule {
    fn from_verified_entry(
        entry: &CertifiedLedgerEntry,
        checkpoint: &VerifiedDepositIndexCheckpoint,
    ) -> Result<Self, LedgerError> {
        let LedgerPayload::Allocation(allocation) = &entry.statement.payload else {
            return Err(LedgerError::InvalidAllocation);
        };
        if checkpoint.operation()
            != (DepositIndexCheckpointOperation::Ledger { statement: entry.statement.digest() })
            || checkpoint.ledger_sequence() != entry.statement.sequence
            || checkpoint.ledger_decision() != entry.statement.digest()
            || checkpoint.resulting_head().wallet_id() != entry.statement.wallet
            || checkpoint.resulting_head().through_sequence() != entry.statement.sequence
            || checkpoint.resulting_head().ledger_head() != entry.statement.digest()
        {
            return Err(LedgerError::AllocationCheckpointMismatch);
        }
        Ok(Self {
            wallet: entry.statement.wallet,
            sequence: entry.statement.sequence,
            statement: entry.statement.digest(),
            address: allocation.address.clone(),
            visible_at: allocation.created_at,
            expires_at: allocation.expires_at,
        })
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement
    }

    #[must_use]
    pub const fn visible_at(&self) -> u64 {
        self.visible_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Release or retrieve the address at/after certified issuance while it remains unexpired.
    ///
    /// Calling early returns `AllocationIssuanceNotReady`. The address remains retrievable after
    /// issuance; its network lifetime is the full thirty days measured from `visible_at`, not
    /// from a later retrieval.
    pub fn release_at(self, now: u64) -> Result<ClientVisibleAllocation, LedgerError> {
        if now < self.visible_at {
            return Err(LedgerError::AllocationIssuanceNotReady);
        }
        if now >= self.expires_at {
            return Err(LedgerError::AllocationIssuanceMissed);
        }
        Ok(ClientVisibleAllocation {
            wallet: self.wallet,
            sequence: self.sequence,
            statement: self.statement,
            address: self.address,
            issued_at: self.visible_at,
            expires_at: self.expires_at,
        })
    }
}

/// Certified allocation which may be returned to a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientVisibleAllocation {
    wallet: DepositWalletId,
    sequence: u64,
    statement: [u8; 32],
    address: CanonicalDepositAddress,
    issued_at: u64,
    expires_at: u64,
}

impl ClientVisibleAllocation {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement
    }

    #[must_use]
    pub const fn address(&self) -> &CanonicalDepositAddress {
        &self.address
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Verify one witness without requiring the entry to have reached quorum yet.
pub fn verify_attestation(
    statement: &LedgerStatement,
    registry: &CompactEpochRegistry,
    envelope: &SignedEnvelope,
) -> Result<PartyId, LedgerError> {
    validate_statement_for_active(registry, statement, None)?;
    let activation = registry.active();
    let expected = statement.attestation_payload()?;
    if envelope.to.is_some() || envelope.payload.len() > MAX_ATTESTATION_BYTES {
        return Err(LedgerError::InvalidAttestation);
    }
    let verifier = activation
        .committee()
        .members
        .first()
        .map(|member| member.id)
        .ok_or(LedgerError::InvalidRegistry)?;
    Identity::verify_envelope(activation.committee(), verifier, envelope)?;
    if envelope.session != statement.slot_session()
        || envelope.sequence != statement.sequence
        || envelope.payload != expected
    {
        return Err(LedgerError::InvalidAttestation);
    }
    Ok(envelope.from)
}

/// Result of certificate verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEntry {
    wallet: DepositWalletId,
    sequence: u64,
    statement_digest: [u8; 32],
    certificate_digest: [u8; 32],
    signers: BTreeSet<PartyId>,
    required: u16,
}

impl VerifiedEntry {
    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    #[must_use]
    pub const fn certificate_digest(&self) -> [u8; 32] {
        self.certificate_digest
    }

    #[must_use]
    pub const fn signers(&self) -> &BTreeSet<PartyId> {
        &self.signers
    }

    #[must_use]
    pub const fn required(&self) -> u16 {
        self.required
    }

    /// Prove this verification capability was issued for these exact canonical certificate bytes.
    pub fn verify_exact_certificate(
        &self,
        certificate: &CertifiedLedgerEntry,
    ) -> Result<(), LedgerError> {
        let signers =
            certificate.attestations.iter().map(|envelope| envelope.from).collect::<BTreeSet<_>>();
        if certificate.statement.wallet != self.wallet
            || certificate.statement.sequence != self.sequence
            || certificate.statement.digest() != self.statement_digest
            || certificate.certificate_digest()? != self.certificate_digest
            || signers != self.signers
        {
            return Err(LedgerError::VerificationCapabilityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalAdmissionKind {
    Completion,
    Abandonment,
    LateSettlement,
}

fn terminal_admission_kind(statement: &LedgerStatement) -> Option<TerminalAdmissionKind> {
    match &statement.payload {
        LedgerPayload::ConsolidationCompletion(_) => Some(TerminalAdmissionKind::Completion),
        LedgerPayload::ConsolidationAbandonment(_) => Some(TerminalAdmissionKind::Abandonment),
        LedgerPayload::LateConsolidationSettlement(_) => {
            Some(TerminalAdmissionKind::LateSettlement)
        }
        LedgerPayload::Allocation(_)
        | LedgerPayload::HandoffFence(_)
        | LedgerPayload::Handoff(_) => None,
    }
}

/// Non-serializable authority to reserve and sign one exact terminal ledger statement.
///
/// The service creates this only after re-verifying the matching completion, abandonment, or
/// late-settlement consensus evidence. It deliberately cannot survive a restart: retained
/// evidence must be verified again before another signing attempt.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedTerminalLedgerAdmission {
    wallet: DepositWalletId,
    registry: RegistryId,
    issuer_epoch: u64,
    issuer_committee: [u8; 32],
    issuer_activation: [u8; 32],
    sequence: u64,
    statement: [u8; 32],
    kind: TerminalAdmissionKind,
    evidence: [u8; 32],
}

impl VerifiedTerminalLedgerAdmission {
    /// Seal a terminal decision only after the service has verified the exact consensus evidence.
    ///
    /// This constructor is crate-private because a network/API caller must never be able to turn
    /// raw statement bytes into terminal signing authority.
    pub(crate) fn from_verified_consensus(
        registry: &CompactEpochRegistry,
        statement: &LedgerStatement,
        evidence_digest: [u8; 32],
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        validate_statement_static(statement)?;
        validate_statement_issuer(statement, registry.active())?;
        let kind =
            terminal_admission_kind(statement).ok_or(LedgerError::InvalidTerminalAdmission)?;
        if evidence_digest == [0; 32] || statement.sequence < registry.active().start_sequence() {
            return Err(LedgerError::InvalidTerminalAdmission);
        }
        Ok(Self {
            wallet: statement.wallet,
            registry: registry.id(),
            issuer_epoch: statement.issuer_epoch,
            issuer_committee: statement.issuer_committee,
            issuer_activation: statement.issuer_activation,
            sequence: statement.sequence,
            statement: statement.digest(),
            kind,
            evidence: evidence_digest,
        })
    }

    fn authorizes(
        &self,
        registry: &CompactEpochRegistry,
        statement: &LedgerStatement,
    ) -> Result<(), LedgerError> {
        registry.validate()?;
        validate_statement_static(statement)?;
        let kind =
            terminal_admission_kind(statement).ok_or(LedgerError::InvalidTerminalAdmission)?;
        let active = registry.active();
        if self.wallet != statement.wallet
            || self.registry != registry.id()
            || self.issuer_epoch != statement.issuer_epoch
            || self.issuer_epoch != active.epoch()
            || self.issuer_committee != statement.issuer_committee
            || self.issuer_committee != active.committee().digest()
            || self.issuer_activation != statement.issuer_activation
            || self.issuer_activation != active.activation()
            || self.sequence != statement.sequence
            || self.statement != statement.digest()
            || self.kind != kind
            || self.evidence == [0; 32]
        {
            return Err(LedgerError::InvalidTerminalAdmission);
        }
        Ok(())
    }
}

/// Bounded live cursor for one authenticated compact-registry issuer.
///
/// Historical allocation, request, address, consolidation, output-claim, and signing-session
/// state lives in the authenticated deposit index. This cursor retains only the moving ledger
/// anchor required to reject gaps, forks, index reuse, and post-handoff issuance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactLedgerCursor {
    wallet: DepositWalletId,
    registry: RegistryId,
    head: [u8; 32],
    next_sequence: u64,
    next_index: DepositSubaddressIndex,
    portable_index: [u8; 32],
    sealed: bool,
}

impl CompactLedgerCursor {
    /// Start a fresh current-format deployment at its compact genesis activation.
    pub fn genesis(
        registry: &CompactEpochRegistry,
        portable_head: &PortableDepositIndexHead,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        let active = registry.active();
        if active.epoch() != 0
            || active.start_sequence() != 1
            || active.predecessor_ledger_head()
                != compact_registry_genesis_ledger_head(registry.wallet())
            || portable_head.wallet_id() != registry.wallet()
            || portable_head.through_sequence() != 0
            || portable_head.ledger_head() != active.predecessor_ledger_head()
            || portable_head.next_index() != active.first_index()
            || portable_head.digest() != active.portable_index_checkpoint()
        {
            return Err(LedgerError::InvalidAuthenticatedCursor);
        }
        Ok(Self {
            wallet: registry.wallet(),
            registry: registry.id(),
            head: active.predecessor_ledger_head(),
            next_sequence: active.start_sequence(),
            next_index: active.first_index(),
            portable_index: portable_head.digest(),
            sealed: false,
        })
    }

    /// Restore a bounded cursor from an independently authenticated portable logical head.
    ///
    /// At an activation boundary the compact registry itself supplies the exact predecessor and
    /// first index. Within an epoch, the supplied last statement must name the exact indexed
    /// statement at the anchor so a pending terminal handoff cannot be reopened after restart.
    pub fn from_authenticated_portable_head(
        registry: &CompactEpochRegistry,
        portable_head: &PortableDepositIndexHead,
        last_statement: Option<&LedgerStatement>,
    ) -> Result<Self, LedgerError> {
        registry.validate()?;
        if portable_head.wallet_id() != registry.wallet() {
            return Err(LedgerError::RegistryMismatch);
        }
        let next_sequence = portable_head
            .through_sequence()
            .checked_add(1)
            .ok_or(LedgerError::SequenceExhausted)?;
        let active = registry.active();
        let sealed = if next_sequence == active.start_sequence() {
            if portable_head.ledger_head() != active.predecessor_ledger_head()
                || portable_head.next_index() != active.first_index()
            {
                return Err(LedgerError::InvalidAuthenticatedCursor);
            }
            false
        } else {
            if next_sequence < active.start_sequence() {
                return Err(LedgerError::InvalidAuthenticatedCursor);
            }
            let last = last_statement.ok_or(LedgerError::InvalidAuthenticatedCursor)?;
            validate_statement_static(last)?;
            validate_statement_issuer(last, active)?;
            if last.sequence != portable_head.through_sequence()
                || last.digest() != portable_head.ledger_head()
            {
                return Err(LedgerError::InvalidAuthenticatedCursor);
            }
            if let LedgerPayload::Handoff(handoff) = &last.payload {
                handoff.transition().validate_against(registry)?;
                true
            } else {
                false
            }
        };
        Ok(Self {
            wallet: registry.wallet(),
            registry: registry.id(),
            head: portable_head.ledger_head(),
            next_sequence,
            next_index: portable_head.next_index(),
            portable_index: portable_head.digest(),
            sealed,
        })
    }

    /// Validate a prospective next statement before its signer lock is persisted.
    ///
    /// Lifetime conflicts are authorized separately by the typed deposit-index transition used
    /// for advancement; this method establishes only the compact cursor and issuer constraints.
    pub fn validate_next_statement<F>(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        statement: &LedgerStatement,
        now: u64,
        recognition: Option<&VerifiedRecognitionAnchor>,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        verify_address: F,
    ) -> Result<(), LedgerError>
    where
        F: FnMut(&CanonicalDepositAddress) -> bool,
    {
        if terminal_admission_kind(statement).is_some() {
            return Err(LedgerError::TerminalAdmissionRequired);
        }
        self.validate_statement_inner(
            registry,
            historical_issuer,
            statement,
            verified_index_preflight,
            verify_address,
        )?;
        if now > MAX_UNIX_TIMESTAMP {
            return Err(LedgerError::InvalidTime);
        }
        if let LedgerPayload::Allocation(allocation) = &statement.payload {
            if !recognition.is_some_and(|verified| {
                verified.authorizes(statement.wallet, allocation.recognition_anchor)
            }) {
                return Err(LedgerError::AllocationRecognitionRequired);
            }
            if allocation.created_at > now.saturating_add(MAX_ALLOCATION_CLOCK_SKEW_SECONDS) {
                return Err(LedgerError::ClockSkew);
            }
            if now
                .checked_add(MIN_ALLOCATION_CERTIFICATION_LEAD_SECONDS)
                .is_none_or(|minimum| allocation.created_at < minimum)
            {
                return Err(LedgerError::AllocationCertificationMissedIssuance);
            }
        }
        Ok(())
    }

    /// Validate a completion, abandonment, or late settlement using service-verified consensus
    /// evidence sealed into an exact non-serializable admission token.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_next_terminal_statement<F>(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        statement: &LedgerStatement,
        now: u64,
        admission: &VerifiedTerminalLedgerAdmission,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        verify_address: F,
    ) -> Result<(), LedgerError>
    where
        F: FnMut(&CanonicalDepositAddress) -> bool,
    {
        admission.authorizes(registry, statement)?;
        self.validate_statement_inner(
            registry,
            historical_issuer,
            statement,
            verified_index_preflight,
            verify_address,
        )?;
        if now > MAX_UNIX_TIMESTAMP {
            return Err(LedgerError::InvalidTime);
        }
        Ok(())
    }

    /// Revalidate a durable signer lock without reapplying wall-clock admission rules.
    pub fn validate_reserved_statement<F>(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        statement: &LedgerStatement,
        recognition: Option<&VerifiedRecognitionAnchor>,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        verify_address: F,
    ) -> Result<(), LedgerError>
    where
        F: FnMut(&CanonicalDepositAddress) -> bool,
    {
        if terminal_admission_kind(statement).is_some() {
            return Err(LedgerError::TerminalAdmissionRequired);
        }
        if let LedgerPayload::Allocation(allocation) = &statement.payload
            && !recognition.is_some_and(|verified| {
                verified.authorizes(statement.wallet, allocation.recognition_anchor)
            })
        {
            return Err(LedgerError::AllocationRecognitionRequired);
        }
        self.validate_statement_inner(
            registry,
            historical_issuer,
            statement,
            verified_index_preflight,
            verify_address,
        )
    }

    /// Revalidate a retained terminal signer lock after independently reconstructing its service
    /// evidence token. No wall-clock rule is replayed.
    pub fn validate_reserved_terminal_statement<F>(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        statement: &LedgerStatement,
        admission: &VerifiedTerminalLedgerAdmission,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        verify_address: F,
    ) -> Result<(), LedgerError>
    where
        F: FnMut(&CanonicalDepositAddress) -> bool,
    {
        admission.authorizes(registry, statement)?;
        self.validate_statement_inner(
            registry,
            historical_issuer,
            statement,
            verified_index_preflight,
            verify_address,
        )
    }

    fn validate_statement_inner<F>(
        &self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        statement: &LedgerStatement,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        mut verify_address: F,
    ) -> Result<(), LedgerError>
    where
        F: FnMut(&CanonicalDepositAddress) -> bool,
    {
        registry.validate()?;
        if self.wallet != registry.wallet() || self.registry != registry.id() {
            return Err(LedgerError::RegistryMismatch);
        }
        if self.sealed {
            return Err(LedgerError::SealedEpoch);
        }
        validate_statement_for_active(registry, statement, historical_issuer)?;
        if statement.sequence != self.next_sequence {
            return if statement.sequence > self.next_sequence {
                Err(LedgerError::Gap { expected: self.next_sequence, actual: statement.sequence })
            } else {
                Err(LedgerError::RevisionMismatch)
            };
        }
        // A certified entry advances the cursor to `sequence + 1`.  Reject the terminal value at
        // pre-signing and durable-lock revalidation time instead of accepting a decision which can
        // never be represented by either the live cursor or a restored portable head.
        statement.sequence.checked_add(1).ok_or(LedgerError::SequenceExhausted)?;
        if statement.previous != self.head {
            return Err(LedgerError::Fork);
        }
        let expected_portable_head =
            PortableDepositIndexHead::from_head(verified_index_preflight.expected_head())
                .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        let candidate_portable_head =
            PortableDepositIndexHead::from_head(verified_index_preflight.candidate_head())
                .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        let expected_next_index = match &statement.payload {
            LedgerPayload::Allocation(allocation) => increment_index(allocation.address.index())?,
            LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => self.next_index,
        };
        if verified_index_preflight.statement_sequence() != statement.sequence
            || verified_index_preflight.statement_digest() != statement.digest()
            || expected_portable_head.wallet_id() != self.wallet
            || expected_portable_head.digest() != self.portable_index
            || expected_portable_head.through_sequence().checked_add(1) != Some(statement.sequence)
            || expected_portable_head.ledger_head() != statement.previous
            || expected_portable_head.next_index() != self.next_index
            || candidate_portable_head.wallet_id() != self.wallet
            || candidate_portable_head.through_sequence() != statement.sequence
            || candidate_portable_head.ledger_head() != statement.digest()
            || candidate_portable_head.next_index() != expected_next_index
        {
            return Err(LedgerError::PortableCheckpointMismatch);
        }
        match &statement.payload {
            LedgerPayload::Allocation(allocation) => {
                if allocation.address.index() != self.next_index {
                    return Err(LedgerError::IndexMismatch {
                        expected: self.next_index,
                        actual: allocation.address.index(),
                    });
                }
                if allocation.address.wallet_id() != self.wallet
                    || !verify_address(&allocation.address)
                {
                    return Err(LedgerError::WrongDerivedAddress);
                }
            }
            LedgerPayload::Handoff(handoff) => {
                if handoff.next_index() != self.next_index {
                    return Err(LedgerError::IndexMismatch {
                        expected: self.next_index,
                        actual: handoff.next_index(),
                    });
                }
                if handoff.source_portable_index() != self.portable_index {
                    return Err(LedgerError::PortableCheckpointMismatch);
                }
            }
            LedgerPayload::HandoffFence(_) => {}
            LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => {}
        }
        Ok(())
    }

    /// Advance to an exact certified decision and its authenticated resulting portable head.
    ///
    /// The caller must stage and verify the corresponding deposit-index semantic update first.
    /// This method checks the resulting anchor exactly and retains only its logical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_certificate<F>(
        &mut self,
        registry: &CompactEpochRegistry,
        historical_issuer: Option<&VerifiedIssuerWindow>,
        entry: CertifiedLedgerEntry,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        verified_index_transition: &VerifiedDepositIndexTransition,
        verify_address: F,
    ) -> Result<(), LedgerError>
    where
        F: FnMut(&CanonicalDepositAddress) -> bool,
    {
        self.validate_statement_inner(
            registry,
            historical_issuer,
            &entry.statement,
            verified_index_preflight,
            verify_address,
        )?;
        entry.verify_active(registry, historical_issuer)?;
        if !verified_index_transition.matches_preflight(verified_index_preflight) {
            return Err(LedgerError::PortableCheckpointMismatch);
        }
        let expected_portable_head =
            PortableDepositIndexHead::from_head(verified_index_transition.expected_head())
                .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        let resulting_portable_head =
            PortableDepositIndexHead::from_head(verified_index_transition.resulting_head())
                .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        let resulting_next_index = match &entry.statement.payload {
            LedgerPayload::Allocation(allocation) => increment_index(allocation.address.index())?,
            LedgerPayload::HandoffFence(_)
            | LedgerPayload::Handoff(_)
            | LedgerPayload::ConsolidationCompletion(_)
            | LedgerPayload::ConsolidationAbandonment(_)
            | LedgerPayload::LateConsolidationSettlement(_) => self.next_index,
        };
        if verified_index_transition.statement_sequence() != entry.statement.sequence
            || verified_index_transition.statement_digest() != entry.statement.digest()
            || expected_portable_head.wallet_id() != self.wallet
            || expected_portable_head.digest() != self.portable_index
            || expected_portable_head.through_sequence().checked_add(1)
                != Some(entry.statement.sequence)
            || expected_portable_head.ledger_head() != entry.statement.previous
            || expected_portable_head.next_index() != self.next_index
            || resulting_portable_head.wallet_id() != self.wallet
            || resulting_portable_head.through_sequence() != entry.statement.sequence
            || resulting_portable_head.ledger_head() != entry.statement.digest()
            || resulting_portable_head.next_index() != resulting_next_index
        {
            return Err(LedgerError::PortableCheckpointMismatch);
        }
        let next_sequence =
            self.next_sequence.checked_add(1).ok_or(LedgerError::SequenceExhausted)?;
        let candidate = Self {
            wallet: self.wallet,
            registry: self.registry,
            head: entry.statement.digest(),
            next_sequence,
            next_index: resulting_next_index,
            portable_index: resulting_portable_head.digest(),
            sealed: matches!(&entry.statement.payload, LedgerPayload::Handoff(_)),
        };
        *self = candidate;
        Ok(())
    }

    /// Adopt an exact verified observation-only portable transition.
    ///
    /// Observation certification is independent of the ordered allocation ledger. Therefore this
    /// changes only the portable-index digest and requires the wallet, ledger sequence/head, and
    /// next allocation index to remain identical across the verified transition.
    pub fn adopt_verified_deposit_observation_transition(
        &mut self,
        transition: &VerifiedDepositObservationIndexTransition,
    ) -> Result<(), LedgerError> {
        let expected = PortableDepositIndexHead::from_head(transition.expected_head())
            .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        let resulting = PortableDepositIndexHead::from_head(transition.resulting_head())
            .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        if expected.wallet_id() != self.wallet
            || expected.digest() != self.portable_index
            || expected.through_sequence().checked_add(1) != Some(self.next_sequence)
            || expected.ledger_head() != self.head
            || expected.next_index() != self.next_index
            || resulting.wallet_id() != self.wallet
            || resulting.through_sequence() != expected.through_sequence()
            || resulting.ledger_head() != expected.ledger_head()
            || resulting.next_index() != expected.next_index()
            || resulting.digest() == expected.digest()
        {
            return Err(LedgerError::PortableCheckpointMismatch);
        }
        self.portable_index = resulting.digest();
        Ok(())
    }

    /// Atomically cross one exact terminal handoff into its authenticated compact successor.
    ///
    /// The source portable head is the pre-terminal logical head signed by the retiring committee;
    /// the resulting portable head is installed in the same snapshot CAS as the new registry.
    pub fn apply_registry_extension(
        &mut self,
        old: &CompactEpochRegistry,
        new: &CompactEpochRegistry,
        handoff_entry: &CertifiedLedgerEntry,
        verified_index_preflight: &VerifiedDepositIndexPreflight,
        verified_index_transition: &VerifiedDepositIndexTransition,
    ) -> Result<(), LedgerError> {
        old.validate()?;
        new.validate()?;
        if self.registry != old.id() || self.wallet != old.wallet() || old.wallet() != new.wallet()
        {
            return Err(LedgerError::RegistryMismatch);
        }
        handoff_entry.registry_handoff_certificate(old)?;
        let LedgerPayload::Handoff(handoff) = &handoff_entry.statement.payload else {
            return Err(LedgerError::InvalidHandoff);
        };
        let transition = handoff.transition();
        let active = new.active();
        if !verified_index_transition.matches_preflight(verified_index_preflight) {
            return Err(LedgerError::PortableCheckpointMismatch);
        }
        let source_portable_head =
            PortableDepositIndexHead::from_head(verified_index_transition.expected_head())
                .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        let resulting_portable_head =
            PortableDepositIndexHead::from_head(verified_index_transition.resulting_head())
                .map_err(|_| LedgerError::PortableCheckpointMismatch)?;
        if verified_index_transition.statement_sequence() != handoff_entry.statement.sequence
            || verified_index_transition.statement_digest() != handoff_entry.statement.digest()
            || source_portable_head.wallet_id() != self.wallet
            || source_portable_head.digest() != transition.source_portable_index()
            || source_portable_head.through_sequence().checked_add(1)
                != Some(transition.terminal_sequence())
            || source_portable_head.ledger_head() != transition.previous_ledger_head()
            || source_portable_head.next_index() != transition.next_index()
            || resulting_portable_head.wallet_id() != self.wallet
            || resulting_portable_head.through_sequence() != transition.terminal_sequence()
            || resulting_portable_head.ledger_head() != handoff_entry.statement.digest()
            || resulting_portable_head.next_index() != transition.next_index()
            || transition.source() != old.id()
            || active.epoch()
                != old.active_epoch().checked_add(1).ok_or(LedgerError::SequenceExhausted)?
            || active.epoch() != transition.target_epoch()
            || active.key_id() != transition.target_key_id()
            || active.group_key() != transition.target_group_key()
            || active.committee().digest() != transition.target_committee()
            || active.fault_bound() != transition.target_fault_bound()
            || active.activation() != transition.target_activation()
            || active.certified_activation_root() != transition.target_certified_activation_root()
            || active.start_sequence()
                != transition
                    .terminal_sequence()
                    .checked_add(1)
                    .ok_or(LedgerError::SequenceExhausted)?
            || active.predecessor_ledger_head() != handoff_entry.statement.digest()
            || active.first_index() != transition.next_index()
            || active.portable_index_checkpoint() != transition.source_portable_index()
        {
            return Err(LedgerError::InvalidHandoff);
        }

        let mut candidate = self.clone();
        if !candidate.sealed {
            if candidate.portable_index != source_portable_head.digest() {
                return Err(LedgerError::PortableCheckpointMismatch);
            }
            candidate.advance_certificate(
                old,
                None,
                handoff_entry.clone(),
                verified_index_preflight,
                verified_index_transition,
                |_| true,
            )?;
        } else if candidate.head != handoff_entry.statement.digest()
            || candidate.next_sequence != active.start_sequence()
            || candidate.next_index != active.first_index()
            || candidate.portable_index != resulting_portable_head.digest()
        {
            return Err(LedgerError::InvalidHandoff);
        }
        candidate.registry = new.id();
        candidate.sealed = false;
        *self = candidate;
        Ok(())
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn registry_id(&self) -> RegistryId {
        self.registry
    }

    #[must_use]
    pub const fn head(&self) -> [u8; 32] {
        self.head
    }

    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    #[must_use]
    pub const fn next_index(&self) -> DepositSubaddressIndex {
        self.next_index
    }

    #[must_use]
    pub const fn portable_index_digest(&self) -> [u8; 32] {
        self.portable_index
    }

    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }
}

fn verify_witnesses(
    entry: &CertifiedLedgerEntry,
    issuer: &ActiveIssuer,
) -> Result<VerifiedEntry, LedgerError> {
    let committee = issuer.committee();
    if entry.attestations.len() > committee.members.len() {
        return Err(LedgerError::CertificateTooLarge);
    }
    let required =
        committee.n().checked_sub(issuer.fault_bound()).ok_or(LedgerError::InvalidFaultBound)?;
    let exact_witness_count = matches!(&entry.statement.payload, LedgerPayload::Handoff(_));
    if entry.attestations.len() < usize::from(required)
        || (exact_witness_count && entry.attestations.len() != usize::from(required))
    {
        return Err(LedgerError::InsufficientCertificate {
            actual: entry.attestations.len(),
            required,
        });
    }
    let expected_payload = entry.statement.attestation_payload()?;
    let mut signers = BTreeSet::new();
    let mut previous = None;
    for envelope in &entry.attestations {
        if envelope.payload.len() > MAX_ATTESTATION_BYTES || envelope.to.is_some() {
            return Err(LedgerError::InvalidAttestation);
        }
        if previous.is_some_and(|sender| sender >= envelope.from) {
            return Err(LedgerError::NonCanonicalCertificate);
        }
        previous = Some(envelope.from);
        let verifier = committee
            .members
            .first()
            .map(|member| member.id)
            .ok_or(LedgerError::InvalidRegistry)?;
        Identity::verify_envelope(committee, verifier, envelope)?;
        if envelope.session != entry.statement.slot_session()
            || envelope.sequence != entry.statement.sequence
            || envelope.payload != expected_payload
            || !signers.insert(envelope.from)
        {
            return Err(LedgerError::InvalidAttestation);
        }
    }
    if let LedgerPayload::ConsolidationCompletion(completion) = &entry.statement.payload {
        let signer_witnesses = signers
            .iter()
            .filter(|party| completion.attempt.signers().binary_search(party).is_ok())
            .count();
        if signer_witnesses < usize::from(committee.threshold) {
            return Err(LedgerError::InsufficientConsolidationSignerWitnesses {
                actual: signer_witnesses,
                required: committee.threshold,
            });
        }
    }
    Ok(VerifiedEntry {
        wallet: entry.statement.wallet,
        sequence: entry.statement.sequence,
        statement_digest: entry.statement.digest(),
        certificate_digest: entry.certificate_digest()?,
        signers,
        required,
    })
}

fn validate_deposit_observation_static(
    statement: &DepositObservationStatement,
) -> Result<(), LedgerError> {
    ChainPoint::new(statement.observed_block.height, statement.observed_block.hash)
        .map_err(|_| LedgerError::InvalidDepositObservation)?;
    ChainPoint::new(statement.confirmation_horizon.height, statement.confirmation_horizon.hash)
        .map_err(|_| LedgerError::InvalidDepositObservation)?;
    let required_distance = u64::from(
        statement
            .confirmation_depth
            .checked_sub(1)
            .ok_or(LedgerError::InvalidDepositObservation)?,
    );
    if statement.version != DEPOSIT_OBSERVATION_VERSION
        || statement.wallet.0 == [0; 32]
        || statement.issuer_committee == [0; 32]
        || statement.issuer_activation == [0; 32]
        || statement.allocation_sequence == 0
        || statement.allocation_statement == [0; 32]
        || statement.output.transaction == [0; 32]
        || statement.output_key == [0; 32]
        || statement.block_timestamp > MAX_UNIX_TIMESTAMP
        || statement.observed_block.height > statement.confirmation_horizon.height
        || statement.observed_block.height.checked_add(required_distance)
            != Some(statement.confirmation_horizon.height)
    {
        return Err(LedgerError::InvalidDepositObservation);
    }
    Ok(())
}

fn validate_deposit_observation_issuer(
    statement: &DepositObservationStatement,
    issuer: &ActiveIssuer,
) -> Result<(), LedgerError> {
    if statement.wallet != issuer.wallet()
        || statement.issuer_epoch != issuer.epoch()
        || statement.issuer_committee != issuer.committee().digest()
        || statement.issuer_activation != issuer.activation()
    {
        return Err(LedgerError::UnknownOrInactiveEpoch);
    }
    Ok(())
}

fn verify_deposit_observation_witnesses(
    certificate: &CertifiedDepositObservation,
    issuer: &ActiveIssuer,
) -> Result<VerifiedDepositObservationCertificate, LedgerError> {
    let committee = issuer.committee();
    if certificate.attestations.len() > committee.members.len() {
        return Err(LedgerError::CertificateTooLarge);
    }
    let required =
        committee.n().checked_sub(issuer.fault_bound()).ok_or(LedgerError::InvalidFaultBound)?;
    if certificate.attestations.len() < usize::from(required) {
        return Err(LedgerError::InsufficientCertificate {
            actual: certificate.attestations.len(),
            required,
        });
    }
    let expected_payload = certificate.statement.attestation_payload()?;
    let verifier =
        committee.members.first().map(|member| member.id).ok_or(LedgerError::InvalidRegistry)?;
    let mut signers = BTreeSet::new();
    let mut previous = None;
    for envelope in &certificate.attestations {
        if envelope.payload.len() > MAX_ATTESTATION_BYTES || envelope.to.is_some() {
            return Err(LedgerError::InvalidAttestation);
        }
        if previous.is_some_and(|sender| sender >= envelope.from) {
            return Err(LedgerError::NonCanonicalCertificate);
        }
        previous = Some(envelope.from);
        Identity::verify_envelope(committee, verifier, envelope)?;
        if envelope.session != certificate.statement.session()
            || envelope.sequence != certificate.statement.allocation_sequence
            || envelope.payload != expected_payload
            || !signers.insert(envelope.from)
        {
            return Err(LedgerError::InvalidAttestation);
        }
    }
    Ok(VerifiedDepositObservationCertificate {
        wallet: certificate.statement.wallet_id(),
        allocation_sequence: certificate.statement.allocation_sequence(),
        output: certificate.statement.output(),
        statement_digest: certificate.statement.digest(),
        certificate_digest: certificate.certificate_digest()?,
        signers,
        required,
    })
}

fn validate_statement_issuer(
    statement: &LedgerStatement,
    issuer: &ActiveIssuer,
) -> Result<(), LedgerError> {
    if statement.wallet != issuer.wallet()
        || statement.issuer_epoch != issuer.epoch()
        || statement.issuer_committee != issuer.committee().digest()
        || statement.issuer_activation != issuer.activation()
    {
        return Err(LedgerError::UnknownOrInactiveEpoch);
    }
    Ok(())
}

fn validate_handoff_for_issuer(
    statement: &LedgerStatement,
    issuer: &ActiveIssuer,
) -> Result<(), LedgerError> {
    let LedgerPayload::Handoff(handoff) = &statement.payload else {
        return Ok(());
    };
    let transition = handoff.transition();
    if transition.source() != issuer.registry_id()
        || transition.wallet() != statement.wallet
        || transition.source_key_id() != issuer.key_id()
        || transition.source_group_key() != issuer.group_key()
        || transition.source_committee() != statement.issuer_committee
        || transition.source_activation() != statement.issuer_activation
        || transition.source_certified_activation_root() != issuer.certified_activation_root()
        || transition.terminal_sequence() != statement.sequence
        || transition.previous_ledger_head() != statement.previous
        || transition.source_portable_index() == [0; 32]
        || transition.target_epoch()
            != statement.issuer_epoch.checked_add(1).ok_or(LedgerError::InvalidHandoff)?
        || transition.target_committee() == [0; 32]
        || transition.target_key_id() != issuer.key_id()
        || transition.target_group_key() != issuer.group_key()
        || transition.target_activation() == [0; 32]
        || transition.target_certified_activation_root() == [0; 32]
    {
        return Err(LedgerError::InvalidHandoff);
    }
    Ok(())
}

fn validate_statement_for_active(
    registry: &CompactEpochRegistry,
    statement: &LedgerStatement,
    historical_issuer: Option<&VerifiedIssuerWindow>,
) -> Result<(), LedgerError> {
    registry.validate()?;
    validate_statement_static(statement)?;
    let issuer = registry.active();
    validate_statement_issuer(statement, issuer)?;
    if statement.sequence < issuer.start_sequence() {
        return Err(LedgerError::UnknownOrInactiveEpoch);
    }
    if let LedgerPayload::Handoff(handoff) = &statement.payload {
        handoff.transition().validate_against(registry)?;
    }
    validate_handoff_for_issuer(statement, issuer)?;
    validate_consolidation_completion(statement, issuer)?;
    validate_consolidation_abandonment(statement, issuer)?;
    validate_late_consolidation_settlement(statement, historical_issuer)
}

fn hash_consolidation_completion(
    hasher: &mut blake3::Hasher,
    completion: &ConsolidationCompletionStatement,
) {
    hasher.update(&completion.version.to_le_bytes());
    hasher.update(&sweep_plan_commitment(&completion.plan));
    hasher.update(&completion.authorization.digest());
    hasher.update(&completion.attempt.digest());
    hasher.update(&completion.signed.authorization);
    hasher.update(&completion.signed.attempt.to_le_bytes());
    hasher.update(&completion.signed.attempt_binding);
    hasher.update(&completion.signed.session.0);
    hasher.update(&completion.signed.signing_context);
    hasher.update(&completion.signed.opaque_intent.0);
    hasher.update(&completion.signed.transaction);
    hasher.update(&completion.signed.exact_bytes);
    hasher.update(&completion.signed.exact_bytes_len.to_le_bytes());
    hasher.update(&completion.signed_transaction.transaction_id());
    let bytes = completion.signed_transaction.as_bytes();
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_consolidation_abandonment(
    hasher: &mut blake3::Hasher,
    abandonment: &ConsolidationAbandonmentStatement,
) {
    hasher.update(&abandonment.version.to_le_bytes());
    hasher.update(&abandonment.family);
    hasher.update(&abandonment.attempt_prefix.family());
    hasher.update(&abandonment.attempt_prefix.family_anchor());
    hasher.update(&abandonment.attempt_prefix.closed_through_view().to_le_bytes());
    hasher.update(&abandonment.attempt_prefix.closed_through_attempt().to_le_bytes());
    hasher.update(&abandonment.attempt_prefix.accumulator());
    hasher.update(&abandonment.slot.digest());
    let binding = postcard::to_allocvec(&abandonment.binding)
        .expect("validated consolidation attempt binding serializes");
    hasher.update(&(binding.len() as u64).to_le_bytes());
    hasher.update(&binding);
    hasher.update(&abandonment.key_images.digest());
    hasher.update(&abandonment.authorization.digest());
    hasher.update(&abandonment.attempt.digest());
    hasher.update(&abandonment.sweep_sequence.to_le_bytes());
    hasher.update(&(abandonment.inputs.len() as u64).to_le_bytes());
    for input in &abandonment.inputs {
        hasher.update(&input.transaction);
        hasher.update(&input.index_in_transaction.to_le_bytes());
    }
    hasher.update(&(abandonment.missing_inputs.len() as u64).to_le_bytes());
    for input in &abandonment.missing_inputs {
        hasher.update(&input.transaction);
        hasher.update(&input.index_in_transaction.to_le_bytes());
    }
    hasher.update(&abandonment.ancestor.height.to_le_bytes());
    hasher.update(&abandonment.ancestor.hash);
    hasher.update(&abandonment.observation_tip.height.to_le_bytes());
    hasher.update(&abandonment.observation_tip.hash);
    hasher.update(&abandonment.finality_depth.to_le_bytes());
}

fn hash_late_consolidation_settlement(
    hasher: &mut blake3::Hasher,
    settlement: &LateConsolidationSettlementStatement,
) {
    hasher.update(&settlement.version.to_le_bytes());
    hasher.update(&settlement.abandonment_statement);
    hash_consolidation_completion(hasher, &settlement.historical_completion);
    hasher.update(&settlement.inclusion.height.to_le_bytes());
    hasher.update(&settlement.inclusion.hash);
    hasher.update(&settlement.observation_tip.height.to_le_bytes());
    hasher.update(&settlement.observation_tip.hash);
    hasher.update(&settlement.finality_depth.to_le_bytes());
}

fn validate_late_consolidation_settlement(
    statement: &LedgerStatement,
    historical_issuer: Option<&VerifiedIssuerWindow>,
) -> Result<(), LedgerError> {
    let LedgerPayload::LateConsolidationSettlement(settlement) = &statement.payload else {
        return Ok(());
    };
    let completion = settlement.historical_completion();
    let historical_epoch = completion.attempt().epoch();
    let historical_window =
        historical_issuer.ok_or(LedgerError::InvalidLateConsolidationSettlement)?;
    historical_window.validate().map_err(|_| LedgerError::InvalidLateConsolidationSettlement)?;
    let historical = historical_window.issuer();
    ChainPoint::new(settlement.inclusion.height, settlement.inclusion.hash)
        .map_err(|_| LedgerError::InvalidLateConsolidationSettlement)?;
    ChainPoint::new(settlement.observation_tip.height, settlement.observation_tip.hash)
        .map_err(|_| LedgerError::InvalidLateConsolidationSettlement)?;
    let finality_height = settlement
        .inclusion
        .height
        .checked_add(u64::from(settlement.finality_depth))
        .ok_or(LedgerError::InvalidLateConsolidationSettlement)?;
    if settlement.version != LATE_CONSOLIDATION_SETTLEMENT_VERSION
        || settlement.abandonment_statement == [0; 32]
        || historical_epoch >= statement.issuer_epoch
        || historical.epoch() != historical_epoch
        || historical.wallet() != statement.wallet
        || historical_window.terminal().is_none()
        || settlement.finality_depth == 0
        || settlement.observation_tip.height != finality_height
        || settlement.observation_tip.height <= settlement.inclusion.height
    {
        return Err(LedgerError::InvalidLateConsolidationSettlement);
    }
    let historical_statement = LedgerStatement {
        version: STATEMENT_VERSION,
        wallet: statement.wallet,
        sequence: historical.start_sequence(),
        previous: historical.predecessor_ledger_head(),
        issuer_epoch: historical_epoch,
        issuer_committee: historical.committee().digest(),
        issuer_activation: historical.activation(),
        payload: LedgerPayload::ConsolidationCompletion(completion.clone()),
    };
    validate_consolidation_completion(&historical_statement, historical)
        .map_err(|_| LedgerError::InvalidLateConsolidationSettlement)
}

fn validate_consolidation_abandonment(
    statement: &LedgerStatement,
    issuer: &ActiveIssuer,
) -> Result<(), LedgerError> {
    let LedgerPayload::ConsolidationAbandonment(abandonment) = &statement.payload else {
        return Ok(());
    };
    abandonment.authorization.validate()?;
    abandonment.attempt.validate()?;
    abandonment
        .slot
        .consensus_context()
        .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?;
    ChainPoint::new(abandonment.ancestor.height, abandonment.ancestor.hash)
        .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?;
    ChainPoint::new(abandonment.observation_tip.height, abandonment.observation_tip.hash)
        .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?;
    let issuer_registry = issuer.registry_id().digest();
    let required_signers = issuer.committee().n() - issuer.fault_bound();
    let expected_family = deterministic_roast_family_digest(
        abandonment.slot.binding(),
        issuer.committee(),
        issuer.fault_bound(),
        &abandonment.authorization,
        abandonment.slot.family_anchor(),
    );
    let finality_height = abandonment
        .ancestor
        .height
        .checked_add(u64::from(abandonment.finality_depth))
        .ok_or(LedgerError::InvalidConsolidationAbandonment)?;
    abandonment
        .binding
        .validate_authorization(&abandonment.authorization)
        .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?;
    abandonment
        .binding
        .validate_active(
            issuer.committee(),
            issuer_registry,
            issuer.activation(),
            abandonment.authorization.root_group_key(),
        )
        .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?;
    let key_images = abandonment
        .key_images
        .verify(
            issuer.committee(),
            issuer.fault_bound(),
            abandonment.slot.binding().network,
            &abandonment.binding,
        )
        .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?;
    if abandonment.version != CONSOLIDATION_ABANDONMENT_VERSION
        || abandonment.family == [0; 32]
        || abandonment.family != expected_family
        || abandonment.attempt_prefix.family() != abandonment.family
        || abandonment.attempt_prefix.family_anchor() != abandonment.slot.family_anchor()
        || abandonment.attempt_prefix.accumulator() == [0; 32]
        || abandonment.attempt_prefix.closed_through_view() != abandonment.slot.roast_view()
        || abandonment.attempt_prefix.closed_through_attempt() != abandonment.attempt.attempt()
        || abandonment.attempt_prefix.closed_through_view().checked_add(1)
            != Some(abandonment.attempt_prefix.closed_through_attempt())
        || abandonment.slot.committee() != issuer.committee()
        || abandonment.slot.fault_bound() != issuer.fault_bound()
        || abandonment.slot.binding().wallet != statement.wallet.0
        || abandonment.slot.binding().network == [0; 32]
        || abandonment.slot.binding().registry != issuer_registry
        || abandonment.slot.binding().activation != statement.issuer_activation
        || abandonment.slot.roast_view().checked_add(1) != Some(abandonment.attempt.attempt())
        || abandonment.binding.attempt() != &abandonment.attempt
        || abandonment.binding.authorization_digest() != abandonment.authorization.digest()
        || abandonment.binding.consolidation_id() != abandonment.authorization.id()
        || abandonment.authorization.wallet_id() != statement.wallet
        || abandonment.authorization.input_set()
            != consolidation_input_set_binding(&abandonment.inputs)
        || abandonment.authorization.input_count()
            != u32::try_from(abandonment.inputs.len())
                .map_err(|_| LedgerError::InvalidConsolidationAbandonment)?
        || abandonment.attempt.epoch() != statement.issuer_epoch
        || abandonment.attempt.registry_digest() != issuer_registry
        || abandonment.attempt.committee_digest() != statement.issuer_committee
        || abandonment.attempt.activation_digest() != statement.issuer_activation
        || abandonment.attempt.root_group_key() != abandonment.authorization.root_group_key()
        || abandonment.attempt.threshold() != issuer.committee().threshold
        || abandonment.attempt.signers().len() < usize::from(required_signers)
        || abandonment.attempt.signers().len() > issuer.committee().members.len()
        || abandonment
            .attempt
            .signers()
            .iter()
            .any(|signer| issuer.committee().member(*signer).is_err())
        || abandonment.inputs.is_empty()
        || abandonment.inputs.len() > MAX_CONSOLIDATION_INPUTS
        || abandonment.inputs.windows(2).any(|window| window[0] >= window[1])
        || abandonment.missing_inputs.is_empty()
        || abandonment.missing_inputs.windows(2).any(|window| window[0] >= window[1])
        || abandonment
            .missing_inputs
            .iter()
            .any(|input| abandonment.inputs.binary_search(input).is_err())
        || abandonment.finality_depth == 0
        || abandonment.observation_tip.height != finality_height
        || abandonment.observation_tip.height <= abandonment.ancestor.height
        || key_images.sweep() != abandonment.authorization.sweep_id()
        || key_images.inputs() != abandonment.inputs.as_slice()
        || key_images.signing_context().into_bytes() != abandonment.attempt.signing_context()
    {
        return Err(LedgerError::InvalidConsolidationAbandonment);
    }
    Ok(())
}

fn validate_consolidation_completion(
    statement: &LedgerStatement,
    issuer: &ActiveIssuer,
) -> Result<(), LedgerError> {
    let LedgerPayload::ConsolidationCompletion(completion) = &statement.payload else {
        return Ok(());
    };
    completion.authorization.validate()?;
    completion.attempt.validate()?;
    completion.signed.validate()?;

    let plan = &completion.plan;
    let authorization = &completion.authorization;
    let attempt = &completion.attempt;
    let signed = &completion.signed;
    let input_count = u32::try_from(plan.inputs.len())
        .map_err(|_| LedgerError::InvalidConsolidationCompletion)?;
    let issuer_registry = issuer.registry_id().digest();
    let required_signers = issuer.committee().n() - issuer.fault_bound();
    let group = CompressedEdwardsY(authorization.root_group_key())
        .decompress()
        .ok_or(LedgerError::InvalidConsolidationCompletion)?;

    if completion.version != CONSOLIDATION_COMPLETION_VERSION
        || plan.wallet != statement.wallet
        || plan.epoch != statement.issuer_epoch
        || plan.destination_binding == [0_u8; 32]
        || plan.inputs.is_empty()
        || plan.inputs.len() > MAX_CONSOLIDATION_INPUTS
        || plan.inputs.windows(2).any(|window| window[0] >= window[1])
        || plan.inputs.iter().any(|input| input.transaction == [0_u8; 32])
        || plan.total_input_atomic_units == 0
        || plan.id.0 != sweep_plan_commitment(plan)
        || crate::deposit_wallet::ChainPoint::new(plan.at_tip.height, plan.at_tip.hash).is_err()
        || authorization.wallet_id() != statement.wallet
        || authorization.sweep_id() != plan.id
        || authorization.input_set() != consolidation_input_set_binding(&plan.inputs)
        || authorization.destination_policy() != plan.destination_binding
        || authorization.input_count() != input_count
        || authorization.total_input_atomic_units() != plan.total_input_atomic_units
        || authorization.root_group_key() != issuer.group_key()
        || attempt.epoch() != statement.issuer_epoch
        || attempt.registry_digest() != issuer_registry
        || attempt.committee_digest() != statement.issuer_committee
        || attempt.activation_digest() != statement.issuer_activation
        || attempt.root_group_key() != authorization.root_group_key()
        || attempt.threshold() != issuer.committee().threshold
        || attempt.signers().len() < usize::from(required_signers)
        || attempt.signers().len() > issuer.committee().members.len()
        || attempt.signers().iter().any(|signer| issuer.committee().member(*signer).is_err())
        || group.is_identity()
        || !group.is_torsion_free()
        || signed.authorization != authorization.digest()
        || signed.attempt != attempt.attempt()
        || signed.attempt_binding != attempt.digest()
        || signed.session != attempt.session()
        || signed.signing_context != attempt.signing_context()
        || signed.opaque_intent != authorization.opaque_intent()
        || signed.transaction != completion.signed_transaction.transaction_id()
        || signed.exact_bytes
            != consolidation_signed_bytes_binding(completion.signed_transaction.as_bytes())
        || usize::try_from(signed.exact_bytes_len).ok()
            != Some(completion.signed_transaction.as_bytes().len())
    {
        return Err(LedgerError::InvalidConsolidationCompletion);
    }

    let canonical = SignedSweepTransaction::from_bytes(
        completion.signed_transaction.as_bytes().to_vec(),
        Some(signed.transaction),
    )?;
    if canonical != completion.signed_transaction {
        return Err(LedgerError::InvalidConsolidationCompletion);
    }
    let transaction = canonical.transaction()?;
    let MoneroTransaction::V2 { prefix, proofs: Some(proofs) } = transaction else {
        return Err(LedgerError::InvalidConsolidationCompletion);
    };
    if proofs.rct_type() != RctType::ClsagBulletproofPlus
        || proofs.base.fee != authorization.fee_atomic_units()
        || proofs.base.fee == 0
        || proofs.base.fee > authorization.maximum_fee_atomic_units()
        || prefix.inputs.len() != plan.inputs.len()
        || prefix.outputs.len() != 2
        || prefix.inputs.iter().any(|input| {
            !matches!(
                input,
                MoneroInput::ToKey { key_offsets, .. } if key_offsets.len() == 16
            )
        })
    {
        return Err(LedgerError::InvalidConsolidationCompletion);
    }
    Ok(())
}

fn sweep_plan_commitment(plan: &SweepPlan) -> [u8; 32] {
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

fn validate_statement_static(statement: &LedgerStatement) -> Result<(), LedgerError> {
    if statement.version != STATEMENT_VERSION
        || statement.wallet.0 == [0_u8; 32]
        || statement.sequence == 0
        || statement.previous == [0_u8; 32]
        || statement.issuer_committee == [0_u8; 32]
        || statement.issuer_activation == [0_u8; 32]
    {
        return Err(LedgerError::InvalidStatement);
    }
    match &statement.payload {
        LedgerPayload::Allocation(allocation) => {
            allocation.address.validate()?;
            ChainPoint::new(
                allocation.recognition_anchor.height,
                allocation.recognition_anchor.hash,
            )
            .map_err(|_| LedgerError::InvalidAllocation)?;
            if allocation.request.0 == [0_u8; 32]
                || allocation.address.wallet_id() != statement.wallet
                || allocation.created_at > MAX_UNIX_TIMESTAMP
                || allocation.expires_at > MAX_UNIX_TIMESTAMP
                || allocation.created_at.checked_add(UNUSED_ALLOCATION_TTL_SECONDS)
                    != Some(allocation.expires_at)
            {
                return Err(LedgerError::InvalidAllocation);
            }
        }
        LedgerPayload::HandoffFence(fence) => {
            if fence.version != HANDOFF_FENCE_VERSION
                || fence.target_epoch
                    != statement
                        .issuer_epoch
                        .checked_add(1)
                        .ok_or(LedgerError::InvalidHandoffFence)?
                || fence.target_committee == [0; 32]
                || fence.target_activation == [0; 32]
                || ChainPoint::new(fence.cutoff.height, fence.cutoff.hash).is_err()
            {
                return Err(LedgerError::InvalidHandoffFence);
            }
        }
        LedgerPayload::Handoff(handoff) => {
            let transition = handoff.transition();
            if transition.wallet() != statement.wallet
                || transition.source().wallet() != statement.wallet
                || transition.source().active_epoch() != statement.issuer_epoch
                || transition.source_committee() != statement.issuer_committee
                || transition.source_activation() != statement.issuer_activation
                || transition.source_key_id() == [0_u8; 32]
                || transition.source_group_key() == [0_u8; 32]
                || transition.source_certified_activation_root() == [0_u8; 32]
                || transition.terminal_sequence() != statement.sequence
                || transition.previous_ledger_head() != statement.previous
                || transition.source_portable_index() == [0; 32]
                || transition.target_epoch()
                    != statement.issuer_epoch.checked_add(1).ok_or(LedgerError::InvalidHandoff)?
                || transition.target_committee() == [0_u8; 32]
                || transition.target_key_id() != transition.source_key_id()
                || transition.target_group_key() != transition.source_group_key()
                || transition.target_activation() == [0_u8; 32]
                || transition.target_certified_activation_root() == [0_u8; 32]
            {
                return Err(LedgerError::InvalidHandoff);
            }
        }
        LedgerPayload::ConsolidationCompletion(completion) => {
            if completion.version != CONSOLIDATION_COMPLETION_VERSION
                || completion.plan.wallet != statement.wallet
                || completion.plan.epoch != statement.issuer_epoch
                || completion.plan.inputs.is_empty()
                || completion.plan.inputs.len() > MAX_CONSOLIDATION_INPUTS
                || completion.signed_transaction.as_bytes().is_empty()
            {
                return Err(LedgerError::InvalidConsolidationCompletion);
            }
        }
        LedgerPayload::ConsolidationAbandonment(abandonment) => {
            if abandonment.version != CONSOLIDATION_ABANDONMENT_VERSION
                || abandonment.family == [0; 32]
                || abandonment.authorization.wallet_id() != statement.wallet
                || abandonment.attempt.epoch() != statement.issuer_epoch
                || abandonment.inputs.is_empty()
                || abandonment.missing_inputs.is_empty()
                || abandonment.finality_depth == 0
            {
                return Err(LedgerError::InvalidConsolidationAbandonment);
            }
        }
        LedgerPayload::LateConsolidationSettlement(settlement) => {
            if settlement.version != LATE_CONSOLIDATION_SETTLEMENT_VERSION
                || settlement.abandonment_statement == [0; 32]
                || settlement.historical_completion.id().0 == [0; 32]
                || settlement.finality_depth == 0
            {
                return Err(LedgerError::InvalidLateConsolidationSettlement);
            }
        }
    }
    Ok(())
}

fn increment_index(index: DepositSubaddressIndex) -> Result<DepositSubaddressIndex, LedgerError> {
    let address = index.address().checked_add(1).ok_or(LedgerError::IndexExhausted)?;
    DepositSubaddressIndex::new(index.account(), address).map_err(LedgerError::Wallet)
}

/// Pinned empty-log head for one stable wallet domain.
#[must_use]
pub fn genesis_head(wallet: DepositWalletId) -> [u8; 32] {
    compact_registry_genesis_ledger_head(wallet)
}

fn network_tag(network: crate::config::NetworkKind) -> u8 {
    match network {
        crate::config::NetworkKind::Regtest => 0,
        crate::config::NetworkKind::Testnet => 1,
        crate::config::NetworkKind::Mainnet => 2,
    }
}

fn exact_certificate_digest(domain: &str, bytes: &[u8]) -> Result<[u8; 32], LedgerError> {
    let byte_len = u64::try_from(bytes.len()).map_err(|_| LedgerError::Serialization)?;
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&byte_len.to_le_bytes());
    hasher.update(bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// Portable ledger validation failure.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("compact registry error: {0}")]
    CompactRegistry(#[from] CompactRegistryError),
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("wallet/address error: {0}")]
    Wallet(#[from] crate::deposit_wallet::DepositWalletError),
    #[error("consolidation binding error: {0}")]
    Consolidation(#[from] ConsolidationError),
    #[error("registry is malformed")]
    InvalidRegistry,
    #[error("registry differs from the one bound to this replay state")]
    RegistryMismatch,
    #[error("authenticated portable head cannot initialize this compact ledger cursor")]
    InvalidAuthenticatedCursor,
    #[error("portable index head does not exactly match the ledger transition")]
    PortableCheckpointMismatch,
    #[error("committee does not satisfy n >= 3f + 1")]
    InvalidFaultBound,
    #[error("statement is malformed")]
    InvalidStatement,
    #[error("allocation statement is malformed")]
    InvalidAllocation,
    #[error("allocation signing requires the exact authenticated local recognition anchor")]
    AllocationRecognitionRequired,
    #[error("certified deposit observation is malformed or inconsistently bound")]
    InvalidDepositObservation,
    #[error("deposit observation signing requires its exact committed local reservation")]
    DepositObservationReservationRequired,
    #[error("handoff statement/certificate is malformed")]
    InvalidHandoff,
    #[error("handoff scanner fence is malformed")]
    InvalidHandoffFence,
    #[error("consolidation completion is malformed or inconsistently bound")]
    InvalidConsolidationCompletion,
    #[error("consolidation abandonment is malformed or inconsistently bound")]
    InvalidConsolidationAbandonment,
    #[error("late consolidation settlement is malformed or inconsistently bound")]
    InvalidLateConsolidationSettlement,
    #[error("terminal statement requires independently verified consensus admission")]
    TerminalAdmissionRequired,
    #[error("terminal consensus admission does not authorize this exact issuer/slot/statement")]
    InvalidTerminalAdmission,
    #[error("statement belongs to an unknown, unactivated, or retired issuer window")]
    UnknownOrInactiveEpoch,
    #[error("retired epoch attempted to replace its terminal handoff")]
    SealedEpoch,
    #[error("timestamp is invalid")]
    InvalidTime,
    #[error("allocation creation time exceeds permitted clock skew")]
    ClockSkew,
    #[error("allocation certificate did not complete before scheduled client-visible issuance")]
    AllocationCertificationMissedIssuance,
    #[error("allocation issuance is not bound to its exact verified n-f portable-index checkpoint")]
    AllocationCheckpointMismatch,
    #[error("certified allocation is not yet at its client-visible issuance instant")]
    AllocationIssuanceNotReady,
    #[error("certified allocation missed its exact client-visible issuance instant")]
    AllocationIssuanceMissed,
    #[error("sequence counter is exhausted")]
    SequenceExhausted,
    #[error("subaddress index is exhausted")]
    IndexExhausted,
    #[error("certificate has too many bytes or witnesses")]
    CertificateTooLarge,
    #[error("attestation payload is too large")]
    AttestationTooLarge,
    #[error("attestation is malformed or not bound to the exact slot/statement")]
    InvalidAttestation,
    #[error("certificate witness order is not canonical")]
    NonCanonicalCertificate,
    #[error("certificate has {actual} witnesses; n-f requires {required}")]
    InsufficientCertificate { actual: usize, required: u16 },
    #[error(
        "consolidation certificate has {actual} signer witnesses; signing threshold requires {required}"
    )]
    InsufficientConsolidationSignerWitnesses { actual: usize, required: u16 },
    #[error("ledger gap: expected sequence {expected}, got {actual}")]
    Gap { expected: u64, actual: u64 },
    #[error("ledger statement forks the certified predecessor/sequence")]
    Fork,
    #[error("stale sequence has no corresponding certified record")]
    RevisionMismatch,
    #[error("index mismatch: expected {expected:?}, got {actual:?}")]
    IndexMismatch { expected: DepositSubaddressIndex, actual: DepositSubaddressIndex },
    #[error("address differs from independent wallet derivation")]
    WrongDerivedAddress,
    #[error("verification capability does not match the exact certified bytes")]
    VerificationCapabilityMismatch,
    #[error("serialization failed")]
    Serialization,
    #[error("deserialization failed")]
    Deserialization,
    #[error("encoding is not canonical")]
    NonCanonicalEncoding,
    #[error("encoded certificate has {0} trailing bytes")]
    TrailingBytes(usize),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        committee::{Committee, Member},
        compact_registry_archive::{
            CompactRegistryArchiveError, CompactRegistryObjectReader, CompactRegistryObjectRef,
            PendingCompactRegistryMutation, prepare_compact_registry_append,
            prepare_compact_registry_genesis,
        },
        config::NetworkKind,
        deposit_index::{
            DepositIndexBuilder, DepositIndexError, DepositIndexHead, DepositIndexObjectId,
            DepositIndexReader, DepositIndexUpdate,
        },
        deposit_index_checkpoint::PortableDepositIndexHead,
        deposit_wallet::{DepositAddressDeriver, ScanState},
        key_rotation::VerifiedRegistryHandoffTarget,
    };

    #[derive(Default)]
    struct MemoryRegistryObjects {
        objects: BTreeMap<CompactRegistryObjectRef, Vec<u8>>,
    }

    impl MemoryRegistryObjects {
        fn install(&mut self, pending: &PendingCompactRegistryMutation) {
            for object in pending.staged_objects() {
                self.objects.insert(object.reference(), object.contents().to_vec());
            }
        }
    }

    impl CompactRegistryObjectReader for MemoryRegistryObjects {
        fn load(
            &self,
            reference: CompactRegistryObjectRef,
        ) -> Result<Option<Vec<u8>>, CompactRegistryArchiveError> {
            Ok(self.objects.get(&reference).cloned())
        }
    }

    struct EmptyIndexReader;

    impl DepositIndexReader for EmptyIndexReader {
        fn load_index_object(
            &self,
            _id: DepositIndexObjectId,
        ) -> Result<Option<Vec<u8>>, DepositIndexError> {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct MemoryIndexObjects {
        objects: BTreeMap<DepositIndexObjectId, Vec<u8>>,
    }

    impl MemoryIndexObjects {
        fn install(&mut self, update: &DepositIndexUpdate) {
            self.objects.extend(
                update.staged_objects().map(|(object, contents)| (object, contents.to_vec())),
            );
        }
    }

    impl DepositIndexReader for MemoryIndexObjects {
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

    fn committee(epoch: u64) -> (Committee, BTreeMap<PartyId, Identity>) {
        let identities = (1_u16..=4)
            .map(|party| {
                let id = PartyId(party);
                let signing_seed = [u8::try_from(party).unwrap(); 32];
                let identity = Identity::from_test_secrets(
                    id,
                    epoch,
                    &signing_seed,
                    test_x25519_secret(id, epoch),
                )
                .unwrap();
                (id, identity)
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

    fn deriver() -> DepositAddressDeriver {
        let root = (ED25519_BASEPOINT_POINT * Scalar::from(42_u64)).compress().to_bytes();
        DepositAddressDeriver::new(
            NetworkKind::Regtest,
            root,
            &Zeroizing::new(Scalar::from(17_u64).to_bytes()),
        )
        .unwrap()
    }

    fn registry_target(
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
            [0xd2; 32],
            [0xd3; 32],
        )
        .unwrap()
    }

    fn certificate(
        statement: LedgerStatement,
        committee: &Committee,
        identities: &BTreeMap<PartyId, Identity>,
        witnesses: usize,
    ) -> CertifiedLedgerEntry {
        let parties = identities.keys().copied().take(witnesses).collect::<Vec<_>>();
        certificate_from_parties(statement, committee, identities, &parties)
    }

    fn certificate_from_parties(
        statement: LedgerStatement,
        committee: &Committee,
        identities: &BTreeMap<PartyId, Identity>,
        parties: &[PartyId],
    ) -> CertifiedLedgerEntry {
        let payload = statement.attestation_payload().unwrap();
        let mut attestations = parties
            .iter()
            .map(|party| {
                identities
                    .get(party)
                    .unwrap()
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
        CertifiedLedgerEntry { statement, attestations }
    }

    fn observation_certificate_from_parties(
        statement: DepositObservationStatement,
        committee: &Committee,
        identities: &BTreeMap<PartyId, Identity>,
        parties: &[PartyId],
    ) -> CertifiedDepositObservation {
        let payload = statement.attestation_payload().unwrap();
        let mut attestations = parties
            .iter()
            .map(|party| {
                identities
                    .get(party)
                    .unwrap()
                    .sign_envelope(
                        committee,
                        statement.session(),
                        None,
                        statement.allocation_sequence(),
                        payload.clone(),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        attestations.sort_by_key(|envelope| envelope.from);
        CertifiedDepositObservation { statement, attestations }
    }

    fn genesis_fixture() -> (
        DepositAddressDeriver,
        DepositIndexHead,
        PendingCompactRegistryMutation,
        BTreeMap<PartyId, Identity>,
    ) {
        let deriver = deriver();
        let wallet = deriver.wallet_id();
        let first_index = DepositSubaddressIndex::new(0, 1).unwrap();
        let portable = DepositIndexHead::empty_portable(wallet, first_index).unwrap();
        let (committee, identities) = committee(0);
        let target = registry_target(wallet, committee, [1; 32], [0xd1; 32]);
        let pending =
            prepare_compact_registry_genesis(&target, first_index, portable.digest()).unwrap();
        (deriver, portable, pending, identities)
    }

    #[test]
    fn unused_allocation_has_exact_thirty_day_release_boundaries() {
        let deriver = deriver();
        let visible_at = 1_700_000_000;
        let expires_at = visible_at + UNUSED_ALLOCATION_TTL_SECONDS;
        let schedule = VerifiedAllocationIssuanceSchedule {
            wallet: deriver.wallet_id(),
            sequence: 1,
            statement: [0xa1; 32],
            address: deriver.derive(DepositSubaddressIndex::new(0, 1).unwrap()),
            visible_at,
            expires_at,
        };

        assert!(matches!(
            schedule.clone().release_at(visible_at - 1),
            Err(LedgerError::AllocationIssuanceNotReady)
        ));
        let first = schedule.clone().release_at(visible_at).unwrap();
        assert_eq!(first.issued_at(), visible_at);
        assert_eq!(first.expires_at(), expires_at);
        let last = schedule.clone().release_at(expires_at - 1).unwrap();
        assert_eq!(last.address(), first.address());
        assert!(matches!(
            schedule.release_at(expires_at),
            Err(LedgerError::AllocationIssuanceMissed)
        ));
        assert_eq!(expires_at - visible_at, 30 * 24 * 60 * 60);
    }

    #[test]
    fn fresh_compact_genesis_allocates_and_replays() {
        let (deriver, portable, pending, identities) = genesis_fixture();
        let registry = pending.proposed_head().registry().clone();
        let committee = registry.active().committee();
        let portable_checkpoint = PortableDepositIndexHead::from_head(&portable).unwrap();
        let ledger = CompactLedgerCursor::genesis(&registry, &portable_checkpoint).unwrap();
        let address = deriver.derive(ledger.next_index());
        let recognition_anchor = ChainPoint::new(0, [0x91; 32]).unwrap();
        let scan = ScanState::new(&deriver, recognition_anchor).unwrap();
        let recognition = scan.verify_recognition_anchor(recognition_anchor).unwrap();
        let statement = LedgerStatement::allocation(
            &registry,
            ledger.next_sequence(),
            ledger.head(),
            LedgerRequestId([3; 32]),
            RequestBinding([4; 32]),
            address.clone(),
            recognition_anchor,
            1_030,
        )
        .unwrap();
        let mut builder = DepositIndexBuilder::new(&EmptyIndexReader, portable).unwrap();
        let preflight = builder.preflight_ledger_statement(&statement).unwrap();
        ledger
            .validate_next_statement(
                &registry,
                None,
                &statement,
                1_000,
                Some(&recognition),
                &preflight,
                |candidate| candidate == &address,
            )
            .unwrap();
        let entry = certificate(statement, committee, &identities, 3);
        entry.verify_active(&registry, None).unwrap();
        assert_eq!(ledger.next_index(), DepositSubaddressIndex::new(0, 1).unwrap());
        assert_eq!(ledger.registry_id(), registry.id());
    }

    #[test]
    fn observation_transition_updates_only_the_cursor_portable_digest() {
        let (deriver, portable, pending, identities) = genesis_fixture();
        let registry = pending.proposed_head().registry().clone();
        let committee = registry.active().committee();
        let genesis_cursor = CompactLedgerCursor::genesis(
            &registry,
            &PortableDepositIndexHead::from_head(&portable).unwrap(),
        )
        .unwrap();
        let allocation = LedgerStatement::allocation(
            &registry,
            genesis_cursor.next_sequence(),
            genesis_cursor.head(),
            LedgerRequestId([0xa1; 32]),
            RequestBinding([0xa2; 32]),
            deriver.derive(genesis_cursor.next_index()),
            ChainPoint::new(10, [0xa3; 32]).unwrap(),
            1_700_000_000,
        )
        .unwrap();
        let allocation_entry = certificate(allocation.clone(), committee, &identities, 3);
        let mut allocation_builder =
            DepositIndexBuilder::new(&EmptyIndexReader, portable.clone()).unwrap();
        assert!(
            allocation_builder
                .apply_verified_active_entry(&allocation_entry, &registry, None)
                .unwrap()
        );
        let allocation_update = allocation_builder.finish().unwrap().unwrap();
        let allocation_head = allocation_update.next_head().clone();
        let allocation_logical = PortableDepositIndexHead::from_head(&allocation_head).unwrap();
        let mut cursor = CompactLedgerCursor::from_authenticated_portable_head(
            &registry,
            &allocation_logical,
            Some(&allocation),
        )
        .unwrap();
        let mut objects = MemoryIndexObjects::default();
        objects.install(&allocation_update);

        let observation_statement = DepositObservationStatement::new(
            &registry,
            &allocation,
            WalletOutputId { transaction: [0xa4; 32], index_in_transaction: 2 },
            [0xa5; 32],
            77,
            91,
            ChainPoint::new(100, [0xa6; 32]).unwrap(),
            1_700_000_100,
            ChainPoint::new(109, [0xa7; 32]).unwrap(),
            10,
        )
        .unwrap();
        let observation = observation_certificate_from_parties(
            observation_statement.clone(),
            committee,
            &identities,
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        let mut observation_builder = DepositIndexBuilder::new(&objects, allocation_head).unwrap();
        assert!(
            observation_builder
                .apply_verified_active_deposit_observation(&observation, &registry)
                .unwrap()
        );
        let observation_update = observation_builder.finish().unwrap().unwrap();
        objects.install(&observation_update);
        let transition = observation_update
            .verify_deposit_observation_transition(&objects, &observation_statement)
            .unwrap();
        let resulting_digest =
            PortableDepositIndexHead::from_head(transition.resulting_head()).unwrap().digest();

        let before_head = cursor.head();
        let before_sequence = cursor.next_sequence();
        let before_index = cursor.next_index();
        let before_registry = cursor.registry_id();
        let before_sealed = cursor.is_sealed();
        cursor.adopt_verified_deposit_observation_transition(&transition).unwrap();
        assert_eq!(cursor.portable_index_digest(), resulting_digest);
        assert_eq!(cursor.head(), before_head);
        assert_eq!(cursor.next_sequence(), before_sequence);
        assert_eq!(cursor.next_index(), before_index);
        assert_eq!(cursor.registry_id(), before_registry);
        assert_eq!(cursor.is_sealed(), before_sealed);

        let adopted = cursor.clone();
        assert!(matches!(
            cursor.adopt_verified_deposit_observation_transition(&transition),
            Err(LedgerError::PortableCheckpointMismatch)
        ));
        assert_eq!(cursor, adopted);

        let mut stale = genesis_cursor;
        let stale_before = stale.clone();
        assert!(matches!(
            stale.adopt_verified_deposit_observation_transition(&transition),
            Err(LedgerError::PortableCheckpointMismatch)
        ));
        assert_eq!(stale, stale_before);
    }

    #[test]
    fn verified_entry_is_bound_to_exact_certificate_witnesses() {
        let (deriver, portable, pending, identities) = genesis_fixture();
        let registry = pending.proposed_head().registry().clone();
        let committee = registry.active().committee();
        let ledger = CompactLedgerCursor::genesis(
            &registry,
            &PortableDepositIndexHead::from_head(&portable).unwrap(),
        )
        .unwrap();
        let statement = LedgerStatement::allocation(
            &registry,
            ledger.next_sequence(),
            ledger.head(),
            LedgerRequestId([0x31; 32]),
            RequestBinding([0x32; 32]),
            deriver.derive(ledger.next_index()),
            ChainPoint::new(5, [0x33; 32]).unwrap(),
            1_030,
        )
        .unwrap();
        let first = certificate_from_parties(
            statement.clone(),
            committee,
            &identities,
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        let swapped = certificate_from_parties(
            statement,
            committee,
            &identities,
            &[PartyId(1), PartyId(2), PartyId(4)],
        );
        let verified = first.verify_active(&registry, None).unwrap();
        swapped.verify_active(&registry, None).unwrap();

        verified.verify_exact_certificate(&first).unwrap();
        assert_eq!(verified.statement_digest(), swapped.statement.digest());
        assert_ne!(verified.certificate_digest(), swapped.certificate_digest().unwrap());
        assert!(matches!(
            verified.verify_exact_certificate(&swapped),
            Err(LedgerError::VerificationCapabilityMismatch)
        ));
    }

    #[test]
    fn verified_observation_is_bound_to_exact_certificate_witnesses() {
        let (_, _, pending, identities) = genesis_fixture();
        let registry = pending.proposed_head().registry().clone();
        let issuer = registry.active();
        let statement = DepositObservationStatement {
            version: DEPOSIT_OBSERVATION_VERSION,
            wallet: registry.wallet(),
            issuer_epoch: issuer.epoch(),
            issuer_committee: issuer.committee().digest(),
            issuer_activation: issuer.activation(),
            allocation_sequence: issuer.start_sequence(),
            allocation_statement: [0x41; 32],
            index: issuer.first_index(),
            output: WalletOutputId { transaction: [0x42; 32], index_in_transaction: 1 },
            output_key: [0x43; 32],
            index_on_blockchain: 7,
            amount_atomic_units: 73,
            observed_block: ChainPoint::new(100, [0x44; 32]).unwrap(),
            block_timestamp: 1_700_000_000,
            confirmation_horizon: ChainPoint::new(109, [0x45; 32]).unwrap(),
            confirmation_depth: 10,
        };
        let first = observation_certificate_from_parties(
            statement.clone(),
            issuer.committee(),
            &identities,
            &[PartyId(1), PartyId(2), PartyId(3)],
        );
        let swapped = observation_certificate_from_parties(
            statement,
            issuer.committee(),
            &identities,
            &[PartyId(1), PartyId(2), PartyId(4)],
        );
        let verified = first.verify_active(&registry).unwrap();
        swapped.verify_active(&registry).unwrap();

        verified.verify_exact_certificate(&first).unwrap();
        assert_eq!(verified.statement_digest(), swapped.statement.digest());
        assert_ne!(verified.certificate_digest(), swapped.certificate_digest().unwrap());
        assert!(matches!(
            verified.verify_exact_certificate(&swapped),
            Err(LedgerError::VerificationCapabilityMismatch)
        ));
    }

    #[test]
    fn terminal_sequence_is_rejected_before_signing_and_never_partially_advances() {
        let (deriver, genesis, pending, identities) = genesis_fixture();
        let registry = pending.proposed_head().registry().clone();
        let first_index = registry.active().first_index();
        let address = deriver.derive(first_index);
        let recognition_anchor = ChainPoint::new(0, [0x92; 32]).unwrap();
        let recognition = ScanState::new(&deriver, recognition_anchor)
            .unwrap()
            .verify_recognition_anchor(recognition_anchor)
            .unwrap();

        // Build genuine typed index evidence. The terminal cursor must reject before consulting
        // it, but the test deliberately avoids fabricating an impossible truncated portable head.
        let first = LedgerStatement::allocation(
            &registry,
            1,
            genesis_head(registry.wallet()),
            LedgerRequestId([0x50; 32]),
            RequestBinding([0x51; 32]),
            address.clone(),
            recognition_anchor,
            1_000,
        )
        .unwrap();
        let mut preflight_builder =
            DepositIndexBuilder::new(&EmptyIndexReader, genesis.clone()).unwrap();
        let preflight = preflight_builder.preflight_ledger_statement(&first).unwrap();
        let first_entry = certificate(first.clone(), registry.active().committee(), &identities, 3);
        let mut transition_builder =
            DepositIndexBuilder::new(&EmptyIndexReader, genesis.clone()).unwrap();
        assert!(
            transition_builder.apply_verified_active_entry(&first_entry, &registry, None).unwrap()
        );
        let update = transition_builder.finish().unwrap().unwrap();
        let transition = update
            .verify_ledger_transition_for_preflight(&EmptyIndexReader, &first, &preflight)
            .unwrap();

        let previous = [0x55_u8; 32];
        let portable = PortableDepositIndexHead::from_head(&genesis).unwrap();
        let mut ledger = CompactLedgerCursor {
            wallet: registry.wallet(),
            registry: registry.id(),
            head: previous,
            next_sequence: u64::MAX,
            next_index: first_index,
            portable_index: portable.digest(),
            sealed: false,
        };
        let statement = LedgerStatement::allocation(
            &registry,
            u64::MAX,
            previous,
            LedgerRequestId([0x56; 32]),
            RequestBinding([0x57; 32]),
            address.clone(),
            recognition_anchor,
            1_000,
        )
        .unwrap();

        assert!(matches!(
            ledger.validate_next_statement(
                &registry,
                None,
                &statement,
                1_000,
                Some(&recognition),
                &preflight,
                |candidate| candidate == &address,
            ),
            Err(LedgerError::SequenceExhausted)
        ));
        assert!(matches!(
            ledger.validate_reserved_statement(
                &registry,
                None,
                &statement,
                Some(&recognition),
                &preflight,
                |candidate| candidate == &address,
            ),
            Err(LedgerError::SequenceExhausted)
        ));

        let entry = certificate(statement.clone(), registry.active().committee(), &identities, 3);
        let before = ledger.clone();
        assert!(matches!(
            ledger.advance_certificate(
                &registry,
                None,
                entry,
                &preflight,
                &transition,
                |candidate| candidate == &address,
            ),
            Err(LedgerError::SequenceExhausted)
        ));
        assert_eq!(ledger, before);
    }

    #[test]
    fn compact_handoff_is_the_single_terminal_ledger_decision() {
        let (_, portable, pending, identities) = genesis_fixture();
        let mut objects = MemoryRegistryObjects::default();
        objects.install(&pending);
        let source_head = pending.proposed_head().clone();
        let source = source_head.registry().clone();
        let portable_checkpoint = PortableDepositIndexHead::from_head(&portable).unwrap();
        let ledger = CompactLedgerCursor::genesis(&source, &portable_checkpoint).unwrap();
        let (target_committee, _) = committee(1);
        let target = registry_target(source.wallet(), target_committee, [2; 32], [0xd4; 32]);
        let source_state =
            DepositHandoffStateBinding::new(Some([0xd5; 32]), portable_checkpoint.clone()).unwrap();
        let statement = LedgerStatement::handoff(
            &source,
            ledger.next_sequence(),
            ledger.head(),
            source_state,
            &target,
            ledger.next_index(),
        )
        .unwrap();
        let LedgerPayload::Handoff(handoff) = &statement.payload else {
            panic!("constructor returned a non-handoff payload");
        };
        assert_eq!(statement.digest(), handoff.transition().digest());
        assert_eq!(
            statement.attestation_payload().unwrap(),
            handoff.transition().signing_payload()
        );

        let entry = certificate(statement, source.active().committee(), &identities, 3);
        let registry_certificate = entry.registry_handoff_certificate(&source).unwrap();
        let successor = prepare_compact_registry_append(
            &source_head,
            &target,
            registry_certificate,
            &portable_checkpoint,
            &objects,
        )
        .unwrap();
        let successor_registry = successor.proposed_head().registry().clone();
        assert_eq!(successor_registry.active().predecessor_ledger_head(), entry.statement.digest());
        assert_eq!(successor_registry.active().start_sequence(), entry.statement.sequence + 1);
        assert_eq!(successor_registry.active().portable_index_checkpoint(), portable.digest());
    }

    #[test]
    fn observation_fact_survives_horizon_and_issuer_retry_but_not_conflict() {
        let statement = DepositObservationStatement {
            version: DEPOSIT_OBSERVATION_VERSION,
            wallet: DepositWalletId([0x11; 32]),
            issuer_epoch: 7,
            issuer_committee: [0x12; 32],
            issuer_activation: [0x13; 32],
            allocation_sequence: 9,
            allocation_statement: [0x14; 32],
            index: DepositSubaddressIndex::new(0, 4).unwrap(),
            output: WalletOutputId { transaction: [0x15; 32], index_in_transaction: 1 },
            output_key: [0x16; 32],
            index_on_blockchain: 42,
            amount_atomic_units: 73,
            observed_block: ChainPoint::new(100, [0x17; 32]).unwrap(),
            block_timestamp: 1_700_000_000,
            confirmation_horizon: ChainPoint::new(109, [0x18; 32]).unwrap(),
            confirmation_depth: 10,
        };
        let mut retry = statement.clone();
        retry.issuer_epoch += 1;
        retry.issuer_committee = [0x19; 32];
        retry.issuer_activation = [0x1a; 32];
        retry.confirmation_horizon = ChainPoint::new(110, [0x1b; 32]).unwrap();

        assert_eq!(statement.fact_digest(), retry.fact_digest());
        assert_ne!(statement.digest(), retry.digest());

        let mut conflict = retry;
        conflict.amount_atomic_units += 1;
        assert_ne!(statement.fact_digest(), conflict.fact_digest());
    }

    #[test]
    fn observation_reissue_changes_only_active_issuer_fields() {
        let (_, _, pending, _) = genesis_fixture();
        let registry = pending.proposed_head().registry().clone();
        let statement = DepositObservationStatement {
            version: DEPOSIT_OBSERVATION_VERSION,
            wallet: registry.wallet(),
            issuer_epoch: 99,
            issuer_committee: [0xb1; 32],
            issuer_activation: [0xb2; 32],
            allocation_sequence: 7,
            allocation_statement: [0xb3; 32],
            index: DepositSubaddressIndex::new(0, 5).unwrap(),
            output: WalletOutputId { transaction: [0xb4; 32], index_in_transaction: 3 },
            output_key: [0xb5; 32],
            index_on_blockchain: 44,
            amount_atomic_units: 101,
            observed_block: ChainPoint::new(200, [0xb6; 32]).unwrap(),
            block_timestamp: 1_700_000_200,
            confirmation_horizon: ChainPoint::new(209, [0xb7; 32]).unwrap(),
            confirmation_depth: 10,
        };
        let reissued = statement.reissue_for_active(&registry).unwrap();
        reissued.validate_active(&registry).unwrap();
        assert_eq!(reissued.issuer_epoch(), registry.active().epoch());
        assert_eq!(reissued.issuer_committee(), registry.active().committee().digest());
        assert_eq!(reissued.issuer_activation(), registry.active().activation());
        assert_eq!(reissued.wallet_id(), statement.wallet_id());
        assert_eq!(reissued.allocation_sequence(), statement.allocation_sequence());
        assert_eq!(reissued.allocation_statement(), statement.allocation_statement());
        assert_eq!(reissued.index(), statement.index());
        assert_eq!(reissued.output(), statement.output());
        assert_eq!(reissued.output_key(), statement.output_key());
        assert_eq!(reissued.index_on_blockchain(), statement.index_on_blockchain());
        assert_eq!(reissued.amount_atomic_units(), statement.amount_atomic_units());
        assert_eq!(reissued.observed_block(), statement.observed_block());
        assert_eq!(reissued.block_timestamp(), statement.block_timestamp());
        assert_eq!(reissued.confirmation_horizon(), statement.confirmation_horizon());
        assert_eq!(reissued.confirmation_depth(), statement.confirmation_depth());
        assert_eq!(reissued.fact_digest(), statement.fact_digest());
        assert_ne!(reissued.digest(), statement.digest());

        let mut wrong_wallet = statement;
        wrong_wallet.wallet = DepositWalletId([0xb8; 32]);
        assert!(matches!(
            wrong_wallet.reissue_for_active(&registry),
            Err(LedgerError::RegistryMismatch)
        ));
    }
}
