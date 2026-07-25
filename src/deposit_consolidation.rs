//! Durable, public coordination state for deposit consolidation signing.
//!
//! This reducer deliberately does **not** contain Monero's private outgoing-view material or the
//! encoded `SignableTransaction`. Those values remain in the encrypted deposit worker. The state
//! below commits to that exact intent and makes the crash boundaries around nonce creation,
//! signing completion, broadcast, confirmation, and reorg handling explicit.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    committee::{PartyId, SessionId},
    deposit_wallet::{
        ChainPoint, DepositWalletId, SweepId, WalletOutputId, derive_sweep_signing_session,
    },
    deposit_worker::{
        SweepSigningAuthorization, VerifiedArchivedSweepSettlement, VerifiedSweepSigningAttempt,
    },
    storage::{PersistedSessionTombstoneReceipt, SessionTombstoneClaim},
};

const CONSOLIDATION_STATE_VERSION: u16 = 3;
const AUTHORIZATION_VERSION: u16 = 1;
const ATTEMPT_VERSION: u16 = 1;
/// Maximum lifetime consolidation records retained by one party-local coordinator.
///
/// The follower Start path also uses this as the largest permitted uncertified sweep-sequence
/// distance from portable history, so one remote leader cannot name an effectively unbounded
/// future sequence which honest state could never justify retaining.
pub const MAX_CONSOLIDATIONS: usize = 100_000;
/// Maximum attempts carried by one portable catch-up batch or one in-memory ROAST campaign.
///
/// This is not a lifetime retry bound. The coordinator's monotonic high-water can advance until
/// `u64::MAX` while retaining only [`MAX_RETAINED_CONSOLIDATION_ATTEMPTS`] exact tombstones.
pub const MAX_CONSOLIDATION_ATTEMPTS: usize = 1_024;
/// Maximum exact attempt tombstones retained in the hot coordinator snapshot for one family.
pub const MAX_RETAINED_CONSOLIDATION_ATTEMPTS: usize = 64;
const MAX_SIGNERS: usize = u16::MAX as usize;
const MAX_CONSOLIDATION_STATE_BYTES: usize = 64 * 1024 * 1024;
const NONCE_TOMBSTONE_PURPOSE_VERSION: u16 = 1;
const NONCE_TOMBSTONE_PURPOSE_DOMAIN: &[u8] = b"threshold-monero/consolidation-nonce-tombstone/v1";

/// Stable identifier derived from an exact public transaction authorization.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConsolidationId(pub [u8; 32]);

/// Commitment to the worker-owned, encrypted `SignableTransaction` and its private offsets.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueIntentBinding(pub [u8; 32]);

impl OpaqueIntentBinding {
    /// Commit to the exact canonical sensitive prepared-intent bytes without retaining them.
    #[must_use]
    pub fn from_prepared_sweep_bytes(bytes: &[u8]) -> Self {
        // This intentionally matches `PreparedSweepIntent::digest` without importing sensitive
        // worker types into the public reducer.
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/prepared-sweep-intent/v1");
        hasher.update(bytes);
        Self(*hasher.finalize().as_bytes())
    }
}

/// Commit to the exact sorted scanner output IDs authorized as consolidation inputs.
///
/// Callers must supply the canonical strictly sorted plan order. The explicit transaction hash
/// and output index encoding is stable across serializer upgrades.
#[must_use]
pub fn consolidation_input_set_binding(inputs: &[WalletOutputId]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/consolidation-input-set/v1");
    hasher.update(&(inputs.len() as u64).to_le_bytes());
    for input in inputs {
        hasher.update(&input.transaction);
        hasher.update(&input.index_in_transaction.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Commit to byte-identical canonical signed transaction bytes retained for restart/rebroadcast.
#[must_use]
pub fn consolidation_signed_bytes_binding(bytes: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/signed-consolidation-bytes/v1");
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Complete public authorization for one exact consolidation transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionAuthorization {
    version: u16,
    id: ConsolidationId,
    wallet: DepositWalletId,
    sweep: SweepId,
    opaque_intent: OpaqueIntentBinding,
    input_set: [u8; 32],
    destination_policy: [u8; 32],
    root_group_key: [u8; 32],
    input_count: u32,
    total_input_atomic_units: u64,
    fee_atomic_units: u64,
    maximum_fee_atomic_units: u64,
}

impl TransactionAuthorization {
    /// Construct and identify an exact public signing authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet: DepositWalletId,
        sweep: SweepId,
        opaque_intent: OpaqueIntentBinding,
        input_set: [u8; 32],
        destination_policy: [u8; 32],
        root_group_key: [u8; 32],
        input_count: u32,
        total_input_atomic_units: u64,
        fee_atomic_units: u64,
        maximum_fee_atomic_units: u64,
    ) -> Result<Self, ConsolidationError> {
        let mut authorization = Self {
            version: AUTHORIZATION_VERSION,
            id: ConsolidationId([0_u8; 32]),
            wallet,
            sweep,
            opaque_intent,
            input_set,
            destination_policy,
            root_group_key,
            input_count,
            total_input_atomic_units,
            fee_atomic_units,
            maximum_fee_atomic_units,
        };
        authorization.id = authorization.derived_id();
        authorization.validate()?;
        Ok(authorization)
    }

    #[must_use]
    pub const fn id(&self) -> ConsolidationId {
        self.id
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn sweep_id(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub const fn opaque_intent(&self) -> OpaqueIntentBinding {
        self.opaque_intent
    }

    #[must_use]
    pub const fn input_set(&self) -> [u8; 32] {
        self.input_set
    }

    #[must_use]
    pub const fn destination_policy(&self) -> [u8; 32] {
        self.destination_policy
    }

    #[must_use]
    pub const fn root_group_key(&self) -> [u8; 32] {
        self.root_group_key
    }

    #[must_use]
    pub const fn input_count(&self) -> u32 {
        self.input_count
    }

    #[must_use]
    pub const fn total_input_atomic_units(&self) -> u64 {
        self.total_input_atomic_units
    }

    #[must_use]
    pub const fn fee_atomic_units(&self) -> u64 {
        self.fee_atomic_units
    }

    #[must_use]
    pub const fn maximum_fee_atomic_units(&self) -> u64 {
        self.maximum_fee_atomic_units
    }

    /// Versioned commitment to every authorization field.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-authorization/v1");
        self.hash_fields(&mut hasher, true);
        *hasher.finalize().as_bytes()
    }

    fn derived_id(&self) -> ConsolidationId {
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/consolidation-id/v1");
        self.hash_fields(&mut hasher, false);
        ConsolidationId(*hasher.finalize().as_bytes())
    }

    fn hash_fields(&self, hasher: &mut blake3::Hasher, include_id: bool) {
        hasher.update(&self.version.to_le_bytes());
        if include_id {
            hasher.update(&self.id.0);
        }
        hasher.update(&self.wallet.0);
        hasher.update(&self.sweep.0);
        hasher.update(&self.opaque_intent.0);
        hasher.update(&self.input_set);
        hasher.update(&self.destination_policy);
        hasher.update(&self.root_group_key);
        hasher.update(&self.input_count.to_le_bytes());
        hasher.update(&self.total_input_atomic_units.to_le_bytes());
        hasher.update(&self.fee_atomic_units.to_le_bytes());
        hasher.update(&self.maximum_fee_atomic_units.to_le_bytes());
    }

    pub(crate) fn validate(&self) -> Result<(), ConsolidationError> {
        if self.version != AUTHORIZATION_VERSION
            || self.wallet.0 == [0_u8; 32]
            || self.sweep.0 == [0_u8; 32]
            || self.opaque_intent.0 == [0_u8; 32]
            || self.input_set == [0_u8; 32]
            || self.destination_policy == [0_u8; 32]
            || self.root_group_key == [0_u8; 32]
            || self.input_count == 0
            || self.fee_atomic_units == 0
            || self.fee_atomic_units > self.maximum_fee_atomic_units
            || self.total_input_atomic_units <= self.fee_atomic_units
            || self.id != self.derived_id()
        {
            return Err(ConsolidationError::InvalidAuthorization);
        }
        Ok(())
    }
}

/// Epoch/session binding which must be durable before a FROSTLASS nonce is created.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttemptBinding {
    version: u16,
    attempt: u64,
    epoch: u64,
    registry: [u8; 32],
    committee: [u8; 32],
    activation: [u8; 32],
    root_group_key: [u8; 32],
    threshold: u16,
    signers: Vec<PartyId>,
    worker_intent: [u8; 32],
    session: SessionId,
    signing_context: [u8; 32],
}

impl AttemptBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attempt: u64,
        epoch: u64,
        registry: [u8; 32],
        committee: [u8; 32],
        activation: [u8; 32],
        root_group_key: [u8; 32],
        threshold: u16,
        signers: Vec<PartyId>,
        worker_intent: [u8; 32],
        session: SessionId,
        signing_context: [u8; 32],
    ) -> Result<Self, ConsolidationError> {
        let binding = Self {
            version: ATTEMPT_VERSION,
            attempt,
            epoch,
            registry,
            committee,
            activation,
            root_group_key,
            threshold,
            signers,
            worker_intent,
            session,
            signing_context,
        };
        binding.validate()?;
        Ok(binding)
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry
    }

    #[must_use]
    pub const fn committee_digest(&self) -> [u8; 32] {
        self.committee
    }

    #[must_use]
    pub const fn activation_digest(&self) -> [u8; 32] {
        self.activation
    }

    #[must_use]
    pub const fn root_group_key(&self) -> [u8; 32] {
        self.root_group_key
    }

    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    #[must_use]
    pub const fn worker_intent_digest(&self) -> [u8; 32] {
        self.worker_intent
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn signing_context(&self) -> [u8; 32] {
        self.signing_context
    }

    #[must_use]
    pub fn signers(&self) -> &[PartyId] {
        &self.signers
    }

    /// Versioned commitment to the complete attempt binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/consolidation-attempt/v1");
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.attempt.to_le_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.registry);
        hasher.update(&self.committee);
        hasher.update(&self.activation);
        hasher.update(&self.root_group_key);
        hasher.update(&self.threshold.to_le_bytes());
        hasher.update(&(self.signers.len() as u64).to_le_bytes());
        for signer in &self.signers {
            hasher.update(&signer.0.to_le_bytes());
        }
        hasher.update(&self.worker_intent);
        hasher.update(&self.session.0);
        hasher.update(&self.signing_context);
        *hasher.finalize().as_bytes()
    }

    pub(crate) fn validate(&self) -> Result<(), ConsolidationError> {
        if self.version != ATTEMPT_VERSION
            || self.attempt == 0
            || self.registry == [0_u8; 32]
            || self.committee == [0_u8; 32]
            || self.activation == [0_u8; 32]
            || self.root_group_key == [0_u8; 32]
            || self.threshold == 0
            || self.signers.is_empty()
            || self.signers.len() > MAX_SIGNERS
            || self.signers.len() < usize::from(self.threshold)
            || self.signers.iter().any(|party| party.0 == 0)
            || self.signers.windows(2).any(|window| window[0] >= window[1])
            || self.worker_intent == [0_u8; 32]
            || self.session.0 == [0_u8; 32]
            || self.signing_context == [0_u8; 32]
        {
            return Err(ConsolidationError::InvalidAttempt);
        }
        Ok(())
    }
}

/// Attempt-invariant public family fields pinned by the first durable attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AttemptFamilyBinding {
    epoch: u64,
    registry: [u8; 32],
    committee: [u8; 32],
    activation: [u8; 32],
    root_group_key: [u8; 32],
    threshold: u16,
}

impl AttemptFamilyBinding {
    fn from_attempt(binding: &AttemptBinding) -> Self {
        Self {
            epoch: binding.epoch,
            registry: binding.registry,
            committee: binding.committee,
            activation: binding.activation,
            root_group_key: binding.root_group_key,
            threshold: binding.threshold,
        }
    }

    fn matches(self, binding: &AttemptBinding) -> bool {
        self == Self::from_attempt(binding)
    }
}

/// Permanent status of one nonce-bearing session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AttemptStatus {
    /// Durable release exists; nonce creation was permitted once in the creating process.
    SigningReleased,
    /// A restart or input reorg made recovery unsafe, so this session can never be used again.
    BurnedAfterRestart,
    /// Signature completion was durably bound to this attempt.
    Completed,
}

/// Exact retained attempt tombstone. Burn permanence is carried by the monotonic high-water after
/// older entries are compacted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttemptTombstone {
    pub binding: AttemptBinding,
    pub status: AttemptStatus,
}

/// Public binding to exact canonical signed transaction bytes held by the encrypted worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedTransactionBinding {
    pub authorization: [u8; 32],
    pub attempt: u64,
    pub attempt_binding: [u8; 32],
    pub session: SessionId,
    pub signing_context: [u8; 32],
    pub opaque_intent: OpaqueIntentBinding,
    pub transaction: [u8; 32],
    pub exact_bytes: [u8; 32],
    pub exact_bytes_len: u32,
}

impl SignedTransactionBinding {
    #[must_use]
    pub const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization
    }

    #[must_use]
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn attempt_binding_digest(&self) -> [u8; 32] {
        self.attempt_binding
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn signing_context(&self) -> [u8; 32] {
        self.signing_context
    }

    #[must_use]
    pub const fn opaque_intent(&self) -> OpaqueIntentBinding {
        self.opaque_intent
    }

    #[must_use]
    pub const fn transaction(&self) -> [u8; 32] {
        self.transaction
    }

    #[must_use]
    pub const fn exact_bytes_digest(&self) -> [u8; 32] {
        self.exact_bytes
    }

    #[must_use]
    pub const fn exact_bytes_len(&self) -> u32 {
        self.exact_bytes_len
    }

    pub(crate) fn validate(&self) -> Result<(), ConsolidationError> {
        if self.authorization == [0_u8; 32]
            || self.attempt == 0
            || self.attempt_binding == [0_u8; 32]
            || self.session.0 == [0_u8; 32]
            || self.signing_context == [0_u8; 32]
            || self.opaque_intent.0 == [0_u8; 32]
            || self.transaction == [0_u8; 32]
            || self.exact_bytes == [0_u8; 32]
            || self.exact_bytes_len == 0
        {
            return Err(ConsolidationError::InvalidSignedTransaction);
        }
        Ok(())
    }
}

/// Durable lifecycle of one consolidation authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsolidationPhase {
    IntentReserved,
    SigningReleased {
        attempt: u64,
    },
    AwaitingFreshAttempt {
        burned_attempt: u64,
    },
    AttemptsExhausted {
        burned_attempt: u64,
    },
    Signed,
    Broadcast,
    Confirmed,
    AbortedBeforeNonce,
    QuarantinedByInputReorg {
        ancestor: ChainPoint,
    },
    /// Quorum-certified terminal closure for an unsigned post-nonce family.
    AbandonedByInputReorg {
        ancestor: ChainPoint,
    },
}

/// Complete public record for one authorization and bounded recent session tombstones.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationRecord {
    pub authorization: TransactionAuthorization,
    pub phase: ConsolidationPhase,
    /// Highest nonce-bearing attempt ever durably admitted for this family.
    pub attempt_high_water: u64,
    attempt_family: Option<AttemptFamilyBinding>,
    /// Bounded recent exact tombstones plus a completed winner, if any.
    pub attempts: BTreeMap<u64, AttemptTombstone>,
    pub signed: Option<SignedTransactionBinding>,
    pub confirmation: Option<ChainPoint>,
}

impl ConsolidationRecord {
    /// Monotonic family attempt counter suitable for a protocol-store rollback fence.
    #[must_use]
    pub const fn attempt_high_water(&self) -> u64 {
        self.attempt_high_water
    }

    /// Oldest exact attempt still retained in the hot snapshot.
    #[must_use]
    pub fn retained_attempt_floor(&self) -> Option<u64> {
        self.attempts.first_key_value().map(|(attempt, _)| *attempt)
    }
}

/// Exact state persistence obligation returned by a coordinator mutation.
///
/// This value is intentionally non-serializable and non-cloneable. A nonce authorization can be
/// derived only by consuming the exact effect returned by the release transition in the same
/// process, after the corresponding state revision is known durable.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsolidationPersistEffect {
    revision: u64,
    state_commitment: [u8; 32],
    release: Option<(ConsolidationId, u64)>,
    signed: Option<ConsolidationId>,
    invalidated_session: Option<SessionId>,
}

impl ConsolidationPersistEffect {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn state_commitment(&self) -> [u8; 32] {
        self.state_commitment
    }

    /// Newly released family attempt which the protocol store must close monotonically before
    /// this effect can become a nonce authorization.
    #[must_use]
    pub const fn released_attempt_high_water(&self) -> Option<(ConsolidationId, u64)> {
        self.release
    }

    /// Exact released session invalidated by this mutation, if any.
    ///
    /// This is set when an input reorg burns an in-flight attempt, when a portable certified
    /// winner from an older attempt terminates a newer locally released signing machine, and when
    /// canonical chain settlement terminates signing which is still locally in flight.
    #[must_use]
    pub const fn invalidated_session(&self) -> Option<SessionId> {
        self.invalidated_session
    }
}

/// Sealed acknowledgement that a compare-and-swap repository accepted the exact candidate.
///
/// Only crate-internal persistence integration can mint this value, and it is non-cloneable. A
/// losing reducer branch therefore cannot turn its mutation effect directly into a nonce or
/// signed-response capability merely by supplying a revision number.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsolidationPersistedReceipt {
    revision: u64,
    state_commitment: [u8; 32],
    release: Option<(ConsolidationId, u64)>,
    signed: Option<ConsolidationId>,
}

/// One-use, post-persistence capability passed to the component which creates FROSTLASS nonces.
#[derive(Debug, Eq, PartialEq)]
pub struct NonceAuthorization {
    consolidation: ConsolidationId,
    authorization: [u8; 32],
    sweep: SweepId,
    attempt: AttemptBinding,
}

impl NonceAuthorization {
    #[must_use]
    pub const fn consolidation_id(&self) -> ConsolidationId {
        self.consolidation
    }

    #[must_use]
    pub const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization
    }

    #[must_use]
    pub const fn sweep_id(&self) -> SweepId {
        self.sweep
    }

    #[must_use]
    pub const fn attempt(&self) -> &AttemptBinding {
        &self.attempt
    }

    /// Consume both independently persisted capabilities and compare every signer-bound field.
    pub fn bind_worker_authorization(
        self,
        worker: SweepSigningAuthorization,
    ) -> Result<ValidatedNonceAuthorization, ConsolidationError> {
        let signers_match = worker.signers().len() == self.attempt.signers().len()
            && worker
                .signers()
                .iter()
                .zip(self.attempt.signers())
                .all(|(worker, coordinator)| *worker == coordinator.0);
        if worker.sweep() != self.sweep
            || worker.attempt() != self.attempt.attempt()
            || worker.session() != self.attempt.session()
            || worker.signing_context() != self.attempt.signing_context()
            || worker.group_key() != self.attempt.root_group_key()
            || worker.intent_digest() != self.attempt.worker_intent_digest()
            || !signers_match
        {
            return Err(ConsolidationError::WorkerAuthorizationMismatch);
        }
        Ok(ValidatedNonceAuthorization { coordinator: self, worker })
    }
}

/// Non-cloneable pair consumed at the actual signer/session-tombstone boundary.
pub struct ValidatedNonceAuthorization {
    coordinator: NonceAuthorization,
    worker: SweepSigningAuthorization,
}

/// Canonical storage request for the nonce capability's permanent one-use tombstone.
///
/// The request contains only public commitments. Holding it is not nonce authority: the matching
/// [`ValidatedNonceAuthorization`] can be consumed only with storage's fresh create-new receipt.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ConsolidationNonceTombstone {
    session: SessionId,
    purpose: Vec<u8>,
}

impl ConsolidationNonceTombstone {
    #[must_use]
    pub(crate) const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub(crate) fn purpose(&self) -> &[u8] {
        &self.purpose
    }

    pub(crate) fn purpose_digest(&self) -> [u8; 32] {
        // This exactly matches ProtocolStore's receipt commitment. Keeping the storage domain
        // separate from the canonical consolidation purpose prevents cross-protocol receipts.
        let mut hasher =
            blake3::Hasher::new_derive_key("threshold-monero/session-tombstone-purpose/v1");
        hasher.update(&self.session.0);
        hasher.update(&(self.purpose.len() as u64).to_le_bytes());
        hasher.update(&self.purpose);
        *hasher.finalize().as_bytes()
    }
}

/// Reconstruct the exact public tombstone purpose for crash-stable closure of a durable attempt.
///
/// This is deliberately not nonce authority. It lets recovery idempotently close a released,
/// burned, or quarantined session after the one-use in-memory capability has disappeared.
pub(crate) fn nonce_tombstone_for_attempt(
    authorization: &TransactionAuthorization,
    attempt: &AttemptBinding,
) -> Result<ConsolidationNonceTombstone, ConsolidationError> {
    authorization.validate()?;
    attempt.validate()?;
    if attempt.root_group_key() != authorization.root_group_key() {
        return Err(ConsolidationError::AttemptAuthorizationMismatch);
    }
    Ok(build_nonce_tombstone(
        authorization.id(),
        authorization.digest(),
        attempt,
        attempt.worker_intent_digest(),
    ))
}

fn build_nonce_tombstone(
    consolidation: ConsolidationId,
    authorization: [u8; 32],
    attempt: &AttemptBinding,
    worker_intent: [u8; 32],
) -> ConsolidationNonceTombstone {
    let mut purpose =
        Vec::with_capacity(NONCE_TOMBSTONE_PURPOSE_DOMAIN.len() + 2 + 32 + 32 + 8 + 32 + 32 + 32);
    purpose.extend_from_slice(NONCE_TOMBSTONE_PURPOSE_DOMAIN);
    purpose.extend_from_slice(&NONCE_TOMBSTONE_PURPOSE_VERSION.to_le_bytes());
    purpose.extend_from_slice(&consolidation.0);
    purpose.extend_from_slice(&authorization);
    purpose.extend_from_slice(&attempt.attempt().to_le_bytes());
    purpose.extend_from_slice(&attempt.digest());
    purpose.extend_from_slice(&attempt.session().0);
    purpose.extend_from_slice(&worker_intent);
    ConsolidationNonceTombstone { session: attempt.session(), purpose }
}

impl fmt::Debug for ValidatedNonceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedNonceAuthorization")
            .field("consolidation", &self.coordinator.consolidation)
            .field("sweep", &self.worker.sweep())
            .field("session", &self.worker.session())
            .field("intent_digest", &hex::encode(self.worker.intent_digest()))
            .finish_non_exhaustive()
    }
}

impl ValidatedNonceAuthorization {
    /// Return the exact public purpose which ProtocolStore must claim with create-new semantics.
    #[must_use]
    pub(crate) fn session_tombstone(&self) -> ConsolidationNonceTombstone {
        let attempt = &self.coordinator.attempt;
        build_nonce_tombstone(
            self.coordinator.consolidation,
            self.coordinator.authorization,
            attempt,
            self.worker.intent_digest(),
        )
    }

    /// Invoke FROST only after ProtocolStore freshly created and exactly read back the tombstone.
    ///
    /// An exact pre-existing tombstone deliberately has no receipt and cannot re-authorize nonce
    /// creation after a retry or restart.
    pub(crate) fn consume_after_tombstone<T>(
        self,
        claim: SessionTombstoneClaim,
        boundary: impl FnOnce(
            ConsolidationId,
            [u8; 32],
            &AttemptBinding,
            &SweepSigningAuthorization,
        ) -> T,
    ) -> Result<T, ConsolidationError> {
        let tombstone = self.session_tombstone();
        validate_fresh_tombstone_claim(&tombstone, claim)?;
        Ok(boundary(
            self.coordinator.consolidation,
            self.coordinator.authorization,
            &self.coordinator.attempt,
            &self.worker,
        ))
    }
}

fn validate_fresh_tombstone_claim(
    expected: &ConsolidationNonceTombstone,
    claim: SessionTombstoneClaim,
) -> Result<(), ConsolidationError> {
    let SessionTombstoneClaim::Created(receipt) = claim else {
        return Err(ConsolidationError::SessionTombstoneAlreadyExists);
    };
    validate_tombstone_receipt(expected, receipt)
}

fn validate_tombstone_receipt(
    expected: &ConsolidationNonceTombstone,
    receipt: PersistedSessionTombstoneReceipt,
) -> Result<(), ConsolidationError> {
    if receipt.session() != expected.session
        || receipt.purpose_digest() != expected.purpose_digest()
    {
        return Err(ConsolidationError::SessionTombstoneReceiptMismatch);
    }
    Ok(())
}

/// Action safe to reconstruct after a coordinator restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorAction {
    DisseminateIntent {
        consolidation: ConsolidationId,
    },
    RecoverOrRestart {
        consolidation: ConsolidationId,
        attempt: u64,
    },
    StartFreshAttempt {
        consolidation: ConsolidationId,
        next_attempt: u64,
    },
    /// Propose the exact signed bytes to the portable ledger. This is not broadcast authority.
    ProposePortableCompletion {
        consolidation: ConsolidationId,
        signed: SignedTransactionBinding,
    },
    /// Resume collecting/adopting the exact portable completion certificate after restart.
    /// This is not broadcast authority.
    AwaitPortableCertification {
        consolidation: ConsolidationId,
        signed: SignedTransactionBinding,
    },
    /// Re-broadcast bytes whose initial publication was already durably recorded.
    RebroadcastExact {
        consolidation: ConsolidationId,
        signed: SignedTransactionBinding,
    },
}

/// Durable coordinator state from the perspective of one party.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationCoordinator {
    version: u16,
    wallet: DepositWalletId,
    revision: u64,
    records: BTreeMap<ConsolidationId, ConsolidationRecord>,
}

impl ConsolidationCoordinator {
    pub fn new(wallet: DepositWalletId) -> Result<Self, ConsolidationError> {
        if wallet.0 == [0_u8; 32] {
            return Err(ConsolidationError::WrongWallet);
        }
        Ok(Self {
            version: CONSOLIDATION_STATE_VERSION,
            wallet,
            revision: 0,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn wallet_id(&self) -> DepositWalletId {
        self.wallet
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn record(&self, id: ConsolidationId) -> Option<&ConsolidationRecord> {
        self.records.get(&id)
    }

    /// Return one family's monotonic attempt high-water for durable rollback fencing.
    #[must_use]
    pub fn attempt_high_water(&self, id: ConsolidationId) -> Option<u64> {
        self.records.get(&id).map(ConsolidationRecord::attempt_high_water)
    }

    /// Read-only canonical-order view used by persistence/status integrations.
    pub fn records(
        &self,
    ) -> impl ExactSizeIterator<Item = (&ConsolidationId, &ConsolidationRecord)> {
        self.records.iter()
    }

    /// Resolve the single immutable authorization associated with a worker sweep.
    #[must_use]
    pub fn record_by_sweep(&self, sweep: SweepId) -> Option<&ConsolidationRecord> {
        self.records.values().find(|record| record.authorization.sweep_id() == sweep)
    }

    pub fn reserve_intent(
        &mut self,
        authorization: TransactionAuthorization,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| candidate.reserve_intent_in_place(authorization))
    }

    pub fn release_signing(
        &mut self,
        id: ConsolidationId,
        binding: AttemptBinding,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        self.transactional(move |candidate| candidate.release_signing_in_place(id, binding))
    }

    pub fn burn_attempt_after_restart(
        &mut self,
        id: ConsolidationId,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        self.transactional(move |candidate| candidate.burn_attempt_in_place(id))
    }

    /// Catch up to an authenticated historical Start without ever releasing a nonce capability.
    ///
    /// Followers may advance directly to an authenticated later high-water without materializing
    /// every predecessor. Skipped deterministic sessions remain permanently below the high-water
    /// and therefore can never be released. The supplied exact binding is retained as burned. If
    /// it is the currently released attempt, that attempt is burned. Exact burned or compacted
    /// replays are read-only and idempotent.
    pub fn catch_up_burned_attempt(
        &mut self,
        id: ConsolidationId,
        binding: AttemptBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| candidate.catch_up_burned_attempt_in_place(id, binding))
    }

    pub fn record_signed(
        &mut self,
        id: ConsolidationId,
        signed: SignedTransactionBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| candidate.record_signed_in_place(id, signed))
    }

    /// Adopt an exact portable-certified winner from any known signing attempt.
    ///
    /// A crash-recovery tombstone deliberately prevents recreating an old attempt's nonce
    /// authority; it does not invalidate a threshold result which that attempt had already
    /// produced elsewhere. The caller must supply the complete attempt binding endorsed by the
    /// portable certificate. It must byte-for-byte match a locally retained attempt tombstone,
    /// and the signed binding must match that authorization, session, context, and opaque worker
    /// intent exactly. If a newer attempt is currently released, it is atomically burned and its
    /// session is returned as invalidated only after this mutation is persisted.
    ///
    /// This transition never carries a nonce-release capability.
    pub fn record_portable_signed_attempt(
        &mut self,
        id: ConsolidationId,
        exact_attempt: &AttemptBinding,
        signed: SignedTransactionBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let exact_attempt = exact_attempt.clone();
        self.transactional(move |candidate| {
            candidate.record_portable_signed_attempt_in_place(id, &exact_attempt, signed, false)
        })
    }

    /// Adopt a portable-certified result from an attempt reconstructed by the encrypted worker.
    ///
    /// `verified_attempt` is a sealed capability created only after the service authenticates the
    /// quorum certificate and the worker recomputes its private intent. It may name compacted
    /// history below the high-water. This transition never carries a nonce release.
    pub fn record_verified_portable_signed_attempt(
        &mut self,
        id: ConsolidationId,
        verified_attempt: VerifiedSweepSigningAttempt,
        signed: SignedTransactionBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let sweep = verified_attempt.sweep();
        let exact_attempt = verified_attempt.exact_attempt().clone();
        self.transactional(move |candidate| {
            let record =
                candidate.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
            if record.authorization.sweep_id() != sweep {
                return Err(ConsolidationError::AttemptAuthorizationMismatch);
            }
            candidate.record_portable_signed_attempt_in_place(id, &exact_attempt, signed, true)
        })
    }

    /// Install a fully verified public completion for a party which never retained the private
    /// prepared sweep.
    ///
    /// The service may call this only after authenticating the self-contained completion evidence
    /// and its Byzantine-agreement commit (or the final ledger certificate). The resulting exact
    /// attempt is a terminal high-water/tombstone: it claims the family and session but has no
    /// path to [`NonceAuthorization`], private intent reconstruction, or signing release.
    pub(crate) fn record_certified_public_terminal_completion(
        &mut self,
        authorization: TransactionAuthorization,
        exact_attempt: AttemptBinding,
        signed: SignedTransactionBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| {
            authorization.validate()?;
            if authorization.wallet_id() != candidate.wallet {
                return Err(ConsolidationError::WrongWallet);
            }
            let id = authorization.id();
            if let Some(existing) = candidate.records.get(&id) {
                if existing.authorization != authorization {
                    return Err(ConsolidationError::AuthorizationConflict);
                }
            } else {
                if candidate.record_by_sweep(authorization.sweep_id()).is_some() {
                    return Err(ConsolidationError::SweepAuthorizationConflict);
                }
                if candidate.records.len() >= MAX_CONSOLIDATIONS {
                    return Err(ConsolidationError::StateTooLarge);
                }
                candidate.records.insert(
                    id,
                    ConsolidationRecord {
                        authorization,
                        phase: ConsolidationPhase::IntentReserved,
                        attempt_high_water: 0,
                        attempt_family: None,
                        attempts: BTreeMap::new(),
                        signed: None,
                        confirmation: None,
                    },
                );
            }
            candidate.record_portable_signed_attempt_in_place(id, &exact_attempt, signed, true)
        })
    }

    pub fn mark_broadcast(
        &mut self,
        id: ConsolidationId,
        transaction: [u8; 32],
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| candidate.mark_broadcast_in_place(id, transaction))
    }

    pub fn mark_confirmed(
        &mut self,
        id: ConsolidationId,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| {
            candidate.mark_confirmed_in_place(id, transaction, block)
        })
    }

    /// Adopt an exact same-family transaction proven canonical by the host's chain scanner.
    ///
    /// The host must call this only after independently validating the complete transaction
    /// against the worker's private prepared family and authenticating exact transaction inclusion
    /// at `block`. This public coordinator then checks that the supplied attempt is a byte-exact
    /// retained tombstone and that the signed binding matches its authorization, session,
    /// context, opaque intent, and the independently supplied transaction ID. Canonical chain
    /// evidence may replace a different merely local `Signed` or `Broadcast` candidate. It can
    /// never recreate nonce authority for the winning attempt or any superseded attempt.
    pub fn record_chain_authoritative_settlement(
        &mut self,
        id: ConsolidationId,
        exact_attempt: &AttemptBinding,
        signed: SignedTransactionBinding,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let exact_attempt = exact_attempt.clone();
        self.transactional(move |candidate| {
            candidate.record_chain_authoritative_settlement_in_place(
                id,
                &exact_attempt,
                signed,
                transaction,
                block,
                false,
            )
        })
    }

    /// Record canonical-chain settlement from a worker-reconstructed retained or compacted
    /// attempt. Canonical inclusion and the portable certificate must be authenticated by the
    /// service before obtaining `verified_attempt`; this mutation can never release a nonce.
    pub fn record_verified_chain_authoritative_settlement(
        &mut self,
        id: ConsolidationId,
        verified_attempt: VerifiedSweepSigningAttempt,
        signed: SignedTransactionBinding,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let sweep = verified_attempt.sweep();
        let exact_attempt = verified_attempt.exact_attempt().clone();
        self.transactional(move |candidate| {
            let record =
                candidate.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
            if record.authorization.sweep_id() != sweep {
                return Err(ConsolidationError::AttemptAuthorizationMismatch);
            }
            candidate.record_chain_authoritative_settlement_in_place(
                id,
                &exact_attempt,
                signed,
                transaction,
                block,
                true,
            )
        })
    }

    /// Settle a quorum-abandoned family from an exact archive-prefix member.
    ///
    /// Only the worker can mint `verified` after checking the immutable ROAST archive and current
    /// canonical-chain certificate. The abandoned high-water is required to equal the archived
    /// prefix boundary and is never lowered when an older winning attempt is installed.
    pub fn record_verified_archived_chain_authoritative_settlement(
        &mut self,
        id: ConsolidationId,
        verified: VerifiedArchivedSweepSettlement,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let sweep = verified.sweep();
        let exact_attempt = verified.attempt().clone();
        let signed = verified.signed_binding();
        let transaction = verified.transaction();
        let prefix = verified.prefix();
        let archive_membership_digest = verified.archive_membership_digest();
        let inclusion_certificate_digest = verified.inclusion_certificate_digest();
        let block = verified.inclusion();
        self.transactional(move |candidate| {
            let record =
                candidate.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
            if !matches!(record.phase, ConsolidationPhase::AbandonedByInputReorg { .. }) {
                return Err(ConsolidationError::InvalidPhase);
            }
            if record.authorization.sweep_id() != sweep
                || record.attempt_family.is_none()
                || prefix.family() == [0_u8; 32]
                || prefix.family_anchor() == [0_u8; 32]
                || prefix.accumulator() == [0_u8; 32]
                || prefix.closed_through_view().checked_add(1)
                    != Some(prefix.closed_through_attempt())
                || prefix.closed_through_attempt() != record.attempt_high_water
                || exact_attempt.attempt() > record.attempt_high_water
                || archive_membership_digest == [0_u8; 32]
                || inclusion_certificate_digest == [0_u8; 32]
            {
                return Err(ConsolidationError::AttemptAuthorizationMismatch);
            }
            validate_attempt_provenance(record, &exact_attempt, true)?;
            candidate.record_chain_authoritative_settlement_in_place(
                id,
                &exact_attempt,
                signed,
                transaction,
                block,
                true,
            )
        })
    }

    pub fn rollback_confirmation(
        &mut self,
        id: ConsolidationId,
        retained_ancestor: ChainPoint,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        self.transactional(move |candidate| {
            candidate.rollback_confirmation_in_place(id, retained_ancestor)
        })
    }

    pub fn handle_input_reorg(
        &mut self,
        id: ConsolidationId,
        retained_ancestor: ChainPoint,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        self.transactional(move |candidate| {
            candidate.handle_input_reorg_in_place(id, retained_ancestor)
        })
    }

    /// Install a quorum-certified terminal abandonment for an unsigned quarantined family.
    ///
    /// The certificate and exact attempt must be authenticated by the service. This method may
    /// advance the public high-water and burn intervening attempts, but it never creates a release
    /// effect or any route to [`NonceAuthorization`].
    #[cfg(test)]
    pub(crate) fn record_certified_abandonment(
        &mut self,
        id: ConsolidationId,
        exact_attempt: &AttemptBinding,
        ancestor: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let exact_attempt = exact_attempt.clone();
        self.transactional(move |candidate| {
            candidate.record_certified_abandonment_in_place(id, &exact_attempt, ancestor)
        })
    }

    /// Install a fully verified public abandonment for a party without the private sweep family.
    ///
    /// The service must authenticate the complete abandonment evidence and Byzantine-agreement
    /// commit before calling this method. A newly synthesized record starts directly in the
    /// terminal abandoned phase with one burned attempt tombstone; no transition exposed by this
    /// reducer can turn it into a nonce authorization. Existing private quarantined records use
    /// the same terminal transition and exact replays are idempotent.
    pub(crate) fn record_certified_public_abandonment(
        &mut self,
        authorization: TransactionAuthorization,
        exact_attempt: AttemptBinding,
        ancestor: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        self.transactional(move |candidate| {
            authorization.validate()?;
            exact_attempt.validate()?;
            validate_chain_point(ancestor)?;
            if authorization.wallet_id() != candidate.wallet {
                return Err(ConsolidationError::WrongWallet);
            }
            if exact_attempt.root_group_key() != authorization.root_group_key()
                || derive_sweep_signing_session(
                    authorization.wallet_id(),
                    authorization.sweep_id(),
                    exact_attempt.attempt(),
                ) != Some(exact_attempt.session())
            {
                return Err(ConsolidationError::AttemptAuthorizationMismatch);
            }
            let id = authorization.id();
            if let Some(existing) = candidate.records.get(&id) {
                if existing.authorization != authorization {
                    return Err(ConsolidationError::AuthorizationConflict);
                }
                return candidate.record_certified_abandonment_in_place(
                    id,
                    &exact_attempt,
                    ancestor,
                );
            }
            if candidate.record_by_sweep(authorization.sweep_id()).is_some() {
                return Err(ConsolidationError::SweepAuthorizationConflict);
            }
            if candidate.records.len() >= MAX_CONSOLIDATIONS {
                return Err(ConsolidationError::StateTooLarge);
            }
            let attempt_number = exact_attempt.attempt();
            candidate.records.insert(
                id,
                ConsolidationRecord {
                    authorization,
                    phase: ConsolidationPhase::AbandonedByInputReorg { ancestor },
                    attempt_high_water: attempt_number,
                    attempt_family: Some(AttemptFamilyBinding::from_attempt(&exact_attempt)),
                    attempts: BTreeMap::from([(
                        attempt_number,
                        AttemptTombstone {
                            binding: exact_attempt,
                            status: AttemptStatus::BurnedAfterRestart,
                        },
                    )]),
                    signed: None,
                    confirmation: None,
                },
            );
            candidate.finish_mutation(None, None).map(Some)
        })
    }

    pub fn abort_before_nonce(
        &mut self,
        id: ConsolidationId,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        self.transactional(move |candidate| candidate.abort_before_nonce_in_place(id))
    }

    /// Reserve an exact worker-owned intent. Exact retries are read-only and idempotent.
    fn reserve_intent_in_place(
        &mut self,
        authorization: TransactionAuthorization,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        authorization.validate()?;
        if authorization.wallet != self.wallet {
            return Err(ConsolidationError::WrongWallet);
        }
        if let Some(existing) = self.records.get(&authorization.id) {
            return if existing.authorization == authorization {
                Ok(None)
            } else {
                Err(ConsolidationError::AuthorizationConflict)
            };
        }
        if self.record_by_sweep(authorization.sweep_id()).is_some() {
            return Err(ConsolidationError::SweepAuthorizationConflict);
        }
        if self.records.len() >= MAX_CONSOLIDATIONS {
            return Err(ConsolidationError::StateTooLarge);
        }
        self.records.insert(
            authorization.id,
            ConsolidationRecord {
                authorization,
                phase: ConsolidationPhase::IntentReserved,
                attempt_high_water: 0,
                attempt_family: None,
                attempts: BTreeMap::new(),
                signed: None,
                confirmation: None,
            },
        );
        self.finish_mutation(None, None).map(Some)
    }

    /// Persist the complete epoch/session/signer/transaction binding before nonce creation.
    fn release_signing_in_place(
        &mut self,
        id: ConsolidationId,
        binding: AttemptBinding,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        binding.validate()?;
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if binding.root_group_key != record.authorization.root_group_key {
            return Err(ConsolidationError::AttemptAuthorizationMismatch);
        }
        let expected_attempt =
            record.attempt_high_water.checked_add(1).ok_or(ConsolidationError::AttemptExhausted)?;
        let may_release = match record.phase {
            ConsolidationPhase::IntentReserved => record.attempt_high_water == 0,
            ConsolidationPhase::AwaitingFreshAttempt { burned_attempt } => {
                burned_attempt.checked_add(1) == Some(expected_attempt)
            }
            _ => false,
        };
        if !may_release || binding.attempt != expected_attempt {
            return Err(ConsolidationError::InvalidPhase);
        }
        if derive_sweep_signing_session(
            record.authorization.wallet_id(),
            record.authorization.sweep_id(),
            binding.attempt,
        ) != Some(binding.session)
        {
            return Err(ConsolidationError::InvalidAttempt);
        }
        if let Some(family) = record.attempt_family {
            if !family.matches(&binding) {
                return Err(ConsolidationError::AttemptAuthorizationMismatch);
            }
        } else {
            record.attempt_family = Some(AttemptFamilyBinding::from_attempt(&binding));
        }
        let attempt = binding.attempt;
        record
            .attempts
            .insert(attempt, AttemptTombstone { binding, status: AttemptStatus::SigningReleased });
        record.attempt_high_water = attempt;
        record.phase = ConsolidationPhase::SigningReleased { attempt };
        compact_burned_attempts(record)?;
        self.finish_mutation(Some((id, attempt)), None)
    }

    /// Consume the release effect only after the exact revision has reached durable storage.
    pub fn nonce_action_after_persist(
        &self,
        receipt: ConsolidationPersistedReceipt,
    ) -> Result<NonceAuthorization, ConsolidationError> {
        self.verify_receipt(&receipt)?;
        let (id, attempt) = receipt.release.ok_or(ConsolidationError::PersistenceMismatch)?;
        if receipt.signed.is_some() {
            return Err(ConsolidationError::PersistenceMismatch);
        }
        let record = self.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if record.phase != (ConsolidationPhase::SigningReleased { attempt }) {
            return Err(ConsolidationError::InvalidPhase);
        }
        let tombstone = record.attempts.get(&attempt).ok_or(ConsolidationError::InvalidState)?;
        if tombstone.status != AttemptStatus::SigningReleased {
            return Err(ConsolidationError::InvalidPhase);
        }
        Ok(NonceAuthorization {
            consolidation: id,
            authorization: record.authorization.digest(),
            sweep: record.authorization.sweep_id(),
            attempt: tombstone.binding.clone(),
        })
    }

    /// Burn an uncertain in-flight session after restart. It can never authorize another nonce.
    fn burn_attempt_in_place(
        &mut self,
        id: ConsolidationId,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        let ConsolidationPhase::SigningReleased { attempt } = record.phase else {
            return Err(ConsolidationError::InvalidPhase);
        };
        let tombstone =
            record.attempts.get_mut(&attempt).ok_or(ConsolidationError::InvalidState)?;
        if tombstone.status != AttemptStatus::SigningReleased {
            return Err(ConsolidationError::InvalidState);
        }
        tombstone.status = AttemptStatus::BurnedAfterRestart;
        record.phase = if attempt == u64::MAX {
            ConsolidationPhase::AttemptsExhausted { burned_attempt: attempt }
        } else {
            ConsolidationPhase::AwaitingFreshAttempt { burned_attempt: attempt }
        };
        compact_burned_attempts(record)?;
        self.finish_mutation(None, None)
    }

    fn catch_up_burned_attempt_in_place(
        &mut self,
        id: ConsolidationId,
        binding: AttemptBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        binding.validate()?;
        let record = self.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if binding.root_group_key != record.authorization.root_group_key {
            return Err(ConsolidationError::AttemptAuthorizationMismatch);
        }
        if derive_sweep_signing_session(
            record.authorization.wallet_id(),
            record.authorization.sweep_id(),
            binding.attempt,
        ) != Some(binding.session)
            || record.attempt_family.is_some_and(|family| !family.matches(&binding))
        {
            return Err(ConsolidationError::InvalidAttempt);
        }

        if let Some(existing) = record.attempts.get(&binding.attempt) {
            if existing.binding != binding {
                return Err(ConsolidationError::InvalidAttempt);
            }
            return match existing.status {
                AttemptStatus::BurnedAfterRestart => Ok(None),
                AttemptStatus::SigningReleased
                    if record.phase
                        == (ConsolidationPhase::SigningReleased { attempt: binding.attempt }) =>
                {
                    self.burn_attempt_in_place(id).map(Some)
                }
                AttemptStatus::SigningReleased | AttemptStatus::Completed => {
                    Err(ConsolidationError::InvalidPhase)
                }
            };
        }

        // An authenticated replay below the high-water names compacted burned history. It is
        // intentionally read-only: no persistence effect and no nonce-release capability exist.
        if binding.attempt <= record.attempt_high_water {
            return Ok(None);
        }

        let may_synthesize = match record.phase {
            ConsolidationPhase::IntentReserved => record.attempt_high_water == 0,
            ConsolidationPhase::AwaitingFreshAttempt { burned_attempt } => {
                burned_attempt == record.attempt_high_water
            }
            _ => false,
        };
        if !may_synthesize || binding.attempt <= record.attempt_high_water {
            return Err(ConsolidationError::InvalidPhase);
        }

        let attempt = binding.attempt;
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if record.attempt_family.is_none() {
            record.attempt_family = Some(AttemptFamilyBinding::from_attempt(&binding));
        }
        record.attempts.insert(
            attempt,
            AttemptTombstone { binding, status: AttemptStatus::BurnedAfterRestart },
        );
        record.attempt_high_water = attempt;
        record.phase = if attempt == u64::MAX {
            ConsolidationPhase::AttemptsExhausted { burned_attempt: attempt }
        } else {
            ConsolidationPhase::AwaitingFreshAttempt { burned_attempt: attempt }
        };
        compact_burned_attempts(record)?;
        self.finish_mutation(None, None).map(Some)
    }

    /// Store the public binding to exact signed bytes before any response or RPC submission.
    fn record_signed_in_place(
        &mut self,
        id: ConsolidationId,
        signed: SignedTransactionBinding,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        signed.validate()?;
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        let attempt = match record.phase {
            ConsolidationPhase::SigningReleased { attempt } => attempt,
            ConsolidationPhase::Signed
            | ConsolidationPhase::Broadcast
            | ConsolidationPhase::Confirmed
            | ConsolidationPhase::QuarantinedByInputReorg { .. }
            | ConsolidationPhase::AbandonedByInputReorg { .. } => {
                return if record.signed == Some(signed) {
                    Ok(None)
                } else {
                    Err(ConsolidationError::SignedTransactionMismatch)
                };
            }
            _ => return Err(ConsolidationError::InvalidPhase),
        };
        let tombstone =
            record.attempts.get_mut(&attempt).ok_or(ConsolidationError::InvalidState)?;
        if signed.authorization != record.authorization.digest()
            || signed.attempt != attempt
            || signed.attempt_binding != tombstone.binding.digest()
            || signed.session != tombstone.binding.session
            || signed.signing_context != tombstone.binding.signing_context
            || signed.opaque_intent != record.authorization.opaque_intent
        {
            return Err(ConsolidationError::SignedTransactionMismatch);
        }
        if tombstone.status != AttemptStatus::SigningReleased {
            return Err(ConsolidationError::InvalidState);
        }
        tombstone.status = AttemptStatus::Completed;
        record.signed = Some(signed);
        record.phase = ConsolidationPhase::Signed;
        self.finish_mutation(None, Some(id)).map(Some)
    }

    fn record_portable_signed_attempt_in_place(
        &mut self,
        id: ConsolidationId,
        exact_attempt: &AttemptBinding,
        signed: SignedTransactionBinding,
        allow_compacted: bool,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        exact_attempt.validate()?;
        signed.validate()?;
        let record = self.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        validate_attempt_provenance(record, exact_attempt, allow_compacted)?;
        if signed.authorization != record.authorization.digest()
            || signed.attempt != exact_attempt.attempt
            || signed.attempt_binding != exact_attempt.digest()
            || signed.session != exact_attempt.session
            || signed.signing_context != exact_attempt.signing_context
            || signed.opaque_intent != record.authorization.opaque_intent
        {
            return Err(ConsolidationError::SignedTransactionMismatch);
        }
        if record.signed == Some(signed) {
            return match record.phase {
                ConsolidationPhase::Signed
                | ConsolidationPhase::Broadcast
                | ConsolidationPhase::Confirmed
                | ConsolidationPhase::QuarantinedByInputReorg { .. }
                | ConsolidationPhase::AbandonedByInputReorg { .. } => Ok(None),
                _ => Err(ConsolidationError::InvalidState),
            };
        }
        match record.phase {
            ConsolidationPhase::SigningReleased { .. }
            | ConsolidationPhase::AwaitingFreshAttempt { .. }
            | ConsolidationPhase::AttemptsExhausted { .. }
            | ConsolidationPhase::Signed => {}
            ConsolidationPhase::Broadcast
            | ConsolidationPhase::Confirmed
            | ConsolidationPhase::QuarantinedByInputReorg { .. }
            | ConsolidationPhase::AbandonedByInputReorg { .. } => {
                return Err(ConsolidationError::SignedTransactionMismatch);
            }
            ConsolidationPhase::IntentReserved if allow_compacted => {}
            ConsolidationPhase::IntentReserved | ConsolidationPhase::AbortedBeforeNonce => {
                return Err(ConsolidationError::InvalidPhase);
            }
        }

        let invalidated_session = match record.phase {
            ConsolidationPhase::SigningReleased { attempt } if attempt != exact_attempt.attempt => {
                Some(
                    record
                        .attempts
                        .get(&attempt)
                        .ok_or(ConsolidationError::InvalidState)?
                        .binding
                        .session,
                )
            }
            _ => None,
        };
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if exact_attempt.attempt > record.attempt_high_water {
            record.attempt_high_water = exact_attempt.attempt;
        }
        if record.attempt_family.is_none() {
            record.attempt_family = Some(AttemptFamilyBinding::from_attempt(exact_attempt));
        }
        for (attempt, tombstone) in &mut record.attempts {
            tombstone.status = if *attempt == exact_attempt.attempt {
                AttemptStatus::Completed
            } else {
                AttemptStatus::BurnedAfterRestart
            };
        }
        record.attempts.entry(exact_attempt.attempt).or_insert_with(|| AttemptTombstone {
            binding: exact_attempt.clone(),
            status: AttemptStatus::Completed,
        });
        compact_burned_attempts(record)?;
        record.signed = Some(signed);
        record.phase = ConsolidationPhase::Signed;
        let mut effect = self.finish_mutation(None, Some(id))?;
        effect.invalidated_session = invalidated_session;
        Ok(Some(effect))
    }

    fn record_certified_abandonment_in_place(
        &mut self,
        id: ConsolidationId,
        exact_attempt: &AttemptBinding,
        ancestor: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        exact_attempt.validate()?;
        validate_chain_point(ancestor)?;
        let record = self.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        validate_attempt_provenance(record, exact_attempt, true)?;
        if record.signed.is_some() || record.confirmation.is_some() {
            return Err(ConsolidationError::InvalidPhase);
        }
        match record.phase {
            ConsolidationPhase::AbandonedByInputReorg { ancestor: known } if known == ancestor => {
                return Ok(None);
            }
            ConsolidationPhase::QuarantinedByInputReorg { ancestor: known }
                if known == ancestor => {}
            ConsolidationPhase::QuarantinedByInputReorg { .. }
            | ConsolidationPhase::AbandonedByInputReorg { .. } => {
                return Err(ConsolidationError::InvalidChainPoint);
            }
            _ => return Err(ConsolidationError::InvalidPhase),
        }

        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if exact_attempt.attempt > record.attempt_high_water {
            record.attempt_high_water = exact_attempt.attempt;
        }
        if record.attempt_family.is_none() {
            record.attempt_family = Some(AttemptFamilyBinding::from_attempt(exact_attempt));
        }
        for tombstone in record.attempts.values_mut() {
            tombstone.status = AttemptStatus::BurnedAfterRestart;
        }
        record.attempts.entry(exact_attempt.attempt).or_insert_with(|| AttemptTombstone {
            binding: exact_attempt.clone(),
            status: AttemptStatus::BurnedAfterRestart,
        });
        compact_burned_attempts(record)?;
        record.phase = ConsolidationPhase::AbandonedByInputReorg { ancestor };
        self.finish_mutation(None, None).map(Some)
    }

    /// Reconstruct the exact portable-ledger proposal only after signed state is durable.
    ///
    /// A signed-state receipt is deliberately not broadcast authority. The service must first
    /// atomically adopt an exact matching portable completion certificate, publish the exact
    /// certified bytes, and durably transition this coordinator to `Broadcast`.
    pub fn signed_action_after_persist(
        &self,
        receipt: ConsolidationPersistedReceipt,
    ) -> Result<CoordinatorAction, ConsolidationError> {
        self.verify_receipt(&receipt)?;
        let id = receipt.signed.ok_or(ConsolidationError::PersistenceMismatch)?;
        if receipt.release.is_some() {
            return Err(ConsolidationError::PersistenceMismatch);
        }
        let record = self.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if record.phase != ConsolidationPhase::Signed {
            return Err(ConsolidationError::InvalidPhase);
        }
        let signed = record.signed.ok_or(ConsolidationError::InvalidState)?;
        Ok(CoordinatorAction::ProposePortableCompletion { consolidation: id, signed })
    }

    fn mark_broadcast_in_place(
        &mut self,
        id: ConsolidationId,
        transaction: [u8; 32],
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        let signed = record.signed.ok_or(ConsolidationError::InvalidPhase)?;
        if transaction != signed.transaction {
            return Err(ConsolidationError::SignedTransactionMismatch);
        }
        match record.phase {
            ConsolidationPhase::Signed => {
                record.phase = ConsolidationPhase::Broadcast;
                self.finish_mutation(None, None).map(Some)
            }
            ConsolidationPhase::Broadcast => Ok(None),
            _ => Err(ConsolidationError::InvalidPhase),
        }
    }

    fn mark_confirmed_in_place(
        &mut self,
        id: ConsolidationId,
        transaction: [u8; 32],
        block: ChainPoint,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        validate_chain_point(block)?;
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        let signed = record.signed.ok_or(ConsolidationError::InvalidPhase)?;
        if transaction != signed.transaction {
            return Err(ConsolidationError::SignedTransactionMismatch);
        }
        match record.phase {
            ConsolidationPhase::Broadcast => {
                record.confirmation = Some(block);
                record.phase = ConsolidationPhase::Confirmed;
                self.finish_mutation(None, None).map(Some)
            }
            ConsolidationPhase::Confirmed if record.confirmation == Some(block) => Ok(None),
            _ => Err(ConsolidationError::InvalidPhase),
        }
    }

    fn record_chain_authoritative_settlement_in_place(
        &mut self,
        id: ConsolidationId,
        exact_attempt: &AttemptBinding,
        signed: SignedTransactionBinding,
        transaction: [u8; 32],
        block: ChainPoint,
        allow_compacted: bool,
    ) -> Result<Option<ConsolidationPersistEffect>, ConsolidationError> {
        exact_attempt.validate()?;
        signed.validate()?;
        validate_chain_point(block)?;
        let record = self.records.get(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        validate_attempt_provenance(record, exact_attempt, allow_compacted)?;
        if signed.authorization != record.authorization.digest()
            || signed.attempt != exact_attempt.attempt
            || signed.attempt_binding != exact_attempt.digest()
            || signed.session != exact_attempt.session
            || signed.signing_context != exact_attempt.signing_context
            || signed.opaque_intent != record.authorization.opaque_intent
            || signed.transaction != transaction
        {
            return Err(ConsolidationError::SignedTransactionMismatch);
        }
        if record.phase == ConsolidationPhase::Confirmed {
            return if record.signed == Some(signed) && record.confirmation == Some(block) {
                Ok(None)
            } else {
                Err(ConsolidationError::ConflictingChainSettlement)
            };
        }
        match record.phase {
            ConsolidationPhase::SigningReleased { .. }
            | ConsolidationPhase::AwaitingFreshAttempt { .. }
            | ConsolidationPhase::AttemptsExhausted { .. }
            | ConsolidationPhase::Signed
            | ConsolidationPhase::Broadcast
            | ConsolidationPhase::QuarantinedByInputReorg { .. }
            | ConsolidationPhase::AbandonedByInputReorg { .. } => {}
            ConsolidationPhase::IntentReserved if allow_compacted => {}
            ConsolidationPhase::IntentReserved
            | ConsolidationPhase::Confirmed
            | ConsolidationPhase::AbortedBeforeNonce => {
                return Err(ConsolidationError::InvalidPhase);
            }
        }

        let invalidated_session = match record.phase {
            ConsolidationPhase::SigningReleased { attempt } => Some(
                record
                    .attempts
                    .get(&attempt)
                    .ok_or(ConsolidationError::InvalidState)?
                    .binding
                    .session,
            ),
            _ => None,
        };
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if exact_attempt.attempt > record.attempt_high_water {
            record.attempt_high_water = exact_attempt.attempt;
        }
        if record.attempt_family.is_none() {
            record.attempt_family = Some(AttemptFamilyBinding::from_attempt(exact_attempt));
        }
        for (attempt, tombstone) in &mut record.attempts {
            tombstone.status = if *attempt == exact_attempt.attempt {
                AttemptStatus::Completed
            } else {
                AttemptStatus::BurnedAfterRestart
            };
        }
        record.attempts.entry(exact_attempt.attempt).or_insert_with(|| AttemptTombstone {
            binding: exact_attempt.clone(),
            status: AttemptStatus::Completed,
        });
        compact_burned_attempts(record)?;
        record.signed = Some(signed);
        record.confirmation = Some(block);
        record.phase = ConsolidationPhase::Confirmed;
        let mut effect = self.finish_mutation(None, None)?;
        effect.invalidated_session = invalidated_session;
        Ok(Some(effect))
    }

    /// Roll back only the confirmation; exact signed bytes remain eligible for rebroadcast.
    fn rollback_confirmation_in_place(
        &mut self,
        id: ConsolidationId,
        retained_ancestor: ChainPoint,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        validate_chain_point(retained_ancestor)?;
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if record.phase != ConsolidationPhase::Confirmed {
            return Err(ConsolidationError::InvalidPhase);
        }
        let confirmation = record.confirmation.ok_or(ConsolidationError::InvalidState)?;
        if retained_ancestor.height >= confirmation.height {
            return Err(ConsolidationError::InvalidChainPoint);
        }
        record.confirmation = None;
        record.phase = ConsolidationPhase::Broadcast;
        self.finish_mutation(None, None)
    }

    /// Handle disappearance of an authorized input. Any nonce-bearing attempt is quarantined.
    fn handle_input_reorg_in_place(
        &mut self,
        id: ConsolidationId,
        retained_ancestor: ChainPoint,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        validate_chain_point(retained_ancestor)?;
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        let mut invalidated_session = None;
        match record.phase {
            ConsolidationPhase::IntentReserved => {
                if record.attempt_high_water != 0 || !record.attempts.is_empty() {
                    return Err(ConsolidationError::InvalidState);
                }
                record.phase = ConsolidationPhase::AbortedBeforeNonce;
            }
            ConsolidationPhase::SigningReleased { attempt } => {
                let tombstone =
                    record.attempts.get_mut(&attempt).ok_or(ConsolidationError::InvalidState)?;
                if tombstone.status != AttemptStatus::SigningReleased {
                    return Err(ConsolidationError::InvalidState);
                }
                tombstone.status = AttemptStatus::BurnedAfterRestart;
                invalidated_session = Some(tombstone.binding.session());
                record.confirmation = None;
                record.phase =
                    ConsolidationPhase::QuarantinedByInputReorg { ancestor: retained_ancestor };
            }
            ConsolidationPhase::AwaitingFreshAttempt { .. }
            | ConsolidationPhase::AttemptsExhausted { .. }
            | ConsolidationPhase::Signed
            | ConsolidationPhase::Broadcast
            | ConsolidationPhase::Confirmed => {
                record.confirmation = None;
                record.phase =
                    ConsolidationPhase::QuarantinedByInputReorg { ancestor: retained_ancestor };
            }
            ConsolidationPhase::QuarantinedByInputReorg { ancestor }
                if ancestor == retained_ancestor =>
            {
                return Err(ConsolidationError::NoMutation);
            }
            ConsolidationPhase::QuarantinedByInputReorg { .. } => {
                // Scanner rollbacks may discover a different retained ancestor later. Preserve
                // every signed binding and permanent attempt tombstone while advancing the exact
                // durable quarantine point.
                record.phase =
                    ConsolidationPhase::QuarantinedByInputReorg { ancestor: retained_ancestor };
            }
            ConsolidationPhase::AbandonedByInputReorg { ancestor }
                if ancestor == retained_ancestor =>
            {
                return Err(ConsolidationError::NoMutation);
            }
            ConsolidationPhase::AbandonedByInputReorg { .. } => {
                record.phase =
                    ConsolidationPhase::AbandonedByInputReorg { ancestor: retained_ancestor };
            }
            ConsolidationPhase::AbortedBeforeNonce => {
                return Err(ConsolidationError::InvalidPhase);
            }
        }
        let mut effect = self.finish_mutation(None, None)?;
        effect.invalidated_session = invalidated_session;
        Ok(effect)
    }

    /// Release a reservation only while no nonce-bearing session has ever existed.
    fn abort_before_nonce_in_place(
        &mut self,
        id: ConsolidationId,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        let record = self.records.get_mut(&id).ok_or(ConsolidationError::UnknownConsolidation)?;
        if record.phase != ConsolidationPhase::IntentReserved
            || record.attempt_high_water != 0
            || !record.attempts.is_empty()
        {
            return Err(ConsolidationError::CannotAbortAfterSigningRelease);
        }
        record.phase = ConsolidationPhase::AbortedBeforeNonce;
        self.finish_mutation(None, None)
    }

    /// Rebuild all safe work after restart without ever re-authorizing an old nonce session.
    #[must_use]
    pub fn restart_actions(&self) -> Vec<CoordinatorAction> {
        let mut actions = Vec::new();
        for (id, record) in &self.records {
            match record.phase {
                ConsolidationPhase::IntentReserved => {
                    actions.push(CoordinatorAction::DisseminateIntent { consolidation: *id });
                }
                ConsolidationPhase::SigningReleased { attempt } => {
                    actions
                        .push(CoordinatorAction::RecoverOrRestart { consolidation: *id, attempt });
                }
                ConsolidationPhase::AwaitingFreshAttempt { burned_attempt } => {
                    if let Some(next_attempt) = record.attempt_high_water.checked_add(1) {
                        debug_assert_eq!(burned_attempt, record.attempt_high_water);
                        actions.push(CoordinatorAction::StartFreshAttempt {
                            consolidation: *id,
                            next_attempt,
                        });
                    }
                }
                ConsolidationPhase::Signed => {
                    if let Some(signed) = record.signed {
                        actions.push(CoordinatorAction::AwaitPortableCertification {
                            consolidation: *id,
                            signed,
                        });
                    }
                }
                ConsolidationPhase::Broadcast => {
                    if let Some(signed) = record.signed {
                        actions.push(CoordinatorAction::RebroadcastExact {
                            consolidation: *id,
                            signed,
                        });
                    }
                }
                ConsolidationPhase::Confirmed
                | ConsolidationPhase::AttemptsExhausted { .. }
                | ConsolidationPhase::AbortedBeforeNonce
                | ConsolidationPhase::QuarantinedByInputReorg { .. }
                | ConsolidationPhase::AbandonedByInputReorg { .. } => {}
            }
        }
        actions
    }

    /// Canonical bounded plaintext encoding. Callers should place it in encrypted storage.
    pub fn encode(&self) -> Result<Vec<u8>, ConsolidationError> {
        self.validate()?;
        let encoded = postcard::to_allocvec(self).map_err(|_| ConsolidationError::Serialization)?;
        if encoded.len() > MAX_CONSOLIDATION_STATE_BYTES {
            return Err(ConsolidationError::StateTooLarge);
        }
        Ok(encoded)
    }

    /// Restore and fully validate session tombstones, phase relationships, and canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ConsolidationError> {
        if bytes.len() > MAX_CONSOLIDATION_STATE_BYTES {
            return Err(ConsolidationError::StateTooLarge);
        }
        let state: Self =
            postcard::from_bytes(bytes).map_err(|_| ConsolidationError::Serialization)?;
        let canonical =
            postcard::to_allocvec(&state).map_err(|_| ConsolidationError::Serialization)?;
        if canonical != bytes {
            return Err(ConsolidationError::NonCanonicalState);
        }
        state.validate()?;
        Ok(state)
    }

    fn transactional<T>(
        &mut self,
        mutation: impl FnOnce(&mut Self) -> Result<T, ConsolidationError>,
    ) -> Result<T, ConsolidationError> {
        self.validate()?;
        let mut candidate = Self {
            version: self.version,
            wallet: self.wallet,
            revision: self.revision,
            records: self.records.clone(),
        };
        let result = mutation(&mut candidate)?;
        candidate.validate()?;
        *self = candidate;
        Ok(result)
    }

    fn finish_mutation(
        &mut self,
        release: Option<(ConsolidationId, u64)>,
        signed: Option<ConsolidationId>,
    ) -> Result<ConsolidationPersistEffect, ConsolidationError> {
        self.revision =
            self.revision.checked_add(1).ok_or(ConsolidationError::RevisionExhausted)?;
        self.validate()?;
        Ok(ConsolidationPersistEffect {
            revision: self.revision,
            state_commitment: self.state_commitment()?,
            release,
            signed,
            invalidated_session: None,
        })
    }

    /// Mint a sealed receipt only after the repository reports an exact CAS revision/commitment.
    /// Persistence adapters must call this with values read back from the successful durable CAS.
    pub(crate) fn persisted_receipt_after_cas(
        &self,
        effect: ConsolidationPersistEffect,
        persisted_revision: u64,
        persisted_state_commitment: [u8; 32],
    ) -> Result<ConsolidationPersistedReceipt, ConsolidationError> {
        if effect.revision != self.revision
            || persisted_revision != self.revision
            || persisted_state_commitment != effect.state_commitment
            || effect.state_commitment != self.state_commitment()?
        {
            return Err(ConsolidationError::PersistenceMismatch);
        }
        Ok(ConsolidationPersistedReceipt {
            revision: effect.revision,
            state_commitment: effect.state_commitment,
            release: effect.release,
            signed: effect.signed,
        })
    }

    fn verify_receipt(
        &self,
        receipt: &ConsolidationPersistedReceipt,
    ) -> Result<(), ConsolidationError> {
        if receipt.revision != self.revision
            || receipt.state_commitment != self.state_commitment()?
        {
            return Err(ConsolidationError::PersistenceMismatch);
        }
        Ok(())
    }

    fn state_commitment(&self) -> Result<[u8; 32], ConsolidationError> {
        let encoded = postcard::to_allocvec(self).map_err(|_| ConsolidationError::Serialization)?;
        if encoded.len() > MAX_CONSOLIDATION_STATE_BYTES {
            return Err(ConsolidationError::StateTooLarge);
        }
        let mut hasher = blake3::Hasher::new_derive_key("threshold-monero/consolidation-state/v2");
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    fn validate(&self) -> Result<(), ConsolidationError> {
        if self.version != CONSOLIDATION_STATE_VERSION {
            return Err(ConsolidationError::UnsupportedStateVersion(self.version));
        }
        if self.wallet.0 == [0_u8; 32] {
            return Err(ConsolidationError::WrongWallet);
        }
        if self.records.len() > MAX_CONSOLIDATIONS {
            return Err(ConsolidationError::StateTooLarge);
        }
        let mut retained_sessions = std::collections::BTreeSet::new();
        let mut rebuilt_sweeps = BTreeMap::new();
        for (id, record) in &self.records {
            record.authorization.validate()?;
            if *id != record.authorization.id || record.authorization.wallet != self.wallet {
                return Err(ConsolidationError::InvalidState);
            }
            if rebuilt_sweeps.insert(record.authorization.sweep_id(), *id).is_some() {
                return Err(ConsolidationError::SweepAuthorizationConflict);
            }
            if record.attempts.len() > MAX_RETAINED_CONSOLIDATION_ATTEMPTS
                || (record.attempt_high_water == 0
                    && (record.attempt_family.is_some() || !record.attempts.is_empty()))
                || (record.attempt_high_water != 0 && record.attempt_family.is_none())
            {
                return Err(ConsolidationError::TooManyAttempts);
            }
            for (attempt, tombstone) in &record.attempts {
                tombstone.binding.validate()?;
                if *attempt == 0
                    || *attempt > record.attempt_high_water
                    || tombstone.binding.attempt != *attempt
                    || tombstone.binding.root_group_key != record.authorization.root_group_key
                    || record
                        .attempt_family
                        .is_none_or(|family| !family.matches(&tombstone.binding))
                    || derive_sweep_signing_session(
                        record.authorization.wallet_id(),
                        record.authorization.sweep_id(),
                        *attempt,
                    ) != Some(tombstone.binding.session)
                {
                    return Err(ConsolidationError::InvalidState);
                }
                if !retained_sessions.insert(tombstone.binding.session) {
                    return Err(ConsolidationError::SessionAlreadyUsed);
                }
            }
            validate_record(record)?;
        }
        Ok(())
    }
}

fn validate_attempt_provenance(
    record: &ConsolidationRecord,
    exact_attempt: &AttemptBinding,
    allow_compacted: bool,
) -> Result<(), ConsolidationError> {
    if exact_attempt.attempt == 0
        || (!allow_compacted && exact_attempt.attempt > record.attempt_high_water)
        || exact_attempt.root_group_key != record.authorization.root_group_key
        || record.attempt_family.is_some_and(|family| !family.matches(exact_attempt))
        || derive_sweep_signing_session(
            record.authorization.wallet_id(),
            record.authorization.sweep_id(),
            exact_attempt.attempt,
        ) != Some(exact_attempt.session)
    {
        return Err(ConsolidationError::InvalidAttempt);
    }
    match record.attempts.get(&exact_attempt.attempt) {
        Some(tombstone) if tombstone.binding == *exact_attempt => Ok(()),
        Some(_) => Err(ConsolidationError::InvalidAttempt),
        None if allow_compacted => Ok(()),
        None => Err(ConsolidationError::InvalidAttempt),
    }
}

fn compact_burned_attempts(record: &mut ConsolidationRecord) -> Result<(), ConsolidationError> {
    while record.attempts.len() > MAX_RETAINED_CONSOLIDATION_ATTEMPTS {
        let oldest_burned = record
            .attempts
            .iter()
            .find_map(|(attempt, tombstone)| {
                (tombstone.status == AttemptStatus::BurnedAfterRestart).then_some(*attempt)
            })
            .ok_or(ConsolidationError::TooManyAttempts)?;
        record.attempts.remove(&oldest_burned);
    }
    Ok(())
}

fn validate_record(record: &ConsolidationRecord) -> Result<(), ConsolidationError> {
    if record.signed.is_none() && record.attempt_high_water != 0 {
        for (attempt, tombstone) in &record.attempts {
            if *attempt != record.attempt_high_water
                && tombstone.status != AttemptStatus::BurnedAfterRestart
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
    }
    let completed: Vec<u64> = record
        .attempts
        .iter()
        .filter_map(|(attempt, tombstone)| {
            (tombstone.status == AttemptStatus::Completed).then_some(*attempt)
        })
        .collect();
    let signed = match record.signed {
        Some(signed) => {
            signed.validate()?;
            let attempt =
                record.attempts.get(&signed.attempt).ok_or(ConsolidationError::InvalidState)?;
            if signed.authorization != record.authorization.digest()
                || signed.attempt_binding != attempt.binding.digest()
                || signed.session != attempt.binding.session
                || attempt.status != AttemptStatus::Completed
                || signed.signing_context != attempt.binding.signing_context
                || signed.opaque_intent != record.authorization.opaque_intent
                || completed.as_slice() != [signed.attempt]
                || record.attempts.iter().any(|(number, tombstone)| {
                    if *number == signed.attempt {
                        tombstone.status != AttemptStatus::Completed
                    } else {
                        tombstone.status != AttemptStatus::BurnedAfterRestart
                    }
                })
            {
                return Err(ConsolidationError::InvalidState);
            }
            Some(signed)
        }
        None => {
            if !completed.is_empty() {
                return Err(ConsolidationError::InvalidState);
            }
            None
        }
    };
    match record.phase {
        ConsolidationPhase::IntentReserved | ConsolidationPhase::AbortedBeforeNonce => {
            if record.attempt_high_water != 0
                || record.attempt_family.is_some()
                || !record.attempts.is_empty()
                || signed.is_some()
                || record.confirmation.is_some()
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
        ConsolidationPhase::SigningReleased { attempt } => {
            if signed.is_some()
                || record.confirmation.is_some()
                || attempt != record.attempt_high_water
                || record.attempts.get(&attempt).map(|tombstone| (attempt, tombstone.status))
                    != Some((attempt, AttemptStatus::SigningReleased))
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
        ConsolidationPhase::AwaitingFreshAttempt { burned_attempt } => {
            if signed.is_some()
                || record.confirmation.is_some()
                || burned_attempt != record.attempt_high_water
                || record
                    .attempts
                    .get(&burned_attempt)
                    .map(|tombstone| (burned_attempt, tombstone.status))
                    != Some((burned_attempt, AttemptStatus::BurnedAfterRestart))
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
        ConsolidationPhase::AttemptsExhausted { burned_attempt } => {
            if burned_attempt != u64::MAX
                || record.attempt_high_water != u64::MAX
                || signed.is_some()
                || record.confirmation.is_some()
                || record
                    .attempts
                    .get(&burned_attempt)
                    .map(|tombstone| (burned_attempt, tombstone.status))
                    != Some((burned_attempt, AttemptStatus::BurnedAfterRestart))
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
        ConsolidationPhase::Signed | ConsolidationPhase::Broadcast => {
            if signed.is_none() || record.confirmation.is_some() {
                return Err(ConsolidationError::InvalidState);
            }
        }
        ConsolidationPhase::Confirmed => {
            if signed.is_none() {
                return Err(ConsolidationError::InvalidState);
            }
            validate_chain_point(record.confirmation.ok_or(ConsolidationError::InvalidState)?)?;
        }
        ConsolidationPhase::QuarantinedByInputReorg { ancestor } => {
            validate_chain_point(ancestor)?;
            if record.attempt_high_water == 0
                || record.attempts.get(&record.attempt_high_water).is_none()
                || record.confirmation.is_some()
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
        ConsolidationPhase::AbandonedByInputReorg { ancestor } => {
            validate_chain_point(ancestor)?;
            if signed.is_some()
                || record.attempt_high_water == 0
                || record.attempts.get(&record.attempt_high_water).is_none()
                || record.confirmation.is_some()
                || record
                    .attempts
                    .values()
                    .any(|tombstone| tombstone.status != AttemptStatus::BurnedAfterRestart)
            {
                return Err(ConsolidationError::InvalidState);
            }
        }
    }
    Ok(())
}

fn validate_chain_point(point: ChainPoint) -> Result<(), ConsolidationError> {
    if point.hash == [0_u8; 32] {
        return Err(ConsolidationError::InvalidChainPoint);
    }
    Ok(())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConsolidationError {
    #[error("unsupported consolidation state version {0}")]
    UnsupportedStateVersion(u16),
    #[error("invalid consolidation transaction authorization")]
    InvalidAuthorization,
    #[error("invalid consolidation signing attempt")]
    InvalidAttempt,
    #[error("invalid signed transaction binding")]
    InvalidSignedTransaction,
    #[error("consolidation belongs to another wallet")]
    WrongWallet,
    #[error("unknown consolidation")]
    UnknownConsolidation,
    #[error("conflicting authorization for the same consolidation ID")]
    AuthorizationConflict,
    #[error("conflicting authorization for the same worker sweep ID")]
    SweepAuthorizationConflict,
    #[error("attempt does not match the transaction authorization")]
    AttemptAuthorizationMismatch,
    #[error("coordinator attempt does not match the independently persisted worker release")]
    WorkerAuthorizationMismatch,
    #[error("session tombstone already existed and cannot authorize a new nonce")]
    SessionTombstoneAlreadyExists,
    #[error("fresh session tombstone receipt does not match the nonce authorization")]
    SessionTombstoneReceiptMismatch,
    #[error("signing session has already been permanently consumed")]
    SessionAlreadyUsed,
    #[error("invalid consolidation phase transition")]
    InvalidPhase,
    #[error("signed transaction does not match its durable authorization")]
    SignedTransactionMismatch,
    #[error("canonical chain settlement conflicts with the already confirmed transaction")]
    ConflictingChainSettlement,
    #[error("cannot abort after signing release")]
    CannotAbortAfterSigningRelease,
    #[error("invalid durable consolidation state")]
    InvalidState,
    #[error("invalid retained chain point")]
    InvalidChainPoint,
    #[error("consolidation state revision exhausted")]
    RevisionExhausted,
    #[error("consolidation attempt sequence exhausted")]
    AttemptExhausted,
    #[error("too many attempts for one consolidation")]
    TooManyAttempts,
    #[error("consolidation state persistence proof mismatch")]
    PersistenceMismatch,
    #[error("consolidation state serialization failed")]
    Serialization,
    #[error("non-canonical consolidation state")]
    NonCanonicalState,
    #[error("consolidation state exceeds its hard size bound")]
    StateTooLarge,
    #[error("transition was an exact duplicate and did not mutate state")]
    NoMutation,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization(seed: u8) -> TransactionAuthorization {
        TransactionAuthorization::new(
            DepositWalletId([seed; 32]),
            SweepId([seed.wrapping_add(1); 32]),
            OpaqueIntentBinding([seed.wrapping_add(2); 32]),
            [seed.wrapping_add(3); 32],
            [seed.wrapping_add(4); 32],
            [seed.wrapping_add(5); 32],
            2,
            50_000,
            1_000,
            2_000,
        )
        .unwrap()
    }

    fn attempt(number: u64, session_seed: u8, group_key: [u8; 32]) -> AttemptBinding {
        let authorization_seed = group_key[0].wrapping_sub(5);
        let session = derive_sweep_signing_session(
            DepositWalletId([authorization_seed; 32]),
            SweepId([authorization_seed.wrapping_add(1); 32]),
            number,
        )
        .unwrap();
        AttemptBinding::new(
            number,
            9,
            [11; 32],
            [12; 32],
            [13; 32],
            group_key,
            2,
            vec![PartyId(1), PartyId(3), PartyId(7)],
            [14; 32],
            session,
            [session_seed.wrapping_add(1); 32],
        )
        .unwrap()
    }

    fn signed(
        authorization: &TransactionAuthorization,
        binding: &AttemptBinding,
    ) -> SignedTransactionBinding {
        SignedTransactionBinding {
            authorization: authorization.digest(),
            attempt: binding.attempt,
            attempt_binding: binding.digest(),
            session: binding.session,
            signing_context: binding.signing_context,
            opaque_intent: authorization.opaque_intent(),
            transaction: [41; 32],
            exact_bytes: [42; 32],
            exact_bytes_len: 8_192,
        }
    }

    fn persisted_round_trip(state: &ConsolidationCoordinator) -> ConsolidationCoordinator {
        ConsolidationCoordinator::decode(&state.encode().unwrap()).unwrap()
    }

    #[test]
    fn restart_burns_uncertain_attempt_and_requires_fresh_session() {
        let auth = authorization(1);
        let id = auth.id();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap().unwrap();
        let first = attempt(1, 21, auth.root_group_key());
        let first_session = first.session();
        let effect = state.release_signing(id, first.clone()).unwrap();
        let revision = effect.revision();
        let commitment = effect.state_commitment();
        let receipt = state.persisted_receipt_after_cas(effect, revision, commitment).unwrap();
        let capability = state.nonce_action_after_persist(receipt).unwrap();
        assert_eq!(capability.attempt(), &first);

        let mut restored = persisted_round_trip(&state);
        assert_eq!(
            restored.restart_actions(),
            vec![CoordinatorAction::RecoverOrRestart { consolidation: id, attempt: 1 }]
        );
        restored.burn_attempt_after_restart(id).unwrap();
        assert_eq!(
            restored.restart_actions(),
            vec![CoordinatorAction::StartFreshAttempt { consolidation: id, next_attempt: 2 }]
        );
        let mut reused_session = attempt(2, 21, auth.root_group_key());
        reused_session.session = first_session;
        assert_eq!(
            restored.release_signing(id, reused_session),
            Err(ConsolidationError::InvalidAttempt)
        );
        let second = attempt(2, 22, auth.root_group_key());
        restored.release_signing(id, second).unwrap();
        assert_eq!(restored.attempt_high_water(id), Some(2));
        assert_eq!(restored.record(id).unwrap().attempts.len(), 2);
    }

    #[test]
    fn follower_catch_up_persists_only_sequential_burned_tombstones() {
        let auth = authorization(201);
        let id = auth.id();
        let first = attempt(1, 202, auth.root_group_key());
        let second = attempt(2, 203, auth.root_group_key());
        let third = attempt(3, 204, auth.root_group_key());
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();

        let effect = state.catch_up_burned_attempt(id, first.clone()).unwrap().unwrap();
        let revision = effect.revision();
        let commitment = effect.state_commitment();
        let receipt = state.persisted_receipt_after_cas(effect, revision, commitment).unwrap();
        assert_eq!(
            state.nonce_action_after_persist(receipt),
            Err(ConsolidationError::PersistenceMismatch)
        );
        assert_eq!(state.catch_up_burned_attempt(id, first.clone()).unwrap(), None);
        assert_eq!(
            state.restart_actions(),
            vec![CoordinatorAction::StartFreshAttempt { consolidation: id, next_attempt: 2 }]
        );

        state.catch_up_burned_attempt(id, second.clone()).unwrap().unwrap();
        let record = state.record(id).unwrap();
        assert_eq!(record.attempts.get(&1).unwrap().status, AttemptStatus::BurnedAfterRestart);
        assert_eq!(record.attempts.get(&2).unwrap().status, AttemptStatus::BurnedAfterRestart);
        state.release_signing(id, third).unwrap();
        persisted_round_trip(&state);

        let mut changed_first = first;
        changed_first.session = SessionId([205; 32]);
        assert_eq!(
            state.catch_up_burned_attempt(id, changed_first),
            Err(ConsolidationError::InvalidAttempt)
        );
    }

    #[test]
    fn authenticated_lagger_catch_up_jumps_high_water_without_nonce_release() {
        let auth = authorization(198);
        let id = auth.id();
        let fiftieth = attempt(50, 199, auth.root_group_key());
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();

        let effect = state.catch_up_burned_attempt(id, fiftieth.clone()).unwrap().unwrap();
        assert_eq!(effect.released_attempt_high_water(), None);
        assert_eq!(state.attempt_high_water(id), Some(50));
        assert_eq!(state.record(id).unwrap().attempts.len(), 1);
        assert_eq!(state.catch_up_burned_attempt(id, fiftieth).unwrap(), None);
        assert_eq!(
            state.restart_actions(),
            vec![CoordinatorAction::StartFreshAttempt { consolidation: id, next_attempt: 51 }]
        );
    }

    #[test]
    fn follower_catch_up_burns_an_exact_current_release_without_reminting_it() {
        let auth = authorization(206);
        let id = auth.id();
        let first = attempt(1, 207, auth.root_group_key());
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.release_signing(id, first.clone()).unwrap();

        let effect = state.catch_up_burned_attempt(id, first).unwrap().unwrap();
        assert_eq!(
            state.record(id).unwrap().phase,
            ConsolidationPhase::AwaitingFreshAttempt { burned_attempt: 1 }
        );
        assert_eq!(effect.release, None);
        assert_eq!(
            state.catch_up_burned_attempt(id, attempt(2, 208, [206; 32])),
            Err(ConsolidationError::AttemptAuthorizationMismatch)
        );
    }

    #[tokio::test]
    async fn only_a_fresh_exact_storage_tombstone_receipt_is_accepted() {
        use crate::storage::{ProtocolStore, SessionTombstoneClaim};

        let directory = tempfile::tempdir().unwrap();
        let store = ProtocolStore::new(directory.path(), PartyId(1), &[211; 32]).unwrap();
        let expected = ConsolidationNonceTombstone {
            session: SessionId([212; 32]),
            purpose: b"canonical-consolidation-nonce-purpose".to_vec(),
        };
        let created = store
            .claim_session_tombstone(expected.session(), expected.purpose(), &mut rand_core::OsRng)
            .await
            .unwrap();
        validate_fresh_tombstone_claim(&expected, created).unwrap();

        let existing = store
            .claim_session_tombstone(expected.session(), expected.purpose(), &mut rand_core::OsRng)
            .await
            .unwrap();
        assert!(matches!(existing, SessionTombstoneClaim::Existing));
        assert_eq!(
            validate_fresh_tombstone_claim(&expected, existing),
            Err(ConsolidationError::SessionTombstoneAlreadyExists)
        );

        let other = ConsolidationNonceTombstone {
            session: SessionId([213; 32]),
            purpose: b"attacker-selected-purpose".to_vec(),
        };
        let mismatched = store
            .claim_session_tombstone(other.session(), other.purpose(), &mut rand_core::OsRng)
            .await
            .unwrap();
        assert_eq!(
            validate_fresh_tombstone_claim(&expected, mismatched),
            Err(ConsolidationError::SessionTombstoneReceiptMismatch)
        );
    }

    #[test]
    fn durable_attempt_reconstructs_the_same_field_complete_tombstone_purpose() {
        let auth = authorization(214);
        let initial_attempt = attempt(1, 215, auth.root_group_key());
        let first = nonce_tombstone_for_attempt(&auth, &initial_attempt).unwrap();
        assert_eq!(first.session(), initial_attempt.session());

        let changed = attempt(1, 216, auth.root_group_key());
        let second = nonce_tombstone_for_attempt(&auth, &changed).unwrap();
        assert_ne!(first.purpose(), second.purpose());

        let wrong_group = attempt(1, 217, [218; 32]);
        assert_eq!(
            nonce_tombstone_for_attempt(&auth, &wrong_group),
            Err(ConsolidationError::AttemptAuthorizationMismatch)
        );
    }

    #[test]
    fn signing_release_is_an_irreversible_abort_boundary() {
        let auth = authorization(2);
        let id = auth.id();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap();
        state.release_signing(id, attempt(1, 31, auth.root_group_key())).unwrap();
        assert_eq!(
            state.abort_before_nonce(id),
            Err(ConsolidationError::CannotAbortAfterSigningRelease)
        );
    }

    #[test]
    fn signed_binding_requires_portable_certification_before_broadcast_and_rebroadcast() {
        let auth = authorization(3);
        let id = auth.id();
        let binding = attempt(1, 51, auth.root_group_key());
        let signed = signed(&auth, &binding);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap();
        state.release_signing(id, binding).unwrap();
        let effect = state.record_signed(id, signed).unwrap().unwrap();
        let persisted = persisted_round_trip(&state);
        let revision = effect.revision();
        let commitment = effect.state_commitment();
        let receipt = persisted.persisted_receipt_after_cas(effect, revision, commitment).unwrap();
        assert_eq!(
            persisted.signed_action_after_persist(receipt),
            Ok(CoordinatorAction::ProposePortableCompletion { consolidation: id, signed })
        );
        assert_eq!(state.record_signed(id, signed).unwrap(), None);

        assert_eq!(
            persisted.restart_actions(),
            vec![CoordinatorAction::AwaitPortableCertification { consolidation: id, signed }]
        );

        state.mark_broadcast(id, signed.transaction).unwrap();
        let restored = persisted_round_trip(&state);
        assert_eq!(
            restored.restart_actions(),
            vec![CoordinatorAction::RebroadcastExact { consolidation: id, signed }]
        );
    }

    #[test]
    fn late_portable_winner_from_retired_attempt_burns_fresh_release_without_nonce_reissue() {
        let auth = authorization(219);
        let id = auth.id();
        let group_key = auth.root_group_key();
        let first = attempt(1, 220, group_key);
        let second = attempt(2, 221, group_key);
        let first_signed = signed(&auth, &first);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.release_signing(id, first.clone()).unwrap();
        state.burn_attempt_after_restart(id).unwrap();

        let second_effect = state.release_signing(id, second.clone()).unwrap();
        let second_revision = second_effect.revision();
        let second_commitment = second_effect.state_commitment();
        let second_receipt = state
            .persisted_receipt_after_cas(second_effect, second_revision, second_commitment)
            .unwrap();

        let effect =
            state.record_portable_signed_attempt(id, &first, first_signed).unwrap().unwrap();
        assert_eq!(effect.invalidated_session(), Some(second.session()));
        assert_eq!(effect.release, None);
        assert_eq!(effect.signed, Some(id));
        assert_eq!(
            state.nonce_action_after_persist(second_receipt),
            Err(ConsolidationError::PersistenceMismatch)
        );
        assert_eq!(
            state.release_signing(id, attempt(3, 222, group_key)),
            Err(ConsolidationError::InvalidPhase)
        );

        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::Signed);
        assert_eq!(record.signed, Some(first_signed));
        assert_eq!(record.attempts.get(&1).unwrap().status, AttemptStatus::Completed);
        assert_eq!(record.attempts.get(&2).unwrap().status, AttemptStatus::BurnedAfterRestart);
        assert_eq!(record.attempt_high_water(), 2);

        let restored = persisted_round_trip(&state);
        let revision = effect.revision();
        let commitment = effect.state_commitment();
        let receipt = restored.persisted_receipt_after_cas(effect, revision, commitment).unwrap();
        assert_eq!(
            restored.signed_action_after_persist(receipt),
            Ok(CoordinatorAction::ProposePortableCompletion {
                consolidation: id,
                signed: first_signed,
            })
        );
        assert_eq!(
            restored.restart_actions(),
            vec![CoordinatorAction::AwaitPortableCertification {
                consolidation: id,
                signed: first_signed,
            }]
        );

        let mut broadcast = restored;
        broadcast.mark_broadcast(id, first_signed.transaction()).unwrap();
        let broadcast = persisted_round_trip(&broadcast);
        assert_eq!(
            broadcast.restart_actions(),
            vec![CoordinatorAction::RebroadcastExact { consolidation: id, signed: first_signed }]
        );
    }

    #[test]
    fn portable_winner_rejects_unknown_or_inexact_old_attempt_transactionally() {
        let auth = authorization(223);
        let id = auth.id();
        let first = attempt(1, 224, auth.root_group_key());
        let second = attempt(2, 225, auth.root_group_key());
        let first_signed = signed(&auth, &first);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap().unwrap();
        state.release_signing(id, first.clone()).unwrap();
        state.burn_attempt_after_restart(id).unwrap();
        state.release_signing(id, second).unwrap();
        let before = state.encode().unwrap();

        let mut inexact = first.clone();
        inexact.signing_context = [226; 32];
        assert_eq!(
            state.record_portable_signed_attempt(id, &inexact, first_signed),
            Err(ConsolidationError::InvalidAttempt)
        );
        assert_eq!(state.encode().unwrap(), before);

        let unknown = attempt(3, 227, auth.root_group_key());
        let unknown_signed = signed(&auth, &unknown);
        assert_eq!(
            state.record_portable_signed_attempt(id, &unknown, unknown_signed),
            Err(ConsolidationError::InvalidAttempt)
        );
        assert_eq!(state.encode().unwrap(), before);
    }

    #[test]
    fn portable_old_attempt_can_replace_a_distinct_unbroadcast_local_completion() {
        let auth = authorization(228);
        let id = auth.id();
        let first = attempt(1, 229, auth.root_group_key());
        let second = attempt(2, 230, auth.root_group_key());
        let first_signed = signed(&auth, &first);
        let mut second_signed = signed(&auth, &second);
        second_signed.transaction = [231; 32];
        second_signed.exact_bytes = [232; 32];
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.release_signing(id, first.clone()).unwrap();
        state.burn_attempt_after_restart(id).unwrap();
        state.release_signing(id, second).unwrap();
        state.record_signed(id, second_signed).unwrap().unwrap();

        let effect =
            state.record_portable_signed_attempt(id, &first, first_signed).unwrap().unwrap();
        assert_eq!(effect.invalidated_session(), None);
        let record = state.record(id).unwrap();
        assert_eq!(record.signed, Some(first_signed));
        assert_eq!(record.attempts.get(&1).unwrap().status, AttemptStatus::Completed);
        assert_eq!(record.attempts.get(&2).unwrap().status, AttemptStatus::BurnedAfterRestart);
        persisted_round_trip(&state);
    }

    #[test]
    fn chain_settlement_replaces_broadcast_candidate_with_older_attempt_and_is_final() {
        let auth = authorization(233);
        let id = auth.id();
        let first = attempt(1, 234, auth.root_group_key());
        let second = attempt(2, 235, auth.root_group_key());
        let mut broadcast = signed(&auth, &second);
        broadcast.transaction = [236; 32];
        broadcast.exact_bytes = [237; 32];
        let mut canonical = signed(&auth, &first);
        canonical.transaction = [238; 32];
        canonical.exact_bytes = [239; 32];
        let block = ChainPoint { height: 400, hash: [240; 32] };

        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.release_signing(id, first.clone()).unwrap();
        state.burn_attempt_after_restart(id).unwrap();
        state.release_signing(id, second.clone()).unwrap();
        state.record_signed(id, broadcast).unwrap().unwrap();
        state.mark_broadcast(id, broadcast.transaction()).unwrap().unwrap();

        let effect = state
            .record_chain_authoritative_settlement(
                id,
                &first,
                canonical,
                canonical.transaction(),
                block,
            )
            .unwrap()
            .unwrap();
        assert_eq!(effect.release, None);
        assert_eq!(effect.signed, None);
        assert_eq!(effect.invalidated_session(), None);
        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::Confirmed);
        assert_eq!(record.signed, Some(canonical));
        assert_eq!(record.confirmation, Some(block));
        assert_eq!(record.attempts.get(&1).unwrap().status, AttemptStatus::Completed);
        assert_eq!(record.attempts.get(&2).unwrap().status, AttemptStatus::BurnedAfterRestart);

        let revision = effect.revision();
        let commitment = effect.state_commitment();
        let mut restored = persisted_round_trip(&state);
        let receipt = restored.persisted_receipt_after_cas(effect, revision, commitment).unwrap();
        assert_eq!(
            restored.nonce_action_after_persist(receipt),
            Err(ConsolidationError::PersistenceMismatch)
        );
        assert!(restored.restart_actions().is_empty());
        assert_eq!(
            restored.record_chain_authoritative_settlement(
                id,
                &first,
                canonical,
                canonical.transaction(),
                block,
            ),
            Ok(None)
        );

        let before_conflicts = restored.encode().unwrap();
        assert_eq!(
            restored.record_chain_authoritative_settlement(
                id,
                &second,
                broadcast,
                broadcast.transaction(),
                block,
            ),
            Err(ConsolidationError::ConflictingChainSettlement)
        );
        assert_eq!(
            restored.record_chain_authoritative_settlement(
                id,
                &first,
                canonical,
                canonical.transaction(),
                ChainPoint { height: 401, hash: [241; 32] },
            ),
            Err(ConsolidationError::ConflictingChainSettlement)
        );
        assert_eq!(restored.encode().unwrap(), before_conflicts);
    }

    #[test]
    fn chain_settlement_accepts_newer_retained_attempt_and_rejects_unknown_or_wrong_family() {
        let auth = authorization(242);
        let id = auth.id();
        let first = attempt(1, 243, auth.root_group_key());
        let second = attempt(2, 244, auth.root_group_key());
        let mut broadcast = signed(&auth, &first);
        broadcast.transaction = [245; 32];
        broadcast.exact_bytes = [246; 32];
        let mut canonical = signed(&auth, &second);
        canonical.transaction = [247; 32];
        canonical.exact_bytes = [248; 32];
        let block = ChainPoint { height: 500, hash: [249; 32] };

        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap().unwrap();
        state.release_signing(id, first.clone()).unwrap();
        state.burn_attempt_after_restart(id).unwrap();
        state.release_signing(id, second.clone()).unwrap();
        state.record_portable_signed_attempt(id, &first, broadcast).unwrap().unwrap();
        state.mark_broadcast(id, broadcast.transaction()).unwrap().unwrap();
        let before_rejections = state.encode().unwrap();

        let unknown = attempt(3, 250, auth.root_group_key());
        let unknown_signed = signed(&auth, &unknown);
        assert_eq!(
            state.record_chain_authoritative_settlement(
                id,
                &unknown,
                unknown_signed,
                unknown_signed.transaction(),
                block,
            ),
            Err(ConsolidationError::InvalidAttempt)
        );
        let mut wrong_family = canonical;
        wrong_family.opaque_intent = OpaqueIntentBinding([251; 32]);
        assert_eq!(
            state.record_chain_authoritative_settlement(
                id,
                &second,
                wrong_family,
                wrong_family.transaction(),
                block,
            ),
            Err(ConsolidationError::SignedTransactionMismatch)
        );
        assert_eq!(
            state.record_chain_authoritative_settlement(id, &second, canonical, [252; 32], block,),
            Err(ConsolidationError::SignedTransactionMismatch)
        );
        assert_eq!(state.encode().unwrap(), before_rejections);

        state
            .record_chain_authoritative_settlement(
                id,
                &second,
                canonical,
                canonical.transaction(),
                block,
            )
            .unwrap()
            .unwrap();
        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::Confirmed);
        assert_eq!(record.signed, Some(canonical));
        assert_eq!(record.confirmation, Some(block));
        assert_eq!(record.attempts.get(&1).unwrap().status, AttemptStatus::BurnedAfterRestart);
        assert_eq!(record.attempts.get(&2).unwrap().status, AttemptStatus::Completed);
        persisted_round_trip(&state);
    }

    #[test]
    fn confirmation_rolls_back_and_signed_input_reorg_quarantines() {
        let auth = authorization(4);
        let id = auth.id();
        let binding = attempt(1, 61, auth.root_group_key());
        let signed = signed(&auth, &binding);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap();
        state.release_signing(id, binding).unwrap();
        state.record_signed(id, signed).unwrap().unwrap();
        state.mark_broadcast(id, signed.transaction).unwrap();
        let confirmed = ChainPoint { height: 100, hash: [71; 32] };
        state.mark_confirmed(id, signed.transaction, confirmed).unwrap();
        state.rollback_confirmation(id, ChainPoint { height: 99, hash: [72; 32] }).unwrap();
        assert_eq!(state.record(id).unwrap().phase, ConsolidationPhase::Broadcast);
        assert_eq!(state.attempt_high_water(id), Some(1));

        let ancestor = ChainPoint { height: 90, hash: [73; 32] };
        state.handle_input_reorg(id, ancestor).unwrap();
        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::QuarantinedByInputReorg { ancestor });
        assert_eq!(record.signed, Some(signed));
        assert_eq!(record.attempts.len(), 1);
        assert_eq!(record.attempt_high_water(), 1);
        assert!(state.restart_actions().is_empty());

        let deeper_ancestor = ChainPoint { height: 80, hash: [74; 32] };
        let effect = state.handle_input_reorg(id, deeper_ancestor).unwrap();
        assert_eq!(effect.invalidated_session(), None);
        let record = state.record(id).unwrap();
        assert_eq!(
            record.phase,
            ConsolidationPhase::QuarantinedByInputReorg { ancestor: deeper_ancestor }
        );
        assert_eq!(record.signed, Some(signed));
        assert_eq!(
            state.handle_input_reorg(id, deeper_ancestor),
            Err(ConsolidationError::NoMutation)
        );
        persisted_round_trip(&state);
    }

    #[test]
    fn input_reorg_atomically_burns_the_exact_released_session() {
        let auth = authorization(209);
        let id = auth.id();
        let binding = attempt(1, 210, auth.root_group_key());
        let late_signed = signed(&auth, &binding);
        let session = binding.session();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.release_signing(id, binding.clone()).unwrap();

        let ancestor = ChainPoint { height: 81, hash: [211; 32] };
        let effect = state.handle_input_reorg(id, ancestor).unwrap();
        assert_eq!(effect.invalidated_session(), Some(session));
        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::QuarantinedByInputReorg { ancestor });
        assert_eq!(record.attempts.get(&1).unwrap().status, AttemptStatus::BurnedAfterRestart);
        assert_eq!(record.attempt_high_water(), 1);
        assert!(state.restart_actions().is_empty());
        persisted_round_trip(&state);

        let abandoned =
            state.record_certified_abandonment(id, &binding, ancestor).unwrap().unwrap();
        assert_eq!(abandoned.released_attempt_high_water(), None);
        assert_eq!(
            state.record(id).unwrap().phase,
            ConsolidationPhase::AbandonedByInputReorg { ancestor }
        );
        assert!(state.restart_actions().is_empty());
        let restored = persisted_round_trip(&state);
        assert_eq!(
            restored.record(id).unwrap().phase,
            ConsolidationPhase::AbandonedByInputReorg { ancestor }
        );

        // A later canonical old-family transaction may settle only through exact chain evidence;
        // abandonment itself never made the attempt signable again.
        let block = ChainPoint { height: 120, hash: [212; 32] };
        state
            .record_chain_authoritative_settlement(
                id,
                &binding,
                late_signed,
                late_signed.transaction,
                block,
            )
            .unwrap()
            .unwrap();
        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::Confirmed);
        assert_eq!(record.confirmation, Some(block));
        assert_eq!(record.attempt_high_water(), 1);
    }

    #[test]
    fn authorization_and_attempt_digests_bind_every_security_field() {
        let base = authorization(5);
        let base_digest = base.digest();
        let variants = [
            TransactionAuthorization::new(
                DepositWalletId([90; 32]),
                base.sweep,
                base.opaque_intent,
                base.input_set,
                base.destination_policy,
                base.root_group_key,
                base.input_count,
                base.total_input_atomic_units,
                base.fee_atomic_units,
                base.maximum_fee_atomic_units,
            )
            .unwrap(),
            TransactionAuthorization::new(
                base.wallet,
                base.sweep,
                base.opaque_intent,
                [91; 32],
                base.destination_policy,
                base.root_group_key,
                base.input_count,
                base.total_input_atomic_units,
                base.fee_atomic_units,
                base.maximum_fee_atomic_units,
            )
            .unwrap(),
            TransactionAuthorization::new(
                base.wallet,
                base.sweep,
                base.opaque_intent,
                base.input_set,
                [92; 32],
                base.root_group_key,
                base.input_count,
                base.total_input_atomic_units,
                base.fee_atomic_units,
                base.maximum_fee_atomic_units,
            )
            .unwrap(),
            TransactionAuthorization::new(
                base.wallet,
                base.sweep,
                base.opaque_intent,
                base.input_set,
                base.destination_policy,
                [93; 32],
                base.input_count,
                base.total_input_atomic_units,
                base.fee_atomic_units,
                base.maximum_fee_atomic_units,
            )
            .unwrap(),
            TransactionAuthorization::new(
                base.wallet,
                base.sweep,
                base.opaque_intent,
                base.input_set,
                base.destination_policy,
                base.root_group_key,
                base.input_count,
                base.total_input_atomic_units,
                base.fee_atomic_units + 1,
                base.maximum_fee_atomic_units,
            )
            .unwrap(),
        ];
        assert!(variants.iter().all(|variant| variant.digest() != base_digest));

        let attempt = attempt(1, 81, base.root_group_key());
        let changed_session = AttemptBinding::new(
            attempt.attempt,
            attempt.epoch,
            attempt.registry,
            attempt.committee,
            attempt.activation,
            attempt.root_group_key,
            attempt.threshold,
            attempt.signers.clone(),
            attempt.worker_intent,
            SessionId([82; 32]),
            attempt.signing_context,
        )
        .unwrap();
        let changed_epoch = AttemptBinding::new(
            attempt.attempt,
            attempt.epoch + 1,
            attempt.registry,
            attempt.committee,
            attempt.activation,
            attempt.root_group_key,
            attempt.threshold,
            attempt.signers.clone(),
            attempt.worker_intent,
            attempt.session,
            attempt.signing_context,
        )
        .unwrap();
        let changed_signers = AttemptBinding::new(
            attempt.attempt,
            attempt.epoch,
            attempt.registry,
            attempt.committee,
            attempt.activation,
            attempt.root_group_key,
            attempt.threshold,
            vec![PartyId(1), PartyId(4), PartyId(7)],
            attempt.worker_intent,
            attempt.session,
            attempt.signing_context,
        )
        .unwrap();
        let changed_worker_intent = AttemptBinding::new(
            attempt.attempt,
            attempt.epoch,
            attempt.registry,
            attempt.committee,
            attempt.activation,
            attempt.root_group_key,
            attempt.threshold,
            attempt.signers.clone(),
            [94; 32],
            attempt.session,
            attempt.signing_context,
        )
        .unwrap();
        assert_ne!(attempt.digest(), changed_session.digest());
        assert_ne!(attempt.digest(), changed_epoch.digest());
        assert_ne!(attempt.digest(), changed_signers.digest());
        assert_ne!(attempt.digest(), changed_worker_intent.digest());
    }

    #[test]
    fn coordinator_never_receives_or_serializes_private_intent_bytes() {
        let private_sentinel = b"outgoing-view-secret-material-must-not-appear";
        let intent = OpaqueIntentBinding(*blake3::hash(private_sentinel).as_bytes());
        let auth = TransactionAuthorization::new(
            DepositWalletId([101; 32]),
            SweepId([102; 32]),
            intent,
            [103; 32],
            [104; 32],
            [105; 32],
            1,
            10_000,
            500,
            500,
        )
        .unwrap();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap();
        let encoded = state.encode().unwrap();
        assert!(!encoded.windows(private_sentinel.len()).any(|window| window == private_sentinel));
    }

    #[test]
    fn read_only_indexes_are_unambiguous_and_signed_binding_has_explicit_getters() {
        let auth = authorization(106);
        let id = auth.id();
        let sweep = auth.sweep_id();
        let binding = attempt(1, 107, auth.root_group_key());
        let signed = signed(&auth, &binding);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap().unwrap();
        assert_eq!(state.records().count(), 1);
        assert_eq!(state.record_by_sweep(sweep), state.record(id));

        let conflicting = TransactionAuthorization::new(
            auth.wallet_id(),
            sweep,
            OpaqueIntentBinding([109; 32]),
            auth.input_set(),
            auth.destination_policy(),
            auth.root_group_key(),
            auth.input_count(),
            auth.total_input_atomic_units(),
            auth.fee_atomic_units(),
            auth.maximum_fee_atomic_units(),
        )
        .unwrap();
        assert_eq!(
            state.reserve_intent(conflicting),
            Err(ConsolidationError::SweepAuthorizationConflict)
        );
        assert_eq!(state.records().count(), 1);

        assert_eq!(signed.authorization_digest(), auth.digest());
        assert_eq!(signed.attempt(), binding.attempt());
        assert_eq!(signed.attempt_binding_digest(), binding.digest());
        assert_eq!(signed.session(), binding.session());
        assert_eq!(signed.signing_context(), binding.signing_context());
        assert_eq!(signed.opaque_intent(), auth.opaque_intent());
        assert_eq!(signed.transaction(), [41; 32]);
        assert_eq!(signed.exact_bytes_digest(), [42; 32]);
        assert_eq!(signed.exact_bytes_len(), 8_192);
    }

    #[test]
    fn losing_branch_effect_cannot_mint_receipt_for_winning_state() {
        let auth = authorization(111);
        let id = auth.id();
        let mut base = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        base.reserve_intent(auth.clone()).unwrap().unwrap();
        let snapshot = base.encode().unwrap();
        let mut winner = ConsolidationCoordinator::decode(&snapshot).unwrap();
        let mut loser = ConsolidationCoordinator::decode(&snapshot).unwrap();
        let winner_attempt = attempt(1, 112, auth.root_group_key());
        let winner_session = winner_attempt.session();
        let winner_effect = winner.release_signing(id, winner_attempt).unwrap();
        let loser_effect =
            loser.release_signing(id, attempt(1, 113, auth.root_group_key())).unwrap();

        let winner_revision = winner_effect.revision();
        let winner_commitment = winner_effect.state_commitment();
        let receipt = winner
            .persisted_receipt_after_cas(winner_effect, winner_revision, winner_commitment)
            .unwrap();
        assert_eq!(
            winner.nonce_action_after_persist(receipt).unwrap().attempt().session(),
            winner_session
        );

        let loser_revision = loser_effect.revision();
        let loser_commitment = loser_effect.state_commitment();
        assert_eq!(
            winner.persisted_receipt_after_cas(loser_effect, loser_revision, loser_commitment,),
            Err(ConsolidationError::PersistenceMismatch)
        );
    }

    #[test]
    fn failed_finish_is_transactional_and_leaves_original_unchanged() {
        let auth = authorization(121);
        let id = auth.id();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.revision = u64::MAX;
        let before = postcard::to_allocvec(&state).unwrap();
        assert_eq!(state.abort_before_nonce(id), Err(ConsolidationError::RevisionExhausted));
        assert_eq!(postcard::to_allocvec(&state).unwrap(), before);
        assert_eq!(state.record(id).unwrap().phase, ConsolidationPhase::IntentReserved);
    }

    #[test]
    fn decoded_attempt_history_requires_every_predecessor_burned() {
        let auth = authorization(131);
        let id = auth.id();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap().unwrap();
        state.release_signing(id, attempt(1, 132, auth.root_group_key())).unwrap();
        state.burn_attempt_after_restart(id).unwrap();
        state.release_signing(id, attempt(2, 133, auth.root_group_key())).unwrap();

        state.records.get_mut(&id).unwrap().attempts.get_mut(&1).unwrap().status =
            AttemptStatus::SigningReleased;
        let corrupt = postcard::to_allocvec(&state).unwrap();
        assert!(matches!(
            ConsolidationCoordinator::decode(&corrupt),
            Err(ConsolidationError::InvalidState)
        ));
    }

    #[test]
    fn signed_binding_rejects_authorization_attempt_and_session_rebinding() {
        let auth = authorization(141);
        let id = auth.id();
        let binding = attempt(1, 142, auth.root_group_key());
        let valid = signed(&auth, &binding);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        state.release_signing(id, binding).unwrap();
        let before = state.encode().unwrap();

        let mut wrong_authorization = valid;
        wrong_authorization.authorization = [151; 32];
        assert_eq!(
            state.record_signed(id, wrong_authorization),
            Err(ConsolidationError::SignedTransactionMismatch)
        );
        let mut wrong_attempt = valid;
        wrong_attempt.attempt_binding = [152; 32];
        assert_eq!(
            state.record_signed(id, wrong_attempt),
            Err(ConsolidationError::SignedTransactionMismatch)
        );
        let mut wrong_session = valid;
        wrong_session.session = SessionId([153; 32]);
        assert_eq!(
            state.record_signed(id, wrong_session),
            Err(ConsolidationError::SignedTransactionMismatch)
        );
        assert_eq!(state.encode().unwrap(), before);
    }

    #[test]
    fn attempt_history_is_bounded_and_high_water_survives_restart() {
        let auth = authorization(161);
        let id = auth.id();
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth.clone()).unwrap().unwrap();
        let total = u64::try_from(MAX_RETAINED_CONSOLIDATION_ATTEMPTS).unwrap() + 9;
        for number in 1..=total {
            state
                .release_signing(id, attempt(number, number as u8, auth.root_group_key()))
                .unwrap();
            state.burn_attempt_after_restart(id).unwrap();
        }
        let record = state.record(id).unwrap();
        assert_eq!(record.attempt_high_water(), total);
        assert_eq!(record.attempts.len(), MAX_RETAINED_CONSOLIDATION_ATTEMPTS);
        assert!(!record.attempts.contains_key(&1));

        let revision = state.revision();
        assert_eq!(
            state.catch_up_burned_attempt(id, attempt(1, 1, auth.root_group_key())).unwrap(),
            None
        );
        assert_eq!(state.revision(), revision);
        let mut restored = persisted_round_trip(&state);
        assert_eq!(
            restored.restart_actions(),
            vec![CoordinatorAction::StartFreshAttempt {
                consolidation: id,
                next_attempt: total + 1,
            }]
        );
        let effect =
            restored.release_signing(id, attempt(total + 1, 170, auth.root_group_key())).unwrap();
        assert_eq!(effect.released_attempt_high_water(), Some((id, total + 1)));
        assert_eq!(
            restored.record(id).unwrap().attempts.len(),
            MAX_RETAINED_CONSOLIDATION_ATTEMPTS
        );
    }

    #[test]
    fn certified_terminal_attempt_installs_above_lagging_high_water_without_nonce_release() {
        let auth = authorization(166);
        let id = auth.id();
        let terminal = attempt(500, 167, auth.root_group_key());
        let terminal_signed = signed(&auth, &terminal);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();

        let effect = state
            .transactional(|candidate| {
                candidate.record_portable_signed_attempt_in_place(
                    id,
                    &terminal,
                    terminal_signed,
                    true,
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(effect.released_attempt_high_water(), None);
        let record = state.record(id).unwrap();
        assert_eq!(record.attempt_high_water(), 500);
        assert_eq!(record.phase, ConsolidationPhase::Signed);
        assert_eq!(record.attempts.len(), 1);
        assert_eq!(record.attempts.get(&500).unwrap().status, AttemptStatus::Completed);

        let restored = persisted_round_trip(&state);
        assert_eq!(restored.attempt_high_water(id), Some(500));
        assert!(matches!(
            restored.restart_actions().as_slice(),
            [CoordinatorAction::AwaitPortableCertification { consolidation, .. }]
                if *consolidation == id
        ));
    }

    #[test]
    fn certified_public_terminal_installs_without_private_reservation_or_nonce_authority() {
        let auth = authorization(168);
        let id = auth.id();
        let terminal = attempt(700, 169, auth.root_group_key());
        let terminal_signed = signed(&auth, &terminal);
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();

        let effect = state
            .record_certified_public_terminal_completion(auth, terminal.clone(), terminal_signed)
            .unwrap()
            .unwrap();
        assert_eq!(effect.released_attempt_high_water(), None);
        let effect_revision = effect.revision();
        let effect_commitment = effect.state_commitment();
        let record = state.record(id).unwrap();
        assert_eq!(record.attempt_high_water(), 700);
        assert_eq!(record.phase, ConsolidationPhase::Signed);
        assert_eq!(record.attempts.len(), 1);
        assert_eq!(record.attempts.get(&700).unwrap().binding, terminal);
        assert_eq!(record.attempts.get(&700).unwrap().status, AttemptStatus::Completed);
        assert_eq!(
            state.nonce_action_after_persist(
                state
                    .persisted_receipt_after_cas(effect, effect_revision, effect_commitment)
                    .unwrap(),
            ),
            Err(ConsolidationError::PersistenceMismatch)
        );

        let restored = persisted_round_trip(&state);
        assert_eq!(restored.attempt_high_water(id), Some(700));
        assert!(matches!(
            restored.restart_actions().as_slice(),
            [CoordinatorAction::AwaitPortableCertification { consolidation, .. }]
                if *consolidation == id
        ));
    }

    #[test]
    fn certified_public_abandonment_is_terminal_for_lagger_and_allows_exact_late_settlement() {
        let auth = authorization(170);
        let id = auth.id();
        let terminal = attempt(900, 171, auth.root_group_key());
        let ancestor = ChainPoint { height: 500, hash: [172; 32] };
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();

        let effect = state
            .record_certified_public_abandonment(auth.clone(), terminal.clone(), ancestor)
            .unwrap()
            .unwrap();
        assert_eq!(effect.released_attempt_high_water(), None);
        let record = state.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::AbandonedByInputReorg { ancestor });
        assert_eq!(record.attempt_high_water(), 900);
        assert_eq!(record.attempts.get(&900).unwrap().binding, terminal);
        assert_eq!(record.attempts.get(&900).unwrap().status, AttemptStatus::BurnedAfterRestart);
        assert!(state.restart_actions().is_empty());
        assert_eq!(
            state
                .record_certified_public_abandonment(auth.clone(), terminal.clone(), ancestor)
                .unwrap(),
            None
        );
        assert_eq!(
            state.release_signing(id, attempt(901, 173, auth.root_group_key())),
            Err(ConsolidationError::InvalidPhase)
        );

        let mut restored = persisted_round_trip(&state);
        let late = signed(&auth, &terminal);
        let inclusion = ChainPoint { height: 800, hash: [174; 32] };
        let settlement = restored
            .record_chain_authoritative_settlement(
                id,
                &terminal,
                late,
                late.transaction(),
                inclusion,
            )
            .unwrap()
            .unwrap();
        assert_eq!(settlement.released_attempt_high_water(), None);
        let record = restored.record(id).unwrap();
        assert_eq!(record.phase, ConsolidationPhase::Confirmed);
        assert_eq!(record.signed, Some(late));
        assert_eq!(record.confirmation, Some(inclusion));
        assert_eq!(record.attempts.get(&900).unwrap().status, AttemptStatus::Completed);
        persisted_round_trip(&restored);
    }

    #[test]
    fn u64_attempt_exhaustion_is_terminal_without_unbounded_history() {
        let auth = authorization(171);
        let id = auth.id();
        let binding = attempt(u64::MAX, 172, auth.root_group_key());
        let mut state = ConsolidationCoordinator::new(auth.wallet_id()).unwrap();
        state.reserve_intent(auth).unwrap().unwrap();
        let record = state.records.get_mut(&id).unwrap();
        record.attempt_high_water = u64::MAX;
        record.attempt_family = Some(AttemptFamilyBinding::from_attempt(&binding));
        record.attempts.insert(
            u64::MAX,
            AttemptTombstone { binding, status: AttemptStatus::BurnedAfterRestart },
        );
        record.phase = ConsolidationPhase::AttemptsExhausted { burned_attempt: u64::MAX };
        state.validate().unwrap();
        assert!(state.restart_actions().is_empty());
    }
}
