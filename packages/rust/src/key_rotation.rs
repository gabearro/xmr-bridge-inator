//! Portable Byzantine agreement for per-epoch X25519 key rotation.
//!
//! A rotation value contains the complete signed advertisement needed to verify it.  Receivers do
//! not need a local advertisement cache: they authenticate every advertisement against the
//! configured target signing policy, reconstruct the target committee deterministically, and then
//! let the source committee
//! [`crate::deposit_consensus`] agree on those exact canonical bytes.
//!
//! This module deliberately owns no private-key persistence or erasure.  A caller creates an
//! advertisement only with a [`PersistedKeyAdvertisementIdentity`], persists the resulting
//! consensus state and outbox, and destroys retired X25519 key handles only after the returned
//! [`KeyRotationCertificate`] is durably activated.

#[cfg(test)]
use std::cell::Cell;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, SeqAccess, Visitor},
};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    committee::{Committee, CommitteeError, MAX_COMMITTEE_MEMBERS, Member, PartyId, SessionId},
    deposit_consensus::{
        CommitCertificate, ConsensusBinding, ConsensusContext, ConsensusError,
        ConsensusMessageBody, ConsensusStep, ConsensusValue, DepositConsensus,
        EquivocationEvidence, MAX_CONSENSUS_VALUE_BYTES, ViewChangeCertificate,
        decode_consensus_message,
    },
    deposit_wallet::{DepositAddressDeriver, DepositWalletId},
    identity::{Identity, IdentityError, PersistedKeyAdvertisementIdentity, SignedEnvelope},
    keys::{EpochPublic, KeyError},
    receiver_key_accumulator::{
        MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES, ReceiverKeyAccumulatorCommitment,
        ReceiverKeyAccumulatorError, ReceiverKeyAccumulatorStore, ReceiverKeyBatchUpdateProof,
    },
};

const KEY_ROTATION_VERSION: u16 = 7;
const KEY_ROTATION_TARGET_POLICY_VERSION: u16 = 7;
const KEY_ADVERTISEMENT_VERSION: u16 = 7;
const KEY_ROTATION_FALLBACK_VOTE_VERSION: u16 = 7;
const KEY_ROTATION_CERTIFICATE_VERSION: u16 = 7;
const KEY_ADVERTISEMENT_SEQUENCE: u64 = 0;
const KEY_ROTATION_FALLBACK_VOTE_SEQUENCE: u64 = 0;
const KEY_ROTATION_APPLICATION: &[u8] = b"x25519-key-rotation/v7";
const KEY_ROTATION_TARGET_POLICY_DOMAIN: &str = "threshold-monero/key-rotation-target-policy/v7";
const KEY_ROTATION_CONTEXT_DOMAIN: &str = "threshold-monero/key-rotation-context/v7";
const KEY_ROTATION_BINDING_DOMAIN: &str = "threshold-monero/key-rotation-binding-domain/v7";
const KEY_ROTATION_REGISTRY_DOMAIN: &str = "threshold-monero/key-rotation-registry/v7";
const KEY_ROTATION_CONSENSUS_SESSION_DOMAIN: &[u8] = b"key-rotation-consensus/v7";
const KEY_ROTATION_ADVERTISEMENT_SESSION_DOMAIN: &[u8] = b"key-rotation-advertisement/v7";
const KEY_ROTATION_FALLBACK_SESSION_DOMAIN: &[u8] = b"key-rotation-selection-fallback/v1";
const KEY_ROTATION_ROUND_STATE_VERSION: u16 = 7;
const KEY_ROTATION_WIRE_DIGEST_DOMAIN: &str = "threshold-monero/key-rotation-wire/v7";
const KEY_ROTATION_SEMANTIC_VALUE_DOMAIN: &str = "threshold-monero/key-rotation-semantic-value/v7";

#[cfg(test)]
thread_local! {
    static SPARSE_PROOF_VERIFICATIONS: Cell<u64> = const { Cell::new(0) };
}

/// API capability proving that one compact-registry target came from a fully verified threshold
/// activation and remains in the configured Monero wallet domain.
///
/// This type deliberately implements neither `Serialize` nor `Deserialize`: wire bytes, callers,
/// and persisted state cannot manufacture it. The server constructs it only after reloading and
/// verifying the durable `n-f` epoch activation certificate; the deposit service supplies its
/// already validated view-key-bound address deriver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRegistryHandoffTarget {
    committee: Committee,
    key_id: [u8; 32],
    group_key: [u8; 32],
    fault_bound: u16,
    activation: [u8; 32],
    certified_activation_root: [u8; 32],
    wallet: DepositWalletId,
}

impl VerifiedRegistryHandoffTarget {
    /// Bind an activation which the caller has already authenticated against its exact AVSS
    /// transition and `n-f` target acknowledgements.
    ///
    /// `source` is absent only for epoch-zero DKG. A successor must immediately follow the source
    /// and retain both the threshold key id and root public spend key. The configured Monero view
    /// material is exercised here, proving that the same public spend key derives the token's
    /// stable [`DepositWalletId`].
    pub(crate) fn from_verified_activation(
        source: Option<&EpochPublic>,
        public: EpochPublic,
        fault_bound: u16,
        certified_activation_root: [u8; 32],
        deriver: &DepositAddressDeriver,
    ) -> Result<Self, KeyRotationError> {
        public.validate()?;
        public.committee.validate_async_security_with_faults(fault_bound)?;
        if certified_activation_root == [0_u8; 32]
            || deriver.wallet_id().0 == [0_u8; 32]
            || deriver.root_spend_key() != public.group_key_bytes()
        {
            return Err(KeyRotationError::InvalidRegistryHandoffTarget);
        }
        match source {
            None => {
                if public.committee.epoch != 0 {
                    return Err(KeyRotationError::InvalidRegistryHandoffTarget);
                }
            }
            Some(source) => {
                source.validate()?;
                if source.committee.epoch.checked_add(1) != Some(public.committee.epoch)
                    || source.key_id != public.key_id
                    || source.group_key_bytes() != public.group_key_bytes()
                    || source.group_key_bytes() != deriver.root_spend_key()
                {
                    return Err(KeyRotationError::InvalidRegistryHandoffTarget);
                }
            }
        }
        let activation = public.activation_digest()?;
        let key_id = public.key_id;
        let group_key = public.group_key_bytes();
        let committee = public.committee;
        Ok(Self {
            committee,
            key_id,
            group_key,
            fault_bound,
            activation,
            certified_activation_root,
            wallet: deriver.wallet_id(),
        })
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
    pub const fn certified_activation_root(&self) -> [u8; 32] {
        self.certified_activation_root
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
    pub const fn wallet(&self) -> DepositWalletId {
        self.wallet
    }

    /// Construct structurally valid authority material for protocol unit tests without weakening
    /// the production constructor or making the capability serializable.
    #[cfg(test)]
    pub(crate) fn for_test(
        committee: Committee,
        fault_bound: u16,
        activation: [u8; 32],
        certified_activation_root: [u8; 32],
        wallet: DepositWalletId,
        key_id: [u8; 32],
        group_key: [u8; 32],
    ) -> Result<Self, KeyRotationError> {
        let committee = committee.canonicalized()?;
        committee.validate_async_security_with_faults(fault_bound)?;
        if activation == [0_u8; 32]
            || certified_activation_root == [0_u8; 32]
            || wallet.0 == [0_u8; 32]
            || key_id == [0_u8; 32]
            || group_key == [0_u8; 32]
        {
            return Err(KeyRotationError::InvalidRegistryHandoffTarget);
        }
        Ok(Self {
            committee,
            key_id,
            group_key,
            fault_bound,
            activation,
            certified_activation_root,
            wallet,
        })
    }
}

/// Hard bound for a canonical signed advertisement body.
pub const MAX_KEY_ADVERTISEMENT_BYTES: usize = 512;
/// Hard bound for the fixed fallback-vote body.
pub const MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES: usize = 256;
/// Hard bound for one portable rotation certificate, including generic commit witnesses.
///
/// The sparse proof is bounded by committee size and tree depth, never by the number of prior
/// epochs. Leave room for the fixed proof, advertisements, and at most one committee of generic
/// PRECOMMIT witnesses.
pub const MAX_KEY_ROTATION_CERTIFICATE_BYTES: usize =
    64 * 1024 + MAX_RECEIVER_KEY_BATCH_UPDATE_PROOF_BYTES;
/// Maximum canonical size accepted for one durable key-rotation round and its retry outbox.
pub const MAX_KEY_ROTATION_ROUND_STATE_BYTES: usize = 8 * 1024 * 1024;
/// A round retains at most one local payload per logical consensus slot. Recipient retry sets are
/// de-duplicated, so a large certificate is encoded once rather than once per committee peer.
pub const MAX_KEY_ROTATION_OUTBOX_ENTRIES: usize = 8;
const MAX_KEY_ROTATION_OUTBOX_RECIPIENTS: usize = MAX_COMMITTEE_MEMBERS * 8;

/// Bounded canonical committee decoding which enforces the engineering cap before allocation.
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

/// Configured successor eligibility, the authenticated used-key accumulator, and exact selected
/// shape.
///
/// `eligible` is an authentication roster, not an activated committee. Its stable party and
/// Ed25519 identities authorize fresh durable X25519 advertisements. Its X25519 bytes are bound
/// into the policy domain but are never eligible to enter the successor: a certified value must
/// contain exactly `desired_n` advertisements and the successor is constructed solely from any
/// certificate-selected exact subset of those fresh advertisers.
///
/// Byzantine liveness requires at least `desired_n + target_fault_bound` eligible identities. The
/// configured `target_fault_bound` is a governance assumption over the **entire eligible roster**,
/// not merely the subset eventually selected: at most that many eligible stable identities may be
/// Byzantine. Equivalently, every subset this policy permits must satisfy the target fault bound.
/// Cryptography cannot infer which governed identity is corrupt. Under that assumption, if up to
/// `f` candidates omit their advertisements, source agreement can still choose an exact
/// `desired_n` subset without silently increasing the target's adversarial budget.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeyRotationTargetPolicy {
    version: u16,
    eligible: Committee,
    prior_receiver_keys: ReceiverKeyAccumulatorCommitment,
    desired_n: u16,
    target_fault_bound: u16,
    primary_source_overlap: u16,
    minimum_source_overlap: u16,
    selection_fallback_window_ms: u64,
}

#[derive(Deserialize)]
struct UncheckedKeyRotationTargetPolicy {
    version: u16,
    eligible: BoundedCommittee,
    prior_receiver_keys: ReceiverKeyAccumulatorCommitment,
    desired_n: u16,
    target_fault_bound: u16,
    primary_source_overlap: u16,
    minimum_source_overlap: u16,
    selection_fallback_window_ms: u64,
}

impl KeyRotationTargetPolicy {
    pub fn new(
        source: &Committee,
        source_fault_bound: u16,
        mut eligible: Committee,
        desired_n: u16,
        target_fault_bound: u16,
        prior_receiver_keys: ReceiverKeyAccumulatorCommitment,
        selection_fallback_window_ms: u64,
    ) -> Result<Self, KeyRotationError> {
        let source = source.clone().canonicalized()?;
        let expected_target = source
            .epoch
            .checked_add(1)
            .ok_or(KeyRotationError::InvalidTargetPolicy("source epoch is exhausted"))?;
        if eligible.epoch != expected_target {
            return Err(KeyRotationError::InvalidTargetPolicy(
                "target epoch must immediately follow the source",
            ));
        }
        // The generic signed-envelope type binds a committee digest. Eligibility needs only
        // stable Ed25519 identities, so replace every caller-supplied X25519 byte with a
        // deterministic, publicly derivable domain separator before canonical validation. These
        // reference points are never used for encryption and can never become successor keys.
        for member in &mut eligible.members {
            member.encryption_key =
                eligibility_reference_key(eligible.epoch, member.id, member.signing_key);
        }
        let eligible = eligible.canonicalized()?;
        let minimum_eligible = desired_n
            .checked_add(target_fault_bound)
            .ok_or(KeyRotationError::InvalidTargetPolicy("eligible target size overflow"))?;
        if desired_n == 0 || eligible.n() < minimum_eligible {
            return Err(KeyRotationError::InsufficientEligibleCandidates {
                actual: eligible.n(),
                desired: desired_n,
                fault_bound: target_fault_bound,
            });
        }
        let selected_shape = Committee {
            epoch: eligible.epoch,
            threshold: eligible.threshold,
            members: eligible.members.iter().take(usize::from(desired_n)).cloned().collect(),
        };
        selected_shape.validate_async_security_with_faults(target_fault_bound)?;
        if selection_fallback_window_ms == 0 {
            return Err(KeyRotationError::InvalidTargetPolicy(
                "selection fallback window must be positive",
            ));
        }

        for member in &source.members {
            validate_x25519_key(member.encryption_key)
                .map_err(|_| KeyRotationError::InvalidSourceKey(member.id))?;
        }
        for member in &eligible.members {
            match source.member(member.id) {
                Ok(source_member) => {
                    if member.signing_key != source_member.signing_key {
                        return Err(KeyRotationError::TargetChangedStableIdentity(member.id));
                    }
                }
                Err(CommitteeError::UnknownParty(_)) => {
                    if source
                        .members
                        .iter()
                        .any(|source_member| source_member.signing_key == member.signing_key)
                    {
                        return Err(KeyRotationError::ReusedSourceSigningKey(member.id));
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }

        prior_receiver_keys.validate()?;
        if prior_receiver_keys.through_epoch() != source.epoch {
            return Err(KeyRotationError::WrongReceiverKeyAccumulatorEpoch {
                expected: source.epoch,
                actual: prior_receiver_keys.through_epoch(),
            });
        }

        source.validate_async_security_with_faults(source_fault_bound)?;
        let eligible_source =
            source.members.iter().filter(|member| eligible.member(member.id).is_ok()).count();
        let primary_source_overlap = usize::from(desired_n).min(eligible_source);
        let tolerated_missing = usize::from(source_fault_bound.min(target_fault_bound));
        let minimum_source_overlap =
            usize::from(desired_n).min(eligible_source.saturating_sub(tolerated_missing));
        let policy = Self {
            version: KEY_ROTATION_TARGET_POLICY_VERSION,
            eligible,
            prior_receiver_keys,
            desired_n,
            target_fault_bound,
            primary_source_overlap: u16::try_from(primary_source_overlap).map_err(|_| {
                KeyRotationError::InvalidTargetPolicy("primary source overlap does not fit u16")
            })?,
            minimum_source_overlap: u16::try_from(minimum_source_overlap).map_err(|_| {
                KeyRotationError::InvalidTargetPolicy("minimum source overlap does not fit u16")
            })?,
            selection_fallback_window_ms,
        };
        if policy.digest() == [0_u8; 32] {
            return Err(KeyRotationError::InvalidTargetPolicy(
                "target-policy digest cannot be zero",
            ));
        }
        Ok(policy)
    }

    fn validate_against(
        &self,
        source: &Committee,
        source_fault_bound: u16,
    ) -> Result<(), KeyRotationError> {
        if self.version != KEY_ROTATION_TARGET_POLICY_VERSION {
            return Err(KeyRotationError::UnsupportedVersion);
        }
        let rebuilt = Self::new(
            source,
            source_fault_bound,
            self.eligible.clone(),
            self.desired_n,
            self.target_fault_bound,
            self.prior_receiver_keys,
            self.selection_fallback_window_ms,
        )?;
        if rebuilt != *self {
            return Err(KeyRotationError::NonCanonicalTargetCommittee);
        }
        Ok(())
    }

    #[must_use]
    pub const fn eligible(&self) -> &Committee {
        &self.eligible
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.eligible.epoch
    }

    #[must_use]
    pub const fn desired_n(&self) -> u16 {
        self.desired_n
    }

    #[must_use]
    pub const fn target_fault_bound(&self) -> u16 {
        self.target_fault_bound
    }

    #[must_use]
    pub const fn primary_source_overlap(&self) -> u16 {
        self.primary_source_overlap
    }

    #[must_use]
    pub const fn minimum_source_overlap(&self) -> u16 {
        self.minimum_source_overlap
    }

    #[must_use]
    pub const fn selection_fallback_window_ms(&self) -> u64 {
        self.selection_fallback_window_ms
    }

    #[must_use]
    pub const fn prior_receiver_keys(&self) -> ReceiverKeyAccumulatorCommitment {
        self.prior_receiver_keys
    }

    #[must_use]
    pub fn selection_size(&self) -> usize {
        usize::from(self.desired_n)
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(KEY_ROTATION_TARGET_POLICY_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.eligible.digest());
        hasher.update(&self.prior_receiver_keys.network());
        hasher.update(&self.prior_receiver_keys.through_epoch().to_le_bytes());
        hasher.update(&self.prior_receiver_keys.leaf_count().to_le_bytes());
        hasher.update(&self.prior_receiver_keys.root());
        hasher.update(&self.desired_n.to_le_bytes());
        hasher.update(&self.target_fault_bound.to_le_bytes());
        hasher.update(&self.primary_source_overlap.to_le_bytes());
        hasher.update(&self.minimum_source_overlap.to_le_bytes());
        hasher.update(&self.selection_fallback_window_ms.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// A fully bound source-to-successor key-rotation height.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeyRotationContext {
    version: u16,
    network: [u8; 32],
    source: Committee,
    source_activation: [u8; 32],
    source_fault_bound: u16,
    target_policy: KeyRotationTargetPolicy,
}

#[derive(Deserialize)]
struct UncheckedKeyRotationContext {
    version: u16,
    network: [u8; 32],
    source: BoundedCommittee,
    source_activation: [u8; 32],
    source_fault_bound: u16,
    target_policy: UncheckedKeyRotationTargetPolicy,
}

impl<'de> Deserialize<'de> for KeyRotationContext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let unchecked = UncheckedKeyRotationContext::deserialize(deserializer)?;
        if unchecked.version != KEY_ROTATION_VERSION {
            return Err(D::Error::custom(KeyRotationError::UnsupportedVersion));
        }
        let source = Committee::from(unchecked.source);
        let original_source = source.clone();
        if unchecked.target_policy.version != KEY_ROTATION_TARGET_POLICY_VERSION {
            return Err(D::Error::custom(KeyRotationError::UnsupportedVersion));
        }
        let target_eligible = Committee::from(unchecked.target_policy.eligible);
        let original_target = target_eligible.clone();
        let target_policy = KeyRotationTargetPolicy::new(
            &source,
            unchecked.source_fault_bound,
            target_eligible,
            unchecked.target_policy.desired_n,
            unchecked.target_policy.target_fault_bound,
            unchecked.target_policy.prior_receiver_keys,
            unchecked.target_policy.selection_fallback_window_ms,
        )
        .map_err(D::Error::custom)?;
        let context = Self::new(
            unchecked.network,
            source,
            unchecked.source_activation,
            unchecked.source_fault_bound,
            target_policy,
        )
        .map_err(D::Error::custom)?;
        if context.source != original_source {
            return Err(D::Error::custom(KeyRotationError::NonCanonicalSourceCommittee));
        }
        if context.target_policy.eligible != original_target {
            return Err(D::Error::custom(KeyRotationError::NonCanonicalTargetCommittee));
        }
        if context.target_policy.primary_source_overlap
            != unchecked.target_policy.primary_source_overlap
            || context.target_policy.minimum_source_overlap
                != unchecked.target_policy.minimum_source_overlap
        {
            return Err(D::Error::custom(KeyRotationError::NonCanonicalContext));
        }
        Ok(context)
    }
}

impl KeyRotationContext {
    pub fn new(
        network: [u8; 32],
        source: Committee,
        source_activation: [u8; 32],
        source_fault_bound: u16,
        target_policy: KeyRotationTargetPolicy,
    ) -> Result<Self, KeyRotationError> {
        if network == [0; 32] || source_activation == [0; 32] {
            return Err(KeyRotationError::InvalidContext(
                "network and source activation must be nonzero",
            ));
        }
        let source = source.canonicalized()?;
        source.validate_async_security_with_faults(source_fault_bound)?;
        for member in &source.members {
            validate_x25519_key(member.encryption_key)
                .map_err(|_| KeyRotationError::InvalidSourceKey(member.id))?;
        }
        target_policy.validate_against(&source, source_fault_bound)?;
        if target_policy.prior_receiver_keys().network() != network {
            return Err(KeyRotationError::WrongReceiverKeyAccumulatorNetwork);
        }
        let context = Self {
            version: KEY_ROTATION_VERSION,
            network,
            source,
            source_activation,
            source_fault_bound,
            target_policy,
        };
        if context.digest() == [0; 32] {
            return Err(KeyRotationError::InvalidContext("context digest cannot be zero"));
        }
        // Exercise every generic binding invariant at construction time.
        drop(context.consensus_context()?);
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), KeyRotationError> {
        if self.version != KEY_ROTATION_VERSION {
            return Err(KeyRotationError::UnsupportedVersion);
        }
        let rebuilt = Self::new(
            self.network,
            self.source.clone(),
            self.source_activation,
            self.source_fault_bound,
            self.target_policy.clone(),
        )?;
        if rebuilt != *self {
            return Err(KeyRotationError::NonCanonicalContext);
        }
        Ok(())
    }

    #[must_use]
    pub const fn network(&self) -> [u8; 32] {
        self.network
    }

    #[must_use]
    pub fn source(&self) -> &Committee {
        &self.source
    }

    #[must_use]
    pub const fn source_activation(&self) -> [u8; 32] {
        self.source_activation
    }

    #[must_use]
    pub const fn target_epoch(&self) -> u64 {
        self.target_policy.target_epoch()
    }

    #[must_use]
    pub const fn source_fault_bound(&self) -> u16 {
        self.source_fault_bound
    }

    #[must_use]
    pub const fn target_policy(&self) -> &KeyRotationTargetPolicy {
        &self.target_policy
    }

    #[must_use]
    pub const fn target_fault_bound(&self) -> u16 {
        self.target_policy.target_fault_bound()
    }

    #[must_use]
    pub fn source_quorum(&self) -> usize {
        usize::from(self.source.n() - self.source_fault_bound)
    }

    #[must_use]
    pub fn selection_size(&self) -> usize {
        self.target_policy.selection_size()
    }

    /// Maximum source membership an honest primary candidate can retain.
    #[must_use]
    pub fn primary_source_overlap(&self) -> usize {
        usize::from(self.target_policy.primary_source_overlap())
    }

    /// Verifier-enforced churn bound for every certified successor.
    ///
    /// At most the smaller source/target Byzantine budget may force replacement of an otherwise
    /// eligible source member. This is an application-value invariant, not an honest-proposer
    /// preference, so a Byzantine consensus leader cannot replace healthy members with spares.
    #[must_use]
    pub fn minimum_source_overlap(&self) -> usize {
        usize::from(self.target_policy.minimum_source_overlap())
    }

    #[must_use]
    pub fn participants(&self) -> BTreeSet<PartyId> {
        self.source
            .members
            .iter()
            .chain(self.target_policy.eligible.members.iter())
            .map(|member| member.id)
            .collect()
    }

    #[must_use]
    pub fn is_participant(&self, party: PartyId) -> bool {
        self.source.member(party).is_ok() || self.target_policy.eligible.member(party).is_ok()
    }

    /// Stable commitment repeated by advertisement bodies and certificate wrappers.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(KEY_ROTATION_CONTEXT_DOMAIN);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.network);
        hasher.update(&self.source.epoch.to_le_bytes());
        hasher.update(&self.source.digest());
        hasher.update(&self.source_activation);
        hasher.update(&self.source_fault_bound.to_le_bytes());
        hasher.update(&self.target_policy.digest());
        *hasher.finalize().as_bytes()
    }

    /// Session used only for signed X25519 advertisements.
    #[must_use]
    pub fn advertisement_session(&self) -> SessionId {
        SessionId::derive(KEY_ROTATION_ADVERTISEMENT_SESSION_DOMAIN, &self.digest())
    }

    /// View-independent session for the source committee's one fallback-authorization vote.
    #[must_use]
    pub fn selection_fallback_session(&self) -> SessionId {
        let mut binding = [0_u8; 64];
        binding[..32].copy_from_slice(&self.digest());
        binding[32..].copy_from_slice(&self.target_policy.digest());
        SessionId::derive(KEY_ROTATION_FALLBACK_SESSION_DOMAIN, &binding)
    }

    /// Generic consensus context for agreeing on one canonical [`KeyRotationValue`].
    pub fn consensus_context(&self) -> Result<ConsensusContext, KeyRotationError> {
        let digest = self.digest();
        let mut registry = blake3::Hasher::new_derive_key(KEY_ROTATION_REGISTRY_DOMAIN);
        registry.update(&digest);
        let binding = ConsensusBinding {
            domain: *blake3::Hasher::new_derive_key(KEY_ROTATION_BINDING_DOMAIN)
                .finalize()
                .as_bytes(),
            application: KEY_ROTATION_APPLICATION.to_vec(),
            wallet: self.source.digest(),
            network: self.network,
            registry: *registry.finalize().as_bytes(),
            activation: self.source_activation,
        };
        let session = SessionId::derive(KEY_ROTATION_CONSENSUS_SESSION_DOMAIN, &digest);
        ConsensusContext::new(
            binding,
            session,
            self.source.clone(),
            self.source_fault_bound,
            self.target_epoch(),
            1,
            self.source_activation,
        )
        .map_err(KeyRotationError::Consensus)
    }
}

/// Canonical Ed25519-authenticated statement for one member's next X25519 key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KeyAdvertisementBody {
    version: u16,
    context: [u8; 32],
    source_epoch: u64,
    target_epoch: u64,
    party: PartyId,
    next_key: [u8; 32],
    durable_record_digest: [u8; 32],
}

/// Authenticated advertisement details returned by universal verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedKeyAdvertisement {
    pub party: PartyId,
    pub next_key: [u8; 32],
    pub durable_record_digest: [u8; 32],
}

/// Create a portable broadcast using a target-epoch identity authenticated from durable storage.
///
/// The non-serializable capability ensures that ordinary production callers cannot advertise a
/// merely generated, crash-vulnerable secret. Remote verification necessarily relies on the
/// stable Ed25519 attestation; a Byzantine party can always advertise a key it later refuses to
/// use.
pub fn sign_key_advertisement(
    context: &KeyRotationContext,
    target_capability: &PersistedKeyAdvertisementIdentity,
) -> Result<SignedEnvelope, KeyRotationError> {
    context.validate()?;
    let target_identity = target_capability.identity();
    let member = context.target_policy.eligible.member(target_identity.party())?;
    if target_identity.encryption_epoch() != context.target_epoch()
        || target_identity.signing_public_key() != member.signing_key
    {
        return Err(KeyRotationError::WrongAdvertisementIdentity);
    }
    let next_key = target_identity.encryption_public_key();
    validate_new_key(context, member.id, next_key)?;
    let body = KeyAdvertisementBody {
        version: KEY_ADVERTISEMENT_VERSION,
        context: context.digest(),
        source_epoch: context.source.epoch,
        target_epoch: context.target_epoch(),
        party: member.id,
        next_key,
        durable_record_digest: target_capability.durable_record_digest(),
    };
    let payload = postcard::to_allocvec(&body).map_err(|_| KeyRotationError::Serialization)?;
    if payload.len() > MAX_KEY_ADVERTISEMENT_BYTES {
        return Err(KeyRotationError::AdvertisementTooLarge {
            actual: payload.len(),
            maximum: MAX_KEY_ADVERTISEMENT_BYTES,
        });
    }
    target_identity
        .sign_envelope(
            &context.target_policy.eligible,
            context.advertisement_session(),
            None,
            KEY_ADVERTISEMENT_SEQUENCE,
            payload,
        )
        .map_err(KeyRotationError::Identity)
}

/// Authenticate and fully context-check one self-contained advertisement.
pub fn verify_key_advertisement(
    context: &KeyRotationContext,
    envelope: &SignedEnvelope,
) -> Result<VerifiedKeyAdvertisement, KeyRotationError> {
    context.validate()?;
    if envelope.payload.len() > MAX_KEY_ADVERTISEMENT_BYTES {
        return Err(KeyRotationError::AdvertisementTooLarge {
            actual: envelope.payload.len(),
            maximum: MAX_KEY_ADVERTISEMENT_BYTES,
        });
    }
    let verifier = context
        .target_policy
        .eligible
        .members
        .first()
        .ok_or(KeyRotationError::InvalidContext("target committee is empty"))?
        .id;
    Identity::verify_envelope(&context.target_policy.eligible, verifier, envelope)?;
    if envelope.to.is_some() {
        return Err(KeyRotationError::NonPortableAdvertisement);
    }
    if envelope.session != context.advertisement_session()
        || envelope.sequence != KEY_ADVERTISEMENT_SEQUENCE
    {
        return Err(KeyRotationError::WrongAdvertisementSlot);
    }
    let (body, trailing) = postcard::take_from_bytes::<KeyAdvertisementBody>(&envelope.payload)
        .map_err(|_| KeyRotationError::Serialization)?;
    if !trailing.is_empty() {
        return Err(KeyRotationError::TrailingAdvertisementBytes);
    }
    let canonical = postcard::to_allocvec(&body).map_err(|_| KeyRotationError::Serialization)?;
    if canonical != envelope.payload {
        return Err(KeyRotationError::NonCanonicalAdvertisement);
    }
    if body.version != KEY_ADVERTISEMENT_VERSION {
        return Err(KeyRotationError::UnsupportedVersion);
    }
    if body.context != context.digest()
        || body.source_epoch != context.source.epoch
        || body.target_epoch != context.target_epoch()
        || body.party != envelope.from
        || body.durable_record_digest == [0_u8; 32]
    {
        return Err(KeyRotationError::WrongAdvertisementContext);
    }
    let _member = context.target_policy.eligible.member(body.party)?;
    validate_new_key(context, body.party, body.next_key)?;
    Ok(VerifiedKeyAdvertisement {
        party: body.party,
        next_key: body.next_key,
        durable_record_digest: body.durable_record_digest,
    })
}

/// Fixed, view-independent source statement authorizing bounded membership fallback.
///
/// A vote does not choose a successor and is never sufficient by itself. Exactly `n_source-f_source`
/// such statements allow a consensus value to retain between R and P-1 eligible source members
/// after the policy-bound primary window has elapsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KeyRotationFallbackVoteBody {
    version: u16,
    context_digest: [u8; 32],
    source_epoch: u64,
    source_activation: [u8; 32],
    target_epoch: u64,
    selection_policy_digest: [u8; 32],
}

/// Canonical source-quorum authorization embedded in every fallback rotation value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FallbackAuthorization {
    #[serde(deserialize_with = "deserialize_fallback_votes")]
    votes: Vec<SignedEnvelope>,
}

impl FallbackAuthorization {
    pub fn new(
        context: &KeyRotationContext,
        mut votes: Vec<SignedEnvelope>,
    ) -> Result<Self, KeyRotationError> {
        votes.sort_unstable_by_key(|vote| vote.from);
        let authorization = Self { votes };
        authorization.verify(context)?;
        Ok(authorization)
    }

    #[must_use]
    pub fn votes(&self) -> &[SignedEnvelope] {
        &self.votes
    }

    pub fn verify(&self, context: &KeyRotationContext) -> Result<(), KeyRotationError> {
        context.validate()?;
        let expected = context.source_quorum();
        if self.votes.len() != expected {
            return Err(KeyRotationError::InvalidFallbackAuthorizationCount {
                actual: self.votes.len(),
                expected,
            });
        }
        let mut previous = None;
        for vote in &self.votes {
            if previous.is_some_and(|party| party >= vote.from) {
                return Err(KeyRotationError::NonCanonicalFallbackAuthorization);
            }
            previous = Some(vote.from);
            verify_selection_fallback_vote(context, vote)?;
        }
        Ok(())
    }
}

/// Sign this source member's sole fallback statement for the exact rotation context.
///
/// The state machine intentionally exposes no timestamp here. The persistent scheduler is the only
/// production caller and invokes it only after its authenticated immutable fallback deadline.
pub fn sign_selection_fallback_vote(
    context: &KeyRotationContext,
    source_identity: &Identity,
) -> Result<SignedEnvelope, KeyRotationError> {
    context.validate()?;
    let source_member = context.source().member(source_identity.party())?;
    if source_identity.signing_public_key() != source_member.signing_key {
        return Err(KeyRotationError::WrongLocalRotationIdentity);
    }
    let body = KeyRotationFallbackVoteBody {
        version: KEY_ROTATION_FALLBACK_VOTE_VERSION,
        context_digest: context.digest(),
        source_epoch: context.source().epoch,
        source_activation: context.source_activation(),
        target_epoch: context.target_epoch(),
        selection_policy_digest: context.target_policy().digest(),
    };
    let payload = postcard::to_allocvec(&body).map_err(|_| KeyRotationError::Serialization)?;
    if payload.len() > MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES {
        return Err(KeyRotationError::FallbackVoteTooLarge {
            actual: payload.len(),
            maximum: MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES,
        });
    }
    source_identity
        .sign_envelope(
            context.source(),
            context.selection_fallback_session(),
            None,
            KEY_ROTATION_FALLBACK_VOTE_SEQUENCE,
            payload,
        )
        .map_err(KeyRotationError::Identity)
}

/// Authenticate one fixed source fallback statement without consulting local clock state.
pub fn verify_selection_fallback_vote(
    context: &KeyRotationContext,
    envelope: &SignedEnvelope,
) -> Result<PartyId, KeyRotationError> {
    context.validate()?;
    if envelope.payload.len() > MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES {
        return Err(KeyRotationError::FallbackVoteTooLarge {
            actual: envelope.payload.len(),
            maximum: MAX_KEY_ROTATION_FALLBACK_VOTE_BYTES,
        });
    }
    let verifier = context
        .source()
        .members
        .first()
        .ok_or(KeyRotationError::InvalidContext("source committee is empty"))?
        .id;
    Identity::verify_envelope(context.source(), verifier, envelope)?;
    if envelope.to.is_some() {
        return Err(KeyRotationError::NonPortableFallbackVote);
    }
    if envelope.session != context.selection_fallback_session()
        || envelope.sequence != KEY_ROTATION_FALLBACK_VOTE_SEQUENCE
    {
        return Err(KeyRotationError::WrongFallbackVoteSlot);
    }
    let (body, trailing) =
        postcard::take_from_bytes::<KeyRotationFallbackVoteBody>(&envelope.payload)
            .map_err(|_| KeyRotationError::Serialization)?;
    if !trailing.is_empty() {
        return Err(KeyRotationError::TrailingFallbackVoteBytes);
    }
    let canonical = postcard::to_allocvec(&body).map_err(|_| KeyRotationError::Serialization)?;
    if canonical != envelope.payload {
        return Err(KeyRotationError::NonCanonicalFallbackVote);
    }
    if body.version != KEY_ROTATION_FALLBACK_VOTE_VERSION {
        return Err(KeyRotationError::UnsupportedVersion);
    }
    if body.context_digest != context.digest()
        || body.source_epoch != context.source().epoch
        || body.source_activation != context.source_activation()
        || body.target_epoch != context.target_epoch()
        || body.selection_policy_digest != context.target_policy().digest()
        || context.source().member(envelope.from).is_err()
    {
        return Err(KeyRotationError::WrongFallbackVoteContext);
    }
    Ok(envelope.from)
}

/// Complete, canonical application value proposed to the generic consensus reducer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationValue {
    version: u16,
    context: [u8; 32],
    #[serde(deserialize_with = "deserialize_advertisements")]
    advertisements: Vec<SignedEnvelope>,
    history_update: ReceiverKeyBatchUpdateProof,
    selection_authorization: Option<FallbackAuthorization>,
}

/// Exact application result authenticated by one rotation value/certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedKeyRotation {
    pub target: Committee,
    pub receiver_keys: ReceiverKeyAccumulatorCommitment,
}

/// Exact application result and witness-independent digest authenticated by one certificate.
///
/// Keeping the digest beside the verified target lets persistence/registration code bind all
/// downstream effects without replaying the bounded sparse proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedKeyRotationCertificate {
    pub target: Committee,
    pub receiver_keys: ReceiverKeyAccumulatorCommitment,
    context_digest: [u8; 32],
    semantic_digest: [u8; 32],
    certificate_wire_digest: [u8; 32],
    value: KeyRotationValue,
}

#[derive(Debug, Eq, PartialEq)]
struct VerifiedKeyRotationCertificateParts {
    target: Committee,
    receiver_keys: ReceiverKeyAccumulatorCommitment,
    semantic_digest: [u8; 32],
    value: KeyRotationValue,
}

impl VerifiedKeyRotationCertificate {
    #[must_use]
    pub const fn semantic_digest(&self) -> [u8; 32] {
        self.semantic_digest
    }

    #[must_use]
    pub const fn history_update(&self) -> &ReceiverKeyBatchUpdateProof {
        self.value.history_update()
    }

    fn authenticate_exact_certificate(
        &self,
        context: &KeyRotationContext,
        certificate: &KeyRotationCertificate,
    ) -> Result<(), KeyRotationError> {
        let digest = key_rotation_wire_digest(&KeyRotationWire::Certificate(certificate.clone()))?;
        if self.context_digest != context.digest() || self.certificate_wire_digest != digest {
            return Err(KeyRotationError::WrongVerifiedCertificate);
        }
        Ok(())
    }
}

impl KeyRotationValue {
    pub fn new(
        context: &KeyRotationContext,
        advertisements: Vec<SignedEnvelope>,
        history_update: ReceiverKeyBatchUpdateProof,
    ) -> Result<Self, KeyRotationError> {
        Self::new_with_authorization(context, advertisements, history_update, None)
    }

    pub fn new_with_authorization(
        context: &KeyRotationContext,
        mut advertisements: Vec<SignedEnvelope>,
        history_update: ReceiverKeyBatchUpdateProof,
        selection_authorization: Option<FallbackAuthorization>,
    ) -> Result<Self, KeyRotationError> {
        advertisements.sort_unstable_by_key(|advertisement| advertisement.from);
        let value = Self {
            version: KEY_ROTATION_VERSION,
            context: context.digest(),
            advertisements,
            history_update,
            selection_authorization,
        };
        drop(value.verify(context)?);
        Ok(value)
    }

    #[must_use]
    pub fn advertisements(&self) -> &[SignedEnvelope] {
        &self.advertisements
    }

    #[must_use]
    pub const fn history_update(&self) -> &ReceiverKeyBatchUpdateProof {
        &self.history_update
    }

    #[must_use]
    pub const fn selection_authorization(&self) -> Option<&FallbackAuthorization> {
        self.selection_authorization.as_ref()
    }

    /// Verify every embedded witness, prove every selected receiver key absent from the
    /// authenticated predecessor set, and deterministically reconstruct the successor.
    pub fn verify(
        &self,
        context: &KeyRotationContext,
    ) -> Result<VerifiedKeyRotation, KeyRotationError> {
        context.validate()?;
        if self.version != KEY_ROTATION_VERSION {
            return Err(KeyRotationError::UnsupportedVersion);
        }
        if self.context != context.digest() {
            return Err(KeyRotationError::WrongValueContext);
        }
        let selection_size = context.selection_size();
        if self.advertisements.len() != selection_size {
            return Err(KeyRotationError::InvalidAdvertisementCount {
                actual: self.advertisements.len(),
                expected: selection_size,
            });
        }

        let mut next_by_party = BTreeMap::new();
        let mut next_keys = BTreeSet::new();
        let mut previous_party = None;
        for envelope in &self.advertisements {
            if previous_party == Some(envelope.from) {
                return Err(KeyRotationError::DuplicateAdvertiser(envelope.from));
            }
            if previous_party.is_some_and(|party| party > envelope.from) {
                return Err(KeyRotationError::NonCanonicalAdvertisementSet);
            }
            previous_party = Some(envelope.from);
            let verified = verify_key_advertisement(context, envelope)?;
            if next_by_party.insert(verified.party, verified.next_key).is_some() {
                return Err(KeyRotationError::DuplicateAdvertiser(verified.party));
            }
            if !next_keys.insert(verified.next_key) {
                return Err(KeyRotationError::DuplicateNextKey);
            }
        }
        let retained_source =
            next_by_party.keys().filter(|party| context.source.member(**party).is_ok()).count();
        let primary_source = context.primary_source_overlap();
        let minimum_source = context.minimum_source_overlap();
        match &self.selection_authorization {
            None if retained_source < primary_source => {
                return Err(KeyRotationError::MissingFallbackAuthorization {
                    actual: retained_source,
                    primary: primary_source,
                });
            }
            Some(_) if retained_source >= primary_source => {
                return Err(KeyRotationError::GratuitousFallbackAuthorization {
                    actual: retained_source,
                    primary: primary_source,
                });
            }
            Some(authorization) => {
                if retained_source < minimum_source {
                    return Err(KeyRotationError::InsufficientSourceRetention {
                        actual: retained_source,
                        minimum: minimum_source,
                    });
                }
                authorization.verify(context)?;
            }
            None => {}
        }

        let members = next_by_party
            .iter()
            .map(|(party, next_key)| {
                let eligible = context.target_policy.eligible.member(*party)?;
                Ok(Member {
                    id: *party,
                    signing_key: eligible.signing_key,
                    encryption_key: *next_key,
                })
            })
            .collect::<Result<Vec<_>, KeyRotationError>>()?;
        let target = Committee {
            epoch: context.target_epoch(),
            threshold: context.target_policy.eligible.threshold,
            members,
        }
        .canonicalized()?;
        target.validate_async_security_with_faults(context.target_fault_bound())?;
        let selected = target
            .members
            .iter()
            .map(|member| (member.id, member.encryption_key))
            .collect::<Vec<_>>();
        #[cfg(test)]
        SPARSE_PROOF_VERIFICATIONS
            .with(|verifications| verifications.set(verifications.get().saturating_add(1)));
        let receiver_keys = self.history_update.verify(
            &context.target_policy.prior_receiver_keys(),
            context.target_epoch(),
            &selected,
        )?;
        Ok(VerifiedKeyRotation { target, receiver_keys })
    }

    pub fn target_committee(
        &self,
        context: &KeyRotationContext,
    ) -> Result<Committee, KeyRotationError> {
        self.verify(context).map(|verified| verified.target)
    }

    pub fn resulting_receiver_keys(
        &self,
        context: &KeyRotationContext,
    ) -> Result<ReceiverKeyAccumulatorCommitment, KeyRotationError> {
        self.verify(context).map(|verified| verified.receiver_keys)
    }

    pub fn to_consensus_value(
        &self,
        context: &KeyRotationContext,
    ) -> Result<ConsensusValue, KeyRotationError> {
        drop(self.verify(context)?);
        let encoded = postcard::to_allocvec(self).map_err(|_| KeyRotationError::Serialization)?;
        if encoded.len() > MAX_CONSENSUS_VALUE_BYTES {
            return Err(KeyRotationError::ValueTooLarge {
                actual: encoded.len(),
                maximum: MAX_CONSENSUS_VALUE_BYTES,
            });
        }
        ConsensusValue::new(encoded).map_err(KeyRotationError::Consensus)
    }

    pub fn from_consensus_value(
        context: &KeyRotationContext,
        value: &ConsensusValue,
    ) -> Result<Self, KeyRotationError> {
        Self::from_consensus_value_verified(context, value).map(|(value, _)| value)
    }

    fn from_consensus_value_verified(
        context: &KeyRotationContext,
        value: &ConsensusValue,
    ) -> Result<(Self, VerifiedKeyRotation), KeyRotationError> {
        value.validate()?;
        Self::decode_verified(context, value.as_bytes())
    }

    pub fn decode(context: &KeyRotationContext, bytes: &[u8]) -> Result<Self, KeyRotationError> {
        Self::decode_verified(context, bytes).map(|(value, _)| value)
    }

    fn decode_verified(
        context: &KeyRotationContext,
        bytes: &[u8],
    ) -> Result<(Self, VerifiedKeyRotation), KeyRotationError> {
        if bytes.len() > MAX_CONSENSUS_VALUE_BYTES {
            return Err(KeyRotationError::ValueTooLarge {
                actual: bytes.len(),
                maximum: MAX_CONSENSUS_VALUE_BYTES,
            });
        }
        let (value, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| KeyRotationError::Serialization)?;
        if !trailing.is_empty() {
            return Err(KeyRotationError::TrailingValueBytes);
        }
        let canonical =
            postcard::to_allocvec(&value).map_err(|_| KeyRotationError::Serialization)?;
        if canonical != bytes {
            return Err(KeyRotationError::NonCanonicalValue);
        }
        let verified = value.verify(context)?;
        Ok((value, verified))
    }
}

/// Portable decision certificate: generic `n-f` PRECOMMIT witnesses plus the self-contained
/// rotation value they committed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationCertificate {
    version: u16,
    context_digest: [u8; 32],
    context: KeyRotationContext,
    commit: CommitCertificate,
}

impl KeyRotationCertificate {
    pub fn from_commit(
        context: &KeyRotationContext,
        commit: CommitCertificate,
    ) -> Result<Self, KeyRotationError> {
        let certificate = Self {
            version: KEY_ROTATION_CERTIFICATE_VERSION,
            context_digest: context.digest(),
            context: context.clone(),
            commit,
        };
        drop(certificate.verify(context)?);
        Ok(certificate)
    }

    /// Verify the generic consensus certificate and reconstruct its exact target committee.
    pub fn verify(&self, context: &KeyRotationContext) -> Result<Committee, KeyRotationError> {
        self.verify_rotation(context).map(|verified| verified.target)
    }

    /// Verify the generic decision plus the bounded used-key accumulator transition.
    pub fn verify_rotation(
        &self,
        context: &KeyRotationContext,
    ) -> Result<VerifiedKeyRotation, KeyRotationError> {
        self.verify_certificate_parts(context).map(|parts| VerifiedKeyRotation {
            target: parts.target,
            receiver_keys: parts.receiver_keys,
        })
    }

    /// Verify the certificate once and return every value needed by durable registration.
    pub fn verify_rotation_certificate(
        &self,
        context: &KeyRotationContext,
    ) -> Result<VerifiedKeyRotationCertificate, KeyRotationError> {
        let parts = self.verify_certificate_parts(context)?;
        let certificate_wire_digest =
            key_rotation_wire_digest(&KeyRotationWire::Certificate(self.clone()))?;
        Ok(VerifiedKeyRotationCertificate {
            target: parts.target,
            receiver_keys: parts.receiver_keys,
            context_digest: context.digest(),
            semantic_digest: parts.semantic_digest,
            certificate_wire_digest,
            value: parts.value,
        })
    }

    fn verify_certificate_parts(
        &self,
        context: &KeyRotationContext,
    ) -> Result<VerifiedKeyRotationCertificateParts, KeyRotationError> {
        context.validate()?;
        if self.version != KEY_ROTATION_CERTIFICATE_VERSION {
            return Err(KeyRotationError::UnsupportedVersion);
        }
        if self.context_digest != context.digest() || self.context != *context {
            return Err(KeyRotationError::WrongCertificateContext);
        }
        let consensus_context = context.consensus_context()?;
        self.commit.verify(&consensus_context)?;
        let (value, verified) =
            KeyRotationValue::from_consensus_value_verified(context, self.commit.value())?;
        let semantic_digest = key_rotation_semantic_digest(context, self.commit.value().as_bytes());
        Ok(VerifiedKeyRotationCertificateParts {
            target: verified.target,
            receiver_keys: verified.receiver_keys,
            semantic_digest,
            value,
        })
    }

    pub fn target_committee(
        &self,
        context: &KeyRotationContext,
    ) -> Result<Committee, KeyRotationError> {
        self.verify(context)
    }

    pub fn resulting_receiver_keys(
        &self,
        context: &KeyRotationContext,
    ) -> Result<ReceiverKeyAccumulatorCommitment, KeyRotationError> {
        self.verify_rotation(context).map(|verified| verified.receiver_keys)
    }

    /// Witness-independent commitment used by epoch-history continuity.
    ///
    /// PRECOMMIT signature vectors are intentionally excluded: honest parties may retain
    /// different valid quorum subsets for the same canonical rotation value.
    pub fn semantic_digest(
        &self,
        context: &KeyRotationContext,
    ) -> Result<[u8; 32], KeyRotationError> {
        self.verify_certificate_parts(context).map(|parts| parts.semantic_digest)
    }

    /// Return whether two independently assembled quorum certificates prove the same decision.
    ///
    /// Honest collectors can retain different exact `n-f` PRECOMMIT witness subsets (and can
    /// learn the decision in different views). Those byte-distinct certificates are equivalent
    /// when they bind the same trusted context and canonical rotation value.
    pub fn proves_same_decision(
        &self,
        other: &Self,
        context: &KeyRotationContext,
    ) -> Result<bool, KeyRotationError> {
        Ok(self.semantic_digest(context)? == other.semantic_digest(context)?)
    }

    pub fn encode(&self, context: &KeyRotationContext) -> Result<Vec<u8>, KeyRotationError> {
        drop(self.verify(context)?);
        let encoded = postcard::to_allocvec(self).map_err(|_| KeyRotationError::Serialization)?;
        if encoded.len() > MAX_KEY_ROTATION_CERTIFICATE_BYTES {
            return Err(KeyRotationError::CertificateTooLarge {
                actual: encoded.len(),
                maximum: MAX_KEY_ROTATION_CERTIFICATE_BYTES,
            });
        }
        Ok(encoded)
    }

    pub fn decode(context: &KeyRotationContext, bytes: &[u8]) -> Result<Self, KeyRotationError> {
        let certificate = Self::decode_embedded(bytes)?;
        drop(certificate.verify(context)?);
        Ok(certificate)
    }

    /// Canonically decode the current certificate wrapper used by authenticated epoch history.
    ///
    /// This deliberately does not establish trust by verifying against its own embedded context.
    /// The caller must reconstruct the expected context from the authenticated predecessor link
    /// and call [`Self::verify`].
    pub fn decode_embedded(bytes: &[u8]) -> Result<Self, KeyRotationError> {
        if bytes.len() > MAX_KEY_ROTATION_CERTIFICATE_BYTES {
            return Err(KeyRotationError::CertificateTooLarge {
                actual: bytes.len(),
                maximum: MAX_KEY_ROTATION_CERTIFICATE_BYTES,
            });
        }
        let (certificate, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| KeyRotationError::Serialization)?;
        if !trailing.is_empty() {
            return Err(KeyRotationError::TrailingCertificateBytes);
        }
        let canonical =
            postcard::to_allocvec(&certificate).map_err(|_| KeyRotationError::Serialization)?;
        if canonical != bytes {
            return Err(KeyRotationError::NonCanonicalCertificate);
        }
        certificate.context.validate()?;
        if certificate.version != KEY_ROTATION_CERTIFICATE_VERSION
            || certificate.context_digest != certificate.context.digest()
        {
            return Err(KeyRotationError::WrongCertificateContext);
        }
        Ok(certificate)
    }

    #[must_use]
    pub const fn embedded_context(&self) -> &KeyRotationContext {
        &self.context
    }

    pub fn value(
        &self,
        context: &KeyRotationContext,
    ) -> Result<KeyRotationValue, KeyRotationError> {
        self.verify_certificate_parts(context).map(|parts| parts.value)
    }

    #[must_use]
    pub fn commit_certificate(&self) -> &CommitCertificate {
        &self.commit
    }

    /// Return concrete same-view double-vote evidence for conflicting decisions.
    ///
    /// The generic core deliberately returns `CrossViewConflict` instead of blaming individual
    /// overlap signers when the certificates are from different views.
    pub fn conflicting_signers(
        &self,
        other: &Self,
        context: &KeyRotationContext,
    ) -> Result<Vec<PartyId>, KeyRotationError> {
        drop(self.verify(context)?);
        drop(other.verify(context)?);
        self.commit
            .conflicting_signers(&other.commit, &context.consensus_context()?)
            .map_err(KeyRotationError::Consensus)
    }
}

fn key_rotation_semantic_digest(context: &KeyRotationContext, value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ROTATION_SEMANTIC_VALUE_DOMAIN);
    hasher.update(&context.digest());
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

/// Stateless predicate suitable for [`crate::deposit_consensus::DepositConsensus::handle_with_value_validator`].
#[must_use]
pub fn valid_key_rotation_consensus_value(
    context: &KeyRotationContext,
    value: &ConsensusValue,
) -> bool {
    KeyRotationValue::from_consensus_value(context, value).is_ok()
}

/// One authenticated, portable key-rotation protocol payload.
///
/// The outer QUIC connection authenticates the immediate relay. Advertisements and consensus
/// messages additionally identify their original signer; certificates are intentionally portable
/// and may be relayed by any source-committee member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyRotationWire {
    Advertisement(SignedEnvelope),
    FallbackVote(SignedEnvelope),
    Consensus(SignedEnvelope),
    ViewCertificate(ViewChangeCertificate),
    Certificate(KeyRotationCertificate),
}

/// Stable logical slot used by the durable retry outbox.
///
/// Replacing obsolete views instead of accumulating every failed delivery means one silent peer
/// cannot exhaust the round merely by withholding transport acknowledgements.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum KeyRotationDeliveryKind {
    Advertisement,
    FallbackVote,
    Proposal { view: u64 },
    Prevote { view: u64 },
    Precommit { view: u64 },
    ViewChange { target_view: u64 },
    ViewCertificate { target_view: u64 },
    Certificate,
}

impl KeyRotationDeliveryKind {
    const fn view(self) -> Option<u64> {
        match self {
            Self::Advertisement | Self::FallbackVote | Self::Certificate => None,
            Self::Proposal { view } | Self::Prevote { view } | Self::Precommit { view } => {
                Some(view)
            }
            Self::ViewChange { target_view } | Self::ViewCertificate { target_view } => {
                Some(target_view)
            }
        }
    }

    /// Causal order for one recipient within this rotation context.
    ///
    /// A higher-view proposal embeds its verified view-change certificate and can initialize an
    /// otherwise absent reducer. It therefore precedes the standalone view-change traffic for the
    /// same target view; reducer validation remains the authority for whether it is admissible.
    #[must_use]
    pub const fn relay_order(self) -> (u64, u8) {
        match self {
            Self::Advertisement => (0, 0),
            Self::FallbackVote => (0, 1),
            Self::Proposal { view } => (view, 2),
            Self::ViewChange { target_view } => (target_view, 3),
            Self::ViewCertificate { target_view } => (target_view, 4),
            Self::Prevote { view } => (view, 5),
            Self::Precommit { view } => (view, 6),
            // Committing clears every nonterminal outbox slot before this is inserted.
            Self::Certificate => (u64::MAX, 7),
        }
    }

    const fn recipient_relay_order(self, proposal_pending: bool) -> (u8, u64, u8) {
        let (view, phase) = self.relay_order();
        if proposal_pending && matches!(self, Self::Proposal { .. }) {
            (0, view, phase)
        } else {
            (1, view, phase)
        }
    }
}

/// Content-authenticated handle which may be acknowledged only after a recipient durably accepts
/// the matching payload.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct KeyRotationMessageId {
    pub context: [u8; 32],
    pub recipient: PartyId,
    pub kind: KeyRotationDeliveryKind,
    pub digest: [u8; 32],
}

/// A pending durable delivery. Reading it is non-destructive; [`KeyRotationRound::acknowledge`]
/// removes only an exact content digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingKeyRotationMessage {
    /// Target epoch named by the authenticated rotation context. Relays use this explicit value
    /// to order a predecessor activation ahead of all work for a later epoch without reparsing
    /// opaque signed envelopes.
    pub target_epoch: u64,
    pub id: KeyRotationMessageId,
    pub wire: KeyRotationWire,
}

/// Build the durable fan-out for a target member's signed advertisement.
///
/// This is the joining-member path: a target-only party does not own a source consensus round, but
/// it must advertise its independently persisted successor key to every source consensus member.
/// The caller persists these immutable retry records before releasing them to QUIC.
pub fn pending_key_rotation_advertisements(
    context: &KeyRotationContext,
    target_capability: &PersistedKeyAdvertisementIdentity,
) -> Result<Vec<PendingKeyRotationMessage>, KeyRotationError> {
    let advertisement = sign_key_advertisement(context, target_capability)?;
    let sender = advertisement.from;
    let wire = KeyRotationWire::Advertisement(advertisement);
    let digest = key_rotation_wire_digest(&wire)?;
    Ok(context
        .source()
        .members
        .iter()
        .map(|member| member.id)
        .filter(|recipient| *recipient != sender)
        .map(|recipient| PendingKeyRotationMessage {
            target_epoch: context.target_epoch(),
            id: KeyRotationMessageId {
                context: context.digest(),
                recipient,
                kind: KeyRotationDeliveryKind::Advertisement,
                digest,
            },
            wire: wire.clone(),
        })
        .collect())
}

/// Construct the content-bound retry item for an immutable, locally verified certificate.
/// Runtimes use this after retiring the large reducer snapshot so a permanently offline peer
/// cannot block later epochs while restart-safe certificate catch-up remains available.
pub fn pending_key_rotation_certificate(
    context: &KeyRotationContext,
    certificate: &KeyRotationCertificate,
    recipient: PartyId,
) -> Result<PendingKeyRotationMessage, KeyRotationError> {
    let verified = certificate.verify_rotation_certificate(context)?;
    pending_verified_key_rotation_certificate(context, certificate, &verified, recipient)
}

/// Build one retry item from the exact certificate represented by a prior verified result.
///
/// The wire digest binds the complete witness representation, so a caller cannot pair a verified
/// result with an unverified or byte-distinct certificate while avoiding certificate validation.
pub fn pending_verified_key_rotation_certificate(
    context: &KeyRotationContext,
    certificate: &KeyRotationCertificate,
    verified: &VerifiedKeyRotationCertificate,
    recipient: PartyId,
) -> Result<PendingKeyRotationMessage, KeyRotationError> {
    if !context.is_participant(recipient) {
        return Err(CommitteeError::UnknownParty(recipient).into());
    }
    let wire = KeyRotationWire::Certificate(certificate.clone());
    let digest = key_rotation_wire_digest(&wire)?;
    if context.digest() != verified.context_digest || digest != verified.certificate_wire_digest {
        return Err(KeyRotationError::WrongVerifiedCertificate);
    }
    Ok(PendingKeyRotationMessage {
        target_epoch: context.target_epoch(),
        id: KeyRotationMessageId {
            context: context.digest(),
            recipient,
            kind: KeyRotationDeliveryKind::Certificate,
            digest,
        },
        wire,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct KeyRotationOutboxEntry {
    digest: [u8; 32],
    wire: KeyRotationWire,
    recipients: BTreeSet<PartyId>,
}

/// Observable result of one atomic key-rotation reducer transition.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyRotationRoundStep {
    pub changed: bool,
    pub duplicate: bool,
    pub committed: Option<KeyRotationCertificate>,
    pub evidence: Vec<EquivocationEvidence>,
}

/// Durable, transport-independent state for one party in one dynamic encryption-key rotation.
///
/// Callers persist the whole encoded round before releasing anything returned by
/// [`Self::pending_messages`]. The outbox is part of the same value, so a crash cannot retain a
/// signed vote while forgetting its network effect. The type owns no secret identity material;
/// callers keep the source and target X25519 handles until the successor activation certificate is
/// durable and erase the source handle only after that cutover.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeyRotationRound {
    state_version: u16,
    context: KeyRotationContext,
    local_party: PartyId,
    advertisements: BTreeMap<PartyId, SignedEnvelope>,
    fallback_votes: BTreeMap<PartyId, SignedEnvelope>,
    consensus: Option<DepositConsensus>,
    outbox: BTreeMap<KeyRotationDeliveryKind, KeyRotationOutboxEntry>,
}

#[derive(Deserialize)]
struct UncheckedKeyRotationRound {
    state_version: u16,
    context: KeyRotationContext,
    local_party: PartyId,
    advertisements: BTreeMap<PartyId, SignedEnvelope>,
    fallback_votes: BTreeMap<PartyId, SignedEnvelope>,
    consensus: Option<DepositConsensus>,
    outbox: BTreeMap<KeyRotationDeliveryKind, KeyRotationOutboxEntry>,
}

impl<'de> Deserialize<'de> for KeyRotationRound {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let unchecked = UncheckedKeyRotationRound::deserialize(deserializer)?;
        let round = Self {
            state_version: unchecked.state_version,
            context: unchecked.context,
            local_party: unchecked.local_party,
            advertisements: unchecked.advertisements,
            fallback_votes: unchecked.fallback_votes,
            consensus: unchecked.consensus,
            outbox: unchecked.outbox,
        };
        round.validate_internal().map_err(D::Error::custom)?;
        Ok(round)
    }
}

impl KeyRotationRound {
    pub fn new(
        context: KeyRotationContext,
        local_party: PartyId,
    ) -> Result<Self, KeyRotationError> {
        context.validate()?;
        context.source().member(local_party)?;
        Ok(Self {
            state_version: KEY_ROTATION_ROUND_STATE_VERSION,
            context,
            local_party,
            advertisements: BTreeMap::new(),
            fallback_votes: BTreeMap::new(),
            consensus: None,
            outbox: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn context(&self) -> &KeyRotationContext {
        &self.context
    }

    #[must_use]
    pub const fn local_party(&self) -> PartyId {
        self.local_party
    }

    #[must_use]
    pub fn view(&self) -> u64 {
        self.consensus.as_ref().map_or(0, DepositConsensus::view)
    }

    #[must_use]
    pub fn advertisement_count(&self) -> usize {
        self.advertisements.len()
    }

    #[must_use]
    pub fn fallback_vote_count(&self) -> usize {
        self.fallback_votes.len()
    }

    /// Return the exact public key authenticated by one retained advertisement. Runtime restore
    /// uses this to bind the encrypted target-epoch secret to the reducer snapshot before the
    /// identity is allowed to sign another vote or decrypt AVSS traffic.
    pub fn advertised_key(&self, party: PartyId) -> Result<Option<[u8; 32]>, KeyRotationError> {
        self.advertisements
            .get(&party)
            .map(|advertisement| {
                verify_key_advertisement(&self.context, advertisement)
                    .map(|verified| verified.next_key)
            })
            .transpose()
    }

    #[must_use]
    pub fn evidence(&self) -> Option<&std::collections::VecDeque<EquivocationEvidence>> {
        self.consensus.as_ref().map(DepositConsensus::evidence)
    }

    /// Sign, retain, and durably enqueue this party's target-epoch advertisement.
    pub fn advertise(
        &mut self,
        target_capability: &PersistedKeyAdvertisementIdentity,
        receiver_keys: &ReceiverKeyAccumulatorStore,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        let target_identity = target_capability.identity();
        if target_identity.party() != self.local_party {
            return Err(KeyRotationError::WrongLocalRotationIdentity);
        }
        let before = self.clone();
        let result = (|| {
            let advertisement = sign_key_advertisement(&self.context, target_capability)?;
            let inserted = self.insert_advertisement(advertisement.clone())?;
            if inserted {
                self.enqueue_for_peers(KeyRotationWire::Advertisement(advertisement))?;
            }
            let mut step = self.maybe_start_consensus(target_identity, receiver_keys)?;
            step.changed |= inserted;
            step.duplicate |= !inserted;
            Ok(step)
        })();
        if result.is_err() {
            *self = before;
        }
        result
    }

    /// Persist this source party's sole fallback vote and retry it to every other source member.
    ///
    /// Production calls this only from the local persistent pacemaker after the schedule-owned
    /// fallback deadline. Receiving a remote vote never invokes this method.
    pub fn authorize_fallback(
        &mut self,
        source_identity: &Identity,
        receiver_keys: &ReceiverKeyAccumulatorStore,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        self.ensure_local_identity(source_identity)?;
        let before = self.clone();
        let result = (|| {
            let vote = sign_selection_fallback_vote(&self.context, source_identity)?;
            let inserted = self.insert_fallback_vote(vote.clone())?;
            if inserted {
                self.enqueue_for_peers(KeyRotationWire::FallbackVote(vote))?;
            }
            let mut step = self.maybe_start_consensus(source_identity, receiver_keys)?;
            step.changed |= inserted;
            step.duplicate |= !inserted;
            Ok(step)
        })();
        if result.is_err() {
            *self = before;
        }
        result
    }

    /// Authenticate and reduce one key-rotation wire message from a mutually authenticated peer.
    pub fn handle_wire(
        &mut self,
        authenticated_party: PartyId,
        wire: KeyRotationWire,
        local_identity: &Identity,
        receiver_keys: &ReceiverKeyAccumulatorStore,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        self.ensure_local_identity(local_identity)?;
        let before = self.clone();
        let result =
            self.handle_wire_inner(authenticated_party, wire, local_identity, receiver_keys);
        if result.is_err() {
            *self = before;
        }
        result
    }

    /// Reduce an exact certificate which was fully verified before crossing a blocking boundary.
    ///
    /// The capability is bound to the complete certificate wire representation. The generic
    /// reducer still authenticates the quorum signatures and state transition, but its value
    /// callback need not replay the receiver-key sparse proof.
    pub fn handle_verified_certificate(
        &mut self,
        authenticated_party: PartyId,
        certificate: KeyRotationCertificate,
        verified: &VerifiedKeyRotationCertificate,
        local_identity: &Identity,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        self.ensure_local_identity(local_identity)?;
        verified.authenticate_exact_certificate(&self.context, &certificate)?;
        let before = self.clone();
        let result = (|| {
            if !self.context.is_participant(authenticated_party) {
                return Err(CommitteeError::UnknownParty(authenticated_party).into());
            }
            let consensus_context = self.context.consensus_context()?;
            let consensus = match self.consensus.as_mut() {
                Some(consensus) => consensus,
                None => self
                    .consensus
                    .insert(DepositConsensus::new(consensus_context, self.local_party)?),
            };
            // `verified` already authenticated this exact certificate's canonical value and
            // accumulator update. The generic core continues to verify its quorum signatures.
            let generic = consensus.handle_commit_certificate_with_validator(
                certificate.commit_certificate().clone(),
                |_| true,
            )?;
            self.apply_consensus_step_inner(generic, Some(&certificate))
        })();
        if result.is_err() {
            *self = before;
        }
        result
    }

    fn handle_wire_inner(
        &mut self,
        authenticated_party: PartyId,
        wire: KeyRotationWire,
        local_identity: &Identity,
        receiver_keys: &ReceiverKeyAccumulatorStore,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        match wire {
            KeyRotationWire::Advertisement(envelope) => {
                self.context.target_policy().eligible().member(authenticated_party)?;
                if envelope.from != authenticated_party {
                    return Err(KeyRotationError::WrongAuthenticatedParty);
                }
                let inserted = self.insert_advertisement(envelope)?;
                let mut step = self.maybe_start_consensus(local_identity, receiver_keys)?;
                step.changed |= inserted;
                step.duplicate |= !inserted;
                Ok(step)
            }
            KeyRotationWire::FallbackVote(envelope) => {
                self.context.source().member(authenticated_party)?;
                if envelope.from != authenticated_party {
                    return Err(KeyRotationError::WrongAuthenticatedParty);
                }
                let inserted = self.insert_fallback_vote(envelope)?;
                // A remote vote is only authenticated, stored, and reduced. It never causes this
                // party to sign its own fallback statement; that authority belongs exclusively to
                // the deadline-gated local scheduler.
                let mut step = self.maybe_start_consensus(local_identity, receiver_keys)?;
                step.changed |= inserted;
                step.duplicate |= !inserted;
                Ok(step)
            }
            KeyRotationWire::Consensus(envelope) => {
                self.context.source().member(authenticated_party)?;
                if envelope.from != authenticated_party {
                    return Err(KeyRotationError::WrongAuthenticatedParty);
                }
                // Bind and authenticate the envelope before reporting local readiness. Besides
                // producing an accurate stale/foreign-context error, this lets a lagging source
                // initialize directly from a leader proposal: the proposal carries the complete
                // signed advertisement set and accumulator update, so a separate local ad cache is
                // not a safety prerequisite.
                let consensus_context = self.context.consensus_context()?;
                let decoded = decode_consensus_message(&consensus_context, &envelope)?;
                if self.consensus.is_none() {
                    if !matches!(decoded.body, ConsensusMessageBody::Proposal(_)) {
                        return Err(KeyRotationError::ConsensusNotReady);
                    }
                    self.consensus =
                        Some(DepositConsensus::new(consensus_context, self.local_party)?);
                }
                let consensus = self.consensus.as_mut().expect("initialized above");
                if consensus.commit().is_some() {
                    return Ok(KeyRotationRoundStep { duplicate: true, ..Default::default() });
                }
                let generic = if consensus.started() {
                    consensus.handle_with_value_validator(local_identity, envelope, |value| {
                        valid_key_rotation_consensus_value(&self.context, value)
                    })
                } else {
                    consensus.handle_initial_proposal_with_value_validator(
                        local_identity,
                        envelope,
                        |value| valid_key_rotation_consensus_value(&self.context, value),
                    )
                };
                match generic {
                    Ok(step) => self.apply_consensus_step(step),
                    Err(ConsensusError::StaleView { .. }) => {
                        Ok(KeyRotationRoundStep { duplicate: true, ..Default::default() })
                    }
                    Err(error) => Err(KeyRotationError::Consensus(error)),
                }
            }
            KeyRotationWire::ViewCertificate(certificate) => {
                self.context.source().member(authenticated_party)?;
                let consensus =
                    self.consensus.as_mut().ok_or(KeyRotationError::ConsensusNotReady)?;
                if consensus.commit().is_some() {
                    certificate.verify(&self.context.consensus_context()?)?;
                    return Ok(KeyRotationRoundStep { duplicate: true, ..Default::default() });
                }
                let generic = consensus.handle_view_certificate_with_validator(
                    local_identity,
                    certificate,
                    |value| valid_key_rotation_consensus_value(&self.context, value),
                );
                match generic {
                    Ok(step) => self.apply_consensus_step(step),
                    Err(ConsensusError::StaleView { .. }) => {
                        Ok(KeyRotationRoundStep { duplicate: true, ..Default::default() })
                    }
                    Err(error) => Err(KeyRotationError::Consensus(error)),
                }
            }
            KeyRotationWire::Certificate(certificate) => {
                if !self.context.is_participant(authenticated_party) {
                    return Err(CommitteeError::UnknownParty(authenticated_party).into());
                }
                drop(certificate.verify(&self.context)?);
                let consensus_context = self.context.consensus_context()?;
                let consensus = match self.consensus.as_mut() {
                    Some(consensus) => consensus,
                    None => self
                        .consensus
                        .insert(DepositConsensus::new(consensus_context, self.local_party)?),
                };
                let generic = consensus.handle_commit_certificate_with_validator(
                    certificate.commit_certificate().clone(),
                    |value| valid_key_rotation_consensus_value(&self.context, value),
                )?;
                self.apply_consensus_step(generic)
            }
        }
    }

    /// Ask the generic BFT reducer to leave a stalled view. The clock/pacemaker stays outside this
    /// deterministic state machine.
    pub fn request_view_change(
        &mut self,
        local_identity: &Identity,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        self.ensure_local_identity(local_identity)?;
        let before = self.clone();
        let result = (|| {
            let consensus = self.consensus.as_mut().ok_or(KeyRotationError::ConsensusNotReady)?;
            if consensus.commit().is_some() {
                return Ok(KeyRotationRoundStep { duplicate: true, ..Default::default() });
            }
            let requested_view =
                consensus.view().checked_add(1).ok_or(ConsensusError::ViewExhausted)?;
            let step = consensus.request_view_change(local_identity)?;
            let mut result = self.apply_consensus_step(step)?;
            // Requesting a view change is an irrevocable local decision not to vote again in the
            // abandoned view. Remove its phase traffic even when this call repaired a restored
            // duplicate request and the reducer has not yet collected a quorum to enter the new
            // view. Advertisement and view-change/certificate slots remain independently
            // retryable.
            result.changed |= self.prune_abandoned_consensus_phases(requested_view);
            Ok(result)
        })();
        if result.is_err() {
            *self = before;
        }
        result
    }

    #[must_use]
    pub fn certificate(&self) -> Option<KeyRotationCertificate> {
        self.consensus
            .as_ref()
            .and_then(DepositConsensus::commit)
            .cloned()
            .and_then(|commit| KeyRotationCertificate::from_commit(&self.context, commit).ok())
    }

    /// Snapshot pending deliveries without removing them. The first pass chooses one message per
    /// recipient, preventing one recipient's multiple slots from monopolizing an ordinary batch.
    /// While a self-contained proposal remains pending for a recipient, its redundant standalone
    /// advertisement is withheld from this multi-peer batch so a downstream earliest-message
    /// reducer cannot select the advertisement over the proposal. The advertisement remains
    /// durable and becomes eligible immediately after that recipient acknowledges the proposal.
    #[must_use]
    pub fn pending_messages(&self, limit: usize) -> Vec<PendingKeyRotationMessage> {
        // `MAX_KEY_ROTATION_OUTBOX_ENTRIES` bounds distinct payload slots, not point-to-point
        // deliveries. Clamping a delivery batch to that value deterministically starved the last
        // peer of a maximum-size committee on every retry.
        let limit = limit.min(MAX_KEY_ROTATION_OUTBOX_RECIPIENTS);
        if limit == 0 {
            return Vec::new();
        }
        let mut selected = BTreeSet::new();
        let mut result = Vec::with_capacity(limit.min(self.outbox.len()));
        for recipient in self.context.participants() {
            if recipient == self.local_party {
                continue;
            }
            let proposal_pending = self.has_pending_proposal(recipient);
            if let Some((kind, entry)) = self
                .outbox
                .iter()
                .filter(|(_, entry)| entry.recipients.contains(&recipient))
                .min_by_key(|(kind, _)| kind.recipient_relay_order(proposal_pending))
            {
                selected.insert((recipient, *kind));
                result.push(self.pending_message(recipient, *kind, entry));
                if result.len() == limit {
                    return result;
                }
            }
        }
        for (kind, entry) in &self.outbox {
            for recipient in &entry.recipients {
                if *kind == KeyRotationDeliveryKind::Advertisement
                    && self.has_pending_proposal(*recipient)
                {
                    continue;
                }
                if !selected.insert((*recipient, *kind)) {
                    continue;
                }
                result.push(self.pending_message(*recipient, *kind, entry));
                if result.len() == limit {
                    return result;
                }
            }
        }
        result
    }

    /// Snapshot retries for one concrete peer. A transport which services peers round-robin can
    /// use this API to preserve fairness even with a batch size smaller than the committee.
    #[must_use]
    pub fn pending_messages_for(
        &self,
        recipient: PartyId,
        limit: usize,
    ) -> Vec<PendingKeyRotationMessage> {
        let proposal_pending = self.has_pending_proposal(recipient);
        let mut pending = self
            .outbox
            .iter()
            .filter(|(_, entry)| entry.recipients.contains(&recipient))
            .collect::<Vec<_>>();
        pending.sort_by_key(|(kind, _)| kind.recipient_relay_order(proposal_pending));
        pending
            .into_iter()
            .take(limit.min(MAX_KEY_ROTATION_OUTBOX_ENTRIES))
            .map(|(kind, entry)| self.pending_message(recipient, *kind, entry))
            .collect()
    }

    fn has_pending_proposal(&self, recipient: PartyId) -> bool {
        self.outbox.iter().any(|(kind, entry)| {
            matches!(kind, KeyRotationDeliveryKind::Proposal { .. })
                && entry.recipients.contains(&recipient)
        })
    }

    /// Remove exact, durably accepted deliveries. Stale or foreign digests are harmless no-ops;
    /// an identifier from another rotation context is rejected rather than silently consumed.
    pub fn acknowledge(
        &mut self,
        acknowledgements: &[KeyRotationMessageId],
    ) -> Result<usize, KeyRotationError> {
        let context = self.context.digest();
        if acknowledgements.iter().any(|acknowledgement| acknowledgement.context != context) {
            return Err(KeyRotationError::WrongOutboxContext);
        }
        let mut removed = 0;
        for acknowledgement in acknowledgements {
            let mut remove_entry = false;
            if let Some(entry) = self.outbox.get_mut(&acknowledgement.kind)
                && entry.digest == acknowledgement.digest
                && entry.recipients.remove(&acknowledgement.recipient)
            {
                removed += 1;
                remove_entry = entry.recipients.is_empty();
            }
            if remove_entry {
                self.outbox.remove(&acknowledgement.kind);
            }
        }
        Ok(removed)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KeyRotationError> {
        self.validate_internal()?;
        let encoded = postcard::to_allocvec(self).map_err(|_| KeyRotationError::Serialization)?;
        if encoded.len() > MAX_KEY_ROTATION_ROUND_STATE_BYTES {
            return Err(KeyRotationError::RoundStateTooLarge {
                actual: encoded.len(),
                maximum: MAX_KEY_ROTATION_ROUND_STATE_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Restore only against a locally reconstructed context and party. A wire-supplied context is
    /// never authoritative, even when every signature nested in the snapshot is valid.
    pub fn decode(
        expected_context: &KeyRotationContext,
        expected_local_party: PartyId,
        bytes: &[u8],
    ) -> Result<Self, KeyRotationError> {
        expected_context.validate()?;
        if bytes.len() > MAX_KEY_ROTATION_ROUND_STATE_BYTES {
            return Err(KeyRotationError::RoundStateTooLarge {
                actual: bytes.len(),
                maximum: MAX_KEY_ROTATION_ROUND_STATE_BYTES,
            });
        }
        let (round, trailing) = postcard::take_from_bytes::<Self>(bytes)
            .map_err(|_| KeyRotationError::Serialization)?;
        if !trailing.is_empty() {
            return Err(KeyRotationError::TrailingRoundStateBytes);
        }
        let canonical =
            postcard::to_allocvec(&round).map_err(|_| KeyRotationError::Serialization)?;
        if canonical != bytes {
            return Err(KeyRotationError::NonCanonicalRoundState);
        }
        if round.context != *expected_context || round.local_party != expected_local_party {
            return Err(KeyRotationError::WrongRoundStateContext);
        }
        Ok(round)
    }

    fn ensure_local_identity(&self, identity: &Identity) -> Result<(), KeyRotationError> {
        let source_member = self.context.source().member(self.local_party)?;
        if identity.party() != self.local_party
            || identity.signing_public_key() != source_member.signing_key
        {
            return Err(KeyRotationError::WrongLocalRotationIdentity);
        }
        Ok(())
    }

    fn insert_advertisement(
        &mut self,
        advertisement: SignedEnvelope,
    ) -> Result<bool, KeyRotationError> {
        let verified = verify_key_advertisement(&self.context, &advertisement)?;
        if let Some(existing) = self.advertisements.get(&verified.party) {
            if existing == &advertisement {
                return Ok(false);
            }
            return Err(KeyRotationError::ConflictingAdvertisement(verified.party));
        }
        if self.advertisements.len() == usize::from(self.context.target_policy().eligible().n()) {
            return Err(KeyRotationError::TooManyAdvertisements);
        }
        self.advertisements.insert(verified.party, advertisement);
        Ok(true)
    }

    fn insert_fallback_vote(&mut self, vote: SignedEnvelope) -> Result<bool, KeyRotationError> {
        let party = verify_selection_fallback_vote(&self.context, &vote)?;
        if let Some(existing) = self.fallback_votes.get(&party) {
            if existing == &vote {
                return Ok(false);
            }
            return Err(KeyRotationError::ConflictingFallbackVote(party));
        }
        if self.fallback_votes.len() == usize::from(self.context.source().n()) {
            return Err(KeyRotationError::TooManyFallbackVotes);
        }
        self.fallback_votes.insert(party, vote);
        Ok(true)
    }

    fn fallback_authorization(&self) -> Result<Option<FallbackAuthorization>, KeyRotationError> {
        let quorum = self.context.source_quorum();
        if self.fallback_votes.len() < quorum {
            return Ok(None);
        }
        FallbackAuthorization::new(
            &self.context,
            self.fallback_votes.values().take(quorum).cloned().collect(),
        )
        .map(Some)
    }

    fn candidate_value(
        &self,
        receiver_keys: &ReceiverKeyAccumulatorStore,
    ) -> Result<Option<KeyRotationValue>, KeyRotationError> {
        if receiver_keys.commitment() != self.context.target_policy().prior_receiver_keys() {
            return Err(KeyRotationError::WrongReceiverKeyAccumulator);
        }
        let mut next_keys = BTreeSet::new();
        let mut advertisements = Vec::with_capacity(self.context.selection_size());
        let mut selected = Vec::with_capacity(self.context.selection_size());
        // Preserve healthy membership independently of PartyId ordering. Source advertisers are
        // canonical within their class and always precede eligible-only spares; a spare is chosen
        // only when the exact desired size cannot be filled by fresh source advertisements.
        let source = self.context.source();
        let ordered = self
            .advertisements
            .values()
            .filter(|advertisement| source.member(advertisement.from).is_ok())
            .chain(
                self.advertisements
                    .values()
                    .filter(|advertisement| source.member(advertisement.from).is_err()),
            );
        for advertisement in ordered {
            let verified = verify_key_advertisement(&self.context, advertisement)?;
            // A stale Byzantine advertisement is validly signed but cannot become part of a
            // freshness-certified value. Skip it so one low-numbered stale advertiser cannot
            // block an otherwise live exact-size subset.
            if receiver_keys.try_contains_key(verified.next_key)? {
                continue;
            }
            if next_keys.insert(verified.next_key) {
                advertisements.push(advertisement.clone());
                selected.push((verified.party, verified.next_key));
                if advertisements.len() == self.context.selection_size() {
                    // Source-first selection is a liveness policy, not the accumulator's wire
                    // order. An eligible-only spare may have a lower PartyId than every retained
                    // source member, so canonicalize the exact chosen set before proving its
                    // append-only receiver-key update.
                    selected.sort_unstable_by_key(|(party, _)| *party);
                    let (history_update, _) =
                        receiver_keys.preview(self.context.target_epoch(), &selected)?;
                    let retained_source =
                        selected.iter().filter(|(party, _)| source.member(*party).is_ok()).count();
                    let authorization = if retained_source < self.context.primary_source_overlap() {
                        let Some(authorization) = self.fallback_authorization()? else {
                            return Ok(None);
                        };
                        Some(authorization)
                    } else {
                        None
                    };
                    return Ok(Some(KeyRotationValue::new_with_authorization(
                        &self.context,
                        advertisements,
                        history_update,
                        authorization,
                    )?));
                }
            }
        }
        Ok(None)
    }

    fn maybe_start_consensus(
        &mut self,
        local_identity: &Identity,
        receiver_keys: &ReceiverKeyAccumulatorStore,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        if self.consensus.is_some() {
            return Ok(KeyRotationRoundStep::default());
        }
        let Some(candidate) = self.candidate_value(receiver_keys)? else {
            return Ok(KeyRotationRoundStep::default());
        };
        let mut consensus =
            DepositConsensus::new(self.context.consensus_context()?, self.local_party)?;
        let step = consensus.start(local_identity, candidate.to_consensus_value(&self.context)?)?;
        self.consensus = Some(consensus);
        self.apply_consensus_step(step)
    }

    fn apply_consensus_step(
        &mut self,
        step: ConsensusStep,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        self.apply_consensus_step_inner(step, None)
    }

    fn apply_consensus_step_inner(
        &mut self,
        step: ConsensusStep,
        verified_certificate: Option<&KeyRotationCertificate>,
    ) -> Result<KeyRotationRoundStep, KeyRotationError> {
        let committed = step
            .commit
            .as_ref()
            .map(|commit| {
                if let Some(certificate) = verified_certificate {
                    if certificate.commit_certificate() != commit {
                        return Err(KeyRotationError::WrongVerifiedCertificate);
                    }
                    Ok(certificate.clone())
                } else {
                    KeyRotationCertificate::from_commit(&self.context, commit.clone())
                }
            })
            .transpose()?;
        if let Some(certificate) = &committed {
            self.outbox.clear();
            if verified_certificate.is_some() {
                self.enqueue_for_peers_with_kind(
                    KeyRotationWire::Certificate(certificate.clone()),
                    KeyRotationDeliveryKind::Certificate,
                )?;
            } else {
                self.enqueue_for_peers(KeyRotationWire::Certificate(certificate.clone()))?;
            }
        } else {
            let current_view = self.view();
            self.prune_obsolete_views(current_view);
            for envelope in step.broadcast {
                self.enqueue_for_peers(KeyRotationWire::Consensus(envelope))?;
            }
            if let Some(certificate) = step.relay_view_certificate {
                self.enqueue_for_peers(KeyRotationWire::ViewCertificate(certificate))?;
            }
            if let Some(commit) = step.relay_commit_certificate {
                let certificate = if let Some(certificate) = verified_certificate {
                    if certificate.commit_certificate() != &commit {
                        return Err(KeyRotationError::WrongVerifiedCertificate);
                    }
                    certificate.clone()
                } else {
                    KeyRotationCertificate::from_commit(&self.context, commit)?
                };
                self.outbox.clear();
                if verified_certificate.is_some() {
                    self.enqueue_for_peers_with_kind(
                        KeyRotationWire::Certificate(certificate),
                        KeyRotationDeliveryKind::Certificate,
                    )?;
                } else {
                    self.enqueue_for_peers(KeyRotationWire::Certificate(certificate))?;
                }
            }
        }
        Ok(KeyRotationRoundStep {
            changed: step.changed,
            duplicate: step.duplicate,
            committed,
            evidence: step.evidence,
        })
    }

    fn enqueue_for_peers(&mut self, wire: KeyRotationWire) -> Result<(), KeyRotationError> {
        let kind = key_rotation_delivery_kind(&self.context, &wire)?;
        self.enqueue_for_peers_with_kind(wire, kind)
    }

    fn enqueue_for_peers_with_kind(
        &mut self,
        wire: KeyRotationWire,
        kind: KeyRotationDeliveryKind,
    ) -> Result<(), KeyRotationError> {
        let digest = key_rotation_wire_digest(&wire)?;
        let recipients = if kind == KeyRotationDeliveryKind::Certificate {
            self.context.participants()
        } else {
            self.context.source().members.iter().map(|member| member.id).collect()
        }
        .into_iter()
        .filter(|party| *party != self.local_party)
        .collect::<BTreeSet<_>>();
        if let Some(existing) = self.outbox.get(&kind) {
            if existing.digest != digest || existing.wire != wire {
                return Err(KeyRotationError::OutboxEquivocation);
            }
            return Ok(());
        }
        if self.outbox.len() == MAX_KEY_ROTATION_OUTBOX_ENTRIES {
            return Err(KeyRotationError::OutboxFull);
        }
        self.outbox.insert(kind, KeyRotationOutboxEntry { digest, wire, recipients });
        Ok(())
    }

    fn prune_obsolete_views(&mut self, current_view: u64) {
        self.outbox.retain(|kind, _| {
            *kind == KeyRotationDeliveryKind::Advertisement
                || *kind == KeyRotationDeliveryKind::FallbackVote
                || kind.view().is_some_and(|view| view >= current_view)
        });
    }

    fn prune_abandoned_consensus_phases(&mut self, requested_view: u64) -> bool {
        let before = self.outbox.len();
        self.outbox.retain(|kind, _| {
            !matches!(
                kind,
                KeyRotationDeliveryKind::Proposal { view }
                    | KeyRotationDeliveryKind::Prevote { view }
                    | KeyRotationDeliveryKind::Precommit { view }
                if *view < requested_view
            )
        });
        self.outbox.len() != before
    }

    fn pending_message(
        &self,
        recipient: PartyId,
        kind: KeyRotationDeliveryKind,
        entry: &KeyRotationOutboxEntry,
    ) -> PendingKeyRotationMessage {
        PendingKeyRotationMessage {
            target_epoch: self.context.target_epoch(),
            id: KeyRotationMessageId {
                context: self.context.digest(),
                recipient,
                kind,
                digest: entry.digest,
            },
            wire: entry.wire.clone(),
        }
    }

    fn validate_internal(&self) -> Result<(), KeyRotationError> {
        if self.state_version != KEY_ROTATION_ROUND_STATE_VERSION {
            return Err(KeyRotationError::InvalidRoundState("unsupported state version"));
        }
        self.context.validate()?;
        self.context.source().member(self.local_party)?;
        let outbox_recipients = self
            .outbox
            .values()
            .try_fold(0_usize, |count, entry| count.checked_add(entry.recipients.len()))
            .ok_or(KeyRotationError::InvalidRoundState("resource bound exceeded"))?;
        if self.advertisements.len() > usize::from(self.context.target_policy().eligible().n())
            || self.fallback_votes.len() > usize::from(self.context.source().n())
            || self.outbox.len() > MAX_KEY_ROTATION_OUTBOX_ENTRIES
            || outbox_recipients > MAX_KEY_ROTATION_OUTBOX_RECIPIENTS
        {
            return Err(KeyRotationError::InvalidRoundState("resource bound exceeded"));
        }
        for (party, advertisement) in &self.advertisements {
            let verified = verify_key_advertisement(&self.context, advertisement)?;
            if verified.party != *party {
                return Err(KeyRotationError::InvalidRoundState("advertisement map key mismatch"));
            }
        }
        for (party, vote) in &self.fallback_votes {
            if verify_selection_fallback_vote(&self.context, vote)? != *party {
                return Err(KeyRotationError::InvalidRoundState("fallback-vote map key mismatch"));
            }
        }

        let consensus_context = self.context.consensus_context()?;
        let committed = if let Some(consensus) = &self.consensus {
            if consensus.context() != &consensus_context
                || consensus.local_party() != self.local_party
            {
                return Err(KeyRotationError::InvalidRoundState("consensus context mismatch"));
            }
            consensus.validate_application_values(|value| {
                valid_key_rotation_consensus_value(&self.context, value)
            })?;
            consensus.commit().cloned()
        } else {
            None
        };

        for (kind, entry) in &self.outbox {
            if entry.recipients.is_empty()
                || entry.recipients.iter().any(|recipient| {
                    *recipient == self.local_party
                        || !delivery_recipient_allowed(&self.context, *kind, *recipient)
                })
                || entry.digest != key_rotation_wire_digest(&entry.wire)?
                || *kind != key_rotation_delivery_kind(&self.context, &entry.wire)?
            {
                return Err(KeyRotationError::InvalidRoundState("invalid outbox entry"));
            }
            match &entry.wire {
                KeyRotationWire::Advertisement(advertisement) => {
                    if advertisement.from != self.local_party
                        || self.advertisements.get(&self.local_party) != Some(advertisement)
                    {
                        return Err(KeyRotationError::InvalidRoundState(
                            "outbound advertisement differs from local state",
                        ));
                    }
                }
                KeyRotationWire::FallbackVote(vote) => {
                    if vote.from != self.local_party
                        || self.fallback_votes.get(&self.local_party) != Some(vote)
                    {
                        return Err(KeyRotationError::InvalidRoundState(
                            "outbound fallback vote differs from local state",
                        ));
                    }
                }
                KeyRotationWire::Consensus(envelope) => {
                    if envelope.from != self.local_party || self.consensus.is_none() {
                        return Err(KeyRotationError::InvalidRoundState(
                            "outbound consensus sender differs from local party",
                        ));
                    }
                }
                KeyRotationWire::ViewCertificate(_) => {
                    if self.consensus.is_none() {
                        return Err(KeyRotationError::InvalidRoundState(
                            "view certificate lacks reducer state",
                        ));
                    }
                }
                KeyRotationWire::Certificate(certificate) => {
                    let Some(commit) = &committed else {
                        return Err(KeyRotationError::InvalidRoundState(
                            "terminal outbox lacks local commit",
                        ));
                    };
                    if certificate.commit_certificate() != commit {
                        return Err(KeyRotationError::InvalidRoundState(
                            "terminal outbox differs from local commit",
                        ));
                    }
                }
            }
        }
        if committed.is_some()
            && self.outbox.keys().any(|kind| *kind != KeyRotationDeliveryKind::Certificate)
        {
            return Err(KeyRotationError::InvalidRoundState(
                "committed state retains obsolete deliveries",
            ));
        }
        Ok(())
    }
}

fn key_rotation_delivery_kind(
    context: &KeyRotationContext,
    wire: &KeyRotationWire,
) -> Result<KeyRotationDeliveryKind, KeyRotationError> {
    Ok(match wire {
        KeyRotationWire::Advertisement(advertisement) => {
            let _ = verify_key_advertisement(context, advertisement)?;
            KeyRotationDeliveryKind::Advertisement
        }
        KeyRotationWire::FallbackVote(vote) => {
            let _ = verify_selection_fallback_vote(context, vote)?;
            KeyRotationDeliveryKind::FallbackVote
        }
        KeyRotationWire::Consensus(envelope) => {
            let message = decode_consensus_message(&context.consensus_context()?, envelope)?;
            match message.body {
                ConsensusMessageBody::Proposal(proposal) => {
                    KeyRotationDeliveryKind::Proposal { view: proposal.view }
                }
                ConsensusMessageBody::Prevote(vote) => {
                    KeyRotationDeliveryKind::Prevote { view: vote.view }
                }
                ConsensusMessageBody::Precommit(vote) => {
                    KeyRotationDeliveryKind::Precommit { view: vote.view }
                }
                ConsensusMessageBody::ViewChange(change) => {
                    KeyRotationDeliveryKind::ViewChange { target_view: change.target_view }
                }
            }
        }
        KeyRotationWire::ViewCertificate(certificate) => {
            certificate.verify(&context.consensus_context()?)?;
            KeyRotationDeliveryKind::ViewCertificate { target_view: certificate.target_view() }
        }
        KeyRotationWire::Certificate(certificate) => {
            drop(certificate.verify(context)?);
            KeyRotationDeliveryKind::Certificate
        }
    })
}

fn delivery_recipient_allowed(
    context: &KeyRotationContext,
    kind: KeyRotationDeliveryKind,
    recipient: PartyId,
) -> bool {
    if kind == KeyRotationDeliveryKind::Certificate {
        context.is_participant(recipient)
    } else {
        context.source().member(recipient).is_ok()
    }
}

fn key_rotation_wire_digest(wire: &KeyRotationWire) -> Result<[u8; 32], KeyRotationError> {
    let encoded = postcard::to_allocvec(wire).map_err(|_| KeyRotationError::Serialization)?;
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ROTATION_WIRE_DIGEST_DOMAIN);
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn deserialize_members<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Member>, D::Error> {
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "committee members")
}

fn deserialize_advertisements<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SignedEnvelope>, D::Error> {
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "key advertisements")
}

fn deserialize_fallback_votes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SignedEnvelope>, D::Error> {
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "selection fallback votes")
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum KeyRotationError {
    #[error("committee error: {0}")]
    Committee(#[from] CommitteeError),
    #[error("threshold key error: {0}")]
    Key(#[from] KeyError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("receiver-key accumulator error: {0}")]
    ReceiverKeyAccumulator(#[from] ReceiverKeyAccumulatorError),
    #[error("unsupported key-rotation version")]
    UnsupportedVersion,
    #[error("invalid key-rotation context: {0}")]
    InvalidContext(&'static str),
    #[error("invalid configured target policy: {0}")]
    InvalidTargetPolicy(&'static str),
    #[error("registry handoff target is not activation-certified in the configured wallet domain")]
    InvalidRegistryHandoffTarget,
    #[error("key-rotation context is not canonical")]
    NonCanonicalContext,
    #[error("source committee is not canonically ordered")]
    NonCanonicalSourceCommittee,
    #[error("target committee is not canonically ordered")]
    NonCanonicalTargetCommittee,
    #[error("receiver-key accumulator belongs to another network")]
    WrongReceiverKeyAccumulatorNetwork,
    #[error("receiver-key accumulator store differs from the authenticated source commitment")]
    WrongReceiverKeyAccumulator,
    #[error(
        "receiver-key accumulator is through epoch {actual}, expected authenticated source epoch {expected}"
    )]
    WrongReceiverKeyAccumulatorEpoch { expected: u64, actual: u64 },
    #[error("source member {0} has a noncontributory X25519 key")]
    InvalidSourceKey(PartyId),
    #[error("joining target member {0} reuses a source Ed25519 signing key")]
    ReusedSourceSigningKey(PartyId),
    #[error(
        "eligible target pool has {actual} identities; desired {desired} with fault bound {fault_bound} requires at least desired+f"
    )]
    InsufficientEligibleCandidates { actual: u16, desired: u16, fault_bound: u16 },
    #[error("target identity is not the configured member's target-epoch identity")]
    WrongAdvertisementIdentity,
    #[error("local identity does not belong to this key-rotation party")]
    WrongLocalRotationIdentity,
    #[error("authenticated peer differs from the signed message origin")]
    WrongAuthenticatedParty,
    #[error("key advertisement has {actual} bytes; maximum is {maximum}")]
    AdvertisementTooLarge { actual: usize, maximum: usize },
    #[error("key advertisements must be portable broadcasts")]
    NonPortableAdvertisement,
    #[error("key advertisement uses the wrong session or sequence")]
    WrongAdvertisementSlot,
    #[error("key advertisement serialization failed")]
    Serialization,
    #[error("key advertisement has trailing bytes")]
    TrailingAdvertisementBytes,
    #[error("key advertisement encoding is not canonical")]
    NonCanonicalAdvertisement,
    #[error("key advertisement belongs to another rotation context")]
    WrongAdvertisementContext,
    #[error("key-rotation fallback vote has {actual} bytes; maximum is {maximum}")]
    FallbackVoteTooLarge { actual: usize, maximum: usize },
    #[error("key-rotation fallback votes must be portable broadcasts")]
    NonPortableFallbackVote,
    #[error("key-rotation fallback vote uses the wrong session or sequence")]
    WrongFallbackVoteSlot,
    #[error("key-rotation fallback vote has trailing bytes")]
    TrailingFallbackVoteBytes,
    #[error("key-rotation fallback vote encoding is not canonical")]
    NonCanonicalFallbackVote,
    #[error("key-rotation fallback vote belongs to another context or policy")]
    WrongFallbackVoteContext,
    #[error("party {0} sent conflicting key-rotation fallback votes")]
    ConflictingFallbackVote(PartyId),
    #[error("key-rotation fallback-vote map exceeds the source committee")]
    TooManyFallbackVotes,
    #[error("fallback authorization has {actual} source votes; exact source quorum is {expected}")]
    InvalidFallbackAuthorizationCount { actual: usize, expected: usize },
    #[error("fallback authorization votes are not strictly ordered by source party")]
    NonCanonicalFallbackAuthorization,
    #[error("party {0} advertised an all-zero X25519 key")]
    AllZeroNextKey(PartyId),
    #[error("party {0} advertised a low-order or noncontributory X25519 key")]
    NonContributoryNextKey(PartyId),
    #[error("party {0} advertised a non-canonical X25519 encoding")]
    NonCanonicalNextKey(PartyId),
    #[error("party {0} reused a historical or policy-reserved X25519 key")]
    ReusedPolicyKey(PartyId),
    #[error("key-rotation value belongs to another context")]
    WrongValueContext,
    #[error("key-rotation certificate belongs to another context")]
    WrongCertificateContext,
    #[error("key-rotation certificate differs from its verified registration result")]
    WrongVerifiedCertificate,
    #[error("key-rotation certificate has {actual} bytes; maximum is {maximum}")]
    CertificateTooLarge { actual: usize, maximum: usize },
    #[error("key-rotation certificate has trailing bytes")]
    TrailingCertificateBytes,
    #[error("key-rotation certificate encoding is not canonical")]
    NonCanonicalCertificate,
    #[error("advertisement count {actual} differs from exact selected committee size {expected}")]
    InvalidAdvertisementCount { actual: usize, expected: usize },
    #[error("advertisement set is not strictly ordered by party")]
    NonCanonicalAdvertisementSet,
    #[error("party {0} appears more than once in an advertisement set")]
    DuplicateAdvertiser(PartyId),
    #[error("party {0} sent conflicting key advertisements")]
    ConflictingAdvertisement(PartyId),
    #[error("advertisement map exceeds the target committee")]
    TooManyAdvertisements,
    #[error("multiple advertisers selected the same next X25519 key")]
    DuplicateNextKey,
    #[error(
        "selected successor retains {actual} eligible source members; policy requires at least {minimum}"
    )]
    InsufficientSourceRetention { actual: usize, minimum: usize },
    #[error(
        "selected successor retains {actual} eligible source members; primary policy requires {primary} without source fallback authorization"
    )]
    MissingFallbackAuthorization { actual: usize, primary: usize },
    #[error(
        "fallback authorization is forbidden when source retention {actual} already meets primary requirement {primary}"
    )]
    GratuitousFallbackAuthorization { actual: usize, primary: usize },
    #[error("target committee changed party {0}'s stable signing identity")]
    TargetChangedStableIdentity(PartyId),
    #[error("key-rotation value has {actual} bytes; maximum is {maximum}")]
    ValueTooLarge { actual: usize, maximum: usize },
    #[error("key-rotation value has trailing bytes")]
    TrailingValueBytes,
    #[error("key-rotation value encoding is not canonical")]
    NonCanonicalValue,
    #[error("key-rotation consensus is waiting for the exact desired number of advertisements")]
    ConsensusNotReady,
    #[error("key-rotation retry outbox is full")]
    OutboxFull,
    #[error("one key-rotation outbox slot contains conflicting payloads")]
    OutboxEquivocation,
    #[error("key-rotation acknowledgement belongs to another context")]
    WrongOutboxContext,
    #[error("key-rotation round state has {actual} bytes; maximum is {maximum}")]
    RoundStateTooLarge { actual: usize, maximum: usize },
    #[error("key-rotation round state has trailing bytes")]
    TrailingRoundStateBytes,
    #[error("key-rotation round state encoding is not canonical")]
    NonCanonicalRoundState,
    #[error("key-rotation round state differs from the trusted local context")]
    WrongRoundStateContext,
    #[error("invalid persisted key-rotation round: {0}")]
    InvalidRoundState(&'static str),
}

fn validate_new_key(
    context: &KeyRotationContext,
    party: PartyId,
    next_key: [u8; 32],
) -> Result<(), KeyRotationError> {
    if next_key == [0; 32] {
        return Err(KeyRotationError::AllZeroNextKey(party));
    }
    match validate_x25519_key(next_key) {
        Ok(()) => {}
        Err(InvalidX25519Key::AllZero) => {
            return Err(KeyRotationError::AllZeroNextKey(party));
        }
        Err(InvalidX25519Key::NonCanonical) => {
            return Err(KeyRotationError::NonCanonicalNextKey(party));
        }
        Err(InvalidX25519Key::NonContributory) => {
            return Err(KeyRotationError::NonContributoryNextKey(party));
        }
    }
    // Historical/bootstrap non-membership is proved only by the canonical sparse batch update
    // embedded in the consensus value. An advertisement alone is not a freshness certificate.
    if context.target_policy.eligible.members.iter().any(|member| member.encryption_key == next_key)
    {
        return Err(KeyRotationError::ReusedPolicyKey(party));
    }
    Ok(())
}

/// Deterministic X25519-shaped reference used only to bind stable eligibility identities through
/// the generic signed-envelope committee digest. The corresponding scalar is public by design;
/// callers must never use this value as an encryption key.
#[must_use]
pub(crate) fn eligibility_reference_key(
    epoch: u64,
    party: PartyId,
    signing_key: [u8; 32],
) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("threshold-monero/key-rotation-eligibility-reference/v1");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&party.0.to_le_bytes());
    hasher.update(&signing_key);
    X25519PublicKey::from(&StaticSecret::from(*hasher.finalize().as_bytes())).to_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvalidX25519Key {
    AllZero,
    NonCanonical,
    NonContributory,
}

fn validate_x25519_key(key: [u8; 32]) -> Result<(), InvalidX25519Key> {
    if key == [0; 32] {
        return Err(InvalidX25519Key::AllZero);
    }
    // X25519 accepts non-canonical field encodings. Committee identity does not: accepting an
    // alias would let byte-wise "new" or "distinct" keys denote a prior or peer group element.
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    if key.iter().rev().cmp(FIELD_MODULUS.iter().rev()) != std::cmp::Ordering::Less {
        return Err(InvalidX25519Key::NonCanonical);
    }
    // A fixed public validation scalar is sufficient: clamped X25519 multiplication yields zero
    // exactly for inputs with no contributory prime-order component.  No secret is involved.
    let validation_secret = StaticSecret::from([0xA5; 32]);
    let public = X25519PublicKey::from(key);
    if validation_secret.diffie_hellman(&public).as_bytes() == &[0; 32] {
        Err(InvalidX25519Key::NonContributory)
    } else {
        Ok(())
    }
}

/// Configuration-time check for separately provisioned bootstrap public keys.
#[must_use]
pub(crate) fn valid_x25519_public_key(key: [u8; 32]) -> bool {
    validate_x25519_key(key).is_ok()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_POINT};
    use rand_core::OsRng;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        config::NetworkKind,
        deposit_consensus::{
            CommitCertificate, ConsensusError, ConsensusMessageBody, DepositConsensus, Proposal,
            ViewChange, Vote, sign_consensus_message,
        },
        identity::EpochEncryptionSecret,
        keys::{PointBytes, SecretPolynomial, scalar_for_party},
    };

    fn reset_sparse_proof_verifications() {
        SPARSE_PROOF_VERIFICATIONS.with(|verifications| verifications.set(0));
    }

    fn sparse_proof_verifications() -> u64 {
        SPARSE_PROOF_VERIFICATIONS.with(Cell::get)
    }

    fn seed(party: PartyId) -> [u8; 32] {
        let mut seed = [u8::try_from(party.0).unwrap().wrapping_mul(37); 32];
        seed[..2].copy_from_slice(&party.0.to_le_bytes());
        seed
    }

    fn identity(party: PartyId, epoch: u64, encryption_tag: u8) -> Identity {
        let signing_seed = seed(party);
        let secret_bytes = [encryption_tag; 32];
        let public_key = X25519PublicKey::from(&StaticSecret::from(secret_bytes)).to_bytes();
        let persisted = EpochEncryptionSecret::from_decrypted(
            party,
            epoch,
            public_key,
            Zeroizing::new(secret_bytes),
        )
        .unwrap();
        Identity::from_encryption_secret(
            party,
            epoch,
            &signing_seed,
            Identity::signing_public_key_from_seed(&signing_seed).unwrap(),
            public_key,
            &persisted,
        )
        .unwrap()
    }

    fn receiver_key_store(
        network: [u8; 32],
        source: &Committee,
        eligible: &Committee,
    ) -> ReceiverKeyAccumulatorStore {
        // One source-epoch accumulator leaf exists per stable party. A canonical target policy
        // replaces overlapping eligibility keys with public reference sentinels, so prefer the
        // actual source key and add only eligible-only spares.
        let mut entries = source
            .members
            .iter()
            .map(|member| (member.id, member.encryption_key))
            .collect::<BTreeMap<_, _>>();
        for member in &eligible.members {
            entries.entry(member.id).or_insert(member.encryption_key);
        }
        let entries = entries.into_iter().collect::<Vec<_>>();
        ReceiverKeyAccumulatorStore::from_entries_at_epoch(network, source.epoch, &entries).unwrap()
    }

    fn advertisable_identity(
        party: PartyId,
        epoch: u64,
        encryption_tag: u8,
    ) -> PersistedKeyAdvertisementIdentity {
        identity(party, epoch, encryption_tag)
            .after_durable_encryption_readback([encryption_tag.wrapping_add(1); 32])
            .unwrap()
    }

    struct Fixture {
        context: KeyRotationContext,
        receiver_keys: ReceiverKeyAccumulatorStore,
        source_identities: Vec<Identity>,
        target_identities: Vec<PersistedKeyAdvertisementIdentity>,
    }

    fn fixture() -> Fixture {
        let source_epoch = 7;
        let target_epoch = source_epoch + 1;
        let source_identities = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                identity(party, source_epoch, 0x10 + u8::try_from(id).unwrap())
            })
            .collect::<Vec<_>>();
        // Async-security selection requires a certified successor of n >= 3f+1 (four members with
        // f=1) and an eligible pool floor of desired_n + f = 5, so the target pool carries a fifth
        // joiner spare that is eligible but never advertised in the common fixture and therefore
        // never selected.
        let target_identities = (1_u16..=5)
            .map(|id| {
                let party = PartyId(id);
                advertisable_identity(party, target_epoch, 0x30 + u8::try_from(id).unwrap())
            })
            .collect::<Vec<_>>();
        let source = Committee {
            epoch: source_epoch,
            threshold: 2,
            members: source_identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let spare = identity(PartyId(5), target_epoch, 0x25);
        let mut eligible = source.clone();
        eligible.epoch = target_epoch;
        eligible.members.push(Member {
            id: PartyId(5),
            signing_key: spare.signing_public_key(),
            encryption_key: spare.encryption_public_key(),
        });
        let network = [0x31; 32];
        let receiver_keys = receiver_key_store(network, &source, &eligible);
        let target_policy = KeyRotationTargetPolicy::new(
            &source,
            1,
            eligible.clone(),
            4,
            1,
            receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let context =
            KeyRotationContext::new(network, source, [0x41; 32], 1, target_policy).unwrap();
        Fixture { context, receiver_keys, source_identities, target_identities }
    }

    fn registry_public(epoch: u64, key_id: [u8; 32], constant: Scalar) -> EpochPublic {
        let identities = (1_u16..=4)
            .map(|party| {
                let party = PartyId(party);
                identity(
                    party,
                    epoch,
                    0x50_u8
                        .wrapping_add(u8::try_from(epoch).unwrap())
                        .wrapping_add(u8::try_from(party.0).unwrap()),
                )
            })
            .collect::<Vec<_>>();
        let committee = Committee {
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
        };
        let polynomial =
            SecretPolynomial::random_with_constant(committee.threshold, constant, &mut OsRng)
                .unwrap();
        let verification_shares = committee
            .members
            .iter()
            .map(|member| {
                let share = polynomial.evaluate(scalar_for_party(&committee, member.id).unwrap());
                (member.id, PointBytes::from(ED25519_BASEPOINT_POINT * share))
            })
            .collect();
        let public = EpochPublic {
            key_id,
            committee,
            verification_shares,
            group_key: PointBytes::from(ED25519_BASEPOINT_POINT * constant),
        };
        public.validate().unwrap();
        public
    }

    #[test]
    fn registry_handoff_capability_binds_certified_activation_and_wallet_key() {
        let key_id = [0x91; 32];
        let constant = Scalar::from(17_u64);
        let source = registry_public(0, key_id, constant);
        let target = registry_public(1, key_id, constant);
        let view = Zeroizing::new(Scalar::from(19_u64).to_bytes());
        let deriver =
            DepositAddressDeriver::new(NetworkKind::Testnet, source.group_key_bytes(), &view)
                .unwrap();

        let genesis = VerifiedRegistryHandoffTarget::from_verified_activation(
            None,
            source.clone(),
            1,
            [0xA1; 32],
            &deriver,
        )
        .unwrap();
        assert_eq!(genesis.wallet(), deriver.wallet_id());
        assert_eq!(genesis.key_id(), key_id);
        assert_eq!(genesis.group_key(), source.group_key_bytes());
        assert_eq!(genesis.activation(), source.activation_digest().unwrap());

        let successor = VerifiedRegistryHandoffTarget::from_verified_activation(
            Some(&source),
            target.clone(),
            1,
            [0xA2; 32],
            &deriver,
        )
        .unwrap();
        assert_eq!(successor.wallet(), genesis.wallet());
        assert_eq!(successor.group_key(), genesis.group_key());

        let foreign = registry_public(1, key_id, Scalar::from(23_u64));
        assert_eq!(
            VerifiedRegistryHandoffTarget::from_verified_activation(
                Some(&source),
                foreign,
                1,
                [0xA3; 32],
                &deriver,
            )
            .unwrap_err(),
            KeyRotationError::InvalidRegistryHandoffTarget,
        );
        assert_eq!(
            VerifiedRegistryHandoffTarget::from_verified_activation(
                Some(&source),
                target,
                1,
                [0; 32],
                &deriver,
            )
            .unwrap_err(),
            KeyRotationError::InvalidRegistryHandoffTarget,
        );
    }

    fn advertisements(fixture: &Fixture) -> Vec<SignedEnvelope> {
        let mut advertisements = fixture
            .target_identities
            .iter()
            .map(|identity| sign_key_advertisement(&fixture.context, identity).unwrap())
            .collect::<Vec<_>>();
        advertisements.truncate(fixture.context.selection_size());
        advertisements
    }

    fn rotation_value(
        context: &KeyRotationContext,
        receiver_keys: &ReceiverKeyAccumulatorStore,
        advertisements: Vec<SignedEnvelope>,
    ) -> Result<KeyRotationValue, KeyRotationError> {
        let selected = advertisements
            .iter()
            .map(|advertisement| {
                verify_key_advertisement(context, advertisement)
                    .map(|verified| (verified.party, verified.next_key))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (history_update, _) = receiver_keys.preview(context.target_epoch(), &selected)?;
        KeyRotationValue::new(context, advertisements, history_update)
    }

    fn fallback_authorization(
        context: &KeyRotationContext,
        source_identities: &[Identity],
    ) -> FallbackAuthorization {
        FallbackAuthorization::new(
            context,
            source_identities
                .iter()
                .take(context.source_quorum())
                .map(|identity| sign_selection_fallback_vote(context, identity).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn fallback_rotation_value(
        context: &KeyRotationContext,
        receiver_keys: &ReceiverKeyAccumulatorStore,
        source_identities: &[Identity],
        advertisements: Vec<SignedEnvelope>,
    ) -> Result<KeyRotationValue, KeyRotationError> {
        let selected = advertisements
            .iter()
            .map(|advertisement| {
                verify_key_advertisement(context, advertisement)
                    .map(|verified| (verified.party, verified.next_key))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (history_update, _) = receiver_keys.preview(context.target_epoch(), &selected)?;
        KeyRotationValue::new_with_authorization(
            context,
            advertisements,
            history_update,
            Some(fallback_authorization(context, source_identities)),
        )
    }

    fn raw_advertisement(
        context: &KeyRotationContext,
        capability: &PersistedKeyAdvertisementIdentity,
        body: KeyAdvertisementBody,
    ) -> SignedEnvelope {
        let identity = capability.identity();
        identity
            .sign_envelope(
                context.target_policy().eligible(),
                context.advertisement_session(),
                None,
                KEY_ADVERTISEMENT_SEQUENCE,
                postcard::to_allocvec(&body).unwrap(),
            )
            .unwrap()
    }

    fn body_for(
        context: &KeyRotationContext,
        capability: &PersistedKeyAdvertisementIdentity,
    ) -> KeyAdvertisementBody {
        let identity = capability.identity();
        KeyAdvertisementBody {
            version: KEY_ADVERTISEMENT_VERSION,
            context: context.digest(),
            source_epoch: context.source().epoch,
            target_epoch: context.target_epoch(),
            party: identity.party(),
            next_key: identity.encryption_public_key(),
            durable_record_digest: capability.durable_record_digest(),
        }
    }

    fn commit(fixture: &Fixture, value: &KeyRotationValue, signers: &[usize]) -> CommitCertificate {
        commit_at_view(fixture, value, signers, 0)
    }

    fn commit_at_view(
        fixture: &Fixture,
        value: &KeyRotationValue,
        signers: &[usize],
        view: u64,
    ) -> CommitCertificate {
        commit_for(&fixture.context, &fixture.source_identities, value, signers, view)
    }

    fn commit_for(
        context: &KeyRotationContext,
        source_identities: &[Identity],
        value: &KeyRotationValue,
        signers: &[usize],
        view: u64,
    ) -> CommitCertificate {
        let consensus_context = context.consensus_context().unwrap();
        let consensus_value = value.to_consensus_value(context).unwrap();
        let witnesses = signers
            .iter()
            .map(|index| {
                sign_consensus_message(
                    &consensus_context,
                    &source_identities[*index],
                    ConsensusMessageBody::Precommit(Vote { view, value: consensus_value.digest() }),
                )
                .unwrap()
            })
            .collect();
        CommitCertificate::from_witnesses(&consensus_context, view, consensus_value, witnesses)
            .unwrap()
    }

    fn drive_durable_round_with_silent_fourth(fixture: &Fixture) -> Vec<KeyRotationRound> {
        let mut rounds = fixture
            .source_identities
            .iter()
            .map(|identity| {
                KeyRotationRound::new(fixture.context.clone(), identity.party()).unwrap()
            })
            .collect::<Vec<_>>();
        // Selection now requires `selection_size` fresh keys, so the fourth party still publishes
        // its advertisement up front before falling silent in consensus; parties one through three
        // carry that value to a certificate on their own quorum.
        let silent_advertisement =
            sign_key_advertisement(&fixture.context, &fixture.target_identities[3]).unwrap();
        for (index, round) in rounds.iter_mut().enumerate().take(3) {
            round.advertise(&fixture.target_identities[index], &fixture.receiver_keys).unwrap();
            round
                .handle_wire(
                    PartyId(4),
                    KeyRotationWire::Advertisement(silent_advertisement.clone()),
                    &fixture.source_identities[index],
                    &fixture.receiver_keys,
                )
                .unwrap();
        }

        for _ in 0..512 {
            if rounds[..3].iter().all(|round| round.certificate().is_some()) {
                return rounds;
            }
            let mut progressed = false;
            for sender_index in 0..3 {
                let sender = fixture.source_identities[sender_index].party();
                let pending = rounds[sender_index].pending_messages(usize::MAX);
                for message in pending {
                    let Some(recipient_index) = fixture
                        .target_identities
                        .iter()
                        .position(|identity| identity.identity().party() == message.id.recipient)
                    else {
                        panic!("pending key-rotation recipient is unknown");
                    };
                    if recipient_index >= 3 {
                        continue;
                    }
                    match rounds[recipient_index].handle_wire(
                        sender,
                        message.wire,
                        fixture.target_identities[recipient_index].identity(),
                        &fixture.receiver_keys,
                    ) {
                        Ok(_) => {
                            assert_eq!(rounds[sender_index].acknowledge(&[message.id]).unwrap(), 1);
                            progressed = true;
                        }
                        Err(KeyRotationError::ConsensusNotReady) => {}
                        Err(error) => panic!("durable key-rotation delivery failed: {error}"),
                    }
                }
            }
            assert!(progressed, "durable key-rotation round stopped making progress");
        }
        panic!("durable key-rotation round did not commit");
    }

    fn start_round_with_local_candidate(fixture: &Fixture, local_index: usize) -> KeyRotationRound {
        let local_party = fixture.source_identities[local_index].party();
        let mut round = KeyRotationRound::new(fixture.context.clone(), local_party).unwrap();
        round.advertise(&fixture.target_identities[local_index], &fixture.receiver_keys).unwrap();
        for (index, capability) in
            fixture.target_identities.iter().take(fixture.context.selection_size()).enumerate()
        {
            if index == local_index {
                continue;
            }
            round
                .handle_wire(
                    capability.identity().party(),
                    KeyRotationWire::Advertisement(
                        sign_key_advertisement(&fixture.context, capability).unwrap(),
                    ),
                    &fixture.source_identities[local_index],
                    &fixture.receiver_keys,
                )
                .unwrap();
        }
        assert!(round.consensus.as_ref().is_some_and(DepositConsensus::started));
        round
    }

    #[test]
    fn exact_value_is_self_contained_and_excludes_the_silent_candidate() {
        let fixture = fixture();
        let all_ads = fixture
            .target_identities
            .iter()
            .map(|identity| sign_key_advertisement(&fixture.context, identity).unwrap())
            .collect::<Vec<_>>();
        let silent = PartyId(2);
        let ads =
            vec![all_ads[0].clone(), all_ads[2].clone(), all_ads[3].clone(), all_ads[4].clone()];
        let value = fallback_rotation_value(
            &fixture.context,
            &fixture.receiver_keys,
            &fixture.source_identities,
            ads,
        )
        .unwrap();
        let consensus_value = value.to_consensus_value(&fixture.context).unwrap();

        // This receiver has only the proposal bytes and immutable source context; it has no ad
        // cache and nevertheless reconstructs the exact target.
        let decoded =
            KeyRotationValue::from_consensus_value(&fixture.context, &consensus_value).unwrap();
        let target = decoded.target_committee(&fixture.context).unwrap();
        assert_eq!(target.epoch, fixture.context.target_epoch());
        assert_eq!(target.threshold, fixture.context.source().threshold);
        assert!(target.member(silent).is_err(), "an omitted identity must receive no share");
        for source in fixture.context.source().members.iter().filter(|member| member.id != silent) {
            let target_member = target.member(source.id).unwrap();
            assert_eq!(target_member.signing_key, source.signing_key);
            assert_ne!(target_member.encryption_key, source.encryption_key);
        }
        assert_eq!(
            target
                .members
                .iter()
                .filter(|target| {
                    fixture
                        .context
                        .source()
                        .member(target.id)
                        .map_or(true, |member| member.encryption_key != target.encryption_key)
                })
                .count(),
            fixture.context.selection_size()
        );

        let mut insufficient = advertisements(&fixture);
        insufficient.truncate(2);
        assert!(matches!(
            rotation_value(&fixture.context, &fixture.receiver_keys, insufficient),
            Err(KeyRotationError::InvalidAdvertisementCount { actual: 2, expected: 4 })
        ));
    }

    #[test]
    fn silent_original_is_replaced_by_a_fresh_advertising_spare_without_key_carry() {
        let source_epoch = 20;
        let target_epoch = 21;
        let source_identities = (1_u16..=4)
            .map(|id| identity(PartyId(id), source_epoch, 0x10 + u8::try_from(id).unwrap()))
            .collect::<Vec<_>>();
        let source = Committee {
            epoch: source_epoch,
            threshold: 2,
            members: source_identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let spare_reference = identity(PartyId(5), target_epoch, 0x25);
        let mut eligible = source.clone();
        eligible.epoch = target_epoch;
        eligible.members.push(Member {
            id: PartyId(5),
            signing_key: spare_reference.signing_public_key(),
            encryption_key: spare_reference.encryption_public_key(),
        });
        let network = [0x61; 32];
        let receiver_keys = receiver_key_store(network, &source, &eligible);
        let policy = KeyRotationTargetPolicy::new(
            &source,
            1,
            eligible.clone(),
            4,
            1,
            receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let context =
            KeyRotationContext::new(network, source.clone(), [0x62; 32], 1, policy).unwrap();
        let target_identities = (1_u16..=5)
            .map(|id| {
                advertisable_identity(PartyId(id), target_epoch, 0x40 + u8::try_from(id).unwrap())
            })
            .collect::<Vec<_>>();
        let silent = PartyId(4);
        let selected = [0_usize, 1, 2, 4]
            .into_iter()
            .map(|index| sign_key_advertisement(&context, &target_identities[index]).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            rotation_value(&context, &receiver_keys, selected.clone()).unwrap_err(),
            KeyRotationError::MissingFallbackAuthorization { actual: 3, primary: 4 }
        );
        let value = fallback_rotation_value(&context, &receiver_keys, &source_identities, selected)
            .unwrap();
        let certificate = KeyRotationCertificate::from_commit(
            &context,
            commit_for(&context, &source_identities, &value, &[0, 1, 2], 0),
        )
        .unwrap();
        let target = certificate.verify(&context).unwrap();
        assert_eq!(target.n(), 4);
        assert!(target.member(silent).is_err());
        assert_eq!(
            target.members.iter().map(|member| member.id).collect::<Vec<_>>(),
            vec![PartyId(1), PartyId(2), PartyId(3), PartyId(5)]
        );
        for member in &target.members {
            let advertised =
                target_identities[usize::from(member.id.0 - 1)].identity().encryption_public_key();
            assert_eq!(member.encryption_key, advertised);
            assert!(
                source
                    .members
                    .iter()
                    .chain(eligible.members.iter())
                    .all(|prior| prior.encryption_key != member.encryption_key),
                "a selected successor key must be independently fresh"
            );
        }
    }

    #[test]
    fn honest_candidate_prefers_healthy_sources_and_verifier_bounds_spare_substitution() {
        let source_epoch = 30;
        let target_epoch = 31;
        let source_identities = (2_u16..=5)
            .map(|id| identity(PartyId(id), source_epoch, 0x10 + u8::try_from(id).unwrap()))
            .collect::<Vec<_>>();
        let source = Committee {
            epoch: source_epoch,
            threshold: 2,
            members: source_identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let target_capabilities = (1_u16..=6)
            .map(|id| {
                advertisable_identity(PartyId(id), target_epoch, 0x50 + u8::try_from(id).unwrap())
            })
            .collect::<Vec<_>>();
        let mut eligible = source.clone();
        eligible.epoch = target_epoch;
        for spare in [PartyId(1), PartyId(6)] {
            let identity = identity(spare, target_epoch, 0x30_u8 + u8::try_from(spare.0).unwrap());
            eligible.members.push(Member {
                id: spare,
                signing_key: identity.signing_public_key(),
                encryption_key: identity.encryption_public_key(),
            });
        }
        let network = [0x71; 32];
        let receiver_keys = receiver_key_store(network, &source, &eligible);
        let policy = KeyRotationTargetPolicy::new(
            &source,
            1,
            eligible,
            4,
            1,
            receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let context =
            KeyRotationContext::new(network, source.clone(), [0x72; 32], 1, policy).unwrap();
        assert_eq!(context.primary_source_overlap(), 4);
        assert_eq!(context.minimum_source_overlap(), 3);

        let mut healthy = KeyRotationRound::new(context.clone(), source.members[0].id).unwrap();
        for capability in &target_capabilities {
            healthy
                .insert_advertisement(sign_key_advertisement(&context, capability).unwrap())
                .unwrap();
        }
        let healthy_target = healthy
            .candidate_value(&receiver_keys)
            .unwrap()
            .unwrap()
            .verify(&context)
            .unwrap()
            .target;
        assert_eq!(
            healthy_target.members.iter().map(|member| member.id).collect::<Vec<_>>(),
            vec![PartyId(2), PartyId(3), PartyId(4), PartyId(5)],
            "a lower-ID spare displaced a responsive source member"
        );

        let mut one_silent = KeyRotationRound::new(context.clone(), source.members[0].id).unwrap();
        for capability in
            target_capabilities.iter().filter(|identity| identity.identity().party() != PartyId(5))
        {
            one_silent
                .insert_advertisement(sign_key_advertisement(&context, capability).unwrap())
                .unwrap();
        }
        assert!(
            one_silent.candidate_value(&receiver_keys).unwrap().is_none(),
            "spare substitution started before source fallback authorization"
        );
        for identity in source_identities.iter().take(context.source_quorum()) {
            one_silent
                .insert_fallback_vote(sign_selection_fallback_vote(&context, identity).unwrap())
                .unwrap();
        }
        let substituted = one_silent
            .candidate_value(&receiver_keys)
            .unwrap()
            .unwrap()
            .verify(&context)
            .unwrap()
            .target;
        assert_eq!(
            substituted.members.iter().map(|member| member.id).collect::<Vec<_>>(),
            vec![PartyId(1), PartyId(2), PartyId(3), PartyId(4)]
        );
        assert!(
            one_silent
                .candidate_value(&receiver_keys)
                .unwrap()
                .unwrap()
                .selection_authorization()
                .is_some()
        );

        let byzantine_selection = [PartyId(1), PartyId(2), PartyId(3), PartyId(6)]
            .into_iter()
            .map(|party| {
                let capability = target_capabilities
                    .iter()
                    .find(|identity| identity.identity().party() == party)
                    .unwrap();
                sign_key_advertisement(&context, capability).unwrap()
            })
            .collect();
        assert_eq!(
            rotation_value(&context, &receiver_keys, byzantine_selection).unwrap_err(),
            KeyRotationError::MissingFallbackAuthorization { actual: 2, primary: 4 },
            "a Byzantine proposer bypassed primary source retention without authorization"
        );
        let byzantine_selection = [PartyId(1), PartyId(2), PartyId(3), PartyId(6)]
            .into_iter()
            .map(|party| {
                let capability = target_capabilities
                    .iter()
                    .find(|identity| identity.identity().party() == party)
                    .unwrap();
                sign_key_advertisement(&context, capability).unwrap()
            })
            .collect();
        assert_eq!(
            fallback_rotation_value(
                &context,
                &receiver_keys,
                &source_identities,
                byzantine_selection,
            )
            .unwrap_err(),
            KeyRotationError::InsufficientSourceRetention { actual: 2, minimum: 3 },
            "a Byzantine proposer bypassed the certified source-retention floor"
        );

        let healthy_advertisements = [PartyId(2), PartyId(3), PartyId(4), PartyId(5)]
            .into_iter()
            .map(|party| {
                let capability = target_capabilities
                    .iter()
                    .find(|identity| identity.identity().party() == party)
                    .unwrap();
                sign_key_advertisement(&context, capability).unwrap()
            })
            .collect();
        assert_eq!(
            fallback_rotation_value(
                &context,
                &receiver_keys,
                &source_identities,
                healthy_advertisements,
            )
            .unwrap_err(),
            KeyRotationError::GratuitousFallbackAuthorization { actual: 4, primary: 4 }
        );
        assert_eq!(
            FallbackAuthorization::new(
                &context,
                vec![sign_selection_fallback_vote(&context, &source_identities[0]).unwrap(),],
            )
            .unwrap_err(),
            KeyRotationError::InvalidFallbackAuthorizationCount {
                actual: 1,
                expected: context.source_quorum(),
            }
        );
    }

    #[test]
    fn fallback_vote_is_context_bound_and_round_restore_preserves_its_retry() {
        let fixture = fixture();
        let mut round =
            KeyRotationRound::new(fixture.context.clone(), fixture.source_identities[0].party())
                .unwrap();
        let step = round
            .authorize_fallback(&fixture.source_identities[0], &fixture.receiver_keys)
            .unwrap();
        assert!(step.changed);
        assert_eq!(round.fallback_vote_count(), 1);
        let pending = round
            .pending_messages(usize::MAX)
            .into_iter()
            .filter(|message| message.id.kind == KeyRotationDeliveryKind::FallbackVote)
            .collect::<Vec<_>>();
        assert_eq!(pending.len(), usize::from(fixture.context.source().n().saturating_sub(1)));
        let vote = match &pending[0].wire {
            KeyRotationWire::FallbackVote(vote) => vote.clone(),
            wire => panic!("unexpected fallback retry: {wire:?}"),
        };
        assert_eq!(
            verify_selection_fallback_vote(&fixture.context, &vote).unwrap(),
            fixture.source_identities[0].party()
        );

        let encoded = round.encode().unwrap();
        let restored = KeyRotationRound::decode(
            &fixture.context,
            fixture.source_identities[0].party(),
            &encoded,
        )
        .unwrap();
        assert_eq!(restored, round);
        assert_eq!(
            restored
                .pending_messages(usize::MAX)
                .into_iter()
                .filter(|message| message.id.kind == KeyRotationDeliveryKind::FallbackVote)
                .count(),
            pending.len()
        );

        let foreign_policy = KeyRotationTargetPolicy::new(
            fixture.context.source(),
            fixture.context.source_fault_bound(),
            fixture.context.target_policy().eligible().clone(),
            fixture.context.target_policy().desired_n(),
            fixture.context.target_fault_bound(),
            fixture.context.target_policy().prior_receiver_keys(),
            fixture.context.target_policy().selection_fallback_window_ms().checked_add(1).unwrap(),
        )
        .unwrap();
        let foreign_context = KeyRotationContext::new(
            fixture.context.network(),
            fixture.context.source().clone(),
            fixture.context.source_activation(),
            fixture.context.source_fault_bound(),
            foreign_policy,
        )
        .unwrap();
        assert!(matches!(
            verify_selection_fallback_vote(&foreign_context, &vote),
            Err(KeyRotationError::WrongFallbackVoteSlot)
                | Err(KeyRotationError::WrongFallbackVoteContext)
        ));
        assert!(matches!(
            KeyRotationRound::new(fixture.context, PartyId(5)),
            Err(KeyRotationError::Committee(CommitteeError::UnknownParty(PartyId(5))))
        ));
    }

    #[test]
    fn byzantine_policy_rejects_a_pool_without_an_f_spare() {
        let fixture = fixture();
        // A pool with exactly `desired_n` eligible identities and no Byzantine spare must be
        // rejected: liveness needs desired_n + f candidates.
        let mut without_spare = fixture.context.source().clone();
        without_spare.epoch = fixture.context.target_epoch();
        assert_eq!(
            KeyRotationTargetPolicy::new(
                fixture.context.source(),
                fixture.context.source_fault_bound(),
                without_spare.clone(),
                4,
                1,
                fixture.receiver_keys.commitment(),
                10_000,
            )
            .unwrap_err(),
            KeyRotationError::InsufficientEligibleCandidates {
                actual: 4,
                desired: 4,
                fault_bound: 1,
            }
        );
    }

    #[test]
    fn sparse_update_rejects_source_or_bootstrap_reuse_without_blocking_admission() {
        let fixture = fixture();
        let source_reuse = advertisable_identity(PartyId(1), fixture.context.target_epoch(), 0x11);
        let source_reuse = sign_key_advertisement(&fixture.context, &source_reuse).unwrap();
        let mut source_selection = advertisements(&fixture);
        source_selection[0] = source_reuse;
        assert!(matches!(
            rotation_value(&fixture.context, &fixture.receiver_keys, source_selection),
            Err(KeyRotationError::ReceiverKeyAccumulator(_))
        ));

        let bootstrap_reuse =
            advertisable_identity(PartyId(5), fixture.context.target_epoch(), 0x25);
        let bootstrap_reuse = sign_key_advertisement(&fixture.context, &bootstrap_reuse).unwrap();
        let mut bootstrap_selection = advertisements(&fixture);
        bootstrap_selection[3] = bootstrap_reuse;
        assert!(matches!(
            rotation_value(&fixture.context, &fixture.receiver_keys, bootstrap_selection),
            Err(KeyRotationError::ReceiverKeyAccumulator(_))
        ));
    }

    #[test]
    fn certified_grow_and_shrink_use_distinct_source_and_target_quorums() {
        let source_epoch = 10;
        let source_identities = (1_u16..=5)
            .map(|id| identity(PartyId(id), source_epoch, 0x10 + u8::try_from(id).unwrap()))
            .collect::<Vec<_>>();
        let source = Committee {
            epoch: source_epoch,
            threshold: 3,
            members: source_identities
                .iter()
                .map(|identity| Member {
                    id: identity.party(),
                    signing_key: identity.signing_public_key(),
                    encryption_key: identity.encryption_public_key(),
                })
                .collect(),
        };
        let target_epoch = source_epoch + 1;
        let eligible = Committee {
            epoch: target_epoch,
            threshold: 4,
            members: (1_u16..=7)
                .map(|id| {
                    let party = PartyId(id);
                    let encryption_key = source.member(party).map_or_else(
                        |_| {
                            identity(party, 0, 0x50 + u8::try_from(id).unwrap())
                                .encryption_public_key()
                        },
                        |member| member.encryption_key,
                    );
                    Member {
                        id: party,
                        signing_key: Identity::signing_public_key_from_seed(&seed(party)).unwrap(),
                        encryption_key,
                    }
                })
                .collect(),
        };
        let network = [0x81; 32];
        let mut grow_receiver_keys = receiver_key_store(network, &source, &eligible);
        let grow_policy = KeyRotationTargetPolicy::new(
            &source,
            1,
            eligible.clone(),
            6,
            1,
            grow_receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let grow_context =
            KeyRotationContext::new(network, source, [0x82; 32], 1, grow_policy).unwrap();
        assert_eq!(grow_context.source_quorum(), 4);
        assert_eq!(grow_context.selection_size(), 6);

        let grow_capabilities = (1_u16..=7)
            .map(|id| {
                advertisable_identity(PartyId(id), target_epoch, 0x70 + u8::try_from(id).unwrap())
            })
            .collect::<Vec<_>>();

        // A joining member has no source reducer, but its persist-before-advertise capability
        // creates a retry record for every source consensus member.
        let joining_fanout =
            pending_key_rotation_advertisements(&grow_context, &grow_capabilities[5]).unwrap();
        assert_eq!(joining_fanout.len(), 5);
        assert_eq!(
            joining_fanout.iter().map(|message| message.id.recipient).collect::<BTreeSet<_>>(),
            (1_u16..=5).map(PartyId).collect()
        );
        let mut source_round = KeyRotationRound::new(grow_context.clone(), PartyId(1)).unwrap();
        source_round
            .handle_wire(
                PartyId(6),
                joining_fanout[0].wire.clone(),
                &source_identities[0],
                &grow_receiver_keys,
            )
            .unwrap();
        assert_eq!(source_round.advertisement_count(), 1);

        let grow_advertisements = grow_capabilities[..6]
            .iter()
            .map(|capability| sign_key_advertisement(&grow_context, capability).unwrap())
            .collect::<Vec<_>>();
        let grow_value =
            rotation_value(&grow_context, &grow_receiver_keys, grow_advertisements).unwrap();
        let grow_target = grow_value.target_committee(&grow_context).unwrap();
        // Exactly `desired_n` advertisements select the successor; the seventh eligible identity is
        // never advertised and therefore never enters the target.
        assert_eq!(grow_target.n(), 6);
        assert_eq!(grow_target.threshold, 4);
        assert!(grow_target.member(PartyId(7)).is_err());
        assert_ne!(
            grow_target.member(PartyId(6)).unwrap().encryption_key,
            eligible.member(PartyId(6)).unwrap().encryption_key
        );

        let grow_certificate = KeyRotationCertificate::from_commit(
            &grow_context,
            commit_for(&grow_context, &source_identities, &grow_value, &[0, 1, 2, 3], 0),
        )
        .unwrap();
        assert_eq!(grow_certificate.verify(&grow_context).unwrap(), grow_target);
        assert_eq!(
            pending_key_rotation_certificate(&grow_context, &grow_certificate, PartyId(6),)
                .unwrap()
                .id
                .recipient,
            PartyId(6)
        );

        // Reconstruct the now-certified grow target (six members) as the next source.
        let shrink_source_identities = (1_u16..=6)
            .map(|id| identity(PartyId(id), target_epoch, 0x70 + u8::try_from(id).unwrap()))
            .collect::<Vec<_>>();
        for identity in &shrink_source_identities {
            assert_eq!(
                identity.encryption_public_key(),
                grow_target.member(identity.party()).unwrap().encryption_key
            );
        }
        let shrink_epoch = target_epoch + 1;
        // A shrink still certifies an async-secure successor (n >= 3f+1), so the eligible pool
        // carries desired_n + f = 5 members while only desired_n = 4 are advertised.
        let shrink_eligible = Committee {
            epoch: shrink_epoch,
            threshold: 2,
            members: [1_u16, 2, 4, 5, 6]
                .into_iter()
                .map(|id| grow_target.member(PartyId(id)).unwrap().clone())
                .collect(),
        };
        let grow_selected = grow_target
            .members
            .iter()
            .map(|member| (member.id, member.encryption_key))
            .collect::<Vec<_>>();
        grow_receiver_keys
            .apply_verified_update(target_epoch, &grow_selected, grow_value.history_update())
            .unwrap();
        let shrink_policy = KeyRotationTargetPolicy::new(
            &grow_target,
            1,
            shrink_eligible.clone(),
            4,
            1,
            grow_receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let shrink_context =
            KeyRotationContext::new(network, grow_target, [0x83; 32], 1, shrink_policy).unwrap();
        assert_eq!(shrink_context.source_quorum(), 5);
        assert_eq!(shrink_context.selection_size(), 4);
        let shrink_capabilities = [2_u16, 4, 5, 6]
            .into_iter()
            .map(|id| {
                advertisable_identity(PartyId(id), shrink_epoch, 0x90 + u8::try_from(id).unwrap())
            })
            .collect::<Vec<_>>();
        let shrink_value = rotation_value(
            &shrink_context,
            &grow_receiver_keys,
            shrink_capabilities
                .iter()
                .map(|capability| sign_key_advertisement(&shrink_context, capability).unwrap())
                .collect(),
        )
        .unwrap();
        let shrink_certificate = KeyRotationCertificate::from_commit(
            &shrink_context,
            commit_for(
                &shrink_context,
                &shrink_source_identities,
                &shrink_value,
                &[0, 1, 2, 3, 4],
                0,
            ),
        )
        .unwrap();
        let shrink_target = shrink_certificate.verify(&shrink_context).unwrap();
        assert_eq!(
            shrink_target.members.iter().map(|member| member.id).collect::<Vec<_>>(),
            vec![PartyId(2), PartyId(4), PartyId(5), PartyId(6)]
        );
        // Fresh keys are mandatory: no selected successor member carries its eligible-pool key.
        assert_ne!(
            shrink_target.member(PartyId(2)).unwrap().encryption_key,
            shrink_eligible.member(PartyId(2)).unwrap().encryption_key
        );
    }

    #[test]
    fn malformed_wrong_context_prior_duplicate_and_noncontributory_ads_are_rejected() {
        let fixture = fixture();
        let identity = &fixture.target_identities[0];

        let mut wrong_epoch = body_for(&fixture.context, identity);
        wrong_epoch.target_epoch += 1;
        assert!(matches!(
            verify_key_advertisement(
                &fixture.context,
                &raw_advertisement(&fixture.context, identity, wrong_epoch)
            ),
            Err(KeyRotationError::WrongAdvertisementContext)
        ));

        let mut all_zero = body_for(&fixture.context, identity);
        all_zero.next_key = [0; 32];
        assert!(matches!(
            verify_key_advertisement(
                &fixture.context,
                &raw_advertisement(&fixture.context, identity, all_zero)
            ),
            Err(KeyRotationError::AllZeroNextKey(PartyId(1)))
        ));

        let mut low_order = body_for(&fixture.context, identity);
        low_order.next_key = {
            let mut one = [0; 32];
            one[0] = 1;
            one
        };
        assert!(matches!(
            verify_key_advertisement(
                &fixture.context,
                &raw_advertisement(&fixture.context, identity, low_order)
            ),
            Err(KeyRotationError::NonContributoryNextKey(PartyId(1)))
        ));

        let mut noncanonical = body_for(&fixture.context, identity);
        noncanonical.next_key[31] |= 0x80;
        assert!(matches!(
            verify_key_advertisement(
                &fixture.context,
                &raw_advertisement(&fixture.context, identity, noncanonical)
            ),
            Err(KeyRotationError::NonCanonicalNextKey(PartyId(1)))
        ));

        let mut reused_policy_key = body_for(&fixture.context, identity);
        reused_policy_key.next_key =
            fixture.context.target_policy().eligible().member(PartyId(2)).unwrap().encryption_key;
        assert!(matches!(
            verify_key_advertisement(
                &fixture.context,
                &raw_advertisement(&fixture.context, identity, reused_policy_key)
            ),
            Err(KeyRotationError::ReusedPolicyKey(PartyId(1)))
        ));

        let first = sign_key_advertisement(&fixture.context, identity).unwrap();
        let mut bad_signature = first.clone();
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            verify_key_advertisement(&fixture.context, &bad_signature),
            Err(KeyRotationError::Identity(IdentityError::InvalidSignature))
        ));

        let mut duplicates = advertisements(&fixture);
        duplicates.truncate(4);
        duplicates[1] = first.clone();
        let proof =
            rotation_value(&fixture.context, &fixture.receiver_keys, advertisements(&fixture))
                .unwrap()
                .history_update()
                .clone();
        assert!(matches!(
            KeyRotationValue::new(&fixture.context, duplicates, proof.clone()),
            Err(KeyRotationError::DuplicateAdvertiser(PartyId(1)))
        ));

        let second_identity = &fixture.target_identities[1];
        let mut duplicate_key = body_for(&fixture.context, second_identity);
        duplicate_key.next_key = identity.identity().encryption_public_key();
        let duplicate_key = raw_advertisement(&fixture.context, second_identity, duplicate_key);
        let mut duplicate_keys = advertisements(&fixture);
        duplicate_keys[1] = duplicate_key;
        duplicate_keys.truncate(4);
        assert!(matches!(
            KeyRotationValue::new(&fixture.context, duplicate_keys, proof),
            Err(KeyRotationError::DuplicateNextKey)
        ));

        let mut foreign_network = fixture.context.network();
        foreign_network[0] ^= 1;
        let foreign_receiver_keys = receiver_key_store(
            foreign_network,
            fixture.context.source(),
            fixture.context.target_policy().eligible(),
        );
        let foreign_policy = KeyRotationTargetPolicy::new(
            fixture.context.source(),
            fixture.context.source_fault_bound(),
            fixture.context.target_policy().eligible().clone(),
            fixture.context.target_policy().desired_n(),
            fixture.context.target_fault_bound(),
            foreign_receiver_keys.commitment(),
            fixture.context.target_policy().selection_fallback_window_ms(),
        )
        .unwrap();
        let other_context = KeyRotationContext::new(
            foreign_network,
            fixture.context.source().clone(),
            fixture.context.source_activation(),
            fixture.context.source_fault_bound(),
            foreign_policy,
        )
        .unwrap();
        let foreign = sign_key_advertisement(&other_context, identity).unwrap();
        assert!(matches!(
            verify_key_advertisement(&fixture.context, &foreign),
            Err(KeyRotationError::WrongAdvertisementSlot)
                | Err(KeyRotationError::WrongAdvertisementContext)
        ));
    }

    #[test]
    fn source_keys_and_target_identity_epoch_are_checked() {
        let fixture = fixture();
        let wrong_epoch = advertisable_identity(PartyId(1), fixture.context.source().epoch, 0x71);
        assert!(matches!(
            sign_key_advertisement(&fixture.context, &wrong_epoch),
            Err(KeyRotationError::WrongAdvertisementIdentity)
        ));

        let mut invalid_source = fixture.context.source().clone();
        invalid_source.members[0].encryption_key = [0; 32];
        assert!(matches!(
            KeyRotationContext::new(
                fixture.context.network(),
                invalid_source,
                fixture.context.source_activation(),
                fixture.context.source_fault_bound(),
                fixture.context.target_policy().clone(),
            ),
            Err(KeyRotationError::InvalidSourceKey(PartyId(1)))
        ));

        let mut noncanonical_source = fixture.context.source().clone();
        noncanonical_source.members[0].encryption_key[31] |= 0x80;
        assert!(matches!(
            KeyRotationContext::new(
                fixture.context.network(),
                noncanonical_source,
                fixture.context.source_activation(),
                fixture.context.source_fault_bound(),
                fixture.context.target_policy().clone(),
            ),
            Err(KeyRotationError::InvalidSourceKey(PartyId(1)))
        ));
    }

    #[test]
    fn every_known_x25519_noncontributory_encoding_is_rejected() {
        let mut one = [0_u8; 32];
        one[0] = 1;
        let order_eight_a = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let order_eight_b = [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ];
        let mut p_minus_one = [0xff; 32];
        p_minus_one[0] = 0xec;
        p_minus_one[31] = 0x7f;
        let mut p = p_minus_one;
        p[0] = 0xed;
        let mut p_plus_one = p_minus_one;
        p_plus_one[0] = 0xee;

        for key in [[0; 32], one, order_eight_a, order_eight_b, p_minus_one, p, p_plus_one] {
            assert!(validate_x25519_key(key).is_err());
        }
    }

    #[test]
    fn wire_decoding_rejects_oversized_collections_before_semantic_validation() {
        let fixture = fixture();
        let one = sign_key_advertisement(&fixture.context, &fixture.target_identities[0]).unwrap();
        let oversized_value = KeyRotationValue {
            version: KEY_ROTATION_VERSION,
            context: fixture.context.digest(),
            advertisements: vec![one; MAX_COMMITTEE_MEMBERS + 1],
            history_update: rotation_value(
                &fixture.context,
                &fixture.receiver_keys,
                advertisements(&fixture),
            )
            .unwrap()
            .history_update()
            .clone(),
            selection_authorization: None,
        };
        let encoded = postcard::to_allocvec(&oversized_value).unwrap();
        assert!(matches!(
            KeyRotationValue::decode(&fixture.context, &encoded),
            Err(KeyRotationError::Serialization)
        ));

        #[derive(Serialize)]
        struct OversizedContext<'a> {
            version: u16,
            network: [u8; 32],
            source: OversizedCommittee<'a>,
            source_activation: [u8; 32],
            source_fault_bound: u16,
            target_policy: &'a KeyRotationTargetPolicy,
        }
        #[derive(Serialize)]
        struct OversizedCommittee<'a> {
            epoch: u64,
            threshold: u16,
            members: &'a [Member],
        }
        let mut members = fixture.context.source().members.clone();
        while members.len() <= MAX_COMMITTEE_MEMBERS {
            members.push(members[0].clone());
        }
        let encoded = postcard::to_allocvec(&OversizedContext {
            version: KEY_ROTATION_VERSION,
            network: fixture.context.network(),
            source: OversizedCommittee {
                epoch: fixture.context.source().epoch,
                threshold: fixture.context.source().threshold,
                members: &members,
            },
            source_activation: fixture.context.source_activation(),
            source_fault_bound: fixture.context.source_fault_bound(),
            target_policy: fixture.context.target_policy(),
        })
        .unwrap();
        assert!(postcard::from_bytes::<KeyRotationContext>(&encoded).is_err());
    }

    #[test]
    fn certificates_reconstruct_targets_and_expose_conflicting_signers() {
        let fixture = fixture();
        let ads = fixture
            .target_identities
            .iter()
            .map(|identity| sign_key_advertisement(&fixture.context, identity).unwrap())
            .collect::<Vec<_>>();
        let left =
            rotation_value(&fixture.context, &fixture.receiver_keys, ads[..4].to_vec()).unwrap();
        let right_value = fallback_rotation_value(
            &fixture.context,
            &fixture.receiver_keys,
            &fixture.source_identities,
            vec![ads[0].clone(), ads[1].clone(), ads[2].clone(), ads[4].clone()],
        )
        .unwrap();
        let left = KeyRotationCertificate::from_commit(
            &fixture.context,
            commit(&fixture, &left, &[0, 1, 2]),
        )
        .unwrap();
        let right = KeyRotationCertificate::from_commit(
            &fixture.context,
            commit(&fixture, &right_value, &[0, 1, 3]),
        )
        .unwrap();
        assert_ne!(left.verify(&fixture.context).unwrap(), right.verify(&fixture.context).unwrap());
        assert_eq!(
            left.conflicting_signers(&right, &fixture.context).unwrap(),
            vec![PartyId(1), PartyId(2)]
        );

        let cross_view = KeyRotationCertificate::from_commit(
            &fixture.context,
            commit_at_view(&fixture, &right_value, &[0, 1, 3], 1),
        )
        .unwrap();
        assert!(matches!(
            left.conflicting_signers(&cross_view, &fixture.context),
            Err(KeyRotationError::Consensus(ConsensusError::CrossViewConflict))
        ));

        let encoded = left.encode(&fixture.context).unwrap();
        assert_eq!(KeyRotationCertificate::decode(&fixture.context, &encoded).unwrap(), left);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            KeyRotationCertificate::decode(&fixture.context, &trailing),
            Err(KeyRotationError::TrailingCertificateBytes)
        ));

        let mut tampered = left.clone();
        tampered.context_digest[0] ^= 1;
        assert!(matches!(
            tampered.verify(&fixture.context),
            Err(KeyRotationError::WrongCertificateContext)
        ));

        let generic_value = left.commit_certificate().value().clone();
        let mut witnesses = left.commit_certificate().witnesses().to_vec();
        witnesses[0].signature[0] ^= 1;
        assert!(
            CommitCertificate::from_witnesses(
                &fixture.context.consensus_context().unwrap(),
                0,
                generic_value,
                witnesses,
            )
            .is_err()
        );
    }

    #[test]
    fn certificate_entry_points_verify_the_sparse_proof_exactly_once() {
        let fixture = fixture();
        let value =
            rotation_value(&fixture.context, &fixture.receiver_keys, advertisements(&fixture))
                .unwrap();
        let certificate = KeyRotationCertificate::from_commit(
            &fixture.context,
            commit(&fixture, &value, &[0, 1, 2]),
        )
        .unwrap();
        let encoded = certificate.encode(&fixture.context).unwrap();
        let expected_target = value.target_committee(&fixture.context).unwrap();

        reset_sparse_proof_verifications();
        assert_eq!(
            KeyRotationCertificate::decode(&fixture.context, &encoded).unwrap(),
            certificate
        );
        assert_eq!(sparse_proof_verifications(), 1, "certificate decode replayed its proof");

        reset_sparse_proof_verifications();
        let verified = certificate.verify_rotation(&fixture.context).unwrap();
        assert_eq!(verified.target, expected_target);
        assert_eq!(sparse_proof_verifications(), 1, "certificate verification replayed its proof");

        reset_sparse_proof_verifications();
        let semantic_digest = certificate.semantic_digest(&fixture.context).unwrap();
        assert_ne!(semantic_digest, [0_u8; 32]);
        assert_eq!(sparse_proof_verifications(), 1, "semantic digest replayed its proof");

        reset_sparse_proof_verifications();
        let registered = certificate.verify_rotation_certificate(&fixture.context).unwrap();
        assert_eq!(registered.semantic_digest(), semantic_digest);
        assert_eq!(registered.target, verified.target);
        assert_eq!(registered.receiver_keys, verified.receiver_keys);
        assert_eq!(
            sparse_proof_verifications(),
            1,
            "combined registration verification replayed its proof"
        );
        let retry = pending_verified_key_rotation_certificate(
            &fixture.context,
            &certificate,
            &registered,
            PartyId(1),
        )
        .unwrap();
        assert_eq!(retry.id.digest, registered.certificate_wire_digest);
        assert_eq!(
            sparse_proof_verifications(),
            1,
            "verified retry construction replayed its proof"
        );
        let mut round = KeyRotationRound::new(fixture.context.clone(), PartyId(1)).unwrap();
        let step = round
            .handle_verified_certificate(
                PartyId(2),
                certificate.clone(),
                &registered,
                &fixture.source_identities[0],
            )
            .unwrap();
        assert!(step.committed.is_some());
        assert_eq!(
            sparse_proof_verifications(),
            1,
            "verified reducer ingress replayed its sparse proof"
        );

        reset_sparse_proof_verifications();
        drop(pending_key_rotation_certificate(&fixture.context, &certificate, PartyId(1)).unwrap());
        assert_eq!(
            sparse_proof_verifications(),
            1,
            "standalone retry construction replayed its proof"
        );

        reset_sparse_proof_verifications();
        assert_eq!(certificate.value(&fixture.context).unwrap(), value);
        assert_eq!(sparse_proof_verifications(), 1, "certificate value replayed its proof");
    }

    #[test]
    fn generic_consensus_commits_only_a_universally_valid_rotation_value() {
        let fixture = fixture();
        let mut ads = fixture
            .target_identities
            .iter()
            .map(|identity| sign_key_advertisement(&fixture.context, identity).unwrap())
            .collect::<Vec<_>>();
        ads.pop(); // One silent advertiser is within f=1, leaving exactly the selection size.
        let rotation =
            rotation_value(&fixture.context, &fixture.receiver_keys, ads.clone()).unwrap();
        let candidate = rotation.to_consensus_value(&fixture.context).unwrap();
        let consensus_context = fixture.context.consensus_context().unwrap();

        let mut malformed_rotation = rotation.clone();
        malformed_rotation.advertisements.truncate(2);
        let malformed =
            ConsensusValue::new(postcard::to_allocvec(&malformed_rotation).unwrap()).unwrap();
        let proposal = sign_consensus_message(
            &consensus_context,
            &fixture.source_identities[0],
            ConsensusMessageBody::Proposal(Proposal {
                view: 0,
                value: malformed,
                proof_of_lock: None,
                view_change: None,
            }),
        )
        .unwrap();
        let mut receiver = DepositConsensus::new(consensus_context.clone(), PartyId(2)).unwrap();
        receiver.start(&fixture.source_identities[1], candidate.clone()).unwrap();
        assert_eq!(
            receiver.handle_with_value_validator(
                &fixture.source_identities[1],
                proposal,
                |value| valid_key_rotation_consensus_value(&fixture.context, value),
            ),
            Err(ConsensusError::InvalidApplicationValue)
        );

        let mut nodes = fixture
            .source_identities
            .iter()
            .map(|identity| {
                DepositConsensus::new(consensus_context.clone(), identity.party()).unwrap()
            })
            .collect::<Vec<_>>();
        let mut network = VecDeque::new();
        for (index, node) in nodes.iter_mut().enumerate() {
            network.extend(
                node.start(&fixture.source_identities[index], candidate.clone()).unwrap().broadcast,
            );
        }
        let mut deliveries = 0;
        while let Some(envelope) = network.pop_front() {
            deliveries += 1;
            assert!(deliveries < 256, "key-rotation consensus did not quiesce");
            for (index, node) in nodes.iter_mut().enumerate() {
                if node.local_party() == envelope.from || node.commit().is_some() {
                    continue;
                }
                let step = node
                    .handle_with_value_validator(
                        &fixture.source_identities[index],
                        envelope.clone(),
                        |value| valid_key_rotation_consensus_value(&fixture.context, value),
                    )
                    .unwrap();
                network.extend(step.broadcast);
            }
        }
        for node in nodes {
            let certificate = KeyRotationCertificate::from_commit(
                &fixture.context,
                node.commit().expect("honest node did not commit").clone(),
            )
            .unwrap();
            assert_eq!(
                certificate.verify(&fixture.context).unwrap(),
                rotation.target_committee(&fixture.context).unwrap()
            );
        }
    }

    #[test]
    fn context_binds_network_activation_epochs_committee_and_fault_bound() {
        let fixture = fixture();
        let original = fixture.context.digest();
        let target_fault_changed = KeyRotationContext::new(
            fixture.context.network(),
            fixture.context.source().clone(),
            fixture.context.source_activation(),
            fixture.context.source_fault_bound(),
            KeyRotationTargetPolicy::new(
                fixture.context.source(),
                fixture.context.source_fault_bound(),
                fixture.context.target_policy().eligible().clone(),
                fixture.context.target_policy().desired_n(),
                0,
                fixture.context.target_policy().prior_receiver_keys(),
                fixture.context.target_policy().selection_fallback_window_ms(),
            )
            .unwrap(),
        )
        .unwrap();
        let source_fault_changed = KeyRotationContext::new(
            fixture.context.network(),
            fixture.context.source().clone(),
            fixture.context.source_activation(),
            0,
            KeyRotationTargetPolicy::new(
                fixture.context.source(),
                0,
                fixture.context.target_policy().eligible().clone(),
                fixture.context.target_policy().desired_n(),
                fixture.context.target_fault_bound(),
                fixture.context.target_policy().prior_receiver_keys(),
                fixture.context.target_policy().selection_fallback_window_ms(),
            )
            .unwrap(),
        )
        .unwrap();
        let foreign_network = [0x32; 32];
        let foreign_receiver_keys = receiver_key_store(
            foreign_network,
            fixture.context.source(),
            fixture.context.target_policy().eligible(),
        );
        let foreign_policy = KeyRotationTargetPolicy::new(
            fixture.context.source(),
            fixture.context.source_fault_bound(),
            fixture.context.target_policy().eligible().clone(),
            fixture.context.target_policy().desired_n(),
            fixture.context.target_fault_bound(),
            foreign_receiver_keys.commitment(),
            fixture.context.target_policy().selection_fallback_window_ms(),
        )
        .unwrap();
        for changed in [
            KeyRotationContext::new(
                foreign_network,
                fixture.context.source().clone(),
                fixture.context.source_activation(),
                fixture.context.source_fault_bound(),
                foreign_policy,
            )
            .unwrap(),
            KeyRotationContext::new(
                fixture.context.network(),
                fixture.context.source().clone(),
                [0x42; 32],
                fixture.context.source_fault_bound(),
                fixture.context.target_policy().clone(),
            )
            .unwrap(),
            source_fault_changed,
            target_fault_changed,
        ] {
            assert_ne!(changed.digest(), original);
            assert_ne!(
                changed.consensus_context().unwrap().digest(),
                fixture.context.consensus_context().unwrap().digest()
            );
        }

        let mut changed_committee = fixture.context.source().clone();
        changed_committee.threshold = 1;
        assert!(
            KeyRotationContext::new(
                fixture.context.network(),
                changed_committee,
                fixture.context.source_activation(),
                fixture.context.source_fault_bound(),
                fixture.context.target_policy().clone(),
            )
            .is_err()
        );
        let mut skipped_epoch = fixture.context.target_policy().eligible().clone();
        skipped_epoch.epoch += 1;
        assert!(
            KeyRotationTargetPolicy::new(
                fixture.context.source(),
                fixture.context.source_fault_bound(),
                skipped_epoch,
                fixture.context.target_policy().desired_n(),
                fixture.context.target_fault_bound(),
                fixture.context.target_policy().prior_receiver_keys(),
                fixture.context.target_policy().selection_fallback_window_ms(),
            )
            .is_err()
        );
    }

    #[test]
    fn durable_round_commits_with_one_silent_party_and_keeps_only_terminal_retry() {
        let fixture = fixture();
        let rounds = drive_durable_round_with_silent_fourth(&fixture);
        let expected = rounds[0].certificate().unwrap();
        for round in &rounds[..3] {
            assert_eq!(round.certificate(), Some(expected.clone()));
            assert_eq!(round.advertisement_count(), 4);
            let pending = round.pending_messages(usize::MAX);
            assert!(pending.len() <= 3);
            // The certificate is re-delivered to the non-committing participants: the silent
            // fourth party and the never-advertising eligible spare.
            assert!(pending.iter().all(|message| {
                message.id.kind == KeyRotationDeliveryKind::Certificate
                    && (message.id.recipient == PartyId(4) || message.id.recipient == PartyId(5))
            }));
            let encoded = round.encode().unwrap();
            assert_eq!(
                KeyRotationRound::decode(&fixture.context, round.local_party(), &encoded).unwrap(),
                *round
            );
        }
        assert_eq!(
            expected.target_committee(&fixture.context).unwrap(),
            rotation_value(&fixture.context, &fixture.receiver_keys, advertisements(&fixture),)
                .unwrap()
                .target_committee(&fixture.context)
                .unwrap()
        );
    }

    #[test]
    fn terminal_certificate_initializes_a_lagging_round_without_advertisements() {
        let fixture = fixture();
        let committed = drive_durable_round_with_silent_fourth(&fixture)[0].certificate().unwrap();
        let mut lagging = KeyRotationRound::new(fixture.context.clone(), PartyId(4)).unwrap();
        let step = lagging
            .handle_wire(
                PartyId(1),
                KeyRotationWire::Certificate(committed.clone()),
                fixture.target_identities[3].identity(),
                &fixture.receiver_keys,
            )
            .unwrap();
        assert_eq!(step.committed, Some(committed.clone()));
        assert_eq!(lagging.certificate(), Some(committed));
        assert_eq!(lagging.advertisement_count(), 0);
        assert!(
            lagging
                .pending_messages(usize::MAX)
                .iter()
                .all(|message| message.id.kind == KeyRotationDeliveryKind::Certificate)
        );
    }

    #[test]
    fn local_view_change_prunes_abandoned_phase_retries_even_after_restore() {
        let fixture = fixture();
        let mut round = start_round_with_local_candidate(&fixture, 0);
        let recipient = PartyId(2);
        let abandoned = round
            .outbox
            .iter()
            .filter(|(kind, _)| {
                matches!(
                    kind,
                    KeyRotationDeliveryKind::Proposal { view: 0 }
                        | KeyRotationDeliveryKind::Prevote { view: 0 }
                        | KeyRotationDeliveryKind::Precommit { view: 0 }
                )
            })
            .map(|(kind, entry)| (*kind, entry.clone()))
            .collect::<Vec<_>>();
        let before = round
            .pending_messages_for(recipient, usize::MAX)
            .into_iter()
            .map(|message| message.id.kind)
            .collect::<Vec<_>>();
        assert!(before.contains(&KeyRotationDeliveryKind::Proposal { view: 0 }));
        assert!(before.contains(&KeyRotationDeliveryKind::Prevote { view: 0 }));

        let step = round.request_view_change(&fixture.source_identities[0]).unwrap();
        assert!(step.changed);
        let after = round
            .pending_messages_for(recipient, usize::MAX)
            .into_iter()
            .map(|message| message.id.kind)
            .collect::<Vec<_>>();
        assert!(
            !after.iter().any(|kind| matches!(
                kind,
                KeyRotationDeliveryKind::Proposal { view: 0 }
                    | KeyRotationDeliveryKind::Prevote { view: 0 }
                    | KeyRotationDeliveryKind::Precommit { view: 0 }
            )),
            "the abandoned view must not delay its replacement: {after:?}"
        );
        assert!(after.contains(&KeyRotationDeliveryKind::Advertisement));
        assert!(after.contains(&KeyRotationDeliveryKind::ViewChange { target_view: 1 }));
        assert_eq!(
            after.iter().copied().find(|kind| *kind != KeyRotationDeliveryKind::Advertisement),
            Some(KeyRotationDeliveryKind::ViewChange { target_view: 1 })
        );

        // Model a snapshot written by a crash-recovered request path that durably retained its
        // local view-change but had not yet cleaned the abandoned retry slots.
        round.outbox.extend(abandoned);
        let encoded = round.encode().unwrap();
        let mut restored =
            KeyRotationRound::decode(&fixture.context, PartyId(1), &encoded).unwrap();
        let duplicate = restored.request_view_change(&fixture.source_identities[0]).unwrap();
        assert!(duplicate.duplicate);
        assert!(duplicate.changed, "restart repair must be persisted");
        let restored_pending = restored
            .pending_messages_for(recipient, usize::MAX)
            .into_iter()
            .map(|message| message.id.kind)
            .collect::<Vec<_>>();
        assert_eq!(restored_pending, after);
    }

    #[test]
    fn higher_view_proposal_relays_first_and_initializes_a_lagging_round() {
        let fixture = fixture();
        let consensus_context = fixture.context.consensus_context().unwrap();
        assert_eq!(consensus_context.leader(1), PartyId(2));
        let mut leader = start_round_with_local_candidate(&fixture, 1);
        leader.request_view_change(&fixture.source_identities[1]).unwrap();
        for index in [0_usize, 2] {
            let identity = &fixture.source_identities[index];
            let view_change = sign_consensus_message(
                &consensus_context,
                identity,
                ConsensusMessageBody::ViewChange(ViewChange {
                    from_view: 0,
                    target_view: 1,
                    highest_prepared: None,
                }),
            )
            .unwrap();
            leader
                .handle_wire(
                    identity.party(),
                    KeyRotationWire::Consensus(view_change),
                    &fixture.source_identities[1],
                    &fixture.receiver_keys,
                )
                .unwrap();
        }
        assert_eq!(leader.view(), 1);

        let recipient = PartyId(4);
        let pending = leader.pending_messages_for(recipient, usize::MAX);
        assert_eq!(
            pending.first().map(|message| message.id.kind),
            Some(KeyRotationDeliveryKind::Proposal { view: 1 }),
            "the self-contained proposal must initialize the peer before ancillary retries"
        );
        let proposal_index = pending
            .iter()
            .position(|message| message.id.kind == KeyRotationDeliveryKind::Proposal { view: 1 })
            .expect("view-one leader did not enqueue a proposal");
        let advertisement_index = pending
            .iter()
            .position(|message| message.id.kind == KeyRotationDeliveryKind::Advertisement)
            .expect("local advertisement retry was lost");
        let view_change_index = pending
            .iter()
            .position(|message| {
                message.id.kind == KeyRotationDeliveryKind::ViewChange { target_view: 1 }
            })
            .expect("local view-change retry was lost");
        let certificate_index = pending
            .iter()
            .position(|message| {
                message.id.kind == KeyRotationDeliveryKind::ViewCertificate { target_view: 1 }
            })
            .expect("portable view certificate was not enqueued");
        assert!(proposal_index < advertisement_index);
        assert!(proposal_index < view_change_index);
        assert!(proposal_index < certificate_index);

        let relay_batch = leader.pending_messages(usize::MAX);
        let recipient_batch = relay_batch
            .iter()
            .filter(|message| message.id.recipient == recipient)
            .collect::<Vec<_>>();
        assert_eq!(
            recipient_batch.first().map(|message| message.id.kind),
            Some(KeyRotationDeliveryKind::Proposal { view: 1 })
        );
        assert!(
            recipient_batch
                .iter()
                .all(|message| message.id.kind != KeyRotationDeliveryKind::Advertisement),
            "the standalone advertisement must not overtake a pending self-contained proposal"
        );

        let proposal = pending[proposal_index].wire.clone();
        let proposal_id = pending[proposal_index].id;
        let mut lagging = KeyRotationRound::new(fixture.context.clone(), recipient).unwrap();
        let step = lagging
            .handle_wire(
                PartyId(2),
                proposal,
                &fixture.source_identities[3],
                &fixture.receiver_keys,
            )
            .unwrap();
        assert!(step.changed);
        assert_eq!(lagging.advertisement_count(), 0);
        assert_eq!(lagging.view(), 1);
        assert!(
            lagging
                .pending_messages_for(PartyId(1), usize::MAX)
                .iter()
                .any(|message| { message.id.kind == KeyRotationDeliveryKind::Prevote { view: 1 } }),
            "lagging reducer did not vote after verifying the self-contained proposal"
        );

        assert_eq!(leader.acknowledge(&[proposal_id]).unwrap(), 1);
        assert!(
            leader.pending_messages(usize::MAX).iter().any(|message| {
                message.id.recipient == recipient
                    && message.id.kind == KeyRotationDeliveryKind::Advertisement
            }),
            "the durable advertisement must become eligible after proposal acceptance"
        );
    }

    #[test]
    fn self_contained_proposal_initializes_a_lagging_round_without_advertisements() {
        let fixture = fixture();
        let leader_party = PartyId(1);
        let mut leader = KeyRotationRound::new(fixture.context.clone(), leader_party).unwrap();
        leader.advertise(&fixture.target_identities[0], &fixture.receiver_keys).unwrap();
        for capability in fixture
            .target_identities
            .iter()
            .skip(1)
            .take(fixture.context.selection_size().saturating_sub(1))
        {
            leader
                .handle_wire(
                    capability.identity().party(),
                    KeyRotationWire::Advertisement(
                        sign_key_advertisement(&fixture.context, capability).unwrap(),
                    ),
                    &fixture.source_identities[0],
                    &fixture.receiver_keys,
                )
                .unwrap();
        }
        let proposal = leader
            .pending_messages(usize::MAX)
            .into_iter()
            .find_map(|message| {
                if message.id.recipient != PartyId(4) {
                    return None;
                }
                let KeyRotationWire::Consensus(envelope) = message.wire else {
                    return None;
                };
                let decoded = decode_consensus_message(
                    &fixture.context.consensus_context().unwrap(),
                    &envelope,
                )
                .unwrap();
                matches!(decoded.body, ConsensusMessageBody::Proposal(_)).then_some(envelope)
            })
            .expect("view-zero leader did not enqueue its self-contained proposal");

        let mut lagging = KeyRotationRound::new(fixture.context.clone(), PartyId(4)).unwrap();
        let step = lagging
            .handle_wire(
                leader_party,
                KeyRotationWire::Consensus(proposal),
                &fixture.source_identities[3],
                &fixture.receiver_keys,
            )
            .unwrap();
        assert!(step.changed);
        assert_eq!(lagging.advertisement_count(), 0);
        assert_eq!(lagging.view(), 0);
        assert!(
            lagging
                .pending_messages(usize::MAX)
                .iter()
                .any(|message| { message.id.kind == KeyRotationDeliveryKind::Prevote { view: 0 } }),
            "lagging source did not vote for the fully verified proposal"
        );
    }

    #[test]
    fn durable_restore_requires_exact_locally_reconstructed_context() {
        let fixture = fixture();
        let mut round = KeyRotationRound::new(fixture.context.clone(), PartyId(1)).unwrap();
        round.advertise(&fixture.target_identities[0], &fixture.receiver_keys).unwrap();
        let encoded = round.encode().unwrap();

        let foreign = KeyRotationContext::new(
            fixture.context.network(),
            fixture.context.source().clone(),
            [0x42; 32],
            fixture.context.source_fault_bound(),
            fixture.context.target_policy().clone(),
        )
        .unwrap();
        assert!(matches!(
            KeyRotationRound::decode(&foreign, PartyId(1), &encoded),
            Err(KeyRotationError::WrongRoundStateContext)
        ));
        assert!(matches!(
            KeyRotationRound::decode(&fixture.context, PartyId(2), &encoded),
            Err(KeyRotationError::WrongRoundStateContext)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            KeyRotationRound::decode(&fixture.context, PartyId(1), &trailing),
            Err(KeyRotationError::TrailingRoundStateBytes)
        ));
    }

    #[test]
    fn authenticated_origin_and_conflicting_advertisement_fail_atomically() {
        let fixture = fixture();
        let mut round = KeyRotationRound::new(fixture.context.clone(), PartyId(2)).unwrap();
        let original =
            sign_key_advertisement(&fixture.context, &fixture.target_identities[0]).unwrap();
        assert!(matches!(
            round.handle_wire(
                PartyId(3),
                KeyRotationWire::Advertisement(original.clone()),
                fixture.target_identities[1].identity(),
                &fixture.receiver_keys,
            ),
            Err(KeyRotationError::WrongAuthenticatedParty)
        ));
        assert_eq!(round.advertisement_count(), 0);
        round
            .handle_wire(
                PartyId(1),
                KeyRotationWire::Advertisement(original),
                fixture.target_identities[1].identity(),
                &fixture.receiver_keys,
            )
            .unwrap();
        let before = round.encode().unwrap();
        let mut conflicting_body = body_for(&fixture.context, &fixture.target_identities[0]);
        conflicting_body.next_key = fixture.target_identities[1].identity().encryption_public_key();
        let conflicting =
            raw_advertisement(&fixture.context, &fixture.target_identities[0], conflicting_body);
        assert!(matches!(
            round.handle_wire(
                PartyId(1),
                KeyRotationWire::Advertisement(conflicting),
                fixture.target_identities[1].identity(),
                &fixture.receiver_keys,
            ),
            Err(KeyRotationError::ConflictingAdvertisement(PartyId(1)))
        ));
        assert_eq!(round.encode().unwrap(), before);
    }

    #[test]
    fn certified_target_can_seed_an_unconfigured_successor_rotation() {
        let mut fixture = fixture();
        let first = drive_durable_round_with_silent_fourth(&fixture)[0].certificate().unwrap();
        let source = first.target_committee(&fixture.context).unwrap();
        let second_epoch = source.epoch + 1;
        // Rotating the certified successor again needs its own eligible pool floor, so extend the
        // eligible pool with a fresh joiner spare that is never advertised.
        let second_spare = identity(PartyId(5), second_epoch, 0x26);
        let mut second_eligible = source.clone();
        second_eligible.epoch = second_epoch;
        second_eligible.members.push(Member {
            id: PartyId(5),
            signing_key: second_spare.signing_public_key(),
            encryption_key: second_spare.encryption_public_key(),
        });
        let first_selected = source
            .members
            .iter()
            .map(|member| (member.id, member.encryption_key))
            .collect::<Vec<_>>();
        let first_value = first.value(&fixture.context).unwrap();
        fixture
            .receiver_keys
            .apply_verified_update(source.epoch, &first_selected, first_value.history_update())
            .unwrap();
        let second_policy = KeyRotationTargetPolicy::new(
            &source,
            1,
            second_eligible,
            4,
            1,
            fixture.receiver_keys.commitment(),
            10_000,
        )
        .unwrap();
        let second_context = KeyRotationContext::new(
            fixture.context.network(),
            source,
            [0x52; 32],
            1,
            second_policy,
        )
        .unwrap();
        let second_identities = (1_u16..=4)
            .map(|id| {
                let party = PartyId(id);
                advertisable_identity(
                    party,
                    second_context.target_epoch(),
                    0x70 + u8::try_from(id).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let second_value = rotation_value(
            &second_context,
            &fixture.receiver_keys,
            second_identities
                .iter()
                .map(|identity| sign_key_advertisement(&second_context, identity).unwrap())
                .collect(),
        )
        .unwrap();
        assert_eq!(
            second_value.target_committee(&second_context).unwrap().epoch,
            fixture.context.target_epoch() + 1
        );
    }
}
